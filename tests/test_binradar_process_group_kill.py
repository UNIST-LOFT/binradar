#!/usr/bin/env python3
"""Tests for process-group kill semantics (br-test 2026-09-08 F2).

The 2026-09-08 br-test run leaked one orphaned `.brpatched` forkserver
child (PPID 1, futex wait) per failed subject: leader-only cleanup
(send_signal/kill, or communicate() on an already-dead leader) never
signals the surviving group members. These tests pin the leak-safe
behavior:

- kill_process_group must kill group members even when the (dead) leader
  was already reaped,
- it must escalate to SIGKILL after the grace period,
- it must be a no-op on an already-empty group,
- the global stop_running_processes() path must sweep the group too,
- execute_await's success path must sweep in-flight children of a leader
  that exited normally.
"""

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
import binradar_utils  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None and _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)


def _alive(pid: int) -> bool:
    """True if `pid` still exists (zombies count as alive here)."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _spawn_leader_with_grandchild(script: str, **popen_kwargs) -> tuple:
    """Spawn a session-leader python process running `script`; the script
    forks a sleeping grandchild and prints its pid on stdout."""
    leader = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE, start_new_session=True, **popen_kwargs)
    grandchild_pid = int(leader.stdout.readline())
    return leader, grandchild_pid


GRANDCHILD_SCRIPT = """
import subprocess, sys
# stdout/stderr must not be inherited: a grandchild holding the leader's
# stdout pipe would make communicate() block until the grandchild exits.
child = subprocess.Popen(["sleep", "60"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(child.pid, flush=True)
"""

TERM_IGNORING_SCRIPT = """
import signal, subprocess, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen(["sleep", "60"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(child.pid, flush=True)
time.sleep(60)
"""


def _assert_grandchild_dead(grandchild_pid):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not _alive(grandchild_pid):
            return
        time.sleep(0.1)
    pytest.fail(f"grandchild {grandchild_pid} survived the group kill")


def test_kill_process_group_kills_grandchild_of_dead_leader():
    # The exact F2 leak: the leader exits while its forked child keeps
    # running; the group id must still reach the surviving member.
    leader, grandchild_pid = _spawn_leader_with_grandchild(GRANDCHILD_SCRIPT)
    try:
        pgid = binradar_utils.process_group_id(leader)
        leader.wait(timeout=10)
        assert _alive(grandchild_pid), "grandchild died before the kill"
        binradar_utils.kill_process_group(pgid, grace=2)
        _assert_grandchild_dead(grandchild_pid)
    finally:
        leader.stdout.close()


def test_kill_process_group_escalates_to_sigkill():
    # Leader ignores SIGTERM; the grace expiry must SIGKILL the group
    # (leader + grandchild).
    leader, grandchild_pid = _spawn_leader_with_grandchild(
        TERM_IGNORING_SCRIPT)
    try:
        pgid = binradar_utils.process_group_id(leader)
        assert _alive(leader.pid) and _alive(grandchild_pid)
        binradar_utils.kill_process_group(pgid, grace=0.5)
        leader.wait(timeout=10)
        assert leader.returncode == -signal.SIGKILL
        _assert_grandchild_dead(grandchild_pid)
    finally:
        leader.stdout.close()


def test_kill_process_group_noop_on_empty_group():
    leader = subprocess.Popen(["sleep", "0"], start_new_session=True)
    leader.wait(timeout=10)
    pgid = leader.pid  # group is empty; pgid equals the leader pid
    # Must not raise.
    binradar_utils.kill_process_group(pgid, grace=0.5)
    # A pgid that never existed must be a no-op too.
    binradar_utils.kill_process_group(2 ** 22, grace=0.5)


def test_kill_process_group_sigint_first_signal():
    # first_signal is honored (the tracer error path uses SIGINT to let
    # the forkserver parent unwind via its own handler first).
    leader, grandchild_pid = _spawn_leader_with_grandchild(
        TERM_IGNORING_SCRIPT.replace("signal.SIGTERM", "signal.SIGINT"))
    try:
        pgid = binradar_utils.process_group_id(leader)
        binradar_utils.kill_process_group(pgid, grace=0.5,
                                          first_signal=signal.SIGINT)
        leader.wait(timeout=10)
        assert leader.returncode == -signal.SIGKILL
        _assert_grandchild_dead(grandchild_pid)
    finally:
        leader.stdout.close()


def test_execute_await_success_path_sweeps_surviving_children():
    # execute_await is also used on probe runners whose leader can exit
    # normally while a group member lingers; the success path must sweep.
    leader, grandchild_pid = _spawn_leader_with_grandchild(GRANDCHILD_SCRIPT)
    try:
        result = binradar_utils.execute_await(leader, timeout=10)
        assert result.success
        assert result.exit_code == 0
        _assert_grandchild_dead(grandchild_pid)
    finally:
        leader.stdout.close()


def test_stop_running_processes_sweeps_registered_group():
    # Register a live leader with a grandchild in the global registry and
    # stop it: the grandchild must not survive as an orphan.
    leader, grandchild_pid = _spawn_leader_with_grandchild(GRANDCHILD_SCRIPT)
    try:
        binradar.register_running_process(leader)
        assert leader.pid in binradar.RUNNING_PROCESS_PGIDS
        binradar.stop_running_processes()
        assert not _alive(leader.pid)
        _assert_grandchild_dead(grandchild_pid)
        assert leader not in binradar.RUNNING_PROCESSES
        assert leader.pid not in binradar.RUNNING_PROCESS_PGIDS
    finally:
        leader.stdout.close()
        binradar.unregister_running_process(leader)


def test_stop_running_processes_cleans_an_empty_registry():
    binradar.stop_running_processes()  # must not raise


def test_register_unregister_roundtrip():
    leader = subprocess.Popen(["sleep", "5"], start_new_session=True)
    try:
        binradar.register_running_process(leader)
        assert leader in binradar.RUNNING_PROCESSES
        assert binradar.RUNNING_PROCESS_PGIDS[leader.pid] == leader.pid
        binradar.unregister_running_process(leader)
        assert leader not in binradar.RUNNING_PROCESSES
        assert leader.pid not in binradar.RUNNING_PROCESS_PGIDS
    finally:
        leader.kill()
        leader.wait(timeout=10)