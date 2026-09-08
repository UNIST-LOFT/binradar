import importlib.util
import os
import select
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
SPEC = importlib.util.spec_from_file_location(
    "binradar_protocol", ROOT / "fuzzolic" / "binradar.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("failed to load fuzzolic/binradar.py")
binradar = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binradar)


FAKE_FORKSERVER = r'''#!/usr/bin/env python3
import os
import select
import struct
import time

ctrl = int(os.environ["BINRADAR_FORKSERVER_CTRL_R"])
stat = int(os.environ["BINRADAR_FORKSERVER_STAT_W"])
mode = os.environ.get("FAKE_MODE", "normal")
log_path = os.environ.get("FAKE_LOG")
version = int(os.environ.get("FAKE_VERSION", "0x41464c01"), 0)
wrong_ack = int(os.environ.get("FAKE_WRONG_ACK", "0x12345678"), 0)


def log(row):
    if log_path:
        with open(log_path, "a", encoding="ascii") as stream:
            stream.write(row + "\n")


def read_exact(fd, size):
    data = b""
    while len(data) < size:
        chunk = os.read(fd, size - len(data))
        if not chunk:
            return data
        data += chunk
    return data


def send(value):
    os.write(stat, struct.pack("<I", value))


def run_statuses(statuses):
    for status, patch, iteration, remaining in statuses:
        command = read_exact(ctrl, 4)
        if len(command) != 4:
            log("parent-eof")
            return
        log("command:" + command.hex())
        if mode == "stall_after_command":
            time.sleep(3)
            return
        if mode in ("partial_status", "close_during_status"):
            os.write(stat, struct.pack("<I", status)[:2])
            if mode == "partial_status":
                time.sleep(3)
            else:
                os.close(stat)
            return
        os.write(stat, struct.pack("<III", status, patch, iteration))
        log("status:%d:%d:%d" % (status, patch, iteration))
        if mode == "stall_after_status":
            time.sleep(3)
            return
        if mode == "close_before_remaining":
            os.close(stat)
            return
        send(remaining)
        log("remaining:%d" % remaining)


if mode == "close_before_banner":
    os.close(stat)
    raise SystemExit(0)

send(version)
if mode == "close_during_handshake":
    os.close(stat)
    raise SystemExit(0)

reply = read_exact(ctrl, 4)
if len(reply) != 4:
    log("handshake-eof")
    raise SystemExit(0)
reply_value = struct.unpack("<I", reply)[0]
expected_reply = version ^ 0xFFFFFFFF
if mode == "new_server_reject_old_ack":
    if reply_value != expected_reply:
        log("ack-mismatch")
    else:
        log("ack-accepted")
    raise SystemExit(0)
if reply_value != expected_reply:
    log("bad-ack:%08x" % reply_value)
    raise SystemExit(0)

if mode == "wrong_ack":
    send(wrong_ack)
    raise SystemExit(0)

send(version)
statuses_text = os.environ.get("FAKE_STATUSES", "7,11,1,5")
statuses = []
for item in statuses_text.split(";"):
    statuses.append(tuple(int(part, 0) for part in item.split(",")))
run_statuses(statuses)
if mode == "check_unread":
    ready, _, _ = select.select([ctrl], [], [], 0.2)
    if ready:
        extra = os.read(ctrl, 4096)
        log("extra:" + (extra.hex() if extra else "none"))
    else:
        log("extra:none")

while True:
    command = read_exact(ctrl, 4)
    if not command:
        log("parent-eof")
        raise SystemExit(0)
    if len(command) != 4:
        log("short-command")
        raise SystemExit(0)
    log("command:" + command.hex())
'''


@pytest.fixture
def fake_script(tmp_path):
    path = tmp_path / "fake_forkserver.py"
    path.write_text(FAKE_FORKSERVER, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def make_executor(tmp_path, monkeypatch, fake_script, mode="check_unread", statuses=None):
    log_path = tmp_path / "fake.log"
    env = os.environ.copy()
    env.update(
        {
            "BINRADAR_FORKSERVER_ENABLE": "1",
            "FAKE_MODE": mode,
            "FAKE_LOG": str(log_path),
        }
    )
    if statuses is not None:
        env["FAKE_STATUSES"] = ";".join(",".join(str(x) for x in row) for row in statuses)
    monkeypatch.setattr(binradar, "TRACER_BIN", str(fake_script))
    executor = binradar.TracerExecutor(
        "protocol",
        env,
        str(tmp_path),
        str(tmp_path),
        "ignored",
        "",
        "ignored",
        1,
    )
    executor.forkserver_init_timeout = 0.5
    executor.forkserver_timeout = 0.25
    return executor, log_path


def stop_executor(executor):
    try:
        executor.stop()
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        if executor.process is not None and executor.process.poll() is None:
            executor.process.kill()
            executor.process.wait(timeout=2)


def read_pipe(fd, size, timeout=1.0):
    deadline = time.monotonic() + timeout
    data = b""
    while len(data) < size:
        wait = deadline - time.monotonic()
        if wait <= 0:
            raise TimeoutError("pipe read timed out")
        ready, _, _ = select.select([fd], [], [], wait)
        if not ready:
            raise TimeoutError("pipe read timed out")
        chunk = os.read(fd, size - len(data))
        if not chunk:
            raise EOFError("pipe EOF")
        data += chunk
    return data


def test_new_protocol_one_run_has_no_payload(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(tmp_path, monkeypatch, fake_script)
    try:
        executor.start()
        elapsed, success, remaining = executor.run()
        assert elapsed >= 0
        assert success is True
        assert remaining == 5
        assert executor.iter == 1
    finally:
        stop_executor(executor)
    rows = log_path.read_text(encoding="ascii").splitlines()
    assert rows.count("command:00000000") == 1
    assert "status:7:11:1" in rows
    assert "remaining:5" in rows
    assert "extra:none" in rows


def test_back_to_back_runs_keep_status_boundaries(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(
        tmp_path,
        monkeypatch,
        fake_script,
        statuses=[(1, 101, 1, 4), (2, 202, 2, 3)],
    )
    try:
        executor.start()
        assert executor.run()[2] == 4
        assert executor.run()[2] == 3
        assert executor.iter == 2
    finally:
        stop_executor(executor)
    rows = log_path.read_text(encoding="ascii").splitlines()
    assert rows.count("command:00000000") == 2
    assert "status:1:101:1" in rows
    assert "status:2:202:2" in rows
    assert rows.count("remaining:4") == 1
    assert rows.count("remaining:3") == 1


@pytest.mark.parametrize(
    "mode, phase",
    [
        ("close_before_banner", "start"),
        ("close_during_handshake", "start"),
        ("close_during_status", "run"),
        ("close_before_remaining", "run"),
    ],
)
def test_protocol_eof_is_fatal(monkeypatch, tmp_path, fake_script, mode, phase):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode=mode)
    started = time.monotonic()
    try:
        with pytest.raises(EOFError):
            executor.start()
            if phase == "run":
                executor.run()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 1.5


def test_idle_parent_close_terminates_tracer(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(tmp_path, monkeypatch, fake_script, mode="normal")
    started = time.monotonic()
    executor.start()
    stop_executor(executor)
    assert time.monotonic() - started < 1.5
    assert "parent-eof" in log_path.read_text(encoding="ascii").splitlines()


@pytest.mark.parametrize("mode", ["stall_after_command", "partial_status", "stall_after_status"])
def test_stalled_peer_hits_bounded_timeout(monkeypatch, tmp_path, fake_script, mode):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode=mode)
    started = time.monotonic()
    try:
        executor.start()
        with pytest.raises(TimeoutError):
            executor.run()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 2.0


@pytest.mark.parametrize("mode", ["wrong_ack"])
def test_wrong_acknowledgement_fails_handshake(monkeypatch, tmp_path, fake_script, mode):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode=mode)
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="Unexpected forkserver ack"):
            executor.start()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 1.5


def test_old_word_tracer_fails_new_runner(monkeypatch, tmp_path, fake_script):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode="normal")
    executor.env["FAKE_VERSION"] = "0x41464c00"
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="Unexpected forkserver handshake"):
            executor.start()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 1.5


def test_old_runner_fails_new_tracer(monkeypatch, tmp_path, fake_script):
    del monkeypatch
    log_path = tmp_path / "old-runner.log"
    ctrl_r, ctrl_w = os.pipe()
    stat_r, stat_w = os.pipe()
    env = os.environ.copy()
    env.update(
        {
            "BINRADAR_FORKSERVER_CTRL_R": str(ctrl_r),
            "BINRADAR_FORKSERVER_STAT_W": str(stat_w),
            "FAKE_MODE": "new_server_reject_old_ack",
            "FAKE_LOG": str(log_path),
        }
    )
    proc = subprocess.Popen(
        [str(fake_script)],
        env=env,
        pass_fds=(ctrl_r, stat_w),
        start_new_session=True,
    )
    os.close(ctrl_r)
    os.close(stat_w)
    try:
        banner = struct.unpack("<I", read_pipe(stat_r, 4))[0]
        assert banner == binradar.HANDSHAKE_EXPECTED
        old_word = 0x41464C00
        os.write(ctrl_w, struct.pack("<I", old_word ^ 0xFFFFFFFF))
        proc.wait(timeout=1)
    finally:
        os.close(ctrl_w)
        os.close(stat_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
    assert log_path.read_text(encoding="ascii").splitlines() == ["ack-mismatch"]


def test_child_timeout_status_has_no_analysis_word(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(
        tmp_path,
        monkeypatch,
        fake_script,
        statuses=[(139, 0, 1, 0)],
    )
    try:
        executor.start()
        _, success, remaining = executor.run()
        assert success is True
        assert remaining == 0
        assert executor.iter == 1
    finally:
        stop_executor(executor)
    rows = log_path.read_text(encoding="ascii").splitlines()
    assert "status:139:0:1" in rows
    assert "extra:none" in rows
