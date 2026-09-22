import importlib.util
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_runtime

SPEC = importlib.util.spec_from_file_location(
    "binradar_runtime_contract", ROOT / "fuzzolic" / "binradar.py")
assert SPEC is not None and SPEC.loader is not None
binradar = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binradar)


def test_unlimited_deadline_stays_unlimited():
    deadline = binradar_runtime.Deadline.from_timeout(0)

    assert deadline.expires_at is None
    assert deadline.remaining() is None
    assert deadline.remaining(3) == 3
    assert deadline.worker_timeout() is None
    assert not deadline.expired()


def test_phase_session_attempts_every_cleanup_and_preserves_primary_error():
    released = []
    session = binradar_runtime.PhaseSession("test", 1)
    session.own("first", lambda: released.append("first"))

    def fail_cleanup():
        released.append("second")
        raise RuntimeError("cleanup failed")

    session.own("second", fail_cleanup)

    with pytest.raises(ValueError, match="primary"):
        with session:
            raise ValueError("primary")

    assert released == ["second", "first"]


def test_phase_session_attempts_every_cleanup_without_primary_error():
    released = []
    session = binradar_runtime.PhaseSession("test", 1)
    session.own("first", lambda: released.append("first"))

    def fail_cleanup():
        released.append("second")
        raise OSError("cleanup failed")

    session.own("second", fail_cleanup)

    with pytest.raises(RuntimeError, match="Failed to release second"):
        session.close()

    assert released == ["second", "first"]


def test_transport_closes_partial_pipe_setup(monkeypatch):
    real_pipe = os.pipe
    acquired = real_pipe()
    calls = 0

    def fail_second_pipe():
        nonlocal calls
        calls += 1
        if calls == 1:
            return acquired
        raise OSError("pipe allocation failed")

    monkeypatch.setattr(binradar_runtime.os, "pipe", fail_second_pipe)
    transport = binradar_runtime.ForkserverTransport({}, "fuzzolic")

    with pytest.raises(OSError, match="pipe allocation failed"):
        transport.setup()

    for fd in acquired:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_transport_treats_fd_zero_as_owned(monkeypatch):
    closed = []
    monkeypatch.setattr(binradar_runtime.os, "close", closed.append)
    transport = binradar_runtime.ForkserverTransport({}, "fuzzolic")
    transport.ctrl_w = 0

    transport.cleanup()

    assert closed == [0]
    assert transport.ctrl_w is None


def _binradar_executor(tmp_path, timeout):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.disable_binradar = False
    executor.resolved_poc_input = lambda: "poc"
    executor.check_requirements = lambda: None
    executor.probe_result = SimpleNamespace(fault_addr=0)
    executor.artifacts = SimpleNamespace(
        manifest=str(tmp_path / "manifest.json"),
        select_tracer=lambda active: SimpleNamespace(
            path="target", cache_requested=False, cache_enabled=False,
            reason="", metadata_prefix="brpatched"),
    )
    executor.filter_result = [1]
    executor.run_dir = str(tmp_path)
    executor.workdir = str(tmp_path)
    executor.test_cmd = "@@"
    executor.fuzzy = False
    executor.timeout = timeout
    executor.start_time = time.time() - 3600
    executor.feedback_mode = False
    executor.run_prefix = "run"
    executor.run_id = 0
    executor._phase_environment = lambda *args: {}
    executor.progress = []
    executor.save_progress = executor.progress.append
    return executor


def _install_runtime_fakes(monkeypatch, solver_start_delay=0):
    deadlines = []

    class FakeShm:
        def __init__(self, env):
            del env

        def assign_random_keys(self):
            pass

        def assign_random_key_for_binradar(self):
            pass

        def cleanup(self):
            pass

    class FakeSolver:
        def __init__(self, *args, deadline, **kwargs):
            del args
            del kwargs
            self.deadline = deadline
            deadlines.append(deadline)

        def start(self):
            time.sleep(solver_start_delay)

        def stop(self):
            pass

    class FakeTracer:
        runs = 0

        def __init__(self, *args, deadline, **kwargs):
            del args
            del kwargs
            self.deadline = deadline
            self.iter = 0
            self.representative_runs = 0
            deadlines.append(deadline)

        def start(self):
            pass

        def run(self):
            type(self).runs += 1
            self.iter += 1
            self.representative_runs = 1
            return 0, True, 0

        def stop(self):
            pass

    monkeypatch.setattr(binradar_runtime, "SharedMemoryManager", FakeShm)
    monkeypatch.setattr(binradar_runtime, "SolverExecutor", FakeSolver)
    monkeypatch.setattr(binradar_runtime, "TracerExecutor", FakeTracer)
    return FakeTracer, deadlines


@pytest.mark.parametrize("timeout", [0, 60])
def test_binradar_uses_phase_local_deadline_after_prior_work(
        tmp_path, monkeypatch, timeout):
    tracer, deadlines = _install_runtime_fakes(monkeypatch)
    executor = _binradar_executor(tmp_path, timeout)

    executor.run_binradar()

    assert tracer.runs == 1
    assert len(deadlines) == 2
    assert deadlines[0] is deadlines[1]
    assert not any("wall-time-reached" in row for row in executor.progress)


def test_binradar_startup_expiry_is_graceful(tmp_path, monkeypatch):
    tracer, _ = _install_runtime_fakes(monkeypatch, solver_start_delay=0.02)
    executor = _binradar_executor(tmp_path, 0.001)

    executor.run_binradar()

    assert tracer.runs == 0
    assert any("[binradar] [wall-time-reached]" in row
               for row in executor.progress)
    assert any("[binradar] [done]" in row for row in executor.progress)
