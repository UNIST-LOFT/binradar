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


def test_advisor_report_counts_applied_children_not_only_proposals(tmp_path):
    log = tmp_path / "tracer.log"
    log.write_text(
        "[symbolic-advisor] [summary] [mode boundary] [sources 2] "
        "[valid-roots 2] [consumers 3] [candidates 8] [families 2] "
        "[unsupported 1] [budget 0] [work 20] [bytes 40] [time-ms 2] "
        "[candidates-generated 4] [families-generated 3] "
        "[families-accepted 2]\n"
        "[binradar] [advisor-attempt] [attempt 2] [advisor-id 2] "
        "[family 11] [source 11] [child-uses 2]\n"
        "[binradar] [advisor-attempt] [attempt 3] [advisor-id 2] "
        "[family 11] [source 11] [child-uses 1]\n"
        "[binradar] [advisor-attempt] [attempt 4] [advisor-id 2] "
        "[family 12] [source 12] [child-uses 0]\n")
    metrics = binradar._read_binradar_advisor_metrics(str(log), "boundary")
    assert metrics["candidates_generated"] == 4
    assert metrics["families_generated"] == 3
    assert metrics["families_accepted"] == 2
    assert metrics["families_executed"] == 1
    assert metrics["child_uses"] == 3
    assert metrics["unsupported_abstentions"] == 1


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
    executor.forkserver_child_timeout = 900
    executor.start_time = time.time() - 3600
    executor.feedback_mode = False
    executor.run_prefix = "run"
    executor.run_id = 0
    executor._phase_environment = lambda *args: {}
    # The pre-flight baseline validation spawns real tracer processes and is
    # covered by its own tests; these cases pin phase-deadline behavior.
    executor._validate_baseline = lambda *args, **kwargs: None
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
            self.forkserver_mode = True
            self.iter = 0
            self.representative_runs = 0
            deadlines.append(deadline)

        def start(self):
            pass

        def run(self):
            type(self).runs += 1
            self.iter += 1
            self.representative_runs = 1
            return binradar_runtime.RunSummary(
                elapsed_ms=0, success=True, attempt=self.iter,
                representative_runs=1, remaining_plans=0,
                attempt_result=binradar_runtime.AttemptResult.COMPLETED,
                stop_reason=binradar_runtime.StopReason.EXHAUSTED)

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
    assert any("[binradar] [stop]" in row and
               "[reason wall-time-reached]" in row and
               "[attempt 0]" in row and "[remaining unknown]" in row and
               "[planned unknown]" in row and "[attempted 0]" in row
               for row in executor.progress)
    assert any("[binradar] [done]" in row for row in executor.progress)


class _RecordingTracer:
    """Minimal v4 executor double replaying a fixed summary sequence."""

    def __init__(self, summaries):
        self.summaries = list(summaries)
        self.forkserver_mode = True
        self.iter = 0
        self.representative_runs = 0

    def run(self):
        summary = self.summaries.pop(0)
        self.iter = summary.attempt
        self.representative_runs = summary.representative_runs
        return summary


def _summary(attempt, remaining, result, stop, runs=1, success=True):
    return binradar_runtime.RunSummary(
        elapsed_ms=1, success=success, attempt=attempt,
        representative_runs=runs, remaining_plans=remaining,
        attempt_result=result, stop_reason=stop)


def _install_binradar_loop_fakes(monkeypatch, tracer):
    class _Session:
        def __init__(self, mode, timeout):
            del mode, timeout
            self.deadline = binradar_runtime.Deadline.from_timeout(60)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def shared_memory(self, *args, **kwargs):
            del args, kwargs

        def start_solver(self, *args, **kwargs):
            del args, kwargs
            return None

        def start_tracer(self, *args, **kwargs):
            del args, kwargs
            return tracer

    monkeypatch.setattr(binradar_runtime, "PhaseSession", _Session)


def _binradar_loop_executor(tmp_path):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.run_prefix = "run"
    executor.run_id = 7
    executor.save_progress = lambda _row: None
    executor.workdir = str(tmp_path)
    executor.run_dir = str(tmp_path)
    executor.test_cmd = "-i @@ out"
    executor.probe_result = SimpleNamespace(poc_input="poc", fault_addr=0)
    executor.feedback_mode = False
    executor.disable_binradar = False
    executor.timeout = 60
    executor.fuzzy = False
    executor.filter_result = [1, 2]
    executor.artifacts = SimpleNamespace(
        original="orig",
        manifest="manifest.json",
        select_tracer=lambda _: SimpleNamespace(
            path="bin", cache_requested=False, cache_enabled=False,
            reason="none", original="orig"))
    executor._phase_environment = lambda *a, **k: {}
    executor._validate_baseline = lambda *a, **k: None
    executor.resolved_poc_input = lambda: "poc"
    executor.check_requirements = lambda: None
    return executor


def test_binradar_inflight_deadline_does_not_reuse_stale_queue_count(
        tmp_path, monkeypatch):
    class _Deadline:
        reached = False

        def expired(self):
            return self.reached

    class _TimeoutTracer:
        forkserver_mode = True
        iter = 0
        representative_runs = 0
        deadline = None

        def run(self):
            if self.iter == 0:
                self.iter = 1
                return _summary(
                    1, 2, binradar_runtime.AttemptResult.COMPLETED,
                    binradar_runtime.StopReason.CONTINUE, runs=3)
            self.deadline.reached = True
            raise TimeoutError("phase deadline")

    tracer = _TimeoutTracer()

    class _Session:
        def __init__(self, mode, timeout):
            del mode, timeout
            self.deadline = _Deadline()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def shared_memory(self, *args, **kwargs):
            del args, kwargs

        def start_solver(self, *args, **kwargs):
            del args, kwargs

        def start_tracer(self, *args, **kwargs):
            del args, kwargs
            tracer.deadline = self.deadline
            return tracer

    monkeypatch.setattr(binradar_runtime, "PhaseSession", _Session)
    executor = _binradar_loop_executor(tmp_path)
    rows: list[str] = []
    executor.save_progress = rows.append

    executor.run_binradar()

    stop = next(row for row in rows if "[binradar] [stop]" in row)
    assert "[reason wall-time-reached]" in stop
    assert "[attempt 1] [remaining unknown]" in stop
    assert "[representative-runs 3] [representative-runs-partial true]" in stop
    assert "[planned 2] [attempted 2]" in stop
    assert "[mutation-attempted 1]" in stop
    assert "[mutation-pending 1] [queued unknown]" in stop


def test_binradar_loop_continues_after_a_discarded_attempt(
        tmp_path, monkeypatch):
    """P2 regression: one unusable attempt must not end the queued sweep."""
    tracer = _RecordingTracer([
        _summary(1, 3, binradar_runtime.AttemptResult.COMPLETED,
                 binradar_runtime.StopReason.CONTINUE),
        _summary(2, 2, binradar_runtime.AttemptResult.UNUSABLE_EXIT,
                 binradar_runtime.StopReason.CONTINUE),
        _summary(3, 1, binradar_runtime.AttemptResult.TIMEOUT,
                 binradar_runtime.StopReason.CONTINUE),
        _summary(4, 0, binradar_runtime.AttemptResult.COMPLETED,
                 binradar_runtime.StopReason.EXHAUSTED),
    ])
    _install_binradar_loop_fakes(monkeypatch, tracer)
    executor = _binradar_loop_executor(tmp_path)
    rows: list[str] = []
    executor.save_progress = rows.append

    executor.run_binradar()

    assert tracer.summaries == []
    attempt_rows = [row for row in rows if "[binradar] [tracer]" in row]
    assert len(attempt_rows) == 4
    assert "[attempt-result unusable-exit]" in attempt_rows[1]
    assert "[discarded true]" in attempt_rows[1]
    stop_rows = [row for row in rows if "[binradar] [stop]" in row]
    assert len(stop_rows) == 1
    assert "[reason exhausted]" in stop_rows[0]
    assert "[attempt 4]" in stop_rows[0]
    assert "[remaining 0]" in stop_rows[0]
    assert "[committed 2]" in stop_rows[0]
    assert "[discarded 2]" in stop_rows[0]
    assert "[planned 3] [attempted 4]" in stop_rows[0]
    assert "[representative-runs 4]" in stop_rows[0]
    assert "[mutation-attempted 3] [mutation-discarded 2] " \
           "[mutation-committed 1] [mutation-pending 0]" in stop_rows[0]


def test_binradar_loop_reports_baseline_unavailable(tmp_path, monkeypatch):
    tracer = _RecordingTracer([
        _summary(1, 0, binradar_runtime.AttemptResult.TIMEOUT,
                 binradar_runtime.StopReason.BASELINE_UNAVAILABLE),
    ])
    _install_binradar_loop_fakes(monkeypatch, tracer)
    executor = _binradar_loop_executor(tmp_path)
    rows: list[str] = []
    executor.save_progress = rows.append

    executor.run_binradar()

    stop_rows = [row for row in rows if "[binradar] [stop]" in row]
    assert len(stop_rows) == 1
    assert "[reason baseline-unavailable]" in stop_rows[0]
    assert "[remaining 0]" in stop_rows[0]
    assert "[discarded 1]" in stop_rows[0]


def test_binradar_loop_records_resource_failure_before_raising(
        tmp_path, monkeypatch):
    tracer = _RecordingTracer([
        _summary(1, 7, binradar_runtime.AttemptResult.UNUSABLE_EXIT,
                 binradar_runtime.StopReason.RESOURCE_FAILURE,
                 success=False),
    ])
    _install_binradar_loop_fakes(monkeypatch, tracer)
    executor = _binradar_loop_executor(tmp_path)
    rows: list[str] = []
    executor.save_progress = rows.append

    with pytest.raises(RuntimeError, match="resource-failure"):
        executor.run_binradar()

    stop_rows = [row for row in rows if "[binradar] [stop]" in row]
    assert len(stop_rows) == 1
    assert "[reason resource-failure]" in stop_rows[0]
    assert "[attempt 1]" in stop_rows[0]
    assert "[remaining 7]" in stop_rows[0]
    assert "[discarded 1]" in stop_rows[0]
    assert not any("[binradar] [done]" in row for row in rows)
