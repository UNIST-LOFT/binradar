import importlib.util
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_config
import binradar_runtime

SPEC = importlib.util.spec_from_file_location(
    "binradar_runtime_contract", ROOT / "fuzzolic" / "binradar.py")
assert SPEC is not None and SPEC.loader is not None
binradar = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binradar)


def test_shared_memory_keys_are_named_distinct_and_fixed_width(monkeypatch):
    generated = iter((0, 0xA, 0xA, 0xFFFFFFFF, 1, 2))
    monkeypatch.setattr(
        binradar_runtime.random, "getrandbits", lambda _width: next(generated))
    environment = {}
    manager = binradar_runtime.SharedMemoryManager(environment)

    manager.assign_random_keys()
    manager.assign_random_key_for_binradar()

    values = [environment[key] for key in binradar_runtime.SHM_KEYS]
    values.append(environment["BINRADAR_PATCH_SHM_KEY"])
    assert values == ["0x0000000a", "0xffffffff", "0x00000001",
                      "0x00000002"]
    assert {len(value) for value in values} == {10}
    assert [int(value, 0) for value in values] == manager.shm_keys
    assert 0 not in manager.shm_keys
    assert len(set(manager.shm_keys)) == len(manager.shm_keys)


def test_shared_memory_key_seed_is_private_and_reproducible():
    def generated_keys(seed):
        environment = {binradar_runtime.SHM_KEY_SEED_ENV: seed}
        manager = binradar_runtime.SharedMemoryManager(environment)
        manager.assign_random_keys()
        manager.assign_random_key_for_binradar()
        return environment, manager.shm_keys

    first_environment, first_keys = generated_keys("0x0123456789abcdef")
    second_environment, second_keys = generated_keys("0x0123456789abcdef")
    other_environment, other_keys = generated_keys("0x0123456789abcdee")

    assert binradar_runtime.SHM_KEY_SEED_ENV not in first_environment
    assert binradar_runtime.SHM_KEY_SEED_ENV not in second_environment
    assert binradar_runtime.SHM_KEY_SEED_ENV not in other_environment
    assert first_keys == second_keys
    assert first_keys != other_keys
    assert all(0 < key <= 0xFFFFFFFF for key in first_keys)
    assert len(set(first_keys)) == len(first_keys)


def test_shared_memory_key_seed_rejects_invalid_values():
    environment = {binradar_runtime.SHM_KEY_SEED_ENV: "0xnot-a-seed"}
    with pytest.raises(ValueError, match="must be 16 lowercase hex digits"):
        binradar_runtime.SharedMemoryManager(environment)
    assert environment == {}


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


def _plan_attempt(attempt=2, advisor="2", source_kind="primitive", **overrides):
    row = {
        "version": "1", "epoch": "9", "attempt": str(attempt),
        "advisor-id": advisor, "family-id": "7", "source-ordinal": "11",
        "source-kind": source_kind, "seed-semantics": "observed-read",
        "write-count": "1", "patch0-applied": "true",
        "patch0-read-witness": "matched-value", "patch0-site": "yes",
        "patch0-exit": "normal", "patch0-fault-valid": "false",
        "patch0-fault-source": "unavailable", "patch0-fault-addr": "unknown",
        "source-retained": "true", "attempt-result": "completed",
        "committed": "true",
    }
    row.update(overrides)
    return row


def _funnel_attempt(row, *, outcome="normal", result="completed",
                    representative_runs=2, elapsed_ms=3,
                    available=True, pending=False):
    return {
        "row": row, "outcome": outcome, "protocol-result": result,
        "representative-runs": representative_runs,
        "elapsed-ms": elapsed_ms, "diagnostic-available": available,
        "pending": pending,
    }


def test_plan_attempt_crash_classification_requires_typed_valid_probe_reference():
    reference = binradar.binradar_verifier.TracerFaultReference(
        0x401234, "guest-signal")
    tracer_row = _plan_attempt(
        **{"patch0-exit": "crash", "patch0-fault-valid": "true",
           "patch0-fault-source": "guest-signal",
           "patch0-fault-addr": "401234"})
    row = binradar._normalize_plan_attempt(tracer_row)
    assert row is not None
    assert row["patch0-fault-addr"] == "401234"

    assert binradar._classify_plan_attempt_outcome(row, reference) == "poc-crash"
    assert binradar._classify_plan_attempt_outcome(
        {**row, "patch0-fault-source": "provenance-access"}, reference
    ) == "poc-crash"
    assert binradar._classify_plan_attempt_outcome(
        row, binradar.binradar_verifier.TracerFaultReference(
            0x401234, "unavailable")) == "unclassified-crash"
    assert binradar._classify_plan_attempt_outcome(
        row, None) == "unclassified-crash"
    assert binradar._classify_plan_attempt_outcome(
        {**row, "patch0-fault-valid": "false"}, reference
    ) == "unclassified-crash"
    assert binradar._classify_plan_attempt_outcome(
        {**row, "patch0-fault-addr": "401235"}, reference
    ) == "other-crash"


def test_not_applicable_read_witness_is_not_reported_as_unknown():
    row = _plan_attempt(
        advisor="0", source_kind="argument-pointer",
        **{"patch0-read-witness": "not-applicable"})
    funnel = binradar._build_plan_funnel(
        [_funnel_attempt(row)], None, "0", False)
    argument = next(
        item for item in funnel
        if item["advisor"] == "generic" and
        item["source-kind"] == "argument-pointer")

    assert row["patch0-read-witness"] == "not-applicable"
    assert argument["matched-witness"] == "0"
    assert argument["witness-unknown"] == "0"


def test_discarded_plan_diagnostic_does_not_count_as_committed_useful():
    row = _plan_attempt(**{"committed": "false"})
    funnel = binradar._build_plan_funnel(
        [_funnel_attempt(row, result="unusable-exit")], None, "0", False)
    primitive = next(
        item for item in funnel
        if item["advisor"] == "symbolic" and
        item["source-kind"] == "primitive")

    assert primitive["attempted"] == "1"
    assert primitive["applied"] == "1"
    assert primitive["normal"] == "1"
    assert primitive["discarded"] == "1"
    assert primitive["committed-useful"] == "0"
    assert primitive["scheduled"] == "unknown"


def test_interrupted_attempt_keeps_outcomes_unknown_and_pending():
    row = binradar._empty_plan_attempt(3, "unknown")
    funnel = binradar._build_plan_funnel(
        [_funnel_attempt(row, outcome="unknown", result="unknown",
                         representative_runs=None, elapsed_ms=None,
                         available=False, pending=True)],
        None, "unknown", True)
    unknown = next(
        item for item in funnel
        if item["advisor"] == "unknown" and item["source-kind"] == "unknown")

    assert unknown["attempted"] == "1"
    assert unknown["unknown"] == "1"
    assert unknown["pending"] == "unknown"
    assert unknown["representative-runs"] == "unknown"
    assert unknown["time-ms"] == "unknown"
    assert unknown["scheduled"] == "unknown"


def test_plan_attempt_reader_retries_partial_tracer_rows(tmp_path):
    log = tmp_path / "tracer.log"
    line = binradar._render_plan_attempt_progress(
        _plan_attempt(), outcome="normal", diagnostic_available=True,
        representative_runs="2", elapsed_ms="3", prefix="run", run_id=0)
    split = len(line) // 2
    log.write_text(line[:split])

    events, queue_row, offset = binradar._read_new_plan_attempt_rows(
        str(log), 0)
    assert events == []
    assert queue_row is None
    assert offset == 0

    with log.open("a") as stream:
        stream.write(line[split:] + "\n")
    events, queue_row, offset = binradar._read_new_plan_attempt_rows(
        str(log), offset)
    assert [event["attempt"] for event in events] == ["2"]
    assert queue_row is None
    assert offset == log.stat().st_size


def test_queue_bins_and_attempts_preserve_mixed_advisor_source_counts(tmp_path):
    log = tmp_path / "tracer.log"
    log.write_text(
        "[binradar] [queue-bins] [version 1] [total 2] "
        "[generic-primitive 1] [generic-primitive-retained 1] "
        "[generic-pointer 0] [generic-pointer-retained 0] "
        "[generic-argument-primitive 0] "
        "[generic-argument-primitive-retained 0] "
        "[generic-argument-pointer 0] "
        "[generic-argument-pointer-retained 0] "
        "[osprey-primitive 0] [osprey-primitive-retained 0] "
        "[osprey-pointer 0] [osprey-pointer-retained 0] "
        "[symbolic-primitive 0] [symbolic-primitive-retained 0] "
        "[symbolic-pointer 1] [symbolic-pointer-retained 0] [unknown 0]\n")
    attempt_line = binradar._render_plan_attempt_progress(
        _plan_attempt(advisor="0"), outcome="normal",
        diagnostic_available=True, representative_runs="2", elapsed_ms="3",
        prefix="run", run_id=0)
    with log.open("a") as stream:
        stream.write(attempt_line + "\n")
    events, queue_row, _ = binradar._read_new_plan_attempt_rows(str(log), 0)
    assert events[0]["attempt"] == "2"
    assert events[0]["source-retained"] == "true"
    scheduled = binradar._scheduled_plan_bins(queue_row)
    assert scheduled is not None
    assert scheduled[("generic", "primitive")] == {
        "scheduled": 1, "retained": 1}
    assert scheduled[("generic", "argument-primitive")] == {
        "scheduled": 0, "retained": 0}
    assert scheduled[("generic", "argument-pointer")] == {
        "scheduled": 0, "retained": 0}
    assert scheduled[("symbolic", "pointer")] == {
        "scheduled": 1, "retained": 0}

    records = [
        _funnel_attempt(_plan_attempt(advisor="0")),
        _funnel_attempt(_plan_attempt(
            attempt=3, advisor="2", source_kind="pointer",
            **{"source-retained": "false"}), outcome="other-crash",
            result="completed", representative_runs=4, elapsed_ms=7),
    ]
    funnel = binradar._build_plan_funnel(records, scheduled, "0", False)
    by_key = {(item["advisor"], item["source-kind"]): item for item in funnel}

    assert by_key[("generic", "primitive")]["scheduled"] == "1"
    assert by_key[("generic", "primitive")]["scheduled-retained"] == "1"
    assert by_key[("generic", "primitive")]["committed-useful"] == "1"
    assert by_key[("symbolic", "pointer")]["scheduled"] == "1"
    assert by_key[("symbolic", "pointer")]["scheduled-not-retained"] == "1"
    assert by_key[("symbolic", "pointer")]["other-crash"] == "1"
    assert by_key[("symbolic", "pointer")]["representative-runs"] == "4"
    assert by_key[("symbolic", "pointer")]["time-ms"] == "7"


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
    executor.symbolic_schedule = binradar_config.SYMBOLIC_SCHEDULE_DEFAULT
    executor.symbolic_budgets = binradar_config.SymbolicBudgets(
        max_work=binradar_config.SYMBOLIC_MAX_WORK_DEFAULT,
        max_bytes=binradar_config.SYMBOLIC_MAX_BYTES_DEFAULT,
        deadline_ms=binradar_config.SYMBOLIC_DEADLINE_MS_DEFAULT)
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
    executor.forkserver_child_timeout = (
        binradar_config.FORKSERVER_CHILD_TIMEOUT_DEFAULT)
    executor.symbolic_schedule = binradar_config.SYMBOLIC_SCHEDULE_DEFAULT
    executor.symbolic_budgets = binradar_config.SymbolicBudgets(
        max_work=binradar_config.SYMBOLIC_MAX_WORK_DEFAULT,
        max_bytes=binradar_config.SYMBOLIC_MAX_BYTES_DEFAULT,
        deadline_ms=binradar_config.SYMBOLIC_DEADLINE_MS_DEFAULT)
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


def test_advisor_profile_metrics_and_budget_traceability(tmp_path):
    """Preserve the tracer's independently reported profile for trial joins.

    Settings v2 records the orchestrator's effective request; `[config]` and
    `[profile]` independently show what the tracer configured and measured. A
    missing profile row is reported as unknown, never as a zero.
    """
    log = tmp_path / "binradar-tracer-msg.log"
    log.write_text(
        "[symbolic-advisor] [config] [mode shadow] [max-work 500000] "
        "[max-bytes 16777216] [deadline-ms 500]\n"
        "[symbolic-advisor] [profile] [version 1] [mode shadow] "
        "[max-work 500000] [max-bytes 16777216] [deadline-ms 500] "
        "[stop-stage consumers] [stop-reason work] "
        "[would-submit-families 4] [would-submit-variants 9] "
        "[analysis-complete 0] [digest 00000000000000ff]\n")

    metrics = binradar._read_binradar_advisor_metrics(str(log), "shadow")
    profile = metrics["profile"]

    assert profile["max-work"] == "500000"
    assert profile["deadline-ms"] == "500"
    assert profile["stop-stage"] == "consumers"
    assert profile["stop-reason"] == "work"
    assert profile["would-submit-families"] == "4"
    assert profile["would-submit-variants"] == "9"
    assert profile["analysis-complete"] == "0"
    assert profile["digest"] == "00000000000000ff"

    # A tracer without the profile row leaves the attribution unknown.
    summary_only = tmp_path / "summary-only.log"
    summary_only.write_text(
        "[symbolic-advisor] [summary] [mode boundary] [sources 2] "
        "[valid-roots 2] [consumers 3] [candidates 8] [families 2] "
        "[unsupported 1] [budget 0] [work 20] [bytes 40] [time-ms 2] "
        "[candidates-generated 4] [families-generated 3] "
        "[families-accepted 2]\n")
    legacy = binradar._read_binradar_advisor_metrics(
        str(summary_only), "boundary")
    assert legacy["families_accepted"] == 2
    assert legacy["profile"] == {}


def test_stop_row_reports_effective_budgets_and_forkserver_margin(
        tmp_path, monkeypatch):
    """The terminal row carries the trial telemetry P4a requires.

    Latency, honest child RSS, configured budgets, effective child timeout and
    forkserver margin must appear on the row a trial reads. Profile attribution
    comes from the tracer's own row; missing or process-global-only values are
    `unknown`, never fabricated measurements.
    """
    tracer = _RecordingTracer([
        _summary(1, 1, binradar_runtime.AttemptResult.COMPLETED,
                 binradar_runtime.StopReason.EXHAUSTED),
    ])
    _install_binradar_loop_fakes(monkeypatch, tracer)
    executor = _binradar_loop_executor(tmp_path)
    executor.symbolic_budgets = binradar_config.SymbolicBudgets(
        max_work=500000, max_bytes=1048576, deadline_ms=500)
    executor._phase_environment = lambda *a, **k: {
        # The phase timeout lowers the requested 900-second cap to 60 seconds;
        # terminal telemetry must report this effective value.
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "60",
    }
    child_usage = iter([
        SimpleNamespace(ru_maxrss=4096),
        SimpleNamespace(ru_maxrss=4096),
    ])
    monkeypatch.setattr(
        binradar.resource, "getrusage", lambda _scope: next(child_usage))
    rows: list[str] = []
    executor.save_progress = rows.append

    executor.run_binradar()

    stop_rows = [row for row in rows if "[binradar] [stop]" in row]
    assert len(stop_rows) == 1
    row = stop_rows[0]
    assert "[advisor-max-work 500000]" in row
    assert "[advisor-max-bytes 1048576]" in row
    assert "[advisor-deadline-ms 500]" in row
    assert "[phase-ms " in row
    # The phase did not raise the process-wide child high-water mark, so the
    # phase-local peak is not knowable and must not reuse 4096 as if measured.
    assert "[child-peak-rss-kib unknown]" in row
    assert "[forkserver-read-timeout 1800]" in row
    assert "[forkserver-child-timeout 60]" in row
    assert "[forkserver-margin 1440]" in row
    # No tracer log was written, so the profile attribution is unknown.
    assert "[advisor-stop-reason unknown]" in row
    assert "[advisor-would-submit-families unknown]" in row
    assert "[advisor-digest unknown]" in row
