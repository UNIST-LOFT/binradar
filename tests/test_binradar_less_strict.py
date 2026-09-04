#!/usr/bin/env python3
"""Tests for the opt-in --less-strict orchestration policy."""

import importlib.util
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None and _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)


def _policy_executor(tmp_path, less_strict):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.less_strict = less_strict
    executor.binradar_failed = False
    executor.phase_failures = {}
    executor.phase_failure_lock = threading.Lock()
    executor.run_prefix = "run"
    executor.run_id = 0
    executor.run_dir = str(tmp_path)
    executor.start_time = time.time()
    executor.progress_filename = str(tmp_path / "progress.sbsv")
    return executor


def test_optional_phase_failure_is_strict_by_default(tmp_path):
    executor = _policy_executor(tmp_path, less_strict=False)

    with pytest.raises(RuntimeError, match="AFL dry run failed"):
        executor._run_optional_phase(
            "fuzzer",
            lambda: (_ for _ in ()).throw(RuntimeError("AFL dry run failed")))

    assert executor.failed_phase_names() == []


def test_less_strict_allowlist_cannot_tolerate_required_phase(tmp_path):
    executor = _policy_executor(tmp_path, less_strict=True)

    with pytest.raises(ValueError, match="not optional"):
        executor._run_optional_phase(
            "verifier", lambda: (_ for _ in ()).throw(RuntimeError("bad")))


def test_optional_phase_failure_is_recorded_in_less_strict_mode(tmp_path):
    executor = _policy_executor(tmp_path, less_strict=True)
    progress = []
    executor.save_progress = progress.append

    succeeded = executor._run_optional_phase(
        "fuzzer",
        lambda: (_ for _ in ()).throw(RuntimeError("AFL dry run failed")))

    assert succeeded is False
    assert executor.failed_phase_names() == ["fuzzer"]
    assert progress == [
        "[fuzzer] [failed] [prefix run] [id 0] [less-strict true]"]


def test_fuzzer_only_runs_fuzzer_then_concrete_pipeline(tmp_path, monkeypatch):
    executor = _policy_executor(tmp_path, less_strict=False)
    executor.disable_binradar = False
    events = []
    monkeypatch.setattr(binradar.logger, "set_file", lambda _: None)

    def set_run_dir(run_prefix="run"):
        executor.run_prefix = run_prefix
        executor.run_id = 0
        executor.run_dir = str(tmp_path / "fuzzer-00000")
        Path(executor.run_dir).mkdir()
        events.append("set-run-dir")

    executor.set_run_dir = set_run_dir
    executor.run_probe = lambda: events.append("probe")
    executor.run_filter = lambda: (events.append("filter") or [1])
    executor.run_fuzzer = lambda: events.append("fuzzer")
    executor.run_minimizer_and_verifier = lambda: events.append(
        "minimizer-verifier")
    executor.run_final = lambda: events.append("final")
    executor.done = lambda: events.append("done")
    executor.run_fuzzolic = lambda: (_ for _ in ()).throw(
        AssertionError("fuzzolic must be skipped"))
    executor.run_directed = lambda: (_ for _ in ()).throw(
        AssertionError("directed must be skipped"))
    executor.run_binradar = lambda: (_ for _ in ()).throw(
        AssertionError("binradar must be skipped"))

    executor.run_fuzzer_only("fuzzer")

    assert executor.disable_binradar is True
    assert events == [
        "set-run-dir", "probe", "filter", "fuzzer",
        "minimizer-verifier", "final", "done"]


def test_multithreaded_less_strict_fuzzer_failure_reaches_final(
        tmp_path, monkeypatch):
    executor = _policy_executor(tmp_path, less_strict=True)
    executor.disable_binradar = True
    events = []
    progress = []
    monkeypatch.setattr(binradar.logger, "set_file", lambda _: None)

    def set_run_dir(run_prefix="run"):
        executor.run_prefix = run_prefix
        executor.run_id = 0
        executor.run_dir = str(tmp_path / "run-00000")
        Path(executor.run_dir).mkdir()

    executor.set_run_dir = set_run_dir
    executor.save_progress = progress.append
    executor.run_probe = lambda: events.append("probe")
    executor.run_filter = lambda: [1]
    executor.prepare_fuzzer_output = lambda: events.append("prepare-fuzzer")
    executor.run_fuzzolic = lambda: events.append("fuzzolic")
    executor.run_directed = lambda: events.append("directed")

    def fail_fuzzer():
        raise RuntimeError("AFL exited with status 1")

    executor.run_fuzzer = fail_fuzzer

    def run_minimizer_and_verifier(producer_threads=None,
                                   producer_exc_queue=None):
        assert producer_threads is not None
        for thread in producer_threads:
            thread.join()
        assert producer_exc_queue is not None and producer_exc_queue.empty()
        events.append("minimizer-verifier")

    executor.run_minimizer_and_verifier = run_minimizer_and_verifier
    executor.run_final = lambda: events.append("final")
    executor.done = lambda: events.append("done")

    executor.run_multithreaded()

    assert executor.failed_phase_names() == ["fuzzer"]
    assert any("[fuzzer] [failed]" in row for row in progress)
    assert events[-2:] == ["final", "done"]


def test_failed_binradar_trace_is_ignored_and_final_is_marked_degraded(
        tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-confidence] [patch 1] [score 1.0] "
        "[accept-evidences 1] [total-evidences 1]\n")
    executor = _policy_executor(tmp_path, less_strict=True)
    executor.disable_binradar = False
    executor.binradar_failed = True
    executor.phase_failures = {"binradar": "RuntimeError: tracer failed"}
    executor.filter_result = [1]
    executor.probe_result = SimpleNamespace(tracer_fault_addr=0xDEAD)
    progress = []
    executor.save_progress = progress.append

    # No binradar-tracer-msg.log exists. A failed BinRadar phase must not make
    # FINAL parse a partial/missing trace under --less-strict.
    executor.run_final()

    final = (tmp_path / "final.sbsv").read_text()
    assert "[binradar failed]" in final
    assert ("[final] [degraded] [prefix run] [id 0] "
            "[failed-phases binradar]") in final
    assert "[final] [binradar] [patch 1]" not in final
    assert "[degraded true] [failed-phases binradar]" in final
    assert "[remaining_patches [1]]" in final
    assert any("[degraded true]" in row for row in progress)


def test_afl_timeout_defaults_to_autoscaling_slow_seed_ceiling(tmp_path):
    env = {
        "BINARY": "target",
        "POC_INPUT": "poc/crash",
        "PATCH_LOC": "0x1000",
        "TEST_CMD": "@@",
    }
    fuzzer = binradar.binradar_fuzzer.AFLppFuzzer.from_env(
        str(tmp_path), str(tmp_path / "out"), env)
    command = fuzzer.get_aflpp_command("target.brpatched", "poc")
    assert command[command.index("-t") + 1] == "10000+"

    env["BINRADAR_AFL_EXEC_TIMEOUT"] = "20000+"
    fuzzer = binradar.binradar_fuzzer.AFLppFuzzer.from_env(
        str(tmp_path), str(tmp_path / "out-2"), env)
    command = fuzzer.get_aflpp_command("target.brpatched", "poc")
    assert command[command.index("-t") + 1] == "20000+"
