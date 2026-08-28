#!/usr/bin/env python3
"""Tests for disabling the optional BinRadar phase."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None
assert _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)


def _stub_executor(tmp_path):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.run_dir = str(tmp_path)
    executor.run_prefix = "run"
    executor.run_id = 0
    executor.progress_filename = str(tmp_path / "progress.sbsv")
    executor.start_time = __import__("time").time()
    executor.probe_result = SimpleNamespace()
    executor.filter_result = [1, 2]
    executor.disable_binradar = True
    return executor


def test_disabled_binradar_skips_execution(tmp_path):
    executor = _stub_executor(tmp_path)
    executor.check_requirements = lambda: (_ for _ in ()).throw(
        AssertionError("disabled BinRadar must not check execution requirements"))

    executor.run_binradar()

    assert not (tmp_path / "binradar-tracer-msg.log").exists()


def test_disabled_binradar_final_uses_concrete_result_without_trace(tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-result] [res rejected] [patch 2] [testcase testcase]\n"
    )
    executor = _stub_executor(tmp_path)
    progress = []
    executor.save_progress = progress.append

    executor.run_final()

    final_text = (tmp_path / "final.sbsv").read_text()
    assert "[final] [verifier] [patch 1] [res verified]" in final_text
    assert "[final] [verifier] [patch 2] [res rejected]" in final_text
    assert "[final] [binradar]" not in final_text
    assert "[remaining_patches [1]]" in final_text
    assert "[binradar_remaining_patches [1]]" in final_text
    assert "binradar-tracer-msg.log" not in final_text
    assert any(row.startswith("[final] [done]") for row in progress)


def test_disabled_binradar_is_not_started_by_multithreaded_orchestration(
        tmp_path, monkeypatch):
    executor = _stub_executor(tmp_path)
    events = []
    monkeypatch.setattr(binradar.logger, "set_file", lambda _: None)
    executor.set_run_dir = lambda run_prefix="run": events.append(
        ("set", run_prefix))
    executor.run_probe = lambda: events.append(("probe",))
    executor.run_filter = lambda: (events.append(("filter",)) or [1])
    executor.run_fuzzolic = lambda: events.append(("fuzzolic",))
    executor.run_directed = lambda: events.append(("directed",))
    executor.run_fuzzer = lambda: events.append(("fuzzer",))
    executor.run_minimizer_and_verifier = lambda: events.append(("min-ver",))
    executor.run_final = lambda: events.append(("final",))
    executor.done = lambda: events.append(("done",))

    executor.run_multithreaded()

    assert ("binradar",) not in events
    assert ("final",) in events
    assert events[-1] == ("done",)
