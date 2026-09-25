#!/usr/bin/env python3
"""Tests for disabling the optional BinRadar phase."""

import importlib.util
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import binradar_config

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None
assert _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)
import binradar_artifacts  # noqa: E402  (same fuzzolic module path)
import binradar_utils  # noqa: E402  (same fuzzolic module path)


def _stub_executor(tmp_path):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.run_dir = str(tmp_path)
    executor.run_prefix = "run"
    executor.run_id = 0
    executor.progress_filename = str(tmp_path / "progress.sbsv")
    executor.start_time = __import__("time").time()
    executor.probe_result = SimpleNamespace()
    executor.filter_result = [1, 2]
    executor.brpatched_total_patches = 2
    executor.filter_total_patches = 2
    executor.total_patches = 2
    executor.workdir = str(tmp_path)
    executor.outdir = str(tmp_path)
    executor.timeout = 60
    executor.disable_binradar = True
    executor.feedback_mode = False
    executor.invocation = "test"
    executor.requested_candidate_scope = "top-30"
    executor.candidate_scope_status = "top-30"
    executor.candidate_scope_reason = "requested top-30"
    executor.symbolic_mutation_mode = "off"
    executor.symbolic_schedule = "existing"
    executor.symbolic_budgets = binradar_config.SymbolicBudgets(
        max_work=binradar_config.SYMBOLIC_MAX_WORK_DEFAULT,
        max_bytes=binradar_config.SYMBOLIC_MAX_BYTES_DEFAULT,
        deadline_ms=binradar_config.SYMBOLIC_DEADLINE_MS_DEFAULT)
    executor.fuzzy = False
    executor.reverse_directed = False
    executor.less_strict = False
    executor.forkserver_child_timeout = 900
    executor.binradar_failed = False
    executor.wall_time_reached = False
    executor.phase_failures = {}
    executor.phase_failure_lock = threading.Lock()
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


def test_final_records_graceful_wall_time_reached_without_issues(tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        f"[verifier] [stopped] [reason {binradar_utils.WALL_TIME_REACHED}]\n"
        "[verifier-result] [res rejected] [patch 1] [testcase crash]\n"
        "[verifier-confidence] [patch 1] [score 0.0] "
        "[accept-evidences 0] [total-evidences 1]\n"
        "[verifier-result] [res verified] [patch 2] [testcase ]\n"
        "[verifier-confidence] [patch 2] [score 0.5] "
        "[accept-evidences 1] [total-evidences 2]\n"
    )
    executor = _stub_executor(tmp_path)
    progress = []
    executor.save_progress = progress.append

    executor.run_final()

    final_text = (tmp_path / "final.sbsv").read_text()
    assert "[final] [verifier] [patch 1] [res rejected]" in final_text
    assert "[final] [verifier] [patch 2] [res verified]" in final_text
    assert "[final] [confidence] [patch 2] [score 0.500000]" in final_text
    # A reached wall-clock budget is a planned graceful cutoff: it is
    # recorded under its own name and never reported as failed phases.
    assert "[final] [wall-time-reached] [prefix run] [id 0]" in final_text
    assert "[final] [failed-phases]" not in final_text
    assert "[issues false] [failed-phases none]" in final_text
    assert "[wall-time-reached true]" in final_text
    assert any("[wall-time-reached true]" in row for row in progress
               if row.startswith("[final] [done]"))


def test_final_rejects_incomplete_verifier_patch_coverage(tmp_path):
    """A missing verdict must not silently default to patch acceptance."""
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res rejected] [patch 1] [testcase crash]\n"
    )
    executor = _stub_executor(tmp_path)
    executor.save_progress = lambda row: None

    with pytest.raises(ValueError, match=r"missing patches \[2\]"):
        executor.run_final()

    assert not (tmp_path / "final.sbsv").exists()


def test_final_rejects_duplicate_verifier_verdicts(tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res rejected] [patch 1] [testcase crash]\n"
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-result] [res verified] [patch 2] [testcase ]\n"
    )
    executor = _stub_executor(tmp_path)
    executor.save_progress = lambda row: None

    with pytest.raises(ValueError, match=r"duplicate patches \[1\]"):
        executor.run_final()

    assert not (tmp_path / "final.sbsv").exists()


def test_concrete_verifier_result_parses_confidence_evidence(tmp_path):
    result_file = tmp_path / "verifier.sbsv"
    result_file.write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-confidence] [patch 1] [score 0.123] "
        "[accept-evidences 2] [total-evidences 3]\n"
    )

    result = binradar.binradar_verifier.BinRadarConcreteVerifierResult.from_sbsv(
        str(result_file))

    assert result is not None
    assert result.patch_verified == {1: True}
    # The parser recomputes the score from evidence rather than trusting the
    # rounded/incorrect serialized value.
    assert result.patch_confidence == {1: 2 / 3}
    assert result.accept_evidences == {1: 2}
    assert result.total_evidences == {1: 3}


def test_concrete_verifier_branch_difference_lowers_confidence_without_rejecting(
        tmp_path):
    class FakeRunner:
        patch_kind = ""
        brcache_stack_size = 0

        def cached_binary(self):
            return str(tmp_path / "missing.brcached")

    verifier = binradar.binradar_verifier.BinRadarConcreteVerifier(
        str(tmp_path), str(tmp_path), FakeRunner(),
        SimpleNamespace(fault_addr=0xDEAD),
        str(tmp_path / "binary.brpatched"), [1])
    testcase = binradar.binradar_verifier.Testcase(
        0, "input", "ok", 0, [0])

    def execution(exit_kind, fault_addr=0):
        return SimpleNamespace(
            fault_addr=fault_addr,
            is_crash=lambda: exit_kind == "crash",
            is_normal_exit=lambda: exit_kind == "ok",
            is_timeout=lambda: exit_kind == "timeout",
        )

    # A behavioral difference is negative evidence, not a rejection.
    assert not verifier._test_result(
        1, testcase, execution("ok"),
        binradar.binradar_verifier.BinRadarPatchResult(1, [1]))
    assert verifier.confidence(1) == 0.0

    # A matching behavior adds accept evidence.
    assert not verifier._test_result(
        1, testcase, execution("ok"),
        binradar.binradar_verifier.BinRadarPatchResult(1, [0]))
    assert verifier.confidence(1) == 0.5

    # A new crash at an unrelated address is ignored. A crash at the POC's
    # fault address remains a hard rejection and negative evidence.
    assert not verifier._test_result(
        1, testcase, execution("crash", 0xBEEF),
        binradar.binradar_verifier.BinRadarPatchResult(1, [0]))
    assert verifier.total_evidences[1] == 2
    assert verifier._test_result(
        1, testcase, execution("crash", 0xDEAD),
        binradar.binradar_verifier.BinRadarPatchResult(1, [0]))
    assert verifier.accept_evidences[1] == 1
    assert verifier.total_evidences[1] == 3


def test_final_branch_difference_reduces_confidence_but_same_crash_rejects(
        tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-confidence] [patch 1] [score 1.0] "
        "[accept-evidences 1] [total-evidences 1]\n"
        "[verifier-result] [res verified] [patch 2] [testcase ]\n"
        "[verifier-confidence] [patch 2] [score 1.0] "
        "[accept-evidences 1] [total-evidences 1]\n"
    )
    (tmp_path / "binradar-tracer-msg.log").write_text(
        # Iteration 1: patch 1 differs; patch 2 matches.
        "[binradar] [normal] [iter 1] [patch 0]\n"
        "[binradar] [commit] [iter 1] [patch 0] [br 0]\n"
        "[binradar] [normal] [iter 1] [patch 1]\n"
        "[binradar] [commit] [iter 1] [patch 1] [br 1]\n"
        "[binradar] [normal] [iter 1] [patch 2]\n"
        "[binradar] [commit] [iter 1] [patch 2] [br 0]\n"
        # Iteration 2: patch 1 fixes the crash; patch 2 retains it.
        "[binradar] [crash] [iter 2] [patch 0] [guest_pc 0] "
        "[guest_cs_base 0] [fault_addr dead] [host_fault_addr 0]\n"
        "[binradar] [commit] [iter 2] [patch 0] [br 0]\n"
        "[binradar] [normal] [iter 2] [patch 1]\n"
        "[binradar] [commit] [iter 2] [patch 1] [br 1]\n"
        "[binradar] [crash] [iter 2] [patch 2] [guest_pc 0] "
        "[guest_cs_base 0] [fault_addr dead] [host_fault_addr 0]\n"
        "[binradar] [commit] [iter 2] [patch 2] [br 0]\n"
    )
    executor = _stub_executor(tmp_path)
    executor.disable_binradar = False
    executor.probe_result = SimpleNamespace(
        tracer_fault_reference=binradar.binradar_verifier.TracerFaultReference(
            0xDEAD, "guest-signal"))
    executor.save_progress = lambda row: None

    executor.run_final()

    final_text = (tmp_path / "final.sbsv").read_text()
    assert ("[final] [binradar] [patch 1] [res verified] "
            "[reason none] [iter -1]") in final_text
    assert ("[final] [binradar] [patch 2] [res rejected] "
            "[reason same-crash] [iter 2]") in final_text
    assert ("[final] [confidence] [patch 1] [score 0.666667] "
            "[accept-evidences 2] [total-evidences 3]") in final_text
    assert ("[final] [confidence] [patch 2] [score 0.666667] "
            "[accept-evidences 2] [total-evidences 3]") in final_text
    assert "[binradar_remaining_patches [1]]" in final_text


def test_final_ignores_interrupted_iteration_without_baseline(tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-confidence] [patch 1] [score 1.0] "
        "[accept-evidences 1] [total-evidences 1]\n"
        "[verifier-result] [res verified] [patch 2] [testcase ]\n"
        "[verifier-confidence] [patch 2] [score 1.0] "
        "[accept-evidences 1] [total-evidences 1]\n"
    )
    (tmp_path / "binradar-tracer-msg.log").write_text(
        # Complete iteration: both candidates match the baseline.
        "[binradar] [normal] [iter 1] [patch 0]\n"
        "[binradar] [commit] [iter 1] [patch 0] [br 0]\n"
        "[binradar] [normal] [iter 1] [patch 1]\n"
        "[binradar] [commit] [iter 1] [patch 1] [br 0]\n"
        "[binradar] [normal] [iter 1] [patch 2]\n"
        "[binradar] [commit] [iter 1] [patch 2] [br 0]\n"
        # The forkserver was stopped mid-iteration. Patch 0 timed out without
        # a result, while a later candidate emitted a termination crash.
        "[binradar] [crash] [iter 2] [patch 2] [guest_pc dead] "
        "[guest_cs_base 0] [fault_addr dead] [host_fault_addr 0]\n"
    )
    executor = _stub_executor(tmp_path)
    executor.disable_binradar = False
    executor.probe_result = SimpleNamespace(
        tracer_fault_reference=binradar.binradar_verifier.TracerFaultReference(
            0xDEAD, "guest-signal"))
    executor.save_progress = lambda row: None

    executor.run_final()

    final_text = (tmp_path / "final.sbsv").read_text()
    assert ("[final] [confidence] [patch 1] [score 1.000000] "
            "[accept-evidences 2] [total-evidences 2]") in final_text
    assert ("[final] [confidence] [patch 2] [score 1.000000] "
            "[accept-evidences 2] [total-evidences 2]") in final_text
    assert "[binradar_remaining_patches [1, 2]]" in final_text


def test_final_confidence_rows_sorted_and_only_accepted_patches(tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-confidence] [patch 1] [score 0.5] "
        "[accept-evidences 1] [total-evidences 2]\n"
        "[verifier-result] [res verified] [patch 2] [testcase ]\n"
        "[verifier-confidence] [patch 2] [score 1.0] "
        "[accept-evidences 2] [total-evidences 2]\n"
        "[verifier-result] [res rejected] [patch 3] [testcase t]\n"
        "[verifier-confidence] [patch 3] [score 0.0] "
        "[accept-evidences 0] [total-evidences 1]\n"
        "[verifier-result] [res verified] [patch 4] [testcase ]\n"
        "[verifier-confidence] [patch 4] [score 0.75] "
        "[accept-evidences 3] [total-evidences 4]\n"
        "[verifier-result] [res verified] [patch 5] [testcase ]\n"
        "[verifier-confidence] [patch 5] [score 0.75] "
        "[accept-evidences 3] [total-evidences 4]\n"
    )
    executor = _stub_executor(tmp_path)
    executor.filter_result = [1, 2, 3, 4, 5]
    executor.save_progress = lambda row: None

    executor.run_final()

    final_text = (tmp_path / "final.sbsv").read_text()
    confidence_rows = [
        line for line in final_text.splitlines()
        if "[final] [confidence]" in line
    ]
    # Rejected patch 3 is not listed; the rest are ranked by score (highest
    # first) with ties keeping the original patch-id order.
    assert len(confidence_rows) == 4
    assert "[patch 2]" in confidence_rows[0]
    assert "[patch 4]" in confidence_rows[1]
    assert "[patch 5]" in confidence_rows[2]
    assert "[patch 1]" in confidence_rows[3]
    assert all("[patch 3]" not in row for row in confidence_rows)


def test_verifier_binary_uses_cached_artifact_for_multiple_patches(tmp_path):
    artifacts = binradar_artifacts.ArtifactSet(
        str(tmp_path), "imginfo", "generic-erm", 0, 2)
    (tmp_path / "imginfo.brpatched").write_bytes(b"patched")
    (tmp_path / "imginfo.brcached").write_bytes(b"cached")

    assert artifacts.select_verifier([1, 2]).path == str(
        tmp_path / "imginfo.brcached")
    assert artifacts.select_verifier([1]).path == str(
        tmp_path / "imginfo.brpatched")

    (tmp_path / "imginfo.brcached").unlink()
    assert artifacts.select_verifier([1, 2]).path == str(
        tmp_path / "imginfo.brpatched")


def test_binradar_binary_requires_valid_manifest_and_active_ids(tmp_path):
    artifacts = binradar_artifacts.ArtifactSet(
        str(tmp_path), "imginfo", "generic-erm", 0, 2)
    (tmp_path / "imginfo.brpatched").write_bytes(b"patched")
    (tmp_path / "imginfo.brcached").write_bytes(b"cached")

    _write_generic_manifest(tmp_path, ["=p0p0", "=p1p0"])
    assert artifacts.select_tracer([1, 2]).path == str(
        tmp_path / "imginfo.brcached")
    with pytest.raises(binradar_artifacts.ArtifactUnavailableError):
        artifacts.select_tracer([1, 3])

    wrong_family = binradar_artifacts.ArtifactSet(
        str(tmp_path), "imginfo", "CWE805-erm", 0, 2)
    assert wrong_family.select_tracer([1, 2]).path == str(
        tmp_path / "imginfo.brpatched")


def _write_generic_manifest(workdir, descriptors):
    (workdir / "brpatches.json").write_text(json.dumps({
        "version": 1,
        "kind": "generic-erm",
        "predicates": [
            {"id": idx, "source_line": idx, "descriptor": descriptor}
            for idx, descriptor in enumerate(descriptors, start=1)
        ],
    }))











def test_disabled_binradar_is_not_started_by_multithreaded_orchestration(
        tmp_path, monkeypatch):
    executor = _stub_executor(tmp_path)
    events = []
    monkeypatch.setattr(binradar.logger, "set_file", lambda _: None)
    executor.set_run_dir = lambda run_prefix="run": events.append(
        ("set", run_prefix))
    executor.run_probe = lambda: events.append(("probe",))
    executor.run_fuzzolic = lambda: events.append(("fuzzolic",))
    executor.run_directed = lambda: events.append(("directed",))
    executor.run_fuzzer = lambda: events.append(("fuzzer",))
    def _run_minimizer_and_verifier(producer_threads=None,
                                    producer_exc_queue=None):
        events.append(("min-ver",))

    executor.run_minimizer_and_verifier = _run_minimizer_and_verifier
    executor.run_final = lambda: events.append(("final",))
    executor.done = lambda: events.append(("done",))

    executor.run_multithreaded()

    assert ("binradar",) not in events
    assert ("final",) in events
    assert events[-1] == ("done",)
