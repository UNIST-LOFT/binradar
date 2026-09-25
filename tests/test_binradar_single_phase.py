#!/usr/bin/env python3
"""Tests for --run-single-phase dispatch, including the combined
minimizer-verifier phase (minimizer + concrete verifier running concurrently
over already-produced testcases)."""

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_artifacts
import binradar_config
import binradar_verifier

_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None
assert _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)


def _probe(exit_info="ok", fault_addr=0x1234):
    return binradar_verifier.BinRadarProbeResult(
        patch_loc=0x1000, patch_func_entry=0x2000, stacktrace=[],
        exit_info=exit_info, patch_hit_cnt=1, patch_func_hit_cnt=1,
        fault_addr=fault_addr, patch_func_candidates=[],
        tracer_fault_reference=None)


def _patch_result():
    return binradar_verifier.BinRadarPatchResult(0, [0])


def _verifier_result(run_dir: Path):
    result = binradar_verifier.BinRadarConcreteVerifierResult.from_file(
        str(run_dir / "verifier.br"))
    assert result is not None
    return result


class StubQemuRunner:
    """Stands in for BinRadarQemuRunner inside probe/filter/minimizer/verifier."""

    patch_kind = ""
    brcache_stack_size = 0
    calls = []  # (patch_id, testcase path)

    def __init__(self, dir, binary, test_cmd, patch_loc):
        self.dir = dir
        self.binary = binary
        self.test_cmd = test_cmd
        self.patch_loc = patch_loc

    def test_with_patched(self, patch_id, testcase, verbose=False):
        StubQemuRunner.calls.append((patch_id, testcase))
        return _probe(), _patch_result()

    def test_with_cached(self, patch_id, predicate, testcase, verbose=False):
        raise AssertionError("cache runs are not expected in these tests")

    def original_binary(self):
        return os.path.join(self.dir, f"{self.binary}.orig")

    def patched_binary(self):
        return os.path.join(self.dir, f"{self.binary}.brpatched")

    def cached_binary(self):
        return os.path.join(self.dir, f"{self.binary}.brcached")


@pytest.fixture
def stub_runner_env(monkeypatch):
    StubQemuRunner.calls = []
    monkeypatch.setattr(
        binradar_verifier.BinRadarQemuRunner, "from_env",
        staticmethod(lambda dir, env: StubQemuRunner(dir, "nm", "-l @@", "0x1000")))


def _make_workdir(tmp_path):
    """Workdir with artifacts, POC, and a pre-populated run directory whose
    probe result already exists (the --run-id resume scenario)."""
    workdir = tmp_path / "workdir"
    rundir = workdir / "out" / "run-00000"
    rundir.mkdir(parents=True)
    (workdir / "nm.orig").write_bytes(b"\x7fELF")
    (workdir / "nm.brpatched").write_bytes(b"\x7fELF")
    poc = workdir / "poc" / "x"
    poc.parent.mkdir(exist_ok=True)
    poc.write_bytes(b"poc")
    # Probe results as run_probe() itself serializes them.
    (rundir / "probe-results.sbsv").write_text(
        "[probe-info] [version 2] [exit crash] [patch-loc 1000] "
        "[func-entry 2000] [patch-hit 1] [func-hit 1] [fault-addr 1234] "
        "[tracer-fault-valid false] [tracer-fault-source unavailable] "
        "[tracer-fault-addr 0] [patch-func-candidates []] [stacktrace []]\n"
        "[file-trace] [need-file-hook false]\n")
    # Already-produced testcases (as the fuzzolic producer phase would leave).
    testcases = rundir / "fuzzolic-tests"
    testcases.mkdir()
    (testcases / "tc_0.dat").write_bytes(b"aaa")
    (testcases / "tc_1.dat").write_bytes(b"bbb")
    return workdir, rundir


def _build_executor(workdir: Path) -> "binradar.BinRadarExecutor":
    run_config = binradar_config.RunConfig.from_environment(str(workdir), {
        "BINRADAR_OUTDIR": str(workdir / "out"),
        "BINRADAR_TIMEOUT": "60",
        "BINARY": "nm",
        "POC_INPUT": "poc/x",
        "TEST_CMD": "-l @@",
        "PATCH_LOC": "0x1000",
        "TOTAL_PATCHES": "2",
        "BRPATCHED_TOTAL_PATCHES": "2",
        "FILTER_TOTAL_PATCHES": "2",
        "BINRADAR_INVOCATION": "test",
        "BINRADAR_TARGET_PATCHES": "top-30",
        "BINRADAR_TARGET_PATCHES_STATUS": "top-30",
        "BINRADAR_TARGET_PATCHES_REASON": "requested top-30",
    })
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.run_config = run_config
    executor.workdir = run_config.workdir
    executor.outdir = run_config.outdir
    executor.timeout = run_config.timeout
    executor.binary = run_config.binary
    executor.poc_input = run_config.poc_input
    executor.test_cmd = run_config.test_cmd
    executor.patch_loc = run_config.patch_loc
    executor.total_patches = run_config.total_patches
    executor.brpatched_total_patches = run_config.brpatched_total_patches
    executor.filter_total_patches = run_config.filter_total_patches
    executor.fuzzy = run_config.fuzzy
    executor.reverse_directed = run_config.reverse_directed
    executor.disable_binradar = run_config.disable_binradar
    executor.less_strict = run_config.less_strict
    executor.feedback_mode = run_config.feedback_mode
    executor.symbolic_mutation_mode = run_config.symbolic_mutation_mode
    executor.symbolic_schedule = run_config.symbolic_schedule
    executor.mutation_portfolio = run_config.mutation_portfolio
    executor.representative_budget = run_config.representative_budget
    executor.symbolic_budgets = run_config.symbolic_budgets
    executor.forkserver_child_timeout = run_config.forkserver_child_timeout
    executor.invocation = run_config.invocation
    executor.requested_candidate_scope = run_config.requested_candidate_scope
    executor.candidate_scope_status = run_config.candidate_scope_status
    executor.candidate_scope_reason = run_config.candidate_scope_reason
    executor.config = binradar_config.build_base_environment(
        run_config, str(workdir / "out" / "plt_info.txt"))
    executor.artifacts = binradar_artifacts.ArtifactSet(
        str(workdir), "nm", "", 0, 2)
    executor.progress_filename = str(workdir / "out" / "progress.sbsv")
    executor.previous_progress = None
    executor.start_time = time.time()
    executor.probe_result = None
    executor.filter_result = [1, 2]
    executor.run_id = -1
    executor.run_prefix = ""
    executor.run_dir = ""
    return executor


def test_phase_name_mapping_accepts_dashed_names():
    assert binradar.phase_from_name("minimizer-verifier") \
        is binradar.BinRadarPhase.MINIMIZER_VERIFIER
    assert binradar.phase_from_name("minimizer") \
        is binradar.BinRadarPhase.MINIMIZER
    assert binradar.phase_from_name("verifier") is binradar.BinRadarPhase.VERIFIER
    # Every CLI choice must map to a phase.
    for name in binradar.SINGLE_PHASE_NAMES:
        binradar.phase_from_name(name)
    with pytest.raises(KeyError):
        binradar.phase_from_name("nonsense")


def test_single_phase_names_include_minimizer_verifier():
    assert "minimizer-verifier" in binradar.SINGLE_PHASE_NAMES
    assert "filter" not in binradar.SINGLE_PHASE_NAMES


def test_minimizer_verifier_timeout_is_one_and_a_half_times_configured():
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.timeout = 6 * 60 * 60
    assert executor.minimizer_verifier_timeout() == 9 * 60 * 60

    executor.timeout = 0
    assert executor.minimizer_verifier_timeout() is None


def test_historical_final_loads_legacy_probe_without_regeneration(tmp_path):
    workdir, rundir = _make_workdir(tmp_path)
    (rundir / "probe-results.sbsv").write_text(
        "[probe-info] [exit crash] [patch-loc 1000] [func-entry 2000] "
        "[patch-hit 1] [func-hit 1] [fault-addr 1234] "
        "[tracer-fault-addr dead] [patch-func-candidates []] "
        "[stacktrace []]\n[file-trace] [need-file-hook false]\n",
        encoding="utf-8",
    )
    executor = _build_executor(workdir)
    executor.save_progress = lambda _row: None
    executor.done = lambda: None
    observed = []
    executor.run_final = lambda: observed.append(
        executor.probe_result.tracer_fault_reference)

    executor.run_single_phase("run", "0", binradar.BinRadarPhase.FINAL)

    assert observed == [
        binradar_verifier.TracerFaultReference(0xDEAD, "legacy-unvalidated")
    ]


def test_run_single_phase_minimizer_verifier(tmp_path, stub_runner_env):
    workdir, rundir = _make_workdir(tmp_path)
    executor = _build_executor(workdir)

    executor.run_single_phase(
        "run", "0", binradar.BinRadarPhase.MINIMIZER_VERIFIER)

    # The minimizer ran in snapshot mode and completed.
    minimizer_log = (rundir / "minimizer.sbsv").read_text()
    assert "[minimizer] [done]" in minimizer_log
    assert "[testcase] [result]" in minimizer_log
    # The verifier streamed the rows concurrently and verified both patches.
    verifier_result = _verifier_result(rundir)
    assert verifier_result.patch_verified[1]
    assert verifier_result.patch_verified[2]
    # The minimizer's patch-0 runs and the verifier's per-candidate runs
    # all went through the patched binary.
    patch_ids = {patch_id for patch_id, _ in StubQemuRunner.calls}
    assert {"0", "1", "2"} <= patch_ids
    progress = (workdir / "out" / "progress.sbsv").read_text()
    assert "[minimizer] [start] [prefix run] [id 0]" in progress
    assert "[verifier] [start] [prefix run] [id 0]" in progress
    assert "[minimizer] [done] [prefix run] [id 0]" in progress
    assert "[verifier] [done] [prefix run] [id 0]" in progress
    assert "[rundir] [done] [prefix run] [id 0]" in progress


def test_run_single_phase_minimizer_then_verifier_replay(
        tmp_path, stub_runner_env):
    """The documented two-step workflow: a standalone minimizer phase, then a
    standalone verifier phase that replays the completed minimizer.sbsv."""
    workdir, rundir = _make_workdir(tmp_path)
    first = _build_executor(workdir)
    first.run_single_phase("run", "0", binradar.BinRadarPhase.MINIMIZER)

    minimizer_log = (rundir / "minimizer.sbsv").read_text()
    assert "[minimizer] [done]" in minimizer_log
    assert not (rundir / "verifier.br").exists()

    second = _build_executor(workdir)
    second.run_single_phase("run", "0", binradar.BinRadarPhase.VERIFIER)

    verifier_result = _verifier_result(rundir)
    assert verifier_result.patch_verified[1]
    assert verifier_result.patch_verified[2]
    progress = (workdir / "out" / "progress.sbsv").read_text()
    assert "[verifier] [done] [prefix run] [id 0]" in progress


def test_run_single_phase_minimizer_verifier_on_prior_full_run(
        tmp_path, stub_runner_env):
    """Re-running minimizer-verifier on a run directory that already holds a
    completed minimizer/verifier state starts fresh: minimizer.sbsv and
    verifier.br are replaced from the producer testcases."""
    workdir, rundir = _make_workdir(tmp_path)
    executor = _build_executor(workdir)
    executor.run_single_phase(
        "run", "0", binradar.BinRadarPhase.MINIMIZER_VERIFIER)

    stale_verifier = (rundir / "verifier.br").read_bytes()
    assert stale_verifier  # first combined run produced compact verdicts

    # Mark the stale artifacts and re-run on the same run id: the minimizer
    # must truncate minimizer.sbsv and regenerate everything.
    (rundir / "minimizer.sbsv").write_text("[stale] [row]\n")
    (rundir / "verifier.br").write_bytes(b"stale")
    rerun = _build_executor(workdir)
    rerun.run_single_phase(
        "run", "0", binradar.BinRadarPhase.MINIMIZER_VERIFIER)

    assert "[stale] [row]" not in (rundir / "minimizer.sbsv").read_text()
    assert "[minimizer] [done]" in (rundir / "minimizer.sbsv").read_text()
    assert _verifier_result(rundir).patch_verified[1]
