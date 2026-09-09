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
        fault_addr=fault_addr, patch_func_candidates=[], tracer_fault_addr=0)


def _patch_result():
    return binradar_verifier.BinRadarPatchResult(0, [0])


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
    """Workdir with artifacts, poc, and a pre-populated run directory whose
    probe/filter results already exist (the --run-id resume scenario: the
    probe and filter phases only load their saved results)."""
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
        "[probe-info] [exit crash] [patch-loc 1000] [func-entry 2000] "
        "[patch-hit 1] [func-hit 1] [fault-addr 1234] [tracer-fault-addr 1234] "
        "[patch-func-candidates []] [stacktrace []]\n"
        "[file-trace] [need-file-hook false]\n")
    (rundir / "filter.sbsv").write_text(
        "[patch] [id 1] [pass true]\n"
        "[patch] [id 2] [pass true]\n")
    # Already-produced testcases (as the fuzzolic producer phase would leave).
    testcases = rundir / "fuzzolic-tests"
    testcases.mkdir()
    (testcases / "tc_0.dat").write_bytes(b"aaa")
    (testcases / "tc_1.dat").write_bytes(b"bbb")
    return workdir, rundir


def _build_executor(workdir: Path) -> "binradar.BinRadarExecutor":
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.workdir = str(workdir)
    executor.outdir = str(workdir / "out")
    executor.timeout = 60
    executor.binary = "nm"
    executor.poc_input = "poc/x"
    executor.test_cmd = "-l @@"
    executor.patch_loc = "0x1000"
    executor.e9_metadata_prefix = "brpatched"
    executor.e9_exclude_ranges = ""
    executor.e9_relocated_calls = ""
    executor.total_patches = 2
    executor.fuzzy = False
    executor.reverse_directed = False
    executor.disable_binradar = False
    executor.config = {}
    executor.progress_filename = str(workdir / "out" / "progress.sbsv")
    executor.previous_progress = None
    executor.start_time = time.time()
    executor.probe_result = None
    executor.filter_result = []
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


def test_minimizer_verifier_timeout_is_one_and_a_half_times_configured():
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.timeout = 6 * 60 * 60
    assert executor.minimizer_verifier_timeout() == 9 * 60 * 60

    executor.timeout = 0
    assert executor.minimizer_verifier_timeout() is None


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
    verifier_log = (rundir / "verifier.sbsv").read_text()
    assert "[verifier-result] [res verified] [patch 1]" in verifier_log
    assert "[verifier-result] [res verified] [patch 2]" in verifier_log
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
    assert not (rundir / "verifier.sbsv").exists()

    second = _build_executor(workdir)
    second.run_single_phase("run", "0", binradar.BinRadarPhase.VERIFIER)

    verifier_log = (rundir / "verifier.sbsv").read_text()
    assert "[verifier-result] [res verified] [patch 1]" in verifier_log
    assert "[verifier-result] [res verified] [patch 2]" in verifier_log
    progress = (workdir / "out" / "progress.sbsv").read_text()
    assert "[verifier] [done] [prefix run] [id 0]" in progress


def test_run_single_phase_minimizer_verifier_on_prior_full_run(
        tmp_path, stub_runner_env):
    """Re-running minimizer-verifier on a run directory that already holds a
    completed minimizer/verifier state starts fresh: minimizer.sbsv and
    verifier.sbsv are truncated and re-produced from the producer testcases."""
    workdir, rundir = _make_workdir(tmp_path)
    executor = _build_executor(workdir)
    executor.run_single_phase(
        "run", "0", binradar.BinRadarPhase.MINIMIZER_VERIFIER)

    stale_verifier_text = (rundir / "verifier.sbsv").read_text()
    assert stale_verifier_text  # first combined run produced verdict rows

    # Mark the stale artifacts and re-run on the same run id: the minimizer
    # must truncate minimizer.sbsv and regenerate everything.
    (rundir / "minimizer.sbsv").write_text("[stale] [row]\n")
    rerun = _build_executor(workdir)
    rerun.run_single_phase(
        "run", "0", binradar.BinRadarPhase.MINIMIZER_VERIFIER)

    assert "[stale] [row]" not in (rundir / "minimizer.sbsv").read_text()
    assert "[minimizer] [done]" in (rundir / "minimizer.sbsv").read_text()
    assert "[verifier-result] [res verified] [patch 1]" in \
        (rundir / "verifier.sbsv").read_text()
