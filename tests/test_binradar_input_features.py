"""Baseline feature transport tests use real pipes, child processes and SysV SHM."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import sys
from dataclasses import FrozenInstanceError

import pytest


from fuzzolic import binradar_input_features as features
from fuzzolic import binradar_utils
from fuzzolic import binradar_verifier as verifier
from fuzzolic.binradar_taosc_predicates import (
    CACHED_SNAPSHOT_HEADER as HEADER, CACHED_SNAPSHOT_MAGIC as MAGIC,
    CACHED_SNAPSHOT_REGS as REGS, CACHED_SNAPSHOT_CLAMPS as CLAMPS,
)


def _record(*, flags=0, branch=0, patch_id=0, stack=b""):
    return (HEADER.pack(MAGIC, 1, patch_id, branch, len(stack), flags)
            + (CLAMPS.pack(*([0] * 512)) if flags & 2 else b"")
            + REGS.pack(*range(16)) + stack)


@pytest.fixture
def runner(tmp_path, monkeypatch):
    original = bytearray(64)
    original[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<Q", original, 32, 64)
    struct.pack_into("<HH", original, 54, 56, 1)
    original += struct.pack("<IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, 0, 0x3000, 0x1000)
    (tmp_path / "target.orig").write_bytes(original)
    for suffix in ("brpatched", "brcached"):
        artifact = tmp_path / ("target." + suffix)
        artifact.write_bytes(suffix.encode())
        Path(str(artifact) + ".e9map.json").write_text(json.dumps({
            "version": 1, "artifact-sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "original-sha256": hashlib.sha256(original).hexdigest(),
            "instructions": [{"relocated": 0x9000, "original": 0x1000}],
        }))
    (tmp_path / "brpatches.json").write_text(json.dumps({
        "version": 1, "kind": "generic-erm", "predicates": [
            {"id": 1, "source_line": 1, "descriptor": "p0"},
            {"id": 2, "source_line": 2, "descriptor": "p1"}],
    }))
    qemu = tmp_path / "qemu"
    qemu.write_bytes(b"qemu-build-identity")
    monkeypatch.setattr(verifier, "QEMU_STACKTRACE_RELEASE", str(qemu))
    return verifier.BinRadarQemuRunner(
        str(tmp_path), "target", "@@", "1000",
        {suffix: ("0x9000-0xa000", []) for suffix in ("brpatched", "brcached")},
        patch_kind="generic-erm")


def _child(runner, monkeypatch, *, capture=None, slot=42, crash=False, cancel=False, hits=1):
    """A real producer using the runner's actual fd/environment contract."""
    if capture is None:
        capture = _record()
    outcome = "crash" if crash else "ok"
    kind = "crash" if crash else "end"
    log = ("[patch-info] [set true] [location 1000]\n"
           f"[patch-cov] [location 1000] [covered true] [hits {hits}]\n"
           f"[exit] [result {outcome}]\n[qemu-exit] [kind {kind}] [detail test]\n"
           + ("[fault-addr] [idx 0] [addr 9000] [symbol relocated]\n" if crash else ""))
    script = f'''
import ctypes, os, signal, sys
assert os.environ.get('AFL_INST_RATIO') == {os.environ.get('AFL_INST_RATIO')!r}
assert os.environ.get('AFL_INST_LIBS') == {os.environ.get('AFL_INST_LIBS')!r}
libc = ctypes.CDLL(None)
libc.shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
libc.shmat.restype = ctypes.c_void_p
if '__AFL_SHM_ID' in os.environ:
    address = libc.shmat(int(os.environ["__AFL_SHM_ID"]), None, 0)
    assert address != ctypes.c_void_p(-1).value
    if {slot!r} is not None:
        ctypes.c_ubyte.from_address(address + {slot or 0}).value = 7
with open({str(Path(runner.dir) / 'executions')!r}, 'a') as stream:
    stream.write('one\\n')
for _ in range({hits!r}):
    os.write(int(os.environ['PATCH_FD']), ('[patch] [id %s] [br 0] [v 1]\\n' % os.environ['PATCH_ID']).encode())
if 'PATCH_CACHED_FD' in os.environ:
    assert os.environ['TAOSC_PRED'] == 'p0'
    os.write(int(os.environ['PATCH_CACHED_FD']), {capture!r})
sys.stderr.write({log!r})
sys.stderr.flush()
if {cancel!r}:
    os.kill(os.getpid(), signal.SIGTERM)
'''
    monkeypatch.setattr(runner, "get_qemu_stacktrace_command_for_binary",
                        lambda binary, testcase: [sys.executable, "-c", script])


def test_single_execution_complete_capture_and_exact_fault_identity(runner, monkeypatch):
    _child(runner, monkeypatch, crash=True)
    with features.BaselineFeatureCollector(runner, [2, 1]) as collector:
        result = collector.run("input")
        assert list(collector.predicates) == [1, 2]
        assert collector.binary.endswith(".brcached")
        assert result.patch_reason == result.coverage_reason == "none"
        assert result.probe.concrete_fault_addr == 0x1000
        assert result.probe.raw_fault_addr == 0x9000
        assert result.probe.concrete_fault_source == "relocated"
        assert result.patch.br_selection == [0]
        assert result.snapshots[0].registers == tuple(range(16))
        assert result.coverage[42] == 7
        assert len(result.coverage) == 65536
        assert runner.run_results.success
    assert (Path(runner.dir) / "executions").read_text() == "one\n"


@pytest.mark.parametrize("capture,reason", [
    (b"broken", "partial-cached-snapshot-header"),
    (_record(flags=1), "cached-snapshot-capture-truncated"),
    (_record(flags=4), "cached-runtime-rejected-the-selected-predicate"),
    (_record(flags=8), "unknown-cached-snapshot-flags-0x8"),
    (_record(branch=1), "brch-text-mismatch"),
    (_record(patch_id=1), "nonneutral-brch"),
    (_record(flags=2), "brch-family-mismatch"),
    (b"", "brch-hit-mismatch"),
    (_record()[:-1], "partial-cached-state-payload"),
])
def test_optional_invalid_brch_preserves_valid_baseline(runner, monkeypatch, capture, reason):
    _child(runner, monkeypatch, capture=capture)
    with features.BaselineFeatureCollector(runner, [1]) as collector:
        result = collector.run("input")
    assert result.probe.is_normal_exit()
    assert result.patch.br_selection == [0]
    assert result.snapshots is None
    assert result.patch_reason == reason
    assert result.coverage_reason == "none"
    assert (Path(runner.dir) / "executions").read_text() == "one\n"


def test_fallback_uses_patched_once_and_records_effective_settings(runner, monkeypatch):
    runner.patch_kind = "CWE805-direct"
    monkeypatch.setenv("AFL_INST_RATIO", "30")
    monkeypatch.setenv("__AFL_SHM_ID", "borrowed-must-not-be-used")
    _child(runner, monkeypatch)
    with features.BaselineFeatureCollector(runner, [1]) as collector:
        result = collector.run("input")
        assert collector.binary.endswith(".brpatched")
        assert not collector.predicates
        assert collector.descriptor_digest == "none"
        settings = json.loads(collector.metadata["coverage_settings"])
        assert settings["AFL_INST_RATIO"] == "30"
        assert settings["AFL_QEMU_INST_RANGES"] == "0x9000-0xa000"
        assert collector.metadata["artifact_sha256"] == hashlib.sha256(b"brpatched").hexdigest()
        assert result.patch_reason != "none"
        assert result.coverage_reason == "none"
    assert os.environ["__AFL_SHM_ID"] == "borrowed-must-not-be-used"


def test_cancellation_never_promotes_salvaged_normal_or_fault(runner, monkeypatch):
    for crash in (False, True):
        _child(runner, monkeypatch, crash=crash, cancel=True)
        with features.BaselineFeatureCollector(runner, [1]) as collector:
            result = collector.run("input")
        assert runner.run_results.exit_code == -signal.SIGTERM
        assert result.probe is result.patch is result.snapshots is result.coverage is None
        assert result.patch_reason == result.coverage_reason == "cancelled"


def test_maps_private_reused_cleared_and_results_not_aliased(runner, monkeypatch):
    _child(runner, monkeypatch)
    with features.BaselineFeatureCollector(runner, [1]) as first:
        with features.BaselineFeatureCollector(runner, [1]) as second:
            assert first._map.ident != second._map.ident
            old = first.run("input")
            other = second.run("input")
            assert old.coverage is not other.coverage
        ident = first._map.ident
        libc = first._map.libc
        snapshots = old.snapshots
        snapshots.clear()
        assert len(old.snapshots) == 1
        with pytest.raises(FrozenInstanceError):
            old.coverage_reason = "changed"
        _child(runner, monkeypatch, slot=17)
        new = first.run("input")
        assert new.coverage[42] == 0 and new.coverage[17] == 7
        assert old.coverage[42] == 7 and old.coverage[17] == 0
    assert libc.shmat(ident, None, 0) == ctypes.c_void_p(-1).value


def test_empty_map_and_unreached_site_are_explicit(runner, monkeypatch):
    _child(runner, monkeypatch, slot=None, hits=0, capture=b"")
    with features.BaselineFeatureCollector(runner, [1]) as collector:
        result = collector.run("input")
    assert result.probe.patch_hit_cnt == 0
    assert result.patch.br_selection == []
    assert result.snapshots == [] and result.patch_reason == "none"
    assert result.coverage is None and result.coverage_reason == "empty-map"


def test_required_map_corruption_is_fatal_not_fallback(runner):
    Path(runner.cached_binary() + ".e9map.json").write_text("{}")
    with pytest.raises(ValueError, match="rerun binradar-setup"):
        features.BaselineFeatureCollector(runner, [1])
    assert not (Path(runner.dir) / "executions").exists()


def test_missing_candidate_resolves_capability_once(runner, monkeypatch):
    _child(runner, monkeypatch)
    with features.BaselineFeatureCollector(runner, [3]) as collector:
        assert collector.binary.endswith(".brpatched")
        assert collector.patch_reason.startswith("missing-runtime-patch-ids")
        (Path(runner.dir) / "brpatches.json").unlink()
        result = collector.run("input")
        assert result.coverage_reason == "none"


def test_launch_failure_closes_fds_and_context_removes_map(runner, monkeypatch):
    monkeypatch.setattr(runner, "get_qemu_stacktrace_command_for_binary",
                        lambda binary, testcase: ["/does/not/exist"])
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(FileNotFoundError):
        with features.BaselineFeatureCollector(runner, [1]) as collector:
            ident, libc = collector._map.ident, collector._map.libc
            collector.run("input")
    assert set(os.listdir("/proc/self/fd")) == before
    assert libc.shmat(ident, None, 0) == ctypes.c_void_p(-1).value
    assert runner.run_results is None


def test_shm_allocation_failure_is_operational(runner, monkeypatch):
    def failure():
        raise OSError(28, "cannot allocate baseline AFL SHM")
    monkeypatch.setattr(features, "_CoverageMap", failure)
    with pytest.raises(OSError, match="baseline AFL SHM"):
        with features.BaselineFeatureCollector(runner, [1]):
            pytest.fail("allocation failure must prevent execution")


@pytest.mark.parametrize("success,timed_out,exit_code,reason", [
    (False, True, -9, "timeout"),
    (False, False, 1, "execution-failed"),
    (True, False, -signal.SIGKILL, "cancelled"),
])
def test_partial_maps_are_not_complete_on_failed_execution(
        runner, monkeypatch, success, timed_out, exit_code, reason):
    def failed(*args, **kwargs):
        runner.run_results = binradar_utils.ExecutionResult(
            success, exit_code, "", "", timed_out=timed_out)
        return None, None, None
    monkeypatch.setattr(runner, "_test_with_capture", failed)
    with features.BaselineFeatureCollector(runner, [1]) as collector:
        ctypes.c_ubyte.from_address(collector._map.address + 10).value = 3
        result = collector.run("input")
    assert result.probe is None and result.coverage is None
    assert result.patch_reason == result.coverage_reason == reason


@pytest.mark.parametrize("stack,reason", [(b"12345678", "none"),
                                          (b"1234", "brch-stack-mismatch")])
def test_cwe805_neutral_capture_requires_family_and_exact_stack(
        runner, monkeypatch, stack, reason):
    runner.patch_kind = "CWE805-erm"
    runner.brcache_stack_size = 8
    (Path(runner.dir) / "brpatches.json").write_text(json.dumps({
        "version": 1, "kind": "CWE805-erm", "predicates": [
            {"id": 1, "source_line": 1, "descriptor": "c1s64i0"}],
    }))
    _child(runner, monkeypatch, capture=_record(flags=2, stack=stack))
    with features.BaselineFeatureCollector(runner, [1]) as collector:
        result = collector.run("input")
    assert result.patch_reason == reason
    assert (result.snapshots is not None) == (reason == "none")
    assert result.probe is not None and result.coverage_reason == "none"


def test_instrumentation_environment_cannot_drift_mid_collection(runner, monkeypatch):
    monkeypatch.delenv("AFL_INST_LIBS", raising=False)
    monkeypatch.delenv("AFL_INST_RATIO", raising=False)
    _child(runner, monkeypatch)
    with features.BaselineFeatureCollector(runner, [1]) as collector:
        monkeypatch.setenv("AFL_INST_LIBS", "1")
        monkeypatch.setenv("AFL_INST_RATIO", "5")
        result = collector.run("input")
        assert result.coverage_reason == "none"
        assert json.loads(collector.metadata["coverage_settings"])["AFL_INST_LIBS"] is None


@pytest.mark.parametrize("supported", [True, False])
def test_capture_only_never_allocates_map_and_preserves_repeated_states(
        runner, monkeypatch, supported):
    if not supported:
        runner.patch_kind = "CWE805-direct"
    monkeypatch.setenv("__AFL_SHM_ID", "inherited-invalid-map")
    monkeypatch.setattr(features, "_CoverageMap", lambda: pytest.fail("capture allocated AFL map"))
    _child(runner, monkeypatch, hits=3, capture=_record() * 3)
    with features.BaselineFeatureCollector(
            runner, [1], coverage_enabled=False) as collector:
        result = collector.run("input")
        assert collector._map is None
        assert collector.metadata["coverage_enabled"] is False
        assert collector.metadata["map_bytes"] is None
    assert result.probe.is_normal_exit()
    assert result.patch.br_selection == [0, 0, 0]
    assert result.coverage is None and result.coverage_reason == "disabled"
    if supported:
        assert len(result.snapshots) == 3
        assert result.snapshots[0] == result.snapshots[1] == result.snapshots[2]
        assert result.patch_reason == "none"
    else:
        assert result.snapshots is None
        assert result.patch_reason != "none"
    assert (Path(runner.dir) / "executions").read_text() == "one\n"


@pytest.mark.parametrize("supported", [True, False])
def test_fifo_feedback_publishes_durable_states_before_baseline_row(
        runner, monkeypatch, tmp_path, supported):
    from fuzzolic import binradar_minimizer
    from fuzzolic.binradar_feedback_capture import CaptureJournal

    if not supported:
        runner.patch_kind = "CWE805-direct"
    _child(runner, monkeypatch, hits=3, capture=_record() * 3)
    monkeypatch.setattr(verifier.BinRadarQemuRunner, "from_env", lambda *args: runner)
    monkeypatch.setattr(features, "_CoverageMap", lambda: pytest.fail("FIFO allocated AFL map"))
    monkeypatch.setattr(binradar_minimizer, "NoveltyScorer",
                        lambda *args: pytest.fail("FIFO instantiated scorer"))
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "case").write_bytes(b"immutable input")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    baseline = verifier.BinRadarProbeResult(
        patch_loc=0x1000, patch_func_entry=0x1000, stacktrace=[],
        exit_info="ok", patch_hit_cnt=1, patch_func_hit_cnt=1,
        fault_addr=0, patch_func_candidates=[], tracer_fault_reference=None)
    minimizer = binradar_minimizer.BinRadarMinimizer(
        str(tmp_path), str(run_dir), baseline, [str(inputs)],
        {"BINRADAR_FEEDBACK_MODE": "1"}, patches=[1])
    actual_record = CaptureJournal.record
    observed = []

    def record(journal, case, filename, **kwargs):
        assert (run_dir / "minimized" / filename).read_bytes() == b"immutable input"
        assert "[testcase] [result]" not in Path(minimizer.log_file).read_text()
        observed.append(kwargs)
        return actual_record(journal, case, filename, **kwargs)

    monkeypatch.setattr(CaptureJournal, "record", record)
    assert minimizer.run_testcases() is False
    assert len(observed) == 1
    observation = observed[0]
    assert observation["branches"] == [0, 0, 0]
    assert observation["members"] == []
    if supported:
        assert len(observation["snapshots"]) == 3
        assert any(path.read_bytes() == _record() * 3
                   for path in (run_dir / "feedback-capture").rglob("*.brch"))
    else:
        assert observation["snapshots"] is None
        assert observation["state_reason"] != "none"
    row = Path(minimizer.log_file).read_text()
    assert "[testcase] [result]" in row and "[minimizer] [done]" in row
    assert "[schedule-seq" not in row
    assert (tmp_path / "executions").read_text() == "one\n"
    assert not minimizer.pending


@pytest.mark.parametrize("enabled,stale_mode", [(True, None), (True, "0"), (False, "1")])
def test_main_feedback_setting_controls_executed_concrete_evidence(
        runner, monkeypatch, tmp_path, enabled, stale_mode):
    from fuzzolic import binradar_artifacts
    from fuzzolic import binradar_config
    from fuzzolic import binradar_evidence
    from fuzzolic.binradar_feedback_bundle import load_bundle
    from fuzzolic import binradar

    _child(runner, monkeypatch, hits=3, capture=_record() * 3)
    monkeypatch.setattr(verifier.BinRadarQemuRunner, "from_env", lambda *args: runner)
    monkeypatch.setattr(features, "_CoverageMap", lambda: pytest.fail("FIFO allocated AFL map"))
    inputs = tmp_path / "input" / "benign"
    inputs.mkdir(parents=True)
    (inputs / "case").write_bytes(b"immutable input")
    env = {
        "BINRADAR_OUTDIR": str(tmp_path / "out"), "BINRADAR_TIMEOUT": "60",
        "BINARY": "target", "POC_INPUT": "input/benign/case", "TEST_CMD": "@@",
        "PATCH_LOC": "0x1000", "TOTAL_PATCHES": "2",
        "BINRADAR_FEEDBACK_MODE": "1" if enabled else "0",
    }
    (tmp_path / "binradar.env").write_text("\n".join(f"{key}={value}" for key, value in env.items()))
    executor = object.__new__(binradar.BinRadarExecutor)
    executor.run_config = binradar_config.RunConfig.from_environment(str(tmp_path), env)
    executor.config = binradar_config.build_base_environment(executor.run_config, "unused-plt")
    if stale_mode is not None:
        executor.config["BINRADAR_FEEDBACK_MODE"] = stale_mode
    executor.workdir = str(tmp_path)
    executor.run_dir = str(tmp_path / "out" / "run-00000")
    Path(executor.run_dir).mkdir(parents=True)
    executor.binary = "target"
    executor.poc_input = env["POC_INPUT"]
    executor.filter_result = [1]
    executor.brpatched_total_patches = 2
    executor.artifacts = binradar_artifacts.ArtifactSet(str(tmp_path), "target", "generic-erm", 0, 2)
    executor.probe_result = verifier.BinRadarProbeResult(
        patch_loc=0x1000, patch_func_entry=0x1000, stacktrace=[],
        exit_info="ok", patch_hit_cnt=1, patch_func_hit_cnt=1,
        fault_addr=0, patch_func_candidates=[], tracer_fault_reference=None)
    executor.run_prefix, executor.run_id = "run", 0
    progress = []
    executor.save_progress = progress.append
    factory = executor._concrete_worker_factory(require_verifier=True)
    minimizer = factory.build_minimizer()
    minimizer.min_file_age = 0
    concrete = factory.build_verifier()
    assert minimizer.run_testcases() is False
    assert concrete.run_verification_streaming(factory.minimizer_result_file, timeout=10) is False
    result = binradar_evidence.read_verifier(Path(executor.run_dir) / "verifier.br")
    assert result.patches[1].observations["no-crash-pass-same-br"] == 1
    assert (tmp_path / "executions").read_text() == "one\none\n"
    if enabled:
        executor.run_feedback()
        bundle = load_bundle(Path(executor.run_dir) / "feedback")
        assert bundle.predicates[1]["concrete-counts"] == "0,0,1,0,0,0"
        assert bundle.coverage["c0"]["status"] == "complete"
        assert {trace["representative"] for trace in bundle.traces.values()} == {0, 1}
        for trace in bundle.traces.values():
            assert [state.branch for state in bundle.states(trace["key"])] == [0, 0, 0]
    else:
        assert not (Path(executor.run_dir) / "feedback-capture").exists()


@pytest.mark.parametrize("termination", ["failed", "wall-time-reached"])
def test_feedback_interruption_never_claims_complete_capture(
        runner, monkeypatch, tmp_path, termination):
    import queue
    from fuzzolic import binradar_minimizer

    monkeypatch.setattr(verifier.BinRadarQemuRunner, "from_env", lambda *args: runner)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    minimizer = binradar_minimizer.BinRadarMinimizer(
        str(tmp_path), str(run_dir), None, [],
        {"BINRADAR_FEEDBACK_MODE": "1"}, patches=[1])
    if termination == "failed":
        failures = queue.Queue()
        failures.put(RuntimeError("producer failed"))
        with pytest.raises(RuntimeError, match="producer failed"):
            minimizer.run_testcases(producer_exc_queue=failures)
    else:
        checks = []

        def cutoff(deadline):
            checks.append(deadline)
            if len(checks) == 2:
                raise binradar_minimizer._MinimizerTimeout()

        monkeypatch.setattr(minimizer, "_raise_if_timed_out", cutoff)
        assert minimizer.run_testcases() is True
    assert "[minimizer] [done]" not in Path(minimizer.log_file).read_text()
    assert not list((run_dir / "minimized").iterdir())
    terminal = run_dir / "feedback-capture" / "baseline" / "terminal.json"
    assert json.loads(terminal.read_text())["reason"] == termination
    assert not (tmp_path / "executions").exists()


def test_descriptor_digest_is_order_independent_and_candidate_bound():
    assert features.descriptor_digest({}) == "none"
    assert features.descriptor_digest({2: "p1", 1: "p0"}) == features.descriptor_digest({1: "p0", 2: "p1"})
    assert features.descriptor_digest({1: "p0"}) != features.descriptor_digest({2: "p0"})


def test_shmat_failure_removes_new_segment(monkeypatch):
    class FailingLibc:
        def __init__(self):
            self.removed = []
            self.shmget = lambda *args: 123
            self.shmat = lambda *args: ctypes.c_void_p(-1).value
            self.shmdt = lambda *args: pytest.fail("failed attach must not detach")
            self.shmctl = lambda ident, command, pointer: self.removed.append((ident, command)) or 0
    libc = FailingLibc()
    monkeypatch.setattr(features.ctypes, "CDLL", lambda *args, **kwargs: libc)
    with pytest.raises(OSError, match="cannot attach baseline AFL SHM"):
        features._CoverageMap()
    assert libc.removed == [(123, 0)]
