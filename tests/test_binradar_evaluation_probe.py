"""Regression tests for binradar-evaluation probe freshness.

A legacy (pre concrete-oracle) probe carries no ``concrete_fault_addr``:
the minimizer drops every crash row as an unevaluable fault address and the
verifier can emit verified candidates with zero crash evidence.  The
evaluation entrypoint must regenerate a fresh probe instead of silently
proceeding on the historical one.
"""

import contextlib
import importlib.util
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_evidence
import binradar_verifier

_spec = importlib.util.spec_from_file_location(
    "binradar_evaluation", ROOT / "fuzzolic" / "binradar-evaluation.py")
assert _spec is not None and _spec.loader is not None
evaluation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluation)


def _probe_row(version: int) -> str:
    if version == 3:
        return ("[version 3] [exit crash] [patch-loc 4585dd] "
                "[func-entry 458020] [patch-hit 1] [func-hit 1] "
                "[fault-addr 4585dd] [tracer-fault-valid false] "
                "[tracer-fault-source unavailable] [tracer-fault-addr 0] "
                "[tracer-fault-image none] [tracer-fault-image-offset 0] "
                "[memcheck-policy unavailable] "
                "[patch-func-candidates [458020:1]] [stacktrace []] "
                "[concrete-oracle qasan-main-v1] [concrete-fault-valid false]")
    return ("[version 4] [exit crash] [patch-loc 4585dd] "
            "[func-entry 458020] [patch-hit 1] [func-hit 1] "
            "[fault-addr 4585dd] [tracer-fault-valid false] "
            "[tracer-fault-source unavailable] [tracer-fault-addr 0] "
            "[tracer-fault-image none] [tracer-fault-image-offset 0] "
            "[memcheck-policy unavailable] "
            "[patch-func-candidates [458020:1]] [stacktrace []] "
            "[concrete-oracle qasan-main-v2] [concrete-fault-valid true] "
            "[raw-fault-addr 4585dd] [concrete-fault-source native]")


class _StubRunner:
    """Returns a proved current crash for patch 0 and a fixing patch 1."""

    def __init__(self):
        self.calls = []

    @staticmethod
    def _probe(exit_info: str, fault_addr: int):
        return binradar_verifier.BinRadarProbeResult(
            patch_loc=0x4585dd, patch_func_entry=0x458020, stacktrace=[],
            patch_hit_cnt=1, patch_func_hit_cnt=1, exit_info=exit_info,
            fault_addr=fault_addr, patch_func_candidates=[(0x458020, 1)],
            memcheck_policy="unavailable",
            concrete_oracle=binradar_verifier.CONCRETE_ORACLE,
            concrete_fault_valid=exit_info == "crash",
            raw_fault_addr=fault_addr,
            concrete_fault_source="native" if exit_info == "crash"
            else "unavailable")

    def test_with_original(self, testcase, verbose=True):
        self.calls.append(("probe",))
        return self._probe("crash", 0x4585dd)

    def test_with_patched(self, patch_id, testcase, verbose=False):
        self.calls.append((patch_id,))
        # The external crash input still crashes at the POC fault under the
        # candidate patch: the stub mirrors a non-fixing candidate so the
        # verifier's crash-evidence path records a hard rejection.
        return self._probe("crash", 0x4585dd), binradar_verifier.BinRadarPatchResult(
            int(patch_id), [0])

    def test_with_file_trace(self, testcase, patch_func_entry=0,
                             verbose=True, timeout=60.0):
        return self._probe("crash", 0x4585dd)


def _workdir_with_probe(tmp_path: Path, version: int) -> Path:
    work = tmp_path / f"evaluation-v{version}"
    latest = work / "out" / "br-feedback-00000"
    latest.mkdir(parents=True)
    (latest / "probe-results.sbsv").write_text(
        f"[probe-info] {_probe_row(version)}\n[file-trace] [need-file-hook False]\n")
    binradar_evidence.write_filter(latest / "filter.br", 1, [1])
    (work / "nm.orig").write_bytes(b"stub")
    (work / "nm.brpatched").write_bytes(b"stub")
    (work / "binradar.env").write_text(
        'BINARY="nm"\nTEST_CMD="-l @@"\nPATCH_LOC="0x4585dd"\n'
        'POC_INPUT="poc/nullderef"\nTOTAL_PATCHES="1"\n')
    (work / "poc").mkdir()
    (work / "poc" / "nullderef").write_bytes(b"poc")
    fuzz = work / "fuzz"
    (fuzz / "queue").mkdir(parents=True)
    (fuzz / "crashes").mkdir()
    (fuzz / "crashes" / "crash").write_bytes(b"crashing-input")
    return work


def _run_evaluation(monkeypatch, work: Path):
    runner = _StubRunner()
    monkeypatch.setattr(
        binradar_verifier.BinRadarQemuRunner, "from_env",
        staticmethod(lambda *args, **kwargs: runner))
    monkeypatch.setattr(
        sys, "argv",
        ["binradar-evaluation.py", "--workdir", str(work),
         "--fuzzer", "repro", "--fuzz-out", str(work / "fuzz")])
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        evaluation.main()
    return runner, output.getvalue()


def test_current_probe_reuses_and_verifies(monkeypatch, tmp_path):
    work = _workdir_with_probe(tmp_path, 4)
    runner, _stdout = _run_evaluation(monkeypatch, work)
    # Current probes are reused: no fresh probe run is triggered.
    assert ("probe",) not in runner.calls
    record = binradar_evidence.read_verifier(
        work / "repro" / "verified.br").patches[1]
    assert not record.verified


def test_legacy_probe_is_regenerated_not_reused(monkeypatch, tmp_path):
    work = _workdir_with_probe(tmp_path, 3)
    runner, _stdout = _run_evaluation(monkeypatch, work)
    # The legacy probe must trigger a fresh probe run (test_with_original)
    # and the fresh probe file must be written into the evaluation dir.
    assert ("probe",) in runner.calls
    fresh = work / "repro" / "probe-results.sbsv"
    assert fresh.is_file()
    probe = binradar_verifier.BinRadarProbeResult.from_sbsv(str(fresh))
    assert probe is not None
    assert getattr(probe, "_probe_serialization_version", 1) == \
        binradar_verifier.CURRENT_PROBE_RESULT_VERSION
    # With a current probe the crash evidence is evaluated, not dropped.
    record = binradar_evidence.read_verifier(
        work / "repro" / "verified.br").patches[1]
    assert record.total_evidences >= 1
    assert not record.verified

