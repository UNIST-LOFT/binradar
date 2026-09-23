#!/usr/bin/env python3
"""Behavioral coverage for compact BinRadar evidence and its text renderer."""

import struct
import subprocess
import sys
import threading
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar
import binradar_evidence
import binradar_results
import binradar_verifier


def _uleb(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def _frame(record_type: int, payload: bytes) -> bytes:
    flags = 0
    checksum = zlib.crc32(
        payload, zlib.crc32(struct.pack("<HH", record_type, flags)))
    return (struct.pack("<IHH", len(payload), record_type, flags)
            + payload + struct.pack("<I", checksum & 0xFFFFFFFF))


def _group(representative: int, outcome: int, fault_addr: int,
           branches, members) -> bytes:
    flags = 0 if branches is not None else 1
    branches = [] if branches is None else branches
    packed = bytearray((len(branches) + 3) // 4)
    for index, branch in enumerate(branches):
        packed[index // 4] |= branch << ((index % 4) * 2)
    member_bytes = bytearray()
    previous = 0
    for index, member in enumerate(members):
        member_bytes.extend(_uleb(member if index == 0 else member - previous))
        previous = member
    return (struct.pack("<IBBHQII", representative, outcome, flags, 0,
                        fault_addr, len(branches), len(members))
            + packed + member_bytes)


def _write_binradar(path: Path, *, truncated_tail: bool = False,
                    version: int = 2, attempts=(1, 2)) -> None:
    baseline = (struct.pack("<II", attempts[0], 1)
                + _group(0, 1, 0, [0], [0]))
    payload = (struct.pack("<II", attempts[1], 2)
               + _group(0, 1, 0, [0, 1, 2, 1], [0])
               + _group(2, 2, 0x1234, [2, 0], [1, 2, 300]))
    data = (struct.pack("<8sHHI", b"BRDATAB1", version, 3, 0)
            + _frame(4, baseline) + _frame(4, payload))
    if truncated_tail:
        data += struct.pack("<IHH", 50, 4, 0) + b"partial"
    path.write_bytes(data)


def test_filter_and_verifier_round_trip_and_detect_corruption(tmp_path):
    filter_path = tmp_path / "filter.br"
    binradar_evidence.write_filter(filter_path, 10, [1, 3, 10])
    assert binradar_evidence.read_filter(filter_path).passed == [1, 3, 10]

    corrupt = bytearray(filter_path.read_bytes())
    corrupt[-5] ^= 0x40
    corrupt_path = tmp_path / "filter-corrupt.br"
    corrupt_path.write_bytes(corrupt)
    with pytest.raises(binradar_evidence.EvidenceError, match="checksum"):
        binradar_evidence.read_filter(corrupt_path)

    verifier_path = tmp_path / "verifier.br"
    binradar_evidence.write_verifier(
        verifier_path,
        [binradar_evidence.VerifierPatchResult(
            patch=3, verified=False, accept_evidences=1,
            total_evidences=2,
            observations={"patch-crashed": 1, "crash-pass": 1},
            testcase="case.dat", has_feedback=True,
            feedback_accepted=False, security_rejected=True)],
        stop_reason="wall-time-reached")
    verifier = binradar_evidence.read_verifier(verifier_path)
    assert verifier.stop_reason == "wall-time-reached"
    assert verifier.patches[3].observations["patch-crashed"] == 1
    assert verifier.patches[3].security_rejected


def test_binradar_reader_expands_groups_and_ignores_truncated_tail(tmp_path):
    path = tmp_path / "binradar.br"
    _write_binradar(path, truncated_tail=True)

    iterations = list(binradar_evidence.read_binradar(path))
    assert len(iterations) == 2
    assert iterations[0].iteration == 1
    assert iterations[1].iteration == 2
    assert iterations[1].groups[0].branches == [0, 1, 2, 1]
    assert iterations[1].groups[1].members == [1, 2, 300]
    assert iterations[1].groups[1].fault_addr == 0x1234


def test_binradar_v2_accepts_gaps_but_rejects_bad_ids(tmp_path):
    """Attempt 2 was discarded, so committed attempts are 1 and 3."""
    gapped = tmp_path / "gapped.br"
    _write_binradar(gapped, attempts=(1, 3))
    assert [row.iteration
            for row in binradar_evidence.read_binradar(gapped)] == [1, 3]

    for name, attempts in (("backward", (1, 1)), ("missing-baseline", (2, 3))):
        path = tmp_path / f"{name}.br"
        _write_binradar(path, attempts=attempts)
        with pytest.raises(binradar_evidence.EvidenceError):
            list(binradar_evidence.read_binradar(path))

    # A version-1 BINRADAR file keeps the historical contiguity requirement.
    legacy = tmp_path / "legacy.br"
    _write_binradar(legacy, version=1, attempts=(1, 3))
    with pytest.raises(binradar_evidence.EvidenceError, match="contiguous"):
        list(binradar_evidence.read_binradar(legacy))
    assert binradar_evidence.evidence_kind(legacy) == \
        binradar_evidence.EvidenceKind.BINRADAR


def test_final_analysis_consumes_compact_equivalence_groups(tmp_path):
    _write_binradar(tmp_path / "binradar.br")
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=patch, verified=True, accept_evidences=0,
            total_evidences=0, observations={})
         for patch in (1, 2, 300)])

    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.run_dir = str(tmp_path)
    executor.run_prefix = "run"
    executor.run_id = 0
    executor.filter_result = [1, 2, 300]
    executor.probe_result = SimpleNamespace(
        tracer_fault_reference=binradar_verifier.TracerFaultReference(
            address=0x1234, source="guest-signal"))
    executor.disable_binradar = False
    executor.binradar_failed = False
    executor.wall_time_reached = False
    executor.phase_failures = {}
    executor.phase_failure_lock = threading.Lock()
    executor.save_progress = lambda _row: None

    executor.run_final()

    final = (tmp_path / "final.sbsv").read_text()
    assert "[verifier verifier.br] [evidence binradar.br]" in final
    for patch in (1, 2, 300):
        assert (f"[final] [binradar] [patch {patch}] [res rejected] "
                f"[reason introduced-crash] [iter 2]") in final


@pytest.mark.parametrize("source,address,hard_rejection", [
    (None, 0, False),
    ("legacy-unvalidated", 0x1234, False),
    ("guest-signal", 0, True),
    ("provenance-access", 0x1234, True),
])
@pytest.mark.parametrize("original_outcome,reason", [
    (2, "same-crash"), (1, "introduced-crash"),
])
def test_final_requires_valid_fault_identity(tmp_path, source, address,
                                             hard_rejection, original_outcome,
                                             reason):
    reference = (None if source is None else
                 binradar_verifier.TracerFaultReference(address, source))
    # Baseline, one crash-classification transition, then confidence evidence.
    frames = [struct.pack("<II", 1, 1)
              + _group(0, 2, address, [0], [0])]
    frames.append(
        struct.pack("<II", 2, 4)
        + _group(0, original_outcome, address, [0], [0])
        + _group(1, 2, address, [1], [1])
        + _group(2, 2, address + 1, [1], [2])
        + _group(3, 1, 0, [0], [3, 4]))
    frames.append(
        struct.pack("<II", 3, 3)
        + _group(0, 1, 0, [0], [0, 2])
        + _group(1, 1, 0, [1], [1, 3])
        + _group(4, 1, 0, [0], [4]))
    (tmp_path / "binradar.br").write_bytes(
        struct.pack("<8sHHI", b"BRDATAB1", 1, 3, 0)
        + b"".join(_frame(4, payload) for payload in frames))
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=patch, verified=patch != 4, accept_evidences=0,
            total_evidences=1 if patch == 4 else 0, observations={})
         for patch in (1, 2, 3, 4)])
    binradar_results.write_final_result(binradar_results.FinalResultRequest(
        run_dir=str(tmp_path), run_prefix="regression", run_id=0,
        candidates=[1, 2, 3, 4], tracer_fault_reference=reference,
        disable_binradar=False, binradar_failed=False, wall_time_reached=False,
        failed_phases=[], save_progress=lambda _: None,
        record_wall_time_reached=lambda: None))
    report = (tmp_path / "final.sbsv").read_text()
    expected = "rejected" if hard_rejection else "verified"
    assert f"[binradar] [patch 1] [res {expected}]" in report
    assert "[binradar] [patch 2] [res verified]" in report
    assert "[binradar] [patch 3] [res verified]" in report
    assert "[verifier] [patch 4] [res rejected]" in report
    assert "[binradar] [patch 4]" not in report
    # A differing normal/normal branch contributes confidence, never rejection.
    assert ("[confidence] [patch 3] [score 0.500000] "
            "[accept-evidences 1] [total-evidences 2]") in report
    if hard_rejection:
        assert f"[res rejected] [reason {reason}] [iter 2]" in report
    else:
        assert "[hard-crash-classification unavailable]" in report
        assert "[reason same-crash]" not in report
        assert "[reason introduced-crash]" not in report


def test_final_reports_overlap_null_baseline_and_partial_queue(tmp_path):
    frames = [
        struct.pack("<II", 1, 1) + _group(0, 2, 0x1234, [0], [0]),
        struct.pack("<II", 2, 2)
        + _group(0, 1, 0, None, [0])
        + _group(1, 1, 0, [0], [1, 2, 3]),
        struct.pack("<II", 4, 4)
        + _group(0, 1, 0, [0], [0])
        + _group(1, 2, 0x1234, [1], [1])
        + _group(2, 2, 0x1234, [1], [2])
        + _group(3, 1, 0, [1], [3]),
    ]
    (tmp_path / "binradar.br").write_bytes(
        struct.pack("<8sHHI", b"BRDATAB1", 2, 3, 0)
        + b"".join(_frame(4, frame) for frame in frames))
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=patch, verified=patch != 1, accept_evidences=0,
            total_evidences=0, observations={}) for patch in (1, 2, 3)])
    out = tmp_path / "out"
    out.mkdir()
    run_dir = out / "trial-00000"
    run_dir.mkdir()
    for file in ("binradar.br", "verifier.br"):
        (run_dir / file).write_bytes((tmp_path / file).read_bytes())
    (out / "progress.sbsv").write_text(
        "[binradar] [stop] [prefix trial] [id 0] [reason failure-limit] "
        "[attempt 4] [remaining 5] [committed 3] [discarded 1]\n")
    binradar_results.write_final_result(binradar_results.FinalResultRequest(
        run_dir=str(run_dir), run_prefix="trial", run_id=0,
        candidates=[1, 2, 3],
        tracer_fault_reference=binradar_verifier.TracerFaultReference(
            0x1234, "guest-signal"),
        disable_binradar=False, binradar_failed=False,
        wall_time_reached=False, failed_phases=[],
        save_progress=lambda _: None, record_wall_time_reached=lambda: None))
    report = (run_dir / "final.sbsv").read_text()
    assert "[binradar-coverage partial] [raw-committed 3] [processed 2]" in report
    assert "[patch0-no-observation 1]" in report
    assert "[original-normal 1] [original-poc-crash 1]" in report
    assert "[normal-branch-differences 1]" in report
    assert ("[standalone-rejected 2] [overlap-rejected 1] "
            "[incremental-rejected 1] [final-survivors 1]") in report
    assert "[final] [binradar] [patch 2] [res rejected]" in report
    assert "[final] [binradar] [patch 1]" not in report
    (out / "progress.sbsv").write_text(
        "[binradar] [stop] [prefix trial] [id 0] [reason exhausted] "
        "[attempt 4] [remaining 0] [committed 3] [discarded 0]\n")
    binradar_results.write_final_result(binradar_results.FinalResultRequest(
        run_dir=str(run_dir), run_prefix="trial", run_id=0,
        candidates=[1, 2, 3],
        tracer_fault_reference=binradar_verifier.TracerFaultReference(
            0x1234, "guest-signal"),
        disable_binradar=False, binradar_failed=False,
        wall_time_reached=False, failed_phases=[],
        save_progress=lambda _: None, record_wall_time_reached=lambda: None))
    assert "[binradar-coverage partial]" in (run_dir / "final.sbsv").read_text()


@pytest.mark.parametrize("other_phase_cutoff", [False, True])
def test_exhausted_queue_with_full_evidence_is_complete(
        tmp_path, other_phase_cutoff):
    run_dir = tmp_path / "trial-00000"
    run_dir.mkdir()
    _write_binradar(run_dir / "binradar.br")
    binradar_evidence.write_verifier(
        run_dir / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=patch, verified=True, accept_evidences=0,
            total_evidences=0, observations={}) for patch in (1, 2, 300)])
    request = binradar_results.FinalResultRequest(
        run_dir=str(run_dir), run_prefix="trial", run_id=0,
        candidates=[1, 2, 300],
        tracer_fault_reference=binradar_verifier.TracerFaultReference(
            0x1234, "guest-signal"),
        disable_binradar=False, binradar_failed=False,
        wall_time_reached=other_phase_cutoff, failed_phases=[],
        save_progress=lambda _: None, record_wall_time_reached=lambda: None)

    # A historical P2 stop row cannot prove that all scheduled work was
    # accounted for, even when its four scalar counters happen to match.
    (tmp_path / "progress.sbsv").write_text(
        "[binradar] [stop] [prefix trial] [id 0] [reason exhausted] "
        "[attempt 2] [remaining 0] [committed 2] [discarded 0]\n")
    binradar_results.write_final_result(request)
    assert "[binradar-coverage partial]" in (
        run_dir / "final.sbsv").read_text()

    (tmp_path / "progress.sbsv").write_text(
        "[binradar] [stop] [prefix trial] [id 0] [reason exhausted] "
        "[attempt 2] [remaining 0] [committed 2] [discarded 0] "
        "[representative-runs 4] [representative-runs-partial false] "
        "[planned 1] [attempted 2] [mutation-attempted 1] "
        "[mutation-discarded 0] [mutation-committed 1] "
        "[mutation-pending 0] [queued 0]\n")
    binradar_results.write_final_result(request)
    report = (run_dir / "final.sbsv").read_text()
    assert "[final] [coverage] [binradar-coverage complete]" in report
    assert (f"[wall-time-reached {str(other_phase_cutoff).lower()}] "
            "[binradar-coverage complete]") in report


def test_converter_renders_each_evidence_kind_and_filters_patch(tmp_path):
    filter_path = tmp_path / "filter.br"
    binradar_evidence.write_filter(filter_path, 3, [2])
    verifier_path = tmp_path / "verifier.br"
    binradar_evidence.write_verifier(
        verifier_path,
        [binradar_evidence.VerifierPatchResult(
            patch=2, verified=True, accept_evidences=4,
            total_evidences=5, observations={"crash-pass": 4})])
    binradar_path = tmp_path / "binradar.br"
    _write_binradar(binradar_path)

    converter = ROOT / "fuzzolic" / "binradar-evidence-to-text.py"

    def convert(path: Path, *arguments: str) -> str:
        result = subprocess.run(
            [sys.executable, str(converter), str(path), *arguments],
            check=True, capture_output=True, text=True)
        return result.stdout

    filter_text = convert(filter_path)
    assert "[patch] [id 1] [pass false]" in filter_text
    assert "[patch] [id 2] [pass true]" in filter_text

    verifier_text = convert(verifier_path)
    assert "[verifier-result] [res verified] [patch 2]" in verifier_text
    assert "[accept-evidences 4] [total-evidences 5]" in verifier_text

    binradar_text = convert(binradar_path, "--iteration", "2",
                            "--patch", "300")
    assert "[binradar] [crash] [iter 2] [patch 300]" in binradar_text
    assert "[binradar] [commit] [iter 2] [patch 300] [br 20]" in binradar_text
    assert "[patch 2]" not in binradar_text


def _write_binradar_frames(path: Path, *, frames=()) -> None:
    """Write v2 BINRADAR evidence from caller-built frame payloads."""
    data = (struct.pack("<8sHHI", b"BRDATAB1", 2, 3, 0)
            + b"".join(_frame(4, frame) for frame in frames))
    path.write_bytes(data)


def _final_request(run_dir: Path, candidates, reference):
    return binradar_results.FinalResultRequest(
        run_dir=str(run_dir), run_prefix="trial", run_id=0,
        candidates=list(candidates), tracer_fault_reference=reference,
        disable_binradar=False, binradar_failed=False,
        wall_time_reached=False, failed_phases=[],
        save_progress=lambda _: None, record_wall_time_reached=lambda: None)


@pytest.mark.parametrize("reference,expected", [
    (binradar_verifier.TracerFaultReference(0x1234, "guest-signal"),
     "[original-other-crash 1] [original-unclassified-crash 0]"),
    (None, "[original-other-crash 0] [original-unclassified-crash 1]"),
])
def test_final_classifies_original_crash_by_reference_validity(
        tmp_path, reference, expected):
    """A crash at another address is only `other` with a valid reference.

    Without one, the baseline crash cannot be typed at all: counting it as
    `other` would silently turn a missing identity into a real comparison.
    """
    frames = [
        struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0]),
        struct.pack("<II", 2, 2)
        + _group(0, 2, 0x9999, [0], [0])
        + _group(1, 2, 0x9999, [1], [1]),
    ]
    _write_binradar_frames(tmp_path / "binradar.br", frames=frames)
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=1, verified=True, accept_evidences=0, total_evidences=0,
            observations={})])
    binradar_results.write_final_result(
        _final_request(tmp_path, [1], reference))
    report = (tmp_path / "final.sbsv").read_text()
    assert expected in report
    # Neither form may hard-reject: the addresses differ from the POC.
    assert "[reason same-crash]" not in report


@pytest.mark.parametrize("disable,binradar_failed,stop_row", [
    (True, False, None),
    (False, True, None),
    (False, False,
     "[binradar] [stop] [prefix trial] [id 0] "
     "[reason baseline-unavailable] [attempt 1] [remaining 0] "
     "[committed 0] [discarded 1]\n"),
])
def test_final_reports_unavailable_coverage(tmp_path, disable,
                                            binradar_failed, stop_row):
    """Disabled, failed, and baseline-unavailable BinRadar are `unavailable`."""
    run_dir = tmp_path / "trial-00000"
    run_dir.mkdir()
    frames = [struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0])]
    _write_binradar_frames(run_dir / "binradar.br", frames=frames)
    binradar_evidence.write_verifier(
        run_dir / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=1, verified=True, accept_evidences=0, total_evidences=0,
            observations={})])
    if stop_row is not None:
        # _run_stop reads the sibling progress file of the run directory.
        (tmp_path / "progress.sbsv").write_text(stop_row)
    request = binradar_results.FinalResultRequest(
        run_dir=str(run_dir), run_prefix="trial", run_id=0,
        candidates=[1],
        tracer_fault_reference=binradar_verifier.TracerFaultReference(
            0x1234, "guest-signal"),
        disable_binradar=disable, binradar_failed=binradar_failed,
        wall_time_reached=False, failed_phases=[],
        save_progress=lambda _: None, record_wall_time_reached=lambda: None)
    binradar_results.write_final_result(request)
    report = (run_dir / "final.sbsv").read_text()
    assert "[binradar-coverage unavailable]" in report


def test_final_reports_singleton_subject_kind(tmp_path):
    """One candidate is reported as a singleton, not as a multi-candidate set."""
    frames = [struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0])]
    _write_binradar_frames(tmp_path / "binradar.br", frames=frames)
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=7, verified=True, accept_evidences=0, total_evidences=0,
            observations={})])
    binradar_results.write_final_result(_final_request(
        tmp_path, [7],
        binradar_verifier.TracerFaultReference(0x1234, "guest-signal")))
    report = (tmp_path / "final.sbsv").read_text()
    assert "[subject-kind singleton]" in report
    assert "[subject-kind multi]" not in report


def test_binradar_frame_corruption_is_rejected(tmp_path):
    """A corrupted complete BINRADAR frame is fatal, not a discarded attempt."""
    frames = [
        struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0]),
        struct.pack("<II", 2, 2)
        + _group(0, 1, 0, [0], [0])
        + _group(1, 1, 0, [1], [1]),
    ]
    path = tmp_path / "binradar.br"
    _write_binradar_frames(path, frames=frames)
    assert len(list(binradar_evidence.read_binradar(path))) == 2

    corrupt = bytearray(path.read_bytes())
    corrupt[-9] ^= 0x20          # payload byte of the final complete frame
    corrupt_path = tmp_path / "binradar-corrupt.br"
    corrupt_path.write_bytes(corrupt)
    with pytest.raises(binradar_evidence.EvidenceError, match="checksum"):
        list(binradar_evidence.read_binradar(corrupt_path))


def test_final_rejects_incomplete_candidate_coverage(tmp_path):
    """A complete mutation frame must cover every candidate exactly once."""
    frames = [
        struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0]),
        struct.pack("<II", 2, 2)
        + _group(0, 1, 0, [0], [0])
        + _group(1, 1, 0, [1], [1, 2]),
    ]
    _write_binradar_frames(tmp_path / "binradar.br", frames=frames)
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=patch, verified=True, accept_evidences=0, total_evidences=0,
            observations={}) for patch in (1, 2, 3)])
    with pytest.raises(ValueError, match="coverage mismatch"):
        binradar_results.write_final_result(_final_request(
            tmp_path, [1, 2, 3],
            binradar_verifier.TracerFaultReference(0x1234, "guest-signal")))


def test_final_publishes_exact_rejection_id_sets(tmp_path):
    """FINAL publishes membership, not only counts, for every rejection set.

    The standalone set intentionally includes patches the concrete verifier
    already rejected, so the recorded intersection is the genuine overlap and
    the coverage row's scalar counts must agree with the emitted IDs.
    """
    frames = [
        struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0]),
        struct.pack("<II", 2, 5)
        + _group(0, 2, 0x1234, [0], [0])
        + _group(1, 2, 0x1234, [1], [1])
        + _group(2, 1, 0, [1], [2])
        + _group(3, 2, 0x1234, [1], [3])
        + _group(4, 1, 0, [1], [4]),
    ]
    _write_binradar_frames(tmp_path / "binradar.br", frames=frames)
    # Patch 3 is both a standalone tracer rejection and a concrete rejection,
    # so the recorded intersection is the genuine, non-empty overlap.
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=patch, verified=patch not in (3, 4), accept_evidences=0,
            total_evidences=0, observations={})
         for patch in (1, 2, 3, 4)])
    binradar_results.write_final_result(_final_request(
        tmp_path, [1, 2, 3, 4],
        binradar_verifier.TracerFaultReference(0x1234, "guest-signal")))
    report = (tmp_path / "final.sbsv").read_text()
    assert ("[final] [rejection-sets] [standalone 1,3] [overlap 3] "
            "[incremental 1] [final-survivors 2] "
            "[truncated-sets ]") in report
    assert ("[standalone-rejected 2] [overlap-rejected 1] "
            "[incremental-rejected 1]") in report


def test_rejection_set_serialization_is_bounded(tmp_path, monkeypatch):
    """A set past the cap is shortened only in its serialization."""
    monkeypatch.setattr(binradar_results, "REJECTION_ID_LIMIT", 2)
    frames = [
        struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0]),
        struct.pack("<II", 2, 2)
        + _group(0, 2, 0x1234, [0], [0])
        + _group(5, 2, 0x1234, [1], [1, 2, 3, 4, 5]),
    ]
    _write_binradar_frames(tmp_path / "binradar.br", frames=frames)
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=patch, verified=True, accept_evidences=0, total_evidences=0,
            observations={}) for patch in (1, 2, 3, 4, 5)])
    binradar_results.write_final_result(_final_request(
        tmp_path, [1, 2, 3, 4, 5],
        binradar_verifier.TracerFaultReference(0x1234, "guest-signal")))
    report = (tmp_path / "final.sbsv").read_text()
    # The exact count survives in the coverage row; the ID row is marked.
    assert "[standalone-rejected 5]" in report
    assert "[standalone 1,2] " in report
    assert "[truncated-sets standalone,incremental]" in report


@pytest.mark.parametrize("reason,expected", [
    ("exhausted", "partial"),
    ("failure-limit", "partial"),
])
def test_discarded_attempt_never_reports_complete_coverage(tmp_path, reason,
                                                           expected):
    """A discarded attempt keeps coverage partial even at `remaining 0`.

    The terminal plan being discarded is the dangerous case: the queue looks
    exhausted and `remaining`/`queued` are zero, but a discarded attempt
    published no evidence, so the run is not the complete finite-queue sweep.
    """
    frames = [
        struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0]),
        struct.pack("<II", 3, 2)
        + _group(0, 1, 0, [0], [0])
        + _group(1, 1, 0, [1], [1]),
    ]
    _write_binradar_frames(tmp_path / "binradar.br", frames=frames)
    binradar_evidence.write_verifier(
        tmp_path / "verifier.br",
        [binradar_evidence.VerifierPatchResult(
            patch=1, verified=True, accept_evidences=0, total_evidences=0,
            observations={})])
    (tmp_path / "progress.sbsv").write_text(
        f"[binradar] [stop] [prefix trial] [id 0] [reason {reason}] "
        "[attempt 3] [remaining 0] [committed 2] [discarded 1] "
        "[representative-runs 4] [representative-runs-partial false] "
        "[planned 2] [attempted 3] [mutation-attempted 2] "
        "[mutation-discarded 1] [mutation-committed 1] "
        "[mutation-pending 0] [queued 0]\n")
    binradar_results.write_final_result(_final_request(
        tmp_path, [1],
        binradar_verifier.TracerFaultReference(0x1234, "guest-signal")))
    report = (tmp_path / "final.sbsv").read_text()
    assert f"[binradar-coverage {expected}]" in report
    assert "[binradar-coverage complete]" not in report
