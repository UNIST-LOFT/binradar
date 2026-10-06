"""Cross-image fault identity and versioned wire contracts."""
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_baseline
import binradar_evidence as evidence
import binradar_feedback
import binradar_results
import binradar_verifier as verifier
from test_binradar_evidence import _frame, _group, _final_request
from test_binradar_feedback import _feedback_executor, _full_row

IMAGE = "ab" * 32
OTHER_IMAGE = "cd" * 32


def _site_group(pc, image=IMAGE, offset=0x123, *, outcome=2):
    fixed = bytearray(_group(0, outcome, pc, [1], [0]))
    fixed[5] |= 2
    return (bytes(fixed[:evidence.BINRADAR_GROUP_STRUCT.size])
            + bytes.fromhex(image) + struct.pack("<Q", offset)
            + bytes(fixed[evidence.BINRADAR_GROUP_STRUCT.size:]))


def _write(path, payload, version=3):
    path.write_bytes(evidence.HEADER_STRUCT.pack(evidence.MAGIC, version, 3, 0)
                     + _frame(4, payload))


@pytest.mark.parametrize("image,offset", [
    (None, 1), (IMAGE, None), ("AB" * 32, 1), ("a" * 63, 1),
    ("gg" * 32, 1), (IMAGE, -1), (IMAGE, 1 << 64), (IMAGE, True),
])
def test_fault_site_rejects_malformed_pairs(image, offset):
    with pytest.raises(ValueError):
        verifier.TracerFaultReference(0, "provenance-access", image, offset)


def test_historical_snapshot_remains_readable_but_not_current():
    row = ("[snapshot] [fault-reference] [version 2] [valid true] "
           "[source guest-signal] [address 0]\n")
    reference = verifier.read_snapshot_fault_reference(row)
    assert reference.identity_key == ("main", 0)
    assert reference.image_id is None
    with pytest.raises(ValueError, match="fresh run"):
        verifier.read_snapshot_fault_reference(row, require_current=True)
    with pytest.raises(ValueError, match="historical snapshot"):
        verifier.read_snapshot_fault_reference(row.rstrip() + f" [image {IMAGE}] [image-offset 123]")


def test_historical_text_expansion_preserves_main_identity(tmp_path):
    trace = tmp_path / "old.sbsv"
    trace.write_text(
        "[binradar] [crash] [iter 1] [patch 0] [guest_pc 0] "
        "[guest_cs_base 0] [fault_addr 0] [host_fault_addr 0]\n"
        "[binradar] [commit] [iter 1] [patch 0] [br 1]\n")
    _, results = next(binradar_results.iter_legacy_binradar_results(str(trace)))
    assert binradar_results._fault_identity_key(results[0]) == ("main", 0)


def test_precise_identity_roundtrip_and_domains():
    original = verifier.TracerFaultReference(0x7000123, "provenance-access", IMAGE, 0x123)
    relocated = verifier.TracerFaultReference(0x9000123, "provenance-access", IMAGE, 0x123)
    assert original.identity_key == relocated.identity_key
    for other in (
            verifier.TracerFaultReference(original.address, "provenance-access", OTHER_IMAGE, 0x123),
            verifier.TracerFaultReference(original.address, "provenance-access", IMAGE, 0x124),
            verifier.TracerFaultReference(original.address, "guest-signal")):
        assert original.identity_key != other.identity_key
    probe = verifier.BinRadarProbeResult(0, 0, [], "crash", 1, 1, 0, [], original,
                                        verifier.MEMCHECK_POLICY)
    restored = verifier.BinRadarProbeResult.deserialize("[probe-info] " + probe.serialize())
    restored.require_current_memcheck_policy()
    assert restored.tracer_fault_reference == original
    assert verifier.TracerFaultReference(0, "guest-signal").identity_key == ("main", 0)


@pytest.mark.parametrize("fields", [
    {}, {"tracer-fault-image": IMAGE}, {"tracer-fault-image-offset": 1},
    {"tracer-fault-image": "none", "tracer-fault-image-offset": 1},
])
def test_probe_v3_requires_complete_site_fields(fields):
    row = {"version": 3, "tracer-fault-valid": True,
           "tracer-fault-source": "provenance-access", "tracer-fault-addr": 0}
    row.update(fields)
    with pytest.raises(ValueError):
        verifier._decode_tracer_fault_reference(row)


@pytest.mark.parametrize("version", [1, 2])
def test_old_evidence_rejects_site_flag(version, tmp_path):
    path = tmp_path / "old.br"
    _write(path, struct.pack("<II", 1, 1) + _site_group(0x7000123), version)
    with pytest.raises(evidence.EvidenceError, match="flags"):
        list(evidence.read_binradar(path))


def test_evidence_converter_preserves_site_and_crc(tmp_path):
    path = tmp_path / "sites.br"
    payload = struct.pack("<II", 1, 1) + _site_group(0x7000123)
    _write(path, payload)
    group = next(evidence.read_binradar(path)).groups[0]
    assert (group.image_id, group.image_offset) == (IMAGE, 0x123)
    output = subprocess.run([sys.executable, str(ROOT / "fuzzolic" / "binradar-evidence-to-text.py"),
                             str(path)], check=True, text=True, capture_output=True).stdout
    text = tmp_path / "converted.sbsv"
    text.write_text(output)
    _, expanded = next(binradar_results.iter_legacy_binradar_results(str(text)))
    assert binradar_results._fault_identity_key(expanded[0]) == ("image", IMAGE, 0x123)
    corrupt = bytearray(path.read_bytes())
    corrupt[evidence.HEADER_STRUCT.size + evidence.FRAME_HEADER_STRUCT.size
            + evidence.BINRADAR_ITERATION_STRUCT.size + evidence.BINRADAR_GROUP_STRUCT.size] ^= 1
    path.write_bytes(corrupt)
    with pytest.raises(evidence.EvidenceError, match="checksum"):
        list(evidence.read_binradar(path))


@pytest.mark.parametrize("length", [0, 1, 31, 32, 39])
def test_committed_truncated_site_is_rejected(length, tmp_path):
    path = tmp_path / "short.br"
    group = _site_group(0x7000123)
    payload = struct.pack("<II", 1, 1) + group[:evidence.BINRADAR_GROUP_STRUCT.size + length]
    _write(path, payload)
    with pytest.raises(evidence.EvidenceError, match="fault site"):
        list(evidence.read_binradar(path))


def test_uncommitted_truncated_site_tail_is_ignored(tmp_path):
    path = tmp_path / "tail.br"
    baseline = struct.pack("<II", 1, 1) + _site_group(0x7000123)
    _write(path, baseline)
    mutation = struct.pack("<II", 2, 1) + _site_group(0x9000123)
    complete = _frame(4, mutation)
    for length in (1, 7, 8, 8 + evidence.BINRADAR_ITERATION_STRUCT.size
                   + evidence.BINRADAR_GROUP_STRUCT.size + 39, len(complete) - 1):
        _write(path, baseline)
        path.write_bytes(path.read_bytes() + complete[:length])
        assert [frame.iteration for frame in evidence.read_binradar(path)] == [1]


def test_normal_outcome_cannot_carry_site(tmp_path):
    path = tmp_path / "normal.br"
    _write(path, struct.pack("<II", 1, 1) + _site_group(0, outcome=1))
    with pytest.raises(evidence.EvidenceError, match="normal"):
        list(evidence.read_binradar(path))


@pytest.mark.parametrize("image,offset,expected", [
    (IMAGE, 0x123, True), (OTHER_IMAGE, 0x123, False), (IMAGE, 0x124, False),
])
def test_final_compares_dso_site_not_raw_pc(tmp_path, image, offset, expected):
    reference = verifier.TracerFaultReference(0x7000123, "provenance-access", IMAGE, 0x123)
    baseline = struct.pack("<II", 1, 1) + _site_group(0x9000123)
    child = bytearray(_site_group(reference.address, image, offset))
    struct.pack_into("<I", child, 0, 1)
    child[-1] = 1
    mutation = struct.pack("<II", 2, 2) + _site_group(0x9000123) + bytes(child)
    (tmp_path / "binradar.br").write_bytes(
        evidence.HEADER_STRUCT.pack(evidence.MAGIC, 3, 3, 0)
        + _frame(4, baseline) + _frame(4, mutation))
    evidence.write_verifier(tmp_path / "verifier.br", [evidence.VerifierPatchResult(
        1, True, 0, 0, {})])
    binradar_results.write_final_result(_final_request(tmp_path, [1], reference))
    report = (tmp_path / "final.sbsv").read_text()
    assert ("[reason same-crash]" in report) is expected
    assert "[original-poc-crash 2]" in report
    assert f"[image {IMAGE}] [image-offset 123]" in report


@pytest.mark.parametrize("image,offset,expected", [
    (IMAGE, 0x123, binradar_baseline.BaselineStatus.REPRODUCED),
    (OTHER_IMAGE, 0x123, binradar_baseline.BaselineStatus.DIFFERENT_FAULT),
    (IMAGE, 0x124, binradar_baseline.BaselineStatus.DIFFERENT_FAULT),
])
def test_baseline_compares_dso_sites_across_aslr(image, offset, expected):
    result = SimpleNamespace(success=True, exit_code=-11, stderr=(
        "[memcheck] [policy coverage-v2]\n"
        "[snapshot] [fault-reference] [version 3] [valid true] "
        f"[source provenance-access] [address 9000123] [image {image}] [image-offset {offset:x}]\n"))
    reference = verifier.TracerFaultReference(0x7000123, "provenance-access", IMAGE, 0x123)
    check = binradar_baseline._classify(".orig", result, reference, [], "", 0)
    assert check.status == expected


def test_feedback_exports_only_matching_dso_sites(tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    executor.probe_result.tracer_fault_reference = verifier.TracerFaultReference(
        0x7000123, "provenance-access", IMAGE, 0x123)
    rows = []
    for index, (image, offset, pc) in enumerate([
            (IMAGE, 0x123, 0x9000123), (OTHER_IMAGE, 0x123, 0x7000123),
            (IMAGE, 0x124, 0x7000123)]):
        name = f"{index}_site"
        (run_dir / "minimized" / name).write_bytes(bytes([index]))
        rows.append(_full_row(index, name, "crash", pc).replace(
            "[tracer-fault-image none] [tracer-fault-image-offset 0]",
            f"[tracer-fault-image {image}] [tracer-fault-image-offset {offset:x}]"))
    (run_dir / "minimizer.sbsv").write_text("".join(rows))
    executor.run_feedback()
    assert [p.name for p in (run_dir / "feedback" / "concrete" / "malicious").iterdir()] == ["0_site"]


def test_plan_diagnostics_compare_sites_and_preserve_main_history():
    import binradar
    row = {"patch0-exit": "crash", "patch0-fault-valid": "true",
           "patch0-fault-source": "provenance-access", "patch0-fault-addr": "9000123"}
    reference = verifier.TracerFaultReference(0x7000123, "provenance-access", IMAGE, 0x123)
    assert binradar._classify_plan_attempt_outcome(row, reference) == "unclassified-crash"
    row.update({"patch0-fault-image": IMAGE, "patch0-fault-image-offset": "123"})
    assert binradar._classify_plan_attempt_outcome(row, reference) == "poc-crash"
    row["patch0-fault-image"] = OTHER_IMAGE
    assert binradar._classify_plan_attempt_outcome(row, reference) == "other-crash"
    row["patch0-fault-image"] = "unknown"
    assert binradar._classify_plan_attempt_outcome(row, reference) == "unclassified-crash"
    del row["patch0-fault-image"]
    del row["patch0-fault-image-offset"]
    main = verifier.TracerFaultReference(0x9000123, "guest-signal")
    assert binradar._classify_plan_attempt_outcome(row, main) == "poc-crash"


def _feedback_header(child_image=IMAGE, child_offset="123", pc="9000123", outcome="crash", same="true"):
    return ("[binradar-feedback] [version 3] "
            f"[outcome {outcome}] [fault-addr {pc}] [fault-valid true] "
            f"[fault-source provenance-access] [fault-image {child_image}] "
            f"[fault-image-offset {child_offset}] [poc-fault-addr 7000123] "
            f"[poc-fault-valid true] [poc-fault-source provenance-access] "
            f"[poc-fault-image {IMAGE}] [poc-fault-image-offset 123] [same-fault {same}]")


def test_feedback_sidecar_uses_precise_identity():
    binradar_feedback._validate_feedback_identity(_feedback_header())
    binradar_feedback._validate_feedback_identity(_feedback_header(OTHER_IMAGE, same="false"))
    binradar_feedback._validate_feedback_identity(_feedback_header(child_offset="124", same="false"))
    with pytest.raises(ValueError, match="same-fault"):
        binradar_feedback._validate_feedback_identity(_feedback_header(OTHER_IMAGE, pc="7000123"))


@pytest.mark.parametrize("line", [
    _feedback_header().replace(f"[fault-image {IMAGE}] ", ""),
    _feedback_header().replace("[fault-image-offset 123] ", ""),
    _feedback_header("AB" * 32), _feedback_header(child_offset="-1"),
    _feedback_header(outcome="normal"),
])
def test_feedback_sidecar_rejects_missing_malformed_or_normal_sites(line):
    with pytest.raises(ValueError):
        binradar_feedback._validate_feedback_identity(line)


def test_standalone_reader_preserves_dso_reference():
    from test_binradar_test import binradar_test
    reference = binradar_test.extract_tracer_fault_reference(
        "[snapshot] [fault-reference] [version 3] [valid true] "
        f"[source provenance-access] [address 9000123] [image {IMAGE}] [image-offset 123]\n")
    assert reference.identity_key == ("image", IMAGE, 0x123)
    assert reference.address == 0x9000123


@pytest.mark.parametrize("version", [1, 2])
def test_old_feedback_pairs_are_not_reexported(version, tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    directory = run_dir / "binradar-feedback"
    directory.mkdir()
    (directory / "old.sbsv").write_text(f"[binradar-feedback] [version {version}]\n")
    with pytest.raises(ValueError, match="fresh run"):
        executor.run_feedback()
