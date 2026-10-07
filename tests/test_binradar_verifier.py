#!/usr/bin/env python3
"""Regression tests for typed BinRadar tracer fault references."""

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_verifier


def _probe(reference):
    return binradar_verifier.BinRadarProbeResult(
        patch_loc=0x1000,
        patch_func_entry=0x2000,
        stacktrace=[(0x30, "frame")],
        exit_info="crash",
        patch_hit_cnt=1,
        patch_func_hit_cnt=1,
        fault_addr=0,
        patch_func_candidates=[],
        tracer_fault_reference=reference,
    )


def test_valid_pc_zero_reference_round_trips():
    original = _probe(
        binradar_verifier.TracerFaultReference(0, "guest-signal"))
    restored = binradar_verifier.BinRadarProbeResult.deserialize(
        "[probe-info] " + original.serialize())

    assert restored is not None
    assert restored.tracer_fault_reference == \
        binradar_verifier.TracerFaultReference(0, "guest-signal")
    assert restored.tracer_fault_reference.valid
    assert restored.stacktrace == [(0x30, "frame")]


def test_invalid_v2_reference_discards_address():
    restored = binradar_verifier.BinRadarProbeResult.deserialize(
        "[probe-info] [version 2] [exit crash] [patch-loc 1000] "
        "[func-entry 2000] [patch-hit 1] [func-hit 1] [fault-addr 0] "
        "[tracer-fault-valid false] [tracer-fault-source unavailable] "
        "[tracer-fault-addr 0] [patch-func-candidates []] "
        "[stacktrace []]")

    assert restored is not None
    assert restored.tracer_fault_reference is None


def test_legacy_zero_is_unavailable_and_nonzero_unvalidated(tmp_path):
    def load(address):
        return binradar_verifier.BinRadarProbeResult.from_sbsv(
            str(_write_legacy_probe(tmp_path, address)))

    zero = load(0)
    assert zero is not None
    assert zero.tracer_fault_reference is None
    with pytest.raises(ValueError):
        zero.serialize()

    legacy = load(0xDEAD)
    assert legacy is not None
    assert legacy.tracer_fault_reference is not None
    assert legacy.tracer_fault_reference.address == 0xDEAD
    assert legacy.tracer_fault_reference.source == "legacy-unvalidated"
    assert not legacy.tracer_fault_reference.valid
    with pytest.raises(ValueError):
        legacy.serialize()


def _write_legacy_probe(tmp_path: Path, address: int) -> Path:
    path = tmp_path / f"probe-{address:x}.sbsv"
    path.write_text(
        "[probe-info] [exit crash] [patch-loc 1000] [func-entry 2000] "
        "[patch-hit 1] [func-hit 1] [fault-addr 0] "
        f"[tracer-fault-addr {address:x}] [patch-func-candidates []] "
        "[stacktrace []]\n[file-trace] [need-file-hook false]\n",
        encoding="utf-8",
    )
    return path


def test_new_policy_restoration_preserves_valid_pc_zero(tmp_path):
    original = _probe(binradar_verifier.TracerFaultReference(0, "guest-signal"))
    original.memcheck_policy = "coverage-v2"
    path = tmp_path / "current.sbsv"
    path.write_text("[probe-info] " + original.serialize()
                    + "\n[file-trace] [need-file-hook false]\n")
    restored = binradar_verifier.BinRadarProbeResult.from_sbsv(str(path))
    restored.require_current_memcheck_policy()
    assert restored.memcheck_policy == "coverage-v2"
    assert restored.tracer_fault_reference == original.tracer_fault_reference
    assert restored._probe_serialization_version == 4


@pytest.mark.parametrize("policy", [None, "coverage-v1", "older-policy", "unavailable"])
def test_freshness_rejects_unacknowledged_or_mismatched_policy(policy):
    probe = _probe(binradar_verifier.TracerFaultReference(0, "guest-signal"))
    probe.memcheck_policy = policy
    restored = binradar_verifier.BinRadarProbeResult.deserialize(
        "[probe-info] " + probe.serialize())
    with pytest.raises(ValueError, match="--run-id n"):
        restored.require_current_memcheck_policy()


def test_v2_valid_reference_is_historical_read_only(tmp_path):
    original = _probe(binradar_verifier.TracerFaultReference(0, "guest-signal"))
    row = original.serialize().replace("[version 4]", "[version 2]").replace(
        "[memcheck-policy unavailable] ", "").replace(
        "[tracer-fault-image none] [tracer-fault-image-offset 0] ", "")
    path = tmp_path / "historical.sbsv"
    path.write_text("[probe-info] " + row
                    + "\n[file-trace] [need-file-hook false]\n")
    for restored in (
            binradar_verifier.BinRadarProbeResult.from_sbsv(str(path)),
            binradar_verifier.BinRadarProbeResult.deserialize("[probe-info] " + row)):
        assert restored.tracer_fault_reference == original.tracer_fault_reference
        assert restored.memcheck_policy is None
        with pytest.raises(ValueError, match="--run-id n"):
            restored.require_current_memcheck_policy()
        with pytest.raises(ValueError, match="fresh data"):
            restored.serialize()


def _identity_runner(tmp_path, entries=None, *, artifact="brpatched"):
    import hashlib
    import json
    original = tmp_path / "target.orig"
    binary = tmp_path / ("target." + artifact)
    import struct
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    original.write_bytes(bytes(header) + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, 0, 0x3000, 0x1000))
    binary.write_bytes(artifact.encode())
    data = {"version": 1,
            "artifact-sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "original-sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
            "instructions": entries if entries is not None else
            [{"relocated": 0x9000, "original": 0x1000}]}
    sidecar = Path(str(binary) + ".e9map.json")
    sidecar.write_text(json.dumps(data))
    runner = binradar_verifier.BinRadarQemuRunner(
        str(tmp_path), "target", "", "0x1000",
        e9_metadata={artifact: ("0x9000-0xa000", ["0x9010:0x1000:0x1003"])})
    return runner, str(binary), sidecar, data


def _concrete_probe(pc, outcome="crash"):
    return binradar_verifier.BinRadarProbeResult.from_log(
        "[patch-info] [set true] [location 1000]\n"
        "[patch-cov] [location 1000] [covered true] [hits 1]\n"
        f"[qemu-exit] [kind {'crash' if outcome == 'crash' else 'end'}] [detail target]\n"
        f"[exit] [result {outcome}]\n"
        + (f"[fault-addr] [idx 0] [addr {pc:x}] [symbol target]\n" if pc is not None else ""))


@pytest.mark.parametrize("raw,canonical,source", [
    (0, 0, "native"), (0x1000, 0x1000, "native"),
    (0x9000, 0x1000, "relocated"), (0x9010, None, "unavailable"),
    (0x9001, None, "unavailable"), (0xb000, None, "unavailable")])
def test_exact_concrete_normalization_roundtrip(tmp_path, raw, canonical, source):
    runner, binary, _, _ = _identity_runner(tmp_path)
    probe = _concrete_probe(raw)
    runner._normalize_probe(probe, binary)
    restored = binradar_verifier.BinRadarProbeResult.deserialize("[probe-info] " + probe.serialize())
    assert restored.raw_fault_addr == raw
    assert restored.concrete_fault_source == source
    assert restored.concrete_fault_addr == canonical
    # Call triples are not an instruction-identity fallback at helper PC 9010.
    assert restored.fault_addr == (raw if canonical is None else canonical)


@pytest.mark.parametrize("defect", ["missing", "artifact", "original", "cross-artifact", "conflict", "bool", "outside"])
def test_concrete_map_rejects_missing_stale_and_malformed(tmp_path, defect):
    import json
    runner, binary, sidecar, data = _identity_runner(tmp_path)
    if defect == "missing":
        sidecar.unlink()
    elif defect == "artifact":
        Path(binary).write_bytes(b"changed")
    elif defect == "original":
        (tmp_path / "target.orig").write_bytes(b"changed")
    elif defect == "cross-artifact":
        binary = str(tmp_path / "target.brcached")
        Path(binary).write_bytes(b"cached")
        Path(binary + ".e9map.json").write_text(json.dumps(data))
    else:
        data["instructions"] = {
            "conflict": [{"relocated": 0x9000, "original": 0x1000}, {"relocated": 0x9000, "original": 0x2000}],
            "bool": [{"relocated": True, "original": 0x1000}],
            "outside": [{"relocated": 0x1000, "original": 0x2000}],
        }[defect]
        sidecar.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="rerun binradar-setup"):
        runner.concrete_fault_identity(0x9000, binary)


def test_original_does_not_require_map_and_loaded_artifact_is_cached(tmp_path):
    runner, binary, sidecar, _ = _identity_runner(tmp_path)
    assert runner.concrete_fault_identity(0, runner.original_binary()) == (0, "native")
    assert runner.concrete_fault_identity(0x9000, binary) == (0x1000, "relocated")
    sidecar.unlink()
    assert runner.concrete_fault_identity(0x9000, binary) == (0x1000, "relocated")


@pytest.mark.parametrize("raw,outcome,rejected", [(0x9000, "crash", True), (0x9010, "crash", False), (0x9000, "ok", False)])
def test_verifier_requires_proved_same_fault(tmp_path, raw, outcome, rejected):
    import logging
    runner, binary, _, _ = _identity_runner(tmp_path)
    verifier = binradar_verifier.BinRadarConcreteVerifier.__new__(binradar_verifier.BinRadarConcreteVerifier)
    verifier.probe_result = _concrete_probe(0x1000)
    verifier.logger = logging.getLogger("concrete-identity-test")
    verifier.observation_counts = {}
    verifier.accept_evidences = {}
    verifier.total_evidences = {}
    verifier.security_rejected = set()
    verifier.feedback_hard_rejected = set()
    verifier.feedback_mode = False
    probe = _concrete_probe(raw, outcome)
    runner._normalize_probe(probe, binary)
    testcase = binradar_verifier.Testcase(0, "poc", "crash", 0x1000, [0])
    assert verifier._test_result(1, testcase, probe, binradar_verifier.BinRadarPatchResult(1, [0])) is rejected
    assert (1 in verifier.security_rejected) is rejected
    assert (verifier._testcase_from_result_row({"id": 0, "file": "poc", "exit": "crash", "fault-addr": 0x1000, "br": [0]}) is None)


@pytest.mark.parametrize("version", [2, 3])
def test_historical_probe_cannot_claim_current_concrete_oracle(version):
    probe = _concrete_probe(0)
    row = "[probe-info] " + probe.serialize().replace("[version 4]", f"[version {version}]")
    if version == 2:
        row = row.replace("[tracer-fault-image none] [tracer-fault-image-offset 0] ", "").replace("[memcheck-policy unavailable] ", "")
    restored = binradar_verifier.BinRadarProbeResult.deserialize(row)
    assert restored.concrete_fault_addr is None
    with pytest.raises(ValueError, match="fresh data"):
        restored.serialize()


def test_concrete_only_probe_does_not_claim_tracer_policy():
    probe = binradar_verifier.BinRadarProbeResult.from_log(
        "[patch-info] [set true] [location 1000]\n[exit] [result crash]\n")
    restored = binradar_verifier.BinRadarProbeResult.deserialize(
        "[probe-info] " + probe.serialize())
    assert restored.memcheck_policy == "unavailable"
    assert restored.tracer_fault_reference is None
    with pytest.raises(ValueError, match="--run-id n"):
        restored.require_current_memcheck_policy()
