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
    assert restored._probe_serialization_version == 3


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
    row = original.serialize().replace("[version 3]", "[version 2]").replace(
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


def test_concrete_only_probe_does_not_claim_tracer_policy():
    probe = binradar_verifier.BinRadarProbeResult.from_log(
        "[patch-info] [set true] [location 1000]\n[exit] [result crash]\n")
    restored = binradar_verifier.BinRadarProbeResult.deserialize(
        "[probe-info] " + probe.serialize())
    assert restored.memcheck_policy == "unavailable"
    assert restored.tracer_fault_reference is None
    with pytest.raises(ValueError, match="--run-id n"):
        restored.require_current_memcheck_policy()
