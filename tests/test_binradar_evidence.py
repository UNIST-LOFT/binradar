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


def _write_binradar(path: Path, *, truncated_tail: bool = False) -> None:
    baseline = (struct.pack("<II", 1, 1)
                + _group(0, 1, 0, [0], [0]))
    payload = (struct.pack("<II", 2, 2)
               + _group(0, 1, 0, [0, 1, 2, 1], [0])
               + _group(2, 2, 0x1234, [2, 0], [1, 2, 300]))
    data = (struct.pack("<8sHHI", b"BRDATAB1", 1, 3, 0)
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
    executor.probe_result = SimpleNamespace(tracer_fault_addr=0x1234)
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
