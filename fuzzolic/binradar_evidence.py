"""Compact, checksummed evidence files for BinRadar phases.

The format is deliberately small and dependency-free so the tracer can emit
BINRADAR iteration frames directly.  Multi-byte integers are little-endian.
Each file starts with ``HEADER_STRUCT`` and contains length-delimited frames;
the CRC covers the frame type, flags, and payload.  FILTER and VERIFIER files
are written atomically.  BINRADAR is append-only, so readers may ignore one
truncated final frame while rejecting corruption in every complete frame.
"""

from __future__ import annotations

import dataclasses
import enum
import os
import struct
import tempfile
import zlib
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import BinaryIO

MAGIC = b"BRDATAB1"
VERSION = 1
HEADER_STRUCT = struct.Struct("<8sHHI")
FRAME_HEADER_STRUCT = struct.Struct("<IHH")
FRAME_CRC_STRUCT = struct.Struct("<I")
MAX_FRAME_SIZE = 256 * 1024 * 1024


class EvidenceError(ValueError):
    """The evidence file is truncated, corrupt, or violates its schema."""


class EvidenceKind(enum.IntEnum):
    FILTER = 1
    VERIFIER = 2
    BINRADAR = 3


class RecordType(enum.IntEnum):
    FILTER_RESULT = 1
    VERIFIER_RESULT = 2
    VERIFIER_STOP = 3
    BINRADAR_ITERATION = 4


FILTER_PREFIX_STRUCT = struct.Struct("<III")
VERIFIER_PREFIX_STRUCT = struct.Struct("<IIQQ")
VERIFIER_COUNT_STRUCT = struct.Struct("<I")
VERIFIER_TESTCASE_LENGTH_STRUCT = struct.Struct("<H")
BINRADAR_ITERATION_STRUCT = struct.Struct("<II")
BINRADAR_GROUP_STRUCT = struct.Struct("<IBBHQII")

VERIFIER_FLAG_VERIFIED = 1 << 0
VERIFIER_FLAG_HAS_FEEDBACK = 1 << 1
VERIFIER_FLAG_FEEDBACK_ACCEPTED = 1 << 2
VERIFIER_FLAG_SECURITY_REJECTED = 1 << 3
BINRADAR_GROUP_BRANCH_NULL = 1 << 0

OUTCOME_NORMAL = 1
OUTCOME_CRASH = 2

OBSERVATION_NAMES = (
    "patch-crashed",
    "crash-skip-diff-addr",
    "crash-fail",
    "crash-pass",
    "crash-timeout",
    "no-crash-skip-diff-addr",
    "no-crash-fail",
    "no-crash-pass-same-br",
    "no-crash-confidence-diff-br",
    "no-crash-timeout",
)


@dataclasses.dataclass(frozen=True)
class FilterResult:
    total: int
    passed: list[int]

    @property
    def decisions(self) -> dict[int, bool]:
        selected = set(self.passed)
        return {patch: patch in selected for patch in range(1, self.total + 1)}


@dataclasses.dataclass(frozen=True)
class VerifierPatchResult:
    patch: int
    verified: bool
    accept_evidences: int
    total_evidences: int
    observations: Mapping[str, int]
    testcase: str = ""
    has_feedback: bool = False
    feedback_accepted: bool = False
    security_rejected: bool = False


@dataclasses.dataclass(frozen=True)
class VerifierResult:
    patches: dict[int, VerifierPatchResult]
    stop_reason: str | None


@dataclasses.dataclass(frozen=True)
class BinradarGroup:
    representative: int
    outcome: str
    fault_addr: int
    branches: list[int] | None
    members: list[int]


@dataclasses.dataclass(frozen=True)
class BinradarIteration:
    iteration: int
    groups: list[BinradarGroup]


def _frame_crc(record_type: int, flags: int, payload: bytes) -> int:
    prefix = struct.pack("<HH", record_type, flags)
    return zlib.crc32(payload, zlib.crc32(prefix)) & 0xFFFFFFFF


def _write_header(stream: BinaryIO, kind: EvidenceKind) -> None:
    stream.write(HEADER_STRUCT.pack(MAGIC, VERSION, int(kind), 0))


def _write_frame(stream: BinaryIO, record_type: RecordType,
                 payload: bytes, flags: int = 0) -> None:
    if len(payload) > MAX_FRAME_SIZE:
        raise EvidenceError(f"evidence frame too large: {len(payload)} bytes")
    stream.write(FRAME_HEADER_STRUCT.pack(len(payload), int(record_type), flags))
    stream.write(payload)
    stream.write(FRAME_CRC_STRUCT.pack(
        _frame_crc(int(record_type), flags, payload)))


def _atomic_writer(path: os.PathLike[str] | str, kind: EvidenceKind,
                   frames: Iterable[tuple[RecordType, bytes, int]]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp",
        dir=str(destination.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            _write_header(stream, kind)
            for record_type, payload, flags in frames:
                _write_frame(stream, record_type, payload, flags)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _open_frames(path: os.PathLike[str] | str, expected: EvidenceKind,
                 *, allow_truncated_tail: bool = False
                 ) -> Iterator[tuple[RecordType, int, bytes]]:
    with open(path, "rb") as stream:
        header = stream.read(HEADER_STRUCT.size)
        if len(header) != HEADER_STRUCT.size:
            raise EvidenceError("truncated evidence header")
        magic, version, kind, reserved = HEADER_STRUCT.unpack(header)
        if magic != MAGIC:
            raise EvidenceError("invalid evidence magic")
        if version != VERSION:
            raise EvidenceError(f"unsupported evidence version {version}")
        if kind != int(expected):
            raise EvidenceError(
                f"evidence kind mismatch: expected {int(expected)}, got {kind}")
        if reserved != 0:
            raise EvidenceError("nonzero reserved evidence header field")

        while True:
            frame_header = stream.read(FRAME_HEADER_STRUCT.size)
            if not frame_header:
                return
            if len(frame_header) != FRAME_HEADER_STRUCT.size:
                if allow_truncated_tail:
                    return
                raise EvidenceError("truncated evidence frame header")
            length, raw_type, flags = FRAME_HEADER_STRUCT.unpack(frame_header)
            if length > MAX_FRAME_SIZE:
                raise EvidenceError(f"evidence frame too large: {length} bytes")
            payload = stream.read(length)
            checksum = stream.read(FRAME_CRC_STRUCT.size)
            if len(payload) != length or len(checksum) != FRAME_CRC_STRUCT.size:
                if allow_truncated_tail:
                    return
                raise EvidenceError("truncated evidence frame")
            expected_crc, = FRAME_CRC_STRUCT.unpack(checksum)
            actual_crc = _frame_crc(raw_type, flags, payload)
            if actual_crc != expected_crc:
                raise EvidenceError(
                    f"evidence frame checksum mismatch: {actual_crc:#x} != "
                    f"{expected_crc:#x}")
            try:
                record_type = RecordType(raw_type)
            except ValueError as exc:
                raise EvidenceError(
                    f"unknown evidence record type {raw_type}") from exc
            yield record_type, flags, payload


def write_filter(path: os.PathLike[str] | str, total: int,
                 passed: Iterable[int]) -> None:
    if total < 0 or total > 0xFFFFFFFF:
        raise EvidenceError(f"invalid filter candidate count {total}")
    selected = sorted(set(passed))
    if selected and (selected[0] < 1 or selected[-1] > total):
        raise EvidenceError("filter survivor id is outside the candidate range")
    bitmap_size = (total + 7) // 8
    if FILTER_PREFIX_STRUCT.size + bitmap_size > MAX_FRAME_SIZE:
        raise EvidenceError("filter bitmap exceeds the maximum frame size")
    bitmap = bytearray(bitmap_size)
    for patch in selected:
        bitmap[(patch - 1) // 8] |= 1 << ((patch - 1) % 8)
    payload = FILTER_PREFIX_STRUCT.pack(total, len(selected), len(bitmap)) \
        + bytes(bitmap)
    _atomic_writer(path, EvidenceKind.FILTER,
                   [(RecordType.FILTER_RESULT, payload, 0)])


def read_filter(path: os.PathLike[str] | str) -> FilterResult:
    frames = list(_open_frames(path, EvidenceKind.FILTER))
    if len(frames) != 1 or frames[0][0] != RecordType.FILTER_RESULT \
            or frames[0][1] != 0:
        raise EvidenceError("filter evidence must contain one result frame")
    payload = frames[0][2]
    if len(payload) < FILTER_PREFIX_STRUCT.size:
        raise EvidenceError("truncated filter result")
    total, passed_count, bitmap_size = FILTER_PREFIX_STRUCT.unpack_from(payload)
    expected_size = (total + 7) // 8
    bitmap = payload[FILTER_PREFIX_STRUCT.size:]
    if bitmap_size != expected_size or len(bitmap) != bitmap_size:
        raise EvidenceError("invalid filter bitmap size")
    if total % 8 and bitmap and bitmap[-1] & ~((1 << (total % 8)) - 1):
        raise EvidenceError("filter bitmap sets ids past the candidate count")
    passed = [patch for patch in range(1, total + 1)
              if bitmap[(patch - 1) // 8] & (1 << ((patch - 1) % 8))]
    if len(passed) != passed_count:
        raise EvidenceError("filter survivor count does not match bitmap")
    return FilterResult(total, passed)


def _verifier_payload(result: VerifierPatchResult) -> bytes:
    if result.patch <= 0 or result.patch > 0xFFFFFFFF:
        raise EvidenceError(f"invalid verifier patch id {result.patch}")
    if (result.accept_evidences < 0
            or result.total_evidences < result.accept_evidences
            or result.total_evidences > 0xFFFFFFFFFFFFFFFF):
        raise EvidenceError("invalid verifier evidence counts")
    if result.feedback_accepted and not result.has_feedback:
        raise EvidenceError("accepted feedback flag requires feedback")
    flags = 0
    if result.verified:
        flags |= VERIFIER_FLAG_VERIFIED
    if result.has_feedback:
        flags |= VERIFIER_FLAG_HAS_FEEDBACK
    if result.feedback_accepted:
        flags |= VERIFIER_FLAG_FEEDBACK_ACCEPTED
    if result.security_rejected:
        flags |= VERIFIER_FLAG_SECURITY_REJECTED
    testcase = result.testcase.encode("utf-8")
    if len(testcase) > 0xFFFF:
        raise EvidenceError("verifier testcase name is too long")
    payload = bytearray(VERIFIER_PREFIX_STRUCT.pack(
        result.patch, flags, result.accept_evidences,
        result.total_evidences))
    for name in OBSERVATION_NAMES:
        count = int(result.observations.get(name, 0))
        if count < 0 or count > 0xFFFFFFFF:
            raise EvidenceError(
                f"invalid verifier observation count {name}={count}")
        payload.extend(VERIFIER_COUNT_STRUCT.pack(count))
    payload.extend(VERIFIER_TESTCASE_LENGTH_STRUCT.pack(len(testcase)))
    payload.extend(testcase)
    return bytes(payload)


def write_verifier(path: os.PathLike[str] | str,
                   patches: Iterable[VerifierPatchResult],
                   stop_reason: str | None = None) -> None:
    ordered = sorted(patches, key=lambda result: result.patch)
    if len({result.patch for result in ordered}) != len(ordered):
        raise EvidenceError("duplicate verifier patch result")
    frames: list[tuple[RecordType, bytes, int]] = [
        (RecordType.VERIFIER_RESULT, _verifier_payload(result), 0)
        for result in ordered
    ]
    if stop_reason is not None:
        frames.append((RecordType.VERIFIER_STOP,
                       stop_reason.encode("utf-8"), 0))
    _atomic_writer(path, EvidenceKind.VERIFIER, frames)


def read_verifier(path: os.PathLike[str] | str) -> VerifierResult:
    patches: dict[int, VerifierPatchResult] = {}
    stop_reason: str | None = None
    fixed_size = (VERIFIER_PREFIX_STRUCT.size
                  + len(OBSERVATION_NAMES) * VERIFIER_COUNT_STRUCT.size
                  + VERIFIER_TESTCASE_LENGTH_STRUCT.size)
    for record_type, flags, payload in _open_frames(
            path, EvidenceKind.VERIFIER):
        if flags != 0:
            raise EvidenceError("nonzero verifier frame flags")
        if record_type == RecordType.VERIFIER_STOP:
            if stop_reason is not None:
                raise EvidenceError("duplicate verifier stop frame")
            try:
                stop_reason = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise EvidenceError("invalid verifier stop reason") from exc
            continue
        if record_type != RecordType.VERIFIER_RESULT:
            raise EvidenceError(
                f"unexpected verifier record {record_type.name}")
        if len(payload) < fixed_size:
            raise EvidenceError("truncated verifier result")
        patch, result_flags, accepted, total = \
            VERIFIER_PREFIX_STRUCT.unpack_from(payload)
        unknown_flags = result_flags & ~(
            VERIFIER_FLAG_VERIFIED | VERIFIER_FLAG_HAS_FEEDBACK
            | VERIFIER_FLAG_FEEDBACK_ACCEPTED
            | VERIFIER_FLAG_SECURITY_REJECTED)
        if unknown_flags:
            raise EvidenceError("unknown verifier result flags")
        if (result_flags & VERIFIER_FLAG_FEEDBACK_ACCEPTED
                and not result_flags & VERIFIER_FLAG_HAS_FEEDBACK):
            raise EvidenceError("accepted feedback flag lacks feedback record")
        if patch == 0 or patch in patches or accepted > total:
            raise EvidenceError("invalid or duplicate verifier result")
        offset = VERIFIER_PREFIX_STRUCT.size
        observations: dict[str, int] = {}
        for name in OBSERVATION_NAMES:
            count, = VERIFIER_COUNT_STRUCT.unpack_from(payload, offset)
            offset += VERIFIER_COUNT_STRUCT.size
            observations[name] = count
        testcase_length, = VERIFIER_TESTCASE_LENGTH_STRUCT.unpack_from(
            payload, offset)
        offset += VERIFIER_TESTCASE_LENGTH_STRUCT.size
        if offset + testcase_length != len(payload):
            raise EvidenceError("invalid verifier testcase length")
        try:
            testcase = payload[offset:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EvidenceError("invalid verifier testcase name") from exc
        patches[patch] = VerifierPatchResult(
            patch=patch,
            verified=bool(result_flags & VERIFIER_FLAG_VERIFIED),
            accept_evidences=accepted,
            total_evidences=total,
            observations=observations,
            testcase=testcase,
            has_feedback=bool(result_flags & VERIFIER_FLAG_HAS_FEEDBACK),
            feedback_accepted=bool(
                result_flags & VERIFIER_FLAG_FEEDBACK_ACCEPTED),
            security_rejected=bool(
                result_flags & VERIFIER_FLAG_SECURITY_REJECTED),
        )
    return VerifierResult(patches, stop_reason)


def _read_uleb128(payload: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if offset >= len(payload):
            raise EvidenceError("truncated candidate-id varint")
        byte = payload[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value > 0xFFFFFFFF:
                raise EvidenceError("candidate-id varint overflows uint32")
            return value, offset
        shift += 7
    raise EvidenceError("candidate-id varint is too long")


def _unpack_branches(data: bytes, count: int) -> list[int]:
    expected = (count + 3) // 4
    if len(data) != expected:
        raise EvidenceError("invalid packed branch-vector size")
    result = [(data[index // 4] >> ((index % 4) * 2)) & 0x3
              for index in range(count)]
    if any(branch > 2 for branch in result):
        raise EvidenceError("invalid branch value in packed vector")
    if count % 4 and data and data[-1] >> ((count % 4) * 2):
        raise EvidenceError("nonzero branch-vector padding")
    return result


def _parse_binradar_iteration(payload: bytes) -> BinradarIteration:
    if len(payload) < BINRADAR_ITERATION_STRUCT.size:
        raise EvidenceError("truncated BINRADAR iteration")
    iteration, group_count = BINRADAR_ITERATION_STRUCT.unpack_from(payload)
    if iteration == 0:
        raise EvidenceError("BINRADAR iteration id must be positive")
    offset = BINRADAR_ITERATION_STRUCT.size
    groups: list[BinradarGroup] = []
    seen_members: set[int] = set()
    for _ in range(group_count):
        if offset + BINRADAR_GROUP_STRUCT.size > len(payload):
            raise EvidenceError("truncated BINRADAR group")
        representative, outcome_value, group_flags, reserved, fault_addr, \
            branch_count, member_count = BINRADAR_GROUP_STRUCT.unpack_from(
                payload, offset)
        offset += BINRADAR_GROUP_STRUCT.size
        if reserved != 0 or group_flags & ~BINRADAR_GROUP_BRANCH_NULL:
            raise EvidenceError("invalid BINRADAR group flags")
        if outcome_value not in (OUTCOME_NORMAL, OUTCOME_CRASH):
            raise EvidenceError("invalid BINRADAR outcome")
        if member_count == 0:
            raise EvidenceError("empty BINRADAR equivalence group")
        branch_size = (branch_count + 3) // 4
        if offset + branch_size > len(payload):
            raise EvidenceError("truncated BINRADAR branch vector")
        packed_branches = payload[offset:offset + branch_size]
        offset += branch_size
        branch_null = bool(group_flags & BINRADAR_GROUP_BRANCH_NULL)
        if branch_null and branch_count != 0:
            raise EvidenceError("null BINRADAR branch vector has values")
        branches = None if branch_null else _unpack_branches(
            packed_branches, branch_count)
        members: list[int] = []
        previous = 0
        for index in range(member_count):
            delta, offset = _read_uleb128(payload, offset)
            member = delta if index == 0 else previous + delta
            if member > 0xFFFFFFFF or (index > 0 and member <= previous):
                raise EvidenceError("unordered BINRADAR group members")
            if member in seen_members:
                raise EvidenceError("duplicate BINRADAR group member")
            seen_members.add(member)
            members.append(member)
            previous = member
        if representative not in members:
            raise EvidenceError("BINRADAR representative is not a group member")
        groups.append(BinradarGroup(
            representative=representative,
            outcome="crash" if outcome_value == OUTCOME_CRASH else "normal",
            fault_addr=fault_addr,
            branches=branches,
            members=members,
        ))
    if offset != len(payload):
        raise EvidenceError("trailing bytes in BINRADAR iteration")
    if not groups:
        raise EvidenceError("BINRADAR iteration has no groups")
    return BinradarIteration(iteration, groups)


def read_binradar(path: os.PathLike[str] | str) -> Iterator[BinradarIteration]:
    previous_iteration = 0
    for record_type, flags, payload in _open_frames(
            path, EvidenceKind.BINRADAR, allow_truncated_tail=True):
        if record_type != RecordType.BINRADAR_ITERATION or flags != 0:
            raise EvidenceError("unexpected BINRADAR evidence frame")
        iteration = _parse_binradar_iteration(payload)
        if iteration.iteration != previous_iteration + 1:
            raise EvidenceError("BINRADAR iterations are not contiguous")
        previous_iteration = iteration.iteration
        yield iteration


def evidence_kind(path: os.PathLike[str] | str) -> EvidenceKind:
    with open(path, "rb") as stream:
        header = stream.read(HEADER_STRUCT.size)
    if len(header) != HEADER_STRUCT.size:
        raise EvidenceError("truncated evidence header")
    magic, version, raw_kind, reserved = HEADER_STRUCT.unpack(header)
    if magic != MAGIC or version != VERSION or reserved != 0:
        raise EvidenceError("invalid evidence header")
    try:
        return EvidenceKind(raw_kind)
    except ValueError as exc:
        raise EvidenceError(f"unknown evidence kind {raw_kind}") from exc
