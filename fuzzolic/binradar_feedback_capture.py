"""Single-writer concrete feedback journals and lossless ordered BRCH storage.

Baseline and verifier own separate per-input journals. Only complete records
reference atomically published, content-addressed states; a torn final journal
line never becomes evidence. Raw state never lives in suspended input sweeps.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence

from binradar_taosc_predicates import (
    CachedSnapshot, CACHED_SNAPSHOT_HEADER, CACHED_SNAPSHOT_MAGIC,
    CACHED_SNAPSHOT_VERSION, CACHED_SNAPSHOT_FLAG_CWE805,
    CACHED_SNAPSHOT_CLAMPS, CACHED_SNAPSHOT_REGS,
)

VERSION = 1
BINS = ("crash-fail", "crash-pass", "no-crash-pass-same-br",
        "no-crash-confidence-diff-br", "no-crash-fail", "patch-crashed")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]+\Z")


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encode_ids(ids) -> str:
    ordered = sorted(ids)
    if any(type(value) is not int or value < 1 for value in ordered):
        raise ValueError("feedback members must be positive integer ids")
    parts = []
    start = previous = None
    for value in ordered:
        if previous is not None and value == previous:
            raise ValueError("duplicate feedback member")
        if previous is not None and value == previous + 1:
            previous = value
            continue
        if previous is not None:
            parts.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = value
    if previous is not None:
        parts.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(parts) or "none"


def parse_id_ranges(text: str) -> list[tuple[int, int]]:
    """Validate sorted inclusive ranges without expanding their members."""
    if text == "none":
        return []
    result = []
    previous = 0
    for part in text.split(","):
        match = re.fullmatch(r"([1-9][0-9]*)(?:-([1-9][0-9]*))?", part)
        if match is None:
            raise ValueError("invalid feedback member range")
        start, end = int(match[1]), int(match[2] or match[1])
        if start <= previous or end < start or end > 0xffffffff:
            raise ValueError("unordered feedback member range")
        result.append((start, end))
        previous = end
    return result


def decode_ids(text: str, *, universe: set[int] | None = None) -> list[int]:
    result = []
    for start, end in parse_id_ranges(text):
        # A corrupt range must not allocate gigabytes before membership checks.
        if universe is None and end - start > 1_000_000:
            raise ValueError("feedback range requires a candidate universe")
        if universe is not None and end - start + 1 > len(universe):
            raise ValueError("feedback range exceeds candidate universe")
        for value in range(start, end + 1):
            if universe is not None and value not in universe:
                raise ValueError("feedback member outside candidate universe")
            result.append(value)
    return result


def pack_branches(branches: Sequence[int] | None) -> tuple[int, str]:
    if branches is None:
        return -1, "none"
    packed = bytearray((len(branches) + 3) // 4)
    for index, branch in enumerate(branches):
        if type(branch) is not int or branch not in (0, 1, 2):
            raise ValueError("invalid feedback branch")
        packed[index // 4] |= branch << (2 * (index % 4))
    return len(branches), packed.hex() or "none"


def unpack_branches(hits: int, packed: str) -> list[int] | None:
    if type(hits) is not int or hits < -1:
        raise ValueError("invalid feedback hit count")
    if hits <= 0:
        if packed != "none":
            raise ValueError("empty feedback vector has bytes")
        return None if hits == -1 else []
    if re.fullmatch(r"[0-9a-f]+", packed) is None or len(packed) != 2 * ((hits + 3) // 4):
        raise ValueError("invalid packed feedback vector length")
    raw = bytes.fromhex(packed)
    if hits % 4 and raw[-1] >> (2 * (hits % 4)):
        raise ValueError("nonzero feedback vector padding")
    result = [(raw[i // 4] >> (2 * (i % 4))) & 3 for i in range(hits)]
    if 3 in result:
        raise ValueError("invalid packed feedback branch")
    return result


def _atomic_json(path: Path, value) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".part-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def concrete_result(probe) -> dict:
    outcome = {"ok": "normal", "crash": "crash", "timeout": "timeout"}.get(
        probe.exit_info if probe is not None else None, "unusable")
    fault = probe.concrete_fault_addr if probe is not None else None
    return {
        "outcome": outcome,
        "oracle": getattr(probe, "concrete_oracle", None) or "unavailable",
        "fault_valid": fault is not None,
        "fault_addr": fault if fault is not None else 0,
        "fault_source": getattr(probe, "concrete_fault_source", "unavailable")
                        if fault is not None else "unavailable",
        "raw_fault_addr": getattr(probe, "raw_fault_addr", 0) if probe is not None else 0,
        "fault_image": "none", "fault_offset": 0,
    }


def write_mutation_context(run_dir: str, *, workdir: str, artifact: str,
                           candidates: Sequence[int], input_file: str) -> None:
    """Pin the actual tracer target before its mutation phase starts."""
    root = Path(run_dir) / "feedback-capture"
    root.mkdir(parents=True, exist_ok=True)
    context = {"version": VERSION, "candidates": encode_ids(candidates),
               "artifact": file_sha256(artifact), "artifact_name": Path(artifact).name,
               "input_sha256": file_sha256(input_file)}
    for name in ("brpatches.json", "binradar.env"):
        path = Path(workdir) / name
        context[name] = file_sha256(path) if path.is_file() else None
    _atomic_json(root / "mutation.json", context)


class CaptureJournal:
    """One producer's append-only observations, bounded to one group in memory."""

    def __init__(self, run_dir: str, channel: str, *, workdir: str,
                 candidates: Sequence[int], context: Mapping | None = None):
        if channel not in ("baseline", "verifier"):
            raise ValueError("invalid feedback capture channel")
        self.run_dir = Path(run_dir)
        self.root = self.run_dir / "feedback-capture"
        self.directory = self.root / channel
        self.channel = channel
        self.candidates = set(candidates)
        candidate_ranges = encode_ids(candidates)
        self._inputs: dict[int, tuple[str, str]] = {}
        self._sequences: dict[int, int] = {}
        self._artifacts: dict[str, str] = {}
        self._finished = False
        self.root.mkdir(parents=True, exist_ok=True)
        if self.directory.exists():
            shutil.rmtree(self.directory)
        self.directory.mkdir()
        (self.root / "states").mkdir(exist_ok=True)
        work = Path(workdir)
        header = {"version": VERSION, "channel": channel,
                  "candidates": candidate_ranges, "context": dict(context or {})}
        for name in ("brpatches.json", "binradar.env"):
            path = work / name
            header[name] = file_sha256(path) if path.is_file() else None
        _atomic_json(self.directory / "header.json", header)

    def _append(self, case: int, record: Mapping) -> None:
        if self._finished:
            raise RuntimeError("feedback journal already finalized")
        with (self.directory / f"{case}.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()

    def start(self, case: int, filename: str) -> None:
        if type(case) is not int or case < 0:
            raise ValueError("invalid feedback testcase id")
        if not filename or Path(filename).name != filename or filename in (".", ".."):
            raise ValueError("feedback testcase must be a minimized basename")
        existing = self._inputs.get(case)
        if existing is not None:
            if existing[0] != filename:
                raise ValueError("feedback testcase id changed filename")
            return
        digest = file_sha256(self.run_dir / "minimized" / filename)
        self._inputs[case] = (filename, digest)
        self._sequences[case] = 0
        self._append(case, {"kind": "input", "case": case,
                            "file": filename, "sha256": digest})

    def _states(self, snapshots: Sequence[CachedSnapshot], branches) -> tuple[str, int]:
        if branches is None or len(snapshots) != len(branches):
            raise ValueError("feedback capture/vector length mismatch")
        fd, temporary = tempfile.mkstemp(prefix=".part-", dir=self.root / "states")
        digest = hashlib.sha256()
        capture_id = -1
        family = None
        try:
            with os.fdopen(fd, "wb") as stream:
                def emit(data):
                    stream.write(data)
                    digest.update(data)
                for index, state in enumerate(snapshots):
                    if state.branch != branches[index] or state.branch not in (0, 1, 2):
                        raise ValueError("feedback capture/vector branch mismatch")
                    if capture_id == -1:
                        capture_id = state.patch_id
                        family = state.is_CWE805
                    if state.patch_id != capture_id or state.is_CWE805 != family:
                        raise ValueError("feedback capture id/family changed")
                    if len(state.registers) != 16 or len(state.stack) > 0x100000:
                        raise ValueError("invalid feedback register/stack capture")
                    if state.is_CWE805 and len(state.clamps) != 256:
                        raise ValueError("feedback CWE805 capture needs all clamps")
                    if not state.is_CWE805 and state.stack:
                        raise ValueError("generic feedback capture has stack bytes")
                    emit(CACHED_SNAPSHOT_HEADER.pack(
                        CACHED_SNAPSHOT_MAGIC, CACHED_SNAPSHOT_VERSION,
                        state.patch_id, state.branch, len(state.stack),
                        CACHED_SNAPSHOT_FLAG_CWE805 if state.is_CWE805 else 0))
                    if state.is_CWE805:
                        emit(CACHED_SNAPSHOT_CLAMPS.pack(
                            *(value for clamp in state.clamps for value in clamp)))
                    emit(CACHED_SNAPSHOT_REGS.pack(*state.registers))
                    emit(state.stack)
                stream.flush()
                os.fsync(stream.fileno())
            hexdigest = digest.hexdigest()
            os.replace(temporary, self.root / "states" / f"{hexdigest}.brch")
            return hexdigest, capture_id
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def record(self, case: int, filename: str, *, representative: int,
               members: Sequence[int], probe, branches: Sequence[int] | None,
               artifact: str, snapshots: Sequence[CachedSnapshot] | None = None,
               state_reason: str | None = None, observation: str = "unobserved") -> str:
        self.start(case, filename)
        if state_reason is None:
            state_reason = "none" if snapshots is not None else "not-captured"
        if type(representative) is not int or representative < 0:
            raise ValueError("invalid feedback representative")
        if not set(members) <= self.candidates:
            raise ValueError("feedback group outside candidate universe")
        member_ranges = encode_ids(members)
        if not _TOKEN.fullmatch(state_reason) or not _TOKEN.fullmatch(observation):
            raise ValueError("invalid feedback observation/reason token")
        if (snapshots is not None) != (state_reason == "none"):
            raise ValueError("inconsistent feedback capture availability")
        hits, vector = pack_branches(branches)
        state_hash, capture_id = (self._states(snapshots, branches)
                                 if snapshots is not None else ("none", -1))
        artifact = os.path.realpath(artifact)
        if artifact not in self._artifacts:
            self._artifacts[artifact] = file_sha256(artifact)
        sequence = self._sequences[case] + 1
        key = f"c{case}-{self.channel[0]}{sequence}"
        record = {"kind": "trace", "key": key, "representative": representative,
                  "members": member_ranges, "artifact": self._artifacts[artifact],
                  "artifact_name": Path(artifact).name,
                  "hits": hits, "branches": vector,
                  "state_sha256": state_hash, "capture_id": capture_id,
                  "state_reason": state_reason, "observation": observation,
                  **concrete_result(probe)}
        self._append(case, record)
        self._sequences[case] = sequence
        return key

    def skip(self, case: int, filename: str, members: Sequence[int], reason: str) -> None:
        if not members:
            return
        self.start(case, filename)
        if not set(members) <= self.candidates or not _TOKEN.fullmatch(reason):
            raise ValueError("invalid feedback skipped group")
        self._append(case, {"kind": "skip", "members": encode_ids(members), "reason": reason})

    def finish(self, reason: str) -> None:
        if not _TOKEN.fullmatch(reason):
            raise ValueError("invalid feedback terminal reason")
        _atomic_json(self.directory / "terminal.json", {"reason": reason})
        self._finished = True


def read_header(run_dir: str | Path, channel: str) -> dict | None:
    path = Path(run_dir) / "feedback-capture" / channel / "header.json"
    if not path.exists():
        return None
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or value.get("version") != VERSION
            or value.get("channel") != channel or not isinstance(value.get("context"), dict)):
        raise ValueError("invalid feedback capture header")
    return value


def read_case(run_dir: str | Path, channel: str, case: int):
    """Yield committed lines only; a final interrupted append remains unknown."""
    path = Path(run_dir) / "feedback-capture" / channel / f"{case}.jsonl"
    if not path.exists():
        return
    with path.open("rb") as stream:
        for line in stream:
            if not line.endswith(b"\n"):
                break
            value = json.loads(line)
            if not isinstance(value, dict) or value.get("kind") not in ("input", "trace", "skip"):
                raise ValueError("invalid feedback capture record")
            yield value
