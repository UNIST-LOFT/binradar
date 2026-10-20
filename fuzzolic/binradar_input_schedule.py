"""Append-only concrete-input novelty and its independent SBSV wire schema."""
from dataclasses import dataclass
import hashlib
import pickle
import re
import select
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Callable, Mapping, Optional

from . import binradar_runtime
from . import binradar_utils
from .binradar_taosc_predicates import (
    CachedSnapshot, ParsedPredicate, PredicateTrap, _compile_patch_str,
    evaluate_cached_branch, wrap64,
)

SCHEDULE_VERSION = 1
SCHEDULE_POLICY = "append-novelty-v1"
_FIELDS = (
    "schedule-version", "schedule-seq", "score-patch-outcomes",
    "score-patch-signatures", "score-edges", "patch-features",
    "patch-feature-reason", "coverage-features", "coverage-feature-reason",
)
_INTEGER_FIELDS = _FIELDS[:5]
_REASON = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*\Z")
_MARKER = re.compile(r"\[(?:" + "|".join(_FIELDS) + r")(?=\s|\]|$)")
_BARE_MARKER = re.compile(r"\b(?:" + "|".join(_FIELDS) + r")\b")
_FRAME = struct.Struct("!Q")
_POLL = 0.05


def _natural(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"Invalid {name}: expected nonnegative integer")


@dataclass(frozen=True)
class InputScore:
    seq: int
    new_patch_outcomes: int
    new_patch_signatures: int
    new_edges: int
    patch_reason: str = "none"
    coverage_reason: str = "none"

    def __post_init__(self):
        for name in ("seq", "new_patch_outcomes", "new_patch_signatures", "new_edges"):
            _natural(getattr(self, name), name)
        for reason in (self.patch_reason, self.coverage_reason):
            if not isinstance(reason, str) or not _REASON.fullmatch(reason):
                raise ValueError("Invalid feature availability reason")
        if self.patch_reason != "none" and (self.new_patch_outcomes or self.new_patch_signatures):
            raise ValueError("Unavailable patch features contribute novelty")
        if self.coverage_reason != "none" and self.new_edges:
            raise ValueError("Unavailable coverage contributes novelty")

    @property
    def heap_key(self):
        return (-self.new_patch_outcomes, -self.new_patch_signatures,
                -self.new_edges, self.seq)

    def as_dict(self):
        return dict(zip(_FIELDS, (
            SCHEDULE_VERSION, self.seq, self.new_patch_outcomes,
            self.new_patch_signatures, self.new_edges,
            "complete" if self.patch_reason == "none" else "unavailable",
            self.patch_reason,
            "complete" if self.coverage_reason == "none" else "unavailable",
            self.coverage_reason,
        )))

    def serialize(self):
        return " ".join(f"[{key} {value}]" for key, value in self.as_dict().items())

    @classmethod
    def from_row(cls, row: Mapping):
        if any(key not in row for key in _FIELDS):
            raise ValueError("Incomplete scheduling fields")
        for key in _INTEGER_FIELDS:
            _natural(row[key], key)
        if row["schedule-version"] != SCHEDULE_VERSION:
            raise ValueError("Unsupported scheduling version")
        for family in ("patch", "coverage"):
            status, reason = row[f"{family}-features"], row[f"{family}-feature-reason"]
            if status not in ("complete", "unavailable") or (status == "complete") != (reason == "none"):
                raise ValueError("Inconsistent feature availability/reason")
        return cls(row["schedule-seq"], row["score-patch-outcomes"],
                   row["score-patch-signatures"], row["score-edges"],
                   row["patch-feature-reason"], row["coverage-feature-reason"])


def split_score(line: str):
    """Strip a complete score suffix; recognized broken suffixes are fatal.

    Timestamp/log prefixes and a logger's trailing time field are preserved.
    Policy headers and other diagnostic rows are outside this row codec.
    """
    result = re.search(r"\[testcase\]\s+\[result\]", line)
    if result is None:
        return line, None
    marker = _MARKER.search(line, result.end())
    if marker is None:
        # Field names inside an ordinary filename are not protocol markers.
        outside_fields = re.sub(r"\[[^\[\]]*\]", "", line[result.end():])
        if _BARE_MARKER.search(outside_fields):
            raise ValueError("Malformed scheduling suffix")
        return line, None
    start = marker.start()
    suffix = line[start:].strip()
    tokens = list(re.finditer(r"\[([^\[\]]+)\]", suffix))
    position = 0
    row = {}
    trailing_time = ""
    for index, token in enumerate(tokens):
        if suffix[position:token.start()].strip():
            raise ValueError("Malformed scheduling suffix")
        position = token.end()
        parts = token.group(1).split()
        if len(parts) != 2:
            raise ValueError("Malformed scheduling field")
        key, value = parts
        if key == "time" and index == len(tokens) - 1 and re.fullmatch(r"[0-9]+", value):
            trailing_time = " " + token.group(0)
            continue
        if key not in _FIELDS or key in row:
            raise ValueError("Unknown or duplicate scheduling field")
        if key in _INTEGER_FIELDS:
            if not re.fullmatch(r"[0-9]+", value):
                raise ValueError("Malformed scheduling integer")
            value = int(value)
        row[key] = value
    if suffix[position:].strip():
        raise ValueError("Malformed scheduling suffix")
    score = InputScore.from_row(row)
    newline = "\n" if line.endswith("\n") else ""
    return line[:start].rstrip() + trailing_time + newline, score


class _Reducer:
    """Prepared descriptor work; only compact aggregate features cross IPC.

    Outcome byte i contains bits 0/1/2 for the ascending candidate at i.
    Signatures retain the original namespace-prefixed two-bit vector digest.
    No state survives a request; equivalent adjacent states need not repeat
    deterministic expression evaluation or insert the same feature twice.
    """
    def __init__(self, predicates, namespace):
        self.count = len(predicates)
        self.prefix = hashlib.sha256(namespace.encode("utf-8")).digest()
        groups = {}
        for index, (_, predicate) in enumerate(sorted(predicates.items())):
            groups.setdefault(predicate, []).append(index)
        self.generic = all(isinstance(predicate, str) for predicate in groups)
        self.groups = [
            (_compile_patch_str(predicate) if self.generic else predicate,
             tuple((index, index // 4, 2 * (index % 4)) for index in indices))
            for predicate, indices in groups.items()
        ]

    def reduce(self, snapshots):
        outcomes = bytearray(self.count)
        signatures = set()
        previous = None
        for snapshot in snapshots:
            if self.generic:
                if snapshot.is_CWE805:
                    raise ValueError("generic predicate with a CWE-805 snapshot")
                state = tuple(wrap64(value) for value in snapshot.registers)
            else:
                state = (snapshot.registers, snapshot.clamps, snapshot.stack)
            if state == previous:
                continue
            previous = state
            packed = bytearray((self.count + 3) // 4)
            for evaluator, positions in self.groups:
                if self.generic:
                    try:
                        outcome = int(evaluator(state) != 0)
                    except PredicateTrap:
                        outcome = 2
                else:
                    outcome = evaluate_cached_branch(evaluator, snapshot)
                if outcome not in (0, 1, 2):
                    raise ValueError("Invalid predicate outcome")
                token = 1 << outcome
                for index, byte_index, shift in positions:
                    outcomes[index] |= token
                    packed[byte_index] |= outcome << shift
            signatures.add(hashlib.sha256(self.prefix + packed).digest())
        return bytes(outcomes), b"".join(signatures)


class NoveltyScorer:
    """Single-owner history; one managed reducer process, one in-flight capture."""
    def __init__(self, predicates: dict[int, ParsedPredicate], namespace: str):
        if not isinstance(namespace, str):
            raise ValueError("Invalid feature namespace")
        for patch_id in predicates:
            _natural(patch_id, "patch id")
        self.predicates = dict(sorted(predicates.items()))
        self.namespace = namespace
        self.backend = "process" if predicates else "coverage-only"
        self._outcomes = bytearray(len(self.predicates))
        self._outcome_count = 0
        self._signatures = set()
        self._edges = set()
        self._process = None
        self._socket = None
        self._closed = False
        self._busy = False
        self.highwater = {"patch_outcomes": 0, "patch_signatures": 0, "edges": 0}

    @property
    def counts(self):
        return {"patch_outcomes": self._outcome_count,
                "patch_signatures": len(self._signatures), "edges": len(self._edges)}

    def __enter__(self):
        if self._closed:
            raise RuntimeError("Scorer is closed")
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._closed = True
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        if self._process is not None:
            process, self._process = self._process, None
            # Kill first: registry.stop's communicate timeout alone permits a
            # longer termination grace inappropriate to deadline cancellation.
            try:
                binradar_utils.kill_process_group(process.pid, grace=_POLL)
            finally:
                binradar_runtime.PROCESS_REGISTRY.stop(process, grace=_POLL)

    def _send(self, value, check):
        assert self._socket is not None, "predicate reducer transport is closed"
        payload = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        for part in (_FRAME.pack(len(payload)), payload):
            view = memoryview(part)
            while view:
                check()
                _, writable, _ = select.select([], [self._socket], [], _POLL)
                if writable:
                    try:
                        count = self._socket.send(view[:65536])
                    except BlockingIOError:
                        continue
                    if not count:
                        raise RuntimeError("Predicate reducer closed during request")
                    view = view[count:]

    def _receive_bytes(self, size, check):
        assert self._socket is not None, "predicate reducer transport is closed"
        result = bytearray()
        while len(result) < size:
            check()
            readable, _, _ = select.select([self._socket], [], [], _POLL)
            if readable:
                try:
                    part = self._socket.recv(min(65536, size - len(result)))
                except BlockingIOError:
                    continue
                if not part:
                    raise RuntimeError("Predicate reducer exited without a complete response")
                result.extend(part)
        return result

    def _reduce_managed(self, snapshots, check):
        if self._process is None:
            parent, child = socket.socketpair()
            try:
                process = subprocess.Popen(
                    [sys.executable, "-m", "fuzzolic.binradar_input_schedule",
                     "--worker", str(child.fileno())],
                    # The worker consumes only IPC data. This also makes source
                    # wrappers usable before installation, from any workdir.
                    cwd=Path(__file__).resolve().parent.parent,
                    pass_fds=(child.fileno(),), start_new_session=True,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except BaseException:
                parent.close()
                raise
            finally:
                child.close()
            self._process, self._socket = process, parent
            binradar_runtime.PROCESS_REGISTRY.register(process)
            parent.setblocking(False)
            self._send((self.predicates, self.namespace), check)
        self._send(snapshots, check)
        size = _FRAME.unpack(self._receive_bytes(_FRAME.size, check))[0]
        ok, value = pickle.loads(self._receive_bytes(size, check))
        if not ok:
            raise RuntimeError(f"Predicate reducer failed: {value}")
        return value

    def score(self, seq: int, snapshots: Optional[list[CachedSnapshot]],
              coverage: Optional[bytes], *, patch_reason: str,
              coverage_reason: str, check: Callable[[], None]) -> InputScore:
        if self._closed or self._busy:
            raise RuntimeError("Scorer is closed or already scoring")
        InputScore(seq, 0, 0, 0, patch_reason, coverage_reason)
        if (snapshots is None) != (patch_reason != "none"):
            raise ValueError("Inconsistent patch capture availability")
        if (coverage is None) != (coverage_reason != "none"):
            raise ValueError("Inconsistent coverage availability")
        if snapshots is not None and not self.predicates:
            raise ValueError("Complete patch features require selected predicates")
        if coverage is not None and (not isinstance(coverage, bytes) or len(coverage) != 65536):
            raise ValueError("Coverage must be a complete 65536-byte bitmap")
        self._busy = True
        try:
            check()
            outcomes, digest_bytes = (self._reduce_managed(snapshots, check)
                                      if snapshots is not None else (b"", b""))
            signatures = {digest_bytes[offset:offset + 32]
                          for offset in range(0, len(digest_bytes), 32)}
            new_outcomes = sum((mask & ~seen).bit_count()
                               for mask, seen in zip(outcomes, self._outcomes))
            edges = {index for index, count in enumerate(coverage) if count} if coverage is not None else set()
            score = InputScore(seq, new_outcomes,
                               len(signatures - self._signatures), len(edges - self._edges),
                               patch_reason, coverage_reason)
            check()
            for index, mask in enumerate(outcomes):
                self._outcomes[index] |= mask
            self._outcome_count += new_outcomes
            self._signatures.update(signatures)
            self._edges.update(edges)
            self.highwater.update(self.counts)
            return score
        except BaseException:
            # A cancelled frame is not reusable. Reap before propagating the
            # original exception and never commit a partial history.
            self.close()
            raise
        finally:
            self._busy = False


def _worker_receive(channel):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            part = channel.recv(min(65536, size - len(data)))
            if not part:
                raise EOFError
            data.extend(part)
        return data
    size = _FRAME.unpack(exact(_FRAME.size))[0]
    return pickle.loads(exact(size))


def _worker(fd):
    with socket.socket(fileno=fd) as channel:
        try:
            predicates, namespace = _worker_receive(channel)
            reducer = _Reducer(predicates, namespace)
            del predicates, namespace
            while True:
                snapshots = _worker_receive(channel)
                try:
                    response = (True, reducer.reduce(snapshots))
                except Exception as exc:
                    response = (False, f"{type(exc).__name__}: {exc}")
                # Drop raw states before returning the compact token sets.
                del snapshots
                payload = pickle.dumps(response, protocol=pickle.HIGHEST_PROTOCOL)
                channel.sendall(_FRAME.pack(len(payload)))
                channel.sendall(payload)
                del response, payload
        except (EOFError, BrokenPipeError, ConnectionResetError):
            return


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit("This module's executable interface is private to its reducer")
    _worker(int(sys.argv[2]))
