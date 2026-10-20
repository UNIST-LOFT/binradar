"""Versioned Taosc handoff reader: normalized SBSV plus ordered BRCH payloads.

No inferred visit labels or synthesized execution outcomes. ``iter_rows`` is
streaming; ``load_bundle`` builds a convenient index without loading raw states.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from collections.abc import Iterator

import sbsv
from binradar_feedback_capture import (
    BINS, decode_ids, file_sha256, parse_id_ranges, unpack_branches,
)
from binradar_taosc_predicates import (
    parse_cached_snapshots, load_runtime_predicates, evaluate_cached_predicate,
)

VERSION = 1
SCHEMAS = {
    "feedback": "[feedback] [version: int] [candidates: str] [metadata: str] [metadata-sha256: str] [bins: str] [semantics: str]",
    "input": "[input] [key: str] [domain: str] [file: str] [sha256: str] [baseline: str] [label: str] [mutation: str]",
    "trace": "[trace] [key: str] [input: str] [representative: int] [artifact: str] [outcome: str] [fault-valid: bool] [fault-source: str] [fault-addr: hex] [fault-image: str] [fault-offset: hex] [hits: int] [branches: str] [state: str] [state-sha256: str] [state-reason: str] [capture-id: int] [sidecar: str]",
    "observation": "[observation] [input: str] [trace: str] [members: str] [bin: str]",
    "coverage": "[coverage] [input: str] [status: str] [not-run: str] [unusable: str] [skipped: str]",
    "predicate": "[predicate] [id: int] [tid: int] [concrete: str] [concrete-counts: str] [mutation: str] [mutation-counts: str]",
    "excluded": "[excluded] [id: int] [reason: str] [concrete-counts: str] [mutation-counts: str]",
    "done": "[done] [inputs: int] [traces: int] [observations: int] [predicates: int] [excluded: int]",
}
_FIELDS = {name: re.findall(r"\[([\w-]+): (int|str|hex|bool)\]", schema)
           for name, schema in SCHEMAS.items()}
_CLASSES = {"ground-truth-equivalent", "subset", "superset", "mixed", "insufficient-evidence"}
_OBSERVATIONS = set(BINS) | {"ignored-other-fault", "unclassified", "unusable", "no-observation"}


def write_row(stream, name: str, **values) -> None:
    fields = _FIELDS[name]
    if set(values) != {key for key, _ in fields}:
        raise ValueError(f"incorrect {name} feedback fields")
    parts = [f"[{name}]"]
    for key, kind in fields:
        value = values[key]
        if kind == "bool":
            if type(value) is not bool:
                raise ValueError(f"invalid feedback boolean {key}")
            value = str(value).lower()
        elif kind in ("int", "hex"):
            if type(value) is not int or (kind == "hex" and not 0 <= value <= 0xffffffffffffffff):
                raise ValueError(f"invalid feedback integer {key}")
            value = f"{value:x}" if kind == "hex" else str(value)
        elif not isinstance(value, str) or not value or re.search(r"[\[\]\r\n]", value):
            raise ValueError(f"unsafe feedback token {key}")
        parts.append(f"[{key} {value}]")
    stream.write(" ".join(parts) + "\n")


def iter_rows(path: str | Path) -> Iterator[tuple[str, dict]]:
    parser = sbsv.parser()
    for schema in SCHEMAS.values():
        parser.add_schema(schema)
    counts = {"inputs": 0, "traces": 0, "observations": 0, "predicates": 0, "excluded": 0}
    plurals = {"input": "inputs", "trace": "traces", "observation": "observations",
               "predicate": "predicates", "excluded": "excluded"}
    header = done = False
    with open(path, encoding="utf-8") as source:
        for line in source:
            if not line.endswith("\n") or done:
                raise ValueError("incomplete or trailing feedback rows")
            match = re.match(r"\[([a-z-]+)\]", line)
            if match is None or match[1] not in SCHEMAS:
                raise ValueError("unknown feedback row")
            name = match[1]
            # The schema parser permits extras. The interchange contract does not.
            tokens = re.findall(r"\[([^\[\]]*)\]", line)
            keys = [token.split(" ", 1)[0] for token in tokens[1:]]
            if (keys != [key for key, _ in _FIELDS[name]]
                    or re.sub(r"\[[^\[\]]*\]", "", line).strip()):
                raise ValueError("invalid/duplicate feedback fields")
            parsed = parser.parse_line_detached(line)
            if parsed is None:
                raise ValueError("malformed feedback row")
            row = dict(parsed.data)
            if not header:
                if (name != "feedback" or row["version"] != VERSION
                        or row["semantics"] != "observed"
                        or row["bins"] != ",".join(BINS)):
                    raise ValueError("unsupported feedback contract")
                header = True
            elif name == "feedback":
                raise ValueError("duplicate feedback header")
            if name in plurals:
                counts[plurals[name]] += 1
            if name == "done":
                if row != counts:
                    raise ValueError("feedback completion count mismatch")
                done = True
            yield name, row
    if not header or not done:
        raise ValueError("feedback bundle has no complete terminal record")


def bundle_path(root: str | Path, relative: str) -> Path:
    root = Path(root).resolve()
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("feedback path escapes bundle")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("feedback file unavailable or outside bundle")
    return resolved


def _counts(value: str) -> list[int]:
    if re.fullmatch(r"[0-9]+(?:,[0-9]+){5}", value) is None:
        raise ValueError("invalid feedback observation counters")
    return [int(item) for item in value.split(",")]


def observed_class(counts: list[int]) -> str:
    if counts[4] or counts[5] or not counts[1] or not (counts[2] or counts[3]):
        return "insufficient-evidence"
    return (("mixed" if counts[3] else "subset") if counts[0]
            else ("superset" if counts[3] else "ground-truth-equivalent"))


def _disjoint_union(groups):
    """Coalesce adjacent intervals; None means duplicate membership."""
    result = []
    for start, end in sorted(span for group in groups for span in group):
        if result and start <= result[-1][1]:
            return None
        if result and start == result[-1][1] + 1:
            result[-1] = (result[-1][0], end)
        else:
            result.append((start, end))
    return result


def _ranges_subset(ranges, universe):
    position = 0
    for start, end in ranges:
        while position < len(universe) and universe[position][1] < start:
            position += 1
        if (position == len(universe) or start < universe[position][0]
                or end > universe[position][1]):
            return False
    return True


def _contains_id(ranges, patch):
    # Binary search the last interval starting at or before this candidate.
    low, high = 0, len(ranges)
    while low < high:
        middle = (low + high) // 2
        if ranges[middle][0] <= patch:
            low = middle + 1
        else:
            high = middle
    return low > 0 and patch <= ranges[low - 1][1]


@dataclass
class FeedbackBundle:
    root: Path
    metadata: dict
    selected: set[int]
    inputs: dict[str, dict] = field(default_factory=dict)
    traces: dict[str, dict] = field(default_factory=dict)
    observations: list[dict] = field(default_factory=list)
    coverage: dict[str, dict] = field(default_factory=dict)
    predicates: dict[int, dict] = field(default_factory=dict)
    excluded: dict[int, dict] = field(default_factory=dict)
    _id_ranges: dict[str, list[tuple[int, int]]] = field(default_factory=dict, repr=False)

    def observations_for(self, predicate_id: int) -> Iterator[dict]:
        """Yield this candidate's evidence in file order, without ID expansion.

        Includes ignored/unusable observations and globally excluded candidates;
        callers collecting counter contributions should filter by BINS.
        """
        if predicate_id not in self.selected:
            raise ValueError("predicate outside feedback scope")
        for row in self.observations:
            if _contains_id(self._id_ranges[row["members"]], predicate_id):
                yield row

    def states(self, trace_key: str):
        trace = self.traces[trace_key]
        if trace["state-reason"] != "none" or trace["state"] == "none":
            raise ValueError("feedback trace has no complete state capture")
        path = bundle_path(self.root, trace["state"])
        if file_sha256(path) != trace["state-sha256"]:
            raise ValueError("feedback state checksum mismatch")
        snapshots, error = parse_cached_snapshots(path.read_bytes())
        branches = unpack_branches(trace["hits"], trace["branches"])
        if (error is not None or branches is None
                or [state.branch for state in snapshots] != branches
                or any(state.patch_id != trace["capture-id"] for state in snapshots)):
            raise ValueError(f"feedback state/vector/id mismatch: {error or trace_key}")
        return snapshots

    def evaluate(self, predicate_id: int, trace_key: str) -> list[int]:
        """Offline guard values only, never a new execution outcome."""
        if predicate_id not in self.selected:
            raise ValueError("predicate outside feedback scope")
        manifest = bundle_path(self.root, "brpatches.json")
        expected = self.metadata.get("files", {}).get("brpatches.json")
        if expected is None or file_sha256(manifest) != expected:
            raise ValueError("feedback descriptor manifest checksum mismatch")
        _, predicates = load_runtime_predicates(manifest)
        if predicate_id not in predicates:
            raise ValueError("feedback predicate has no supported descriptor")
        return evaluate_cached_predicate(predicates[predicate_id], self.states(trace_key))


def load_bundle(path: str | Path) -> FeedbackBundle:
    path = Path(path)
    if path.is_dir():
        path = path / "feedback.sbsv"
    rows = iter_rows(path)
    _, header = next(rows)
    metadata_path = bundle_path(path.parent, header["metadata"])
    if file_sha256(metadata_path) != header["metadata-sha256"]:
        raise ValueError("feedback metadata checksum mismatch")
    metadata = json.loads(metadata_path.read_text())
    if not isinstance(metadata, dict) or metadata.get("version") != VERSION:
        raise ValueError("unsupported feedback metadata")
    for relative, digest in metadata["files"].items():
        if file_sha256(bundle_path(path.parent, relative)) != digest:
            raise ValueError("feedback artifact checksum mismatch")
    selected = set(decode_ids(header["candidates"]))
    selected_ranges = _disjoint_union([parse_id_ranges(header["candidates"])])
    bundle = FeedbackBundle(path.parent, metadata, selected)

    def ranges(text):
        cached = bundle._id_ranges.get(text)
        if cached is None:
            cached = parse_id_ranges(text)
            if not _ranges_subset(cached, selected_ranges):
                raise ValueError("feedback member outside candidate universe")
            bundle._id_ranges[text] = cached
        return cached

    for name, row in rows:
        if name == "input":
            if row["key"] in bundle.inputs or row["domain"] not in ("concrete", "mutation"):
                raise ValueError("invalid/duplicate feedback input")
            bundle.inputs[row["key"]] = row
        elif name == "trace":
            if row["key"] in bundle.traces or row["input"] not in bundle.inputs:
                raise ValueError("invalid/duplicate feedback trace")
            unpack_branches(row["hits"], row["branches"])
            if row["outcome"] not in ("normal", "crash", "timeout", "unusable"):
                raise ValueError("invalid feedback outcome")
            if row["outcome"] != "crash" and row["fault-valid"]:
                raise ValueError("normal feedback trace carries a fault")
            if (row["state"] == "none") != (row["state-reason"] != "none"):
                raise ValueError("inconsistent feedback state availability")
            bundle.traces[row["key"]] = row
        elif name == "observation":
            trace = bundle.traces.get(row["trace"])
            members = ranges(row["members"])
            if (trace is None or trace["input"] != row["input"] or not members
                    or row["bin"] not in _OBSERVATIONS
                    or (trace["representative"] and not _contains_id(members, trace["representative"]))):
                raise ValueError("invalid feedback observation join")
            bundle.observations.append(row)
        elif name == "coverage":
            if row["input"] not in bundle.inputs or row["input"] in bundle.coverage:
                raise ValueError("invalid/duplicate feedback input coverage")
            if row["status"] not in ("complete", "partial", "unavailable"):
                raise ValueError("invalid feedback coverage status")
            groups = [ranges(row[key]) for key in ("not-run", "unusable", "skipped")]
            if _disjoint_union(groups) is None:
                raise ValueError("overlapping feedback coverage groups")
            bundle.coverage[row["input"]] = row
        elif name in ("predicate", "excluded"):
            patch = row["id"]
            if patch not in selected or patch in bundle.predicates or patch in bundle.excluded:
                raise ValueError("invalid/duplicate feedback candidate")
            concrete, mutation = _counts(row["concrete-counts"]), _counts(row["mutation-counts"])
            if name == "predicate":
                if (row["tid"] < 1 or any(concrete[4:]) or any(mutation[4:])
                        or any(row[key] not in _CLASSES for key in ("concrete", "mutation"))
                        or row["concrete"] != observed_class(concrete)
                        or row["mutation"] != observed_class(mutation)):
                    raise ValueError("invalid feedback predicate classification")
                bundle.predicates[patch] = row
            else:
                bundle.excluded[patch] = row
    if set(bundle.coverage) != set(bundle.inputs):
        raise ValueError("feedback input coverage missing")
    if set(bundle.predicates) | set(bundle.excluded) != selected:
        raise ValueError("feedback candidate coverage missing")
    input_hashes = {}
    for item in bundle.inputs.values():
        if item["file"] != "none":
            relative = item["file"]
            if relative not in input_hashes:
                input_hashes[relative] = file_sha256(bundle_path(bundle.root, relative))
            if input_hashes[relative] != item["sha256"]:
                raise ValueError("feedback input checksum mismatch")
        elif item["sha256"] != "none":
            raise ValueError("missing feedback input carries checksum")
        baseline = item["baseline"]
        if baseline != "none" and (baseline not in bundle.traces
                                   or bundle.traces[baseline]["input"] != item["key"]
                                   or bundle.traces[baseline]["representative"] != 0):
            raise ValueError("feedback baseline join mismatch")
    observations = {key: [] for key in bundle.inputs}
    ordered = sorted(selected)
    positions = {patch: index for index, patch in enumerate(ordered)}
    # Each member interval contributes +1 at its first candidate and -1 after
    # its last. Prefix sums validate every summary without visiting each member
    # of every observation group. Coordinates are candidate indices, not ids.
    changes = {domain: [[0] * (len(ordered) + 1) for _ in BINS]
               for domain in ("concrete", "mutation")}
    for row in bundle.observations:
        observations[row["input"]].append(row)
    for key, item in bundle.inputs.items():
        observed_groups, usable_groups = [], []
        for row in observations[key]:
            members = ranges(row["members"])
            observed_groups.append(members)
            if row["bin"] in BINS:
                usable_groups.append(members)
                delta = changes[item["domain"]][BINS.index(row["bin"])]
                for start, end in members:
                    delta[positions[start]] += 1
                    delta[positions[end] + 1] -= 1
        observed = _disjoint_union(observed_groups)
        if observed is None:
            raise ValueError("duplicate candidate/input feedback observation")
        usable = _disjoint_union(usable_groups)
        coverage = bundle.coverage[key]
        missing, unusable, skipped = [ranges(coverage[field])
                                      for field in ("not-run", "unusable", "skipped")]
        expected_status = ("complete" if not (missing or unusable or skipped) else
                           "partial" if observed else "unavailable")
        if (_disjoint_union([observed, missing, skipped]) != selected_ranges
                or _disjoint_union([usable, unusable]) != observed
                or coverage["status"] != expected_status):
            raise ValueError("feedback coverage disagrees with observations")
    for domain, deltas in changes.items():
        totals = [0] * len(BINS)
        for index, patch in enumerate(ordered):
            for bin_index, delta in enumerate(deltas):
                totals[bin_index] += delta[index]
            row = bundle.predicates.get(patch) or bundle.excluded[patch]
            if _counts(row[domain + "-counts"]) != totals:
                raise ValueError("feedback summary disagrees with observations")
    return bundle
