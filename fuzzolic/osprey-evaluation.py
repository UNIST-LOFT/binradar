#!/usr/bin/env python3
"""Evaluate canonical in-process OSPREY models against an explicit manifest.

The evaluator never discovers subjects implicitly.  A manifest row names one
debug/fully-stripped build pair, input, function, and optional reviewed JSON
ground truth.  If ``--run-command`` is supplied it runs once per row with
``{debug}``, ``{stripped}``, ``{input}``, ``{model}``, ``{facts}``, ``{graph}``,
``{workdir}``, ``{id}``, and ``{seed}`` substitutions.  Without a run command,
the manifest must name checksum-pinned model, fact, graph, and tracer-log
artifacts plus their tracer commit.

The SBSV and CSV result data are deterministic apart from SBSV rows explicitly
labelled ``timing`` and ``rss``.  Ground truth may be supplied as a JSON sidecar
for reviewed fixtures.  Without a sidecar, the DWARF reader extracts simple
x86-64 global and CFA-relative stack locations, expands aggregate storage, and
records unsupported expressions as counted exclusions.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import shutil
import statistics
import struct
import subprocess
import sys
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

try:
    from elftools.dwarf.descriptions import describe_form_class
    from elftools.dwarf.dwarf_expr import DWARFExprParser
    from elftools.elf.elffile import ELFFile
except ImportError:  # The project dependency supplies this in evaluation envs.
    describe_form_class = None
    DWARFExprParser = None
    ELFFile = None

SCHEMA_VERSION = 1
MODEL_VERSION = 1


class EvaluationError(ValueError):
    """Manifest, model, or ground-truth input is malformed."""


def _tokens(line: str) -> list[str]:
    """Decode one SBSV line without depending on a parser's row ordering."""
    result: list[str] = []
    index = 0
    while index < len(line):
        while index < len(line) and line[index].isspace():
            index += 1
        if index == len(line):
            break
        if line[index] != "[":
            raise EvaluationError(f"malformed SBSV row: {line!r}")
        index += 1
        value: list[str] = []
        while index < len(line):
            char = line[index]
            if char == "]":
                index += 1
                break
            if char == "\\":
                index += 1
                if index == len(line):
                    raise EvaluationError("unterminated SBSV escape")
                value.append(line[index])
                index += 1
            else:
                value.append(char)
                index += 1
        else:
            raise EvaluationError("unterminated SBSV token")
        result.append("".join(value))
    return result


def _sbsv_escape(value: object) -> str:
    text = str(value)
    return "".join("\\" + char if char in "\\[]\t\r\n " else char for char in text)


def _sbsv_row(tag: str, fields: Iterable[tuple[str, object]]) -> str:
    values = [f"[{_sbsv_escape(tag)}]"]
    for key, value in fields:
        values.append(f"[{_sbsv_escape(key)} {_sbsv_escape(value)}]")
    return " ".join(values)


def _field_tokens(tokens: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in tokens:
        if " " not in token:
            continue
        key, value = token.split(" ", 1)
        if key in fields:
            raise EvaluationError(f"duplicate SBSV field {key!r}")
        fields[key] = value
    return fields


@dataclass(frozen=True)
class ManifestRow:
    stable_id: str
    debug: Path
    stripped: Path
    input: Path
    function: str
    name: str
    linkage_address: int | None = None
    model: Path | None = None
    facts: Path | None = None
    graph: Path | None = None
    log: Path | None = None
    truth: Path | None = None
    metadata: dict[str, str] = dataclass_field(default_factory=dict)


def load_manifest(path: str | os.PathLike[str]) -> list[ManifestRow]:
    """Load and validate explicit ``[subject]`` manifest rows."""
    manifest = Path(path).resolve()
    rows: list[ManifestRow] = []
    required = {"id", "debug", "stripped", "input", "function", "name"}
    for line_no, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        tokens = _tokens(raw)
        if not tokens or tokens[0] != "subject":
            raise EvaluationError(f"{manifest}:{line_no}: expected [subject]")
        fields = _field_tokens(tokens[1:])
        missing = required - fields.keys()
        if missing:
            raise EvaluationError(f"{manifest}:{line_no}: missing {sorted(missing)}")
        path_fields = {"model", "facts", "graph", "log", "truth"}
        metadata_fields = {
            "compiler",
            "flags",
            "build-id",
            "debug-sha256",
            "stripped-sha256",
            "input-sha256",
            "model-sha256",
            "facts-sha256",
            "graph-sha256",
            "log-sha256",
            "truth-sha256",
            "tracer-commit",
        }
        unknown = (
            set(fields) - required - {"linkage-address"} - path_fields - metadata_fields
        )
        if unknown:
            raise EvaluationError(
                f"{manifest}:{line_no}: unknown fields {sorted(unknown)}"
            )
        linkage = fields.get("linkage-address")
        linkage_value = int(linkage, 0) if linkage is not None else None

        def relative(name: str, values: dict[str, str] = fields) -> Path:
            value = Path(values[name])
            return value if value.is_absolute() else manifest.parent / value

        rows.append(
            ManifestRow(
                stable_id=fields["id"],
                debug=relative("debug").resolve(),
                stripped=relative("stripped").resolve(),
                input=relative("input").resolve(),
                function=fields["function"],
                name=fields["name"],
                linkage_address=linkage_value,
                model=(relative("model").resolve() if "model" in fields else None),
                facts=(relative("facts").resolve() if "facts" in fields else None),
                graph=(relative("graph").resolve() if "graph" in fields else None),
                log=(relative("log").resolve() if "log" in fields else None),
                truth=(relative("truth").resolve() if "truth" in fields else None),
                metadata={
                    key: value
                    for key, value in fields.items()
                    if key in metadata_fields
                },
            )
        )
    if not rows:
        raise EvaluationError(f"{manifest}: no subject rows")
    ids = [row.stable_id for row in rows]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise EvaluationError("manifest rows must have unique sorted stable ids")
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def elf_metadata(path: Path) -> dict[str, str]:
    """Return canonical ELF/build metadata through pyelftools."""
    if ELFFile is None:
        raise EvaluationError("pyelftools is required for ELF/DWARF evaluation")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        build_id = ""
        executable_bases: list[int] = []
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_LOAD" and segment.header.p_flags & 1:
                executable_bases.append(int(segment.header.p_vaddr))
            if segment.header.p_type != "PT_NOTE":
                continue
            for note in segment.iter_notes():
                if note.get("n_type") == "NT_GNU_BUILD_ID":
                    value = note.get("n_desc", b"")
                    build_id = value.hex() if isinstance(value, bytes) else str(value)
                    break
        if not executable_bases:
            raise EvaluationError(f"{path}: no executable PT_LOAD segment")
        producer = ""
        if elf.has_dwarf_info():
            dwarf = elf.get_dwarf_info()
            for unit in dwarf.iter_CUs():
                attribute = unit.get_top_DIE().attributes.get("DW_AT_producer")
                if attribute is not None:
                    value = attribute.value
                    producer = (
                        value.decode(errors="replace")
                        if isinstance(value, bytes)
                        else str(value)
                    )
                    break
        return {
            "class": str(elf.elfclass),
            "machine": str(elf.header.e_machine),
            "build_id": build_id,
            "executable_base": str(min(executable_bases)),
            "producer": producer,
        }


def _check_digest(path: Path, expected: str, label: str) -> str:
    actual = sha256_file(path)
    if expected and actual.lower() != expected.lower():
        raise EvaluationError(f"manifest {label} SHA-256 mismatch")
    return actual


def _address(value: Any) -> tuple[int, int, int, int]:
    if isinstance(value, dict):
        image = value["image"]
        site = value["site"]
        return (
            int(value["kind"]),
            int(image, 0) if isinstance(image, str) else int(image),
            int(site, 0) if isinstance(site, str) else int(site),
            int(value["offset"]),
        )
    if isinstance(value, (list, tuple)) and len(value) == 4:
        return int(value[0]), int(value[1]), int(value[2]), int(value[3])
    raise EvaluationError(f"invalid canonical address {value!r}")


def _chunk(value: Any) -> tuple[tuple[int, int, int, int], int]:
    if not isinstance(value, dict):
        raise EvaluationError(f"invalid canonical chunk {value!r}")
    return _address(value["address"]), int(value["size"])


def load_truth(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvaluationError("ground truth must be a JSON object")
    return value


def _model_address(fields: dict[str, str], prefix: str) -> tuple[int, int, int, int]:
    try:
        return (
            int(fields[f"{prefix}-region"]),
            int(fields[f"{prefix}-image"], 16),
            int(fields[f"{prefix}-site"], 16),
            int(fields[f"{prefix}-offset"]),
        )
    except (KeyError, ValueError) as exc:
        raise EvaluationError(f"malformed model address {prefix}") from exc


def _model_fields(line: str) -> dict[str, str]:
    return _field_tokens(_tokens(line)[1:])


def parse_model_dump(text: str) -> dict[str, Any]:
    """Parse the canonical model schema emitted after validation/install."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise EvaluationError("empty model dump")
    header_tokens = _tokens(lines[0])
    header = _field_tokens(header_tokens)
    if "model-version" not in header or int(header["model-version"]) != MODEL_VERSION:
        raise EvaluationError("unsupported model header")
    result: dict[str, Any] = {"types": [], "fields": [], "arrays": [], "objects": []}
    kind_map = {
        "primitive": "primitive",
        "pointer": "pointer",
        "array": "array",
        "struct": "struct",
    }
    family_order = {"type": 0, "field": 1, "array": 2, "object": 3}
    previous_family = -1
    for line in lines[1:]:
        row = _tokens(line)
        if not row or row[0] not in family_order:
            tag = row[0] if row else ""
            raise EvaluationError(f"unknown model row {tag!r}")
        family = family_order[row[0]]
        if family < previous_family:
            raise EvaluationError(f"model row {row[0]!r} is out of order")
        previous_family = family
        fields = _field_tokens(row[1:])
        if row[0] == "type":
            result["types"].append(
                {
                    "id": int(fields["id"]),
                    "kind": kind_map.get(fields["kind"], "invalid"),
                    "name": fields["name"],
                    "size": int(fields["size"]),
                    "count": int(fields["count"]),
                    "element_size": int(fields["element-size"]),
                    "element_type": int(fields["element-type"]),
                    "target_void": int(fields["target-void"]),
                    "target_type": int(fields["target-type"]),
                    "field_begin": int(fields["field-begin"]),
                    "field_count": int(fields["field-count"]),
                    "evidence": int(fields["evidence"]),
                    "posterior_bits": int(fields["posterior-bits"], 16),
                    "support": int(fields["support"]),
                    "rules": int(fields["rules"], 16),
                    "base": _model_address(fields, "base"),
                }
            )
        elif row[0] == "field":
            result["fields"].append(
                {
                    "id": int(fields["id"]),
                    "owner": _model_address(fields, "owner"),
                    "relative": int(fields["relative"]),
                    "value_type": int(fields["value-type"]),
                    "posterior_bits": int(fields["posterior-bits"], 16),
                    "support": int(fields["support"]),
                    "rules": int(fields["rules"], 16),
                    "chunk": (_model_address(fields, "chunk"), int(fields["size"])),
                }
            )
        elif row[0] == "array":
            result["arrays"].append(
                {
                    "id": int(fields["id"]),
                    "lo": int(fields["lo"]),
                    "hi": int(fields["hi"]),
                    "size": int(fields["size"]),
                    "stride": int(fields["stride"]),
                    "count": int(fields["count"]),
                    "element_type": int(fields["element-type"]),
                    "posterior_bits": int(fields["posterior-bits"], 16),
                    "support": int(fields["support"]),
                    "rules": int(fields["rules"], 16),
                    "base": _model_address(fields, "base"),
                }
            )
        elif row[0] == "object":
            object_row = {
                "id": int(fields["id"]),
                "role": fields["role"],
                "value_type": int(fields["value-type"]),
                "pointer": int(fields["pointer"]),
                "storage_bits": int(fields["storage-posterior-bits"], 16),
                "storage_support": int(fields["storage-support"]),
                "storage_rules": int(fields["storage-rules"], 16),
                "pointer_bits": int(fields["pointer-posterior-bits"], 16),
                "pointer_support": int(fields["pointer-support"]),
                "pointer_rules": int(fields["pointer-rules"], 16),
                "chunk": (_model_address(fields, "chunk"), int(fields["size"])),
                "owner": _model_address(fields, "owner"),
            }
            if "target-region" in fields:
                object_row["target"] = _model_address(fields, "target")
            result["objects"].append(object_row)
        else:
            raise EvaluationError(f"unknown model row {row[0]!r}")
    for name in ("types", "fields", "objects"):
        family = result[name]
        if [row["id"] for row in family] != list(range(len(family))):
            raise EvaluationError(f"model {name} ids are not canonical")
        count = int(header[name])
        if len(family) != count:
            raise EvaluationError(f"model {name} count mismatch")
    array_ids = [row["id"] for row in result["arrays"]]
    if array_ids != sorted(set(array_ids)) or any(
        type_id >= len(result["types"]) or result["types"][type_id]["kind"] != "array"
        for type_id in array_ids
    ):
        raise EvaluationError("model array ids are not canonical type ids")
    return result


def _bits_float(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits))[0]


def _truth_variable_key(row: dict[str, Any]) -> tuple[Any, ...]:
    chunk = _chunk(row["chunk"])
    return chunk[0] + (chunk[1],)


def _recovered_variables(
    model: dict[str, Any],
) -> dict[tuple[Any, ...], dict[str, Any]]:
    return {
        _truth_variable_key(
            {"chunk": {"address": row["chunk"][0], "size": row["chunk"][1]}}
        ): row
        for row in model["objects"]
    }


def _precision_recall(
    matched: int, false_positive: int, false_negative: int
) -> tuple[float, float, float]:
    precision = (
        matched / (matched + false_positive) if matched + false_positive else 1.0
    )
    recall = matched / (matched + false_negative) if matched + false_negative else 1.0
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def _tree(node: Any) -> Any:
    if isinstance(node, dict):
        kind = node.get("kind", "primitive")
        if kind == "struct":
            fields = tuple(
                (
                    int(field["offset"]),
                    int(field["size"]),
                    _tree(
                        field.get("type", {"kind": "primitive", "size": field["size"]})
                    ),
                )
                for field in node.get("fields", [])
            )
            return ("struct", fields)
        if kind == "array":
            return (
                "array",
                int(node["count"]),
                int(node["stride"]),
                _tree(node.get("element", {"kind": "primitive"})),
            )
        if kind == "pointer":
            return ("pointer", _tree(node.get("target", {"kind": "void"})))
        if kind in {"void", "reference"}:
            return (kind,)
        return ("primitive", int(node.get("size", 0)))
    return ("primitive", 0)


def tree_distance(left: Any, right: Any) -> int:
    """Ordered unit-cost tree distance, bounded by the larger tree size.

    Node-kind or primitive-width replacement costs one.  Array geometry is
    one node label, so any count/stride change costs one.  Structure children
    use ordered dynamic programming; changing a field offset/width adds one to
    the recursively matched child, while insertion/deletion costs that child
    subtree's size.
    """
    if left == right:
        return 0
    if not left or not right:
        return 1
    maximum = max(tree_size(left), tree_size(right))
    if left[0] != right[0]:
        return maximum
    if left[0] == "struct":
        first, second = left[1], right[1]
        previous = [0]
        for field in second:
            previous.append(previous[-1] + tree_size(field[2]))
        for left_field in first:
            current = [previous[0] + tree_size(left_field[2])]
            for right_index, right_field in enumerate(second, 1):
                edge_cost = int(left_field[:2] != right_field[:2])
                replace = (
                    previous[right_index - 1]
                    + edge_cost
                    + tree_distance(left_field[2], right_field[2])
                )
                delete = previous[right_index] + tree_size(left_field[2])
                insert = current[right_index - 1] + tree_size(right_field[2])
                current.append(min(replace, delete, insert))
            previous = current
        return min(previous[-1], maximum)
    if left[0] == "array":
        label_cost = int(left[1:3] != right[1:3])
        return min(label_cost + tree_distance(left[3], right[3]), maximum)
    if left[0] == "pointer":
        return min(tree_distance(left[1], right[1]), maximum)
    return 1


def tree_size(node: Any) -> int:
    if node[0] == "struct":
        return 1 + sum(tree_size(field[2]) for field in node[1])
    if node[0] == "array":
        return 1 + tree_size(node[3])
    if node[0] == "pointer":
        return 1 + tree_size(node[1])
    return 1


def _model_tree(
    model: dict[str, Any], type_id: int, seen: set[int] | None = None
) -> Any:
    seen = set() if seen is None else seen
    if type_id < 0 or type_id >= len(model["types"]):
        return ("void",)
    if type_id in seen:
        return ("reference",)
    row = model["types"][type_id]
    if row["kind"] == "primitive":
        return ("primitive", row["size"])
    if row["kind"] == "pointer":
        return (
            "pointer",
            ("void",)
            if row["target_void"]
            else _model_tree(model, row["target_type"], seen | {type_id}),
        )
    if row["kind"] == "array":
        return (
            "array",
            row["count"],
            row["element_size"],
            _model_tree(model, row["element_type"], seen | {type_id}),
        )
    fields = []
    for field in model["fields"][
        row["field_begin"] : row["field_begin"] + row["field_count"]
    ]:
        fields.append(
            (
                field["relative"],
                field["chunk"][1],
                _model_tree(model, field["value_type"], seen | {type_id}),
            )
        )
    return ("struct", tuple(fields))


def score_model(model: dict[str, Any], truth: dict[str, Any]) -> dict[str, Any]:
    truth_variables = {
        _truth_variable_key(row): row for row in truth.get("variables", [])
    }
    recovered_variables = _recovered_variables(model)
    matched_keys = truth_variables.keys() & recovered_variables.keys()
    matched = len(matched_keys)
    variable_precision, variable_recall, variable_f1 = _precision_recall(
        matched, len(recovered_variables) - matched, len(truth_variables) - matched
    )

    truth_complex = {
        _address(row["base"]): row for row in truth.get("complex_types", [])
    }
    recovered_complex = {
        row["base"]: row for row in model["types"] if row["kind"] in ("struct", "array")
    }
    common_complex = truth_complex.keys() & recovered_complex.keys()
    differences = []
    complex_matches = 0
    truth_trees: dict[tuple[int, int, int, int], Any] = {}
    for key in sorted(common_complex):
        reference = _tree(truth_complex[key].get("type", truth_complex[key]))
        recovered = _model_tree(model, recovered_complex[key]["id"])
        truth_trees[key] = reference
        difference = tree_distance(reference, recovered) / max(
            tree_size(reference), tree_size(recovered), 1
        )
        differences.append(difference)
        complex_matches += int(reference == recovered)
    complex_precision, complex_recall, complex_f1 = _precision_recall(
        complex_matches,
        len(recovered_complex) - complex_matches,
        len(truth_complex) - complex_matches,
    )

    truth_pointers = {
        _truth_variable_key(row): row for row in truth.get("pointers", [])
    }
    recovered_pointers: dict[tuple[Any, ...], tuple[Any, Any] | None] = {}
    for row in model["objects"]:
        if not row["pointer"]:
            continue
        key = _truth_variable_key(
            {"chunk": {"address": row["chunk"][0], "size": row["chunk"][1]}}
        )
        pointer_type = (
            model["types"][row["value_type"]]
            if 0 <= row["value_type"] < len(model["types"])
            else None
        )
        if (
            pointer_type is None
            or pointer_type["kind"] != "pointer"
            or pointer_type["target_void"]
            or "target" not in row
            or not 0 <= pointer_type["target_type"] < len(model["types"])
        ):
            recovered_pointers[key] = None
            continue
        target_tree = _model_tree(model, pointer_type["target_type"])
        if target_tree[0] not in ("struct", "array"):
            recovered_pointers[key] = None
            continue
        recovered_pointers[key] = (row["target"], target_tree)

    pointer_matches = 0
    for key, truth_pointer in truth_pointers.items():
        recovered_pointer = recovered_pointers.get(key)
        if recovered_pointer is None:
            continue
        truth_target = _address(truth_pointer["target"])
        truth_tree = (
            _tree(truth_pointer["target_type"])
            if "target_type" in truth_pointer
            else truth_trees.get(truth_target)
        )
        _recovered_target, recovered_tree = recovered_pointer
        if truth_tree is None:
            raise EvaluationError(
                f"pointer truth at {key!r} has no aggregate target type"
            )
        if recovered_tree == truth_tree:
            pointer_matches += 1
    pointer_precision, pointer_recall, pointer_f1 = _precision_recall(
        pointer_matches,
        len(recovered_pointers) - pointer_matches,
        len(truth_pointers) - pointer_matches,
    )
    return {
        "variables_matched": matched,
        "variables_false_positive": len(recovered_variables) - matched,
        "variables_false_negative": len(truth_variables) - matched,
        "variable_precision": variable_precision,
        "variable_recall": variable_recall,
        "variable_f1": variable_f1,
        "complex_matched": complex_matches,
        "complex_false_positive": len(recovered_complex) - complex_matches,
        "complex_false_negative": len(truth_complex) - complex_matches,
        "complex_precision": complex_precision,
        "complex_recall": complex_recall,
        "complex_f1": complex_f1,
        "tree_difference_mean": (statistics.fmean(differences) if differences else 0.0),
        "tree_difference_median": (
            statistics.median(differences) if differences else 0.0
        ),
        "pointer_matched": pointer_matches,
        "pointer_false_positive": len(recovered_pointers) - pointer_matches,
        "pointer_false_negative": len(truth_pointers) - pointer_matches,
        "pointer_precision": pointer_precision,
        "pointer_recall": pointer_recall,
        "pointer_f1": pointer_f1,
        "_tree_differences": differences,
    }


def _die_name(die: Any) -> str:
    attribute = die.attributes.get("DW_AT_name")
    if attribute is None:
        return ""
    value = attribute.value
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def _die_descendants(die: Any) -> Iterable[Any]:
    for child in die.iter_children():
        yield child
        if child.tag not in {"DW_TAG_subprogram", "DW_TAG_inlined_subroutine"}:
            yield from _die_descendants(child)


def _dwarf_type_size(die: Any, address_size: int, seen: set[int] | None = None) -> int:
    if die is None:
        return 0
    seen = set() if seen is None else seen
    if die.offset in seen:
        return 0
    seen.add(die.offset)
    byte_size = die.attributes.get("DW_AT_byte_size")
    if byte_size is not None:
        return int(byte_size.value)
    if die.tag == "DW_TAG_pointer_type":
        return address_size
    target = (
        die.get_DIE_from_attribute("DW_AT_type")
        if "DW_AT_type" in die.attributes
        else None
    )
    if die.tag == "DW_TAG_array_type" and target is not None:
        count = 1
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            count_attr = child.attributes.get("DW_AT_count")
            upper = child.attributes.get("DW_AT_upper_bound")
            lower = child.attributes.get("DW_AT_lower_bound")
            if count_attr is not None:
                count *= int(count_attr.value)
            elif upper is not None:
                count *= int(upper.value) - int(lower.value if lower else 0) + 1
            else:
                return 0
        return count * _dwarf_type_size(target, address_size, seen)
    return _dwarf_type_size(target, address_size, seen)


def _dwarf_type_tree(
    die: Any, address_size: int, seen: set[int] | None = None
) -> dict[str, Any]:
    if die is None:
        return {"kind": "primitive", "size": 0}
    seen = set() if seen is None else seen
    if die.offset in seen:
        return {"kind": "reference"}
    next_seen = seen | {die.offset}
    target = (
        die.get_DIE_from_attribute("DW_AT_type")
        if "DW_AT_type" in die.attributes
        else None
    )
    if die.tag in {
        "DW_TAG_typedef",
        "DW_TAG_const_type",
        "DW_TAG_volatile_type",
        "DW_TAG_restrict_type",
    }:
        return _dwarf_type_tree(target, address_size, next_seen)
    if die.tag == "DW_TAG_pointer_type":
        return (
            {
                "kind": "pointer",
                "target": _dwarf_type_tree(target, address_size, next_seen),
            }
            if target is not None
            else {"kind": "pointer", "target": {"kind": "void"}}
        )
    if die.tag == "DW_TAG_array_type" and "DW_AT_GNU_vector" in die.attributes:
        return {"kind": "primitive", "size": _dwarf_type_size(die, address_size)}
    if die.tag == "DW_TAG_array_type":
        count = 1
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            count_attr = child.attributes.get("DW_AT_count")
            upper = child.attributes.get("DW_AT_upper_bound")
            lower = child.attributes.get("DW_AT_lower_bound")
            if count_attr is not None:
                count *= int(count_attr.value)
            elif upper is not None:
                count *= int(upper.value) - int(lower.value if lower else 0) + 1
            else:
                raise ValueError("array-bound")
        element_size = _dwarf_type_size(target, address_size)
        return {
            "kind": "array",
            "count": count,
            "stride": element_size,
            "element": _dwarf_type_tree(target, address_size, next_seen),
        }
    if die.tag in {"DW_TAG_structure_type", "DW_TAG_class_type"}:
        fields = []
        for child in die.iter_children():
            if child.tag != "DW_TAG_member":
                continue
            location = child.attributes.get("DW_AT_data_member_location")
            member_type = (
                child.get_DIE_from_attribute("DW_AT_type")
                if "DW_AT_type" in child.attributes
                else None
            )
            if location is None or not isinstance(location.value, int):
                raise ValueError("complex-member-location")
            size = _dwarf_type_size(member_type, address_size)
            if size <= 0:
                raise ValueError("complex-member-size")
            fields.append(
                {
                    "offset": int(location.value),
                    "size": size,
                    "type": _dwarf_type_tree(member_type, address_size, next_seen),
                }
            )
        fields.sort(key=lambda field: (field["offset"], field["size"]))
        return {"kind": "struct", "fields": fields}
    return {"kind": "primitive", "size": _dwarf_type_size(die, address_size)}


def _dwarf_variable_rows(
    name: str,
    address: list[int],
    type_tree: dict[str, Any],
    size: int,
    address_size: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def append_leaves(
        prefix: str, base: list[int], node: dict[str, Any], fallback_size: int
    ) -> None:
        kind = node["kind"]
        if kind == "struct":
            for index, member in enumerate(node["fields"]):
                child_base = [base[0], base[1], base[2], base[3] + member["offset"]]
                append_leaves(
                    f"{prefix}.{index}", child_base, member["type"], member["size"]
                )
            return
        if kind == "array":
            if node["count"] > 4096:
                raise ValueError("array-element-limit")
            for index in range(node["count"]):
                child_base = [
                    base[0],
                    base[1],
                    base[2],
                    base[3] + index * node["stride"],
                ]
                append_leaves(
                    f"{prefix}[{index}]", child_base, node["element"], node["stride"]
                )
            return
        leaf_size = address_size if kind == "pointer" else fallback_size
        if leaf_size <= 0:
            raise ValueError("variable-size")
        rows.append(
            {
                "name": prefix,
                "chunk": {"address": base, "size": leaf_size},
                "role": kind,
            }
        )

    append_leaves(name, address, type_tree, size)
    return rows


def _dwarf_function_bounds(die: Any) -> tuple[int, int]:
    low_attr = die.attributes.get("DW_AT_low_pc")
    high_attr = die.attributes.get("DW_AT_high_pc")
    if low_attr is None or high_attr is None or describe_form_class is None:
        raise ValueError("function-range")
    low = int(low_attr.value)
    high = int(high_attr.value)
    if describe_form_class(high_attr.form) != "address":
        high += low
    if high <= low:
        raise ValueError("function-range")
    return low, high


def _dwarf_truth(row: ManifestRow) -> tuple[dict[str, Any], list[str]]:
    """Extract simple canonical locations under the x86-64 CFA policy.

    OSPREY stack offsets use function-entry RSP.  For the accepted
    ``DW_OP_call_frame_cfa`` frame base, x86-64 SysV CFA is entry RSP + 8,
    so one ``DW_OP_fbreg`` offset maps to ``offset + 8``.  Other frame-base
    and location expressions are counted exclusions.
    """
    if ELFFile is None or DWARFExprParser is None:
        return {}, ["pyelftools-unavailable"]
    exclusions: list[str] = []
    truth: dict[str, Any] = {"variables": [], "complex_types": [], "pointers": []}
    with row.debug.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or str(elf.header.e_machine) != "EM_X86_64":
            return truth, ["unsupported-elf-target"]
        if not elf.has_dwarf_info():
            return truth, ["no-dwarf"]
        executable_bases = [
            int(segment.header.p_vaddr)
            for segment in elf.iter_segments()
            if segment.header.p_type == "PT_LOAD" and segment.header.p_flags & 1
        ]
        if not executable_bases:
            return truth, ["no-executable-load"]
        executable_base = min(executable_bases)
        dwarf = elf.get_dwarf_info()
        target_functions = []
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or _die_name(die) != row.function:
                    continue
                try:
                    low, high = _dwarf_function_bounds(die)
                except ValueError as exc:
                    exclusions.append(f"{row.function}:<function>:{exc}")
                    continue
                target_functions.append((unit, die, low, high))
        if len(target_functions) != 1:
            reason = (
                "function-not-found" if not target_functions else "function-ambiguous"
            )
            exclusions.append(reason)
            return truth, exclusions
        unit, function_die, function_low, function_high = target_functions[0]
        function_site = (
            row.linkage_address if row.linkage_address is not None else function_low
        )
        function_site -= executable_base
        truth["function_range"] = [
            function_low - executable_base,
            function_high - executable_base,
        ]
        parser = DWARFExprParser(dwarf.structs)
        frame_base = function_die.attributes.get("DW_AT_frame_base")
        frame_is_cfa = False
        if frame_base is not None and frame_base.form == "DW_FORM_exprloc":
            frame_ops = parser.parse_expr(frame_base.value)
            frame_is_cfa = (
                len(frame_ops) == 1 and frame_ops[0].op_name == "DW_OP_call_frame_cfa"
            )
        address_size = int(unit["address_size"])
        for die in _die_descendants(function_die):
            if die.tag not in {"DW_TAG_variable", "DW_TAG_formal_parameter"}:
                continue
            name = _die_name(die) or "<anonymous>"
            location = die.attributes.get("DW_AT_location")
            type_die = (
                die.get_DIE_from_attribute("DW_AT_type")
                if "DW_AT_type" in die.attributes
                else None
            )
            size = _dwarf_type_size(type_die, address_size)
            if location is None or location.form != "DW_FORM_exprloc" or size <= 0:
                exclusions.append(f"{row.function}:{name}:unsupported-location")
                continue
            try:
                operations = parser.parse_expr(location.value)
                if len(operations) != 1:
                    raise ValueError("multiple-location-operations")
                operation = operations[0]
                if operation.op_name == "DW_OP_fbreg":
                    if not frame_is_cfa:
                        raise ValueError("unsupported-frame-base")
                    address = [
                        2,
                        0,
                        function_site,
                        int(operation.args[0]) + address_size,
                    ]
                elif operation.op_name == "DW_OP_addr":
                    address = [0, 0, 0, int(operation.args[0]) - executable_base]
                else:
                    raise ValueError(operation.op_name)
                type_tree = _dwarf_type_tree(type_die, address_size)
                truth["variables"].extend(
                    _dwarf_variable_rows(name, address, type_tree, size, address_size)
                )
                if type_tree["kind"] in {"struct", "array"}:
                    truth["complex_types"].append(
                        {
                            "base": address,
                            "size": size,
                            "type": type_tree,
                        }
                    )
            except (KeyError, TypeError, ValueError) as exc:
                exclusions.append(f"{row.function}:{name}:{exc}")

        for die in unit.get_top_DIE().iter_children():
            if die.tag != "DW_TAG_variable":
                continue
            location = die.attributes.get("DW_AT_location")
            type_die = (
                die.get_DIE_from_attribute("DW_AT_type")
                if "DW_AT_type" in die.attributes
                else None
            )
            size = _dwarf_type_size(type_die, address_size)
            if location is None or location.form != "DW_FORM_exprloc" or size <= 0:
                continue
            try:
                operations = parser.parse_expr(location.value)
                if len(operations) != 1 or operations[0].op_name != "DW_OP_addr":
                    continue
                name = _die_name(die) or "<anonymous>"
                address = [0, 0, 0, int(operations[0].args[0]) - executable_base]
                type_tree = _dwarf_type_tree(type_die, address_size)
                truth["variables"].extend(
                    _dwarf_variable_rows(name, address, type_tree, size, address_size)
                )
                if type_tree["kind"] in {"struct", "array"}:
                    truth["complex_types"].append(
                        {
                            "base": address,
                            "size": size,
                            "type": type_tree,
                        }
                    )
            except (KeyError, TypeError, ValueError):
                continue
    return truth, exclusions


def _diagnostic_counts(text: str) -> dict[str, int]:
    counts = {
        "facts": 0,
        "relations": 0,
        "variables": 0,
        "factors": 0,
        "components": 0,
        "cliques": 0,
        "max_clique_variables": 0,
        "exact_table_bytes": 0,
        "bp_edges": 0,
        "bp_workspace_bytes": 0,
        "decoded_objects": 0,
        "decoded_types": 0,
        "exact_iterations": 0,
        "bp_iterations": 0,
        "rejected": 0,
        "oversized_components": 0,
        "non_convergence": 0,
    }
    for line in text.splitlines():
        if "[osprey] [facts]" in line:
            family_counts = [
                int(value)
                for value in re.findall(
                    r"\[(?:access|base|copy|points|alloc|may-array|regions) (\d+)\]",
                    line,
                )
            ]
            counts["facts"] = max(counts["facts"], sum(family_counts))
        if "[osprey] [graph] [stage" in line:
            match = re.search(r"\[vars (\d+)\] \[factors (\d+)", line)
            if match:
                counts["variables"] = max(counts["variables"], int(match.group(1)))
                counts["factors"] = max(counts["factors"], int(match.group(2)))
        if "[osprey] [infer] [exact]" in line:
            match = re.search(r"\[components (\d+)\].*\[cliques (\d+)", line)
            if match:
                counts["components"] = max(counts["components"], int(match.group(1)))
                counts["cliques"] = max(counts["cliques"], int(match.group(2)))
            max_clique = re.search(r"\[max-clique (\d+)\]", line)
            table_bytes = re.search(r"\[table-bytes (\d+)\]", line)
            if max_clique:
                counts["max_clique_variables"] = max(
                    counts["max_clique_variables"], int(max_clique.group(1))
                )
            if table_bytes:
                counts["exact_table_bytes"] = max(
                    counts["exact_table_bytes"], int(table_bytes.group(1))
                )
            counts["exact_iterations"] += 1
        if "[osprey] [infer] [bp] [version" in line:
            match = re.search(r"\[edges (\d+)\] \[iters (\d+)", line)
            workspace = re.search(r"\[workspace (\d+)\]", line)
            if match:
                counts["bp_edges"] = max(counts["bp_edges"], int(match.group(1)))
                counts["bp_iterations"] = max(
                    counts["bp_iterations"], int(match.group(2))
                )
            if workspace:
                counts["bp_workspace_bytes"] = max(
                    counts["bp_workspace_bytes"], int(workspace.group(1))
                )
        if "[osprey] [decode]" in line:
            match = re.search(r"\[objects (\d+)\] \[types (\d+)", line)
            if match:
                counts["decoded_objects"] = int(match.group(1))
                counts["decoded_types"] = int(match.group(2))
        if "[osprey] [reject]" in line:
            counts["rejected"] += 1
            if "non-convergence" in line or "fixed graph round failed" in line:
                counts["non_convergence"] += 1
            if "large component" in line or "exact component" in line:
                counts["oversized_components"] += 1
    return counts


def _rejection_reasons(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        if "[osprey] [reject]" not in line:
            continue
        match = re.search(r"\[reason ([^]]+)\]", line)
        reason = match.group(1) if match else "unspecified"
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def _format_counts(counts: dict[str, int]) -> str:
    return ";".join(f"{key}={counts[key]}" for key in sorted(counts))


def _canonical_artifact_counts(
    fact_text: str, graph_text: str, model: dict[str, Any]
) -> dict[str, int]:
    fact_tags = {"access", "base", "copy", "points", "alloc", "may-array"}
    valid_fact_tags = fact_tags | {"region"}
    fact_lines = [line for line in fact_text.splitlines() if line]
    unknown_fact_tags = sorted(
        {line.split(" ", 1)[0] for line in fact_lines} - valid_fact_tags
    )
    if unknown_fact_tags:
        raise EvaluationError(f"unknown canonical fact rows {unknown_fact_tags}")
    graph_lines = graph_text.splitlines()
    if not graph_lines or graph_lines[0] != "OSPREY_GRAPH 1":
        raise EvaluationError("invalid canonical graph header")
    facts = sum(1 for line in fact_lines if line.split(" ", 1)[0] in fact_tags)
    relations = 0
    variables = 0
    factors = 0
    in_relations = False
    for line in graph_lines:
        if line == "RELATIONS":
            in_relations = True
            continue
        if line.startswith("PREDICATES "):
            in_relations = False
            variables = int(line.split()[1])
            continue
        if line.startswith("FACTORS "):
            factors = int(line.split()[1])
            continue
        if in_relations and re.match(r"^R(?:0[1-9]|1[0-2]) ", line):
            relations += 1
    return {
        "facts": facts,
        "relations": relations,
        "variables": variables,
        "factors": factors,
        "decoded_objects": len(model["objects"]),
        "decoded_types": len(model["types"]),
    }


def _fact_accesses_in_function(
    fact_text: str, function_range: Any
) -> set[tuple[int, int, int, int, int]]:
    if not isinstance(function_range, (list, tuple)) or len(function_range) != 2:
        return set()
    low, high = (int(function_range[0]), int(function_range[1]))
    if high <= low:
        return set()
    accesses: set[tuple[int, int, int, int, int]] = set()
    for line in fact_text.splitlines():
        fields = line.split()
        if len(fields) not in (8, 9) or fields[0] != "access":
            continue
        try:
            pc = int(fields[1], 16)
            offset = int(fields[5], 16)
            if offset >= 1 << 63:
                offset -= 1 << 64
            if low <= pc < high:
                accesses.add(
                    (int(fields[3]), 0, int(fields[4], 16), offset, int(fields[6]))
                )
        except ValueError:
            continue
    return accesses


def _fact_covers_function(fact_text: str, function_range: Any) -> bool:
    return bool(_fact_accesses_in_function(fact_text, function_range))


def _tree_extent(node: Any, pointer_size: int = 8) -> int:
    if not isinstance(node, dict):
        return 0
    kind = node.get("kind")
    if kind == "primitive":
        return int(node.get("size", 0))
    if kind == "pointer":
        return pointer_size
    if kind == "array":
        return int(node.get("count", 0)) * int(node.get("stride", 0))
    if kind == "struct":
        return max(
            (
                int(field["offset"]) + int(field["size"])
                for field in node.get("fields", [])
            ),
            default=0,
        )
    return 0


def _filter_truth_to_accesses(truth: dict[str, Any], fact_text: str) -> dict[str, Any]:
    accesses = _fact_accesses_in_function(fact_text, truth.get("function_range"))
    filtered = dict(truth)
    filtered["variables"] = [
        row
        for row in truth.get("variables", [])
        if _truth_variable_key(row) in accesses
    ]
    complex_types = []
    for row in truth.get("complex_types", []):
        base = _address(row["base"])
        extent = int(row.get("size", _tree_extent(row.get("type", row))))
        if extent <= 0:
            continue
        if any(
            kind == base[0]
            and image == base[1]
            and site == base[2]
            and base[3] <= offset
            and offset + size <= base[3] + extent
            for kind, image, site, offset, size in accesses
        ):
            complex_types.append(row)
    filtered["complex_types"] = complex_types
    covered_bases = {_address(row["base"]) for row in complex_types}
    filtered["pointers"] = [
        row
        for row in truth.get("pointers", [])
        if (
            _truth_variable_key(row) in accesses
            and ("target_type" in row or _address(row["target"]) in covered_bases)
        )
    ]
    return filtered


def _run_timed(
    command: str, cwd: Path, timeout: float, metrics_path: Path
) -> tuple[subprocess.CompletedProcess[str], float, float, int]:
    time_binary = shutil.which("time")
    if time_binary is None:
        raise EvaluationError("GNU time is required for runtime metrics")
    argv = [
        time_binary,
        "-q",
        "-f",
        "%U %S %M",
        "-o",
        str(metrics_path),
        "--",
        *shlex.split(command),
    ]
    start = time.perf_counter()
    completed = subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, "LC_ALL": "C"},
    )
    wall = time.perf_counter() - start
    try:
        values = metrics_path.read_text(encoding="utf-8").splitlines()[-1].split()
        if len(values) != 3:
            raise ValueError("wrong field count")
        cpu = float(values[0]) + float(values[1])
        peak_rss = int(values[2])
    except (IndexError, OSError, ValueError) as exc:
        raise EvaluationError("GNU time did not emit usable metrics") from exc
    return completed, wall, cpu, peak_rss


def _exclusion_counts(exclusions: Iterable[str]) -> str:
    counts: dict[str, int] = {}
    for exclusion in exclusions:
        reason = exclusion.rsplit(":", 1)[-1]
        counts[reason] = counts.get(reason, 0) + 1
    return ";".join(f"{reason}={counts[reason]}" for reason in sorted(counts))


def _empty_metrics() -> dict[str, Any]:
    metrics = {
        "covered_functions": 0,
        "eligible_functions": 0,
        "variables_matched": 0,
        "variables_false_positive": 0,
        "variables_false_negative": 0,
        "variable_precision": 0.0,
        "variable_recall": 0.0,
        "variable_f1": 0.0,
        "complex_matched": 0,
        "complex_false_positive": 0,
        "complex_false_negative": 0,
        "complex_precision": 0.0,
        "complex_recall": 0.0,
        "complex_f1": 0.0,
        "tree_difference_mean": 0.0,
        "tree_difference_median": 0.0,
        "pointer_matched": 0,
        "pointer_false_positive": 0,
        "pointer_false_negative": 0,
        "pointer_precision": 0.0,
        "pointer_recall": 0.0,
        "pointer_f1": 0.0,
    }
    metrics.update(_diagnostic_counts(""))
    return metrics


def evaluate_subject(
    row: ManifestRow, args: argparse.Namespace, output_dir: Path
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": row.stable_id,
        "name": row.name,
        "function": row.function,
        "status": "rejected",
        "exclusions": [],
        "wall_seconds": 0.0,
        "cpu_seconds": 0.0,
        "peak_rss_kib": 0,
    }
    metrics = _empty_metrics()
    try:
        for path in (row.debug, row.stripped, row.input):
            if not path.is_file():
                raise EvaluationError(f"missing input {path}")
        debug_meta = elf_metadata(row.debug)
        stripped_meta = elf_metadata(row.stripped)
        if (debug_meta["class"], debug_meta["machine"]) != (
            stripped_meta["class"],
            stripped_meta["machine"],
        ):
            raise EvaluationError("debug/stripped ELF target mismatch")
        if (
            not debug_meta["build_id"]
            or debug_meta["build_id"] != stripped_meta["build_id"]
        ):
            raise EvaluationError("debug/stripped build-id mismatch or missing")
        expected_build_id = row.metadata.get("build-id", "")
        if expected_build_id and debug_meta["build_id"] != expected_build_id:
            raise EvaluationError("manifest build-id mismatch")
        producer = debug_meta["producer"]
        if row.metadata.get("compiler") and row.metadata["compiler"] not in producer:
            raise EvaluationError("manifest compiler does not match DWARF producer")
        if row.metadata.get("flags") and row.metadata["flags"] not in producer:
            raise EvaluationError("manifest flags do not match DWARF producer")

        debug_sha = _check_digest(
            row.debug, row.metadata.get("debug-sha256", ""), "debug"
        )
        stripped_sha = _check_digest(
            row.stripped, row.metadata.get("stripped-sha256", ""), "stripped"
        )
        input_sha = _check_digest(
            row.input, row.metadata.get("input-sha256", ""), "input"
        )
        result.update(
            {
                "debug_sha256": debug_sha,
                "stripped_sha256": stripped_sha,
                "input_sha256": input_sha,
                "debug_build_id": debug_meta["build_id"],
                "stripped_build_id": stripped_meta["build_id"],
                "compiler": producer,
            }
        )

        workdir = output_dir / row.stable_id
        workdir.mkdir(parents=True, exist_ok=True)
        if args.run_command:
            model_path = workdir / "model.txt"
            facts_path = workdir / "facts.txt"
            graph_path = workdir / "graph.txt"
            log_path = workdir / "run.log"
            metrics_path = workdir / "time.txt"
            for path in (model_path, facts_path, graph_path, log_path, metrics_path):
                path.unlink(missing_ok=True)
                for stale in path.parent.glob(path.name + ".tmp.*"):
                    stale.unlink(missing_ok=True)
            command = args.run_command.format(
                debug=str(row.debug),
                stripped=str(row.stripped),
                input=str(row.input),
                model=str(model_path),
                facts=str(facts_path),
                graph=str(graph_path),
                workdir=str(workdir),
                id=row.stable_id,
                seed=args.seed,
            )
            completed, wall, cpu, peak_rss = _run_timed(
                command, workdir, args.timeout, metrics_path
            )
            result.update(
                {"wall_seconds": wall, "cpu_seconds": cpu, "peak_rss_kib": peak_rss}
            )
            log_text = completed.stdout + completed.stderr
            log_path.write_text(log_text, encoding="utf-8")
            if completed.returncode != 0:
                metrics.update(_diagnostic_counts(log_text))
                result["_rejection_reasons"] = _rejection_reasons(log_text)
                result["rejection_counts"] = _format_counts(
                    result["_rejection_reasons"]
                )
                raise EvaluationError(
                    f"run command exited with status {completed.returncode}"
                )
        else:
            required_pins = {
                "build-id",
                "debug-sha256",
                "stripped-sha256",
                "input-sha256",
                "model-sha256",
                "facts-sha256",
                "graph-sha256",
                "log-sha256",
                "tracer-commit",
            }
            if row.truth is not None:
                required_pins.add("truth-sha256")
            missing_pins = sorted(required_pins - row.metadata.keys())
            if missing_pins:
                raise EvaluationError(
                    f"precomputed artifacts require manifest pins {missing_pins}"
                )
            if (
                args.tracer_commit == "unknown"
                or row.metadata["tracer-commit"] != args.tracer_commit
            ):
                raise EvaluationError("manifest tracer commit mismatch")
            if (
                row.model is None
                or row.facts is None
                or row.graph is None
                or row.log is None
            ):
                raise EvaluationError(
                    "precomputed evaluation requires model/facts/graph/log paths"
                )
            model_path, facts_path = row.model, row.facts
            graph_path, log_path = row.graph, row.log

        if not log_path.is_file():
            raise EvaluationError("log-output-missing")
        result["log_sha256"] = _check_digest(
            log_path, row.metadata.get("log-sha256", ""), "log"
        )
        log_text = log_path.read_text(encoding="utf-8")
        metrics.update(_diagnostic_counts(log_text))
        result["_rejection_reasons"] = _rejection_reasons(log_text)
        result["rejection_counts"] = _format_counts(result["_rejection_reasons"])
        if metrics["rejected"]:
            raise EvaluationError("analysis log contains a rejected transaction")
        if "[osprey] [done] [status 0]" not in log_text:
            raise EvaluationError("analysis log lacks successful model installation")
        for label, path in (
            ("model", model_path),
            ("facts", facts_path),
            ("graph", graph_path),
        ):
            if not path.is_file():
                raise EvaluationError(f"{label}-output-missing")
            digest = _check_digest(path, row.metadata.get(f"{label}-sha256", ""), label)
            result[f"{label}_sha256"] = digest
        model = parse_model_dump(model_path.read_text(encoding="utf-8"))
        fact_text = facts_path.read_text(encoding="utf-8")
        graph_text = graph_path.read_text(encoding="utf-8")
        metrics.update(_canonical_artifact_counts(fact_text, graph_text, model))

        dwarf_truth, dwarf_exclusions = _dwarf_truth(row)
        if row.truth is not None:
            if not row.truth.is_file():
                raise EvaluationError(f"missing ground truth {row.truth}")
            result["truth_sha256"] = _check_digest(
                row.truth, row.metadata.get("truth-sha256", ""), "truth"
            )
            truth = load_truth(row.truth)
            if "function_range" not in truth:
                truth["function_range"] = dwarf_truth.get("function_range")
            exclusions = (
                [] if truth.get("function_range") is not None else dwarf_exclusions
            )
        else:
            truth, exclusions = dwarf_truth, dwarf_exclusions
        if not args.run_command:
            exclusions.append("runtime-metrics-unavailable")

        metrics["eligible_functions"] = int(truth.get("function_range") is not None)
        covered = _fact_covers_function(fact_text, truth.get("function_range"))
        metrics["covered_functions"] = int(covered)
        if covered:
            truth = _filter_truth_to_accesses(truth, fact_text)
            if any(
                truth.get(name) for name in ("variables", "complex_types", "pointers")
            ):
                scored = score_model(model, truth)
                for key, value in scored.items():
                    metrics[key] = value
            else:
                exclusions.append("no-covered-ground-truth")
        else:
            exclusions.append("function-not-covered")
        result["exclusions"] = sorted(exclusions)
        result["status"] = (
            "accepted" if covered and not exclusions else "accepted-with-exclusions"
        )
    except (
        EvaluationError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        result["status"] = "rejected"
        result["exclusions"] = [str(exc)]
    except Exception as exc:  # noqa: BLE001 — every subject gets a result row
        result["status"] = "rejected"
        result["exclusions"] = [f"unexpected: {exc}"]
    result["exclusions"] = sorted(result["exclusions"])
    result["exclusions_total"] = len(result["exclusions"])
    result["exclusion_counts"] = _exclusion_counts(result["exclusions"])
    result.setdefault("_rejection_reasons", {})
    result.setdefault("rejection_counts", "")
    result.update(metrics)
    return result


def _aggregate_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    aggregate: dict[str, Any] = {
        "id": "TOTAL",
        "name": "aggregate",
        "function": "*",
        "status": (
            "rejected"
            if any(row["status"] == "rejected" for row in results)
            else "accepted-with-exclusions"
            if any(row["status"] != "accepted" for row in results)
            else "accepted"
        ),
        "subjects": len(results),
        "rejected_subjects": sum(row["status"] == "rejected" for row in results),
        "excluded_subjects": sum(
            row["status"] == "accepted-with-exclusions" for row in results
        ),
    }
    count_keys = {
        "covered_functions",
        "eligible_functions",
        "variables_matched",
        "variables_false_positive",
        "variables_false_negative",
        "complex_matched",
        "complex_false_positive",
        "complex_false_negative",
        "pointer_matched",
        "pointer_false_positive",
        "pointer_false_negative",
        "facts",
        "relations",
        "variables",
        "factors",
        "components",
        "cliques",
        "bp_edges",
        "decoded_objects",
        "decoded_types",
        "exact_iterations",
        "bp_iterations",
        "rejected",
        "oversized_components",
        "non_convergence",
        "exclusions_total",
    }
    for key in sorted(count_keys):
        aggregate[key] = sum(int(row.get(key, 0)) for row in results)
    for key in ("max_clique_variables", "exact_table_bytes", "bp_workspace_bytes"):
        aggregate[key] = max((int(row.get(key, 0)) for row in results), default=0)
    for prefix in ("variable", "complex", "pointer"):
        precision, recall, f1 = _precision_recall(
            aggregate[
                f"{prefix}s_matched" if prefix == "variable" else f"{prefix}_matched"
            ],
            aggregate[
                f"{prefix}s_false_positive"
                if prefix == "variable"
                else f"{prefix}_false_positive"
            ],
            aggregate[
                f"{prefix}s_false_negative"
                if prefix == "variable"
                else f"{prefix}_false_negative"
            ],
        )
        aggregate[f"{prefix}_precision"] = precision
        aggregate[f"{prefix}_recall"] = recall
        aggregate[f"{prefix}_f1"] = f1
    differences = [
        value for row in results for value in row.get("_tree_differences", [])
    ]
    aggregate["tree_difference_mean"] = (
        statistics.fmean(differences) if differences else 0.0
    )
    aggregate["tree_difference_median"] = (
        statistics.median(differences) if differences else 0.0
    )
    aggregate["tree_difference_count"] = len(differences)
    aggregate["exclusion_counts"] = _exclusion_counts(
        exclusion for row in results for exclusion in row.get("exclusions", [])
    )
    rejection_reasons: dict[str, int] = {}
    for row in results:
        for reason, count in row.get("_rejection_reasons", {}).items():
            rejection_reasons[reason] = rejection_reasons.get(reason, 0) + count
    aggregate["rejection_counts"] = _format_counts(rejection_reasons)
    aggregate["exclusions"] = []
    aggregate["wall_seconds"] = sum(
        float(row.get("wall_seconds", 0.0)) for row in results
    )
    aggregate["cpu_seconds"] = sum(
        float(row.get("cpu_seconds", 0.0)) for row in results
    )
    aggregate["peak_rss_kib"] = max(
        (int(row.get("peak_rss_kib", 0)) for row in results), default=0
    )
    return aggregate


def _stable_result_fields(result: dict[str, Any], kind: str) -> list[tuple[str, Any]]:
    fields: list[tuple[str, Any]] = [
        ("schema", SCHEMA_VERSION),
        ("kind", kind),
        ("id", result["id"]),
        ("name", result["name"]),
        ("function", result["function"]),
        ("status", result["status"]),
    ]
    omitted = {
        "id",
        "name",
        "function",
        "status",
        "wall_seconds",
        "cpu_seconds",
        "peak_rss_kib",
        "exclusions",
    }
    for key in sorted(result):
        if key in omitted or key.startswith("_"):
            continue
        fields.append((key, result[key]))
    fields.append(("exclusions", ",".join(result.get("exclusions", []))))
    return fields


def _write_outputs(
    results: list[dict[str, Any]], output_prefix: Path, metadata: dict[str, str]
) -> None:
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    detail = output_prefix.with_suffix(".sbsv")
    csv_path = output_prefix.with_suffix(".csv")
    lines = [
        _sbsv_row(
            "evaluation",
            [
                ("schema", SCHEMA_VERSION),
                ("kind", "meta"),
                ("seed", metadata["seed"]),
                ("jobs", metadata["jobs"]),
                ("manifest-sha256", metadata["manifest_sha256"]),
            ],
        )
    ]
    for key in sorted(metadata):
        if key in {"seed", "jobs", "manifest_sha256"}:
            continue
        lines.append(
            _sbsv_row(
                "evaluation",
                [
                    ("schema", SCHEMA_VERSION),
                    ("kind", "meta"),
                    ("key", key),
                    ("value", metadata[key]),
                ],
            )
        )
    stable_results = sorted(results, key=lambda row: (row["id"], row["function"]))
    aggregate = _aggregate_results(stable_results)
    for result in stable_results:
        lines.append(_sbsv_row("evaluation", _stable_result_fields(result, "detail")))
        lines.append(
            _sbsv_row(
                "evaluation",
                [
                    ("schema", SCHEMA_VERSION),
                    ("kind", "timing"),
                    ("id", result["id"]),
                    ("wall-seconds", f"{result.get('wall_seconds', 0.0):.9f}"),
                    ("cpu-seconds", f"{result.get('cpu_seconds', 0.0):.9f}"),
                ],
            )
        )
        lines.append(
            _sbsv_row(
                "evaluation",
                [
                    ("schema", SCHEMA_VERSION),
                    ("kind", "rss"),
                    ("id", result["id"]),
                    ("peak-rss-kib", result.get("peak_rss_kib", 0)),
                ],
            )
        )
    lines.append(_sbsv_row("evaluation", _stable_result_fields(aggregate, "aggregate")))
    lines.append(
        _sbsv_row(
            "evaluation",
            [
                ("schema", SCHEMA_VERSION),
                ("kind", "timing"),
                ("id", "TOTAL"),
                ("wall-seconds", f"{aggregate['wall_seconds']:.9f}"),
                ("cpu-seconds", f"{aggregate['cpu_seconds']:.9f}"),
            ],
        )
    )
    lines.append(
        _sbsv_row(
            "evaluation",
            [
                ("schema", SCHEMA_VERSION),
                ("kind", "rss"),
                ("id", "TOTAL"),
                ("peak-rss-kib", aggregate["peak_rss_kib"]),
            ],
        )
    )
    detail.write_text("\n".join(lines) + "\n", encoding="utf-8")

    csv_rows = [*stable_results, aggregate]
    omitted = {"wall_seconds", "cpu_seconds", "peak_rss_kib", "exclusions"}
    csv_fields = sorted(
        {
            key
            for result in csv_rows
            for key in result
            if key not in omitted and not key.startswith("_")
        }
    )
    csv_fields.insert(0, "kind")
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for result in csv_rows:
            row = {key: result.get(key, "") for key in csv_fields}
            row["kind"] = "aggregate" if result is aggregate else "detail"
            writer.writerow(row)


def _run_once(
    rows: list[ManifestRow],
    args: argparse.Namespace,
    manifest_sha: str,
    output_prefix: Path,
) -> list[dict[str, Any]]:
    output_dir = output_prefix.resolve().parent / (output_prefix.name + ".subjects")
    worker = lambda row: evaluate_subject(row, args, output_dir)
    if args.jobs == 1:
        results = [worker(row) for row in rows]
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(worker, rows))
    metadata = {
        "seed": str(args.seed),
        "jobs": str(args.jobs),
        "manifest_sha256": manifest_sha,
        "tracer_commit": args.tracer_commit,
        "superproject_commit": args.superproject_commit,
        "python": sys.version.split()[0],
        "pyelftools": importlib_metadata.version("pyelftools"),
        "tree_costs": (
            "unit-node-substitute,unit-subtree-insert-delete,ordered-fields"
        ),
    }
    _write_outputs(results, output_prefix.resolve(), metadata)
    return results


def _stable_output(path: Path) -> str:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if "[kind timing]" in line or "[kind rss]" in line:
            continue
        lines.append(line)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output-prefix", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="run the fixed manifest repeatedly and compare stable rows",
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--run-command", default="")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--tracer-commit", required=True)
    parser.add_argument("--superproject-commit", required=True)
    args = parser.parse_args(argv)
    if args.jobs < 1 or args.repeat < 1:
        parser.error("--jobs and --repeat must be positive")
    rows = load_manifest(args.manifest)
    manifest_sha = sha256_file(args.manifest.resolve())
    prefixes = (
        [args.output_prefix.resolve()]
        if args.repeat == 1
        else [
            args.output_prefix.resolve().with_name(f"{args.output_prefix.name}-{index}")
            for index in range(args.repeat)
        ]
    )
    all_results = []
    for prefix in prefixes:
        all_results.append(_run_once(rows, args, manifest_sha, prefix))
    stable = [
        _stable_output(prefix.with_suffix(".sbsv"))
        + "\0CSV\n"
        + prefix.with_suffix(".csv").read_text(encoding="utf-8")
        for prefix in prefixes
    ]
    reproducible = len(set(stable)) == 1
    if args.repeat > 1:
        repro_path = args.output_prefix.resolve().with_suffix(".reproducibility.sbsv")
        rows_out = [
            _sbsv_row(
                "evaluation",
                [
                    ("schema", SCHEMA_VERSION),
                    ("kind", "reproducibility"),
                    ("runs", args.repeat),
                    ("stable", str(reproducible).lower()),
                    ("stable-sha256", hashlib.sha256(stable[0].encode()).hexdigest()),
                ],
            )
        ]
        for index, text in enumerate(stable):
            rows_out.append(
                _sbsv_row(
                    "evaluation",
                    [
                        ("schema", SCHEMA_VERSION),
                        ("kind", "run"),
                        ("run", index),
                        ("stable-sha256", hashlib.sha256(text.encode()).hexdigest()),
                    ],
                )
            )
        repro_path.write_text("\n".join(rows_out) + "\n", encoding="utf-8")
    successful = all(
        result["status"] != "rejected" for results in all_results for result in results
    )
    return 0 if successful and reproducible else 1


if __name__ == "__main__":
    raise SystemExit(main())
