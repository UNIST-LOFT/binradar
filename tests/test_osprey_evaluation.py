import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "osprey_evaluation", ROOT / "fuzzolic" / "osprey-evaluation.py"
)
assert SPEC is not None and SPEC.loader is not None
evaluation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evaluation
SPEC.loader.exec_module(evaluation)


def _address(kind, image, site, offset):
    return {"kind": kind, "image": image, "site": site, "offset": offset}


def _model_text():
    return "".join(
        f"{line}\n"
        for line in [
            "[model-version 1] [objects 3] [types 3] [fields 2]",
            "[type] [id 0] [kind struct] [name struct_h] [size 16] [count 0] [element-size 0] [element-type 4294967295] [target-void 0] [target-type 4294967295] [field-begin 0] [field-count 2] [evidence 1] [posterior-bits 0x3fe0000000000000] [support 1] [rules 0x1] [base-region 1] [base-image 0x0000000000000000] [base-site 0x0000000000000100] [base-offset 0]",
            "[type] [id 1] [kind primitive] [name prim_b8] [size 8] [count 0] [element-size 0] [element-type 4294967295] [target-void 0] [target-type 4294967295] [field-begin 0] [field-count 0] [evidence 1] [posterior-bits 0x3fe0000000000000] [support 1] [rules 0x1] [base-region 0] [base-image 0x0000000000000000] [base-site 0x0000000000000000] [base-offset 0]",
            "[type] [id 2] [kind pointer] [name ptr] [size 8] [count 0] [element-size 0] [element-type 4294967295] [target-void 0] [target-type 0] [field-begin 0] [field-count 0] [evidence 1] [posterior-bits 0x3fe0000000000000] [support 1] [rules 0x1] [base-region 0] [base-image 0x0000000000000000] [base-site 0x0000000000000000] [base-offset 0]",
            "[field] [id 0] [owner-region 1] [owner-image 0x0000000000000000] [owner-site 0x0000000000000100] [owner-offset 0] [relative 0] [value-type 1] [posterior-bits 0x3fe0000000000000] [support 1] [rules 0x1] [chunk-region 1] [chunk-image 0x0000000000000000] [chunk-site 0x0000000000000100] [chunk-offset 0] [size 8]",
            "[field] [id 1] [owner-region 1] [owner-image 0x0000000000000000] [owner-site 0x0000000000000100] [owner-offset 0] [relative 8] [value-type 1] [posterior-bits 0x3fe0000000000000] [support 1] [rules 0x1] [chunk-region 1] [chunk-image 0x0000000000000000] [chunk-site 0x0000000000000100] [chunk-offset 8] [size 8]",
            "[object] [id 0] [role field] [value-type 1] [pointer 0] [storage-posterior-bits 0x3fe0000000000000] [storage-support 1] [storage-rules 0x1] [pointer-posterior-bits 0x0000000000000000] [pointer-support 0] [pointer-rules 0x0] [chunk-region 1] [chunk-image 0x0000000000000000] [chunk-site 0x0000000000000100] [chunk-offset 0] [size 8] [owner-region 1] [owner-image 0x0000000000000000] [owner-site 0x0000000000000100] [owner-offset 0]",
            "[object] [id 1] [role field] [value-type 1] [pointer 0] [storage-posterior-bits 0x3fe0000000000000] [storage-support 1] [storage-rules 0x1] [pointer-posterior-bits 0x0000000000000000] [pointer-support 0] [pointer-rules 0x0] [chunk-region 1] [chunk-image 0x0000000000000000] [chunk-site 0x0000000000000100] [chunk-offset 8] [size 8] [owner-region 1] [owner-image 0x0000000000000000] [owner-site 0x0000000000000100] [owner-offset 0]",
            "[object] [id 2] [role scalar] [value-type 2] [pointer 1] [storage-posterior-bits 0x3fe0000000000000] [storage-support 1] [storage-rules 0x1] [pointer-posterior-bits 0x3fe0000000000000] [pointer-support 1] [pointer-rules 0x1] [chunk-region 0] [chunk-image 0x0000000000000000] [chunk-site 0x0000000000000000] [chunk-offset 200] [size 8] [owner-region 0] [owner-image 0x0000000000000000] [owner-site 0x0000000000000000] [owner-offset 0] [target-region 1] [target-image 0x0000000000000000] [target-site 0x0000000000000100] [target-offset 0]",
        ]
    )


def test_model_parser_and_metrics_are_canonical():
    model = evaluation.parse_model_dump(_model_text())
    truth = {
        "variables": [
            {"chunk": {"address": [1, 0, 0x100, 0], "size": 8}},
            {"chunk": {"address": [1, 0, 0x100, 8], "size": 8}},
            {"chunk": {"address": [0, 0, 0, 200], "size": 8}},
        ],
        "complex_types": [
            {
                "base": [1, 0, 0x100, 0],
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"offset": 0, "size": 8},
                        {"offset": 8, "size": 8},
                    ],
                },
            }
        ],
        "pointers": [
            {
                "chunk": {"address": [0, 0, 0, 200], "size": 8},
                "target": [1, 0, 0x100, 0],
            }
        ],
    }
    metrics = evaluation.score_model(model, truth)
    assert metrics["variable_f1"] == pytest.approx(1.0)
    assert metrics["complex_f1"] == pytest.approx(1.0)
    assert metrics["pointer_f1"] == pytest.approx(1.0)
    assert metrics["tree_difference_mean"] == pytest.approx(0.0)


def test_manifest_requires_explicit_sorted_subjects(tmp_path):
    manifest = tmp_path / "subjects.sbsv"
    manifest.write_text(
        "[subject] [id a] [debug debug.bin] [stripped stripped.bin] "
        "[input input.dat] [function huft_build] [name gzip\\ subject]\n",
        encoding="utf-8",
    )
    rows = evaluation.load_manifest(manifest)
    assert rows[0].stable_id == "a"
    assert rows[0].name == "gzip subject"
    assert rows[0].debug == (tmp_path / "debug.bin").resolve()


def test_manifest_rejects_duplicate_or_unsorted_ids(tmp_path):
    manifest = tmp_path / "subjects.sbsv"
    row = "[subject] [id b] [debug d] [stripped s] [input i] [function f] [name n]\n"
    manifest.write_text(row + row.replace("id b", "id a"), encoding="utf-8")
    with pytest.raises(evaluation.EvaluationError):
        evaluation.load_manifest(manifest)


def test_model_parser_accepts_array_rows_keyed_by_type_id():
    text = _model_text().replace("[id 2] [kind pointer]", "[id 2] [kind array]")
    array_row = (
        "[array] [id 2] [lo 0] [hi 16] [size 16] [stride 8] "
        "[count 2] [element-type 1] "
        "[posterior-bits 0x3fe0000000000000] [support 1] "
        "[rules 0x1] [base-region 1] "
        "[base-image 0x0000000000000000] "
        "[base-site 0x0000000000000100] [base-offset 0]\n"
    )
    text = text.replace("[object] [id 0]", array_row + "[object] [id 0]", 1)
    model = evaluation.parse_model_dump(text)
    assert model["arrays"][0]["id"] == 2


def test_tree_distance_is_normalized_by_node_count():
    left = ("struct", ((0, 8, ("primitive", 8)),))
    right = ("struct", ((0, 8, ("primitive", 8)), (8, 8, ("primitive", 8))))
    assert evaluation.tree_distance(left, right) == 1
    assert evaluation.tree_size(right) == 3


def test_output_rows_separate_timing_and_rss(tmp_path):
    result = {
        "id": "a",
        "name": "subject",
        "function": "f",
        "status": "accepted",
        "variables_matched": 1,
        "wall_seconds": 0.1,
        "cpu_seconds": 0.05,
        "peak_rss_kib": 12,
        "exclusions": [],
    }
    prefix = tmp_path / "evaluation"
    evaluation._write_outputs(
        [result], prefix, {"seed": "0", "jobs": "1", "manifest_sha256": "x"}
    )
    text = prefix.with_suffix(".sbsv").read_text(encoding="utf-8")
    assert "[kind detail]" in text
    assert "[kind timing]" in text
    assert "[kind rss]" in text
    assert "[kind aggregate]" in text
    csv_text = prefix.with_suffix(".csv").read_text(encoding="utf-8")
    assert "wall_seconds" not in csv_text.splitlines()[0]
    assert ",aggregate," in csv_text


def test_complex_and_pointer_matches_require_structural_types():
    model = evaluation.parse_model_dump(_model_text())
    truth = {
        "variables": [],
        "complex_types": [
            {
                "base": [1, 0, 0x100, 0],
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"offset": 0, "size": 8},
                        {"offset": 8, "size": 8},
                    ],
                },
            }
        ],
        "pointers": [
            {
                "chunk": {"address": [0, 0, 0, 200], "size": 8},
                "target": [1, 0, 0x100, 0],
            }
        ],
    }
    model["types"][0]["field_count"] = 1
    metrics = evaluation.score_model(model, truth)
    assert metrics["complex_matched"] == 0
    assert metrics["pointer_matched"] == 0

    model = evaluation.parse_model_dump(_model_text())
    model["types"][2]["target_void"] = 1
    metrics = evaluation.score_model(model, truth)
    assert metrics["pointer_matched"] == 0


def test_tree_distance_stays_normalized_for_array_geometry():
    left = ("array", 100, 8, ("primitive", 8))
    right = ("array", 1, 4, ("primitive", 4))
    distance = evaluation.tree_distance(left, right)
    assert distance == 2
    assert (
        distance / max(evaluation.tree_size(left), evaluation.tree_size(right)) == 1.0
    )


def test_dwarf_truth_uses_entry_rsp_canonical_offsets(tmp_path):
    source = tmp_path / "fixture.c"
    debug = tmp_path / "fixture.debug"
    stripped = tmp_path / "fixture"
    source.write_text(
        "typedef struct Pair { unsigned long a; unsigned long b; } Pair;\n"
        "__attribute__((noinline)) unsigned long target(unsigned long x) {\n"
        "  volatile Pair pair = {x, x + 1}; return pair.a + pair.b;\n"
        "}\nint main(void) { return (int)target(1); }\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "cc",
            "-O0",
            "-g",
            "-fPIE",
            "-pie",
            "-fomit-frame-pointer",
            "-o",
            str(debug),
            str(source),
        ],
        check=True,
    )
    shutil.copy2(debug, stripped)
    subprocess.run(["strip", "--strip-all", str(stripped)], check=True)
    row = evaluation.ManifestRow(
        "fixture", debug, stripped, source, "target", "fixture"
    )
    truth, exclusions = evaluation._dwarf_truth(row)
    assert not exclusions
    assert truth["function_range"][0] >= 0
    pair = [item for item in truth["variables"] if item["name"].startswith("pair.")]
    assert len(pair) == 2
    assert pair[0]["chunk"]["address"][0:2] == [2, 0]
    assert pair[0]["chunk"]["address"][2] == truth["function_range"][0]
    complex_type = next(
        item
        for item in truth["complex_types"]
        if item["base"] == pair[0]["chunk"]["address"]
    )
    assert [field["offset"] for field in complex_type["type"]["fields"]] == [0, 8]


def test_failed_run_command_cannot_accept_fresh_model(tmp_path, monkeypatch):
    for name in ("debug", "stripped", "input"):
        (tmp_path / name).write_bytes(b"x")
    row = evaluation.ManifestRow(
        "fixture",
        tmp_path / "debug",
        tmp_path / "stripped",
        tmp_path / "input",
        "target",
        "fixture",
    )
    metadata = {
        "class": "64",
        "machine": "EM_X86_64",
        "build_id": "abc",
        "executable_base": "4096",
        "producer": "cc",
    }
    monkeypatch.setattr(evaluation, "elf_metadata", lambda _path: metadata)
    monkeypatch.setattr(
        evaluation,
        "_run_timed",
        lambda *_args: (
            subprocess.CompletedProcess([], 7, "", "failed"),
            0.1,
            0.05,
            10,
        ),
    )
    args = argparse.Namespace(
        run_command="false", timeout=1, tracer_commit="abc", seed=0
    )
    result = evaluation.evaluate_subject(row, args, tmp_path / "out")
    assert result["status"] == "rejected"
    assert "status 7" in result["exclusions"][0]

    monkeypatch.setattr(
        evaluation,
        "_run_timed",
        lambda *_args: (
            subprocess.CompletedProcess(
                [],
                0,
                "[osprey] [reject] [status 9] [stage infer] "
                "[reason fixed graph round failed]\n",
                "",
            ),
            0.1,
            0.05,
            10,
        ),
    )
    result = evaluation.evaluate_subject(row, args, tmp_path / "out-reject")
    assert result["status"] == "rejected"
    assert result["rejected"] == 1
    assert result["rejection_counts"] == "fixed graph round failed=1"
