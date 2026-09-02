#!/usr/bin/env python3
"""Tests for SBSV parsing in binradar-collect-results.py."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "binradar_collect_results",
    ROOT / "benchmarks" / "scripts" / "binradar-collect-results.py",
)
collector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collector)


def test_parse_prefilter_new_id_rows(tmp_path):
    path = tmp_path / "prefilter.sbsv"
    path.write_text(
        "[prefilter] [res] [id 1] [pass false] [new-id -1]\n"
        "[prefilter] [res] [id 4] [pass true] [new-id 1]\n"
        "[prefilter] [done] [total 2] [survived 1] [time 0.1]\n"
    )
    assert collector.parse_prefilter_sbsv(str(path)) == {
        "total": 2,
        "survived": 1,
        "done": 1,
    }


def test_parse_prefilter_meta_row(tmp_path):
    """The versioned [prefilter] [meta] row is accepted and ignored."""
    path = tmp_path / "prefilter.sbsv"
    path.write_text(
        "[prefilter] [meta] [version 1] [kind generic-erm] "
        "[sha256 0123456789abcdef]\n"
        "[prefilter] [res] [id 1] [pass false] [new-id -1]\n"
        "[prefilter] [res] [id 4] [pass true] [new-id 1]\n"
        "[prefilter] [done] [total 2] [survived 1] [time 0.1]\n"
    )
    assert collector.parse_prefilter_sbsv(str(path)) == {
        "total": 2,
        "survived": 1,
        "done": 1,
    }


def test_prefilter_skipped_for_existing_brpatched_without_predicates(tmp_path):
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    out_dir.mkdir(parents=True)
    (workdir / "sample.brpatched").touch()
    (out_dir / "progress.sbsv").write_text(
        "[filter] [start] [prefix run] [id 0]\n"
        "[filter] [done] [prefix run] [id 0] [survived []]\n"
    )

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run")

    assert result.runs[0].prefilter_done is collector.DoneStatus.SKIPPED
    assert "status: SKIPPED" in collector.format_result_log(result)
    csv_row = collector.format_results_csv([result])[0]
    assert csv_row["prefilter_done"] == "SKIPPED"


def test_parse_timestamped_progress_with_sbsv(tmp_path):
    path = tmp_path / "progress.sbsv"
    path.write_text(
        "2026-08-12 00:00:00,000 - "
        "[rundir] [set] [prefix run] [id 0] [dir /tmp/run] [time 1]\n"
        "2026-08-12 00:00:00,001 - "
        "[filter] [done] [prefix run] [id 0] [survived [1, 2]] [time 2]\n"
        "2026-08-12 00:00:00,002 - "
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches []] [time 3]\n"
    )
    rows = collector.parse_progress_sbsv(str(path))
    assert rows[0]["_phase"] == "rundir"
    assert rows[0]["_action"] == "set"
    assert rows[1]["survived"] == "[1, 2]"
    assert rows[2]["remaining_patches"] == "[1]"


def test_parse_final_sbsv(tmp_path):
    path = tmp_path / "final.sbsv"
    path.write_text(
        "[final] [start] [prefix run] [id 0] "
        "[verifier verifier.sbsv] [trace binradar-tracer-msg.log]\n"
        "[final] [verifier] [patch 1] [res verified]\n"
        "[final] [verifier] [patch 2] [res rejected]\n"
        "[final] [binradar] [patch 1] [res verified] [reason none] [iter -1]\n"
        "[final] [binradar] [patch 2] [res rejected] "
        "[reason different-br] [iter 3]\n"
        "[final] [confidence] [patch 1] [score 0.5] "
        "[accept-evidences 1] [total-evidences 2]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches []]\n"
    )
    verifier, binradar, confidence = collector.parse_final_sbsv(str(path))
    assert verifier == {1: "verified", 2: "rejected"}
    assert binradar == {
        1: {"res": "verified", "reason": "none", "iter": "-1"},
        2: {"res": "rejected", "reason": "different-br", "iter": "3"},
    }
    assert confidence == {
        1: {"score": "0.5", "accept-evidences": "1",
            "total-evidences": "2"},
    }


def test_top_patches_by_confidence_ranking_and_ties():
    confidence = {
        1: {"score": "0.5"},
        2: {"score": "1.0"},
        3: {"score": "0.75"},
        4: {"score": "0.75"},
        5: {"score": "0.0"},
    }
    top, total = collector.top_patches_by_confidence(confidence, 3)
    assert top == [2, 3, 4]
    assert total == 5


def test_collect_cutoff_top_patches_by_confidence(tmp_path):
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[rundir] [set] [prefix run] [id 0] [dir /tmp/run]\n"
        "[filter] [done] [prefix run] [id 0] [survived [1, 2, 3, 4, 5]]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1, 2, 3, 4, 5]] "
        "[binradar_remaining_patches [1, 2, 3, 4, 5]]\n"
    )
    (run_dir / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-result] [res verified] [patch 2] [testcase ]\n"
        "[verifier-result] [res verified] [patch 3] [testcase ]\n"
        "[verifier-result] [res verified] [patch 4] [testcase ]\n"
        "[verifier-result] [res verified] [patch 5] [testcase ]\n"
    )
    (run_dir / "final.sbsv").write_text(
        "[final] [verifier] [patch 1] [res verified]\n"
        "[final] [verifier] [patch 2] [res verified]\n"
        "[final] [verifier] [patch 3] [res verified]\n"
        "[final] [verifier] [patch 4] [res verified]\n"
        "[final] [verifier] [patch 5] [res verified]\n"
        "[final] [confidence] [patch 1] [score 0.5] "
        "[accept-evidences 1] [total-evidences 2]\n"
        "[final] [confidence] [patch 2] [score 1.0] "
        "[accept-evidences 2] [total-evidences 2]\n"
        "[final] [confidence] [patch 3] [score 0.75] "
        "[accept-evidences 3] [total-evidences 4]\n"
        "[final] [confidence] [patch 4] [score 0.75] "
        "[accept-evidences 3] [total-evidences 4]\n"
        "[final] [confidence] [patch 5] [score 0.25] "
        "[accept-evidences 1] [total-evidences 4]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1, 2, 3, 4, 5]] "
        "[binradar_remaining_patches [1, 2, 3, 4, 5]]\n"
    )

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run", top_patches=3)

    run_res = result.runs[0]
    assert run_res.top_patches == [2, 3, 4]
    assert run_res.top_patches_total == 5
    assert run_res.verifier_accepted == "2,3,4"
    log = collector.format_result_log(result)
    assert "top 3 of 5 by confidence" in log
    assert "patch 2:" in log
    assert "patch 3:" in log
    assert "patch 4:" in log
    assert "patch 1:" not in log
    assert "patch 5:" not in log
    assert "(+2 more)" in log
    csv_row = collector.format_results_csv([result])[0]
    assert csv_row["verifier_accepted_patches"] == "2,3,4"
    assert csv_row["verifier_rejected_patches"] == ""
    assert "(+2 more)" in csv_row["remaining_patches"]


def test_collect_taosc_counts_original_and_prefiltered_predicates(tmp_path):
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()
    (workdir / "predicates").write_text("first\n\nsecond\n")
    (workdir / "prefilter.sbsv").write_text(
        "[prefilter] [meta] [version 1] [kind generic-erm] [sha256 abc]\n"
        "[prefilter] [res] [id 1] [pass true] [new-id 1]\n"
        "[prefilter] [res] [id 2] [pass false] [new-id -1]\n"
        "[prefilter] [done] [total 2] [survived 1] [time 0.1]\n"
    )

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.status == "ok"
    assert result.original_predicates == 2
    assert result.prefiltered_predicates == 1
    assert result.prefilter_total == 2
    assert result.prefilter_done is collector.DoneStatus.OK
    assert "original predicates: 2" in collector.format_taosc_result_log(result)
    assert "prefiltered predicates: 1" in collector.format_taosc_result_log(result)

    row = collector.format_taosc_results_csv([result])[0]
    assert row["original_predicates"] == "2"
    assert row["prefiltered_predicates"] == "1"


def test_collect_taosc_skips_prefilter_without_predicates(tmp_path):
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.status == "ok"
    assert result.original_predicates == 0
    assert result.prefiltered_predicates == 0
    assert result.prefilter_done is collector.DoneStatus.SKIPPED


def test_collect_taosc_skips_prefilter_with_single_patch_format(tmp_path):
    """A Single CWE-* patch-format skips the prefilter even with a brpatched."""
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()
    (workdir / "patch-format").write_text("Single CWE-617\n")
    (workdir / "sample.brpatched").touch()

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.status == "ok"
    assert result.patch_format == "Single CWE-617"
    assert result.original_predicates == 0
    assert result.prefiltered_predicates == 0
    assert result.prefilter_done is collector.DoneStatus.SKIPPED
    assert "patch-format: Single CWE-617" in collector.format_taosc_result_log(result)
    row = collector.format_taosc_results_csv([result])[0]
    assert row["patch_format"] == "Single CWE-617"


def test_collect_taosc_erm_patch_format_without_prefilter_is_incomplete(tmp_path):
    """An ERM patch-format with no prefilter.sbsv is INCOMPLETE, not skipped."""
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()
    (workdir / "patch-format").write_text("ERM generic\n")
    (workdir / "predicates").write_text("max1 - rax == ~max1\n")

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.patch_format == "ERM generic"
    assert result.original_predicates == 1
    assert result.prefilter_done is collector.DoneStatus.INCOMPLETE
    assert result.status == "issues"


def test_prefilter_skipped_for_single_patch_format(tmp_path):
    """A Single CWE-* patch-format marks the binradar prefilter as skipped."""
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    out_dir.mkdir(parents=True)
    (workdir / "patch-format").write_text("Single CWE-805\n")
    (workdir / "sample.brpatched").touch()
    (out_dir / "progress.sbsv").write_text(
        "[filter] [start] [prefix run] [id 0]\n"
        "[filter] [done] [prefix run] [id 0] [survived []]\n"
    )

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run")

    assert result.runs[0].prefilter_done is collector.DoneStatus.SKIPPED
    assert "status: SKIPPED" in collector.format_result_log(result)
