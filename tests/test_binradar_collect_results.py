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
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches []]\n"
    )
    verifier, binradar = collector.parse_final_sbsv(str(path))
    assert verifier == {1: "verified", 2: "rejected"}
    assert binradar == {
        1: {"res": "verified", "reason": "none", "iter": "-1"},
        2: {"res": "rejected", "reason": "different-br", "iter": "3"},
    }
