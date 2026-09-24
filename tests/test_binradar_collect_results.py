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


def test_parse_compact_filter_and_verifier_artifacts(tmp_path):
    filter_path = tmp_path / "filter.br"
    collector.binradar_evidence.write_filter(filter_path, 3, [1, 3])
    assert collector.parse_filter_sbsv(str(filter_path)) == {
        1: True, 2: False, 3: True,
    }

    verifier_path = tmp_path / "verifier.br"
    collector.binradar_evidence.write_verifier(
        verifier_path,
        [collector.binradar_evidence.VerifierPatchResult(
            patch=1, verified=False, accept_evidences=1,
            total_evidences=2,
            observations={"crash-fail": 1, "crash-pass": 1})])
    assert collector.parse_verifier_sbsv(str(verifier_path)) == {
        1: ["rejected"],
    }
    stats = collector.parse_verifier_test_result_stats(str(verifier_path))
    assert stats[1]["crash-fail"] == 1
    assert stats[1]["crash-pass"] == 1
    representatives = collector.parse_verifier_representative_stats(
        str(verifier_path))
    assert representatives.runs == -1


def test_collect_verifier_representative_runs(tmp_path):
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[verifier] [start] [prefix run] [id 0]\n"
        "[verifier] [done] [prefix run] [id 0]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1, 2]] "
        "[binradar_remaining_patches [1, 2]]\n")
    collector.binradar_evidence.write_verifier(
        run_dir / "verifier.br",
        [
            collector.binradar_evidence.VerifierPatchResult(
                patch=1, verified=True, accept_evidences=2,
                total_evidences=2, observations={"crash-pass": 2}),
            collector.binradar_evidence.VerifierPatchResult(
                patch=2, verified=True, accept_evidences=2,
                total_evidences=2, observations={"crash-pass": 2}),
            collector.binradar_evidence.VerifierPatchResult(
                patch=3, verified=False, accept_evidences=0,
                total_evidences=1, observations={"crash-fail": 1}),
            collector.binradar_evidence.VerifierPatchResult(
                patch=4, verified=False, accept_evidences=0,
                total_evidences=1, observations={"crash-fail": 1}),
        ])
    (run_dir / "verifier.log").write_text(
        "2026-09-15 00:00:00,000 - "
        "[verifier-cache] [miss] [patch 1] [id 0] [file first]\n"
        "2026-09-15 00:00:00,001 - "
        "[verifier-cache] [group] [representative 1] [members 3] [id 0]\n"
        "[verifier-cache] [miss] [patch 4] [id 0] [file first]\n"
        "[verifier-cache] [fallback] [patch 4] [id 0]\n"
        "[testcase] [try] [patch 4] [id 0] / 2: [file first]\n"
        "[verifier-cache] [miss] [patch 1] [id 1] [file second]\n"
        "[verifier-cache] [group] [representative 1] [members 2] [id 1]\n")

    result = collector.collect_stats_experiment(
        str(tmp_path), "workdir", "run")

    run = result.runs[0]
    assert run.verifier_observations == 6
    assert run.representatives.source == "verifier.log"
    assert run.representatives.testcases == 2
    assert run.representatives.runs == 3
    assert run.representatives.represented_patch_runs == 6
    assert run.representatives.fallbacks == 1

    log = collector.format_stats_result_log(result)
    assert "[representatives] runs: 3" in log
    assert "runs/testcase: 1.50" in log
    assert "representative runs avoided: 3 (50.00%)" in log

    csv_row = collector.format_stats_results_csv([result])[0]
    assert csv_row["verifier_observations"] == "6"
    assert csv_row["representative_runs"] == "3"
    assert csv_row["representative_runs_per_testcase"] == "1.50"
    assert csv_row["represented_patch_runs"] == "6"
    assert csv_row["representative_saved_runs"] == "3"
    assert csv_row["representative_reduction_pct"] == "50.00"
    assert csv_row["representative_fallbacks"] == "1"


def test_parse_individual_verifier_runs_as_representatives(tmp_path):
    verifier_log = tmp_path / "verifier.log"
    verifier_log.write_text(
        "2026-09-22 01:53:41,426 - "
        "[testcase] [try] [patch 1] [id 0] / 1: [file first]\n"
        "[testcase] [try] [patch 1] [id 1] / 2: [file second]\n"
        "[testcase] [try] [patch 1] [id 2] / 3: [file third]\n")

    representatives = collector.parse_verifier_representative_stats(
        str(verifier_log))

    assert representatives.source == "verifier.log"
    assert representatives.testcases == 3
    assert representatives.runs == 3
    assert representatives.represented_patch_runs == 3
    assert representatives.fallbacks == 0


def test_parse_filter_new_id_rows(tmp_path):
    path = tmp_path / "filter.sbsv"
    path.write_text(
        "[filter] [res] [id 1] [pass false] [new-id -1]\n"
        "[filter] [res] [id 4] [pass true] [new-id 1]\n"
        "[filter] [done] [total 2] [survived 1] [time 0.1]\n"
    )
    assert collector.parse_setup_filter_sbsv(str(path)) == {
        "total": 2,
        "survived": 1,
        "done": 1,
    }


def test_parse_filter_meta_row(tmp_path):
    """The versioned [filter] [meta] row is accepted and ignored."""
    path = tmp_path / "filter.sbsv"
    path.write_text(
        "[filter] [meta] [version 1] [kind generic-erm] "
        "[sha256 0123456789abcdef]\n"
        "[filter] [res] [id 1] [pass false] [new-id -1]\n"
        "[filter] [res] [id 4] [pass true] [new-id 1]\n"
        "[filter] [done] [total 2] [survived 1] [time 0.1]\n"
    )
    assert collector.parse_setup_filter_sbsv(str(path)) == {
        "total": 2,
        "survived": 1,
        "done": 1,
    }


def test_filter_skipped_for_existing_brpatched_without_predicates(tmp_path):
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

    assert result.runs[0].setup_filter_done is collector.DoneStatus.SKIPPED
    assert "status: SKIPPED" in collector.format_result_log(result)
    csv_row = collector.format_results_csv([result])[0]
    assert csv_row["setup_filter_done"] == "SKIPPED"


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


def test_collect_marks_failed_phases_as_issues(tmp_path):
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[rundir] [set] [prefix run] [id 0] [dir /tmp/run]\n"
        "[fuzzer] [start] [prefix run] [id 0]\n"
        "[fuzzer] [failed] [prefix run] [id 0] [less-strict true]\n"
        "[final] [failed-phases] [prefix run] [id 0] "
        "[failed-phases fuzzer]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches [1]] "
        "[issues true] [failed-phases fuzzer] "
        "[wall-time-reached false]\n")
    (run_dir / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n")

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run")

    run = result.runs[0]
    assert run.issues is True
    assert run.failed_phases == "fuzzer"
    assert run.wall_time_reached is False
    assert run.status == "ISSUES: failed phases: fuzzer"
    assert result.overall_status == "issues"


def test_collect_legacy_degraded_final_still_reports_failed_phases(tmp_path):
    """Runs recorded before the rename must keep their failure meaning."""
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[final] [degraded] [prefix run] [id 0] [failed-phases binradar]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches [1]] "
        "[degraded true] [failed-phases binradar]\n")
    (run_dir / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n")

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run")

    run = result.runs[0]
    assert run.issues is True
    assert run.failed_phases == "binradar"
    assert run.wall_time_reached is False
    assert run.status == "ISSUES: failed phases: binradar"
    assert result.overall_status == "issues"


def test_collect_legacy_cutoff_only_is_not_an_issue(tmp_path):
    """The pre-rename cutoff label must not read back as a failed phase.

    Legacy rows encoded the concrete wall-clock cutoff as the synthetic
    ``minimizer-verifier`` entry of the failure list; that run was a graceful
    cut, so it must report as a cutoff rather than as an issue.
    """
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[verifier] [timeout] [prefix run] [id 0]\n"
        "[final] [degraded] [prefix run] [id 0] "
        "[failed-phases minimizer-verifier]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches [1]] "
        "[degraded true] [failed-phases minimizer-verifier]\n")
    (run_dir / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n")

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run")

    run = result.runs[0]
    assert run.issues is False
    assert run.failed_phases == ""
    assert run.wall_time_reached is True
    assert run.status == "OK (wall-time-reached)"
    assert result.overall_status == "ok"


def test_collect_legacy_cutoff_with_real_failure_reports_only_the_failure(
        tmp_path):
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches [1]] "
        "[degraded true] [failed-phases fuzzer,minimizer-verifier]\n")
    (run_dir / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n")

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run")

    run = result.runs[0]
    assert run.issues is True
    assert run.failed_phases == "fuzzer"
    assert run.wall_time_reached is True
    assert run.status == "ISSUES: failed phases: fuzzer; wall-time-reached"


def test_collect_wall_time_reached_is_not_an_issue(tmp_path):
    """A graceful wall-clock cutoff is expected behavior, not a failure."""
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[verifier] [wall-time-reached] [prefix run] [id 0]\n"
        "[final] [wall-time-reached] [prefix run] [id 0]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches [1]] "
        "[issues false] [failed-phases none] "
        "[wall-time-reached true]\n")
    (run_dir / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n")

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run")

    run = result.runs[0]
    assert run.wall_time_reached is True
    assert run.issues is False
    assert run.failed_phases == ""
    assert run.status == "OK (wall-time-reached)"
    assert result.overall_status == "ok"


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


def _make_run(tmp_path, name, progress_lines):
    """Create an experiment dir with one workdir/out/progress.sbsv."""
    exp_dir = tmp_path / name
    (exp_dir / "workdir" / "out").mkdir(parents=True)
    (exp_dir / "workdir" / "out" / "progress.sbsv").write_text(progress_lines)
    return str(exp_dir)


def test_collect_at_least_one_remaining_patches(tmp_path):
    """at_least_one_remaining_patches is True only for a FINAL run with a
    non-empty remaining_patches list; csv/tsv places it next to has_final."""
    final_one = _make_run(
        tmp_path, "exp-one",
        # FINAL with one remaining patch -> True
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1]] [binradar_remaining_patches [1]]\n")
    final_none = _make_run(
        tmp_path, "exp-none",
        # FINAL with no remaining patches -> False
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches []] [binradar_remaining_patches []]\n")
    no_final = _make_run(
        tmp_path, "exp-no-final",
        # never reached FINAL -> False
        "[filter] [done] [prefix run] [id 0] [survived [1, 2]]\n")

    results = [
        collector.collect_experiment_result(d, "workdir", "run")
        for d in (final_one, final_none, no_final)
    ]

    assert [r.runs[0].at_least_one_remaining_patches for r in results] == \
        [True, False, False]

    rows = collector.format_results_csv(results)
    assert [row["at_least_one_remaining_patches"] for row in rows] == \
        ["True", "False", "False"]
    columns = collector.CSV_COLUMNS
    assert columns.index("at_least_one_remaining_patches") == \
        columns.index("has_final") + 1


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
    assert run_res.verifier_rejected == ""
    log = collector.format_result_log(result)
    assert "top 3 of 5 by confidence" in log
    assert "patch 2:" in log
    assert "patch 3:" in log
    assert "patch 4:" in log
    assert "patch 1:" not in log
    assert "patch 5:" not in log
    assert "(+2 more)" in log
    csv_row = collector.format_results_csv([result])[0]
    assert "verifier_accepted_patches" not in csv_row
    assert "binradar_verified_patches" not in csv_row
    assert csv_row["verifier_rejected_patches"] == ""
    assert "binradar_rejected_patches" in csv_row
    assert "(+2 more)" in csv_row["remaining_patches"]


def test_collect_reports_untruncated_binradar_counts(tmp_path):
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1, 2, 3, 4, 5]] "
        "[binradar_remaining_patches [2, 4]]\n")
    collector.binradar_evidence.write_verifier(
        run_dir / "verifier.br",
        [collector.binradar_evidence.VerifierPatchResult(
            patch=patch, verified=True, accept_evidences=1,
            total_evidences=1, observations={"crash-pass": 1})
         for patch in range(1, 6)])
    (run_dir / "binradar.log").write_text(
        "[FINAL] Processed 17 complete BINRADAR evidence iteration(s); "
        "rejected 3 patch(es).\n")
    (run_dir / "final.sbsv").write_text(
        "[final] [confidence] [patch 1] [score 1.0] "
        "[accept-evidences 1] [total-evidences 1]\n"
        "[final] [binradar] [patch 1] [res rejected] "
        "[reason same-crash] [iter 3]\n"
        "[final] [binradar] [patch 2] [res verified] "
        "[reason none] [iter -1]\n"
        "[final] [binradar] [patch 3] [res rejected] "
        "[reason same-crash] [iter 4]\n"
        "[final] [binradar] [patch 4] [res verified] "
        "[reason none] [iter -1]\n"
        "[final] [binradar] [patch 5] [res rejected] "
        "[reason same-crash] [iter 5]\n")

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run", top_patches=1)

    run = result.runs[0]
    assert run.verifier_candidate_count == 5
    assert run.remaining_patches_count == 5
    assert run.binradar_evidence_iterations == 17
    assert run.binradar_rejected_count == 3
    assert run.binradar_remaining_patches_count == 2
    assert run.binradar_rejected == "1"

    row = collector.format_results_csv([result])[0]
    assert row["verifier_candidate_count"] == "5"
    assert row["remaining_patches_count"] == "5"
    assert row["binradar_evidence_iterations"] == "17"
    assert row["binradar_coverage"] == ""
    assert row["binradar_raw_committed"] == ""
    assert row["binradar_processed"] == ""
    assert row["binradar_rejected_count"] == "3"
    assert row["binradar_remaining_patches_count"] == "2"
    assert row["binradar_rejected_patches"] == "1"
    log = collector.format_result_log(result)
    assert "[verifier] candidates: 5  remaining: 5" in log
    assert "[binradar] complete iterations: 17  rejected: 3  remaining: 2" in log


def test_collect_taosc_counts_original_and_filtered_predicates(tmp_path):
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()
    (workdir / "predicates").write_text("first\n\nsecond\n")
    (workdir / "filter.sbsv").write_text(
        "[filter] [meta] [version 1] [kind generic-erm] [sha256 abc]\n"
        "[filter] [res] [id 1] [pass true] [new-id 1]\n"
        "[filter] [res] [id 2] [pass false] [new-id -1]\n"
        "[filter] [done] [total 2] [survived 1] [time 0.1]\n"
    )

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.status == "ok"
    assert result.original_predicates == 2
    assert result.filtered_predicates == 1
    assert result.setup_filter_total == 2
    assert result.setup_filter_done is collector.DoneStatus.OK
    assert "original predicates: 2" in collector.format_taosc_result_log(result)
    assert "filtered predicates: 1" in collector.format_taosc_result_log(result)

    row = collector.format_taosc_results_csv([result])[0]
    assert row["original_predicates"] == "2"
    assert row["filtered_predicates"] == "1"


def test_collect_taosc_skips_filter_without_predicates(tmp_path):
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.status == "ok"
    assert result.original_predicates == 0
    assert result.filtered_predicates == 0
    assert result.setup_filter_done is collector.DoneStatus.SKIPPED


def test_collect_taosc_skips_filter_with_single_patch_format(tmp_path):
    """A Single CWE-* patch-format skips the filter even with a brpatched."""
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()
    (workdir / "patch-format").write_text("Single CWE-617\n")
    (workdir / "sample.brpatched").touch()

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.status == "ok"
    assert result.patch_format == "Single CWE-617"
    assert result.original_predicates == 0
    assert result.filtered_predicates == 0
    assert result.setup_filter_done is collector.DoneStatus.SKIPPED
    assert "patch-format: Single CWE-617" in collector.format_taosc_result_log(result)
    row = collector.format_taosc_results_csv([result])[0]
    assert row["patch_format"] == "Single CWE-617"


def test_collect_taosc_erm_patch_format_without_filter_is_incomplete(tmp_path):
    """An ERM patch-format with no filter.sbsv is INCOMPLETE, not skipped."""
    workdir = tmp_path / "workdir-013"
    workdir.mkdir()
    (workdir / "patch-format").write_text("ERM generic\n")
    (workdir / "predicates").write_text("max1 - rax == ~max1\n")

    result = collector.collect_taosc_experiment(str(tmp_path), "workdir-013")

    assert result.patch_format == "ERM generic"
    assert result.original_predicates == 1
    assert result.setup_filter_done is collector.DoneStatus.INCOMPLETE
    assert result.status == "issues"


def test_filter_skipped_for_single_patch_format(tmp_path):
    """A Single CWE-* patch-format marks the binradar filter as skipped."""
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

    assert result.runs[0].setup_filter_done is collector.DoneStatus.SKIPPED
    assert "status: SKIPPED" in collector.format_result_log(result)


def test_collect_partial_coverage_and_runtime_metrics_ignore_top_limit(tmp_path):
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[rundir] [set] [prefix run] [id 0] [dir /tmp/run]\n"
        "[binradar] [tracer] [attempt 1] [representative-runs 98] "
        "[prefix run] [id 0]\n"
        "[binradar] [start] [prefix run] [id 0]\n"
        "[binradar] [tracer] [attempt 1] [representative-runs 6] "
        "[time 10] [remaining 5] [attempt-result completed] [stop none] "
        "[prefix run] [id 0]\n"
        "[binradar] [tracer] [attempt 5] [representative-runs 99] "
        "[time 12] [remaining 1] [attempt-result completed] [stop none] "
        "[prefix other] [id 4]\n"
        "[binradar] [tracer] [attempt 2] [representative-runs 6] "
        "[time 11] [remaining 4] [attempt-result completed] [stop none] "
        "[prefix run] [id 0]\n"
        "[binradar] [baseline] [reproduced] [artifact .brcached] "
        "[reference 401234 guest-signal] [prefix run] [id 0]\n"
        "[binradar] [stop] [prefix run] [id 0] "
        "[reason wall-time-reached] [attempt 3] [remaining 4] "
        "[representative-runs 12] [representative-runs-partial true] "
        "[planned 20] [attempted 2] "
        "[discarded 0] [committed 2] [queued 4] [memcheck true] "
        "[mutation-attempted 3] [mutation-discarded 1] "
        "[mutation-committed 2] [mutation-pending 0] "
        "[advisor-mode boundary] [advisor-candidates-generated 9] "
        "[advisor-families-generated 4] [advisor-families-accepted 3] "
        "[advisor-unsupported-abstentions 1] "
        "[advisor-budget-abstentions 2] [advisor-families-executed 2] "
        "[advisor-child-uses 7]\n"
        "[final] [done] [prefix run] [id 0] "
        "[remaining_patches [1, 2, 3, 4, 5]] "
        "[binradar_remaining_patches [2, 3]] [issues false] "
        "[failed-phases none] [wall-time-reached true] "
        "[binradar-coverage partial]\n")
    (run_dir / "binradar.log").write_text(
        "[FINAL] Processed 99 complete BINRADAR evidence iteration(s); "
        "rejected 3 patch(es).\n")
    # Settings v2 records the effective advisor budgets.  They are read from
    # the settings row, so a trial can be matched against the tracer's own
    # `[config]`/`[profile]` rows after the fact.
    (run_dir / "binradar-setting.sbsv").write_text(
        '[binradar-setting] [version 2] [run-prefix "run"] [run-id 0] '
        '[symbolic-mutation-mode "boundary"] [symbolic-max-work "500000"] '
        '[symbolic-max-bytes "16777216"] [symbolic-deadline-ms "500"]\n')
    confidence_rows = "".join(
        f"[final] [confidence] [patch {patch}] [score {1.0 - patch / 10}] "
        f"[accept-evidences 1] [total-evidences 1]\n"
        for patch in range(1, 6))
    (run_dir / "final.sbsv").write_text(
        confidence_rows
        + "[final] [coverage] [binradar-coverage partial] "
        "[raw-committed 8] [processed 7] "
        "[patch0-no-observation 1] [original-normal 4] "
        "[original-poc-crash 2] [original-other-crash 1] "
        "[original-unclassified-crash 0] "
        "[normal-branch-differences 3] [standalone-rejected 3] "
        "[overlap-rejected 1] [incremental-rejected 2] "
        "[final-survivors 2] [subject-kind multi] "
        "[fault-reference-valid true]\n"
        "[final] [rejection-sets] [standalone 1,3,9] [overlap 3] "
        "[incremental 1,9] [final-survivors 2,4] [truncated-sets ]\n")

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run", top_patches=1)

    run = result.runs[0]
    assert run.status == "OK (wall-time-reached; binradar partial coverage)"
    assert run.top_patches == [1]
    assert run.binradar_coverage == "partial"
    assert run.binradar_evidence_iterations == 7
    assert run.binradar_raw_committed == 8
    assert run.binradar_patch0_no_observation == 1
    assert run.binradar_overlap_rejected == 1
    assert run.binradar_incremental_rejected == 2
    assert run.binradar_original_unclassified_crash == 0
    assert run.binradar_final_survivors == 2
    # Exact membership survives --top and is independent of the scalar counts.
    assert run.binradar_standalone_ids == [1, 3, 9]
    assert run.binradar_overlap_ids == [3]
    assert run.binradar_incremental_ids == [1, 9]
    assert run.binradar_rejection_ids_truncated is False
    assert run.binradar_stop_reason == "wall-time-reached"
    assert run.binradar_attempted == 2
    assert run.binradar_committed == 2
    assert run.binradar_discarded == 0
    assert run.binradar_queued == 4
    assert run.binradar_representative_runs == 12
    assert run.binradar_representative_runs_partial is True
    assert run.binradar_stop_attempt == 3
    assert run.binradar_planned == 20
    assert run.binradar_tracer_attempts == 2
    assert run.binradar_baseline_reproduced is True
    assert run.binradar_memcheck_enabled is True
    assert run.binradar_mutation_attempted == 3
    assert run.binradar_mutation_discarded == 1
    assert run.binradar_mutation_committed == 2
    assert run.binradar_mutation_pending == 0
    assert run.binradar_advisor_mode == "boundary"
    assert run.binradar_advisor_candidates_generated == 9
    assert run.binradar_advisor_families_generated == 4
    assert run.binradar_advisor_families_accepted == 3
    assert run.binradar_advisor_unsupported_abstentions == 1
    assert run.binradar_advisor_budget_abstentions == 2
    assert run.binradar_advisor_families_executed == 2
    assert run.binradar_advisor_child_uses == 7
    assert run.binradar_advisor_max_work == 500000
    assert run.binradar_advisor_max_bytes == 16777216
    assert run.binradar_advisor_deadline_ms == 500

    row = collector.format_results_csv([result])[0]
    assert row["remaining_patches_count"] == "5"
    assert row["remaining_patches"] == "[1(0.900)] (+4 more)"
    assert row["binradar_coverage"] == "partial"
    assert row["binradar_raw_committed"] == "8"
    assert row["binradar_processed"] == "7"
    assert row["binradar_overlap_rejected"] == "1"
    assert row["binradar_incremental_rejected"] == "2"
    assert row["binradar_final_survivors"] == "2"
    assert row["binradar_original_unclassified_crash"] == "0"
    assert row["binradar_standalone_ids"] == "1,3,9"
    assert row["binradar_overlap_ids"] == "3"
    assert row["binradar_incremental_ids"] == "1,9"
    assert row["binradar_rejection_ids_truncated"] == "False"
    assert row["binradar_stop_reason"] == "wall-time-reached"
    assert row["binradar_representative_runs_partial"] == "True"
    assert row["binradar_memcheck_enabled"] == "True"
    assert row["binradar_baseline_reproduced"] == "True"
    assert row["binradar_mutation_attempted"] == "3"
    assert row["binradar_mutation_discarded"] == "1"
    assert row["binradar_mutation_committed"] == "2"
    assert row["binradar_mutation_pending"] == "0"
    assert row["binradar_advisor_mode"] == "boundary"
    assert row["binradar_advisor_candidates_generated"] == "9"
    assert row["binradar_advisor_families_generated"] == "4"
    assert row["binradar_advisor_families_accepted"] == "3"
    assert row["binradar_advisor_unsupported_abstentions"] == "1"
    assert row["binradar_advisor_budget_abstentions"] == "2"
    assert row["binradar_advisor_families_executed"] == "2"
    assert row["binradar_advisor_child_uses"] == "7"
    assert row["binradar_advisor_max_work"] == "500000"
    assert row["binradar_advisor_max_bytes"] == "16777216"
    assert row["binradar_advisor_deadline_ms"] == "500"
    log = collector.format_result_log(result)
    assert "[coverage] partial" in log
    assert "stop reason: wall-time-reached" in log
    assert "reproduces POC: True" in log
    assert "complete iterations: 7" in log

    # An explicitly empty rejection set is not a missing legacy row. Even
    # when only final survivors exceed the serialization cap, the marker
    # must still reach CSV despite all three rejection lists being empty.
    final_path = run_dir / "final.sbsv"
    final_text = final_path.read_text()
    original_sets = ("[standalone 1,3,9] [overlap 3] "
                     "[incremental 1,9] [final-survivors 2,4] "
                     "[truncated-sets ]")
    final_path.write_text(final_text.replace(
        original_sets,
        "[standalone ] [overlap ] [incremental ] "
        "[final-survivors 2,4] [truncated-sets final-survivors]"))
    empty_row = collector.format_results_csv([
        collector.collect_experiment_result(
            str(tmp_path), "workdir", "run", top_patches=1)])[0]
    assert empty_row["binradar_standalone_ids"] == ""
    assert empty_row["binradar_rejection_ids_truncated"] == "True"

    final_path.write_text(final_text.replace(
        original_sets,
        "[standalone ] [overlap ] [incremental ] "
        "[final-survivors 2,4] [truncated-sets ]"))
    no_reject_row = collector.format_results_csv([
        collector.collect_experiment_result(
            str(tmp_path), "workdir", "run", top_patches=1)])[0]
    assert no_reject_row["binradar_rejection_ids_truncated"] == "False"

    final_path.write_text(final_text.replace(
        "[final] [rejection-sets] " + original_sets + "\n", ""))
    legacy_row = collector.format_results_csv([
        collector.collect_experiment_result(
            str(tmp_path), "workdir", "run", top_patches=1)])[0]
    assert legacy_row["binradar_rejection_ids_truncated"] == ""


def test_legacy_settings_row_reports_unknown_advisor_budgets(tmp_path):
    """A settings v1 row must not be read as the built-in defaults."""
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[rundir] [set] [prefix run] [id 0] [dir /tmp/run]\n"
        "[binradar] [start] [prefix run] [id 0]\n")
    (run_dir / "binradar.log").write_text("")
    (run_dir / "binradar-setting.sbsv").write_text(
        '[binradar-setting] [version 1] [run-prefix "run"] [run-id 0] '
        '[symbolic-mutation-mode "shadow"]\n')

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run", top_patches=1)

    run = result.runs[0]
    assert run.binradar_advisor_mode == "shadow"
    assert run.binradar_advisor_max_work == -1
    assert run.binradar_advisor_max_bytes == -1
    assert run.binradar_advisor_deadline_ms == -1

    row = collector.format_results_csv([result])[0]
    assert row["binradar_advisor_max_work"] == ""
    assert row["binradar_advisor_deadline_ms"] == ""


def test_settings_v2_with_unknown_budgets_is_not_a_default(tmp_path):
    """An explicitly unknown budget stays absent, not 100/1e6/16 MiB."""
    workdir = tmp_path / "workdir"
    out_dir = workdir / "out"
    run_dir = out_dir / "run-00000"
    run_dir.mkdir(parents=True)
    (out_dir / "progress.sbsv").write_text(
        "[rundir] [set] [prefix run] [id 0] [dir /tmp/run]\n"
        "[binradar] [start] [prefix run] [id 0]\n")
    (run_dir / "binradar.log").write_text("")
    (run_dir / "binradar-setting.sbsv").write_text(
        '[binradar-setting] [version 2] [run-prefix "run"] [run-id 0] '
        '[symbolic-max-work "unknown"] [symbolic-max-bytes "unknown"] '
        '[symbolic-deadline-ms "unknown"]\n')

    result = collector.collect_experiment_result(
        str(tmp_path), "workdir", "run", top_patches=1)
    run = result.runs[0]

    assert run.binradar_advisor_max_work == -1
    assert run.binradar_advisor_max_bytes == -1
    assert run.binradar_advisor_deadline_ms == -1
