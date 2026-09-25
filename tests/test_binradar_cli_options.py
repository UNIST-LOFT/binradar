#!/usr/bin/env python3
"""Focused tests for binradar's public boolean and target-count options."""

import argparse
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None and _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)
import binradar_config


def _run_main(monkeypatch, tmp_path, extra_args, extra_env=""):
    workdir = tmp_path / "workdir"
    workdir.mkdir(parents=True)
    (workdir / "poc").write_bytes(b"x")
    (workdir / "binradar.env").write_text(
        'BINARY="bin"\n'
        'POC_INPUT="poc"\n'
        'TEST_CMD="./bin @@"\n'
        'PATCH_LOC="0x1234"\n'
        'TOTAL_PATCHES="30"\n'
        'FILTER_TOTAL_PATCHES="32"\n' + extra_env)
    captured = {}

    class FakeExecutor:
        def run_multithreaded(self, prefix):
            captured["run_prefix"] = prefix

    def fake_from_env(workdir_arg, env):
        captured.update(env)
        return FakeExecutor()

    monkeypatch.setattr(binradar, "setlimits", lambda: None)
    monkeypatch.setattr(binradar.signal, "signal", lambda *args: None)
    monkeypatch.setattr(binradar.os, "chdir", lambda path: None)
    monkeypatch.setattr(
        binradar.BinRadarExecutor, "from_env",
        staticmethod(fake_from_env))
    monkeypatch.setattr(
        sys, "argv",
        ["binradar.py", "--workdir", str(workdir)] + list(extra_args))
    binradar.main()
    return captured


def test_boolean_parser_accepts_true_false_values():
    assert binradar.parse_bool("true") is True
    assert binradar.parse_bool("false") is False
    with pytest.raises(argparse.ArgumentTypeError):
        binradar.parse_bool("not-a-bool")


def test_reverse_directed_bare_flag_and_explicit_disable(tmp_path, monkeypatch):
    enabled = _run_main(monkeypatch, tmp_path / "enabled", [
        "--reverse-directed", "true"])
    assert enabled["BINRADAR_REVERSE_DIRECTED"] == "1"

    disabled = _run_main(monkeypatch, tmp_path / "disabled", [
        "--reverse-directed", "false", "--feedback", "false"])
    assert disabled["BINRADAR_REVERSE_DIRECTED"] == "0"
    assert disabled["BINRADAR_FEEDBACK_MODE"] == "0"

    enabled_feedback = _run_main(monkeypatch, tmp_path / "feedback", [
        "--feedback"])
    assert enabled_feedback["BINRADAR_FEEDBACK_MODE"] == "1"


def test_symbolic_budget_cli_option_reaches_the_phase_environment(
        tmp_path, monkeypatch):
    """End-to-end: `--symbolic-deadline-ms 500` must arrive as 500.

    The pre-change path delivered the constant default 100, so this fixture is
    the regression for a requested budget being silently discarded.
    """
    captured = _run_main(
        monkeypatch, tmp_path,
        ["--symbolic-mutation-mode", "shadow",
         "--symbolic-max-work", "500000",
         "--symbolic-deadline-ms", "500"],
        extra_env='BINRADAR_SYMBOLIC_DEADLINE_MS="100"\n')
    workdir = tmp_path / "workdir"

    assert captured["BINRADAR_SYMBOLIC_MAX_WORK"] == "500000"
    assert captured["BINRADAR_SYMBOLIC_DEADLINE_MS"] == "500"
    assert captured["BINRADAR_SYMBOLIC_MAX_BYTES"] == str(
        binradar_config.SYMBOLIC_MAX_BYTES_DEFAULT)

    run_config = binradar_config.RunConfig.from_environment(
        str(workdir), captured)
    environment = binradar_config.build_base_environment(
        run_config, str(tmp_path / "plt_info.txt"))
    assert environment["BINRADAR_SYMBOLIC_DEADLINE_MS"] == "500"
    assert environment["BINRADAR_SYMBOLIC_MAX_WORK"] == "500000"


def test_symbolic_budget_cli_option_rejects_malformed_workdir_value(
        tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        _run_main(monkeypatch, tmp_path, [],
                  extra_env='BINRADAR_SYMBOLIC_MAX_WORK="-5"\n')


def test_symbolic_schedule_cli_option_reaches_the_phase_environment(
        tmp_path, monkeypatch):
    """`--symbolic-schedule` must reach the tracer environment verbatim.

    The policy is only meaningful in the BinRadar phase and only when the
    advisor actually proposes plans, so this fixture also pins the
    phase-scoping: other phases must not inherit an experiment.
    """
    captured = _run_main(
        monkeypatch, tmp_path,
        ["--symbolic-mutation-mode", "boundary",
         "--symbolic-schedule", "retained-first"],
        extra_env='BINRADAR_SYMBOLIC_SCHEDULE="existing"\n')
    workdir = tmp_path / "workdir"

    assert captured["BINRADAR_SYMBOLIC_SCHEDULE"] == "retained-first"
    run_config = binradar_config.RunConfig.from_environment(
        str(workdir), captured)
    environment = binradar_config.build_base_environment(
        run_config, str(tmp_path / "plt_info.txt"))
    assert environment["BINRADAR_SYMBOLIC_SCHEDULE"] == "retained-first"


def test_symbolic_schedule_rejects_unknown_policy(tmp_path, monkeypatch):
    """The CLI must reject a policy name the tracer would not recognize."""
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, tmp_path,
                  ["--symbolic-schedule", "retainedfirst"])


def test_symbolic_schedule_defaults_to_existing(tmp_path, monkeypatch):
    captured = _run_main(monkeypatch, tmp_path, [])
    assert captured["BINRADAR_SYMBOLIC_SCHEDULE"] == "existing"


def test_target_patches_all_stays_within_compiled_count(tmp_path, monkeypatch):
    captured = _run_main(monkeypatch, tmp_path, ["--target-patches", "all"])
    assert captured["TOTAL_PATCHES"] == "30"
    assert captured["BINRADAR_TARGET_PATCHES_STATUS"] == "all-clamped"


def test_run_settings_records_resolved_candidate_scope(tmp_path):
    run_dir = tmp_path / "out" / "br-off-no-feedback-00000"
    run_dir.mkdir(parents=True)
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.invocation = "binradar.py --label '[debug]' --target-patches all"
    executor.workdir = str(tmp_path)
    executor.outdir = str(tmp_path / "out")
    executor.run_dir = str(run_dir)
    executor.run_prefix = "br-off-no-feedback"
    executor.run_id = 0
    executor.timeout = 7200
    executor.requested_candidate_scope = "all"
    executor.candidate_scope_status = "all-expanded"
    executor.candidate_scope_reason = (
        "cached artifact and manifest cover every filtered patch")
    executor.brpatched_total_patches = 30
    executor.filter_total_patches = 41
    executor.total_patches = 41
    executor.disable_binradar = False
    executor.feedback_mode = False
    executor.symbolic_mutation_mode = "off"
    executor.symbolic_schedule = "retained-first"
    executor.symbolic_budgets = binradar_config.SymbolicBudgets(
        max_work=500000, max_bytes=1048576, deadline_ms=500)
    executor.fuzzy = False
    executor.reverse_directed = True
    executor.less_strict = False
    executor.forkserver_child_timeout = 900

    executor.write_run_settings("multithreaded")

    parser = binradar.sbsv.parser()
    parser.add_schema(
        "[binradar-setting] [version: int] [invocation: str] "
        "[execution-mode: str] [workdir: str] [outdir: str] "
        "[run-prefix: str] [run-id: int] [timeout: int] "
        "[target-patches: str] [target-patches-status: str] "
        "[target-patches-reason: str] [compiled-patches: int] "
        "[filtered-patches: int] [effective-patches: int] "
        "[disable-binradar: bool] [feedback: bool] "
        "[symbolic-mutation-mode: str] [symbolic-schedule: str] "
        "[fuzzy: bool] "
        "[reverse-directed: bool] [less-strict: bool] "
        "[forkserver-child-timeout: int] [symbolic-max-work: str] "
        "[symbolic-max-bytes: str] [symbolic-deadline-ms: str]")
    with (run_dir / "binradar-setting.sbsv").open() as settings_file:
        row = parser.load(settings_file)["binradar-setting"][0]

    assert row["invocation"] == executor.invocation
    assert row["target-patches"] == "all"
    assert row["target-patches-status"] == "all-expanded"
    assert row["compiled-patches"] == 30
    assert row["filtered-patches"] == 41
    assert row["effective-patches"] == 41
    assert row["disable-binradar"] is False
    assert row["symbolic-mutation-mode"] == "off"
    # Settings v2 records the effective budgets, so a reader can match a trial
    # against the tracer's own `[config]`/`[profile]` rows.
    assert row["version"] == 2
    assert row["symbolic-max-work"] == "500000"
    assert row["symbolic-max-bytes"] == "1048576"
    assert row["symbolic-deadline-ms"] == "500"
    # A recorded policy is written verbatim; only an unrecorded field is
    # `unknown`, never the built-in default.
    assert row["symbolic-schedule"] == "retained-first"

    executor.invocation = "binradar.py --run-single-phase final --run-id 0"
    executor.write_run_settings("single-phase-final")
    with (run_dir / "binradar-setting.sbsv").open() as settings_file:
        rows = parser.load(settings_file)["binradar-setting"]

    assert len(rows) == 2
    assert rows[0]["target-patches-status"] == "all-expanded"
    assert rows[1]["invocation"] == executor.invocation
    assert rows[1]["execution-mode"] == "single-phase-final"
