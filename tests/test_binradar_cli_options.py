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


def _run_main(monkeypatch, tmp_path, extra_args):
    workdir = tmp_path / "workdir"
    workdir.mkdir(parents=True)
    (workdir / "binradar.env").write_text(
        'BINARY="bin"\n'
        'POC_INPUT="poc"\n'
        'TEST_CMD="./bin @@"\n'
        'PATCH_LOC="0x1234"\n'
        'TOTAL_PATCHES="30"\n'
        'FILTER_TOTAL_PATCHES="32"\n')
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
        "[symbolic-mutation-mode: str] [fuzzy: bool] "
        "[reverse-directed: bool] [less-strict: bool] "
        "[forkserver-child-timeout: int]")
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

    executor.invocation = "binradar.py --run-single-phase final --run-id 0"
    executor.write_run_settings("single-phase-final")
    with (run_dir / "binradar-setting.sbsv").open() as settings_file:
        rows = parser.load(settings_file)["binradar-setting"]

    assert len(rows) == 2
    assert rows[0]["target-patches-status"] == "all-expanded"
    assert rows[1]["invocation"] == executor.invocation
    assert rows[1]["execution-mode"] == "single-phase-final"
