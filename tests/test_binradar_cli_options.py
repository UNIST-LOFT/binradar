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
        'PREFILTER_TOTAL_PATCHES="32"\n')
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
        "--reverse-directed"])
    assert enabled["BINRADAR_REVERSE_DIRECTED"] == "1"

    disabled = _run_main(monkeypatch, tmp_path / "disabled", [
        "--reverse-directed", "false", "--feedback", "false"])
    assert disabled["BINRADAR_REVERSE_DIRECTED"] == "0"


def test_target_patches_all_stays_within_compiled_count(tmp_path, monkeypatch):
    captured = _run_main(monkeypatch, tmp_path, ["--target-patches", "all"])
    assert captured["TOTAL_PATCHES"] == "30"
