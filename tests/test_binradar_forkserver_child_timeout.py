#!/usr/bin/env python3
"""Tests for the forkserver child-timeout cap (br-test 2026-09-08 F1).

The tracer parent waits for a hung forkserver child up to
BINRADAR_FORKSERVER_CHILD_TIMEOUT.  That value used to be the whole-run
budget (21600 s) while python's forkserver read timeout is a fixed
1800 s, so any hung child failed the phase at exactly 1800 s.  get_env
must now set the child cap well below the python read timeout, and a
misconfigured cap must fail the startup invariant instead of silently
exceeding the read timeout.
"""

import argparse
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None and _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)


def _executor(tmp_path, timeout=21600, cap=binradar.FORKSERVER_CHILD_TIMEOUT_DEFAULT):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.timeout = timeout
    executor.forkserver_child_timeout = cap
    executor.probe_result = SimpleNamespace(patch_func_hit_cnt=1)
    executor.filter_result = [1, 2, 3]
    executor.e9_exclude_ranges = ""
    executor.e9_relocated_calls = ""
    executor.reverse_directed = False
    executor.config = {}
    executor.outdir = str(tmp_path)
    return executor


def test_binradar_env_child_timeout_is_capped_below_read_timeout(tmp_path):
    executor = _executor(tmp_path, timeout=21600)
    env = executor.get_env("binradar", str(tmp_path))
    child_timeout = int(env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"])
    assert child_timeout == binradar.FORKSERVER_CHILD_TIMEOUT_DEFAULT
    assert child_timeout < binradar.TracerExecutor.forkserver_timeout
    # Invariant from the F1 plan: child cap + analyze margin stays below
    # python's forkserver read timeout.
    assert (child_timeout + binradar.TracerExecutor.forkserver_analyze_margin
            < binradar.TracerExecutor.forkserver_timeout)


def test_directed_env_gets_the_same_cap(tmp_path):
    executor = _executor(tmp_path, timeout=21600)
    env = executor.get_env("directed", str(tmp_path))
    assert (int(env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"])
            == binradar.FORKSERVER_CHILD_TIMEOUT_DEFAULT)


def test_reverse_directed_is_enabled_only_for_directed_mode(tmp_path):
    executor = _executor(tmp_path)
    executor.reverse_directed = True
    assert executor.get_env("directed", str(tmp_path))["BINRADAR_REVERSE_DIRECTED"] == "1"
    for mode in ("fuzzolic", "binradar"):
        assert executor.get_env(mode, str(tmp_path))["BINRADAR_REVERSE_DIRECTED"] == "0"


def test_cap_is_clamped_to_the_run_budget(tmp_path):
    # A short whole-run budget must also cap the child timeout.
    executor = _executor(tmp_path, timeout=600, cap=900)
    env = executor.get_env("binradar", str(tmp_path))
    assert env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"] == "600"


@pytest.mark.parametrize("timeout", [0, -1])
def test_non_positive_run_timeout_keeps_positive_child_cap(tmp_path, timeout):
    # Unlimited whole-run execution must still bound each forkserver child.
    executor = _executor(tmp_path, timeout=timeout, cap=900)
    env = executor.get_env("binradar", str(tmp_path))
    assert env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"] == "900"


def test_custom_cap_flag_is_honoured(tmp_path):
    executor = _executor(tmp_path, timeout=21600, cap=600)
    env = executor.get_env("binradar", str(tmp_path))
    assert env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"] == "600"


@pytest.mark.parametrize("cap", [0, -1])
def test_non_positive_cap_is_rejected_at_phase_start(tmp_path, cap):
    executor = _executor(tmp_path, cap=cap)
    with pytest.raises(RuntimeError, match="must be positive"):
        executor.get_env("binradar", str(tmp_path))


@pytest.mark.parametrize("cap", [0, -1])
def test_non_positive_cap_is_rejected_by_cli_type(cap):
    with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
        binradar.positive_int(str(cap))


def test_cap_above_read_timeout_fails_at_phase_start(tmp_path):
    # A cap that would exceed python's read timeout must fail loudly at
    # phase start, not silently reintroduce the 1800 s TimeoutError.
    executor = _executor(tmp_path, timeout=21600, cap=1700)
    with pytest.raises(RuntimeError, match="forkserver child timeout"):
        executor.get_env("binradar", str(tmp_path))


def test_cap_of_one_marginal_second_fails(tmp_path):
    # 1500 + 300 == 1800 is not strictly below the read timeout.
    executor = _executor(tmp_path, timeout=21600, cap=1500)
    with pytest.raises(RuntimeError, match="forkserver child timeout"):
        executor.get_env("binradar", str(tmp_path))


def test_fuzzolic_mode_does_not_enable_forkserver(tmp_path):
    executor = _executor(tmp_path)
    env = executor.get_env("fuzzolic", str(tmp_path))
    assert env["BINRADAR_FORKSERVER_ENABLE"] == "0"
    assert "BINRADAR_FORKSERVER_CHILD_TIMEOUT" not in env


def test_from_env_reads_the_cap_env_key(tmp_path):
    env = {
        "BINRADAR_OUTDIR": str(tmp_path),
        "BINRADAR_TIMEOUT": "3600",
        "BINARY": "bin",
        "POC_INPUT": "poc",
        "TEST_CMD": "./bin @@",
        "PATCH_LOC": "0x1234",
        "TOTAL_PATCHES": "1",
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP": "600",
    }
    executor = binradar.BinRadarExecutor.from_env(str(tmp_path), env)
    assert executor.forkserver_child_timeout == 600


@pytest.mark.parametrize("cap", [0, -1])
def test_from_env_rejects_non_positive_cap(tmp_path, cap):
    env = {
        "BINRADAR_OUTDIR": str(tmp_path),
        "BINRADAR_TIMEOUT": "3600",
        "BINARY": "bin",
        "POC_INPUT": "poc",
        "TEST_CMD": "./bin @@",
        "PATCH_LOC": "0x1234",
        "TOTAL_PATCHES": "1",
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP": str(cap),
    }
    with pytest.raises(ValueError, match="must be positive"):
        binradar.BinRadarExecutor.from_env(str(tmp_path), env)


def test_from_env_defaults_to_900(tmp_path):
    env = {
        "BINRADAR_OUTDIR": str(tmp_path),
        "BINRADAR_TIMEOUT": "3600",
        "BINARY": "bin",
        "POC_INPUT": "poc",
        "TEST_CMD": "./bin @@",
        "PATCH_LOC": "0x1234",
        "TOTAL_PATCHES": "1",
    }
    executor = binradar.BinRadarExecutor.from_env(str(tmp_path), env)
    assert (executor.forkserver_child_timeout
            == binradar.FORKSERVER_CHILD_TIMEOUT_DEFAULT)