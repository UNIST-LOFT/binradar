#!/usr/bin/env python3
"""Child caps share the native attempt budget, not Python's response grace.

A configured child cap may reach the full native attempt budget; larger caps
are clamped. A positive phase budget caps children; the runtime independently
bounds response waiting by the remaining phase deadline.
"""

import argparse
from types import SimpleNamespace

import pytest


from binradar import cli as binradar
from binradar import binradar_artifacts
from binradar import binradar_config
from test_binradar_e9_metadata import _write_bound_identity_artifacts


def _executor(
        tmp_path, timeout=21600,
        cap=binradar_config.FORKSERVER_CHILD_TIMEOUT_DEFAULT):
    _write_bound_identity_artifacts(tmp_path, "bin")
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.workdir = str(tmp_path)
    executor.binary = "bin"
    executor.test_cmd = "@@"
    executor.patch_loc = "0x401000"
    executor.timeout = timeout
    executor.forkserver_child_timeout = cap
    executor.probe_result = SimpleNamespace(patch_func_hit_cnt=1)
    executor.filter_result = [1, 2, 3]
    executor.reverse_directed = False
    executor.config = {
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x70000000-0x70001000",
    }
    executor.brpatched_total_patches = len(executor.filter_result)
    executor.outdir = str(tmp_path)
    executor.artifacts = binradar_artifacts.ArtifactSet(
        str(tmp_path), "bin", "", 0, executor.brpatched_total_patches)
    return executor


def _phase_env(executor, mode, run_dir):
    artifact = None
    if mode == "binradar":
        artifact = executor.artifacts.select_tracer(executor.filter_result)
    return executor._phase_environment(mode, str(run_dir), artifact)


@pytest.mark.parametrize("mode", ["binradar", "directed"])
@pytest.mark.parametrize("timeout", [0, -1, 21600])
@pytest.mark.parametrize("cap,expected", [
    (600, 600), (1500, 1500), (1700, 1700), (1800, 1800), (2400, 1800),
])
def test_child_cap_does_not_shrink_or_exceed_native_attempt_budget(
        tmp_path, mode, timeout, cap, expected):
    executor = _executor(tmp_path, timeout=timeout, cap=cap)
    env = _phase_env(executor, mode, tmp_path)
    assert int(env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"]) == expected
    assert env["BINRADAR_FORKSERVER_ITERATION_TIMEOUT"] == "1800"


def test_reverse_directed_is_enabled_only_for_directed_mode(tmp_path):
    executor = _executor(tmp_path)
    executor.reverse_directed = True
    assert _phase_env(executor, "directed", tmp_path)["BINRADAR_REVERSE_DIRECTED"] == "1"
    for mode in ("fuzzolic", "binradar"):
        assert _phase_env(executor, mode, tmp_path)["BINRADAR_REVERSE_DIRECTED"] == "0"


@pytest.mark.parametrize("mode", ["binradar", "directed"])
@pytest.mark.parametrize("cap,expected", [(300, 300), (900, 600), (2400, 600)])
def test_positive_phase_budget_bounds_children(
        tmp_path, mode, cap, expected):
    executor = _executor(tmp_path, timeout=600, cap=cap)
    env = _phase_env(executor, mode, tmp_path)
    assert int(env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"]) == expected


@pytest.mark.parametrize("cap", [0, -1])
def test_non_positive_cap_is_rejected_at_phase_start(tmp_path, cap):
    executor = _executor(tmp_path, cap=cap)
    with pytest.raises(RuntimeError, match="must be positive"):
        _phase_env(executor, "binradar", tmp_path)


@pytest.mark.parametrize("cap", [0, -1])
def test_non_positive_cap_is_rejected_by_cli_type(cap):
    with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
        binradar.positive_int(str(cap))


def test_fuzzolic_mode_does_not_enable_forkserver(tmp_path):
    executor = _executor(tmp_path)
    env = _phase_env(executor, "fuzzolic", tmp_path)
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


