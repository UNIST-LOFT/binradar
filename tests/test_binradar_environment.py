import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
SPEC = importlib.util.spec_from_file_location(
    "binradar_environment", ROOT / "fuzzolic" / "binradar.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("failed to load fuzzolic/binradar.py")
binradar = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binradar)


@pytest.fixture
def executor(tmp_path):
    instance = object.__new__(binradar.BinRadarExecutor)
    instance.config = {}
    instance.probe_result = SimpleNamespace(patch_func_hit_cnt=3)
    instance.timeout = 17
    instance.reverse_directed = False
    instance.e9_exclude_ranges = ""
    instance.e9_relocated_calls = ""
    instance.forkserver_child_timeout = 900
    instance.filter_result = [1, 2]
    return instance, tmp_path


@pytest.mark.parametrize(
    "mode, expected_osprey",
    [("fuzzolic", "0"), ("directed", "0"), ("binradar", "1"), ("other", "0")],
)
def test_get_env_gates_osprey_by_mode(monkeypatch, executor, mode, expected_osprey):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_OSPREY_ENABLE", "1")
    env = instance.get_env(mode, str(run_dir))
    assert env["BINRADAR_OSPREY_ENABLE"] == expected_osprey
    assert env["BINRADAR_TRACER_LOG_FILE"] == str(run_dir / f"{mode}-tracer-msg.log")


def test_binradar_disables_trace_artifact(executor):
    instance, run_dir = executor
    env = instance.get_env("binradar", str(run_dir))
    assert env["BINRADAR_TRACE_FILE"] == "none"
    assert not (run_dir / "binradar-tracer-trace.log").exists()


def test_non_binradar_modes_cannot_inherit_osprey(monkeypatch, executor):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_OSPREY_ENABLE", "1")
    for mode in ("fuzzolic", "directed"):
        env = instance.get_env(mode, str(run_dir / mode))
        assert env["BINRADAR_OSPREY_ENABLE"] == "0"
        assert env["BINRADAR_TRACE_FILE"] == "none"


def test_binradar_keeps_developer_dump_paths_output_only(monkeypatch, executor):
    monkeypatch.delenv("BINRADAR_OSPREY_DUMP_FILE", raising=False)
    monkeypatch.delenv("BINRADAR_OSPREY_GRAPH_DUMP_FILE", raising=False)
    instance, run_dir = executor
    env = instance.get_env("binradar", str(run_dir))
    assert "BINRADAR_OSPREY_DUMP_FILE" not in env
    assert "BINRADAR_OSPREY_GRAPH_DUMP_FILE" not in env
    assert env["BINRADAR_TRACER_LOG_FILE"].endswith("binradar-tracer-msg.log")


def test_probe_tracer_cannot_inherit_osprey(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    run_dir = tmp_path / "run"
    workdir.mkdir()
    run_dir.mkdir()
    (workdir / "target.orig").write_bytes(b"binary")
    (workdir / "input").write_bytes(b"input")

    instance = object.__new__(binradar.BinRadarExecutor)
    instance.workdir = str(workdir)
    instance.binary = "target"
    instance.poc_input = "input"
    instance.test_cmd = "@@"
    instance.run_dir = str(run_dir)
    instance.run_prefix = "run"
    instance.run_id = 0
    instance.config = {}
    instance.extract_config = dict
    instance.save_progress = lambda _row: None

    probe_result = SimpleNamespace(
        patch_func_entry=0x1000,
        fault_addr=0x2000,
        tracer_fault_addr=0,
        patch_hit=lambda: True,
        is_timeout=lambda: False,
        is_crash=lambda: True,
        is_normal_exit=lambda: False,
        patch_func_hit=lambda: True,
        multi_patch_func=lambda: False,
        serialize=lambda: "[probe]",
    )
    file_trace_result = SimpleNamespace(
        serialize_file_trace_result=lambda: "[file-trace]"
    )
    runner = SimpleNamespace(
        test_with_original=lambda _input: probe_result,
        test_with_file_trace=lambda _input, **_kwargs: file_trace_result,
    )
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner,
        "from_env",
        lambda *_args: runner,
    )

    captured = {}

    def execute(_command, **kwargs):
        captured.update(kwargs["env"])
        return SimpleNamespace(success=False, stderr=b"")

    monkeypatch.setattr(binradar.binradar_utils, "execute", execute)
    monkeypatch.setenv("BINRADAR_OSPREY_ENABLE", "1")

    instance.run_probe()

    assert captured["BINRADAR_FORKSERVER_ENABLE"] == "0"
    assert captured["BINRADAR_OSPREY_ENABLE"] == "0"
    assert captured["BINRADAR_TRACE_FILE"] == "none"
