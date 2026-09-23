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
import binradar_artifacts
import binradar_config


@pytest.fixture
def executor(tmp_path):
    instance = object.__new__(binradar.BinRadarExecutor)
    instance.config = {}
    instance.probe_result = SimpleNamespace(patch_func_hit_cnt=3)
    instance.timeout = 17
    instance.reverse_directed = False
    instance.config.update({
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x70000000-0x70001000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS":
            "0x70000010:0x401000:0x401005",
    })
    instance.forkserver_child_timeout = 900
    instance.filter_result = [1, 2]
    instance.artifacts = binradar_artifacts.ArtifactSet(
        str(tmp_path), "bin", "", 0, 2)
    return instance, tmp_path


def _phase_env(instance, mode, run_dir):
    artifact = None
    if mode == "binradar":
        artifact = binradar_artifacts.ArtifactSelection(
            instance.artifacts.patched, "brpatched", False, False,
            "cached artifact not required")
    return instance._phase_environment(mode, str(run_dir), artifact)


@pytest.mark.parametrize(
    "mode, expected_osprey",
    [("fuzzolic", "0"), ("directed", "0"), ("binradar", "1"), ("other", "0")],
)
def test_get_env_gates_osprey_by_mode(monkeypatch, executor, mode, expected_osprey):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_OSPREY_ENABLE", "1")
    env = _phase_env(instance, mode, run_dir)
    assert env["BINRADAR_OSPREY_ENABLE"] == expected_osprey
    assert env["BINRADAR_TRACER_LOG_FILE"] == str(run_dir / f"{mode}-tracer-msg.log")
    if mode == "binradar":
        assert env["E9_EXCLUDE_RANGES"] == "0x70000000-0x70001000"
        assert env["E9_RELOCATED_CALL_JUMPS"] == \
            "0x70000010:0x401000:0x401005"
        assert env["BINRADAR_EVIDENCE_FILE"] == str(run_dir / "binradar.br")
    else:
        assert env["E9_EXCLUDE_RANGES"] == ""
        assert env["E9_RELOCATED_CALL_JUMPS"] == ""


def test_binradar_disables_trace_artifact(executor):
    instance, run_dir = executor
    env = _phase_env(instance, "binradar", run_dir)
    assert env["BINRADAR_TRACE_FILE"] == "none"
    assert not (run_dir / "binradar-tracer-trace.log").exists()


def test_non_binradar_modes_cannot_inherit_osprey(monkeypatch, executor):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_OSPREY_ENABLE", "1")
    for mode in ("fuzzolic", "directed"):
        env = _phase_env(instance, mode, run_dir / mode)
        assert env["BINRADAR_OSPREY_ENABLE"] == "0"
        assert env["BINRADAR_TRACE_FILE"] == "none"


def test_binradar_keeps_developer_dump_paths_output_only(monkeypatch, executor):
    monkeypatch.delenv("BINRADAR_OSPREY_DUMP_FILE", raising=False)
    monkeypatch.delenv("BINRADAR_OSPREY_GRAPH_DUMP_FILE", raising=False)
    instance, run_dir = executor
    env = _phase_env(instance, "binradar", run_dir)
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
    instance._worker_environment = dict
    instance.artifacts = SimpleNamespace(
        original=str(workdir / "target.orig"))
    instance.save_progress = lambda _row: None

    probe_result = SimpleNamespace(
        patch_func_entry=0x1000,
        fault_addr=0x2000,
        tracer_fault_reference=None,
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


def test_get_env_gates_symbolic_advisor_by_mode(monkeypatch, executor):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_SYMBOLIC_MUTATION_MODE", "boundary")

    env = _phase_env(instance, "binradar", run_dir)
    assert env["BINRADAR_SYMBOLIC_MUTATION_MODE"] == "boundary"

    for index, mode in enumerate(
            ["fuzzolic", "directed", "probe", "minimizer", "verifier"]):
        forced = _phase_env(instance, mode, run_dir / f"m{index}")
        assert forced["BINRADAR_SYMBOLIC_MUTATION_MODE"] == "off", mode


def test_feedback_and_symbolic_advisor_are_independent(monkeypatch, executor):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_SYMBOLIC_MUTATION_MODE", "boundary")

    # Feedback on does not turn the advisor on, and the advisor being on does
    # not turn feedback on: each feature reads only its own configuration.
    instance.feedback_mode = True
    feedback_on = _phase_env(instance, "binradar", run_dir)
    instance.feedback_mode = False
    feedback_off = _phase_env(instance, "binradar", run_dir / "off")

    assert feedback_on["BINRADAR_SYMBOLIC_MUTATION_MODE"] == "boundary"
    assert feedback_off["BINRADAR_SYMBOLIC_MUTATION_MODE"] == "boundary"
    # get_env is not the place that arms feedback; it must not inject the
    # staging directory in either case.
    for env in (feedback_on, feedback_off):
        assert "BINRADAR_FEEDBACK_DIR" not in env


def test_symbolic_mode_defaults_off_without_environment(monkeypatch, executor):
    instance, run_dir = executor
    monkeypatch.delenv("BINRADAR_SYMBOLIC_MUTATION_MODE", raising=False)
    env = _phase_env(instance, "binradar", run_dir)
    assert env["BINRADAR_SYMBOLIC_MUTATION_MODE"] == "off"


def test_config_overrides_inherited_symbolic_mode(monkeypatch, executor):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_SYMBOLIC_MUTATION_MODE", "shadow")
    instance.config["BINRADAR_SYMBOLIC_MUTATION_MODE"] = "boundary"
    env = _phase_env(instance, "binradar", run_dir)
    assert env["BINRADAR_SYMBOLIC_MUTATION_MODE"] == "boundary"


def test_symbolic_mode_rejects_unknown_value():
    with pytest.raises(ValueError):
        binradar_config.validate_symbolic_mutation_mode("aggressive")
    assert binradar_config.validate_symbolic_mutation_mode(
        " Boundary ") == "boundary"


def test_memcheck_policy_is_explicit_per_mode(monkeypatch, executor):
    """The crash-detection policy is set by the phase, never inherited."""
    instance, run_dir = executor
    # An ambient value must not decide whether a phase can observe a guest
    # memory violation at all.
    monkeypatch.setenv("BINRADAR_MEMCHECK_ENABLE", "1")

    # BINRADAR must detect what PROBE detects, so it is enabled there.
    assert _phase_env(instance, "binradar", run_dir)[
        "BINRADAR_MEMCHECK_ENABLE"] == "1"
    # FUZZOLIC and DIRECTED keep their existing policy.
    for index, mode in enumerate(["fuzzolic", "directed", "probe",
                                  "minimizer", "verifier"]):
        forced = _phase_env(instance, mode, run_dir / f"m{index}")
        assert forced["BINRADAR_MEMCHECK_ENABLE"] == "0", mode


def test_memcheck_policy_overrides_inherited_disabled_value(
        monkeypatch, executor):
    instance, run_dir = executor
    monkeypatch.setenv("BINRADAR_MEMCHECK_ENABLE", "0")
    assert _phase_env(instance, "binradar", run_dir)[
        "BINRADAR_MEMCHECK_ENABLE"] == "1"
