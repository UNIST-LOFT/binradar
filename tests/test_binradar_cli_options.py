#!/usr/bin/env python3
"""Focused tests for binradar's public boolean and target-count options."""

import argparse
import sys
from pathlib import Path

import pytest


from binradar import cli as binradar
from binradar import binradar_config


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


@pytest.mark.parametrize(("flags", "configured", "expected"), [
    ([], "47", 47),
    (["--forkserver-child-timeout", "83"], "47", 83),
    (["--forkserver-child-timeout", "83"], "invalid", 83),
])
def test_child_timeout_cli_overrides_only_when_explicit(
        tmp_path, monkeypatch, flags, configured, expected):
    env = _run_main(
        monkeypatch, tmp_path, flags,
        extra_env=f'BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP="{configured}"\n')
    config = binradar_config.RunConfig.from_environment(
        str(tmp_path / "workdir"), env)
    assert config.forkserver_child_timeout == expected


@pytest.mark.parametrize("extra_args,setting", [
    (["--concrete-input-schedule", "novelty"], ""),
    ([], 'BINRADAR_CONCRETE_INPUT_SCHEDULE="novelty"\n'),
    (["--feedback"], ""),
    ([], 'BINRADAR_FEEDBACK_MODE="1"\n'),
    (["--fuzzer-only"], ""),
    (["--run-single-phase", "binradar"], ""),
    (["--run-single-phase", "verifier"], ""),
    (["--run-single-phase", "minimizer-verifier"], ""),
    (["--run-single-phase", "final"], ""),
    (["--run-single-phase", "feedback"], ""),
    (["--run-id", "l"], ""),
])
def test_generation_rejects_patch_features_and_reuse_before_preparation(
        tmp_path, monkeypatch, extra_args, setting):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    # The normal environment deliberately disagrees: generation must load its
    # own file and reject its effective policy, without touching existing runs.
    (workdir / "binradar.env").write_text('BINRADAR_CONCRETE_INPUT_SCHEDULE="fifo"\n')
    (workdir / "generate-concrete.env").write_text(
        'BINARY="guest"\nPOC_INPUT="poc"\nTEST_CMD="@@"\n'
        'PATCH_LOC="0x401000"\nTOTAL_PATCHES="0"\n' + setting)
    saved = workdir / "out" / "run-00000" / "minimized" / "existing"
    saved.parent.mkdir(parents=True)
    saved.write_bytes(b"preserved corpus")
    monkeypatch.setattr(binradar, "setlimits", lambda: None)
    monkeypatch.setattr(binradar.signal, "signal", lambda *args: None)
    monkeypatch.setattr(sys, "argv", [
        "binradar", "-w", str(workdir), "--generate-concrete", *extra_args])
    with pytest.raises(SystemExit) as failure:
        binradar.main()
    assert failure.value.code == 2
    assert saved.read_bytes() == b"preserved corpus"
    assert not (workdir / "out" / "progress.sbsv").exists()
    assert not (workdir / "out" / "plt_info.txt").exists()


def test_binradar_generation_unsupported_exits_without_run_side_effects(
        tmp_path, monkeypatch, capsys):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "binradar.env").write_text('BINARY="stale"\n')
    (workdir / "generate-binradar.env").write_text(
        'BINRADAR_GENERATE_BINRADAR="1"\n'
        'BINRADAR_PATCH_KIND="unsupported"\nTOTAL_PATCHES="0"\n'
        'BINRADAR_GENERATION_PATCH_FORMAT="Single CWE-369"\n')
    output = tmp_path / "custom-output"
    monkeypatch.setattr(binradar, "setlimits", lambda: None)
    monkeypatch.setattr(binradar.signal, "signal", lambda *args: None)
    monkeypatch.setattr(sys, "argv", [
        "binradar", "-w", str(workdir), "--generate-binradar", "-o", str(output)])
    binradar.main()
    assert not output.exists()
    assert not (workdir / "out").exists()
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("arguments", [
    ["--generate-concrete"], ["--disable-binradar"], ["--fuzzer-only"],
    ["--run-id", "l"], ["--run-single-phase", "final"],
    ["--run-single-phase", "feedback"], ["--run-single-phase", "verifier"],
])
def test_binradar_generation_rejects_incompatible_modes_before_output(
        tmp_path, monkeypatch, arguments):
    monkeypatch.setattr(binradar, "setlimits", lambda: None)
    monkeypatch.setattr(binradar.signal, "signal", lambda *args: None)
    monkeypatch.setattr(sys, "argv", [
        "binradar", "-w", str(tmp_path), "--generate-binradar", *arguments])
    with pytest.raises(SystemExit) as failure:
        binradar.main()
    assert failure.value.code == 2
    assert not (tmp_path / "out").exists()


def test_binradar_generation_config_forces_baseline_feedback_and_retains_cache(tmp_path):
    from dataclasses import replace

    env = {
        "BINRADAR_GENERATE_BINRADAR": "1", "BINRADAR_OUTDIR": str(tmp_path / "out"),
        "BINRADAR_TIMEOUT": "60", "BINARY": "guest", "POC_INPUT": "poc",
        "TEST_CMD": "@@", "PATCH_LOC": "0x401000", "TOTAL_PATCHES": "invalid",
        "BRPATCHED_TOTAL_PATCHES": "stale", "FILTER_TOTAL_PATCHES": "stale",
        "BINRADAR_FEEDBACK_MODE": "0", "BINRADAR_PATCH_KIND": "CWE805-erm",
        "BRCACHE_STACK_SIZE": "4096", "E9_METADATA_PREFIX": "brcached",
        "BRCACHED_E9_EXCLUDE_RANGES": "0x1000-0x2000",
    }
    config = binradar_config.RunConfig.from_environment(str(tmp_path), env)
    assert config.feedback_mode and not config.disable_binradar
    assert (config.total_patches, config.brpatched_total_patches,
            config.filter_total_patches) == (0, 0, 0)
    base = binradar_config.build_base_environment(config, "plt.txt")
    assert base["BINRADAR_PATCH_KIND"] == "CWE805-erm"
    assert base["BRCACHE_STACK_SIZE"] == "4096"
    assert base["BRCACHED_E9_EXCLUDE_RANGES"] == "0x1000-0x2000"
    worker = binradar_config.build_worker_environment(config, {"BINRADAR_FEEDBACK_MODE": "0"})
    assert worker["BINRADAR_FEEDBACK_MODE"] == "1"
    assert worker["BINRADAR_GENERATE_BINRADAR"] == "1"
    for invalid in ({"disable_binradar": True}, {"feedback_mode": False},
                    {"total_patches": 1}, {"brpatched_total_patches": 1},
                    {"filter_total_patches": 1}, {"generate_concrete": True}):
        with pytest.raises(ValueError):
            replace(config, **invalid)
    with pytest.raises(ValueError, match="requires the BINRADAR phase"):
        binradar_config.RunConfig.from_environment(
            str(tmp_path), {**env, "BINRADAR_DISABLE_BINRADAR": "1"})


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


@pytest.mark.parametrize("args,env_value,expected", [
    ([], None, "fifo"),
    ([], "novelty", "novelty"),
    (["--concrete-input-schedule", "fifo"], "novelty", "fifo"),
    (["--concrete-input-schedule", "novelty"], "invalid", "novelty"),
])
def test_concrete_input_schedule_precedence_and_roundtrip(
        tmp_path, monkeypatch, args, env_value, expected):
    from dataclasses import FrozenInstanceError

    extra_env = ("" if env_value is None else
                 f'BINRADAR_CONCRETE_INPUT_SCHEDULE="{env_value}"\n')
    captured = _run_main(monkeypatch, tmp_path, args, extra_env)
    config = binradar_config.RunConfig.from_environment(
        str(tmp_path / "workdir"), captured)
    assert config.concrete_input_schedule == expected
    with pytest.raises(FrozenInstanceError):
        config.concrete_input_schedule = "fifo"
    base = binradar_config.build_base_environment(config, "unused-plt")
    workers = binradar_config.build_worker_environment(config, {
        "BINRADAR_CONCRETE_INPUT_SCHEDULE": "invalid"})
    assert base["BINRADAR_CONCRETE_INPUT_SCHEDULE"] == expected
    assert workers["BINRADAR_CONCRETE_INPUT_SCHEDULE"] == expected
    assert config.symbolic_schedule == "existing"


@pytest.mark.parametrize("args,extra_env,error", [
    (["--concrete-input-schedule", "random"], "", SystemExit),
    ([], 'BINRADAR_CONCRETE_INPUT_SCHEDULE="random"\n', ValueError),
])
def test_invalid_concrete_policy_does_not_prepare_run(
        tmp_path, monkeypatch, args, extra_env, error):
    with pytest.raises(error):
        _run_main(monkeypatch, tmp_path, args, extra_env)
    assert not (tmp_path / "workdir" / "out").exists()


def test_mixed_portfolio_and_budget_reach_resolved_configuration(
        tmp_path, monkeypatch):
    captured = _run_main(
        monkeypatch, tmp_path,
        ["--symbolic-mutation-mode", "boundary",
         "--mutation-portfolio", "mixed",
         "--binradar-representative-budget", "1000"],
        extra_env=(
            'BINRADAR_MUTATION_PORTFOLIO="replacement"\n'
            'BINRADAR_REPRESENTATIVE_BUDGET="17"\n'))
    workdir = tmp_path / "workdir"

    assert captured["BINRADAR_MUTATION_PORTFOLIO"] == "mixed"
    assert captured["BINRADAR_REPRESENTATIVE_BUDGET"] == "1000"
    run_config = binradar_config.RunConfig.from_environment(
        str(workdir), captured)
    assert run_config.mutation_portfolio == "mixed"
    assert run_config.representative_budget == 1000
    environment = binradar_config.build_base_environment(
        run_config, str(tmp_path / "plt_info.txt"))
    assert environment["BINRADAR_MUTATION_PORTFOLIO"] == "mixed"
    assert "BINRADAR_REPRESENTATIVE_BUDGET" not in environment


@pytest.mark.parametrize("extra_args", [
    ["--symbolic-mutation-mode", "boundary",
     "--mutation-portfolio", "mixed"],
    ["--symbolic-mutation-mode", "boundary",
     "--symbolic-schedule", "retained-first",
     "--mutation-portfolio", "mixed",
     "--binradar-representative-budget", "100"],
])
def test_mixed_portfolio_rejects_unbounded_or_rescheduled_trials(
        tmp_path, monkeypatch, extra_args):
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, tmp_path, extra_args)


def test_portfolio_and_representative_budget_defaults(tmp_path, monkeypatch):
    captured = _run_main(monkeypatch, tmp_path, [])
    assert captured["BINRADAR_MUTATION_PORTFOLIO"] == "replacement"
    assert captured["BINRADAR_REPRESENTATIVE_BUDGET"] == "0"


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
    executor.concrete_input_schedule = "novelty"
    executor.mutation_portfolio = "replacement"
    executor.representative_budget = 1234
    executor.symbolic_budgets = binradar_config.SymbolicBudgets(
        max_work=500000, max_bytes=1048576, deadline_ms=500)
    executor.fuzzy = False
    executor.reverse_directed = True
    executor.less_strict = False
    executor.forkserver_child_timeout = 900

    executor.write_run_settings("multithreaded")

    parser = binradar.sbsv.parser()
    parser.add_schema(
        "[binradar-setting] [version: int] [memcheck-policy: str] [invocation: str] "
        "[execution-mode: str] [workdir: str] [outdir: str] "
        "[run-prefix: str] [run-id: int] [timeout: int] "
        "[target-patches: str] [target-patches-status: str] "
        "[target-patches-reason: str] [compiled-patches: int] "
        "[filtered-patches: int] [effective-patches: int] "
        "[disable-binradar: bool] [feedback: bool] "
        "[symbolic-mutation-mode: str] [symbolic-schedule: str] "
        "[mutation-portfolio: str] [representative-budget: str] "
        "[fuzzy: bool] "
        "[reverse-directed: bool] [less-strict: bool] "
        "[forkserver-child-timeout: int] [symbolic-max-work: str] "
        "[symbolic-max-bytes: str] [symbolic-deadline-ms: str] "
        "[concrete-input-schedule: str]")
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
    assert row["version"] == 4
    assert row["mutation-portfolio"] == "replacement"
    assert row["representative-budget"] == "1234"
    assert row["symbolic-max-work"] == "500000"
    assert row["symbolic-max-bytes"] == "1048576"
    assert row["symbolic-deadline-ms"] == "500"
    # A recorded policy is written verbatim; only an unrecorded field is
    # `unknown`, never the built-in default.
    assert row["symbolic-schedule"] == "retained-first"
    assert row["concrete-input-schedule"] == "novelty"

    executor.invocation = "binradar.py --run-single-phase final --run-id 0"
    executor.write_run_settings("single-phase-final")
    with (run_dir / "binradar-setting.sbsv").open() as settings_file:
        rows = parser.load(settings_file)["binradar-setting"]

    assert len(rows) == 2
    assert rows[0]["target-patches-status"] == "all-expanded"
    assert rows[1]["invocation"] == executor.invocation
    assert rows[1]["execution-mode"] == "single-phase-final"
    assert [row["concrete-input-schedule"] for row in rows] == ["novelty", "novelty"]


@pytest.fixture
def output_cli(tmp_path, monkeypatch):
    """Use real executor initialization/records, replacing only native phases."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    env = ('BINARY="guest"\nPOC_INPUT="poc"\nTEST_CMD="@@"\n'
           'PATCH_LOC="0x401000"\nTOTAL_PATCHES="1"\n'
           'BINRADAR_PATCH_KIND="generic-erm"\n')
    for name in ("binradar.env", "generate-concrete.env", "generate-binradar.env"):
        (workdir / name).write_text(env)
    monkeypatch.setattr(binradar, "setlimits", lambda: None)
    monkeypatch.setattr(binradar.signal, "signal", lambda *args: None)
    monkeypatch.chdir(tmp_path)

    def prepare_plt(self, filename):
        Path(filename).write_text("initialized PLT\n")
        return filename

    monkeypatch.setattr(binradar.BinRadarExecutor, "set_plt_info", prepare_plt)
    for name in ("run_probe", "run_fuzzolic", "run_directed", "run_fuzzer",
                 "run_minimizer", "run_minimizer_and_verifier", "run_binradar",
                 "run_feedback", "run_final"):
        monkeypatch.setattr(binradar.BinRadarExecutor, name,
                            lambda self, *args, **kwargs: None)
    # Logging ownership is unrelated to output selection; avoid leaving the
    # process-global logger attached to a temporary directory across tests.
    monkeypatch.setattr(binradar.logger, "set_file", lambda filename: None)

    def invoke(*args):
        monkeypatch.setattr(sys, "argv", ["binradar", "-w", str(workdir), *args])
        binradar.main()

    return workdir, invoke


@pytest.mark.parametrize("mode", [
    [], ["--seq"], ["--fuzzer-only"], ["--generate-concrete"],
    ["--generate-concrete", "--seq"], ["--generate-binradar"],
    ["--run-single-phase", "probe"],
    ["--generate-concrete", "--run-single-phase", "probe"],
    ["--generate-binradar", "--run-single-phase", "probe"],
])
@pytest.mark.parametrize("run_id", ["37", "last"])
def test_explicit_output_is_fresh_exact_leaf_for_every_schedule(
        tmp_path, output_cli, mode, run_id):
    workdir, invoke = output_cli
    output = tmp_path / "requested"
    output.mkdir()
    (output / "old-result").write_bytes(b"old")
    (output / "progress.sbsv").write_text(
        "[rundir] [set] [prefix ignored] [id 99] [dir stale]\n")
    invoke("--output", str(output), "--run-prefix", "ignored",
           "--run-id", run_id, *mode)
    assert not (output / "old-result").exists()
    assert not (output / "ignored-00037").exists()
    assert not (output / "run-00000").exists()
    assert (output / "plt_info.txt").read_text() == "initialized PLT\n"
    progress = (output / "progress.sbsv").read_text()
    assert "[prefix run] [id 0]" in progress
    assert "stale" not in progress
    settings = (output / "binradar-setting.sbsv").read_text()
    assert "[run-prefix run]" in settings or '[run-prefix "run"]' in settings
    assert not (workdir / "out").exists()


def test_omitted_output_preserves_progression_and_last_resume(output_cli):
    workdir, invoke = output_cli
    invoke()
    first = workdir / "out" / "run-00000"
    (first / "preserved").write_bytes(b"first")
    invoke()
    second = workdir / "out" / "run-00001"
    (second / "preserved").write_bytes(b"second")
    invoke("--run-single-phase", "probe", "--run-id", "last")
    assert (first / "preserved").read_bytes() == b"first"
    assert (second / "preserved").read_bytes() == b"second"
    assert not (workdir / "out" / "run-00002").exists()


def test_relative_output_uses_invocation_cwd_and_preserves_parent_alias(
        tmp_path, output_cli):
    workdir, invoke = output_cli
    physical = tmp_path / "physical"
    physical.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(physical, target_is_directory=True)
    invoke("--output", "alias/run")
    assert (physical / "run" / "binradar-setting.sbsv").is_file()
    settings = (physical / "run" / "binradar-setting.sbsv").read_text()
    assert str(alias / "run") in settings
    assert not (workdir / "alias").exists()


@pytest.mark.parametrize("kind", ["workdir", "ancestor", "ancestor-alias", "file"])
def test_exact_output_rejects_destructive_boundaries_without_deletion(
        tmp_path, output_cli, kind):
    workdir, invoke = output_cli
    marker = workdir / "source"
    marker.write_bytes(b"source input")
    output = {"workdir": workdir, "ancestor": tmp_path}.get(kind)
    if kind == "ancestor-alias":
        output = tmp_path / "ancestor-alias"
        output.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "file":
        output = tmp_path / "file"
        output.write_bytes(b"not a directory")
    with pytest.raises(ValueError, match="--output"):
        invoke("--output", str(output))
    assert marker.read_bytes() == b"source input"
    if kind == "file":
        assert output.read_bytes() == b"not a directory"
    if kind == "ancestor-alias":
        assert output.is_symlink()


def test_exact_output_unlinks_final_symlink_without_deleting_target(
        tmp_path, output_cli):
    _, invoke = output_cli
    target = tmp_path / "unrelated"
    target.mkdir()
    (target / "source").write_bytes(b"unrelated input")
    output = tmp_path / "requested"
    output.symlink_to(target, target_is_directory=True)
    invoke("--output", str(output))
    assert not output.is_symlink()
    assert (output / "plt_info.txt").is_file()
    assert (target / "source").read_bytes() == b"unrelated input"
    assert not (target / "plt_info.txt").exists()


@pytest.mark.parametrize("flags", [
    ["--fuzzer-only", "--seq"],
    ["--generate-binradar", "--disable-binradar"],
    ["--generate-concrete", "--feedback"],
    ["--mutation-portfolio", "mixed"],
])
def test_invalid_modes_preserve_explicit_existing_output(tmp_path, output_cli, flags):
    _, invoke = output_cli
    output = tmp_path / "requested"
    output.mkdir()
    marker = output / "existing"
    marker.write_bytes(b"previous results")
    with pytest.raises(SystemExit) as failure:
        invoke("--output", str(output), *flags)
    assert failure.value.code == 2
    assert marker.read_bytes() == b"previous results"
    assert not (output / "plt_info.txt").exists()
