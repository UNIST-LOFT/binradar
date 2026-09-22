"""Resolved BinRadar configuration and pure phase-environment construction."""

import os
from collections.abc import Mapping
from dataclasses import dataclass

import binradar_utils

FORKSERVER_CHILD_TIMEOUT_DEFAULT = 900
SYMBOLIC_MUTATION_MODE_DEFAULT = "off"
SYMBOLIC_MUTATION_MODES = ("off", "shadow", "boundary")
SYMBOLIC_MAX_WORK_DEFAULT = 1_000_000
SYMBOLIC_MAX_BYTES_DEFAULT = 16 * 1024 * 1024
SYMBOLIC_DEADLINE_MS_DEFAULT = 100

_RETAINED_ENVIRONMENT_KEYS = (
    "BINRADAR_PATCH_KIND",
    "BRCACHE_STACK_SIZE",
    "BINRADAR_AFL_EXEC_TIMEOUT",
)


def validate_symbolic_mutation_mode(value: str) -> str:
    """Normalize and validate a symbolic advisor mode name."""
    normalized = str(value).strip().lower()
    if normalized not in SYMBOLIC_MUTATION_MODES:
        raise ValueError(
            f"invalid symbolic mutation mode {value!r}; expected one of "
            f"{', '.join(SYMBOLIC_MUTATION_MODES)}")
    return normalized


@dataclass(frozen=True)
class RunConfig:
    """Immutable options resolved before executor startup has side effects."""

    workdir: str
    outdir: str
    timeout: int
    binary: str
    poc_input: str
    test_cmd: str
    patch_loc: str
    total_patches: int
    brpatched_total_patches: int
    filter_total_patches: int
    fuzzy: bool
    reverse_directed: bool
    disable_binradar: bool
    less_strict: bool
    feedback_mode: bool
    forkserver_child_timeout: int
    symbolic_mutation_mode: str
    requested_candidate_scope: str
    candidate_scope_status: str
    candidate_scope_reason: str
    invocation: str
    e9_metadata_prefix: str
    retained_environment: tuple[tuple[str, str], ...]

    @classmethod
    def from_environment(
            cls, workdir: str, env: Mapping[str, str]) -> "RunConfig":
        child_timeout = int(env.get(
            "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP",
            str(FORKSERVER_CHILD_TIMEOUT_DEFAULT)))
        if child_timeout <= 0:
            raise ValueError(
                "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP must be positive")

        prefix = env.get("E9_METADATA_PREFIX", "brpatched")
        # Validate the name before any executor preparation starts.
        binradar_utils.e9_metadata_keys(prefix)

        retained = {}
        for artifact in binradar_utils.E9_METADATA_PREFIXES:
            ranges_key, calls_key = binradar_utils.e9_metadata_keys(artifact)
            for key in (ranges_key, calls_key):
                if key in env:
                    retained[key] = env[key]
        for key in _RETAINED_ENVIRONMENT_KEYS:
            if key in env:
                retained[key] = env[key]

        total_patches = int(env["TOTAL_PATCHES"])
        return cls(
            workdir=os.path.abspath(workdir),
            outdir=os.path.abspath(env["BINRADAR_OUTDIR"]),
            timeout=int(env["BINRADAR_TIMEOUT"]),
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            test_cmd=env["TEST_CMD"],
            patch_loc=env["PATCH_LOC"],
            total_patches=total_patches,
            brpatched_total_patches=int(env.get(
                "BRPATCHED_TOTAL_PATCHES", env["TOTAL_PATCHES"])),
            filter_total_patches=int(env.get(
                "FILTER_TOTAL_PATCHES", env["TOTAL_PATCHES"])),
            fuzzy=env.get("BINRADAR_FUZZY", "0") == "1",
            reverse_directed=(
                env.get("BINRADAR_REVERSE_DIRECTED", "0") == "1"),
            disable_binradar=(
                env.get("BINRADAR_DISABLE_BINRADAR", "0") == "1"),
            less_strict=env.get("BINRADAR_LESS_STRICT", "0") == "1",
            feedback_mode=(
                env.get("BINRADAR_FEEDBACK_MODE", "0") == "1"),
            forkserver_child_timeout=child_timeout,
            symbolic_mutation_mode=validate_symbolic_mutation_mode(env.get(
                "BINRADAR_SYMBOLIC_MUTATION_MODE",
                SYMBOLIC_MUTATION_MODE_DEFAULT)),
            requested_candidate_scope=env.get(
                "BINRADAR_TARGET_PATCHES", "configured"),
            candidate_scope_status=env.get(
                "BINRADAR_TARGET_PATCHES_STATUS", "configured"),
            candidate_scope_reason=env.get(
                "BINRADAR_TARGET_PATCHES_REASON", "not-recorded"),
            invocation=env.get("BINRADAR_INVOCATION", ""),
            e9_metadata_prefix=prefix,
            retained_environment=tuple(retained.items()),
        )

    def resolved_poc_input(self) -> str:
        if os.path.isabs(self.poc_input):
            return self.poc_input
        return os.path.join(self.workdir, self.poc_input)


def build_base_environment(config: RunConfig, plt_info_file: str) -> dict[str, str]:
    """Build the executor's stable environment after preparation completes."""
    environment = {
        "BINRADAR_TIMEOUT": str(config.timeout),
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "BINRADAR_SYMBOLIC_MUTATION_MODE": config.symbolic_mutation_mode,
        "BINRADAR_SYMBOLIC_MAX_WORK": str(SYMBOLIC_MAX_WORK_DEFAULT),
        "BINRADAR_SYMBOLIC_MAX_BYTES": str(SYMBOLIC_MAX_BYTES_DEFAULT),
        "BINRADAR_SYMBOLIC_DEADLINE_MS": str(SYMBOLIC_DEADLINE_MS_DEFAULT),
        "SYMBOLIC_TESTCASE_NAME": config.resolved_poc_input(),
        "PLT_INFO_FILE": plt_info_file,
    }
    if config.timeout > 0:
        environment["SOLVER_TIMEOUT"] = str(int(config.timeout * 1000))
    environment.update(config.retained_environment)
    return environment


def build_worker_environment(
        config: RunConfig, dynamic_environment: Mapping[str, str]) -> dict[str, str]:
    """Build the config consumed by verifier, minimizer, and fuzzer workers."""
    environment = dict(dynamic_environment)
    environment.update({
        "BINRADAR_OUTDIR": config.outdir,
        "BINRADAR_TIMEOUT": str(config.timeout),
        "BINARY": config.binary,
        "POC_INPUT": config.poc_input,
        "TEST_CMD": config.test_cmd,
        "PATCH_LOC": config.patch_loc,
        "E9_METADATA_PREFIX": config.e9_metadata_prefix,
        "TOTAL_PATCHES": str(config.total_patches),
    })
    return environment


@dataclass(frozen=True)
class PhaseEnvironmentConfig:
    """Inputs needed to construct one tracer/solver phase environment."""

    timeout: int
    forkserver_child_timeout: int
    reverse_directed: bool
    probe_patch_hit_count: int
    active_patch_count: int
    e9_exclude_ranges: str = ""
    e9_relocated_calls: str = ""


def phase_log_file(mode: str, run_dir: str) -> str:
    return os.path.join(run_dir, f"{mode}-tracer-msg.log")


def build_phase_environment(
        mode: str,
        run_dir: str,
        base_environment: Mapping[str, str],
        phase: PhaseEnvironmentConfig,
        *,
        inherited_environment: Mapping[str, str] | None = None,
        forkserver_read_timeout: float = 1800,
        forkserver_analyze_margin: float = 300) -> dict[str, str]:
    """Build a phase environment without touching files or process state."""
    environment = dict(
        os.environ if inherited_environment is None else inherited_environment)
    environment.update(base_environment)
    environment["BINRADAR_OSPREY_ENABLE"] = (
        "1" if mode == "binradar" else "0")

    requested_mode = validate_symbolic_mutation_mode(
        base_environment.get(
            "BINRADAR_SYMBOLIC_MUTATION_MODE",
            environment.get("BINRADAR_SYMBOLIC_MUTATION_MODE",
                            SYMBOLIC_MUTATION_MODE_DEFAULT)))
    environment["BINRADAR_SYMBOLIC_MUTATION_MODE"] = (
        requested_mode if mode == "binradar" else "off")
    environment["BINRADAR_TRACER_LOG_FILE"] = phase_log_file(mode, run_dir)

    # Original-binary phases must not inherit patched E9 metadata.
    environment["E9_EXCLUDE_RANGES"] = ""
    environment["E9_RELOCATED_CALL_JUMPS"] = ""
    if mode == "binradar":
        environment["E9_EXCLUDE_RANGES"] = phase.e9_exclude_ranges
        environment["E9_RELOCATED_CALL_JUMPS"] = phase.e9_relocated_calls

    environment["BINRADAR_REVERSE_DIRECTED"] = "0"
    if mode == "fuzzolic":
        environment["BINRADAR_PROBE_FILE"] = os.path.join(
            run_dir, "probe-result-fuzzolic.sbsv")
        environment["BINRADAR_FORKSERVER_ENABLE"] = "0"
        environment["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = "0"
        environment["BINRADAR_TRACE_FILE"] = "none"
        return environment

    if mode not in ("directed", "binradar"):
        return environment

    if phase.forkserver_child_timeout <= 0:
        raise RuntimeError("forkserver child timeout cap must be positive")
    child_timeout = phase.forkserver_child_timeout
    if phase.timeout > 0:
        child_timeout = min(child_timeout, phase.timeout)
    if forkserver_read_timeout <= child_timeout + forkserver_analyze_margin:
        raise RuntimeError(
            f"forkserver iteration timeout {child_timeout}s + analyze margin "
            f"{forkserver_analyze_margin:g}s must stay below the forkserver "
            f"read timeout {forkserver_read_timeout:g}s; lower "
            f"--forkserver-child-timeout")

    environment["BINRADAR_FORKSERVER_ENABLE"] = "1"
    environment["BINRADAR_FORKSERVER_CHILD_TIMEOUT"] = str(int(child_timeout))
    environment["BINRADAR_FORKSERVER_ITERATION_TIMEOUT"] = str(
        int(child_timeout))
    environment["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = str(
        phase.probe_patch_hit_count)
    if mode == "directed":
        environment["BINRADAR_REVERSE_DIRECTED"] = (
            "1" if phase.reverse_directed else "0")
        environment["BINRADAR_QUERY_WINDOW_FILE"] = os.path.join(
            run_dir, "binradar-query-window.sbsv")
        environment["BINRADAR_PRESERVE_CHILD_QUERIES"] = "1"
        environment["BINRADAR_TRACE_FILE"] = "none"
    else:
        environment["BINRADAR_TRACE_FILE"] = "none"
        environment["BINRADAR_PRESERVE_CHILD_QUERIES"] = "0"
        environment["PATCH_ID"] = "123456"
        environment["BINRADAR_PATCH_CNT"] = str(phase.active_patch_count)
        environment["BINRADAR_EVIDENCE_FILE"] = os.path.join(
            run_dir, "binradar.br")
    return environment
