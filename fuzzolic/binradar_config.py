"""Resolved BinRadar configuration and pure phase-environment construction."""

import os
from collections.abc import Mapping
from dataclasses import dataclass

import binradar_utils

FORKSERVER_CHILD_TIMEOUT_DEFAULT = 900
SYMBOLIC_MUTATION_MODE_DEFAULT = "off"
SYMBOLIC_MUTATION_MODES = ("off", "shadow", "boundary")
# Queue scheduling policy for mutation plans.  `existing` is the historical
# order and the default; `retained-first` is the one P4b B2 experiment.
SYMBOLIC_SCHEDULE_DEFAULT = "existing"
SYMBOLIC_SCHEDULES = ("existing", "retained-first")
SYMBOLIC_SCHEDULE_LAYOUT_WIDTH = max(map(len, SYMBOLIC_SCHEDULES))
SYMBOLIC_SCHEDULE_LAYOUT_PAD_KEY = "BINRADAR_SYMBOLIC_SCHEDULE_LAYOUT_PAD"
SYMBOLIC_MAX_WORK_DEFAULT = 1_000_000
SYMBOLIC_MAX_BYTES_DEFAULT = 16 * 1024 * 1024
SYMBOLIC_DEADLINE_MS_DEFAULT = 100
# The tracer guards the deadline by adding the span to the monotonic clock.
# A span that cannot leave room for that sum is unrepresentable, and the
# tracer clamps to this same ceiling; both sides must agree, so a larger
# request is a configuration failure rather than a silent clamp.
SYMBOLIC_DEADLINE_MS_MAX = (2 ** 63 - 1) // 4 // 1000
SYMBOLIC_BUDGET_MAX = 2 ** 64 - 1

# CLI destination -> (environment key, default, allow-zero-means-default)
SYMBOLIC_BUDGET_FIELDS = (
    ("symbolic_max_work", "BINRADAR_SYMBOLIC_MAX_WORK",
     SYMBOLIC_MAX_WORK_DEFAULT, True),
    ("symbolic_max_bytes", "BINRADAR_SYMBOLIC_MAX_BYTES",
     SYMBOLIC_MAX_BYTES_DEFAULT, True),
    ("symbolic_deadline_ms", "BINRADAR_SYMBOLIC_DEADLINE_MS",
     SYMBOLIC_DEADLINE_MS_DEFAULT, False),
)

# We need to turn on MEMCHECK in tracer for binradar phase
MEMCHECK_ENABLED_MODES = ("binradar",)

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


def validate_symbolic_schedule(value: str) -> str:
    """Normalize and validate a mutation queue scheduling policy name."""
    normalized = str(value).strip().lower()
    if normalized not in SYMBOLIC_SCHEDULES:
        raise ValueError(
            f"invalid symbolic schedule {value!r}; expected one of "
            f"{', '.join(SYMBOLIC_SCHEDULES)}")
    return normalized


def parse_bounded_unsigned_decimal(name: str, value: object,
                                   maximum: int) -> int:
    """Parse an unsigned decimal budget without wrapping.

    Rejects signs, whitespace, fractional, and out-of-range input
    instead of silently truncating it; a budget that cannot be represented is
    a configuration failure, not a fallback to the default.
    """
    text = str(value)
    if not text or not all(character in "0123456789" for character in text):
        raise ValueError(
            f"invalid {name} {value!r}; expected an unsigned decimal integer")
    parsed = int(text, 10)
    if parsed > maximum:
        raise ValueError(
            f"{name} {parsed} exceeds the supported maximum {maximum}")
    return parsed


def resolve_symbolic_budgets(
        cli_values: Mapping[str, object], env: Mapping[str, str]
) -> dict[str, int]:
    """Resolve the three advisor budgets once, before any trial runs.

    Precedence is explicit CLI value, then the value loaded from the workdir's
    ``binradar.env``, then the built-in default - the same shape the advisor
    mode uses.  A work/byte zero means "use the default", matching the
    tracer's existing behavior; a deadline of zero disables the emergency
    guard and keeps that explicit meaning.
    """
    resolved: dict[str, int] = {}
    for field, key, default, zero_is_default in SYMBOLIC_BUDGET_FIELDS:
        cli_value = cli_values.get(field)
        raw = cli_value if cli_value is not None else env.get(key, default)
        maximum = (SYMBOLIC_DEADLINE_MS_MAX
                   if field == "symbolic_deadline_ms"
                   else SYMBOLIC_BUDGET_MAX)
        parsed = parse_bounded_unsigned_decimal(key, raw, maximum)
        if zero_is_default and parsed == 0:
            parsed = default
        resolved[field] = parsed
    return resolved


@dataclass(frozen=True)
class SymbolicBudgets:
    """Effective advisor budgets for one run."""

    max_work: int
    max_bytes: int
    deadline_ms: int

    @classmethod
    def from_mapping(cls, resolved: Mapping[str, int]) -> "SymbolicBudgets":
        return cls(
            max_work=resolved["symbolic_max_work"],
            max_bytes=resolved["symbolic_max_bytes"],
            deadline_ms=resolved["symbolic_deadline_ms"],
        )

    def environment(self) -> dict[str, str]:
        return {
            "BINRADAR_SYMBOLIC_MAX_WORK": str(self.max_work),
            "BINRADAR_SYMBOLIC_MAX_BYTES": str(self.max_bytes),
            "BINRADAR_SYMBOLIC_DEADLINE_MS": str(self.deadline_ms),
        }


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
    symbolic_schedule: str
    symbolic_budgets: SymbolicBudgets
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
            symbolic_schedule=validate_symbolic_schedule(env.get(
                "BINRADAR_SYMBOLIC_SCHEDULE",
                SYMBOLIC_SCHEDULE_DEFAULT)),
            # CLI overrides arrive pre-merged into `env`, so the effective
            # value here is already the resolved one.
            symbolic_budgets=SymbolicBudgets.from_mapping(
                resolve_symbolic_budgets({}, env)),
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
        "BINRADAR_SYMBOLIC_SCHEDULE": config.symbolic_schedule,
        "SYMBOLIC_TESTCASE_NAME": config.resolved_poc_input(),
        "PLT_INFO_FILE": plt_info_file,
    }
    # The resolved budgets, not the module defaults: a per-run override must
    # reach the tracer, and nothing later may overwrite it with a constant.
    environment.update(config.symbolic_budgets.environment())
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
    requested_schedule = validate_symbolic_schedule(
        base_environment.get(
            "BINRADAR_SYMBOLIC_SCHEDULE",
            environment.get("BINRADAR_SYMBOLIC_SCHEDULE",
                            SYMBOLIC_SCHEDULE_DEFAULT)))
    # The schedule only permutes mutation plans, which exist only in this
    # phase; every other phase would inherit a meaningless value.  Keep the
    # combined schedule+padding value width fixed so an A/B policy spelling
    # cannot shift the guest's initial stack and manufacture different plan
    # addresses before the scheduler runs.
    effective_schedule = (
        requested_schedule if mode == "binradar" else SYMBOLIC_SCHEDULE_DEFAULT)
    environment["BINRADAR_SYMBOLIC_SCHEDULE"] = effective_schedule
    environment[SYMBOLIC_SCHEDULE_LAYOUT_PAD_KEY] = (
        "_" * (SYMBOLIC_SCHEDULE_LAYOUT_WIDTH - len(effective_schedule)))
    environment["BINRADAR_TRACER_LOG_FILE"] = phase_log_file(mode, run_dir)

    # Explicit crash-detection policy.
    environment["BINRADAR_MEMCHECK_ENABLE"] = (
        "1" if mode in MEMCHECK_ENABLED_MODES else "0")

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
