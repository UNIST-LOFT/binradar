"""Patch-0 artifact baseline validation for the BINRADAR phase."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

import sbsv

from . import binradar_evidence
from . import binradar_utils
from . import binradar_verifier
from . import logger
from . import paths

_EXIT_SCHEMA = (
    "[snapshot] [exit] [normal] [entrypoint-hit: int]")
_PARSER: Optional[sbsv.parser] = None


class BaselineStatus(str, Enum):
    """Outcome of validating the selected artifact's patch-0 baseline."""

    REPRODUCED = "reproduced"
    #: Patch 0 not reproducing the POC fault.
    NORMAL = "normal"
    #: Patch 0 crashed, but provably at a different original instruction.
    DIFFERENT_FAULT = "different-fault"
    #: The baseline could not be established (missing artifact, timeout,
    #: unreadable log, or no validated fault identity where one is required).
    UNUSABLE = "unusable"


@dataclass(frozen=True)
class BaselineCheck:
    """One artifact's baseline observation."""

    artifact: str
    status: BaselineStatus
    reference: Optional[binradar_verifier.TracerFaultReference]
    detail: str


@dataclass(frozen=True)
class BaselineResult:
    """The whole baseline validation: the reference identity and each run."""

    reference: Optional[binradar_verifier.TracerFaultReference]
    selected_suffix: str
    checks: Tuple[BaselineCheck, ...]

    def check(self, artifact: str) -> Optional[BaselineCheck]:
        for entry in self.checks:
            if entry.artifact == artifact:
                return entry
        return None

    @property
    def selected(self) -> Optional[BaselineCheck]:
        """The check for the artifact the phase will actually execute."""
        return self.check(self.selected_suffix)

    def summary(self) -> str:
        parts = []
        for entry in self.checks:
            parts.append(f"[{entry.artifact} {entry.status.value}]")
        return " ".join(parts)


def reference_from_baseline(
        frame: binradar_evidence.BinradarIteration,
) -> Optional[binradar_verifier.TracerFaultReference]:
    """Use only the selected artifact's committed, unmutated patch 0.

    PROBE and preflight observations are separate diagnostics. A normal or
    historical untyped baseline cannot authorize hard-crash classifications,
    and a later mutation must never supply the missing reference.
    """
    if (frame.iteration != 1 or len(frame.groups) != 1
            or frame.groups[0].representative != 0
            or frame.groups[0].members != [0]):
        raise ValueError("BINRADAR reference requires unmutated baseline patch 0")
    group = frame.groups[0]
    if group.outcome != "crash" or group.source is None:
        return None
    reference = binradar_verifier.TracerFaultReference(
        group.fault_addr, group.source, group.image_id, group.image_offset)
    if not reference.valid:
        raise ValueError("BINRADAR baseline has an invalid fault reference")
    return reference


def read_mutation_reference(
        evidence_path: os.PathLike[str] | str,
) -> Optional[binradar_verifier.TracerFaultReference]:
    """Recover the immutable mutation oracle without rerunning an artifact."""
    if not os.path.isfile(evidence_path):
        return None
    frames = binradar_evidence.read_binradar(evidence_path)
    try:
        frame = next(frames, None)
        return reference_from_baseline(frame) if frame is not None else None
    finally:
        frames.close()


def _parser() -> sbsv.parser:
    global _PARSER
    if _PARSER is None:
        parser = sbsv.parser()
        parser.add_schema(_EXIT_SCHEMA)
        _PARSER = parser
    return _PARSER


def _controlled_environment(config: Dict[str, str], *,
                            e9_ranges: str = "",
                            relocated_calls: str = "",
                            relocated_instructions: str = "",
                            patch_fd: Optional[int] = None) -> Dict[str, str]:
    """Environment for one baseline tracer run."""
    environment = dict(config)
    for key in (
            # forkserver control/status and patch channels
            "BINRADAR_FORKSERVER_CTRL_R", "BINRADAR_FORKSERVER_STAT_W",
            "BINRADAR_FORKSERVER_ENABLE", "BINRADAR_FORKSERVER_CHILD_TIMEOUT",
            "BINRADAR_FORKSERVER_ITERATION_TIMEOUT",
            "BINRADAR_PATCH_FD_R", "PATCH_FD", "BINRADAR_PATCH_CACHED_FD_R",
            "PATCH_CACHED_FD", "BINRADAR_PATCH_SHM_KEY",
            "BINRADAR_PATCH_CACHE_ENABLE", "BINRADAR_PATCH_MANIFEST",
            "BINRADAR_PATCH_FILTER_FILE", "BINRADAR_EVIDENCE_FILE",
            "BINRADAR_PATCH_CNT", "PATCH_ID", "TAOSC_PRED",
            "AFL_QEMU_INST_RANGES", "AFL_USE_QASAN",
            # phase-only instrumentation and structured destinations
            "BINRADAR_TRACER_LOG_FILE", "BINRADAR_PROBE_FILE",
            "BINRADAR_QUERY_WINDOW_FILE", "BINRADAR_FEEDBACK_DIR",
    ):
        environment.pop(key, None)
    environment["BINRADAR_FORKSERVER_ENABLE"] = "0"
    environment["BINRADAR_MEMCHECK_ENABLE"] = "1"
    environment["BINRADAR_MEMCHECK_POLICY"] = binradar_verifier.MEMCHECK_POLICY
    environment["BINRADAR_TRACE_FILE"] = "none"
    environment["BINRADAR_OSPREY_ENABLE"] = "0"
    environment["BINRADAR_SYMBOLIC_MUTATION_MODE"] = "off"
    environment["PATCH_ID"] = "0"
    environment["E9_EXCLUDE_RANGES"] = e9_ranges
    environment["E9_RELOCATED_CALL_JUMPS"] = relocated_calls
    environment["E9_RELOCATED_INSTRUCTIONS"] = relocated_instructions
    if patch_fd is not None:
        environment["PATCH_FD"] = str(patch_fd)
    return environment


def _parse_reference(log: str) -> Optional[binradar_verifier.TracerFaultReference]:
    return binradar_verifier.read_snapshot_fault_reference(log, require_current=True)


def _is_normal_exit(log: str) -> bool:
    """True when the log carries a clean guest normal exit row."""
    parser = _parser()
    result = parser.loads(log)
    return bool(result["snapshot"]["exit"]["normal"])


def _run_tracer(workdir: str, binary: str, environment: Dict[str, str],
                test_cmd: str, testcase: str, timeout: float):
    """Run the real tracer once on `binary` and return its execution result.
    """
    command = [paths.TRACER_BIN, "-symbolic", "-d", "page", binary] + shlex.split(
        test_cmd.replace("@@", testcase))
    patch_rfd = patch_wfd = None
    env = dict(environment)
    env["NO_EXTERNAL_SOLVER"] = "1"
    if "PATCH_FD" in environment:
        patch_rfd, patch_wfd = os.pipe()
        env["PATCH_FD"] = str(patch_wfd)
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            cwd=workdir, env=env, start_new_session=True,
            pass_fds=((patch_wfd,) if patch_wfd is not None else ()))
    except Exception:
        if patch_rfd is not None:
            os.close(patch_rfd)
        if patch_wfd is not None:
            os.close(patch_wfd)
        raise
    reader = None
    try:
        if patch_wfd is not None:
            os.close(patch_wfd)
            reader, _chunks = binradar_utils.create_pipe_reader_thread(
                patch_rfd)
        result = binradar_utils.execute_await(process, timeout=timeout,
                                              verbose=False)
        return result
    finally:
        if reader is not None:
            reader.join(timeout=5)


def _classify(artifact: str, result, reference) -> BaselineCheck:
    """Classify one artifact's patch-0 observation against `reference`."""
    if result is None:
        return BaselineCheck(artifact, BaselineStatus.UNUSABLE, None,
                             "phase deadline reached before execution")
    if not result.success:
        reason = "timeout" if result.timed_out else result.decode_status()
        return BaselineCheck(artifact, BaselineStatus.UNUSABLE, None,
                             f"execution unusable ({reason})")
    # `execute_await` reports success for a process killed by an external
    # termination signal, and the tracer's signal path can salvage the
    # interrupted guest pc as a valid-looking fault reference (or emit a
    # normal row) at its kill PC.  That is not this artifact's baseline
    # identity, so reject the cancellation before reading the log even when
    # the salvaged rows look usable.  A genuine guest SIGSEGV re-raised by
    # QEMU stays usable.
    if binradar_verifier.tracer_execution_cancelled(result.exit_code):
        return BaselineCheck(
            artifact, BaselineStatus.UNUSABLE, None,
            f"tracer cancelled on signal {-result.exit_code}")
    log = result.stderr or ""
    if not binradar_verifier.tracer_memcheck_policy_acknowledged(log):
        return BaselineCheck(
            artifact, BaselineStatus.UNUSABLE, None,
            f"tracer did not acknowledge memcheck policy {binradar_verifier.MEMCHECK_POLICY}")
    try:
        observed = _parse_reference(log)
    except ValueError as exc:
        return BaselineCheck(artifact, BaselineStatus.UNUSABLE, None,
                             f"invalid fault identity ({exc})")
    if observed is None:
        # Normal is observable even when PROBE has no fault reference.
        if _is_normal_exit(log):
            return BaselineCheck(
                artifact, BaselineStatus.NORMAL, None,
                "patch 0 exited normally (POC fault not observed)")
        return BaselineCheck(artifact, BaselineStatus.UNUSABLE, None,
                             "no validated fault identity published")
    if reference is None:
        return BaselineCheck(artifact, BaselineStatus.UNUSABLE, observed,
                             "PROBE has no validated fault identity")

    if observed.image_id is not None or reference.image_id is not None:
        status = (BaselineStatus.REPRODUCED
                  if observed.identity_key == reference.identity_key
                  else BaselineStatus.DIFFERENT_FAULT)
        return BaselineCheck(artifact, status, observed,
                             f"fault identity {observed.identity_key!r}")
    if observed.identity_key == reference.identity_key:
        return BaselineCheck(artifact, BaselineStatus.REPRODUCED, observed,
                             f"{observed.source} at {observed.address:#x}")
    return BaselineCheck(
        artifact, BaselineStatus.DIFFERENT_FAULT, observed,
        f"{observed.source} at {observed.address:#x} differs from the "
        f"original fault {reference.address:#x}")


def validate_patch_zero_baseline(
        workdir: str,
        config: Dict[str, str],
        *,
        original: str,
        probe_reference: Optional[binradar_verifier.TracerFaultReference],
        selected_binary: str,
        test_cmd: str,
        testcase: str,
        timeout: float,
        phase_deadline: Optional[float] = None,
        identity_runner: binradar_verifier.BinRadarQemuRunner,
        probe_policy: Optional[str] = None,
        selected_only: bool = False,
) -> BaselineResult:
    """Validate original and patch-zero artifacts against the saved POC.

    Baseline-only feedback excludes unrelated patched artifacts, including
    their identity maps; ordinary verification still checks every artifact.
    """
    if probe_policy != binradar_verifier.MEMCHECK_POLICY:
        raise ValueError(
            "PROBE memcheck policy is old, absent, or mismatched; "
            "start a fresh run with --run-id n")

    # Validate every executed artifact before the first tracer launch. Each
    # path uses its own bound map, never inherited data from another artifact.
    patched_paths = ([selected_binary] if selected_only else [
        original[:-len(".orig")] + suffix
        for suffix in (".brpatched", ".brcached")])
    instruction_pairs = {original: ""}
    for path in patched_paths:
        if os.path.exists(path):
            instruction_pairs[path] = identity_runner.tracer_instruction_pairs(path)

    def metadata_for(path: str) -> Tuple[str, Sequence[str]]:
        return identity_runner.e9_metadata_for_binary(path)

    def suffix_of(path: str) -> str:
        for suffix in (".brpatched", ".brcached", ".orig"):
            if path.endswith(suffix):
                return suffix
        return ""

    def run_artifact(path: str, ranges: str, records: Sequence[str],
                     patched: bool):
        remaining = (timeout if phase_deadline is None else
                     min(timeout, phase_deadline - time.monotonic()))
        if remaining <= 0:
            return None
        return _run_tracer(
            workdir, path,
            _controlled_environment(config, e9_ranges=ranges,
                                    relocated_calls=",".join(records),
                                    relocated_instructions=instruction_pairs[path],
                                    patch_fd=-1 if patched else None),
            test_cmd, testcase, remaining)

    selected_suffix = suffix_of(selected_binary)
    checks: List[BaselineCheck] = []
    # FINAL compares mutation crashes to PROBE, not to a new reference
    # discovered by this preflight. A changed original oracle must not make
    # both original and patched executions look mutually "reproduced".
    reference = (probe_reference if probe_reference is not None
                 and probe_reference.valid else None)
    if os.path.exists(original):
        ranges, records = metadata_for(original)
        result = run_artifact(original, ranges, records, False)
        original_check = _classify(".orig", result, reference)
        checks.append(original_check)
    else:
        return BaselineResult(
            None, selected_suffix,
            (BaselineCheck(".orig", BaselineStatus.UNUSABLE, None,
                           "the original binary is missing"),))

    for path in patched_paths:
        if not os.path.exists(path):
            continue
        suffix = suffix_of(path)
        ranges, records = metadata_for(path)
        result = run_artifact(path, ranges, records, True)
        check = _classify(suffix, result, reference)
        if (check.status is BaselineStatus.REPRODUCED
                and original_check.status is not BaselineStatus.REPRODUCED):
            check = BaselineCheck(
                suffix, BaselineStatus.UNUSABLE, check.reference,
                f"artifact matches PROBE but .orig baseline is "
                f"{original_check.status.value}: {original_check.detail}")
        checks.append(check)
    return BaselineResult(reference, selected_suffix, tuple(checks))


def log_result(result: BaselineResult) -> None:
    """Emit one structured summary row for the baseline validation."""
    reference = result.reference
    if reference is None:
        logger.warning(
            f"[binradar] [baseline] [reference unavailable] "
            f"{result.summary()}")
    else:
        logger.info(
            f"[binradar] [baseline] [reference {reference.address:#x} "
            f"({reference.source})] {result.summary()}")
    for entry in result.checks:
        if entry.status in (BaselineStatus.UNUSABLE,
                            BaselineStatus.DIFFERENT_FAULT):
            logger.warning(
                f"[binradar] [baseline] [{entry.artifact} "
                f"{entry.status.value}] [detail {entry.detail}]")
