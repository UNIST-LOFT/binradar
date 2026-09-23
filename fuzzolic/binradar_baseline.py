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

import binradar_utils
import binradar_verifier
import logger

TRACER_BIN = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "..", "tracer", "build", "x86_64-linux-user", "qemu-x86_64")

_SCHEMA = (
    "[snapshot] [fault-reference] [version: int] [valid: bool] "
    "[source: str] [address: hex]")
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


def _parser() -> sbsv.parser:
    global _PARSER
    if _PARSER is None:
        parser = sbsv.parser()
        parser.add_schema(_SCHEMA)
        parser.add_schema(_EXIT_SCHEMA)
        _PARSER = parser
    return _PARSER


def _controlled_environment(config: Dict[str, str], *,
                            e9_ranges: str = "",
                            relocated_calls: str = "",
                            patch_fd: Optional[int] = None) -> Dict[str, str]:
    """Environment for one baseline tracer run."""
    environment = dict(config)
    for key in (
            # forkserver control/status and patch channels
            "BINRADAR_FORKSERVER_CTRL_R", "BINRADAR_FORKSERVER_STAT_W",
            "BINRADAR_FORKSERVER_ENABLE", "BINRADAR_FORKSERVER_CHILD_TIMEOUT",
            "BINRADAR_FORKSERVER_ITERATION_TIMEOUT",
            "BINRADAR_FORKSERVER_TARGET_HIT_COUNT",
            "BINRADAR_PATCH_FD_R", "PATCH_FD", "BINRADAR_PATCH_CACHED_FD_R",
            "PATCH_CACHED_FD", "BINRADAR_PATCH_SHM_KEY",
            "BINRADAR_PATCH_CACHE_ENABLE", "BINRADAR_PATCH_MANIFEST",
            "BINRADAR_PATCH_FILTER_FILE", "BINRADAR_EVIDENCE_FILE",
            "BINRADAR_PATCH_CNT", "PATCH_ID", "TAOSC_PRED",
            "AFL_QEMU_INST_RANGES", "AFL_USE_QASAN",
            # phase-only instrumentation and structured destinations
            "BINRADAR_PRESERVE_CHILD_QUERIES",
            "BINRADAR_TRACER_LOG_FILE", "BINRADAR_PROBE_FILE",
            "BINRADAR_QUERY_WINDOW_FILE", "BINRADAR_FEEDBACK_DIR",
    ):
        environment.pop(key, None)
    environment["BINRADAR_FORKSERVER_ENABLE"] = "0"
    environment["BINRADAR_TRACE_FILE"] = "none"
    environment["BINRADAR_OSPREY_ENABLE"] = "0"
    environment["BINRADAR_SYMBOLIC_MUTATION_MODE"] = "off"
    environment["PATCH_ID"] = "0"
    environment["E9_EXCLUDE_RANGES"] = e9_ranges
    environment["E9_RELOCATED_CALL_JUMPS"] = relocated_calls
    if patch_fd is not None:
        environment["PATCH_FD"] = str(patch_fd)
    return environment


def _parse_reference(log: str) -> Optional[binradar_verifier.TracerFaultReference]:
    parser = _parser()
    result = parser.loads(log)
    rows = result["snapshot"]["fault-reference"]
    if not rows:
        return None
    row = rows[-1]
    if (row["version"] == 2 and row["valid"]
            and row["source"] in binradar_verifier.TRACER_FAULT_VALID_SOURCES):
        return binradar_verifier.TracerFaultReference(
            row["address"], row["source"])
    return None


def _is_normal_exit(log: str) -> bool:
    """True when the log carries a clean guest normal exit row."""
    parser = _parser()
    result = parser.loads(log)
    return bool(result["snapshot"]["exit"]["normal"])


def _run_tracer(workdir: str, binary: str, environment: Dict[str, str],
                test_cmd: str, testcase: str, timeout: float):
    """Run the real tracer once on `binary` and return its execution result.
    """
    command = [TRACER_BIN, "-symbolic", "-d", "page", binary] + shlex.split(
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


def _classify(artifact: str, result, reference, relocation_records, ranges,
              patch_loc: int) -> BaselineCheck:
    """Classify one artifact's patch-0 observation against `reference`."""
    if result is None:
        return BaselineCheck(artifact, BaselineStatus.UNUSABLE, None,
                             "phase deadline reached before execution")
    if not result.success:
        reason = "timeout" if result.timed_out else result.decode_status()
        return BaselineCheck(artifact, BaselineStatus.UNUSABLE, None,
                             f"execution unusable ({reason})")
    log = result.stderr or ""
    observed = _parse_reference(log)
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

    site = binradar_verifier.e9_relocated_call_site(observed.address,
                                                    relocation_records)
    normalized_address = site if site is not None else observed.address
    if (site is None and ranges
            and binradar_verifier.addr_in_e9_ranges(observed.address, ranges)):
        return BaselineCheck(
            artifact, BaselineStatus.UNUSABLE, observed,
            f"fault pc {observed.address:#x} lies in the E9 trampoline/"
            f"reserve pages with no relocation record proving it is the "
            f"relocated copy of the patch site ({patch_loc:#x})")
    if normalized_address == reference.address:
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
        patch_loc: str,
        test_cmd: str,
        testcase: str,
        timeout: float,
        phase_deadline: Optional[float] = None,
        metadata: Dict[str, Tuple[str, Sequence[str]]],
) -> BaselineResult:
    """Validate the POC on `.orig`, `.brpatched`, and `.brcached` patch 0.
    """
    def metadata_for(path: str) -> Tuple[str, Sequence[str]]:
        for suffix in (".brpatched", ".brcached", ".orig"):
            if path.endswith(suffix):
                return metadata.get(suffix, ("", ()))
        return "", ()

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
        original_check = _classify(".orig", result, reference, records, ranges,
                                   int(patch_loc, 0))
        checks.append(original_check)
    else:
        return BaselineResult(
            None, selected_suffix,
            (BaselineCheck(".orig", BaselineStatus.UNUSABLE, None,
                           "the original binary is missing"),))

    for suffix in (".brpatched", ".brcached"):
        path = original[: -len(".orig")] + suffix
        if not os.path.exists(path):
            continue
        ranges, records = metadata_for(path)
        result = run_artifact(path, ranges, records, True)
        check = _classify(suffix, result, reference, records, ranges,
                          int(patch_loc, 0))
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
