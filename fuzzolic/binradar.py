#!/usr/bin/python3 -u

import argparse
import enum
import os
import queue
import resource
import shlex
import shutil
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import binradar_artifacts
import binradar_baseline
import binradar_config
import binradar_feedback
import binradar_fuzzer
import binradar_minimizer
import binradar_pipeline
import binradar_results
import binradar_run_records
import binradar_runtime
import binradar_utils
import binradar_verifier
import logger
import sbsv

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TRACER_BIN = SCRIPT_DIR + "/../tracer/build/x86_64-linux-user/qemu-x86_64"
FIND_MODELS_BIN = SCRIPT_DIR + "/find_models_addrs.py"
TRACER_FAULT_REFERENCE_SCHEMA = (
    "[snapshot] [fault-reference] [version: int] [valid: bool] "
    "[source: str] [address: hex]")

MINIMIZER_VERIFIER_TIMEOUT_FACTOR = 1.5
MAX_VIRTUAL_MEMORY = 256 * 1024 * 1024 * 1024 * 1024  # 256 TB (for ASAN shadow mapping)


def parse_bool(value):
    """Parse a boolean CLI value while retaining bare-flag compatibility."""
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in ("1", "true", "t", "yes", "y", "on"):
        return True
    if normalized in ("0", "false", "f", "no", "n", "off"):
        return False
    raise argparse.ArgumentTypeError(
        f"expected a boolean value, got {value!r}")


def positive_int(value):
    """Parse a strictly positive integer CLI value."""
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(
            f"expected a positive integer, got {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(
            f"expected a positive integer, got {value!r}")
    return parsed


class BinRadarPhase(enum.IntEnum):
    ALL = 0
    PROBE = 1
    FUZZOLIC = 2
    DIRECTED = 3
    FUZZER = 4
    MINIMIZER = 5
    VERIFIER = 6
    BINRADAR = 7
    FINAL = 8
    FEEDBACK = 9
    # Combined single phase: minimizer + concrete verifier running
    # concurrently over already-produced testcases (same as their part of
    # --seq). CLI name: "minimizer-verifier".
    MINIMIZER_VERIFIER = 10


def phase_from_name(name: str) -> BinRadarPhase:
    """Map a --run-single-phase name to its phase value.

    Dashes map to the underscore in the enum member name, so the CLI can
    use "minimizer-verifier" while the enum member is MINIMIZER_VERIFIER.
    """
    return BinRadarPhase[name.upper().replace("-", "_")]


# Valid --run-single-phase names; each must map through phase_from_name.
SINGLE_PHASE_NAMES = ["probe", "fuzzolic", "directed", "fuzzer",
                      "minimizer", "verifier", "minimizer-verifier",
                      "binradar", "feedback", "final"]


def setlimits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY, MAX_VIRTUAL_MEMORY))


class BinRadarExecutor:
    # Config from binradar.env and command line arguments
    workdir: str
    outdir: str
    timeout: int
    binary: str
    poc_input: str
    test_cmd: str
    patch_loc: str
    run_config: binradar_config.RunConfig
    artifacts: binradar_artifacts.ArtifactSet
    total_patches: int
    # Candidate ids compiled into the .brpatched predicate table. With
    # --target-patches all and a cached artifact covering the full setup-filter
    # survivor list, total_patches exceeds this cap.
    brpatched_total_patches: int
    fuzzy: bool
    reverse_directed: bool
    disable_binradar: bool
    less_strict: bool
    binradar_failed: bool
    # The concrete minimizer/verifier pair reached its configured wall-clock
    # budget. This is a planned, graceful cutoff, not a phase failure, so it is
    # tracked separately from ``phase_failures`` throughout.
    wall_time_reached: bool
    feedback_mode: bool
    # Symbolic boundary advisor mode for the BinRadar tracer phase only:
    # "off" | "shadow" | "boundary".  Always explicit so an inherited CLI
    # environment cannot enable it in another phase.
    symbolic_mutation_mode: str
    requested_candidate_scope: str
    candidate_scope_status: str
    candidate_scope_reason: str
    filter_total_patches: int
    invocation: str
    # Control
    phase_failures: Dict[str, str]
    phase_failure_lock: threading.Lock
    # Data
    config: Dict[str, str]
    progress_filename: str
    previous_progress: Optional[binradar_run_records.BinRadarProgress]
    run_records: binradar_run_records.RunRecordStore
    run_prefix: str
    run_id: int
    run_dir: str
    probe_result: Optional[binradar_verifier.BinRadarProbeResult]
    filter_result: List[int]
    start_time: float
    def __init__(self, config: binradar_config.RunConfig):
        self.run_config = config
        self.workdir = config.workdir
        self.outdir = config.outdir
        self.timeout = config.timeout
        self.forkserver_child_timeout = config.forkserver_child_timeout
        self.binary = config.binary
        self.poc_input = config.poc_input
        self.total_patches = config.total_patches
        self.brpatched_total_patches = config.brpatched_total_patches
        self.fuzzy = config.fuzzy
        self.reverse_directed = config.reverse_directed
        self.disable_binradar = config.disable_binradar
        self.less_strict = config.less_strict
        self.feedback_mode = config.feedback_mode
        self.symbolic_mutation_mode = config.symbolic_mutation_mode
        self.requested_candidate_scope = config.requested_candidate_scope
        self.candidate_scope_status = config.candidate_scope_status
        self.candidate_scope_reason = config.candidate_scope_reason
        self.filter_total_patches = config.filter_total_patches
        self.invocation = config.invocation
        self.binradar_failed = False
        self.wall_time_reached = False
        self._fuzzer_output_prepared = False
        self.phase_failures = {}
        self.phase_failure_lock = threading.Lock()
        self.test_cmd = config.test_cmd
        self.patch_loc = config.patch_loc
        self.filter_result = list(range(1, config.total_patches + 1))

        os.makedirs(self.outdir, exist_ok=True)
        self.progress_filename = os.path.join(self.outdir, "progress.sbsv")
        self.previous_progress = None
        self.start_time = time.time()
        self.run_records = binradar_run_records.RunRecordStore(
            self.outdir, self.progress_filename, self.start_time)

        retained = dict(config.retained_environment)
        self.artifacts = binradar_artifacts.ArtifactSet(
            workdir=self.workdir,
            binary=self.binary,
            patch_kind=retained.get("BINRADAR_PATCH_KIND", ""),
            stack_size=int(retained.get("BRCACHE_STACK_SIZE", "0"), 0),
            compiled_total=self.brpatched_total_patches,
        )
        plt_info = self.set_plt_info(os.path.join(self.outdir, "plt_info.txt"))
        self.config = binradar_config.build_base_environment(config, plt_info)

        self.probe_result = None
        self.run_dir = ""
        self.run_prefix = ""
        self.run_id = -1

    @staticmethod
    def from_workdir(workdir: str, outdir: Optional[str] = None,
                     timeout: int = 3600) -> "BinRadarExecutor":
        env = binradar_utils.load_env(os.path.join(workdir, "binradar.env"))
        env["BINRADAR_OUTDIR"] = (
            outdir if outdir is not None else os.path.join(workdir, "out"))
        env["BINRADAR_TIMEOUT"] = str(timeout)
        return BinRadarExecutor.from_env(workdir, env)

    @staticmethod
    def from_env(workdir: str, env: Dict[str, str]) -> "BinRadarExecutor":
        return BinRadarExecutor(
            binradar_config.RunConfig.from_environment(workdir, env))

    def _worker_environment(self) -> Dict[str, str]:
        return binradar_config.build_worker_environment(
            self.run_config, self.config)

    def _record_tolerated_phase_failure(
            self, phase: str, exc: BaseException) -> None:
        """Record an optional evidence phase that failed under --less-strict.

        Required phases (probe, minimizer, verifier, and final) never
        call this helper. Keeping the failure separate from a successful
        ``[phase] [done]`` marker prevents a run with failed optional phases
        from masquerading as a complete run in progress logs.
        """
        if phase not in binradar_pipeline.OPTIONAL_EVIDENCE_PHASES:
            raise ValueError(
                f"Required phase {phase!r} cannot be tolerated")
        if not hasattr(self, "phase_failure_lock"):
            # Some unit tests construct executors with __new__. Production
            # executors initialize these fields in __init__.
            self.phase_failure_lock = threading.Lock()
            self.phase_failures = {}
        detail = f"{type(exc).__name__}: {exc}"
        with self.phase_failure_lock:
            self.phase_failures[phase] = detail
            if phase == "binradar":
                self.binradar_failed = True
        logger.warning(
            f"[LESS-STRICT] [{phase}] failed ({detail}); continuing with "
            f"the evidence produced by the remaining phases.")
        self.save_progress(
            f"[{phase}] [failed] [prefix {self.run_prefix}] "
            f"[id {self.run_id}] [less-strict true]")

    def _run_optional_phase(self, phase: str, target) -> bool:
        """Run an evidence-producing phase, optionally tolerating failure."""
        if phase not in binradar_pipeline.OPTIONAL_EVIDENCE_PHASES:
            raise ValueError(f"Phase {phase!r} is not optional")
        try:
            target()
            return True
        except Exception as exc:
            if not self.less_strict:
                raise
            self._record_tolerated_phase_failure(phase, exc)
            return False

    def failed_phase_names(self) -> List[str]:
        lock = self.phase_failure_lock
        if lock is None:
            return []
        with lock:
            return sorted(self.phase_failures)

    def _record_wall_time_reached(self, phases: List[str]) -> None:
        """Record the planned concrete-evidence wall-clock cutoff.
        Reaching the configured budget is a graceful, expected stop.
        """
        self.wall_time_reached = True
        logger.warning(
            "[MINIMIZER/VERIFIER] Wall-clock budget reached; finalizing "
            "verdicts and confidence from the evidence collected so far. "
            "This is a planned graceful cutoff, not a phase failure.")
        for phase in phases:
            self.save_progress(
                f"[{phase}] [wall-time-reached] [prefix {self.run_prefix}] "
                f"[id {self.run_id}]")

    def phase_deadline(
            self, factor: float = 1.0) -> binradar_runtime.Deadline:
        """Create the single absolute monotonic deadline for a phase."""
        return binradar_runtime.Deadline.from_timeout(self.timeout, factor)

    @staticmethod
    def remaining_concrete_timeout(
            deadline: binradar_runtime.Deadline) -> Optional[float]:
        return deadline.worker_timeout()

    def minimizer_verifier_timeout(self) -> Optional[float]:
        """Wall-clock budget for each minimizer/verifier phase.

        These concrete phases may need to drain testcases produced during the
        configured producer budget, so they receive 50% additional time.
        As elsewhere in the pipeline, a non-positive configured timeout means
        no phase deadline.
        """
        if self.timeout <= 0:
            return None
        return self.timeout * MINIMIZER_VERIFIER_TIMEOUT_FACTOR

    def _run_record_store(self) -> binradar_run_records.RunRecordStore:
        store = getattr(self, "run_records", None)
        if (store is None
                or store.outdir != self.outdir
                or store.progress_filename != self.progress_filename
                or store.start_time != self.start_time):
            store = binradar_run_records.RunRecordStore(
                self.outdir, self.progress_filename, self.start_time)
            self.run_records = store
        return store

    def save_progress(self, data: str):
        self._run_record_store().save_progress(data)

    def set_plt_info(self, plt_info: str) -> str:
        if os.path.exists(plt_info):
            logger.info(f"PLT info file already exists: {plt_info}")
            return plt_info
        plt_result = binradar_utils.execute(
            [FIND_MODELS_BIN, "-o", plt_info, self.artifacts.original])
        if not plt_result.success:
            logger.warning("Failed to find PLT info. PLT-based optimizations will be disabled.")
            sys.exit(plt_result.exit_code)
        return plt_info

    def resolved_poc_input(self) -> str:
        if os.path.isabs(self.poc_input):
            return self.poc_input
        return os.path.join(self.workdir, self.poc_input)

    def set_run_dir(self, run_prefix: str = "run", use_last_run_id: bool = False, resume_phase: BinRadarPhase = BinRadarPhase.ALL):
        del resume_phase
        previous, run_id, run_dir = self._run_record_store().select_run_directory(run_prefix, use_last_run_id)
        self.previous_progress = previous
        self.run_id = run_id
        self.run_dir = run_dir
        self.run_prefix = run_prefix

    def write_run_settings(self, execution_mode: str) -> None:
        binradar_run_records.RunRecordStore.write_settings(
            self.run_dir,
            binradar_run_records.RunSettings(
                invocation=self.invocation,
                execution_mode=execution_mode,
                workdir=self.workdir,
                outdir=self.outdir,
                run_prefix=self.run_prefix,
                run_id=self.run_id,
                timeout=self.timeout,
                target_patches=self.requested_candidate_scope,
                target_patches_status=self.candidate_scope_status,
                target_patches_reason=self.candidate_scope_reason,
                compiled_patches=self.brpatched_total_patches,
                filtered_patches=self.filter_total_patches,
                effective_patches=self.total_patches,
                disable_binradar=self.disable_binradar,
                feedback=self.feedback_mode,
                symbolic_mutation_mode=self.symbolic_mutation_mode,
                fuzzy=self.fuzzy,
                reverse_directed=self.reverse_directed,
                less_strict=self.less_strict,
                forkserver_child_timeout=self.forkserver_child_timeout,
            ),
        )

    def set_config(self, key: str, value: str):
        self.config[key] = value
        logger.debug(f"Config updated: {key}={value}")
    
    def _phase_environment(
            self, mode: str, run_dir: str,
            artifact: Optional[binradar_artifacts.ArtifactSelection] = None
    ) -> Dict[str, str]:
        if self.probe_result is None:
            raise RuntimeError(
                "Probe result is not available. Cannot set environment for "
                "tracer and solver.")

        exclude_ranges = ""
        relocated_calls = ""
        if mode == "binradar":
            if artifact is None:
                raise RuntimeError(
                    "BinRadar phase environment requires an artifact selection")
            exclude_ranges, relocated_calls = binradar_utils.get_e9_metadata(
                self.config, artifact.metadata_prefix)

        log_file = binradar_config.phase_log_file(mode, run_dir)
        if os.path.exists(log_file):
            with open(log_file, "w", encoding="utf-8"):
                pass
        return binradar_config.build_phase_environment(
            mode,
            run_dir,
            self.config,
            binradar_config.PhaseEnvironmentConfig(
                timeout=self.timeout,
                forkserver_child_timeout=self.forkserver_child_timeout,
                reverse_directed=self.reverse_directed,
                probe_patch_hit_count=self.probe_result.patch_func_hit_cnt,
                active_patch_count=len(self.filter_result),
                e9_exclude_ranges=exclude_ranges,
                e9_relocated_calls=relocated_calls,
            ),
            forkserver_read_timeout=binradar_runtime.TracerExecutor.forkserver_timeout,
            forkserver_analyze_margin=binradar_runtime.TracerExecutor.forkserver_analyze_margin,
        )

    def _artifact_e9_metadata(self) -> Dict[str, Tuple[str, List[str]]]:
        """Every artifact's own E9 metadata, keyed by binary suffix.

        Each artifact is validated with the metadata of the artifact being
        executed, never another artifact's: `.brpatched` and `.brcached`
        have distinct RESERVE/TRAMPOLINE maps and therefore distinct
        exclusion ranges.
        """
        metadata: Dict[str, Tuple[str, List[str]]] = {".orig": ("", [])}
        for suffix, prefix in ((".brpatched", "brpatched"),
                               (".brcached", "brcached")):
            ranges, calls = binradar_utils.get_e9_metadata(self.config, prefix)
            metadata[suffix] = (
                ranges,
                [record for record in calls.split(",") if record.strip()])
        return metadata

    def _validate_baseline(
            self, tracer_binary: str, testcase: str,
            phase_environment: Dict[str, str],
            deadline: binradar_runtime.Deadline) -> None:
        """Validate the POC on the original and on the selected artifact's
        unmutated patch 0 under this phase's crash-detection policy.

        The phase environment supplies the policy (memcheck, E9 metadata)
        but every descriptor and structured destination is stripped by the
        validator: this is a pre-flight, not part of the forkserver, and it
        completes and is reaped before the phase session exists.
        """
        # Bound the pre-flight by the same child-timeout rule the phase
        # environment uses, so a hanging baseline can never consume more
        # than one child's budget.
        timeout = deadline.remaining(float(self.forkserver_child_timeout))
        if timeout <= 0:
            logger.warning(
                "[binradar] [baseline] [skipped] [reason non-positive "
                "child timeout]")
            self._record_baseline_result(None)
            return
        try:
            result = binradar_baseline.validate_patch_zero_baseline(
                self.workdir,
                dict(phase_environment),
                original=self.artifacts.original,
                probe_reference=self.probe_result.tracer_fault_reference,
                selected_binary=tracer_binary,
                patch_loc=self.patch_loc,
                test_cmd=self.test_cmd,
                testcase=testcase,
                timeout=timeout,
                phase_deadline=deadline.expires_at,
                metadata=self._artifact_e9_metadata(),
            )
        except Exception as exc:
            logger.warning(
                f"[binradar] [baseline] [unusable] [detail {type(exc).__name__}: "
                f"{exc}]")
            self._record_baseline_result(None)
            return
        binradar_baseline.log_result(result)
        self._record_baseline_result(result)

    def _record_baseline_result(
            self, result: Optional[binradar_baseline.BaselineResult]) -> None:
        """Persist the baseline outcome as an ignorable diagnostic row.

        The row uses no registered action, so progress/collector consumers
        skip it, and it is deliberately not a `[binradar] [crash]` row: the
        canonical evidence must not carry a fabricated iteration.
        """
        if result is None or result.selected is None:
            self.save_progress(
                f"[binradar] [baseline] [unusable] "
                f"[prefix {self.run_prefix}] [id {self.run_id}]")
            return
        reference = result.reference
        reference_text = (
            f"{reference.address:x} {reference.source}"
            if reference is not None else "unavailable 0")
        entry = result.selected
        self.save_progress(
            f"[binradar] [baseline] [{entry.status.value}] "
            f"[artifact {entry.artifact}] [reference {reference_text}] "
            f"[prefix {self.run_prefix}] [id {self.run_id}]")

    def run_probe(self):
        if not os.path.exists(self.artifacts.original):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(self.resolved_poc_input()):
            sys.exit("ERROR: input does not exist.")
        probe_file = os.path.join(self.run_dir, "probe-results.sbsv")
        if os.path.exists(probe_file):
            self.probe_result = binradar_verifier.BinRadarProbeResult.from_sbsv(
                probe_file)
            if self.probe_result is None:
                sys.exit(
                    "ERROR: existing probe result is unreadable; start a fresh "
                    "run with --run-id n instead of overwriting it.")
            if getattr(self.probe_result, "_probe_serialization_version", 1) != 2:
                sys.exit(
                    "ERROR: existing probe result uses the legacy fault "
                    "reference format; start a fresh run with --run-id n "
                    "to regenerate PROBE without rewriting historical data.")
            self.set_config("BINRADAR_ENTRYPOINT",
                            hex(self.probe_result.patch_func_entry))
            logger.info(
                f"[PROBE] Loaded existing probe result: "
                f"{self.probe_result.serialize()}")
            return
        config = self._worker_environment()
        self.save_progress(f"[probe] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        probe_runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        probe_result = probe_runner.test_with_original(self.resolved_poc_input())
        if probe_result is None:
            logger.info("[PROBE] Failed to get probe result. Check if patch location is set or qemu_stacktrace is available.")
            sys.exit(1)
        assert probe_result is not None
        if not probe_result.patch_hit():
            logger.info(f"[PROBE] No patch hit found. The patch location might be incorrect - timeout {probe_result.is_timeout()} - crash {probe_result.is_crash()} - normal exit {probe_result.is_normal_exit()}.")
            sys.exit(1)
        if not probe_result.is_crash():
            logger.info("[PROBE] No crash found. The patch might not be effective.")
            sys.exit(1)
        if not probe_result.patch_func_hit():
            logger.info("[PROBE] No hit found in the patch function. Failed to extract patch function info.")
            sys.exit(1)
        if probe_result.multi_patch_func():
            logger.info("[PROBE] Multiple patch function hits found. Current implementation does not support this case.")
            sys.exit(1)
        self.probe_result = probe_result
        # Run the tracer on .orig to obtain a normalized fault reference.
        # It is used for BINRADAR analysis in FINAL; QASAN's concrete address
        # remains a separate observation.
        tracer_cmd = [TRACER_BIN, self.artifacts.original] + shlex.split(
            self.test_cmd.replace("@@", self.resolved_poc_input()))
        tracer_env = os.environ.copy()
        tracer_env["BINRADAR_FORKSERVER_ENABLE"] = "0"
        tracer_env["BINRADAR_OSPREY_ENABLE"] = "0"
        # The probe runs the unpatched original binary; a mutated scalar would
        # corrupt the fault-address observation this path exists to produce.
        tracer_env["BINRADAR_SYMBOLIC_MUTATION_MODE"] = "off"
        tracer_env["BINRADAR_TRACE_FILE"] = "none"
        # The original binary has no E9 mappings and no relocated calls.
        tracer_env["E9_EXCLUDE_RANGES"] = ""
        tracer_env["E9_RELOCATED_CALL_JUMPS"] = ""
        tracer_env["BINRADAR_MEMCHECK_ENABLE"] = "1"
        tracer_env["PLT_INFO_FILE"] = self.config.get("PLT_INFO_FILE", "")
        tracer_result = binradar_utils.execute(
            tracer_cmd, cwd=self.workdir, env=tracer_env, timeout=60.0, verbose=False)
        parser = sbsv.parser()
        parser.add_schema(TRACER_FAULT_REFERENCE_SCHEMA)
        tracer_fault_reference = None
        if tracer_result.success:
            result = parser.loads(tracer_result.stderr)
            rows = result["snapshot"]["fault-reference"]
            if rows:
                row = rows[-1]
                if row["version"] == 2 and row["valid"] \
                        and row["source"] in binradar_verifier.TRACER_FAULT_VALID_SOURCES:
                    tracer_fault_reference = (
                        binradar_verifier.TracerFaultReference(
                            row["address"], row["source"]))

        if tracer_fault_reference is None:
            logger.warning(
                "[PROBE] Tracer did not publish a valid normalized fault "
                "reference; final BINRADAR crash classification is unavailable.")
        probe_result.tracer_fault_reference = tracer_fault_reference
        if tracer_fault_reference is not None:
            logger.info(
                f"[PROBE] Tracer fault reference: "
                f"{tracer_fault_reference.address:#x} "
                f"({tracer_fault_reference.source}) "
                f"(afl-qemu-trace fault address: {probe_result.fault_addr:#x})")
        else:
            logger.info(
                f"[PROBE] Tracer fault reference unavailable "
                f"(afl-qemu-trace fault address: {probe_result.fault_addr:#x})")
        file_trace_runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        file_trace_result = file_trace_runner.test_with_file_trace(self.resolved_poc_input(), patch_func_entry=probe_result.patch_func_entry, verbose=True)
        if file_trace_result is None:
            logger.info("[PROBE] Failed to get file trace result. Check if patch location is set or qemu_stacktrace is available.")
            sys.exit(1)
        # Set config
        self.set_config("BINRADAR_ENTRYPOINT", hex(probe_result.patch_func_entry))
        self.save_progress(f"[probe] [done] [prefix {self.run_prefix}] [id {self.run_id}] {probe_result.serialize()} {file_trace_result.serialize_file_trace_result()}")
        with open(os.path.join(self.run_dir, "probe-results.sbsv"), "w", encoding="utf-8") as f:
            f.write(f"[probe-info] {probe_result.serialize()}\n")
            f.write(f"[file-trace] {file_trace_result.serialize_file_trace_result()}\n")

    def check_requirements(self):
        if not os.path.exists(self.artifacts.original):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(self.artifacts.patched):
            sys.exit("ERROR: patched binary does not exist.")
        if not os.path.exists(self.resolved_poc_input()):
            sys.exit("ERROR: input does not exist.")
        if self.probe_result is None:
            sys.exit("ERROR: probe result not found. Please run the probe phase first.")
        # TODO: Implement stdin
        if "@@" not in self.test_cmd:
            sys.exit("ERROR: current implementation requires a file-based testcase (@@).")
        if self.probe_result is None:
            sys.exit("ERROR: probe result not found. Please run the probe phase first.")
    
    def _run_concolic_phase(self, exec_mode: str) -> None:
        """Run fuzzolic/directed under one total, graceful phase deadline."""
        testcase = self.resolved_poc_input()
        self.check_requirements()
        phase_name = exec_mode.capitalize()

        logger.info(
            f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} "
            f"with testcase: {testcase}")
        self.save_progress(
            f"[{exec_mode}] [start] [prefix {self.run_prefix}] "
            f"[id {self.run_id}]")
        timed_out = False
        phase_env = self._phase_environment(exec_mode, self.run_dir)
        session = binradar_runtime.PhaseSession(exec_mode, self.timeout)

        try:
            with session:
                session.shared_memory(phase_env)
                solver = session.start_solver(
                    mode=exec_mode, testcase=testcase, run_dir=self.run_dir,
                    env=phase_env, workdir=self.workdir, fuzzy=self.fuzzy,
                    reverse_directed=(self.reverse_directed
                                      if exec_mode == "directed" else False))
                if session.deadline.expired():
                    timed_out = True
                else:
                    tracer = session.start_tracer(
                        mode=exec_mode, env=phase_env, workdir=self.workdir,
                        rundir=self.run_dir, binary=self.artifacts.original,
                        test_cmd=self.test_cmd, testcase=testcase)
                    tracer_time, tracer_success, _ = tracer.run()
                    self.save_progress(
                        f"[{exec_mode}] [tracer] [prefix {self.run_prefix}] "
                        f"[id {self.run_id}] [tracer-time {tracer_time}] "
                        f"[tracer-success {tracer_success}]")
                    if not tracer_success:
                        if (tracer.run_result is not None
                                and tracer.run_result.timed_out):
                            timed_out = True
                        else:
                            raise RuntimeError(f"{phase_name} tracer failed")
                if not timed_out:
                    if session.deadline.expired():
                        timed_out = True
                    else:
                        solver.create_inputs()
                        solver_time, solver_success = solver.wait()
                        self.save_progress(
                            f"[{exec_mode}] [solver] "
                            f"[prefix {self.run_prefix}] [id {self.run_id}] "
                            f"[solver-time {solver_time}] "
                            f"[solver-success {solver_success}]")
                        if not solver_success:
                            if solver.timed_out or session.deadline.expired():
                                timed_out = True
                            else:
                                raise RuntimeError(
                                    f"{phase_name} solver exited with status "
                                    f"{solver.process.returncode if solver.process else 'unknown'}")
        except TimeoutError as exc:
            if session.deadline.expired():
                timed_out = True
            else:
                logger.error(
                    f"Error during {exec_mode} execution: {str(exc)}")
                raise
        except Exception as exc:
            logger.error(f"Error during {exec_mode} execution: {str(exc)}")
            raise

        if timed_out:
            logger.info(
                f"[{phase_name.upper()}] Reached its configured phase "
                "wall-clock budget; keeping testcases published before the "
                "cutoff. This is a planned graceful cutoff, not a failure.")
            self.save_progress(
                f"[{exec_mode}] [{binradar_utils.WALL_TIME_REACHED}] "
                f"[prefix {self.run_prefix}] [id {self.run_id}]")
        self.save_progress(
            f"[{exec_mode}] [done] [prefix {self.run_prefix}] "
            f"[id {self.run_id}]")

    def run_fuzzolic(self):
        self._run_concolic_phase("fuzzolic")

    def run_directed(self):
        self._run_concolic_phase("directed")
    
    def fuzzer_outdir(self) -> str:
        return os.path.join(self.run_dir, "fuzzer-out")

    def prepare_fuzzer_output(self) -> None:
        """Reset fuzzer output before producer/minimizer concurrency starts."""
        fuzzer_outdir = self.fuzzer_outdir()
        if os.path.exists(fuzzer_outdir):
            logger.info(
                f"Fuzzer output directory already exists: {fuzzer_outdir}. "
                f"It will be overwritten.")
            shutil.rmtree(fuzzer_outdir)
        os.makedirs(fuzzer_outdir, exist_ok=True)
        self._fuzzer_output_prepared = True

    def run_fuzzer(self):
        self.check_requirements()
        exec_mode = "fuzzer"
        self.save_progress(f"[fuzzer] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        session = binradar_runtime.PhaseSession(exec_mode, self.timeout)
        config = self._worker_environment()
        fuzzer_outdir = self.fuzzer_outdir()
        if not getattr(self, "_fuzzer_output_prepared", False):
            self.prepare_fuzzer_output()
        self._fuzzer_output_prepared = False
        fuzzer = binradar_fuzzer.AFLppFuzzer.from_env(
            self.workdir, fuzzer_outdir, config)
        with session:
            fuzzer.start()
            if fuzzer.process is None:
                raise RuntimeError("Failed to start fuzzer process")
            session.track_process(fuzzer.process)
            result = fuzzer.wait(timeout=session.deadline.remaining())
        if result is None:
            raise RuntimeError("Fuzzer process was not started")
        if result.timed_out:
            # AFL++ intentionally runs until the phase deadline. execute_await
            # terminates the process group and waits for it to exit.
            logger.info(
                "Fuzzer reached its configured phase wall-clock budget; this "
                "is a planned graceful cutoff, not a failure.")
            self.save_progress(
                f"[fuzzer] [{binradar_utils.WALL_TIME_REACHED}] "
                f"[prefix {self.run_prefix}] [id {self.run_id}]")
        elif not result.success or result.exit_code != 0:
            raise RuntimeError(
                f"Fuzzer exited unexpectedly with status {result.exit_code}")
        self.save_progress(f"[fuzzer] [done] [prefix {self.run_prefix}] [id {self.run_id}]")
    
    def _concrete_worker_factory(
            self, require_verifier: bool) -> binradar_pipeline.ConcreteWorkerFactory:
        verifier_binary = None
        if require_verifier:
            verifier_binary = self.artifacts.select_verifier(
                self.filter_result).path
        return binradar_pipeline.ConcreteWorkerFactory.create(
            workdir=self.workdir,
            run_dir=self.run_dir,
            probe_result=self.probe_result,
            config=self._worker_environment(),
            fuzzer_outdir=self.fuzzer_outdir(),
            patches=self.filter_result,
            verifier_binary=verifier_binary,
            patched_binary_patches=range(
                1, self.brpatched_total_patches + 1))

    def run_minimizer(self):
        self.check_requirements()
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run minimizer.")
            raise RuntimeError("Probe result not found.")
        self.save_progress(f"[minimizer] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        deadline = self.phase_deadline(MINIMIZER_VERIFIER_TIMEOUT_FACTOR)
        minimizer = self._concrete_worker_factory(
            require_verifier=False).build_minimizer()
        minimizer.load_testcases()
        timed_out = minimizer.run_testcases(
            timeout=self.remaining_concrete_timeout(deadline))
        if timed_out:
            self._record_wall_time_reached(["minimizer"])
        self.save_progress(f"[minimizer] [done] [prefix {self.run_prefix}] [id {self.run_id}]")

    def run_verifier(self):
        self.check_requirements()
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run verifier.")
            raise RuntimeError("Probe result not found.")
        minimizer_result_file = os.path.join(self.run_dir, "minimizer.sbsv")
        if not os.path.exists(minimizer_result_file):
            logger.info("[VERIFIER] Minimizer results not found. Please run the minimizer phase first.")
            sys.exit(1)

        self.save_progress(f"[verifier] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        deadline = self.phase_deadline(MINIMIZER_VERIFIER_TIMEOUT_FACTOR)
        factory = self._concrete_worker_factory(require_verifier=True)
        timed_out = factory.build_verifier().run_verification_streaming(
            factory.minimizer_result_file,
            timeout=self.remaining_concrete_timeout(deadline))
        if timed_out:
            self._record_wall_time_reached(["verifier"])
        self.save_progress(f"[verifier] [done] [prefix {self.run_prefix}] [id {self.run_id}]")

    def run_minimizer_and_verifier(self,
                                   producer_threads: Optional[List[threading.Thread]] = None,
                                   producer_exc_queue: Optional["queue.Queue[BaseException]"] = None) -> bool:
        # Run the minimizer and the concrete verifier together.
        self.check_requirements()
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run minimizer and verifier.")
            raise RuntimeError("Probe result not found.")
        self.save_progress(f"[minimizer] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        self.save_progress(f"[verifier] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        deadline = self.phase_deadline(MINIMIZER_VERIFIER_TIMEOUT_FACTOR)
        factory = self._concrete_worker_factory(require_verifier=True)
        timed_out = binradar_minimizer.run_minimizer_and_verifier(
            factory.build_minimizer(), factory.build_verifier(),
            factory.minimizer_result_file,
            producer_threads=producer_threads,
            producer_exc_queue=producer_exc_queue,
            timeout=self.remaining_concrete_timeout(deadline))
        if timed_out:
            self._record_wall_time_reached(
                ["minimizer", "verifier"])
        self.save_progress(f"[minimizer] [done] [prefix {self.run_prefix}] [id {self.run_id}]")
        self.save_progress(f"[verifier] [done] [prefix {self.run_prefix}] [id {self.run_id}]")
        return timed_out

    def run_binradar(self):
        if self.disable_binradar:
            logger.info("[BINRADAR] BinRadar phase disabled; skipping execution.")
            return
        testcase = self.resolved_poc_input()
        self.check_requirements()
        if self.probe_result is None:
            raise RuntimeError("Probe result is not available for BinRadar")
        
        exec_mode = "binradar"
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[binradar] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        
        artifact = self.artifacts.select_tracer(self.filter_result)
        if artifact.cache_requested and not artifact.cache_enabled:
            logger.warning(
                f"[BINRADAR] Cached tracer disabled: {artifact.reason}")
        tracer_binary = artifact.path
        binradar_env = self._phase_environment(
            exec_mode, self.run_dir, artifact)
        feedback_staging = os.path.join(self.run_dir, "binradar-feedback")
        if self.feedback_mode and os.path.exists(feedback_staging):
            shutil.rmtree(feedback_staging)
        if artifact.cache_enabled:
            binradar_env["BINRADAR_PATCH_CACHE_ENABLE"] = "1"
            binradar_env["BINRADAR_PATCH_MANIFEST"] = str(
                Path(self.artifacts.manifest).resolve())
            if self.feedback_mode:
                os.makedirs(feedback_staging)
                binradar_env["BINRADAR_FEEDBACK_DIR"] = feedback_staging
                reference = self.probe_result.tracer_fault_reference
                reference_valid = (reference is not None and reference.valid)
                binradar_env["BINRADAR_POC_FAULT_VALID"] = (
                    "1" if reference_valid else "0")
                binradar_env["BINRADAR_POC_FAULT_SOURCE"] = (
                    reference.source if reference_valid else "unavailable")
                if reference_valid:
                    binradar_env["BINRADAR_POC_FAULT_ADDR"] = hex(
                        reference.address)
                else:
                    binradar_env.pop("BINRADAR_POC_FAULT_ADDR", None)
        else:
            if self.feedback_mode:
                logger.warning(
                    "[BINRADAR] Mutation feedback requires .brcached; "
                    "the selected artifact has no snapshot channel")
            binradar_env.pop("BINRADAR_PATCH_CACHE_ENABLE", None)
            binradar_env.pop("BINRADAR_PATCH_MANIFEST", None)
        session = binradar_runtime.PhaseSession(exec_mode, self.timeout)
        timed_out = False
        try:
            with session:
                self._validate_baseline(
                    tracer_binary, testcase, binradar_env, session.deadline)
                if session.deadline.expired():
                    timed_out = True
                else:
                    session.shared_memory(binradar_env, include_patch_key=True)
                    session.start_solver(
                        mode=exec_mode, testcase=testcase, run_dir=self.run_dir,
                        env=binradar_env, workdir=self.workdir, fuzzy=self.fuzzy)
                    tracer = session.start_tracer(
                        mode=exec_mode, env=binradar_env,
                        workdir=self.workdir, rundir=self.run_dir,
                        binary=tracer_binary, test_cmd=self.test_cmd,
                        testcase=testcase)
                    remaining = 1
                    while remaining > 0:
                        if session.deadline.expired():
                            timed_out = True
                            break
                        tracer_time, tracer_success, remaining = tracer.run()
                        message = (
                            f"[binradar] [tracer] [iter {tracer.iter}] "
                            f"[representative-runs "
                            f"{tracer.representative_runs}] "
                            f"[time {tracer_time}] [remaining {remaining}]")
                        if tracer_success:
                            logger.debug(message)
                        else:
                            logger.warning(message + " [failed true]")
        except TimeoutError as exc:
            if session.deadline.expired():
                timed_out = True
            else:
                logger.error(f"Error during binradar execution: {exc}")
                raise
        except Exception as exc:
            logger.error(f"Error during binradar execution: {exc}")
            raise

        if timed_out:
            logger.info(
                f"[BINRADAR] [id {self.run_id}] Phase deadline reached; "
                "stopping binradar execution.")
            self.save_progress(
                f"[binradar] [{binradar_utils.WALL_TIME_REACHED}] "
                f"[prefix {self.run_prefix}] [id {self.run_id}]")
        self.save_progress(
            f"[binradar] [done] [prefix {self.run_prefix}] "
            f"[id {self.run_id}]")
    
    def run_feedback(self):
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run feedback analysis.")
            raise RuntimeError("Probe result not found.")
        binradar_feedback.export_feedback(
            binradar_feedback.FeedbackExportRequest(
                workdir=self.workdir,
                run_dir=self.run_dir,
                original_binary=self.artifacts.original,
                poc_source=self.resolved_poc_input(),
                poc_fault_addr=self.probe_result.fault_addr,
                run_prefix=self.run_prefix,
                run_id=self.run_id,
                save_progress=self.save_progress,
            )
        )

    def run_final(self):
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run final analysis.")
            raise RuntimeError("Probe result not found.")
        skip_binradar = self.disable_binradar or self.binradar_failed
        binradar_results.write_final_result(
            binradar_results.FinalResultRequest(
                run_dir=self.run_dir,
                run_prefix=self.run_prefix,
                run_id=self.run_id,
                candidates=self.filter_result,
                tracer_fault_reference=(
                    None if skip_binradar
                    else self.probe_result.tracer_fault_reference),
                disable_binradar=self.disable_binradar,
                binradar_failed=self.binradar_failed,
                wall_time_reached=self.wall_time_reached,
                failed_phases=self.failed_phase_names(),
                save_progress=self.save_progress,
                record_wall_time_reached=lambda: (
                    self._record_wall_time_reached([])),
            )
        )

    def done(self):
        self.save_progress(f"[rundir] [done] [prefix {self.run_prefix}] [id {self.run_id}] [dir {self.run_dir}]")
    
    def run_fuzzer_only(self, run_prefix: str = "run"):
        """Run the AFL++ producer and concrete verification pipeline only.

        PROBE remains mandatory; setup already filtered the candidates.
        FUZZOLIC, DIRECTED, and BINRADAR are skipped; FINAL therefore uses
        concrete-verifier evidence only. AFL++, the streaming minimizer, and
        the verifier run concurrently.
        """
        self.disable_binradar = True
        self.set_run_dir(run_prefix=run_prefix)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.write_run_settings("fuzzer-only")
        self.run_probe()
        if not self.filter_result:
            logger.info("[BINRADAR] No patch survived setup filtering. Skipping the remaining phases.")
            self.save_progress(f"[final] [done] [prefix {self.run_prefix}] [id {self.run_id}] [remaining_patches []] [binradar_remaining_patches []]")
            self.done()
            return

        # Reset the AFL++ directory before either its writer or the streaming
        # minimizer can observe it. run_fuzzer consumes this prepared marker
        # instead of deleting the directory after discovery has started.
        self.prepare_fuzzer_output()
        binradar_pipeline.PipelineCoordinator(
            less_strict=self.less_strict,
            record_tolerated_failure=self._record_tolerated_phase_failure,
            stream_concrete=self.run_minimizer_and_verifier,
        ).run([
            binradar_pipeline.Producer("fuzzer", self.run_fuzzer),
        ])
        if self.feedback_mode:
            self._run_optional_phase("feedback", self.run_feedback)
        self.run_final()
        self.done()

    def run_sequential(self, run_prefix: str = "run"):
        self.set_run_dir(run_prefix=run_prefix)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.write_run_settings("sequential")
        self.run_probe()
        if not self.filter_result:
            logger.info("[BINRADAR] No patch survived setup filtering. Skipping the remaining phases.")
            self.save_progress(f"[final] [done] [prefix {self.run_prefix}] [id {self.run_id}] [remaining_patches []] [binradar_remaining_patches []]")
            self.done()
            return
        self._run_optional_phase("fuzzolic", self.run_fuzzolic)
        self._run_optional_phase("directed", self.run_directed)
        self._run_optional_phase("fuzzer", self.run_fuzzer)
        self.run_minimizer_and_verifier()
        if not self.disable_binradar:
            self._run_optional_phase("binradar", self.run_binradar)
        else:
            logger.info("[BINRADAR] BinRadar phase disabled; skipping execution.")
        if self.feedback_mode:
            self._run_optional_phase("feedback", self.run_feedback)
        self.run_final()
        self.done()
    
    def run_single_phase(self, run_prefix: str, run_id: str, phase: BinRadarPhase):
        if run_id in ("n", "new"):
            self.set_run_dir(run_prefix=run_prefix)
        elif run_id in ("l", "last"):
            self.set_run_dir(run_prefix=run_prefix, use_last_run_id=True)
        else:
            self.run_id = int(run_id)
            self.run_prefix = run_prefix
            self.run_dir = os.path.join(self.outdir, f"{run_prefix}-{self.run_id:05d}")
            os.makedirs(self.run_dir, exist_ok=True)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        phase_name = phase.name.lower().replace("_", "-")
        self.write_run_settings(f"single-phase-{phase_name}")
        if phase == BinRadarPhase.FINAL:
            probe_file = os.path.join(self.run_dir, "probe-results.sbsv")
            if not os.path.exists(probe_file):
                sys.exit(
                    "ERROR: historical FINAL requires an existing "
                    "probe-results.sbsv")
            self.probe_result = (
                binradar_verifier.BinRadarProbeResult.from_sbsv(probe_file))
            if self.probe_result is None:
                sys.exit("ERROR: failed to parse historical probe result")
            self.set_config("BINRADAR_ENTRYPOINT",
                            hex(self.probe_result.patch_func_entry))
            reference = self.probe_result.tracer_fault_reference
            legacy_probe = (
                getattr(self.probe_result, "_probe_serialization_version", 1)
                != 2)
            if legacy_probe:
                if reference is None:
                    probe_summary = "legacy probe (fault reference unavailable)"
                else:
                    probe_summary = (
                        f"legacy reference {reference.address:#x} "
                        f"({reference.source})")
            else:
                probe_summary = self.probe_result.serialize()
            logger.info(
                f"[PROBE] Loaded historical probe result: {probe_summary}")
        else:
            self.run_probe()
        if phase == BinRadarPhase.PROBE:
            return
        if phase == BinRadarPhase.FUZZOLIC:
            self._run_optional_phase("fuzzolic", self.run_fuzzolic)
        elif phase == BinRadarPhase.DIRECTED:
            self._run_optional_phase("directed", self.run_directed)
        elif phase == BinRadarPhase.FUZZER:
            self._run_optional_phase("fuzzer", self.run_fuzzer)
        elif phase == BinRadarPhase.MINIMIZER:
            self.run_minimizer()
        elif phase == BinRadarPhase.VERIFIER:
            self.run_verifier()
        elif phase == BinRadarPhase.MINIMIZER_VERIFIER:
            self.run_minimizer_and_verifier()
        elif phase == BinRadarPhase.BINRADAR:
            self._run_optional_phase("binradar", self.run_binradar)
        elif phase == BinRadarPhase.FINAL:
            self.run_final()
        elif phase == BinRadarPhase.FEEDBACK:
            self._run_optional_phase("feedback", self.run_feedback)
        else:
            raise ValueError(f"Unknown phase: {phase}")
        self.done()
    
    def run_multithreaded(self, run_prefix: str = "run"):
        self.set_run_dir(run_prefix=run_prefix)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.write_run_settings("multithreaded")
        self.run_probe()

        if not self.filter_result:
            logger.info("[BINRADAR] No patch survived setup filtering. Skipping the remaining phases.")
            self.save_progress(f"[final] [done] [prefix {self.run_prefix}] [id {self.run_id}] [remaining_patches []] [binradar_remaining_patches []]")
            self.done()
            return

        # Reset output before either the fuzzer or the minimizer can touch it.
        # Queue paths are derived without constructing another fuzzer object.
        self.prepare_fuzzer_output()

        independent = None
        if not self.disable_binradar:
            independent = binradar_pipeline.IndependentWorker(
                "binradar", self.run_binradar)
        else:
            logger.info(
                "[BINRADAR] BinRadar phase disabled; skipping execution.")

        binradar_pipeline.PipelineCoordinator(
            less_strict=self.less_strict,
            record_tolerated_failure=self._record_tolerated_phase_failure,
            stream_concrete=self.run_minimizer_and_verifier,
        ).run([
            binradar_pipeline.Producer("fuzzolic", self.run_fuzzolic),
            binradar_pipeline.Producer("directed", self.run_directed),
            binradar_pipeline.Producer("fuzzer", self.run_fuzzer),
        ], independent=independent)
        if self.feedback_mode:
            self._run_optional_phase("feedback", self.run_feedback)
        self.run_final()
        self.done()

    
def main():
    setlimits()
    signal.signal(signal.SIGINT, binradar_runtime.abort_handler)
    signal.signal(signal.SIGTERM, binradar_runtime.abort_handler)

    parser = argparse.ArgumentParser(
        description="binradar: a binary patch verification tool")
    parser.add_argument(
        "-w", "--workdir", required=True,
        help="set the working directory for binradar")
    parser.add_argument(
        "-t", "--timeout", type=int, default=-1,
        help="set the base timeout in seconds (minimizer/verifier use 1.5x)")
    parser.add_argument(
        "-o", "--output", default="",
        help="set the output directory for fuzzolic (default: workdir/out)")
    parser.add_argument("--fuzzy", action="store_true", help="use the Fuzzy-SAT solver")
    parser.add_argument(
        "--feedback-mode", "--feedback", dest="feedback_mode",
        default=False, nargs="?", const=True, type=parse_bool,
        help="Give feedback to taosc")
    parser.add_argument(
        "--reverse-directed", default=True, nargs="?", const=True,
        type=parse_bool,
        help="prioritize directed candidates from the end of the forward trace (Z3 only); optionally pass true/false")
    parser.add_argument("--disable-binradar", action="store_true",
        help="disable the binradar phase")
    parser.add_argument(
        "--symbolic-mutation-mode", dest="symbolic_mutation_mode",
        choices=binradar_config.SYMBOLIC_MUTATION_MODES,
        default=None,
        help=("symbolic boundary advisor mode for the BinRadar tracer phase "
              "(default: off, or BINRADAR_SYMBOLIC_MUTATION_MODE from "
              "binradar.env); 'shadow' ranks and reports without proposing, "
              "'boundary' proposes comparison-guided values.  Every other "
              "phase always runs with the advisor off"))
    parser.add_argument("--less-strict", action="store_true",
        help=("continue when optional evidence phases (fuzzolic, directed, "
              "fuzzer, binradar, or feedback) fail; final output records the "
              "failed phases as issues"))
    parser.add_argument("--fuzzer-only", action="store_true",
        help=("run probe, AFL++ fuzzer, minimizer/verifier, and final; "
              "skip fuzzolic, directed, and binradar"))
    parser.add_argument("--target-patches", choices=["top-30", "all"], default="top-30")
    parser.add_argument("--forkserver-child-timeout", type=positive_int,
                        default=binradar_config.FORKSERVER_CHILD_TIMEOUT_DEFAULT,
                        help=("per-iteration cap in seconds for one forkserver "
                              "child in the directed/binradar tracer phases "
                              "(default: 900); must stay below the forkserver "
                              "read timeout (1800s) minus the analyze margin "
                              "(300s)"))
    # The following argument is for experiments and debugging
    parser.add_argument("--run-single-phase", default="", 
        choices=SINGLE_PHASE_NAMES, help="run a specific phase")
    parser.add_argument("--run-prefix", default="run", help="set the prefix for run directories (default: run)")
    parser.add_argument("--run-id", default="n", help="n=new run (default), l=last run, or a numeric run id (only valid when --run-single-phase is set)")
    parser.add_argument("--seq", action="store_true", help="run all phases sequentially (for debugging)")
    args = parser.parse_args()
    if args.fuzzer_only and (args.run_single_phase or args.seq):
        parser.error(
            "--fuzzer-only cannot be combined with --run-single-phase or --seq")

    workdir = os.path.abspath(args.workdir)
    if not os.path.exists(workdir):
        sys.exit(f"ERROR: workdir {workdir} does not exist.")

    env = binradar_utils.load_env(os.path.join(workdir, "binradar.env"))
    if args.timeout >= 0:
        env["BINRADAR_TIMEOUT"] = str(args.timeout)
    else:
        env["BINRADAR_TIMEOUT"] = "3600" # 1 hours

    env["BINRADAR_WORKDIR"] = os.path.abspath(workdir)
    env["BINRADAR_FUZZY"] = "1" if args.fuzzy else "0"
    env["BINRADAR_REVERSE_DIRECTED"] = "1" if args.reverse_directed else "0"
    env["BINRADAR_DISABLE_BINRADAR"] = "1" if (args.disable_binradar or args.fuzzer_only) else "0"
    env["BINRADAR_LESS_STRICT"] = "1" if args.less_strict else "0"
    env["BINRADAR_FEEDBACK_MODE"] = "1" if args.feedback_mode else "0"
    # The advisor is independent of feedback: enabling one never enables the
    # other.  Precedence is CLI flag, then binradar.env, then the off default,
    # so a rollout can pin a subject in binradar.env without a flag and a flag
    # still overrides it.
    env["BINRADAR_SYMBOLIC_MUTATION_MODE"] = \
        binradar_config.validate_symbolic_mutation_mode(
            args.symbolic_mutation_mode
            if args.symbolic_mutation_mode is not None
            else env.get(
                "BINRADAR_SYMBOLIC_MUTATION_MODE",
                binradar_config.SYMBOLIC_MUTATION_MODE_DEFAULT))
    env["BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP"] = str(args.forkserver_child_timeout)
    env["BINRADAR_INVOCATION"] = shlex.join(sys.argv)
    candidate_set = binradar_artifacts.resolve_candidate_set(
        workdir, env, args.target_patches)
    env.update(candidate_set.environment())
    if candidate_set.status == "all-clamped":
        logger.warning(
            f"--target-patches all: only the top "
            f"{candidate_set.compiled_total} setup-filter survivors are "
            f"compiled into the binaries "
            f"(FILTER_TOTAL_PATCHES={candidate_set.filtered_total}); "
            f"candidates past the compiled cap cannot be run "
            f"({candidate_set.reason})")
    elif candidate_set.status == "all-expanded":
        logger.info(
            f"--target-patches all: the .brcached artifact and "
            f"brpatches.json cover all {candidate_set.filtered_total} "
            f"setup-filter survivors; running the full set (the .brpatched "
            f"artifact compiles only the top "
            f"{candidate_set.compiled_total})")
    outdir = os.path.abspath(os.path.join(workdir, "out")) 
    if args.output != "":
        outdir = os.path.abspath(args.output)
    env["BINRADAR_OUTDIR"] = outdir
    os.makedirs(outdir, exist_ok=True)
    os.chdir(workdir)

    executor = BinRadarExecutor.from_env(workdir, env)
    if args.run_single_phase:
        executor.run_single_phase(args.run_prefix, args.run_id, phase_from_name(args.run_single_phase))
    elif args.fuzzer_only:
        executor.run_fuzzer_only(args.run_prefix)
    elif args.seq:
        executor.run_sequential(args.run_prefix)
    else:
        executor.run_multithreaded(args.run_prefix)


if __name__ == "__main__":
    main()
