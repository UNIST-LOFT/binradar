#!/usr/bin/python3 -u

import argparse
import enum
import fcntl
import hashlib
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
from types import TracebackType
from typing import Callable, Dict, List, Optional, Set, Tuple

import binradar_artifacts
import binradar_config
import binradar_evidence
import binradar_fuzzer
import binradar_minimizer
import binradar_runtime
import binradar_utils
import binradar_verifier
import logger
import sbsv

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TRACER_BIN = SCRIPT_DIR + "/../tracer/build/x86_64-linux-user/qemu-x86_64"
FIND_MODELS_BIN = SCRIPT_DIR + "/find_models_addrs.py"

MINIMIZER_VERIFIER_TIMEOUT_FACTOR = 1.5
# Security boundary for --less-strict: only independent evidence producers
# may fail open. Phases needed to establish or serialize a verdict are never
# members of this set.
OPTIONAL_EVIDENCE_PHASES = frozenset({
    "fuzzolic", "directed", "fuzzer", "binradar", "feedback",
})

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




class BinRadarProgress:
    run_id: int
    run_dir: str
    probe_done: bool
    fuzzolic_done: bool
    directed_done: bool
    fuzzer_done: bool
    minimizer_done: bool
    verifier_done: bool
    done: bool
    def __init__(self, run_id: int, run_dir: str, probe_done: bool, fuzzolic_done: bool, directed_done: bool, fuzzer_done: bool, minimizer_done: bool, verifier_done: bool, done: bool):
        self.run_id = run_id
        self.run_dir = run_dir
        self.probe_done = probe_done
        self.fuzzolic_done = fuzzolic_done
        self.directed_done = directed_done
        self.fuzzer_done = fuzzer_done
        self.minimizer_done = minimizer_done
        self.verifier_done = verifier_done
        self.done = done
    
    @staticmethod
    def from_progress_file(run_prefix: str, file: str) -> Optional["BinRadarProgress"]:
        if not os.path.exists(file):
            return None
        parser = sbsv.parser()
        parser.add_schema("[rundir] [set] [prefix: str] [id: int] [dir: str]")
        parser.add_schema("[rundir] [done] [prefix: str] [id: int] [dir: str]")
        parser.add_schema("[probe] [done] [prefix: str] [id: int]")
        parser.add_schema("[fuzzolic] [done] [prefix: str] [id: int]")
        parser.add_schema("[directed] [done] [prefix: str] [id: int]")
        parser.add_schema("[fuzzer] [done] [prefix: str] [id: int]")
        parser.add_schema("[minimizer] [done] [prefix: str] [id: int]")
        parser.add_schema("[verifier] [done] [prefix: str] [id: int]")
        parser.add_schema("[final] [done] [prefix: str] [id: int] [remaining_patches: str] [binradar_remaining_patches: str]")
        with open(file, "r", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            parser.load(f)
            fcntl.flock(f, fcntl.LOCK_UN)
        rundir_log = parser.get_result()["rundir"]["set"]
        if len(rundir_log) == 0:
            return None
        run_id = -1
        run_dir = ""
        for item in rundir_log:
            if item["prefix"] != run_prefix:
                continue
            if item["id"] > run_id:
                run_id = int(item["id"])
                run_dir = item["dir"]
        if run_dir == "":
            return None

        probe_done = False
        fuzzolic_done = False
        directed_done = False
        fuzzer_done = False
        minimizer_done = False
        verifier_done = False
        done = False
        for probe in parser.get_result()["probe"]["done"]:
            if int(probe["id"]) == run_id and probe["prefix"] == run_prefix:
                probe_done = True
                break
        for fuzzolic in parser.get_result()["fuzzolic"]["done"]:
            if int(fuzzolic["id"]) == run_id and fuzzolic["prefix"] == run_prefix:
                fuzzolic_done = True
                break
        for directed in parser.get_result()["directed"]["done"]:
            if int(directed["id"]) == run_id and directed["prefix"] == run_prefix:
                directed_done = True
                break
        for fuzzer in parser.get_result()["fuzzer"]["done"]:
            if int(fuzzer["id"]) == run_id and fuzzer["prefix"] == run_prefix:
                fuzzer_done = True
                break
        for done_item in parser.get_result()["rundir"]["done"]:
            if int(done_item["id"]) == run_id and done_item["prefix"] == run_prefix:
                done = True
                break
        for minimizer in parser.get_result()["minimizer"]["done"]:
            if int(minimizer["id"]) == run_id and minimizer["prefix"] == run_prefix:
                minimizer_done = True
                break
        for verifier in parser.get_result()["verifier"]["done"]:
            if int(verifier["id"]) == run_id and verifier["prefix"] == run_prefix:
                verifier_done = True
                break
        return BinRadarProgress(run_id, run_dir, probe_done, fuzzolic_done, directed_done, fuzzer_done, minimizer_done, verifier_done, done)

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
    previous_progress: Optional[BinRadarProgress]
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

    def elapsed_time_ms(self) -> int:
        return int((time.time() - self.start_time) * 1000)

    def _record_tolerated_phase_failure(
            self, phase: str, exc: BaseException) -> None:
        """Record an optional evidence phase that failed under --less-strict.

        Required phases (probe, minimizer, verifier, and final) never
        call this helper. Keeping the failure separate from a successful
        ``[phase] [done]`` marker prevents a run with failed optional phases
        from masquerading as a complete run in progress logs.
        """
        if phase not in OPTIONAL_EVIDENCE_PHASES:
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
        if phase not in OPTIONAL_EVIDENCE_PHASES:
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

        Reaching the configured budget is a graceful, expected stop: no new
        concrete work is started, already-observed hard failures stay
        rejected, and the remaining verdicts are finalized from the evidence
        consumed so far. It is deliberately **not** a phase failure, so it is
        never added to ``phase_failures`` and never reported as an issue by
        ``binradar-collect-results.py``.
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

    def save_progress(self, data: str):
        time = self.elapsed_time_ms()
        logger.info(f"[PROGRESS] {data} [time {time}]")
        with open(self.progress_filename, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(f"{data} [time {time}]\n")
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

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
        run_id = 0
        # Currently, start a new run if the previous run exists.
        # Can resume in more fine-grained way if needed.
        self.previous_progress = BinRadarProgress.from_progress_file(run_prefix, self.progress_filename)
        if self.previous_progress is not None:
            run_id = self.previous_progress.run_id
            if not use_last_run_id:
                run_id += 1
        run_dir = os.path.join(self.outdir, f"{run_prefix}-{run_id:05d}")
        os.makedirs(run_dir, exist_ok=True)
        self.save_progress(f"[rundir] [set] [prefix {run_prefix}] [id {run_id}] [dir {run_dir}]")
        self.run_id = run_id
        self.run_dir = run_dir
        self.run_prefix = run_prefix

    def write_run_settings(self, execution_mode: str) -> None:
        """Append the resolved invocation before any phase starts."""
        def field(name: str, value: object) -> str:
            if isinstance(value, bool):
                rendered = "true" if value else "false"
            else:
                rendered = str(value)
            return f"[{name} {sbsv.escape_str(rendered, quote=True)}]"

        settings = [
            "[binradar-setting]",
            "[version 1]",
            field("invocation", self.invocation),
            field("execution-mode", execution_mode),
            field("workdir", self.workdir),
            field("outdir", self.outdir),
            field("run-prefix", self.run_prefix),
            field("run-id", self.run_id),
            field("timeout", self.timeout),
            field("target-patches", self.requested_candidate_scope),
            field("target-patches-status", self.candidate_scope_status),
            field("target-patches-reason", self.candidate_scope_reason),
            field("compiled-patches", self.brpatched_total_patches),
            field("filtered-patches", self.filter_total_patches),
            field("effective-patches", self.total_patches),
            field("disable-binradar", self.disable_binradar),
            field("feedback", self.feedback_mode),
            field("symbolic-mutation-mode", self.symbolic_mutation_mode),
            field("fuzzy", self.fuzzy),
            field("reverse-directed", self.reverse_directed),
            field("less-strict", self.less_strict),
            field("forkserver-child-timeout", self.forkserver_child_timeout),
        ]
        output = os.path.join(self.run_dir, "binradar-setting.sbsv")
        previous = ""
        if os.path.exists(output):
            with open(output, "r", encoding="utf-8") as settings_file:
                previous = settings_file.read()
            if previous and not previous.endswith("\n"):
                previous += "\n"
        temporary = f"{output}.tmp"
        with open(temporary, "w", encoding="utf-8") as settings_file:
            settings_file.write(previous)
            settings_file.write(" ".join(settings) + "\n")
        os.replace(temporary, output)

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
    
    def run_probe(self):
        if not os.path.exists(self.artifacts.original):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(self.resolved_poc_input()):
            sys.exit("ERROR: input does not exist.")
        if os.path.exists(os.path.join(self.run_dir, "probe-results.sbsv")):
            self.probe_result = binradar_verifier.BinRadarProbeResult.from_sbsv(os.path.join(self.run_dir, "probe-results.sbsv"))
            if self.probe_result is not None:
                self.set_config("BINRADAR_ENTRYPOINT", hex(self.probe_result.patch_func_entry))
                logger.info(f"[PROBE] Loaded existing probe result: {self.probe_result.serialize()}")
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
        # Run the tracer on .orig to obtain the tracer's fault address. 
        # It will be used for analyzing the result of BINRADAR phase in FINAL phase.
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
        parser.add_schema("[snapshot] [crash] [hit-count: int] [reason: str] [guest_pc: hex] [guest_cs_base: hex] [fault_addr: hex] [host_fault_addr: hex]")
        tracer_fault_addr = 0
        if tracer_result.success:
            result = parser.loads(tracer_result.stderr)
            if len(result["snapshot"]["crash"]) > 0:
                tracer_fault_addr = result["snapshot"]["crash"][0]["fault_addr"]

        if tracer_fault_addr == 0:
            logger.warning(f"[PROBE] Tracer did not detect a crash fault address. "
                           f"tracer_fault_addr will be 0; final phase binradar comparison disabled.")
        probe_result.tracer_fault_addr = tracer_fault_addr
        logger.info(f"[PROBE] Tracer fault address: {tracer_fault_addr:#x} (afl-qemu-trace fault address: {probe_result.fault_addr:#x})")
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
    
    def run_minimizer(self):
        self.check_requirements()
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run minimizer.")
            raise RuntimeError("Probe result not found.")
        exec_mode = "minimizer"
        self.save_progress(f"[minimizer] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        deadline = self.phase_deadline(MINIMIZER_VERIFIER_TIMEOUT_FACTOR)
        config = self._worker_environment()
        testcase_dirs = [os.path.join(self.run_dir, f"{mode}-tests") for mode in ["fuzzolic", "directed"]]
        testcase_dirs.extend(
            binradar_fuzzer.AFLppFuzzer.testcase_dirs_for_outdir(
                self.fuzzer_outdir()))
        benign_inputs = os.path.join(self.workdir, "input", "benign")
        malicious_inputs = os.path.join(self.workdir, "input", "malicious")
        if os.path.exists(benign_inputs):
            testcase_dirs.append(benign_inputs)
        if os.path.exists(malicious_inputs):
            testcase_dirs.append(malicious_inputs)
        print("TESTCASE_DIRS: " + ", ".join(testcase_dirs))
        minimizer = binradar_minimizer.BinRadarMinimizer(self.workdir, self.run_dir, self.probe_result, testcase_dirs, config)
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
        exec_mode = "verifier"
        minimizer_result_file = os.path.join(self.run_dir, "minimizer.sbsv")
        if not os.path.exists(minimizer_result_file):
            logger.info("[VERIFIER] Minimizer results not found. Please run the minimizer phase first.")
            sys.exit(1)
        
        config = self._worker_environment()
        self.save_progress(f"[verifier] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        deadline = self.phase_deadline(MINIMIZER_VERIFIER_TIMEOUT_FACTOR)
        # Implementation for concrete verifier
        runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        logger.info(
            f"[VERIFIER] Verifying {len(self.filter_result)} patch(es)")
        verifier = binradar_verifier.BinRadarConcreteVerifier(
            self.workdir, self.run_dir, runner, self.probe_result,
            self.artifacts.select_verifier(self.filter_result).path,
            self.filter_result,
            patched_binary_patches=list(
                range(1, self.brpatched_total_patches + 1)))
        timed_out = verifier.run_verification_streaming(
            minimizer_result_file,
            timeout=self.remaining_concrete_timeout(deadline))
        if timed_out:
            self._record_wall_time_reached(["verifier"])
        self.save_progress(f"[verifier] [done] [prefix {self.run_prefix}] [id {self.run_id}]")

    def run_minimizer_and_verifier(self,
                                   producer_threads: Optional[List[threading.Thread]] = None,
                                   producer_exc_queue: Optional["queue.Queue[BaseException]"] = None) -> bool:
        """Run the minimizer and the concrete verifier together.

        With ``producer_threads`` (the fuzzolic/directed/fuzzer threads), the
        minimizer discovers testcase files incrementally while those phases
        still run and finishes only after all of them have ended; the verifier
        consumes the [testcase] rows as they appear. Without them (e.g.
        --seq), it behaves like a standalone snapshot run over the already
        complete testcase dirs.
        """
        self.check_requirements()
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run minimizer and verifier.")
            raise RuntimeError("Probe result not found.")
        self.save_progress(f"[minimizer] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        self.save_progress(f"[verifier] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        deadline = self.phase_deadline(MINIMIZER_VERIFIER_TIMEOUT_FACTOR)
        config = self._worker_environment()
        testcase_dirs = [os.path.join(self.run_dir, f"{mode}-tests") for mode in ["fuzzolic", "directed"]]
        testcase_dirs.extend(
            binradar_fuzzer.AFLppFuzzer.testcase_dirs_for_outdir(
                self.fuzzer_outdir()))
        benign_inputs = os.path.join(self.workdir, "input", "benign")
        malicious_inputs = os.path.join(self.workdir, "input", "malicious")
        if os.path.exists(benign_inputs):
            testcase_dirs.append(benign_inputs)
        if os.path.exists(malicious_inputs):
            testcase_dirs.append(malicious_inputs)
        print("TESTCASE_DIRS: " + ", ".join(testcase_dirs))
        minimizer = binradar_minimizer.BinRadarMinimizer(self.workdir, self.run_dir, self.probe_result, testcase_dirs, config)
        runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        logger.info(
            f"[VERIFIER] Verifying {len(self.filter_result)} patch(es)")
        verifier = binradar_verifier.BinRadarConcreteVerifier(
            self.workdir, self.run_dir, runner, self.probe_result,
            self.artifacts.select_verifier(self.filter_result).path,
            self.filter_result,
            patched_binary_patches=list(
                range(1, self.brpatched_total_patches + 1)))
        minimizer_result_file = os.path.join(self.run_dir, "minimizer.sbsv")
        timed_out = binradar_minimizer.run_minimizer_and_verifier(
            minimizer, verifier, minimizer_result_file,
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
                binradar_env["BINRADAR_POC_FAULT_ADDR"] = hex(
                    self.probe_result.fault_addr)
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
                session.shared_memory(binradar_env, include_patch_key=True)
                session.start_solver(
                    mode=exec_mode, testcase=testcase, run_dir=self.run_dir,
                    env=binradar_env, workdir=self.workdir, fuzzy=self.fuzzy)
                if session.deadline.expired():
                    timed_out = True
                else:
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
        # Generate feedback for taosc
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run feedback analysis.")
            raise RuntimeError("Probe result not found.")

        minimizer_result_file = os.path.join(self.run_dir, "minimizer.sbsv")
        if not os.path.exists(minimizer_result_file):
            raise FileNotFoundError(
                f"Minimizer result file not found: {minimizer_result_file}")

        self.save_progress(
            f"[feedback] [start] [prefix {self.run_prefix}] [id {self.run_id}]")

        feedback_dir = os.path.join(self.run_dir, "feedback")
        if os.path.exists(feedback_dir):
            shutil.rmtree(feedback_dir)
        os.makedirs(feedback_dir)

        # Required files for the feedback analysis.
        shutil.copyfile(
            os.path.join(self.workdir, "binradar.env"),
            os.path.join(feedback_dir, "binradar.env"))
        shutil.copyfile(
            self.artifacts.original,
            os.path.join(feedback_dir, os.path.basename(self.artifacts.original)))

        poc_source = self.resolved_poc_input()
        poc_relative = os.path.relpath(poc_source, self.workdir)
        if poc_relative == os.pardir or poc_relative.startswith(
                os.pardir + os.sep):
            poc_relative = os.path.join("poc", os.path.basename(poc_source))
        poc_destination = os.path.join(feedback_dir, poc_relative)
        os.makedirs(os.path.dirname(poc_destination), exist_ok=True)
        shutil.copyfile(poc_source, poc_destination)
        if os.path.exists(os.path.join(self.workdir, "brpatches.json")):
            shutil.copyfile(
                os.path.join(self.workdir, "brpatches.json"),
                os.path.join(feedback_dir, "brpatches.json"))
        mutation_feedback = os.path.join(self.run_dir, "binradar-feedback")
        if os.path.isdir(mutation_feedback):
            shutil.copytree(
                mutation_feedback, os.path.join(feedback_dir, "binradar"))
        concrete_dir = os.path.join(feedback_dir, "concrete")
        benign_dir = os.path.join(concrete_dir, "benign")
        malicious_dir = os.path.join(concrete_dir, "malicious")
        os.makedirs(benign_dir, exist_ok=True)
        os.makedirs(malicious_dir, exist_ok=True)

        # The full minimizer row is emitted by BinRadarMinimizer.  The
        # fallback schema keeps feedback usable with older minimizer logs,
        # whose rows contain only the fields consumed by the verifier.
        full_parser = sbsv.parser()
        full_parser.add_schema(
            "[testcase] [result] [id: int] [file: str] [exit: str] "
            "[patch-loc: hex] [func-entry: hex] [patch-hit: int] "
            "[func-hit: int] [fault-addr: hex] "
            "[tracer-fault-addr: hex] "
            "[patch-func-candidates: list[str]] [stacktrace: list[str]] "
            "[pid: int] [br: list[int]]")
        legacy_parser = sbsv.parser()
        legacy_parser.add_schema(
            "[testcase] [result] [id: int] [file: str] [exit: str] "
            "[fault-addr: hex] [pid: int] [br: list[int]]")
        minimal_parser = sbsv.parser()
        minimal_parser.add_schema(
            "[testcase] [result] [id: int] [file: str] [exit: str] "
            "[fault-addr: hex]")

        def parse_result_row(line: str):
            for parser in (full_parser, legacy_parser, minimal_parser):
                try:
                    row = parser.parse_line_detached(line)
                except ValueError:
                    continue
                if row is not None and row.schema_name == "testcase$result":
                    return row
            return None

        copied_hashes: Set[str] = set()
        copied_counts = {"benign": 0, "malicious": 0}
        minimized_dir = os.path.join(self.run_dir, "minimized")
        with open(minimizer_result_file, "r", encoding="utf-8") as result_file:
            for line_number, line in enumerate(result_file, start=1):
                row = parse_result_row(line)
                if row is None:
                    continue

                patch_hit = row.data.get("patch-hit")
                if patch_hit is not None and patch_hit <= 0:
                    continue

                exit_info = row["exit"]
                if exit_info == "ok":
                    category = "benign"
                elif (exit_info == "crash"
                      and row["fault-addr"] == self.probe_result.fault_addr):
                    category = "malicious"
                else:
                    # Timeouts, unrelated crashes, and malformed baseline
                    # outcomes are not useful concrete feedback.
                    continue

                filename = os.path.basename(row["file"])
                source = os.path.join(minimized_dir, filename)
                try:
                    with open(source, "rb") as source_file:
                        data = source_file.read()
                except OSError as exc:
                    logger.warning(
                        f"[FEEDBACK] Skipping missing testcase {source} "
                        f"from minimizer line {line_number}: {exc}")
                    continue

                digest = hashlib.sha256(data).hexdigest()
                if digest in copied_hashes:
                    continue

                destination_dir = benign_dir if category == "benign" \
                    else malicious_dir
                destination = os.path.join(destination_dir, filename)
                if os.path.exists(destination):
                    destination = os.path.join(
                        destination_dir, f"{row['id']}_{filename}")
                shutil.copyfile(source, destination)
                copied_hashes.add(digest)
                copied_counts[category] += 1

        logger.info(
            f"[FEEDBACK] Copied concrete inputs: "
            f"benign {copied_counts['benign']}, "
            f"malicious {copied_counts['malicious']}")
        self.save_progress(
            f"[feedback] [done] [prefix {self.run_prefix}] [id {self.run_id}]")

    @staticmethod
    def _iter_legacy_binradar_results(trace_file: str):
        """Stream old per-patch SBSV traces one iteration at a time."""
        parser = sbsv.parser()
        parser.add_schema(
            "[binradar] [crash] [iter: int] [patch: int] "
            "[guest_pc: hex] [guest_cs_base: hex] [fault_addr: hex] "
            "[host_fault_addr: hex]")
        parser.add_schema(
            "[binradar] [normal] [iter: int] [patch: int]")
        parser.add_schema(
            "[binradar] [commit] [iter: int] [patch: int] [br: str]")
        current_iteration: Optional[int] = None
        current: Dict[int, dict] = {}
        with open(trace_file, "r", encoding="utf-8") as stream:
            for line in stream:
                result = parser.parse_line_detached(line)
                if result is None:
                    continue
                iteration = result["iter"]
                if current_iteration is None:
                    current_iteration = iteration
                elif iteration != current_iteration:
                    if iteration < current_iteration:
                        raise ValueError(
                            "legacy BINRADAR trace iterations are unordered")
                    yield current_iteration, current
                    current_iteration = iteration
                    current = {}
                patch = result["patch"]
                patch_result = current.setdefault(patch, {})
                if result.schema_name == "binradar$crash":
                    patch_result["result"] = "crash"
                    patch_result["fault_addr"] = result["fault_addr"]
                elif result.schema_name == "binradar$normal":
                    patch_result["result"] = "normal"
                else:
                    patch_result["br"] = result["br"]
        if current_iteration is not None:
            yield current_iteration, current

    @staticmethod
    def _iter_binary_binradar_results(evidence_file: str):
        """Expand one compact equivalence-class frame at a time."""
        for iteration in binradar_evidence.read_binradar(evidence_file):
            results: Dict[int, dict] = {}
            for group in iteration.groups:
                branch = ("null" if group.branches is None else
                          "".join(str(value) for value in group.branches))
                for patch in group.members:
                    result = {"result": group.outcome, "br": branch}
                    if group.outcome == "crash":
                        result["fault_addr"] = group.fault_addr
                    results[patch] = result
            yield iteration.iteration, results

    def run_final(self):
        # Read compact verifier and BINRADAR evidence and save final results.
        # Legacy SBSV artifacts remain readable for completed old workdirs.
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run final analysis.")
            raise RuntimeError("Probe result not found.")
        verifier_result_file = os.path.join(self.run_dir, "verifier.br")
        legacy_verifier_file = os.path.join(self.run_dir, "verifier.sbsv")
        if not os.path.exists(verifier_result_file):
            verifier_result_file = legacy_verifier_file
        binradar_evidence_file = os.path.join(self.run_dir, "binradar.br")
        trace_msg_log_file = os.path.join(
            self.run_dir, "binradar-tracer-msg.log")
        self.save_progress(
            f"[final] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        if not os.path.exists(verifier_result_file):
            logger.error(
                "Verifier result file not found. BinRadar results might be "
                "incomplete.")
            raise FileNotFoundError(
                f"Verifier result file not found: {verifier_result_file}")
        remaining_patches = set(self.filter_result)
        concrete_verifier_result = \
            binradar_verifier.BinRadarConcreteVerifierResult.from_file(
                verifier_result_file)
        if concrete_verifier_result is None:
            logger.error("Failed to parse verifier result. BinRadar results might be incomplete.")
            raise ValueError("Failed to parse verifier result.")
        if (concrete_verifier_result.stop_reason == "wall-time-reached"
                and not self.wall_time_reached):
            # Preserve the cutoff marker when FINAL is resumed in a fresh
            # process after graceful timeout finalization already produced a
            # complete verifier result file.
            self._record_wall_time_reached([])
        try:
            concrete_verifier_result.require_complete_verdicts(
                self.filter_result)
        except ValueError as exc:
            # Missing verdicts previously defaulted to verified here, which
            # could silently retain patches after an incomplete verifier run.
            logger.error(f"Incomplete verifier result: {exc}")
            raise
        # FINAL combines concrete-verifier and BinRadar observations into one
        # confidence score per patch. Older verifier files have no evidence
        # rows and therefore start at 0/0 (score 0.0).
        accept_evidences = {
            patch: concrete_verifier_result.accept_evidences.get(patch, 0)
            for patch in self.filter_result
        }
        total_evidences = {
            patch: concrete_verifier_result.total_evidences.get(patch, 0)
            for patch in self.filter_result
        }

        def record_evidence(patch: int, accepted: bool) -> None:
            total_evidences[patch] = total_evidences.get(patch, 0) + 1
            if accepted:
                accept_evidences[patch] = accept_evidences.get(patch, 0) + 1

        binradar_failed = self.binradar_failed
        skip_binradar_analysis = self.disable_binradar or binradar_failed
        compact_binradar = False
        if self.disable_binradar:
            logger.info(
                "[FINAL] BinRadar phase disabled; skipping evidence analysis.")
            binradar_iterations = iter(())
        elif binradar_failed:
            logger.warning(
                "[FINAL] BinRadar phase failed under --less-strict; ignoring "
                "its potentially incomplete evidence and using concrete "
                "verifier evidence only.")
            binradar_iterations = iter(())
        elif os.path.exists(binradar_evidence_file):
            compact_binradar = True
            binradar_iterations = self._iter_binary_binradar_results(
                binradar_evidence_file)
        elif os.path.exists(trace_msg_log_file):
            binradar_iterations = self._iter_legacy_binradar_results(
                trace_msg_log_file)
        else:
            logger.error(
                "BINRADAR evidence file not found. Results might be "
                "incomplete.")
            raise FileNotFoundError(
                f"BINRADAR evidence file not found: {binradar_evidence_file}")
        for patch_id in self.filter_result:
            if not concrete_verifier_result.patch_verified[patch_id]:
                remaining_patches.discard(patch_id)
        binradar_remaining_patches = remaining_patches.copy()
        binradar_reject_reasons: Dict[int, Tuple[str, int]] = dict()
        poc_fault_loc = (0 if skip_binradar_analysis
                         else self.probe_result.tracer_fault_addr)
        if not skip_binradar_analysis and poc_fault_loc == 0:
            logger.warning(
                "[FINAL] tracer_fault_addr is 0; binradar crash comparison "
                "will not match any fault address.")

        expected_candidates = set(self.filter_result)
        processed_iterations = 0
        for iteration, iteration_results in binradar_iterations:
            actual = set(iteration_results)
            expected = {0} if iteration == 1 \
                else expected_candidates | {0}
            if compact_binradar and actual != expected:
                raise ValueError(
                    f"BINRADAR iteration {iteration} coverage mismatch: "
                    f"missing {sorted(expected - actual)}; "
                    f"unexpected {sorted(actual - expected)}")
            # A legacy timeout tail may have only one half of an outcome.
            # Compact frames are committed atomically and were checked above.
            original = iteration_results.get(0)
            if original is None or "result" not in original \
                    or "br" not in original or original["br"] == "null":
                continue
            processed_iterations += 1
            for patch in remaining_patches:
                patch_result = iteration_results.get(patch)
                if patch_result is None or "result" not in patch_result \
                        or "br" not in patch_result:
                    continue
                if original["result"] == "crash" \
                        and patch_result["result"] == "crash":
                    if original.get("fault_addr") == poc_fault_loc \
                            and patch_result.get("fault_addr") == \
                            poc_fault_loc:
                        record_evidence(patch, False)
                        binradar_remaining_patches.discard(patch)
                        binradar_reject_reasons[patch] = (
                            "same-crash", iteration)
                elif original["result"] == "crash" \
                        and patch_result["result"] == "normal":
                    record_evidence(patch, True)
                elif original["result"] == "normal" \
                        and patch_result["result"] == "crash":
                    if patch_result.get("fault_addr") == poc_fault_loc:
                        record_evidence(patch, False)
                        binradar_remaining_patches.discard(patch)
                        binradar_reject_reasons[patch] = (
                            "introduced-crash", iteration)
                elif original["result"] == "normal" \
                        and patch_result["result"] == "normal":
                    record_evidence(
                        patch, original["br"] == patch_result["br"])
        if not skip_binradar_analysis:
            logger.info(
                f"[FINAL] Processed {processed_iterations} complete "
                f"BINRADAR evidence iteration(s); rejected "
                f"{len(remaining_patches - binradar_remaining_patches)} "
                f"patch(es).")
        # Two orthogonal status concepts, kept distinct in every output row:
        #   * failed phases (--less-strict) are real issues;
        #   * a reached wall-clock budget is a planned graceful cutoff.
        failed_phases = self.failed_phase_names()
        issues_suffix = (
            f" [issues true] [failed-phases {','.join(failed_phases)}]"
            if failed_phases else " [issues false] [failed-phases none]")
        wall_time_suffix = (
            " [wall-time-reached true]" if self.wall_time_reached
            else " [wall-time-reached false]")
        if failed_phases:
            self.save_progress(
                f"[final] [failed-phases] [prefix {self.run_prefix}] "
                f"[id {self.run_id}] "
                f"[failed-phases {','.join(failed_phases)}]")
        if self.wall_time_reached:
            self.save_progress(
                f"[final] [wall-time-reached] [prefix {self.run_prefix}] "
                f"[id {self.run_id}]")
        self.save_progress(f"[final] [done] [prefix {self.run_prefix}] [id {self.run_id}] [remaining_patches {sorted(remaining_patches)}] [binradar_remaining_patches {sorted(binradar_remaining_patches)}]{issues_suffix}{wall_time_suffix}")

        # Write a self-contained final.sbsv with per-patch verdicts from the
        # concrete verifier and, when enabled, the binradar analysis.
        final_result_file = os.path.join(self.run_dir, "final.sbsv")
        if self.disable_binradar:
            trace_metadata = "[binradar disabled]"
        elif binradar_failed:
            trace_metadata = "[binradar failed]"
        elif compact_binradar:
            trace_metadata = (
                f"[evidence {os.path.basename(binradar_evidence_file)}]")
        else:
            trace_metadata = f"[trace {os.path.basename(trace_msg_log_file)}]"
        with open(final_result_file, "w", encoding="utf-8") as f:
            f.write(f"[final] [start] [prefix {self.run_prefix}] [id {self.run_id}] "
                    f"[verifier {os.path.basename(verifier_result_file)}] "
                    f"{trace_metadata}\n")
            if failed_phases:
                f.write(f"[final] [failed-phases] [prefix {self.run_prefix}] "
                        f"[id {self.run_id}] "
                        f"[failed-phases {','.join(failed_phases)}]\n")
            if self.wall_time_reached:
                f.write(f"[final] [wall-time-reached] "
                        f"[prefix {self.run_prefix}] [id {self.run_id}]\n")
            for patch_id in sorted(self.filter_result):
                verified = concrete_verifier_result.patch_verified[patch_id]
                res = "verified" if verified else "rejected"
                f.write(f"[final] [verifier] [patch {patch_id}] [res {res}]\n")
            # Confidence rows cover only patches accepted by the concrete
            # verifier, ranked by score (highest first). Ties keep the
            # original patch-id order (stable sort).
            confidence_rows = []
            for patch_id in sorted(self.filter_result):
                if not concrete_verifier_result.patch_verified[patch_id]:
                    continue
                accepted = accept_evidences.get(patch_id, 0)
                total = total_evidences.get(patch_id, 0)
                confidence = accepted / total if total > 0 else 0.0
                confidence_rows.append((patch_id, confidence, accepted, total))
            confidence_rows.sort(key=lambda row: row[1], reverse=True)
            for patch_id, confidence, accepted, total in confidence_rows:
                f.write(f"[final] [confidence] [patch {patch_id}] "
                        f"[score {confidence:.6f}] "
                        f"[accept-evidences {accepted}] "
                        f"[total-evidences {total}]\n")
            if not skip_binradar_analysis:
                for patch_id in sorted(remaining_patches):
                    if patch_id in binradar_remaining_patches:
                        f.write(f"[final] [binradar] [patch {patch_id}] [res verified] "
                                f"[reason none] [iter -1]\n")
                    else:
                        reason, reject_iter = binradar_reject_reasons.get(patch_id, ("unknown", -1))
                        f.write(f"[final] [binradar] [patch {patch_id}] [res rejected] "
                                f"[reason {reason}] [iter {reject_iter}]\n")
            f.write(f"[final] [done] [prefix {self.run_prefix}] [id {self.run_id}] "
                    f"[remaining_patches {sorted(remaining_patches)}] "
                    f"[binradar_remaining_patches {sorted(binradar_remaining_patches)}]"
                    f"{issues_suffix}{wall_time_suffix}\n")
        logger.info(f"[FINAL] Saved final result: {final_result_file}")

    def done(self):
        self.save_progress(f"[rundir] [done] [prefix {self.run_prefix}] [id {self.run_id}] [dir {self.run_dir}]")
    
    def _run_streaming_concrete_producers(
            self,
            producers: List[Tuple[str, Callable[[], None]]]) -> None:
        """Run concrete producers with the streaming minimizer/verifier.

        Every producer is an optional evidence phase. In strict mode, a
        producer exception is sent to the minimizer so an incomplete testcase
        stream cannot produce a verdict. Under --less-strict, the failure is
        recorded and the minimizer drains the outputs from the producers that
        remain.
        """
        thread_errors: "queue.Queue[Tuple[str, BaseException, Optional[TracebackType]]]" = queue.Queue()
        producer_exc_queue: "queue.Queue[BaseException]" = queue.Queue()

        def run_producer_captured(
                name: str, target: Callable[[], None]) -> None:
            try:
                target()
            except BaseException as exc:
                if (name in OPTIONAL_EVIDENCE_PHASES
                        and self.less_strict
                        and isinstance(exc, Exception)):
                    self._record_tolerated_phase_failure(name, exc)
                    return
                producer_exc_queue.put(exc)
                thread_errors.put((name, exc, exc.__traceback__))
                logger.error(f"[{name}] failed: {exc}")

        producer_threads = [
            threading.Thread(
                target=run_producer_captured, args=(name, target), name=name)
            for name, target in producers
        ]
        for thread in producer_threads:
            thread.start()

        try:
            self.run_minimizer_and_verifier(
                producer_threads=producer_threads,
                producer_exc_queue=producer_exc_queue)
        except BaseException:
            # A producer, the minimizer, or the verifier failed. Stop external
            # processes and wait for every producer wrapper before surfacing
            # the authoritative exception.
            binradar_runtime.PROCESS_REGISTRY.stop_all()
            for thread in producer_threads:
                thread.join(timeout=60)
            raise

        for thread in producer_threads:
            thread.join()
        if not thread_errors.empty():
            _, exc, tb = thread_errors.get()
            binradar_runtime.PROCESS_REGISTRY.stop_all()
            if tb is not None:
                raise exc.with_traceback(tb)
            raise exc

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
        self._run_streaming_concrete_producers([
            ("fuzzer", self.run_fuzzer),
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

        thread_errors: "queue.Queue[Tuple[str, BaseException, Optional[TracebackType]]]" = queue.Queue()
        producer_exc_queue: "queue.Queue[BaseException]" = queue.Queue()
        binradar_thread: Optional[threading.Thread] = None
        
        def tolerate_thread_failure(name: str, exc: BaseException) -> bool:
            # Do not swallow process-control exceptions such as SystemExit or
            # KeyboardInterrupt. Ordinary optional-phase failures are the only
            # failures relaxed by --less-strict.
            if (name not in OPTIONAL_EVIDENCE_PHASES
                    or not self.less_strict
                    or not isinstance(exc, Exception)):
                return False
            self._record_tolerated_phase_failure(name, exc)
            return True

        def run_captured(name: str, target):
            try:
                target()
            except BaseException as exc:
                if tolerate_thread_failure(name, exc):
                    return
                thread_errors.put((name, exc, exc.__traceback__))
                logger.error(f"[{name}] failed: {exc}")

        # In strict mode, concrete testcase producers additionally re-raise
        # into producer_exc_queue so the concurrently running minimizer aborts
        # instead of silently verifying a truncated testcase set. Less-strict
        # failures are recorded above and deliberately do not enter the queue.
        def run_producer_captured(name: str, target):
            try:
                target()
            except BaseException as exc:
                if tolerate_thread_failure(name, exc):
                    return
                producer_exc_queue.put(exc)
                thread_errors.put((name, exc, exc.__traceback__))
                logger.error(f"[{name}] failed: {exc}")

        def raise_thread_error_if_any(wait_for_binradar: bool = False):
            if thread_errors.empty():
                return
            _, exc, tb = thread_errors.get()
            binradar_runtime.PROCESS_REGISTRY.stop_all()
            if wait_for_binradar and binradar_thread is not None:
                binradar_thread.join()
            if tb is not None:
                raise exc.with_traceback(tb)
            raise exc

        if not self.disable_binradar:
            binradar_thread = threading.Thread(target=run_captured, args=("binradar", self.run_binradar))
            binradar_thread.start()
        else:
            logger.info("[BINRADAR] BinRadar phase disabled; skipping execution.")

        fuzzolic_thread = threading.Thread(target=run_producer_captured, args=("fuzzolic", self.run_fuzzolic))
        directed_thread = threading.Thread(target=run_producer_captured, args=("directed", self.run_directed))
        fuzzer_thread = threading.Thread(target=run_producer_captured, args=("fuzzer", self.run_fuzzer))
        threads_concrete = [fuzzolic_thread, directed_thread, fuzzer_thread]
        for thread in threads_concrete:
            thread.start()

        # The minimizer+verifier no longer wait for the producers: the
        # minimizer discovers testcase files incrementally while
        # fuzzolic/directed/fuzzer are still running and logs its done marker
        # only after all three have ended, and the verifier consumes the
        # [testcase] rows as they appear.
        try:
            self.run_minimizer_and_verifier(
                producer_threads=threads_concrete,
                producer_exc_queue=producer_exc_queue)
        except BaseException:
            # A producer, the minimizer, or the verifier failed: stop the
            # remaining phases before surfacing the error.
            binradar_runtime.PROCESS_REGISTRY.stop_all()
            for thread in threads_concrete:
                thread.join(timeout=60)
            if binradar_thread is not None:
                binradar_thread.join(timeout=10)
            raise
        for thread in threads_concrete:
            thread.join()

        raise_thread_error_if_any(wait_for_binradar=True)

        if binradar_thread is not None:
            binradar_thread.join(timeout=60)
            if binradar_thread.is_alive():
                logger.error("[BINRADAR] binradar thread did not finish within 60s after minimizer/verifier - stopping remaining processes")
                binradar_runtime.PROCESS_REGISTRY.stop_all()
                binradar_thread.join(timeout=10)
        raise_thread_error_if_any()
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
