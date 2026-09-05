#!/usr/bin/python3 -u

import argparse
import ctypes
import os
import random
import resource
import shlex
import shutil
import signal
import subprocess
import threading
import multiprocessing
import queue
import sys
import select
import struct
import io
import time
import enum
import fcntl
from pathlib import Path
from types import TracebackType
from typing import Callable, Dict, List, Tuple, Set, Optional, TextIO, BinaryIO

import analyze_type
import binradar_verifier
import binradar_fuzzer
import binradar_minimizer
import binradar_utils
import logger
import sbsv

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SOLVER_SMT_BIN = SCRIPT_DIR + "/../solver/build/solver-smt"
SOLVER_FUZZY_BIN = SCRIPT_DIR + "/../solver/build/solver-fuzzy"
TRACER_BIN = SCRIPT_DIR + "/../tracer/build/x86_64-linux-user/qemu-x86_64"
FIND_MODELS_BIN = SCRIPT_DIR + "/find_models_addrs.py"

SOLVER_WAIT_TIME_AT_STARTUP = 1 # s
SOLVER_TIMEOUT = 10 # s
MINIMIZER_VERIFIER_TIMEOUT_FACTOR = 1.5
# Security boundary for --less-strict: only independent evidence producers
# may fail open. Phases needed to establish or serialize a verdict are never
# members of this set.
OPTIONAL_EVIDENCE_PHASES = frozenset({
    "fuzzolic", "directed", "fuzzer", "binradar",
})

RUNNING_PROCESSES: List[subprocess.Popen] = []
RUNNING_PROCESSES_LOCK = threading.Lock()
MAX_VIRTUAL_MEMORY = 256 * 1024 * 1024 * 1024 * 1024  # 256 TB (for ASAN shadow mapping)
SHM_KEYS = ["EXPR_POOL_SHM_KEY", "QUERY_SHM_KEY", "BITMAP_SHM_KEY"]

# Tracer forkserver
HANDSHAKE_EXPECTED = 0x41464C00


class BinRadarPhase(enum.IntEnum):
    ALL = 0
    PROBE = 1
    FILTER = 2
    FUZZOLIC = 3
    DIRECTED = 4
    FUZZER = 5
    MINIMIZER = 6
    VERIFIER = 7
    BINRADAR = 8
    FINAL = 9
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
SINGLE_PHASE_NAMES = ["probe", "filter", "fuzzolic", "directed", "fuzzer",
                      "minimizer", "verifier", "minimizer-verifier",
                      "binradar", "final"]


def setlimits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY, MAX_VIRTUAL_MEMORY))


def stop_running_processes():
    with RUNNING_PROCESSES_LOCK:
        processes = list(RUNNING_PROCESSES)
    for proc in processes:
        binradar_utils.execute_await(proc, timeout=1)
        with RUNNING_PROCESSES_LOCK:
            if proc in RUNNING_PROCESSES:
                RUNNING_PROCESSES.remove(proc)

def handler(signo, stackframe):
    del signo
    del stackframe

    print("[BINRADAR] Aborting... Wait for safe cleanup.")
    stop_running_processes()
    sys.exit(f"Aborted binradar with cleanup.")

class SharedMemoryManager:
    def __init__(self, env: Dict[str, str]):
        self.env = env
        self.libc = ctypes.CDLL("libc.so.6")
        self.shm_keys = list()
    
    def assign_random_keys(self):
        for key in SHM_KEYS:
            shm_key = random.getrandbits(32)
            self.env[key] = hex(shm_key)
            self.shm_keys.append(shm_key)
    
    def assign_random_key_for_binradar(self):
        shm_key = random.getrandbits(32)
        self.env["BINRADAR_PATCH_SHM_KEY"] = hex(shm_key)
        self.shm_keys.append(shm_key)
    
    def cleanup(self):
        ipc_rmid = 0
        for shm_key in self.shm_keys:
            shm_id = self.libc.shmget(
                ctypes.c_int(shm_key), ctypes.c_int(1), ctypes.c_int(0))
            if shm_id != -1:
                result = self.libc.shmctl(
                    ctypes.c_int(shm_id),
                    ctypes.c_int(ipc_rmid),
                    ctypes.c_void_p(0))
                logger.info(
                    "Shared memory detach on (%s, %s): %s"
                    % (shm_key, shm_id, result))


class PipeManager:
    def __init__(self, env: Dict[str, str], mode: str):
        self.env = env
        self.mode = mode
        self.closed = False
        self.cleanup_done = False
        self.ctrl_r = 0
        self.ctrl_w = 0
        self.stat_r = 0
        self.stat_w = 0
        self.patch_fd_r = 0
        self.patch_fd_w = 0
    
    def setup_pipe(self):
        result = list()
        self.ctrl_r, self.ctrl_w = os.pipe()
        self.stat_r, self.stat_w = os.pipe()
        self.env["BINRADAR_FORKSERVER_CTRL_R"] = str(self.ctrl_r)
        self.env["BINRADAR_FORKSERVER_STAT_W"] = str(self.stat_w)
        if self.mode == "binradar":
            self.patch_fd_r, self.patch_fd_w = os.pipe()
            self.env["PATCH_FD"] = str(self.patch_fd_w)
            self.env["BINRADAR_PATCH_FD_R"] = str(self.patch_fd_r)
        return result
    
    def get_pass_fds(self) -> List[int]:
        pass_fds = [self.ctrl_r, self.stat_w]
        if self.mode == "binradar":
            pass_fds += [self.patch_fd_r, self.patch_fd_w]
        return pass_fds
    
    def close_passed_fds(self):
        if self.closed:
            return
        for fd in self.get_pass_fds():
            os.close(fd)
        self.closed = True

    def cleanup(self):
        if self.cleanup_done:
            return
        if not self.closed:
            self.close_passed_fds()
        os.close(self.ctrl_w)
        os.close(self.stat_r)
        self.cleanup_done = True
    
    def get_ctrl_w(self) -> int:
        return self.ctrl_w

    def get_stat_r(self) -> int:
        return self.stat_r

class TracerExecutor:
    forkserver_init_timeout: float = 1800.0
    forkserver_timeout: float = 1800.0
    analyzer_timeout: float = 1200.0
    command: List[str]
    mode: str
    env: Dict[str, str]
    workdir: str
    rundir: str
    trace_file: str
    process: Optional[subprocess.Popen]
    timeout: float
    # Forkserver
    forkserver_mode: bool
    pipe_manager: Optional[PipeManager]
    iter: int
    run_result: Optional[binradar_utils.ExecutionResult]
    def __init__(self, mode: str, env: Dict[str, str], workdir: str, rundir: str, binary: str, test_cmd: str, testcase: str, timeout: float):
        self.command = [TRACER_BIN, "-symbolic", "-d", "page", binary] + shlex.split(test_cmd.replace("@@", testcase))
        self.mode = mode
        self.env = env
        self.workdir = workdir
        self.rundir = rundir
        self.trace_file = ""
        if "BINRADAR_TRACE_FILE" in env:
            self.trace_file = env["BINRADAR_TRACE_FILE"]
        self.timeout = timeout
        self.process = None
        self.forkserver_mode = self.env.get("BINRADAR_FORKSERVER_ENABLE", "0") == "1"
        self.iter = 0
        self.run_result = None
        self.pipe_manager = None
    
    def start(self):
        """ 
        Start the tracer process and set up forkserver communication if enabled. 
        Should be called after SolverExecutor.start() - shared memory is set in solver process
        """
        self.start_time = time.time()
        if not self.forkserver_mode:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=self.workdir,
                env=self.env,
                start_new_session=True)
            with RUNNING_PROCESSES_LOCK:
                RUNNING_PROCESSES.append(self.process)
            logger.info(f"[TRACER] [{self.mode}] Started tracer without forkserver mode. {' '.join(self.command)}")
            return

        # Set up pipes for forkserver communication
        self.pipe_manager = PipeManager(self.env, self.mode)
        self.pipe_manager.setup_pipe()
        pass_fds = self.pipe_manager.get_pass_fds()
        
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.workdir,
            env=self.env,
            pass_fds=pass_fds,
            start_new_session=True)
        
        with RUNNING_PROCESSES_LOCK:
            RUNNING_PROCESSES.append(self.process)
        self.pipe_manager.close_passed_fds()
        
        # Handshake with forkserver
        logger.info(f"[TRACER] [{self.mode}] Started tracer {' '.join(self.command)}")
        banner = self._read_u32(self.forkserver_init_timeout)
        if banner != HANDSHAKE_EXPECTED:
            raise RuntimeError(f"[TRACER] [{self.mode}] Unexpected forkserver handshake: {banner:#x}")
        self._write_u32(HANDSHAKE_EXPECTED ^ 0xFFFFFFFF)
        ack = self._read_u32(self.forkserver_timeout)
        if ack != HANDSHAKE_EXPECTED:
            raise RuntimeError(f"[TRACER] [{self.mode}] Unexpected forkserver ack: {ack:#x}")
        logger.info(f"[TRACER] [{self.mode}] Tracer forkserver started successfully.")
        
    def run(self) -> Tuple[int, bool, int]: # synchronous run, wait for target binary to finish
        if self.process is None:
            raise RuntimeError(f"[TRACER] [{self.mode}] Tracer process not started")
        start_time = time.time()
        if not self.forkserver_mode:
            self.run_result = binradar_utils.execute_await(self.process, timeout=self.timeout)
            logger.info(f"[TRACER] [{self.mode}] Target process finished with exit code {self.run_result.decode_status()}, success {self.run_result.success}")
            return int((time.time() - start_time) * 1000), self.run_result.success, 0
        self._write_u32(0)  # was_killed - send run command to forkserver
        is_timeout = False
        try:
            exit_status, patch_id, iter = self._read_status(self.forkserver_timeout)
            self.iter = iter
            analyze_result = b""
            if self._need_type_analysis(patch_id, iter):
                logger.info(f"[TRACER] Start type analysis for patch {patch_id}, iter {iter} in {self.mode} mode")
                if not os.path.exists(self.trace_file):
                    raise RuntimeError(f"Log file for type analysis not found: {self.trace_file}")
                analyze_result_file = os.path.join(self.rundir, f"analyzed-type.{self.iter}.sbsv")
                analyze_start_time = time.time()
                analyze_process = multiprocessing.get_context("spawn").Process(target=analyze_type.osprey_analyze, args=(self.trace_file, analyze_result_file), daemon=False)
                analyze_process.start()
                analyze_process.join(timeout=self.analyzer_timeout)
                if analyze_process.is_alive():
                    is_timeout = True
                    logger.error(f"Osprey analysis is taking too long. Let us stop it.")
                    analyze_process.terminate()
                    analyze_process.join(timeout=5)
                    if analyze_process.is_alive():
                        logger.error(f"Osprey analysis will be killed.")
                        analyze_process.kill()
                    raise TimeoutError(f"Osprey analysis timed out")
                if analyze_process.exitcode != 0:
                    raise RuntimeError(f"Osprey analysis failed with exit code {analyze_process.exitcode}")
                if not os.path.exists(analyze_result_file):
                    raise RuntimeError(f"Osprey analysis result file not found: {analyze_result_file}")
                with open(analyze_result_file, "rb") as f:
                    analyze_result = f.read()
                logger.info(f"[osprey-analyzer] [it {self.iter}] [len {len(analyze_result)}] [time {round(time.time() - analyze_start_time, 3)}] [saved {analyze_result_file}]")
            if self.mode != "binradar":
                # In binradar mode the caller logs one line per iteration;
                # logging it here too would duplicate every iteration.
                logger.debug(f"[TRACER] [{self.mode}] Target process patch {patch_id}, iter {iter}, finished with status {exit_status:#x}")
        except Exception as e:
            is_timeout = True
            logger.error(f"[TRACER] [{self.mode}] Error while waiting for tracer forkserver: {str(e)}")
            # Check if process died - print exit status
            if self.process.poll() is not None:
                logger.error(f"[TRACER] [{self.mode}] Tracer process exited with code {self.process.returncode}")
            else:
                logger.error(f"[TRACER] [{self.mode}] Tracer process is still running - sending SIGINT to stop it")
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.error(f"[TRACER] [{self.mode}] Tracer did not exit after SIGINT - sending SIGKILL")
                self.process.kill()
                self.process.wait()
            raise e
        analyze_result_size = len(analyze_result)
        if analyze_result_size > 0xFFFFFFFF:
            raise ValueError(f"[TRACER] [{self.mode}] Analyze result too large")
        self._write_u32(len(analyze_result))
        self._write(analyze_result)
        remaining = self._read_u32(self.forkserver_timeout)
        return int((time.time() - start_time) * 1000), (not is_timeout), remaining
    
    def stop(self):
        if self.pipe_manager is not None:
            self.pipe_manager.cleanup()
        if self.process is not None:
            logger.info(f"[TRACER] [{self.mode}] Stopping tracer process...")
            self.run_result = binradar_utils.execute_await(self.process, timeout=5)
            with RUNNING_PROCESSES_LOCK:
                if self.process in RUNNING_PROCESSES:
                    RUNNING_PROCESSES.remove(self.process)
            self.process = None
        
    def _need_type_analysis(self, patch_id: int, iter: int) -> bool:
        """
        Determine if type analysis is needed:
        - It has large overhead, so we only want to run it when necessary.
        """
        if self.mode == "binradar":
            if patch_id == 0 and iter == 1:
                return True
        return False
    
    def _write_u32(self, value: int):
        self._write(struct.pack("<I", value))
    
    def _write(self, data: bytes):
        if self.pipe_manager is None:
            raise RuntimeError(f"[TRACER] [{self.mode}] Pipe manager not initialized")
        total_written = 0
        while total_written < len(data):
            try:
                written = os.write(self.pipe_manager.get_ctrl_w(), data[total_written:])
                total_written += written
            except BrokenPipeError:
                raise RuntimeError(f"[TRACER] [{self.mode}] Tracer forkserver pipe is broken")
            except BlockingIOError:
                continue
    
    def _read_u32(self, timeout: float) -> int:
        if self.pipe_manager is None:
            raise RuntimeError(f"[TRACER] [{self.mode}] Pipe manager not initialized")
        rlist, _, _ = select.select([self.pipe_manager.get_stat_r()], [], [], timeout)
        if not rlist:
            raise TimeoutError(f"[TRACER] [{self.mode}] Timeout while waiting for forkserver response")
        data = self._read(4)
        if len(data) < 4:
            raise EOFError(f"[TRACER] [{self.mode}] Failed to read 4 bytes from forkserver")
        return struct.unpack("<I", data)[0]
    
    def _read_status(self, timeout: float) -> Tuple[int, int, int]:
        if self.pipe_manager is None:
            raise RuntimeError(f"[TRACER] [{self.mode}] Pipe manager not initialized")
        rlist, _, _ = select.select([self.pipe_manager.get_stat_r()], [], [], timeout)
        if not rlist:
            raise TimeoutError(f"[TRACER] [{self.mode}] Timeout while waiting for forkserver response")
        data = self._read(12)
        if len(data) < 12:
            raise EOFError(f"[TRACER] [{self.mode}] Failed to read 12 bytes from forkserver")
        return struct.unpack("<III", data)
    
    def _read(self, size: int) -> bytes:
        if self.pipe_manager is None:
            raise RuntimeError(f"[TRACER] [{self.mode}] Pipe manager not initialized")
        data = b''
        while len(data) < size:
            try:
                chunk = os.read(self.pipe_manager.get_stat_r(), size - len(data))
                if not chunk:
                    raise EOFError(f"[TRACER] [{self.mode}] EOF while reading from forkserver")
                data += chunk
            except BlockingIOError:
                continue
        return data

class SolverExecutor:
    mode: str
    command: List[str]
    out_dir: str
    env: Dict[str, str]
    workdir: str
    rundir: str
    log_fp: BinaryIO
    process: Optional[subprocess.Popen]
    timeout: float
    run_result: Optional[binradar_utils.ExecutionResult]
    def __init__(self, mode: str, testcase: str, run_dir: str, env: Dict[str, str], workdir: str, timeout: float, fuzzy: bool = False, reverse_directed: bool = False):
        self.mode = mode
        global_bitmap = os.path.join(run_dir, f"{mode}-branch-bitmap")
        context_bitmap = os.path.join(run_dir, f"{mode}-context-bitmap")
        memory_bitmap = os.path.join(run_dir, f"{mode}-memory-bitmap")
        self.out_dir = os.path.join(run_dir, f"{mode}-tests")
        os.makedirs(self.out_dir, exist_ok=True)
        for bitmap in [global_bitmap, context_bitmap, memory_bitmap]:
            with open(bitmap, "w") as f:
                pass
        # Reverse-directed solving currently uses the Z3 bounded-prefix path.
        # Keep --fuzzy available for the other phases until fuzzy parity exists.
        solver_bin = SOLVER_SMT_BIN if reverse_directed else (SOLVER_FUZZY_BIN if fuzzy else SOLVER_SMT_BIN)
        self.command = ["stdbuf", "-o0", solver_bin,
                        "-i", testcase, 
                        "-o", self.out_dir, 
                        "-b", global_bitmap,
                        "-c", context_bitmap,
                        "-m", memory_bitmap]
        self.env = env
        self.workdir = workdir
        self.rundir = run_dir
        self.timeout = timeout
        log_file = os.path.join(run_dir, f"{mode}-solver.log")
        self.log_fp = open(log_file, "wb")
        self.process = None
        self.run_result = None
    
    def start(self):
        logger.info(f"[SOLVER] [{self.mode}] Starting solver with command: {' '.join(self.command)}")
        logger.debug(f"[SOLVER] [{self.mode}] timeout set to {self.timeout} seconds")
        self.process = subprocess.Popen(
            self.command,
            stdout=self.log_fp,
            stderr=subprocess.STDOUT,
            cwd=self.rundir,
            env=self.env,
            start_new_session=True)
        with RUNNING_PROCESSES_LOCK:
            RUNNING_PROCESSES.append(self.process)
        # Give the solver some time to start up and create shared memories
        time.sleep(SOLVER_WAIT_TIME_AT_STARTUP)
    
    def create_inputs(self):
        if self.process is None:
            raise RuntimeError(f"[SOLVER] [{self.mode}] Solver process not started")
        logger.info(f"[SOLVER] [{self.mode}] Sending signal to create inputs...")
        self.process.send_signal(signal.SIGUSR1)
    
    def wait(self) -> Tuple[int, bool]:
        if self.process is None:
            raise RuntimeError(f"[SOLVER] [{self.mode}] Solver process not started - cannot wait")
        start_time = time.time()
        elapsed = 0
        is_timeout = False
        while True:
            try:
                self.process.wait(SOLVER_TIMEOUT)
                break
            except subprocess.TimeoutExpired:
                pass
            elapsed += SOLVER_TIMEOUT
            if self.timeout > 0 and elapsed > (self.timeout + 10):
                is_timeout = True
                break
        if is_timeout:
            logger.info(f"[SOLVER] [{self.mode}] Solver is taking too long. Let us stop it.")
            self.process.send_signal(signal.SIGUSR2)
            try:
                self.process.wait(SOLVER_TIMEOUT)
            except subprocess.TimeoutExpired:
                logger.info(f"[SOLVER] [{self.mode}] Solver will be killed.")
                binradar_utils.execute_await(self.process, timeout=1)
        succeeded = (not is_timeout and self.process.returncode == 0)
        return int((time.time() - start_time) * 1000), succeeded

    def stop(self):
        if self.process:
            logger.info(f"[SOLVER] [{self.mode}] Stopping solver process...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            with RUNNING_PROCESSES_LOCK:
                if self.process in RUNNING_PROCESSES:
                    RUNNING_PROCESSES.remove(self.process)
            self.process = None
        if not self.log_fp.closed:
            self.log_fp.close()

class BinRadarProgress:
    run_id: int
    run_dir: str
    probe_done: bool
    filter_done: bool
    fuzzolic_done: bool
    directed_done: bool
    fuzzer_done: bool
    minimizer_done: bool
    verifier_done: bool
    done: bool
    def __init__(self, run_id: int, run_dir: str, probe_done: bool, filter_done: bool, fuzzolic_done: bool, directed_done: bool, fuzzer_done: bool, minimizer_done: bool, verifier_done: bool, done: bool):
        self.run_id = run_id
        self.run_dir = run_dir
        self.probe_done = probe_done
        self.filter_done = filter_done
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
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[rundir] [set] [prefix: str] [id: int] [dir: str]")
        parser.add_schema("[rundir] [done] [prefix: str] [id: int] [dir: str]")
        parser.add_schema("[probe] [done] [prefix: str] [id: int]")
        parser.add_schema("[filter] [done] [prefix: str] [id: int]")
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
        filter_done = False
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
        for filter in parser.get_result()["filter"]["done"]:
            if int(filter["id"]) == run_id and filter["prefix"] == run_prefix:
                filter_done = True
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
        return BinRadarProgress(run_id, run_dir, probe_done, filter_done, fuzzolic_done, directed_done, fuzzer_done, minimizer_done, verifier_done, done)

class BinRadarExecutor:
    # Config from binradar.env and command line arguments
    workdir: str
    outdir: str
    timeout: int
    binary: str
    poc_input: str
    test_cmd: str
    patch_loc: str
    # Artifact whose E9 metadata this run executes: "brpatched" (default),
    # "prefilter", or "brcached".  The prefixed binradar.env keys
    # (<PREFIX>_E9_EXCLUDE_RANGES / <PREFIX>_E9_RELOCATED_CALL_JUMPS) are
    # selected at load time; the tracer process env receives the unprefixed
    # names as its runtime contract.
    e9_metadata_prefix: str
    e9_exclude_ranges: str
    e9_relocated_calls: str
    total_patches: int
    fuzzy: bool
    reverse_directed: bool
    disable_binradar: bool
    less_strict: bool
    binradar_failed: bool
    concrete_evidence_timed_out: bool
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
    def __init__(self, workdir: str, outdir: str, timeout: int, binary: str, poc_input: str, test_cmd: str, patch_loc: str, e9_metadata_prefix: str = "brpatched", e9_exclude_ranges: str = "", e9_relocated_calls: str = "", total_patches: int = 1, fuzzy: bool = False, reverse_directed: bool = False, disable_binradar: bool = False, less_strict: bool = False):
        self.workdir = os.path.abspath(workdir)
        self.outdir = os.path.abspath(outdir)
        self.timeout = timeout
        self.binary = binary
        self.poc_input = poc_input
        self.total_patches = total_patches
        self.fuzzy = fuzzy
        self.reverse_directed = reverse_directed
        self.disable_binradar = disable_binradar
        self.less_strict = less_strict
        self.binradar_failed = False
        self.concrete_evidence_timed_out = False
        self.phase_failures = {}
        self.phase_failure_lock = threading.Lock()
        self.test_cmd = test_cmd
        self.patch_loc = patch_loc
        self.e9_metadata_prefix = e9_metadata_prefix
        self.e9_exclude_ranges = e9_exclude_ranges
        self.e9_relocated_calls = e9_relocated_calls
        self.filter_result = list(range(1, total_patches + 1))

        self.libc = ctypes.CDLL("libc.so.6")

        os.makedirs(self.outdir, exist_ok=True)
        
        self.progress_filename = os.path.join(self.outdir, "progress.sbsv")
        self.previous_progress = None
        
        self.start_time = time.time()
        self.config = dict()
        self.set_base_config()
        
        self.probe_result = None
        
        self.run_dir = ""
        self.run_prefix = ""
        self.run_id = -1

    @staticmethod
    def from_workdir(workdir: str, outdir: Optional[str] = None, timeout: int = 3600) -> "BinRadarExecutor":
        env = binradar_utils.load_env(os.path.join(workdir, "binradar.env"))
        if outdir is not None:
            env["BINRADAR_OUTDIR"] = outdir
        else:
            env["BINRADAR_OUTDIR"] = os.path.join(workdir, "out")
        env["BINRADAR_TIMEOUT"] = str(timeout)
        return BinRadarExecutor.from_env(workdir, env)

    @staticmethod
    def from_env(workdir: str, env: Dict[str, str]) -> "BinRadarExecutor":
        prefix = env.get("E9_METADATA_PREFIX", "brpatched")
        e9_exclude_ranges, e9_relocated_calls = \
            binradar_utils.get_e9_metadata(env, prefix)
        binradar = BinRadarExecutor(
            workdir=workdir,
            outdir=env["BINRADAR_OUTDIR"],
            timeout=int(env["BINRADAR_TIMEOUT"]),
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            test_cmd=env["TEST_CMD"],
            patch_loc=env["PATCH_LOC"],
            e9_metadata_prefix=prefix,
            e9_exclude_ranges=e9_exclude_ranges,
            e9_relocated_calls=e9_relocated_calls,
            total_patches=int(env["TOTAL_PATCHES"]),
            fuzzy=env.get("BINRADAR_FUZZY", "0") == "1",
            reverse_directed=env.get("BINRADAR_REVERSE_DIRECTED", "0") == "1",
            disable_binradar=env.get("BINRADAR_DISABLE_BINRADAR", "0") == "1",
            less_strict=env.get("BINRADAR_LESS_STRICT", "0") == "1")
        # Retain every artifact's prefixed E9 metadata so extract_config
        # passes all of it to BinRadarQemuRunner.from_env, which selects
        # by the executed binary path.
        for artifact in binradar_utils.E9_METADATA_PREFIXES:
            ranges_key, calls_key = binradar_utils.e9_metadata_keys(artifact)
            if ranges_key in env:
                binradar.config[ranges_key] = env[ranges_key]
            if calls_key in env:
                binradar.config[calls_key] = env[calls_key]
        for key in ("BINRADAR_PATCH_KIND", "BRCACHE_STACK_SIZE",
                    "BINRADAR_AFL_EXEC_TIMEOUT"):
            if key in env:
                binradar.config[key] = env[key]
        return binradar

    def extract_config(self) -> Dict[str, str]:
        config = self.config.copy()
        config["BINRADAR_OUTDIR"] = self.outdir
        config["BINRADAR_TIMEOUT"] = str(self.timeout)
        config["BINARY"] = self.binary
        config["POC_INPUT"] = self.poc_input
        config["TEST_CMD"] = self.test_cmd
        config["PATCH_LOC"] = self.patch_loc
        config["E9_METADATA_PREFIX"] = self.e9_metadata_prefix
        # Re-emit the selected artifact's prefixed keys so downstream
        # BinRadarQemuRunner.from_env selects the same artifact.
        binradar_utils.set_e9_metadata(
            config, self.e9_metadata_prefix,
            self.e9_exclude_ranges, self.e9_relocated_calls)
        config["TOTAL_PATCHES"] = str(self.total_patches)
        return config

    def elapsed_time_ms(self) -> int:
        return int((time.time() - self.start_time) * 1000)

    def _record_tolerated_phase_failure(
            self, phase: str, exc: BaseException) -> None:
        """Record an optional evidence phase that failed under --less-strict.

        Required phases (probe, filter, minimizer, verifier, and final) never
        call this helper. Keeping the failure separate from a successful
        ``[phase] [done]`` marker prevents a degraded run from masquerading as
        a complete run in progress logs.
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
            if not getattr(self, "less_strict", False):
                raise
            self._record_tolerated_phase_failure(phase, exc)
            return False

    def failed_phase_names(self) -> List[str]:
        lock = getattr(self, "phase_failure_lock", None)
        if lock is None:
            return []
        with lock:
            return sorted(self.phase_failures)

    def _record_concrete_evidence_timeout(self, phases: List[str]) -> None:
        """Mark a planned concrete-evidence cutoff as degraded, not fatal."""
        if not hasattr(self, "phase_failure_lock"):
            # Some unit tests construct executors with __new__.
            self.phase_failure_lock = threading.Lock()
            self.phase_failures = {}
        self.concrete_evidence_timed_out = True
        with self.phase_failure_lock:
            self.phase_failures["minimizer-verifier"] = (
                "wall-clock evidence budget reached")
        logger.warning(
            "[MINIMIZER/VERIFIER] Wall-clock budget reached; finalizing "
            "verdicts and confidence from the evidence collected so far.")
        for phase in phases:
            self.save_progress(
                f"[{phase}] [timeout] [prefix {self.run_prefix}] "
                f"[id {self.run_id}]")

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
        plt_result = binradar_utils.execute([FIND_MODELS_BIN, "-o", plt_info, self.original_binary()])
        if not plt_result.success:
            logger.warning("Failed to find PLT info. PLT-based optimizations will be disabled.")
            sys.exit(plt_result.exit_code)
        return plt_info

    def original_binary(self) -> str:
        return os.path.join(self.workdir, f"{self.binary}.orig")

    def patched_binary(self) -> str:
        return os.path.join(self.workdir, f"{self.binary}.brpatched")

    def cached_binary(self) -> str:
        return os.path.join(self.workdir, f"{self.binary}.brcached")

    def verifier_binary(self) -> str:
        """Binary the concrete verifier runs candidates on.

        With more than one surviving patch, the verifier executes one
        representative per distinct branch vector on the cached capture
        artifact (<binary>.brcached) and reuses the result for equivalent
        predicates; individual fallback runs still use .brpatched.  Without
        the cached artifact (or with a single patch) the verifier runs
        .brpatched directly.
        """
        if len(self.filter_result) > 1 and os.path.exists(self.cached_binary()):
            return self.cached_binary()
        return self.patched_binary()

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

    def set_config(self, key: str, value: str):
        self.config[key] = value
        logger.debug(f"Config updated: {key}={value}")
    
    def set_base_config(self):
        # Basic default config
        # TODO: implement stdin
        self.set_config("BINRADAR_TIMEOUT", str(self.timeout))
        self.set_config("SYMBOLIC_INJECT_INPUT_MODE", "FROM_FILE")
        testcase = self.resolved_poc_input()
        self.set_config("SYMBOLIC_TESTCASE_NAME", testcase)
        if self.timeout > 0:
            self.set_config("SOLVER_TIMEOUT", str(int(self.timeout * 1000)))
        self.set_config("PLT_INFO_FILE", self.set_plt_info(os.path.join(self.outdir, "plt_info.txt")))
    
    def get_env(self, mode: str, run_dir: str) -> Dict[str, str]:
        env = os.environ.copy()
        env.update(self.config)
        if self.probe_result is None:
            raise RuntimeError("Probe result is not available. Cannot set environment for tracer and solver.")
        trace_file = os.path.join(run_dir, f"{mode}-tracer-trace.log")
        log_file = os.path.join(run_dir, f"{mode}-tracer-msg.log")
        if os.path.exists(log_file):
            open(log_file, "w").close()
        env["BINRADAR_TRACER_LOG_FILE"] = log_file
        # Tracer
        env["E9_EXCLUDE_RANGES"] = self.e9_exclude_ranges
        # E9Patch relocated call records (jump:site:return, comma separated).
        # Every patched symbolic tracer mode needs these to reinterpret E9's
        # push original_return; jmp target sequence as the original call.
        env["E9_RELOCATED_CALL_JUMPS"] = self.e9_relocated_calls
        if mode == "fuzzolic":
            env["BINRADAR_PROBE_FILE"] = os.path.join(run_dir, "probe-result-fuzzolic.sbsv")
            env["BINRADAR_FORKSERVER_ENABLE"] = "0"
            env["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = "0"
            env["BINRADAR_TRACE_FILE"] = "none"
        elif mode in ["directed", "binradar"]:
            env["BINRADAR_FORKSERVER_ENABLE"] = "1"
            env["BINRADAR_FORKSERVER_CHILD_TIMEOUT"] = str(int(self.timeout))
            env["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = str(self.probe_result.patch_func_hit_cnt)
            if mode == "directed":
                env["BINRADAR_REVERSE_DIRECTED"] = "1" if self.reverse_directed else "0"
                env["BINRADAR_QUERY_WINDOW_FILE"] = os.path.join(run_dir, 'binradar-query-window.sbsv')
                env["BINRADAR_PRESERVE_CHILD_QUERIES"] = "1"
                env["BINRADAR_TRACE_FILE"] = "none"
            else:
                open(trace_file, "w").close()
                env["BINRADAR_TRACE_FILE"] = trace_file
                env["BINRADAR_PRESERVE_CHILD_QUERIES"] = "0"
                env["PATCH_ID"] = "123456"
                env["BINRADAR_PATCH_CNT"] = str(len(self.filter_result))
                filter_file = os.path.join(run_dir, "filter.sbsv")
                if os.path.exists(filter_file):
                    env["BINRADAR_PATCH_FILTER_FILE"] = filter_file
        return env
    
    def run_probe(self):
        if not os.path.exists(self.original_binary()):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(self.resolved_poc_input()):
            sys.exit("ERROR: input does not exist.")
        if os.path.exists(os.path.join(self.run_dir, "probe-results.sbsv")):
            self.probe_result = binradar_verifier.BinRadarProbeResult.from_sbsv(os.path.join(self.run_dir, "probe-results.sbsv"))
            if self.probe_result is not None:
                self.set_config("BINRADAR_ENTRYPOINT", hex(self.probe_result.patch_func_entry))
                logger.info(f"[PROBE] Loaded existing probe result: {self.probe_result.serialize()}")
                return
        config = self.extract_config()
        self.save_progress(f"[probe] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        probe_runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        probe_result = probe_runner.test_with_original(self.resolved_poc_input())
        if probe_result is None:
            logger.info("[PROBE] Failed to get probe result. Check if patch location is set or qemu_stacktrace is available.")
            sys.exit(1)
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
        tracer_cmd = [TRACER_BIN, self.original_binary()] + shlex.split(
            self.test_cmd.replace("@@", self.resolved_poc_input()))
        tracer_env = os.environ.copy()
        tracer_env["BINRADAR_FORKSERVER_ENABLE"] = "0"
        tracer_env["BINRADAR_TRACE_FILE"] = "none"
        # The original binary has no E9 mappings and no relocated calls.
        tracer_env["E9_EXCLUDE_RANGES"] = ""
        tracer_env["E9_RELOCATED_CALL_JUMPS"] = ""
        tracer_env["BINRADAR_MEMCHECK_ENABLE"] = "1"
        tracer_env["PLT_INFO_FILE"] = self.config.get("PLT_INFO_FILE", "")
        tracer_result = binradar_utils.execute(
            tracer_cmd, cwd=self.workdir, env=tracer_env, timeout=60.0, verbose=False)
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
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
    
    def load_filter_result(self, filter_result_file: str) -> List[int]:
        survived_patches: List[int] = list()
        with open(filter_result_file, encoding="utf-8") as f:
            parser = sbsv.parser()
            parser.add_schema("[patch] [id: int] [pass: bool]")
            rows = parser.load(f)
        for row in rows["patch"]:
            if row["pass"]:
                survived_patches.append(row["id"])
        return survived_patches

    def _load_cached_predicates(self, runner) -> Optional[Dict[int, binradar_verifier.ParsedPredicate]]:
        """Load the runtime predicate manifest for cached filter execution.

        Returns None when the cache is unavailable (single patch, missing
        manifest or .brcached, family mismatch, or missing CWE-805 stack
        size), so the filter falls back to individual executions.
        """
        if self.total_patches <= 1:
            return None
        manifest = os.path.join(self.workdir, "brpatches.json")
        if not os.path.exists(manifest) \
                or not os.path.exists(runner.cached_binary()):
            return None
        try:
            family, predicates = binradar_verifier.load_runtime_predicates(
                Path(manifest))
        except ValueError as e:
            logger.warning(f"[FILTER] Predicate cache disabled: {e}")
            return None
        if runner.patch_kind and runner.patch_kind != family.value:
            logger.warning(
                f"[FILTER] Predicate cache disabled: manifest family "
                f"{family.value} != configured family {runner.patch_kind}")
            return None
        missing = [patch for patch in range(1, self.total_patches + 1)
                   if patch not in predicates]
        if missing:
            logger.warning(
                f"[FILTER] Predicate cache disabled: missing runtime "
                f"patch ids {missing}")
            return None
        if family == binradar_verifier.PredicateFamily.CWE805_ERM \
                and runner.brcache_stack_size <= 0:
            logger.warning(
                "[FILTER] Predicate cache disabled: missing CWE-805 "
                "cache stack size")
            return None
        return predicates

    def _filter_decision(self, patch_id: int, result,
                         patch_result: Optional[binradar_verifier.BinRadarPatchResult],
                         f: TextIO) -> bool:
        """Evaluate one filter observation and write its [patch] row."""
        if result is None:
            logger.warning(
                f"[FILTER] [patch {patch_id}] Failed to run patched binary "
                f"with the poc input. Keeping the patch.")
            passed = True
        elif patch_result is not None and patch_result.crashed():
            passed = False
            logger.info(
                f"[FILTER] [patch {patch_id}] Patch itself crashed "
                f"(division/modulo by zero). Filtered out.")
        elif result.is_crash() and result.fault_addr == self.probe_result.fault_addr:
            passed = False
            logger.info(
                f"[FILTER] [patch {patch_id}] Still crashes at the original "
                f"fault address {result.fault_addr:#x}. Filtered out.")
        else:
            # Surviving patches are not logged individually: with many
            # candidates this floods the log; the [patch] rows in filter.sbsv
            # and the [FILTER] [survived ...] summary cover them.
            passed = True
        f.write(f"[patch] [id {patch_id}] [pass {passed}]\n")
        return passed

    def _filter_patch(self, patch_id: int, runner,
                      testcase: str, f: TextIO) -> bool:
        """Run one candidate individually on .brpatched and evaluate it."""
        result, patch_result = runner.test_with_patched(
            str(patch_id), testcase)
        return self._filter_decision(patch_id, result, patch_result, f)

    def run_filter(self) -> List[int]:
        self.check_requirements()
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run filter.")
            raise RuntimeError("Probe result not found.")
        filter_result_file = os.path.join(self.run_dir, "filter.sbsv")
        if os.path.exists(filter_result_file):
            try:
                survived_patches = self.load_filter_result(filter_result_file)
            except Exception:
                logger.warning("[FILTER] Failed to load the existing filter result. Re-running the filter phase.")
            else:
                logger.info(f"[FILTER] Loaded existing filter result: {survived_patches}")
                self.filter_result = survived_patches
                return survived_patches
        exec_mode = "filter"
        self.save_progress(f"[filter] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        config = self.extract_config()
        runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        testcase = self.resolved_poc_input()
        survived_patches: List[int] = list()
        with open(filter_result_file, "w", encoding="utf-8") as f:
            cached_predicates = self._load_cached_predicates(runner)
            if cached_predicates is None:
                for patch_id in range(1, self.total_patches + 1):
                    if self._filter_patch(patch_id, runner, testcase, f):
                        survived_patches.append(patch_id)
            else:
                # Cached execution: run one representative per distinct
                # complete branch vector on .brcached and reuse its process
                # result for every predicate with the same vector.
                remaining = list(range(1, self.total_patches + 1))
                while remaining:
                    representative = remaining.pop(0)
                    logger.info(
                        f"[FILTER] [cache-run] [patch {representative}]")
                    result, cached = runner.test_with_cached(
                        representative, cached_predicates[representative],
                        testcase)
                    if result is None or cached is None:
                        logger.warning(
                            f"[FILTER] [patch {representative}] Cached run "
                            f"failed; falling back to individual execution.")
                        if self._filter_patch(
                                representative, runner, testcase, f):
                            survived_patches.append(representative)
                        continue
                    observed = cached.br_selection
                    try:
                        evaluated = binradar_verifier.evaluate_cached_predicate(
                            cached_predicates[representative],
                            cached.snapshots)
                    except (IndexError, ValueError) as e:
                        logger.warning(
                            f"[FILTER] [patch {representative}] Predicate "
                            f"evaluation failed ({e}); falling back to "
                            f"individual execution.")
                        evaluated = None
                    if evaluated is None or evaluated != observed:
                        logger.warning(
                            f"[FILTER] [patch {representative}] Cached "
                            f"branch vector mismatch; falling back to "
                            f"individual execution.")
                        if self._filter_patch(
                                representative, runner, testcase, f):
                            survived_patches.append(representative)
                        continue
                    # Reuse the representative's result for every predicate
                    # with the same complete branch vector.
                    equivalent = [representative]
                    for patch in remaining:
                        try:
                            branches = binradar_verifier.evaluate_cached_predicate(
                                cached_predicates[patch], cached.snapshots)
                        except (IndexError, ValueError):
                            branches = None
                        if branches is not None and branches == observed:
                            equivalent.append(patch)
                    reused = equivalent[1:]
                    for patch in reused:
                        remaining.remove(patch)
                    if reused:
                        logger.info(
                            f"[FILTER] [cache-reuse] [representative "
                            f"{representative}] [patches {reused}]")
                    for patch in equivalent:
                        if self._filter_decision(
                                patch, result,
                                binradar_verifier.BinRadarPatchResult(
                                    patch, observed), f):
                            survived_patches.append(patch)
        logger.info(
            f"[FILTER] [summary] [total {self.total_patches}] "
            f"[survived {len(survived_patches)}] "
            f"[filtered {self.total_patches - len(survived_patches)}]")
        logger.info(f"[FILTER] [survived {survived_patches}]")
        self.save_progress(f"[filter] [done] [prefix {self.run_prefix}] [id {self.run_id}] [survived {survived_patches}]")
        self.filter_result = survived_patches
        return survived_patches

    def check_requirements(self):
        if not os.path.exists(self.original_binary()):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(self.patched_binary()):
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
    
    def run_fuzzolic(self):
        testcase = self.resolved_poc_input()
        self.check_requirements()
        
        exec_mode = "fuzzolic"
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[fuzzolic] [start] [prefix {self.run_prefix}] [id {self.run_id}]")

        fuzzolic_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(fuzzolic_env)
        shm.assign_random_keys()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, fuzzolic_env, self.workdir, timeout=self.timeout, fuzzy=self.fuzzy)
        tracer = TracerExecutor(exec_mode, fuzzolic_env, self.workdir, self.run_dir, self.original_binary(), self.test_cmd, testcase, timeout=self.timeout)
        
        try:
            solver.start()
            tracer.start()
            tracer_time, tracer_success, _ = tracer.run()
            self.save_progress(f"[fuzzolic] [tracer] [prefix {self.run_prefix}] [id {self.run_id}] [tracer-time {tracer_time}] [tracer-success {tracer_success}]")
            if not tracer_success:
                raise RuntimeError("Fuzzolic tracer timed out or failed")
            solver.create_inputs()
            solver_time, solver_success = solver.wait()
            self.save_progress(f"[fuzzolic] [solver] [prefix {self.run_prefix}] [id {self.run_id}] [solver-time {solver_time}] [solver-success {solver_success}]")
            if not solver_success:
                raise RuntimeError(
                    f"Fuzzolic solver timed out or exited with status "
                    f"{solver.process.returncode if solver.process else 'unknown'}")
            tracer.stop()
            solver.stop()
        except Exception as e:
            logger.error(f"Error during fuzzolic execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()
        
        self.save_progress(f"[fuzzolic] [done] [prefix {self.run_prefix}] [id {self.run_id}]")
    
    def run_directed(self):
        testcase = self.resolved_poc_input()
        self.check_requirements()
        
        exec_mode = "directed"
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[directed] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        
        directed_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(directed_env)
        shm.assign_random_keys()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, directed_env, self.workdir, timeout=self.timeout, fuzzy=self.fuzzy, reverse_directed=self.reverse_directed)
        tracer = TracerExecutor(exec_mode, directed_env, self.workdir, self.run_dir, self.original_binary(), self.test_cmd, testcase, timeout=self.timeout)
        try:
            solver.start()
            tracer.start()
            tracer_time, tracer_success, _ = tracer.run()
            self.save_progress(f"[directed] [tracer] [prefix {self.run_prefix}] [id {self.run_id}] [tracer-time {tracer_time}] [tracer-success {tracer_success}]")
            if not tracer_success:
                raise RuntimeError("Directed tracer timed out or failed")
            solver.create_inputs()
            solver_time, solver_success = solver.wait()
            self.save_progress(f"[directed] [solver] [prefix {self.run_prefix}] [id {self.run_id}] [solver-time {solver_time}] [solver-success {solver_success}]")
            if not solver_success:
                raise RuntimeError(
                    f"Directed solver timed out or exited with status "
                    f"{solver.process.returncode if solver.process else 'unknown'}")
            tracer.stop()
            solver.stop()
        except Exception as e:
            logger.error(f"Error during directed execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()

        self.save_progress(f"[directed] [done] [prefix {self.run_prefix}] [id {self.run_id}]")
    
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
        config = self.extract_config()
        fuzzer_outdir = self.fuzzer_outdir()
        if not getattr(self, "_fuzzer_output_prepared", False):
            self.prepare_fuzzer_output()
        self._fuzzer_output_prepared = False
        fuzzer = binradar_fuzzer.AFLppFuzzer.from_env(
            self.workdir, fuzzer_outdir, config)
        fuzzer.start()
        if fuzzer.process is None:
            raise RuntimeError("Failed to start fuzzer process")
        with RUNNING_PROCESSES_LOCK:
            RUNNING_PROCESSES.append(fuzzer.process)
        try:
            result = fuzzer.wait(timeout=self.timeout)
        finally:
            with RUNNING_PROCESSES_LOCK:
                if fuzzer.process in RUNNING_PROCESSES:
                    RUNNING_PROCESSES.remove(fuzzer.process)
        if result is None:
            raise RuntimeError("Fuzzer process was not started")
        if result.timed_out:
            # AFL++ intentionally runs until the phase deadline. execute_await
            # terminates the process group and waits for it to exit.
            logger.info("Fuzzer reached its configured phase timeout.")
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
        config = self.extract_config()
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
            timeout=self.minimizer_verifier_timeout())
        if timed_out:
            self._record_concrete_evidence_timeout(["minimizer"])
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
        
        config = self.extract_config()
        self.save_progress(f"[verifier] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        # Implementation for concrete verifier
        runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        logger.info(f"[VERIFIER] Verifying patches: {self.filter_result}")
        verifier = binradar_verifier.BinRadarConcreteVerifier(self.workdir, self.run_dir, runner, self.probe_result, self.verifier_binary(), self.filter_result)
        timed_out = verifier.run_verification_streaming(
            minimizer_result_file,
            timeout=self.minimizer_verifier_timeout())
        if timed_out:
            self._record_concrete_evidence_timeout(["verifier"])
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
        config = self.extract_config()
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
        logger.info(f"[VERIFIER] Verifying patches: {self.filter_result}")
        verifier = binradar_verifier.BinRadarConcreteVerifier(self.workdir, self.run_dir, runner, self.probe_result, self.verifier_binary(), self.filter_result)
        minimizer_result_file = os.path.join(self.run_dir, "minimizer.sbsv")
        timed_out = binradar_minimizer.run_minimizer_and_verifier(
            minimizer, verifier, minimizer_result_file,
            producer_threads=producer_threads,
            producer_exc_queue=producer_exc_queue,
            timeout=self.minimizer_verifier_timeout())
        if timed_out:
            self._record_concrete_evidence_timeout(
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
        
        exec_mode = "binradar"
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[binradar] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        
        binradar_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(binradar_env)
        shm.assign_random_keys()
        shm.assign_random_key_for_binradar()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, binradar_env, self.workdir, timeout=self.timeout, fuzzy=self.fuzzy)
        tracer = TracerExecutor(exec_mode, binradar_env, self.workdir, self.run_dir, self.patched_binary(), self.test_cmd, testcase, timeout=self.timeout)
        
        try:
            solver.start()
            tracer.start()
            remaining = 1
            while remaining > 0:
                if time.time() - self.start_time > self.timeout:
                    logger.info(f"[BINRADAR] [id {self.run_id}] Timeout reached. Stopping binradar execution.")
                    break
                tracer_time, tracer_success, remaining = tracer.run()
                message = (f"[binradar] [tracer] [iter {tracer.iter}] "
                           f"[time {tracer_time}] [remaining {remaining}]")
                if tracer_success:
                    logger.debug(message)
                else:
                    logger.warning(message + " [failed true]")
            # TODO: currently, we don't utilize collected constraints
            tracer.stop()
            solver.stop()
        except Exception as e:
            logger.error(f"Error during binradar execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()

        self.save_progress(f"[binradar] [done] [prefix {self.run_prefix}] [id {self.run_id}]")
    
    def run_final(self):
        # Read verifier.sbsv and, when enabled, binradar-trace-msg.log to
        # get final results and save them to the progress file.
        if self.probe_result is None:
            logger.error("Probe result not found. Cannot run final analysis.")
            raise RuntimeError("Probe result not found.")
        verifier_result_file = os.path.join(self.run_dir, "verifier.sbsv")
        trace_msg_log_file = os.path.join(self.run_dir, "binradar-tracer-msg.log")
        self.save_progress(f"[final] [start] [prefix {self.run_prefix}] [id {self.run_id}]")
        if not os.path.exists(verifier_result_file):
            logger.error("Verifier result file not found. BinRadar results might be incomplete.")
            raise FileNotFoundError(f"Verifier result file not found: {verifier_result_file}")
        remaining_patches = set(self.filter_result)
        concrete_verifier_result = binradar_verifier.BinRadarConcreteVerifierResult.from_sbsv(verifier_result_file)
        if concrete_verifier_result is None:
            logger.error("Failed to parse verifier result. BinRadar results might be incomplete.")
            raise ValueError("Failed to parse verifier result.")
        if (concrete_verifier_result.stop_reason == "timeout"
                and not getattr(self, "concrete_evidence_timed_out", False)):
            # Preserve the degraded marker when FINAL is resumed in a fresh
            # process after graceful timeout finalization already produced a
            # complete verifier result file.
            self._record_concrete_evidence_timeout([])
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

        binradar_failed = getattr(self, "binradar_failed", False)
        skip_binradar_analysis = self.disable_binradar or binradar_failed
        if self.disable_binradar:
            logger.info("[FINAL] BinRadar phase disabled; skipping trace analysis.")
            trace_file = io.StringIO()
        elif binradar_failed:
            logger.warning(
                "[FINAL] BinRadar phase failed under --less-strict; ignoring "
                "its potentially incomplete trace and using concrete "
                "verifier evidence only.")
            trace_file = io.StringIO()
        else:
            if not os.path.exists(trace_msg_log_file):
                logger.error("Trace message log file not found. BinRadar results might be incomplete.")
                raise FileNotFoundError(f"Trace message log file not found: {trace_msg_log_file}")
            trace_file = open(trace_msg_log_file, "r", encoding="utf-8")
        for patch_id in self.filter_result:
            if not concrete_verifier_result.patch_verified[patch_id]:
                remaining_patches.discard(patch_id)
        binradar_remaining_patches = remaining_patches.copy()
        binradar_reject_reasons: Dict[int, Tuple[str, int]] = dict()
        with trace_file as f:
            parser = sbsv.parser()
            parser.add_custom_type("hex", lambda x: int(x, 16))
            parser.add_schema("[binradar] [crash] [iter: int] [patch: int] [guest_pc: hex] [guest_cs_base: hex] [fault_addr: hex] [host_fault_addr: hex]")
            parser.add_schema("[binradar] [normal] [iter: int] [patch: int]")
            parser.add_schema("[binradar] [commit] [iter: int] [patch: int] [br: str]")
            iter_map: Dict[int, Dict[int, dict]] = dict()
            for line in f:
                result = parser.parse_line_detached(line)
                if result is None:
                    continue
                iter = result["iter"]
                patch = result["patch"]
                if iter not in iter_map:
                    iter_map[iter] = dict()
                if patch not in iter_map[iter]:
                    iter_map[iter][patch] = dict()
                current = iter_map[iter][patch]
                if result.schema_name == "binradar$crash":
                    current["result"] = "crash"
                    current["fault_addr"] = result["fault_addr"]
                elif result.schema_name == "binradar$normal":
                    current["result"] = "normal"
                elif result.schema_name == "binradar$commit":
                    current["br"] = result["br"]
            
            poc_fault_loc = (0 if skip_binradar_analysis
                             else self.probe_result.tracer_fault_addr)
            if not skip_binradar_analysis and poc_fault_loc == 0:
                logger.warning("[FINAL] tracer_fault_addr is 0; binradar crash comparison will not match any fault address.")

            for iter in iter_map:
                original = iter_map[iter][0]
                if original is None:
                    continue
                if "result" not in original or "br" not in original:
                    continue
                if original["br"] == "null":
                    continue
                for patch in remaining_patches:
                    patch_result = iter_map[iter].get(patch, None)
                    if patch_result is None:
                        continue
                    if "result" not in patch_result or "br" not in patch_result:
                        continue
                    if original["result"] == "crash" and patch_result["result"] == "crash":
                        if original["fault_addr"] == poc_fault_loc and patch_result["fault_addr"] == poc_fault_loc:
                            record_evidence(patch, False)
                            if patch in binradar_remaining_patches:
                                logger.info(f"[final] [binradar] [patch {patch}] [iter {iter}] still causes the same crash - likely not fixed.")
                            binradar_remaining_patches.discard(patch)
                            binradar_reject_reasons[patch] = ("same-crash", iter)
                    elif original["result"] == "crash" and patch_result["result"] == "normal":
                        record_evidence(patch, True)
                    elif original["result"] == "normal" and patch_result["result"] == "crash":
                        if patch_result["fault_addr"] == poc_fault_loc:
                            record_evidence(patch, False)
                            if patch in binradar_remaining_patches:
                                logger.info(f"[final] [binradar] [patch {patch}] [iter {iter}] introduces a crash - likely not fixed.")
                            binradar_remaining_patches.discard(patch)
                            binradar_reject_reasons[patch] = ("introduced-crash", iter)
                    elif original["result"] == "normal" and patch_result["result"] == "normal":
                        same_behavior = original["br"] == patch_result["br"]
                        record_evidence(patch, same_behavior)
                        if not same_behavior:
                            logger.info(f"[final] [binradar] [patch {patch}] [iter {iter}] causes a different behavior (BR {patch_result['br']} vs original {original['br']}); reducing confidence without rejecting the patch.")
        failed_phases = self.failed_phase_names()
        degraded_suffix = (
            f" [degraded true] [failed-phases {','.join(failed_phases)}]"
            if failed_phases else " [degraded false] [failed-phases none]")
        if failed_phases:
            self.save_progress(
                f"[final] [degraded] [prefix {self.run_prefix}] "
                f"[id {self.run_id}] "
                f"[failed-phases {','.join(failed_phases)}]")
        self.save_progress(f"[final] [done] [prefix {self.run_prefix}] [id {self.run_id}] [remaining_patches {sorted(remaining_patches)}] [binradar_remaining_patches {sorted(binradar_remaining_patches)}]{degraded_suffix}")

        # Write a self-contained final.sbsv with per-patch verdicts from the
        # concrete verifier and, when enabled, the binradar analysis.
        final_result_file = os.path.join(self.run_dir, "final.sbsv")
        if self.disable_binradar:
            trace_metadata = "[binradar disabled]"
        elif binradar_failed:
            trace_metadata = "[binradar failed]"
        else:
            trace_metadata = f"[trace {os.path.basename(trace_msg_log_file)}]"
        with open(final_result_file, "w", encoding="utf-8") as f:
            f.write(f"[final] [start] [prefix {self.run_prefix}] [id {self.run_id}] "
                    f"[verifier {os.path.basename(verifier_result_file)}] "
                    f"{trace_metadata}\n")
            if failed_phases:
                f.write(f"[final] [degraded] [prefix {self.run_prefix}] "
                        f"[id {self.run_id}] "
                        f"[failed-phases {','.join(failed_phases)}]\n")
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
                    f"{degraded_suffix}\n")
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
                        and getattr(self, "less_strict", False)
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
            stop_running_processes()
            for thread in producer_threads:
                thread.join(timeout=60)
            raise

        for thread in producer_threads:
            thread.join()
        if not thread_errors.empty():
            _, exc, tb = thread_errors.get()
            stop_running_processes()
            if tb is not None:
                raise exc.with_traceback(tb)
            raise exc

    def run_fuzzer_only(self, run_prefix: str = "run"):
        """Run the AFL++ producer and concrete verification pipeline only.

        PROBE and FILTER remain mandatory prerequisites. FUZZOLIC, DIRECTED,
        and BINRADAR are skipped; FINAL therefore uses concrete-verifier
        evidence only. AFL++, the streaming minimizer, and the verifier run
        concurrently.
        """
        self.disable_binradar = True
        self.set_run_dir(run_prefix=run_prefix)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.run_probe()
        survived_patches = self.run_filter()
        if len(survived_patches) == 0:
            logger.info("[BINRADAR] No patch survived the filter phase. Skipping the remaining phases.")
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
        self.run_final()
        self.done()

    def run_sequential(self, run_prefix: str = "run"):
        self.set_run_dir(run_prefix=run_prefix)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.run_probe()
        survived_patches = self.run_filter()
        if len(survived_patches) == 0:
            logger.info("[BINRADAR] No patch survived the filter phase. Skipping the remaining phases.")
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
        self.run_probe()
        if phase == BinRadarPhase.PROBE:
            return
        self.run_filter()
        if phase == BinRadarPhase.FILTER:
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
        else:
            raise ValueError(f"Unknown phase: {phase}")
        self.done()
    
    def run_multithreaded(self, run_prefix: str = "run"):
        self.set_run_dir(run_prefix=run_prefix)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.run_probe()

        survived_patches = self.run_filter()
        if len(survived_patches) == 0:
            logger.info("[BINRADAR] No patch survived the filter phase. Skipping the remaining phases.")
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
                    or not getattr(self, "less_strict", False)
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
            stop_running_processes()
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
            stop_running_processes()
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
                stop_running_processes()
                binradar_thread.join(timeout=10)
        raise_thread_error_if_any()
        self.run_final()
        self.done()

    
def main():
    setlimits()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

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
    parser.add_argument(
        "-f", "--fuzzy", action="store_true",
        help="use the Fuzzy-SAT solver")
    parser.add_argument(
        "--reverse-directed", type=bool, default=True,
        help="prioritize directed candidates from the end of the forward trace (Z3 only)")
    parser.add_argument("--disable-binradar", action="store_true",
        help="disable the binradar phase")
    parser.add_argument("--less-strict", action="store_true",
        help=("continue when optional evidence phases (fuzzolic, directed, "
              "fuzzer, or binradar) fail; final output is marked degraded"))
    parser.add_argument("--fuzzer-only", action="store_true",
        help=("run probe/filter, AFL++ fuzzer, minimizer/verifier, and final; "
              "skip fuzzolic, directed, and binradar"))
    parser.add_argument("--target-patches", choices=["top-30", "all"], default="top-30")
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
    if args.target_patches == "all":
        # Run every predicate that survived the offline prefilter instead of
        # the top-30 subset.  Setup caps the compiled candidates at the
        # top 30, so candidates past the cap are never compiled into the
        # binaries and cannot be run; clamp to the compiled set.
        pref_total = int(env.get("PREFILTER_TOTAL_PATCHES",
                                 env["TOTAL_PATCHES"]))
        if pref_total > int(env["TOTAL_PATCHES"]):
            logger.warning(
                f"--target-patches all: only the top "
                f"{env['TOTAL_PATCHES']} prefilter survivors are compiled "
                f"into the binaries (PREFILTER_TOTAL_PATCHES="
                f"{pref_total}); candidates past the compiled cap cannot "
                f"be run")
        env["TOTAL_PATCHES"] = str(pref_total)
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
