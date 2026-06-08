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
from typing import Dict, List, Tuple, Set, Optional, TextIO, BinaryIO

import analyze_type
import binradar_verifier
import binradar_fuzzer
import binradar_minimizer
import binradar_utils
import logger
import sbsv

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SOLVER_SMT_BIN = SCRIPT_DIR + "/../solver/build/solver-smt"
TRACER_BIN = SCRIPT_DIR + "/../tracer/build/x86_64-linux-user/qemu-x86_64"
FIND_MODELS_BIN = SCRIPT_DIR + "/find_models_addrs.py"

SOLVER_WAIT_TIME_AT_STARTUP = 1 # s
SOLVER_TIMEOUT = 10 # s

RUNNING_PROCESSES: List[subprocess.Popen] = []
RUNNING_PROCESSES_LOCK = threading.Lock()
MAX_VIRTUAL_MEMORY = 32 * 1024 * 1024 * 1024  # 32 GB
SHM_KEYS = ["EXPR_POOL_SHM_KEY", "QUERY_SHM_KEY", "BITMAP_SHM_KEY"]

# Tracer forkserver
HANDSHAKE_EXPECTED = 0x41464C00

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

    print("[BINRADAR] Aborting....")
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
                preexec_fn=setlimits,
                start_new_session=True)
            with RUNNING_PROCESSES_LOCK:
                RUNNING_PROCESSES.append(self.process)
            logger.info(f"[TRACER] Started tracer without forkserver mode. {' '.join(self.command)}")
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
            preexec_fn=setlimits, 
            start_new_session=True)
        
        with RUNNING_PROCESSES_LOCK:
            RUNNING_PROCESSES.append(self.process)
        self.pipe_manager.close_passed_fds()
        
        # Handshake with forkserver
        logger.info("[TRACER] Waiting for forkserver handshake...")
        banner = self._read_u32(self.timeout)
        if banner != HANDSHAKE_EXPECTED:
            raise RuntimeError(f"Unexpected forkserver handshake: {banner:#x}")
        self._write_u32(HANDSHAKE_EXPECTED ^ 0xFFFFFFFF)
        ack = self._read_u32(self.timeout)
        if ack != HANDSHAKE_EXPECTED:
            raise RuntimeError(f"Unexpected forkserver ack: {ack:#x}")
        logger.info("[TRACER] Tracer forkserver started successfully.")
        
    def run(self) -> Tuple[int, bool, int]: # synchronous run, wait for target binary to finish
        if self.process is None:
            raise RuntimeError("Tracer process not started")
        start_time = time.time()
        if not self.forkserver_mode:
            self.run_result = binradar_utils.execute_await(self.process, timeout=self.timeout)
            logger.info(f"[TRACER] Target process finished with exit code {self.run_result.decode_status()}, success {self.run_result.success}")
            return int((time.time() - start_time) * 1000), self.run_result.success, 0
        self._write_u32(0)  # was_killed - send run command to forkserver
        is_timeout = False
        try:
            exit_status, patch_id, iter = self._read_status(self.timeout)
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
                analyze_process.join(timeout=self.timeout)
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
            logger.debug(f"[TRACER] Target process patch {patch_id}, iter {iter}, finished with status {exit_status:#x}")
        except Exception as e:
            is_timeout = True
            logger.error(f"Error while waiting for tracer forkserver: {str(e)}")
            # Check if process died - print exit status
            if self.process.poll() is not None:
                logger.error(f"Tracer process exited with code {self.process.returncode}")
            else:
                logger.error("Tracer process is still running - sending SIGINT to stop it")
            self.process.send_signal(signal.SIGINT)
            self.process.wait()
            raise e
        analyze_result_size = len(analyze_result)
        if analyze_result_size > 0xFFFFFFFF:
            raise ValueError("Analyze result too large")
        self._write_u32(len(analyze_result))
        self._write(analyze_result)
        remaining = self._read_u32(self.timeout)
        return int((time.time() - start_time) * 1000), (not is_timeout), remaining
    
    def stop(self):
        if self.pipe_manager is not None:
            self.pipe_manager.cleanup()
        if self.process is not None:
            logger.info("[TRACER] Stopping tracer process...")
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
            raise RuntimeError("Pipe manager not initialized")
        total_written = 0
        while total_written < len(data):
            try:
                written = os.write(self.pipe_manager.get_ctrl_w(), data[total_written:])
                total_written += written
            except BrokenPipeError:
                raise RuntimeError("Tracer forkserver pipe is broken")
            except BlockingIOError:
                continue
    
    def _read_u32(self, timeout: float) -> int:
        if self.pipe_manager is None:
            raise RuntimeError("Pipe manager not initialized")
        rlist, _, _ = select.select([self.pipe_manager.get_stat_r()], [], [], timeout)
        if not rlist:
            raise TimeoutError("Timeout while waiting for forkserver response")
        data = self._read(4)
        if len(data) < 4:
            raise EOFError("Failed to read 4 bytes from forkserver")
        return struct.unpack("<I", data)[0]
    
    def _read_status(self, timeout: float) -> Tuple[int, int, int]:
        if self.pipe_manager is None:
            raise RuntimeError("Pipe manager not initialized")
        rlist, _, _ = select.select([self.pipe_manager.get_stat_r()], [], [], timeout)
        if not rlist:
            raise TimeoutError("Timeout while waiting for forkserver response")
        data = self._read(12)
        if len(data) < 12:
            raise EOFError("Failed to read 12 bytes from forkserver")
        return struct.unpack("<III", data)
    
    def _read(self, size: int) -> bytes:
        if self.pipe_manager is None:
            raise RuntimeError("Pipe manager not initialized")
        data = b''
        while len(data) < size:
            try:
                chunk = os.read(self.pipe_manager.get_stat_r(), size - len(data))
                if not chunk:
                    raise EOFError("EOF while reading from forkserver")
                data += chunk
            except BlockingIOError:
                continue
        return data

class SolverExecutor:
    command: List[str]
    out_dir: str
    env: Dict[str, str]
    workdir: str
    rundir: str
    log_fp: BinaryIO
    process: Optional[subprocess.Popen]
    timeout: float
    run_result: Optional[binradar_utils.ExecutionResult]
    def __init__(self, mode: str, testcase: str, run_dir: str, env: Dict[str, str], workdir: str, timeout: float):
        global_bitmap = os.path.join(run_dir, f"{mode}-branch-bitmap")
        context_bitmap = os.path.join(run_dir, f"{mode}-context-bitmap")
        memory_bitmap = os.path.join(run_dir, f"{mode}-memory-bitmap")
        self.out_dir = os.path.join(run_dir, f"{mode}-tests")
        os.makedirs(self.out_dir, exist_ok=True)
        for bitmap in [global_bitmap, context_bitmap, memory_bitmap]:
            with open(bitmap, "w") as f:
                pass
        self.command = ["stdbuf", "-o0", SOLVER_SMT_BIN, 
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
        logger.info(f"[SOLVER] Starting solver with command: {' '.join(self.command)}")
        logger.debug(f"[SOLVER] timeout set to {self.timeout} seconds")
        self.process = subprocess.Popen(
            self.command,
            stdout=self.log_fp,
            stderr=subprocess.STDOUT,
            cwd=self.rundir,
            env=self.env,
            preexec_fn=setlimits, 
            start_new_session=True)
        with RUNNING_PROCESSES_LOCK:
            RUNNING_PROCESSES.append(self.process)
        # Give the solver some time to start up and create shared memories
        time.sleep(SOLVER_WAIT_TIME_AT_STARTUP)
    
    def create_inputs(self):
        if self.process is None:
            raise RuntimeError("Solver process not started")
        logger.info("[SOLVER] Sending signal to create inputs...")
        self.process.send_signal(signal.SIGUSR1)
    
    def wait(self) -> Tuple[int, bool]:
        if self.process is None:
            raise RuntimeError("Solver process not started - cannot wait")
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
            logger.info("[SOLVER] Solver is taking too long. Let us stop it.")
            self.process.send_signal(signal.SIGUSR2)
            try:
                self.process.wait(SOLVER_TIMEOUT)
            except subprocess.TimeoutExpired:
                logger.info("[SOLVER] Solver will be killed.")
                binradar_utils.execute_await(self.process, timeout=1)
        return int((time.time() - start_time) * 1000), (not is_timeout)

    def stop(self):
        if self.process:
            logger.info("[SOLVER] Stopping solver process...")
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
    def from_progress_file(file: str) -> Optional["BinRadarProgress"]:
        if not os.path.exists(file):
            return None
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[rundir] [set] [id: int] [dir: str]")
        parser.add_schema("[rundir] [done] [id: int] [dir: str]")
        parser.add_schema("[probe] [done] [id: int]")
        parser.add_schema("[fuzzolic] [done] [id: int]")
        parser.add_schema("[directed] [done] [id: int]")
        parser.add_schema("[fuzzer] [done] [id: int]")
        parser.add_schema("[minimizer] [done] [id: int]")
        parser.add_schema("[verifier] [done] [id: int]")
        with open(file, "r", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            parser.load(f)
            fcntl.flock(f, fcntl.LOCK_UN)
        rundir_log = parser.get_result()["rundir"]["set"]
        if len(rundir_log) == 0:
            return None
        run_id = 0
        run_dir = ""
        for item in rundir_log:
            if item["id"] > run_id:
                run_id = int(item["id"])
                run_dir = item["dir"]
        
        probe_done = False
        fuzzolic_done = False
        directed_done = False
        fuzzer_done = False
        minimizer_done = False
        verifier_done = False
        done = False
        for probe in parser.get_result()["probe"]["done"]:
            if int(probe["id"]) == run_id:
                probe_done = True
                break
        for fuzzolic in parser.get_result()["fuzzolic"]["done"]:
            if int(fuzzolic["id"]) == run_id:
                fuzzolic_done = True
                break
        for directed in parser.get_result()["directed"]["done"]:
            if int(directed["id"]) == run_id:
                directed_done = True
                break
        for fuzzer in parser.get_result()["fuzzer"]["done"]:
            if int(fuzzer["id"]) == run_id:
                fuzzer_done = True
                break
        for done_item in parser.get_result()["rundir"]["done"]:
            if int(done_item["id"]) == run_id:
                done = True
                break
        for minimizer in parser.get_result()["minimizer"]["done"]:
            if int(minimizer["id"]) == run_id:
                minimizer_done = True
                break
        for verifier in parser.get_result()["verifier"]["done"]:
            if int(verifier["id"]) == run_id:
                verifier_done = True
                break
        return BinRadarProgress(run_id, run_dir, probe_done, fuzzolic_done, directed_done, fuzzer_done, minimizer_done, verifier_done, done)

class BinRadarExecutor:
    # Config from config.env and command line arguments
    workdir: str
    outdir: str
    timeout: int
    binary: str
    poc_input: str
    test_cmd: str
    patch_loc: str
    total_patches: int
    # Data
    config: Dict[str, str]
    progress_filename: str
    previous_progress: Optional[BinRadarProgress]
    run_id: int
    run_dir: str
    probe_result: Optional[binradar_verifier.BinRadarProbeResult]
    start_time: float
    def __init__(self, workdir: str, outdir: str, timeout: int, binary: str, poc_input: str, test_cmd: str, patch_loc: str, total_patches: int):
        self.workdir = os.path.abspath(workdir)
        self.outdir = os.path.abspath(outdir)
        self.timeout = timeout
        self.binary = binary
        self.poc_input = poc_input
        self.total_patches = total_patches
        self.test_cmd = test_cmd
        self.patch_loc = patch_loc

        self.libc = ctypes.CDLL("libc.so.6")

        os.makedirs(self.outdir, exist_ok=True)
        
        self.progress_filename = os.path.join(self.outdir, "progress.sbsv")
        self.previous_progress = BinRadarProgress.from_progress_file(self.progress_filename)
        
        self.start_time = time.time()
        self.config = dict()
        self.set_base_config()
        
        self.probe_result = None
        
        self.run_dir = ""
        self.run_id = -1

    @staticmethod
    def from_workdir(workdir: str) -> "BinRadarExecutor":
        env = binradar_utils.load_env(os.path.join(workdir, "config.env"))
        return BinRadarExecutor.from_env(workdir, env)

    @staticmethod
    def from_env(workdir: str, env: Dict[str, str]) -> "BinRadarExecutor":
        binradar = BinRadarExecutor(
            workdir=workdir,
            outdir=env["BINRADAR_OUTDIR"],
            timeout=int(env["BINRADAR_TIMEOUT"]),
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            test_cmd=env["TEST_CMD"],
            patch_loc=env["PATCH_LOC"],
            total_patches=int(env["TOTAL_PATCHES"]))
        return binradar
    
    def extract_config(self) -> Dict[str, str]:
        config = self.config.copy()
        config["BINRADAR_OUTDIR"] = self.outdir
        config["BINRADAR_TIMEOUT"] = str(self.timeout)
        config["BINARY"] = self.binary
        config["POC_INPUT"] = self.poc_input
        config["TEST_CMD"] = self.test_cmd
        config["PATCH_LOC"] = self.patch_loc
        config["TOTAL_PATCHES"] = str(self.total_patches)
        return config

    def elapsed_time_ms(self) -> int:
        return int((time.time() - self.start_time) * 1000)

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
        return os.path.join(self.workdir, f"{self.binary}.patched")

    def resolved_poc_input(self) -> str:
        if os.path.isabs(self.poc_input):
            return self.poc_input
        return os.path.join(self.workdir, self.poc_input)

    def set_run_dir(self, resume_phase: BinRadarPhase = BinRadarPhase.ALL):
        run_id = 0
        # Currently, start a new run if the previous run exists.
        # Can resume in more fine-grained way if needed.
        if self.previous_progress is not None:
            run_id = self.previous_progress.run_id
            if resume_phase == BinRadarPhase.ALL:
                run_id += 1
        run_dir = os.path.join(self.outdir, f"run-{run_id:05d}")
        os.makedirs(run_dir, exist_ok=True)
        self.save_progress(f"[rundir] [set] [id {run_id}] [dir {run_dir}]")
        self.run_id = run_id
        self.run_dir = run_dir

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
        if mode == "fuzzolic":
            env["BINRADAR_PROBE_FILE"] = os.path.join(run_dir, "probe-result-fuzzolic.sbsv")
            env["BINRADAR_FORKSERVER_ENABLE"] = "0"
            env["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = "0"
            env["BINRADAR_TRACE_FILE"] = "none"
        elif mode in ["directed", "binradar"]:
            env["BINRADAR_FORKSERVER_ENABLE"] = "1"
            env["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = str(self.probe_result.patch_func_hit_cnt)
            if mode == "directed":
                env["BINRADAR_QUERY_WINDOW_FILE"] = os.path.join(run_dir, 'binradar-query-window.sbsv')
                env["BINRADAR_PRESERVE_CHILD_QUERIES"] = "1"
                env["BINRADAR_TRACE_FILE"] = "none"
            else:
                open(trace_file, "w").close()
                env["BINRADAR_TRACE_FILE"] = trace_file
                env["BINRADAR_PRESERVE_CHILD_QUERIES"] = "0"
                env["PATCH_ID"] = "123456"
                env["BINRADAR_PATCH_CNT"] = str(self.total_patches)
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
        self.save_progress(f"[probe] [start] [id {self.run_id}]")
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
        file_trace_runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        file_trace_result = file_trace_runner.test_with_file_trace(self.resolved_poc_input(), patch_func_entry=probe_result.patch_func_entry, verbose=True)
        if file_trace_result is None:
            logger.info("[PROBE] Failed to get file trace result. Check if patch location is set or qemu_stacktrace is available.")
            sys.exit(1)
        # Set config
        self.set_config("BINRADAR_ENTRYPOINT", hex(probe_result.patch_func_entry))
        self.save_progress(f"[probe] [done] [id {self.run_id}] {probe_result.serialize()} {file_trace_result.serialize_file_trace_result()}")
        with open(os.path.join(self.run_dir, "probe-results.sbsv"), "w", encoding="utf-8") as f:
            f.write(f"[probe-info] {probe_result.serialize()}\n")
            f.write(f"[file-trace] {file_trace_result.serialize_file_trace_result()}\n")
    
    def check_requirements(self):
        if not os.path.exists(self.original_binary()):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(self.resolved_poc_input()):
            sys.exit("ERROR: input does not exist.")
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
        self.save_progress(f"[fuzzolic] [start] [id {self.run_id}]")

        fuzzolic_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(fuzzolic_env)
        shm.assign_random_keys()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, fuzzolic_env, self.workdir, timeout=self.timeout)
        tracer = TracerExecutor(exec_mode, fuzzolic_env, self.workdir, self.run_dir, self.original_binary(), self.test_cmd, testcase, timeout=self.timeout)
        
        try:
            solver.start()
            tracer.start()
            tracer_time, tracer_success, _ = tracer.run()
            self.save_progress(f"[fuzzolic] [tracer] [id {self.run_id}] [tracer-time {tracer_time}] [tracer-success {tracer_success}]")
            solver.create_inputs()
            solver_time, solver_success = solver.wait()
            self.save_progress(f"[fuzzolic] [solver] [id {self.run_id}] [solver-time {solver_time}] [solver-success {solver_success}]")
            tracer.stop()
            solver.stop()
        except Exception as e:
            logger.error(f"Error during fuzzolic execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()
        
        self.save_progress(f"[fuzzolic] [done] [id {self.run_id}]")
    
    def run_directed(self):
        testcase = self.resolved_poc_input()
        self.check_requirements()
        
        exec_mode = "directed"
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[directed] [start] [id {self.run_id}]")
        
        directed_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(directed_env)
        shm.assign_random_keys()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, directed_env, self.workdir, timeout=self.timeout)
        tracer = TracerExecutor(exec_mode, directed_env, self.workdir, self.run_dir, self.original_binary(), self.test_cmd, testcase, timeout=self.timeout)
        try:
            solver.start()
            tracer.start()
            tracer_time, tracer_success, _ = tracer.run()
            self.save_progress(f"[directed] [tracer] [id {self.run_id}] [tracer-time {tracer_time}] [tracer-success {tracer_success}]")
            solver.create_inputs()
            solver_time, solver_success = solver.wait()
            self.save_progress(f"[directed] [solver] [id {self.run_id}] [solver-time {solver_time}] [solver-success {solver_success}]")
            tracer.stop()
            solver.stop()
        except Exception as e:
            logger.error(f"Error during directed execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()

        self.save_progress(f"[directed] [done] [id {self.run_id}]")
    
    def run_fuzzer(self):
        self.check_requirements()
        exec_mode = "fuzzer"
        self.save_progress(f"[fuzzer] [start] [id {self.run_id}]")
        config = self.extract_config()
        fuzzer_outdir = os.path.join(self.run_dir, "fuzzer-out")
        if os.path.exists(fuzzer_outdir):
            logger.info(f"Fuzzer output directory already exists: {fuzzer_outdir}. It will be overwritten.")
            shutil.rmtree(fuzzer_outdir)
        fuzzer = binradar_fuzzer.BinRadarFuzzer.from_env(self.workdir, fuzzer_outdir, config)
        fuzzer.run(self.timeout)
        self.save_progress(f"[fuzzer] [done] [id {self.run_id}]")
    
    def run_minimizer(self):
        self.check_requirements()
        exec_mode = "minimizer"
        self.save_progress(f"[minimizer] [start] [id {self.run_id}]")
        config = self.extract_config()
        testcase_dirs = [os.path.join(self.run_dir, f"{mode}-tests") for mode in ["fuzzolic", "directed"]]
        testcase_dirs.append(os.path.join(self.run_dir, "fuzzer-out", "reached"))
        minimizer = binradar_minimizer.BinRadarMinimizer(self.workdir, self.run_dir, testcase_dirs, config)
        minimizer.load_testcases()
        minimizer.run_testcases()
        self.save_progress(f"[minimizer] [done] [id {self.run_id}]")
    
    def run_verifier(self):
        self.check_requirements()
        exec_mode = "verifier"
        minimizer_result_file = os.path.join(self.run_dir, "minimizer.sbsv")
        if not os.path.exists(minimizer_result_file):
            logger.info("[VERIFIER] Minimizer results not found. Please run the minimizer phase first.")
            sys.exit(1)
        
        config = self.extract_config()
        self.save_progress(f"[verifier] [start] [id {self.run_id}]")
        # Implementation for concrete verifier
        runner = binradar_verifier.BinRadarQemuRunner.from_env(self.workdir, config)
        verifier = binradar_verifier.BinRadarConcreteVerifier(self.workdir, self.run_dir, runner, self.patched_binary(), list(range(1, self.total_patches + 1)))
        verifier.load_testcases(minimizer_result_file)
        verifier.run_verification_concrete_testcases()
        self.save_progress(f"[verifier] [done] [id {self.run_id}]")

    def run_binradar(self):
        testcase = self.resolved_poc_input()
        self.check_requirements()
        
        exec_mode = "binradar"
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[binradar] [start] [id {self.run_id}]")
        
        binradar_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(binradar_env)
        shm.assign_random_keys()
        shm.assign_random_key_for_binradar()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, binradar_env, self.workdir, timeout=self.timeout)
        tracer = TracerExecutor(exec_mode, binradar_env, self.workdir, self.run_dir, self.patched_binary(), self.test_cmd, testcase, timeout=self.timeout)
        
        try:
            solver.start()
            tracer.start()
            remaining = 1
            while remaining > 0:
                tracer_time, tracer_success, remaining = tracer.run()
                logger.debug(f"[binradar] [tracer] [id {self.run_id}] [iter {tracer.iter}] [tracer-time {tracer_time}] [tracer-success {tracer_success}]")
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

        self.save_progress(f"[binradar] [done] [id {self.run_id}]")
    
    def run_final(self):
        # Read verifier.sbsv and binradar-trace-msg.log to get final results and save them to progress file
        verifier_result_file = os.path.join(self.run_dir, "verifier.sbsv")
        trace_msg_log_file = os.path.join(self.run_dir, "binradar-tracer-msg.log")
        verifier_result = None
        self.save_progress(f"[final] [start] [id {self.run_id}]")
        if not os.path.exists(trace_msg_log_file):
            logger.error("Trace message log file not found. BinRadar results might be incomplete.")
            raise FileNotFoundError(f"Trace message log file not found: {trace_msg_log_file}")
        if not os.path.exists(verifier_result_file):
            logger.error("Verifier result file not found. BinRadar results might be incomplete.")
            raise FileNotFoundError(f"Verifier result file not found: {verifier_result_file}")
        remaining_patches = set(range(1, self.total_patches + 1))
        concrete_verifier_result = binradar_verifier.BinRadarConcreteVerifierResult.from_sbsv(verifier_result_file)
        if concrete_verifier_result is None:
            logger.error("Failed to parse verifier result. BinRadar results might be incomplete.")
            raise ValueError("Failed to parse verifier result.")
        for result in concrete_verifier_result.patch_verified:
            verified = concrete_verifier_result.patch_verified[result]
            if not verified:
                remaining_patches.discard(result)
        binradar_remaining_patches = remaining_patches.copy()
        with open(trace_msg_log_file, "r", encoding="utf-8") as f:
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
                        binradar_remaining_patches.discard(patch)
                    elif original["result"] == "normal" and patch_result["result"] == "crash":
                        binradar_remaining_patches.discard(patch)
                    elif original["result"] == "normal" and patch_result["result"] == "normal":
                        if original["br"] != patch_result["br"]:
                            binradar_remaining_patches.discard(patch)
        self.save_progress(f"[final] [done] [id {self.run_id}] [remaining_patches {sorted(remaining_patches)}] [binradar_remaining_patches {sorted(binradar_remaining_patches)}]")

    def done(self):
        self.save_progress(f"[rundir] [done] [id {self.run_id}] [dir {self.run_dir}]")
    
    def run_sequential(self):
        self.set_run_dir(resume_phase=BinRadarPhase.ALL)
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.run_probe()
        self.run_fuzzolic()
        self.run_directed()
        self.run_fuzzer()
        self.run_minimizer()
        self.run_verifier()
        self.run_binradar()
        self.run_final()
        self.done()
    
    def run_single_phase(self, run_id: int, phase: BinRadarPhase):
        if run_id < 0:
            self.set_run_dir()
        else:
            self.run_id = run_id
            self.run_dir = os.path.join(self.outdir, f"run-{run_id:05d}")
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.run_probe()
        if phase == BinRadarPhase.FUZZOLIC:
            self.run_fuzzolic()
        elif phase == BinRadarPhase.DIRECTED:
            self.run_directed()
        elif phase == BinRadarPhase.FUZZER:
            self.run_fuzzer()
        elif phase == BinRadarPhase.MINIMIZER:
            self.run_minimizer()
        elif phase == BinRadarPhase.VERIFIER:
            self.run_verifier()
        elif phase == BinRadarPhase.BINRADAR:
            self.run_binradar()
        elif phase == BinRadarPhase.FINAL:
            self.run_final()
        else:
            raise ValueError(f"Unknown phase: {phase}")
        self.done()
    
    def run_multithreaded(self):
        self.set_run_dir()
        logger.set_file(os.path.join(self.run_dir, "binradar.log"))
        self.run_probe()

        thread_errors: "queue.Queue[Tuple[str, BaseException, object]]" = queue.Queue()
        
        def run_captured(name: str, target):
            try:
                target()
            except BaseException as exc:
                thread_errors.put((name, exc, exc.__traceback__))
                logger.error(f"[{name}] failed: {exc}")

        def raise_thread_error_if_any(wait_for_binradar: bool = False):
            if thread_errors.empty():
                return
            _, exc, tb = thread_errors.get()
            stop_running_processes()
            if wait_for_binradar:
                binradar_thread.join()
            if tb is not None:
                raise exc.with_traceback(tb)
            raise exc

        binradar_thread = threading.Thread(target=run_captured, args=("binradar", self.run_binradar))
        binradar_thread.start()

        fuzzolic_thread = threading.Thread(target=run_captured, args=("fuzzolic", self.run_fuzzolic))
        directed_thread = threading.Thread(target=run_captured, args=("directed", self.run_directed))
        fuzzer_thread = threading.Thread(target=run_captured, args=("fuzzer", self.run_fuzzer))
        threads_concrete = [fuzzolic_thread, directed_thread, fuzzer_thread]
        for thread in threads_concrete:
            thread.start()
        for thread in threads_concrete:
            thread.join()

        raise_thread_error_if_any()

        # TODO: we can modify minimizer and verifier to be run in parallel as well
        self.run_minimizer()
        raise_thread_error_if_any(wait_for_binradar=True)
        self.run_verifier()
        raise_thread_error_if_any(wait_for_binradar=True)

        binradar_thread.join()
        raise_thread_error_if_any()
        self.run_final()
        self.done()

    
def main():
    setlimits()
    signal.signal(signal.SIGINT, handler)

    parser = argparse.ArgumentParser(
        description="binradar: a binary patch verification tool")
    parser.add_argument(
        "-w", "--workdir", required=True,
        help="set the working directory for binradar")
    parser.add_argument(
        "-t", "--timeout", type=int, default=-1,
        help="set timeout for each test case (s)")
    parser.add_argument(
        "-p", "--patch-loc", default="",
        help="set the patch location for fuzzolic (hex)")
    parser.add_argument(
        "-i", "--input", default="",
        help="set the input file for fuzzolic")
    parser.add_argument(
        "-o", "--output", default="out",
        help="set the output directory for fuzzolic")
    parser.add_argument(
        "--cmd", default="",
        help="set the test command for fuzzolic (overrides TEST_CMD in config.env)")
    # The following argument is for experiments and debugging
    phases = ["probe", "fuzzolic", "directed", "fuzzer", "minimizer", "verifier", "binradar", "final"]
    parser.add_argument("--run-single-phase", default="", 
        choices=phases, help="run a specific phase")
    parser.add_argument("--run-id", type=int, default=-1, help="Rerun a specific phase with a given run id (only valid when --run-single-phase is set)")
    parser.add_argument("--seq", action="store_true", help="run all phases sequentially (for debugging)")
    args = parser.parse_args()

    if not os.path.exists(args.workdir):
        sys.exit(f"ERROR: workdir {args.workdir} does not exist.")
    
    os.chdir(args.workdir)

    env = binradar_utils.load_env(os.path.join(args.workdir, "config.env"))
    if args.patch_loc:
        env["PATCH_LOC"] = args.patch_loc
    if args.input:
        env["POC_INPUT"] = args.input
    if args.cmd:
        env["TEST_CMD"] = args.cmd
    if args.timeout >= 0:
        env["BINRADAR_TIMEOUT"] = str(args.timeout)
    else:
        env["BINRADAR_TIMEOUT"] = "3600" # 1 hours

    env["BINRADAR_OUTDIR"] = os.path.abspath(args.output)
    env["BINRADAR_WORKDIR"] = os.path.abspath(args.workdir)
    os.makedirs(env["BINRADAR_OUTDIR"], exist_ok=True)

    executor = BinRadarExecutor.from_env(args.workdir, env)
    if args.run_single_phase:
        executor.run_single_phase(args.run_id, BinRadarPhase[args.run_single_phase.upper()])
    elif args.seq:
        executor.run_sequential()
    else:
        executor.run_multithreaded()


if __name__ == "__main__":
    main()
