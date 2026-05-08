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
import sys
import select
import io
import time
from typing import Dict, List, Tuple, Set, Optional, TextIO, BinaryIO

import analyze_type
import binradar_verifier
import binradar_utils
import logger
import sbsv

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SOLVER_SMT_BIN = SCRIPT_DIR + "/../solver/build/solver-smt"
TRACER_BIN = SCRIPT_DIR + "/../tracer/build/x86_64-linux-user/qemu-x86_64"
FIND_MODELS_BIN = SCRIPT_DIR + "/find_models_addrs.py"

SOLVER_WAIT_TIME_AT_STARTUP = 1 # s
SOLVER_TIMEOUT = 10 # s

RUNNING_PROCESSES = []
MAX_VIRTUAL_MEMORY = 16 * 1024 * 1024 * 1024  # 16 GB
SHM_KEYS = ["EXPR_POOL_SHM_KEY", "QUERY_SHM_KEY", "BITMAP_SHM_KEY"]

# Tracer forkserver
HANDSHAKE_EXPECTED = 0x41464C00
CTRL_FD = 198


def setlimits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY, MAX_VIRTUAL_MEMORY))


def handler(signo, stackframe):
    del signo
    del stackframe

    print("[BINRADAR] Aborting....")
    global SHUTDOWN
    SHUTDOWN = True

    for proc in list(RUNNING_PROCESSES):
        print("[BINRADAR] Sending SIGINT")
        try:
            proc.send_signal(signal.SIGINT)
            proc.send_signal(signal.SIGUSR2)
            proc.wait(2)
        except Exception:
            print("[BINRADAR] Sending SIGKILL")
            try:
                proc.send_signal(signal.SIGKILL)
            except Exception:
                pass
            try:
                proc.wait()
            except Exception:
                pass
        finally:
            if proc in RUNNING_PROCESSES:
                RUNNING_PROCESSES.remove(proc)

    sys.exit(f"Aborted binradar with cleanup.")

class SharedMemoryManager:
    def __init__(self, env: Dict[str, str]):
        self.env = env
        self.libc = ctypes.CDLL("libc.so.6")
    
    def assign_random_keys(self):
        for key in SHM_KEYS:
            self.env[key] = hex(random.getrandbits(32))
    
    def cleanup(self):
        shm_keys = list()
        for key in SHM_KEYS:
            if key not in self.env:
                continue
            shm_keys.append(int(self.env[key], 16))

        ipc_rmid = 0
        for shm_key in shm_keys:
            shm_id = self.libc.shmget(
                ctypes.c_int(shm_key), ctypes.c_int(1), ctypes.c_int(0))
            if shm_id > 0:
                result = self.libc.shmctl(
                    ctypes.c_int(shm_id),
                    ctypes.c_int(ipc_rmid),
                    ctypes.c_int(0))
                logger.info(
                    "Shared memory detach on (%s, %s): %s"
                    % (shm_key, shm_id, result))

class TracerExecutor:
    command: List[str]
    mode: str
    env: Dict[str, str]
    workdir: str
    rundir: str
    log_fp: BinaryIO
    process: Optional[subprocess.Popen]
    timeout: float
    # Forkserver
    forkserver_mode: bool
    ctrl_w: int
    stat_r: int
    iter: int
    run_result: Optional[binradar_utils.ExecutionResult]
    def __init__(self, mode: str, env: Dict[str, str], workdir: str, rundir: str, binary: str, test_cmd: str, testcase: str, timeout: float):
        self.command = [TRACER_BIN, "-symbolic", "-d", "page", binary] + shlex.split(test_cmd.replace("@@", testcase))
        self.mode = mode
        self.env = env
        self.workdir = workdir
        self.rundir = rundir
        self.timeout = timeout
        log_file = os.path.join(rundir, f"{mode}-tracer.log")
        self.log_fp = open(log_file, "wb")
        self.process = None
        self.forkserver_mode = self.env.get("BINRADAR_FORKSERVER_ENABLE", "0") == "1"
        self.ctrl_w = 0
        self.stat_r = 0
        self.iter = 0
        self.run_result = None
    
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
                stderr=self.log_fp,
                cwd=self.workdir,
                env=self.env,
                preexec_fn=setlimits,
                start_new_session=True)
            RUNNING_PROCESSES.append(self.process)
            logger.info(f"[TRACER] Started tracer without forkserver mode. {' '.join(self.command)}")
            return

        # Set up pipes for forkserver communication
        ctl_r, ctl_w = os.pipe()
        st_r, st_w = os.pipe()
        ctrl_fd = CTRL_FD
        status_fd = CTRL_FD + 1
        os.dup2(ctl_r, ctrl_fd)
        os.dup2(st_w, status_fd)
        os.close(ctl_r)
        os.close(st_w)
        os.set_inheritable(ctrl_fd, True)
        os.set_inheritable(status_fd, True)
        
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.DEVNULL,
            stderr=self.log_fp,
            cwd=self.workdir,
            env=self.env,
            pass_fds=(ctrl_fd, status_fd),
            preexec_fn=setlimits, 
            start_new_session=True)
        
        RUNNING_PROCESSES.append(self.process)
        os.close(ctrl_fd)
        os.close(status_fd)
        self.ctrl_w = ctl_w
        self.stat_r = st_r
        
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
        self.iter += 1
        if not self.forkserver_mode:
            self.run_result = binradar_utils.execute_await(self.process, timeout=self.timeout)
            logger.info(f"[TRACER] Target process finished with exit code {self.run_result.decode_status()}, success {self.run_result.success}")
            return int((time.time() - start_time) * 1000), self.run_result.success, 0
        self._write_u32(0)  # Send run command to forkserver
        is_timeout = False
        child_pid = self._read_u32(self.timeout)
        try:
            status = self._read_u32(self.timeout)
            analyze_result = b""
            if self._need_type_analysis():
                out_buf = io.StringIO()
                start_time = time.time()
                self.log_fp.flush()
                with open(self.log_fp.name, "r", encoding="utf-8", errors="ignore") as log_file:
                    osprey = analyze_type.OspreyAnalyzer(log_file, out_buf)
                    osprey.analyze()
                    osprey.dump_results(dump_mode="best")
                analyze_result = out_buf.getvalue().encode("utf-8")
                analyze_result_file = os.path.join(self.rundir, f"analyzed-type.{self.iter}.sbsv")
                with open(analyze_result_file, "wb") as f:
                    f.write(analyze_result)
                logger.info(f"[osprey-analyzer] [it {self.iter}] [len {len(analyze_result)}] [time {round(time.time() - start_time, 3)}] [saved {analyze_result_file}]")
            logger.info(f"[TRACER] Target process finished with status {status:#x}")
        except Exception as e:
            is_timeout = True
            logger.error(f"Error while waiting for tracer forkserver: {str(e)}")
            self.process.send_signal(signal.SIGINT)
            self.process.wait()
            raise e
        analyze_result_size = len(analyze_result)
        if analyze_result_size > 0xFFFFFFFF:
            raise ValueError("Analyze result too large")
        self._write_u32(len(analyze_result))
        self._write(analyze_result)
        remaining = self._read_u32(self.timeout)
        return int((time.time() - start_time) * 1000), is_timeout, remaining
    
    def stop(self):
        if self.ctrl_w != 0:
            os.close(self.ctrl_w)
            self.ctrl_w = 0
        if self.stat_r != 0:
            os.close(self.stat_r)
            self.stat_r = 0
        if self.process is not None:
            logger.info("[TRACER] Stopping tracer process...")
            self.run_result = binradar_utils.execute_await(self.process, timeout=5)
            RUNNING_PROCESSES.remove(self.process)
            self.process = None
        if not self.log_fp.closed:
            self.log_fp.close()
        
    def _need_type_analysis(self) -> bool:
        """
        Determine if type analysis is needed:
        - It has large overhead, so we only want to run it when necessary.
        """
        return self.mode == "binradar" and self.iter == 1
    
    def _write_u32(self, value: int):
        self._write(value.to_bytes(4, byteorder="little"))
    
    def _write(self, data: bytes):
        total_written = 0
        while total_written < len(data):
            try:
                written = os.write(self.ctrl_w, data[total_written:])
                total_written += written
            except BrokenPipeError:
                raise RuntimeError("Tracer forkserver pipe is broken")
            except BlockingIOError:
                continue
    
    def _read_u32(self, timeout: float) -> int:
        rlist, _, _ = select.select([self.stat_r], [], [], timeout)
        if not rlist:
            raise TimeoutError("Timeout while waiting for forkserver response")
        data = self._read(4)
        if len(data) < 4:
            raise EOFError("Failed to read 4 bytes from forkserver")
        return int.from_bytes(data, byteorder="little")
    
    def _read(self, size: int) -> bytes:
        data = b''
        while len(data) < size:
            try:
                chunk = os.read(self.stat_r, size - len(data))
                if not chunk:
                    raise EOFError("EOF while reading from forkserver")
                data += chunk
            except BlockingIOError:
                continue
        return data

class SolverExecutor:
    command: List[str]
    mode: str
    env: Dict[str, str]
    workdir: str
    rundir: str
    log_fp: BinaryIO
    process: Optional[subprocess.Popen]
    timeout: float
    run_result: Optional[binradar_utils.ExecutionResult]
    def __init__(self, mode: str, testcase: str, run_dir: str, env: Dict[str, str], workdir: str, timeout: float):
        testcase_dir = os.path.join(run_dir, f"{mode}-tests")
        os.makedirs(testcase_dir, exist_ok=True)
        global_bitmap = os.path.join(run_dir, f"{mode}-branch-bitmap")
        context_bitmap = os.path.join(run_dir, f"{mode}-context-bitmap")
        memory_bitmap = os.path.join(run_dir, f"{mode}-memory-bitmap")
        for bitmap in [global_bitmap, context_bitmap, memory_bitmap]:
            with open(bitmap, "a") as f:
                pass
        self.command = ["stdbuf", "-o0", SOLVER_SMT_BIN, 
                        "-i", testcase, 
                        "-t", testcase_dir, 
                        "-o", run_dir, 
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
        return int((time.time() - start_time) * 1000), is_timeout

    def stop(self):
        if self.process:
            logger.info("[SOLVER] Stopping solver process...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            RUNNING_PROCESSES.remove(self.process)
            self.process = None
        if not self.log_fp.closed:
            self.log_fp.close()

class BinRadarProgress:
    run_id: int
    run_dir: str
    probe_done: bool
    directed_done: bool
    done: bool
    def __init__(self, run_id: int, run_dir: str, probe_done: bool, directed_done: bool, done: bool):
        self.run_id = run_id
        self.run_dir = run_dir
        self.probe_done = probe_done
        self.directed_done = directed_done
        self.done = done
    
    @staticmethod
    def from_progress_file(file: str) -> Optional["BinRadarProgress"]:
        if not os.path.exists(file):
            return None
        parser = sbsv.parser()
        parser.add_schema("[rundir] [set] [id: int] [dir: str]")
        parser.add_schema("[rundir] [done] [id: int] [dir: str]")
        parser.add_schema("[probe] [done] [id: int] [hit-count: int]")
        parser.add_schema("[directed] [done] [id: int]")
        with open(file, "r", encoding="utf-8") as f:
            parser.load(f)
        rundir = parser.get_result()["rundir"]["set"]
        if len(rundir) == 0:
            return None
        last_rundir = rundir[-1]
        run_id = int(last_rundir["id"])
        run_dir = last_rundir["dir"]
        
        probe_done = False
        directed_done = False
        done = False
        for probe in parser.get_result()["probe"]["done"]:
            if int(probe["id"]) == run_id:
                probe_done = True
                break
        for directed in parser.get_result()["directed"]["done"]:
            if int(directed["id"]) == run_id:
                directed_done = True
                break
        for done_item in parser.get_result()["rundir"]["done"]:
            if int(done_item["id"]) == run_id:
                done = True
                break
        return BinRadarProgress(run_id, run_dir, probe_done, directed_done, done)

class BinRadarExecutor:
    # Config from config.env and command line arguments
    workdir: str
    outdir: str
    timeout: int
    binary: str
    poc_input: str
    test_cmd: str
    target_function_entry: str
    patch_loc: str
    # Data
    config: Dict[str, str]
    progress_file: TextIO
    previous_progress: Optional[BinRadarProgress]
    run_id: int
    run_dir: str
    probe_hit_count: int
    probe_file: str
    start_time: float
    def __init__(self, workdir: str, outdir: str, timeout: int, binary: str, poc_input: str, test_cmd: str, target_function_entry: str, patch_loc: str):
        self.workdir = os.path.abspath(workdir)
        self.outdir = os.path.abspath(outdir)
        self.timeout = timeout
        self.binary = binary
        self.poc_input = poc_input
        self.test_cmd = test_cmd
        self.target_function_entry = target_function_entry
        self.patch_loc = patch_loc

        self.libc = ctypes.CDLL("libc.so.6")
        self.probe_hit_count = 0
        self.probe_file = ""

        os.makedirs(self.outdir, exist_ok=True)
        logger.set_file(os.path.join(self.outdir, "binradar.log"))
        
        progress_filename = os.path.join(self.outdir, "progress.sbsv")
        self.previous_progress = BinRadarProgress.from_progress_file(progress_filename)
        self.progress_file = open(progress_filename, "a", encoding="utf-8")
        
        self.start_time = time.time()
        self.config = dict()
        self.set_base_config()
        self.run_id, self.run_dir = self.set_run_dir()

    @staticmethod
    def init(workdir: str) -> "BinRadarExecutor":
        env = binradar_utils.load_env(os.path.join(workdir, "config.env"))
        return BinRadarExecutor.init_from_env(workdir, env)

    @staticmethod
    def init_from_env(workdir: str, env: Dict[str, str]) -> "BinRadarExecutor":
        binradar = BinRadarExecutor(
            workdir=workdir,
            outdir=env["BINRADAR_OUTDIR"],
            timeout=int(env["BINRADAR_TIMEOUT"]),
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            test_cmd=env["TEST_CMD"],
            target_function_entry=env["TARGET_FUNCTION_ENTRY"],
            patch_loc=env["PATCH_LOC"],
        )
        # Backup config.env to run_dir
        config_file = os.path.join(binradar.run_dir, "config.env")
        if not os.path.exists(config_file):
            binradar_utils.save_env(env, config_file)
        return binradar

    def elapsed_time_ms(self) -> int:
        return int((time.time() - self.start_time) * 1000)

    def save_progress(self, data: str):
        if self.progress_file.closed:
            logger.warning("Progress file is already closed. Cannot save progress.")
            return
        time = self.elapsed_time_ms()
        logger.info(f"[PROGRESS] {data} [time {time}]")
        self.progress_file.write(f"{data} [time {time}]\n")
        self.progress_file.flush()
    
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

    def resolved_poc_input(self) -> str:
        if os.path.isabs(self.poc_input):
            return self.poc_input
        return os.path.join(self.workdir, self.poc_input)

    def set_run_dir(self) -> Tuple[int, str]:
        run_id = 0
        # Currently, start a new run if the previous run exists.
        # Can resume in more fine-grained way if needed.
        if self.previous_progress is not None:
            run_id = self.previous_progress.run_id + 1
        run_dir = os.path.join(self.outdir, f"fuzzolic-{run_id:05d}")
        os.makedirs(run_dir, exist_ok=True)
        self.save_progress(f"[rundir] [set] [id {run_id}] [dir {run_dir}]")
        return run_id, run_dir

    def set_base_config(self):
        # Basic default config
        # TODO: implement stdin
        self.config["BINRADAR_TIMEOUT"] = str(self.timeout)
        self.config["SYMBOLIC_INJECT_INPUT_MODE"] = "FROM_FILE"
        testcase = self.resolved_poc_input()
        self.config["SYMBOLIC_TESTCASE_NAME"] = testcase
        self.config["BINRADAR_ENTRYPOINT"] = self.target_function_entry
        if self.timeout > 0:
            self.config["SOLVER_TIMEOUT"] = str(int(self.timeout * 1000))
        self.config["PLT_INFO_FILE"] = self.set_plt_info(os.path.join(self.outdir, "plt_info.txt"))
    
    def get_env(self, mode: str, run_dir: str) -> Dict[str, str]:
        env = os.environ.copy()
        env.update(self.config)
        # Tracer
        if mode == "probe":
            self.probe_file = os.path.join(run_dir, "probe-result.sbsv")
            env["BINRADAR_PROBE_FILE"] = self.probe_file
            env["BINRADAR_FORKSERVER_ENABLE"] = "0"
            env["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = "0"
        elif mode in ["directed", "binradar"]:
            env["BINRADAR_FORKSERVER_ENABLE"] = "1"
            env["BINRADAR_FORKSERVER_TARGET_HIT_COUNT"] = str(self.probe_hit_count)
            env["BINRADAR_QUERY_WINDOW_FILE"] = os.path.join(run_dir, 'binradar-query-window.sbsv')
            if mode == "directed":
                env["BINRADAR_PRESERVE_CHILD_QUERIES"] = "1"
            else:
                env["BINRADAR_PRESERVE_CHILD_QUERIES"] = "0"
        # Solver
        env["BINRADAR_SOLVER_CONCRETE_OUTDIR"] = os.path.join(run_dir, f"solver-out-{mode}")
        os.makedirs(env["BINRADAR_SOLVER_CONCRETE_OUTDIR"], exist_ok=True)
        return env

    def run_probe(self) -> int:
        testcase = self.resolved_poc_input()
        if not os.path.exists(self.original_binary()):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(testcase):
            sys.exit("ERROR: input does not exist.")
        # TODO: support stdin
        if "@@" not in self.test_cmd:
            sys.exit("ERROR: probe phase requires a file-based testcase (@@).")

        exec_mode = "probe"
        shutil.copy2(testcase, self.run_dir)
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[probe] [start] [id {self.run_id}]")

        probe_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(probe_env)
        shm.assign_random_keys()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, probe_env, self.workdir, timeout=self.timeout)
        tracer = TracerExecutor(exec_mode, probe_env, self.workdir, self.run_dir, self.original_binary(), self.test_cmd, testcase, timeout=self.timeout)
        
        try:
            solver.start()
            tracer.start()
            tracer_time, tracer_success, _ = tracer.run()
            self.save_progress(f"[probe] [tracer] [id {self.run_id}] [tracer-time {tracer_time}] [tracer-success {tracer_success}]")
            solver.create_inputs()
            solver_time, solver_success = solver.wait()
            self.save_progress(f"[probe] [solver] [id {self.run_id}] [solver-time {solver_time}] [solver-success {solver_success}]")
        except Exception as e:
            logger.error(f"Error during probe execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()

        if not os.path.exists(self.probe_file):
            sys.exit(f"[binradar] [error] crash call index file not found: {self.probe_file}")

        logger.info(f"[binradar] [probe] [done] [file {self.probe_file}]")
        with open(self.probe_file, "r", encoding="utf-8", errors="ignore") as probe_fp:
            parser = sbsv.parser()
            parser.add_schema(
                "[snapshot] [crash] [hit-count: int] [reason: str] "
                "[guest_pc: str] [guest_cs_base: str] [fault_addr: str] "
                "[host_fault_addr: str]")
            result = parser.load(probe_fp)
            crashes = result["snapshot"]["crash"]
            if not crashes:
                sys.exit(f"[binradar] [error] no crash found in probe result.")
            self.probe_hit_count = int(crashes[-1]["hit-count"])
            self.save_progress(f"[probe] [done] [id {self.run_id}] [hit-count {self.probe_hit_count}]")
        return self.probe_hit_count
    
    def run_directed(self):
        testcase = self.resolved_poc_input()
        if not os.path.exists(self.original_binary()):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(testcase):
            sys.exit("ERROR: input does not exist.")
        # TODO: support stdin
        if "@@" not in self.test_cmd:
            sys.exit("ERROR: probe phase requires a file-based testcase (@@).")

        exec_mode = "directed"
        shutil.copy2(testcase, self.run_dir)
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
        except Exception as e:
            logger.error(f"Error during directed execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()

        self.save_progress(f"[directed] [done] [id {self.run_id}]")
    
    def run_binradar(self):
        testcase = self.resolved_poc_input()
        if not os.path.exists(self.original_binary()):
            sys.exit("ERROR: binary does not exist.")
        if not os.path.exists(testcase):
            sys.exit("ERROR: input does not exist.")
        # TODO: support stdin
        if "@@" not in self.test_cmd:
            sys.exit("ERROR: probe phase requires a file-based testcase (@@).")

        exec_mode = "binradar"
        shutil.copy2(testcase, self.run_dir)
        logger.info(f"[BINRADAR] Running {exec_mode} in directory: {self.run_dir} with testcase: {testcase}")
        self.save_progress(f"[binradar] [start] [id {self.run_id}]")
        
        binradar_env = self.get_env(exec_mode, self.run_dir)
        shm = SharedMemoryManager(binradar_env)
        shm.assign_random_keys()
        
        solver = SolverExecutor(exec_mode, testcase, self.run_dir, binradar_env, self.workdir, timeout=self.timeout)
        tracer = TracerExecutor(exec_mode, binradar_env, self.workdir, self.run_dir, self.original_binary(), self.test_cmd, testcase, timeout=self.timeout)
        
        try:
            solver.start()
            tracer.start()
            remaining = 1
            while remaining > 0:
                # TODO: implement behavior comparison
                tracer_time, tracer_success, remaining = tracer.run()
                self.save_progress(f"[binradar] [tracer] [id {self.run_id}] [iter {tracer.iter}] [tracer-time {tracer_time}] [tracer-success {tracer_success}]")
            # TODO: we can generate more inputs - currently, we don't utilize collected constraints
            solver.stop()
        except Exception as e:
            logger.error(f"Error during binradar execution: {str(e)}")
            tracer.stop()
            solver.stop()
            raise e
        finally:
            shm.cleanup()

        self.save_progress(f"[binradar] [done] [id {self.run_id}]")
    
    def done(self):
        self.save_progress(f"[rundir] [done] [id {self.run_id}] [dir {self.run_dir}]")
        self.progress_file.close()

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
        "-f", "--target-function-entry", default="",
        help="set the target function entry point for fuzzolic (hex)")
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
    args = parser.parse_args()

    if not os.path.exists(args.workdir):
        sys.exit(f"ERROR: workdir {args.workdir} does not exist.")

    env = binradar_utils.load_env(os.path.join(args.workdir, "config.env"))
    if args.target_function_entry:
        env["TARGET_FUNCTION_ENTRY"] = args.target_function_entry
    if args.patch_loc:
        env["PATCH_LOC"] = args.patch_loc
    if args.input:
        env["POC_INPUT"] = args.input
    if args.cmd:
        env["TEST_CMD"] = args.cmd
    if args.timeout >= 0:
        env["BINRADAR_TIMEOUT"] = str(args.timeout)
    else:
        env["BINRADAR_TIMEOUT"] = "600" # 10 minutes

    env["BINRADAR_OUTDIR"] = os.path.abspath(args.output)
    env["BINRADAR_WORKDIR"] = os.path.abspath(args.workdir)
    os.makedirs(env["BINRADAR_OUTDIR"], exist_ok=True)

    executor = BinRadarExecutor.init_from_env(args.workdir, env)
    executor.run_probe()
    executor.run_directed()
    # executor.run_binradar()
    executor.done()


if __name__ == "__main__":
    main()
