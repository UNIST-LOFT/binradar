"""Phase runtime ownership for BinRadar subprocesses and transports."""

import ctypes
import os
import random
import select
import shlex
import signal
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple

import binradar_utils
import logger

SCRIPT_DIR = Path(__file__).resolve().parent
SOLVER_SMT_BIN = str(SCRIPT_DIR / "../solver/build/solver-smt")
SOLVER_FUZZY_BIN = str(SCRIPT_DIR / "../solver/build/solver-fuzzy")
TRACER_BIN = str(SCRIPT_DIR / "../tracer/build/x86_64-linux-user/qemu-x86_64")

SOLVER_WAIT_TIME_AT_STARTUP = 1.0
SOLVER_TIMEOUT = 10.0
SHM_KEYS = ("EXPR_POOL_SHM_KEY", "QUERY_SHM_KEY", "BITMAP_SHM_KEY")
HANDSHAKE_EXPECTED = 0x41464C02


@dataclass(frozen=True)
class Deadline:
    """One absolute monotonic deadline shared by a phase's resources."""

    expires_at: Optional[float]

    @classmethod
    def from_timeout(cls, timeout: Optional[float], factor: float = 1.0) -> "Deadline":
        if timeout is None or timeout <= 0:
            return cls(None)
        return cls(time.monotonic() + timeout * factor)

    def remaining(self, cap: Optional[float] = None) -> Optional[float]:
        if self.expires_at is None:
            return cap
        remaining = max(0.0, self.expires_at - time.monotonic())
        return remaining if cap is None else min(cap, remaining)

    def expired(self) -> bool:
        return self.expires_at is not None and time.monotonic() >= self.expires_at

    def worker_timeout(self) -> Optional[float]:
        """Adapt this deadline to workers whose non-positive timeout means off."""
        remaining = self.remaining()
        if remaining is None or remaining > 0:
            return remaining
        return 1e-9


class ProcessRegistry:
    """Thread-safe owner of spawn-time process-group identities."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._processes: Dict[int, Tuple[subprocess.Popen, int]] = {}

    def register(self, process: subprocess.Popen) -> int:
        pgid = binradar_utils.process_group_id(process)
        with self._lock:
            self._processes[process.pid] = (process, pgid)
        return pgid

    def unregister(self, process: subprocess.Popen) -> None:
        with self._lock:
            self._processes.pop(process.pid, None)

    def pgid(self, process: subprocess.Popen) -> Optional[int]:
        with self._lock:
            item = self._processes.get(process.pid)
        return None if item is None else item[1]

    def contains(self, process: subprocess.Popen) -> bool:
        with self._lock:
            return process.pid in self._processes

    def snapshot(self) -> List[Tuple[subprocess.Popen, int]]:
        with self._lock:
            return list(self._processes.values())

    def stop(self, process: subprocess.Popen, grace: float = 1.0) -> None:
        pgid = self.pgid(process)
        try:
            binradar_utils.execute_await(process, timeout=grace)
            if pgid is not None:
                binradar_utils.kill_process_group(pgid, grace=grace)
            else:
                logger.warning(
                    f"[CLEANUP] No registered process group for pid {process.pid}")
        finally:
            self.unregister(process)

    def stop_all(self) -> None:
        for process, _ in self.snapshot():
            try:
                self.stop(process)
            except BaseException as exc:
                logger.error(
                    f"[CLEANUP] Failed to stop process {process.pid}: {exc}")


PROCESS_REGISTRY = ProcessRegistry()


def abort_handler(signo, stackframe) -> None:
    del signo
    del stackframe
    print("[BINRADAR] Aborting... Wait for safe cleanup.")
    PROCESS_REGISTRY.stop_all()
    sys.exit("Aborted binradar with cleanup.")


class SharedMemoryManager:
    def __init__(self, env: Dict[str, str]):
        self.env = env
        self.libc = ctypes.CDLL("libc.so.6")
        self.shm_keys: List[int] = []

    def assign_random_keys(self) -> None:
        for key in SHM_KEYS:
            shm_key = random.getrandbits(32)
            self.env[key] = hex(shm_key)
            self.shm_keys.append(shm_key)

    def assign_random_key_for_binradar(self) -> None:
        shm_key = random.getrandbits(32)
        self.env["BINRADAR_PATCH_SHM_KEY"] = hex(shm_key)
        self.shm_keys.append(shm_key)

    def cleanup(self) -> None:
        ipc_rmid = 0
        for shm_key in self.shm_keys:
            shm_id = self.libc.shmget(
                ctypes.c_int(shm_key), ctypes.c_int(1), ctypes.c_int(0))
            if shm_id == -1:
                continue
            result = self.libc.shmctl(
                ctypes.c_int(shm_id), ctypes.c_int(ipc_rmid), ctypes.c_void_p(0))
            logger.info(
                "Shared memory detach on (%s, %s): %s"
                % (shm_key, shm_id, result))
        self.shm_keys.clear()


class ForkserverTransport:
    """Owned forkserver descriptors plus exact bounded protocol I/O."""

    def __init__(self, env: Dict[str, str], mode: str):
        self.env = env
        self.mode = mode
        self.ctrl_r: Optional[int] = None
        self.ctrl_w: Optional[int] = None
        self.stat_r: Optional[int] = None
        self.stat_w: Optional[int] = None
        self.patch_fd_r: Optional[int] = None
        self.patch_fd_w: Optional[int] = None
        self.patch_cached_fd_r: Optional[int] = None
        self.patch_cached_fd_w: Optional[int] = None

    def setup(self) -> None:
        try:
            self.ctrl_r, self.ctrl_w = os.pipe()
            self.stat_r, self.stat_w = os.pipe()
            self.env["BINRADAR_FORKSERVER_CTRL_R"] = str(self.ctrl_r)
            self.env["BINRADAR_FORKSERVER_STAT_W"] = str(self.stat_w)
            if self.mode != "binradar":
                return
            self.patch_fd_r, self.patch_fd_w = os.pipe()
            self.env["PATCH_FD"] = str(self.patch_fd_w)
            self.env["BINRADAR_PATCH_FD_R"] = str(self.patch_fd_r)
            if self.env.get("BINRADAR_PATCH_CACHE_ENABLE") == "1":
                self.patch_cached_fd_r, self.patch_cached_fd_w = os.pipe()
                self.env["PATCH_CACHED_FD"] = str(self.patch_cached_fd_w)
                self.env["BINRADAR_PATCH_CACHED_FD_R"] = str(
                    self.patch_cached_fd_r)
        except BaseException:
            self.cleanup()
            raise

    def pass_fds(self) -> List[int]:
        descriptors = [self.ctrl_r, self.stat_w]
        if self.mode == "binradar":
            descriptors.extend([self.patch_fd_r, self.patch_fd_w])
            if self.patch_cached_fd_r is not None:
                descriptors.extend(
                    [self.patch_cached_fd_r, self.patch_cached_fd_w])
        return [fd for fd in descriptors if fd is not None]

    def close_child_ends(self) -> None:
        for name in (
                "ctrl_r", "stat_w", "patch_fd_r", "patch_fd_w",
                "patch_cached_fd_r", "patch_cached_fd_w"):
            self._close(name)

    def cleanup(self) -> None:
        for name in (
                "ctrl_r", "ctrl_w", "stat_r", "stat_w", "patch_fd_r",
                "patch_fd_w", "patch_cached_fd_r", "patch_cached_fd_w"):
            self._close(name)

    def _close(self, name: str) -> None:
        fd = getattr(self, name)
        if fd is None:
            return
        try:
            os.close(fd)
        except OSError:
            pass
        setattr(self, name, None)

    def write_u32(self, value: int) -> None:
        self.write(struct.pack("<I", value))

    def write(self, data: bytes) -> None:
        if self.ctrl_w is None:
            raise RuntimeError(
                f"[TRACER] [{self.mode}] Forkserver control pipe is closed")
        total_written = 0
        while total_written < len(data):
            try:
                written = os.write(self.ctrl_w, data[total_written:])
                if written == 0:
                    raise RuntimeError(
                        f"[TRACER] [{self.mode}] Forkserver control pipe made no progress")
                total_written += written
            except BrokenPipeError as exc:
                raise RuntimeError(
                    f"[TRACER] [{self.mode}] Tracer forkserver pipe is broken") from exc
            except BlockingIOError:
                continue

    def read_u32(self, timeout: Optional[float]) -> int:
        return struct.unpack("<I", self.read(4, timeout))[0]

    def read_status(self, timeout: Optional[float]) -> Tuple[int, int, int]:
        return struct.unpack("<III", self.read(12, timeout))

    def read(self, size: int, timeout: Optional[float]) -> bytes:
        if self.stat_r is None:
            raise RuntimeError(
                f"[TRACER] [{self.mode}] Forkserver status pipe is closed")
        expires_at = None if timeout is None else time.monotonic() + timeout
        data = bytearray()
        while len(data) < size:
            wait = None
            if expires_at is not None:
                wait = expires_at - time.monotonic()
                if wait <= 0:
                    raise TimeoutError(
                        f"[TRACER] [{self.mode}] Timeout while waiting for forkserver response")
            try:
                readable, _, _ = select.select([self.stat_r], [], [], wait)
            except InterruptedError:
                continue
            if not readable:
                raise TimeoutError(
                    f"[TRACER] [{self.mode}] Timeout while waiting for forkserver response")
            try:
                chunk = os.read(self.stat_r, size - len(data))
            except InterruptedError:
                continue
            if not chunk:
                raise EOFError(
                    f"[TRACER] [{self.mode}] EOF while reading from forkserver")
            data.extend(chunk)
        return bytes(data)


class TracerExecutor:
    forkserver_init_timeout = 1800.0
    forkserver_timeout = 1800.0
    forkserver_analyze_margin = 300.0
    process_cleanup_grace = 0.2
    process_cleanup_wait = 0.25
    process_reap_timeout = 0.5

    def __init__(
            self, mode: str, env: Dict[str, str], workdir: str, rundir: str,
            binary: str, test_cmd: str, testcase: str, deadline: Deadline,
            registry: ProcessRegistry = PROCESS_REGISTRY):
        self.command = [TRACER_BIN, "-symbolic", "-d", "page", binary] + \
            shlex.split(test_cmd.replace("@@", testcase))
        self.mode = mode
        self.env = env
        self.workdir = workdir
        self.rundir = rundir
        self.deadline = deadline
        self.registry = registry
        self.process: Optional[subprocess.Popen] = None
        self.pgid: Optional[int] = None
        self._process_cleanup_started = False
        self._process_cleanup_done = False
        self.forkserver_mode = env.get("BINRADAR_FORKSERVER_ENABLE", "0") == "1"
        self.iter = 0
        self.representative_runs = 0
        self.run_result: Optional[binradar_utils.ExecutionResult] = None
        self.transport: Optional[ForkserverTransport] = None

    def remaining_phase_time(self, cap: Optional[float] = None) -> Optional[float]:
        return self.deadline.remaining(cap)

    def phase_deadline_reached(self) -> bool:
        return self.deadline.expired()

    def start(self) -> None:
        self._process_cleanup_started = False
        self._process_cleanup_done = False
        if not self.forkserver_mode:
            self.process = subprocess.Popen(
                self.command, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, cwd=self.workdir, env=self.env,
                start_new_session=True)
            self.pgid = self.registry.register(self.process)
            logger.info(
                f"[TRACER] [{self.mode}] Started tracer without forkserver mode. "
                f"{' '.join(self.command)}")
            return

        self.transport = ForkserverTransport(self.env, self.mode)
        self.transport.setup()
        pass_fds = self.transport.pass_fds()
        self.process = subprocess.Popen(
            self.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=self.workdir, env=self.env, pass_fds=pass_fds,
            start_new_session=True)
        self.pgid = self.registry.register(self.process)
        self.transport.close_child_ends()

        logger.info(f"[TRACER] [{self.mode}] Started tracer {' '.join(self.command)}")
        banner = self.transport.read_u32(
            self.deadline.remaining(self.forkserver_init_timeout))
        if banner != HANDSHAKE_EXPECTED:
            raise RuntimeError(
                f"[TRACER] [{self.mode}] Unexpected forkserver handshake: {banner:#x}")
        self.transport.write_u32(HANDSHAKE_EXPECTED ^ 0xFFFFFFFF)
        ack = self.transport.read_u32(
            self.deadline.remaining(self.forkserver_timeout))
        if ack != HANDSHAKE_EXPECTED:
            raise RuntimeError(
                f"[TRACER] [{self.mode}] Unexpected forkserver ack: {ack:#x}")
        logger.info(
            f"[TRACER] [{self.mode}] Tracer forkserver started successfully.")

    def run(self) -> Tuple[int, bool, int]:
        if self.process is None:
            raise RuntimeError(
                f"[TRACER] [{self.mode}] Tracer process not started")
        started = time.monotonic()
        if not self.forkserver_mode:
            self.run_result = binradar_utils.execute_await(
                self.process, timeout=self.deadline.remaining())
            logger.info(
                f"[TRACER] [{self.mode}] Target process finished with exit code "
                f"{self.run_result.decode_status()}, success {self.run_result.success}")
            self.representative_runs = 1
            return (int((time.monotonic() - started) * 1000),
                    self.run_result.success, 0)
        try:
            assert self.transport is not None
            self.transport.write_u32(0)
            iteration, representative_runs, remaining = \
                self.transport.read_status(
                    self.deadline.remaining(self.forkserver_timeout))
            self.iter = iteration
            self.representative_runs = representative_runs
            if representative_runs == 0:
                raise RuntimeError(
                    f"[TRACER] [{self.mode}] Forkserver returned an empty "
                    f"iteration summary for iteration {iteration}")
            if self.mode != "binradar":
                logger.debug(
                    f"[TRACER] [{self.mode}] Logical iteration {iteration} "
                    f"finished after {representative_runs} child run(s); "
                    f"remaining {remaining}")
        except Exception as exc:
            logger.error(
                f"[TRACER] [{self.mode}] Error while waiting for tracer "
                f"forkserver: {exc}")
            if self.process.poll() is not None:
                logger.error(
                    f"[TRACER] [{self.mode}] Tracer process exited with code "
                    f"{self.process.returncode}")
            else:
                logger.error(
                    f"[TRACER] [{self.mode}] Tracer process is still running - "
                    "killing its process group")
            self._cleanup_process_group(grace=self.process_cleanup_grace)
            raise
        return int((time.monotonic() - started) * 1000), True, remaining

    def _cleanup_process_group(
            self, grace: float, wait_before_signal: float = 0.0) -> None:
        if self.process is None or self._process_cleanup_done:
            return
        process = self.process
        if self.pgid is None:
            self.pgid = self.registry.pgid(process)
        retry = self._process_cleanup_started
        self._process_cleanup_started = True
        if not retry and wait_before_signal and process.poll() is None:
            try:
                process.wait(timeout=wait_before_signal)
            except subprocess.TimeoutExpired:
                pass
        if self.pgid is not None:
            binradar_utils.kill_process_group(
                self.pgid, grace=0 if retry else grace,
                first_signal=signal.SIGKILL if retry else signal.SIGINT)
        else:
            logger.warning(
                f"[TRACER] [{self.mode}] No registered process group for pid "
                f"{process.pid}")
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=self.process_reap_timeout)
        except subprocess.TimeoutExpired:
            if self.pgid is not None:
                binradar_utils.kill_process_group(
                    self.pgid, grace=0, first_signal=signal.SIGKILL)
            else:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=self.process_reap_timeout)
            except subprocess.TimeoutExpired:
                logger.error(
                    f"[TRACER] [{self.mode}] Tracer did not reap after "
                    "process-group SIGKILL")
        if process.poll() is None:
            return
        self._process_cleanup_done = True
        self.registry.unregister(process)

    def stop(self) -> None:
        if self.transport is not None:
            self.transport.cleanup()
            self.transport = None
        if self.process is None:
            return
        logger.info(f"[TRACER] [{self.mode}] Stopping tracer process...")
        self._cleanup_process_group(
            grace=self.process_cleanup_grace,
            wait_before_signal=self.process_cleanup_wait)
        if self._process_cleanup_done:
            self.process = None


class SolverExecutor:
    def __init__(
            self, mode: str, testcase: str, run_dir: str, env: Dict[str, str],
            workdir: str, deadline: Deadline, fuzzy: bool = False,
            reverse_directed: bool = False,
            registry: ProcessRegistry = PROCESS_REGISTRY):
        self.mode = mode
        self.testcase = testcase
        self.run_dir = run_dir
        self.env = env
        self.workdir = workdir
        self.deadline = deadline
        self.fuzzy = fuzzy
        self.reverse_directed = reverse_directed
        self.registry = registry
        self.out_dir = os.path.join(run_dir, f"{mode}-tests")
        self.command: List[str] = []
        self.log_fp: Optional[BinaryIO] = None
        self.process: Optional[subprocess.Popen] = None
        self.pgid: Optional[int] = None
        self.run_result: Optional[binradar_utils.ExecutionResult] = None
        self.timed_out = False

    def _prepare(self) -> None:
        global_bitmap = os.path.join(self.run_dir, f"{self.mode}-branch-bitmap")
        context_bitmap = os.path.join(self.run_dir, f"{self.mode}-context-bitmap")
        memory_bitmap = os.path.join(self.run_dir, f"{self.mode}-memory-bitmap")
        os.makedirs(self.out_dir, exist_ok=True)
        for bitmap in (global_bitmap, context_bitmap, memory_bitmap):
            with open(bitmap, "w", encoding="utf-8"):
                pass
        solver_bin = (SOLVER_SMT_BIN if self.reverse_directed else
                      (SOLVER_FUZZY_BIN if self.fuzzy else SOLVER_SMT_BIN))
        self.command = [
            "stdbuf", "-o0", solver_bin, "-i", self.testcase,
            "-o", self.out_dir, "-b", global_bitmap, "-c", context_bitmap,
            "-m", memory_bitmap,
        ]
        self.log_fp = open(
            os.path.join(self.run_dir, f"{self.mode}-solver.log"), "wb")

    def start(self) -> None:
        self._prepare()
        logger.info(
            f"[SOLVER] [{self.mode}] Starting solver with command: "
            f"{' '.join(self.command)}")
        logger.debug(
            f"[SOLVER] [{self.mode}] phase deadline: {self.deadline.expires_at}")
        assert self.log_fp is not None
        self.process = subprocess.Popen(
            self.command, stdout=self.log_fp, stderr=subprocess.STDOUT,
            cwd=self.run_dir, env=self.env, start_new_session=True)
        self.pgid = self.registry.register(self.process)
        startup_wait = self.deadline.remaining(SOLVER_WAIT_TIME_AT_STARTUP)
        if startup_wait is None:
            startup_wait = SOLVER_WAIT_TIME_AT_STARTUP
        if startup_wait > 0:
            time.sleep(startup_wait)

    def create_inputs(self) -> None:
        if self.process is None:
            raise RuntimeError(
                f"[SOLVER] [{self.mode}] Solver process not started")
        logger.info(f"[SOLVER] [{self.mode}] Sending signal to create inputs...")
        self.process.send_signal(signal.SIGUSR1)

    def wait(self) -> Tuple[int, bool]:
        if self.process is None:
            raise RuntimeError(
                f"[SOLVER] [{self.mode}] Solver process not started - cannot wait")
        started = time.monotonic()
        self.timed_out = False
        while True:
            remaining = self.deadline.remaining(SOLVER_TIMEOUT)
            if remaining == 0:
                self.timed_out = True
                break
            try:
                self.process.wait(timeout=remaining)
                break
            except subprocess.TimeoutExpired:
                if self.deadline.expired():
                    self.timed_out = True
                    break
        if self.timed_out:
            logger.info(
                f"[SOLVER] [{self.mode}] Solver reached its phase deadline. "
                "Let us stop it.")
            try:
                self.process.send_signal(signal.SIGUSR2)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(SOLVER_TIMEOUT)
            except subprocess.TimeoutExpired:
                logger.info(f"[SOLVER] [{self.mode}] Solver will be killed.")
                self._kill_group()
        succeeded = not self.timed_out and self.process.returncode == 0
        return int((time.monotonic() - started) * 1000), succeeded

    def _kill_group(self) -> None:
        if self.process is None:
            return
        if self.pgid is None:
            self.pgid = self.registry.pgid(self.process)
        if self.pgid is not None:
            binradar_utils.kill_process_group(self.pgid, grace=1)
        else:
            logger.warning(
                f"[SOLVER] [{self.mode}] No registered process group for pid "
                f"{self.process.pid}")
            try:
                self.process.kill()
            except ProcessLookupError:
                pass

    def stop(self) -> None:
        try:
            if self.process is not None:
                process = self.process
                logger.info(f"[SOLVER] [{self.mode}] Stopping solver process...")
                if process.poll() is None:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._kill_group()
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                self._kill_group()
                if process.poll() is not None:
                    self.registry.unregister(process)
                    self.process = None
        finally:
            if self.log_fp is not None and not self.log_fp.closed:
                self.log_fp.close()


class PhaseSession:
    """LIFO owner for one phase's SHM, executors, transports and processes."""

    def __init__(
            self, mode: str, timeout: Optional[float], factor: float = 1.0,
            registry: ProcessRegistry = PROCESS_REGISTRY):
        self.mode = mode
        self.deadline = Deadline.from_timeout(timeout, factor)
        self.registry = registry
        self._cleanups: List[Tuple[str, Callable[[], None]]] = []
        self._closed = False

    def __enter__(self) -> "PhaseSession":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        del exc_type
        del traceback
        self.close(primary_exception=exc)
        return False

    def own(self, name: str, cleanup: Callable[[], None]) -> None:
        self._cleanups.append((name, cleanup))

    def shared_memory(
            self, env: Dict[str, str], include_patch_key: bool = False
    ) -> SharedMemoryManager:
        manager = SharedMemoryManager(env)
        self.own("shared memory", manager.cleanup)
        manager.assign_random_keys()
        if include_patch_key:
            manager.assign_random_key_for_binradar()
        return manager

    def start_solver(self, **kwargs) -> SolverExecutor:
        solver = SolverExecutor(
            deadline=self.deadline, registry=self.registry, **kwargs)
        self.own("solver", solver.stop)
        solver.start()
        return solver

    def start_tracer(self, **kwargs) -> TracerExecutor:
        tracer = TracerExecutor(
            deadline=self.deadline, registry=self.registry, **kwargs)
        self.own("tracer", tracer.stop)
        tracer.start()
        return tracer

    def track_process(self, process: subprocess.Popen) -> None:
        self.registry.register(process)
        self.own(
            f"process {process.pid}", lambda: self.registry.stop(process))

    def close(self, primary_exception: Optional[BaseException] = None) -> None:
        if self._closed:
            return
        self._closed = True
        failures: List[Tuple[str, BaseException]] = []
        while self._cleanups:
            name, cleanup = self._cleanups.pop()
            try:
                cleanup()
            except BaseException as exc:
                failures.append((name, exc))
                logger.error(f"[CLEANUP] Failed to release {name}: {exc}")
        if failures and primary_exception is None:
            name, failure = failures[0]
            raise RuntimeError(f"Failed to release {name}") from failure
