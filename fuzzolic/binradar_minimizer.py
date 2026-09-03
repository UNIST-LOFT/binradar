#!/usr/bin/env python3

import os
import sys
import glob
import subprocess
import tempfile
import shutil
import hashlib
import time
import threading
import queue
import fcntl

from typing import List, Dict, Set, Tuple, Any, Optional

import binradar_verifier

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU_STACKTRACE_RELEASE = os.path.join(ROOT_DIR, "LibAFL", "fuzzers", "binary_only", "qemu_stacktrace", "target", "release", "qemu_stacktrace")

class TestcaseInfo:
    hash: str
    data: bytes
    filename: str
    is_crash: bool
    patch_hit_cnt: int
    patch_func_hit_cnt: int
    stacktrace: List[Tuple[int, str]]
    fault_addr: Optional[Tuple[int, str]]
    def __init__(self, data: bytes, filename: str):
        self.data = data
        self.filename = filename
        self.hash = self.compute_hash(data)
        self.is_crash = False
        self.patch_hit_cnt = 0
        self.patch_func_hit_cnt = 0
        self.stacktrace = []
        self.fault_addr = None
    
    def __hash__(self):
        return hash(self.hash)
    
    def __eq__(self, other):
        if not isinstance(other, TestcaseInfo):
            return False
        return self.hash == other.hash

    def __lt__(self, other):
        return self.filename < other.filename
    
    def compute_hash(self, data: bytes) -> str:
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

"""
Minimize testcases
Filter out same testcases based on hash, 
and run them to get more info (patch hit count, stacktrace, etc).
Currently, we just run them one by one, which is not very efficient.
Plus, we only check if they hit the patch or not, without doing any actual minimization.

In streaming mode (producer_threads given to run_testcases), testcase files are
discovered incrementally while the producer phases (fuzzolic/directed/fuzzer)
still run. Producers publish final filenames atomically; temporary
``*.binradar-part`` files are ignored. The age guard remains a conservative
delay for unknown/external writers, not the publication protocol.
"""


class _MinimizerCancelled(Exception):
    """Internal cooperative-cancellation signal for verifier failures."""


class BinRadarMinimizer:
    work_dir: str
    run_dir: str
    probe_result: binradar_verifier.BinRadarProbeResult
    minimized_dir: str
    testcases_dirs: List[str]
    files: Dict[str, Tuple[int, int, int, int]]
    testcases: Set[TestcaseInfo]
    pending: List[TestcaseInfo]
    min_file_age: float
    config: Dict[str, str]
    log_file: str
    start_time: float
    def __init__(self, work_dir: str, run_dir: str, probe_result: binradar_verifier.BinRadarProbeResult, testcases_dirs: List[str], config: Dict[str, str],
                 min_file_age: float = 10.0):
        self.work_dir = work_dir
        self.run_dir = run_dir
        self.minimized_dir = os.path.join(run_dir, "minimized")
        if os.path.exists(self.minimized_dir):
            shutil.rmtree(self.minimized_dir)
        os.makedirs(self.minimized_dir, exist_ok=True)
        self.testcases_dirs = testcases_dirs
        self.files = {}
        self.testcases = set()
        self.pending = list()
        self.min_file_age = min_file_age
        self.config = config
        self.probe_result = probe_result
        self.start_time = time.time()
        self.log_file = os.path.join(run_dir, "minimizer.sbsv")
        with open(self.log_file, "a+", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            f.truncate()
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def log(self, msg: str):
        elapsed = int((time.time() - self.start_time) * 1000)
        ts = time.strftime("%Y-%m-%d %H:%M:%S") + f",{int(time.time() * 1000) % 1000:03d}"
        line = f"{ts} - {msg} [time {elapsed}]\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(line)
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)

    def load_testcases(self):
        """One-shot discovery: scan every testcase dir once (standalone runs
        where the producers have already finished)."""
        self.scan_testcases(producers_alive=False)

    def scan_testcases(self, producers_alive: bool = False):
        """Discover testcase files not seen before and queue the new unique
        ones for processing.

        Producers write ``*.binradar-part`` and atomically rename/link the
        completed file into its final name. Partial names are ignored. While
        ``producers_alive`` is true, the additional ``min_file_age`` guard
        defers recently modified final files from unknown/external writers;
        files that vanish between glob and open are retried. Once every
        producer has ended, the final scan reads every published final file.
        """
        for testcases_dir in self.testcases_dirs:
            for testcase_file in sorted(glob.glob(os.path.join(testcases_dir, "*"))):
                if (testcase_file.endswith(".binradar-part")
                        or os.path.basename(testcase_file) == "README.txt"):
                    continue
                if producers_alive and self._recently_modified(testcase_file):
                    continue
                try:
                    path_stat = os.stat(testcase_file)
                    path_version = self._file_version(path_stat)
                    if self.files.get(testcase_file) == path_version:
                        continue
                    with open(testcase_file, "rb") as f:
                        data = f.read()
                        opened_version = self._file_version(os.fstat(f.fileno()))
                except OSError:
                    if producers_alive:
                        continue
                    raise
                # Remember the inode actually read, not the pre-open path.
                # If an atomic producer replacement won the race with open(),
                # the next scan sees the new path version and consumes it too.
                self.files[testcase_file] = opened_version
                testcase_info = TestcaseInfo(data, testcase_file)
                if testcase_info in self.testcases:
                    continue
                self.testcases.add(testcase_info)
                self.pending.append(testcase_info)

    @staticmethod
    def _file_version(stat: os.stat_result) -> Tuple[int, int, int, int]:
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def _recently_modified(self, path: str) -> bool:
        """Conservatively defer a recently changed external final file.

        BinRadar's own producers use atomic publication; this guard covers
        unknown writers while producer phases are still active.
        """
        try:
            stat = os.stat(path)
        except OSError:
            return True
        return (time.time() - stat.st_mtime) < self.min_file_age
    
    def run_testcases(self,
                      producer_threads: Optional[List[threading.Thread]] = None,
                      producer_exc_queue: Optional["queue.Queue[BaseException]"] = None,
                      poll_interval: float = 0.2,
                      scan_interval: float = 1.0,
                      cancel_event: Optional[threading.Event] = None) -> None:
        """Run the discovered testcases and log one [testcase] row per kept
        testcase, then the done marker.

        With ``producer_threads`` (streaming mode), testcases are discovered
        while the producers still run: each round rescans the testcase dirs,
        processes whatever is new, and polls until every producer thread has
        ended; a final scan without the file-age guard then picks up
        everything written before the producers exited. A failure queued in
        ``producer_exc_queue`` is re-raised so the minimizer aborts instead
        of silently verifying a truncated testcase set. Without producers,
        all queued testcases are processed once (previous behavior).
        """
        runner = binradar_verifier.BinRadarQemuRunner.from_env(self.work_dir, self.config)
        id = 0
        last_scan = 0.0
        with tempfile.TemporaryDirectory(dir=self.run_dir) as tmpdir:
            current_testcase = os.path.join(tmpdir, ".cur_input")
            while True:
                self._raise_if_cancelled(cancel_event)
                self._raise_producer_failure(producer_exc_queue)
                producers_alive = (producer_threads is not None
                                   and any(t.is_alive() for t in producer_threads))
                now = time.time()
                if (now - last_scan) >= scan_interval or not producers_alive:
                    self.scan_testcases(producers_alive=producers_alive)
                    last_scan = now
                id = self._process_pending(
                    runner, id, current_testcase, producer_exc_queue,
                    cancel_event)
                if not producers_alive:
                    self._raise_producer_failure(producer_exc_queue)
                    break
                time.sleep(poll_interval)
        self.log("[minimizer] [done]")

    @staticmethod
    def _raise_if_cancelled(
            cancel_event: Optional[threading.Event]) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise _MinimizerCancelled()

    @staticmethod
    def _raise_producer_failure(
            producer_exc_queue: Optional["queue.Queue[BaseException]"]) -> None:
        if producer_exc_queue is None:
            return
        try:
            exc = producer_exc_queue.get_nowait()
        except queue.Empty:
            return
        raise exc

    def _process_pending(
            self, runner, id: int, current_testcase: str,
            producer_exc_queue: Optional["queue.Queue[BaseException]"] = None,
            cancel_event: Optional[threading.Event] = None) -> int:
        """Run queued immutable testcase snapshots and return the next id."""
        for testcase in sorted(self.pending):
            self._raise_if_cancelled(cancel_event)
            self._raise_producer_failure(producer_exc_queue)
            self.log(f"[testcase] [try] [id {id}] / {len(self.testcases)}: [file {testcase.filename}]")
            with open(current_testcase, "wb") as f:
                f.write(testcase.data)
            # TODO: better minimization
            run_res, patch_res = runner.test_with_patched("0", current_testcase, verbose=False)
            # run_result = runner.test_with_original(current_testcase, verbose=False)
            if run_res is None:
                self.log(f"Failed {testcase.filename} with error.")
                continue
            if not run_res.patch_hit():
                self.log(f"[testcase] [skip] [id {id}] [file {testcase.filename}] {run_res.serialize()}")
                continue
            if patch_res is None:
                self.log(f"Failed to run patched binary for {testcase.filename}.")
                continue
            self._raise_if_cancelled(cancel_event)
            self._raise_producer_failure(producer_exc_queue)
            save_file = f"{id}_{os.path.basename(testcase.filename)}"
            with open(os.path.join(self.minimized_dir, save_file), "wb") as f:
                f.write(testcase.data)
            self.log(f"[testcase] [result] [id {id}] [file {save_file}] {run_res.serialize()} {patch_res.serialize()}")
            id += 1
        self.pending.clear()
        return id


def run_minimizer_and_verifier(minimizer: BinRadarMinimizer,
                               verifier: "binradar_verifier.BinRadarConcreteVerifier",
                               minimizer_result_file: str,
                               poll_interval: float = 0.2,
                               producer_threads: Optional[List[threading.Thread]] = None,
                               producer_exc_queue: Optional["queue.Queue[BaseException]"] = None) -> None:
    """Run the minimizer and the concrete verifier concurrently: the verifier
    streams [testcase] [result] rows from minimizer.sbsv while the minimizer
    appends them, and finishes when the minimizer ends (or earlier, when every
    patch is already rejected). The minimizer's exceptions are re-raised here.

    With ``producer_threads`` (the fuzzolic/directed/fuzzer threads), the
    minimizer itself streams too: it discovers testcase files while those
    phases still run and finishes only after all of them have ended. A
    producer failure raised through ``producer_exc_queue`` aborts the
    minimizer and therefore the verifier.
    """
    exc_queue: "queue.Queue[BaseException]" = queue.Queue()
    cancel_event = threading.Event()

    def _run_minimizer():
        try:
            minimizer.run_testcases(
                producer_threads=producer_threads,
                producer_exc_queue=producer_exc_queue,
                poll_interval=poll_interval,
                cancel_event=cancel_event)
        except _MinimizerCancelled:
            # The verifier failed. Leave the stream incomplete and let the
            # verifier's original exception remain authoritative.
            return
        except BaseException as exc:
            exc_queue.put(exc)

    thread = threading.Thread(target=_run_minimizer, name="minimizer", daemon=True)
    thread.start()
    try:
        verifier.run_verification_streaming(
            minimizer_result_file,
            poll_interval=poll_interval,
            minimizer_thread=thread,
            minimizer_exc_queue=exc_queue,
        )
        thread.join()
    except BaseException:
        # Cooperatively stop discovery/processing. A currently running QEMU
        # check has a bounded timeout; join fully so no minimizer can keep
        # mutating the run directory after this function returns.
        cancel_event.set()
        thread.join()
        raise
    if not exc_queue.empty():
        raise exc_queue.get()
