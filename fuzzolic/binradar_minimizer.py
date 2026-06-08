#!/usr/bin/env python3

import os
import sys
import glob
import subprocess
import tempfile
import shutil
import hashlib
import logging
import time

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
"""
class BinRadarMinimizer:
    work_dir: str
    run_dir: str
    minimized_dir: str
    testcases_dirs: List[str]
    files: Set[str]
    testcases: Set[TestcaseInfo]
    config: Dict[str, str]
    logger: logging.Logger
    start_time: float
    def __init__(self, work_dir: str, run_dir: str, testcases_dirs: List[str], config: Dict[str, str]):
        self.work_dir = work_dir
        self.run_dir = run_dir
        self.minimized_dir = os.path.join(run_dir, "minimized")
        if os.path.exists(self.minimized_dir):
            shutil.rmtree(self.minimized_dir)
        os.makedirs(self.minimized_dir, exist_ok=True)
        self.testcases_dirs = testcases_dirs
        self.files = set()
        self.testcases = set()
        self.config = config
        self.start_time = time.time()
        # Setup logger
        log_file = os.path.join(run_dir, "minimizer.sbsv")
        self.logger = logging.getLogger(__name__)
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_file, mode="w")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s - %(message)s")
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
    
    def log(self, msg: str):
        elapsed = int((time.time() - self.start_time) * 1000)
        self.logger.info(f"{msg} [time {elapsed}]")
    
    def load_testcases(self):
        for testcases_dir in self.testcases_dirs:
            for testcase_file in sorted(glob.glob(os.path.join(testcases_dir, "*"))):
                if testcase_file in self.files:
                    continue
                self.files.add(testcase_file)
                with open(testcase_file, "rb") as f:
                    data = f.read()
                    testcase_info = TestcaseInfo(data, testcase_file)
                    if testcase_info in self.testcases:
                        continue
                    self.testcases.add(testcase_info)
    
    def run_testcases(self):
        runner = binradar_verifier.BinRadarQemuRunner.from_env(self.work_dir, self.config)
        id = 0
        env = os.environ.copy()
        with tempfile.TemporaryDirectory(dir=self.run_dir) as tmpdir:
            current_testcase = os.path.join(tmpdir, ".cur_input")
            for testcase in sorted(self.testcases):
                self.log(f"[testcase] [try] [id {id}] / {len(self.testcases)}: [file {testcase.filename}]")
                if os.path.exists(current_testcase):
                    os.unlink(current_testcase)
                os.link(testcase.filename, current_testcase)
                # TODO: better minimization
                run_res, patch_res = runner.test_with_patched("0", current_testcase, env=env, verbose=False)
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
                save_file = f"{id}_{os.path.basename(testcase.filename)}"
                os.link(testcase.filename, os.path.join(self.minimized_dir, save_file))
                self.log(f"[testcase] [result] [id {id}] [file {save_file}] {run_res.serialize()} {patch_res.serialize()}")
                id += 1