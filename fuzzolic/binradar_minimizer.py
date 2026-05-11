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
    testcases: Dict[str, TestcaseInfo]
    config: Dict[str, str]
    logger: logging.Logger
    start_time: float
    def __init__(self, work_dir: str, run_dir: str, testcases_dirs: List[str], config: Dict[str, str]):
        self.work_dir = work_dir
        self.run_dir = run_dir
        self.minimized_dir = os.path.join(run_dir, "minimized")
        os.makedirs(self.minimized_dir, exist_ok=True)
        self.testcases_dirs = testcases_dirs
        self.files = set()
        self.testcases = dict()
        self.config = config
        self.start_time = time.time()
        log_file = os.path.join(run_dir, "minimizer.sbsv")
        self.logger = logging.getLogger(__name__)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s - %(message)s")
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
    
    def log(self, msg: str):
        elapsed = int((time.time() - self.start_time) * 1000)
        self.logger.info(f"{msg} [time {elapsed}]")
    
    def load_testcases(self):
        for testcases_dir in self.testcases_dirs:
            for testcase_file in glob.glob(os.path.join(testcases_dir, "*")):
                if testcase_file in self.files:
                    continue
                self.files.add(testcase_file)
                with open(testcase_file, "rb") as f:
                    data = f.read()
                    testcase_info = TestcaseInfo(data, testcase_file)
                    if testcase_info.hash in self.testcases:
                        continue
                    self.testcases[testcase_info.hash] = testcase_info
    
    def run_testcases(self):
        verifier = binradar_verifier.BinRadarVerifier.init_from_env(self.work_dir, self.config)
        id = 0
        with tempfile.TemporaryDirectory(dir=self.run_dir) as tmpdir:
            current_testcase = os.path.join(tmpdir, ".cur_input")
            for hash, testcase in self.testcases.items():
                id += 1
                self.log(f"[testcase] [info] [id {id}] / {len(self.testcases)}: [file {testcase.filename}]")
                if os.path.exists(current_testcase):
                    os.unlink(current_testcase)
                os.link(testcase.filename, current_testcase)
                # TODO: better minimization
                run_result = verifier.test_with_original(current_testcase)
                if run_result is None:
                    self.log(f"Failed {testcase.filename} with error.")
                    continue
                save_file = f"{id}_{os.path.basename(testcase.filename)}"
                os.link(testcase.filename, os.path.join(self.minimized_dir, save_file))
                self.log(f"[testcase] [result] [id {id}] [file {save_file}] {run_result.serialize()}")
                