import subprocess
import os
import signal
import shlex
import logging
import time
from typing import List, Set, Tuple, Dict, Optional, Any, TextIO

import sbsv

import logger

import binradar_utils

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU_TARGETED_SIMPLE_RELEASE = os.path.join(ROOT_DIR, "LibAFL", "fuzzers", "binary_only", "qemu_targeted_simple", "target", "release", "qemu_targeted_simple")
AFL_PATH = os.path.join(ROOT_DIR, "utils", "AFLplusplus")

class BinRadarFuzzer:
    def __init__(self, workdir: str, outdir: str, binary: str, poc_input: str, patch_loc: str, test_cmd: str, exclude_addrs: List[str] = []):
        self.workdir = workdir
        self.outdir = outdir
        os.makedirs(self.outdir, exist_ok=True)
        self.binary = binary
        self.poc_input = poc_input
        self.patch_loc = patch_loc
        self.test_cmd = test_cmd
        self.exclude_addrs = exclude_addrs
        self.process: Optional[subprocess.Popen] = None
    
    @classmethod
    def from_workdir(cls, dir: str, outdir: str) -> "BinRadarFuzzer":
        env = binradar_utils.load_env(os.path.join(dir, "binradar.env"))
        return cls.from_env(dir, outdir, env)

    @classmethod
    def from_env(cls, dir: str, outdir: str, env: Dict[str, str]) -> "BinRadarFuzzer":
        return cls(
            workdir=dir,
            outdir=outdir,
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            patch_loc=env["PATCH_LOC"],
            test_cmd=env["TEST_CMD"],
            exclude_addrs=[env["PATCH_RESERVE_RANGE"], env["E9_TRAMPOLINE_RANGE"], env["E9_LOADER_RANGE"]]
        )
    
    def get_patched_binary_path(self) -> str:
        return os.path.join(self.workdir, f"{self.binary}.brpatched")

    def start(self) -> subprocess.Popen:
        raise NotImplementedError("start() method must be implemented in subclasses")

    def wait(self, timeout: float = 1800.0):
        if self.process:
            result = binradar_utils.execute_await(self.process, timeout=timeout, verbose=True)
            if result is None:
                logger.info("Fuzzer execution timed out.")
                return
    
    def get_testcase_dirs(self) -> List[str]:
        raise NotImplementedError("get_testcase_dirs() method must be implemented")

class TargetedSimpleFuzzer(BinRadarFuzzer):
    def get_qemu_targeted_simple_command(self, binary: str, input_path: str) -> List[str]:
        cmd = [
            QEMU_TARGETED_SIMPLE_RELEASE,
            "-t", self.patch_loc,
            "-i", input_path,
            "-o", self.outdir,
            "--asan", "host",
        ]
        for addr_range in self.exclude_addrs:
            cmd += ["--asan-exclude", addr_range]
        cmd = cmd + [binary, "--",] + shlex.split(self.test_cmd)
        return cmd

    def start(self) -> subprocess.Popen:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        command = self.get_qemu_targeted_simple_command(self.get_patched_binary_path(), self.poc_input)
        logger.info(f"Running command: {' '.join(command)}")
        with open(os.path.join(self.outdir, "fuzzer.log"), "w") as log_file:
            self.process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, cwd=self.workdir, start_new_session=True, env=env)
        return self.process

    def get_testcase_dirs(self) -> List[str]:
        return []
            
class AFLppFuzzer(BinRadarFuzzer):
    def get_aflpp_command(self, binary: str, input_path: str) -> List[str]:
        cmd = [
            os.path.join(AFL_PATH, "afl-fuzz"),
            "-Q",
            "-t", "3000",
            "-i", input_path,
            "-o", self.outdir,
        ]
        # for addr_range in self.exclude_addrs:
        #     cmd += ["--asan-exclude", addr_range]
        cmd = cmd + ["--", binary] + shlex.split(self.test_cmd)
        return cmd

    def start(self) -> subprocess.Popen:
        env = os.environ.copy()
        # env["LC_ALL"] = "C"
        env["AFL_PATH"] = AFL_PATH
        env["AFL_NO_UI"] = "1"
        env["AFL_USE_QASAN"] = "1"
        # Currently, all benchmarks are using poc/testcases
        # But if it's not, it can be problematic
        input_dir = os.path.dirname(self.poc_input)
        command = self.get_aflpp_command(self.get_patched_binary_path(), input_dir)
        logger.info(f"Running command: {' '.join(command)}")
        with open(os.path.join(self.outdir, "fuzzer.log"), "w") as log_file:
            self.process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, cwd=self.workdir, start_new_session=True, env=env)
        return self.process

    def get_testcase_dirs(self) -> List[str]:
        outdirs = [
            os.path.join(self.outdir, "default", "queue"),
            os.path.join(self.outdir, "default", "crashes")
        ]
        return outdirs
