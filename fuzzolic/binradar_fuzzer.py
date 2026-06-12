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


class BinRadarFuzzer:
    def __init__(self, workdir: str, outdir: str, binary: str, poc_input: str, patch_loc: str, test_cmd: str):
        self.workdir = workdir
        self.outdir = outdir
        os.makedirs(self.outdir, exist_ok=True)
        self.binary = binary
        self.poc_input = poc_input
        self.patch_loc = patch_loc
        self.test_cmd = test_cmd
    
    @staticmethod
    def from_workdir(dir: str, outdir: str) -> "BinRadarFuzzer":
        env = binradar_utils.load_env(os.path.join(dir, "config.env"))
        return BinRadarFuzzer.from_env(dir, outdir, env)

    @staticmethod
    def from_env(dir: str, outdir: str, env: Dict[str, str]) -> "BinRadarFuzzer":
        return BinRadarFuzzer(
            workdir=dir,
            outdir=outdir,
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            patch_loc=env["PATCH_LOC"],
            test_cmd=env["TEST_CMD"],
        )
    
    def get_qemu_targeted_simple_command(self, binary: str, input_path: str) -> List[str]:
        cmd = [
            QEMU_TARGETED_SIMPLE_RELEASE,
            "-t", self.patch_loc,
            "-i", input_path,
            "-o", self.outdir,
            binary,
            "--",
        ] + shlex.split(self.test_cmd)
        return cmd
    
    def get_patched_binary_path(self) -> str:
        return os.path.join(self.workdir, f"{self.binary}.brpatched")

    def run(self, timeout: float = 1800.0):
        command = self.get_qemu_targeted_simple_command(self.get_patched_binary_path(), self.poc_input)
        logger.info(f"Running command: {' '.join(command)}")
        with open(os.path.join(self.outdir, "fuzzer.log"), "w") as log_file:
            process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, cwd=self.workdir, start_new_session=True)
        result = binradar_utils.execute_await(process, timeout=timeout, verbose=True)
        if result is None:
            logger.info("QEMU execution timed out.")
            return
    