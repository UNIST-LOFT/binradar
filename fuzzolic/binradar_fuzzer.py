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

    def run(self, timeout: float = 1800.0):
        command = self.get_qemu_targeted_simple_command(self.binary, self.poc_input)
        logger.info(f"Running command: {' '.join(command)}")
        result = binradar_utils.execute(command, cwd=self.workdir, timeout=timeout)
        if result is None:
            logger.info("QEMU execution timed out.")
            return
    