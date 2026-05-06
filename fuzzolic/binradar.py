import os
import sys
import glob
import subprocess
import time
import signal
import re
import shutil
import functools
import tempfile
import random
import ctypes
import resource
import errno
import struct
import select
import threading
import io
import argparse
import shlex
from typing import List, Set, Tuple, Dict, Optional

import sbsv

import analyze_type
import binradar_minimizer
import binradar_verifier
import logger

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SOLVER_SMT_BIN = SCRIPT_DIR + '/../solver/build/solver-smt'
SOLVER_FUZZY_BIN = SCRIPT_DIR + '/../solver/build/solver-fuzzy'
TRACER_BIN = SCRIPT_DIR + '/../tracer/build/x86_64-linux-user/qemu-x86_64'

SOLVER_WAIT_TIME_AT_STARTUP = 0.0010
SOLVER_TIMEOUT = 10000
SHUTDOWN = False

RUNNING_PROCESSES = []
MAX_VIRTUAL_MEMORY = 16 * 1024 * 1024 * 1024 # 16 GB

def setlimits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_VIRTUAL_MEMORY, MAX_VIRTUAL_MEMORY))

class SolverExecutor:
    def __init__(self, timeout: int):
        self.timeout = timeout
    
    def start(self, command: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None) -> subprocess.Popen:
        return binradar_verifier.execute_async(command, env=env, cwd=cwd, timeout=self.timeout)

class TracerExecutor:
    def __init__(self, timeout: int):
        self.timeout = timeout
    
    def execute(self, command: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None) -> Tuple[bool, int, str, str]:
        return binradar_verifier.execute(command, env=env, cwd=cwd, timeout=self.timeout)

class BinRadarExecutor:
    workdir: str
    outdir: str
    timeout: int
    binary: str
    poc_input: str
    test_cmd: str
    target_function_entry: str
    patch_loc: str
    run_results: Optional[Tuple[bool, int, str, str]]
    def __init__(self, workdir: str, outdir: str, timeout: int, binary: str, poc_input: str, test_cmd: str, target_function_entry: str, patch_loc: str):
        self.workdir = workdir
        self.outdir = outdir
        self.timeout = timeout
        self.binary = binary
        self.poc_input = poc_input
        self.test_cmd = test_cmd
        self.target_function_entry = target_function_entry
        self.patch_loc = patch_loc
        self.run_results = None
    
    @staticmethod
    def init(workdir: str) -> "BinRadarExecutor":
        env = binradar_verifier.load_env(os.path.join(workdir, "config.env"))
        return BinRadarExecutor.init_from_env(workdir, env)
    
    @staticmethod
    def init_from_env(workdir: str, env: Dict[str, str]) -> "BinRadarExecutor":
        return BinRadarExecutor(
            workdir=workdir,
            outdir=env["BINRADAR_OUTDIR"],
            timeout=int(env["BINRADAR_TIMEOUT"]),
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            test_cmd=env["TEST_CMD"],
            target_function_entry=env["TARGET_FUNCTION_ENTRY"],
            patch_loc=env["PATCH_LOC"]
        )
    
    def original_binary(self) -> str:
        return os.path.join(self.workdir, f"{self.binary}.orig")

    def get_tracer_command(self, binary: str, input_file: str) -> List[str]:
        return [TRACER_BIN, "-symbolic", "-d", "page", binary] + shlex.split(self.test_cmd.replace("@@", input_file))

    def get_solver_command(self, input_file: str) -> List[str]:
        return [SOLVER_SMT_BIN, "-i", input_file, "-t", self.outdir, "-o", self.outdir, "-p"]
    
    def test_with_original(self):
        command = self.get_tracer_command(self.original_binary(), self.poc_input)
        self.run_results = binradar_verifier.execute(command, cwd=self.workdir, timeout=self.timeout)

def main():
    setlimits()
    parser = argparse.ArgumentParser(
        description='binradar: a binary patch verification tool')
    # positional args passed to BinRadarExecutor
    parser.add_argument("-w", "--workdir", required=True, help="set the working directory for binradar")
    parser.add_argument("-t", "--timeout", type=int, default=SOLVER_TIMEOUT, help="set timeout for each test case (ms)")
    parser.add_argument("-f", "--target-function-entry", default="", help="set the target function entry point for fuzzolic (hex)")
    parser.add_argument("-p", "--patch-loc", default="", help="set the patch location for fuzzolic (hex)")
    parser.add_argument("-i", "--input", default="", help="set the input file for fuzzolic")
    parser.add_argument("-o", "--output", default="workdir", help="set the output directory for fuzzolic")
    parser.add_argument("--cmd", default="", help="set the test command for fuzzolic (overrides TEST_CMD in config.env)")
    args = parser.parse_args()
    if not os.path.exists(args.workdir):
        sys.exit("ERROR: workdir does not exist.")
    
    env = binradar_verifier.load_env(os.path.join(args.workdir, "config.env"))
    # Override env with command line arguments if provided
    if args.target_function_entry:
        env["TARGET_FUNCTION_ENTRY"] = args.target_function_entry
    if args.patch_loc:
        env["PATCH_LOC"] = args.patch_loc
    if args.input:
        env["POC_INPUT"] = args.input
    if args.cmd:
        env["TEST_CMD"] = args.cmd
    output_dir = args.output
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    env["BINRADAR_OUTDIR"] = output_dir
    env["BINRADAR_WORKDIR"] = args.workdir
    env["BINRADAR_TIMEOUT"] = str(args.timeout)
    binradar_verifier.save_env(env, os.path.join(output_dir, "config.env"))
    executor = BinRadarExecutor.init_from_env(args.workdir, env)
    