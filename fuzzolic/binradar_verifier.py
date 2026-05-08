import subprocess
import os
import signal
import shlex
from typing import List, Set, Tuple, Dict, Optional, Any

import sbsv

import logger

import binradar_utils

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU_STACKTRACE_RELEASE = os.path.join(ROOT_DIR, "LibAFL", "fuzzers", "binary_only", "qemu_stacktrace", "target", "release", "qemu_stacktrace")

class BinRadarVerifier:
    dir: str
    binary: str
    poc_input: str
    test_cmd: str
    target_function_entry: str
    patch_loc: str
    run_results: Optional[binradar_utils.ExecutionResult]
    def __init__(self, dir: str, binary: str, poc_input: str, test_cmd: str, target_function_entry: str, patch_loc: str):
        self.dir = dir
        self.binary = binary
        self.poc_input = poc_input
        self.test_cmd = test_cmd
        self.target_function_entry = target_function_entry
        self.patch_loc = patch_loc
        self.run_results = None
    
    @staticmethod
    def init(dir: str) -> "BinRadarVerifier":
        env = binradar_utils.load_env(os.path.join(dir, "config.env"))
        return BinRadarVerifier.init_from_env(dir, env)
    
    @staticmethod
    def init_from_env(dir: str, env: Dict[str, str]) -> "BinRadarVerifier":
        return BinRadarVerifier(
            dir=dir,
            binary=env["BINARY"],
            poc_input=env["POC_INPUT"],
            test_cmd=env["TEST_CMD"],
            target_function_entry=env["TARGET_FUNCTION_ENTRY"],
            patch_loc=env["PATCH_LOC"]
        )
    
    def original_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.orig")

    def get_qemu_stacktrace_command(self, binary: str, input_file: str) -> List[str]:
        return [QEMU_STACKTRACE_RELEASE, "--input", input_file, "--patch-loc", self.patch_loc, binary, "--"] + shlex.split(self.test_cmd)

    def test_with_original(self):
        command = self.get_qemu_stacktrace_command(self.original_binary(), self.poc_input)
        self.run_results = binradar_utils.execute(command, cwd=self.dir)
        parsed = self.parse_results(self.run_results.stderr)
    
    def parse_results(self, log: str) -> Dict[str, Any]:
        if self.run_results is None:
            raise ValueError("No results to parse. Please run the test first.")
        if not self.run_results.success:
            logger.error("Failed to execute the command.")
            return {}
        print(f"Success: {self.run_results.success}")
        print(f"Exit code: {self.run_results.exit_code}")
        print(f"Stdout: {self.run_results.stdout}")
        print(f"Stderr: {self.run_results.stderr}")
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[patch-info] [set: bool] [location: hex]")
        parser.add_schema("[exit] [result: str]")
        parser.add_schema("[stacktrace] [idx: int] [addr: hex] [symbol: str]")
        parser.add_schema("[patch-cov] [location: hex] [covered: bool] [hits: int]")
        parser.add_schema("[patch-func] [location: hex] [entry: hex] [hit: int]")
        result = parser.loads(log)
        return result


