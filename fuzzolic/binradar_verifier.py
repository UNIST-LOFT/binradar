import subprocess
import os
import signal
import shlex
from typing import List, Set, Tuple, Dict, Optional, Any, TextIO

import sbsv

import logger

import binradar_utils

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QEMU_STACKTRACE_RELEASE = os.path.join(ROOT_DIR, "LibAFL", "fuzzers", "binary_only", "qemu_stacktrace", "target", "release", "qemu_stacktrace")

class BinRadarProbeResult:
    def __init__(self, patch_loc: int, patch_func_entry: int, stacktrace: List[Tuple[int, str]], exit_info: str, patch_hit_cnt: int, patch_func_hit_cnt: int, fault_addr: int):
        self.patch_loc = patch_loc
        self.patch_func_entry = patch_func_entry
        self.stacktrace = stacktrace
        self.exit_info = exit_info
        self.patch_hit_cnt = patch_hit_cnt
        self.patch_func_hit_cnt = patch_func_hit_cnt
        self.fault_addr = fault_addr
    
    @staticmethod
    def get_parser() -> sbsv.parser:
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[patch-info] [set: bool] [location: hex]")
        parser.add_schema("[exit] [result: str]")
        parser.add_schema("[stacktrace] [idx: int] [addr: hex] [symbol: str]")
        parser.add_schema("[patch-cov] [location: hex] [covered: bool] [hits: int]")
        parser.add_schema("[patch-func] [location: hex] [entry: hex] [hit: int]")
        parser.add_schema("[fault-addr] [idx: int] [addr: hex] [symbol: str]")
        return parser
    
    @staticmethod
    def load_from_log(log: str) -> Optional["BinRadarProbeResult"]:
        parser = BinRadarProbeResult.get_parser()
        result = parser.loads(log)
        if len(result["patch-info"]) == 0:
            logger.error("No patch info found in the log.")
            return None
        patch_info = result["patch-info"][-1]
        if not patch_info["set"]:
            logger.error("Patch was not set during execution.")
            return None
        patch_loc = patch_info["location"]
        if len(result["exit"]) == 0:
            logger.error("No exit info found in the log.")
            return None
        exit_info = result["exit"][-1]
        exit_result = exit_info["result"]
        if len(result["stacktrace"]) == 0:
            logger.error("No stacktrace info found in the log.")
            return None
        stacktrace = [(entry["addr"], entry["symbol"]) for entry in result["stacktrace"]]
        if len(result["patch-cov"]) == 0:
            logger.error("No patch coverage info found in the log.")
            return None
        patch_cov_info = result["patch-cov"][-1]
        if not patch_cov_info["covered"]:
            logger.error("Patch location was not covered during execution.")
            return None
        patch_hit_cnt = patch_cov_info["hits"]
        if len(result["patch-func"]) == 0:
            logger.error("No patch function info found in the log.")
            return None
        if len(result["patch-func"]) > 1:
            logger.warning("Multiple patch function entries found in the log. Using the last one.")
            return None
        if len(result["fault-addr"]) == 0:
            logger.error("No fault address info found in the log.")
            return None
        patch_func_info = result["patch-func"][-1]
        patch_func_entry = patch_func_info["entry"]
        patch_func_hit_cnt = patch_func_info["hit"]
        fault_addr_info = result["fault-addr"][-1]
        fault_addr = fault_addr_info["addr"]
        return BinRadarProbeResult(
            patch_loc=patch_loc,
            patch_func_entry=patch_func_entry,
            stacktrace=stacktrace,
            exit_info=exit_result,
            patch_hit_cnt=patch_hit_cnt,
            patch_func_hit_cnt=patch_func_hit_cnt,
            fault_addr=fault_addr
        )
    
    def serialize(self) -> str:
        return f"[exit {self.exit_info}] [func-entry {self.patch_func_entry:x}] [func-hit {self.patch_func_hit_cnt}] [patch {self.patch_loc:x}] [patch-hit {self.patch_hit_cnt}] [fault-addr {self.fault_addr:x}]"


class BinRadarDetailedProbeResult(BinRadarProbeResult):
    pass

class BinRadarVerifier:
    dir: str
    binary: str
    test_cmd: str
    patch_loc: str
    run_results: Optional[binradar_utils.ExecutionResult]
    def __init__(self, dir: str, binary: str, test_cmd: str, patch_loc: str):
        self.dir = dir
        self.binary = binary
        self.test_cmd = test_cmd
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
            test_cmd=env["TEST_CMD"],
            patch_loc=env["PATCH_LOC"]
        )
    
    def original_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.orig")

    def get_qemu_stacktrace_command(self, binary: str, input_file: str) -> List[str]:
        return [QEMU_STACKTRACE_RELEASE, "--input", input_file, "--patch-loc", self.patch_loc, binary, "--"] + shlex.split(self.test_cmd)

    def test_with_original(self, testcase: str) -> Optional[BinRadarProbeResult]:
        command = self.get_qemu_stacktrace_command(self.original_binary(), testcase)
        result = binradar_utils.execute(command, cwd=self.dir)
        if not result.success:
            logger.error("Failed to execute the command.")
            return None
        return BinRadarProbeResult.load_from_log(result.stderr)


