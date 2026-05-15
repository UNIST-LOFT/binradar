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
QEMU_STACKTRACE_RELEASE = os.path.join(ROOT_DIR, "LibAFL", "fuzzers", "binary_only", "qemu_stacktrace", "target", "release", "qemu_stacktrace")

class BinRadarProbeResult:
    def __init__(self, patch_loc: int, patch_func_entry: int, stacktrace: List[Tuple[int, str]], exit_info: str, patch_hit_cnt: int, patch_func_hit_cnt: int, fault_addr: int, patch_func_candidates: List[Tuple[int, int]]):
        self.patch_loc = patch_loc
        self.patch_func_entry = patch_func_entry
        self.stacktrace = stacktrace
        self.exit_info = exit_info
        self.patch_hit_cnt = patch_hit_cnt
        self.patch_func_hit_cnt = patch_func_hit_cnt
        self.fault_addr = fault_addr
        self.patch_func_candidates = patch_func_candidates
        self.need_file_hook = False
    
    @staticmethod
    def get_parser() -> sbsv.parser:
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[patch-info] [set: bool] [location: hex]")
        parser.add_schema("[exit] [result: str]")
        parser.add_schema("[qemu-exit] [kind: str] [detail: str]")
        parser.add_schema("[stacktrace] [idx: int] [addr: hex] [symbol: str]")
        parser.add_schema("[patch-cov] [location: hex] [covered: bool] [hits: int]")
        parser.add_schema("[patch-func] [location: hex] [entry: hex] [hits: int]")
        parser.add_schema("[fault-addr] [idx: int] [addr: hex] [symbol: str]")
        return parser
    
    @staticmethod
    def get_parser_for_file_trace() -> sbsv.parser:
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[patch-func-entry] [set] [set: bool]")
        parser.add_schema("[file-trace] [open] [path: str] [fd: int] [gid: int] [offset: int] [seekable: bool] [after_patch: bool]")
        parser.add_schema("[file-trace] [read] [syscall: int] [fd: int] [gid: int] [offset: int] [seekable: bool] [bytes: int] [after_patch: bool]")
        # parser.add_schema("[file-trace] [pread64] [syscall: int] [fd: int] [gid: int] [offset: int] [requested_offset: int] [bytes: int] [after_patch: bool]")
        parser.add_schema("[file-trace] [lseek] [fd: int] [gid: int] [offset: int] [whence: int] [new_offset: int] [seekable: bool] [succ: bool] [after_patch: bool]")
        parser.add_schema("[file-trace] [dup] [old_fd: int] [new_fd: int] [gid: int] [offset: int] [seekable: bool] [after_patch: bool]")
        parser.add_schema("[file-trace] [fcntl-dup] [fd: int] [cmd: str] [new_fd: int] [gid: int] [offset: int] [seekable: bool] [after_patch: bool]")
        parser.add_schema("[file-trace] [close] [fd: int] [gid: int] [offset: int] [result: int] [after_patch: bool]")
        parser.add_schema("[file-trace] [group-close] [gid: int] [after_patch: bool]")
        return parser
    
    @staticmethod
    def from_log(log: str) -> Optional["BinRadarProbeResult"]:
        parser = BinRadarProbeResult.get_parser()
        result = parser.loads(log)
        if len(result["patch-info"]) == 0:
            logger.error("Patch info not found in the log.")
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
        
        stacktrace = []
        if len(result["stacktrace"]) > 0:
            stacktrace = [(entry["addr"], entry["symbol"]) for entry in result["stacktrace"]]
        patch_hit_cnt = 0
        if len(result["patch-cov"]) != 0:
            patch_cov_info = result["patch-cov"][-1]
            patch_hit_cnt = patch_cov_info["hits"]
        
        patch_funcs = list()
        if len(result["patch-func"]) != 0:
            patch_funcs = result["patch-func"]

        patch_func_entry = 0
        patch_func_hit_cnt = 0
        patch_func_candidates = list()
        if len(patch_funcs) != 0:
            for func_info in patch_funcs:
                if func_info["hits"] > 0:
                    patch_func_candidates.append((func_info["entry"], func_info["hits"]))
            patch_func_info = patch_funcs[-1]
            patch_func_entry = patch_func_info["entry"]
            patch_func_hit_cnt = patch_func_info["hits"]

        fault_addr = 0
        if len(result["fault-addr"]) != 0:
            fault_addr_info = result["fault-addr"][-1]
            fault_addr = fault_addr_info["addr"]
        
        return BinRadarProbeResult(
            patch_loc=patch_loc,
            patch_func_entry=patch_func_entry,
            stacktrace=stacktrace,
            exit_info=exit_result,
            patch_hit_cnt=patch_hit_cnt,
            patch_func_hit_cnt=patch_func_hit_cnt,
            fault_addr=fault_addr,
            patch_func_candidates=patch_func_candidates
        )
        
    def update_with_file_trace(self, log: str):
        parser = BinRadarProbeResult.get_parser_for_file_trace()
        result = parser.loads(log)
        if len(result["patch-func-entry"]["set"]) == 0:
            raise ValueError("Patch func entry info not found in the log.")
        if not result["patch-func-entry"]["set"][-1]["set"]:
            raise ValueError("Patch func entry was not set during execution.")
        # Check file trace
        open_file_desc_read_after_patch_func = dict()  # gid -> bool
        for trace in parser.get_result_in_order():
            if self.need_file_hook:
                break
            if trace.get_name() == "file-trace$open":
                path = trace["path"]
                after_patch = trace["after_patch"]
                gid = trace["gid"]
                seekable = trace["seekable"]
                # We only care about files opened before hitting the patch func entry
                if not seekable or after_patch:
                    continue
                open_file_desc_read_after_patch_func[gid] = False
            elif trace.get_name() == "file-trace$read":
                gid = trace["gid"]
                seekable = trace["seekable"]
                if not seekable:
                    continue
                after_patch = trace["after_patch"]
                if gid in open_file_desc_read_after_patch_func:
                    if after_patch:
                        open_file_desc_read_after_patch_func[gid] = True
                        self.need_file_hook = True
                        break
            elif trace.get_name() == "file-trace$lseek":
                gid = trace["gid"]
                offset = trace["offset"]
                whence = trace["whence"]
                seekable = trace["seekable"]
                if not seekable:
                    continue
                after_patch = trace["after_patch"]
                if gid in open_file_desc_read_after_patch_func:
                    if after_patch:
                        if open_file_desc_read_after_patch_func[gid]:
                            # Already read: need reset
                            self.need_file_hook = True
                            break
                        else:
                            if whence != 1:
                                # No need to reset
                                del open_file_desc_read_after_patch_func[gid]
                            else:
                                # Need to reset
                                self.need_file_hook = True
                                break

    def serialize(self) -> str:
        return f"[exit {self.exit_info}] [func-entry {self.patch_func_entry:x}] [func-hit {self.patch_func_hit_cnt}] [patch {self.patch_loc:x}] [patch-hit {self.patch_hit_cnt}] [fault-addr {self.fault_addr:x}]"

    def serialize_file_trace_result(self) -> str:
        return f"[need-file-hook {self.need_file_hook}]"

    def patch_hit(self) -> bool:
        return self.patch_hit_cnt > 0

    def patch_func_hit(self) -> bool:
        return self.patch_func_hit_cnt > 0
    
    def multi_patch_func(self) -> bool:
        return len(self.patch_func_candidates) > 1

    def is_crash(self) -> bool:
        return self.exit_info == "crash"
    
    def is_timeout(self) -> bool:
        return self.exit_info == "timeout"
    
    def is_normal_exit(self) -> bool:
        return self.exit_info == "ok"
    

class BinRadarQemuRunner:
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
    def from_workdir(dir: str) -> "BinRadarQemuRunner":
        env = binradar_utils.load_env(os.path.join(dir, "config.env"))
        return BinRadarQemuRunner.from_env(dir, env)
    
    @staticmethod
    def from_env(dir: str, env: Dict[str, str]) -> "BinRadarQemuRunner":
        return BinRadarQemuRunner(
            dir=dir,
            binary=env["BINARY"],
            test_cmd=env["TEST_CMD"],
            patch_loc=env["PATCH_LOC"]
        )
    
    def original_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.orig")

    def get_qemu_stacktrace_command(self, binary: str, input_file: str, patch_func_entry: int = 0) -> List[str]:
        cmd = [QEMU_STACKTRACE_RELEASE, "--input", input_file, "--patch-loc", self.patch_loc]
        if patch_func_entry != 0:
            cmd += [ "--patch-func-entry", f"{patch_func_entry:x}"] 
        cmd += [binary, "--"] + shlex.split(self.test_cmd)
        return cmd

    def test_with_original(self, testcase: str, verbose: bool = True) -> Optional[BinRadarProbeResult]:
        command = self.get_qemu_stacktrace_command(self.original_binary(), testcase)
        result = binradar_utils.execute(command, cwd=self.dir, verbose=verbose)
        if not result.success:
            logger.error("Failed to execute the command.")
            return None
        return BinRadarProbeResult.from_log(result.stderr)

    def test_with_patched(self, binary: str, testcase: str, verbose: bool = False) -> Optional[BinRadarProbeResult]:
        command = self.get_qemu_stacktrace_command(binary, testcase)
        result = binradar_utils.execute(command, cwd=self.dir, verbose=verbose)
        if not result.success:
            logger.error("Failed to execute the command")
            return None
        return BinRadarProbeResult.from_log(result.stderr)
    
    def test_with_patched_and_file_trace(self, binary: str, testcase: str, patch_func_entry: int, verbose: bool = False) -> Optional[BinRadarProbeResult]:
        command = self.get_qemu_stacktrace_command(binary, testcase, patch_func_entry=patch_func_entry)
        result = binradar_utils.execute(command, cwd=self.dir, verbose=verbose)
        if not result.success:
            logger.error("Failed to execute the command")
            return None
        probe_result = BinRadarProbeResult.from_log(result.stderr)
        if probe_result is None:
            logger.error("Failed to parse the probe result from log.")
            return None
        probe_result.update_with_file_trace(result.stderr)
        return probe_result


class Testcase:
    id: int
    filename: str
    exit: str
    fault_addr: int
    def __init__(self, id: int, filename: str, exit: str, fault_addr: int):
        self.id = id
        self.filename = filename
        self.exit = exit
        self.fault_addr = fault_addr


class BinRadarConcreteVerifier:
    dir: str
    run_dir: str
    runner: BinRadarQemuRunner
    patched_binary: str
    testcases: List[Testcase]
    start_time: float
    logger: logging.Logger
    minimized_dir: str
    def __init__(self, dir: str, run_dir: str, runner: BinRadarQemuRunner, patched_binary: str):
        self.dir = dir
        self.run_dir = run_dir
        self.minimized_dir = os.path.join(run_dir, "minimized")
        self.runner = runner
        self.patched_binary = patched_binary
        self.testcases = list()
        self.start_time = time.time()
        # Setup logger
        log_file = os.path.join(run_dir, "verifier.sbsv")
        self.logger = logging.getLogger(__name__)
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_file, mode="w")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s - %(message)s")
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
    
    def load_testcases(self, minimizer_result: str):
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[testcase] [result] [id: int] [file: str] [exit: str] [fault-addr: hex]")
        with open(minimizer_result, "r", encoding="utf-8") as f:
            parser.load(f)
        testcases = parser.get_result()["testcase"]["result"]
        for testcase in testcases:
            self.testcases.append(Testcase(
                id=testcase["id"],
                filename=testcase["file"],
                exit=testcase["exit"],
                fault_addr=testcase["fault-addr"]
            ))
    
    def run_testcase_crash(self, testcase: Testcase) -> Optional[BinRadarProbeResult]:
        result = self.runner.test_with_patched(self.patched_binary, os.path.join(self.minimized_dir, testcase.filename), verbose=False)
        if result is None:
            self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
            return None
        return result
    
    def run_testcase_no_crash(self, testcase: Testcase) -> Optional[BinRadarProbeResult]:
        result = self.runner.test_with_patched(self.patched_binary, os.path.join(self.minimized_dir, testcase.filename), verbose=False)
        if result is None:
            self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
            return None
        return result

    def run_verification_concrete_testcases(self):
        for testcase in self.testcases:
            self.logger.info(f"[testcase] [try] [id {testcase.id}] / {len(self.testcases)}: [file {testcase.filename}]")
            if testcase.exit == "crash":
                result = self.run_testcase_crash(testcase)
                if result is None:
                    self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
                    continue
                if result.is_crash():
                    self.logger.info(f"[verifier] [crash-fail] [id {testcase.id}] [file {testcase.filename}] [fault-addr {result.fault_addr:x}]")
                elif result.is_normal_exit():
                    self.logger.info(f"[verifier] [crash-pass] [id {testcase.id}] [file {testcase.filename}]")
                elif result.is_timeout():
                    self.logger.info(f"[verifier] [crash-timeout] [id {testcase.id}] [file {testcase.filename}]")
            else:
                result = self.run_testcase_no_crash(testcase)
                if result is None:
                    self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
                    continue
                if result.is_crash():
                    self.logger.info(f"[verifier] [no-crash-fail] [id {testcase.id}] [file {testcase.filename}] [fault-addr {result.fault_addr:x}]")
                elif result.is_normal_exit():
                    self.logger.info(f"[verifier] [no-crash-pass] [id {testcase.id}] [file {testcase.filename}]")
                elif result.is_timeout():
                    self.logger.info(f"[verifier] [no-crash-timeout] [id {testcase.id}] [file {testcase.filename}]")