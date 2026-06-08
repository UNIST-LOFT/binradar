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
    line_parser: sbsv.parser = sbsv.parser()
    line_parser.add_custom_type("hex", lambda x: int(x, 16))
    line_parser.add_schema("[probe-info] [exit: str] [patch-loc: hex] [func-entry: hex] [patch-hit: int] [func-hit: int] [fault-addr: hex] [patch-func-candidates: list[str]] [stacktrace: list[str]]")
    line_parser.add_schema("[file-trace] [need-file-hook: bool]")
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
    
    @staticmethod
    def from_sbsv(sbsv_file: str) -> Optional["BinRadarProbeResult"]:
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[probe-info] [exit: str] [patch-loc: hex] [func-entry: hex] [patch-hit: int] [func-hit: int] [fault-addr: hex] [patch-func-candidates: list[str]] [stacktrace: list[str]]")
        parser.add_schema("[file-trace] [need-file-hook: bool]")
        with open(sbsv_file, "r", encoding="utf-8") as f:
            result = parser.load(f)
        if len(result["probe-info"]) == 0:
            logger.error("Probe info not found in the log.")
            return None
        if len(result["file-trace"]) == 0:
            logger.error("File trace info not found in the log.")
            return None
        probe_info = result["probe-info"][-1]
        patch_loc = probe_info["patch-loc"]
        patch_func_entry = probe_info["func-entry"]
        stacktrace = list()
        for entry in probe_info["stacktrace"]:
            addr, symbol = entry.split(":", 1)
            stacktrace.append((int(addr, 16), symbol))
        
        exit_info = probe_info["exit"]
        patch_hit_cnt = probe_info["patch-hit"]
        patch_func_hit_cnt = probe_info["func-hit"]
        fault_addr = probe_info["fault-addr"]
        patch_func_candidates = list()
        for func in probe_info["patch-func-candidates"]:
            entry, hits = func.split(":", 1)
            patch_func_candidates.append((int(entry, 16), int(hits)))
        need_file_hook = result["file-trace"][-1]["need-file-hook"]
        probe_result = BinRadarProbeResult(
            patch_loc=patch_loc,
            patch_func_entry=patch_func_entry,
            stacktrace=stacktrace,
            exit_info=exit_info,
            patch_hit_cnt=patch_hit_cnt,
            patch_func_hit_cnt=patch_func_hit_cnt,
            fault_addr=fault_addr,
            patch_func_candidates=patch_func_candidates
        )
        probe_result.need_file_hook = need_file_hook
        return probe_result
        
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
        return f"[exit {self.exit_info}] [patch-loc {self.patch_loc:x}] [func-entry {self.patch_func_entry:x}] [patch-hit {self.patch_hit_cnt}] [func-hit {self.patch_func_hit_cnt}] [fault-addr {self.fault_addr:x}] [patch-func-candidates [{'] ['.join([f'{entry:x}:{hits}' for entry, hits in self.patch_func_candidates])}]] [stacktrace [{'] ['.join([f'{addr:x}:{symbol}' for addr, symbol in self.stacktrace])}]]"

    def serialize_file_trace_result(self) -> str:
        return f"[need-file-hook {self.need_file_hook}]"
    
    @classmethod
    def deserialize(cls, data: str) -> Optional["BinRadarProbeResult"]:
        for line in data.splitlines():
            res = cls.line_parser.parse_line_detached(line)
            if res is not None:
                if res.get_name() == "probe-info":
                    return cls(
                        patch_loc=res["patch-loc"],
                        patch_func_entry=res["func-entry"],
                        stacktrace=[(entry["addr"], entry["symbol"]) for entry in res["stacktrace"]],
                        exit_info=res["exit"],
                        patch_hit_cnt=res["patch-hit"],
                        patch_func_hit_cnt=res["func-hit"],
                        fault_addr=res["fault-addr"],
                        patch_func_candidates=[(int(func.split(":")[0], 16), int(func.split(":")[1])) for func in res["patch-func-candidates"]]
                    )
                elif res.get_name() == "file-trace":
                    tmp = cls(
                        patch_loc=0,
                        patch_func_entry=0,
                        stacktrace=[],
                        exit_info="",
                        patch_hit_cnt=0,
                        patch_func_hit_cnt=0,
                        fault_addr=0,
                        patch_func_candidates=[],
                    )
                    tmp.need_file_hook = res["need-file-hook"]
                    return tmp
        return None
    
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


class BinRadarPatchResult:
    line_parser: sbsv.parser = sbsv.parser()
    line_parser.add_schema("[patch] [id: int] [br: bool]")
    line_parser.add_schema("[patch-res] [pid: int] [br: list[bool]]")
    
    def __init__(self, patch_id: int, br_selection: List[bool]):
        self.patch_id = patch_id
        self.br_selection = br_selection
    
    @classmethod
    def from_log(cls, log: str) -> Optional["BinRadarPatchResult"]:
        result: List[sbsv.SbsvData] = list()
        for line in log.splitlines():
            res = cls.line_parser.parse_line_detached(line)
            if res is not None:
                result.append(res)

        if len(result) == 0:
            return None
        
        patch_id = -1
        for entry in result:
            if entry.get_name() == "patch":
                patch_id = entry["id"]
                br_selection = entry["br"]
                break
        if patch_id == -1:
            return None
        br_selection: List[bool] = list()
        for entry in result:
            if entry.get_name() == "patch" and entry["id"] == patch_id:
                br = entry["br"]
                br_selection.append(br)
            elif entry.get_name() == "patch" and entry["id"] != patch_id:
                logger.warning(f"Multiple patch results found in the log. Using the first one with id {patch_id}.")
        return BinRadarPatchResult(patch_id=patch_id, br_selection=br_selection)

    def serialize(self) -> str:
        return f"[pid {self.patch_id}] [br [{'] ['.join([str(br) for br in self.br_selection])}]]"
    
    @classmethod
    def deserialize(cls, data: str) -> Optional["BinRadarPatchResult"]:
        for line in data.splitlines():
            res = cls.line_parser.parse_line_detached(line)
            if res is not None and res.get_name() == "patch-res":
                return cls(patch_id=res["pid"], br_selection=res["br"])
        return None

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

    def patched_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.patched")

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
    
    def test_with_file_trace(self, testcase: str, patch_func_entry: int, verbose: bool = True):
        command = self.get_qemu_stacktrace_command(self.original_binary(), testcase, patch_func_entry=patch_func_entry)
        result = binradar_utils.execute(command, cwd=self.dir, verbose=verbose)
        if not result.success:
            logger.error("Failed to execute the command.")
            return None
        probe_result = BinRadarProbeResult.from_log(result.stderr)
        if probe_result is None:
            logger.error("Failed to parse probe result from the log.")
            return None
        return probe_result

    def test_with_patched(self, patch_id: str, testcase: str, env: Dict[str, str], verbose: bool = False) -> Tuple[Optional[BinRadarProbeResult], Optional[BinRadarPatchResult]]:
        command = self.get_qemu_stacktrace_command(self.patched_binary(), testcase)
        rfd, wfd = os.pipe()
        env = env.copy()
        env["PATCH_ID"] = patch_id
        env["PATCH_FD"] = str(wfd)
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir, start_new_session=True, pass_fds=(wfd,), env=env)
        os.close(wfd)
        thread, patch_result_chunks = binradar_utils.create_pipe_reader_thread(rfd, verbose=verbose)
        result = binradar_utils.execute_await(proc, timeout=60.0, verbose=verbose)
        thread.join() # Read all patch results and close the pipe(rfd)
        
        patch_result_data = b"".join(patch_result_chunks).decode(errors="ignore")
        if not result.success:
            logger.error("Failed to execute the command")
            return None, None
        patch_result = BinRadarPatchResult.from_log(patch_result_data)
        if patch_result is None:
            logger.error("Failed to parse patch result from the log.")
            return None, None
        return BinRadarProbeResult.from_log(result.stderr), patch_result


class Testcase:
    id: int
    filename: str
    exit: str
    fault_addr: int
    br: List[bool]
    def __init__(self, id: int, filename: str, exit: str, fault_addr: int, br: List[bool]):
        self.id = id
        self.filename = filename
        self.exit = exit
        self.fault_addr = fault_addr
        self.br = br


class BinRadarConcreteVerifier:
    dir: str
    run_dir: str
    runner: BinRadarQemuRunner
    patched_binary: str
    testcases: List[Testcase]
    patches: List[int]
    start_time: float
    logger: logging.Logger
    minimized_dir: str
    env: Dict[str, str]
    def __init__(self, dir: str, run_dir: str, runner: BinRadarQemuRunner, patched_binary: str, patches: List[int]):
        self.dir = dir
        self.run_dir = run_dir
        self.minimized_dir = os.path.join(run_dir, "minimized")
        self.runner = runner
        self.patched_binary = patched_binary
        self.patches = patches
        self.testcases = list()
        self.start_time = time.time()
        self.env = os.environ.copy()
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
        parser.add_schema("[testcase] [result] [id: int] [file: str] [exit: str] [fault-addr: hex] [pid: int] [br: list[bool]]")
        with open(minimizer_result, "r", encoding="utf-8") as f:
            parser.load(f)
        testcases = parser.get_result()["testcase"]["result"]
        for testcase in testcases:
            self.testcases.append(Testcase(
                id=testcase["id"],
                filename=testcase["file"],
                exit=testcase["exit"],
                fault_addr=testcase["fault-addr"],
                br=testcase["br"]
            ))
    
    def run_testcase_patched(self, patch_id: int, testcase: Testcase) -> Tuple[Optional[BinRadarProbeResult], Optional[BinRadarPatchResult]]:
        result, patch_result = self.runner.test_with_patched(str(patch_id), os.path.join(self.minimized_dir, testcase.filename), self.env)
        if result is None:
            self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
            return None, None
        return result, patch_result

    def run_verification_concrete_testcases(self):
        for patch in self.patches:
            patch_reject: Optional[Testcase] = None
            for testcase in self.testcases:
                self.logger.info(f"[testcase] [try] [patch {patch}] [id {testcase.id}] / {len(self.testcases)}: [file {testcase.filename}]")
                if testcase.exit == "crash":
                    result, patch_result = self.run_testcase_patched(patch, testcase)
                    if result is None:
                        self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
                        continue
                    if result.is_crash():
                        patch_reject = testcase
                        self.logger.info(f"[verifier] [crash-fail] [patch {patch}] [id {testcase.id}] [file {testcase.filename}] [fault-addr {result.fault_addr:x}]")
                        # TODO: check if the crash is same with original crash
                        break # Patch is incorrect: no need to check further
                    elif result.is_normal_exit():
                        self.logger.info(f"[verifier] [crash-pass] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                    elif result.is_timeout():
                        self.logger.info(f"[verifier] [crash-timeout] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                        # TODO: retry
                else:
                    result, patch_result = self.run_testcase_patched(patch, testcase)
                    if result is None:
                        self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
                        continue
                    if result.is_crash():
                        self.logger.info(f"[verifier] [no-crash-fail] [patch {patch}] [id {testcase.id}] [file {testcase.filename}] [fault-addr {result.fault_addr:x}]")
                        patch_reject = testcase
                        # TODO: check if the crash is same with original crash
                        break # Patch is incorrect: no need to check further
                    elif result.is_normal_exit():
                        if patch_result is None:
                            self.logger.error(f"Failed to get patch result for {testcase.filename} with patch {patch}.")
                            continue
                        if testcase.br == patch_result.br_selection:
                            self.logger.info(f"[verifier] [no-crash-pass-same-br] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                        else:
                            patch_reject = testcase
                            self.logger.info(f"[verifier] [no-crash-pass-diff-br] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                    elif result.is_timeout():
                        self.logger.info(f"[verifier] [no-crash-timeout] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                        # TODO: retry
            
            if patch_reject is None:
                self.logger.info(f"[verifier] [patch-verified] [patch {patch}]")
            else:
                self.logger.info(f"[verifier] [patch-rejected] [patch {patch}] [testcase {patch_reject.filename}]")