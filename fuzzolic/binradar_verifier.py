import subprocess
import os
import signal
import shlex
import logging
import time
import threading
import fcntl
from pathlib import Path
from typing import List, Set, Tuple, Dict, Optional, Any, TextIO

import sbsv

import logger

import binradar_utils
from binradar_taosc_predicates import (
    CachedSnapshot,
    ParsedPredicate,
    PredicateFamily,
    evaluate_cached_predicate,
    load_runtime_predicates,
    parse_cached_snapshots,
    predicate_descriptor,
)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# os.path.join(ROOT_DIR, "LibAFL", "fuzzers", "binary_only", "qemu_stacktrace", "target", "release", "qemu_stacktrace")
QEMU_STACKTRACE_RELEASE = os.path.join(ROOT_DIR, "utils", "binradar-aflplusplus", "afl-qemu-trace")


class BinRadarProbeResult:
    line_parser: sbsv.parser = sbsv.parser()
    line_parser.add_custom_type("hex", lambda x: int(x, 16))
    line_parser.add_schema("[probe-info] [exit: str] [patch-loc: hex] [func-entry: hex] [patch-hit: int] [func-hit: int] [fault-addr: hex] [tracer-fault-addr: hex] [patch-func-candidates: list[str]] [stacktrace: list[str]]")
    line_parser.add_schema("[file-trace] [need-file-hook: bool]")
    def __init__(self, patch_loc: int, patch_func_entry: int, stacktrace: List[Tuple[int, str]], exit_info: str, patch_hit_cnt: int, patch_func_hit_cnt: int, fault_addr: int, patch_func_candidates: List[Tuple[int, int]], tracer_fault_addr: int = 0):
        self.patch_loc = patch_loc
        self.patch_func_entry = patch_func_entry
        self.stacktrace = stacktrace
        self.exit_info = exit_info
        self.patch_hit_cnt = patch_hit_cnt
        self.patch_func_hit_cnt = patch_func_hit_cnt
        self.fault_addr = fault_addr
        self.patch_func_candidates = patch_func_candidates
        self.tracer_fault_addr = tracer_fault_addr
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
        parser.add_schema("[probe-info] [exit: str] [patch-loc: hex] [func-entry: hex] [patch-hit: int] [func-hit: int] [fault-addr: hex] [tracer-fault-addr: hex] [patch-func-candidates: list[str]] [stacktrace: list[str]]")
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
        tracer_fault_addr = probe_info["tracer-fault-addr"]
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
            patch_func_candidates=patch_func_candidates,
            tracer_fault_addr=tracer_fault_addr
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
        return f"[exit {self.exit_info}] [patch-loc {self.patch_loc:x}] [func-entry {self.patch_func_entry:x}] [patch-hit {self.patch_hit_cnt}] [func-hit {self.patch_func_hit_cnt}] [fault-addr {self.fault_addr:x}] [tracer-fault-addr {self.tracer_fault_addr:x}] [patch-func-candidates [{'] ['.join([f'{entry:x}:{hits}' for entry, hits in self.patch_func_candidates])}]] [stacktrace [{'] ['.join([f'{addr:x}:{symbol}' for addr, symbol in self.stacktrace])}]]"

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
                        patch_func_candidates=[(int(func.split(":")[0], 16), int(func.split(":")[1])) for func in res["patch-func-candidates"]],
                        tracer_fault_addr=res["tracer-fault-addr"]
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
                        tracer_fault_addr=0
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
    line_parser.add_schema("[patch] [id: int] [br: int]")
    line_parser.add_schema("[patch-res] [pid: int] [br: list[int]]")
    
    def __init__(self, patch_id: int, br_selection: List[int]):
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
        br_selection: List[int] = list()
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

    def crashed(self) -> bool:
        """True if the patch itself crashed at the patch site (br 2),
        e.g. a division/modulo by zero in the predicate."""
        return 2 in self.br_selection


class BinRadarCachedRun:
    def __init__(self, patch_id: int, snapshots: List[CachedSnapshot]):
        self.patch_id = patch_id
        self.snapshots = snapshots

    @property
    def br_selection(self) -> List[int]:
        return [snapshot.branch for snapshot in self.snapshots]


class BinRadarQemuRunner:
    dir: str
    binary: str
    test_cmd: str
    patch_loc: str
    # E9 metadata per artifact ("brpatched", "prefilter", "brcached"):
    # (exclude_ranges, [relocated-call records]).  All prefixed values are
    # stored; the executed binary's path selects the proper one.
    e9_metadata: Dict[str, Tuple[str, List[str]]]
    patch_kind: str
    brcache_stack_size: int
    run_results: Optional[binradar_utils.ExecutionResult]
    def __init__(self, dir: str, binary: str, test_cmd: str, patch_loc: str,
                 e9_metadata: Optional[Dict[str, Tuple[str, List[str]]]] = None,
                 patch_kind: str = "", brcache_stack_size: int = 0):
        self.dir = dir
        self.binary = binary
        self.test_cmd = test_cmd
        self.patch_loc = patch_loc
        self.e9_metadata = e9_metadata if e9_metadata is not None else {}
        self.patch_kind = patch_kind
        self.brcache_stack_size = brcache_stack_size
        self.run_results = None
    
    @staticmethod
    def from_workdir(dir: str) -> "BinRadarQemuRunner":
        env = binradar_utils.load_env(os.path.join(dir, "binradar.env"))
        return BinRadarQemuRunner.from_env(dir, env)
    
    @staticmethod
    def from_env(dir: str, env: Dict[str, str]) -> "BinRadarQemuRunner":
        e9_metadata: Dict[str, Tuple[str, List[str]]] = {}
        for artifact in binradar_utils.E9_METADATA_PREFIXES:
            exclude_ranges, relocated_calls_str = \
                binradar_utils.get_e9_metadata(env, artifact)
            records: List[str] = []
            for record in relocated_calls_str.split(","):
                record = record.strip()
                if record:
                    fields = [f"0x{int(field, 0):x}"
                              for field in record.split(":")]
                    records.append(":".join(fields))
            e9_metadata[artifact] = (exclude_ranges, records)
        return BinRadarQemuRunner(
            dir=dir,
            binary=env["BINARY"],
            test_cmd=env["TEST_CMD"],
            patch_loc=env["PATCH_LOC"],
            e9_metadata=e9_metadata,
            patch_kind=env.get("BINRADAR_PATCH_KIND", ""),
            brcache_stack_size=int(env.get("BRCACHE_STACK_SIZE", "0"), 0),
        )

    def e9_metadata_for_binary(self, binary_path: str) -> Tuple[str, List[str]]:
        """(exclude_ranges, relocated-call records) of the artifact the
        given binary path belongs to.  Original binaries have no E9
        metadata; .brpatched/.brprefilter/.brcached each select their own
        prefixed values."""
        for artifact, suffix in (("brpatched", ".brpatched"),
                                 ("prefilter", ".brprefilter"),
                                 ("brcached", ".brcached")):
            if binary_path.endswith(suffix):
                return self.e9_metadata.get(artifact, ("", []))
        return "", []
    
    def get_env_for_exec(self, patch_id: str, patch_fd: Optional[int] = None) -> Dict[str, str]:
        env = os.environ.copy()
        # env["LC_ALL"] = "C"
        env["AFL_USE_QASAN"] = "1"
        env["PATCH_ID"] = patch_id
        if patch_fd is not None:
            env["PATCH_FD"] = str(patch_fd)
        return env
    
    def original_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.orig")

    def patched_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.brpatched")

    def cached_binary(self) -> str:
        return os.path.join(self.dir, f"{self.binary}.brcached")

    def get_qemu_stacktrace_command_for_binary(
        self, binary: str, input_file: str, patch_func_entry: int = 0,
    ) -> List[str]:
        cmd = [QEMU_STACKTRACE_RELEASE, "--input", input_file,
               "--patch-loc", self.patch_loc, "--asan", "host"]
        if patch_func_entry != 0:
            cmd += ["--patch-func-entry", f"0x{patch_func_entry:x}"]
        _, relocated_calls = self.e9_metadata_for_binary(binary)
        for addr in relocated_calls:
            cmd += ["--e9-relocated-call", addr]
        cmd += [binary, "--"] + shlex.split(self.test_cmd)
        return cmd

    def get_qemu_stacktrace_command(
        self, use_patched_bin: bool, input_file: str,
        patch_func_entry: int = 0,
    ) -> List[str]:
        binary = self.patched_binary() if use_patched_bin \
            else self.original_binary()
        return self.get_qemu_stacktrace_command_for_binary(
            binary, input_file, patch_func_entry)


    def test_with_original(self, testcase: str, verbose: bool = True) -> Optional[BinRadarProbeResult]:
        command = self.get_qemu_stacktrace_command(False, testcase)
        env = self.get_env_for_exec(patch_id="0")
        result = binradar_utils.execute(command, cwd=self.dir, verbose=verbose, env=env)
        if not result.success:
            logger.error("Failed to execute the command.")
            return None
        return BinRadarProbeResult.from_log(result.stderr)
    
    def test_with_file_trace(self, testcase: str, patch_func_entry: int, verbose: bool = True):
        command = self.get_qemu_stacktrace_command(False, testcase, patch_func_entry=patch_func_entry)
        env = self.get_env_for_exec(patch_id="0")
        result = binradar_utils.execute(command, cwd=self.dir, verbose=verbose, env=env)
        if not result.success:
            logger.error("Failed to execute the command.")
            return None
        probe_result = BinRadarProbeResult.from_log(result.stderr)
        if probe_result is None:
            logger.error("Failed to parse probe result from the log.")
            return None
        return probe_result

    def _test_with_capture(
        self, binary: str, patch_id: str, testcase: str,
        verbose: bool = False, extra_env: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[BinRadarProbeResult], Optional[bytes]]:
        command = self.get_qemu_stacktrace_command_for_binary(binary, testcase)
        rfd, wfd = os.pipe()
        env = self.get_env_for_exec(patch_id=patch_id, patch_fd=wfd)
        if extra_env is not None:
            env.update(extra_env)
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.dir, start_new_session=True, pass_fds=(wfd,), env=env)
        os.close(wfd)
        thread, chunks = binradar_utils.create_pipe_reader_thread(
            rfd, verbose=verbose)
        result = binradar_utils.execute_await(
            proc, timeout=60.0, verbose=verbose)
        thread.join()
        if not result.success:
            logger.error("Failed to execute the command")
            return None, None
        return BinRadarProbeResult.from_log(result.stderr), b"".join(chunks)

    def test_with_patched(
        self, patch_id: str, testcase: str, verbose: bool = False,
    ) -> Tuple[Optional[BinRadarProbeResult], Optional[BinRadarPatchResult]]:
        probe, data = self._test_with_capture(
            self.patched_binary(), patch_id, testcase, verbose)
        if probe is None or data is None:
            return None, None
        patch_result = BinRadarPatchResult.from_log(
            data.decode(errors="ignore"))
        if patch_result is None:
            return None, None
        return probe, patch_result

    def test_with_cached(
        self, patch_id: int, predicate: ParsedPredicate, testcase: str,
        verbose: bool = False,
    ) -> Tuple[Optional[BinRadarProbeResult], Optional[BinRadarCachedRun]]:
        probe, data = self._test_with_capture(
            self.cached_binary(), "0", testcase, verbose,
            {
                "TAOSC_PRED": predicate_descriptor(predicate),
                "BRCACHE_STACK_SIZE": str(self.brcache_stack_size),
            })
        if probe is None or data is None:
            return None, None
        snapshots, error = parse_cached_snapshots(data)
        if error is not None:
            logger.warning(f"Cached capture rejected: {error}")
            return probe, None
        if probe.patch_hit_cnt != len(snapshots):
            logger.warning(
                f"Cached capture hit mismatch: probe={probe.patch_hit_cnt} "
                f"snapshots={len(snapshots)}")
            return probe, None
        return probe, BinRadarCachedRun(patch_id, snapshots)


class Testcase:
    id: int
    filename: str
    exit: str
    fault_addr: int
    br: List[int]
    def __init__(self, id: int, filename: str, exit: str, fault_addr: int, br: List[int]):
        self.id = id
        self.filename = filename
        self.exit = exit
        self.fault_addr = fault_addr
        self.br = br


class BinRadarConcreteVerifierResult:
    patch_verified: Dict[int, bool]
    def __init__(self, results: dict):
        self.patch_verified = dict()
        for res in results["verifier-result"]:
            patch_id = res["patch"]
            verified = res["res"] == "verified"
            self.patch_verified[patch_id] = verified
    
    @classmethod
    def from_sbsv(cls, sbsv_file: str) -> Optional["BinRadarConcreteVerifierResult"]:
        parser = sbsv.parser()
        parser.add_schema("[verifier-result] [res: str] [patch: int] [testcase?: str]")
        with open(sbsv_file, "r", encoding="utf-8") as f:
            result = parser.load(f)
        if "verifier-result" not in result:
            logger.error("Verifier result not found in the sbsv file.")
            return None
        return cls(result)


class BinRadarConcreteVerifier:
    dir: str
    run_dir: str
    probe_result: BinRadarProbeResult
    runner: BinRadarQemuRunner
    patched_binary: str
    testcases: List[Testcase]
    patches: List[int]
    start_time: float
    logger: logging.Logger
    minimized_dir: str
    cached_predicates: Dict[int, ParsedPredicate]
    cache_family: Optional[PredicateFamily]
    def __init__(self, dir: str, run_dir: str, runner: BinRadarQemuRunner, probe_result: BinRadarProbeResult, patched_binary: str, patches: List[int]):
        self.dir = dir
        self.run_dir = run_dir
        self.minimized_dir = os.path.join(run_dir, "minimized")
        self.runner = runner
        self.probe_result = probe_result
        self.patched_binary = patched_binary
        self.patches = patches
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

        self.cached_predicates = {}
        self.cache_family = None
        manifest = Path(dir) / "brpatches.json"
        cached_binary = Path(runner.cached_binary())
        if len(patches) > 1 and manifest.is_file() and cached_binary.is_file():
            try:
                family, predicates = load_runtime_predicates(manifest)
                if runner.patch_kind and runner.patch_kind != family.value:
                    raise ValueError(
                        f"manifest family {family.value} != "
                        f"configured family {runner.patch_kind}")
                missing = [patch for patch in patches
                           if patch not in predicates]
                if missing:
                    raise ValueError(f"missing runtime patch ids {missing}")
                if family == PredicateFamily.CWE805_ERM \
                        and runner.brcache_stack_size <= 0:
                    raise ValueError("missing CWE-805 cache stack size")
                self.cache_family = family
                self.cached_predicates = predicates
            except ValueError as e:
                self.logger.warning(
                    f"[verifier-cache] [disabled] [reason {e}]")
    
    def _testcase_from_result_row(self, row: Dict[str, Any]) -> Optional[Testcase]:
        id = row["id"]
        filename = row["file"]
        exit = row["exit"]
        fault_addr = row["fault-addr"]
        if exit == "crash" and fault_addr != self.probe_result.fault_addr:
            self.logger.debug(f"[testcase] [skip-fault-diff] [id {id}] [file {filename}] [fault-addr {fault_addr:x}] [original-fault-addr {self.probe_result.fault_addr:x}]")
            return None
        return Testcase(
            id=id,
            filename=filename,
            exit=exit,
            fault_addr=fault_addr,
            br=row["br"]
        )

    def _test_result(
        self, patch: int, testcase: Testcase, result: BinRadarProbeResult,
        patch_result: Optional[BinRadarPatchResult],
    ) -> bool:
        """Return whether one observed execution rejects the candidate."""
        if patch_result is not None and patch_result.crashed():
            self.logger.info(f"[verifier] [patch-crashed] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
            return True
        if testcase.exit == "crash":
            if result.is_crash():
                if result.fault_addr != self.probe_result.fault_addr:
                    self.logger.info(f"[verifier] [crash-skip-diff-addr] [patch {patch}] [id {testcase.id}] [file {testcase.filename}] [fault-addr {result.fault_addr:x}] [original-fault-addr {self.probe_result.fault_addr:x}]")
                    return False
                self.logger.info(f"[verifier] [crash-fail] [patch {patch}] [id {testcase.id}] [file {testcase.filename}] [fault-addr {result.fault_addr:x}]")
                return True
            if result.is_normal_exit():
                self.logger.info(f"[verifier] [crash-pass] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                return False
            if result.is_timeout():
                self.logger.info(f"[verifier] [crash-timeout] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                return False
        else:
            if result.is_crash():
                self.logger.info(f"[verifier] [no-crash-fail] [patch {patch}] [id {testcase.id}] [file {testcase.filename}] [fault-addr {result.fault_addr:x}]")
                return True
            if result.is_normal_exit():
                if patch_result is None:
                    self.logger.error(f"Failed to get patch result for {testcase.filename} with patch {patch}.")
                    return False
                if testcase.br == patch_result.br_selection:
                    self.logger.info(f"[verifier] [no-crash-pass-same-br] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                    return False
                self.logger.info(f"[verifier] [no-crash-pass-diff-br] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                return True
            if result.is_timeout():
                self.logger.info(f"[verifier] [no-crash-timeout] [patch {patch}] [id {testcase.id}] [file {testcase.filename}]")
                return False
        return False

    def _test_testcase(self, patch: int, testcase: Testcase) -> bool:
        """Run one candidate normally and return whether it is rejected."""
        self.logger.info(f"[testcase] [try] [patch {patch}] [id {testcase.id}] / {len(self.testcases)}: [file {testcase.filename}]")
        result, patch_result = self.run_testcase_patched(patch, testcase)
        if result is None:
            self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
            return False
        return self._test_result(patch, testcase, result, patch_result)

    def _cached_branches(
        self, patch: int, snapshots: List[CachedSnapshot],
    ) -> Optional[List[int]]:
        predicate = self.cached_predicates.get(patch)
        if predicate is None:
            return None
        try:
            return evaluate_cached_predicate(predicate, snapshots)
        except (IndexError, ValueError) as e:
            self.logger.warning(
                f"[verifier-cache] [predicate-error] [patch {patch}] "
                f"[reason {e}]")
            return None

    def _test_testcase_batch(
        self, patches: List[int], testcase: Testcase,
    ) -> Set[int]:
        """Run one representative per distinct complete branch vector."""
        if self.cache_family is None or len(patches) <= 1:
            return {patch for patch in patches
                    if self._test_testcase(patch, testcase)}

        rejected: Set[int] = set()
        remaining = list(patches)
        while remaining:
            if len(remaining) == 1:
                patch = remaining.pop()
                if self._test_testcase(patch, testcase):
                    rejected.add(patch)
                continue

            representative = remaining.pop(0)
            self.logger.info(
                f"[verifier-cache] [miss] [patch {representative}] "
                f"[id {testcase.id}] [file {testcase.filename}]")
            result, cached = self.run_testcase_cached(
                representative, testcase)
            if result is None or cached is None:
                self.logger.warning(
                    f"[verifier-cache] [fallback] [patch {representative}] "
                    f"[id {testcase.id}]")
                if self._test_testcase(representative, testcase):
                    rejected.add(representative)
                continue

            observed = cached.br_selection
            evaluated = self._cached_branches(
                representative, cached.snapshots)
            if evaluated is None or evaluated != observed:
                self.logger.warning(
                    f"[verifier-cache] [runtime-mismatch] "
                    f"[patch {representative}] [id {testcase.id}]")
                if self._test_testcase(representative, testcase):
                    rejected.add(representative)
                continue

            representative_result = BinRadarPatchResult(
                representative, observed)
            if self._test_result(
                    representative, testcase, result,
                    representative_result):
                rejected.add(representative)

            equivalent: List[Tuple[int, List[int]]] = []
            for patch in remaining:
                branches = self._cached_branches(patch, cached.snapshots)
                if branches is not None and branches == observed:
                    equivalent.append((patch, branches))
            for patch, branches in equivalent:
                remaining.remove(patch)
                self.logger.info(
                    f"[verifier-cache] [hit] [patch {patch}] "
                    f"[representative {representative}] "
                    f"[id {testcase.id}]")
                if self._test_result(
                        patch, testcase, result,
                        BinRadarPatchResult(patch, branches)):
                    rejected.add(patch)
        return rejected

    def run_testcase_patched(self, patch_id: int, testcase: Testcase) -> Tuple[Optional[BinRadarProbeResult], Optional[BinRadarPatchResult]]:
        result, patch_result = self.runner.test_with_patched(str(patch_id), os.path.join(self.minimized_dir, testcase.filename))
        if result is None:
            self.logger.error(f"Failed to run the test case {testcase.filename} with patched binary.")
            return None, None
        return result, patch_result

    def run_testcase_cached(self, patch_id: int, testcase: Testcase) -> Tuple[Optional[BinRadarProbeResult], Optional[BinRadarCachedRun]]:
        predicate = self.cached_predicates.get(patch_id)
        if predicate is None:
            return None, None
        return self.runner.test_with_cached(
            patch_id, predicate,
            os.path.join(self.minimized_dir, testcase.filename))

    def run_verification_streaming(self, minimizer_result_file: str,
                                   poll_interval: float = 0.2,
                                   minimizer_thread: Optional[threading.Thread] = None,
                                   minimizer_exc_queue: Optional[Any] = None) -> None:
        """Stream [testcase] [result] rows from minimizer.sbsv and verify the
        patches against each testcase as it appears. A standalone replay
        requires the done marker; a live stream may stop consuming rows once
        every patch is rejected while the minimizer continues to completion.
        """
        parser = sbsv.parser()
        parser.add_custom_type("hex", lambda x: int(x, 16))
        parser.add_schema("[testcase] [result] [id: int] [file: str] [exit: str] [fault-addr: hex] [pid: int] [br: list[int]]")
        parser.add_schema("[minimizer] [done] [time: int]")
        if not os.path.exists(minimizer_result_file):
            if minimizer_thread is None:
                raise RuntimeError(f"Minimizer results not found: {minimizer_result_file}")
            waited = 0.0
            while not os.path.exists(minimizer_result_file):
                if minimizer_thread is not None and not minimizer_thread.is_alive():
                    if minimizer_exc_queue is not None and not minimizer_exc_queue.empty():
                        raise minimizer_exc_queue.get_nowait()
                    raise RuntimeError("Minimizer ended without writing the done marker. Its results are incomplete.")
                time.sleep(poll_interval)
                waited += poll_interval
                if waited >= 60:
                    raise RuntimeError(f"Minimizer results not found: {minimizer_result_file}")
        pending_patches = list(self.patches)
        done_seen = False
        dead_without_marker = False
        with open(minimizer_result_file, "r", encoding="utf-8") as f:
            offset = f.tell()
            while True:
                f.seek(offset)
                fcntl.flock(f, fcntl.LOCK_EX)
                data = f.read()
                offset = f.tell()
                fcntl.flock(f, fcntl.LOCK_UN)
                for line in data.split("\n"):
                    row = parser.parse_line_detached(line)
                    if row is None:
                        continue
                    if row.schema_name == "testcase$result":
                        testcase = self._testcase_from_result_row(row.data)
                        if testcase is None:
                            continue
                        self.testcases.append(testcase)
                        rejected = self._test_testcase_batch(
                            list(pending_patches), testcase)
                        for patch in list(pending_patches):
                            if patch not in rejected:
                                continue
                            self.logger.info(f"[verifier-result] [res rejected] [patch {patch}] [testcase {testcase.filename}]")
                            pending_patches.remove(patch)
                        if not pending_patches and minimizer_thread is not None:
                            return
                    elif row.schema_name == "minimizer$done":
                        done_seen = True
                if minimizer_thread is None:
                    if done_seen:
                        break
                    raise RuntimeError("minimizer.sbsv does not contain a completed minimizer run ([minimizer] [done] missing). Run the minimizer phase first.")
                if not minimizer_thread.is_alive():
                    if done_seen:
                        break
                    if minimizer_exc_queue is not None and not minimizer_exc_queue.empty():
                        raise minimizer_exc_queue.get_nowait()
                    # The marker may have been written between our last read
                    # and the thread's exit; the file is final once the thread
                    # is dead, so one more read round is conclusive before
                    # declaring the run incomplete.
                    if dead_without_marker:
                        raise RuntimeError("Minimizer ended without writing the done marker. Its results are incomplete.")
                    dead_without_marker = True
                time.sleep(poll_interval)
            # Final drain guard: the writer holds the lock across write+flush, so
            # a non-newline-terminated tail means a torn row from a non-locking writer.
            f.seek(offset)
            fcntl.flock(f, fcntl.LOCK_EX)
            tail = f.read()
            fcntl.flock(f, fcntl.LOCK_UN)
            if tail and not tail.endswith("\n"):
                raise RuntimeError("minimizer.sbsv contains an unterminated line")
        for patch in pending_patches:
            self.logger.info(f"[verifier-result] [res verified] [patch {patch}] [testcase ]")