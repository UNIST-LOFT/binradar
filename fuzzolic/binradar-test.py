#!/usr/bin/env python3
import argparse
import csv
import enum
import os
import random
import re
import sbsv
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import binradar_utils
from binradar_verifier import (
    BinRadarProbeResult,
    BinRadarQemuRunner,
    QEMU_STACKTRACE_RELEASE,
)

LOFTIX_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "benchmarks", "loftix"))
TRACER_BIN = os.path.join(SCRIPT_DIR, "..", "tracer", "build", "x86_64-linux-user", "qemu-x86_64")
SOLVER_BIN = os.path.join(SCRIPT_DIR, "..", "solver", "build", "solver-smt")

"""
Run tests on binradar benchmark subjects listed in exp.list.

Usage:
    cd benchmarks/loftix
    uv run ../../fuzzolic/binradar-test.py qasan [options]

Subcommands:
    qasan
        Run the probe-style QASAN execution (afl-qemu-trace --asan host)
        against <binary>.orig and <binary>.brpatched (PATCH_ID=0, i.e.
        original behavior) for every subject in exp.list and check that
        QASAN detects the same crash (same fault address) on the patched
        binary as on the original one.  When the workdir also contains a
        <binary>.brcached artifact (built by binradar-setup.py when more
        than one predicate survived the prefilter), the same PATCH_ID=0
        probe is run against it too and its crash must match .orig as
        well (with TAOSC_PRED unset the cached plugin takes the no-branch
        fallback, so .brcached must behave like the original binary).

        Verdicts:
          PASS          - qasan detects the same crash (same fault address)
                          on .orig and every checked artifact (.brpatched,
                          plus .brcached when present).
          FAIL          - the patched binary does not crash, crashes at a
                          different fault address, the probe on .brpatched
                          fails (timeout / no crash detected), or the
                          .brcached artifact fails the same check.
          BASELINE-FAIL - the probe on .orig does not reproduce the crash;
                          the subject cannot be tested.
          SKIP          - workdir / binary / poc input files missing.

    valgrind
        Check that QASAN reports the same crash location as valgrind.
        For every subject in exp.list it runs valgrind (--tool=memcheck)
        on <binary>.orig with the POC and parses the first invalid
        read/write's stacktrace (falling back to a non-memory crash such as
        SIGFPE when no invalid access is reported), then runs the probe-style
        QASAN execution (afl-qemu-trace --asan host) on <binary>.orig and
        compares the reported fault-addr against the normalized Valgrind
        location.

        Verdicts:
          PASS          - valgrind and QASAN agree on the crash location.
          FAIL          - QASAN's crash location differs from valgrind's, or
                          one detects a crash that the other does not.
          SKIP          - workdir / binary / poc input files missing, or
                          neither valgrind nor QASAN detects a crash.

    tracer
        Compare the fuzzolic tracer's reported crash fault address
        against afl-qemu-trace on <binary>.orig for every subject in
        exp.list. Runs afl-qemu-trace (--asan host) and the fuzzolic
        tracer (tracer/build/.../qemu-x86_64, no -symbolic) on .orig
        with the POC and checks both report the same fault address
        (the faulting instruction's code address).

        Verdicts:
          PASS          - tracer and afl-qemu-trace report the same
                          fault address.
          FAIL          - tracer does not crash, records a crash but no
                          fault address, or reports a different fault
                          address than afl-qemu-trace.
          BASELINE-FAIL - afl-qemu-trace does not reproduce the crash;
                          the subject cannot be tested.
          SKIP          - workdir / binary / poc input / tracer binary
                          missing.

    memcheck-reach
        Check whether the target reaches the patch function entry point
        when the tracer runs with BINRADAR_MEMCHECK_ENABLE=1 (the
        QASAN-like concrete bounds checking). The directed/binradar
        phases enable memcheck and set BINRADAR_ENTRYPOINT to the patch
        function entry: if the POC triggers a heap-buffer-overflow or
        use-after-free before that entry point is executed, the tracer
        dies before the forkserver handshake and the phase fails with
        "EOF while reading from forkserver". This test runs the fuzzolic
        tracer (no -symbolic) on <binary>.orig with memcheck enabled and
        BINRADAR_ENTRYPOINT taken from the latest probe result, then
        reports the [snapshot] [exit] entrypoint-hit count.

        Verdicts:
          PASS          - the target reached the patch function
                          (entrypoint-hit > 0), or ran to completion
                          without a memcheck-detected crash.
          FAIL          - the target crashed (e.g. memcheck) before
                          reaching the patch function (entrypoint-hit 0);
                          the directed/binradar phases would fail with EOF.
          BASELINE-FAIL - no probe result found in <workdir>/out (cannot
                          determine the patch function entry point), or
                          the tracer probe itself failed.
          SKIP          - workdir / binary / poc input / tracer binary
                          missing.
Results are summarized in a single file (logs/qasan-<timestamp>.log by
default, or logs/qasan-<timestamp>.csv / .tsv with --format csv / tsv;
likewise logs/valgrind-<timestamp>.<ext> for the valgrind subcommand,
logs/tracer-<timestamp>.<ext> for the tracer subcommand, and
logs/memcheck-reach-<timestamp>.<ext> for the memcheck-reach subcommand).
With --format log, --verbose adds a reproduction command line per probe
(`cd <workdir> && ENV=...; <command>`) so a failing subject can be
re-run by hand.
"""



def display_path(exp_file_dir: str, path: str) -> str:
    """Return a path relative to the exp list directory, for output."""
    if not os.path.isabs(path):
        return os.path.normpath(path)
    try:
        rel = os.path.relpath(path, exp_file_dir)
    except ValueError:
        return path
    if rel.startswith(".."):
        return path
    return rel


class Status(str, enum.Enum):
    """Verdict of a test for a single subject."""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    BASELINE = "BASELINE-FAIL"


@dataclass
class QasanSubjectResult:
    exp_dir: str
    status: Status
    detail: str = ""
    orig_exit: str = ""
    orig_fault_addr: str = ""
    patched_exit: str = ""
    patched_fault_addr: str = ""
    cached_exit: str = ""
    cached_fault_addr: str = ""
    orig_cmd: str = ""
    patched_cmd: str = ""
    cached_cmd: str = ""


@dataclass
class ValgrindSubjectResult:
    exp_dir: str
    status: Status
    detail: str = ""
    valgrind_fault_addr: str = ""
    qasan_fault_addr: str = ""
    valgrind_cmd: str = ""
    qasan_cmd: str = ""


@dataclass
class TracerSubjectResult:
    exp_dir: str
    status: Status
    detail: str = ""
    afl_fault_addr: str = ""
    tracer_fault_addr: str = ""
    afl_cmd: str = ""
    tracer_cmd: str = ""

@dataclass
class MemcheckReachResult:
    exp_dir: str
    status: Status
    detail: str = ""
    entrypoint: str = ""
    entrypoint_hit: str = ""
    crash_reason: str = ""
    fault_addr: str = ""
    tracer_cmd: str = ""


def format_repro_command(workdir: str, command: List[str],
                         env: Dict[str, str]) -> str:
    """Build a single-line reproduction command for a probe run.

    Format: cd <workdir> && ENV=...; <command>. Only env vars that differ
    from the current environment are listed (the runner's overrides).
    """
    assignments = " ".join(
        f"{k}={shlex.quote(v)}"
        for k, v in sorted(env.items())
        if v != os.environ.get(k))
    cmd_str = shlex.join(command)
    if assignments:
        return f"cd {shlex.quote(workdir)} && {assignments}; {cmd_str}"
    return f"cd {shlex.quote(workdir)} && {cmd_str}"


def extract_exit_info(log: str) -> Optional[str]:
    """Fallback exit-info extraction when the probe result cannot be parsed."""
    for line in log.splitlines():
        m = re.search(r"\[exit\]\s+\[result\s+(\w+)\]", line)
        if m:
            return m.group(1)
    return None


_VALGRIND_FRAME_RE = re.compile(
    r"\b(at|by)\s+0x([0-9A-Fa-f]+):.*?(?:\(in\s+(.+?)\))?\s*$")


def _valgrind_frame_is_binary(frame_path: Optional[str],
                              binary_path: Optional[str]) -> bool:
    if not frame_path or not binary_path:
        return False
    if os.path.realpath(frame_path) == os.path.realpath(binary_path):
        return True
    return os.path.basename(frame_path) == os.path.basename(binary_path)


def _collect_valgrind_frames(lines: List[str],
                             header_idx: int) -> List[Tuple[str, int, Optional[str]]]:
    """Parse the ``at``/``by`` frames following a valgrind header line.

    Each frame is ``(kind, address, path)`` where ``kind`` is ``at`` or
    ``by`` and ``path`` is the ``(in ...)`` component when present. Parsing
    stops at the first non-frame line after at least one frame has been seen
    (valgrind separates the stack trace from the following section with an
    empty ``==PID==`` line or an ``Address ...`` / ``HEAP SUMMARY`` line).
    """
    frames = []
    for frame_line in lines[header_idx + 1:header_idx + 64]:
        match = _VALGRIND_FRAME_RE.search(frame_line)
        if match:
            frames.append((
                match.group(1),
                int(match.group(2), 16),
                match.group(3),
            ))
            continue
        if frames:
            break
    return frames


def _normalize_valgrind_frames(
        frames: List[Tuple[str, int, Optional[str]]],
        binary_path: Optional[str]) -> Optional[int]:
    """Return the crash address for a valgrind stack trace.

    The ``at`` frame is the actual faulting instruction; use it when it
    belongs to the target binary. Otherwise (interceptor / shared library /
    compiler helper), QASAN reports the caller in the target binary, so use
    the first target-binary ``by`` frame and add one to convert its return
    address to the call-site address reported by QASAN.
    """
    at_frame = next(
        (frame for frame in frames if frame[0] == "at"), None)
    if at_frame and _valgrind_frame_is_binary(at_frame[2], binary_path):
        return at_frame[1]

    target_by_frame = next(
        (frame for frame in frames
         if frame[0] == "by" and
         _valgrind_frame_is_binary(frame[2], binary_path)),
        None)
    if target_by_frame:
        return target_by_frame[1] + 1

    if at_frame:
        return at_frame[1]
    return None


def extract_valgrind_fault_addr(log: str,
                                binary_path: Optional[str] = None) -> Optional[int]:
    """Return the normalized address for the first invalid read/write.

    Valgrind's ``at`` frame is the actual invalid-access instruction. When
    that instruction belongs to an interceptor or shared library, QASAN
    reports the caller in the target binary instead. In that case use the
    first target-binary ``by`` frame and add one to convert its return address
    to the call-site address reported by QASAN.
    """
    lines = log.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"Invalid (read|write) of size", line):
            frames = _collect_valgrind_frames(lines, i)
            addr = _normalize_valgrind_frames(frames, binary_path)
            if addr is not None:
                return addr
    return None


def extract_valgrind_signal_addr(
        log: str, binary_path: Optional[str] = None) -> Optional[int]:
    """Return the crash address for a non-memory (signal) crash.

    When the program dies from a signal that is not a memory error (e.g.
    SIGFPE from an integer divide by zero), valgrind prints ``Process
    terminating with default action of signal N (SIGxxx)`` followed by the
    usual ``at``/``by`` stack trace. Parse that stack trace and normalize it
    the same way as memory errors.
    """
    lines = log.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"Process terminating with default action of signal",
                     line):
            frames = _collect_valgrind_frames(lines, i)
            addr = _normalize_valgrind_frames(frames, binary_path)
            if addr is not None:
                return addr
    return None


def extract_qasan_fault_addr(log: str) -> Optional[Tuple[int, str]]:
    """Return (fault_addr, exit_result) parsed from a QASAN probe log.

    Unlike BinRadarProbeResult.from_log this does not require the patch to
    have been set, so it also works on subjects that have not gone through
    the full binradar setup (where no patch-info row is emitted)."""
    parser = BinRadarProbeResult.get_parser()
    result = parser.loads(log)
    if len(result["fault-addr"]) == 0:
        return None
    fault_addr = result["fault-addr"][-1]["addr"]
    exit_info = result["exit"][-1]["result"] if result["exit"] else ""
    return fault_addr, exit_info


_TRACER_PARSER = sbsv.parser()
_TRACER_PARSER.add_custom_type("hex", lambda x: int(x, 16))
_TRACER_PARSER.add_schema(
    "[snapshot] [crash] [hit-count: int] [reason: str] [guest_pc: hex] "
    "[guest_cs_base: hex] [fault_addr: hex] [host_fault_addr: hex]")
_TRACER_PARSER.add_schema("[snapshot] [exit] [crash] [entrypoint-hit: int]")
_TRACER_PARSER.add_schema("[snapshot] [exit] [normal] [entrypoint-hit: int]")


def extract_tracer_fault_addr(log: str) -> Optional[int]:
    """Return the fault_addr from a tracer crash log line.

    The tracer records info->fault_addr (= guest_pc, the faulting
    instruction) in its [snapshot] [crash] line written to
    BINRADAR_TRACER_LOG_FILE."""
    for line in log.splitlines():
        row = _TRACER_PARSER.parse_line_detached(line)
        if row is not None and row.get_name() == "snapshot$crash":
            return row["fault_addr"]
    return None


def extract_tracer_exit(log: str) -> str:
    """Return 'crash' if a [snapshot] [crash] line present, 'ok' if a
    [snapshot] [exit] [normal] line present, else ''."""
    for line in log.splitlines():
        row = _TRACER_PARSER.parse_line_detached(line)
        if row is None:
            continue
        if row.get_name() in ("snapshot$crash", "snapshot$exit$crash"):
            return "crash"
        if row.get_name() == "snapshot$exit$normal":
            return "ok"
    return ""


def extract_tracer_entrypoint_hit(log: str) -> int:
    """Return the entrypoint-hit count from the [snapshot] [exit] line.

    The tracer logs [snapshot] [exit] [crash|normal] [entrypoint-hit N]
    at exit; N is how many times the patch function entry point was
    reached before the exit. N=0 with a crash means the target crashed
    (e.g. from memcheck) before reaching the patch function."""
    for line in log.splitlines():
        row = _TRACER_PARSER.parse_line_detached(line)
        if row is None:
            continue
        if row.get_name() in ("snapshot$exit$crash", "snapshot$exit$normal"):
            return row["entrypoint-hit"]
    return -1


def extract_tracer_crash_reason(log: str) -> str:
    """Return the reason from the [snapshot] [crash] line (e.g.
    'memcheck: heap-buffer-overflow'), or '' if absent."""
    for line in log.splitlines():
        row = _TRACER_PARSER.parse_line_detached(line)
        if row is not None and row.get_name() == "snapshot$crash":
            return row["reason"]
    return ""


def run_qasan_probe(workdir: str, env: Dict[str, str], use_patched: bool,
                    testcase: str, timeout: float,
                    binary_path: Optional[str] = None):
    """Run the probe-style qasan execution and parse the probe result.

    When binary_path is given it is probed directly (e.g. <binary>.brcached);
    otherwise use_patched selects .orig vs .brpatched."""
    runner = BinRadarQemuRunner.from_env(workdir, env)
    if binary_path is not None:
        command = runner.get_qemu_stacktrace_command_for_binary(
            binary_path, testcase)
    else:
        command = runner.get_qemu_stacktrace_command(use_patched, testcase)
    proc_env = runner.get_env_for_exec(patch_id="0")
    if binary_path is not None and binary_path.endswith(".brcached"):
        # The cached artifact's dest() takes the no-branch fallback only
        # when TAOSC_PRED is unset; make sure a stale value from the
        # surrounding shell cannot turn the probe into a patched run.
        proc_env.pop("TAOSC_PRED", None)
        if runner.brcache_stack_size:
            proc_env["BRCACHE_STACK_SIZE"] = str(runner.brcache_stack_size)
    result = binradar_utils.execute(
        command, cwd=workdir, env=proc_env, timeout=timeout, verbose=False)
    probe = None
    exit_hint = ""
    if result.success:
        probe = BinRadarProbeResult.from_log(result.stderr)
        if probe is None:
            exit_hint = extract_exit_info(result.stderr) or ""
    repro = format_repro_command(workdir, command, proc_env)
    return probe, exit_hint, result, repro


def run_tracer_probe(workdir: str, env: Dict[str, str],
                     testcase: str, timeout: float):
    """Run the fuzzolic tracer on <binary>.orig (no -symbolic) and parse
    the crash fault_addr from its log. Returns (fault_addr, exit_str,
    result, repro)."""
    binary = env.get("BINARY", "")
    orig_bin = os.path.join(workdir, f"{binary}.orig")
    test_cmd = env.get("TEST_CMD", "")
    command = [TRACER_BIN, orig_bin] + shlex.split(
        test_cmd.replace("@@", testcase))
    proc_env = dict(os.environ)
    proc_env["BINRADAR_FORKSERVER_ENABLE"] = "0"
    proc_env["BINRADAR_TRACE_FILE"] = "none"
    # The original binary has no E9 mappings: an empty exclusion list and
    # no relocated calls.  A missing E9_EXCLUDE_RANGES is also safe (the
    # tracer treats missing/empty as "no E9 regions").
    proc_env["E9_EXCLUDE_RANGES"] = ""
    proc_env["E9_RELOCATED_CALL_JUMPS"] = ""
    proc_env["BINRADAR_MEMCHECK_ENABLE"] = "1"
    # Set PLT_INFO_FILE for heap allocation tracking (memcheck).
    # Look for plt_info.txt in the workdir's out directory.
    # Regenerate if it doesn't contain malloc/free entries.
    plt_info = os.path.join(workdir, "out", "plt_info.txt")
    need_regen = True
    if os.path.isfile(plt_info):
        try:
            with open(plt_info, "r") as f:
                content = f.read()
            if "malloc" in content and "free" in content:
                need_regen = False
        except Exception:
            pass
    if need_regen:
        find_models = os.path.join(SCRIPT_DIR, "find_models_addrs.py")
        try:
            regen_result = binradar_utils.execute(
                [sys.executable, find_models, "-o", plt_info, orig_bin],
                cwd=workdir, timeout=30, verbose=False)
        except Exception:
            pass
    if os.path.isfile(plt_info):
        proc_env["PLT_INFO_FILE"] = plt_info
    result = binradar_utils.execute(
        command, cwd=workdir, env=proc_env, timeout=timeout, verbose=False)
    fault_addr = extract_tracer_fault_addr(result.stderr) if result.success else None
    exit_str = extract_tracer_exit(result.stderr) if result.success else ""
    repro = format_repro_command(workdir, command, proc_env)
    return fault_addr, exit_str, result, repro


def find_latest_probe_results(out_dir: str) -> Optional[str]:
    """Find the most recent probe-results.sbsv under <out_dir>/*/."""
    if not os.path.isdir(out_dir):
        return None
    candidates = []
    for name in os.listdir(out_dir):
        path = os.path.join(out_dir, name, "probe-results.sbsv")
        if os.path.isfile(path):
            candidates.append(path)
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def run_memcheck_reach_probe(workdir: str, env: Dict[str, str],
                             testcase: str, entrypoint: str,
                             timeout: float):
    """Run the fuzzolic tracer on <binary>.orig in the real directed-mode
    configuration (-symbolic, solver shared memory) with
    BINRADAR_MEMCHECK_ENABLE=1 and BINRADAR_ENTRYPOINT=<entrypoint>, and
    parse whether the target reached the patch function before any
    memcheck-detected crash. Returns (entrypoint_hit, exit_str,
    crash_reason, fault_addr, result, repro).

    The entrypoint-hit counter is only incremented by the symbolic
    instrumentation (symbolic.c, TCG insn_start), so the tracer must run
    with -symbolic and a live solver providing the shared-memory pool."""
    binary = env.get("BINARY", "")
    orig_bin = os.path.join(workdir, f"{binary}.orig")
    test_cmd = env.get("TEST_CMD", "")
    command = [TRACER_BIN, "-symbolic", "-d", "page", orig_bin] + shlex.split(
        test_cmd.replace("@@", testcase))
    proc_env = dict(os.environ)
    proc_env["BINRADAR_FORKSERVER_ENABLE"] = "0"
    proc_env["BINRADAR_TRACE_FILE"] = "none"
    # The original binary has no E9 mappings: an empty exclusion list and
    # no relocated calls.  A missing E9_EXCLUDE_RANGES is also safe (the
    # tracer treats missing/empty as "no E9 regions").
    proc_env["E9_EXCLUDE_RANGES"] = ""
    proc_env["E9_RELOCATED_CALL_JUMPS"] = ""
    proc_env["BINRADAR_MEMCHECK_ENABLE"] = "1"
    if entrypoint:
        proc_env["BINRADAR_ENTRYPOINT"] = entrypoint
    # Set PLT_INFO_FILE for heap allocation tracking (memcheck).
    # Look for plt_info.txt in the workdir's out directory.
    # Regenerate if it doesn't contain malloc/free entries.
    plt_info = os.path.join(workdir, "out", "plt_info.txt")
    need_regen = True
    if os.path.isfile(plt_info):
        try:
            with open(plt_info, "r") as f:
                content = f.read()
            if "malloc" in content and "free" in content:
                need_regen = False
        except Exception:
            pass
    if need_regen:
        find_models = os.path.join(SCRIPT_DIR, "find_models_addrs.py")
        try:
            regen_result = binradar_utils.execute(
                [sys.executable, find_models, "-o", plt_info, orig_bin],
                cwd=workdir, timeout=30, verbose=False)
        except Exception:
            pass
    if os.path.isfile(plt_info):
        proc_env["PLT_INFO_FILE"] = plt_info

    # The symbolic tracer needs a live solver to attach its expression
    # pool / query shared memory (the tracer polls for SHM_READY). Run the
    # same solver command the directed phase uses, with fresh random keys.
    for key in ("EXPR_POOL_SHM_KEY", "QUERY_SHM_KEY", "BITMAP_SHM_KEY",
                "MUTATION_REQ_SHM_KEY"):
        proc_env[key] = hex(random.getrandbits(32))
    proc_env["SOLVER_TIMEOUT"] = str(int(timeout) + 10)
    proc_env["SYMBOLIC_INJECT_INPUT_MODE"] = "FROM_FILE"
    proc_env["SYMBOLIC_TESTCASE_NAME"] = testcase

    run_dir = tempfile.mkdtemp(prefix="memcheck-reach-")
    solver = None
    try:
        out_dir = os.path.join(run_dir, "solver-out")
        os.makedirs(out_dir, exist_ok=True)
        for bitmap in ("global", "context", "memory"):
            with open(os.path.join(run_dir, f"{bitmap}-bitmap"), "w") as f:
                pass
        solver_cmd = ["stdbuf", "-o0", SOLVER_BIN,
                      "-i", testcase,
                      "-o", out_dir,
                      "-b", os.path.join(run_dir, "global-bitmap"),
                      "-c", os.path.join(run_dir, "context-bitmap"),
                      "-m", os.path.join(run_dir, "memory-bitmap")]
        try:
            solver = subprocess.Popen(
                solver_cmd, cwd=workdir, env=proc_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
        except Exception:
            solver = None
        # Give the solver time to create and initialize the shared
        # memories before the tracer attaches.
        time.sleep(1)

        result = binradar_utils.execute(
            command, cwd=workdir, env=proc_env, timeout=timeout,
            verbose=False)
    finally:
        if solver is not None:
            try:
                solver.terminate()
                solver.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    solver.kill()
                    solver.wait(timeout=5)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    pass
        import shutil
        shutil.rmtree(run_dir, ignore_errors=True)

    entry_hits = extract_tracer_entrypoint_hit(
        result.stderr) if result.success else -1
    exit_str = extract_tracer_exit(result.stderr) if result.success else ""
    crash_reason = extract_tracer_crash_reason(
        result.stderr) if result.success else ""
    fault_addr = extract_tracer_fault_addr(
        result.stderr) if result.success else None
    repro = format_repro_command(workdir, command, proc_env)
    return entry_hits, exit_str, crash_reason, fault_addr, result, repro


def run_qasan_subject(exp_dir: str, workdir_name: str,
                      timeout: float) -> QasanSubjectResult:
    workdir = os.path.join(exp_dir, workdir_name)
    result = QasanSubjectResult(exp_dir=exp_dir, status=Status.SKIP)

    env_path = os.path.join(workdir, "binradar.env")
    if not os.path.isfile(env_path):
        result.detail = "binradar.env not found"
        return result
    env = binradar_utils.load_env(env_path)

    binary = env.get("BINARY", "")
    orig_bin = os.path.join(workdir, f"{binary}.orig")
    patched_bin = os.path.join(workdir, f"{binary}.brpatched")
    cached_bin = os.path.join(workdir, f"{binary}.brcached")
    poc_input = env.get("POC_INPUT", "")
    testcase = (poc_input if os.path.isabs(poc_input)
                else os.path.join(workdir, poc_input))

    missing = [name for path, name in [
        (orig_bin, "orig binary"),
        (patched_bin, "patched binary"),
        (testcase, "poc input")] if not os.path.exists(path)]
    if missing:
        result.detail = "missing: " + ", ".join(missing)
        return result

    try:
        orig_probe, orig_hint, orig_res, orig_repro = run_qasan_probe(
            workdir, env, False, testcase, timeout)
        patched_probe, patched_hint, patched_res, patched_repro = run_qasan_probe(
            workdir, env, True, testcase, timeout)
    except Exception as e:
        result.detail = f"execution error: {e}"
        return result

    result.orig_cmd = orig_repro
    result.patched_cmd = patched_repro

    if orig_probe is None:
        reason = "timeout" if not orig_res.success else (orig_hint or "parse failure")
        result.status = Status.BASELINE
        result.orig_exit = orig_hint
        result.detail = f"probe on .orig failed ({reason})"
        return result
    if orig_probe.exit_info != "crash":
        result.status = Status.BASELINE
        result.orig_exit = orig_probe.exit_info
        result.detail = f"probe on .orig did not crash (exit: {orig_probe.exit_info})"
        return result

    result.orig_exit = orig_probe.exit_info
    result.orig_fault_addr = hex(orig_probe.fault_addr)

    if patched_probe is None:
        reason = "timeout" if not patched_res.success else (patched_hint or "no crash detected")
        result.status = Status.FAIL
        result.detail = f"probe on .brpatched failed ({reason})"
        return result

    result.patched_exit = patched_probe.exit_info
    result.patched_fault_addr = hex(patched_probe.fault_addr)

    if patched_probe.exit_info != "crash":
        result.status = Status.FAIL
        result.detail = f"no crash detected on .brpatched (exit: {patched_probe.exit_info})"
    elif patched_probe.fault_addr != orig_probe.fault_addr:
        result.status = Status.FAIL
        result.detail = "fault address differs"

    # Also check the .brcached artifact when setup built one: with
    # TAOSC_PRED unset its dest() must take the no-branch fallback, so the
    # POC must reproduce the same crash as on .orig.
    if os.path.isfile(cached_bin):
        try:
            cached_probe, cached_hint, cached_res, cached_repro = run_qasan_probe(
                workdir, env, False, testcase, timeout,
                binary_path=cached_bin)
        except Exception as e:
            cached_probe, cached_hint, cached_res, cached_repro = \
                None, f"execution error: {e}", None, ""
        result.cached_cmd = cached_repro
        if cached_probe is None:
            reason = "timeout" if (cached_res is not None and not cached_res.success) \
                else (cached_hint or "no crash detected")
            result.cached_exit = "failed"
            result.status = Status.FAIL
            reason_txt = f"probe on .brcached failed ({reason})"
            result.detail = (f"{result.detail}; {reason_txt}"
                             if result.detail else reason_txt)
            return result
        result.cached_exit = cached_probe.exit_info
        result.cached_fault_addr = hex(cached_probe.fault_addr)
        if cached_probe.exit_info != "crash":
            result.status = Status.FAIL
            detail = (f"no crash detected on .brcached "
                      f"(exit: {cached_probe.exit_info})")
            result.detail = f"{result.detail}; {detail}" if result.detail else detail
            return result
        if cached_probe.fault_addr != orig_probe.fault_addr:
            result.status = Status.FAIL
            detail = "fault address differs on .brcached"
            result.detail = f"{result.detail}; {detail}" if result.detail else detail
            return result

    if result.status == Status.FAIL:
        return result
    result.status = Status.PASS
    result.detail = "same crash detected on all checked binaries"
    return result


def run_valgrind_subject(exp_dir: str, workdir_name: str,
                         timeout: float) -> ValgrindSubjectResult:
    """Run valgrind and the QASAN probe on a subject and compare the crash
    locations they report.

    Reads binradar.env when present, otherwise falls back to config.env, so
    the crash-location check also works on subjects that have not gone
    through the full binradar setup (only <binary>.orig is required)."""
    workdir = os.path.join(exp_dir, workdir_name)
    result = ValgrindSubjectResult(exp_dir=exp_dir, status=Status.SKIP)

    env_path = os.path.join(workdir, "binradar.env")
    if not os.path.isfile(env_path):
        env_path = os.path.join(exp_dir, "config.env")
    if not os.path.isfile(env_path):
        result.detail = "binradar.env / config.env not found"
        return result
    env = binradar_utils.load_env(env_path)

    binary = env.get("BINARY", "")
    orig_bin = os.path.join(workdir, f"{binary}.orig")
    poc_input = env.get("POC_INPUT", "")
    testcase = (poc_input if os.path.isabs(poc_input)
                else os.path.join(workdir, poc_input))
    test_cmd = env.get("TEST_CMD", "")

    missing = [name for path, name in [
        (orig_bin, "orig binary"),
        (testcase, "poc input")] if not os.path.exists(path)]
    if missing:
        result.detail = "missing: " + ", ".join(missing)
        return result

    proc_env: Dict[str, str] = {}
    try:
        valgrind_cmd = ["valgrind", "--error-exitcode=99", "--tool=memcheck",
                        orig_bin] + shlex.split(test_cmd.replace("@@", testcase))
        valgrind_res = binradar_utils.execute(
            valgrind_cmd, cwd=workdir, timeout=timeout, verbose=False)

        qasan_cmd = [QEMU_STACKTRACE_RELEASE, "--input", testcase,
                     "--asan", "host"]
        if env.get("PATCH_LOC"):
            qasan_cmd += ["--patch-loc", env["PATCH_LOC"]]
        qasan_cmd += [orig_bin, "--"] + shlex.split(test_cmd)
        proc_env = dict(os.environ)
        proc_env["AFL_USE_QASAN"] = "1"
        proc_env["PATCH_ID"] = "0"
        qasan_res = binradar_utils.execute(
            qasan_cmd, cwd=workdir, env=proc_env, timeout=timeout,
            verbose=False)
        qasan_fault = extract_qasan_fault_addr(qasan_res.stderr) \
            if qasan_res.success else None
    except Exception as e:
        result.detail = f"execution error: {e}"
        return result

    result.valgrind_cmd = format_repro_command(workdir, valgrind_cmd, {})
    result.qasan_cmd = format_repro_command(workdir, qasan_cmd, proc_env)

    valgrind_fault = extract_valgrind_fault_addr(valgrind_res.stderr, orig_bin)
    if valgrind_fault is None:
        valgrind_fault = extract_valgrind_signal_addr(valgrind_res.stderr,
                                                      orig_bin)

    qasan_addr = qasan_exit = None
    if qasan_fault is not None:
        qasan_addr, qasan_exit = qasan_fault
        result.qasan_fault_addr = hex(qasan_addr)

    if valgrind_fault is None:
        # Valgrind found neither a memory error nor a signal crash.
        if qasan_fault is None:
            result.status = Status.SKIP
            result.detail = "no crash under valgrind or qasan"
            return result
        result.status = Status.FAIL
        result.detail = "qasan detected a crash valgrind did not reproduce"
        return result

    result.valgrind_fault_addr = hex(valgrind_fault)

    if qasan_fault is None:
        result.status = Status.FAIL
        result.detail = "valgrind crashed but qasan did not detect it"
        return result
    if qasan_exit != "crash":
        result.status = Status.FAIL
        result.detail = f"qasan did not crash (exit: {qasan_exit})"
        return result

    if qasan_addr != valgrind_fault:
        result.status = Status.FAIL
        result.detail = "crash location differs"
        return result

    result.status = Status.PASS
    result.detail = "qasan crash location matches valgrind"
    return result


def run_tracer_subject(exp_dir: str, workdir_name: str,
                       timeout: float) -> TracerSubjectResult:
    workdir = os.path.join(exp_dir, workdir_name)
    result = TracerSubjectResult(exp_dir=exp_dir, status=Status.SKIP)

    env_path = os.path.join(workdir, "binradar.env")
    if not os.path.isfile(env_path):
        env_path = os.path.join(exp_dir, "config.env")
    if not os.path.isfile(env_path):
        result.detail = "binradar.env / config.env not found"
        return result
    env = binradar_utils.load_env(env_path)

    binary = env.get("BINARY", "")
    orig_bin = os.path.join(workdir, f"{binary}.orig")
    poc_input = env.get("POC_INPUT", "")
    testcase = (poc_input if os.path.isabs(poc_input)
                else os.path.join(workdir, poc_input))

    missing = [name for path, name in [
        (orig_bin, "orig binary"),
        (testcase, "poc input")] if not os.path.exists(path)]
    if missing:
        result.detail = "missing: " + ", ".join(missing)
        return result
    if not os.path.isfile(TRACER_BIN):
        result.detail = f"tracer binary not found: {TRACER_BIN}"
        return result

    # Build the afl-qemu-trace probe command by hand (like run_valgrind_subject)
    # instead of using run_qasan_probe, whose BinRadarQemuRunner.from_env
    # requires PATCH_LOC in the env; subjects with only a config.env
    # fallback lack that key. None of them are needed for an .orig probe.
    try:
        qasan_cmd = [QEMU_STACKTRACE_RELEASE, "--input", testcase,
                     "--asan", "host"]
        if env.get("PATCH_LOC"):
            qasan_cmd += ["--patch-loc", env["PATCH_LOC"]]
        qasan_cmd += [orig_bin, "--"] + shlex.split(env.get("TEST_CMD", ""))
        qasan_proc_env = dict(os.environ)
        qasan_proc_env["AFL_USE_QASAN"] = "1"
        qasan_proc_env["PATCH_ID"] = "0"
        afl_res = binradar_utils.execute(
            qasan_cmd, cwd=workdir, env=qasan_proc_env, timeout=timeout,
            verbose=False)
        afl_addr = afl_exit = None
        if afl_res.success:
            afl_fault = extract_qasan_fault_addr(afl_res.stderr)
            if afl_fault is not None:
                afl_addr, afl_exit = afl_fault
            else:
                afl_exit = extract_exit_info(afl_res.stderr) or ""
        afl_repro = format_repro_command(workdir, qasan_cmd, qasan_proc_env)

        tracer_addr, tracer_exit, tracer_res, tracer_repro = run_tracer_probe(
            workdir, env, testcase, timeout)
    except Exception as e:
        result.detail = f"execution error: {e}"
        return result

    result.afl_cmd = afl_repro
    result.tracer_cmd = tracer_repro

    if afl_addr is None:
        reason = "timeout" if not afl_res.success else (afl_exit or "parse failure")
        result.status = Status.BASELINE
        result.detail = f"afl-qemu-trace probe failed ({reason})"
        return result
    if afl_exit != "crash":
        result.status = Status.BASELINE
        result.detail = f"afl-qemu-trace did not crash (exit: {afl_exit})"
        return result

    result.afl_fault_addr = hex(afl_addr)

    if not tracer_res.success and tracer_addr is None:
        result.status = Status.FAIL
        result.detail = "tracer probe failed (timeout / no crash log)"
        return result
    if tracer_addr is None:
        result.status = Status.FAIL
        result.detail = f"tracer did not record a crash (exit: {tracer_exit or 'none'})"
        return result

    result.tracer_fault_addr = hex(tracer_addr)

    if tracer_addr != afl_addr:
        result.status = Status.FAIL
        result.detail = "fault address differs"
        return result
    result.status = Status.PASS
    result.detail = "tracer and afl-qemu-trace report the same fault address"
    return result


def run_memcheck_reach_subject(exp_dir: str, workdir_name: str,
                               timeout: float) -> MemcheckReachResult:
    """Run the fuzzolic tracer with BINRADAR_MEMCHECK_ENABLE=1 on
    <binary>.orig and check whether the target reaches the patch
    function entry point before any memcheck-detected crash.

    The directed/binradar phases set BINRADAR_ENTRYPOINT to the patch
    function entry and enable memcheck: if the POC triggers a
    heap-buffer-overflow / use-after-free before that entry point is
    executed, the tracer dies before the forkserver handshake and the
    phase fails with EOF. This test detects that condition."""
    workdir = os.path.join(exp_dir, workdir_name)
    result = MemcheckReachResult(exp_dir=exp_dir, status=Status.SKIP)

    env_path = os.path.join(workdir, "binradar.env")
    if not os.path.isfile(env_path):
        env_path = os.path.join(exp_dir, "config.env")
    if not os.path.isfile(env_path):
        result.detail = "binradar.env / config.env not found"
        return result
    env = binradar_utils.load_env(env_path)

    binary = env.get("BINARY", "")
    orig_bin = os.path.join(workdir, f"{binary}.orig")
    poc_input = env.get("POC_INPUT", "")
    testcase = (poc_input if os.path.isabs(poc_input)
                else os.path.join(workdir, poc_input))

    missing = [name for path, name in [
        (orig_bin, "orig binary"),
        (testcase, "poc input")] if not os.path.exists(path)]
    if missing:
        result.detail = "missing: " + ", ".join(missing)
        return result
    if not os.path.isfile(TRACER_BIN):
        result.detail = f"tracer binary not found: {TRACER_BIN}"
        return result

    # Determine the patch function entry point from the latest probe
    # result. The probe result is needed: BINRADAR_ENTRYPOINT must match
    # what the directed/binradar phases use.
    probe_file = find_latest_probe_results(os.path.join(workdir, "out"))
    entrypoint = ""
    if probe_file is not None:
        probe = BinRadarProbeResult.from_sbsv(probe_file)
        if probe is not None and probe.patch_func_entry != 0:
            entrypoint = hex(probe.patch_func_entry)
    result.entrypoint = entrypoint

    try:
        entry_hits, exit_str, crash_reason, fault_addr, res, repro = \
            run_memcheck_reach_probe(workdir, env, testcase, entrypoint,
                                     timeout)
    except Exception as e:
        result.detail = f"execution error: {e}"
        return result

    result.tracer_cmd = repro

    if entrypoint == "":
        # Without a probe result we cannot distinguish "crash before the
        # patch function" from "crash after it"; run still tells us
        # whether memcheck fires at all.
        if not res.success:
            result.status = Status.BASELINE
            result.detail = f"tracer probe failed ({'timeout' if not res.success else 'no crash log'})"
            return result
        result.status = Status.BASELINE
        result.detail = (f"no probe result found; tracer exit {exit_str or 'none'}"
                         + (f" ({crash_reason})" if crash_reason else ""))
        return result

    if not res.success:
        result.status = Status.FAIL
        result.detail = f"tracer probe failed ({'timeout' if not res.success else 'no crash log'})"
        return result

    result.entrypoint_hit = str(entry_hits)
    result.crash_reason = crash_reason
    if fault_addr is not None:
        result.fault_addr = hex(fault_addr)

    if exit_str == "crash" and entry_hits == 0:
        result.status = Status.FAIL
        result.detail = ("crash before reaching the patch function "
                         f"(entrypoint-hit 0, reason: {crash_reason or 'unknown'})")
        return result

    if exit_str == "":
        # No [snapshot] [exit] line at all (e.g. tracer crashed on its
        # own, or the target exited without snapshot instrumentation).
        result.status = Status.FAIL
        result.detail = "no snapshot exit line recorded"
        return result
    
    
    if entry_hits > 0:
        if exit_str != "crash":
            result.status = Status.FAIL
            result.detail = f"Could not detect crash: {exit_str}"
            return result
        result.status = Status.PASS
        result.detail = f"reached the patch function (entrypoint-hit {entry_hits})"
    else:
        result.status = Status.FAIL
        result.detail = "no crash detected by memcheck before the patch function"
    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_log_result(result: QasanSubjectResult, verbose: bool = False) -> str:
    lines = [f"=== {result.exp_dir} ==="]
    if result.status == Status.SKIP:
        lines.append(f"  [STATUS] SKIP: {result.detail}")
        return "\n".join(lines)
    lines.append(f"  [orig]    exit: {result.orig_exit or 'n/a'}  "
                 f"fault-addr: {result.orig_fault_addr or 'n/a'}")
    if result.status != Status.BASELINE:
        lines.append(f"  [patched] exit: {result.patched_exit or 'n/a'}  "
                     f"fault-addr: {result.patched_fault_addr or 'n/a'}")
    if result.cached_exit:
        lines.append(f"  [cached]  exit: {result.cached_exit or 'n/a'}  "
                     f"fault-addr: {result.cached_fault_addr or 'n/a'}")
    if verbose:
        if result.orig_cmd:
            lines.append(f"  [cmd orig] {result.orig_cmd}")
        if result.patched_cmd:
            lines.append(f"  [cmd patched] {result.patched_cmd}")
        if result.cached_cmd:
            lines.append(f"  [cmd cached] {result.cached_cmd}")
    lines.append(f"  [VERDICT] {result.status} ({result.detail})")
    return "\n".join(lines)


def format_valgrind_log_result(result: ValgrindSubjectResult,
                               verbose: bool = False) -> str:
    lines = [f"=== {result.exp_dir} ==="]
    if result.status == Status.SKIP:
        lines.append(f"  [STATUS] SKIP: {result.detail}")
        return "\n".join(lines)
    lines.append(f"  [valgrind] fault-addr: {result.valgrind_fault_addr or 'n/a'}")
    lines.append(f"  [qasan]    fault-addr: {result.qasan_fault_addr or 'n/a'}")
    if verbose:
        if result.valgrind_cmd:
            lines.append(f"  [cmd valgrind] {result.valgrind_cmd}")
        if result.qasan_cmd:
            lines.append(f"  [cmd qasan] {result.qasan_cmd}")
    lines.append(f"  [VERDICT] {result.status} ({result.detail})")
    return "\n".join(lines)


def format_tracer_log_result(result: TracerSubjectResult,
                             verbose: bool = False) -> str:
    lines = [f"=== {result.exp_dir} ==="]
    if result.status == Status.SKIP:
        lines.append(f"  [STATUS] SKIP: {result.detail}")
        return "\n".join(lines)
    lines.append(f"  [afl]     fault-addr: {result.afl_fault_addr or 'n/a'}")
    lines.append(f"  [tracer]  fault-addr: {result.tracer_fault_addr or 'n/a'}")
    if verbose:
        if result.afl_cmd:
            lines.append(f"  [cmd afl] {result.afl_cmd}")
        if result.tracer_cmd:
            lines.append(f"  [cmd tracer] {result.tracer_cmd}")
    lines.append(f"  [VERDICT] {result.status} ({result.detail})")
    return "\n".join(lines)


def format_memcheck_reach_log_result(result: MemcheckReachResult,
                                     verbose: bool = False) -> str:
    lines = [f"=== {result.exp_dir} ==="]
    if result.status == Status.SKIP:
        lines.append(f"  [STATUS] SKIP: {result.detail}")
        return "\n".join(lines)
    lines.append(f"  [entrypoint] {result.entrypoint or 'n/a'}")
    lines.append(f"  [entrypoint-hit] {result.entrypoint_hit or 'n/a'}")
    if result.crash_reason:
        lines.append(f"  [crash-reason] {result.crash_reason}")
    if result.fault_addr:
        lines.append(f"  [fault-addr] {result.fault_addr}")
    if verbose:
        if result.tracer_cmd:
            lines.append(f"  [cmd tracer] {result.tracer_cmd}")
    lines.append(f"  [VERDICT] {result.status} ({result.detail})")
    return "\n".join(lines)


CSV_COLUMNS = [
    "experiment",
    "verdict",
    "detail",
    "orig_exit",
    "orig_fault_addr",
    "patched_exit",
    "patched_fault_addr",
    "cached_exit",
    "cached_fault_addr",
]


def write_delimited(output_path: str, results: List[QasanSubjectResult],
                    delimiter: str, include_subject_id: bool = True):
    columns = list(CSV_COLUMNS)
    if not include_subject_id:
        columns.remove("experiment")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, delimiter=delimiter)
        writer.writeheader()
        for r in results:
            row = {
                "verdict": r.status,
                "detail": r.detail,
                "orig_exit": r.orig_exit,
                "orig_fault_addr": r.orig_fault_addr,
                "patched_exit": r.patched_exit,
                "patched_fault_addr": r.patched_fault_addr,
                "cached_exit": r.cached_exit,
                "cached_fault_addr": r.cached_fault_addr,
            }
            if include_subject_id:
                row["experiment"] = r.exp_dir
            writer.writerow(row)


VALGRIND_CSV_COLUMNS = [
    "experiment",
    "verdict",
    "detail",
    "valgrind_fault_addr",
    "qasan_fault_addr",
]


def write_valgrind_delimited(output_path: str,
                             results: List[ValgrindSubjectResult],
                             delimiter: str, include_subject_id: bool = True):
    columns = list(VALGRIND_CSV_COLUMNS)
    if not include_subject_id:
        columns.remove("experiment")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, delimiter=delimiter)
        writer.writeheader()
        for r in results:
            row = {
                "verdict": r.status,
                "detail": r.detail,
                "valgrind_fault_addr": r.valgrind_fault_addr,
                "qasan_fault_addr": r.qasan_fault_addr,
            }
            if include_subject_id:
                row["experiment"] = r.exp_dir
            writer.writerow(row)


TRACER_CSV_COLUMNS = [
    "experiment",
    "verdict",
    "detail",
    "afl_fault_addr",
    "tracer_fault_addr",
]


def write_tracer_delimited(output_path: str,
                           results: List[TracerSubjectResult],
                           delimiter: str, include_subject_id: bool = True):
    columns = list(TRACER_CSV_COLUMNS)
    if not include_subject_id:
        columns.remove("experiment")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, delimiter=delimiter)
        writer.writeheader()
        for r in results:
            row = {
                "verdict": r.status,
                "detail": r.detail,
                "afl_fault_addr": r.afl_fault_addr,
                "tracer_fault_addr": r.tracer_fault_addr,
            }
            if include_subject_id:
                row["experiment"] = r.exp_dir
            writer.writerow(row)


MEMCHECK_REACH_CSV_COLUMNS = [
    "experiment",
    "verdict",
    "detail",
    "entrypoint",
    "entrypoint_hit",
    "crash_reason",
    "fault_addr",
]


def write_memcheck_reach_delimited(output_path: str,
                                   results: List[MemcheckReachResult],
                                   delimiter: str,
                                   include_subject_id: bool = True):
    columns = list(MEMCHECK_REACH_CSV_COLUMNS)
    if not include_subject_id:
        columns.remove("experiment")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, delimiter=delimiter)
        writer.writeheader()
        for r in results:
            row = {
                "verdict": r.status,
                "detail": r.detail,
                "entrypoint": r.entrypoint,
                "entrypoint_hit": r.entrypoint_hit,
                "crash_reason": r.crash_reason,
                "fault_addr": r.fault_addr,
            }
            if include_subject_id:
                row["experiment"] = r.exp_dir
            writer.writerow(row)


def write_log(output_path: str, args, results: List[QasanSubjectResult],
              counts: Dict[Status, int], total: int):
    lines = [
        "QASAN Test Results",
        f"Generated: {datetime.now().isoformat()}",
        f"Experiment list: {args.exp}",
        f"Workdir: {args.workdir}",
        f"Timeout: {args.timeout}s",
        f"Total experiments: {total}",
        "=" * 60,
        "",
    ]
    for r in results:
        lines.append(format_log_result(r, verbose=args.verbose))
        lines.append("")
    lines.append("=" * 60)
    lines.append(
        f"SUMMARY: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
        f"{counts[Status.BASELINE]} BASELINE-FAIL, {counts[Status.SKIP]} SKIP "
        f"(total {total})")
    with open(output_path, "w") as f:
        f.write("\n".join(lines))


def write_valgrind_log(output_path: str, args,
                       results: List[ValgrindSubjectResult],
                       counts: Dict[Status, int], total: int):
    lines = [
        "Valgrind vs QASAN Crash Location Test Results",
        f"Generated: {datetime.now().isoformat()}",
        f"Experiment list: {args.exp}",
        f"Workdir: {args.workdir}",
        f"Timeout: {args.timeout}s",
        f"Total experiments: {total}",
        "=" * 60,
        "",
    ]
    for r in results:
        lines.append(format_valgrind_log_result(r, verbose=args.verbose))
        lines.append("")
    lines.append("=" * 60)
    lines.append(
        f"SUMMARY: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
        f"{counts[Status.SKIP]} SKIP (total {total})")
    with open(output_path, "w") as f:
        f.write("\n".join(lines))


def write_tracer_log(output_path: str, args,
                     results: List[TracerSubjectResult],
                     counts: Dict[Status, int], total: int):
    lines = [
        "Tracer vs afl-qemu-trace Fault Address Test Results",
        f"Generated: {datetime.now().isoformat()}",
        f"Experiment list: {args.exp}",
        f"Workdir: {args.workdir}",
        f"Timeout: {args.timeout}s",
        f"Total experiments: {total}",
        "=" * 60,
        "",
    ]
    for r in results:
        lines.append(format_tracer_log_result(r, verbose=args.verbose))
        lines.append("")
    lines.append("=" * 60)
    lines.append(
        f"SUMMARY: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
        f"{counts[Status.BASELINE]} BASELINE-FAIL, {counts[Status.SKIP]} SKIP "
        f"(total {total})")
    with open(output_path, "w") as f:
        f.write("\n".join(lines))


def write_memcheck_reach_log(output_path: str, args,
                             results: List[MemcheckReachResult],
                             counts: Dict[Status, int], total: int):
    lines = [
        "Memcheck Patch-Function Reach Test Results",
        f"Generated: {datetime.now().isoformat()}",
        f"Experiment list: {args.exp}",
        f"Workdir: {args.workdir}",
        f"Timeout: {args.timeout}s",
        f"Total experiments: {total}",
        "=" * 60,
        "",
    ]
    for r in results:
        lines.append(format_memcheck_reach_log_result(r, verbose=args.verbose))
        lines.append("")
    lines.append("=" * 60)
    lines.append(
        f"SUMMARY: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
        f"{counts[Status.BASELINE]} BASELINE-FAIL, {counts[Status.SKIP]} SKIP "
        f"(total {total})")
    with open(output_path, "w") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_qasan(args):
    if args.verbose and args.format != "log":
        print("ERROR: --verbose only works with --format=log", file=sys.stderr)
        sys.exit(1)

    exp_file = args.exp
    if not os.path.isfile(exp_file):
        print(f"ERROR: exp list file not found: {exp_file}")
        sys.exit(1)

    with open(exp_file, "r") as f:
        exp_dirs = [line.strip() for line in f if line.strip()]

    exp_file_dir = os.path.dirname(os.path.abspath(exp_file))
    resolved = []
    display = []
    for d in exp_dirs:
        display.append(display_path(exp_file_dir, d))
        if not os.path.isabs(d):
            d = os.path.normpath(os.path.join(exp_file_dir, d))
        resolved.append(d)

    if args.jobs > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(
                lambda d: run_qasan_subject(d, args.workdir, args.timeout),
                resolved))
    else:
        results = [run_qasan_subject(d, args.workdir, args.timeout)
                   for d in resolved]

    if args.format in ("csv", "tsv"):
        for r, name in zip(results, display):
            r.exp_dir = name

    for r in results:
        print(f"[{r.status:>13}] {r.exp_dir}"
              + (f" ({r.detail})" if r.detail else ""))

    counts = {s: sum(1 for r in results if r.status == s)
              for s in (Status.PASS, Status.FAIL, Status.SKIP, Status.BASELINE)}

    if args.output:
        output_path = args.output
    else:
        logs_dir = os.path.join(LOFTIX_DIR, "logs")
        if not os.path.isdir(LOFTIX_DIR):
            logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        ext = args.format if args.format in ("csv", "tsv") else "log"
        output_path = os.path.join(
            logs_dir, f"qasan-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{ext}")

    if args.format in ("csv", "tsv"):
        delimiter = "\t" if args.format == "tsv" else ","
        write_delimited(output_path, results, delimiter,
                        include_subject_id=not args.no_subject_id)
    else:
        write_log(output_path, args, results, counts, len(resolved))

    print(f"Results written to: {output_path}")
    print(f"Summary: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
          f"{counts[Status.BASELINE]} BASELINE-FAIL, {counts[Status.SKIP]} SKIP "
          f"(total {len(resolved)})")


def cmd_valgrind(args):
    if args.verbose and args.format != "log":
        print("ERROR: --verbose only works with --format=log", file=sys.stderr)
        sys.exit(1)

    exp_file = args.exp
    if not os.path.isfile(exp_file):
        print(f"ERROR: exp list file not found: {exp_file}")
        sys.exit(1)

    with open(exp_file, "r") as f:
        exp_dirs = [line.strip() for line in f if line.strip()]

    exp_file_dir = os.path.dirname(os.path.abspath(exp_file))
    resolved = []
    display = []
    for d in exp_dirs:
        display.append(display_path(exp_file_dir, d))
        if not os.path.isabs(d):
            d = os.path.normpath(os.path.join(exp_file_dir, d))
        resolved.append(d)

    if args.jobs > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(
                lambda d: run_valgrind_subject(d, args.workdir, args.timeout),
                resolved))
    else:
        results = [run_valgrind_subject(d, args.workdir, args.timeout)
                   for d in resolved]

    if args.format in ("csv", "tsv"):
        for r, name in zip(results, display):
            r.exp_dir = name

    for r in results:
        print(f"[{r.status:>13}] {r.exp_dir}"
              + (f" ({r.detail})" if r.detail else ""))

    counts = {s: sum(1 for r in results if r.status == s)
              for s in (Status.PASS, Status.FAIL, Status.SKIP, Status.BASELINE)}

    if args.output:
        output_path = args.output
    else:
        logs_dir = os.path.join(LOFTIX_DIR, "logs")
        if not os.path.isdir(LOFTIX_DIR):
            logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        ext = args.format if args.format in ("csv", "tsv") else "log"
        output_path = os.path.join(
            logs_dir, f"valgrind-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{ext}")

    if args.format in ("csv", "tsv"):
        delimiter = "\t" if args.format == "tsv" else ","
        write_valgrind_delimited(output_path, results, delimiter,
                                 include_subject_id=not args.no_subject_id)
    else:
        write_valgrind_log(output_path, args, results, counts, len(resolved))

    print(f"Results written to: {output_path}")
    print(f"Summary: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
          f"{counts[Status.SKIP]} SKIP (total {len(resolved)})")



def cmd_tracer(args):
    if args.verbose and args.format != "log":
        print("ERROR: --verbose only works with --format=log", file=sys.stderr)
        sys.exit(1)

    exp_file = args.exp
    if not os.path.isfile(exp_file):
        print(f"ERROR: exp list file not found: {exp_file}")
        sys.exit(1)

    with open(exp_file, "r") as f:
        exp_dirs = [line.strip() for line in f if line.strip()]

    exp_file_dir = os.path.dirname(os.path.abspath(exp_file))
    resolved = []
    display = []
    for d in exp_dirs:
        display.append(display_path(exp_file_dir, d))
        if not os.path.isabs(d):
            d = os.path.normpath(os.path.join(exp_file_dir, d))
        resolved.append(d)

    if args.jobs > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(
                lambda d: run_tracer_subject(d, args.workdir, args.timeout),
                resolved))
    else:
        results = [run_tracer_subject(d, args.workdir, args.timeout)
                   for d in resolved]

    if args.format in ("csv", "tsv"):
        for r, name in zip(results, display):
            r.exp_dir = name

    for r in results:
        print(f"[{r.status:>13}] {r.exp_dir}"
              + (f" ({r.detail})" if r.detail else ""))

    counts = {s: sum(1 for r in results if r.status == s)
              for s in (Status.PASS, Status.FAIL, Status.SKIP, Status.BASELINE)}

    if args.output:
        output_path = args.output
    else:
        logs_dir = os.path.join(LOFTIX_DIR, "logs")
        if not os.path.isdir(LOFTIX_DIR):
            logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        ext = args.format if args.format in ("csv", "tsv") else "log"
        output_path = os.path.join(
            logs_dir, f"tracer-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{ext}")

    if args.format in ("csv", "tsv"):
        delimiter = "\t" if args.format == "tsv" else ","
        write_tracer_delimited(output_path, results, delimiter,
                               include_subject_id=not args.no_subject_id)
    else:
        write_tracer_log(output_path, args, results, counts, len(resolved))

    print(f"Results written to: {output_path}")
    print(f"Summary: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
          f"{counts[Status.BASELINE]} BASELINE-FAIL, {counts[Status.SKIP]} SKIP "
          f"(total {len(resolved)})")


def cmd_memcheck_reach(args):
    if args.verbose and args.format != "log":
        print("ERROR: --verbose only works with --format=log", file=sys.stderr)
        sys.exit(1)

    exp_file = args.exp
    if not os.path.isfile(exp_file):
        print(f"ERROR: exp list file not found: {exp_file}")
        sys.exit(1)

    with open(exp_file, "r") as f:
        exp_dirs = [line.strip() for line in f if line.strip()]

    exp_file_dir = os.path.dirname(os.path.abspath(exp_file))
    resolved = []
    display = []
    for d in exp_dirs:
        display.append(display_path(exp_file_dir, d))
        if not os.path.isabs(d):
            d = os.path.normpath(os.path.join(exp_file_dir, d))
        resolved.append(d)

    if args.jobs > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(
                lambda d: run_memcheck_reach_subject(d, args.workdir, args.timeout),
                resolved))
    else:
        results = [run_memcheck_reach_subject(d, args.workdir, args.timeout)
                   for d in resolved]

    if args.format in ("csv", "tsv"):
        for r, name in zip(results, display):
            r.exp_dir = name

    for r in results:
        print(f"[{r.status:>13}] {r.exp_dir}"
              + (f" ({r.detail})" if r.detail else ""))

    counts = {s: sum(1 for r in results if r.status == s)
              for s in (Status.PASS, Status.FAIL, Status.SKIP, Status.BASELINE)}

    if args.output:
        output_path = args.output
    else:
        logs_dir = os.path.join(LOFTIX_DIR, "logs")
        if not os.path.isdir(LOFTIX_DIR):
            logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        ext = args.format if args.format in ("csv", "tsv") else "log"
        output_path = os.path.join(
            logs_dir, f"memcheck-reach-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{ext}")

    if args.format in ("csv", "tsv"):
        delimiter = "\t" if args.format == "tsv" else ","
        write_memcheck_reach_delimited(output_path, results, delimiter,
                                       include_subject_id=not args.no_subject_id)
    else:
        write_memcheck_reach_log(output_path, args, results, counts, len(resolved))

    print(f"Results written to: {output_path}")
    print(f"Summary: {counts[Status.PASS]} PASS, {counts[Status.FAIL]} FAIL, "
          f"{counts[Status.BASELINE]} BASELINE-FAIL, {counts[Status.SKIP]} SKIP "
          f"(total {len(resolved)})")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Run tests on binradar benchmark subjects")
    sub = parser.add_subparsers(dest="command", required=True)

    qasan = sub.add_parser(
        "qasan", help="test qasan crash detection on .brpatched vs .orig")
    qasan.add_argument(
        "--exp", default="exp.list",
        help="path to experiment list file (one dir per line)")
    qasan.add_argument(
        "--workdir", default="workdir",
        help="work directory name (default: workdir)")
    qasan.add_argument(
        "--timeout", type=int, default=180,
        help="timeout per probe run in seconds (default: 180)")
    qasan.add_argument(
        "--format", choices=["log", "csv", "tsv"], default="log",
        help="output format: log (default), csv, or tsv")
    qasan.add_argument(
        "--output", default="",
        help="output file path (default: logs/qasan-<timestamp>.<ext>)")
    qasan.add_argument(
        "--jobs", type=int, default=1,
        help="number of subjects to test in parallel (default: 1)")
    qasan.add_argument(
        "--verbose", action="store_true",
        help="with --format=log, add a reproduction command line per probe "
             "(cd <workdir> && ENV=...; <command>); incompatible with csv/tsv")
    qasan.add_argument(
        "-n", "--no-subject-id", action="store_true",
        help="omit the experiment subject id column in csv/tsv output")
    qasan.set_defaults(func=cmd_qasan)

    valgrind = sub.add_parser(
        "valgrind", help="check qasan crash location against valgrind")
    valgrind.add_argument(
        "--exp", default="exp.list",
        help="path to experiment list file (one dir per line)")
    valgrind.add_argument(
        "--workdir", default="workdir",
        help="work directory name (default: workdir)")
    valgrind.add_argument(
        "--timeout", type=int, default=180,
        help="timeout per run in seconds (default: 180)")
    valgrind.add_argument(
        "--format", choices=["log", "csv", "tsv"], default="log",
        help="output format: log (default), csv, or tsv")
    valgrind.add_argument(
        "--output", default="",
        help="output file path (default: logs/valgrind-<timestamp>.<ext>)")
    valgrind.add_argument(
        "--jobs", type=int, default=1,
        help="number of subjects to test in parallel (default: 1)")
    valgrind.add_argument(
        "--verbose", action="store_true",
        help="with --format=log, add a reproduction command line per run "
             "(cd <workdir> && ENV=...; <command>); incompatible with csv/tsv")
    valgrind.add_argument(
        "-n", "--no-subject-id", action="store_true",
        help="omit the experiment subject id column in csv/tsv output")
    valgrind.set_defaults(func=cmd_valgrind)

    tracer = sub.add_parser(
        "tracer",
        help="compare fuzzolic tracer fault address against afl-qemu-trace")
    tracer.add_argument(
        "--exp", default="exp.list",
        help="path to experiment list file (one dir per line)")
    tracer.add_argument(
        "--workdir", default="workdir",
        help="work directory name (default: workdir)")
    tracer.add_argument(
        "--timeout", type=int, default=180,
        help="timeout per run in seconds (default: 180)")
    tracer.add_argument(
        "--format", choices=["log", "csv", "tsv"], default="log",
        help="output format: log (default), csv, or tsv")
    tracer.add_argument(
        "--output", default="",
        help="output file path (default: logs/tracer-<timestamp>.<ext>)")
    tracer.add_argument(
        "--jobs", type=int, default=1,
        help="number of subjects to test in parallel (default: 1)")
    tracer.add_argument(
        "--verbose", action="store_true",
        help="with --format=log, add a reproduction command line per run "
             "(cd <workdir> && ENV=...; <command>); incompatible with csv/tsv")
    tracer.add_argument(
        "-n", "--no-subject-id", action="store_true",
        help="omit the experiment subject id column in csv/tsv output")
    tracer.set_defaults(func=cmd_tracer)

    memcheck_reach = sub.add_parser(
        "memcheck-reach",
        help="check whether the target reaches the patch function under "
             "BINRADAR_MEMCHECK_ENABLE=1")
    memcheck_reach.add_argument(
        "--exp", default="exp.list",
        help="path to experiment list file (one dir per line)")
    memcheck_reach.add_argument(
        "--workdir", default="workdir",
        help="work directory name (default: workdir)")
    memcheck_reach.add_argument(
        "--timeout", type=int, default=180,
        help="timeout per run in seconds (default: 180)")
    memcheck_reach.add_argument(
        "--format", choices=["log", "csv", "tsv"], default="log",
        help="output format: log (default), csv, or tsv")
    memcheck_reach.add_argument(
        "--output", default="",
        help="output file path (default: logs/memcheck-reach-<timestamp>.<ext>)")
    memcheck_reach.add_argument(
        "--jobs", type=int, default=1,
        help="number of subjects to test in parallel (default: 1)")
    memcheck_reach.add_argument(
        "--verbose", action="store_true",
        help="with --format=log, add a reproduction command line per run "
             "(cd <workdir> && ENV=...; <command>); incompatible with csv/tsv")
    memcheck_reach.add_argument(
        "-n", "--no-subject-id", action="store_true",
        help="omit the experiment subject id column in csv/tsv output")
    memcheck_reach.set_defaults(func=cmd_memcheck_reach)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
