#!/usr/bin/env python3
import argparse
import csv
import enum
import os
import re
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import binradar_utils
from binradar_verifier import BinRadarProbeResult, BinRadarQemuRunner

LOFTIX_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "benchmarks", "loftix"))

"""
Run tests on binradar benchmark subjects listed in exp.list.

Usage:
    cd benchmarks/loftix
    uv run ../../fuzzolic/binradar-test.py qasan [options]

Subcommands:
    qasan
        Run the probe-style QASAN execution (afl-qemu-trace --asan host)
        against both <binary>.orig and <binary>.brpatched (PATCH_ID=0,
        i.e. original behavior) for every subject in exp.list and check
        that QASAN detects the same crash (same fault address) on the
        patched binary as on the original one.

        Verdicts:
          PASS          - qasan detects the same crash (same fault address)
                          on both .orig and .brpatched.
          FAIL          - the patched binary does not crash, crashes at a
                          different fault address, or the probe on
                          .brpatched fails (timeout / no crash detected).
          BASELINE-FAIL - the probe on .orig does not reproduce the crash;
                          the subject cannot be tested.
          SKIP          - workdir / binary / poc input files missing.

Results are summarized in a single file (logs/qasan-<timestamp>.log by
default, or logs/qasan-<timestamp>.csv / .tsv with --format csv / tsv).
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
    orig_cmd: str = ""
    patched_cmd: str = ""


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


def run_qasan_probe(workdir: str, env: Dict[str, str], use_patched: bool,
                    testcase: str, timeout: float):
    """Run the probe-style qasan execution and parse the probe result."""
    runner = BinRadarQemuRunner.from_env(workdir, env)
    command = runner.get_qemu_stacktrace_command(use_patched, testcase)
    proc_env = runner.get_env_for_exec(patch_id="0")
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
        return result
    if patched_probe.fault_addr != orig_probe.fault_addr:
        result.status = Status.FAIL
        result.detail = "fault address differs"
        return result
    result.status = Status.PASS
    result.detail = "same crash detected on both binaries"
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
    if verbose:
        if result.orig_cmd:
            lines.append(f"  [cmd orig] {result.orig_cmd}")
        if result.patched_cmd:
            lines.append(f"  [cmd patched] {result.patched_cmd}")
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
]


def write_delimited(output_path: str, results: List[QasanSubjectResult],
                    delimiter: str):
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, delimiter=delimiter)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "experiment": r.exp_dir,
                "verdict": r.status,
                "detail": r.detail,
                "orig_exit": r.orig_exit,
                "orig_fault_addr": r.orig_fault_addr,
                "patched_exit": r.patched_exit,
                "patched_fault_addr": r.patched_fault_addr,
            })


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
        write_delimited(output_path, results, delimiter)
    else:
        write_log(output_path, args, results, counts, len(resolved))

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
    qasan.set_defaults(func=cmd_qasan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
