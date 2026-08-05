#!/usr/bin/env python3
import argparse
import os
import shutil
import sys
import time
from typing import Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import binradar_minimizer
import binradar_utils
import binradar_verifier
import logger

"""
Evaluate binradar patches using test cases produced by an external fuzzer.

This script is designed for a single subject; run it in parallel across
subjects (e.g. with a Justfile). It reuses the existing minimizer and
concrete-verifier pipeline from binradar:

    probe (original binary + POC, reused from workdir/out when present)
    -> minimizer on <fuzz-out>/queue and <fuzz-out>/crashes
    -> concrete verifier on the patched binary for every patch candidate
    -> final remaining-patches analysis

Output layout (relative to --workdir):
    <workdir>/<fuzzer>/probe-results.sbsv  probe result (reused if rerun)
    <workdir>/<fuzzer>/minimizer/          minimizer run dir (minimized/, minimizer.sbsv)
    <workdir>/<fuzzer>/verified.sbsv       verifier result
    <workdir>/<fuzzer>/final.sbsv          final remaining patches
    <workdir>/<fuzzer>/evaluation.log      debug log

Usage:
    uv run fuzzolic/binradar-evaluation.py \
        --fuzzer sdfuzz \
        --fuzz-out /path/to/work-sdfuzz/out \
        --workdir /path/to/loftix/workdir
"""


def find_latest_probe_results(out_dir: str) -> Optional[str]:
    """Find the most recent probe-results.sbsv under <out_dir>/run-*/."""
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


def run_probe(workdir: str, env: Dict[str, str], save_file: str) -> binradar_verifier.BinRadarProbeResult:
    """Run the probe phase on the original binary (mirrors binradar.run_probe)."""
    runner = binradar_verifier.BinRadarQemuRunner.from_env(workdir, env)
    poc_input = env["POC_INPUT"]
    testcase = poc_input if os.path.isabs(poc_input) else os.path.join(workdir, poc_input)
    if not os.path.isfile(testcase):
        sys.exit(f"ERROR: poc input not found: {testcase}")

    logger.info(f"[PROBE] Running probe with poc: {testcase}")
    probe_result = runner.test_with_original(testcase)
    if probe_result is None:
        sys.exit("ERROR: failed to get probe result. Check patch location or qemu_stacktrace availability.")
    if not probe_result.patch_hit():
        sys.exit("ERROR: no patch hit found. The patch location might be incorrect.")
    if not probe_result.is_crash():
        sys.exit("ERROR: no crash found. The patch might not be effective.")
    if not probe_result.patch_func_hit():
        sys.exit("ERROR: no hit found in the patch function. Failed to extract patch function info.")
    if probe_result.multi_patch_func():
        sys.exit("ERROR: multiple patch function hits found. Current implementation does not support this case.")

    file_trace_result = runner.test_with_file_trace(
        testcase, patch_func_entry=probe_result.patch_func_entry, verbose=False)
    if file_trace_result is None:
        sys.exit("ERROR: failed to get file trace result.")

    with open(save_file, "w", encoding="utf-8") as f:
        f.write(f"[probe-info] {probe_result.serialize()}\n")
        f.write(f"[file-trace] {file_trace_result.serialize_file_trace_result()}\n")
    logger.info(f"[PROBE] Saved probe result: {save_file}")
    return probe_result


def write_final(final_file: str, verified_file: str, total_patches: int,
                fuzzer: str) -> List[int]:
    """Parse the verifier output and write the final remaining-patches analysis.

    Mirrors binradar.run_final for the concrete-verifier part: a patch stays in
    the remaining set unless the verifier explicitly rejected it.
    """
    verifier_result = binradar_verifier.BinRadarConcreteVerifierResult.from_sbsv(verified_file)
    if verifier_result is None:
        sys.exit(f"ERROR: failed to parse verifier result: {verified_file}")
    remaining = set(range(1, total_patches + 1))
    for patch_id, verified in verifier_result.patch_verified.items():
        if not verified:
            remaining.discard(patch_id)
    with open(final_file, "w", encoding="utf-8") as f:
        f.write(f"[final] [start] [fuzzer {fuzzer}] [verified {os.path.basename(verified_file)}]\n")
        for patch_id in sorted(verifier_result.patch_verified):
            res = "verified" if verifier_result.patch_verified[patch_id] else "rejected"
            f.write(f"[final] [verifier] [patch {patch_id}] [res {res}]\n")
        f.write(f"[final] [done] [fuzzer {fuzzer}] [remaining_patches {sorted(remaining)}] [binradar_remaining_patches {sorted(remaining)}]\n")
    return sorted(remaining)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate binradar patches with external fuzzer test cases")
    parser.add_argument(
        "-w", "--workdir", required=True,
        help="binradar work directory (with binradar.env, <binary>.orig, <binary>.brpatched)")
    parser.add_argument(
        "--fuzzer", required=True,
        help="fuzzer name; output goes to <workdir>/<fuzzer>/")
    parser.add_argument(
        "--fuzz-out", required=True,
        help="external fuzzer output directory (contains queue/ and crashes/)")
    parser.add_argument(
        "--queue-dir", default="queue",
        help="queue directory name under --fuzz-out (default: queue)")
    parser.add_argument(
        "--crashes-dir", default="crashes",
        help="crashes directory name under --fuzz-out (default: crashes)")
    parser.add_argument(
        "--probe-results", default="",
        help="use an existing probe-results.sbsv file (default: reuse from "
             "workdir/out if present, otherwise run the probe)")
    args = parser.parse_args()

    workdir = os.path.abspath(args.workdir)
    env_path = os.path.join(workdir, "binradar.env")
    if not os.path.isfile(env_path):
        sys.exit(f"ERROR: binradar.env not found: {env_path}")
    env = binradar_utils.load_env(env_path)

    for key in ("BINARY", "TEST_CMD", "PATCH_LOC", "TOTAL_PATCHES",
                "PATCH_RESERVE_RANGE", "E9_TRAMPOLINE_RANGE", "E9_LOADER_RANGE"):
        if key not in env:
            sys.exit(f"ERROR: {key} not found in binradar.env")

    binary = env["BINARY"]
    for name, path in [("orig binary", os.path.join(workdir, f"{binary}.orig")),
                       ("patched binary", os.path.join(workdir, f"{binary}.brpatched"))]:
        if not os.path.isfile(path):
            sys.exit(f"ERROR: {name} not found: {path}")

    queue_dir = os.path.join(args.fuzz_out, args.queue_dir)
    crashes_dir = os.path.join(args.fuzz_out, args.crashes_dir)
    for name, path in [("queue dir", queue_dir), ("crashes dir", crashes_dir)]:
        if not os.path.isdir(path):
            sys.exit(f"ERROR: {name} not found: {path}")

    eval_dir = os.path.join(workdir, args.fuzzer)
    minimizer_dir = os.path.join(eval_dir, "minimizer")
    os.makedirs(eval_dir, exist_ok=True)
    logger.set_file(os.path.join(eval_dir, "evaluation.log"))

    start_time = time.time()

    # 1. Probe (reuse existing result when possible)
    probe_file = args.probe_results
    if not probe_file:
        probe_file = find_latest_probe_results(os.path.join(workdir, "out"))
    if not probe_file:
        probe_file = os.path.join(eval_dir, "probe-results.sbsv")
    if os.path.isfile(probe_file):
        probe_result = binradar_verifier.BinRadarProbeResult.from_sbsv(probe_file)
        if probe_result is None:
            sys.exit(f"ERROR: failed to parse probe result: {probe_file}")
        logger.info(f"[PROBE] Loaded existing probe result: {probe_file}")
    else:
        probe_result = run_probe(workdir, env, probe_file)
    logger.info(f"[PROBE] {probe_result.serialize()}")

    # 2. Minimizer on the external fuzzer test cases
    testcase_dirs = [queue_dir, crashes_dir]
    logger.info(f"[MINIMIZER] Testcase dirs: {', '.join(testcase_dirs)}")
    minimizer = binradar_minimizer.BinRadarMinimizer(
        workdir, minimizer_dir, probe_result, testcase_dirs, env)
    minimizer.load_testcases()
    logger.info(f"[MINIMIZER] Loaded {len(minimizer.testcases)} unique testcases")
    minimizer.run_testcases()
    logger.info(f"[MINIMIZER] Minimized {len(os.listdir(minimizer.minimized_dir))} testcases")

    # 3. Concrete verifier on the patched binary
    minimizer_result_file = os.path.join(minimizer_dir, "minimizer.sbsv")
    total_patches = int(env["TOTAL_PATCHES"])
    runner = binradar_verifier.BinRadarQemuRunner.from_env(workdir, env)
    verifier = binradar_verifier.BinRadarConcreteVerifier(
        workdir, minimizer_dir, runner, probe_result,
        os.path.join(workdir, f"{binary}.brpatched"),
        list(range(1, total_patches + 1)))
    verifier.load_testcases(minimizer_result_file)
    logger.info(f"[VERIFIER] Loaded {len(verifier.testcases)} testcases")
    if len(verifier.testcases) == 0:
        logger.warning(
            "[VERIFIER] No testcases survived minimization/fault-addr filtering; "
            "all patches will be reported as remaining (nothing to reject them).")
    verifier.run_verification_concrete_testcases()

    verified_file = os.path.join(eval_dir, "verified.sbsv")
    shutil.copyfile(os.path.join(minimizer_dir, "verifier.sbsv"), verified_file)
    logger.info(f"[VERIFIER] Saved verified result: {verified_file}")

    # 4. Final analysis
    final_file = os.path.join(eval_dir, "final.sbsv")
    remaining = write_final(final_file, verified_file, total_patches, args.fuzzer)
    logger.info(f"[FINAL] Saved final result: {final_file}")

    elapsed = int((time.time() - start_time) * 1000)
    print(f"[final] [done] [fuzzer {args.fuzzer}] [workdir {workdir}] "
          f"[queue {len(os.listdir(queue_dir))}] [crashes {len(os.listdir(crashes_dir))}] "
          f"[verifier_testcases {len(verifier.testcases)}] "
          f"[remaining_patches {remaining}] [time {elapsed}]")


if __name__ == "__main__":
    main()
