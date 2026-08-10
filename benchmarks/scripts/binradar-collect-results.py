#!/usr/bin/env python3
"""
Collect binradar results from multiple experiments into a single log or CSV file.

Usage:
    cd benchmarks/loftix
    python ../scripts/binradar-collect-results.py binradar --exp exp.list --workdir workdir --run-prefix run
    python ../scripts/binradar-collect-results.py binradar --exp exp.list --format csv
    python ../scripts/binradar-collect-results.py sdfuzz --exp exp.list --workdir workdir

Subcommands:
    binradar (default)
        Collect results from <workdir>/out (progress.sbsv + verifier.sbsv).
        For each experiment listed in exp.list, it:
          1. Checks if the workdir exists and has output
          2. Parses progress.sbsv to determine if the run completed successfully
          3. Looks for errors in binradar.log (and binradar-tracer-msg.log) for each run
          4. Shows the [final] result (remaining_patches)

    sdfuzz
        Collect external-fuzzer evaluation results from <workdir>/<fuzzer>
        (output of fuzzolic/binradar-evaluation.py). For each experiment:
          1. Checks <workdir>/<fuzzer> exists
          2. Parses final.sbsv for remaining_patches and per-patch verdicts
          3. Parses evaluation.log for minimized/verifier testcase counts and errors

Output is saved to logs/binradar-<datetime>.log / logs/sdfuzz-<datetime>.log
(or .csv/.tsv with --format csv / tsv)
"""

import argparse
import csv
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SCRIPT_DIR = Path(__file__).parent.resolve()
LOFTIX_DIR = SCRIPT_DIR.parent / "loftix"


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

# Phases that appear in progress.sbsv
KNOWN_PHASES = {"probe", "binradar", "directed", "fuzzer", "fuzzolic",
                "minimizer", "verifier", "final"}


@dataclass
class RunResult:
    """Structured result for a single run within an experiment."""
    run_name: str
    status: str  # "OK", "OK (rundir done, no final)", "INCOMPLETE: ...", etc.
    has_final: bool = False
    remaining_patches: str = ""  # e.g. "[1, 2, 3]" or "[]"
    binradar_remaining_patches: str = ""
    verifier_accepted: str = ""  # e.g. "1,3,5" or "" if none accepted
    verifier_rejected: str = ""  # e.g. "2,4,6"
    verifier_data: Dict[int, List[str]] = field(default_factory=dict)  # raw verifier results
    log_errors: List[str] = field(default_factory=list)
    tracer_errors: List[str] = field(default_factory=list)


@dataclass
class ExperimentResult:
    """Structured result for a single experiment."""
    exp_dir: str
    overall_status: str  # "ok", "issues", "no_data"
    runs: List[RunResult] = field(default_factory=list)
    error_message: str = ""  # for workdir-not-found, empty-progress, etc.


@dataclass
class SdfuzzResult:
    """Structured result of an external-fuzzer evaluation for one experiment."""
    exp_dir: str
    status: str  # "ok", "issues", "no_data"
    error_message: str = ""  # for eval-dir-not-found, empty-final, etc.
    has_final: bool = False
    remaining_patches: str = ""  # e.g. "[1, 2, 3]" or "[]"
    binradar_remaining_patches: str = ""
    verified_patches: str = ""  # e.g. "1,3,5" or "" if none
    rejected_patches: str = ""  # e.g. "2,4,6"
    minimizer_unique: int = -1  # unique testcases loaded by the minimizer
    minimized: int = -1  # testcases that hit the patch
    verifier_testcases: int = -1  # testcases used by the verifier
    log_errors: List[str] = field(default_factory=list)


def parse_sbsv_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parse a single sbsv line like:
      [phase] [action] [prefix run] [id 0] [remaining_patches [1,2]] ...

    Returns a dict of key->value, plus '_phase' and '_action' keys.
    Returns None if the line cannot be parsed.
    """
    line = line.strip()
    if not line:
        return None

    # Find all top-level [...] tokens (handles one level of nesting)
    tokens = re.findall(r'\[(?:[^\[\]]|\[[^\]]*\])*\]', line)
    if not tokens:
        return None

    entry: Dict[str, str] = {}

    # First token is always the phase
    entry["_phase"] = strip_brackets(tokens[0])
    if len(tokens) >= 2:
        entry["_action"] = strip_brackets(tokens[1])

    # Process remaining tokens as key-value pairs
    i = 2
    while i < len(tokens):
        inner = strip_brackets(tokens[i])
        parts = inner.split(None, 1)  # split on first whitespace
        if len(parts) == 2:
            entry[parts[0]] = parts[1]
        elif len(parts) == 1:
            # Some tokens are standalone (like [crash])
            pass
        i += 1

    return entry


def strip_brackets(token: str) -> str:
    """Remove the outer [ ] from a token like '[key value]'."""
    token = token.strip()
    if token.startswith('[') and token.endswith(']'):
        return token[1:-1]
    return token


def parse_progress_sbsv(sbsv_path: str) -> List[Dict[str, str]]:
    """Parse a progress.sbsv file. Returns a list of parsed line dicts."""
    results: List[Dict[str, str]] = []
    if not os.path.isfile(sbsv_path):
        return results

    with open(sbsv_path, "r") as f:
        for line in f:
            entry = parse_sbsv_line(line)
            if entry:
                results.append(entry)
    return results


def find_errors_in_log(log_path: str) -> List[str]:
    """Extract error lines from a binradar.log file."""
    errors: List[str] = []
    if not os.path.isfile(log_path):
        return errors
    with open(log_path, "r") as f:
        for line in f:
            if re.search(r'Error|Traceback|Exception', line, re.IGNORECASE):
                errors.append(line.strip())
    return errors


def find_errors_in_tracer_msg(log_path: str) -> List[str]:
    """Extract crash/error/warning lines from binradar-tracer-msg.log."""
    errors: List[str] = []
    if not os.path.isfile(log_path):
        return errors
    with open(log_path, "r") as f:
        for line in f:
            if re.search(r'(?:error|fail|timeout|signal|crash|abort)',
                         line, re.IGNORECASE):
                # Skip env-var check lines that are informational
                if "check-env-var" in line:
                    continue
                errors.append(line.strip())
    return errors


def parse_verifier_sbsv(sbsv_path: str) -> Dict[int, List[str]]:
    """
    Parse a verifier.sbsv file.
    Returns dict mapping patch_id -> list of result strings.
    """
    results: Dict[int, List[str]] = {}
    if not os.path.isfile(sbsv_path):
        return results

    with open(sbsv_path, "r") as f:
        for line in f:
            m = re.search(
                r'\[verifier-result\]\s+\[res\s+(\w+)\]\s+\[patch\s+(\d+)\]',
                line)
            if m:
                res = m.group(1)
                patch_id = int(m.group(2))
                results.setdefault(patch_id, []).append(res)
    return results


def verifier_summary(verifier_results: Dict[int, List[str]]) -> Tuple[str, str]:
    """Return (verified_patches_csv, rejected_patches_csv) from verifier data."""
    verified: List[str] = []
    rejected: List[str] = []
    for pid in sorted(verifier_results.keys()):
        res_list = verifier_results[pid]
        if "verified" in res_list:
            verified.append(str(pid))
        if "rejected" in res_list:
            rejected.append(str(pid))
    return (",".join(verified), ",".join(rejected))


def safe_int(s: str) -> int:
    """Safely convert a string to int, returns 0 on failure."""
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _fix_bracket_value(value: str) -> str:
    """Fix bracket values that may have had trailing ] stripped by tokenizer."""
    if not value:
        return "[]"
    if value.startswith('[') and not value.endswith(']'):
        if value == '[':
            return '[]'
        return value + ']'
    return value


def collect_experiment_result(exp_dir: str, workdir_name: str,
                               run_prefix: str) -> ExperimentResult:
    """
    Collect results for a single experiment.

    Returns an ExperimentResult with structured data.
    """
    workdir = os.path.join(exp_dir, workdir_name)
    out_dir = os.path.join(workdir, "out")
    progress_path = os.path.join(out_dir, "progress.sbsv")

    result = ExperimentResult(exp_dir=exp_dir, overall_status="no_data")

    if not os.path.isdir(workdir):
        result.error_message = "workdir not found"
        return result

    if not os.path.isfile(progress_path):
        result.error_message = "progress.sbsv not found (no run data)"
        return result

    progress = parse_progress_sbsv(progress_path)

    if not progress:
        result.error_message = "progress.sbsv is empty"
        return result

    # Group entries by (prefix, id) — only those matching run_prefix
    runs: Dict[Tuple[str, str], List[Dict[str, str]]] = {}
    for entry in progress:
        prefix = entry.get("prefix", "")
        run_id = entry.get("id", "")
        if prefix and run_id:
            if not prefix.startswith(run_prefix):
                continue
            key = (prefix, run_id)
            runs.setdefault(key, []).append(entry)

    if not runs:
        result.error_message = f"No runs found with prefix '{run_prefix}'"
        return result

    overall_ok = True
    has_any_final = False

    for (prefix, run_id), entries in runs.items():
        started: set = set()
        done_phases: set = set()
        final_entry: Optional[Dict[str, str]] = None

        for entry in entries:
            phase = entry.get("_phase", "")
            action = entry.get("_action", "")

            if action == "start" and phase in KNOWN_PHASES:
                started.add(phase)
            elif action == "done" and phase in KNOWN_PHASES:
                done_phases.add(phase)
                if phase == "final":
                    final_entry = entry

        incomplete_phases = started - done_phases

        # Build run dir name
        run_id_int = safe_int(run_id)
        run_dir_name = f"{prefix}-{run_id_int:05d}"
        run_dir = os.path.join(out_dir, run_dir_name)

        # Check logs for errors
        binradar_log = os.path.join(run_dir, "binradar.log")
        log_errors = find_errors_in_log(binradar_log)

        tracer_msg_log = os.path.join(run_dir, "binradar-tracer-msg.log")
        tracer_errors: List[str] = []
        if incomplete_phases or log_errors:
            tracer_errors = find_errors_in_tracer_msg(tracer_msg_log)

        # Determine status
        if final_entry is not None:
            status = "OK"
            has_any_final = True
        elif not incomplete_phases:
            status = "OK (rundir done, no final)"
        elif incomplete_phases:
            status = (f"INCOMPLETE: phases not done: "
                      f"{', '.join(sorted(incomplete_phases))}")
            overall_ok = False
        else:
            status = "UNKNOWN"
            overall_ok = False

        # Build run result
        run_res = RunResult(
            run_name=run_dir_name,
            status=status,
            has_final=(final_entry is not None),
            log_errors=log_errors,
            tracer_errors=tracer_errors,
        )

        if final_entry:
            remaining = final_entry.get("remaining_patches", "N/A")
            br_remaining = final_entry.get("binradar_remaining_patches", "N/A")
            run_res.remaining_patches = _fix_bracket_value(remaining)
            run_res.binradar_remaining_patches = _fix_bracket_value(br_remaining)

            verifier_path = os.path.join(run_dir, "verifier.sbsv")
            verifier_results = parse_verifier_sbsv(verifier_path)
            if verifier_results:
                accepted, rejected = verifier_summary(verifier_results)
                run_res.verifier_accepted = accepted
                run_res.verifier_rejected = rejected
                run_res.verifier_data = verifier_results

        result.runs.append(run_res)

    if not overall_ok:
        result.overall_status = "issues"
    elif has_any_final:
        result.overall_status = "ok"
    else:
        result.overall_status = "issues"

    return result


def extract_count(log_path: str, pattern: str) -> int:
    """Return the last match of a numeric pattern in a log file, or -1."""
    if not os.path.isfile(log_path):
        return -1
    last = -1
    with open(log_path, "r") as f:
        for line in f:
            m = re.search(pattern, line)
            if m:
                last = int(m.group(1))
    return last


def collect_sdfuzz_experiment(exp_dir: str, workdir_name: str,
                              fuzzer_name: str) -> SdfuzzResult:
    """
    Collect results of an external-fuzzer evaluation for a single experiment.

    Reads <workdir>/<fuzzer>/, the output layout of
    fuzzolic/binradar-evaluation.py:
      final.sbsv        final remaining patches + per-patch verdicts
      verified.sbsv     concrete verifier result
      evaluation.log    evaluation log (minimizer/verifier counts, errors)
    """
    workdir = os.path.join(exp_dir, workdir_name)
    eval_dir = os.path.join(workdir, fuzzer_name)
    result = SdfuzzResult(exp_dir=exp_dir, status="no_data")

    if not os.path.isdir(eval_dir):
        result.error_message = f"{fuzzer_name} dir not found"
        return result

    final_path = os.path.join(eval_dir, "final.sbsv")
    if not os.path.isfile(final_path):
        result.error_message = "final.sbsv not found (no run data)"
        return result

    entries = parse_progress_sbsv(final_path)
    if not entries:
        result.error_message = "final.sbsv is empty"
        return result

    done_entry: Optional[Dict[str, str]] = None
    verified: List[int] = []
    rejected: List[int] = []
    for entry in entries:
        phase = entry.get("_phase", "")
        action = entry.get("_action", "")
        if phase == "final" and action == "done":
            done_entry = entry
        elif phase == "final" and action == "verifier":
            pid = entry.get("patch", "")
            res = entry.get("res", "")
            if pid.isdigit():
                if res == "verified":
                    verified.append(int(pid))
                elif res == "rejected":
                    rejected.append(int(pid))

    if done_entry is None:
        result.error_message = "final.sbsv has no [final] [done] entry (incomplete run)"
        return result

    result.has_final = True
    result.remaining_patches = _fix_bracket_value(
        done_entry.get("remaining_patches", "N/A"))
    result.binradar_remaining_patches = _fix_bracket_value(
        done_entry.get("binradar_remaining_patches", "N/A"))
    result.verified_patches = ",".join(str(p) for p in sorted(verified))
    result.rejected_patches = ",".join(str(p) for p in sorted(rejected))

    eval_log = os.path.join(eval_dir, "evaluation.log")
    result.log_errors = find_errors_in_log(eval_log)
    result.minimizer_unique = extract_count(
        eval_log, r"\[MINIMIZER\] Loaded (\d+) unique testcases")
    result.minimized = extract_count(
        eval_log, r"\[MINIMIZER\] Minimized (\d+) testcases")
    result.verifier_testcases = extract_count(
        eval_log, r"\[VERIFIER\] Loaded (\d+) testcases")

    result.status = "ok" if not result.log_errors else "issues"
    return result


# ---------------------------------------------------------------------------
# Log formatter (human-readable)
# ---------------------------------------------------------------------------

def format_result_log(result: ExperimentResult) -> str:
    """Format an ExperimentResult as a human-readable log block."""
    lines: List[str] = []
    lines.append(f"=== {result.exp_dir} ===")

    if result.error_message:
        lines.append(f"  [STATUS] ERROR: {result.error_message}")
        return "\n".join(lines)

    for run_res in result.runs:
        lines.append(f"  [{run_res.run_name}] {run_res.status}")

        if run_res.has_final:
            lines.append(
                f"    [final] remaining_patches: {run_res.remaining_patches}")
            lines.append(
                f"    [final] binradar_remaining_patches: "
                f"{run_res.binradar_remaining_patches}")

            if run_res.verifier_accepted or run_res.verifier_rejected:
                lines.append("    [verifier] summary:")
                for pid in sorted(run_res.verifier_data.keys()):
                    res_list = run_res.verifier_data[pid]
                    verified = res_list.count("verified")
                    rejected = res_list.count("rejected")
                    lines.append(
                        f"      patch {pid}: {verified} verified, "
                        f"{rejected} rejected")

        if run_res.log_errors:
            lines.append("    [errors from binradar.log]:")
            for err in run_res.log_errors[:10]:
                lines.append(f"      {err}")

        if run_res.tracer_errors:
            lines.append("    [errors from binradar-tracer-msg.log]:")
            for err in run_res.tracer_errors[:10]:
                lines.append(f"      {err}")

    # Overall
    if result.overall_status == "ok":
        lines.append("  [OVERALL] OK")
    elif result.overall_status == "issues":
        if result.runs and any(r.has_final for r in result.runs):
            lines.append("  [OVERALL] HAS ISSUES")
        else:
            lines.append("  [OVERALL] INCOMPLETE (no final result)")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV formatter
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "experiment",
    "run",
    "status",
    "has_final",
    "remaining_patches",
    "binradar_remaining_patches",
    "verifier_accepted_patches",
    "verifier_rejected_patches",
    "log_errors_count",
    "tracer_errors_count",
    "error_preview",
]


def format_results_csv(all_results: List[ExperimentResult],
                       include_subject_id: bool = True) -> List[Dict[str, str]]:
    """Convert a list of ExperimentResults into CSV rows (list of dicts)."""
    rows: List[Dict[str, str]] = []
    for result in all_results:
        if result.error_message:
            row = {
                "run": "",
                "status": f"ERROR: {result.error_message}",
                "has_final": "",
                "remaining_patches": "",
                "binradar_remaining_patches": "",
                "verifier_accepted_patches": "",
                "verifier_rejected_patches": "",
                "log_errors_count": "",
                "tracer_errors_count": "",
                "error_preview": result.error_message,
            }
            if include_subject_id:
                row["experiment"] = result.exp_dir
            rows.append(row)
            continue

        for run_res in result.runs:
            # Combine log+tracer errors for preview
            all_errors = run_res.log_errors + run_res.tracer_errors
            error_preview = "; ".join(
                _truncate(e, 120) for e in all_errors[:3])

            row = {
                "run": run_res.run_name,
                "status": run_res.status,
                "has_final": str(run_res.has_final),
                "remaining_patches": run_res.remaining_patches,
                "binradar_remaining_patches": run_res.binradar_remaining_patches,
                "verifier_accepted_patches": run_res.verifier_accepted,
                "verifier_rejected_patches": run_res.verifier_rejected,
                "log_errors_count": str(len(run_res.log_errors)),
                "tracer_errors_count": str(len(run_res.tracer_errors)),
                "error_preview": error_preview,
            }
            if include_subject_id:
                row["experiment"] = result.exp_dir
            rows.append(row)
    return rows


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string to max_len, adding '...' if truncated."""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


# ---------------------------------------------------------------------------
# Sdfuzz log/CSV formatters
# ---------------------------------------------------------------------------

def format_sdfuzz_result_log(result: SdfuzzResult) -> str:
    """Format a SdfuzzResult as a human-readable log block."""
    lines: List[str] = []
    lines.append(f"=== {result.exp_dir} ===")

    if result.error_message:
        lines.append(f"  [STATUS] ERROR: {result.error_message}")
        return "\n".join(lines)

    if result.has_final:
        lines.append(
            f"  [final] remaining_patches: {result.remaining_patches}")
        lines.append(
            f"  [final] binradar_remaining_patches: "
            f"{result.binradar_remaining_patches}")
        lines.append(
            f"  [verifier] verified: {result.verified_patches or 'none'}  "
            f"rejected: {result.rejected_patches or 'none'}")
        lines.append(
            f"  [minimizer] unique: {result.minimizer_unique}  "
            f"minimized: {result.minimized}  verifier testcases: "
            f"{result.verifier_testcases}")

    if result.log_errors:
        lines.append("    [errors from evaluation.log]:")
        for err in result.log_errors[:10]:
            lines.append(f"      {err}")

    lines.append(
        f"  [OVERALL] {'OK' if result.status == 'ok' else 'HAS ISSUES'}")
    lines.append("")
    return "\n".join(lines)


SDFUZZ_CSV_COLUMNS = [
    "experiment",
    "status",
    "remaining_patches",
    "binradar_remaining_patches",
    "verified_patches",
    "rejected_patches",
    "minimizer_unique",
    "minimized",
    "verifier_testcases",
    "log_errors_count",
    "error_preview",
]


def format_sdfuzz_results_csv(all_results: List[SdfuzzResult],
                              include_subject_id: bool = True) -> List[Dict[str, str]]:
    """Convert a list of SdfuzzResults into CSV rows (list of dicts)."""
    rows: List[Dict[str, str]] = []
    for result in all_results:
        error_preview = "; ".join(
            _truncate(e, 120) for e in result.log_errors[:3])
        row = {
            "status": result.error_message
            if result.error_message else result.status,
            "remaining_patches": result.remaining_patches,
            "binradar_remaining_patches": result.binradar_remaining_patches,
            "verified_patches": result.verified_patches,
            "rejected_patches": result.rejected_patches,
            "minimizer_unique": str(result.minimizer_unique),
            "minimized": str(result.minimized),
            "verifier_testcases": str(result.verifier_testcases),
            "log_errors_count": str(len(result.log_errors)),
            "error_preview": error_preview,
        }
        if include_subject_id:
            row["experiment"] = result.exp_dir
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_experiment_list(exp_file: str) -> Tuple[str, List[str], List[str]]:
    """Read exp.list, return (exp_file_dir, resolved_dirs, display_dirs)."""
    if not os.path.isfile(exp_file):
        print(f"ERROR: exp list file not found: {exp_file}")
        sys.exit(1)

    with open(exp_file, "r") as f:
        exp_dirs = [line.strip() for line in f if line.strip()]

    exp_file_dir = os.path.dirname(os.path.abspath(exp_file))
    resolved_dirs = []
    display_dirs = []
    for d in exp_dirs:
        display_dirs.append(display_path(exp_file_dir, d))
        if not os.path.isabs(d):
            d = os.path.normpath(os.path.join(exp_file_dir, d))
        resolved_dirs.append(d)
    return exp_file_dir, resolved_dirs, display_dirs


def write_output(output_path: str, output_format: str, header: List[str],
                 csv_rows: List[Dict[str, str]], log_lines: List[str],
                 counts: Dict[str, int]):
    """Write the collected results to output_path in the requested format."""
    if output_format in ("csv", "tsv"):
        delimiter = "\t" if output_format == "tsv" else ","
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=header, delimiter=delimiter)
            writer.writeheader()
            writer.writerows(csv_rows)
            summary_row = {col: "" for col in header}
            if "experiment" in header:
                summary_row["experiment"] = "SUMMARY"
                summary_row["status"] = " ".join(
                    f"{name}={value}" for name, value in counts.items())
            else:
                summary_row[header[0]] = "SUMMARY"
                summary_row[header[1] if len(header) > 1 else header[0]] = " ".join(
                    f"{name}={value}" for name, value in counts.items())
            writer.writerow(summary_row)
    else:
        with open(output_path, "w") as f:
            f.write("\n".join(log_lines))
    print(f"Results written to: {output_path}")
    print("Summary: " + ", ".join(
        f"{name} {value}" for name, value in counts.items()))


def cmd_binradar(args):
    exp_file = args.exp
    workdir_name = args.workdir
    run_prefix = args.run_prefix
    output_format = args.format

    _, resolved_dirs, display_dirs = load_experiment_list(exp_file)

    # Create logs directory
    logs_dir = SCRIPT_DIR.parent / "loftix" / "logs"
    os.makedirs(logs_dir, exist_ok=True)

    # Collect all results
    all_results: List[ExperimentResult] = []
    for exp_dir, display in zip(resolved_dirs, display_dirs):
        result = collect_experiment_result(exp_dir, workdir_name, run_prefix)
        if output_format in ("csv", "tsv"):
            result.exp_dir = display
        all_results.append(result)

    # Output file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ext = output_format if output_format in ("csv", "tsv") else "log"
    output_path = (args.output if args.output
                   else os.path.join(logs_dir, f"binradar-{timestamp}.{ext}"))

    # Count
    ok_count = sum(1 for r in all_results if r.overall_status == "ok")
    issues_count = sum(1 for r in all_results if r.overall_status == "issues")
    no_data_count = sum(1 for r in all_results if r.overall_status == "no_data")

    counts = {"OK": ok_count, "issues": issues_count,
              "no_data": no_data_count, "total": len(resolved_dirs)}

    if output_format in ("csv", "tsv"):
        columns = list(CSV_COLUMNS)
        if args.no_subject_id:
            columns.remove("experiment")
        csv_rows = format_results_csv(
            all_results, include_subject_id=not args.no_subject_id)
        write_output(output_path, output_format, columns, csv_rows, [],
                     counts)
    else:
        output_lines: List[str] = []
        output_lines.append("BinRadar Results Collection")
        output_lines.append(f"Generated: {datetime.now().isoformat()}")
        output_lines.append(f"Experiment list: {exp_file}")
        output_lines.append(f"Workdir: {workdir_name}")
        output_lines.append(f"Run prefix: {run_prefix}")
        output_lines.append(f"Total experiments: {len(resolved_dirs)}")
        output_lines.append("=" * 60)
        output_lines.append("")

        for result in all_results:
            output_lines.append(format_result_log(result))

        output_lines.append("=" * 60)
        output_lines.append(
            f"SUMMARY: {ok_count} OK, {issues_count} with issues, "
            f"{no_data_count} no data")
        output_lines.append(f"Total: {len(resolved_dirs)} experiments")
        write_output(output_path, output_format, [], [], output_lines,
                     counts)


def cmd_sdfuzz(args):
    exp_file = args.exp
    workdir_name = args.workdir
    fuzzer_name = args.fuzzer
    output_format = args.format

    _, resolved_dirs, display_dirs = load_experiment_list(exp_file)

    # Create logs directory
    logs_dir = SCRIPT_DIR.parent / "loftix" / "logs"
    os.makedirs(logs_dir, exist_ok=True)

    # Collect all results
    all_results: List[SdfuzzResult] = []
    for exp_dir, display in zip(resolved_dirs, display_dirs):
        result = collect_sdfuzz_experiment(exp_dir, workdir_name, fuzzer_name)
        if output_format in ("csv", "tsv"):
            result.exp_dir = display
        all_results.append(result)

    # Output file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ext = output_format if output_format in ("csv", "tsv") else "log"
    output_path = (args.output if args.output
                   else os.path.join(logs_dir, f"sdfuzz-{timestamp}.{ext}"))

    # Count
    ok_count = sum(1 for r in all_results if r.status == "ok")
    issues_count = sum(1 for r in all_results if r.status == "issues")
    no_data_count = sum(1 for r in all_results if r.status == "no_data")

    counts = {"OK": ok_count, "issues": issues_count,
              "no_data": no_data_count, "total": len(resolved_dirs)}

    if output_format in ("csv", "tsv"):
        columns = list(SDFUZZ_CSV_COLUMNS)
        if args.no_subject_id:
            columns.remove("experiment")
        csv_rows = format_sdfuzz_results_csv(
            all_results, include_subject_id=not args.no_subject_id)
        write_output(output_path, output_format, columns, csv_rows,
                     [], counts)
    else:
        output_lines: List[str] = []
        output_lines.append("Sdfuzz Evaluation Results Collection")
        output_lines.append(f"Generated: {datetime.now().isoformat()}")
        output_lines.append(f"Experiment list: {exp_file}")
        output_lines.append(f"Workdir: {workdir_name}")
        output_lines.append(f"Fuzzer dir: {fuzzer_name}")
        output_lines.append(f"Total experiments: {len(resolved_dirs)}")
        output_lines.append("=" * 60)
        output_lines.append("")

        for result in all_results:
            output_lines.append(format_sdfuzz_result_log(result))

        output_lines.append("=" * 60)
        output_lines.append(
            f"SUMMARY: {ok_count} OK, {issues_count} with issues, "
            f"{no_data_count} no data")
        output_lines.append(f"Total: {len(resolved_dirs)} experiments")
        write_output(output_path, output_format, [], [], output_lines,
                     counts)


def main():
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--exp", default="exp.list",
                        help="Path to experiment list file (one dir per line)")
    shared.add_argument("--workdir", default="workdir",
                        help="Work directory name (default: workdir)")
    shared.add_argument("--format", choices=["log", "csv", "tsv"], default="log",
                        help="Output format: log (default), csv, or tsv")
    shared.add_argument("--output", default="",
                        help="Output file path (default: logs/<cmd>-<timestamp>.<ext>)")
    shared.add_argument("--run-prefix", default="run",
                        help="Run directory prefix (binradar only, default: run)")
    shared.add_argument("--fuzzer", default="sdfuzz",
                        help="Fuzzer output directory name under workdir "
                             "(sdfuzz only, default: sdfuzz)")
    shared.add_argument(
        "-n", "--no-subject-id", action="store_true",
        help="omit the experiment subject id column in csv/tsv output")

    parser = argparse.ArgumentParser(
        description="Collect binradar results from experiments",
        parents=[shared])
    sub = parser.add_subparsers(dest="command")

    sub.add_parser(
        "binradar", parents=[shared],
        help="collect binradar run results from workdir/out (default)")

    sub.add_parser(
        "sdfuzz", parents=[shared],
        help="collect external fuzzer evaluation results from workdir/<fuzzer>")

    args = parser.parse_args()

    # Default to binradar when no subcommand is given (backward compatible)
    if args.command is None or args.command == "binradar":
        cmd_binradar(args)
    else:
        cmd_sdfuzz(args)


if __name__ == "__main__":
    main()
