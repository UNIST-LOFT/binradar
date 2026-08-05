#!/usr/bin/env python3
"""
Collect binradar results from multiple experiments into a single log or CSV file.

Usage:
    cd benchmarks/loftix
    python ../scripts/binradar-collect-results.py --exp exp.list --workdir workdir --run-prefix run
    python ../scripts/binradar-collect-results.py --exp exp.list --format csv

For each experiment listed in exp.list, it:
  1. Checks if the workdir exists and has output
  2. Parses progress.sbsv to determine if the run completed successfully
  3. Looks for errors in binradar.log (and binradar-tracer-msg.log) for each run
  4. Shows the [final] result (remaining_patches)

Output is saved to logs/binradar-<datetime>.log (or .csv/.tsv)
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
    """Return (accepted_patches_csv, rejected_patches_csv) from verifier data."""
    accepted: List[str] = []
    rejected: List[str] = []
    for pid in sorted(verifier_results.keys()):
        res_list = verifier_results[pid]
        if "accepted" in res_list:
            accepted.append(str(pid))
        if "rejected" in res_list:
            rejected.append(str(pid))
    return (",".join(accepted), ",".join(rejected))


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
                    accepted = res_list.count("accepted")
                    rejected = res_list.count("rejected")
                    lines.append(
                        f"      patch {pid}: {accepted} accepted, "
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


def format_results_csv(all_results: List[ExperimentResult]) -> List[Dict[str, str]]:
    """Convert a list of ExperimentResults into CSV rows (list of dicts)."""
    rows: List[Dict[str, str]] = []
    for result in all_results:
        if result.error_message:
            rows.append({
                "experiment": result.exp_dir,
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
            })
            continue

        for run_res in result.runs:
            # Combine log+tracer errors for preview
            all_errors = run_res.log_errors + run_res.tracer_errors
            error_preview = "; ".join(
                _truncate(e, 120) for e in all_errors[:3])

            rows.append({
                "experiment": result.exp_dir,
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
            })
    return rows


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string to max_len, adding '...' if truncated."""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Collect binradar results from experiments")
    parser.add_argument("--exp", default="exp.list",
                        help="Path to experiment list file (one dir per line)")
    parser.add_argument("--workdir", default="workdir",
                        help="Work directory name (default: workdir)")
    parser.add_argument("--run-prefix", default="run",
                        help="Run directory prefix (default: run)")
    parser.add_argument("--format", choices=["log", "csv", "tsv"], default="log",
                        help="Output format: log (default), csv, or tsv")
    args = parser.parse_args()

    exp_file = args.exp
    workdir_name = args.workdir
    run_prefix = args.run_prefix
    output_format = args.format

    # Read experiment list
    if not os.path.isfile(exp_file):
        print(f"ERROR: exp list file not found: {exp_file}")
        sys.exit(1)

    with open(exp_file, "r") as f:
        exp_dirs = [line.strip() for line in f if line.strip()]

    # Resolve relative paths against the exp_file directory
    exp_file_dir = os.path.dirname(os.path.abspath(exp_file))
    resolved_dirs = []
    display_dirs = []
    for d in exp_dirs:
        display_dirs.append(display_path(exp_file_dir, d))
        if not os.path.isabs(d):
            d = os.path.normpath(os.path.join(exp_file_dir, d))
        resolved_dirs.append(d)

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
    output_path = os.path.join(logs_dir, f"binradar-{timestamp}.{ext}")

    # Count
    ok_count = sum(1 for r in all_results if r.overall_status == "ok")
    issues_count = sum(1 for r in all_results if r.overall_status == "issues")
    no_data_count = sum(1 for r in all_results if r.overall_status == "no_data")

    if output_format in ("csv", "tsv"):
        # Write CSV/TSV
        delimiter = "\t" if output_format == "tsv" else ","
        csv_rows = format_results_csv(all_results)
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, delimiter=delimiter)
            writer.writeheader()
            # Also write a summary row at the end
            writer.writerows(csv_rows)
            # Summary line as a comment-like row
            writer.writerow({
                "experiment": "SUMMARY",
                "run": "",
                "status": f"OK={ok_count} issues={issues_count} no_data={no_data_count} total={len(resolved_dirs)}",
                "has_final": "",
                "remaining_patches": "",
                "binradar_remaining_patches": "",
                "verifier_accepted_patches": "",
                "verifier_rejected_patches": "",
                "log_errors_count": "",
                "tracer_errors_count": "",
                "error_preview": "",
            })
    else:
        # Write log
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

        # Final summary
        output_lines.append("=" * 60)
        output_lines.append(
            f"SUMMARY: {ok_count} OK, {issues_count} with issues, "
            f"{no_data_count} no data")
        output_lines.append(f"Total: {len(resolved_dirs)} experiments")

        with open(output_path, "w") as f:
            f.write("\n".join(output_lines))

    # Print to stdout
    print(f"Results written to: {output_path}")
    print(f"Summary: {ok_count} OK, {issues_count} with issues, "
          f"{no_data_count} no data (total {len(resolved_dirs)})")


if __name__ == "__main__":
    main()
