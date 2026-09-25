#!/usr/bin/env python3
"""
Collect binradar results from multiple experiments into a single log or CSV file.

Usage:
    cd benchmarks/loftix
    python ../scripts/binradar-collect-results.py binradar --exp exp.list --workdir workdir --run-prefix run
    python ../scripts/binradar-collect-results.py binradar --exp exp.list --format csv
    python ../scripts/binradar-collect-results.py sdfuzz --exp exp.list --workdir workdir
    python ../scripts/binradar-collect-results.py taosc --exp exp.list --workdir workdir-013

Subcommands:
    binradar (default)
        Collect results from <workdir>/out (progress.sbsv, verifier.br,
        final.sbsv; legacy verifier.sbsv is accepted).
        For each experiment listed in exp.list, it:
          1. Checks if the workdir exists and has output
          2. Parses progress.sbsv to determine if the run completed successfully
          3. Looks for errors in binradar.log (and binradar-tracer-msg.log) for each run
          4. Shows the [filter] result (survived patches) and the [final]
             result (remaining_patches), plus per-patch verifier/binradar
             verdicts from final.sbsv. Per-patch output is limited to the
             top --top patches ranked by confidence (default 10); the
             remaining patches are summarized as counts, and the shown
             remaining patches are annotated with their confidence score
             (e.g. "142(0.731)"). Runs that never reached FINAL (no
             confidence rows) have no ranking to order by: their filter
             survivors are capped at the top --top patches in patch-id
             order instead of being printed in full.
          5. Shows exact, untruncated verifier candidate/remaining counts and
             BinRadar complete-iteration/rejected/remaining counts. Patch-id
             lists remain limited by --top.
          6. Shows the patch filter context from <workdir>/filter.sbsv
             (predicates evaluated/survived) when present

    sdfuzz
        Collect external-fuzzer evaluation results from <workdir>/<fuzzer>
        (output of fuzzolic/binradar-evaluation.py). For each experiment:
          1. Checks <workdir>/<fuzzer> exists
          2. Parses final.sbsv for remaining_patches and per-patch verdicts
          3. Parses evaluation.log for minimized/verifier testcase counts and errors
          4. Reports the patch filter context from <workdir>/filter.sbsv
             when present

    taosc
        Collect predicate counts from <workdir>/predicates and
        <workdir>/filter.sbsv.  The latter contains the predicates that
        survived BinRadar's filter.  The Taosc family is read from
        <workdir>/patch-format: Single CWE-* workdirs have no predicate list
        and are reported with zero counts and a skipped filter status.
        Workdirs with no predicates are reported with zero counts and a
        skipped filter status.

    binradar-stats
        Collect verifier representative-run and per-patch evidence-class
        statistics for the top --top patches ranked by confidence (from
        final.sbsv). Representative runs, represented patch runs, savings,
        testcase counts, and fallbacks come from <run>/verifier.log (or
        legacy verifier.sbsv): cached runs use [verifier-cache] [miss], while
        uncached single/direct families use [testcase] [try]. Aggregate
        observation counters come from
        <run>/verifier.br (or legacy [verifier] [...] rows): pc
        (patch-crashed), csda (crash-skip-diff-addr), cf (crash-fail), cp
        (crash-pass), ct (crash-timeout), ncsda
        (no-crash-skip-diff-addr), ncf (no-crash-fail), ncpsb
        (no-crash-pass-same-br), nccdb
        (no-crash-confidence-diff-br), and nct (no-crash-timeout).

Output is saved to logs/binradar-<datetime>.log / logs/sdfuzz-<datetime>.log /
logs/taosc-<datetime>.log / logs/binradar-stats-<datetime>.log
(or .csv/.tsv with --format csv / tsv)
"""

import argparse
import csv
import json
import os
import re
import sbsv
import sys
import enum
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from itertools import repeat
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).parent.resolve()
LOFTIX_DIR = SCRIPT_DIR.parent / "loftix"
sys.path.insert(0, str(SCRIPT_DIR.parent.parent / "fuzzolic"))

import binradar_evidence
import binradar_utils


def _result_artifact(run_dir: str, stem: str) -> str:
    compact = os.path.join(run_dir, f"{stem}.br")
    if os.path.isfile(compact):
        return compact
    return os.path.join(run_dir, f"{stem}.sbsv")


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
KNOWN_PHASES = {"probe", "filter", "binradar", "directed", "fuzzer", "fuzzolic",
                "minimizer", "verifier", "final"}

class DoneStatus(enum.Enum):
    OK = "OK"
    INCOMPLETE = "INCOMPLETE"
    SKIPPED = "SKIPPED"


# Taosc patch-format families that carry no predicate list and therefore do
# not run BinRadar's predicate filter (Single CWE-* synth paths).
PATCH_FORMAT_SINGLE = frozenset({
    "Single CWE-369", "Single CWE-617", "Single CWE-823", "Single CWE-805",
})


def read_patch_format(workdir: str) -> Optional[str]:
    """Return the Taosc patch-format string from workdir/patch-format.

    Returns None when the file is absent or empty.
    """
    path = os.path.join(workdir, "patch-format")
    if not os.path.isfile(path):
        return None
    with open(path, "r") as f:
        value = f.read().strip()
    return value or None

def _build_sbsv_parser() -> sbsv.parser:
    """Build a parser for the structured rows consumed by this collector."""
    parser = sbsv.parser()
    special = {
        ("rundir", "set"), ("rundir", "done"),
        ("filter", "done"), ("final", "start"), ("final", "done"),
    }
    for phase in ("rundir", "probe", "filter", "fuzzolic", "directed",
                  "fuzzer", "minimizer", "verifier", "binradar", "final"):
        for action in ("set", "start", "done"):
            if (phase, action) not in special:
                parser.add_schema(
                    f"[{phase}] [{action}] [prefix: str] [id: str]")
    parser.add_schema(
        "[rundir] [set] [prefix: str] [id: str] [dir?: str]")
    parser.add_schema(
        "[rundir] [done] [prefix: str] [id: str] [dir?: str]")
    parser.add_schema(
        "[filter] [done] [prefix: str] [id: str] [survived?: str]")
    parser.add_schema("[final] [start] [prefix: str] [id: str]")
    parser.add_schema(
        "[final] [done] [prefix: str] [id: str] "
        "[remaining_patches?: str] [binradar_remaining_patches?: str]")
    # Real issues: optional evidence phases that failed under --less-strict.
    parser.add_schema(
        "[final] [failed-phases] [prefix: str] [id: str] [failed-phases: str]")
    # Planned graceful cutoff: a phase (or the minimizer/verifier pair)
    # reached its configured wall-clock budget. Never an issue.
    for phase in ("rundir", "probe", "filter", "fuzzolic", "directed",
                  "fuzzer", "minimizer", "verifier", "binradar", "feedback",
                  "final"):
        parser.add_schema(
            f"[{phase}] [{binradar_utils.WALL_TIME_REACHED}] "
            f"[prefix: str] [id: str]")
    # Legacy notation from runs recorded before the wall-time-reached rename.
    # ``[final] [degraded]`` bundled both the tolerated-failure and the
    # wall-clock-cutoff cases, so it maps onto the failure concept it used to
    # report; ``[<phase>] [timeout]`` was only ever the planned cutoff.
    parser.add_schema(
        "[final] [degraded] [prefix: str] [id: str] [failed-phases: str]")
    for phase in ("rundir", "probe", "filter", "fuzzolic", "directed",
                  "fuzzer", "minimizer", "verifier", "binradar", "feedback",
                  "final"):
        parser.add_schema(
            f"[{phase}] [timeout] [prefix: str] [id: str]")
    parser.add_schema("[verifier-result] [res: str] [patch: str]")
    parser.add_schema("[patch] [id: int] [pass: bool]")
    parser.add_schema("[final] [verifier] [patch: str] [res: str]")
    parser.add_schema(
        "[final] [confidence] [patch: str] [score: str] "
        "[accept-evidences: str] [total-evidences: str]")
    parser.add_schema(
        "[final] [binradar] [patch: str] [res: str] [reason: str] [iter: int]")
    return parser


def _strip_log_prefix(line: str) -> str:
    """Remove timestamp/log text before the first SBSV token."""
    start = line.find("[")
    return line[start:] if start >= 0 else ""


SBSV_PARSER = _build_sbsv_parser()
SETUP_FILTER_SBSV_PARSER = sbsv.parser()
SETUP_FILTER_SBSV_PARSER.add_schema(
    "[filter] [res] [id: int] [pass: bool] [new-id: int]")
SETUP_FILTER_SBSV_PARSER.add_schema(
    "[filter] [done] [total: int] [survived: int] [time: float]")
SETUP_FILTER_SBSV_PARSER.add_schema(
    "[filter] [meta] [version: int] [kind: str] [sha256: str]")


@dataclass
class RunResult:
    """Structured result for a single run within an experiment."""
    run_name: str
    status: str  # "OK", "OK (rundir done, no final)", "INCOMPLETE: ...", etc.
    has_final: bool = False
    # True when the run reached FINAL with a non-empty remaining_patches
    # list (at least one remaining patch).
    at_least_one_remaining_patches: bool = False
    # Exact counts remain untruncated even when the displayed patch lists are
    # limited to --top.  -1 means the run did not produce that result.
    verifier_candidate_count: int = -1
    remaining_patches_count: int = -1
    binradar_evidence_iterations: int = -1
    binradar_rejected_count: int = -1
    binradar_remaining_patches_count: int = -1
    # P3's reduction counters are independent of confidence-ranked patch lists;
    # -1/None means the archived run did not record that field.
    binradar_coverage: str = ""
    binradar_raw_committed: int = -1
    binradar_processed: int = -1
    binradar_patch0_no_observation: int = -1
    binradar_original_normal: int = -1
    binradar_original_poc_crash: int = -1
    binradar_original_other_crash: int = -1
    binradar_original_unclassified_crash: int = -1
    binradar_normal_branch_differences: int = -1
    binradar_standalone_rejected: int = -1
    binradar_overlap_rejected: int = -1
    binradar_incremental_rejected: int = -1
    binradar_final_survivors: int = -1
    # Serialized rejection ID prefixes from FINAL; only complete when the
    # truncation marker is false. None distinguishes absent legacy telemetry
    # from an explicit, empty or non-truncated set (counts remain exact).
    binradar_standalone_ids: List[int] = field(default_factory=list)
    binradar_overlap_ids: List[int] = field(default_factory=list)
    binradar_incremental_ids: List[int] = field(default_factory=list)
    binradar_rejection_ids_truncated: Optional[bool] = None
    binradar_subject_kind: str = ""
    binradar_fault_reference_valid: Optional[bool] = None
    binradar_attempted: int = -1
    binradar_committed: int = -1
    binradar_discarded: int = -1
    binradar_queued: int = -1
    binradar_representative_runs: int = -1
    binradar_representative_runs_partial: Optional[bool] = None
    binradar_representative_budget: int = -1
    binradar_representative_budget_remaining: str = ""
    binradar_representative_reservation: int = -1
    binradar_mutation_portfolio: str = ""
    binradar_planned: int = -1
    binradar_tracer_attempts: int = -1
    binradar_stop_reason: str = ""
    binradar_stop_attempt: int = -1
    binradar_memcheck_enabled: Optional[bool] = None
    binradar_baseline_status: str = ""
    binradar_baseline_artifact: str = ""
    binradar_baseline_reproduced: Optional[bool] = None
    binradar_mutation_attempted: int = -1
    binradar_mutation_discarded: int = -1
    binradar_mutation_committed: int = -1
    binradar_mutation_pending: int = -1
    binradar_advisor_mode: str = ""
    binradar_advisor_schedule: str = ""
    binradar_advisor_candidates_generated: int = -1
    binradar_advisor_families_generated: int = -1
    binradar_advisor_families_accepted: int = -1
    binradar_advisor_unsupported_abstentions: int = -1
    binradar_advisor_budget_abstentions: int = -1
    binradar_advisor_families_executed: int = -1
    binradar_advisor_child_uses: int = -1
    binradar_advisor_telemetry: Dict[str, str] = field(default_factory=dict)
    # Bounded B1 diagnostic rows are keyed by tracer attempt ID within this
    # run; absent legacy data remains empty rather than becoming zero counters.
    binradar_plan_attempts: Dict[str, Dict[str, str]] = field(
        default_factory=dict)
    binradar_plan_funnel: Dict[str, Dict[str, str]] = field(
        default_factory=dict)
    # Effective advisor budgets present since settings v2; -1 means the run
    # predates budget provenance.
    binradar_advisor_max_work: int = -1
    binradar_advisor_max_bytes: int = -1
    binradar_advisor_deadline_ms: int = -1
    remaining_patches: str = ""  # e.g. "[1, 2, 3]" or "[]"
    binradar_remaining_patches: str = ""
    verifier_rejected: str = ""  # e.g. "2,4,6"
    verifier_data: Dict[int, List[str]] = field(default_factory=dict)  # raw verifier results
    binradar_rejected: str = ""  # e.g. "2,4,6"
    binradar_reject_reasons: str = ""  # e.g. "2:different-br; 4:introduced-crash"
    binradar_data: Dict[int, Dict[str, str]] = field(default_factory=dict)  # patch -> {res, reason, iter}
    confidence_data: Dict[int, Dict[str, str]] = field(default_factory=dict)  # patch -> {score, accept-evidences, total-evidences}
    top_patches: List[int] = field(default_factory=list)  # top-N patch ids by confidence
    top_patches_total: int = 0  # total patches ranked by confidence
    filter_done: bool = False
    filter_survived: str = ""  # e.g. "[1, 2]" or "[]"
    filter_rejected: str = ""  # e.g. "3" or "" if none
    # Real issues: optional evidence phases that failed under --less-strict.
    issues: bool = False
    failed_phases: str = ""
    # Planned graceful cutoff: a phase (or the concrete minimizer/verifier
    # pair) reached its configured wall-clock budget. Informational only.
    wall_time_reached: bool = False
    setup_filter_total: int = -1  # predicates evaluated by the filter
    setup_filter_survived: int = -1  # predicates kept (pass=true)
    setup_filter_done: DoneStatus = DoneStatus.INCOMPLETE
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
    setup_filter_total: int = -1  # predicates evaluated by the filter
    setup_filter_survived: int = -1  # predicates kept (pass=true)
    setup_filter_done: DoneStatus = DoneStatus.INCOMPLETE
    log_errors: List[str] = field(default_factory=list)


@dataclass
class TaoscResult:
    """Structured predicate result for one taosc workdir."""
    exp_dir: str
    status: str  # "ok", "issues", "no_data"
    error_message: str = ""  # for workdir-not-found, etc.
    patch_format: str = ""  # Taosc workdir/patch-format, when present
    original_predicates: int = -1
    filtered_predicates: int = -1
    setup_filter_total: int = -1
    setup_filter_done: DoneStatus = DoneStatus.INCOMPLETE


# Observation classes of BinRadarConcreteVerifier._test_result
# (fuzzolic/binradar_verifier.py), mapped to the short keys used by the
# binradar-stats output. Each compact counter or legacy verifier.sbsv row
# name maps to exactly one class; note that a naive substring match is unsafe (e.g. "crash-fail" is
# a substring of "no-crash-fail"), so the row action is matched exactly.
VERIFIER_RESULT_ROW_KEYS = {
    "patch-crashed": "patch-crashed",
    "crash-skip-diff-addr": "crash-skip-diff-addr",
    "crash-fail": "crash-fail",
    "crash-pass": "crash-pass",
    "crash-timeout": "crash-timeout",
    "no-crash-skip-diff-addr": "no-crash-skip-diff-addr",
    "no-crash-fail": "no-crash-fail",
    "no-crash-pass-same-br": "no-crash-pass-same-br",
    "no-crash-confidence-diff-br": "no-crash-confidence-diff-br",
    "no-crash-timeout": "no-crash-timeout",
}
STATS_KEYS = ["patch-crashed", "crash-skip-diff-addr", "crash-fail", "crash-pass", "crash-timeout", "no-crash-skip-diff-addr", "no-crash-fail", "no-crash-pass-same-br", "no-crash-confidence-diff-br", "no-crash-timeout"]


@dataclass
class PatchStats:
    """Per-patch counts of the _test_result observation classes."""
    patch: int
    score: str = ""  # raw confidence score from final.sbsv; "" when absent
    counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class RepresentativeStats:
    """Observed verifier branch-cache representative-run statistics.

    Values remain -1 when the human verifier log is unavailable: compact
    verifier.br evidence retains per-patch outcomes, but not cache groups.
    """
    source: str = ""
    testcases: int = -1
    runs: int = -1
    represented_patch_runs: int = -1
    fallbacks: int = -1


@dataclass
class StatsRunResult:
    """Verifier stats for a single run within an experiment."""
    run_name: str
    status: str
    has_final: bool = False
    top_shown: int = 0  # patches shown
    total_ranked: int = 0  # total patches in the ranking universe
    verifier_observations: int = 0
    representatives: RepresentativeStats = field(
        default_factory=RepresentativeStats)
    patches: List[PatchStats] = field(default_factory=list)


@dataclass
class StatsExperimentResult:
    """Structured result of one experiment for the binradar-stats command."""
    exp_dir: str
    overall_status: str  # "ok", "issues", "no_data"
    error_message: str = ""
    runs: List[StatsRunResult] = field(default_factory=list)


_DONE_STATUS_MARKER_RE = re.compile(r"\[(issues|failed-phases|wall-time-reached) ([^\]]*)\]")

# The pre-rename cutoff recorder inserted this synthetic entry into the
# phase-failure map, so a legacy `failed-phases` list can mix a real tolerated
# failure with the wall-clock cutoff. The name is not a
# ``binradar.OPTIONAL_EVIDENCE_PHASES`` member and no other code path writes it.
LEGACY_WALL_TIME_PHASE = "minimizer-verifier"


def _split_legacy_failed_phases(value: str) -> Tuple[str, bool]:
    """Split a legacy ``failed-phases`` list into (real failures, cutoff).

    Rows written before the wall-time-reached rename stored the concrete
    cutoff under the synthetic phase name ``minimizer-verifier`` inside the
    same list as genuine tolerated failures, so both must be separated here to
    keep the two concepts distinct for historical runs.
    """
    names = [n.strip() for n in value.split(",")] if value else []
    cutoff = LEGACY_WALL_TIME_PHASE in names
    remaining = [n for n in names
                 if n and n != "none" and n != LEGACY_WALL_TIME_PHASE]
    return ",".join(remaining), cutoff


def _done_status_markers(line: str) -> Dict[str, str]:
    """Extract the ``[final] [done]`` status markers from a raw log line.

    The markers trail the schema-mapped fields, so they are read from the raw
    line instead of widening the ``final$done`` schema: the sbsv parser
    rejects a row with fewer tokens than the schema declares, which would
    break every previously written row. Absent markers (legacy rows) simply
    stay absent, so callers must treat "missing" as "not recorded" rather
    than as ``false``.
    """
    return {name: value.strip()
            for name, value in _DONE_STATUS_MARKER_RE.findall(line)}


def parse_sbsv_line(line: str) -> Optional[Dict[str, str]]:
    """Parse one timestamp-prefixed or plain SBSV row with ``sbsv``."""
    payload = _strip_log_prefix(line.strip())
    if not payload:
        return None
    try:
        row = SBSV_PARSER.parse_line_detached(payload)
    except Exception:
        return None
    if row is None:
        return None
    schema_parts = row.schema_name.split("$", 1)
    entry: Dict[str, str] = {"_phase": schema_parts[0]}
    if len(schema_parts) == 2:
        entry["_action"] = schema_parts[1]
    for key, value in row.data.items():
        entry[key] = str(value)
    if row.schema_name == "final$done":
        entry.update(_done_status_markers(payload))
    return entry


def parse_progress_sbsv(sbsv_path: str) -> List[Dict[str, str]]:
    """Parse a progress.sbsv file with the schema-driven SBSV parser."""
    results: List[Dict[str, str]] = []
    if not os.path.isfile(sbsv_path):
        return results

    with open(sbsv_path, "r") as f:
        for line in f:
            entry = parse_sbsv_line(line)
            if entry:
                results.append(entry)
    return results

def _parse_row_with_fallback(line: str, parser: sbsv.parser,
                             legacy_parser: Optional[sbsv.parser] = None):
    """Parse an SBSV row, optionally retrying a legacy schema parser."""
    payload = _strip_log_prefix(line.strip())
    if not payload:
        return None
    try:
        row = parser.parse_line_detached(payload)
    except Exception:
        row = None
    if row is None and legacy_parser is not None:
        try:
            row = legacy_parser.parse_line_detached(payload)
        except Exception:
            row = None
    return row




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
    """Parse compact verifier results or legacy verifier-result rows."""
    results: Dict[int, List[str]] = {}
    if not os.path.isfile(sbsv_path):
        return results
    if sbsv_path.endswith(".br"):
        evidence = binradar_evidence.read_verifier(sbsv_path)
        return {
            patch: ["verified" if result.verified else "rejected"]
            for patch, result in evidence.patches.items()
        }

    with open(sbsv_path, "r") as f:
        for line in f:
            # Cheap filter: verifier.sbsv can be tens of GB of per-testcase
            # rows ([verifier] [crash-pass], [verifier-cache] [hit], ...), and
            # the sbsv tokenizer is ~85x slower than this substring check.
            # Any line parsing to schema "verifier-result" must contain the
            # token, so skipping the rest cannot drop a kept row.
            if "verifier-result" not in line:
                continue
            row = _parse_row_with_fallback(line, SBSV_PARSER)
            if row is not None and row.schema_name == "verifier-result":
                patch_id = safe_int(str(row["patch"]))
                results.setdefault(patch_id, []).append(str(row["res"]))
    return results


_VERIFIER_ROW_RE = re.compile(r"^\[verifier\] \[([a-z-]+)\]")
_VERIFIER_PATCH_RE = re.compile(r"\[patch (\d+)\]")


def parse_verifier_test_result_stats(sbsv_path: str) -> Dict[int, Dict[str, int]]:
    """Load aggregate observation counts from compact or legacy evidence.

    Compact ``verifier.br`` records carry the counters directly. For legacy
    SBSV, every counted row is a ``[verifier] [<action>] [patch N] ...`` log row
    emitted by BinRadarConcreteVerifier._test_result, one per
    (patch, testcase) observation. The rows carry a logging timestamp
    prefix, which _strip_log_prefix removes; the action and patch id are
    then matched with anchored regexes instead of the sbsv tokenizer for
    speed.

    verifier.sbsv can be tens of GB of per-testcase rows, so each line is
    first skipped by a cheap substring check: ``[verifier] [`` occurs in
    every counted row and cannot occur in any other row schema
    ([verifier-cache], [verifier-result], and [verifier] [stopped] do not
    match it).

    Returns patch id -> {short key -> count} with all keys present.
    """
    counts: Dict[int, Dict[str, int]] = {}
    if not os.path.isfile(sbsv_path):
        return counts
    if sbsv_path.endswith(".br"):
        evidence = binradar_evidence.read_verifier(sbsv_path)
        for patch, result in evidence.patches.items():
            entry = dict.fromkeys(STATS_KEYS, 0)
            for name, count in result.observations.items():
                key = VERIFIER_RESULT_ROW_KEYS.get(name)
                if key is not None:
                    entry[key] = count
            counts[patch] = entry
        return counts
    with open(sbsv_path, "r") as f:
        for line in f:
            if "[verifier] [" not in line:
                continue
            payload = _strip_log_prefix(line.strip())
            row = _VERIFIER_ROW_RE.match(payload)
            if row is None:
                continue
            key = VERIFIER_RESULT_ROW_KEYS.get(row.group(1))
            if key is None:
                continue
            patch = _VERIFIER_PATCH_RE.search(payload)
            if patch is None:
                continue
            entry = counts.setdefault(int(patch.group(1)),
                                      dict.fromkeys(STATS_KEYS, 0))
            entry[key] += 1
    return counts


_VERIFIER_CACHE_MISS_RE = re.compile(
    r"^\[verifier-cache\] \[miss\] \[patch (\d+)\] \[id (\d+)\]")
_VERIFIER_CACHE_GROUP_RE = re.compile(
    r"^\[verifier-cache\] \[group\] \[representative (\d+)\] "
    r"\[members (\d+)\] \[id (\d+)\]")
_VERIFIER_CACHE_FALLBACK_RE = re.compile(
    r"^\[verifier-cache\] \[(?:fallback|runtime-mismatch)\] "
    r"\[patch (\d+)\] \[id (\d+)\]")
_VERIFIER_TESTCASE_TRY_RE = re.compile(
    r"^\[testcase\] \[try\] \[patch (\d+)\] \[id (\d+)\]")


def parse_verifier_representative_stats(log_path: str) -> RepresentativeStats:
    """Count cache representatives and the patch runs they stand for.

    Every ``[verifier-cache] [miss]`` starts one cached representative run.
    A matching ``[group]`` row records the complete group size, including the
    representative; a miss without a group is a singleton. ``fallback`` and
    ``runtime-mismatch`` rows count representative attempts that required a
    second, uncached execution. When a verifier has no cache misses, each
    ``[testcase] [try]`` is an individual representative run; this is the
    normal path for single/direct patch families without a cache artifact.

    Compact ``verifier.br`` does not retain these cache events. Callers must
    therefore pass ``verifier.log`` or a legacy ``verifier.sbsv`` containing
    the diagnostic rows. Missing files return unavailable (-1) counters.
    """
    if not os.path.isfile(log_path) or log_path.endswith(".br"):
        return RepresentativeStats()

    misses: List[Tuple[int, int]] = []
    individual_runs: List[Tuple[int, int]] = []
    group_sizes: Dict[Tuple[int, int], int] = {}
    fallbacks = 0
    with open(log_path, "r") as f:
        for line in f:
            if ("[verifier-cache] [" not in line
                    and "[testcase] [try]" not in line):
                continue
            payload = _strip_log_prefix(line.strip())
            match = _VERIFIER_CACHE_MISS_RE.match(payload)
            if match is not None:
                misses.append((int(match.group(2)), int(match.group(1))))
                continue
            match = _VERIFIER_CACHE_GROUP_RE.match(payload)
            if match is not None:
                key = (int(match.group(3)), int(match.group(1)))
                group_sizes[key] = int(match.group(2))
                continue
            if _VERIFIER_CACHE_FALLBACK_RE.match(payload) is not None:
                fallbacks += 1
                continue
            match = _VERIFIER_TESTCASE_TRY_RE.match(payload)
            if match is not None:
                individual_runs.append(
                    (int(match.group(2)), int(match.group(1))))

    runs = misses or individual_runs
    testcases = {testcase for testcase, _ in runs}
    represented_patch_runs = (
        sum(group_sizes.get(key, 1) for key in misses)
        if misses else len(individual_runs))
    return RepresentativeStats(
        source=os.path.basename(log_path),
        testcases=len(testcases),
        runs=len(runs),
        represented_patch_runs=represented_patch_runs,
        fallbacks=fallbacks if misses else 0)


def parse_filter_sbsv(sbsv_path: str) -> Dict[int, bool]:
    """Parse a compact filter bitmap or legacy [patch] rows."""
    results: Dict[int, bool] = {}
    if not os.path.isfile(sbsv_path):
        return results
    if sbsv_path.endswith(".br"):
        return binradar_evidence.read_filter(sbsv_path).decisions

    with open(sbsv_path, "r") as f:
        for line in f:
            row = _parse_row_with_fallback(line, SBSV_PARSER)
            if row is not None and row.schema_name == "patch":
                results[int(row["id"])] = bool(row["pass"])
    return results


def parse_final_sbsv(sbsv_path: str) -> Tuple[Dict[int, str], Dict[int, Dict[str, str]], Dict[int, Dict[str, str]]]:
    """Parse per-patch verdicts from a final.sbsv file.

    Returns (verifier_verdicts, binradar_verdicts, confidence_data):
      verifier_verdicts: patch id -> "verified" / "rejected"
      binradar_verdicts:  patch id -> {"res": ..., "reason": ..., "iter": ...}
      confidence_data:    patch id -> {"score": ..., "accept-evidences": ...,
                                       "total-evidences": ...}
    """
    verifier_verdicts: Dict[int, str] = {}
    binradar_verdicts: Dict[int, Dict[str, str]] = {}
    confidence_data: Dict[int, Dict[str, str]] = {}
    if not os.path.isfile(sbsv_path):
        return verifier_verdicts, binradar_verdicts, confidence_data

    with open(sbsv_path, "r") as f:
        for line in f:
            entry = parse_sbsv_line(line)
            if entry is None:
                continue
            phase = entry.get("_phase", "")
            action = entry.get("_action", "")
            if phase != "final":
                continue
            patch = entry.get("patch", "")
            if not patch.isdigit():
                continue
            pid = int(patch)
            if action == "verifier":
                verifier_verdicts[pid] = entry.get("res", "")
            elif action == "binradar":
                binradar_verdicts[pid] = {
                    "res": entry.get("res", ""),
                    "reason": entry.get("reason", ""),
                    "iter": entry.get("iter", ""),
                }
            elif action == "confidence":
                confidence_data[pid] = {
                    "score": entry.get("score", ""),
                    "accept-evidences": entry.get("accept-evidences", ""),
                    "total-evidences": entry.get("total-evidences", ""),
                }
    return verifier_verdicts, binradar_verdicts, confidence_data


COVERAGE_COUNTER_FIELDS = (
    "raw-committed", "processed", "patch0-no-observation",
    "original-normal", "original-poc-crash", "original-other-crash",
    "original-unclassified-crash", "normal-branch-differences",
    "standalone-rejected", "overlap-rejected", "incremental-rejected",
    "final-survivors",
)


def _bracket_fields(line: str) -> Dict[str, str]:
    """Read flat ``[key value]`` fields from one of our SBSV telemetry rows."""
    return {key: value.strip().strip('"')
            for key, value in re.findall(r"\[([\w-]+) ([^\]]*)\]", line)}


def _optional_int(value: Optional[str]) -> int:
    """Convert a telemetry counter without turning absent/bad data into zero."""
    try:
        return int(value) if value is not None else -1
    except (TypeError, ValueError):
        return -1


def _optional_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in ("true", "1", "yes", "enabled"):
        return True
    if normalized in ("false", "0", "no", "disabled"):
        return False
    return None


def parse_final_coverage(final_path: str) -> Dict[str, str]:
    """Read the reducer's scalar coverage row without loading patch matrices."""
    coverage: Dict[str, str] = {}
    if not os.path.isfile(final_path):
        return coverage
    with open(final_path, "r", encoding="utf-8") as stream:
        for line in stream:
            payload = _strip_log_prefix(line.strip())
            if not payload.startswith("[final] [coverage]"):
                continue
            coverage = _bracket_fields(payload)
    return coverage


def parse_final_rejection_sets(
        final_path: str) -> Tuple[List[int], List[int], List[int], Optional[bool]]:
    """Read sorted serialized ID prefixes; None means no producer row."""
    sets: Tuple[List[int], List[int], List[int], Optional[bool]] = (
        [], [], [], None)
    if not os.path.isfile(final_path):
        return sets
    with open(final_path, "r", encoding="utf-8") as stream:
        for line in stream:
            payload = _strip_log_prefix(line.strip())
            if not payload.startswith("[final] [rejection-sets]"):
                continue
            fields = _bracket_fields(payload)
            sets = (
                _parse_patch_list(fields.get("standalone", "")),
                _parse_patch_list(fields.get("overlap", "")),
                _parse_patch_list(fields.get("incremental", "")),
                bool(fields.get("truncated-sets", "").strip()),
            )
    return sets


def parse_progress_coverage_marker(progress_path: str, prefix: str,
                                   run_id: str) -> str:
    """Read coverage status appended to the matching final done row."""
    if not os.path.isfile(progress_path):
        return ""
    status = ""
    with open(progress_path, "r", encoding="utf-8") as stream:
        for line in stream:
            payload = _strip_log_prefix(line.strip())
            if not payload.startswith("[final] [done]"):
                continue
            fields = _bracket_fields(payload)
            if (fields.get("prefix") == prefix and
                    fields.get("id") == str(run_id)):
                status = fields.get("binradar-coverage", status)
    return status


def parse_binradar_runtime_telemetry(progress_path: str, run_dir: str,
                                    prefix: str, run_id: str) -> Dict[str, object]:
    """Collect scalar BinRadar stop, attempt, baseline and advisor telemetry.

    Current attempt rows carry a run id. Historical unscoped rows fall back to
    the active ``[rundir] [set]`` record; run-scoped rows are checked against
    the requested prefix/id to avoid reading another run's terminal data.
    Mutation diagnostics are joined to the v4 tracer attempt ID, not an
    evidence-frame ID; absent historical diagnostic rows stay absent.
    """
    telemetry: Dict[str, object] = {
        "stop": {}, "baseline_status": "", "baseline_artifact": "",
        "tracer_attempts": -1, "advisor": {}, "settings": {},
        "plan_attempts": {}, "plan_funnel": {}, "queue_bins": {},
    }
    active_run: Optional[Tuple[str, str]] = None
    tracer_rows: List[Dict[str, str]] = []
    plan_attempts: Dict[str, Dict[str, str]] = {}
    plan_funnel: Dict[str, Dict[str, str]] = {}
    queue_bins: Dict[str, str] = {}
    advisor: Dict[str, str] = {}
    if os.path.isfile(progress_path):
        with open(progress_path, "r", encoding="utf-8") as stream:
            for line in stream:
                payload = _strip_log_prefix(line.strip())
                if not payload:
                    continue
                fields = _bracket_fields(payload)
                if payload.startswith("[rundir] [set]"):
                    active_run = (fields.get("prefix", ""),
                                  fields.get("id", ""))
                    continue
                if "prefix" in fields or "id" in fields:
                    scoped = (fields.get("prefix") == prefix and
                              fields.get("id") == str(run_id))
                else:
                    scoped = active_run == (prefix, str(run_id))
                if payload.startswith("[binradar] [start]") and scoped:
                    tracer_rows.clear()
                    advisor.clear()
                    telemetry["stop"] = {}
                    telemetry["baseline_status"] = ""
                    telemetry["baseline_artifact"] = ""
                    plan_attempts.clear()
                    plan_funnel.clear()
                    queue_bins.clear()
                elif payload.startswith("[binradar] [tracer]") and scoped:
                    tracer_rows.append(fields)
                elif payload.startswith("[binradar] [plan-attempt]") and scoped:
                    attempt = fields.get("attempt", "")
                    if fields.get("version") == "1" and attempt.isdigit():
                        plan_attempts[attempt] = fields
                elif payload.startswith("[binradar] [plan-funnel]") and scoped:
                    if fields.get("version") == "1":
                        key = (fields.get("advisor", "unknown") + "/" +
                               fields.get("source-kind", "unknown"))
                        plan_funnel[key] = fields
                elif payload.startswith("[binradar] [queue-bins]") and scoped:
                    if fields.get("version") == "1":
                        queue_bins.update(fields)
                elif payload.startswith("[binradar] [advisor]") and scoped:
                    advisor.update({key: value for key, value in fields.items()
                                    if key not in ("binradar", "advisor")})
                elif payload.startswith("[binradar] [stop]") and (
                        fields.get("prefix") == prefix and
                        fields.get("id") == str(run_id)):
                    telemetry["stop"] = fields
                elif payload.startswith("[binradar] [baseline]") and (
                        fields.get("prefix") == prefix and
                        fields.get("id") == str(run_id)):
                    status_match = re.match(
                        r"\[binradar\] \[baseline\] \[([^\]]+)\]",
                        payload)
                    if status_match:
                        telemetry["baseline_status"] = status_match.group(1)
                        telemetry["baseline_artifact"] = fields.get(
                            "artifact", "")

    telemetry["tracer_attempts"] = len(tracer_rows) if tracer_rows else -1
    telemetry["advisor"] = advisor
    tracer_by_attempt = {
        fields["attempt"]: fields for fields in tracer_rows
        if fields.get("attempt", "").isdigit()
    }
    for attempt, diagnostic in plan_attempts.items():
        tracer_row = tracer_by_attempt.get(attempt)
        if tracer_row is None:
            diagnostic["joined"] = "false"
            continue
        diagnostic["joined"] = "true"
        diagnostic["protocol-attempt-result"] = tracer_row.get(
            "attempt-result", "unknown")
        diagnostic["attempt-result-match"] = str(
            diagnostic.get("attempt-result", "unknown") ==
            tracer_row.get("attempt-result", "unknown")).lower()
        diagnostic["representative-runs"] = tracer_row.get(
            "representative-runs", "unknown")
        diagnostic["elapsed-ms"] = tracer_row.get("time", "unknown")
    telemetry["plan_attempts"] = plan_attempts
    telemetry["plan_funnel"] = plan_funnel
    telemetry["queue_bins"] = queue_bins
    settings: Dict[str, str] = {}
    settings_path = os.path.join(run_dir, "binradar-setting.sbsv")
    if os.path.isfile(settings_path):
        with open(settings_path, "r", encoding="utf-8") as stream:
            for line in stream:
                payload = _strip_log_prefix(line.strip())
                if not payload.startswith("[binradar-setting]"):
                    continue
                fields = _bracket_fields(payload)
                if (fields.get("run-prefix", prefix) == prefix and
                        fields.get("run-id", str(run_id)) == str(run_id)):
                    settings.update(fields)
    telemetry["settings"] = settings
    return telemetry


def parse_setup_filter_sbsv(sbsv_path: str) -> Dict[str, int]:
    """Parse current setup-filter result and done rows."""
    result = {"total": -1, "survived": -1, "done": 0}
    if not os.path.isfile(sbsv_path):
        return result
    total = 0
    survived = 0
    with open(sbsv_path, "r") as f:
        for line in f:
            row = _parse_row_with_fallback(line, SETUP_FILTER_SBSV_PARSER)
            if row is None:
                continue
            if row.schema_name == "filter$done":
                result["total"] = int(row["total"])
                result["survived"] = int(row["survived"])
                result["done"] = 1
            elif row.schema_name == "filter$meta":
                continue
            elif row.schema_name == "filter$res":
                total += 1
                if bool(row["pass"]):
                    survived += 1
    if result["done"] == 0 and total > 0:
        result["total"] = total
        result["survived"] = survived
    return result


def setup_filter_done_status(workdir: str,
                             setup_filter: Dict[str, int]) -> DoneStatus:
    """Return the setup-filter state represented by a workdir."""
    if setup_filter["done"]:
        return DoneStatus.OK
    if read_patch_format(workdir) in PATCH_FORMAT_SINGLE:
        return DoneStatus.SKIPPED
    if (setup_filter["total"] < 0
            and not os.path.isfile(os.path.join(workdir, "predicates"))
            and any(path.is_file()
                    for path in Path(workdir).glob("*.brpatched"))):
        return DoneStatus.SKIPPED
    return DoneStatus.INCOMPLETE


def safe_float(s: str) -> float:
    """Safely convert a string to float, returns 0.0 on failure."""
    try:
        return float(s)
    except (ValueError, TypeError):
        return 0.0


def top_patches_by_confidence(confidence_data: Dict[int, Dict[str, str]],
                              top: int) -> Tuple[List[int], int]:
    """Return the top-N patch ids ranked by confidence score.

    Ranking is by score (highest first); ties keep the original patch-id
    order. Returns (top_ids, total_count).
    """
    ranked = sorted(
        confidence_data.items(),
        key=lambda item: (-safe_float(item[1].get("score", "")), item[0]))
    return [pid for pid, _ in ranked[:top]], len(ranked)


def _parse_patch_list(value: str) -> List[int]:
    """Parse a patch-id list like "[1, 2, 3]" or "1,2,3" into ints."""
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value:
        return []
    ids: List[int] = []
    for part in value.split(","):
        part = part.strip()
        if part.isdigit():
            ids.append(int(part))
    return ids


def _format_confidence_score(score: str) -> str:
    """Format a confidence score for display (e.g. 0.192036 -> "0.192")."""
    try:
        return f"{float(score):.3f}"
    except (ValueError, TypeError):
        return score


def _truncate_patch_list(value: str, top_patches: List[int],
                         confidence_data: Optional[Dict[int, Dict[str, str]]] = None) -> str:
    """Truncate a patch-id list to the top-ranked patches.

    Accepts bracket lists ("[1, 2, 3]") and comma lists ("1,2,3") and
    preserves the input format. Returns the original value when it is not a
    list or when every id is already in the top set; otherwise returns the
    top ids with a "+N more" suffix. When none of the list's ids are
    top-ranked (e.g. a rejected list), the first ids of the list are shown
    instead so the line is never empty.

    When ``confidence_data`` (the [final] [confidence] rows keyed by patch
    id) is given, shown ids are ordered by score descending (ties keep the
    patch-id order) and annotated with their score: "142(0.731)". Ids
    without a confidence row keep the plain form.
    """
    if not top_patches:
        return value
    ids = _parse_patch_list(value)
    if not ids:
        return value
    top_set = set(top_patches)
    shown = [pid for pid in ids if pid in top_set]
    if not confidence_data:
        # No confidence context (filter lists, legacy runs): keep the
        # historical behavior byte-for-byte.
        if len(shown) == len(ids):
            return value
        if not shown:
            shown = ids[:len(top_patches)]
        text = ", ".join(str(p) for p in shown)
        if value.strip().startswith("["):
            text = "[" + text + "]"
        return text + f" (+{len(ids) - len(shown)} more)"
    if not shown:
        shown = ids[:len(top_patches)]
    shown = sorted(
        shown,
        key=lambda pid: (-safe_float(
            confidence_data.get(pid, {}).get("score", "")), pid))
    text = ", ".join(
        f"{pid}({_format_confidence_score(confidence_data[pid]['score'])})"
        if pid in confidence_data else str(pid)
        for pid in shown)
    if value.strip().startswith("["):
        text = "[" + text + "]"
    if len(shown) < len(ids):
        return text + f" (+{len(ids) - len(shown)} more)"
    return text


def _verifier_rejected_top(verifier_data: Dict[int, List[str]],
                           top_patches: List[int]) -> str:
    """Return the rejected patch ids as csv, limited to the top patches.

    Verified patches are not summarized separately: the remaining_patches
    column already carries the verified set (FINAL computes remaining as
    the concrete-verifier-verified filter survivors).
    """
    rejected: List[str] = []
    for pid in top_patches:
        res_list = verifier_data.get(pid)
        if res_list is not None and "rejected" in res_list:
            rejected.append(str(pid))
    return ",".join(rejected)


def _binradar_reject_summary_top(binradar_data: Dict[int, Dict[str, str]],
                                 top_patches: List[int]) -> Tuple[str, str]:
    """Return (rejected_csv, reject_reasons) limited to the top patches.

    Verified patches are not summarized separately: the
    binradar_remaining_patches column already carries the verified set.
    """
    rejected: List[str] = []
    reasons: List[str] = []
    for pid in top_patches:
        d = binradar_data.get(pid)
        if d is None:
            continue
        if d.get("res") == "rejected":
            rejected.append(str(pid))
            reasons.append(f"{pid}:{d.get('reason', '')}")
    return ",".join(rejected), "; ".join(reasons)


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
                               run_prefix: str,
                               top_patches: int = 10) -> ExperimentResult:
    """
    Collect results for a single experiment.

    Per-patch output is limited to the top ``top_patches`` patches ranked
    by confidence (from final.sbsv); the rest is summarized as counts.
    A run that never reached FINAL has no confidence rows, so its patch
    lists are capped at the top ``top_patches`` patches in patch-id order
    (falling back to the filter survivors when no verdicts exist).

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

    # Group entries by (prefix, id) — only those matching run_prefix exactly
    # (so `--run-prefix br` does not also collect `br-test-*` runs).
    runs: Dict[Tuple[str, str], List[Dict[str, str]]] = {}
    for entry in progress:
        prefix = entry.get("prefix", "")
        run_id = entry.get("id", "")
        if prefix and run_id:
            if prefix != run_prefix:
                continue
            key = (prefix, run_id)
            runs.setdefault(key, []).append(entry)

    if not runs:
        result.error_message = f"No runs found with prefix '{run_prefix}'"
        return result

    # Keep only the most recent run (highest numeric id) for the requested
    # prefix: a subject may have been rerun several times (br-00000, br-00001, ...).
    latest_run_id = max(safe_int(run_id) for _, run_id in runs.keys())
    runs = {
        key: entries
        for key, entries in runs.items()
        if safe_int(key[1]) == latest_run_id
    }

    # Workdir-level patch filter context (setup-time artifact shared by
    # all runs of this experiment).
    filter = parse_setup_filter_sbsv(os.path.join(workdir, "filter.sbsv"))

    overall_ok = True
    has_any_final = False

    for (prefix, run_id), entries in runs.items():
        started: set = set()
        done_phases: set = set()
        final_entry: Optional[Dict[str, str]] = None
        failed_phases_entry: Optional[Dict[str, str]] = None
        legacy_degraded_entry: Optional[Dict[str, str]] = None
        filter_entry: Optional[Dict[str, str]] = None
        wall_time_reached = False

        for entry in entries:
            phase = entry.get("_phase", "")
            action = entry.get("_action", "")

            if action == "start" and phase in KNOWN_PHASES:
                started.add(phase)
            elif action == "done" and phase in KNOWN_PHASES:
                done_phases.add(phase)
                if phase == "final":
                    final_entry = entry
                elif phase == "filter":
                    filter_entry = entry
            elif action == binradar_utils.WALL_TIME_REACHED:
                wall_time_reached = True
            elif phase == "final" and action == "failed-phases":
                failed_phases_entry = entry
            elif phase == "final" and action == "degraded":
                # Legacy notation: bundled tolerated failures with the
                # wall-clock cutoff, so it maps onto the failure concept.
                legacy_degraded_entry = entry

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

        # Determine status from two orthogonal signals.
        #   * failed phases (--less-strict toleration) are real issues and must
        #     not be reported as a complete security-verification result;
        #   * a reached wall-clock budget is a planned graceful cutoff and is
        #     not an error, so it never turns the run into an issue.
        failed_phases = ""
        if failed_phases_entry is not None:
            failed_phases = failed_phases_entry.get("failed-phases", "")
        elif legacy_degraded_entry is not None:
            failed_phases = legacy_degraded_entry.get("failed-phases", "")
        elif final_entry is not None:
            failed_phases = final_entry.get("failed-phases", "")
        # Legacy rows can hide the cutoff inside the failure list; split it out
        # so the two concepts stay distinct for historical runs too.
        failed_phases, legacy_cutoff = _split_legacy_failed_phases(failed_phases)
        if legacy_cutoff:
            wall_time_reached = True
        issues = bool(failed_phases)
        if final_entry is not None:
            if final_entry.get("issues", "").lower() == "true":
                issues = True
            if final_entry.get("wall-time-reached", "").lower() == "true":
                wall_time_reached = True
        if issues:
            status = f"ISSUES: failed phases: {failed_phases or 'unknown'}"
            if wall_time_reached:
                status += "; wall-time-reached"
            has_any_final = True
            overall_ok = False
        elif final_entry is not None:
            status = ("OK (wall-time-reached)" if wall_time_reached
                      else "OK")
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

        # Filter result: compact bitmap or legacy per-patch rows, with the
        # [filter] [done] progress survivor list as fallback for older runs.
        filter_path = _result_artifact(run_dir, "filter")
        filter_results = parse_filter_sbsv(filter_path)
        filter_survived = ""
        filter_rejected = ""
        if filter_results:
            survived = [pid for pid, passed in sorted(filter_results.items())
                        if passed]
            rejected = [pid for pid, passed in sorted(filter_results.items())
                        if not passed]
            filter_survived = "[" + ", ".join(str(p) for p in survived) + "]"
            filter_rejected = ",".join(str(p) for p in rejected)
        elif filter_entry is not None:
            filter_survived = _fix_bracket_value(
                filter_entry.get("survived", "[]"))

        # Build run result
        run_res = RunResult(
            run_name=run_dir_name,
            status=status,
            has_final=(final_entry is not None),
            filter_done=("filter" in done_phases or bool(filter_results)),
            filter_survived=filter_survived,
            filter_rejected=filter_rejected,
            issues=issues,
            failed_phases=failed_phases,
            wall_time_reached=wall_time_reached,
            setup_filter_total=filter["total"],
            setup_filter_survived=filter["survived"],
            setup_filter_done=setup_filter_done_status(workdir, filter),
            log_errors=log_errors,
            tracer_errors=tracer_errors,
        )

        final_path = os.path.join(run_dir, "final.sbsv")
        coverage = parse_final_coverage(final_path)
        run_res.binradar_coverage = coverage.get("binradar-coverage", "")
        if not run_res.binradar_coverage:
            run_res.binradar_coverage = parse_progress_coverage_marker(
                progress_path, prefix, run_id)
        if (run_res.has_final and not run_res.issues
                and run_res.binradar_coverage in ("partial", "unavailable")):
            cutoff = "wall-time-reached; " if run_res.wall_time_reached else ""
            run_res.status = (
                f"OK ({cutoff}binradar {run_res.binradar_coverage} coverage)")
        for counter in COVERAGE_COUNTER_FIELDS:
            attr = "binradar_" + counter.replace("-", "_")
            setattr(run_res, attr, _optional_int(coverage.get(counter)))
        run_res.binradar_subject_kind = coverage.get("subject-kind", "")
        run_res.binradar_fault_reference_valid = _optional_bool(
            coverage.get("fault-reference-valid"))
        (run_res.binradar_standalone_ids, run_res.binradar_overlap_ids,
         run_res.binradar_incremental_ids,
         run_res.binradar_rejection_ids_truncated) = (
            parse_final_rejection_sets(final_path))

        runtime = parse_binradar_runtime_telemetry(
            progress_path, run_dir, prefix, run_id)
        stop = runtime["stop"]
        if isinstance(stop, dict):
            run_res.binradar_attempted = _optional_int(stop.get("attempted"))
            run_res.binradar_committed = _optional_int(stop.get("committed"))
            run_res.binradar_discarded = _optional_int(stop.get("discarded"))
            run_res.binradar_queued = _optional_int(stop.get("queued"))
            run_res.binradar_representative_runs = _optional_int(
                stop.get("representative-runs"))
            run_res.binradar_representative_runs_partial = _optional_bool(
                stop.get("representative-runs-partial"))
            run_res.binradar_representative_budget = _optional_int(
                stop.get("representative-budget"))
            run_res.binradar_representative_budget_remaining = stop.get(
                "representative-budget-remaining", "")
            run_res.binradar_representative_reservation = _optional_int(
                stop.get("representative-reservation"))
            run_res.binradar_mutation_portfolio = stop.get(
                "mutation-portfolio", "")
            run_res.binradar_planned = _optional_int(stop.get("planned"))
            run_res.binradar_stop_reason = stop.get("reason", "")
            run_res.binradar_stop_attempt = _optional_int(stop.get("attempt"))
            run_res.binradar_memcheck_enabled = _optional_bool(
                stop.get("memcheck"))
            run_res.binradar_mutation_attempted = _optional_int(
                stop.get("mutation-attempted"))
            run_res.binradar_mutation_discarded = _optional_int(
                stop.get("mutation-discarded"))
            run_res.binradar_mutation_committed = _optional_int(
                stop.get("mutation-committed"))
            run_res.binradar_mutation_pending = _optional_int(
                stop.get("mutation-pending"))
            run_res.binradar_advisor_mode = stop.get("advisor-mode", "")
            run_res.binradar_advisor_schedule = stop.get(
                "advisor-schedule", "")
            for name in (
                    "candidates-generated", "families-generated",
                    "families-accepted",
                    "unsupported-abstentions", "budget-abstentions",
                    "families-executed", "child-uses"):
                column = "binradar_advisor_" + name.replace("-", "_")
                setattr(run_res, column, _optional_int(
                    stop.get("advisor-" + name)))
            run_res.binradar_advisor_telemetry.update({
                key: value for key, value in stop.items()
                if key.startswith("advisor-") or
                key.startswith("mutation-") or
                key.startswith("representative-") or
                key.startswith("plan-funnel-")
            })
        plan_attempts = runtime.get("plan_attempts", {})
        if isinstance(plan_attempts, dict):
            run_res.binradar_plan_attempts = plan_attempts
        plan_funnel = runtime.get("plan_funnel", {})
        if isinstance(plan_funnel, dict):
            run_res.binradar_plan_funnel = plan_funnel
        run_res.binradar_tracer_attempts = _optional_int(
            str(runtime.get("tracer_attempts", "")))
        run_res.binradar_baseline_status = str(
            runtime.get("baseline_status", ""))
        run_res.binradar_baseline_artifact = str(
            runtime.get("baseline_artifact", ""))
        if run_res.binradar_baseline_status in (
                "reproduced", "normal", "different-fault"):
            run_res.binradar_baseline_reproduced = (
                run_res.binradar_baseline_status == "reproduced")
        settings = runtime.get("settings", {})
        if isinstance(settings, dict):
            if run_res.binradar_memcheck_enabled is None:
                for key, value in settings.items():
                    normalized_key = key.lower().replace("_", "-")
                    if normalized_key in (
                            "binradar-memcheck-enable", "memcheck-enable",
                            "memcheck-enabled", "memcheck"):
                        run_res.binradar_memcheck_enabled = _optional_bool(
                            value)
                        break
            if not run_res.binradar_advisor_mode:
                for key, value in settings.items():
                    if key.lower().replace("_", "-") == \
                            "symbolic-mutation-mode":
                        run_res.binradar_advisor_mode = value
                        break
            if not run_res.binradar_advisor_schedule:
                for key, value in settings.items():
                    if key.lower().replace("_", "-") == \
                            "symbolic-schedule":
                        run_res.binradar_advisor_schedule = value
                        break
            if not run_res.binradar_mutation_portfolio:
                for key, value in settings.items():
                    if key.lower().replace("_", "-") == \
                            "mutation-portfolio":
                        run_res.binradar_mutation_portfolio = value
                        break
            if run_res.binradar_representative_budget < 0:
                for key, value in settings.items():
                    if key.lower().replace("_", "-") != \
                            "representative-budget":
                        continue
                    if str(value).strip().lower() != "unknown":
                        run_res.binradar_representative_budget = \
                            _optional_int(value)
                    break
            # A settings v1 row carries no advisor budgets.  Missing values
            # stay absent rather than being reported as the built-in default,
            # which would look like a measured configuration.
            for key, column in (
                    ("symbolic-max-work", "binradar_advisor_max_work"),
                    ("symbolic-max-bytes", "binradar_advisor_max_bytes"),
                    ("symbolic-deadline-ms", "binradar_advisor_deadline_ms")):
                for setting_key, value in settings.items():
                    if setting_key.lower().replace("_", "-") != key:
                        continue
                    if str(value).strip().lower() == "unknown":
                        break
                    setattr(run_res, column, _optional_int(value))
                    run_res.binradar_advisor_telemetry[
                        key] = str(value)
                    break
        advisor = runtime.get("advisor", {})
        if isinstance(advisor, dict):
            run_res.binradar_advisor_telemetry.update(advisor)

        if final_entry:
            remaining = final_entry.get("remaining_patches", "N/A")
            br_remaining = final_entry.get("binradar_remaining_patches", "N/A")
            run_res.remaining_patches = _fix_bracket_value(remaining)
            run_res.binradar_remaining_patches = _fix_bracket_value(br_remaining)
            remaining_ids = set(_parse_patch_list(run_res.remaining_patches))
            binradar_remaining_ids = set(
                _parse_patch_list(run_res.binradar_remaining_patches))
            run_res.at_least_one_remaining_patches = bool(remaining_ids)
            run_res.remaining_patches_count = len(remaining_ids)
            run_res.binradar_remaining_patches_count = len(
                binradar_remaining_ids)
            run_res.binradar_rejected_count = len(
                remaining_ids - binradar_remaining_ids)

            verifier_path = _result_artifact(run_dir, "verifier")
            verifier_results = parse_verifier_sbsv(verifier_path)
            if verifier_results:
                run_res.verifier_data = verifier_results
                run_res.verifier_candidate_count = len(verifier_results)

        run_res.binradar_evidence_iterations = (
            run_res.binradar_processed
            if run_res.binradar_processed >= 0 else extract_count(
                binradar_log,
                r"Processed (\d+) complete BINRADAR evidence iteration"))

        # Per-patch binradar verdicts and confidence from final.sbsv (written
        # by the FINAL phase). The confidence rows rank the accepted patches;
        # only the top-N of them are shown in the per-patch output.
        final_path = os.path.join(run_dir, "final.sbsv")
        _, binradar_verdicts, confidence_data = parse_final_sbsv(final_path)
        if binradar_verdicts:
            run_res.binradar_data = binradar_verdicts
        if confidence_data:
            run_res.confidence_data = confidence_data
            run_res.top_patches, run_res.top_patches_total = \
                top_patches_by_confidence(confidence_data, top_patches)
        else:
            # No confidence rows: legacy final.sbsv from old workdirs, or an
            # incomplete run whose FINAL phase never wrote them.  Legacy
            # complete runs keep every patch with a verdict (old behavior);
            # an incomplete run has no confidence ranking to order by, so its
            # patch lists (e.g. [filter] survived) are capped at the top-N
            # patches in patch-id order like a completed run, instead of
            # printing e.g. the whole filter survivor list.
            all_patches = sorted(
                set(run_res.verifier_data) | set(run_res.binradar_data))
            if final_entry is None and not all_patches:
                # Incomplete run: verifier/binradar verdicts are only
                # collected for runs that reached FINAL, so fall back to the
                # filter survivors as the patch universe to truncate.
                all_patches = _parse_patch_list(run_res.filter_survived)
            if final_entry is None:
                run_res.top_patches = all_patches[:top_patches]
            else:
                run_res.top_patches = all_patches
            run_res.top_patches_total = len(all_patches)

        # Per-patch summaries limited to the top-ranked patches.
        if run_res.verifier_data:
            run_res.verifier_rejected = _verifier_rejected_top(
                run_res.verifier_data, run_res.top_patches)
        if run_res.binradar_data:
            rejected, reasons = _binradar_reject_summary_top(
                run_res.binradar_data, run_res.top_patches)
            run_res.binradar_rejected = rejected
            run_res.binradar_reject_reasons = reasons

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


def count_predicates(predicates_path: str) -> int:
    """Count non-empty original taosc predicates, or return -1 if absent."""
    if not os.path.isfile(predicates_path):
        return -1
    with open(predicates_path, "r") as f:
        return sum(1 for line in f if line.strip())


def collect_sdfuzz_experiment(exp_dir: str, workdir_name: str,
                              fuzzer_name: str) -> SdfuzzResult:
    """
    Collect results of an external-fuzzer evaluation for a single experiment.

    Reads <workdir>/<fuzzer>/, the output layout of
    fuzzolic/binradar-evaluation.py:
      final.sbsv        final remaining patches + per-patch verdicts
      verified.br       compact concrete-verifier result
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

    # Patch filter context: the evaluated binary's patch candidates were
    # capped from workdir/filter.sbsv survivors (when it existed at
    # setup time).
    filter = parse_setup_filter_sbsv(os.path.join(workdir, "filter.sbsv"))
    result.setup_filter_total = filter["total"]
    result.setup_filter_survived = filter["survived"]
    result.setup_filter_done = setup_filter_done_status(workdir, filter)

    result.status = "ok" if not result.log_errors else "issues"
    return result


def collect_taosc_experiment(exp_dir: str, workdir_name: str) -> TaoscResult:
    """Collect original and filtered predicate counts from one workdir."""
    workdir = os.path.join(exp_dir, workdir_name)
    result = TaoscResult(exp_dir=exp_dir, status="no_data")

    if not os.path.isdir(workdir):
        result.error_message = "workdir not found"
        return result

    patch_format = read_patch_format(workdir)
    result.patch_format = patch_format or ""

    original = count_predicates(os.path.join(workdir, "predicates"))
    result.original_predicates = max(original, 0)

    filter_path = os.path.join(workdir, "filter.sbsv")
    filter = parse_setup_filter_sbsv(filter_path)
    result.setup_filter_total = filter["total"]
    if filter["survived"] >= 0:
        result.filtered_predicates = filter["survived"]

    if filter["done"]:
        result.setup_filter_done = DoneStatus.OK
    elif patch_format in PATCH_FORMAT_SINGLE:
        # Single CWE-* taosc patches have no predicate file and do not run
        # BinRadar's predicate filter.
        result.filtered_predicates = 0
        result.setup_filter_done = DoneStatus.SKIPPED
    elif not os.path.isfile(filter_path) and result.original_predicates == 0:
        # Direct-call and specialized taosc patches have no predicate file and
        # do not run BinRadar's predicate filter.
        result.filtered_predicates = 0
        result.setup_filter_done = DoneStatus.SKIPPED

    result.status = ("ok" if result.setup_filter_done in
                     (DoneStatus.OK, DoneStatus.SKIPPED) else "issues")
    return result


def collect_stats_experiment(exp_dir: str, workdir_name: str, run_prefix: str,
                             top_patches: int = 10) -> StatsExperimentResult:
    """Collect per-patch verifier _test_result case counts for one experiment.

    Mirrors collect_experiment_result's run selection (latest run id for the
    requested prefix) and ranks patches by the final.sbsv confidence rows;
    a run without confidence rows falls back to patch-id order over the
    verifier evidence and the filter survivors.
    """
    workdir = os.path.join(exp_dir, workdir_name)
    out_dir = os.path.join(workdir, "out")
    progress_path = os.path.join(out_dir, "progress.sbsv")

    result = StatsExperimentResult(exp_dir=exp_dir, overall_status="no_data")

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

    runs: Dict[Tuple[str, str], List[Dict[str, str]]] = {}
    for entry in progress:
        prefix = entry.get("prefix", "")
        run_id = entry.get("id", "")
        if prefix and run_id:
            if prefix != run_prefix:
                continue
            runs.setdefault((prefix, run_id), []).append(entry)
    if not runs:
        result.error_message = f"No runs found with prefix '{run_prefix}'"
        return result

    latest_run_id = max(safe_int(run_id) for _, run_id in runs.keys())
    runs = {
        key: entries
        for key, entries in runs.items()
        if safe_int(key[1]) == latest_run_id
    }

    overall_ok = True
    has_any_final = False

    for (prefix, run_id), entries in runs.items():
        started: set = set()
        done_phases: set = set()
        final_entry: Optional[Dict[str, str]] = None
        failed_phases_entry: Optional[Dict[str, str]] = None
        legacy_degraded_entry: Optional[Dict[str, str]] = None
        wall_time_reached = False
        for entry in entries:
            phase = entry.get("_phase", "")
            action = entry.get("_action", "")
            if action == "start" and phase in KNOWN_PHASES:
                started.add(phase)
            elif action == "done" and phase in KNOWN_PHASES:
                done_phases.add(phase)
                if phase == "final":
                    final_entry = entry
            elif action == binradar_utils.WALL_TIME_REACHED:
                wall_time_reached = True
            elif phase == "final" and action == "failed-phases":
                failed_phases_entry = entry
            elif phase == "final" and action == "degraded":
                legacy_degraded_entry = entry

        incomplete_phases = started - done_phases
        failed_phases = ""
        if failed_phases_entry is not None:
            failed_phases = failed_phases_entry.get("failed-phases", "")
        elif legacy_degraded_entry is not None:
            failed_phases = legacy_degraded_entry.get("failed-phases", "")
        elif final_entry is not None:
            failed_phases = final_entry.get("failed-phases", "")
        failed_phases, legacy_cutoff = _split_legacy_failed_phases(failed_phases)
        if legacy_cutoff:
            wall_time_reached = True
        issues = bool(failed_phases)
        if final_entry is not None:
            if final_entry.get("issues", "").lower() == "true":
                issues = True
            if final_entry.get("wall-time-reached", "").lower() == "true":
                wall_time_reached = True
        if issues:
            status = f"ISSUES: failed phases: {failed_phases or 'unknown'}"
            if wall_time_reached:
                status += "; wall-time-reached"
            has_any_final = True
            overall_ok = False
        elif final_entry is not None:
            status = ("OK (wall-time-reached)" if wall_time_reached
                      else "OK")
            has_any_final = True
        elif not incomplete_phases:
            status = "OK (rundir done, no final)"
        else:
            status = (f"INCOMPLETE: phases not done: "
                      f"{', '.join(sorted(incomplete_phases))}")
            overall_ok = False

        run_id_int = safe_int(run_id)
        run_name = f"{prefix}-{run_id_int:05d}"
        run_dir = os.path.join(out_dir, run_name)

        _, _, confidence_data = parse_final_sbsv(
            os.path.join(run_dir, "final.sbsv"))
        filter_results = parse_filter_sbsv(
            _result_artifact(run_dir, "filter"))
        verifier_artifact = _result_artifact(run_dir, "verifier")
        stats = parse_verifier_test_result_stats(verifier_artifact)
        verifier_observations = sum(
            sum(counts.values()) for counts in stats.values())
        verifier_log = os.path.join(run_dir, "verifier.log")
        if not os.path.isfile(verifier_log) \
                and verifier_artifact.endswith(".sbsv"):
            # Before compact evidence split diagnostics from results, the
            # cache events and terminal verifier rows shared verifier.sbsv.
            verifier_log = verifier_artifact
        representatives = parse_verifier_representative_stats(verifier_log)

        if confidence_data:
            top, total = top_patches_by_confidence(confidence_data,
                                                   top_patches)
        else:
            universe = sorted(
                set(stats)
                | {pid for pid, passed in filter_results.items() if passed})
            top, total = universe[:top_patches], len(universe)

        patches: List[PatchStats] = []
        for pid in top:
            conf = confidence_data.get(pid, {})
            counts = stats.get(pid) or dict.fromkeys(STATS_KEYS, 0)
            patches.append(PatchStats(patch=pid, score=conf.get("score", ""),
                                      counts=dict(counts)))

        result.runs.append(StatsRunResult(
            run_name=run_name, status=status,
            has_final=(final_entry is not None),
            top_shown=len(top), total_ranked=total,
            verifier_observations=verifier_observations,
            representatives=representatives, patches=patches))

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

        if run_res.binradar_coverage:
            rendered_counts = []
            for key in COVERAGE_COUNTER_FIELDS:
                value = getattr(
                    run_res, "binradar_" + key.replace("-", "_"))
                rendered_counts.append(
                    f"{key} {value if value >= 0 else 'N/A'}")
            coverage_counts = "; ".join(rendered_counts)
            fault_reference = (
                str(run_res.binradar_fault_reference_valid)
                if run_res.binradar_fault_reference_valid is not None else "N/A")
            lines.append(
                f"    [coverage] {run_res.binradar_coverage}: "
                f"{coverage_counts}; subject-kind "
                f"{run_res.binradar_subject_kind or 'N/A'}; "
                f"fault-reference-valid {fault_reference}")
        if (run_res.binradar_attempted >= 0 or
                run_res.binradar_stop_reason or
                run_res.binradar_tracer_attempts >= 0):
            attempted = (str(run_res.binradar_attempted)
                         if run_res.binradar_attempted >= 0 else "N/A")
            committed = (str(run_res.binradar_committed)
                         if run_res.binradar_committed >= 0 else "N/A")
            discarded = (str(run_res.binradar_discarded)
                         if run_res.binradar_discarded >= 0 else "N/A")
            queued = (str(run_res.binradar_queued)
                      if run_res.binradar_queued >= 0 else "N/A")
            lines.append(
                f"    [binradar] attempts: {attempted}  committed: "
                f"{committed}  discarded: {discarded}  queued: {queued}  "
                f"stop reason: {run_res.binradar_stop_reason or 'N/A'}")
        if run_res.binradar_tracer_attempts >= 0:
            representative_runs = (
                str(run_res.binradar_representative_runs)
                if run_res.binradar_representative_runs >= 0 else "N/A")
            planned = (str(run_res.binradar_planned)
                       if run_res.binradar_planned >= 0 else "N/A")
            memcheck = (str(run_res.binradar_memcheck_enabled)
                        if run_res.binradar_memcheck_enabled is not None
                        else "N/A")
            representative_partial = (
                str(run_res.binradar_representative_runs_partial)
                if run_res.binradar_representative_runs_partial is not None
                else "N/A")
            lines.append(
                f"    [binradar] tracer attempts observed: "
                f"{run_res.binradar_tracer_attempts}  representative runs: "
                f"{representative_runs}  representative-runs-partial: "
                f"{representative_partial}  planned: {planned}  memcheck: "
                f"{memcheck}")
        if run_res.binradar_baseline_status:
            reproduced = (
                str(run_res.binradar_baseline_reproduced)
                if run_res.binradar_baseline_reproduced is not None else "N/A")
            lines.append(
                f"    [binradar] selected baseline: "
                f"{run_res.binradar_baseline_artifact or 'N/A'} "
                f"status {run_res.binradar_baseline_status}; reproduces POC: "
                f"{reproduced}")
        if run_res.binradar_advisor_telemetry:
            advisor_summary = "  ".join(
                f"{key}: {value}" for key, value in sorted(
                    run_res.binradar_advisor_telemetry.items()))
            lines.append(f"    [binradar] advisor: {advisor_summary}")
        for attempt, diagnostic in sorted(
                run_res.binradar_plan_attempts.items(),
                key=lambda item: _optional_int(item[0])):
            lines.append(
                f"    [mutation-plan] attempt {attempt}: "
                f"{diagnostic.get('advisor-id', 'unknown')}/"
                f"{diagnostic.get('source-kind', 'unknown')} "
                f"source-retained "
                f"{diagnostic.get('source-retained', 'unknown')} "
                f"applied {diagnostic.get('patch0-applied', 'unknown')} "
                f"witness {diagnostic.get('patch0-read-witness', 'unknown')} "
                f"site {diagnostic.get('patch0-site', 'unknown')} "
                f"outcome {diagnostic.get('patch0-outcome', 'unknown')} "
                f"committed {diagnostic.get('committed', 'unknown')} "
                f"joined {diagnostic.get('joined', 'false')}")
        for key, funnel in sorted(run_res.binradar_plan_funnel.items()):
            lines.append(
                f"    [mutation-funnel] {key}: "
                f"scheduled {funnel.get('scheduled', 'unknown')} "
                f"scheduled-retained "
                f"{funnel.get('scheduled-retained', 'unknown')} "
                f"scheduled-not-retained "
                f"{funnel.get('scheduled-not-retained', 'unknown')} "
                f"scheduled-retention-unknown "
                f"{funnel.get('scheduled-retention-unknown', 'unknown')} "
                f"attempted {funnel.get('attempted', 'unknown')} "
                f"applied {funnel.get('applied', 'unknown')} "
                f"not-applied {funnel.get('not-applied', 'unknown')} "
                f"applied-unknown {funnel.get('applied-unknown', 'unknown')} "
                f"matched-witness {funnel.get('matched-witness', 'unknown')} "
                f"witness-unknown {funnel.get('witness-unknown', 'unknown')} "
                f"site-yes {funnel.get('site-yes', 'unknown')} "
                f"site-no {funnel.get('site-no', 'unknown')} "
                f"site-unknown {funnel.get('site-unknown', 'unknown')} "
                f"normal {funnel.get('normal', 'unknown')} "
                f"poc-crash {funnel.get('poc-crash', 'unknown')} "
                f"other-crash {funnel.get('other-crash', 'unknown')} "
                f"unclassified-crash "
                f"{funnel.get('unclassified-crash', 'unknown')} "
                f"unusable {funnel.get('unusable', 'unknown')} "
                f"outcome-unknown {funnel.get('outcome-unknown', 'unknown')} "
                f"unknown {funnel.get('unknown', 'unknown')} "
                f"discarded {funnel.get('discarded', 'unknown')} "
                f"committed-useful {funnel.get('committed-useful', 'unknown')} "
                f"representative-runs "
                f"{funnel.get('representative-runs', 'unknown')} "
                f"time-ms {funnel.get('time-ms', 'unknown')} "
                f"pending {funnel.get('pending', 'unknown')}")

        if run_res.has_final:
            lines.append(
                f"    [final] remaining_patches: "
                f"{_truncate_patch_list(run_res.remaining_patches, run_res.top_patches, run_res.confidence_data)}")
            lines.append(
                f"    [final] binradar_remaining_patches: "
                f"{_truncate_patch_list(run_res.binradar_remaining_patches, run_res.top_patches, run_res.confidence_data)}")
            if run_res.verifier_candidate_count >= 0:
                lines.append(
                    f"    [verifier] candidates: "
                    f"{run_res.verifier_candidate_count}  remaining: "
                    f"{run_res.remaining_patches_count}")
            if run_res.binradar_evidence_iterations >= 0:
                lines.append(
                    f"    [binradar] complete iterations: "
                    f"{run_res.binradar_evidence_iterations}  rejected: "
                    f"{run_res.binradar_rejected_count}  remaining: "
                    f"{run_res.binradar_remaining_patches_count}")

            if run_res.verifier_data and run_res.top_patches:
                header = "    [verifier] summary:"
                if run_res.top_patches_total > len(run_res.top_patches):
                    header = (f"    [verifier] summary (top "
                              f"{len(run_res.top_patches)} of "
                              f"{run_res.top_patches_total} by confidence):")
                lines.append(header)
                for pid in run_res.top_patches:
                    res_list = run_res.verifier_data.get(pid)
                    if res_list is None:
                        continue
                    verified = res_list.count("verified")
                    rejected = res_list.count("rejected")
                    lines.append(
                        f"      patch {pid}: {verified} verified, "
                        f"{rejected} rejected")

            if run_res.binradar_data and run_res.top_patches:
                header = "    [binradar] summary:"
                if run_res.top_patches_total > len(run_res.top_patches):
                    header = (f"    [binradar] summary (top "
                              f"{len(run_res.top_patches)} of "
                              f"{run_res.top_patches_total} by confidence):")
                lines.append(header)
                for pid in run_res.top_patches:
                    d = run_res.binradar_data.get(pid)
                    if d is None:
                        continue
                    if d.get("res") == "rejected":
                        detail = f" ({d.get('reason')}"
                        if d.get("iter"):
                            detail += f", iter {d['iter']}"
                        detail += ")"
                        lines.append(f"      patch {pid}: rejected{detail}")
                    else:
                        lines.append(f"      patch {pid}: verified")

        if run_res.filter_done:
            lines.append(
                f"    [filter] survived: "
                f"{_truncate_patch_list(run_res.filter_survived or '[]', run_res.top_patches)}  "
                f"rejected: "
                f"{_truncate_patch_list(run_res.filter_rejected or 'none', run_res.top_patches)}")

        if run_res.setup_filter_total >= 0:
            pct = ""
            if run_res.setup_filter_total > 0:
                pct = f" ({run_res.setup_filter_survived * 100 // run_res.setup_filter_total}%)"
            lines.append(
                f"    [filter] total: {run_res.setup_filter_total}  "
                f"survived: {run_res.setup_filter_survived}{pct}  "
                f"status: {run_res.setup_filter_done.value}")
        else:
            lines.append(
                f"    [filter] status: {run_res.setup_filter_done.value}")

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
    "at_least_one_remaining_patches",
    "verifier_candidate_count",
    "remaining_patches_count",
    "binradar_evidence_iterations",
    "binradar_rejected_count",
    "binradar_remaining_patches_count",
    "binradar_coverage",
    "binradar_raw_committed",
    "binradar_processed",
    "binradar_patch0_no_observation",
    "binradar_original_normal",
    "binradar_original_poc_crash",
    "binradar_original_other_crash",
    "binradar_original_unclassified_crash",
    "binradar_normal_branch_differences",
    "binradar_standalone_rejected",
    "binradar_overlap_rejected",
    "binradar_incremental_rejected",
    "binradar_final_survivors",
    "binradar_standalone_ids",
    "binradar_overlap_ids",
    "binradar_incremental_ids",
    "binradar_rejection_ids_truncated",
    "binradar_subject_kind",
    "binradar_fault_reference_valid",
    "binradar_attempted",
    "binradar_committed",
    "binradar_discarded",
    "binradar_queued",
    "binradar_representative_runs",
    "binradar_representative_runs_partial",
    "binradar_representative_budget",
    "binradar_representative_budget_remaining",
    "binradar_representative_reservation",
    "binradar_mutation_portfolio",
    "binradar_planned",
    "binradar_tracer_attempts",
    "binradar_stop_reason",
    "binradar_stop_attempt",
    "binradar_memcheck_enabled",
    "binradar_baseline_status",
    "binradar_baseline_artifact",
    "binradar_baseline_reproduced",
    "binradar_mutation_attempted",
    "binradar_mutation_discarded",
    "binradar_mutation_committed",
    "binradar_mutation_pending",
    "binradar_advisor_mode",
    "binradar_advisor_schedule",
    "binradar_advisor_candidates_generated",
    "binradar_advisor_families_generated",
    "binradar_advisor_families_accepted",
    "binradar_advisor_unsupported_abstentions",
    "binradar_advisor_budget_abstentions",
    "binradar_advisor_families_executed",
    "binradar_advisor_child_uses",
    "binradar_advisor_max_work",
    "binradar_advisor_max_bytes",
    "binradar_advisor_deadline_ms",
    "binradar_advisor_telemetry",
    "binradar_plan_attempts",
    "binradar_plan_funnel",
    "remaining_patches",
    "binradar_remaining_patches",
    "filter_survived_patches",
    "filter_rejected_patches",
    "setup_filter_total",
    "setup_filter_survived",
    "setup_filter_done",
    "verifier_rejected_patches",
    "binradar_rejected_patches",
    "binradar_reject_reasons",
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
            row = {column: "" for column in CSV_COLUMNS
                   if include_subject_id or column != "experiment"}
            row["status"] = f"ERROR: {result.error_message}"
            row["error_preview"] = result.error_message
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
                "at_least_one_remaining_patches":
                    str(run_res.at_least_one_remaining_patches),
                "verifier_candidate_count": (
                    str(run_res.verifier_candidate_count)
                    if run_res.verifier_candidate_count >= 0 else ""),
                "remaining_patches_count": (
                    str(run_res.remaining_patches_count)
                    if run_res.remaining_patches_count >= 0 else ""),
                "binradar_evidence_iterations": (
                    str(run_res.binradar_evidence_iterations)
                    if run_res.binradar_evidence_iterations >= 0 else ""),
                "binradar_rejected_count": (
                    str(run_res.binradar_rejected_count)
                    if run_res.binradar_rejected_count >= 0 else ""),
                "binradar_remaining_patches_count": (
                    str(run_res.binradar_remaining_patches_count)
                    if run_res.binradar_remaining_patches_count >= 0 else ""),
                "remaining_patches": _truncate_patch_list(
                    run_res.remaining_patches, run_res.top_patches,
                    run_res.confidence_data),
                "binradar_remaining_patches": _truncate_patch_list(
                    run_res.binradar_remaining_patches, run_res.top_patches,
                    run_res.confidence_data),
                "filter_survived_patches": _truncate_patch_list(
                    run_res.filter_survived, run_res.top_patches),
                "filter_rejected_patches": _truncate_patch_list(
                    run_res.filter_rejected, run_res.top_patches),
                "setup_filter_total": str(run_res.setup_filter_total)
                if run_res.setup_filter_total >= 0 else "",
                "setup_filter_survived": str(run_res.setup_filter_survived)
                if run_res.setup_filter_survived >= 0 else "",
                "setup_filter_done": run_res.setup_filter_done.value,
                "verifier_rejected_patches": run_res.verifier_rejected,
                "binradar_rejected_patches": run_res.binradar_rejected,
                "binradar_reject_reasons": run_res.binradar_reject_reasons,
                "log_errors_count": str(len(run_res.log_errors)),
                "tracer_errors_count": str(len(run_res.tracer_errors)),
                "error_preview": error_preview,
            }
            row["binradar_coverage"] = run_res.binradar_coverage
            for counter in COVERAGE_COUNTER_FIELDS:
                column = "binradar_" + counter.replace("-", "_")
                value = getattr(run_res, column)
                row[column] = str(value) if value >= 0 else ""
            row["binradar_subject_kind"] = run_res.binradar_subject_kind
            for column, ids in (
                    ("binradar_standalone_ids", run_res.binradar_standalone_ids),
                    ("binradar_overlap_ids", run_res.binradar_overlap_ids),
                    ("binradar_incremental_ids",
                     run_res.binradar_incremental_ids)):
                row[column] = ",".join(str(entry) for entry in ids)
            row["binradar_rejection_ids_truncated"] = (
                str(run_res.binradar_rejection_ids_truncated)
                if run_res.binradar_rejection_ids_truncated is not None
                else "")
            row["binradar_fault_reference_valid"] = (
                str(run_res.binradar_fault_reference_valid)
                if run_res.binradar_fault_reference_valid is not None else "")
            for column, value in (
                    ("binradar_attempted", run_res.binradar_attempted),
                    ("binradar_committed", run_res.binradar_committed),
                    ("binradar_discarded", run_res.binradar_discarded),
                    ("binradar_queued", run_res.binradar_queued),
                    ("binradar_representative_runs",
                     run_res.binradar_representative_runs),
                    ("binradar_representative_budget",
                     run_res.binradar_representative_budget),
                    ("binradar_representative_reservation",
                     run_res.binradar_representative_reservation),
                    ("binradar_planned", run_res.binradar_planned),
                    ("binradar_tracer_attempts",
                     run_res.binradar_tracer_attempts),
                    ("binradar_stop_attempt", run_res.binradar_stop_attempt)):
                row[column] = str(value) if value >= 0 else ""
            row["binradar_representative_runs_partial"] = (
                str(run_res.binradar_representative_runs_partial)
                if run_res.binradar_representative_runs_partial is not None
                else "")
            row["binradar_representative_budget_remaining"] = \
                run_res.binradar_representative_budget_remaining
            row["binradar_mutation_portfolio"] = \
                run_res.binradar_mutation_portfolio
            row["binradar_stop_reason"] = run_res.binradar_stop_reason
            row["binradar_memcheck_enabled"] = (
                str(run_res.binradar_memcheck_enabled)
                if run_res.binradar_memcheck_enabled is not None else "")
            row["binradar_baseline_status"] = (
                run_res.binradar_baseline_status)
            row["binradar_baseline_artifact"] = (
                run_res.binradar_baseline_artifact)
            row["binradar_baseline_reproduced"] = (
                str(run_res.binradar_baseline_reproduced)
                if run_res.binradar_baseline_reproduced is not None else "")
            row["binradar_advisor_mode"] = run_res.binradar_advisor_mode
            row["binradar_advisor_schedule"] = \
                run_res.binradar_advisor_schedule
            for column, value in (
                    ("binradar_mutation_attempted",
                     run_res.binradar_mutation_attempted),
                    ("binradar_mutation_discarded",
                     run_res.binradar_mutation_discarded),
                    ("binradar_mutation_committed",
                     run_res.binradar_mutation_committed),
                    ("binradar_mutation_pending",
                     run_res.binradar_mutation_pending),
                    ("binradar_advisor_candidates_generated",
                     run_res.binradar_advisor_candidates_generated),
                    ("binradar_advisor_families_generated",
                     run_res.binradar_advisor_families_generated),
                    ("binradar_advisor_families_accepted",
                     run_res.binradar_advisor_families_accepted),
                    ("binradar_advisor_unsupported_abstentions",
                     run_res.binradar_advisor_unsupported_abstentions),
                    ("binradar_advisor_budget_abstentions",
                     run_res.binradar_advisor_budget_abstentions),
                    ("binradar_advisor_families_executed",
                     run_res.binradar_advisor_families_executed),
                    ("binradar_advisor_child_uses",
                     run_res.binradar_advisor_child_uses),
                    ("binradar_advisor_max_work",
                     run_res.binradar_advisor_max_work),
                    ("binradar_advisor_max_bytes",
                     run_res.binradar_advisor_max_bytes),
                    ("binradar_advisor_deadline_ms",
                     run_res.binradar_advisor_deadline_ms)):
                row[column] = str(value) if value >= 0 else ""
            row["binradar_advisor_telemetry"] = ";".join(
                f"{key}={value}" for key, value in sorted(
                    run_res.binradar_advisor_telemetry.items()))
            row["binradar_plan_attempts"] = (
                json.dumps(run_res.binradar_plan_attempts, sort_keys=True,
                           separators=(",", ":"))
                if run_res.binradar_plan_attempts else "")
            row["binradar_plan_funnel"] = (
                json.dumps(run_res.binradar_plan_funnel, sort_keys=True,
                           separators=(",", ":"))
                if run_res.binradar_plan_funnel else "")
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
# Stats (binradar-stats) log/CSV formatters
# ---------------------------------------------------------------------------

def format_patch_stats(patch: PatchStats) -> str:
    """Format one patch as ``1(c: 0.991, pc: 10, csda: 20, ...)``."""
    score = _format_confidence_score(patch.score) if patch.score else "-"
    counts = patch.counts or dict.fromkeys(STATS_KEYS, 0)
    body = ", ".join(
        [f"c: {score}"]
        + [f"{key}: {counts.get(key, 0)}" for key in STATS_KEYS])
    return f"{patch.patch}({body})"


def format_stats_result_log(result: StatsExperimentResult) -> str:
    """Format a StatsExperimentResult as a human-readable log block."""
    lines: List[str] = []
    lines.append(f"=== {result.exp_dir} ===")

    if result.error_message:
        lines.append(f"  [STATUS] ERROR: {result.error_message}")
        return "\n".join(lines)

    for run in result.runs:
        lines.append(f"  [{run.run_name}] {run.status}")
        representatives = run.representatives
        lines.append(
            f"    [verifier] observations: {run.verifier_observations}")
        if representatives.runs >= 0:
            saved = (representatives.represented_patch_runs
                     - representatives.runs)
            reduction = (
                saved * 100.0 / representatives.represented_patch_runs
                if representatives.represented_patch_runs > 0 else 0.0)
            average = (
                representatives.runs / representatives.testcases
                if representatives.testcases > 0 else 0.0)
            lines.append(
                f"    [representatives] runs: {representatives.runs}  "
                f"testcases: {representatives.testcases}  "
                f"runs/testcase: {average:.2f}  "
                f"represented patch runs: "
                f"{representatives.represented_patch_runs}  "
                f"representative runs avoided: {saved} ({reduction:.2f}%)  "
                f"fallbacks: {representatives.fallbacks}  "
                f"source: {representatives.source}")
        else:
            lines.append(
                "    [representatives] runs: N/A "
                "(requires verifier.log or legacy verifier.sbsv; "
                "verifier.br does not encode cache groups)")
        if run.total_ranked > run.top_shown:
            lines.append(f"    [stats] (top {run.top_shown} of "
                         f"{run.total_ranked} patches by confidence)")
        else:
            noun = "patch" if run.top_shown == 1 else "patches"
            lines.append(f"    [stats] ({run.top_shown} {noun})")
        lines.append("    [" + ", ".join(
            format_patch_stats(patch) for patch in run.patches) + "]")

    if result.overall_status == "ok":
        lines.append("  [OVERALL] OK")
    elif result.overall_status == "issues":
        if result.runs and any(run.has_final for run in result.runs):
            lines.append("  [OVERALL] HAS ISSUES")
        else:
            lines.append("  [OVERALL] INCOMPLETE (no final result)")

    lines.append("")
    return "\n".join(lines)


STATS_CSV_COLUMNS = [
    "experiment",
    "run",
    "status",
    "verifier_observations",
    "representative_source",
    "representative_testcases",
    "representative_runs",
    "representative_runs_per_testcase",
    "represented_patch_runs",
    "representative_saved_runs",
    "representative_reduction_pct",
    "representative_fallbacks",
    "patch",
    "score",
] + STATS_KEYS


def format_stats_results_csv(all_results: List[StatsExperimentResult],
                             include_subject_id: bool = True) -> List[Dict[str, str]]:
    """Convert a list of StatsExperimentResults into CSV rows (one per patch)."""
    rows: List[Dict[str, str]] = []
    for result in all_results:
        if result.error_message:
            row = {col: "" for col in STATS_CSV_COLUMNS}
            row["status"] = f"ERROR: {result.error_message}"
            if include_subject_id:
                row["experiment"] = result.exp_dir
            rows.append(row)
            continue
        for run in result.runs:
            representatives = run.representatives
            available = representatives.runs >= 0
            saved = (representatives.represented_patch_runs
                     - representatives.runs) if available else -1
            reduction = (
                saved * 100.0 / representatives.represented_patch_runs
                if available and representatives.represented_patch_runs > 0
                else 0.0)
            average = (
                representatives.runs / representatives.testcases
                if available and representatives.testcases > 0 else 0.0)
            representative_columns = {
                "verifier_observations": str(run.verifier_observations),
                "representative_source": (representatives.source
                                          if available else ""),
                "representative_testcases": (str(representatives.testcases)
                                             if available else ""),
                "representative_runs": (str(representatives.runs)
                                        if available else ""),
                "representative_runs_per_testcase": (
                    f"{average:.2f}" if available else ""),
                "represented_patch_runs": (
                    str(representatives.represented_patch_runs)
                    if available else ""),
                "representative_saved_runs": (str(saved)
                                              if available else ""),
                "representative_reduction_pct": (
                    f"{reduction:.2f}" if available else ""),
                "representative_fallbacks": (str(representatives.fallbacks)
                                             if available else ""),
            }
            for patch in run.patches:
                row = {
                    "run": run.run_name,
                    "status": run.status,
                    **representative_columns,
                    "patch": str(patch.patch),
                    "score": (_format_confidence_score(patch.score)
                              if patch.score else ""),
                }
                for key in STATS_KEYS:
                    row[key] = str(patch.counts.get(key, 0))
                if include_subject_id:
                    row["experiment"] = result.exp_dir
                rows.append(row)
    return rows


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

    if result.setup_filter_total >= 0:
        lines.append(
            f"  [filter] total: {result.setup_filter_total}  "
            f"survived: {result.setup_filter_survived}  "
            f"status: {result.setup_filter_done.value}")
    else:
        lines.append(
            f"  [filter] status: {result.setup_filter_done.value}")

    if result.log_errors:
        lines.append("    [errors from evaluation.log]:")
        for err in result.log_errors[:10]:
            lines.append(f"      {err}")

    lines.append(
        f"  [OVERALL] {'OK' if result.status == 'ok' else 'HAS ISSUES'}")
    lines.append("")
    return "\n".join(lines)


def format_taosc_result_log(result: TaoscResult) -> str:
    """Format a TaoscResult as a human-readable log block."""
    lines: List[str] = []
    lines.append(f"=== {result.exp_dir} ===")

    if result.error_message:
        lines.append(f"  [STATUS] ERROR: {result.error_message}")
        return "\n".join(lines)

    original = (str(result.original_predicates)
                if result.original_predicates >= 0 else "N/A")
    filtered = (str(result.filtered_predicates)
                   if result.filtered_predicates >= 0 else "N/A")
    lines.append(f"  [taosc] patch-format: {result.patch_format or 'N/A'}")
    lines.append(f"  [taosc] original predicates: {original}")
    lines.append(f"  [taosc] filtered predicates: {filtered}")

    if result.setup_filter_total >= 0:
        pct = ""
        if result.setup_filter_total > 0:
            pct = (f" ({result.filtered_predicates * 100 // result.setup_filter_total}%)")
        lines.append(
            f"  [filter] total: {result.setup_filter_total}  "
            f"survived: {filtered}{pct}  "
            f"status: {result.setup_filter_done.value}")
    else:
        lines.append(f"  [filter] status: {result.setup_filter_done.value}")

    overall = "OK" if result.status == "ok" else "HAS ISSUES"
    lines.append(f"  [OVERALL] {overall}")
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
    "setup_filter_total",
    "setup_filter_survived",
    "setup_filter_done",
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
            "setup_filter_total": str(result.setup_filter_total)
            if result.setup_filter_total >= 0 else "",
            "setup_filter_survived": str(result.setup_filter_survived)
            if result.setup_filter_survived >= 0 else "",
            "setup_filter_done": result.setup_filter_done.value,
            "log_errors_count": str(len(result.log_errors)),
            "error_preview": error_preview,
        }
        if include_subject_id:
            row["experiment"] = result.exp_dir
        rows.append(row)
    return rows


TAOSC_CSV_COLUMNS = [
    "experiment",
    "status",
    "patch_format",
    "original_predicates",
    "filtered_predicates",
    "setup_filter_total",
    "setup_filter_done",
    "error_preview",
]


def format_taosc_results_csv(all_results: List[TaoscResult],
                             include_subject_id: bool = True) -> List[Dict[str, str]]:
    """Convert TaoscResults into CSV rows (list of dicts)."""
    rows: List[Dict[str, str]] = []
    for result in all_results:
        row = {
            "status": (f"ERROR: {result.error_message}"
                        if result.error_message else result.status),
            "patch_format": (result.patch_format
                             if not result.error_message else ""),
            "original_predicates": (str(result.original_predicates)
                                     if not result.error_message else ""),
            "filtered_predicates": (str(result.filtered_predicates)
                                        if not result.error_message else ""),
            "setup_filter_total": (str(result.setup_filter_total)
                                 if result.setup_filter_total >= 0 else ""),
            "setup_filter_done": (result.setup_filter_done.value
                               if not result.error_message else ""),
            "error_preview": result.error_message,
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


def _auto_workers(count: int) -> int:
    """Default worker count: one per CPU, capped by the number of tasks."""
    cpus = os.cpu_count() or 1
    return max(1, min(cpus, count))


def _collect_task(collect: Callable[[str], object], exp_dir: str) -> object:
    """Collect one experiment; convert unexpected errors to a placeholder.

    A broken experiment (e.g. unreadable file) must not abort the whole
    run, so failures become a placeholder result with an error message.
    """
    try:
        return collect(exp_dir)
    except Exception as e:
        message = f"collection failed: {type(e).__name__}: {e}"
        func = getattr(collect, "func", None)
        if func is collect_experiment_result:
            return ExperimentResult(exp_dir=exp_dir,
                                    overall_status="no_data",
                                    error_message=message)
        if func is collect_sdfuzz_experiment:
            return SdfuzzResult(exp_dir=exp_dir, status="no_data",
                                error_message=message)
        if func is collect_stats_experiment:
            return StatsExperimentResult(exp_dir=exp_dir,
                                         overall_status="no_data",
                                         error_message=message)
        return TaoscResult(exp_dir=exp_dir, status="no_data",
                           error_message=message)


def collect_all(collect: Callable[[str], object], resolved_dirs: List[str],
                jobs: int) -> List[object]:
    """Collect results for all experiments, in parallel when requested.

    Results are returned in the same order as ``resolved_dirs`` regardless
    of worker scheduling.  ``jobs`` is the worker count; 0 means auto
    (one worker per CPU, capped by the number of experiments), 1 forces
    sequential collection in-process.
    """
    workers = jobs if jobs > 0 else _auto_workers(len(resolved_dirs))
    if workers <= 1 or len(resolved_dirs) <= 1:
        return [_collect_task(collect, d) for d in resolved_dirs]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        # map() preserves input order; chunksize=1 since each task is heavy.
        return list(pool.map(_collect_task, repeat(collect), resolved_dirs,
                             chunksize=1))


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

    # Collect all results (in parallel; see --jobs)
    collect = partial(collect_experiment_result, workdir_name=workdir_name,
                      run_prefix=run_prefix, top_patches=args.top)
    all_results = collect_all(collect, resolved_dirs, args.jobs)
    if output_format in ("csv", "tsv"):
        for result, display in zip(all_results, display_dirs):
            result.exp_dir = display

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
        output_lines.append(
            f"Per-patch output: top {args.top} patches by confidence")
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


def cmd_binradar_stats(args):
    exp_file = args.exp
    workdir_name = args.workdir
    run_prefix = args.run_prefix
    output_format = args.format

    _, resolved_dirs, display_dirs = load_experiment_list(exp_file)

    # Create logs directory
    logs_dir = SCRIPT_DIR.parent / "loftix" / "logs"
    os.makedirs(logs_dir, exist_ok=True)

    # Collect all results (in parallel; see --jobs)
    collect = partial(collect_stats_experiment, workdir_name=workdir_name,
                      run_prefix=run_prefix, top_patches=args.top)
    all_results: List[StatsExperimentResult] = collect_all(
        collect, resolved_dirs, args.jobs)
    if output_format in ("csv", "tsv"):
        for result, display in zip(all_results, display_dirs):
            result.exp_dir = display

    # Output file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ext = output_format if output_format in ("csv", "tsv") else "log"
    output_path = (args.output if args.output
                   else os.path.join(logs_dir,
                                     f"binradar-stats-{timestamp}.{ext}"))

    # Count
    ok_count = sum(1 for r in all_results if r.overall_status == "ok")
    issues_count = sum(1 for r in all_results if r.overall_status == "issues")
    no_data_count = sum(1 for r in all_results if r.overall_status == "no_data")

    counts = {"OK": ok_count, "issues": issues_count,
              "no_data": no_data_count, "total": len(resolved_dirs)}

    if output_format in ("csv", "tsv"):
        columns = list(STATS_CSV_COLUMNS)
        if args.no_subject_id:
            columns.remove("experiment")
        csv_rows = format_stats_results_csv(
            all_results, include_subject_id=not args.no_subject_id)
        write_output(output_path, output_format, columns, csv_rows, [], counts)
    else:
        output_lines: List[str] = []
        output_lines.append("BinRadar Verifier Stats Collection")
        output_lines.append(f"Generated: {datetime.now().isoformat()}")
        output_lines.append(f"Experiment list: {exp_file}")
        output_lines.append(f"Workdir: {workdir_name}")
        output_lines.append(f"Run prefix: {run_prefix}")
        output_lines.append(
            f"Per-patch output: top {args.top} patches by confidence")
        output_lines.append(f"Total experiments: {len(resolved_dirs)}")
        output_lines.append("=" * 60)
        output_lines.append("")

        for result in all_results:
            output_lines.append(format_stats_result_log(result))

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

    # Collect all results (in parallel; see --jobs)
    collect = partial(collect_sdfuzz_experiment, workdir_name=workdir_name,
                      fuzzer_name=fuzzer_name)
    all_results: List[SdfuzzResult] = collect_all(collect, resolved_dirs,
                                                  args.jobs)
    if output_format in ("csv", "tsv"):
        for result, display in zip(all_results, display_dirs):
            result.exp_dir = display

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


def cmd_taosc(args):
    exp_file = args.exp
    workdir_name = args.workdir
    output_format = args.format

    _, resolved_dirs, display_dirs = load_experiment_list(exp_file)

    # Create logs directory
    logs_dir = SCRIPT_DIR.parent / "loftix" / "logs"
    os.makedirs(logs_dir, exist_ok=True)

    collect = partial(collect_taosc_experiment, workdir_name=workdir_name)
    all_results: List[TaoscResult] = collect_all(collect, resolved_dirs,
                                                 args.jobs)
    if output_format in ("csv", "tsv"):
        for result, display in zip(all_results, display_dirs):
            result.exp_dir = display

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ext = output_format if output_format in ("csv", "tsv") else "log"
    output_path = (args.output if args.output
                   else os.path.join(logs_dir, f"taosc-{timestamp}.{ext}"))

    ok_count = sum(1 for r in all_results if r.status == "ok")
    issues_count = sum(1 for r in all_results if r.status == "issues")
    no_data_count = sum(1 for r in all_results if r.status == "no_data")
    counts = {"OK": ok_count, "issues": issues_count,
              "no_data": no_data_count, "total": len(resolved_dirs)}

    if output_format in ("csv", "tsv"):
        columns = list(TAOSC_CSV_COLUMNS)
        if args.no_subject_id:
            columns.remove("experiment")
        csv_rows = format_taosc_results_csv(
            all_results, include_subject_id=not args.no_subject_id)
        write_output(output_path, output_format, columns, csv_rows, [], counts)
    else:
        output_lines: List[str] = []
        output_lines.append("Taosc Results Collection")
        output_lines.append(f"Generated: {datetime.now().isoformat()}")
        output_lines.append(f"Experiment list: {exp_file}")
        output_lines.append(f"Workdir: {workdir_name}")
        output_lines.append(f"Total experiments: {len(resolved_dirs)}")
        output_lines.append("=" * 60)
        output_lines.append("")

        for result in all_results:
            output_lines.append(format_taosc_result_log(result))

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
    shared.add_argument("--jobs", type=int, default=0,
                        help="number of parallel collection workers (0 = auto: one per CPU; 1 = sequential)")
    shared.add_argument(
        "--top", type=int, default=10,
        help="show only the top N patches by confidence (binradar only, "
             "default: 10)")
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

    sub.add_parser(
        "taosc", parents=[shared],
        help="collect original and filtered taosc predicate counts")

    sub.add_parser(
        "binradar-stats", parents=[shared],
        help="collect verifier representative-run statistics and per-patch "
             "_test_result counts for the top-N confidence patches")

    args = parser.parse_args()

    # Default to binradar when no subcommand is given (backward compatible)
    if args.command is None or args.command == "binradar":
        cmd_binradar(args)
    elif args.command == "sdfuzz":
        cmd_sdfuzz(args)
    elif args.command == "binradar-stats":
        cmd_binradar_stats(args)
    else:
        cmd_taosc(args)


if __name__ == "__main__":
    main()
