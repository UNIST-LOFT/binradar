"""Final BinRadar evidence reduction and report rendering."""

import os
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

import binradar_evidence
import binradar_verifier
import logger
import sbsv

IterationResults = tuple[int, dict[int, dict]]

# Serialization bound for the exact rejection ID sets.  The sets themselves
# stay exact; only a single report row is bounded so a 100k-candidate subject
# cannot emit a megabyte-long line.
REJECTION_ID_LIMIT = 512


@dataclass(frozen=True)
class FinalResultRequest:
    run_dir: str
    run_prefix: str
    run_id: int
    candidates: Sequence[int]
    tracer_fault_reference: binradar_verifier.TracerFaultReference | None
    disable_binradar: bool
    binradar_failed: bool
    wall_time_reached: bool
    failed_phases: Sequence[str]
    save_progress: Callable[[str], None]
    record_wall_time_reached: Callable[[], None]


def iter_legacy_binradar_results(trace_file: str) -> Iterator[IterationResults]:
    """Stream old per-patch SBSV traces one iteration at a time."""
    parser = sbsv.parser()
    parser.add_schema(
        "[binradar] [crash] [iter: int] [patch: int] "
        "[guest_pc: hex] [guest_cs_base: hex] [fault_addr: hex] "
        "[host_fault_addr: hex]")
    parser.add_schema("[binradar] [normal] [iter: int] [patch: int]")
    parser.add_schema(
        "[binradar] [commit] [iter: int] [patch: int] [br: str]")
    current_iteration = None
    current: dict[int, dict] = {}
    with open(trace_file, "r", encoding="utf-8") as stream:
        for line in stream:
            result = parser.parse_line_detached(line)
            if result is None:
                continue
            iteration = result["iter"]
            if current_iteration is None:
                current_iteration = iteration
            elif iteration != current_iteration:
                if iteration < current_iteration:
                    raise ValueError(
                        "legacy BINRADAR trace iterations are unordered")
                yield current_iteration, current
                current_iteration = iteration
                current = {}
            patch = result["patch"]
            patch_result = current.setdefault(patch, {})
            if result.schema_name == "binradar$crash":
                patch_result["result"] = "crash"
                patch_result["fault_addr"] = result["fault_addr"]
            elif result.schema_name == "binradar$normal":
                patch_result["result"] = "normal"
            else:
                patch_result["br"] = result["br"]
    if current_iteration is not None:
        yield current_iteration, current


def _run_stop(run_dir: str, prefix: str, run_id: int) -> dict[str, str]:
    """Read the last terminal row for this run, not another run's progress."""
    path = os.path.join(os.path.dirname(os.path.normpath(run_dir)),
                        "progress.sbsv")
    stop: dict[str, str] = {}
    if not os.path.isfile(path):
        return stop
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            if not line.startswith("[binradar] [stop] "):
                continue
            fields = dict(re.findall(r"\[([\w-]+) ([^\]]*)\]", line))
            if fields.get("prefix") == prefix and fields.get("id") == str(run_id):
                stop = fields
    return stop


def _has_complete_coverage_contract(
        stop: dict[str, str], raw_committed: int,
        patch0_no_observation: int) -> bool:
    """Prove that the finite P3 queue completed from the full stop record.

    P2 stop rows carried only reason/attempt/remaining/commit counts.  They
    cannot prove that no request was in flight or that every planned mutation
    was accounted for, so they remain partial even when their scalar counts
    happen to match the evidence file.
    """
    integer_fields = (
        "attempt", "remaining", "committed", "discarded", "attempted",
        "representative-runs", "planned", "queued", "mutation-attempted",
        "mutation-discarded", "mutation-committed", "mutation-pending",
    )
    try:
        counters = {name: int(stop[name]) for name in integer_fields}
    except (KeyError, ValueError):
        return False

    planned = raw_committed - 1
    return (
        raw_committed > 0
        and patch0_no_observation == 0
        and stop.get("reason") == "exhausted"
        and stop.get("representative-runs-partial") == "false"
        and counters["attempt"] == raw_committed
        and counters["remaining"] == 0
        and counters["committed"] == raw_committed
        and counters["discarded"] == 0
        and counters["attempted"] == raw_committed
        and counters["representative-runs"] >= raw_committed
        and counters["planned"] == planned
        and counters["queued"] == 0
        and counters["mutation-attempted"] == planned
        and counters["mutation-discarded"] == 0
        and counters["mutation-committed"] == planned
        and counters["mutation-pending"] == 0)


def write_final_result(request: FinalResultRequest) -> None:
    """Reduce verifier and BinRadar evidence and write final.sbsv.

    Compact evidence stays streaming: only one iteration is expanded at once.
    Progress publication intentionally retains the historical ordering where
    the final done row precedes the final.sbsv write.
    """
    verifier_result_file = os.path.join(request.run_dir, "verifier.br")
    legacy_verifier_file = os.path.join(request.run_dir, "verifier.sbsv")
    if not os.path.exists(verifier_result_file):
        verifier_result_file = legacy_verifier_file
    binradar_evidence_file = os.path.join(request.run_dir, "binradar.br")
    trace_msg_log_file = os.path.join(
        request.run_dir, "binradar-tracer-msg.log")
    request.save_progress(
        f"[final] [start] [prefix {request.run_prefix}] "
        f"[id {request.run_id}]")
    if not os.path.exists(verifier_result_file):
        logger.error(
            "Verifier result file not found. BinRadar results might be "
            "incomplete.")
        raise FileNotFoundError(
            f"Verifier result file not found: {verifier_result_file}")

    candidates = list(request.candidates)
    remaining_patches = set(candidates)
    concrete_verifier_result = \
        binradar_verifier.BinRadarConcreteVerifierResult.from_file(
            verifier_result_file)
    if concrete_verifier_result is None:
        logger.error(
            "Failed to parse verifier result. BinRadar results might be "
            "incomplete.")
        raise ValueError("Failed to parse verifier result.")

    wall_time_reached = request.wall_time_reached
    if (concrete_verifier_result.stop_reason == "wall-time-reached"
            and not wall_time_reached):
        request.record_wall_time_reached()
        wall_time_reached = True
    try:
        concrete_verifier_result.require_complete_verdicts(candidates)
    except ValueError as exc:
        logger.error(f"Incomplete verifier result: {exc}")
        raise

    accept_evidences = {
        patch: concrete_verifier_result.accept_evidences.get(patch, 0)
        for patch in candidates
    }
    total_evidences = {
        patch: concrete_verifier_result.total_evidences.get(patch, 0)
        for patch in candidates
    }

    def record_evidence(patch: int, accepted: bool) -> None:
        total_evidences[patch] = total_evidences.get(patch, 0) + 1
        if accepted:
            accept_evidences[patch] = accept_evidences.get(patch, 0) + 1

    skip_binradar_analysis = (
        request.disable_binradar or request.binradar_failed)
    compact_binradar = False
    stop = _run_stop(request.run_dir, request.run_prefix, request.run_id)
    if request.disable_binradar:
        logger.info(
            "[FINAL] BinRadar phase disabled; skipping evidence analysis.")
        binradar_iterations = iter(())
    elif request.binradar_failed:
        logger.warning(
            "[FINAL] BinRadar phase failed under --less-strict; ignoring "
            "its potentially incomplete evidence and using concrete "
            "verifier evidence only.")
        binradar_iterations = iter(())
    elif os.path.exists(binradar_evidence_file):
        compact_binradar = True
        binradar_iterations = binradar_evidence.read_binradar(
            binradar_evidence_file)
    elif os.path.exists(trace_msg_log_file):
        binradar_iterations = iter_legacy_binradar_results(
            trace_msg_log_file)
    else:
        logger.error(
            "BINRADAR evidence file not found. Results might be incomplete.")
        raise FileNotFoundError(
            f"BINRADAR evidence file not found: {binradar_evidence_file}")

    for patch_id in candidates:
        if not concrete_verifier_result.patch_verified[patch_id]:
            remaining_patches.discard(patch_id)
    binradar_remaining_patches = remaining_patches.copy()
    binradar_reject_reasons: dict[int, tuple[str, int]] = {}
    fault_reference = request.tracer_fault_reference
    fault_reference_valid = (
        fault_reference is not None and fault_reference.valid)
    poc_fault_loc = fault_reference.address if fault_reference_valid else None
    if not skip_binradar_analysis and not fault_reference_valid:
        logger.warning(
            "[FINAL] No validated tracer fault reference; BINRADAR hard-crash "
            "classification is unavailable. Concrete verdicts and "
            "normal/normal confidence evidence remain available.")

    expected_candidates = set(candidates)
    processed_iterations = raw_committed = patch0_no_observation = 0
    original_normal = original_poc_crash = original_other_crash = 0
    original_unclassified_crash = normal_branch_differences = 0
    standalone_rejections: set[int] = set()
    for frame in binradar_iterations:
        if compact_binradar:
            assert isinstance(frame, binradar_evidence.BinradarIteration)
            iteration = frame.iteration
            actual = {member for group in frame.groups for member in group.members}
            expected = {0} if iteration == 1 else expected_candidates | {0}
            if actual != expected:
                raise ValueError(
                    f"BINRADAR iteration {iteration} coverage mismatch: "
                    f"missing {sorted(expected - actual)}; "
                    f"unexpected {sorted(actual - expected)}")
            original_group = next(group for group in frame.groups
                                  if 0 in group.members)
            original = {"result": original_group.outcome,
                        "br": original_group.branches,
                        "fault_addr": original_group.fault_addr}
            groups = ((group.members,
                       {"result": group.outcome, "br": group.branches,
                        "fault_addr": group.fault_addr})
                      for group in frame.groups)
        else:
            assert not isinstance(frame, binradar_evidence.BinradarIteration)
            iteration, iteration_results = frame
            original = iteration_results.get(0)
            groups = (([patch], result)
                      for patch, result in iteration_results.items())
        raw_committed += 1
        if (original is None or "result" not in original
                or "br" not in original or original["br"] in (None, "null")):
            patch0_no_observation += 1
            continue
        processed_iterations += 1
        if original["result"] == "normal":
            original_normal += 1
        elif fault_reference_valid:
            if original.get("fault_addr") == poc_fault_loc:
                original_poc_crash += 1
            else:
                original_other_crash += 1
        else:
            original_unclassified_crash += 1
        for members, patch_result in groups:
            if "result" not in patch_result or "br" not in patch_result:
                continue
            same_crash = (original["result"] == "crash"
                          and patch_result["result"] == "crash"
                          and fault_reference_valid
                          and original.get("fault_addr") == poc_fault_loc
                          and patch_result.get("fault_addr") == poc_fault_loc)
            introduced_crash = (original["result"] == "normal"
                                and patch_result["result"] == "crash"
                                and fault_reference_valid
                                and patch_result.get("fault_addr") == poc_fault_loc)
            same_branch = original["br"] == patch_result["br"]
            for patch in members:
                if patch not in expected_candidates:
                    continue
                if same_crash or introduced_crash:
                    standalone_rejections.add(patch)
                    if patch in remaining_patches:
                        record_evidence(patch, False)
                        binradar_remaining_patches.discard(patch)
                        binradar_reject_reasons[patch] = (
                            "same-crash" if same_crash else "introduced-crash",
                            iteration)
                elif patch in remaining_patches:
                    if (original["result"] == "crash"
                            and patch_result["result"] == "normal"):
                        record_evidence(patch, True)
                    elif (original["result"] == "normal"
                          and patch_result["result"] == "normal"):
                        record_evidence(patch, same_branch)
                        if not same_branch:
                            normal_branch_differences += 1

    if not skip_binradar_analysis:
        logger.info(
            f"[FINAL] Processed {processed_iterations} complete "
            f"BINRADAR evidence iteration(s); rejected "
            f"{len(remaining_patches - binradar_remaining_patches)} "
            f"patch(es).")

    concrete_rejected = expected_candidates - remaining_patches
    overlap = standalone_rejections & concrete_rejected
    incremental = standalone_rejections - concrete_rejected
    # `representative-budget-unavailable` stops before the first attempt, so
    # the phase produced no BinRadar evidence at all: that is the same
    # no-evidence class as a disabled/failed/baseline-unavailable phase, not a
    # partial sweep of real attempts.
    if (skip_binradar_analysis
            or stop.get("reason") in ("baseline-unavailable",
                                      "representative-budget-unavailable")):
        coverage = "unavailable"
    elif _has_complete_coverage_contract(
            stop, raw_committed, patch0_no_observation):
        coverage = "complete"
    elif raw_committed or stop:
        coverage = "partial"
    else:
        coverage = "unavailable"
    coverage_row = (
        f"[final] [coverage] [binradar-coverage {coverage}] "
        f"[raw-committed {raw_committed}] [processed {processed_iterations}] "
        f"[patch0-no-observation {patch0_no_observation}] "
        f"[original-normal {original_normal}] "
        f"[original-poc-crash {original_poc_crash}] "
        f"[original-other-crash {original_other_crash}] "
        f"[original-unclassified-crash {original_unclassified_crash}] "
        f"[normal-branch-differences {normal_branch_differences}] "
        f"[standalone-rejected {len(standalone_rejections)}] "
        f"[overlap-rejected {len(overlap)}] "
        f"[incremental-rejected {len(incremental)}] "
        f"[final-survivors {len(binradar_remaining_patches)}] "
        f"[subject-kind {'singleton' if len(candidates) == 1 else 'multi' if candidates else 'empty'}] "
        f"[fault-reference-valid {str(fault_reference_valid).lower()}]")
    request.save_progress(coverage_row)

    def bounded_ids(ids: set[int]) -> tuple[str, bool]:
        """Comma-joined sorted IDs plus whether the list hit the cap.

        The sets themselves stay exact; only this row's serialization is
        bounded, so a 100,000-candidate subject cannot write a megabyte-long
        line.  Exact totals remain in the coverage row.
        """
        ordered = sorted(ids)
        if len(ordered) > REJECTION_ID_LIMIT:
            return (",".join(str(entry)
                             for entry in ordered[:REJECTION_ID_LIMIT]), True)
        return ",".join(str(entry) for entry in ordered), False

    # The exact standalone/overlap/incremental membership, not only the
    # scalar counts.  These are FINAL's own classification: the standalone
    # set includes patches the concrete verifier already rejected, so the
    # intersection here is the genuine overlap.
    fields = {
        "standalone": standalone_rejections,
        "overlap": overlap,
        "incremental": incremental,
        "final-survivors": binradar_remaining_patches,
    }
    rendered: dict[str, str] = {}
    truncated_sets: list[str] = []
    for name, ids in fields.items():
        text, truncated = bounded_ids(ids)
        rendered[name] = text
        if truncated:
            truncated_sets.append(name)
    rejection_sets_row = (
        f"[final] [rejection-sets] "
        f"[standalone {rendered['standalone']}] "
        f"[overlap {rendered['overlap']}] "
        f"[incremental {rendered['incremental']}] "
        f"[final-survivors {rendered['final-survivors']}] "
        f"[truncated-sets {','.join(truncated_sets)}]")
    request.save_progress(rejection_sets_row)

    failed_phases = list(request.failed_phases)
    issues_suffix = (
        f" [issues true] [failed-phases {','.join(failed_phases)}]"
        if failed_phases else " [issues false] [failed-phases none]")
    wall_time_suffix = (
        " [wall-time-reached true]" if wall_time_reached
        else " [wall-time-reached false]")
    coverage_suffix = f" [binradar-coverage {coverage}]"
    if failed_phases:
        request.save_progress(
            f"[final] [failed-phases] [prefix {request.run_prefix}] "
            f"[id {request.run_id}] "
            f"[failed-phases {','.join(failed_phases)}]")
    if wall_time_reached:
        request.save_progress(
            f"[final] [wall-time-reached] [prefix {request.run_prefix}] "
            f"[id {request.run_id}]")
    request.save_progress(
        f"[final] [done] [prefix {request.run_prefix}] "
        f"[id {request.run_id}] "
        f"[remaining_patches {sorted(remaining_patches)}] "
        f"[binradar_remaining_patches {sorted(binradar_remaining_patches)}]"
        f"{issues_suffix}{wall_time_suffix}{coverage_suffix}")

    final_result_file = os.path.join(request.run_dir, "final.sbsv")
    if request.disable_binradar:
        trace_metadata = "[binradar disabled]"
    elif request.binradar_failed:
        trace_metadata = "[binradar failed]"
    elif compact_binradar:
        trace_metadata = (
            f"[evidence {os.path.basename(binradar_evidence_file)}]")
    else:
        trace_metadata = f"[trace {os.path.basename(trace_msg_log_file)}]"

    with open(final_result_file, "w", encoding="utf-8") as result_file:
        result_file.write(
            f"[final] [start] [prefix {request.run_prefix}] "
            f"[id {request.run_id}] "
            f"[verifier {os.path.basename(verifier_result_file)}] "
            f"{trace_metadata}\n")
        reference_source = (fault_reference.source if fault_reference is not None
                            else "unavailable")
        reference_address = (fault_reference.address if fault_reference is not None
                             else 0)
        crash_classification = (
            "available" if fault_reference_valid and not skip_binradar_analysis
            else "unavailable")
        result_file.write(
            f"[final] [fault-reference] [version 2] "
            f"[valid {str(fault_reference_valid).lower()}] "
            f"[source {reference_source}] [address {reference_address:x}] "
            f"[hard-crash-classification {crash_classification}]\n")
        result_file.write(coverage_row + "\n")
        result_file.write(rejection_sets_row + "\n")
        if failed_phases:
            result_file.write(
                f"[final] [failed-phases] [prefix {request.run_prefix}] "
                f"[id {request.run_id}] "
                f"[failed-phases {','.join(failed_phases)}]\n")
        if wall_time_reached:
            result_file.write(
                f"[final] [wall-time-reached] "
                f"[prefix {request.run_prefix}] [id {request.run_id}]\n")
        for patch_id in sorted(candidates):
            verified = concrete_verifier_result.patch_verified[patch_id]
            result = "verified" if verified else "rejected"
            result_file.write(
                f"[final] [verifier] [patch {patch_id}] "
                f"[res {result}]\n")

        confidence_rows = []
        for patch_id in sorted(candidates):
            if not concrete_verifier_result.patch_verified[patch_id]:
                continue
            accepted = accept_evidences.get(patch_id, 0)
            total = total_evidences.get(patch_id, 0)
            confidence = accepted / total if total > 0 else 0.0
            confidence_rows.append((patch_id, confidence, accepted, total))
        confidence_rows.sort(key=lambda row: row[1], reverse=True)
        for patch_id, confidence, accepted, total in confidence_rows:
            result_file.write(
                f"[final] [confidence] [patch {patch_id}] "
                f"[score {confidence:.6f}] "
                f"[accept-evidences {accepted}] "
                f"[total-evidences {total}]\n")

        if not skip_binradar_analysis:
            for patch_id in sorted(remaining_patches):
                if patch_id in binradar_remaining_patches:
                    result_file.write(
                        f"[final] [binradar] [patch {patch_id}] "
                        f"[res verified] [reason none] [iter -1]\n")
                else:
                    reason, reject_iter = binradar_reject_reasons.get(
                        patch_id, ("unknown", -1))
                    result_file.write(
                        f"[final] [binradar] [patch {patch_id}] "
                        f"[res rejected] [reason {reason}] "
                        f"[iter {reject_iter}]\n")
        result_file.write(
            f"[final] [done] [prefix {request.run_prefix}] "
            f"[id {request.run_id}] "
            f"[remaining_patches {sorted(remaining_patches)}] "
            f"[binradar_remaining_patches "
            f"{sorted(binradar_remaining_patches)}]"
            f"{issues_suffix}{wall_time_suffix}{coverage_suffix}\n")
    logger.info(f"[FINAL] Saved final result: {final_result_file}")
