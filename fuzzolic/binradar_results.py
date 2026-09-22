"""Final BinRadar evidence reduction and report rendering."""

import os
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

import binradar_evidence
import binradar_verifier
import logger
import sbsv

IterationResults = tuple[int, dict[int, dict]]


@dataclass(frozen=True)
class FinalResultRequest:
    run_dir: str
    run_prefix: str
    run_id: int
    candidates: Sequence[int]
    tracer_fault_addr: int
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


def iter_binary_binradar_results(
        evidence_file: str) -> Iterator[IterationResults]:
    """Expand one compact equivalence-class frame at a time."""
    for iteration in binradar_evidence.read_binradar(evidence_file):
        results: dict[int, dict] = {}
        for group in iteration.groups:
            branch = ("null" if group.branches is None else
                      "".join(str(value) for value in group.branches))
            for patch in group.members:
                result = {"result": group.outcome, "br": branch}
                if group.outcome == "crash":
                    result["fault_addr"] = group.fault_addr
                results[patch] = result
        yield iteration.iteration, results


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
    if request.disable_binradar:
        logger.info(
            "[FINAL] BinRadar phase disabled; skipping evidence analysis.")
        binradar_iterations: Iterator[IterationResults] = iter(())
    elif request.binradar_failed:
        logger.warning(
            "[FINAL] BinRadar phase failed under --less-strict; ignoring "
            "its potentially incomplete evidence and using concrete "
            "verifier evidence only.")
        binradar_iterations = iter(())
    elif os.path.exists(binradar_evidence_file):
        compact_binradar = True
        binradar_iterations = iter_binary_binradar_results(
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
    poc_fault_loc = 0 if skip_binradar_analysis else request.tracer_fault_addr
    if not skip_binradar_analysis and poc_fault_loc == 0:
        logger.warning(
            "[FINAL] tracer_fault_addr is 0; binradar crash comparison "
            "will not match any fault address.")

    expected_candidates = set(candidates)
    processed_iterations = 0
    for iteration, iteration_results in binradar_iterations:
        actual = set(iteration_results)
        expected = {0} if iteration == 1 else expected_candidates | {0}
        if compact_binradar and actual != expected:
            raise ValueError(
                f"BINRADAR iteration {iteration} coverage mismatch: "
                f"missing {sorted(expected - actual)}; "
                f"unexpected {sorted(actual - expected)}")
        original = iteration_results.get(0)
        if (original is None or "result" not in original
                or "br" not in original or original["br"] == "null"):
            continue
        processed_iterations += 1
        for patch in remaining_patches:
            patch_result = iteration_results.get(patch)
            if (patch_result is None or "result" not in patch_result
                    or "br" not in patch_result):
                continue
            if (original["result"] == "crash"
                    and patch_result["result"] == "crash"):
                if (original.get("fault_addr") == poc_fault_loc
                        and patch_result.get("fault_addr") == poc_fault_loc):
                    record_evidence(patch, False)
                    binradar_remaining_patches.discard(patch)
                    binradar_reject_reasons[patch] = (
                        "same-crash", iteration)
            elif (original["result"] == "crash"
                  and patch_result["result"] == "normal"):
                record_evidence(patch, True)
            elif (original["result"] == "normal"
                  and patch_result["result"] == "crash"):
                if patch_result.get("fault_addr") == poc_fault_loc:
                    record_evidence(patch, False)
                    binradar_remaining_patches.discard(patch)
                    binradar_reject_reasons[patch] = (
                        "introduced-crash", iteration)
            elif (original["result"] == "normal"
                  and patch_result["result"] == "normal"):
                record_evidence(
                    patch, original["br"] == patch_result["br"])

    if not skip_binradar_analysis:
        logger.info(
            f"[FINAL] Processed {processed_iterations} complete "
            f"BINRADAR evidence iteration(s); rejected "
            f"{len(remaining_patches - binradar_remaining_patches)} "
            f"patch(es).")

    failed_phases = list(request.failed_phases)
    issues_suffix = (
        f" [issues true] [failed-phases {','.join(failed_phases)}]"
        if failed_phases else " [issues false] [failed-phases none]")
    wall_time_suffix = (
        " [wall-time-reached true]" if wall_time_reached
        else " [wall-time-reached false]")
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
        f"{issues_suffix}{wall_time_suffix}")

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
            f"{issues_suffix}{wall_time_suffix}\n")
    logger.info(f"[FINAL] Saved final result: {final_result_file}")
