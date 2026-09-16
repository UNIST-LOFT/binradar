#!/usr/bin/env python3
"""Render compact BinRadar evidence as SBSV-like debugging text."""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path
from typing import Iterable, Optional, TextIO

import binradar_evidence


def _write_filter(path: Path, output: TextIO,
                  selected_patch: Optional[int]) -> None:
    result = binradar_evidence.read_filter(path)
    passed = set(result.passed)
    for patch in range(1, result.total + 1):
        if selected_patch is not None and patch != selected_patch:
            continue
        output.write(
            f"[patch] [id {patch}] [pass "
            f"{'true' if patch in passed else 'false'}]\n")


def _feedback_reason(result: binradar_evidence.VerifierPatchResult) -> str:
    observations = result.observations
    if observations.get("patch-crashed", 0):
        return "patch-crashed"
    if observations.get("no-crash-fail", 0):
        return "no-crash-fail"
    if observations.get("crash-fail", 0):
        return "crash-fail-security-rejection"
    return "eligible"


def _write_verifier(path: Path, output: TextIO,
                    selected_patch: Optional[int]) -> None:
    result = binradar_evidence.read_verifier(path)
    if result.stop_reason is not None:
        output.write(
            f"[verifier] [stopped] [reason {result.stop_reason}]\n")
    for patch, record in sorted(result.patches.items()):
        if selected_patch is not None and patch != selected_patch:
            continue
        verdict = "verified" if record.verified else "rejected"
        testcase = (f" [testcase {record.testcase}]"
                    if record.testcase else "")
        output.write(
            f"[verifier-result] [res {verdict}] [patch {patch}]"
            f"{testcase}\n")
        score = (record.accept_evidences / record.total_evidences
                 if record.total_evidences else 0.0)
        output.write(
            f"[verifier-confidence] [patch {patch}] [score {score:.6f}] "
            f"[accept-evidences {record.accept_evidences}] "
            f"[total-evidences {record.total_evidences}]\n")
        for name in binradar_evidence.OBSERVATION_NAMES:
            count = record.observations.get(name, 0)
            if count:
                output.write(
                    f"[verifier-observation] [patch {patch}] "
                    f"[kind {name}] [count {count}]\n")
        if record.has_feedback:
            output.write(
                f"[verifier-feedback] [patch {patch}] "
                f"[feedback-res "
                f"{'accepted' if record.feedback_accepted else 'rejected'}] "
                f"[feedback-reason {_feedback_reason(record)}] "
                f"[security-res "
                f"{'rejected' if record.security_rejected else 'verified'}] "
                f"[patch-crashed "
                f"{record.observations.get('patch-crashed', 0)}] "
                f"[crash-fail {record.observations.get('crash-fail', 0)}] "
                f"[crash-pass {record.observations.get('crash-pass', 0)}] "
                f"[no-crash-fail "
                f"{record.observations.get('no-crash-fail', 0)}] "
                f"[no-crash-pass-same-br "
                f"{record.observations.get('no-crash-pass-same-br', 0)}] "
                f"[behavior-diff "
                f"{record.observations.get('no-crash-confidence-diff-br', 0)}] "
                f"[accept-evidences {record.accept_evidences}] "
                f"[total-evidences {record.total_evidences}]\n")


def _branch_text(branches: Optional[Iterable[int]]) -> str:
    if branches is None:
        return "null"
    return "".join(str(branch) for branch in branches)


def _write_binradar(path: Path, output: TextIO,
                    selected_iteration: Optional[int],
                    selected_patch: Optional[int]) -> None:
    for iteration in binradar_evidence.read_binradar(path):
        if selected_iteration is not None \
                and iteration.iteration != selected_iteration:
            continue
        for group in iteration.groups:
            for patch in group.members:
                if selected_patch is not None and patch != selected_patch:
                    continue
                if group.outcome == "crash":
                    output.write(
                        f"[binradar] [crash] [iter {iteration.iteration}] "
                        f"[patch {patch}] [guest_pc 0] [guest_cs_base 0] "
                        f"[fault_addr {group.fault_addr:x}] "
                        f"[host_fault_addr 0]\n")
                else:
                    output.write(
                        f"[binradar] [normal] [iter {iteration.iteration}] "
                        f"[patch {patch}]\n")
                output.write(
                    f"[binradar] [commit] [iter {iteration.iteration}] "
                    f"[patch {patch}] [br {_branch_text(group.branches)}]\n")
            if selected_patch is None:
                members = ",".join(str(patch) for patch in group.members)
                output.write(
                    f"[binradar] [equivalence-group] "
                    f"[iter {iteration.iteration}] "
                    f"[representative {group.representative}] "
                    f"[members {members}]\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="convert BinRadar binary evidence to debugging text")
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--iteration", type=int,
                        help="render only one BINRADAR iteration")
    parser.add_argument("--patch", type=int,
                        help="render only one patch id")
    args = parser.parse_args()

    kind = binradar_evidence.evidence_kind(args.input)
    stream_context = (open(args.output, "w", encoding="utf-8")
                      if args.output is not None
                      else contextlib.nullcontext(sys.stdout))
    with stream_context as output:
        if kind == binradar_evidence.EvidenceKind.FILTER:
            if args.iteration is not None:
                parser.error("--iteration is only valid for BINRADAR evidence")
            _write_filter(args.input, output, args.patch)
        elif kind == binradar_evidence.EvidenceKind.VERIFIER:
            if args.iteration is not None:
                parser.error("--iteration is only valid for BINRADAR evidence")
            _write_verifier(args.input, output, args.patch)
        else:
            _write_binradar(args.input, output, args.iteration, args.patch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
