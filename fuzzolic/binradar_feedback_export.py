"""Join durable concrete captures and committed mutation frames for Taosc."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil

from . import binradar_evidence as evidence
from . import binradar_verifier as verifier
from .binradar_feedback_capture import (
    BINS, decode_ids, encode_ids, file_sha256, pack_branches, read_case,
    read_header, unpack_branches,
)
from .binradar_feedback_bundle import VERSION, observed_class, write_row
from .binradar_taosc_predicates import REGISTER_TO_VAR, load_runtime_predicates, parse_cached_snapshots


def _label(trace, reference, *, mutation=False):
    if trace is None:
        return "unknown"
    if trace["outcome"] == "normal":
        return "normal"
    if trace["outcome"] != "crash" or not trace["fault_valid"] or reference is None:
        return "unknown"
    if mutation:
        observed = verifier.TracerFaultReference(
            trace["fault_addr"], trace["fault_source"],
            None if trace["fault_image"] == "none" else trace["fault_image"],
            None if trace["fault_image"] == "none" else trace["fault_offset"])
        if not observed.valid or not reference.valid:
            return "unknown"
        same = observed.identity_key == reference.identity_key
    else:
        same = trace["fault_addr"] == reference
    return "target-crash" if same else "other-crash"


def _observation(baseline, trace, reference, *, mutation=False):
    original = _label(baseline, reference, mutation=mutation)
    if original not in ("normal", "target-crash"):
        return "ignored-other-fault" if original == "other-crash" else "unclassified"
    branches = unpack_branches(trace["hits"], trace["branches"])
    if branches is not None and 2 in branches:
        return "patch-crashed"
    outcome = _label(trace, reference, mutation=mutation)
    if outcome == "other-crash":
        return "ignored-other-fault"
    if outcome not in ("normal", "target-crash"):
        return "unusable"
    if original == "target-crash":
        return "crash-pass" if outcome == "normal" else "crash-fail"
    if outcome == "target-crash":
        return "no-crash-fail"
    original_branches = unpack_branches(baseline["hits"], baseline["branches"])
    if branches is None or original_branches is None:
        return "unusable"
    return ("no-crash-pass-same-br" if branches == original_branches
            else "no-crash-confidence-diff-br")


def _baseline(row):
    current = (row.data.get("version") == 4
               and row.data.get("concrete-oracle") == verifier.CONCRETE_ORACLE)
    fault = verifier.concrete_fault_addr_from_row(row) if current else None
    branches = row.data.get("br") if current else None
    if branches is not None and len(branches) != row.data.get("patch-hit"):
        branches = None
    hits, packed = pack_branches(branches)
    return {"key": f"c{row['id']}-b1", "representative": 0,
            "artifact": "unavailable", "outcome":
                {"ok": "normal", "crash": "crash", "timeout": "timeout"}.get(row["exit"], "unusable") if current else "unusable",
            "fault_valid": fault is not None, "fault_addr": fault or 0,
            "fault_source": row.data.get("concrete-fault-source", "unavailable") if fault is not None else "unavailable",
            "fault_image": "none", "fault_offset": 0,
            "hits": hits, "branches": packed, "state_sha256": "none",
            "state_reason": "not-captured", "capture_id": -1}


def _require_concrete_capture(headers):
    missing = [channel for channel, header in headers.items() if header is None]
    if missing:
        raise ValueError(
            "Concrete feedback capture missing for " + ", ".join(missing)
            + "; rerun MINIMIZER/VERIFIER with --feedback-mode in a new run. "
              "Existing verifier totals cannot reconstruct input/trace observations.")


class _Writer:
    def __init__(self, request, root, stream, selected):
        self.request, self.root, self.stream = request, Path(root), stream
        self.selected = selected
        self.counts = {patch: {domain: [0] * len(BINS) for domain in ("concrete", "mutation")}
                       for patch in selected}
        self.totals = {"inputs": 0, "traces": 0, "observations": 0, "predicates": 0, "excluded": 0}
        self.states = set()
        self.input_files = {}

    def emit(self, name, **values):
        write_row(self.stream, name, **values)
        plural = {"input": "inputs", "trace": "traces", "observation": "observations",
                  "predicate": "predicates", "excluded": "excluded"}.get(name)
        if plural is not None:
            self.totals[plural] += 1

    def payload(self, trace, source, *, existing=None):
        digest = trace["state_sha256"]
        if digest == "none":
            if trace["state_reason"] == "none":
                raise ValueError("missing complete feedback state")
            return "none"
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or trace["state_reason"] != "none":
            raise ValueError("invalid feedback state digest/availability")
        if file_sha256(source) != digest:
            raise ValueError("feedback state checksum mismatch")
        snapshots, error = parse_cached_snapshots(Path(source).read_bytes())
        branches = unpack_branches(trace["hits"], trace["branches"])
        if (error is not None or branches is None
                or [state.branch for state in snapshots] != branches
                or any(state.patch_id != trace["capture_id"] for state in snapshots)):
            raise ValueError("feedback state/vector/raw-id mismatch")
        if existing is not None:
            return existing
        relative = f"states/{digest}.brch"
        if digest not in self.states:
            (self.root / "states").mkdir(exist_ok=True)
            shutil.copyfile(source, self.root / relative)
            self.states.add(digest)
        return relative

    def trace(self, key, trace, *, source=None, sidecar="none"):
        state = (self.payload(trace, source,
                              existing=f"binradar/{Path(source).name}" if sidecar != "none" else None)
                 if source is not None else "none")
        if source is None and trace["state_reason"] == "none":
            raise ValueError("complete feedback state has no payload")
        self.emit("trace", **{
            "key": trace["key"], "input": key, "representative": trace["representative"],
            "artifact": trace["artifact"], "outcome": trace["outcome"],
            "fault-valid": trace["fault_valid"], "fault-source": trace["fault_source"],
            "fault-addr": trace["fault_addr"], "fault-image": trace["fault_image"],
            "fault-offset": trace["fault_offset"], "hits": trace["hits"], "branches": trace["branches"],
            "state": state, "state-sha256": trace["state_sha256"],
            "state-reason": trace["state_reason"], "capture-id": trace["capture_id"], "sidecar": sidecar})

    def observe(self, key, domain, trace, members, observation):
        self.emit("observation", **{"input": key, "trace": trace["key"],
                                   "members": encode_ids(members), "bin": observation})
        if observation in BINS:
            index = BINS.index(observation)
            for patch in members:
                self.counts[patch][domain][index] += 1

    def coverage(self, key, observed, usable, skipped):
        missing = self.selected - observed - skipped
        unusable = observed - usable
        status = ("complete" if not (missing or unusable or skipped) else
                  "partial" if observed else "unavailable")
        self.emit("coverage", **{"input": key, "status": status, "not-run": encode_ids(missing),
                                 "unusable": encode_ids(unusable), "skipped": encode_ids(skipped)})

    def concrete(self, headers):
        parsers = verifier.concrete_result_parsers()
        seen = set()
        with open(Path(self.request.run_dir) / "minimizer.sbsv", encoding="utf-8") as rows:
            for line in rows:
                row = verifier.parse_concrete_result_row(line, parsers)
                if row is None:
                    continue
                _require_concrete_capture(headers)
                case, filename = row["id"], row["file"]
                if type(case) is not int or case < 0 or case in seen or Path(filename).name != filename:
                    raise ValueError("invalid/duplicate minimized input identity")
                seen.add(case)
                source = Path(self.request.run_dir) / "minimized" / filename
                if not source.is_file():
                    # Keep absence explicit, rather than silently dropping a coverage row.
                    digest = relative = "none"
                else:
                    digest = file_sha256(source)
                    relative = self.input_files.get(digest)
                baseline = _baseline(row)
                channel_records = {}
                for channel, header in headers.items():
                    records = list(read_case(self.request.run_dir, channel, case)) if header else []
                    if records:
                        first = records[0]
                        if (first != {"kind": "input", "case": case, "file": filename, "sha256": digest}
                                or any(item["kind"] == "input" for item in records[1:])):
                            raise ValueError("feedback capture/input checksum mismatch")
                    channel_records[channel] = records[1:]
                baseline_records = channel_records["baseline"]
                if baseline_records:
                    if (len(baseline_records) != 1 or baseline_records[0]["kind"] != "trace"
                            or baseline_records[0]["representative"] != 0
                            or baseline_records[0]["members"] != "none"):
                        raise ValueError("invalid feedback baseline capture")
                    recorded = baseline_records[0]
                    if any(recorded[field] != baseline[field] for field in (
                            "outcome", "fault_valid", "fault_addr", "fault_source", "hits", "branches")):
                        raise ValueError("feedback baseline differs from published minimizer result")
                    baseline = recorded
                label = _label(baseline, self.request.poc_concrete_fault_addr)
                eligible = label in ("normal", "target-crash") and row.data.get("patch-hit", 0) > 0
                if relative is None:
                    category = ("benign" if label == "normal" else "malicious") if eligible else "unclassified"
                    safe_name = filename if not re.search(r"[\[\]\r\n]", filename) else digest
                    relative = f"concrete/{category}/{safe_name}"
                    target = self.root / relative
                    target.parent.mkdir(exist_ok=True)
                    if target.exists() and file_sha256(target) != digest:
                        relative = f"concrete/{category}/{digest}"
                    shutil.copyfile(source, self.root / relative)
                    self.input_files[digest] = relative
                    if eligible:
                        with (self.root / "concrete/results.sbsv").open("a", encoding="utf-8") as diagnostics:
                            diagnostics.write(line if line.endswith("\n") else line + "\n")
                key = f"c{case}"
                self.emit("input", key=key, domain="concrete", file=relative, sha256=digest,
                          baseline=baseline["key"], label=label, mutation="none")
                state_source = (Path(self.request.run_dir) / "feedback-capture/states" / f"{baseline['state_sha256']}.brch"
                                if baseline["state_sha256"] != "none" else None)
                self.trace(key, baseline, source=state_source)
                observed, usable, skipped = set(), set(), set()
                keys = {baseline["key"]}
                for trace in channel_records["verifier"]:
                    members = set(decode_ids(trace["members"], universe=self.selected))
                    if members & (observed | skipped):
                        raise ValueError("duplicate concrete feedback candidate observation")
                    if trace["kind"] == "skip":
                        skipped.update(members)
                        continue
                    if trace["kind"] != "trace" or trace["key"] in keys:
                        raise ValueError("invalid/duplicate concrete feedback trace")
                    keys.add(trace["key"])
                    if members and trace["representative"] not in members:
                        raise ValueError("feedback representative outside observed group")
                    state_source = (Path(self.request.run_dir) / "feedback-capture/states" / f"{trace['state_sha256']}.brch"
                                    if trace["state_sha256"] != "none" else None)
                    self.trace(key, trace, source=state_source)
                    if not members:
                        continue  # Actual discarded attempt, no inferred members.
                    observation = _observation(baseline, trace, self.request.poc_concrete_fault_addr)
                    advertised = trace["observation"]
                    canonical = {"crash-skip-diff-addr": "ignored-other-fault",
                                 "no-crash-skip-diff-addr": "ignored-other-fault",
                                 "crash-timeout": "unusable", "no-crash-timeout": "unusable",
                                 "unobserved": "unusable", "attempted-unusable": "unusable"}.get(advertised, advertised)
                    if canonical == "ignored-other-fault" and _label(trace, self.request.poc_concrete_fault_addr) == "unknown":
                        canonical = "unusable"
                    if label in ("normal", "target-crash") and canonical != observation:
                        raise ValueError("feedback journal classification disagrees with execution")
                    self.observe(key, "concrete", trace, members, observation)
                    observed.update(members)
                    if observation in BINS:
                        usable.update(members)
                self.coverage(key, observed, usable, skipped)

    def mutation(self, pairs, context):
        path = Path(self.request.run_dir) / "binradar.br"
        if not path.exists():
            return
        if evidence.evidence_version(path, evidence.EvidenceKind.BINRADAR) != 4:
            return  # Historical evidence is not upgraded into typed observations.
        pair_index = {}
        for pair in pairs:
            match = re.fullmatch(r"iteration-([0-9]+)-patch-([0-9]+)\.brch", Path(pair[0]).name)
            if match is None:
                raise ValueError("invalid committed mutation pair filename")
            pair_index[int(match[1]), int(match[2])] = pair
        for frame in evidence.read_binradar(path):
            if frame.iteration == 1:
                continue  # Initial POC execution is not a mutation experiment.
            key = f"m{frame.iteration}"
            traces = []
            baseline = None
            write_digest = None
            observed, usable = set(), set()
            for group in frame.groups:
                members = set(group.members)
                if not members or not members <= self.selected | {0} or group.representative not in members:
                    raise ValueError("invalid mutation feedback group membership")
                if members & observed:
                    raise ValueError("duplicate mutation feedback candidate observation")
                observed.update(members)
                hits, branches = pack_branches(group.branches)
                trace = {"key": f"{key}-r{group.representative}", "representative": group.representative,
                         "artifact": context["artifact"] if context else "unavailable", "outcome": group.outcome,
                         "fault_valid": group.outcome == "crash" and group.source is not None,
                         "fault_addr": group.fault_addr,
                         "fault_source": group.source or "unavailable", "fault_image": group.image_id or "none",
                         "fault_offset": group.image_offset or 0, "hits": hits, "branches": branches,
                         "state_sha256": "none", "state_reason": "not-published", "capture_id": -1}
                pair = pair_index.get((frame.iteration, group.representative))
                if pair is not None:
                    digest = hashlib.sha256()
                    with open(pair[1], "rb") as sidecar:
                        sidecar.readline()  # Representative header is intentionally distinct.
                        for line in sidecar:
                            digest.update(line)
                    current = digest.hexdigest()
                    if write_digest is not None and current != write_digest:
                        raise ValueError("mutation representatives disagree on write set")
                    write_digest = current
                if pair is not None and group.branches is not None:
                    trace.update(state_sha256=file_sha256(pair[0]), state_reason="none",
                                 capture_id=group.representative if group.branches else -1)
                if 0 in members:
                    if group.representative != 0:
                        raise ValueError("mutation baseline must be executed representative zero")
                    baseline = trace
                traces.append((trace, members - {0}, pair))
            sidecars = [f"binradar/{Path(pair[1]).name}" for _, _, pair in traces if pair]
            self.emit("input", key=key, domain="mutation", file="none", sha256="none",
                      baseline=baseline["key"] if baseline else "none",
                      label=_label(baseline, self.request.poc_fault_reference, mutation=True),
                      mutation=sidecars[0] if sidecars else "none")
            for trace, members, pair in traces:
                self.trace(key, trace,
                           source=pair[0] if pair and trace["state_reason"] == "none" else None,
                           sidecar=f"binradar/{Path(pair[1]).name}" if pair else "none")
                if members:
                    observation = (_observation(baseline, trace, self.request.poc_fault_reference, mutation=True)
                                   if context else "unclassified")
                    self.observe(key, "mutation", trace, members, observation)
                    if observation in BINS:
                        usable.update(members)
            self.coverage(key, observed - {0}, usable, set())


def write_classification(request, root, pairs):
    """Stream per-input evidence; only per-candidate counters survive each input."""
    root = Path(root)
    selected = set(request.candidate_ids)
    candidate_ranges = encode_ids(request.candidate_ids)
    tids = {}
    manifest = root / "brpatches.json"
    family = "unsupported"
    if manifest.exists():
        family_enum, predicates = load_runtime_predicates(manifest)
        family = family_enum.value
        raw = json.loads(manifest.read_text())
        for item in raw["predicates"]:
            if item["source_line"] < 1:
                raise ValueError("invalid Taosc physical source line")
            tids[item["id"]] = item["source_line"]
        if not selected <= predicates.keys():
            raise ValueError("feedback selected candidates missing from manifest")
    files = {item.relative_to(root).as_posix(): file_sha256(item)
             for item in root.rglob("*") if item.is_file()}
    # These are Taosc source/lowering inputs, not additional synthesized outputs.
    for name in ("predicates", "destinations", "patch-location", "patch-format", "stack-size"):
        source = Path(request.workdir) / name
        if source.is_file():
            shutil.copyfile(source, root / name)
            files[name] = file_sha256(source)
    headers = {channel: read_header(request.run_dir, channel) for channel in ("baseline", "verifier")}
    terminal = {}
    for channel, header in headers.items():
        if header:
            if set(decode_ids(header["candidates"])) != selected:
                raise ValueError("feedback capture candidate universe mismatch")
            if any(header.get(name) != files.get(name) for name in ("brpatches.json", "binradar.env")):
                raise ValueError("feedback capture manifest/configuration mismatch")
            original_hash = header["context"].get("original_sha256")
            if original_hash is not None and original_hash != file_sha256(request.original_binary):
                raise ValueError("feedback original executable changed after capture")
        end = Path(request.run_dir) / "feedback-capture" / channel / "terminal.json"
        terminal[channel] = json.loads(end.read_text())["reason"] if header and end.exists() else "unavailable"
    mutation_path = Path(request.run_dir) / "feedback-capture/mutation.json"
    mutation_context = json.loads(mutation_path.read_text()) if mutation_path.exists() else None
    if mutation_context is not None:
        if (mutation_context.get("version") != VERSION
                or set(decode_ids(mutation_context["candidates"])) != selected
                or mutation_context["input_sha256"] != file_sha256(request.poc_source)
                or any(mutation_context.get(name) != files.get(name)
                       for name in ("brpatches.json", "binradar.env"))):
            raise ValueError("mutation feedback execution context mismatch")
    terminal_hard_rejects = set()
    terminal_path = Path(request.run_dir) / "verifier.br"
    if terminal_path.exists():
        _require_concrete_capture(headers)
        terminal_result = evidence.read_verifier(terminal_path)
        if set(terminal_result.patches) != selected:
            raise ValueError("terminal verifier candidate universe mismatch")
        if any(not record.has_feedback for record in terminal_result.patches.values()):
            raise ValueError(
                "Concrete verifier did not run in feedback mode; rerun "
                "MINIMIZER/VERIFIER with --feedback-mode in a new run")
        terminal_hard_rejects = {patch for patch, record in terminal_result.patches.items()
                                 if not record.feedback_accepted}
    reference = request.poc_fault_reference
    metadata = {
        "version": VERSION, "family": family, "files": files,
        "run": {"prefix": request.run_prefix, "id": request.run_id},
        "capture": headers, "terminal": terminal, "mutation_capture": mutation_context,
        "terminal_hard_rejects": encode_ids(terminal_hard_rejects),
        "oracles": {"concrete": verifier.CONCRETE_ORACLE,
                    "concrete_reference": request.poc_concrete_fault_addr,
                    "mutation_policy": request.poc_memcheck_policy,
                    "mutation_reference": ({"address": reference.address, "source": reference.source,
                                            "image": reference.image_id, "offset": reference.image_offset}
                                           if reference is not None and reference.valid else None)},
        "state": {"format": "BRCH", "version": 1, "endianness": "little", "arch": "x86_64",
                  "registers": sorted(REGISTER_TO_VAR, key=REGISTER_TO_VAR.__getitem__),
                  "branches": {"0": "original", "1": "error-handling", "2": "predicate-trap"},
                  "packing": "2-bit-lsb-first;hits=-1:unavailable;hits=0:empty",
                  "visit_labels": "unavailable", "alignment": "trace-local-order-only",
                  "offline_evaluation": "guard-values-only-not-execution-outcomes"},
        "classification": {"scope": "observed-only", "normal_requires": "known-full-branch-vector",
                           "hard_reject": ["no-crash-fail", "patch-crashed"],
                           "minimum": "crash-pass and a normal-baseline observation",
                           "bins": list(BINS)},
    }
    (root / "metadata.json").write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n")
    with (root / "feedback.sbsv").open("w", encoding="utf-8") as stream:
        writer = _Writer(request, root, stream, selected)
        writer.emit("feedback", **{"version": VERSION, "candidates": candidate_ranges,
                    "metadata": "metadata.json", "metadata-sha256": file_sha256(root / "metadata.json"),
                    "bins": ",".join(BINS), "semantics": "observed"})
        writer.concrete(headers)
        writer.mutation(pairs, mutation_context)
        for patch, domains in sorted(writer.counts.items()):
            concrete, mutation = domains["concrete"], domains["mutation"]
            values = {"id": patch, "concrete-counts": ",".join(map(str, concrete)),
                      "mutation-counts": ",".join(map(str, mutation))}
            if any(concrete[4:]) or any(mutation[4:]):
                writer.emit("excluded", reason="hard-reject", **values)
            elif patch in terminal_hard_rejects:
                writer.emit("excluded", reason="hard-reject-witness-unavailable", **values)
            elif patch not in tids:
                writer.emit("excluded", reason="unsupported-family", **values)
            else:
                writer.emit("predicate", tid=tids[patch], concrete=observed_class(concrete),
                            mutation=observed_class(mutation), **values)
        writer.emit("done", **writer.totals)
