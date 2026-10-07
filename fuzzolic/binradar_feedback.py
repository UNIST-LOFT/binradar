"""Taosc feedback artifact export."""

import hashlib
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass

import binradar_evidence
import binradar_verifier
from binradar_taosc_predicates import parse_cached_snapshots
import logger
import sbsv


@dataclass(frozen=True)
class FeedbackExportRequest:
    workdir: str
    run_dir: str
    original_binary: str
    poc_source: str
    run_prefix: str
    run_id: int
    save_progress: Callable[[str], None]
    poc_fault_reference: binradar_verifier.TracerFaultReference | None = None
    poc_concrete_fault_addr: int | None = None
    poc_memcheck_policy: str | None = None


def _result_parsers():
    return binradar_verifier.concrete_result_parsers()


def _parse_result_row(line, parsers):
    try:
        return binradar_verifier.parse_concrete_result_row(line, parsers)
    except ValueError:
        # Export may omit malformed observations; verification must fail instead.
        return None


def _validate_feedback_identity(line: str) -> None:
    fields = dict(re.findall(r"\[([\w-]+) ([^\[\]]*)\]", line))

    def reference(prefix: str):
        valid = fields[prefix + "fault-valid"]
        if valid not in ("true", "false"):
            raise ValueError("invalid feedback fault validity")
        image, offset = binradar_verifier.decode_fault_image_fields({
            "image": fields[prefix + "fault-image"],
            "image-offset": int(fields[prefix + "fault-image-offset"], 16)})
        address = int(fields[prefix + "fault-addr"], 16)
        if valid == "false":
            if image is not None or address != 0:
                raise ValueError("unavailable feedback fault carries identity")
            return None
        result = binradar_verifier.TracerFaultReference(
            address, fields[prefix + "fault-source"], image, offset)
        if not result.valid:
            raise ValueError("invalid feedback fault source")
        return result

    try:
        observed = reference("")
        poc = reference("poc-")
        if fields["outcome"] == "normal" and observed is not None:
            raise ValueError("normal feedback outcome carries fault identity")
        expected = (fields["outcome"] == "crash" and observed is not None
                    and poc is not None and observed.identity_key == poc.identity_key)
        if fields["same-fault"] != str(expected).lower():
            raise ValueError("feedback same-fault claim disagrees with identity")
    except (KeyError, TypeError) as exc:
        raise ValueError("missing feedback fault identity fields") from exc


_PAIR_NAME = re.compile(r"iteration-([0-9]{8,10})-patch-([0-9]{8,10})\.(brch|sbsv)\Z")
_FEEDBACK_SCHEMA = (
    "[binradar-feedback] [version: int] [iteration: int] [patch: int] "
    "[snapshot-file: str] [snapshot-count: int] [branches: str] "
    "[outcome: str] [fault-addr: hex] [fault-valid: bool] [fault-source: str] "
    "[poc-fault-addr: hex] [poc-fault-valid: bool] [poc-fault-source: str] "
    "[same-fault: bool] [result: str] [mutation-writes: int] "
    "[fault-image: str] [fault-image-offset: hex] "
    "[poc-fault-image: str] [poc-fault-image-offset: hex]")
_MUTATION_SCHEMA = (
    "[binradar-mutation] [index: int] [kind: str] [addr: hex] "
    "[size: int] [value: str] [target-extent: int]")


def _validate_mutation_pair(request, pair, iteration, group, parser) -> None:
    snapshot_path, sidecar_path = pair
    with open(sidecar_path, "r", encoding="utf-8") as sidecar:
        line = sidecar.readline()
        header = parser.parse_line_detached(line)
        if header is None or header.get_name() != "binradar-feedback":
            raise ValueError(f"Invalid mutation feedback header: {sidecar_path}")
        _validate_feedback_identity(line)
        if (header["iteration"] != iteration or header["patch"] != group.representative
                or header["snapshot-file"] != os.path.basename(snapshot_path)):
            raise ValueError(f"Mutation feedback pair identity mismatch: {sidecar_path}")
        references = []
        for prefix in ("", "poc-"):
            references.append(binradar_verifier.decode_snapshot_fault_reference({
                "version": header["version"], "valid": header[prefix + "fault-valid"],
                "source": header[prefix + "fault-source"], "address": header[prefix + "fault-addr"],
                "image": header[prefix + "fault-image"],
                "image-offset": header[prefix + "fault-image-offset"]}))
        observed, poc = references
        expected_poc = request.poc_fault_reference
        expected_key = (expected_poc.identity_key
                        if expected_poc is not None and expected_poc.valid else None)
        if (poc.identity_key if poc is not None else None) != expected_key:
            raise ValueError(f"Mutation feedback POC reference mismatch: {sidecar_path}")
        expected_result = ("benign" if header["outcome"] == "normal" else
                           "malicious" if header["same-fault"] else "ignored")
        if (header["outcome"] != group.outcome or header["result"] != expected_result
                or header["fault-addr"] != group.fault_addr
                or (observed.image_id if observed is not None else None) != group.image_id
                or (observed.image_offset if observed is not None else None) != group.image_offset):
            raise ValueError(f"Mutation feedback disagrees with committed outcome: {sidecar_path}")
        writes = 0
        for line in sidecar:
            row = parser.parse_line_detached(line)
            if (row is None or row.get_name() != "binradar-mutation"
                    or row["index"] != writes or row["size"] <= 0
                    or row["kind"] not in ("bytes", "pointer-null", "pointer-oob", "pointer-fresh")
                    or (row["kind"] == "pointer-fresh" and row["value"] != "dynamic")
                    or (row["kind"] != "pointer-fresh"
                        and re.fullmatch(r"[0-9a-f]{%d}" % (2 * row["size"]), row["value"]) is None)):
                raise ValueError(f"Invalid or incomplete mutation writes: {sidecar_path}")
            writes += 1
        if writes != header["mutation-writes"]:
            raise ValueError(f"Incomplete mutation writes: {sidecar_path}")
    with open(snapshot_path, "rb") as snapshot_file:
        capture = snapshot_file.read()
    snapshots, error = parse_cached_snapshots(capture)
    # The sidecar writes `none` both when the representative recorded a null
    # vector and when it recorded an empty one; the committed frame keeps
    # that distinction, so compare the three sources with `none` ≡ empty.
    branches = [] if header["branches"] == "none" else [
        int(value) for value in header["branches"].split(",")]
    committed = [] if group.branches is None else list(group.branches)
    pair_branches = [snapshot.branch for snapshot in snapshots]
    if (error is not None or header["snapshot-count"] != len(snapshots)
            or branches != pair_branches or branches != committed
            or any(snapshot.patch_id != group.representative for snapshot in snapshots)):
        raise ValueError(f"Invalid or inconsistent BRCH pair {snapshot_path}: {error or 'vector/count/id mismatch'}")


def _committed_mutation_pairs(request: FeedbackExportRequest) -> list[tuple[str, str]]:
    """Preflight without changing source or the previous export.

    A split rename or truncated final evidence frame is an interruption remnant,
    not a published pair. Never recover it by recursively reading staging.
    """
    directory = os.path.join(request.run_dir, "binradar-feedback")
    if not os.path.isdir(directory):
        return []
    version_parser = sbsv.parser()
    version_parser.add_schema("[binradar-feedback] [version: int]")
    names = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                logger.warning(f"[FEEDBACK] Excluding unpublished/non-file entry: {entry.path}")
                continue
            if entry.name.endswith(".sbsv"):
                with open(entry.path, "r", encoding="utf-8") as sidecar:
                    header = version_parser.parse_line_detached(sidecar.readline())
                if header is None or header["version"] != 3:
                    raise ValueError(
                        "Mutation feedback requires fault-reference version 3; "
                        "use a fresh run rather than reclassifying archived pairs: " + entry.path)
            match = _PAIR_NAME.fullmatch(entry.name)
            if match is None:
                raise ValueError(f"Unrecognized mutation feedback file: {entry.path}")
            iteration, patch = int(match[1]), int(match[2])
            canonical = f"iteration-{iteration:08d}-patch-{patch:08d}.{match[3]}"
            if iteration <= 1 or max(iteration, patch) > 0xffffffff or entry.name != canonical:
                raise ValueError(f"Invalid mutation feedback file identity: {entry.path}")
            names.add(entry.name)
    candidates = {}
    for name in sorted(names):
        if not name.endswith(".sbsv"):
            if name[:-5] + ".sbsv" not in names:
                logger.warning(f"[FEEDBACK] Skipping interrupted split pair: {directory}/{name}")
            continue
        peer = name[:-5] + ".brch"
        if peer not in names:
            logger.warning(f"[FEEDBACK] Skipping interrupted split pair: {directory}/{name}")
            continue
        match = _PAIR_NAME.fullmatch(name)
        assert match is not None
        candidates[int(match[1]), int(match[2])] = (
            os.path.join(directory, peer), os.path.join(directory, name))
    if not candidates:
        return []
    if request.poc_memcheck_policy != binradar_verifier.MEMCHECK_POLICY:
        raise ValueError("Mutation feedback requires current memcheck policy; use a fresh run")
    parser = sbsv.parser()
    parser.add_schema(_FEEDBACK_SCHEMA)
    parser.add_schema(_MUTATION_SCHEMA)
    pairs = []
    for frame in binradar_evidence.read_binradar(os.path.join(request.run_dir, "binradar.br")):
        for group in frame.groups:
            pair = candidates.pop((frame.iteration, group.representative), None)
            if pair is not None:
                _validate_mutation_pair(request, pair, frame.iteration, group, parser)
                pairs.append(pair)
    for pair in candidates.values():
        logger.warning(f"[FEEDBACK] Skipping pair without a committed representative: {pair[1]}")
    return pairs


def export_feedback(request: FeedbackExportRequest) -> None:
    """Export baseline minimizer and cached-mutation feedback for Taosc."""
    minimizer_result_file = os.path.join(request.run_dir, "minimizer.sbsv")
    if not os.path.exists(minimizer_result_file):
        raise FileNotFoundError(
            f"Minimizer result file not found: {minimizer_result_file}")

    mutation_pairs = _committed_mutation_pairs(request)

    request.save_progress(
        f"[feedback] [start] [prefix {request.run_prefix}] "
        f"[id {request.run_id}]")

    feedback_dir = os.path.join(request.run_dir, "feedback")
    # Only the final directory is consumable. Interruption during copying can
    # leave a hidden staging directory, never a split pair under feedback/.
    with tempfile.TemporaryDirectory(prefix=".feedback-", dir=request.run_dir) as staging:
        staged_bundle = os.path.join(staging, "bundle")
        _write_feedback_bundle(request, staged_bundle, mutation_pairs)
        if os.path.exists(feedback_dir):
            shutil.rmtree(feedback_dir)
        os.replace(staged_bundle, feedback_dir)
    request.save_progress(
        f"[feedback] [done] [prefix {request.run_prefix}] "
        f"[id {request.run_id}]")


def _write_feedback_bundle(request: FeedbackExportRequest, feedback_dir: str,
                           mutation_pairs: list[tuple[str, str]]) -> None:
    minimizer_result_file = os.path.join(request.run_dir, "minimizer.sbsv")
    os.makedirs(feedback_dir)
    shutil.copyfile(
        os.path.join(request.workdir, "binradar.env"),
        os.path.join(feedback_dir, "binradar.env"))
    shutil.copyfile(
        request.original_binary,
        os.path.join(feedback_dir, os.path.basename(request.original_binary)))

    poc_relative = os.path.relpath(request.poc_source, request.workdir)
    if (poc_relative == os.pardir
            or poc_relative.startswith(os.pardir + os.sep)):
        poc_relative = os.path.join(
            "poc", os.path.basename(request.poc_source))
    poc_destination = os.path.join(feedback_dir, poc_relative)
    os.makedirs(os.path.dirname(poc_destination), exist_ok=True)
    shutil.copyfile(request.poc_source, poc_destination)

    manifest = os.path.join(request.workdir, "brpatches.json")
    if os.path.exists(manifest):
        shutil.copyfile(manifest, os.path.join(feedback_dir, "brpatches.json"))
    if os.path.isdir(os.path.join(request.run_dir, "binradar-feedback")):
        mutation_destination = os.path.join(feedback_dir, "binradar")
        os.makedirs(mutation_destination)
        for pair in mutation_pairs:
            for source in pair:
                shutil.copyfile(source, os.path.join(
                    mutation_destination, os.path.basename(source)))

    concrete_dir = os.path.join(feedback_dir, "concrete")
    benign_dir = os.path.join(concrete_dir, "benign")
    malicious_dir = os.path.join(concrete_dir, "malicious")
    os.makedirs(benign_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)
    with open(os.path.join(concrete_dir, "oracle.sbsv"), "w", encoding="utf-8") as oracle:
        reference = request.poc_concrete_fault_addr
        oracle.write(
            f"[concrete-feedback] [version 1] [oracle {binradar_verifier.CONCRETE_ORACLE}] "
            f"[poc-fault-valid {'true' if reference is not None else 'false'}] "
            f"[poc-fault-addr {reference if reference is not None else 0:x}]\n")

    parsers = _result_parsers()
    copied_hashes = set()
    copied_counts = {"benign": 0, "malicious": 0}
    minimized_dir = os.path.join(request.run_dir, "minimized")
    with open(minimizer_result_file, "r", encoding="utf-8") as result_file:
        for line_number, line in enumerate(result_file, start=1):
            row = _parse_result_row(line, parsers)
            if row is None:
                continue

            patch_hit = row.data.get("patch-hit")
            if patch_hit is None or patch_hit <= 0:
                continue

            exit_info = row["exit"]
            if (row.data.get("version") != 4
                    or row.data.get("concrete-oracle") != binradar_verifier.CONCRETE_ORACLE):
                continue
            if exit_info == "ok":
                category = "benign"
            elif exit_info == "crash":
                # Concrete inputs were run by QASAN, not the symbolic tracer.
                # Require the independently recorded oracle/validity on both
                # observations; never promote a historical bare fault-addr or
                # use a tracer finding to attest a concrete crash.
                if (request.poc_concrete_fault_addr is None
                        or binradar_verifier.concrete_fault_addr_from_row(row) is None
                        or row["fault-addr"] != request.poc_concrete_fault_addr):
                    continue
                category = "malicious"
            else:
                continue

            filename = os.path.basename(row["file"])
            source = os.path.join(minimized_dir, filename)
            try:
                with open(source, "rb") as source_file:
                    data = source_file.read()
            except OSError as exc:
                logger.warning(
                    f"[FEEDBACK] Skipping missing testcase {source} "
                    f"from minimizer line {line_number}: {exc}")
                continue

            digest = hashlib.sha256(data).hexdigest()
            if digest in copied_hashes:
                continue

            destination_dir = (
                benign_dir if category == "benign" else malicious_dir)
            destination = os.path.join(destination_dir, filename)
            if os.path.exists(destination):
                destination = os.path.join(
                    destination_dir, f"{row['id']}_{filename}")
            shutil.copyfile(source, destination)
            with open(os.path.join(concrete_dir, "results.sbsv"), "a", encoding="utf-8") as diagnostics:
                diagnostics.write(line if line.endswith("\n") else line + "\n")
            copied_hashes.add(digest)
            copied_counts[category] += 1

    logger.info(
        f"[FEEDBACK] Copied concrete inputs: "
        f"benign {copied_counts['benign']}, "
        f"malicious {copied_counts['malicious']}")
