"""Taosc feedback artifact export."""

import hashlib
import os
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass

import binradar_verifier
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


def _result_parsers():
    full_parsers = []
    for schema in (binradar_verifier.PROBE_RESULT_SCHEMA_V3,
                   binradar_verifier.PROBE_RESULT_SCHEMA_V2,
                   binradar_verifier.PROBE_RESULT_SCHEMA_V1):
        parser = sbsv.parser()
        parser.add_schema(
            "[testcase] [result] [id: int] [file: str] "
            + schema.removeprefix("[probe-info] ")
            + " [pid: int] [br: list[int]]")
        full_parsers.append(parser)
    legacy_parser = sbsv.parser()
    legacy_parser.add_schema(
        "[testcase] [result] [id: int] [file: str] [exit: str] "
        "[fault-addr: hex] [pid: int] [br: list[int]]")
    minimal_parser = sbsv.parser()
    minimal_parser.add_schema(
        "[testcase] [result] [id: int] [file: str] [exit: str] "
        "[fault-addr: hex]")
    return *full_parsers, legacy_parser, minimal_parser


def _parse_result_row(line: str, parsers) -> sbsv.SbsvData | None:
    for parser in parsers:
        try:
            row = parser.parse_line_detached(line)
        except ValueError:
            continue
        if row is not None and row.schema_name == "testcase$result":
            return row
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


def export_feedback(request: FeedbackExportRequest) -> None:
    """Export baseline minimizer and cached-mutation feedback for Taosc."""
    minimizer_result_file = os.path.join(request.run_dir, "minimizer.sbsv")
    if not os.path.exists(minimizer_result_file):
        raise FileNotFoundError(
            f"Minimizer result file not found: {minimizer_result_file}")

    # Version 1 classified mutation crashes against the QASAN address without
    # explicit tracer-reference validity. Never re-export that classification
    # as corrected feedback; leave historical artifacts untouched.
    mutation_feedback = os.path.join(request.run_dir, "binradar-feedback")
    if os.path.isdir(mutation_feedback):
        parser = sbsv.parser()
        parser.add_schema("[binradar-feedback] [version: int]")
        with os.scandir(mutation_feedback) as entries:
            for entry in entries:
                if not entry.name.endswith(".sbsv"):
                    continue
                with open(entry.path, "r", encoding="utf-8") as sidecar:
                    line = sidecar.readline()
                    header = parser.parse_line_detached(line)
                if header is None or header["version"] != 3:
                    raise ValueError(
                        "Mutation feedback requires fault-reference version 3; "
                        "use a fresh run rather than reclassifying archived pairs: "
                        f"{entry.path}")
                _validate_feedback_identity(line)

    request.save_progress(
        f"[feedback] [start] [prefix {request.run_prefix}] "
        f"[id {request.run_id}]")

    feedback_dir = os.path.join(request.run_dir, "feedback")
    if os.path.exists(feedback_dir):
        shutil.rmtree(feedback_dir)
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
    if os.path.isdir(mutation_feedback):
        shutil.copytree(
            mutation_feedback, os.path.join(feedback_dir, "binradar"))

    concrete_dir = os.path.join(feedback_dir, "concrete")
    benign_dir = os.path.join(concrete_dir, "benign")
    malicious_dir = os.path.join(concrete_dir, "malicious")
    os.makedirs(benign_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)

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
            if patch_hit is not None and patch_hit <= 0:
                continue

            exit_info = row["exit"]
            if exit_info == "ok":
                category = "benign"
            elif exit_info == "crash":
                reference = request.poc_fault_reference
                if reference is not None and reference.valid:
                    if (row.data.get("version") != 3
                            or row.data.get("memcheck-policy") != binradar_verifier.MEMCHECK_POLICY):
                        continue
                    observed = binradar_verifier._decode_tracer_fault_reference(row)
                    if observed is None or observed.identity_key != reference.identity_key:
                        continue
                else:
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
            copied_hashes.add(digest)
            copied_counts[category] += 1

    logger.info(
        f"[FEEDBACK] Copied concrete inputs: "
        f"benign {copied_counts['benign']}, "
        f"malicious {copied_counts['malicious']}")
    request.save_progress(
        f"[feedback] [done] [prefix {request.run_prefix}] "
        f"[id {request.run_id}]")
