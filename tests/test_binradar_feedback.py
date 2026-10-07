import importlib.util
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None and _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)

import binradar_evidence as evidence
import binradar_taosc_predicates as predicates
from test_binradar_evidence import _frame, _group


def _feedback_executor(tmp_path):
    workdir = tmp_path / "workdir"
    run_dir = workdir / "out" / "run-00000"
    (run_dir / "minimized").mkdir(parents=True)
    (workdir / "poc").mkdir()
    (workdir / "poc" / "input").write_bytes(b"poc")
    (workdir / "binradar.env").write_text("BINARY=target\n")
    (workdir / "brpatches.json").write_text(json.dumps({"version": 1}))
    (workdir / "target.orig").write_bytes(b"original")
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.workdir = str(workdir)
    executor.run_dir = str(run_dir)
    executor.binary = "target"
    executor.artifacts = SimpleNamespace(original=str(workdir / "target.orig"))
    executor.poc_input = "poc/input"
    executor.probe_result = SimpleNamespace(
        fault_addr=0x1234, concrete_fault_addr=0x1234, memcheck_policy="coverage-v2",
        tracer_fault_reference=binradar.binradar_verifier.TracerFaultReference(
            0x1234, "guest-signal"))
    executor.run_prefix = "run"
    executor.run_id = 0
    progress = []
    executor.save_progress = progress.append
    return executor, run_dir, progress


def _full_row(testcase_id, filename, exit_info, fault_addr, patch_hit=1, version=4):
    return (
        f"[testcase] [result] [id {testcase_id}] [file {filename}] "
        f"[version {version}] [exit {exit_info}] [patch-loc 1000] [func-entry 2000] "
        f"[patch-hit {patch_hit}] [func-hit 1] [fault-addr {fault_addr:x}] "
        "[tracer-fault-valid false] [tracer-fault-source unavailable] [tracer-fault-addr 0] "
        + ("[tracer-fault-image none] [tracer-fault-image-offset 0] "
           "[memcheck-policy unavailable] " if version in (3, 4) else "")
        + "[patch-func-candidates []] [stacktrace []] "
        + (f"[concrete-oracle {'qasan-main-v2' if version == 4 else 'qasan-main-v1'}] [concrete-fault-valid {'true' if exit_info == 'crash' else 'false'}] "
           if version in (3, 4) else "")
        + (f"[raw-fault-addr {fault_addr:x}] [concrete-fault-source {'native' if exit_info == 'crash' else 'unavailable'}] "
           if version == 4 else "")
        + "[pid 0] [br [0]] [time 1]\n")


def _pair(run_dir, iteration=2, patch=1, branches=(1,), *, outcome="normal", fault=0, writes=True):
    directory = run_dir / "binradar-feedback"
    directory.mkdir(exist_ok=True)
    stem = f"iteration-{iteration:08d}-patch-{patch:08d}"
    capture = b"".join(
        predicates.CACHED_SNAPSHOT_HEADER.pack(
            predicates.CACHED_SNAPSHOT_MAGIC, predicates.CACHED_SNAPSHOT_VERSION,
            patch, branch, 0, 0) + predicates.CACHED_SNAPSHOT_REGS.pack(*range(16))
        for branch in branches or ())
    (directory / (stem + ".brch")).write_bytes(capture)
    same = outcome == "crash" and fault == 0x1234
    valid = outcome == "crash" and fault != 0
    result = "benign" if outcome == "normal" else "malicious" if same else "ignored"
    header = (
        f"[binradar-feedback] [version 3] [iteration {iteration}] [patch {patch}] "
        f"[snapshot-file {stem}.brch] [snapshot-count {len(branches or ())}] "
        f"[branches {'none' if branches is None else ','.join(map(str, branches)) if branches else 'none'}] "
        f"[outcome {outcome}] [fault-addr {fault:x}] "
        f"[fault-valid {'true' if valid else 'false'}] "
        f"[fault-source {'provenance-access' if valid else 'unavailable'}] "
        "[poc-fault-addr 1234] [poc-fault-valid true] [poc-fault-source guest-signal] "
        f"[same-fault {'true' if same else 'false'}] [result {result}] "
        f"[mutation-writes {int(writes)}] "
        "[fault-image none] [fault-image-offset 0] "
        "[poc-fault-image none] [poc-fault-image-offset 0]\n")
    body = ("[binradar-mutation] [index 0] [kind bytes] [addr 404080] [size 4] "
            "[value 00100000] [target-extent 0]\n") if writes else ""
    (directory / (stem + ".sbsv")).write_text(header + body)
    return directory / (stem + ".brch"), directory / (stem + ".sbsv")


def _commits(run_dir, frames, *, truncated_tail=False):
    baseline = struct.pack("<II", 1, 1) + _group(0, 1, 0, [0], [0])
    data = struct.pack("<8sHHI", b"BRDATAB1", 3, 3, 0) + _frame(4, baseline)
    for iteration, groups in frames:
        data += _frame(4, struct.pack("<II", iteration, len(groups)) + b"".join(groups))
    if truncated_tail:
        data += struct.pack("<IHH", 50, 4, 0) + b"partial"
    (run_dir / "binradar.br").write_bytes(data)


def test_feedback_rejects_legacy_mutation_classification_without_overwrite(tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    mutation = run_dir / "binradar-feedback"
    mutation.mkdir()
    sidecar = mutation / "iteration-00000002-patch-00000001.sbsv"
    legacy = "[binradar-feedback] [version 1] [result malicious]\n"
    sidecar.write_text(legacy)
    existing = run_dir / "feedback"
    existing.mkdir()
    (existing / "keep").write_bytes(b"historical")
    with pytest.raises(ValueError, match="fresh run"):
        executor.run_feedback()
    assert sidecar.read_text() == legacy
    assert (existing / "keep").read_bytes() == b"historical"


def test_concrete_feedback_classifies_actual_oracle_not_tracer_and_deduplicates(tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    executor.probe_result.tracer_fault_reference = None
    cases = [
        ("benign", "ok", 0, 1, 4), ("malicious", "crash", 0x1234, 1, 4),
        ("other", "crash", 0x5678, 1, 4), ("duplicate", "ok", 0, 1, 4),
        ("no-hit", "ok", 0, 0, 4), ("timeout", "timeout", 0, 1, 4),
        ("old-crash", "crash", 0x1234, 1, 2)]
    rows = []
    for index, (name, outcome, fault, hit, version) in enumerate(cases):
        filename = f"{index}_{name}"
        (run_dir / "minimized" / filename).write_bytes(b"benign" if name == "duplicate" else name.encode())
        rows.append(_full_row(index, filename, outcome, fault, hit, version))
    rows.insert(0, _full_row(99, "1_malicious", "crash", 0x1234).replace(
        "[fault-addr 1234]", "[fault-addr nothex]"))
    (run_dir / "minimizer.sbsv").write_text("".join(rows))
    executor.run_feedback()
    concrete = run_dir / "feedback" / "concrete"
    assert {p.name for p in (concrete / "benign").iterdir()} == {"0_benign"}
    assert {p.name for p in (concrete / "malicious").iterdir()} == {"1_malicious"}
    assert (concrete / "malicious" / "1_malicious").read_bytes() == b"malicious"


@pytest.mark.parametrize("oracle,valid,poc", [
    ("unavailable", "true", 0x1234), ("older-qasan", "true", 0x1234),
    ("qasan-main-v1", "false", 0x1234), (None, None, 0x1234),
    ("qasan-main-v1", "true", None)])
def test_concrete_feedback_requires_both_oracle_observations(tmp_path, oracle, valid, poc):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    executor.probe_result.concrete_fault_addr = poc
    (run_dir / "minimized" / "input").write_bytes(b"fault")
    row = _full_row(0, "input", "crash", 0x1234)
    extension = "[concrete-oracle qasan-main-v2] [concrete-fault-valid true] "
    row = row.replace(extension, "" if oracle is None else
                      f"[concrete-oracle {oracle}] [concrete-fault-valid {valid}] ")
    # A matching valid tracer reference cannot authorize this concrete row.
    (run_dir / "minimizer.sbsv").write_text(row)
    executor.run_feedback()
    assert list((run_dir / "feedback/concrete/malicious").iterdir()) == []


def test_feedback_only_exports_current_proved_identity_and_retains_raw(tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    rows = []
    cases = [("mapped", 4, "relocated", 0x9000),
             ("helper", 4, "unavailable", 0x9010),
             ("invalid-native", 4, "native", 0x9000),
             ("historical-crash", 3, None, 0x1234),
             ("historical-normal", 3, None, 0)]
    for index, (name, version, source, raw) in enumerate(cases):
        (run_dir / "minimized" / name).write_bytes(name.encode())
        outcome = "ok" if name == "historical-normal" else "crash"
        row = _full_row(index, name, outcome, 0x1234, version=version)
        if source is not None:
            row = row.replace("[raw-fault-addr 1234]", f"[raw-fault-addr {raw:x}]").replace(
                "[concrete-fault-source native]", f"[concrete-fault-source {source}]")
        rows.append(row)
    (run_dir / "minimizer.sbsv").write_text("".join(rows))
    executor.run_feedback()
    concrete = run_dir / "feedback/concrete"
    assert {p.name for p in (concrete / "malicious").iterdir()} == {"mapped"}
    assert list((concrete / "benign").iterdir()) == []
    assert "[raw-fault-addr 9000] [concrete-fault-source relocated]" in (concrete / "results.sbsv").read_text()


def test_explicit_qasan_pc_zero_exports_but_absent_address_does_not(tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    verifier = binradar.binradar_verifier
    common = ("[patch-info] [set true] [location 1000]\n"
              "[patch-cov] [location 1000] [covered true] [hits 1]\n"
              "[qemu-exit] [kind crash] [detail target crash]\n[exit] [result crash]\n")
    probe = verifier.BinRadarProbeResult.from_log(common + "[fault-addr] [idx 0] [addr 0] [symbol target]\n")
    executor.probe_result.concrete_fault_addr = probe.concrete_fault_addr
    rows = []
    for index, log in enumerate((common + "[fault-addr] [idx 0] [addr 0] [symbol target]\n", common)):
        result = verifier.BinRadarProbeResult.from_log(log)
        name = f"{index}_zero"
        (run_dir / "minimized" / name).write_bytes(bytes([index]))
        rows.append(f"[testcase] [result] [id {index}] [file {name}] {result.serialize()} [pid 0] [br [0]]\n")
    (run_dir / "minimizer.sbsv").write_text("".join(rows))
    executor.run_feedback()
    assert {p.name for p in (run_dir / "feedback/concrete/malicious").iterdir()} == {"0_zero"}


def test_mutation_export_excludes_staging_splits_uncommitted_and_inferred_members(tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    good = _pair(run_dir)
    _pair(run_dir, patch=2)  # committed member, but not an executed representative
    _pair(run_dir, iteration=3)  # only an incomplete final evidence frame
    _pair(run_dir, iteration=4)  # no commit
    brch_only = _pair(run_dir, iteration=5)
    brch_only[1].unlink()
    sbsv_only = _pair(run_dir, iteration=6)
    sbsv_only[0].unlink()
    staging = run_dir / "binradar-feedback/.staging-123"
    staging.mkdir()
    (staging / good[0].name).write_bytes(good[0].read_bytes())
    (staging / good[1].name).write_text("[binradar-feedback] [version 1]\n")
    _commits(run_dir, [(2, [_group(1, 1, 0, [1], [1, 2])])], truncated_tail=True)
    sources = {p: p.read_bytes() for p in (run_dir / "binradar-feedback").rglob("*") if p.is_file()}
    executor.run_feedback()
    exported = run_dir / "feedback/binradar"
    assert {p.name for p in exported.iterdir()} == {p.name for p in good}
    assert all(p.read_bytes() == data for p, data in sources.items())
    assert (exported / good[1].name).read_bytes() == good[1].read_bytes()


def test_committed_empty_capture_is_a_complete_pair(tmp_path):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    pair = _pair(run_dir, branches=(), outcome="crash", writes=False)
    _commits(run_dir, [(2, [_group(1, 2, 0, [], [1])])])
    executor.run_feedback()
    assert (run_dir / "feedback/binradar" / pair[0].name).read_bytes() == b""
    assert (run_dir / "feedback/binradar" / pair[1].name).exists()


def test_pair_copy_failure_never_publishes_split_export(tmp_path, monkeypatch):
    executor, run_dir, progress = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    _, sidecar = _pair(run_dir)
    _commits(run_dir, [(2, [_group(1, 1, 0, [1], [1])])])
    previous = run_dir / "feedback"
    previous.mkdir()
    (previous / "keep").write_bytes(b"previous complete export")
    original_copy = binradar.binradar_feedback.shutil.copyfile

    def fail_second_file(source, destination, **kwargs):
        if Path(source) == sidecar:
            raise OSError("interrupted pair copy")
        return original_copy(source, destination, **kwargs)

    monkeypatch.setattr(binradar.binradar_feedback.shutil, "copyfile", fail_second_file)
    with pytest.raises(OSError):
        executor.run_feedback()
    assert {p.name for p in previous.iterdir()} == {"keep"}
    assert (previous / "keep").read_bytes() == b"previous complete export"
    assert not any("[done]" in line for line in progress)
    assert list(run_dir.glob(".feedback-*")) == []


@pytest.mark.parametrize("branches,group_branches,accepted", [
    (None, None, True), (None, [0], False), ([], [0], False), ([], [], True)])
def test_committed_null_branch_vector_must_match(tmp_path, branches, group_branches, accepted):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    pair = _pair(run_dir, branches=branches, outcome="crash", writes=False)
    _commits(run_dir, [(2, [_group(1, 2, 0, group_branches, [1])])])
    if accepted:
        executor.run_feedback()
        assert (run_dir / "feedback/binradar" / pair[1].name).exists()
    else:
        with pytest.raises(ValueError):
            executor.run_feedback()
        assert not (run_dir / "feedback").exists()


@pytest.mark.parametrize("committed_offset", [0x123, 0x124])
def test_mutation_dso_identity_uses_image_offset_not_raw_poc_pc(tmp_path, committed_offset):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    image = "12" * 32
    executor.probe_result.tracer_fault_reference = binradar.binradar_verifier.TracerFaultReference(
        0x7000123, "provenance-access", image, 0x123)
    brch, sidecar = _pair(run_dir, outcome="crash", fault=0x9000123)
    sidecar.write_text(sidecar.read_text().replace(
        "[fault-image none] [fault-image-offset 0]",
        f"[fault-image {image}] [fault-image-offset 123]").replace(
        "[poc-fault-addr 1234]", "[poc-fault-addr 7000123]").replace(
        "[poc-fault-image none] [poc-fault-image-offset 0]",
        f"[poc-fault-image {image}] [poc-fault-image-offset 123]").replace(
        "[same-fault false] [result ignored]", "[same-fault true] [result malicious]"))
    group = bytearray(_group(1, 2, 0x9000123, [1], [1]))
    group[5] |= 2
    header_size = evidence.BINRADAR_GROUP_STRUCT.size
    group[header_size:header_size] = bytes.fromhex(image) + struct.pack("<Q", committed_offset)
    _commits(run_dir, [(2, [bytes(group)])])
    if committed_offset == 0x123:
        executor.run_feedback()
        assert (run_dir / "feedback/binradar" / sidecar.name).read_bytes() == sidecar.read_bytes()
    else:
        with pytest.raises(ValueError):
            executor.run_feedback()
        assert not (run_dir / "feedback").exists()


@pytest.mark.parametrize("defect", [
    "partial-brch", "count", "branches", "filename", "writes", "classification",
    "committed-outcome", "poc-reference", "checksum", "old-policy"])
def test_malformed_committed_pair_preserves_source_and_previous_export(tmp_path, defect):
    executor, run_dir, _ = _feedback_executor(tmp_path)
    (run_dir / "minimizer.sbsv").write_text("")
    brch, sidecar = _pair(run_dir)
    _commits(run_dir, [(2, [_group(1, 1, 0, [1], [1])])])
    if defect == "partial-brch":
        brch.write_bytes(brch.read_bytes()[:-1])
    elif defect in ("count", "branches", "filename", "writes", "classification", "poc-reference"):
        old, new = {
            "count": ("[snapshot-count 1]", "[snapshot-count 2]"),
            "branches": ("[branches 1]", "[branches 0]"),
            "filename": (f"[snapshot-file {brch.name}]", "[snapshot-file other.brch]"),
            "writes": ("[mutation-writes 1]", "[mutation-writes 2]"),
            "classification": ("[result benign]", "[result malicious]"),
            "poc-reference": ("[poc-fault-addr 1234]", "[poc-fault-addr 5678]"),
        }[defect]
        sidecar.write_text(sidecar.read_text().replace(old, new))
    elif defect == "committed-outcome":
        _commits(run_dir, [(2, [_group(1, 2, 0x4321, [1], [1])])])
    elif defect == "checksum":
        data = bytearray((run_dir / "binradar.br").read_bytes())
        data[-1] ^= 1
        (run_dir / "binradar.br").write_bytes(data)
    else:
        executor.probe_result.memcheck_policy = "coverage-v1"
    existing = run_dir / "feedback"
    existing.mkdir()
    (existing / "keep").write_bytes(b"historical")
    sources = (brch.read_bytes(), sidecar.read_bytes())
    with pytest.raises(ValueError):
        executor.run_feedback()
    assert (existing / "keep").read_bytes() == b"historical"
    assert (brch.read_bytes(), sidecar.read_bytes()) == sources
