import importlib.util
import json
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


def _feedback_executor(tmp_path):
    workdir = tmp_path / "workdir"
    run_dir = workdir / "out" / "run-00000"
    (run_dir / "minimized").mkdir(parents=True)
    (workdir / "poc").mkdir()
    (workdir / "poc" / "input").write_bytes(b"poc")
    (workdir / "binradar.env").write_text("BINARY=target\n")
    (workdir / "brpatches.json").write_text(json.dumps({"version": 1}))
    (workdir / "target.orig").write_bytes(b"original")

    executor = binradar.BinRadarExecutor.__new__(
        binradar.BinRadarExecutor)
    executor.workdir = str(workdir)
    executor.run_dir = str(run_dir)
    executor.binary = "target"
    executor.artifacts = SimpleNamespace(
        original=str(workdir / "target.orig"))
    executor.poc_input = "poc/input"
    executor.probe_result = SimpleNamespace(fault_addr=0x1234)
    executor.run_prefix = "run"
    executor.run_id = 0
    progress = []
    executor.save_progress = progress.append
    return executor, run_dir, progress


def _full_row(testcase_id, filename, exit_info, fault_addr, patch_hit=1):
    return (
        f"[testcase] [result] [id {testcase_id}] [file {filename}] "
        f"[version 2] [exit {exit_info}] [patch-loc 1000] [func-entry 2000] "
        f"[patch-hit {patch_hit}] [func-hit 1] [fault-addr {fault_addr:x}] "
        "[tracer-fault-valid false] [tracer-fault-source unavailable] "
        "[tracer-fault-addr 0] [patch-func-candidates []] "
        "[stacktrace []] [pid 0] [br [0]] [time 1]\n"
    )


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


def test_feedback_uses_minimizer_baseline_rows_only_and_deduplicates(tmp_path):
    executor, run_dir, progress = _feedback_executor(tmp_path)
    minimized = run_dir / "minimized"
    (minimized / "0_benign").write_bytes(b"benign")
    (minimized / "1_malicious").write_bytes(b"malicious")
    (minimized / "2_other-fault").write_bytes(b"other")
    (minimized / "3_duplicate").write_bytes(b"benign")
    (minimized / "4_no-hit").write_bytes(b"no-hit")
    (minimized / "5_timeout").write_bytes(b"timeout")
    (minimized / "6_legacy").write_bytes(b"legacy")

    mutation_feedback = run_dir / "binradar-feedback"
    mutation_feedback.mkdir()
    (mutation_feedback / "iteration-00000002-patch-00000001.brch").write_bytes(
        b"BRCH-snapshot")
    # A realistic symbolic-advisor pair: the sidecar carries the complete
    # applied plan, including the synthesized value, so the copy must preserve
    # every mutation row byte for byte and not just the header.
    symbolic_sidecar = (
        "[binradar-feedback] [version 2] [iteration 2] [patch 1] "
        "[snapshot-file iteration-00000002-patch-00000001.brch] "
        "[snapshot-count 1] [branches 1] [outcome normal] [fault-addr 0] "
        "[fault-valid false] [fault-source unavailable] "
        "[poc-fault-addr 1234] [poc-fault-valid true] "
        "[poc-fault-source guest-signal] [same-fault false] [result benign] "
        "[mutation-writes 1]\n"
        "[binradar-mutation] [index 0] [kind bytes] [addr 404080] [size 4] "
        "[value 00100000] [target-extent 0]\n"
    )
    (mutation_feedback / "iteration-00000002-patch-00000001.sbsv").write_text(
        symbolic_sidecar)

    (run_dir / "minimizer.sbsv").write_text(
        _full_row(0, "0_benign", "ok", 0)
        + _full_row(1, "1_malicious", "crash", 0x1234)
        + _full_row(2, "2_other-fault", "crash", 0x5678)
        + _full_row(3, "3_duplicate", "ok", 0)
        + _full_row(4, "4_no-hit", "ok", 0, patch_hit=0)
        + _full_row(5, "5_timeout", "timeout", 0)
        + "[testcase] [result] [id 6] [file 6_legacy] [exit ok] "
        "[fault-addr 0] [pid 0] [br [0]] [time 1]\n"
    )

    # No verifier.br is needed: the classification is the PATCH_ID=0
    # result already serialized by the minimizer.
    executor.run_feedback()

    benign = executor.run_dir
    assert (Path(benign) / "feedback" / "concrete" / "benign" /
            "0_benign").read_bytes() == b"benign"
    assert (Path(benign) / "feedback" / "concrete" / "benign" /
            "6_legacy").read_bytes() == b"legacy"
    assert (Path(benign) / "feedback" / "concrete" / "malicious" /
            "1_malicious").read_bytes() == b"malicious"
    assert sorted(
        path.name for path in
        (Path(benign) / "feedback" / "concrete" / "benign").iterdir()
    ) == ["0_benign", "6_legacy"]
    assert sorted(
        path.name for path in
        (Path(benign) / "feedback" / "concrete" / "malicious").iterdir()
    ) == ["1_malicious"]
    assert (Path(benign) / "feedback" / "poc" / "input").read_bytes() == b"poc"
    assert (Path(benign) / "feedback" / "binradar" /
            "iteration-00000002-patch-00000001.brch").read_bytes() == \
        b"BRCH-snapshot"
    copied_sidecar = (Path(benign) / "feedback" / "binradar" /
                      "iteration-00000002-patch-00000001.sbsv").read_text()
    assert copied_sidecar == symbolic_sidecar
    assert "[binradar-mutation] [index 0] [kind bytes] [addr 404080] " \
        "[size 4] [value 00100000]" in copied_sidecar
    assert progress == [
        "[feedback] [start] [prefix run] [id 0]",
        "[feedback] [done] [prefix run] [id 0]",
    ]
