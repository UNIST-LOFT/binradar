import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

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
        f"[exit {exit_info}] [patch-loc 1000] [func-entry 2000] "
        f"[patch-hit {patch_hit}] [func-hit 1] [fault-addr {fault_addr:x}] "
        "[tracer-fault-addr 0] [patch-func-candidates []] "
        "[stacktrace []] [pid 0] [br [0]] [time 1]\n"
    )


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

    # No verifier.sbsv is needed: the classification is the PATCH_ID=0
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
    assert progress == [
        "[feedback] [start] [prefix run] [id 0]",
        "[feedback] [done] [prefix run] [id 0]",
    ]
