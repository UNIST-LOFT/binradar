"""Behavioral coverage for BinRadar progress and run records."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "binradar_run_records", ROOT / "fuzzolic" / "binradar_run_records.py")
assert _spec is not None and _spec.loader is not None
binradar_run_records = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar_run_records)


def test_progress_loads_latest_matching_run_and_phase_flags(tmp_path):
    progress_file = tmp_path / "progress.sbsv"
    progress_file.write_text(
        "[rundir] [set] [prefix run] [id 0] [dir /tmp/run-0]\n"
        "[probe] [done] [prefix run] [id 0]\n"
        "[rundir] [set] [prefix other] [id 99] [dir /tmp/other]\n"
        "[rundir] [set] [prefix run] [id 2] [dir /tmp/run-2]\n"
        "[probe] [done] [prefix run] [id 2]\n"
        "[fuzzer] [done] [prefix run] [id 2]\n"
        "[minimizer] [done] [prefix run] [id 2]\n"
        "[verifier] [done] [prefix run] [id 2]\n"
        "[rundir] [done] [prefix run] [id 2] [dir /tmp/run-2]\n"
    )

    progress = binradar_run_records.BinRadarProgress.from_progress_file(
        "run", str(progress_file))

    assert progress == binradar_run_records.BinRadarProgress(
        run_id=2,
        run_dir="/tmp/run-2",
        probe_done=True,
        fuzzolic_done=False,
        directed_done=False,
        fuzzer_done=True,
        minimizer_done=True,
        verifier_done=True,
        done=True,
    )


def test_run_directory_selection_preserves_new_and_last_semantics(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir()
    progress_file = outdir / "progress.sbsv"
    progress_file.write_text(
        f"[rundir] [set] [prefix run] [id 4] "
        f"[dir {outdir / 'run-00004'}]\n"
    )
    store = binradar_run_records.RunRecordStore(
        str(outdir), str(progress_file), 0.0)

    previous, run_id, run_dir = store.select_run_directory("run", False)
    assert previous is not None and previous.run_id == 4
    assert run_id == 5
    assert run_dir == str(outdir / "run-00005")
    assert Path(run_dir).is_dir()

    previous, run_id, run_dir = store.select_run_directory("run", True)
    assert previous is not None and previous.run_id == 5
    assert run_id == 5
    assert run_dir == str(outdir / "run-00005")

    rows = progress_file.read_text().splitlines()
    assert "[rundir] [set] [prefix run] [id 5]" in rows[-1]
    assert "[time " in rows[-1]
