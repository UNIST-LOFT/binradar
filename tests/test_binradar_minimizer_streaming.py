#!/usr/bin/env python3
"""Tests for the streaming minimizer.

The minimizer discovers atomically published testcase files while producer
phases run, executes immutable byte snapshots, propagates producer failures,
cancels on verifier errors, and keeps standalone snapshot behavior.
"""

import importlib.util
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_fuzzer
import binradar_minimizer
import binradar_utils
import binradar_verifier

_spec_bin = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec_bin is not None
assert _spec_bin.loader is not None
binradar = importlib.util.module_from_spec(_spec_bin)
_spec_bin.loader.exec_module(binradar)


def _probe(exit_info="ok", fault_addr=0x1234):
    return binradar_verifier.BinRadarProbeResult(
        patch_loc=0x1000, patch_func_entry=0x2000, stacktrace=[],
        exit_info=exit_info, patch_hit_cnt=1, patch_func_hit_cnt=1,
        fault_addr=fault_addr, patch_func_candidates=[], tracer_fault_addr=0)


def _patch_result():
    return binradar_verifier.BinRadarPatchResult(0, [0])


class StubQemuRunner:
    """Stands in for BinRadarQemuRunner inside the minimizer/verifier."""

    def __init__(self):
        self.calls = []  # (testcase path, wall time)
        self.input_bytes = []

    def test_with_patched(self, patch_id, testcase, verbose=False):
        self.calls.append((testcase, time.time()))
        self.input_bytes.append(Path(testcase).read_bytes())
        return _probe(), _patch_result()

    def patched_binary(self):
        return "nm.brpatched"

    def cached_binary(self):
        return "nm.brcached"


@pytest.fixture
def stub_runner_env(monkeypatch):
    stub = StubQemuRunner()
    monkeypatch.setattr(
        binradar_verifier.BinRadarQemuRunner, "from_env",
        staticmethod(lambda dir, env: stub))
    return stub


def _publish(path: Path, data: bytes) -> None:
    partial = Path(f"{path}.binradar-part")
    partial.write_bytes(data)
    partial.replace(path)


def _make_minimizer(tmp_path, testcase_dirs, **kwargs):
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    return binradar_minimizer.BinRadarMinimizer(
        str(tmp_path), str(run_dir), _probe(), testcase_dirs, {}, **kwargs)


def _make_verifier(tmp_path):
    runner = binradar_verifier.BinRadarQemuRunner(
        dir=str(tmp_path), binary="nm", test_cmd="-l @@", patch_loc="0x1000")
    runner.test_with_patched = \
        lambda patch_id, testcase, verbose=False: (_probe(), _patch_result())
    return binradar_verifier.BinRadarConcreteVerifier(
        str(tmp_path), str(tmp_path / "run"), runner, _probe(),
        "nm.brpatched", [1])


def test_default_min_file_age_is_10s(tmp_path):
    minimizer = _make_minimizer(tmp_path, [])
    assert minimizer.min_file_age == 10.0


def test_scan_defers_recent_files_while_producers_alive(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    testcases = tmp_path / "tests"
    testcases.mkdir()
    recent = testcases / "recent.dat"
    recent.write_bytes(b"recent")
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=60.0)

    # While producers run, a file younger than min_file_age is deferred.
    minimizer.scan_testcases(producers_alive=True)
    assert len(minimizer.testcases) == 0
    assert len(minimizer.pending) == 0

    # The final scan (producers done) skips the age guard.
    minimizer.scan_testcases(producers_alive=False)
    assert len(minimizer.testcases) == 1
    assert len(minimizer.pending) == 1

    # Already-seen files are not queued twice.
    minimizer.scan_testcases(producers_alive=False)
    assert len(minimizer.pending) == 1


def test_scan_picks_old_files_immediately(tmp_path):
    testcases = tmp_path / "tests"
    testcases.mkdir()
    old_file = testcases / "old.dat"
    old_file.write_bytes(b"old")
    stale = time.time() - 120
    os.utime(old_file, (stale, stale))
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=60.0)

    minimizer.scan_testcases(producers_alive=True)
    assert len(minimizer.pending) == 1


def test_vanished_file_is_retried_while_producers_alive(tmp_path):
    testcases = tmp_path / "tests"
    testcases.mkdir()
    ghost = testcases / "ghost.dat"
    ghost.write_bytes(b"ghost")
    stale = time.time() - 120
    os.utime(ghost, (stale, stale))
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=1.0)

    removed = threading.Event()

    def remove_between_glob_and_open():
        # Simulate a file disappearing between the glob and the read.
        real_glob = __import__("glob").glob

        def fake_glob(pattern):
            result = real_glob(pattern)
            if result and not removed.is_set():
                removed.set()
                os.unlink(ghost)
            return result

        __import__("glob").glob = fake_glob
        try:
            minimizer.scan_testcases(producers_alive=True)
        finally:
            __import__("glob").glob = real_glob

    remove_between_glob_and_open()
    assert len(minimizer.testcases) == 0
    # The file is gone; a later scan finds nothing and does not crash.
    minimizer.scan_testcases(producers_alive=False)
    assert len(minimizer.testcases) == 0


def test_standalone_processes_all_without_age_guard(tmp_path, stub_runner_env):
    testcases = tmp_path / "tests"
    testcases.mkdir()
    (testcases / "a.dat").write_bytes(b"aaa")  # fresh mtime
    (testcases / "b.dat").write_bytes(b"bbb")
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=60.0)

    minimizer.load_testcases()
    assert len(minimizer.testcases) == 2
    minimizer.run_testcases()

    assert len(stub_runner_env.calls) == 2
    assert len(os.listdir(minimizer.minimized_dir)) == 2
    assert "[minimizer] [done]" in (tmp_path / "run" / "minimizer.sbsv").read_text()


def test_standalone_minimizer_enforces_phase_timeout(tmp_path, monkeypatch):
    testcases = tmp_path / "tests"
    testcases.mkdir()
    (testcases / "a.dat").write_bytes(b"aaa")
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=0.0)
    minimizer.load_testcases()

    class SlowRunner(StubQemuRunner):
        def test_with_patched(self, patch_id, testcase, verbose=False):
            time.sleep(0.05)
            return super().test_with_patched(patch_id, testcase, verbose)

    monkeypatch.setattr(
        binradar_verifier.BinRadarQemuRunner, "from_env",
        staticmethod(lambda dir, env: SlowRunner()))

    with pytest.raises(TimeoutError, match="Minimizer phase timed out"):
        minimizer.run_testcases(timeout=0.01)

    assert "[minimizer] [done]" not in \
        (tmp_path / "run" / "minimizer.sbsv").read_text()


def test_standalone_verifier_enforces_phase_timeout(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    minimized = run_dir / "minimized"
    minimized.mkdir()
    (minimized / "0_case.dat").write_bytes(b"aaa")
    minimizer_log = run_dir / "minimizer.sbsv"
    minimizer_log.write_text(
        "[testcase] [result] [id 0] [file 0_case.dat] [exit ok] "
        "[fault-addr 1234] [pid 0] [br [0]]\n"
        "[minimizer] [done] [time 0]\n")

    verifier = _make_verifier(tmp_path)

    def slow_test(patch_id, testcase, verbose=False):
        time.sleep(0.05)
        return _probe(), _patch_result()

    verifier.runner.test_with_patched = slow_test
    with pytest.raises(TimeoutError, match="Verifier phase timed out"):
        verifier.run_verification_streaming(
            str(minimizer_log), timeout=0.01)

    assert "[verifier-result]" not in (run_dir / "verifier.sbsv").read_text()


def test_dedup_across_dirs(tmp_path, stub_runner_env):
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()
    (d1 / "x.dat").write_bytes(b"same")
    (d2 / "y.dat").write_bytes(b"same")
    minimizer = _make_minimizer(tmp_path, [str(d1), str(d2)], min_file_age=0.0)

    minimizer.load_testcases()
    minimizer.run_testcases()
    assert len(stub_runner_env.calls) == 1


def test_partial_publication_names_are_ignored(tmp_path):
    testcases = tmp_path / "tests"
    testcases.mkdir()
    (testcases / "case.dat.binradar-part").write_bytes(b"partial")
    (testcases / "README.txt").write_bytes(b"AFL metadata")
    (testcases / "case.dat").write_bytes(b"complete")
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=0.0)

    minimizer.load_testcases()

    assert [case.data for case in minimizer.pending] == [b"complete"]


def test_atomic_replacement_of_same_path_is_discovered(tmp_path):
    testcases = tmp_path / "tests"
    testcases.mkdir()
    testcase = testcases / "case.dat"
    _publish(testcase, b"first")
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=0.0)

    minimizer.scan_testcases()
    assert [case.data for case in minimizer.pending] == [b"first"]
    minimizer.pending.clear()
    _publish(testcase, b"second")
    minimizer.scan_testcases()

    assert [case.data for case in minimizer.pending] == [b"second"]


def test_minimizer_executes_and_saves_scanned_snapshot(
        tmp_path, stub_runner_env):
    testcases = tmp_path / "tests"
    testcases.mkdir()
    source = testcases / "case.dat"
    source.write_bytes(b"scanned-bytes")
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=0.0)

    minimizer.load_testcases()
    source.write_bytes(b"producer-mutated-source")
    # Isolate processing of the already captured version; normal streaming
    # discovery would correctly queue the atomic replacement as another case.
    minimizer.testcases_dirs = []
    minimizer.run_testcases()

    assert stub_runner_env.input_bytes == [b"scanned-bytes"]
    saved = list(Path(minimizer.minimized_dir).iterdir())
    assert len(saved) == 1
    assert saved[0].read_bytes() == b"scanned-bytes"


def test_streaming_waits_for_atomic_publication(tmp_path, stub_runner_env):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    testcases = tmp_path / "tests"
    testcases.mkdir()
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=0.0)
    verifier = _make_verifier(tmp_path)
    published = threading.Event()

    def producer():
        partial = testcases / "case.dat.binradar-part"
        partial.write_bytes(b"incomplete")
        time.sleep(0.15)
        partial.write_bytes(b"complete")
        partial.replace(testcases / "case.dat")
        published.set()
        time.sleep(0.05)

    thread = threading.Thread(target=producer)
    thread.start()
    binradar_minimizer.run_minimizer_and_verifier(
        minimizer, verifier, str(run_dir / "minimizer.sbsv"),
        poll_interval=0.01, producer_threads=[thread])
    thread.join()

    assert published.is_set()
    assert stub_runner_env.input_bytes == [b"complete"]


def test_streaming_minimizer_and_verifier(tmp_path, stub_runner_env):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d1 = tmp_path / "fuzzolic-tests"
    d1.mkdir()
    minimizer = _make_minimizer(tmp_path, [str(d1)], min_file_age=0.2)
    verifier = _make_verifier(tmp_path)

    def producer():
        for i in range(5):
            time.sleep(0.15)
            _publish(d1 / f"tc_{i}.dat", f"data-{i}".encode())

    thread = threading.Thread(target=producer)
    thread.start()
    binradar_minimizer.run_minimizer_and_verifier(
        minimizer, verifier, str(run_dir / "minimizer.sbsv"),
        poll_interval=0.05, producer_threads=[thread])
    thread.join()

    # Files written while the producer was still running were all picked up.
    assert len(stub_runner_env.calls) == 5
    assert len(os.listdir(minimizer.minimized_dir)) == 5
    assert "[minimizer] [done]" in (run_dir / "minimizer.sbsv").read_text()
    # The verifier consumed the streamed rows and verified patch 1.
    assert len(verifier.testcases) == 5
    verifier_log = (run_dir / "verifier.sbsv").read_text()
    assert "[verifier-result] [res verified] [patch 1]" in verifier_log


def test_queued_producer_failure_aborts(tmp_path, stub_runner_env):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    testcases = tmp_path / "tests"
    testcases.mkdir()
    (testcases / "tc.dat").write_bytes(b"data")
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=0.2)
    verifier = _make_verifier(tmp_path)

    exc_queue = queue.Queue()
    exc_queue.put(RuntimeError("directed failed"))
    with pytest.raises(RuntimeError, match="directed failed"):
        binradar_minimizer.run_minimizer_and_verifier(
            minimizer, verifier, str(run_dir / "minimizer.sbsv"),
            poll_interval=0.05, producer_threads=[],
            producer_exc_queue=exc_queue)
    assert "[minimizer] [done]" not in (run_dir / "minimizer.sbsv").read_text()


def test_producer_thread_failure_propagates(tmp_path, stub_runner_env):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    d1 = tmp_path / "fuzzolic-tests"
    d1.mkdir()
    minimizer = _make_minimizer(tmp_path, [str(d1)], min_file_age=0.2)
    verifier = _make_verifier(tmp_path)
    exc_queue = queue.Queue()

    def producer():
        for i in range(3):
            time.sleep(0.1)
            _publish(d1 / f"tc_{i}.dat", f"data-{i}".encode())
        exc_queue.put(RuntimeError("fuzzer exploded"))

    thread = threading.Thread(target=producer)
    thread.start()
    with pytest.raises(RuntimeError, match="fuzzer exploded"):
        binradar_minimizer.run_minimizer_and_verifier(
            minimizer, verifier, str(run_dir / "minimizer.sbsv"),
            poll_interval=0.05, producer_threads=[thread],
            producer_exc_queue=exc_queue)
    thread.join()
    assert "[minimizer] [done]" not in (run_dir / "minimizer.sbsv").read_text()


def test_verifier_failure_cancels_minimizer_waiting_for_producer(
        tmp_path, stub_runner_env):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    testcases = tmp_path / "tests"
    testcases.mkdir()
    minimizer = _make_minimizer(tmp_path, [str(testcases)], min_file_age=0.0)
    stop = threading.Event()

    def producer():
        stop.wait(timeout=5)

    producer_thread = threading.Thread(target=producer)
    producer_thread.start()

    class FailingVerifier:
        def run_verification_streaming(self, *args, **kwargs):
            raise ValueError("verifier failed")

    start = time.monotonic()
    with pytest.raises(ValueError, match="verifier failed"):
        binradar_minimizer.run_minimizer_and_verifier(
            minimizer, FailingVerifier(), str(run_dir / "minimizer.sbsv"),
            poll_interval=0.01, producer_threads=[producer_thread])
    elapsed = time.monotonic() - start

    stop.set()
    producer_thread.join()
    assert elapsed < 1.0
    assert not any(t.name == "minimizer" and t.is_alive()
                   for t in threading.enumerate())
    assert "[minimizer] [done]" not in \
        (run_dir / "minimizer.sbsv").read_text()


def _stub_executor(tmp_path):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.workdir = str(tmp_path)
    executor.outdir = str(tmp_path / "out")
    executor.timeout = 10
    executor.binary = "nm"
    executor.poc_input = "poc"
    executor.test_cmd = "-l @@"
    executor.patch_loc = "0x1000"
    executor.e9_metadata_prefix = "brpatched"
    executor.e9_exclude_ranges = ""
    executor.e9_relocated_calls = ""
    executor.total_patches = 1
    executor.fuzzy = False
    executor.reverse_directed = False
    executor.disable_binradar = True
    executor.config = {}
    executor.progress_filename = str(tmp_path / "out" / "progress.sbsv")
    executor.previous_progress = None
    executor.start_time = time.time()
    executor.probe_result = SimpleNamespace(fault_addr=0x1234)
    executor.filter_result = [1]
    executor.run_id = -1
    executor.run_prefix = ""
    executor.run_dir = ""
    return executor


def test_fuzzer_paths_do_not_create_output_directory(tmp_path):
    outdir = tmp_path / "not-created"

    paths = binradar_fuzzer.AFLppFuzzer.testcase_dirs_for_outdir(str(outdir))

    assert paths == [str(outdir / "default" / "queue"),
                     str(outdir / "default" / "crashes")]
    assert not outdir.exists()


def test_prepare_fuzzer_output_removes_stale_cases(tmp_path):
    executor = _stub_executor(tmp_path)
    executor.run_dir = str(tmp_path / "run")
    stale = Path(executor.fuzzer_outdir()) / "default" / "queue" / "stale"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")

    executor.prepare_fuzzer_output()

    assert Path(executor.fuzzer_outdir()).is_dir()
    assert not stale.exists()
    assert executor._fuzzer_output_prepared is True


def test_run_fuzzer_rejects_unexpected_exit(tmp_path, monkeypatch):
    executor = _stub_executor(tmp_path)
    executor.run_dir = str(tmp_path / "run")
    Path(executor.run_dir).mkdir()
    executor.check_requirements = lambda: None
    executor.extract_config = lambda: {}
    progress = []
    executor.save_progress = progress.append
    process = object()
    fake = SimpleNamespace(
        process=process,
        start=lambda: process,
        wait=lambda timeout: binradar_utils.ExecutionResult(
            True, 7, "", ""))
    monkeypatch.setattr(
        binradar_fuzzer.AFLppFuzzer, "from_env",
        staticmethod(lambda workdir, outdir, config: fake))

    with pytest.raises(RuntimeError, match="status 7"):
        executor.run_fuzzer()

    assert not any("[fuzzer] [done]" in row for row in progress)
    assert process not in binradar.RUNNING_PROCESSES


def test_run_fuzzer_accepts_configured_timeout(tmp_path, monkeypatch):
    executor = _stub_executor(tmp_path)
    executor.run_dir = str(tmp_path / "run")
    Path(executor.run_dir).mkdir()
    executor.check_requirements = lambda: None
    executor.extract_config = lambda: {}
    progress = []
    executor.save_progress = progress.append
    process = object()
    fake = SimpleNamespace(
        process=process,
        start=lambda: process,
        wait=lambda timeout: binradar_utils.ExecutionResult(
            False, -15, "", "", timed_out=True))
    monkeypatch.setattr(
        binradar_fuzzer.AFLppFuzzer, "from_env",
        staticmethod(lambda workdir, outdir, config: fake))

    executor.run_fuzzer()

    assert any("[fuzzer] [done]" in row for row in progress)
    assert process not in binradar.RUNNING_PROCESSES


def test_solver_wait_rejects_nonzero_exit():
    solver = binradar.SolverExecutor.__new__(binradar.SolverExecutor)
    solver.mode = "test"
    solver.timeout = 1
    solver.process = subprocess.Popen(["sh", "-c", "exit 7"])

    _, succeeded = solver.wait()

    assert succeeded is False
    assert solver.process.returncode == 7


def test_run_multithreaded_starts_minimizer_while_producers_run(
        tmp_path, stub_runner_env, monkeypatch):
    """The minimizer must process producer testcases while fuzzolic is still
    running instead of waiting for it to finish."""

    # Keep the file-age guard short so the test does not need 10s.
    real_minimizer = binradar_minimizer.BinRadarMinimizer

    class FastMinimizer(real_minimizer):
        def __init__(self, *args, **kwargs):
            kwargs["min_file_age"] = 0.2
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(binradar_minimizer, "BinRadarMinimizer", FastMinimizer)
    fuzzer_queue = tmp_path / "fuzzer-out" / "default" / "queue"
    monkeypatch.setattr(
        binradar_fuzzer.AFLppFuzzer, "from_env",
        staticmethod(lambda workdir, outdir, config: SimpleNamespace(
            get_testcase_dirs=lambda: [str(fuzzer_queue)])))

    executor = _stub_executor(tmp_path)
    events = []
    executor.run_probe = lambda: None
    executor.run_filter = lambda: [1]
    executor.check_requirements = lambda: None
    executor.run_directed = lambda: None
    executor.run_fuzzer = lambda: None
    executor.run_final = lambda: events.append("final")
    executor.done = lambda: events.append("done")

    def run_fuzzolic():
        fuzz_tests = Path(executor.run_dir) / "fuzzolic-tests"
        fuzz_tests.mkdir(parents=True, exist_ok=True)
        for i in range(10):
            time.sleep(0.3)
            _publish(fuzz_tests / f"tc_{i}.dat", f"data-{i}".encode())
        events.append(("fuzzolic_done", time.time()))

    executor.run_fuzzolic = run_fuzzolic

    binradar.BinRadarExecutor.run_multithreaded(executor)

    calls = stub_runner_env.calls
    # Both the minimizer and the verifier run on the stubbed runner: the
    # minimizer executes the hard-linked .cur_input, the verifier the
    # minimized copies.
    minimizer_calls = [c for c in calls if ".cur_input" in c[0]]
    verifier_calls = [c for c in calls if "/minimized/" in c[0]]
    assert len(minimizer_calls) == 10
    assert len(verifier_calls) == 10
    fuzzolic_done_time = next(t for name, t in events if name == "fuzzolic_done")
    # The first testcase was already minimized while fuzzolic was running.
    assert minimizer_calls[0][1] < fuzzolic_done_time
    assert len(os.listdir(Path(executor.run_dir) / "minimized")) == 10
    assert "[minimizer] [done]" in \
        (Path(executor.run_dir) / "minimizer.sbsv").read_text()
    verifier_log = (Path(executor.run_dir) / "verifier.sbsv").read_text()
    assert "[verifier-result] [res verified] [patch 1]" in verifier_log
    assert "final" in events and "done" in events