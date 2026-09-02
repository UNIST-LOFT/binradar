#!/usr/bin/env python3
"""Tests for disabling the optional BinRadar phase."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
_spec = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec is not None
assert _spec.loader is not None
binradar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar)


def _stub_executor(tmp_path):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.run_dir = str(tmp_path)
    executor.run_prefix = "run"
    executor.run_id = 0
    executor.progress_filename = str(tmp_path / "progress.sbsv")
    executor.start_time = __import__("time").time()
    executor.probe_result = SimpleNamespace()
    executor.filter_result = [1, 2]
    executor.disable_binradar = True
    return executor


def test_disabled_binradar_skips_execution(tmp_path):
    executor = _stub_executor(tmp_path)
    executor.check_requirements = lambda: (_ for _ in ()).throw(
        AssertionError("disabled BinRadar must not check execution requirements"))

    executor.run_binradar()

    assert not (tmp_path / "binradar-tracer-msg.log").exists()


def test_disabled_binradar_final_uses_concrete_result_without_trace(tmp_path):
    (tmp_path / "verifier.sbsv").write_text(
        "[verifier-result] [res verified] [patch 1] [testcase ]\n"
        "[verifier-result] [res rejected] [patch 2] [testcase testcase]\n"
    )
    executor = _stub_executor(tmp_path)
    progress = []
    executor.save_progress = progress.append

    executor.run_final()

    final_text = (tmp_path / "final.sbsv").read_text()
    assert "[final] [verifier] [patch 1] [res verified]" in final_text
    assert "[final] [verifier] [patch 2] [res rejected]" in final_text
    assert "[final] [binradar]" not in final_text
    assert "[remaining_patches [1]]" in final_text
    assert "[binradar_remaining_patches [1]]" in final_text
    assert "binradar-tracer-msg.log" not in final_text
    assert any(row.startswith("[final] [done]") for row in progress)


def test_verifier_binary_uses_cached_artifact_for_multiple_patches(tmp_path):
    executor = _stub_executor(tmp_path)
    executor.workdir = str(tmp_path)
    executor.binary = "imginfo"
    (tmp_path / "imginfo.brpatched").write_bytes(b"patched")
    (tmp_path / "imginfo.brcached").write_bytes(b"cached")

    executor.filter_result = [1, 2]
    assert executor.verifier_binary() == str(tmp_path / "imginfo.brcached")

    executor.filter_result = [1]
    assert executor.verifier_binary() == str(tmp_path / "imginfo.brpatched")

    executor.filter_result = [1, 2]
    (tmp_path / "imginfo.brcached").unlink()
    assert executor.verifier_binary() == str(tmp_path / "imginfo.brpatched")


def _write_generic_manifest(workdir, descriptors):
    (workdir / "brpatches.json").write_text(json.dumps({
        "version": 1,
        "kind": "generic-erm",
        "predicates": [
            {"id": idx, "source_line": idx, "descriptor": descriptor}
            for idx, descriptor in enumerate(descriptors, start=1)
        ],
    }))


def _filter_executor(tmp_path, workdir, total_patches):
    executor = _stub_executor(tmp_path)
    executor.workdir = str(workdir)
    executor.total_patches = total_patches
    executor.probe_result = SimpleNamespace(fault_addr=0xDEAD)
    executor.check_requirements = lambda: None
    executor.resolved_poc_input = lambda: str(workdir / "poc")
    executor.extract_config = lambda: {}
    progress = []
    executor.save_progress = progress.append
    return executor


def test_filter_uses_cached_execution_for_equivalent_predicates(
        tmp_path, monkeypatch):
    """The filter runs one representative per distinct branch vector on
    .brcached and reuses its result for equivalent predicates.

    With zero registers, "=p1p0" and "=p2p0" are false (branch 0, no jump
    -> original crash) and "=p0p0" is true (branch 1, jump -> fixed).
    Patches 1 and 3 share the crash vector, so patch 3 is judged offline
    from patch 1's run; only patch 2 needs its own cached run.
    """
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "imginfo.brcached").write_bytes(b"cache")
    _write_generic_manifest(workdir, ["=p1p0", "=p0p0", "=p2p0"])

    executor = _filter_executor(tmp_path, workdir, 3)

    class FakeRunner:
        patch_kind = "generic-erm"
        brcache_stack_size = 0

        def __init__(self):
            self.cached_calls = []
            self.patched_calls = []

        def cached_binary(self):
            return str(workdir / "imginfo.brcached")

        def test_with_cached(self, patch_id, predicate, testcase):
            self.cached_calls.append((patch_id, predicate))
            branch = 1 if predicate == "=p0p0" else 0
            snapshot = binradar.binradar_verifier.CachedSnapshot(
                patch_id=0, branch=branch, registers=(0,) * 16)
            if branch == 1:
                result = SimpleNamespace(
                    fault_addr=0, patch_hit_cnt=1,
                    is_crash=lambda: False, is_normal_exit=lambda: True,
                    is_timeout=lambda: False, exit_info="ok")
            else:
                result = SimpleNamespace(
                    fault_addr=0xDEAD, patch_hit_cnt=1,
                    is_crash=lambda: True, is_normal_exit=lambda: False,
                    is_timeout=lambda: False, exit_info="crash")
            return result, binradar.binradar_verifier.BinRadarCachedRun(
                patch_id, [snapshot])

        def test_with_patched(self, patch_id, testcase):
            self.patched_calls.append(int(patch_id))
            result = SimpleNamespace(
                fault_addr=0, is_crash=lambda: False,
                is_normal_exit=lambda: True, is_timeout=lambda: False,
                exit_info="ok")
            return result, binradar.binradar_verifier.BinRadarPatchResult(
                int(patch_id), [0])

    runner = FakeRunner()
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner, "from_env",
        lambda *args, **kwargs: runner)

    survived = executor.run_filter()

    # Two cached runs for three patches; no individual executions.  Patch 3
    # reuses patch 1's crash result and is filtered out with it.
    assert survived == [2]
    assert runner.cached_calls == [(1, "=p1p0"), (2, "=p0p0")]
    assert runner.patched_calls == []
    rows = (tmp_path / "filter.sbsv").read_text()
    assert "[patch] [id 1] [pass False]" in rows
    assert "[patch] [id 2] [pass True]" in rows
    assert "[patch] [id 3] [pass False]" in rows
    assert executor.filter_result == [2]


def test_filter_falls_back_to_individual_execution_when_cache_fails(
        tmp_path, monkeypatch):
    """A failed cached run falls back to the individual .brpatched run."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "imginfo.brcached").write_bytes(b"cache")
    _write_generic_manifest(workdir, ["=p1p0", "=p0p0"])

    executor = _filter_executor(tmp_path, workdir, 2)

    class BrokenCacheRunner:
        patch_kind = "generic-erm"
        brcache_stack_size = 0

        def __init__(self):
            self.cached_calls = []
            self.patched_calls = []

        def cached_binary(self):
            return str(workdir / "imginfo.brcached")

        def test_with_cached(self, patch_id, predicate, testcase):
            self.cached_calls.append((patch_id, predicate))
            return None, None

        def test_with_patched(self, patch_id, testcase):
            self.patched_calls.append(int(patch_id))
            result = SimpleNamespace(
                fault_addr=0, is_crash=lambda: False,
                is_normal_exit=lambda: True, is_timeout=lambda: False,
                exit_info="ok")
            return result, binradar.binradar_verifier.BinRadarPatchResult(
                int(patch_id), [0])

    runner = BrokenCacheRunner()
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner, "from_env",
        lambda *args, **kwargs: runner)

    survived = executor.run_filter()

    assert survived == [1, 2]
    assert runner.cached_calls == [(1, "=p1p0"), (2, "=p0p0")]
    assert runner.patched_calls == [1, 2]
    rows = (tmp_path / "filter.sbsv").read_text()
    assert "[patch] [id 1] [pass True]" in rows
    assert "[patch] [id 2] [pass True]" in rows


def test_disabled_binradar_is_not_started_by_multithreaded_orchestration(
        tmp_path, monkeypatch):
    executor = _stub_executor(tmp_path)
    events = []
    monkeypatch.setattr(binradar.logger, "set_file", lambda _: None)
    executor.set_run_dir = lambda run_prefix="run": events.append(
        ("set", run_prefix))
    executor.run_probe = lambda: events.append(("probe",))
    executor.run_filter = lambda: (events.append(("filter",)) or [1])
    executor.run_fuzzolic = lambda: events.append(("fuzzolic",))
    executor.run_directed = lambda: events.append(("directed",))
    executor.run_fuzzer = lambda: events.append(("fuzzer",))
    executor.run_minimizer_and_verifier = lambda: events.append(("min-ver",))
    executor.run_final = lambda: events.append(("final",))
    executor.done = lambda: events.append(("done",))

    executor.run_multithreaded()

    assert ("binradar",) not in events
    assert ("final",) in events
    assert events[-1] == ("done",)
