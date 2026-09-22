#!/usr/bin/env python3
"""`--target-patches all` expands past the .brpatched compile cap only when
the .brcached artifact and its runtime manifest can execute every survivor.

.brpatched compiles a static predicate table capped at the setup-time top 30,
so an id past that cap has no entry there and silently evaluates as the false
predicate. The cached artifact resolves its predicate per run from
brpatches.json, which exports every filter survivor. These tests pin the
boundary between the two artifacts: the expansion, the artifact selection that
must follow it, and the refusal to run such an id on .brpatched.
"""

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
import binradar_artifacts

binradar_verifier = binradar.binradar_verifier


def _write_manifest(workdir, descriptors, kind="generic-erm"):
    (workdir / "brpatches.json").write_text(json.dumps({
        "version": 1,
        "kind": kind,
        "predicates": [
            {"id": idx, "source_line": idx, "descriptor": descriptor}
            for idx, descriptor in enumerate(descriptors, start=1)
        ],
    }))


def _run_main(monkeypatch, tmp_path, extra_args, env_lines, prepare=None):
    workdir = tmp_path / "workdir"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "binradar.env").write_text("".join(env_lines))
    if prepare is not None:
        prepare(workdir)
    captured = {}

    class FakeExecutor:
        def run_multithreaded(self, prefix):
            captured["run_prefix"] = prefix

    def fake_from_env(workdir_arg, env):
        captured.update(env)
        return FakeExecutor()

    monkeypatch.setattr(binradar, "setlimits", lambda: None)
    monkeypatch.setattr(binradar.signal, "signal", lambda *args: None)
    monkeypatch.setattr(binradar.os, "chdir", lambda path: None)
    monkeypatch.setattr(
        binradar.BinRadarExecutor, "from_env", staticmethod(fake_from_env))
    monkeypatch.setattr(
        sys, "argv",
        ["binradar.py", "--workdir", str(workdir)] + list(extra_args))
    binradar.main()
    return workdir, captured


_BASE_ENV = [
    'BINARY="bin"\n',
    'POC_INPUT="poc"\n',
    'TEST_CMD="./bin @@"\n',
    'PATCH_LOC="0x1234"\n',
    'TOTAL_PATCHES="30"\n',
]


def _cover_all(descriptors, kind="generic-erm"):
    def prepare(workdir):
        (workdir / "bin.brcached").write_bytes(b"cached")
        _write_manifest(workdir, descriptors, kind=kind)
    return prepare


def test_target_patches_all_expands_when_brcached_covers_every_survivor(
        tmp_path, monkeypatch):
    """32 filter survivors with a covering .brcached must all run."""
    _, captured = _run_main(
        monkeypatch, tmp_path, ["--target-patches", "all"],
        _BASE_ENV + ['FILTER_TOTAL_PATCHES="32"\n',
                     'BINRADAR_PATCH_KIND="generic-erm"\n',
                     'BRCACHE_STACK_SIZE="0"\n'],
        prepare=_cover_all(["=p0p0"] * 32))

    assert captured["TOTAL_PATCHES"] == "32"
    # The compiled cap stays visible so no phase runs an id past it on
    # .brpatched.
    assert captured["BRPATCHED_TOTAL_PATCHES"] == "30"
    assert captured["BINRADAR_TARGET_PATCHES"] == "all"
    assert captured["BINRADAR_TARGET_PATCHES_STATUS"] == "all-expanded"
    assert captured["BINRADAR_TARGET_PATCHES_REASON"] == (
        "cached artifact and manifest cover every filtered patch")
    assert "--target-patches all" in captured["BINRADAR_INVOCATION"]


def test_target_patches_all_clamps_without_a_covering_cache(
        tmp_path, monkeypatch):
    """Without .brcached the run stays clamped to the compiled set."""
    _, captured = _run_main(
        monkeypatch, tmp_path, ["--target-patches", "all"],
        _BASE_ENV + ['FILTER_TOTAL_PATCHES="32"\n',
                     'BINRADAR_PATCH_KIND="generic-erm"\n',
                     'BRCACHE_STACK_SIZE="0"\n'])

    assert captured["TOTAL_PATCHES"] == "30"
    assert captured["BRPATCHED_TOTAL_PATCHES"] == "30"
    assert captured["BINRADAR_TARGET_PATCHES"] == "all"
    assert captured["BINRADAR_TARGET_PATCHES_STATUS"] == "all-clamped"
    assert captured["BINRADAR_TARGET_PATCHES_REASON"]


def test_target_patches_all_clamps_when_manifest_is_short(
        tmp_path, monkeypatch):
    """A manifest missing past-cap ids cannot cover the survivor list."""
    _, captured = _run_main(
        monkeypatch, tmp_path, ["--target-patches", "all"],
        _BASE_ENV + ['FILTER_TOTAL_PATCHES="32"\n',
                     'BINRADAR_PATCH_KIND="generic-erm"\n',
                     'BRCACHE_STACK_SIZE="0"\n'],
        prepare=_cover_all(["=p0p0"] * 30))

    assert captured["TOTAL_PATCHES"] == "30"


def test_target_patches_all_records_within_compiled_scope(
        tmp_path, monkeypatch):
    _, captured = _run_main(
        monkeypatch, tmp_path, ["--target-patches", "all"],
        _BASE_ENV + ['FILTER_TOTAL_PATCHES="12"\n'])

    assert captured["TOTAL_PATCHES"] == "12"
    assert captured["BINRADAR_TARGET_PATCHES_STATUS"] == "all-within-compiled"
    assert captured["BINRADAR_TARGET_PATCHES_REASON"] == (
        "filtered total does not exceed compiled capacity")


def test_target_patches_top_30_records_the_compiled_cap(
        tmp_path, monkeypatch):
    _, captured = _run_main(
        monkeypatch, tmp_path, ["--target-patches", "top-30"],
        _BASE_ENV + ['FILTER_TOTAL_PATCHES="32"\n'])

    assert captured["TOTAL_PATCHES"] == "30"
    assert captured["BRPATCHED_TOTAL_PATCHES"] == "30"
    assert captured["BINRADAR_TARGET_PATCHES_STATUS"] == "top-30"
    assert captured["BINRADAR_TARGET_PATCHES_REASON"] == "requested top-30"


def test_target_patches_all_expands_under_the_smaller_compiled_set(
        tmp_path, monkeypatch):
    """The cap is whatever setup compiled, not a hard-coded 30."""
    _, captured = _run_main(
        monkeypatch, tmp_path, ["--target-patches", "all"],
        ['BINARY="bin"\n', 'POC_INPUT="poc"\n', 'TEST_CMD="./bin @@"\n',
         'PATCH_LOC="0x1234"\n', 'TOTAL_PATCHES="9"\n',
         'FILTER_TOTAL_PATCHES="12"\n',
         'BINRADAR_PATCH_KIND="CWE805-erm"\n',
         'BRCACHE_STACK_SIZE="64"\n'],
        prepare=_cover_all(["c1p0"] * 12, kind="CWE805-erm"))

    assert captured["TOTAL_PATCHES"] == "12"
    assert captured["BRPATCHED_TOTAL_PATCHES"] == "9"


@pytest.mark.parametrize(
    "descriptor,stack_size,expected",
    [
        ("c1p0", 0, "CWE805-erm"),
        ("c1s64i0", 0, None),
        ("c1s64i0", 7, None),
        ("c1s64i0", 8, "CWE805-erm"),
        ("c2s32i2q1", 11, None),
        ("c2s32i2q1", 12, "CWE805-erm"),
    ],
)
def test_cwe805_coverage_requires_only_the_used_stack_bytes(
        tmp_path, descriptor, stack_size, expected):
    """Register-only CWE-805 caches need no stack payload."""
    workdir = tmp_path / "workdir"
    workdir.mkdir(parents=True)
    (workdir / "bin.brcached").write_bytes(b"cached")
    _write_manifest(workdir, [descriptor], kind="CWE805-erm")

    coverage = binradar_verifier.load_cached_predicate_set(
        workdir / "brpatches.json", workdir / "bin.brcached",
        "CWE805-erm", stack_size, [1])

    assert (coverage.family.value if coverage.family else None) == expected
    assert (coverage.reason == "") if expected else bool(coverage.reason)


def test_artifact_selection_prefers_brcached_for_a_cached_only_survivor(
        tmp_path):
    """A lone survivor past the compile cap can only run on .brcached."""
    artifacts = binradar_artifacts.ArtifactSet(
        str(tmp_path), "bin", "generic-erm", 0, 30)
    (tmp_path / "bin.brpatched").write_bytes(b"patched")
    (tmp_path / "bin.brcached").write_bytes(b"cached")
    _write_manifest(tmp_path, ["=p0p0"] * 31)

    assert artifacts.requires_cache([31]) is True
    assert artifacts.select_verifier([31]).path == str(
        tmp_path / "bin.brcached")
    assert artifacts.select_tracer([31]).path == str(
        tmp_path / "bin.brcached")

    # A compiled survivor keeps the previous behaviour.
    assert artifacts.requires_cache([5]) is False
    assert artifacts.select_verifier([5]).path == str(
        tmp_path / "bin.brpatched")


def test_artifact_selection_refuses_an_uncovered_survivor(tmp_path):
    """Above-cap survivors without coverage fail before tracer startup."""
    artifacts = binradar_artifacts.ArtifactSet(
        str(tmp_path), "bin", "generic-erm", 0, 30)
    (tmp_path / "bin.brpatched").write_bytes(b"patched")
    (tmp_path / "bin.brcached").write_bytes(b"cached")
    _write_manifest(tmp_path, ["=p0p0"] * 30)

    with pytest.raises(binradar_artifacts.ArtifactUnavailableError):
        artifacts.select_tracer([31])








def test_verifier_never_runs_an_uncompiled_id_on_brpatched(tmp_path):
    """The verifier records no evidence for an id .brpatched cannot express."""
    runner = binradar_verifier.BinRadarQemuRunner(
        dir=str(tmp_path), binary="bin", test_cmd="-l @@", patch_loc="0x1000")
    runner.test_with_patched = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("uncompiled id must not run on .brpatched"))

    def _probe():
        return binradar_verifier.BinRadarProbeResult(
            0x1000, 0x1000, [], "ok", 1, 1, 0, [])

    (tmp_path / "run").mkdir(exist_ok=True)
    verifier = binradar_verifier.BinRadarConcreteVerifier(
        str(tmp_path), str(tmp_path / "run"), runner, _probe(),
        str(tmp_path / "bin.brpatched"), [31],
        patched_binary_patches=list(range(1, 31)))

    testcase = binradar_verifier.Testcase(0, "input", "ok", 0, [0])
    result, patch_result = verifier.run_testcase_patched(31, testcase)

    assert result is None and patch_result is None
    assert verifier.accept_evidences == {31: 0}
    assert verifier.total_evidences == {31: 0}
