#!/usr/bin/env python3
"""PATCH_TYPE / TAOSC_TOTAL_PATCHES / PREFILTER_TOTAL_PATCHES in binradar.env."""

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

_spec = importlib.util.spec_from_file_location(
    "binradar_setup", ROOT / "fuzzolic" / "binradar-setup.py")
assert _spec is not None and _spec.loader is not None
binradar_setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar_setup)

import binradar_taosc_predicates


def _fake_run(calls):
    def fake_run(cmd, cwd=None, **kwargs):
        calls.append(list(cmd))
        if "e9tool" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(
                b"\x7fELF" + b"\0" * 100)
        return subprocess.CompletedProcess(cmd, 0)
    return fake_run


def _patch_extract(monkeypatch):
    metadata = binradar_setup.E9RuntimeMetadata((), ())
    monkeypatch.setattr(
        binradar_setup, "extract_e9_runtime_metadata",
        lambda *args, **kwargs: metadata)


def _prepare_workdir(tmp_path, predicates_text="", extra=None):
    workdir = tmp_path / "workdir"
    workdir.mkdir(exist_ok=True)
    (workdir / "patch-location").write_text("410735")
    (workdir / "destinations").write_text("4106d8\n")
    if predicates_text is not None:
        (workdir / "predicates").write_text(predicates_text)
    orig = workdir / "imginfo.orig"
    orig.write_bytes(b"\x7fELF" + b"\0" * 100)
    env = {"BINARY": "imginfo", "PATCH_LOC": "0x410735"}
    if extra:
        env.update(extra)
    return workdir, env


def test_generic_env_counters_without_prefilter(tmp_path, monkeypatch):
    workdir, env = _prepare_workdir(
        tmp_path, "max1 - rax == ~max1\nmax1 / rax < +max1\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "generic-erm"
    assert env["TAOSC_TOTAL_PATCHES"] == "2"
    assert env["PREFILTER_TOTAL_PATCHES"] == "2"
    assert env["TOTAL_PATCHES"] == "2"


def test_generic_env_counters_with_prefilter(tmp_path, monkeypatch):
    workdir, env = _prepare_workdir(
        tmp_path, "max1 - rax == ~max1\nmax1 / rax < +max1\n")
    # Prefilter: line 1 branches, line 2 does not.
    sha256 = binradar_setup.predicates_sha256(workdir / "predicates")
    (workdir / "prefilter.sbsv").write_text(
        f"[prefilter] [meta] [version 1] [kind generic-erm] "
        f"[sha256 {sha256}]\n"
        "[prefilter] [res] [id 1] [pass true] [new-id 1] x\n"
        "[prefilter] [res] [id 2] [pass false] [new-id -1] y\n"
        "[prefilter] [done] [total 2] [survived 1] [time 0.00]\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "generic-erm"
    assert env["TAOSC_TOTAL_PATCHES"] == "2"
    assert env["PREFILTER_TOTAL_PATCHES"] == "1"
    assert env["TOTAL_PATCHES"] == "1"


def test_brpatches_json_exports_all_prefilter_survivors(tmp_path, monkeypatch):
    """brpatches.json keeps every prefilter survivor past the top-30 cap."""
    predicates = "\n".join("max1 - rax == ~max1" for _ in range(32)) + "\n"
    workdir, env = _prepare_workdir(tmp_path, predicates)
    sha256 = binradar_setup.predicates_sha256(workdir / "predicates")
    lines = [f"[prefilter] [meta] [version 1] [kind generic-erm] "
             f"[sha256 {sha256}]"]
    for i in range(1, 33):
        lines.append(f"[prefilter] [res] [id {i}] [pass true] "
                     f"[new-id {i}] x")
    lines.append("[prefilter] [done] [total 32] [survived 32] [time 0.00]")
    (workdir / "prefilter.sbsv").write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    # The binaries and TOTAL_PATCHES stay capped at the top 30...
    assert env["PREFILTER_TOTAL_PATCHES"] == "32"
    assert env["TOTAL_PATCHES"] == "30"
    # ...but the manifest exports all 32 prefilter survivors, consecutively
    # from id 1 so load_runtime_predicates still accepts it.
    import json
    manifest = json.loads((workdir / "brpatches.json").read_text())
    assert [row["id"] for row in manifest["predicates"]] == \
        list(range(1, 33))
    family, predicates = binradar_taosc_predicates.load_runtime_predicates(
        workdir / "brpatches.json")
    assert family is binradar_setup.PredicateFamily.GENERIC_ERM
    assert set(predicates) == set(range(1, 33))


def test_target_patches_all_compiles_every_survivor(tmp_path, monkeypatch):
    """--target-patches all compiles every prefilter survivor (no cap)."""
    predicates = "\n".join("max1 - rax == ~max1" for _ in range(32)) + "\n"
    workdir, env = _prepare_workdir(tmp_path, predicates)
    sha256 = binradar_setup.predicates_sha256(workdir / "predicates")
    lines = [f"[prefilter] [meta] [version 1] [kind generic-erm] "
             f"[sha256 {sha256}]"]
    for i in range(1, 33):
        lines.append(f"[prefilter] [res] [id {i}] [pass true] "
                     f"[new-id {i}] x")
    lines.append("[prefilter] [done] [total 32] [survived 32] [time 0.00]")
    (workdir / "prefilter.sbsv").write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(
        tmp_path, workdir, env, target_patches="all")
    assert env["TOTAL_PATCHES"] == "32"
    assert env["PREFILTER_TOTAL_PATCHES"] == "32"
    # brpatches.inc compiles every survivor, not just the top 30.
    inc = (workdir / "brpatches.inc").read_text()
    assert "case 32:" in inc
    # brpatches.json exports all 32 as well.
    import json
    manifest = json.loads((workdir / "brpatches.json").read_text())
    assert [row["id"] for row in manifest["predicates"]] == \
        list(range(1, 33))


def test_cwe805_direct_env_counters(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    trace = workdir / "trace"
    trace.mkdir(parents=True)
    (trace / "malloc.calls").write_text("0 4066e4\n")
    (trace / "malloc.returns").write_text("4066f0\n")
    (trace / "crash.address").write_text("410735")
    workdir, env = _prepare_workdir(tmp_path, None)
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "CWE805-direct"
    assert env["TAOSC_TOTAL_PATCHES"] == "1"
    assert env["PREFILTER_TOTAL_PATCHES"] == "1"
    assert env["TOTAL_PATCHES"] == "1"
    assert not (workdir / "brpatches.json").exists()


def test_specialized_env_counters(tmp_path, monkeypatch):
    workdir, env = _prepare_workdir(tmp_path, None)
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "taosc-specialized"
    # No prebuilt .brpatched and no predicates: the zero-candidate build.
    assert env["TAOSC_TOTAL_PATCHES"] == "0"
    assert env["PREFILTER_TOTAL_PATCHES"] == "0"
    assert env["TOTAL_PATCHES"] == "0"


def test_setup_persists_new_env_keys(tmp_path, monkeypatch):
    workdir, _ = _prepare_workdir(
        tmp_path, "max1 - rax == ~max1\nmax1 / rax < +max1\n")
    configdir = tmp_path
    (configdir / "config.env").write_text(
        'POC_INPUT="poc/x"\nPOC_DIR="poc"\nBINARY="imginfo"\n'
        'TEST_CMD="-l @@"\n')
    (configdir / "poc").mkdir()
    (configdir / "poc" / "x").write_text("poc")

    calls = []
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run(calls))
    _patch_extract(monkeypatch)
    binradar_env = binradar_setup.create_binradar_env(
        configdir, configdir / "config.env", workdir)
    binradar_setup.prepare_patch(configdir, workdir, binradar_env)
    binradar_setup.save_env(binradar_env, workdir / "binradar.env")

    saved = binradar_setup.load_env(workdir / "binradar.env")
    assert saved["PATCH_TYPE"] == "generic-erm"
    assert saved["TAOSC_TOTAL_PATCHES"] == "2"
    assert saved["PREFILTER_TOTAL_PATCHES"] == "2"
    assert saved["TOTAL_PATCHES"] == "2"


def test_patch_format_erm_generic_classifies_generic(tmp_path, monkeypatch):
    """patch-format 'ERM generic' drives the generic-erm family."""
    workdir, env = _prepare_workdir(
        tmp_path, "max1 - rax == ~max1\nmax1 / rax < +max1\n")
    (workdir / "patch-format").write_text("ERM generic\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "generic-erm"
    assert env["TAOSC_TOTAL_PATCHES"] == "2"


def test_patch_format_single_cwe805_classifies_direct(tmp_path, monkeypatch):
    """patch-format 'Single CWE-805' drives the CWE805-direct family."""
    workdir = tmp_path / "workdir"
    trace = workdir / "trace"
    trace.mkdir(parents=True)
    (trace / "malloc.calls").write_text("0 4066e4\n")
    (trace / "malloc.returns").write_text("4066f0\n")
    (trace / "crash.address").write_text("410735")
    workdir, env = _prepare_workdir(tmp_path, None)
    (workdir / "patch-format").write_text("Single CWE-805\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "CWE805-direct"
    assert env["TAOSC_TOTAL_PATCHES"] == "1"


def test_patch_format_single_cwe617_classifies_specialized(tmp_path, monkeypatch):
    """patch-format 'Single CWE-617' drives the taosc-specialized family."""
    workdir, env = _prepare_workdir(tmp_path, None)
    (workdir / "patch-format").write_text("Single CWE-617\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "taosc-specialized"
    assert env["TAOSC_TOTAL_PATCHES"] == "0"


def test_patch_format_erm_cwe805_classifies_erm(tmp_path, monkeypatch):
    """patch-format 'ERM CWE-805' drives the CWE805-erm family."""
    workdir = tmp_path / "workdir"
    trace = workdir / "trace"
    trace.mkdir(parents=True)
    (trace / "realloc.calls").write_text("0 486b4f\n")
    (trace / "realloc.returns").write_text("486b55\n")
    (trace / "crash.address").write_text("4d56d6")
    workdir, env = _prepare_workdir(
        tmp_path, "s->rax >= i->begin && s->rax < i->end\n")
    (workdir / "patch-format").write_text("ERM CWE-805\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env)
    assert env["PATCH_TYPE"] == "CWE805-erm"
    assert env["TAOSC_TOTAL_PATCHES"] == "1"


def test_patch_format_mismatch_rejected(tmp_path):
    """patch-format 'Single CWE-805' without an allocator trace fails."""
    workdir, _ = _prepare_workdir(tmp_path, None)
    (workdir / "patch-format").write_text("Single CWE-805\n")
    try:
        binradar_setup.detect_predicate_family(workdir)
    except ValueError as e:
        assert "no allocator trace" in str(e)
    else:
        raise AssertionError("mismatched patch-format must be rejected")