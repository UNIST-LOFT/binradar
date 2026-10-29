#!/usr/bin/env python3
"""PATCH_TYPE / TAOSC_TOTAL_PATCHES / FILTER_TOTAL_PATCHES in binradar.env."""

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from binradar import binradar_setup

from binradar import binradar_taosc_predicates


@pytest.fixture(autouse=True)
def _e9_executables(monkeypatch):
    monkeypatch.setenv("E9TOOL", "/bin/true")
    monkeypatch.setenv("E9COMPILE", "/bin/false")


def _fake_run(calls):
    def fake_run(cmd, cwd=None, **kwargs):
        calls.append(list(cmd))
        if cmd[0] == "/bin/true":
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


def test_setup_predicate_snapshot_preserves_source_lines_and_exact_digest(tmp_path):
    import hashlib

    data = b"\r\nrax\v==+max1\r\n\r\nrbx==+max1\r"
    workdir, _ = _prepare_workdir(tmp_path)
    (workdir / "patch-format").write_text("ERM generic\n")
    (workdir / "predicates").write_bytes(data)

    loaded = binradar_setup.load_setup_predicates(workdir)
    assert loaded.sha256 == hashlib.sha256(data).hexdigest()
    assert [(r.runtime_id, r.source_line, r.parsed) for r in loaded.records] == [
        (1, 2, "==v0p0p0"), (2, 4, "==v1p0p0")]


def test_generic_env_counters_without_filter(tmp_path, monkeypatch):
    workdir, env = _prepare_workdir(
        tmp_path, "max1 - rax == ~max1\nmax1 / rax < +max1\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
    assert env["PATCH_TYPE"] == "generic-erm"
    assert env["TAOSC_TOTAL_PATCHES"] == "2"
    assert env["FILTER_TOTAL_PATCHES"] == "2"
    assert env["TOTAL_PATCHES"] == "2"


def test_generic_env_counters_with_survivor_selection(tmp_path, monkeypatch):
    workdir, env = _prepare_workdir(
        tmp_path, "\nrax == +max1\n\nrbx == +max1\nrcx == +max1\n")
    loaded = binradar_setup.load_setup_predicates(workdir)
    # A previous invocation's result must not override current decisions.
    (workdir / "filter.sbsv").write_text("stale filter\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env, loaded, [2, 3])
    assert env["PATCH_TYPE"] == "generic-erm"
    assert env["TAOSC_TOTAL_PATCHES"] == "3"
    assert env["FILTER_TOTAL_PATCHES"] == "2"
    assert env["TOTAL_PATCHES"] == "2"
    import json
    manifest = json.loads((workdir / "brpatches.json").read_text())
    assert manifest["predicates"] == [
        {"id": 1, "source_line": 4, "descriptor": "==v1p0p0"},
        {"id": 2, "source_line": 5, "descriptor": "==v2p0p0"},
    ]


def test_setup_filter_probes_original_and_uses_cached_representatives(
        tmp_path, monkeypatch):
    """Setup filters real POC outcomes and reuses equivalent cache vectors."""
    workdir, env = _prepare_workdir(
        tmp_path,
        "max1 - rax == ~max1\nmax1 / rax < +max1\n"
        "max1 - rax == ~max1\n",
        extra={
            "POC_INPUT": "poc/input",
            "TEST_CMD": "-l @@",
            "BINRADAR_PATCH_KIND": "generic-erm",
            "TOTAL_PATCHES": "3",
            "BRCACHE_STACK_SIZE": "0",
        },
    )
    poc = workdir / "poc" / "input"
    poc.parent.mkdir()
    poc.write_bytes(b"poc")

    predicates = {1: "=p1p0", 2: "=p0p0", 3: "=p2p0"}
    monkeypatch.setattr(
        binradar_setup.binradar_verifier,
        "load_cached_predicate_set",
        lambda *args, **kwargs: SimpleNamespace(
            predicates=predicates, reason=""),
    )

    class FakeProbe:
        fault_addr = 0xDEAD

        def patch_hit(self):
            return True

        def is_crash(self):
            return True

        def patch_func_hit(self):
            return True

        def multi_patch_func(self):
            return False

    class FakeRunner:
        def __init__(self):
            self.cached_calls = []

        def test_with_original(self, testcase):
            assert testcase == str(poc)
            return FakeProbe()

        def test_with_cached(self, patch_id, predicate, testcase):
            self.cached_calls.append((patch_id, predicate))
            branch = 1 if predicate == "=p0p0" else 0
            snapshot = binradar_setup.binradar_verifier.CachedSnapshot(
                patch_id=0, branch=branch, registers=(0,) * 16)
            result = SimpleNamespace(
                fault_addr=(0 if branch else 0xDEAD),
                is_crash=lambda: not branch,
            )
            cached = binradar_setup.binradar_verifier.BinRadarCachedRun(
                patch_id, [snapshot])
            return result, cached

        def test_with_patched(self, patch_id, testcase):
            raise AssertionError("valid cached observations must not fall back")

    runner = FakeRunner()
    monkeypatch.setattr(
        binradar_setup.binradar_verifier.BinRadarQemuRunner,
        "from_env", staticmethod(lambda *args, **kwargs: runner))

    survived = binradar_setup.run_setup_filter(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))

    assert survived == [2]
    assert runner.cached_calls == [(1, "=p1p0"), (2, "=p0p0")]
    assert env["FILTER_TOTAL_PATCHES"] == "1"
    assert binradar_taosc_predicates.load_filter_passed_ids(
        workdir / "filter.sbsv",
        expected_kind="generic-erm",
        expected_sha256=binradar_taosc_predicates.predicates_sha256(
            workdir / "predicates"),
    ) == {2: 1}


def test_brpatches_json_exports_all_filter_survivors(tmp_path, monkeypatch):
    """brpatches.json keeps every filter survivor past the top-30 cap."""
    predicates = "\n".join("max1 - rax == ~max1" for _ in range(34)) + "\n"
    workdir, env = _prepare_workdir(tmp_path, predicates)
    loaded = binradar_setup.load_setup_predicates(workdir)
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(
        tmp_path, workdir, env, loaded, list(range(2, 34)))
    assert env["TAOSC_TOTAL_PATCHES"] == "34"
    # The binaries and TOTAL_PATCHES stay capped at the top 30...
    assert env["FILTER_TOTAL_PATCHES"] == "32"
    assert env["TOTAL_PATCHES"] == "30"
    # ...but the manifest exports all 32 filter survivors, consecutively
    # from id 1 so load_runtime_predicates still accepts it.
    import json
    manifest = json.loads((workdir / "brpatches.json").read_text())
    assert [(row["id"], row["source_line"]) for row in manifest["predicates"]] == \
        list(enumerate(range(2, 34), start=1))
    family, predicates = binradar_taosc_predicates.load_runtime_predicates(
        workdir / "brpatches.json")
    assert family is binradar_setup.PredicateFamily.GENERIC_ERM
    assert set(predicates) == set(range(1, 33))





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

    binradar_setup.prepare_patch(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
    assert env["PATCH_TYPE"] == "CWE805-direct"
    assert env["TAOSC_TOTAL_PATCHES"] == "1"
    assert env["FILTER_TOTAL_PATCHES"] == "1"
    assert env["TOTAL_PATCHES"] == "1"
    assert not (workdir / "brpatches.json").exists()


def test_specialized_env_counters(tmp_path, monkeypatch):
    workdir, env = _prepare_workdir(tmp_path, None)
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
    assert env["PATCH_TYPE"] == "taosc-specialized"
    # No prebuilt .brpatched and no predicates: the zero-candidate build.
    assert env["TAOSC_TOTAL_PATCHES"] == "0"
    assert env["FILTER_TOTAL_PATCHES"] == "0"
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
    obsolete = (
        "PREFILTER_TOTAL_PATCHES", "PREFILTER_E9_EXCLUDE_RANGES",
        "PREFILTER_E9_RELOCATED_CALL_JUMPS")
    (workdir / "binradar.env").write_text(
        "".join(f'{key}="stale"\n' for key in obsolete))

    calls = []
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run(calls))
    _patch_extract(monkeypatch)
    binradar_env = binradar_setup.create_binradar_env(
        configdir, configdir / "config.env", workdir)
    binradar_setup.prepare_patch(configdir, workdir, binradar_env, binradar_setup.load_setup_predicates(workdir))
    binradar_setup.save_env(binradar_env, workdir / "binradar.env")

    saved = binradar_setup.load_env(workdir / "binradar.env")
    assert not set(obsolete).intersection(saved)
    assert saved["PATCH_TYPE"] == "generic-erm"
    assert saved["TAOSC_TOTAL_PATCHES"] == "2"
    assert saved["FILTER_TOTAL_PATCHES"] == "2"
    assert saved["TOTAL_PATCHES"] == "2"


@pytest.mark.parametrize("name", [
    "BINRADAR_QEMU_EXEC_TIMEOUT", "BINRADAR_PROBE_TRACER_TIMEOUT",
    "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP"])
@pytest.mark.parametrize("value", ["nan", "inf", "0", "-1", "malformed"])
def test_setup_rejects_invalid_duration_before_artifact_work(tmp_path, name, value):
    workdir, _ = _prepare_workdir(tmp_path, "")
    # Missing POC fields deliberately prove timeout validation runs first.
    config = tmp_path / "config.env"
    config.write_text(f'{name}="{value}"\n')
    with pytest.raises(ValueError, match=name):
        binradar_setup.create_binradar_env(tmp_path, config, workdir)
    assert not (workdir / "imginfo.brpatched").exists()


def test_setup_rejects_fractional_forkserver_child_cap(tmp_path):
    workdir, _ = _prepare_workdir(tmp_path, "")
    config = tmp_path / "config.env"
    config.write_text('BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP="1.5"\n')
    with pytest.raises(ValueError, match="BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP"):
        binradar_setup.create_binradar_env(tmp_path, config, workdir)


def test_setup_original_filter_honors_configured_qemu_cap(tmp_path, monkeypatch):
    import sys

    workdir, env = _prepare_workdir(tmp_path, "rax == +max1\n", extra={
        "POC_INPUT": "input", "TEST_CMD": "@@",
        "BINRADAR_QEMU_EXEC_TIMEOUT": "0.1"})
    (workdir / "input").write_text("benign")
    script = "import pathlib,time; time.sleep(0.4); pathlib.Path('completed').touch()"
    monkeypatch.setattr(
        binradar_setup.binradar_verifier.BinRadarQemuRunner,
        "get_qemu_stacktrace_command_for_binary",
        lambda *args, **kwargs: [sys.executable, "-c", script])

    with pytest.raises(RuntimeError, match="could not probe the original"):
        binradar_setup.run_setup_filter(
            tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
    assert not (workdir / "completed").exists()


def test_patch_format_erm_generic_classifies_generic(tmp_path, monkeypatch):
    """patch-format 'ERM generic' drives the generic-erm family."""
    workdir, env = _prepare_workdir(
        tmp_path, "max1 - rax == ~max1\nmax1 / rax < +max1\n")
    (workdir / "patch-format").write_text("ERM generic\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
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

    binradar_setup.prepare_patch(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
    assert env["PATCH_TYPE"] == "CWE805-direct"
    assert env["TAOSC_TOTAL_PATCHES"] == "1"


def test_patch_format_single_cwe617_classifies_specialized(tmp_path, monkeypatch):
    """patch-format 'Single CWE-617' drives the taosc-specialized family."""
    workdir, env = _prepare_workdir(tmp_path, None)
    (workdir / "patch-format").write_text("Single CWE-617\n")
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run([]))
    _patch_extract(monkeypatch)

    binradar_setup.prepare_patch(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
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

    binradar_setup.prepare_patch(tmp_path, workdir, env, binradar_setup.load_setup_predicates(workdir))
    assert env["PATCH_TYPE"] == "CWE805-erm"
    assert env["TAOSC_TOTAL_PATCHES"] == "1"


def test_patch_format_mismatch_rejected(tmp_path):
    """patch-format 'Single CWE-805' without an allocator trace fails."""
    workdir, _ = _prepare_workdir(tmp_path, None)
    (workdir / "patch-format").write_text("Single CWE-805\n")
    try:
        binradar_setup.load_setup_predicates(workdir)
    except ValueError as e:
        assert "no allocator trace" in str(e)
    else:
        raise AssertionError("mismatched patch-format must be rejected")


def _concrete_subject(tmp_path):
    configdir = tmp_path / "config"
    configdir.mkdir()
    (configdir / "config.env").write_text(
        'BINARY="benign"\nPOC_DIR="poc"\nPOC_INPUT="poc/input"\n'
        'TEST_CMD="@@"\nBINRADAR_QEMU_EXEC_TIMEOUT="2.5"\n'
        'BINRADAR_PROBE_TRACER_TIMEOUT="11"\n'
        'BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP="9"\n'
        'BINRADAR_AFL_EXEC_TIMEOUT="1200+"\n'
        'BINRADAR_SYMBOLIC_SCHEDULE="existing"\n')
    (configdir / "patch-location").write_text("401000\n")
    (configdir / "poc").mkdir()
    (configdir / "poc" / "input").write_bytes(b"benign source")
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "benign.orig").write_bytes(b"original fixture")
    return configdir, workdir


def _forbid_patch_setup(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("original-only setup must not invoke patch tools")

    for name in ("run_fix", "load_setup_predicates", "prepare_patch",
                 "run_setup_filter"):
        monkeypatch.setattr(binradar_setup, name, forbidden)
    monkeypatch.setattr(binradar_setup.paths, "e9tool", forbidden)
    monkeypatch.setattr(binradar_setup.paths, "e9compile", forbidden)
    monkeypatch.setattr(binradar_setup.subprocess, "run", forbidden)


def test_generate_concrete_cli_isolated_environment(tmp_path, monkeypatch):
    import sys

    configdir, workdir = _concrete_subject(tmp_path)
    protected = {
        "binradar.env": b'BINARY="must-not-load"\n',
        "predicates": b"invalid predicate data\n",
        "patch-destination": b"unchanged destination\n",
        "filter.sbsv": b"unchanged filter\n",
        "brpatches.json": b"unchanged metadata\n",
        "benign.brpatched": b"unchanged patched executable",
    }
    for name, data in protected.items():
        (workdir / name).write_bytes(data)
    _forbid_patch_setup(monkeypatch)
    load_env = binradar_setup.load_env

    def guarded_load(path):
        assert path.name != "binradar.env"
        return load_env(path)

    monkeypatch.setattr(binradar_setup, "load_env", guarded_load)
    monkeypatch.setattr(sys, "argv", [
        "binradar-setup", "--generate-concrete", "-c", str(configdir),
        "-w", str(workdir)])
    binradar_setup.main()
    saved = load_env(workdir / "generate-concrete.env")
    expected = {
        "BINARY": "benign", "PATCH_LOC": "0x401000", "TOTAL_PATCHES": "0",
        "BINRADAR_GENERATE_CONCRETE": "1", "BINRADAR_CONCRETE_INPUT_SCHEDULE": "fifo",
        "BINRADAR_SYMBOLIC_SCHEDULE": "existing", "BINRADAR_QEMU_EXEC_TIMEOUT": "2.5",
        "BINRADAR_PROBE_TRACER_TIMEOUT": "11", "BINRADAR_AFL_EXEC_TIMEOUT": "1200+",
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP": "9",
    }
    assert expected.items() <= saved.items()
    assert not {"PATCH_TYPE", "BINRADAR_PATCH_KIND", "TAOSC_TOTAL_PATCHES",
                "FILTER_TOTAL_PATCHES"}.intersection(saved)
    assert (workdir / "poc" / "input").read_bytes() == b"benign source"
    assert (workdir / "benign.orig").read_bytes() == b"original fixture"
    for name, data in protected.items():
        assert (workdir / name).read_bytes() == data


def test_generate_concrete_requires_no_patch_artifacts(tmp_path, monkeypatch):
    configdir, workdir = _concrete_subject(tmp_path)
    _forbid_patch_setup(monkeypatch)
    binradar_setup._generate_concrete(configdir, workdir)
    assert (workdir / "generate-concrete.env").is_file()
    assert not (workdir / "binradar.env").exists()
    assert not (workdir / "patch-destination").exists()
    assert not (workdir / "predicates").exists()


def test_generate_concrete_preserves_poc_snapshot_and_copies_missing_files(
        tmp_path, monkeypatch):
    configdir, workdir = _concrete_subject(tmp_path)
    (workdir / "poc").mkdir()
    (workdir / "poc" / "input").write_bytes(b"existing snapshot")
    (workdir / "poc" / "local").write_bytes(b"local only")
    (configdir / "poc" / "nested").mkdir()
    (configdir / "poc" / "nested" / "other").write_bytes(b"other source")
    _forbid_patch_setup(monkeypatch)
    binradar_setup._generate_concrete(configdir, workdir)
    assert (workdir / "poc" / "input").read_bytes() == b"existing snapshot"
    assert (workdir / "poc" / "local").read_bytes() == b"local only"
    assert (workdir / "poc" / "nested" / "other").read_bytes() == b"other source"
    (configdir / "poc" / "input").unlink()
    binradar_setup._generate_concrete(configdir, workdir)
    assert (workdir / "poc" / "input").read_bytes() == b"existing snapshot"


@pytest.mark.parametrize("setting", [
    'BINRADAR_QEMU_EXEC_TIMEOUT="nan"\n',
    'BINRADAR_PROBE_TRACER_TIMEOUT="0"\n',
    'BINRADAR_FORKSERVER_CHILD_TIMEOUT_CAP="1.5"\n',
    'BINRADAR_CONCRETE_INPUT_SCHEDULE="novelty"\n',
    'BINRADAR_FEEDBACK_MODE="1"\n',
])
@pytest.mark.parametrize("existing", [False, True])
def test_generate_concrete_invalid_config_never_publishes(
        tmp_path, monkeypatch, setting, existing):
    configdir, workdir = _concrete_subject(tmp_path)
    with (configdir / "config.env").open("a") as stream:
        stream.write(setting)
    output = workdir / "generate-concrete.env"
    if existing:
        output.write_bytes(b"previous complete environment")
    _forbid_patch_setup(monkeypatch)
    with pytest.raises(ValueError):
        binradar_setup._generate_concrete(configdir, workdir)
    if existing:
        assert output.read_bytes() == b"previous complete environment"
    else:
        assert not output.exists()
    assert not list(workdir.glob(".generate-concrete-*"))


@pytest.mark.parametrize("missing", ["config.env", "patch-location", "poc/input"])
def test_generate_concrete_missing_prerequisites_do_not_run_taosc(
        tmp_path, monkeypatch, missing):
    configdir, workdir = _concrete_subject(tmp_path)
    (configdir / missing).unlink()
    _forbid_patch_setup(monkeypatch)
    with pytest.raises(FileNotFoundError):
        binradar_setup._generate_concrete(configdir, workdir)
    assert not (workdir / "generate-concrete.env").exists()


def test_generate_concrete_publishes_complete_env_atomically(tmp_path, monkeypatch):
    configdir, workdir = _concrete_subject(tmp_path)
    output = workdir / "generate-concrete.env"
    output.write_bytes(b"previous environment")
    replace = binradar_setup.os.replace
    observed = []

    def publish(source, destination):
        assert destination == output
        assert source.parent == workdir
        assert output.read_bytes() == b"previous environment"
        assert binradar_setup.load_env(source)["TOTAL_PATCHES"] == "0"
        observed.append(source)
        replace(source, destination)

    _forbid_patch_setup(monkeypatch)
    monkeypatch.setattr(binradar_setup.os, "replace", publish)
    binradar_setup._generate_concrete(configdir, workdir)
    assert len(observed) == 1
    assert not observed[0].exists()
    assert binradar_setup.load_env(output)["BINRADAR_GENERATE_CONCRETE"] == "1"


@pytest.mark.parametrize("patch_format,family,stack_size", [
    ("ERM generic", "generic-erm", 0),
    ("ERM CWE-805", "CWE805-erm", 4096),
    ("ERM CWE-805", "CWE805-erm", 0),
])
@pytest.mark.parametrize("predicates", [None, "not even valid predicate syntax!"])
def test_generate_binradar_builds_patchless_capture(
        tmp_path, monkeypatch, patch_format, family, stack_size, predicates):
    import sys

    configdir, workdir = _concrete_subject(tmp_path)
    (configdir / "patch-format").write_text(patch_format)
    (configdir / "destinations").write_text("401040\n")
    if predicates is not None:
        (workdir / "predicates").write_text(predicates)
    if family == "CWE805-erm":
        trace = configdir / "trace"
        trace.mkdir()
        (trace / "malloc.calls").write_text("0 401010\n")
        (trace / "malloc.returns").write_text("401015\n")
        (configdir / "stack-size").write_text(str(stack_size))
    with (configdir / "config.env").open("a") as stream:
        stream.write('BRPATCHED_E9_EXCLUDE_RANGES="stale"\n'
                     'BRCACHED_E9_RELOCATED_CALL_JUMPS="stale"\n'
                     'TAOSC_TOTAL_PATCHES="99"\n'
                     'BINRADAR_CONCRETE_INPUT_SCHEDULE="stale"\n')
    protected = {
        "binradar.env": b"existing ordinary environment",
        "generate-concrete.env": b"existing concrete environment",
        "benign.brpatched": b"existing patched binary",
        "benign.orig": b"original fixture",
        "filter.sbsv": b"existing filter",
    }
    for name, data in protected.items():
        (workdir / name).write_bytes(data)
    calls = []
    monkeypatch.setattr(binradar_setup.subprocess, "run", _fake_run(calls))
    _patch_extract(monkeypatch)
    monkeypatch.setattr(sys, "argv", [
        "binradar-setup", "--generate-binradar", "-c", str(configdir),
        "-w", str(workdir)])
    binradar_setup.main()

    saved = binradar_setup.load_env(workdir / "generate-binradar.env")
    assert saved["BINRADAR_PATCH_KIND"] == family
    assert saved["BINRADAR_GENERATE_BINRADAR"] == "1"
    assert saved["BINRADAR_GENERATE_CONCRETE"] == "0"
    assert saved["BINRADAR_FEEDBACK_MODE"] == "1"
    assert saved["BRCACHE_STACK_SIZE"] == str(stack_size)
    assert all(saved[key] == "0" for key in (
        "TOTAL_PATCHES", "BRPATCHED_TOTAL_PATCHES", "FILTER_TOTAL_PATCHES"))
    assert not {"BRPATCHED_E9_EXCLUDE_RANGES", "TAOSC_TOTAL_PATCHES",
                "BINRADAR_CONCRETE_INPUT_SCHEDULE"}.intersection(saved)
    loaded_family, loaded = binradar_taosc_predicates.load_runtime_predicates(
        workdir / "brpatches.json")
    assert loaded_family.value == family
    assert loaded == {}
    assert (workdir / "benign.brcached").is_file()
    assert (workdir / "benign.brcached.json").is_file()
    assert not (workdir / "brpatches.inc").exists()
    for name, data in protected.items():
        assert (workdir / name).read_bytes() == data
    assert (workdir / "poc" / "input").read_bytes() == b"benign source"
    if predicates is not None:
        assert (workdir / "predicates").read_text() == predicates


@pytest.mark.parametrize("patch_format", ["Single CWE-805", "Single CWE-617", "unknown future format"])
def test_generate_binradar_unsupported_replaces_stale_env_quietly(
        tmp_path, monkeypatch, capsys, patch_format):
    configdir = tmp_path / "config"
    configdir.mkdir()
    (configdir / "patch-format").write_text("ERM generic")
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "patch-format").write_text(patch_format)
    output = workdir / "generate-binradar.env"
    output.write_text('BINRADAR_PATCH_KIND="generic-erm"\nBINARY="stale"\n')
    (workdir / "subject.orig").write_bytes(b"original")
    (workdir / "subject.brpatched").write_bytes(b"patched")
    _forbid_patch_setup(monkeypatch)
    binradar_setup._generate_binradar(configdir, workdir)
    assert capsys.readouterr() == ("", "")
    assert binradar_setup.load_env(output) == {
        "BINRADAR_GENERATE_BINRADAR": "1", "BINRADAR_PATCH_KIND": "unsupported",
        "TOTAL_PATCHES": "0", "BINRADAR_GENERATION_PATCH_FORMAT": patch_format,
    }
    assert (workdir / "subject.orig").read_bytes() == b"original"
    assert (workdir / "subject.brpatched").read_bytes() == b"patched"
    assert not (workdir / "brpatches.json").exists()


@pytest.mark.parametrize("missing", ["patch-format", "patch-location", "destinations"])
def test_generate_binradar_missing_metadata_preserves_published_env(
        tmp_path, monkeypatch, missing):
    configdir, workdir = _concrete_subject(tmp_path)
    (configdir / "patch-format").write_text("ERM generic")
    (configdir / "destinations").write_text("401040\n")
    (configdir / missing).unlink()
    output = workdir / "generate-binradar.env"
    output.write_bytes(b"previous complete environment")
    _forbid_patch_setup(monkeypatch)
    with pytest.raises((ValueError, FileNotFoundError), match=missing.replace("destinations", "destination")):
        binradar_setup._generate_binradar(configdir, workdir)
    assert output.read_bytes() == b"previous complete environment"


@pytest.mark.parametrize("stack_size", [None, "", "invalid", "-1", "1048577"])
def test_generate_binradar_cwe805_requires_valid_capture_size(
        tmp_path, monkeypatch, stack_size):
    configdir, workdir = _concrete_subject(tmp_path)
    (configdir / "patch-format").write_text("ERM CWE-805")
    (configdir / "destinations").write_text("401040\n")
    trace = workdir / "trace"
    trace.mkdir()
    (trace / "malloc.calls").write_text("0 401010\n")
    (trace / "malloc.returns").write_text("401015\n")
    if stack_size is not None:
        (workdir / "stack-size").write_text(stack_size)
    _forbid_patch_setup(monkeypatch)
    with pytest.raises((ValueError, FileNotFoundError), match="stack-size"):
        binradar_setup._generate_binradar(configdir, workdir)
    assert not (workdir / "generate-binradar.env").exists()


def test_generate_binradar_empty_workdir_format_is_not_unsupported(
        tmp_path, monkeypatch):
    configdir, workdir = _concrete_subject(tmp_path)
    (configdir / "patch-format").write_text("ERM generic")
    (workdir / "patch-format").write_text(" \n")
    output = workdir / "generate-binradar.env"
    output.write_bytes(b"previous complete environment")
    _forbid_patch_setup(monkeypatch)
    with pytest.raises(ValueError, match="patch-format is empty"):
        binradar_setup._generate_binradar(configdir, workdir)
    assert output.read_bytes() == b"previous complete environment"


def test_generate_binradar_cwe805_missing_trace_is_error(tmp_path, monkeypatch):
    configdir, workdir = _concrete_subject(tmp_path)
    (configdir / "patch-format").write_text("ERM CWE-805")
    (configdir / "destinations").write_text("401040\n")
    (workdir / "stack-size").write_text("0")
    _forbid_patch_setup(monkeypatch)
    with pytest.raises(ValueError, match="allocator trace"):
        binradar_setup._generate_binradar(configdir, workdir)
    assert not (workdir / "generate-binradar.env").exists()


