#!/usr/bin/env python3
"""Phase 0 contract tests: pin the two P0 E9 runtime-metadata defects.

FIX_E9PATCH_RUNTIME_METADATA.md Phase 0 — these tests fail on the current
production code and pass once the exact-interval and relocated-call
propagation contracts land (Phases 1-2).

P0-1: disjoint E9 trampoline/reserve maps are collapsed into one min..max
      envelope by fuzzolic/binradar-setup.py::extract_trampoline_info,
      excluding unmapped gaps (39.5 MiB for xmllint, 1.93 GiB for tiffcp).
P0-2: phase-environment construction must set E9_RELOCATED_CALL_JUMPS for the
      selected symbolic tracer artifact, and the .orig memcheck run receives the
      patched binary's range values.

The synthetic E9 binaries embed a minimal e9_config_s (the same layout
parsed by parse_e9patch_config) so the tests exercise the real production
parser without invoking e9tool.
"""

import importlib.util
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

_spec = importlib.util.spec_from_file_location(
    "binradar_setup", ROOT / "fuzzolic" / "binradar-setup.py")
assert _spec is not None and _spec.loader is not None
binradar_setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar_setup)

_spec_utils = importlib.util.spec_from_file_location(
    "binradar_utils", ROOT / "fuzzolic" / "binradar_utils.py")
assert _spec_utils is not None and _spec_utils.loader is not None
binradar_utils = importlib.util.module_from_spec(_spec_utils)
_spec_utils.loader.exec_module(binradar_utils)

_spec2 = importlib.util.spec_from_file_location(
    "binradar", ROOT / "fuzzolic" / "binradar.py")
assert _spec2 is not None and _spec2.loader is not None
binradar = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(binradar)
import binradar_artifacts

PAGE = binradar_setup.PAGE_SIZE
TRAMPOLINE = binradar_setup.E9MapType.TRAMPOLINE
RESERVE = binradar_setup.E9MapType.RESERVE
REFACTOR = binradar_setup.E9MapType.REFACTOR

# One relocated-call record set, in the canonical jump:site:return form.
RECORDS = "0x54b091:0x4d60a5:0x4d60aa,0x54b0a1:0x486b4f:0x486b55"


def _write_synthetic_e9_binary(path, *, loader_base, loader_size, maps,
                               entry=0x401000):
    """Write a minimal binary with an embedded e9_config_s.

    maps: list of (vaddr, file_offset, size, map_type, absolute).  The
    config is placed at offset 0; map content is not required for the
    range-extraction tests.
    """
    cfg = binradar_setup.E9_CONFIG_STRUCT
    m = binradar_setup.E9_MAP_STRUCT
    maps_off = cfg.size
    data = bytearray(cfg.size + len(maps) * m.size)
    cfg.pack_into(data, 0,
                  b"E9PATCH\0",      # magic
                  b"",               # version
                  0,                 # flags
                  loader_size,       # loader_size
                  loader_base,       # base
                  entry,             # entry
                  0,                 # fini
                  0,                 # mmap
                  len(maps),         # num_maps0
                  0,                 # num_maps1
                  maps_off,          # maps0_off
                  0,                 # maps1_off
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  # preinits..handler
    for i, (vaddr, file_off, size, map_type, absolute) in enumerate(maps):
        bitfield = (size // PAGE) | (map_type << 20) | (0b111 << 28) \
            | (int(absolute) << 31)
        m.pack_into(data, maps_off + i * m.size,
                    vaddr // PAGE, file_off // PAGE, bitfield)
    path.write_bytes(data)


# ---------------------------------------------------------------------------
# P0-1: exact interval union, not a min..max envelope
# ---------------------------------------------------------------------------

def test_disjoint_trampoline_maps_are_not_enveloped(tmp_path):
    """Three separated trampoline maps keep their exact intervals.

    Mirrors the observed xmllint.brpatched layout: 0x54b000-0x54c000 and
    the adjacent 0x2cc7000-0x2cc8000/0x2cc8000-0x2cc9000 pair.  The old
    min..max envelope recorded 0x54b000-0x2cc9000 (~39.5 MiB of excluded
    gaps); the contract is the exact union (adjacent maps may coalesce).
    """
    patched = tmp_path / "xmllint.brpatched"
    _write_synthetic_e9_binary(
        patched,
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[
            (0x54b000, 0x1000, PAGE, TRAMPOLINE, False),
            (0x2cc7000, 0x2000, PAGE, TRAMPOLINE, False),
            (0x2cc8000, 0x3000, PAGE, TRAMPOLINE, False),
        ])
    metadata = binradar_setup.extract_e9_runtime_metadata(patched)
    assert metadata.exclude_ranges == (
        binradar_setup.AddressRange(0x54b000, 0x54c000),
        binradar_setup.AddressRange(0x2cc7000, 0x2cc9000),
        binradar_setup.AddressRange(0x20e9e9000, 0x20e9ea000),
    )


def test_trampoline_gap_is_not_excluded(tmp_path):
    """A one-page gap between trampoline maps must remain a gap."""
    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched,
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[
            (0x54b000, 0x1000, PAGE, TRAMPOLINE, False),
            (0x2cc7000, 0x2000, PAGE, TRAMPOLINE, False),
            (0x2cc9000, 0x3000, PAGE, TRAMPOLINE, False),  # gap 0x2cc8000
        ])
    metadata = binradar_setup.extract_e9_runtime_metadata(patched)
    assert metadata.exclude_ranges == (
        binradar_setup.AddressRange(0x54b000, 0x54c000),
        binradar_setup.AddressRange(0x2cc7000, 0x2cc8000),
        binradar_setup.AddressRange(0x2cc9000, 0x2cca000),
        binradar_setup.AddressRange(0x20e9e9000, 0x20e9ea000),
    )


def test_disjoint_reserve_maps_are_not_enveloped(tmp_path):
    """P0-1 for RESERVE maps: four separated pages stay separate.

    Mirrors the observed tiffcp.brpatched layout, whose old envelope
    excluded ~1.93 GiB of unmapped address space.
    """
    patched = tmp_path / "tiffcp.brpatched"
    _write_synthetic_e9_binary(
        patched,
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[
            (0x129a000, 0x1000, PAGE, RESERVE, False),
            (0x1000d000, 0x2000, PAGE, RESERVE, False),
            (0x7c254000, 0x3000, PAGE, RESERVE, False),
            (0x7ccba000, 0x4000, PAGE, RESERVE, False),
        ])
    metadata = binradar_setup.extract_e9_runtime_metadata(patched)
    assert metadata.exclude_ranges == (
        binradar_setup.AddressRange(0x129a000, 0x129b000),
        binradar_setup.AddressRange(0x1000d000, 0x1000e000),
        binradar_setup.AddressRange(0x7c254000, 0x7c255000),
        binradar_setup.AddressRange(0x7ccba000, 0x7ccbb000),
        binradar_setup.AddressRange(0x20e9e9000, 0x20e9ea000),
    )


def test_unsorted_overlapping_adjacent_maps_normalize_to_exact_union(
        tmp_path):
    """Order, overlap, and adjacency do not change the exact union."""
    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched,
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[
            (0x2cc8000, 0x1000, PAGE, TRAMPOLINE, False),   # unsorted
            (0x54b000, 0x2000, PAGE, TRAMPOLINE, False),
            (0x54b000, 0x3000, PAGE, TRAMPOLINE, False),    # overlaps
            (0x2cc7000, 0x4000, PAGE, TRAMPOLINE, False),   # adjacent
        ])
    metadata = binradar_setup.extract_e9_runtime_metadata(patched)
    assert metadata.exclude_ranges == (
        binradar_setup.AddressRange(0x54b000, 0x54c000),
        binradar_setup.AddressRange(0x2cc7000, 0x2cc9000),
        binradar_setup.AddressRange(0x20e9e9000, 0x20e9ea000),
    )


def test_loader_range_is_exact(tmp_path):
    """The loader interval is already exact (guard)."""
    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched, loader_base=0x20e9e9000, loader_size=0x2000, maps=[])
    metadata = binradar_setup.extract_e9_runtime_metadata(patched)
    assert metadata.exclude_ranges == (
        binradar_setup.AddressRange(0x20e9e9000, 0x20e9eb000),)


def test_metadata_is_scoped_to_the_parsed_artifact(tmp_path):
    """Two artifacts with different layouts never share metadata (guard)."""
    a = tmp_path / "a.brpatched"
    b = tmp_path / "b.brpatched"
    _write_synthetic_e9_binary(
        a, loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[(0x54b000, 0x1000, PAGE, TRAMPOLINE, False)])
    _write_synthetic_e9_binary(
        b, loader_base=0x10000000, loader_size=PAGE,
        maps=[(0x7c254000, 0x1000, PAGE, TRAMPOLINE, False)])
    meta_a = binradar_setup.extract_e9_runtime_metadata(a)
    meta_b = binradar_setup.extract_e9_runtime_metadata(b)
    assert meta_a.exclude_ranges_str() == \
        "0x54b000-0x54c000,0x20e9e9000-0x20e9ea000"
    assert meta_b.exclude_ranges_str() == \
        "0x10000000-0x10001000,0x7c254000-0x7c255000"
    assert meta_a.exclude_ranges != meta_b.exclude_ranges


def test_refactor_maps_are_never_excluded(tmp_path):
    """REFACTOR maps execute original code and stay out of the list."""
    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched,
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[
            (0x401000, 0x1000, PAGE, REFACTOR, False),
            (0x54b000, 0x1000, PAGE, TRAMPOLINE, False),
        ])
    metadata = binradar_setup.extract_e9_runtime_metadata(patched)
    assert metadata.exclude_ranges == (
        binradar_setup.AddressRange(0x54b000, 0x54c000),
        binradar_setup.AddressRange(0x20e9e9000, 0x20e9ea000),
    )


def test_absolute_excluded_map_is_rejected(tmp_path):
    """An absolute RESERVE/TRAMPOLINE map is a configuration error."""
    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched,
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[(0x54b000, 0x1000, PAGE, TRAMPOLINE, True)])
    with pytest.raises(ValueError, match="absolute"):
        binradar_setup.extract_e9_runtime_metadata(patched)


def test_exclude_ranges_serialize_parse_roundtrip():
    """Canonical serialization round-trips through the strict parser."""
    ranges = (
        binradar_setup.AddressRange(0x54b000, 0x54c000),
        binradar_setup.AddressRange(0x2cc7000, 0x2cc9000),
    )
    text = binradar_setup.serialize_exclude_ranges(ranges)
    assert text == "0x54b000-0x54c000,0x2cc7000-0x2cc9000"
    assert binradar_setup.parse_exclude_ranges(text) == ranges


def test_parse_exclude_ranges_empty_and_malformed():
    """Empty is the empty list; malformed non-empty values are errors."""
    assert binradar_setup.parse_exclude_ranges("") == ()
    for bad in ("0x1000", "0x1000-0x2000,", "0x1000-0x2000junk",
                "0x2000-0x1000", "0x1000-0x1000", "1000-0x2000",
                "0x1000-2000", "0xzz00-0x3000", "0x1000-0x2000,0x3000"):
        with pytest.raises(ValueError):
            binradar_setup.parse_exclude_ranges(bad)


def test_normalize_address_ranges_validation():
    """Zero-length and reversed intervals are rejected."""
    with pytest.raises(ValueError):
        binradar_setup.normalize_address_ranges([(0x1000, 0x1000)])
    with pytest.raises(ValueError):
        binradar_setup.normalize_address_ranges([(0x2000, 0x1000)])


def test_e9_metadata_helpers_roundtrip():
    """Prefixed set/get helpers round-trip; missing keys yield empty."""
    env = {}
    binradar_utils.set_e9_metadata(
        env, "brpatched", "0x54b000-0x54c000", RECORDS)
    binradar_utils.set_e9_metadata(
        env, "brcached", "0x7c254000-0x7c255000", "")
    assert env["BRPATCHED_E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
    assert env["BRPATCHED_E9_RELOCATED_CALL_JUMPS"] == RECORDS
    assert env["BRCACHED_E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert env["BRCACHED_E9_RELOCATED_CALL_JUMPS"] == ""
    assert binradar_utils.get_e9_metadata(env, "brpatched") == \
        ("0x54b000-0x54c000", RECORDS)
    assert binradar_utils.get_e9_metadata(env, "brcached") == \
        ("0x7c254000-0x7c255000", "")


def test_persist_e9_metadata_preserves_subject_fields(tmp_path):
    """Persistence updates only the prefixed keys of binradar.env."""
    env_path = tmp_path / "binradar.env"
    env_path.write_text('BINARY="nm"\nPATCH_LOC="0x4585dd"\n')
    metadata = binradar_setup.E9RuntimeMetadata(
        (binradar_setup.AddressRange(0x54b000, 0x54c000),), ())
    binradar_setup.persist_e9_metadata(tmp_path, "brcached", metadata)
    binradar_setup.persist_e9_metadata(
        tmp_path, "brpatched",
        binradar_setup.E9RuntimeMetadata(
            (binradar_setup.AddressRange(0x7c254000, 0x7c255000),),
            ((0x54b091, 0x4d60a5, 0x4d60aa),)))
    env = binradar_setup.load_env(env_path)
    assert env["BINARY"] == "nm"
    assert env["PATCH_LOC"] == "0x4585dd"
    assert env["BRCACHED_E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
    assert env["BRPATCHED_E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert env["BRPATCHED_E9_RELOCATED_CALL_JUMPS"] == \
        "0x54b091:0x4d60a5:0x4d60aa"
    assert "E9_EXCLUDE_RANGES" not in env
    assert "E9_RELOCATED_CALL_JUMPS" not in env


def test_verifier_from_env_stores_all_prefixed_metadata(tmp_path):
    """BinRadarQemuRunner.from_env stores every artifact's records and
    selects them by the executed binary path."""
    env = {
        "BINARY": "nm",
        "TEST_CMD": "-l @@",
        "PATCH_LOC": "0x4585dd",
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": "0x54b091:0x4d60a5:0x4d60aa",
        "BRCACHED_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000",
        "BRCACHED_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    runner = binradar.binradar_verifier.BinRadarQemuRunner.from_env(
        str(tmp_path), env)
    # All prefixed values are stored.
    assert runner.e9_metadata["brpatched"] == (
        "0x54b000-0x54c000", ["0x54b091:0x4d60a5:0x4d60aa"])
    assert runner.e9_metadata["brcached"] == (
        "0x7c254000-0x7c255000", ["0x7c254091:0x4d60a5:0x4d60aa"])
    # Selection follows the executed binary path.
    assert runner.e9_metadata_for_binary(
        str(tmp_path / "nm.brpatched")) == (
            "0x54b000-0x54c000", ["0x54b091:0x4d60a5:0x4d60aa"])
    assert runner.e9_metadata_for_binary(
        str(tmp_path / "nm.brcached")) == (
            "0x7c254000-0x7c255000", ["0x7c254091:0x4d60a5:0x4d60aa"])
    # Original binaries have no E9 metadata.
    assert runner.e9_metadata_for_binary(
        str(tmp_path / "nm.orig")) == ("", [])


def test_verifier_command_selects_records_by_binary(tmp_path):
    """The stacktrace command carries the executed artifact's records."""
    env = {
        "BINARY": "nm",
        "TEST_CMD": "-l @@",
        "PATCH_LOC": "0x4585dd",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": "0x54b091:0x4d60a5:0x4d60aa",
        "BRCACHED_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    runner = binradar.binradar_verifier.BinRadarQemuRunner.from_env(
        str(tmp_path), env)
    patched_cmd = runner.get_qemu_stacktrace_command(True, "poc")
    assert "--e9-relocated-call" in patched_cmd
    assert "0x54b091:0x4d60a5:0x4d60aa" in patched_cmd
    assert "0x7c254091:0x4d60a5:0x4d60aa" not in patched_cmd
    orig_cmd = runner.get_qemu_stacktrace_command(False, "poc")
    assert "--e9-relocated-call" not in orig_cmd


def test_file_trace_forwards_explicit_timeout(tmp_path, monkeypatch):
    runner = binradar.binradar_verifier.BinRadarQemuRunner(
        dir=str(tmp_path), binary="nm", test_cmd="-l @@",
        patch_loc="0x4585dd")
    monkeypatch.setattr(
        runner, "get_qemu_stacktrace_command",
        lambda *_args, **_kwargs: ["qemu-stacktrace"])
    captured = {}

    def fake_execute(command, cwd=None, env=None, timeout=60.0, verbose=True):
        captured["timeout"] = timeout
        return binradar.binradar_utils.ExecutionResult(
            success=False, exit_code=1, stdout="", stderr="")

    monkeypatch.setattr(binradar.binradar_utils, "execute", fake_execute)

    assert runner.test_with_file_trace(
        "poc", patch_func_entry=0x401000, timeout=600.0) is None
    assert captured["timeout"] == 600.0


def test_executor_retains_all_prefixed_metadata(tmp_path):
    """from_env keeps every artifact's prefixed keys in extract_config."""
    env = {
        "BINARY": "nm",
        "POC_INPUT": "poc/nullderef",
        "TEST_CMD": "-l @@",
        "PATCH_LOC": "0x4585dd",
        "TOTAL_PATCHES": "2",
        "BINRADAR_PATCH_KIND": "CWE805-erm",
        "BRCACHE_STACK_SIZE": "256",
        "BINRADAR_OUTDIR": str(tmp_path / "out"),
        "BINRADAR_TIMEOUT": "60",
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": "0x54b091:0x4d60a5:0x4d60aa",
        "BRCACHED_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000",
        "BRCACHED_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    executor = binradar.BinRadarExecutor.from_env(str(tmp_path), env)
    config = executor._worker_environment()
    assert config["BRPATCHED_E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
    assert config["BRPATCHED_E9_RELOCATED_CALL_JUMPS"] == \
        "0x54b091:0x4d60a5:0x4d60aa"
    assert config["BRCACHED_E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert config["BRCACHED_E9_RELOCATED_CALL_JUMPS"] == \
        "0x7c254091:0x4d60a5:0x4d60aa"
    assert config["BINRADAR_PATCH_KIND"] == "CWE805-erm"
    assert config["BRCACHE_STACK_SIZE"] == "256"
    # The runner built from that config selects by binary path.
    runner = binradar.binradar_verifier.BinRadarQemuRunner.from_env(
        str(tmp_path), config)
    assert runner.e9_metadata_for_binary(
        str(tmp_path / "nm.brpatched"))[1] == ["0x54b091:0x4d60a5:0x4d60aa"]
    assert runner.patch_kind == "CWE805-erm"
    assert runner.brcache_stack_size == 256


def test_verifier_selects_brcached_by_binary_path(tmp_path):
    """The .brcached artifact selects its own BRCACHED_* values."""
    env = {
        "BINARY": "nm",
        "TEST_CMD": "-l @@",
        "PATCH_LOC": "0x4585dd",
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": "0x54b091:0x4d60a5:0x4d60aa",
        "BRCACHED_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000",
        "BRCACHED_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    runner = binradar.binradar_verifier.BinRadarQemuRunner.from_env(
        str(tmp_path), env)
    assert runner.e9_metadata_for_binary(
        str(tmp_path / "nm.brcached")) == (
            "0x7c254000-0x7c255000", ["0x7c254091:0x4d60a5:0x4d60aa"])
    # The .brpatched stacktrace command never unions in cached records.
    cmd = runner.get_qemu_stacktrace_command(True, "poc")
    assert "0x54b091:0x4d60a5:0x4d60aa" in cmd
    assert "0x7c254091:0x4d60a5:0x4d60aa" not in cmd


def test_cached_build_persists_brcached_metadata(tmp_path, monkeypatch):
    """build_cached_binary e9compiles brpatch-cached.c, instruments the
    original binary, and persists the BRCACHED_* metadata."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "destinations").write_text("4106d8\n")
    (workdir / "patch-location").write_text("410735")
    orig = workdir / "imginfo.orig"
    orig.write_bytes(b"\x7fELF" + b"\0" * 100)
    (workdir / "brpatch.c").write_text("/* generated */\n")
    (workdir / "brpatches.inc").write_text(
        'case 0: return "p0";\ncase 1: return "p1";\n'
        'case 2: return "p0";\ndefault: return "p0";\n')
    binradar_env = {
        "BINARY": "imginfo",
        "PATCH_LOC": "0x410735",
        "BINRADAR_PATCH_KIND": "generic-erm",
    }

    calls = []

    def fake_run(cmd, cwd=None, **kwargs):
        calls.append((list(cmd), cwd))
        # e9compile and e9tool both succeed; e9tool writes the outputs.
        if cmd[0] == "guix" and "e9tool" in cmd:
            out = cmd[cmd.index("-o") + 1]
            Path(out).write_bytes(b"\x7fELF" + b"\0" * 100)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(binradar_setup.subprocess, "run", fake_run)
    metadata = binradar_setup.E9RuntimeMetadata(
        (binradar_setup.AddressRange(0x7c254000, 0x7c255000),),
        ((0x7c254091, 0x4d60a5, 0x4d60aa),))
    monkeypatch.setattr(
        binradar_setup, "extract_e9_runtime_metadata",
        lambda *args, **kwargs: metadata)

    out = binradar_setup.build_cached_binary(
        workdir, tmp_path, binradar_env,
        binradar_setup.PredicateFamily.GENERIC_ERM, None)
    assert out == metadata
    assert (workdir / "imginfo.brcached").exists()
    assert (workdir / "imginfo.brcached.json").exists()
    assert (workdir / "brpatch-cached.c").exists()

    # e9compile ran with the destination define.
    compile_cmds = [c for c, _ in calls
                    if "e9compile" in c and "brpatch-cached.c" in c]
    assert compile_cmds, "e9compile brpatch-cached.c not invoked"
    assert "-DTAOSC_DEST=0x4106d8" in compile_cmds[0]
    assert "-DBRPATCH_CWE805" not in compile_cmds[0]
    # e9tool ran the JSON and binary commands from one spec.
    tool_cmds = [c for c, _ in calls if "e9tool" in c]
    assert len(tool_cmds) == 2
    json_cmd = tool_cmds[0]
    bin_cmd = tool_cmds[1]
    assert "--format=json" in json_cmd
    assert "--format=json" not in bin_cmd
    assert "if dest(state)@brpatch-cached goto" in bin_cmd
    assert any("imginfo.brcached.json" in c for c in json_cmd)
    assert any("imginfo.brcached" in c for c in bin_cmd)

    # The BRCACHED_* keys landed in binradar.env.
    env = binradar_setup.load_env(workdir / "binradar.env")
    assert env["BRCACHED_E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert env["BRCACHED_E9_RELOCATED_CALL_JUMPS"] == \
        "0x7c254091:0x4d60a5:0x4d60aa"


def test_cwe805_cached_build_uses_allocator_hooks(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "destinations").write_text("4106d8\n")
    (workdir / "brpatch.c").write_text("/* generated */\n")
    (workdir / "brpatches.inc").write_text(
        'case 0: return "p0";\ncase 1: return "c1p0";\n'
        'case 2: return "c1p1";\ndefault: return "p0";\n')
    (workdir / "imginfo.orig").write_bytes(b"\x7fELF" + b"\0" * 100)
    env = {"BINARY": "imginfo", "PATCH_LOC": "0x410735"}
    allocator = binradar_setup.AllocatorTrace(
        "malloc", [(0, "40661c"), (1, "404eb4")], ["406621"])
    calls = []

    def fake_run(cmd, cwd=None, **kwargs):
        calls.append(list(cmd))
        if "e9tool" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_bytes(
                b"\x7fELF" + b"\0" * 100)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(binradar_setup.subprocess, "run", fake_run)
    monkeypatch.setattr(
        binradar_setup, "extract_e9_runtime_metadata",
        lambda *args, **kwargs: binradar_setup.E9RuntimeMetadata((), ()))

    binradar_setup.build_cached_binary(
        workdir, tmp_path, env,
        binradar_setup.PredicateFamily.CWE805_ERM, allocator)

    compile_cmd = next(cmd for cmd in calls if "e9compile" in cmd)
    assert "-DBRPATCH_CWE805" in compile_cmd
    assert "-DBRPATCH_ALLOC_MALLOC" in compile_cmd
    tool_cmds = [cmd for cmd in calls if "e9tool" in cmd]
    assert len(tool_cmds) == 2
    for cmd in tool_cmds:
        assert "-O0" in cmd
        joined = " ".join(cmd)
        assert "set_size(rdi,rsi)@brpatch-cached" in joined
        assert "mark(1)@brpatch-cached" in joined
        assert "set_base(rax)@brpatch-cached" in joined
        assert "if dest(state)@brpatch-cached goto" in joined


def test_cwe805_cached_build_accepts_zero_for_register_predicates(
        tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "stack-size").write_text("0\n")
    env = {"BINARY": "imginfo", "PATCH_LOC": "0x410735"}
    predicates = [
        binradar_setup.PredicateRecord(
            1, 1, "pointer",
            binradar_setup.CWE805PointerPredicate(
                binradar_setup.RegisterCell(0))),
        binradar_setup.PredicateRecord(
            2, 2, "size",
            binradar_setup.CWE805SizePredicate(
                4, binradar_setup.RegisterCell(1))),
    ]
    monkeypatch.setattr(
        binradar_setup, "build_cached_binary",
        lambda *args, **kwargs: binradar_setup.E9RuntimeMetadata((), ()))

    binradar_setup.build_cached_artifact(
        workdir, tmp_path, env,
        binradar_setup.PredicateFamily.CWE805_ERM,
        binradar_setup.AllocatorTrace("malloc", [(0, "40661c")], ["406621"]),
        predicates,
    )

    assert env["BRCACHE_STACK_SIZE"] == "0"
    family, loaded = (
        binradar_setup.binradar_taosc_predicates.load_runtime_predicates(
            workdir / "brpatches.json"))
    assert family is binradar_setup.PredicateFamily.CWE805_ERM
    assert set(loaded) == {1, 2}


def test_verifier_capture_drains_text_and_cached_channels(tmp_path, monkeypatch):
    helper = tmp_path / "emit-cached-capture.py"
    helper.write_text(
        "import os\n"
        "os.write(int(os.environ['PATCH_FD']), b'[patch] [id 0] [br 1] [v 0]\\n')\n"
        "os.write(int(os.environ['PATCH_CACHED_FD']), b'BRCH-snapshot')\n")
    # A patched-artifact capture validates its E9 identity map before any
    # execution, so the fixture carries a bound artifact/original pair.
    import hashlib
    import json
    import struct
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    (tmp_path / "subject.orig").write_bytes(
        bytes(header)
        + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0x1000, 0x1000))
    binary = tmp_path / "subject.brcached"
    binary.write_bytes(b"cache")
    (tmp_path / "subject.brcached.e9map.json").write_text(json.dumps({
        "version": 1,
        "artifact-sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "original-sha256": hashlib.sha256(
            (tmp_path / "subject.orig").read_bytes()).hexdigest(),
        "instructions": [],
    }))
    runner = binradar.binradar_verifier.BinRadarQemuRunner(
        dir=str(tmp_path), binary="subject", test_cmd="",
        patch_loc="0x400000",
        e9_metadata={"brcached": ("0x6000-0x7000", [])})
    monkeypatch.setattr(
        runner, "get_qemu_stacktrace_command_for_binary",
        lambda _binary, _testcase: [sys.executable, str(helper)])
    probe = SimpleNamespace(fault_addr=0, concrete_fault_valid=False)
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarProbeResult, "from_log",
        lambda _log: probe)

    captured_probe, patch_data, cached_data = runner._test_with_capture(
        runner.cached_binary(), "0", "input", capture_cached=True)

    assert captured_probe is probe
    assert patch_data == b"[patch] [id 0] [br 1] [v 0]\n"
    assert cached_data == b"BRCH-snapshot"


def test_verifier_cache_runs_one_representative_per_branch_vector(tmp_path):
    workdir = tmp_path / "workdir"
    run_dir = tmp_path / "run"
    (run_dir / "minimized").mkdir(parents=True)
    workdir.mkdir()
    (workdir / "imginfo.brcached").write_bytes(b"cache")

    # Over zero registers: "=p1p0" and "=v1p0" are both false (branch 0);
    # "=p0p0" is true (branch 1). Patch 3 therefore needs its own run.
    predicates = binradar_setup.binradar_taosc_predicates
    selected = [
        predicates.PredicateRecord(1, 1, "p1", "=p1p0"),
        predicates.PredicateRecord(2, 2, "p2", "=p0p0"),
        predicates.PredicateRecord(3, 3, "p3", "=v1p0"),
    ]
    predicates.write_runtime_predicates(
        workdir / "brpatches.json",
        predicates.PredicateFamily.GENERIC_ERM,
        selected,
    )

    normal_result = SimpleNamespace(
        fault_addr=0,
        patch_hit_cnt=1,
        is_crash=lambda: False,
        is_normal_exit=lambda: True,
        is_timeout=lambda: False,
    )

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
            # Mirror the real plugin: branch 0 while rax and rbx are zero,
            # branch 1 for a predicate that is true there ("=p0p0").
            branch = 1 if predicate == "=p0p0" else 0
            snapshot = binradar.binradar_verifier.CachedSnapshot(
                patch_id=patch_id,
                branch=branch,
                registers=(0,) * 16,
            )
            return normal_result, binradar.binradar_verifier.BinRadarCachedRun(
                patch_id, [snapshot])

        def test_with_patched(self, patch_id, testcase):
            self.patched_calls.append(int(patch_id))
            return normal_result, binradar.binradar_verifier.BinRadarPatchResult(
                int(patch_id), [0])

    runner = FakeRunner()
    verifier = binradar.binradar_verifier.BinRadarConcreteVerifier(
        str(workdir), str(run_dir), runner,
        SimpleNamespace(fault_addr=0xDEAD),
        str(workdir / "imginfo.brpatched"), [1, 2, 3])
    # The cached run (representative patch 1) took branch 0; the minimizer
    # observed the same branch vector [0] for the original run. Matching
    # vectors are accept evidence; differing vectors lower confidence without
    # rejecting the patch.
    testcase = binradar.binradar_verifier.Testcase(
        0, "input", "ok", 0, [0])
    verifier.testcases.append(testcase)

    rejected = verifier._test_testcase_batch([1, 2, 3], testcase)
    assert rejected == set()
    assert verifier.accept_evidences == {1: 1, 2: 0, 3: 0}
    assert verifier.total_evidences == {1: 1, 2: 1, 3: 1}
    # One representative run per distinct branch vector. Both representatives
    # reuse the cached artifact; only the third predicate's vector differs
    # from the representative's, and it is judged offline from the snapshot.
    assert runner.cached_calls == [(1, "=p1p0"), (2, "=p0p0")]
    assert runner.patched_calls == []


def test_cached_artifact_skips_single_predicate_and_removes_stale_files(
        tmp_path, monkeypatch):
    """Caching is useful only when at least two predicates can share a run."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "imginfo.brcached").write_bytes(b"stale")
    (workdir / "brpatches.json").write_text("{}")
    binradar_env = {
        "BINARY": "imginfo",
        "PATCH_LOC": "0x410735",
        "BRCACHED_E9_EXCLUDE_RANGES": "stale",
        "BRCACHED_E9_RELOCATED_CALL_JUMPS": "stale",
        "BRCACHE_STACK_SIZE": "99",
    }
    selected = [binradar_setup.PredicateRecord(1, 1, "max1", "=p0p0")]

    monkeypatch.setattr(
        binradar_setup, "build_cached_binary",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("single predicate must not build a cache")))
    binradar_setup.build_cached_artifact(
        workdir, tmp_path, binradar_env,
        binradar_setup.PredicateFamily.GENERIC_ERM, None, selected)
    assert not (workdir / "imginfo.brcached").exists()
    assert not (workdir / "brpatches.json").exists()
    assert "BRCACHED_E9_EXCLUDE_RANGES" not in binradar_env
    assert "BRCACHE_STACK_SIZE" not in binradar_env


def test_detect_family_CWE805_erm_empty_predicates_no_raise(tmp_path):
    """Empty CWE-119 predicates classify as CWE805_ERM, not an error."""
    workdir = tmp_path / "workdir"
    trace = workdir / "trace"
    trace.mkdir(parents=True)
    (trace / "realloc.calls").write_text("0 4066e4\n")
    (trace / "realloc.returns").write_text("4066f0\n")
    (trace / "crash.address").write_text("410735")
    (workdir / "patch-location").write_text("410736")
    (workdir / "predicates").write_text("")
    family, allocator = binradar_setup.detect_predicate_family(workdir)
    assert family is binradar_setup.PredicateFamily.CWE805_ERM
    assert allocator is not None


def test_detect_family_CWE805_erm_missing_predicates_no_raise(tmp_path):
    """Missing CWE-119 predicates classify as CWE805_ERM, not an error."""
    workdir = tmp_path / "workdir"
    trace = workdir / "trace"
    trace.mkdir(parents=True)
    (trace / "realloc.calls").write_text("0 4066e4\n")
    (trace / "realloc.returns").write_text("4066f0\n")
    (trace / "crash.address").write_text("410735")
    (workdir / "patch-location").write_text("410736")
    family, allocator = binradar_setup.detect_predicate_family(workdir)
    assert family is binradar_setup.PredicateFamily.CWE805_ERM
    assert allocator is not None


def test_prepare_patch_empty_predicates_builds_zero_candidates(
        tmp_path, monkeypatch):
    """Empty predicates build brpatched only; no cache can save a run."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "patch-location").write_text("410735")
    (workdir / "destinations").write_text("4106d8\n")
    (workdir / "predicates").write_text("")
    orig = workdir / "imginfo.orig"
    orig.write_bytes(b"\x7fELF" + b"\0" * 100)
    binradar_env = {"BINARY": "imginfo", "PATCH_LOC": "0x410735"}

    def fake_run(cmd, cwd=None, **kwargs):
        if cmd[0] == "guix" and "e9tool" in cmd:
            out = cmd[cmd.index("-o") + 1]
            Path(out).write_bytes(b"\x7fELF" + b"\0" * 100)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(binradar_setup.subprocess, "run", fake_run)
    metadata = binradar_setup.E9RuntimeMetadata(
        (binradar_setup.AddressRange(0x42209000, 0x4220a000),),
        ((0x42209114, 0x410735, 0x410737),))
    monkeypatch.setattr(
        binradar_setup, "extract_e9_runtime_metadata",
        lambda *args, **kwargs: metadata)

    binradar_setup.prepare_patch(tmp_path, workdir, binradar_env)
    assert binradar_env["TOTAL_PATCHES"] == "0"
    assert binradar_env["BRPATCHED_E9_EXCLUDE_RANGES"] == \
        "0x42209000-0x4220a000"
    assert "BRCACHED_E9_EXCLUDE_RANGES" not in binradar_env
    assert (workdir / "imginfo.brpatched").exists()
    assert not (workdir / "imginfo.brcached").exists()
    assert (workdir / "brpatches.inc").exists()


def test_cmd_setup_builds_filters_then_rebuilds_erm(tmp_path, monkeypatch):
    """The cache-capable bootstrap build precedes filtering and compaction."""
    configdir = tmp_path / "config"
    workdir = tmp_path / "workdir"
    (configdir / "poc").mkdir(parents=True)
    workdir.mkdir()
    (configdir / "config.env").write_text(
        'BINARY="imginfo"\n'
        'POC_INPUT="poc/input"\n'
        'POC_DIR="poc"\n'
        'TEST_CMD="./imginfo @@"\n')
    (workdir / "patch-location").write_text("410735\n")
    (workdir / "binradar.env").write_text(
        'PREFILTER_TOTAL_PATCHES="stale"\n'
        'PREFILTER_E9_EXCLUDE_RANGES="stale"\n'
        'PREFILTER_E9_RELOCATED_CALL_JUMPS="stale"\n')

    events = []

    def fake_prepare(configdir_arg, workdir_arg, env_arg):
        events.append("prepare")
        env_arg["BINRADAR_PATCH_KIND"] = "generic-erm"
        env_arg["TAOSC_TOTAL_PATCHES"] = "2"
        env_arg["FILTER_TOTAL_PATCHES"] = "2"
        env_arg["TOTAL_PATCHES"] = "2"

    def fake_filter(configdir_arg, workdir_arg, env_arg):
        events.append("filter")
        env_arg["FILTER_TOTAL_PATCHES"] = "1"
        return [1]

    monkeypatch.setattr(binradar_setup, "prepare_patch", fake_prepare)
    monkeypatch.setattr(binradar_setup, "run_setup_filter", fake_filter)

    binradar_setup.cmd_setup(configdir, workdir)

    assert events == ["prepare", "filter", "prepare"]
    saved = binradar_setup.load_env(workdir / "binradar.env")
    assert "PREFILTER_TOTAL_PATCHES" not in saved
    assert "PREFILTER_E9_EXCLUDE_RANGES" not in saved
    assert "PREFILTER_E9_RELOCATED_CALL_JUMPS" not in saved


# ---------------------------------------------------------------------------
# P0-2: relocated-call propagation to symbolic tracer runs
# ---------------------------------------------------------------------------

def _write_bound_identity_artifacts(tmp_path, binary="nm"):
    """Minimal executable ELF plus two independently hash-bound empty maps."""
    import hashlib
    import json
    original = tmp_path / f"{binary}.orig"
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    original.write_bytes(bytes(header) + struct.pack(
        "<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0x100000, 0x1000))
    for suffix in ("brpatched", "brcached"):
        artifact = tmp_path / f"{binary}.{suffix}"
        artifact.write_bytes(suffix.encode())
        artifact.with_name(artifact.name + ".e9map.json").write_text(json.dumps({
            "version": 1,
            "artifact-sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "original-sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
            "instructions": [],
        }))


def _stub_executor(tmp_path, e9_metadata_prefix="brpatched", config=None):
    _write_bound_identity_artifacts(tmp_path)
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.workdir = str(tmp_path)
    executor.outdir = str(tmp_path / "out")
    executor.timeout = 60
    executor.forkserver_child_timeout = \
        binradar.binradar_config.FORKSERVER_CHILD_TIMEOUT_DEFAULT
    executor.binary = "nm"
    executor.poc_input = "poc/nullderef"
    executor.test_cmd = "-l @@"
    executor.patch_loc = "0x4585dd"
    executor.config = config if config is not None else {}
    executor.total_patches = 2
    executor.brpatched_total_patches = 2
    executor.artifacts = binradar_artifacts.ArtifactSet(
        str(tmp_path), "nm", "", 0, 2)
    artifact_path = (executor.artifacts.cached
                     if e9_metadata_prefix == "brcached"
                     else executor.artifacts.patched)
    executor.test_artifact_selection = binradar_artifacts.ArtifactSelection(
        artifact_path, e9_metadata_prefix,
        e9_metadata_prefix == "brcached", False, "test selection")
    executor.fuzzy = False
    executor.reverse_directed = False
    executor.disable_binradar = False
    executor.probe_result = SimpleNamespace(patch_func_hit_cnt=3)
    executor.filter_result = [1, 2]
    executor.run_dir = str(tmp_path)
    executor.run_prefix = "run"
    executor.run_id = 0
    executor.progress_filename = str(tmp_path / "progress.sbsv")
    executor.start_time = time.time()
    return executor


def _phase_env(executor, mode, run_dir):
    artifact = (executor.test_artifact_selection
                if mode == "binradar" else None)
    return executor._phase_environment(mode, str(run_dir), artifact)


def test_get_env_scopes_e9_metadata_to_patched_mode(tmp_path):
    """Original producers get empty E9 metadata; BinRadar gets its pair."""
    config = {
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000,0x2cc7000-0x2cc9000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": RECORDS,
        "E9_RELOCATED_INSTRUCTIONS": "dead:beef",
    }
    executor = _stub_executor(tmp_path, config=config)
    for mode in ("fuzzolic", "directed"):
        env = _phase_env(executor, mode, tmp_path)
        assert env["E9_RELOCATED_CALL_JUMPS"] == ""
        assert env["E9_EXCLUDE_RANGES"] == ""
        assert env["E9_RELOCATED_INSTRUCTIONS"] == ""
    env = _phase_env(executor, "binradar", tmp_path)
    assert env["E9_RELOCATED_CALL_JUMPS"] == RECORDS
    assert env["E9_EXCLUDE_RANGES"] == \
        "0x54b000-0x54c000,0x2cc7000-0x2cc9000"
    for key in ("PATCH_RESERVE_RANGE", "E9_TRAMPOLINE_RANGE",
                "E9_LOADER_RANGE"):
        assert key not in env


def test_metadata_selection_is_artifact_scoped(tmp_path):
    """Selecting an artifact selects only its own prefixed metadata.

    Two artifacts with intentionally different ranges and jumps: the
    brpatched run must never receive the brcached values and vice versa.
    """
    config = {
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": "0x54b091:0x4d60a5:0x4d60aa",
        "BRCACHED_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000",
        "BRCACHED_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    brpatched = _stub_executor(tmp_path, e9_metadata_prefix="brpatched",
                               config=config)
    brcached = _stub_executor(tmp_path, e9_metadata_prefix="brcached",
                              config=config)
    import json
    for suffix, relocated in (("brpatched", 0x54b091), ("brcached", 0x7c254091)):
        sidecar = tmp_path / f"nm.{suffix}.e9map.json"
        data = json.loads(sidecar.read_text())
        data["instructions"] = [{"relocated": relocated + 1, "original": 0x4585dd},
                                {"relocated": relocated, "original": 0x4d60a5}]
        sidecar.write_text(json.dumps(data))
    env_b = _phase_env(brpatched, "binradar", tmp_path)
    env_p = _phase_env(brcached, "binradar", tmp_path)
    assert env_b["E9_RELOCATED_INSTRUCTIONS"] == "54b091:4d60a5,54b092:4585dd"
    assert env_p["E9_RELOCATED_INSTRUCTIONS"] == "7c254091:4d60a5,7c254092:4585dd"
    assert env_b["E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
    assert env_b["E9_RELOCATED_CALL_JUMPS"] == \
        "0x54b091:0x4d60a5:0x4d60aa"
    assert env_p["E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert env_p["E9_RELOCATED_CALL_JUMPS"] == \
        "0x7c254091:0x4d60a5:0x4d60aa"


def test_selected_phase_rejects_missing_bound_map(tmp_path):
    executor = _stub_executor(tmp_path, config={
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000"})
    (tmp_path / "nm.brpatched.e9map.json").unlink()
    with pytest.raises(ValueError, match="rerun binradar-setup"):
        _phase_env(executor, "binradar", tmp_path)


def test_preflight_map_error_is_not_an_ignorable_baseline_warning(tmp_path, monkeypatch):
    executor = _stub_executor(tmp_path, config={
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000",
        "BRCACHED_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000"})
    environment = _phase_env(executor, "binradar", tmp_path)
    # The selected map is already prepared, but preflight must independently
    # reject the other artifact before its diagnostic exception handler.
    (tmp_path / "nm.brcached.e9map.json").unlink()
    recorded = []
    monkeypatch.setattr(executor, "_record_baseline_result", recorded.append)
    deadline = SimpleNamespace(remaining=lambda timeout: timeout, expires_at=None)
    with pytest.raises(ValueError, match="rerun binradar-setup"):
        executor._validate_baseline(executor.artifacts.patched, "poc", environment, deadline)
    assert recorded == []


def test_original_binary_run_has_no_e9_metadata(tmp_path, monkeypatch):
    """P0-2: the .orig memcheck run must not receive E9 metadata.

    run_probe() executes the tracer on the original binary, which has no
    E9 mappings: E9_EXCLUDE_RANGES and E9_RELOCATED_CALL_JUMPS must be
    present and empty, and the old singular range keys must be gone.
    """
    (tmp_path / "nm.orig").write_bytes(b"")
    (tmp_path / "poc").mkdir()
    (tmp_path / "poc" / "nullderef").write_bytes(b"")
    executor = _stub_executor(
        tmp_path, config={
            "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000",
            "BRPATCHED_E9_RELOCATED_CALL_JUMPS": RECORDS,
            "E9_RELOCATED_INSTRUCTIONS": "dead:beef",
        })
    executor._worker_environment = lambda: {
        **executor.config,
        "BINARY": executor.binary,
        "POC_INPUT": executor.poc_input,
        "TEST_CMD": executor.test_cmd,
        "PATCH_LOC": executor.patch_loc,
        "TOTAL_PATCHES": str(executor.total_patches),
    }

    captured = {}

    def fake_execute(command, cwd=None, env=None, timeout=60.0, verbose=True):
        captured["env"] = env
        return binradar.binradar_utils.ExecutionResult(
            success=True, exit_code=0, stdout="", stderr="[memcheck] [policy coverage-v4]\n")

    monkeypatch.setattr(binradar.binradar_utils, "execute", fake_execute)

    probe = SimpleNamespace(
        patch_hit=lambda: True,
        is_crash=lambda: True,
        patch_func_hit=lambda: True,
        multi_patch_func=lambda: False,
        patch_func_entry=0x401000,
        fault_addr=0x1234,
        patch_func_hit_cnt=3,
        serialize=lambda: "probe")
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner, "test_with_original",
        lambda self, testcase, verbose=True: probe)
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner, "test_with_file_trace",
        lambda self, testcase, patch_func_entry=0, verbose=True, timeout=60.0:
            SimpleNamespace(
                serialize_file_trace_result=lambda: "file-trace"))

    executor.run_probe()

    env = captured["env"]
    assert env["E9_EXCLUDE_RANGES"] == ""
    assert env["E9_RELOCATED_CALL_JUMPS"] == ""
    assert env["E9_RELOCATED_INSTRUCTIONS"] == ""
    for old_key in ("PATCH_RESERVE_RANGE", "E9_TRAMPOLINE_RANGE",
                    "E9_LOADER_RANGE"):
        assert old_key not in env, old_key


# ---------------------------------------------------------------------------
# Relocated-call extraction on synthetic artifacts (fixture guard)
# ---------------------------------------------------------------------------

def _write_original_instruction(path, instruction, address=0x401000):
    """Minimal ELF64 executable with one file-backed executable segment."""
    data = bytearray(PAGE * 2)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     2, 62, 1, address, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64,
                     1, 5, PAGE, address, address, PAGE, PAGE, PAGE)
    data[PAGE:PAGE + len(instruction)] = instruction
    path.write_bytes(data)


def _write_call_artifacts(tmp_path):
    """Original with one direct call; patched with refactor + trampoline.

    Original: call at 0x401000 (E8 rel32) -> ret 0x401005, target 0x401105.
    Patched:  REFACTOR map at 0x401000 containing ``jmp 0x54b000``;
              TRAMPOLINE map at 0x54b000 containing
              ``push 0x401005; jmp 0x401105`` (the E9 call-emulation pair).
    """
    original = tmp_path / "bin.orig"
    _write_original_instruction(original, b"\xe8\x00\x01\x00\x00")

    metadata = tmp_path / "bin.brpatched.json"
    metadata.write_text(
        '{"jsonrpc":"2.0","method":"instruction","params":'
        '{"address":"0x401000","length":5,"offset":4096},"id":1}\n'
        '{"jsonrpc":"2.0","method":"patch","params":{"trampoline":"$tmp_0",'
        '"metadata":{},"offset":4096},"id":2}\n')

    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched,
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[
            (0x401000, 0x1000, PAGE, REFACTOR, False),
            (0x54b000, 0x2000, PAGE, TRAMPOLINE, False),
        ])
    data = bytearray(patched.read_bytes())
    data.extend(b"\x00" * (0x3000 - len(data)))  # cover map file offsets
    refactor = bytearray(PAGE)
    refactor[0] = 0xE9
    struct.pack_into("<i", refactor, 1, 0x54b000 - 0x401005)
    data[0x1000:0x2000] = refactor
    trampoline = bytearray(PAGE)
    trampoline[0:5] = b"\x68\x05\x10\x40\x00"          # push 0x401005
    trampoline[5] = 0xE9
    struct.pack_into("<i", trampoline, 6, 0x401105 - 0x54b00a)
    data[0x2000:0x3000] = trampoline
    patched.write_bytes(data)
    return original, metadata, patched


@pytest.mark.parametrize("instruction,moved", [
    (b"\xff\x14\x24", b"\xff\x64\x24\x08"),
    (b"\xff\x54\x24\xf8", b"\xff\x24\x24"),  # disp8 -> disp0
    (b"\xff\x54\x24\x77", b"\xff\x64\x24\x7f"),
    (b"\xff\x54\x24\x78", b"\xff\xa4\x24\x80\x00\x00\x00"),
    (b"\xff\x94\x24\x78\xff\xff\xff", b"\xff\x64\x24\x80"),
    (b"\xff\x94\x24\xf8\xff\xff\xff", b"\xff\x24\x24"),
    (b"\xff\x94\x24\x00\x01\x00\x00", b"\xff\xa4\x24\x08\x01\x00\x00"),
    (b"\xff\x14\xcc", b"\xff\x64\xcc\x08"),  # rsp + rcx*8
    (b"\x42\xff\x14\x64", b"\x42\xff\x64\x64\x08"),  # rsp + r12*2
    (b"\x67\xff\x14\x24", b"\x67\xff\x64\x24\x08"),
    (b"\x64\xff\x14\x24", b"\x64\xff\x64\x24\x08"),
    (b"\x41\xff\x14\x24", b"\x41\xff\x24\x24"),  # r12 is not rsp
])
def test_rsp_memory_call_exact_identity(tmp_path, instruction, moved):
    import json
    prefix = b"\x68" + struct.pack("<I", 0x401000 + len(instruction))
    original, metadata, patched, pc = _write_instruction_artifacts(
        tmp_path, instruction, relocated=moved, prefix=prefix)
    runtime = binradar_setup.extract_e9_runtime_metadata(
        patched, metadata, original, 0x401000)
    assert runtime.relocated_calls == ((pc, 0x401000, 0x401000 + len(instruction)),)
    assert json.loads(Path(str(patched) + ".e9map.json").read_text())["instructions"] == [
        {"relocated": pc, "original": 0x401000}]


@pytest.mark.parametrize("instruction,moved", [
    (b"\xff\x14\x24", b"\xff\x24\x24"),  # missing adjustment
    (b"\xff\x14\x24", b"\xff\x64\x24\x10"),
    (b"\xff\x14\xcc", b"\xff\x64\xd4\x08"),  # wrong base
    (b"\xff\x14\xcc", b"\xff\x64\xc4\x08"),  # wrong index
    (b"\xff\x14\xcc", b"\xff\x64\x8c\x08"),  # wrong scale
    (b"\x67\xff\x14\x24", b"\xff\x64\x24\x08"),
    (b"\x41\xff\x14\x24", b"\x41\xff\x64\x24\x08"),
])
def test_rsp_memory_call_mismatch_rejects_identity(tmp_path, instruction, moved):
    prefix = b"\x68" + struct.pack("<I", 0x401000 + len(instruction))
    original, metadata, patched, _ = _write_instruction_artifacts(
        tmp_path, instruction, relocated=moved, prefix=prefix)
    sidecar = Path(str(patched) + ".e9map.json")
    sidecar.write_text("stale")
    with pytest.raises(ValueError, match="expected one proved"):
        binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert not sidecar.exists()


def test_original_call_at_executable_segment_end(tmp_path):
    import json
    original, metadata, patched = _write_call_artifacts(tmp_path)
    data = bytearray(original.read_bytes())
    struct.pack_into("<QQ", data, 64 + 32, 5, 5)
    original.write_bytes(data)
    runtime = binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert runtime.relocated_calls == ((0x54b005, 0x401000, 0x401005),)
    assert json.loads(Path(str(patched) + ".e9map.json").read_text())["instructions"] == [
        {"relocated": 0x54b005, "original": 0x401000}]
    # The fifth byte physically exists, but is outside executable file bytes.
    struct.pack_into("<QQ", data, 64 + 32, 4, 4)
    original.write_bytes(data)
    assert binradar_setup._original_instruction_run(bytes(data), 0x401000) == []
    with pytest.raises(ValueError, match="original ELF address"):
        binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert not Path(str(patched) + ".e9map.json").exists()


def _install_trap_records(patched, records, *, table_offset=512, trap_sites=(0x401000,)):
    data = bytearray(patched.read_bytes())
    fields = list(binradar_setup.E9_CONFIG_STRUCT.unpack_from(data))
    fields[20:22] = [len(records), table_offset]
    binradar_setup.E9_CONFIG_STRUCT.pack_into(data, 0, *fields)
    for index, record in enumerate(records):
        struct.pack_into("<qq", data, table_offset + index * 16, *record)
    for site in trap_sites:
        data[PAGE + site - 0x401000] = 0x27
    patched.write_bytes(data)


@pytest.mark.parametrize("is_call", [False, True])
@pytest.mark.parametrize("chain", ["trap", "trap-jump", "jump-trap", "trap-trap"])
def test_trap_executed_instruction_identity(tmp_path, is_call, chain):
    import json
    if is_call:
        original, metadata, patched = _write_call_artifacts(tmp_path)
        pc, ret = 0x54b005, 0x401005
    else:
        original, metadata, patched, pc = _write_instruction_artifacts(tmp_path, b"\x80\x38\x03")
    if chain == "trap":
        _install_trap_records(patched, [(0x401000, 0x54b000)])
    elif chain == "trap-trap":
        _install_trap_records(patched, [(0x401000, 0x401010), (0x401010, 0x54b000)],
                              trap_sites=(0x401000, 0x401010))
    else:
        data = bytearray(patched.read_bytes())
        source, target = ((0x401010, 0x54b000) if chain == "trap-jump"
                          else (0x401000, 0x401010))
        position = PAGE + source - 0x401000
        data[position:position + 5] = b"\xe9" + struct.pack("<i", target - source - 5)
        patched.write_bytes(data)
        trap_source, trap_target = ((0x401000, 0x401010) if chain == "trap-jump"
                                    else (0x401010, 0x54b000))
        _install_trap_records(patched, [(trap_source, trap_target)], trap_sites=(trap_source,))
    runtime = binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert runtime.relocated_calls == (((pc, 0x401000, ret),) if is_call else ())
    assert json.loads(Path(str(patched) + ".e9map.json").read_text())["instructions"] == [
        {"relocated": pc, "original": 0x401000}]


@pytest.mark.parametrize("recorded", [False, True])
def test_unresolvable_trap_entry_never_uses_dead_copy(tmp_path, recorded):
    import json
    original, metadata, patched, _ = _write_instruction_artifacts(tmp_path, b"\x80\x38\x03")
    records = [(0x401000, 0x401010), (0x401010, 0x401000)] if recorded else []
    if recorded:
        _install_trap_records(patched, records, trap_sites=(0x401000, 0x401010))
    else:
        data = bytearray(patched.read_bytes())
        data[PAGE] = 0x27
        patched.write_bytes(data)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert json.loads(Path(str(patched) + ".e9map.json").read_text())["instructions"] == []


@pytest.mark.parametrize("encoded", [b"\x48", b"\x66", b"\xff", b"\xe8\x00\x01\x00"])
def test_original_run_rejects_incomplete_segment_tail(tmp_path, encoded):
    original = tmp_path / "bin.orig"
    _write_original_instruction(original, encoded)
    data = bytearray(original.read_bytes())
    struct.pack_into("<QQ", data, 64 + 32, len(encoded), len(encoded))
    assert binradar_setup._original_instruction_run(bytes(data), 0x401000) == []


@pytest.mark.parametrize("defect", ["past-loader", "past-file", "header", "duplicate",
                                    "unsorted", "wrong-byte", "wrong-site", "wrong-target", "negative"])
def test_invalid_artifact_trap_records_remove_stale_map(tmp_path, defect):
    original, metadata, patched = _write_call_artifacts(tmp_path)
    records = [(0x401000, 0x54b000)]
    offset = 512
    trap_sites = (0x401000,)
    if defect == "duplicate":
        records.append((0x401000, 0x54b010))
    elif defect == "unsorted":
        records = [(0x401010, 0x54b000), (0x401000, 0x54b000)]
        trap_sites = (0x401000, 0x401010)
    elif defect == "wrong-byte":
        trap_sites = ()
    elif defect == "wrong-site":
        records = [(0x402000, 0x54b000)]
    elif defect == "wrong-target":
        records = [(0x401000, 0xdeadbeef)]
    elif defect == "negative":
        records = [(-1, 0x54b000)]
    elif defect == "header":
        offset = 16
    elif defect == "past-loader":
        offset = PAGE - 8
    elif defect == "past-file":
        offset = 3 * PAGE - 8
    if defect == "past-file":
        data = bytearray(patched.read_bytes())
        data.extend(b"\0" * 16)
        patched.write_bytes(data)
    _install_trap_records(patched, records, table_offset=offset, trap_sites=trap_sites)
    if defect == "past-file":
        data = patched.read_bytes()[:3 * PAGE]
        patched.write_bytes(data)
    sidecar = Path(str(patched) + ".e9map.json")
    sidecar.write_text("stale")
    with pytest.raises(ValueError):
        binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert not sidecar.exists()


def test_extract_relocated_call_jumps_synthetic(tmp_path):
    """One instrumented direct call maps to its trampoline jump (guard).

    Validates the synthetic fixture machinery end to end; Phase 2 reuses
    the same artifacts to test typed metadata extraction.
    """
    original, metadata, patched = _write_call_artifacts(tmp_path)
    jumps = binradar_setup.extract_relocated_call_jumps(
        patched, metadata, original, 0x401000)
    assert jumps == [(0x54b005, 0x401000, 0x401005)]
    import json
    runtime = binradar_setup.extract_e9_runtime_metadata(
        patched, metadata, original, 0x401000)
    assert runtime.relocated_calls == tuple(jumps)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == [{"relocated": 0x54b005, "original": 0x401000}]


def _write_instruction_artifacts(tmp_path, instruction, *, relocated=None,
                                 trampoline_address=0x54b000, prefix=b"",
                                 suffix="brpatched"):
    original = tmp_path / "bin.orig"
    patched = tmp_path / f"bin.{suffix}"
    metadata = tmp_path / f"bin.{suffix}.json"
    _write_original_instruction(original, instruction)
    metadata.write_text(
        '{"method":"instruction","params":{"address":"0x401000",'
        f'"length":{len(instruction)},"offset":4096}}}}\n'
        '{"method":"patch","params":{"offset":4096}}\n')
    _write_synthetic_e9_binary(
        patched, loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[(0x401000, PAGE, PAGE, REFACTOR, False),
              (trampoline_address, 2 * PAGE, PAGE, TRAMPOLINE, False)])
    data = bytearray(patched.read_bytes())
    data.extend(b"\xcc" * (3 * PAGE - len(data)))
    # Match E9's actual prefixed entry transfer (48 e9), not only bare E9.
    data[PAGE:PAGE + 6] = b"\x48\xe9" + struct.pack(
        "<i", trampoline_address - 0x401006)
    code = instruction if relocated is None else relocated
    relocated_pc = trampoline_address + len(prefix)
    tail = b"\xe9" + struct.pack(
        "<i", 0x401000 + len(instruction) - relocated_pc - len(code) - 5)
    data[2 * PAGE:2 * PAGE + len(prefix + code + tail)] = prefix + code + tail
    patched.write_bytes(data)
    return original, metadata, patched, relocated_pc


@pytest.mark.parametrize("instruction", [
    b"\x80\x38\x03",  # cmp byte ptr [rax],3: observed 14940 shape
    b"\x48\x8b\x00",  # mov rax,[rax]
    b"\xf7\x30",      # div dword ptr [rax]
    b"\xff\x20",      # jmp qword ptr [rax]
])
def test_exact_noncall_instruction_map(tmp_path, instruction):
    import hashlib
    import json
    original, metadata, patched, relocated_pc = _write_instruction_artifacts(
        tmp_path, instruction)
    result = binradar_setup.extract_e9_runtime_metadata(
        patched, metadata, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload == {
        "version": 1,
        "artifact-sha256": hashlib.sha256(patched.read_bytes()).hexdigest(),
        "original-sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "instructions": [{"relocated": relocated_pc, "original": 0x401000}],
    }
    assert result.relocated_calls == ()
    assert all(row["relocated"] != relocated_pc + 1 for row in payload["instructions"])


@pytest.mark.parametrize("opcode", [b"\x48\x8b\x05", b"\xff\x15"])
def test_rip_relative_instruction_adjustment(tmp_path, opcode):
    import json
    target = 0x402100
    original_code = opcode + struct.pack("<i", target - 0x401000 - len(opcode) - 4)
    if opcode == b"\xff\x15":
        prefix = b"\x68" + struct.pack("<I", 0x401006)
        relocated_pc = 0x54b005
        relocated_opcode = b"\xff\x25"
    else:
        prefix = b""
        relocated_pc = 0x54b000
        relocated_opcode = opcode
    moved = relocated_opcode + struct.pack("<i", target - relocated_pc - len(opcode) - 4)
    original, metadata, patched, pc = _write_instruction_artifacts(
        tmp_path, original_code, relocated=moved, prefix=prefix)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == [{"relocated": pc, "original": 0x401000}]


@pytest.mark.parametrize("defect", ["operand", "continuation", "rip-target"])
def test_unproved_instruction_semantics_are_omitted(tmp_path, defect):
    import json
    instruction = b"\x80\x38\x03"
    moved = b"\x80\x38\x04" if defect == "operand" else instruction
    if defect == "rip-target":
        instruction = b"\x48\x8b\x05" + struct.pack("<i", 0x402100 - 0x401007)
        moved = b"\x48\x8b\x05" + struct.pack("<i", 0x402101 - 0x54b007)
    original, metadata, patched, pc = _write_instruction_artifacts(
        tmp_path, instruction, relocated=moved)
    if defect == "continuation":
        data = bytearray(patched.read_bytes())
        # A helper can have exactly the original bytes, but a different
        # continuation is not the relocated original instruction.
        struct.pack_into("<i", data, 2 * PAGE + len(moved) + 1,
                         0x401100 - pc - len(moved) - 5)
        patched.write_bytes(data)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert json.loads(Path(str(patched) + ".e9map.json").read_text())["instructions"] == []


@pytest.mark.parametrize("opcode", [b"\xe9", b"\x0f\x85"])
def test_relocated_direct_branch_preserves_target(tmp_path, opcode):
    import json
    target = 0x402100
    instruction = opcode + struct.pack("<i", target - 0x401000 - len(opcode) - 4)
    moved = opcode + struct.pack("<i", target - 0x54b000 - len(opcode) - 4)
    original, metadata, patched, pc = _write_instruction_artifacts(
        tmp_path, instruction, relocated=moved)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert json.loads(Path(str(patched) + ".e9map.json").read_text())["instructions"] == [
        {"relocated": pc, "original": 0x401000}]


def test_dead_instruction_copy_does_not_map(tmp_path):
    import json
    instruction = b"\x80\x38\x03"
    original, metadata, patched, pc = _write_instruction_artifacts(tmp_path, instruction)
    data = bytearray(patched.read_bytes())
    dead_pc = pc + 0x100
    duplicate = instruction + b"\xe9" + struct.pack("<i", 0x401003 - dead_pc - 8)
    data[2 * PAGE + 0x100:2 * PAGE + 0x100 + len(duplicate)] = duplicate
    patched.write_bytes(data)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == [{"relocated": pc, "original": 0x401000}]


def test_ambiguous_reachable_instruction_copies_are_omitted(tmp_path):
    import json
    instruction = b"\x80\x38\x03"
    # Both arms are reachable and both reproduce the instruction and its
    # continuation. No address-order tiebreaker is an identity proof.
    original, metadata, patched, pc = _write_instruction_artifacts(
        tmp_path, instruction, prefix=b"\x74\x0e")
    data = bytearray(patched.read_bytes())
    duplicate_pc = 0x54b010
    duplicate = instruction + b"\xe9" + struct.pack("<i", 0x401003 - duplicate_pc - 8)
    data[2 * PAGE + 0x10:2 * PAGE + 0x10 + len(duplicate)] = duplicate
    patched.write_bytes(data)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert json.loads(Path(str(patched) + ".e9map.json").read_text())["instructions"] == []


@pytest.mark.parametrize("defect", ["wrong-length", "wrong-address", "conflict", "past-end"])
def test_invalid_producer_evidence_removes_stale_map(tmp_path, defect):
    original, metadata, patched, _ = _write_instruction_artifacts(tmp_path, b"\x80\x38\x03")
    sidecar = Path(str(patched) + ".e9map.json")
    sidecar.write_text('{"version":1,"instructions":[]}')
    evidence = metadata.read_text()
    if defect == "wrong-length":
        evidence = evidence.replace('"length":3', '"length":2')
    elif defect == "wrong-address":
        evidence = evidence.replace('"address":"0x401000"', '"address":"0x401001"')
    elif defect == "past-end":
        evidence = evidence.replace('"offset":4096', '"offset":999999')
    else:
        evidence += '{"method":"instruction","params":{"address":"0x401000","length":4,"offset":4096}}\n'
    metadata.write_text(evidence)
    with pytest.raises(ValueError):
        binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    assert not sidecar.exists()


def test_artifacts_have_independent_refreshed_instruction_maps(tmp_path):
    import json
    original, metadata, patched, pc = _write_instruction_artifacts(tmp_path, b"\x80\x38\x03")
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    first = json.loads(Path(str(patched) + ".e9map.json").read_text())
    original, cached_metadata, cached, cached_pc = _write_instruction_artifacts(
        tmp_path, b"\x80\x38\x03", trampoline_address=0x64b000, suffix="brcached")
    binradar_setup.extract_e9_runtime_metadata(cached, cached_metadata, original, 0x401000)
    second = json.loads(Path(str(cached) + ".e9map.json").read_text())
    assert first["instructions"] == [{"relocated": pc, "original": 0x401000}]
    assert second["instructions"] == [{"relocated": cached_pc, "original": 0x401000}]
    assert first["artifact-sha256"] != second["artifact-sha256"]
    binradar_setup._remove_cached_artifact(tmp_path, {"BINARY": "bin"})
    assert not cached.exists()
    assert not Path(str(cached) + ".e9map.json").exists()
    assert Path(str(patched) + ".e9map.json").exists()


def test_missing_specialized_metadata_emits_empty_bound_map(tmp_path):
    import json
    original, _, patched, _ = _write_instruction_artifacts(tmp_path, b"\x80\x38\x03")
    binradar_setup.extract_e9_runtime_metadata(patched, None, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == []
    assert len(payload["artifact-sha256"]) == len(payload["original-sha256"]) == 64


def _write_block_copy_artifacts(tmp_path, original_run, copied_run, *,
                                site_length, suffix="brpatched"):
    """E9 block relocation: refactor hops to a trampoline holding a run.

    ``original_run`` is the original byte sequence at the site;
    ``copied_run`` is its trampoline copy, with PC-relative operands
    re-encoded by E9 exactly as the real artifact does.  ``site_length`` is
    the decoded length of the first instruction, which is what e9tool records
    for the instrumented site.
    """
    original = tmp_path / "bin.orig"
    patched = tmp_path / f"bin.{suffix}"
    metadata = tmp_path / f"bin.{suffix}.json"
    _write_original_instruction(original, original_run)
    metadata.write_text(
        '{"method":"instruction","params":{"address":"0x401000",'
        f'"length":{site_length},"offset":4096}}}}\n'
        '{"method":"patch","params":{"offset":4096}}\n')
    _write_synthetic_e9_binary(
        patched, loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[(0x401000, PAGE, PAGE, REFACTOR, False),
              (0x54b000, 2 * PAGE, PAGE, TRAMPOLINE, False)])
    data = bytearray(patched.read_bytes())
    data.extend(b"\xcc" * (3 * PAGE - len(data)))
    data[PAGE:PAGE + 6] = b"\x48\xe9" + struct.pack("<i", 0x54b000 - 0x401006)
    data[2 * PAGE:2 * PAGE + len(copied_run)] = copied_run
    patched.write_bytes(data)
    return original, metadata, patched


def test_block_copy_run_with_original_branch_target_maps_every_instruction(
        tmp_path):
    """E9 may copy a run whose exit is a branch to the original address.

    Observed on libming/CVE-2018-8806: the trampoline copy of the site's
    ``mov r12,[rax+rdx*8]`` is followed by the copied ``movzx`` and
    ``test``/``je`` pair, whose ``je`` still targets the original image.
    The whole run proves one identity per original instruction.
    """
    import json
    head = b"\x48\x8b\x24\xd0" + b"\x41\x0f\xb6\x1c\x24" + b"\x84\xdb"
    branch_at = len(head)
    original_run = head + b"\x0f\x85" + struct.pack(
        "<i", 0x401100 - (0x401000 + branch_at) - 6)
    # The copied branch keeps the original target, re-encoded from the copy.
    copied_run = head + b"\x0f\x85" + struct.pack(
        "<i", 0x401100 - (0x54b000 + branch_at) - 6)
    original, metadata, patched = _write_block_copy_artifacts(
        tmp_path, original_run, copied_run, site_length=4)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original,
                                               0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == [
        {"relocated": 0x54b000, "original": 0x401000},
        {"relocated": 0x54b004, "original": 0x401004},
        {"relocated": 0x54b009, "original": 0x401009},
        {"relocated": 0x54b00b, "original": 0x40100b},
    ]


def test_register_indirect_call_emulation_maps_exact_jump(tmp_path):
    """A non-RIP indirect call site maps through its emulated jmp copy.

    Observed on libjpeg/CVE-2018-14498: original ``call [rbx+0x8]`` is
    rewritten as ``push <ret>; jmp [rbx+0x8]`` in the trampoline.  Objdump
    pads the rewritten ``jmp``/``call`` mnemonic column differently, so a
    whitespace-sensitive text comparison rejected the exact same operand
    encoding and aborted setup for every such subject.
    """
    import hashlib
    import json
    # call QWORD PTR [rbx+0x8]; ret = 0x401003
    instruction = b"\xff\x53\x08"
    # Trampoline: push 0x401003 ; jmp QWORD PTR [rbx+0x8]
    prefix = b"\x68" + struct.pack("<I", 0x401003)
    relocated = b"\xff\x63\x08"
    original, metadata, patched, pc = _write_instruction_artifacts(
        tmp_path, instruction, relocated=relocated, prefix=prefix)
    jumps = binradar_setup.extract_relocated_call_jumps(
        patched, metadata, original, 0x401000)
    assert jumps == [(pc, 0x401000, 0x401003)]
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload == {
        "version": 1,
        "artifact-sha256": hashlib.sha256(patched.read_bytes()).hexdigest(),
        "original-sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "instructions": [{"relocated": pc, "original": 0x401000}],
    }


def test_pure_register_indirect_call_emulation_maps(tmp_path):
    """``call rax`` (FF /2 with ModRM 0xD0) emulates through ``jmp rax``."""
    import json
    instruction = b"\xff\xd0"
    prefix = b"\x68" + struct.pack("<I", 0x401002)
    relocated = b"\xff\xe0"
    original, metadata, patched, pc = _write_instruction_artifacts(
        tmp_path, instruction, relocated=relocated, prefix=prefix)
    jumps = binradar_setup.extract_relocated_call_jumps(
        patched, metadata, original, 0x401000)
    assert jumps == [(pc, 0x401000, 0x401002)]
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == [{"relocated": pc, "original": 0x401000}]


def _write_diverged_execution_artifacts(tmp_path, *, second_trampoline):
    """Executed copy mutated; optionally a second, unreachable trampoline.

    The second trampoline holds the only byte-identical copy plus a jump
    back to the original continuation, but no edge reaches it.
    """
    instruction = b"\x80\x38\x03"
    original = tmp_path / "bin.orig"
    metadata = tmp_path / "bin.brpatched.json"
    _write_original_instruction(original, instruction)
    metadata.write_text(
        '{"method":"instruction","params":{"address":"0x401000",'
        f'"length":{len(instruction)},"offset":4096}}}}\n'
        '{"method":"patch","params":{"offset":4096}}\n')
    maps = [(0x401000, PAGE, PAGE, REFACTOR, False),
            (0x54b000, 2 * PAGE, PAGE, TRAMPOLINE, False)]
    if second_trampoline:
        maps.append((0x64b000, 3 * PAGE, PAGE, TRAMPOLINE, False))
    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched, loader_base=0x20e9e9000, loader_size=PAGE, maps=maps)
    data = bytearray(patched.read_bytes())
    data.extend(b"\xcc" * (4 * PAGE - len(data)))
    data[PAGE:PAGE + 6] = b"\x48\xe9" + struct.pack("<i", 0x54b000 - 0x401006)
    # Mutate the executed copy's operand so it no longer matches.
    data[2 * PAGE:2 * PAGE + 3] = b"\x80\x38\x04"
    data[2 * PAGE + 3:2 * PAGE + 8] = b"\xe9" + struct.pack(
        "<i", 0x401003 - (0x54b000 + 8))
    if second_trampoline:
        second = 3 * PAGE
        data[second:second + 3] = instruction
        data[second + 3:second + 8] = b"\xe9" + struct.pack(
            "<i", 0x401003 - (0x64b000 + 8))
    patched.write_bytes(data)
    return original, metadata, patched


@pytest.mark.parametrize("second_trampoline", [False, True])
def test_dead_copy_is_never_an_identity(tmp_path, second_trampoline):
    """Only the executed copy can be an instruction identity.

    When the executed trampoline copy diverges, the earlier code fell back
    to a unique byte-identical copy — reachable-code or not — and published
    that dead address as a proved identity.  Both shapes must stay
    unmapped: a diverged executed copy, with or without a second
    trampoline holding the only matching copy.
    """
    import json
    original, metadata, patched = _write_diverged_execution_artifacts(
        tmp_path, second_trampoline=second_trampoline)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == []


def test_run_length_rejects_mid_instruction_decode():
    """A branch entry decoded inside another instruction is not a run step.

    ``instruction_at`` merges branch-entry decodes into the sorted list; the
    run proof must require each matched instruction to start exactly where
    the previous one ended, and the jump-back proof must start where the
    matched instruction ends.  A mid-instruction decode that happens to
    match the next original instruction must not be accepted as its copy.
    """
    head = b"\xb8" + struct.pack("<I", 0x90008b)
    second = b"\x8b\x00"
    original_run = [
        (0x401000, head, "mov    eax,0x90008b"),
        (0x401005, second, "mov    eax,QWORD PTR [rax]"),
        (0x401007, b"\xe9\x00\x00\x00\x00", "jmp    0x402000"),
    ]
    in_e9 = lambda address: 0x54b000 <= address < 0x54d000
    # Sorted list with a branch-entry decode at 0x54b002 (inside the mov's
    # immediate) that matches the second original instruction, followed by a
    # jump back to the original continuation.
    non_contiguous = [
        (0x54b000, head, "mov    eax,0x90008b"),
        (0x54b002, second, "mov    eax,QWORD PTR [rax]"),
        (0x54b007, b"\xe9" + struct.pack("<i", 0x401007 - 0x54b00c),
         "jmp    0x401007"),
    ]
    assert binradar_setup._relocated_run_length(
        original_run, non_contiguous, 0, in_e9) is None
    # The genuine contiguous copy still proves the same run length.
    contiguous = [
        (0x54b000, head, "mov    eax,0x90008b"),
        (0x54b005, second, "mov    eax,QWORD PTR [rax]"),
        (0x54b007, b"\xe9" + struct.pack("<i", 0x401007 - 0x54b00c),
         "jmp    0x401007"),
    ]
    assert binradar_setup._relocated_run_length(
        original_run, contiguous, 0, in_e9) == 2


def test_prefixed_transfers_do_not_create_fall_through_edges():
    """A prefixed jump stays terminal; its following bytes are not reachable.

    E9 may preserve original prefix bytes ahead of its own transfer
    (``f2 e9`` renders as ``bnd jmp``, ``26 e9`` as ``es jmp``, a stray REX
    byte as ``rex.W``).  Treating those as non-terminal would add a false
    fall-through edge into dead bytes and let them reachable-publish.
    """
    assert binradar_setup._mnemonic("bnd jmp 0x402000") == "jmp"
    assert binradar_setup._mnemonic("es jmp 0x6239ac7") == "jmp"
    assert binradar_setup._mnemonic("rex.W") == ""
    assert binradar_setup._direct_jump_target("es jmp 0x6239ac7") == 0x6239ac7
    assert binradar_setup._direct_jump_target("bnd jmp 0x402000") == 0x402000
    assert binradar_setup._mnemonic("jmp    0x402000") == "jmp"
    # Every control-flow decision classifies through the same prefix-aware
    # rule: branch-condition comparison, terminality, and call emulation.
    original = (0x401000, b"\xeb\x02", "jmp    0x401004")
    prefixed = (0x54b000, b"\xf2\xeb\x02", "bnd jmp 0x401004")
    assert binradar_setup._same_instruction(original, prefixed)
    assert not binradar_setup._same_instruction(
        original, (0x54b000, b"\xf2\x75\x02", "bnd jne 0x401004"))
    assert binradar_setup._semantic_tokens("bnd jmp 0x401004") == [
        "jmp", "0x401004"]
    call = (0x401000, b"\xf2\xff\xd0", "call   rax")
    emulated = (0x54b000, b"\xf2\xff\xe0", "bnd jmp rax")
    assert binradar_setup._same_instruction(call, emulated, call_emulation=True)
    # A different indirect target is still rejected after the same rewrite:
    # the relocated bytes must differ from the original only at the opcode.
    assert not binradar_setup._same_instruction(
        call, (0x54b000, b"\xf2\xff\xe3", "bnd jmp rbx"), call_emulation=True)


def test_prefixed_site_copy_still_resolves_the_trampoline_entry(tmp_path):
    """A site copy may keep an original prefix byte before its own transfer.

    Observed on binutils/CVE-2017-6966: the rewritten copy of the site
    instruction decodes as ``rex.W`` followed by ``es jmp <trampoline>``.
    The entry resolver must skip the prefix rather than read the first
    decoded row, which is not a jump at all.
    """
    import json
    instruction = b"\x80\x38\x03"
    original = tmp_path / "bin.orig"
    metadata = tmp_path / "bin.brpatched.json"
    patched = tmp_path / "bin.brpatched"
    _write_original_instruction(original, instruction)
    metadata.write_text(
        '{"method":"instruction","params":{"address":"0x401000",'
        f'"length":{len(instruction)},"offset":4096}}}}\n'
        '{"method":"patch","params":{"offset":4096}}\n')
    _write_synthetic_e9_binary(
        patched, loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[(0x401000, PAGE, PAGE, REFACTOR, False),
              (0x54b000, 2 * PAGE, PAGE, TRAMPOLINE, False)])
    data = bytearray(patched.read_bytes())
    data.extend(b"\xcc" * (4 * PAGE - len(data)))
    # REFACTOR copy: preserved '48' prefix byte, then '26 e9' (es jmp) into
    # the trampoline — the real 6966 layout.
    hop = 0x54b000 - (0x401001 + 6)
    data[PAGE:PAGE + 1] = b"\x48"
    data[PAGE + 1:PAGE + 7] = b"\x26\xe9" + struct.pack("<i", hop)
    tail = b"\xe9" + struct.pack("<i", 0x401003 - 0x54b008)
    data[2 * PAGE:2 * PAGE + len(instruction) + len(tail)] = instruction + tail
    patched.write_bytes(data)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original, 0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == [{"relocated": 0x54b000, "original": 0x401000}]


def test_two_hop_rewrite_chain_reaches_the_trampoline(tmp_path):
    """The site copy may jump to a second rewritten location, not directly.

    Observed on libming/CVE-2018-8964: the refactor site jumps to 0xf407660,
    another rewritten page, which jumps into the real trampoline.  A single
    hop lookup would miss the executed copy entirely.
    """
    import json
    instruction = b"\x80\x38\x03"
    # Build the fixture with the intermediate page registered as a REFACTOR
    # map, exactly like the real libming/CVE-2018-8964 artifact: E9 rewrites
    # the site page, whose copy jumps to a second REFACTOR page that jumps
    # into the trampoline.  An unregistered page would not be followable.
    original = tmp_path / "bin.orig"
    metadata = tmp_path / "bin.brpatched.json"
    _write_original_instruction(original, instruction)
    metadata.write_text(
        '{"method":"instruction","params":{"address":"0x401000",'
        f'"length":{len(instruction)},"offset":4096}}}}\n'
        '{"method":"patch","params":{"offset":4096}}\n')
    _write_synthetic_e9_binary(
        patched := tmp_path / "bin.brpatched",
        loader_base=0x20e9e9000, loader_size=PAGE,
        maps=[(0x401000, PAGE, PAGE, REFACTOR, False),
              (0x64b000, 3 * PAGE, PAGE, REFACTOR, False),
              (0x54b000, 2 * PAGE, PAGE, TRAMPOLINE, False)])
    data = bytearray(patched.read_bytes())
    data.extend(b"\xcc" * (4 * PAGE - len(data)))
    # Trampoline copy of the site instruction plus its continuation jump.
    tail = b"\xe9" + struct.pack("<i", 0x401003 - (0x54b000 + 8))
    data[2 * PAGE:2 * PAGE + len(instruction) + len(tail)] = instruction + tail
    # Second rewritten page at 0x64b000: jmp into the trampoline.
    data[3 * PAGE:3 * PAGE + 5] = b"\xe9" + struct.pack(
        "<i", 0x54b000 - 0x64b005)
    # Site copy now hops to that page instead of the trampoline.
    data[PAGE:PAGE + 6] = b"\x48\xe9" + struct.pack("<i", 0x64b000 - 0x401006)
    pc = 0x54b000
    patched.write_bytes(data)
    binradar_setup.extract_e9_runtime_metadata(patched, metadata, original,
                                               0x401000)
    payload = json.loads(Path(str(patched) + ".e9map.json").read_text())
    assert payload["instructions"] == [{"relocated": pc, "original": 0x401000}]



# ---------------------------------------------------------------------------
# PROBE normalized-fault-reference run budget
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("policy_ack", [
    "[memcheck] [policy coverage-v4]\n", "[memcheck] [policy coverage-v3]\n",
    "[memcheck] [policy coverage-v2]\n",
    "[memcheck] [policy coverage-v1]\n",
    "", "[memcheck] [policy old]\n"])
@pytest.mark.parametrize(("success", "timed_out", "exit_code", "expected"), [
    (False, True, -signal.SIGTERM, None),  # managed timeout with salvage
    (True, False, -signal.SIGTERM, None),  # external SIGTERM after communicate
    (True, False, -signal.SIGSEGV, 0x4000affb90),  # real guest crash self-signals
])
def test_probe_reference_discriminates_guest_and_termination_signals(
        tmp_path, monkeypatch, success, timed_out, exit_code, expected, policy_ack):
    """Ignore cancellation salvage but retain a real guest-signal fault.

    QEMU re-raises real guest faults through a host signal too; blanket
    negative-return-code rejection would discard a legitimate SIGSEGV POC.
    """
    (tmp_path / "nm.orig").write_bytes(b"")
    (tmp_path / "poc").mkdir()
    (tmp_path / "poc" / "nullderef").write_bytes(b"")
    executor = _stub_executor(tmp_path)
    executor._worker_environment = lambda: {
        **executor.config,
        "BINARY": executor.binary,
        "POC_INPUT": executor.poc_input,
        "TEST_CMD": executor.test_cmd,
        "PATCH_LOC": executor.patch_loc,
        "TOTAL_PATCHES": str(executor.total_patches),
    }

    captured = {}

    def fake_execute(command, cwd=None, env=None, timeout=60.0, verbose=True):
        captured["reference_timeout"] = timeout
        return SimpleNamespace(
            success=success, timed_out=timed_out, exit_code=exit_code,
            stdout="",
            stderr=policy_ack + "[snapshot] [fault-reference] [version 3] [valid true] "
                   "[source guest-signal] [address 4000affb90] [image none] [image-offset 0]\n")

    def fake_file_trace(
            self, testcase, patch_func_entry=0, verbose=True, timeout=60.0):
        captured["file_trace_timeout"] = timeout
        return SimpleNamespace(
            serialize_file_trace_result=lambda: "file-trace")

    monkeypatch.setattr(binradar.binradar_utils, "execute", fake_execute)

    probe = SimpleNamespace(
        patch_hit=lambda: True,
        is_crash=lambda: True,
        patch_func_hit=lambda: True,
        multi_patch_func=lambda: False,
        patch_func_entry=0x401000,
        fault_addr=0x41ab2b,
        patch_func_hit_cnt=3,
        serialize=lambda: "probe")
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner, "test_with_original",
        lambda self, testcase, verbose=True: probe)
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner,
        "test_with_file_trace", fake_file_trace)

    if policy_ack != "[memcheck] [policy coverage-v4]\n":
        with pytest.raises(SystemExit, match="fresh run"):
            executor.run_probe()
        assert not (Path(executor.run_dir) / "probe-results.sbsv").exists()
        assert "file_trace_timeout" not in captured
        return
    executor.run_probe()

    # The default 900 s child cap is above the 600 s floor; neither PROBE
    # tracer invocation may fall back to execute()'s old 60 s default.
    expected_timeout = float(executor.forkserver_child_timeout)
    assert captured["reference_timeout"] == expected_timeout
    assert captured["file_trace_timeout"] == expected_timeout
    assert expected_timeout > 60.0
    reference = executor.probe_result.tracer_fault_reference
    assert (reference.address if reference is not None else None) == expected
    if reference is not None:
        assert reference.source == "guest-signal"


@pytest.mark.parametrize(("child_timeout", "expected_timeout"), [
    (300, 600),
    (1800, 1800),
])
def test_probe_run_budget_respects_floor_and_child_cap(
        tmp_path, monkeypatch, child_timeout, expected_timeout):
    """A low cap keeps the safety floor; a larger cap is not truncated."""

    (tmp_path / "nm.orig").write_bytes(b"")
    (tmp_path / "poc").mkdir()
    (tmp_path / "poc" / "nullderef").write_bytes(b"")
    executor = _stub_executor(tmp_path)
    executor.forkserver_child_timeout = child_timeout
    executor._worker_environment = lambda: {
        **executor.config,
        "BINARY": executor.binary,
        "POC_INPUT": executor.poc_input,
        "TEST_CMD": executor.test_cmd,
        "PATCH_LOC": executor.patch_loc,
        "TOTAL_PATCHES": str(executor.total_patches),
    }

    captured = {}

    def fake_execute(command, cwd=None, env=None, timeout=60.0, verbose=True):
        captured["reference_timeout"] = timeout
        return SimpleNamespace(success=True, timed_out=False, exit_code=0,
                               stdout="", stderr="[memcheck] [policy coverage-v4]\n")

    def fake_file_trace(
            self, testcase, patch_func_entry=0, verbose=True, timeout=60.0):
        captured["file_trace_timeout"] = timeout
        return SimpleNamespace(
            serialize_file_trace_result=lambda: "file-trace")

    monkeypatch.setattr(binradar.binradar_utils, "execute", fake_execute)
    probe = SimpleNamespace(
        patch_hit=lambda: True,
        is_crash=lambda: True,
        patch_func_hit=lambda: True,
        multi_patch_func=lambda: False,
        patch_func_entry=0x401000,
        fault_addr=0x41ab2b,
        patch_func_hit_cnt=3,
        serialize=lambda: "probe")
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner, "test_with_original",
        lambda self, testcase, verbose=True: probe)
    monkeypatch.setattr(
        binradar.binradar_verifier.BinRadarQemuRunner,
        "test_with_file_trace", fake_file_trace)

    executor.run_probe()

    assert captured["reference_timeout"] == expected_timeout
    assert captured["file_trace_timeout"] == expected_timeout
