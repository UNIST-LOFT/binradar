#!/usr/bin/env python3
"""Phase 0 contract tests: pin the two P0 E9 runtime-metadata defects.

FIX_E9PATCH_RUNTIME_METADATA.md Phase 0 — these tests fail on the current
production code and pass once the exact-interval and relocated-call
propagation contracts land (Phases 1-2).

P0-1: disjoint E9 trampoline/reserve maps are collapsed into one min..max
      envelope by fuzzolic/binradar-setup.py::extract_trampoline_info,
      excluding unmapped gaps (39.5 MiB for xmllint, 1.93 GiB for tiffcp).
P0-2: BinRadarExecutor.get_env() never sets E9_RELOCATED_CALL_JUMPS for the
      symbolic tracer modes, and the .orig memcheck run receives the
      patched binary's range values.

The synthetic E9 binaries embed a minimal e9_config_s (the same layout
parsed by parse_e9patch_config) so the tests exercise the real production
parser without invoking e9tool.
"""

import importlib.util
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
        env, "prefilter", "0x7c254000-0x7c255000", "")
    assert env["BRPATCHED_E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
    assert env["BRPATCHED_E9_RELOCATED_CALL_JUMPS"] == RECORDS
    assert env["PREFILTER_E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert env["PREFILTER_E9_RELOCATED_CALL_JUMPS"] == ""
    assert binradar_utils.get_e9_metadata(env, "brpatched") == \
        ("0x54b000-0x54c000", RECORDS)
    assert binradar_utils.get_e9_metadata(env, "brcached") == ("", "")


def test_persist_e9_metadata_preserves_subject_fields(tmp_path):
    """Persistence updates only the prefixed keys of binradar.env."""
    env_path = tmp_path / "binradar.env"
    env_path.write_text('BINARY="nm"\nPATCH_LOC="0x4585dd"\n')
    metadata = binradar_setup.E9RuntimeMetadata(
        (binradar_setup.AddressRange(0x54b000, 0x54c000),), ())
    binradar_setup.persist_e9_metadata(tmp_path, "prefilter", metadata)
    binradar_setup.persist_e9_metadata(
        tmp_path, "brpatched",
        binradar_setup.E9RuntimeMetadata(
            (binradar_setup.AddressRange(0x7c254000, 0x7c255000),),
            ((0x54b091, 0x4d60a5, 0x4d60aa),)))
    env = binradar_setup.load_env(env_path)
    assert env["BINARY"] == "nm"
    assert env["PATCH_LOC"] == "0x4585dd"
    assert env["PREFILTER_E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
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
        "PREFILTER_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000",
        "PREFILTER_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    runner = binradar.binradar_verifier.BinRadarQemuRunner.from_env(
        str(tmp_path), env)
    # All prefixed values are stored.
    assert runner.e9_metadata["brpatched"] == (
        "0x54b000-0x54c000", ["0x54b091:0x4d60a5:0x4d60aa"])
    assert runner.e9_metadata["prefilter"] == (
        "0x7c254000-0x7c255000", ["0x7c254091:0x4d60a5:0x4d60aa"])
    assert runner.e9_metadata["brcached"] == ("", [])
    # Selection follows the executed binary path.
    assert runner.e9_metadata_for_binary(
        str(tmp_path / "nm.brpatched")) == (
            "0x54b000-0x54c000", ["0x54b091:0x4d60a5:0x4d60aa"])
    assert runner.e9_metadata_for_binary(
        str(tmp_path / "nm.brprefilter")) == (
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
        "PREFILTER_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    runner = binradar.binradar_verifier.BinRadarQemuRunner.from_env(
        str(tmp_path), env)
    patched_cmd = runner.get_qemu_stacktrace_command(True, "poc")
    assert "--e9-relocated-call" in patched_cmd
    assert "0x54b091:0x4d60a5:0x4d60aa" in patched_cmd
    assert "0x7c254091:0x4d60a5:0x4d60aa" not in patched_cmd
    orig_cmd = runner.get_qemu_stacktrace_command(False, "poc")
    assert "--e9-relocated-call" not in orig_cmd


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
        "PREFILTER_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000",
        "PREFILTER_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    executor = binradar.BinRadarExecutor.from_env(str(tmp_path), env)
    config = executor.extract_config()
    assert config["BRPATCHED_E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
    assert config["BRPATCHED_E9_RELOCATED_CALL_JUMPS"] == \
        "0x54b091:0x4d60a5:0x4d60aa"
    assert config["PREFILTER_E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert config["PREFILTER_E9_RELOCATED_CALL_JUMPS"] == \
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
        binradar_setup.PredicateFamily.GENERIC_ERM, None, 2)
    assert out == metadata
    assert (workdir / "imginfo.brcached").exists()
    assert (workdir / "imginfo.brcached.json").exists()
    assert (workdir / "brpatch-cached.c").exists()

    # e9compile ran with the destination define.
    compile_cmds = [c for c, _ in calls
                    if "e9compile" in c and "brpatch-cached.c" in c]
    assert compile_cmds, "e9compile brpatch-cached.c not invoked"
    assert "-DTAOSC_DEST=0x4106d8" in compile_cmds[0]
    assert "-DBRPATCH_TOTAL_PATCHES=2" in compile_cmds[0]
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
        binradar_setup.PredicateFamily.CWE805_ERM, allocator, 2)

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


def test_verifier_cache_runs_one_representative_per_branch_vector(tmp_path):
    workdir = tmp_path / "workdir"
    run_dir = tmp_path / "run"
    (run_dir / "minimized").mkdir(parents=True)
    workdir.mkdir()
    (workdir / "imginfo.brcached").write_bytes(b"cache")

    predicates = binradar_setup.binradar_taosc_predicates
    selected = [
        predicates.PredicateRecord(1, 1, "p1", "=v0p0"),
        predicates.PredicateRecord(2, 2, "p2", "=v1p0"),
        predicates.PredicateRecord(3, 3, "p3", "=v2p0"),
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

        def test_with_cached(self, patch_id, testcase):
            self.cached_calls.append(patch_id)
            snapshot = binradar.binradar_verifier.CachedSnapshot(
                patch_id=patch_id,
                branch=1,
                registers=(0, 0, 1) + (0,) * 13,
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
    testcase = binradar.binradar_verifier.Testcase(
        0, "input", "ok", 0, [0])
    verifier.testcases.append(testcase)

    rejected = verifier._test_testcase_batch([1, 2, 3], testcase)
    assert rejected == {1, 2}
    assert runner.cached_calls == [1]
    assert runner.patched_calls == [3]


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


# ---------------------------------------------------------------------------
# P0-2: relocated-call propagation to symbolic tracer runs
# ---------------------------------------------------------------------------

def _stub_executor(tmp_path, e9_metadata_prefix="brpatched", config=None):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.workdir = str(tmp_path)
    executor.outdir = str(tmp_path / "out")
    executor.timeout = 60
    executor.binary = "nm"
    executor.poc_input = "poc/nullderef"
    executor.test_cmd = "-l @@"
    executor.patch_loc = "0x4585dd"
    executor.e9_metadata_prefix = e9_metadata_prefix
    executor.config = config if config is not None else {}
    executor.e9_exclude_ranges, executor.e9_relocated_calls = \
        binradar_utils.get_e9_metadata(executor.config, e9_metadata_prefix)
    executor.total_patches = 2
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


def test_get_env_sets_relocated_calls_for_patched_modes(tmp_path):
    """P0-2: every patched symbolic tracer mode receives the records.

    The old get_env() set only the three range variables; the
    E9_RELOCATED_CALL_JUMPS value retained by from_env()/extract_config()
    never reached the tracer environment.
    """
    config = {
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000,0x2cc7000-0x2cc9000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": RECORDS,
    }
    executor = _stub_executor(tmp_path, config=config)
    for mode in ("fuzzolic", "directed", "binradar"):
        env = executor.get_env(mode, str(tmp_path))
        assert env.get("E9_RELOCATED_CALL_JUMPS") == RECORDS, mode
        assert env.get("E9_EXCLUDE_RANGES") == \
            "0x54b000-0x54c000,0x2cc7000-0x2cc9000", mode
        assert "PATCH_RESERVE_RANGE" not in env, mode
        assert "E9_TRAMPOLINE_RANGE" not in env, mode
        assert "E9_LOADER_RANGE" not in env, mode


def test_metadata_selection_is_artifact_scoped(tmp_path):
    """Selecting an artifact selects only its own prefixed metadata.

    Two artifacts with intentionally different ranges and jumps: the
    brpatched run must never receive the prefilter values and vice versa.
    """
    config = {
        "BRPATCHED_E9_EXCLUDE_RANGES": "0x54b000-0x54c000",
        "BRPATCHED_E9_RELOCATED_CALL_JUMPS": "0x54b091:0x4d60a5:0x4d60aa",
        "PREFILTER_E9_EXCLUDE_RANGES": "0x7c254000-0x7c255000",
        "PREFILTER_E9_RELOCATED_CALL_JUMPS": "0x7c254091:0x4d60a5:0x4d60aa",
    }
    brpatched = _stub_executor(tmp_path, e9_metadata_prefix="brpatched",
                               config=config)
    prefilter = _stub_executor(tmp_path, e9_metadata_prefix="prefilter",
                               config=config)
    env_b = brpatched.get_env("fuzzolic", str(tmp_path))
    env_p = prefilter.get_env("fuzzolic", str(tmp_path))
    assert env_b["E9_EXCLUDE_RANGES"] == "0x54b000-0x54c000"
    assert env_b["E9_RELOCATED_CALL_JUMPS"] == \
        "0x54b091:0x4d60a5:0x4d60aa"
    assert env_p["E9_EXCLUDE_RANGES"] == "0x7c254000-0x7c255000"
    assert env_p["E9_RELOCATED_CALL_JUMPS"] == \
        "0x7c254091:0x4d60a5:0x4d60aa"


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
        })

    captured = {}

    def fake_execute(command, cwd=None, env=None, timeout=60.0, verbose=True):
        captured["env"] = env
        return SimpleNamespace(success=True, stderr="")

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
        lambda self, testcase, patch_func_entry=0, verbose=True:
            SimpleNamespace(
                serialize_file_trace_result=lambda: "file-trace"))

    executor.run_probe()

    env = captured["env"]
    assert env["E9_EXCLUDE_RANGES"] == ""
    assert env["E9_RELOCATED_CALL_JUMPS"] == ""
    for old_key in ("PATCH_RESERVE_RANGE", "E9_TRAMPOLINE_RANGE",
                    "E9_LOADER_RANGE"):
        assert old_key not in env, old_key


# ---------------------------------------------------------------------------
# Relocated-call extraction on synthetic artifacts (fixture guard)
# ---------------------------------------------------------------------------

def _write_call_artifacts(tmp_path):
    """Original with one direct call; patched with refactor + trampoline.

    Original: call at 0x401000 (E8 rel32) -> ret 0x401005, target 0x401105.
    Patched:  REFACTOR map at 0x401000 containing ``jmp 0x54b000``;
              TRAMPOLINE map at 0x54b000 containing
              ``push 0x401005; jmp 0x401105`` (the E9 call-emulation pair).
    """
    original = tmp_path / "bin.orig"
    original.write_bytes(b"\xe8\x00\x01\x00\x00" + b"\x00" * 0xFFB)

    metadata = tmp_path / "bin.brpatched.json"
    metadata.write_text(
        '{"jsonrpc":"2.0","method":"instruction","params":'
        '{"address":"0x401000","length":5,"offset":0},"id":1}\n'
        '{"jsonrpc":"2.0","method":"patch","params":{"trampoline":"$tmp_0",'
        '"metadata":{},"offset":0},"id":2}\n')

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


def test_extract_relocated_call_jumps_synthetic(tmp_path):
    """One instrumented direct call maps to its trampoline jump (guard).

    Validates the synthetic fixture machinery end to end; Phase 2 reuses
    the same artifacts to test typed metadata extraction.
    """
    original, metadata, patched = _write_call_artifacts(tmp_path)
    jumps = binradar_setup.extract_relocated_call_jumps(
        patched, metadata, original, 0x401000)
    assert jumps == [(0x54b005, 0x401000, 0x401005)]
