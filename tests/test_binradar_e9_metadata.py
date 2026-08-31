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


def _parse_ranges(value: str):
    """Parse a comma-separated 0x..-0x.. interval list into (start, end)."""
    return [tuple(int(x, 16) for x in part.split("-"))
            for part in value.split(",")]


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
    the adjacent 0x2cc7000-0x2cc8000/0x2cc8000-0x2cc9000 pair.  The current
    min..max envelope records 0x54b000-0x2cc9000 (~39.5 MiB of excluded
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
    env = binradar_setup.extract_trampoline_info(patched)
    assert _parse_ranges(env["E9_TRAMPOLINE_RANGE"]) == [
        (0x54b000, 0x54c000), (0x2cc7000, 0x2cc9000)]


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
    env = binradar_setup.extract_trampoline_info(patched)
    assert _parse_ranges(env["E9_TRAMPOLINE_RANGE"]) == [
        (0x54b000, 0x54c000), (0x2cc7000, 0x2cc8000),
        (0x2cc9000, 0x2cca000)]


def test_disjoint_reserve_maps_are_not_enveloped(tmp_path):
    """P0-1 for RESERVE maps: four separated pages stay separate.

    Mirrors the observed tiffcp.brpatched layout, whose envelope excludes
    ~1.93 GiB of unmapped address space.
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
    env = binradar_setup.extract_trampoline_info(patched)
    assert _parse_ranges(env["PATCH_RESERVE_RANGE"]) == [
        (0x129a000, 0x129b000), (0x1000d000, 0x1000e000),
        (0x7c254000, 0x7c255000), (0x7ccba000, 0x7ccbb000)]


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
    env = binradar_setup.extract_trampoline_info(patched)
    assert _parse_ranges(env["E9_TRAMPOLINE_RANGE"]) == [
        (0x54b000, 0x54c000), (0x2cc7000, 0x2cc9000)]


def test_loader_range_is_exact(tmp_path):
    """The loader interval is already exact (guard)."""
    patched = tmp_path / "bin.brpatched"
    _write_synthetic_e9_binary(
        patched, loader_base=0x20e9e9000, loader_size=0x2000, maps=[])
    env = binradar_setup.extract_trampoline_info(patched)
    assert env["E9_LOADER_RANGE"] == "0x20e9e9000-0x20e9eb000"


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
    env_a = binradar_setup.extract_trampoline_info(a)
    env_b = binradar_setup.extract_trampoline_info(b)
    assert env_a["E9_TRAMPOLINE_RANGE"] == "0x54b000-0x54c000"
    assert env_b["E9_TRAMPOLINE_RANGE"] == "0x7c254000-0x7c255000"
    assert env_a["E9_LOADER_RANGE"] != env_b["E9_LOADER_RANGE"]


# ---------------------------------------------------------------------------
# P0-2: relocated-call propagation to symbolic tracer runs
# ---------------------------------------------------------------------------

def _stub_executor(tmp_path, e9_relocated_calls="",
                   patch_addr_ranges=("0x1-0x2", "0x3-0x4", "0x5-0x6")):
    executor = binradar.BinRadarExecutor.__new__(binradar.BinRadarExecutor)
    executor.workdir = str(tmp_path)
    executor.outdir = str(tmp_path / "out")
    executor.timeout = 60
    executor.binary = "nm"
    executor.poc_input = "poc/nullderef"
    executor.test_cmd = "-l @@"
    executor.patch_loc = "0x4585dd"
    executor.patch_addr_ranges = patch_addr_ranges
    executor.total_patches = 2
    executor.e9_relocated_calls = e9_relocated_calls
    executor.fuzzy = False
    executor.reverse_directed = False
    executor.disable_binradar = False
    executor.config = {}
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

    The current get_env() sets only the three range variables; the
    E9_RELOCATED_CALL_JUMPS value retained by from_env()/extract_config()
    never reaches the tracer environment.
    """
    executor = _stub_executor(tmp_path, e9_relocated_calls=RECORDS)
    for mode in ("fuzzolic", "directed", "binradar"):
        env = executor.get_env(mode, str(tmp_path))
        assert env.get("E9_RELOCATED_CALL_JUMPS") == RECORDS, mode


def test_original_binary_run_has_no_relocated_calls(tmp_path, monkeypatch):
    """P0-2: the .orig memcheck run must not receive relocated-call records.

    run_probe() executes the tracer on the original binary, which has no
    E9 mappings; E9_RELOCATED_CALL_JUMPS must be present and empty.  (The
    three singular range variables still carry patched values until the
    Phase 4 cutover removes them.)
    """
    (tmp_path / "nm.orig").write_bytes(b"")
    (tmp_path / "poc").mkdir()
    (tmp_path / "poc" / "nullderef").write_bytes(b"")
    executor = _stub_executor(tmp_path)

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
    assert "E9_RELOCATED_CALL_JUMPS" in env
    assert env["E9_RELOCATED_CALL_JUMPS"] == ""


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
