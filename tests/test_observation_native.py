"""Real opt-in native capture; fixtures contain only local allocation/syscalls."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from binradar import paths


@pytest.fixture(scope="module")
def observation_guest(tmp_path_factory):
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required")
    work = tmp_path_factory.mktemp("observation-native")
    source = work / "observation.c"
    source.write_text(r'''
#include <stdlib.h>
struct Leaf { void *reserved; unsigned value; unsigned uninitialized; };
struct Root { struct Leaf *next; unsigned long uninitialized; };
unsigned global_value = 0;
void *calloc_block;
extern void capture(struct Root *, unsigned);
int main(int argc, char **argv) {
    struct Root *r = malloc(sizeof(*r));
    struct Leaf *leaf = malloc(sizeof(*leaf));
    if (!r || !leaf) return 2;
    r->next = leaf;
    leaf->value = argc > 1;
    r = realloc(r, 32);
    calloc_block = calloc(3, 8);
    if (!r || !calloc_block) return 2;
    global_value = argc > 1;
    capture(r, argc > 4 ? 3 : argc > 3 ? 2 : argc > 2);
    return 3;
}
__asm__(
".text\n"
".globl capture, patch_site, fault_site\n"
"capture: mov $2,%r13d\n"
"patch_site: nop\n"
"cmp $3,%esi\n"
"jne 4f\n"
".globl deferred_site, after_deferred_site\n"
"deferred_site: mov 32(%rdi),%ecx\n"
"after_deferred_site: mov $1,%ecx\n"
"xor %edi,%edi\n"
"mov $60,%eax\n"
"syscall\n"
"4: cmp $2,%esi\n"
"jne 2f\n"
"dec %r13d\n"
"jz 3f\n"
"movq $0,8(%rdi)\n"
"jmp patch_site\n"
"3: xor %esi,%esi\n"
"2:\n"
"mov (%rdi),%r12\n"
"test %esi,%esi\n"
"jz 1f\n"
"xor %eax,%eax\n"
"xor %edi,%edi\n"
"lea 8(%r12),%rsi\n"
"mov $1,%edx\n"
"syscall\n"
"1: mov 8(%r12),%ecx\n"
"mov global_value(%rip),%r10d\n"
"add %r10d,%ecx\n"
"mov $42,%eax\n"
"xor %edx,%edx\n"
"fault_site: div %ecx\n"
"xor %edi,%edi\n"
"mov $60,%eax\n"
"syscall\n"
);
''', encoding="ascii")
    guest = work / "observation"
    subprocess.run(["cc", "-O0", "-fno-pie", "-no-pie", "-fno-builtin",
                    str(source), "-o", str(guest)],
                   check=True, capture_output=True, timeout=20)
    table = work / "models.plt"
    subprocess.run([os.sys.executable, "tracer/tests/provenance/gen_plt.py",
                    "-o", str(table), str(guest)],
                   check=True, capture_output=True, timeout=20)
    output = subprocess.run(["nm", "-n", str(guest)], check=True,
                            capture_output=True, text=True, timeout=5).stdout
    symbols = {row.split()[2]: int(row.split()[0], 16)
               for row in output.splitlines() if len(row.split()) == 3}
    return guest, table, symbols


def run_capture(tmp_path, fixture, args=(), *, enabled=True, input_bytes=b"", cap=None):
    guest, table, symbols = fixture
    target = tmp_path / "observation.jsonl"
    env = {"PATH": os.environ["PATH"], "BINRADAR_FORKSERVER_ENABLE": "0",
           "BINRADAR_OSPREY_ENABLE": "0", "BINRADAR_TRACE_FILE": "none",
           "BINRADAR_TRACER_LOG_FILE": str(tmp_path / "tracer.log"),
           "PLT_INFO_FILE": str(table), "MALLOC_PERTURB_": "085",
           "BINRADAR_OBS_PATCH_LOC": hex(symbols["patch_site"]),
           "BINRADAR_OBS_TRACE_FILE": str(target)}
    if enabled:
        env["BINRADAR_OBS_ANALYSIS"] = "1"
    if cap is not None:
        env["BINRADAR_OBS_MAX_EVENTS"] = str(cap)
    result = subprocess.run([paths.TRACER_BIN, "-d", "page", str(guest), *args],
                            env=env, input=input_bytes, capture_output=True,
                            timeout=10, check=False)
    records = [json.loads(line) for line in target.read_text().splitlines()] if target.exists() else []
    return result, records, target


@pytest.mark.parametrize("normal", [False, True])
def test_real_heap_two_hop_global_and_initialization(tmp_path, observation_guest, normal):
    result, records, _ = run_capture(tmp_path, observation_guest, ("normal",) if normal else ())
    assert bool(result.returncode == 0) == normal, (result.stdout, result.stderr)
    assert records[0] == {"kind": "header", "schema_version": 1}
    assert records[-1] == {"kind": "end", "status": "ok"}, records[-5:]
    patch = next(r for r in records if r["kind"] == "patch")
    heaps = {r["base"]: r for r in patch["regions"] if r["kind"] == "heap" and r["state"] == "live"}
    root = heaps[patch["regs"][7]]
    leaf_base = int.from_bytes(bytes.fromhex(root["data"])[:8], "little")
    leaf = heaps[leaf_base]
    root_init = int.from_bytes(bytes.fromhex(root["init"]), "little")
    leaf_init = int.from_bytes(bytes.fromhex(leaf["init"]), "little")
    assert root_init & 0xFF == 0xFF
    assert root["size"] == 32
    assert root_init >> 8 == 0
    zeroed = next(r for r in heaps.values() if r["size"] == 24)
    assert int.from_bytes(bytes.fromhex(zeroed["init"]), "little") == (1 << 24) - 1
    assert bytes.fromhex(zeroed["data"]) == bytes(24)
    assert any(r["state"] == "freed" for r in patch["regions"] if r["kind"] == "heap")
    assert leaf_init & 0xF00 == 0xF00
    assert leaf_init & 0xF000 == 0
    loads = [r for r in records if r["kind"] == "load"]
    assert any(r["addr"] == root["base"] and r["size"] == 8 for r in loads)
    assert any(r["addr"] == leaf_base + 8 and r["size"] == 4 for r in loads)
    assert any(r["addr"] == observation_guest[2]["global_value"] for r in loads)
    faults = [r for r in records if r["kind"] == "fault"]
    assert bool(faults) != normal
    if faults:
        assert faults[0]["pc"] == observation_guest[2]["fault_site"]
        assert faults[0]["regs"], "divisor dependency must be captured"
        assert faults[0]["mem"] == [], "register division must not invent a memory sink"
    assert any(r["kind"] == "branch" for r in records)


def test_real_postpatch_read_is_actual_positive_interval(tmp_path, observation_guest):
    result, records, _ = run_capture(tmp_path, observation_guest, ("normal", "postread"), input_bytes=b"\x02")
    assert result.returncode == 0, result.stderr
    assert records[-1] == {"kind": "end", "status": "ok"}, records[-5:]
    reads = [r for r in records if r["kind"] == "sys_read"]
    assert len(reads) == 1 and reads[0]["size"] == 1
    assert reads[0]["src"] == []


def test_real_deferred_finding_freezes_before_continuation(tmp_path, observation_guest):
    _, records, _ = run_capture(tmp_path, observation_guest, ("normal", "deferred", "continue", "exit"))
    assert records[-1] == {"kind": "end", "status": "ok"}, records[-5:]
    faults = [row for row in records if row["kind"] == "fault"]
    assert len(faults) == 1
    fault = faults[0]
    assert records[-2] == fault, "no event may follow the admitted fault boundary"
    assert fault["pc"] == observation_guest[2]["deferred_site"]
    assert fault["quality"] == "tagged", "same-access promotion must retain object identity"
    assert fault["object_id"] > 0
    assert fault["requested_size"] == 32
    assert not any(row.get("pc") == observation_guest[2]["after_deferred_site"] for row in records)


def test_real_disabled_mode_has_no_analysis_file(tmp_path, observation_guest):
    result, records, target = run_capture(tmp_path, observation_guest, ("normal",), enabled=False)
    assert result.returncode == 0, result.stderr
    assert not records and not target.exists()


def test_real_capacity_is_explicit_not_complete(tmp_path, observation_guest):
    _, records, _ = run_capture(tmp_path, observation_guest, ("normal",), cap=1)
    assert records[-1] == {"kind": "end", "status": "window_overflow"}


def test_real_prior_snapshots_preserve_uninitialized_visit(tmp_path, observation_guest):
    result, records, _ = run_capture(tmp_path, observation_guest, ("normal", "repeat", "again"))
    assert result.returncode == 0, result.stderr
    assert records[-1] == {"kind": "end", "status": "ok"}, records[-5:]
    patches = [r for r in records if r["kind"] == "patch"]
    assert [p["hit_id"] for p in patches] == [0, 1]
    assert records[1:3] == patches, "old events must be replaced without dropping snapshots"
    init = []
    for patch in patches:
        root = next(r for r in patch["regions"]
                    if r["kind"] == "heap" and r["state"] == "live"
                    and r["base"] == patch["regs"][7])
        init.append(int.from_bytes(bytes.fromhex(root["init"]), "little"))
    assert init[0] & 0xFF00 == 0
    assert init[1] & 0xFF00 == 0xFF00
