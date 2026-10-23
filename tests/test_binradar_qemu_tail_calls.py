"""Native compatibility-tracer edges; uses the built BinRadar QEMU, not mocks."""

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
QEMU = ROOT / "utils/binradar-aflplusplus/afl-qemu-trace"

ASSEMBLY = r"""
.text
.globl _start
.type _start,@function
_start:
.cfi_startproc
call_patch:
    call leaf
    call direct
    call indirect
    mov $3, %edi
    call recursive
    mov $3, %edi
    call ordinary
    call relocated
after_calls:
    mov $60, %eax
    xor %edi, %edi
    syscall
.cfi_endproc
.size _start,.-_start

.type leaf,@function
leaf:
.cfi_startproc
leaf_patch:
    nop
    ret
.cfi_endproc
.size leaf,.-leaf

/* Force direct's tail jump to use E9 rather than EB. */
.space 160,0x90
.type direct,@function
direct:
.cfi_startproc
jump_patch:
    jmp leaf
.cfi_endproc
.size direct,.-direct

.type indirect,@function
indirect:
.cfi_startproc
    lea leaf(%rip), %rax
    jmp *%rax
.cfi_endproc
.size indirect,.-indirect

.type recursive,@function
recursive:
.cfi_startproc
recursive_patch:
    nop
    dec %edi
    jz recursive_done
    jmp recursive
recursive_done:
    ret
.cfi_endproc
.size recursive,.-recursive

.type ordinary,@function
ordinary:
.cfi_startproc
    lea ordinary_patch(%rip), %rax
ordinary_dispatch:
    jmp *%rax
ordinary_patch:
    nop
    dec %edi
    jnz ordinary_dispatch
    ret
.cfi_endproc
.size ordinary,.-ordinary

.type relocated,@function
relocated:
.cfi_startproc
    push $relocated_return
relocated_jump:
    jmp leaf
relocated_return:
    ret
.cfi_endproc
.size relocated,.-relocated
.section .note.GNU-stack,"",@progbits
"""


@pytest.fixture(scope="module")
def native_guest(tmp_path_factory):
    if platform.machine() != "x86_64" or not QEMU.is_file():
        pytest.skip("requires built x86_64 BinRadar afl-qemu-trace")
    for binary in ("cc", "nm", "strip"):
        if not shutil.which(binary):
            pytest.skip(f"requires {binary}")
    work = tmp_path_factory.mktemp("qemu-tail")
    return build_guest(work, ASSEMBLY)


def build_guest(work, assembly, *, stripped=True):
    source = work / "tail.S"
    source.write_text(assembly)
    guest = work / "tail"
    subprocess.run(["cc", "-nostdlib", "-static", "-no-pie",
                    "-Wl,--eh-frame-hdr", str(source), "-o", str(guest)],
                   check=True, capture_output=True)
    listing = subprocess.run(["nm", "-n", str(guest)], check=True,
                             text=True, capture_output=True).stdout
    symbols = {fields[2]: int(fields[0], 16)
               for line in listing.splitlines()
               if len(fields := line.split()) == 3}
    # No .symtab remains: attribution must really use unwind evidence.
    if stripped:
        subprocess.run(["strip", "--strip-all", str(guest)], check=True,
                       capture_output=True)
    return guest, symbols


def run_trace(native_guest, patch, *, basic_blocks=False, expect_crash=False):
    guest, symbols = native_guest
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("AFL_", "QASAN_", "E9_"))}
    args = [str(QEMU), "--asan", "none", "--patch-loc", hex(symbols[patch]),
            "--e9-relocated-call",
            ":".join(hex(symbols[name]) for name in
                     ("relocated_jump", "relocated_jump", "relocated_return"))]
    if basic_blocks:
        args.append("--trace-basic-blocks")
    result = subprocess.run(args + [str(guest)], env=env, capture_output=True,
                            text=True, timeout=15, check=False)
    if expect_crash:
        assert result.returncode != 0, result.stderr
        assert "[exit] [result crash]" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
    owners = [(int(entry, 16), int(hits)) for entry, hits in re.findall(
        r"\[patch-func\] \[location 0x[0-9a-f]+\] \[entry 0x([0-9a-f]+)\] "
        r"\[hits (\d+)\]", result.stderr)]
    return owners, result.stderr


@pytest.mark.parametrize("basic_blocks", [False, True])
@pytest.mark.parametrize("patch,owner,visits,hits", [
    ("leaf_patch", "leaf", 4, 4),
    ("recursive_patch", "recursive", 3, 3),
    ("ordinary_patch", "ordinary", 1, 3),
    ("call_patch", "_start", 1, 1),
    ("after_calls", "_start", 1, 1),
    ("jump_patch", "direct", 1, 1),
    ("relocated_jump", "relocated", 1, 1),
])
def test_stripped_tail_owners(native_guest, patch, owner, visits, hits,
                              basic_blocks):
    owners, log = run_trace(native_guest, patch, basic_blocks=basic_blocks)
    assert owners == [(native_guest[1][owner], visits)], log
    assert re.search(rf"\[patch-cov\].*\[covered true\] \[hits {hits}\]", log), log


def test_tail_crash_retains_original_caller(native_guest, tmp_path):
    assembly = ASSEMBLY.replace("    call leaf\n", "    call direct\ncaller_return:\n", 1)
    assembly = assembly.replace("leaf_patch:\n    nop", "leaf_patch:\n    ud2")
    guest = build_guest(tmp_path, assembly)
    owners, log = run_trace(guest, "leaf_patch", expect_crash=True)
    assert owners == [(guest[1]["leaf"], 1)], log
    assert re.search(rf"\[stacktrace\] \[idx 1\] \[addr 0x{guest[1]['caller_return']:x}\]",
                     log), log


def test_secondary_fde_inside_sized_function_is_not_a_tail(native_guest, tmp_path):
    assembly = ASSEMBLY.replace("ordinary_patch:\n", ".cfi_endproc\nordinary_patch:\n.cfi_startproc\n")
    guest = build_guest(tmp_path, assembly, stripped=False)
    owners, log = run_trace(guest, "ordinary_patch")
    assert owners == [(guest[1]["ordinary"], 1)], log
