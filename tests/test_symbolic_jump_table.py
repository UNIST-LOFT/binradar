"""Scaled qword loads and indirect dispatch retain real guest semantics."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from binradar import paths


@pytest.fixture(scope="module")
def jump_table_guest(tmp_path_factory):
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for jump-table integration")
    work = tmp_path_factory.mktemp("jump-table-guest")
    source = work / "jump-table.S"
    source.write_text(r'''
.text
.globl _start
_start:
    cmpq $2, (%rsp)
    jne fail
    mov 16(%rsp), %rdi
    xor %esi, %esi
    xor %edx, %edx
    mov $2, %eax
    syscall
    test %eax, %eax
    js fail
    mov %eax, %r14d
    mov %eax, %edi
    lea input(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    cmp $1, %rax
    jne fail
    mov %r14d, %edi
    mov $3, %eax
    syscall

    movzbl input(%rip), %eax
    and $3, %eax
    mov %rax, %rbx
    /* Absolute displacement plus a named scaled index matches the retired
     * finder. Reusing the index as the load destination and copying its value
     * stresses temporary reuse without retaining instrumentation scratch. */
    mov values(,%rax,8), %rax
    mov %rax, %r12
    mov %r12, output(%rip)
    mov dispatch(,%rbx,8), %rbx
    jmp *%rbx
case_zero:
    mov $20, %r12d
    jmp emit
case_one:
    mov $21, %r12d
    jmp emit
case_two:
    mov $22, %r12d
    jmp emit
case_three:
    mov $23, %r12d
emit:
    mov $1, %eax
    mov $1, %edi
    lea output(%rip), %rsi
    mov $8, %edx
    syscall
    cmp $8, %rax
    jne fail
    mov %r12d, %edi
    mov $60, %eax
    syscall
fail:
    mov $99, %edi
    mov $60, %eax
    syscall

.section .rodata
.balign 8
values:
    .ascii "zero000\n"
    .ascii "one1111\n"
    .ascii "two2222\n"
    .ascii "thr3333\n"
dispatch:
    .quad case_zero, case_one, case_two, case_three
/* Keep the writable segment file-backed: this tiny static ELF otherwise
 * hits the unrelated zero_bss loader failure before any guest instruction. */
.data
.balign 8
output: .quad 0
input: .byte 0
.section .note.GNU-stack,"",@progbits
''', encoding="ascii")
    guest = work / "jump-table"
    subprocess.run(
        ["cc", "-nostdlib", "-static", "-no-pie", "-o", str(guest), str(source)],
        check=True, capture_output=True, timeout=20)
    return guest


@pytest.mark.parametrize("index,output,exit_code", [
    (0, b"zero000\n", 20),
    (1, b"one1111\n", 21),
    (2, b"two2222\n", 22),
    (3, b"thr3333\n", 23),
])
def test_real_symbolic_scaled_load_and_dispatch(
        tmp_path, jump_table_guest, index, output, exit_code):
    testcase = tmp_path / "input"
    testcase.write_bytes(bytes([index]))
    log_path = tmp_path / "tracer.log"
    status_path = tmp_path / "collection.json"
    env = {
        "PATH": os.environ["PATH"],
        "NO_EXTERNAL_SOLVER": "1",
        "BINRADAR_FORKSERVER_ENABLE": "0",
        "BINRADAR_OSPREY_ENABLE": "0",
        "BINRADAR_MEMCHECK_ENABLE": "1",
        "BINRADAR_TRACE_FILE": "none",
        "BINRADAR_TRACER_LOG_FILE": str(log_path),
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "SYMBOLIC_TESTCASE_NAME": str(testcase),
        "SYMBOLIC_COLLECTION_STATUS_FILE": str(status_path),
    }
    result = subprocess.run(
        [paths.TRACER_BIN, "-symbolic", "-d", "page", str(jump_table_guest),
         str(testcase)], env=env, capture_output=True, timeout=30, check=False)
    log = log_path.read_text(encoding="utf-8")
    diagnostics = (result.stdout, result.stderr, log)
    assert result.returncode == exit_code, diagnostics
    assert result.stdout == output, diagnostics
    assert "[snapshot] [crash]" not in log, diagnostics
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["complete"] is True, status
    assert status["reason"] == "none", status
    assert status["queries"] > 0, "the table index must actually be symbolic"
