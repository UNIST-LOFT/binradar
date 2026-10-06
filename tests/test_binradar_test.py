"""Tests for the Valgrind/QASAN address normalization."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "binradar_test", ROOT / "fuzzolic" / "binradar-test.py")
binradar_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binradar_test)


def test_tracer_reference_requires_explicit_valid_v2_row():
    old_row = (
        "[snapshot] [crash] [hit-count 1] [reason memcheck] "
        "[guest_pc dead] [guest_cs_base 0] [fault_addr dead] "
        "[host_fault_addr 0]\n")
    assert binradar_test.extract_tracer_fault_reference(old_row) is None

    normalized = (
        "[snapshot] [fault-reference] [version 2] [valid true] "
        "[source provenance-access] [address 0]\n")
    assert binradar_test.extract_tracer_fault_reference(normalized).identity_key == ("main", 0)


def test_tracer_probe_rejects_an_externally_cancelled_run(monkeypatch, tmp_path):
    """`execute` reports success for a process killed by an external
    termination signal, and the tracer can salvage the interrupted guest pc
    as a valid-looking v2 reference at its kill PC. That is not the subject's
    observed crash, so the probe must report it as failed rather than
    returning the salvaged address."""
    import binradar_utils
    from binradar_verifier import tracer_execution_cancelled
    import signal as signal_module

    salvaged = (
        "[snapshot] [fault-reference] [version 2] [valid true] "
        "[source guest-signal] [address 4000affb90]\n")

    def fake_execute(command, **kwargs):
        return binradar_utils.ExecutionResult(
            success=True, exit_code=-int(signal_module.SIGTERM),
            stdout="", stderr=salvaged)

    monkeypatch.setattr(binradar_test.binradar_utils, "execute", fake_execute)
    workdir = str(tmp_path)
    (tmp_path / "guest.orig").write_bytes(b"")
    fault_addr, exit_str, result, _ = binradar_test.run_tracer_probe(
        workdir, {"BINARY": "guest", "TEST_CMD": "@@"}, "poc", 5.0)
    assert fault_addr is None
    assert exit_str == ""
    assert result.success is False
    assert tracer_execution_cancelled(result.exit_code)


def test_valgrind_interceptor_uses_target_return_address():
    log = """
==1== Invalid write of size 1
==1==    at 0x484EA13: memmove (vg_replace_strmem.c:1382)
==1==    by 0x42A69B: ??? (in /work/tiffcrop.orig)
==1==    by 0x426F5F: ??? (in /work/tiffcrop.orig)
==1==  Address 0x0 is 1 bytes before a block
"""

    assert binradar_test.extract_valgrind_fault_addr(
        log, "/work/tiffcrop.orig") == 0x42A69C


def test_valgrind_direct_binary_access_keeps_at_address():
    log = """
==1== Invalid read of size 1
==1==    at 0x4066D0: ??? (in /work/tiffcp.orig)
==1==    by 0x404EB5: ??? (in /work/tiffcp.orig)
==1==  Address 0x0 is 0 bytes after a block
"""

    assert binradar_test.extract_valgrind_fault_addr(
        log, "/work/tiffcp.orig") == 0x4066D0


def test_valgrind_signal_uses_target_at_frame():
    log = """
==1== Process terminating with default action of signal 8 (SIGFPE)
==1==    at 0x456845: ??? (in /work/nm.orig)
==1==    by 0x4588C5: ??? (in /work/nm.orig)
==1==    by 0x4881BD6: (below main) (in /gnu/store/libc.so.6)
==1== 
==1== HEAP SUMMARY:
==1==    in use at exit: 0 bytes in 0 blocks
"""

    assert binradar_test.extract_valgrind_signal_addr(
        log, "/work/nm.orig") == 0x456845


def test_valgrind_signal_not_a_memory_error():
    log = """
==1== Process terminating with default action of signal 8 (SIGFPE)
==1==  Integer divide by zero at address 0x1002D052A1
==1==    at 0x42D80C: ??? (in /work/tiffmedian.orig)
==1==    by 0x413EED: ??? (in /work/tiffmedian.orig)
==1== ERROR SUMMARY: 0 errors from 0 contexts
"""

    assert binradar_test.extract_valgrind_fault_addr(
        log, "/work/tiffmedian.orig") is None
    assert binradar_test.extract_valgrind_signal_addr(
        log, "/work/tiffmedian.orig") == 0x42D80C


def test_valgrind_signal_interceptor_uses_target_return_address():
    log = """
==1== Process terminating with default action of signal 8 (SIGFPE)
==1==    at 0x4970184: __mktime_internal (in /gnu/store/libc.so.6)
==1==    by 0x4018AB: ??? (in /work/unzzipcat-mem.orig)
==1==    by 0x401985: ??? (in /work/unzzipcat-mem.orig)
==1== ERROR SUMMARY: 0 errors from 0 contexts
"""

    assert binradar_test.extract_valgrind_signal_addr(
        log, "/work/unzzipcat-mem.orig") == 0x4018AC
