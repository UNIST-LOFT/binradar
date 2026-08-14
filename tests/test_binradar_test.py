"""Tests for the Valgrind/QASAN address normalization."""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "binradar_test", ROOT / "fuzzolic" / "binradar-test.py")
binradar_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binradar_test)


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
