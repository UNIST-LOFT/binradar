#!/usr/bin/env python3
"""Phase A contract tests: freeze the Taosc 61f9f3a predicate formats.

These tests pin the exact Taosc output contract that the CWE-119
compatibility cutover (TAOSC_PREDICATE_COMPATIBILITY_PLAN.md) must satisfy.
They are written against the *current* binradar-setup.py behavior: the
generic family must keep converting, and the CWE-119 family must fail
loudly (never silently mis-parse).  Later phases replace the failure
assertions with typed-descriptor parsing.

Fixtures under tests/fixtures/taosc-61f9f3a/ are verbatim copies of Taosc
revision 61f9f3a6ad09bb0a7a6712a71c32d9da922333ed output, taken from the
stored workdirs:

  generic/            jasper/CVE-2016-8691/workdir (82,365 generic lines)
  cwe119-erm/         libxml2/CVE-2016-1839/workdir-013 (342 CWE-119 lines,
                      realloc allocator, crash.address != patch-location)
  cwe119-direct/      libtiff/CVE-2017-5225/workdir (malloc allocator,
                      crash.address == patch-location, stale predicates)
  calloc-trace/       potrace/CVE-2013-7437/workdir-013 (calloc allocator)
  taosc-specialized/  libjpeg/CVE-2012-2806/workdir (no predicates, no
                      allocator trace; CWE-369/476/617-style prebuilt)

Grammar source: utils/taosc/cwe119/filter.zig (61f9f3a).
"""

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "taosc-61f9f3a"
TAOSC_REV = "61f9f3a6ad09bb0a7a6712a71c32d9da922333ed"

_spec = importlib.util.spec_from_file_location(
    "binradar_setup", ROOT / "fuzzolic" / "binradar-setup.py")
binradar_setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar_setup)

predicate_to_branch_patch_str = binradar_setup.predicate_to_branch_patch_str
load_predicates = binradar_setup.load_predicates

REGISTERS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")

# The closed CWE-119 grammar emitted by cwe119/filter.zig (plan §2.1).
POINTER_REGEX = re.compile(
    r"^(?P<c1>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint64_t \*\)s->rsp\)\[[0-9]+\]) >= i->begin && "
    r"(?P<c2>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint64_t \*\)s->rsp\)\[[0-9]+\]) < i->end$")
SIZE_REGEX = re.compile(
    r"^(?P<scale>[1-9][0-9]*) \* "
    r"(?P<cell>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint(?:8|16|32)_t \*\)s->rsp\)\[[0-9]+\]) < i->end - i->begin$")


def _load_lines(name: str) -> list:
    return (FIXTURES / name / "predicates").read_text().splitlines()


def test_fixture_revision_recorded():
    """The Taosc revision and grammar source are recorded in the tests."""
    assert TAOSC_REV == "61f9f3a6ad09bb0a7a6712a71c32d9da922333ed"
    assert (ROOT / "utils" / "taosc" / "cwe119" / "filter.zig").exists()


def test_generic_fixture_is_generic():
    """Every generic fixture line parses with the current converter."""
    lines = _load_lines("generic")
    assert lines, "generic fixture must not be empty"
    for line in lines:
        assert predicate_to_branch_patch_str(line), line


def test_generic_fixture_has_no_cwe119_forms():
    for line in _load_lines("generic"):
        assert "i->begin" not in line and "i->end" not in line
        assert not line.startswith("s->")
        assert "s->rsp" not in line


def test_generic_fixture_covers_operator_forms():
    """The generic fixture exercises every operator the converter supports."""
    lines = _load_lines("generic")
    text = "\n".join(lines)
    for op in ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>",
               "==", "!=", "<", "<=", ">", ">=", "~"):
        assert op in text, f"generic fixture lacks operator {op!r}"
    # Unary plus and minus (e.g. "+max1", "-max1").
    assert re.search(r"(?<![<>=!])[+-]max1", text)


def test_cwe119_erm_fixture_matches_closed_grammar():
    """Every CWE-119 ERM line matches the closed filter.zig grammar."""
    lines = _load_lines("cwe119-erm")
    assert lines, "cwe119-erm fixture must not be empty"
    for line in lines:
        m = POINTER_REGEX.match(line)
        if m:
            assert m.group("c1") == m.group("c2"), \
                f"pointer predicate cells differ: {line!r}"
            continue
        m = SIZE_REGEX.match(line)
        assert m, f"line outside the closed CWE-119 grammar: {line!r}"
        assert m.group("scale") in ("1", "2", "4", "8"), \
            f"unexpected size scale: {line!r}"


def test_cwe119_erm_fixture_covers_all_forms():
    """All 16 registers, both cell kinds, all widths, and all 4 scales."""
    lines = _load_lines("cwe119-erm")
    text = "\n".join(lines)

    for reg in REGISTERS:
        assert f"s->{reg} >= i->begin" in text, f"missing pointer reg {reg}"
        assert f"{reg} < i->end" in text, f"missing size reg {reg}"

    for width in ("8", "16", "32", "64"):
        assert f"((uint{width}_t *)s->rsp)" in text, \
            f"missing stack width {width}"
    for scale in ("1", "2", "4", "8"):
        assert re.search(rf"^{scale} \* ", text, re.M), \
            f"missing size scale {scale}"

    # Pointer predicates must use uint64_t stack cells only.
    assert re.search(r"\(\(uint64_t \*\)s->rsp\)\[[0-9]+\] >= i->begin", text)
    assert not re.search(r"\(\(uint(?:8|16|32)_t \*\)s->rsp\)\[[0-9]+\] >= "
                         r"i->begin", text)


def test_cwe119_erm_fixture_stack_bounds():
    """Stack cell indices stay within stack-size (104 bytes)."""
    stack_size = int((FIXTURES / "cwe119-erm" / "stack-size").read_text())
    assert stack_size == 104
    for line in _load_lines("cwe119-erm"):
        for m in re.finditer(r"\(\(uint(8|16|32|64)_t \*\)s->rsp\)\[([0-9]+)\]",
                             line):
            width, index = int(m.group(1)), int(m.group(2))
            assert (index + 1) * (width // 8) <= stack_size, line


def test_cwe119_erm_fixture_allocator_trace():
    """The realloc calls/returns pair is present and well-formed."""
    trace = FIXTURES / "cwe119-erm" / "trace"
    calls = trace.joinpath("realloc.calls").read_text().splitlines()
    returns = trace.joinpath("realloc.returns").read_text().splitlines()
    assert calls and returns
    for line in calls:
        assert re.match(r"^[0-9]+\s+[0-9a-f]+$", line), line
    for line in returns:
        assert re.match(r"^[0-9a-f]+$", line), line
    # First call address receives set_size; first return receives set_base.
    assert calls[0].split()[1] == "486b4f"
    assert returns[0] == "486b55"
    # Bit indices must fit Taosc's 64-bit trace mask.
    assert all(int(line.split()[0]) < 64 for line in calls)


def test_cwe119_erm_fixture_crash_address_differs_from_patch_location():
    crash = (FIXTURES / "cwe119-erm" / "trace" / "crash.address").read_text()
    patch = (FIXTURES / "cwe119-erm" / "patch-location").read_text()
    assert crash.strip() == "4d56d6"
    assert patch.strip() == "4d60a5"
    assert crash.strip() != patch.strip()


def test_cwe119_direct_fixture_manifest():
    """crash.address == patch-location; stale predicates are generic."""
    trace = FIXTURES / "cwe119-direct" / "trace"
    crash = trace.joinpath("crash.address").read_text().strip()
    patch = (FIXTURES / "cwe119-direct" / "patch-location").read_text().strip()
    assert crash == patch == "4066d0"
    assert trace.joinpath("malloc.calls").exists()
    assert trace.joinpath("malloc.returns").exists()
    # The leftover predicates file is stale generic output, not CWE-119.
    for line in _load_lines("cwe119-direct"):
        assert "i->begin" not in line and "i->end" not in line


def test_calloc_trace_fixture():
    calls = (FIXTURES / "calloc-trace" / "calloc.calls").read_text().splitlines()
    returns = (FIXTURES / "calloc-trace" / "calloc.returns").read_text().splitlines()
    assert calls and returns
    assert calls[0].split()[1] == "40675c"
    assert returns[0] == "406761"


def test_taosc_specialized_fixture_manifest():
    """No predicates, no allocator trace: the prebuilt specialized path."""
    assert (FIXTURES / "taosc-specialized" / "predicates").read_text() == ""
    trace = FIXTURES / "taosc-specialized" / "trace"
    assert not trace.joinpath("malloc.calls").exists()
    assert not trace.joinpath("realloc.calls").exists()
    assert not trace.joinpath("calloc.calls").exists()
    crash = trace.joinpath("crash.address").read_text().strip()
    patch = (FIXTURES / "taosc-specialized" / "patch-location").read_text().strip()
    assert crash == "40a569"
    assert patch == "407f98"
    assert crash != patch


def test_current_converter_rejects_cwe119_erm():
    """The current converter must fail loudly on CWE-119 lines.

    This is the Phase A regression pin: the plan's §2.3 observed breakage.
    Later phases replace this with typed-descriptor parsing.
    """
    for line in _load_lines("cwe119-erm"):
        try:
            predicate_to_branch_patch_str(line)
        except ValueError as e:
            assert "unknown identifier" in str(e) or "unexpected" in str(e), \
                f"unexpected error for {line!r}: {e}"
        else:
            raise AssertionError(
                f"CWE-119 line must not convert with the generic parser: "
                f"{line!r}")


def test_current_converter_rejects_malformed_cwe119():
    """Malformed CWE-119 variants fail loudly, never silently mis-parse."""
    malformed = [
        "s->rax >= i->begin && s->rbx < i->end",   # mismatched cells
        "s->rax >= i->begin && s->rax < i->end && s->rax > i->begin",
        "s->rax >= i->begin",                       # truncated
        "1 * s->rax < i->end - i->begin + 1",       # extra term
        "1 * s->rax < i->end - i->begin",           # valid size form
        "((uint64_t *)s->rsp)[0] >= i->begin && ((uint64_t *)s->rsp)[0] < i->end",
        "s->rax >= i->begin && s->rax < i->end",    # valid pointer form
    ]
    for line in malformed:
        try:
            predicate_to_branch_patch_str(line)
        except ValueError:
            pass
        else:
            raise AssertionError(f"malformed line must not convert: {line!r}")


def test_load_predicates_keeps_physical_lines():
    """load_predicates retains physical source line numbers."""
    records = load_predicates(FIXTURES / "cwe119-erm" / "predicates")
    assert len(records) == 342
    assert records[0] == (1, "s->rax >= i->begin && s->rax < i->end")
    assert records[-1][0] == 342
    assert records[-1][1].startswith("8 * ")


def _main():
    import sys
    failed = 0
    for name in sorted(globals()):
        if name.startswith("test_") and callable(globals()[name]):
            try:
                globals()[name]()
                print(f"PASS {name}")
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                import traceback
                traceback.print_exc()
    if failed:
        print(f"{failed} test(s) failed")
        sys.exit(1)
    print("all tests passed")


if __name__ == "__main__":
    _main()
