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
import struct
import subprocess
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


# ---------------------------------------------------------------------------
# Phase B: typed parser and lowering (TAOSC_PREDICATE_COMPATIBILITY_PLAN §6)
# ---------------------------------------------------------------------------

def test_strict_generic_lexer():
    """Unknown punctuation is an error, never silently skipped."""
    tokenize = binradar_setup.tokenize_generic
    assert tokenize("max1 - rdx == ~max1") == \
        ["max1", "-", "rdx", "==", "~", "max1"]
    # Whitespace variants are fine.
    assert tokenize("  max1\t- rdx  == ~max1 ") == \
        ["max1", "-", "rdx", "==", "~", "max1"]
    for bad in ("max1 ? rdx", "max1 @ rdx", "max1 # rdx", "max1; rdx",
                "max1, rdx", "max1!rdx"):
        try:
            tokenize(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"must reject {bad!r}")
    # "s->rax" is a valid generic token sequence (identifier, -, identifier);
    # the CWE-119 family detection, not the lexer, routes it to the typed
    # parser.
    assert tokenize("s->rax") == ["s", "-", ">", "rax"]


def test_parse_cwe119_pointer_descriptors():
    parse = binradar_setup.parse_cwe119_predicate
    RegisterCell = binradar_setup.RegisterCell
    StackCell = binradar_setup.StackCell
    Cwe119PointerPredicate = binradar_setup.Cwe119PointerPredicate

    pred = parse("s->rax >= i->begin && s->rax < i->end")
    assert pred == Cwe119PointerPredicate(RegisterCell(0))
    pred = parse("s->r15 >= i->begin && s->r15 < i->end")
    assert pred == Cwe119PointerPredicate(RegisterCell(15))
    pred = parse("((uint64_t *)s->rsp)[3] >= i->begin && "
                 "((uint64_t *)s->rsp)[3] < i->end")
    assert pred == Cwe119PointerPredicate(StackCell(64, 3))


def test_parse_cwe119_size_descriptors():
    parse = binradar_setup.parse_cwe119_predicate
    RegisterCell = binradar_setup.RegisterCell
    StackCell = binradar_setup.StackCell
    Cwe119SizePredicate = binradar_setup.Cwe119SizePredicate

    assert parse("1 * s->rbx < i->end - i->begin") == \
        Cwe119SizePredicate(1, RegisterCell(1))
    assert parse("8 * s->r15 < i->end - i->begin") == \
        Cwe119SizePredicate(8, RegisterCell(15))
    assert parse("2 * ((uint8_t *)s->rsp)[40] < i->end - i->begin") == \
        Cwe119SizePredicate(2, StackCell(8, 40))
    assert parse("4 * ((uint16_t *)s->rsp)[8] < i->end - i->begin") == \
        Cwe119SizePredicate(4, StackCell(16, 8))
    assert parse("8 * ((uint32_t *)s->rsp)[4] < i->end - i->begin") == \
        Cwe119SizePredicate(8, StackCell(32, 4))


def test_parse_cwe119_rejects_malformed():
    parse = binradar_setup.parse_cwe119_predicate
    malformed = [
        "s->rax >= i->begin && s->rbx < i->end",   # mismatched cells
        "s->rax >= i->begin && s->rax < i->end && s->rax > i->begin",
        "s->rax >= i->begin",                       # truncated
        "1 * s->rax < i->end - i->begin + 1",       # extra term
        "3 * s->rax < i->end - i->begin",           # unsupported scale
        "0 * s->rax < i->end - i->begin",           # zero scale
        "1 * ((uint64_t *)s->rsp)[0] < i->end - i->begin",  # 64-bit size cell
        "1 * s->rax < i->end",                      # missing - i->begin
        "s->rax >= i->begin && s->rax < i->end;",   # trailing junk
        "max1 - rdx == ~max1",                      # generic line
    ]
    for line in malformed:
        try:
            parse(line)
        except ValueError:
            pass
        else:
            raise AssertionError(f"must reject {line!r}")


def test_detect_family_generic():
    family, allocator = binradar_setup.detect_predicate_family(
        FIXTURES / "generic")
    assert family is binradar_setup.PredicateFamily.GENERIC_ERM
    assert allocator is None


def test_detect_family_cwe119_erm():
    family, allocator = binradar_setup.detect_predicate_family(
        FIXTURES / "cwe119-erm")
    assert family is binradar_setup.PredicateFamily.CWE119_ERM
    assert allocator is not None
    assert allocator.kind == "realloc"
    assert allocator.calls[0] == (0, "486b4f")
    assert allocator.returns[0] == "486b55"


def test_detect_family_cwe119_direct():
    family, allocator = binradar_setup.detect_predicate_family(
        FIXTURES / "cwe119-direct")
    assert family is binradar_setup.PredicateFamily.CWE119_DIRECT
    assert allocator is not None
    assert allocator.kind == "malloc"


def test_detect_family_taosc_specialized():
    family, allocator = binradar_setup.detect_predicate_family(
        FIXTURES / "taosc-specialized")
    assert family is binradar_setup.PredicateFamily.TAOSC_SPECIALIZED
    assert allocator is None


def test_detect_family_mixed_file_rejected(tmp_path):
    """Mixed generic/CWE-119 files fail with a source-line diagnostic."""
    workdir = tmp_path / "workdir"
    (workdir / "trace").mkdir(parents=True)
    (workdir / "predicates").write_text(
        "max1 - rdx == ~max1\n"
        "s->rax >= i->begin && s->rax < i->end\n")
    try:
        binradar_setup.detect_predicate_family(workdir)
    except ValueError as e:
        assert "predicates:2:" in str(e)
    else:
        raise AssertionError("mixed family must be rejected")


def test_detect_family_unknown_punctuation_rejected(tmp_path):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "predicates").write_text("max1 ? rdx == ~max1\n")
    try:
        binradar_setup.detect_predicate_family(workdir)
    except ValueError as e:
        assert "predicates:1:" in str(e)
    else:
        raise AssertionError("unknown punctuation must be rejected")


def test_parse_allocator_trace(tmp_path):
    parse = binradar_setup.parse_allocator_trace
    trace = tmp_path / "trace"
    trace.mkdir()

    # No artifacts -> None.
    assert parse(trace) is None

    # Partial set -> ValueError.
    (trace / "malloc.calls").write_text("0\t409200\n")
    try:
        parse(trace)
    except ValueError as e:
        assert "incomplete" in str(e)
    else:
        raise AssertionError("partial trace must be rejected")

    # Ambiguous kinds -> ValueError.
    (trace / "malloc.returns").write_text("409205\n")
    (trace / "realloc.calls").write_text("0\t486b4f\n")
    (trace / "realloc.returns").write_text("486b55\n")
    try:
        parse(trace)
    except ValueError as e:
        assert "ambiguous" in str(e)
    else:
        raise AssertionError("ambiguous trace must be rejected")

    # Bit index >= 64 -> ValueError.
    (trace / "malloc.calls").unlink()
    (trace / "malloc.returns").unlink()
    (trace / "realloc.calls").write_text("64\t486b4f\n")
    (trace / "realloc.returns").write_text("486b55\n")
    try:
        parse(trace)
    except ValueError as e:
        assert "bit index" in str(e)
    else:
        raise AssertionError("bit index >= 64 must be rejected")

    # Malformed call line -> ValueError.
    (trace / "realloc.calls").write_text("0 486b4f extra\n")
    try:
        parse(trace)
    except ValueError as e:
        assert "realloc.calls:1" in str(e)
    else:
        raise AssertionError("malformed call line must be rejected")

    # Empty files -> ValueError.
    (trace / "realloc.calls").write_text("")
    try:
        parse(trace)
    except ValueError as e:
        assert "empty" in str(e)
    else:
        raise AssertionError("empty calls must be rejected")


def test_parse_allocator_trace_calloc_fixture():
    allocator = binradar_setup.parse_allocator_trace(
        FIXTURES / "calloc-trace")
    assert allocator is not None
    assert allocator.kind == "calloc"
    assert allocator.calls[0] == (0, "40675c")
    assert allocator.returns[0] == "406761"


def test_emit_brpatches_inc_generic_and_cwe119(tmp_path):
    emit = binradar_setup._emit_brpatches_inc
    PredicateRecord = binradar_setup.PredicateRecord
    RegisterCell = binradar_setup.RegisterCell
    StackCell = binradar_setup.StackCell
    Cwe119PointerPredicate = binradar_setup.Cwe119PointerPredicate
    Cwe119SizePredicate = binradar_setup.Cwe119SizePredicate

    records = [
        PredicateRecord(1, 3, "max1 - rdx == ~max1",
                        "==-p0v3~p0p0"),
        PredicateRecord(2, 7, "s->rax >= i->begin && s->rax < i->end",
                        Cwe119PointerPredicate(RegisterCell(0))),
        PredicateRecord(3, 9, "((uint64_t *)s->rsp)[2] >= i->begin && "
                        "((uint64_t *)s->rsp)[2] < i->end",
                        Cwe119PointerPredicate(StackCell(64, 2))),
        PredicateRecord(4, 30, "1 * s->rbx < i->end - i->begin",
                        Cwe119SizePredicate(1, RegisterCell(1))),
        PredicateRecord(5, 42, "2 * ((uint8_t *)s->rsp)[40] < i->end - "
                        "i->begin",
                        Cwe119SizePredicate(2, StackCell(8, 40))),
    ]
    out = tmp_path / "brpatches.inc"
    emit(out, records)
    text = out.read_text()
    assert 'case 0:\n\treturn "p0";\n' in text
    assert 'case 1:\n\treturn "==-p0v3~p0p0"; /* predicate line 3 */' in text
    assert 'case 2:\n\treturn "c1p0"; /* predicate line 7: pointer register */' \
        in text
    assert 'case 3:\n\treturn "c1s64i2"; /* predicate line 9: pointer stack cell */' \
        in text
    assert 'case 4:\n\treturn "c2p1q1"; /* predicate line 30: size register */' \
        in text
    assert 'case 5:\n\treturn "c2s8i40q2"; /* predicate line 42: size stack cell */' \
        in text
    assert 'default:\n\treturn "p0";\n' in text
    # No CWE-119 source text may leak into the generated table.
    assert "i->begin" not in text and "i->end" not in text


def test_prefilter_meta_identity(tmp_path):
    """prefilter.sbsv metadata pins kind + predicates SHA-256."""
    load = binradar_setup.load_prefilter_passed_ids
    write = binradar_setup.write_prefilter
    sha = binradar_setup.predicates_sha256

    predicates = tmp_path / "predicates"
    predicates.write_text("max1 - rdx == ~max1\n")
    sbsv = tmp_path / "prefilter.sbsv"
    write(sbsv, [(1, True, "", "max1 - rdx == ~max1")], 0.0,
          kind="generic-erm", sha256=sha(predicates))

    # Matching metadata parses.
    assert load(sbsv, expected_kind="generic-erm",
                expected_sha256=sha(predicates)) == {1: 1}
    # Wrong kind fails open.
    assert load(sbsv, expected_kind="cwe119-erm",
                expected_sha256=sha(predicates)) is None
    # Wrong hash fails open.
    assert load(sbsv, expected_kind="generic-erm",
                expected_sha256="0" * 64) is None
    # Missing metadata fails open when expected.
    legacy = tmp_path / "legacy.sbsv"
    legacy.write_text(
        "[prefilter] [res] [id 1] [pass true] [new-id 1]\n"
        "[prefilter] [done] [total 1] [survived 1] [time 0.01]\n")
    assert load(legacy, expected_kind="generic-erm",
                expected_sha256=sha(predicates)) is None
    # Legacy files without expectations still parse (fail-open path).
    assert load(legacy) == {1: 1}
    # The meta row is written first.
    assert sbsv.read_text().startswith(
        f"[prefilter] [meta] [version 1] [kind generic-erm] [sha256 {sha(predicates)}]\n")


def test_predicates_sha256_stable():
    sha = binradar_setup.predicates_sha256
    assert sha(FIXTURES / "generic" / "predicates") == \
        sha(FIXTURES / "generic" / "predicates")
    assert len(sha(FIXTURES / "generic" / "predicates")) == 64


# ---------------------------------------------------------------------------
# Phase C: runtime parity (TAOSC_PREDICATE_COMPATIBILITY_PLAN §7)
# ---------------------------------------------------------------------------

# Scenario table shared with tests/test_brpatch_dest.c.  Each entry is
# (name, descriptor, registers, stack bytes, clamps, expected_br).
# The C test prints "RESULT <name> <br> <jumped>"; the Python mirror must
# agree on <br> for every scenario.
CWE119_SCENARIOS = [
    # (name, predicate, regs, stack, clamps, expected_br)
    ("ptr-reg-inside", "s->rax >= i->begin && s->rax < i->end",
     [0x1000] + [0] * 15, b"", [(0x1000, 0x2000)], 0),
    ("ptr-reg-outside", "s->rax >= i->begin && s->rax < i->end",
     [0x3000] + [0] * 15, b"", [(0x1000, 0x2000)], 1),
    ("ptr-reg-boundary", "s->rax >= i->begin && s->rax < i->end",
     [0x2000] + [0] * 15, b"", [(0x1000, 0x2000)], 1),
    ("ptr-stack-inside", "((uint64_t *)s->rsp)[0] >= i->begin && "
     "((uint64_t *)s->rsp)[0] < i->end",
     [0] * 16, (0x1500).to_bytes(8, "little"), [(0x1000, 0x2000)], 0),
    ("ptr-zero-clamp", "s->rax >= i->begin && s->rax < i->end",
     [0] * 16, b"", [(0, 0)], 1),
    ("size-reg-equal", "1 * s->rbx < i->end - i->begin",
     [0, 0x1000] + [0] * 14, b"", [(0x1000, 0x2000)], 1),
    ("size-reg-inside", "1 * s->rbx < i->end - i->begin",
     [0, 0x800] + [0] * 14, b"", [(0x1000, 0x2000)], 0),
    ("size-reg-scale8", "8 * s->rbx < i->end - i->begin",
     [0, 0x1ff] + [0] * 14, b"", [(0x1000, 0x2000)], 0),
    ("size-reg-overflow", "8 * s->rbx < i->end - i->begin",
     [0, 0x2000000000000000] + [0] * 14, b"", [(0x1000, 0x2000)], 2),
    ("size-stack16", "2 * ((uint16_t *)s->rsp)[0] < i->end - i->begin",
     [0] * 16, (0x500).to_bytes(2, "little"), [(0x1000, 0x2000)], 0),
    ("size-stack8", "1 * ((uint8_t *)s->rsp)[0] < i->end - i->begin",
     [0] * 16, b"\xff", [(0x1000, 0x2000)], 0),
    ("ptr-multi-clamp", "s->rax >= i->begin && s->rax < i->end",
     [0x2500] + [0] * 15, b"", [(0x1000, 0x2000), (0x2000, 0x3000)], 0),
    ("size-multi-clamp-none", "1 * s->rbx < i->end - i->begin",
     [0, 0x5000] + [0] * 14, b"", [(0x1000, 0x2000), (0x2000, 0x3000)], 1),
]

# jnz() scenarios: (name, patch_id, base, index, size, disp, clamps, br).
JNZ_SCENARIOS = [
    ("jnz-id0-inside", 0, 0x1000, 0, 1, 0, [(0x1000, 0x2000)], 0),
    ("jnz-id1-inside", 1, 0x1000, 0, 1, 0, [(0x1000, 0x2000)], 0),
    ("jnz-id1-outside", 1, 0x3000, 0, 1, 0, [(0x1000, 0x2000)], 1),
    ("jnz-id1-indexed", 1, 0x1000, 2, 8, 0x10, [(0x1000, 0x2000)], 0),
    ("jnz-id1-multi", 1, 0x2500, 0, 1, 0,
     [(0x1000, 0x2000), (0x2000, 0x3000)], 0),
]


def _build_brpatches_inc(tmp_path):
    """Write the brpatches.inc used by the C runtime test.

    Descriptor ids must match the scenario ids in test_brpatch_dest.c:
      0: "p0" (false)            1: "=p1p1" (generic, always true)
      2: "c1p0"                  3: "c1s64i0"
      4: "c2p1q1"                5: "c2s16i0q2"
      6: "c2p1q8"                7: "c1s32i0" (malformed descriptor)
    """
    out = tmp_path / "brpatches.inc"
    out.write_text(
        'case 0:\n\treturn "p0";\n'
        'case 1:\n\treturn "=p1p1";\n'
        'case 2:\n\treturn "c1p0";\n'
        'case 3:\n\treturn "c1s64i0";\n'
        'case 4:\n\treturn "c2p1q1";\n'
        'case 5:\n\treturn "c2s16i0q2";\n'
        'case 6:\n\treturn "c2p1q8";\n'
        'case 7:\n\treturn "c1s32i0";\n'
        'default:\n\treturn "p0";\n')
    return out


def _run_c_runtime_test(tmp_path):
    """Compile and run tests/test_brpatch_dest.c, returning its output."""
    executable = tmp_path / "test_brpatch_dest"
    subprocess.run([
        "cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-Wno-missing-field-initializers", "-Wno-unused-parameter",
        "-Wno-unused-function", "-Wno-implicit-fallthrough",
        "-DBRPATCH_CWE119", "-DBRPATCH_ALLOC_MALLOC",
        f"-I{ROOT / 'utils' / 'e9patch' / 'examples'}",
        f"-I{tmp_path}",
        str(ROOT / "tests" / "test_brpatch_dest.c"),
        "-o", str(executable),
    ], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_c_runtime_parity():
    """C dest()/jnz() and the Python mirror agree on every CWE-119 vector."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _build_brpatches_inc(tmp_path)
        output = _run_c_runtime_test(tmp_path)

    results = {}
    for line in output.splitlines():
        if line.startswith("RESULT "):
            fields = line.split()
            results[fields[1]] = fields[2:]
    assert "ALL-PASS" in output, output

    # dest() scenarios: mirror must agree with the C branch value.
    for name, text, regs, stack, clamps, expected in CWE119_SCENARIOS:
        predicate = binradar_setup.parse_cwe119_predicate(text)
        br = binradar_setup.cwe119_branch_taken(predicate, regs, stack, clamps)
        assert br == expected, f"{name}: mirror br {br} != expected {expected}"
        c_br, jumped = results[name]
        assert int(c_br) == expected, \
            f"{name}: C br {c_br} != expected {expected}"
        assert jumped == ("1" if expected == 1 else "0"), \
            f"{name}: C jumped {jumped} inconsistent with br {c_br}"

    # jnz() scenarios: id 0 never jumps; id 1 jumps iff outside all clamps.
    for name, patch_id, base, index, size, disp, clamps, expected in \
            JNZ_SCENARIOS:
        address = (base + index * size + disp) & ((1 << 64) - 1)
        if patch_id == 0:
            assert expected == 0
        else:
            inside = any(begin <= address < end for begin, end in clamps)
            assert expected == (0 if inside else 1)
        c_br, jumped = results[name]
        assert int(c_br) == expected, f"{name}: C br {c_br}"
        assert jumped == ("1" if expected == 1 else "0"), name

    # Dynamic selection: patch_shm {id=1, v=7} overrides env PATCH_ID.
    assert results["jnz-dynamic"] == ["1", "1", "1", "7"]

    # Tracker semantics: mark arms the hooks; set_size/set_base record.
    assert results["tracker-record"] == ["PASS"]
    assert results["tracker-ring"] == ["PASS"]

    # Malformed descriptor and unknown id follow the original path (br 0).
    assert results["malformed-descriptor"] == ["0", "0"]
    assert results["unknown-id"] == ["0", "0"]
    # Generic entry still evaluates: "=p1p1" is always true.
    assert results["generic-always-true"] == ["1", "1"]
    # Patch id 0 never jumps.
    assert results["patch-id-0"] == ["0", "0"]


def test_c_runtime_parity_overflow_and_boundary():
    """Overflow reports br 2; the size boundary is a branch (not <)."""
    predicate = binradar_setup.parse_cwe119_predicate(
        "8 * s->rbx < i->end - i->begin")
    # 8 * 0x2000000000000000 overflows u64 -> br 2.
    assert binradar_setup.cwe119_branch_taken(
        predicate, [0, 0x2000000000000000] + [0] * 14, b"",
        [(0x1000, 0x2000)]) == 2
    # size == capacity is NOT < capacity -> branch (br 1).
    assert binradar_setup.cwe119_branch_taken(
        predicate, [0, 0x200] + [0] * 14, b"",
        [(0x1000, 0x2000)]) == 1
    # size < capacity -> no branch (br 0).
    assert binradar_setup.cwe119_branch_taken(
        predicate, [0, 0x1ff] + [0] * 14, b"",
        [(0x1000, 0x2000)]) == 0


# ---------------------------------------------------------------------------
# Phase D: multipoint E9 build (TAOSC_PREDICATE_COMPATIBILITY_PLAN §6.3/§6.4)
# ---------------------------------------------------------------------------

def test_parse_e9tool_patch_metadata_all_offsets(tmp_path):
    """All patch offsets are returned, not just the last one."""
    metadata = tmp_path / "meta.json"
    metadata.write_text(
        '{"jsonrpc":"2.0","method":"instruction","params":'
        '{"address":"0x40de52","length":5,"offset":56914},"id":1}\n'
        '{"jsonrpc":"2.0","method":"instruction","params":'
        '{"address":"0x4d60a5","length":5,"offset":876709},"id":2}\n'
        '{"jsonrpc":"2.0","method":"patch","params":{"trampoline":"$tmp_0",'
        '"metadata":{},"offset":56914},"id":3}\n'
        '{"jsonrpc":"2.0","method":"patch","params":{"trampoline":"$tmp_1",'
        '"metadata":{},"offset":876709,},"id":4}\n')
    offsets, instructions = binradar_setup._parse_e9tool_patch_metadata(
        metadata)
    assert offsets == [56914, 876709]
    assert instructions[56914] == (0x40de52, 5)
    assert instructions[876709] == (0x4d60a5, 5)


def test_build_instrumentation_spec_order():
    """First call gets set_size, later calls mark, first return set_base,
    patch site last (mirrors taosc cwe119/synth.in::e9trace)."""
    trace = binradar_setup.AllocatorTrace(
        "malloc",
        [(0, "409200"), (1, "410370"), (2, "4046a9")],
        ["409205", "410375", "4046ae"])
    spec = binradar_setup.build_instrumentation_spec(
        trace, "0x409249", "if dest(state)@brpatch goto")
    assert spec.entries == (
        ("0x409200", "set_size(rdi,rsi)@brpatch"),
        ("0x410370", "mark(1)@brpatch"),
        ("0x4046a9", "mark(2)@brpatch"),
        ("0x409205", "set_base(rax)@brpatch"),
        ("0x409249", "if dest(state)@brpatch goto"),
    )
    assert spec.o0 is True


def test_e9tool_command_identical_spec():
    """JSON-metadata and final-binary commands share one ordered spec."""
    trace = binradar_setup.AllocatorTrace(
        "realloc",
        [(0, "486b4f"), (1, "487287")],
        ["486b55", "48728c"])
    spec = binradar_setup.build_instrumentation_spec(
        trace, "0x4d60a5", "if jnz($mem0,dest)@brpatch goto")
    json_cmd = binradar_setup.e9tool_command(
        spec, Path("out.json"), Path("bin.orig"), fmt="json")
    bin_cmd = binradar_setup.e9tool_command(
        spec, Path("out.bin"), Path("bin.orig"))
    # Identical ordered -M/-P pairs; only --format and -o differ.
    json_pairs = [(json_cmd[i], json_cmd[i + 1])
                  for i in range(len(json_cmd))
                  if json_cmd[i] == "-M"]
    bin_pairs = [(bin_cmd[i], bin_cmd[i + 1])
                 for i in range(len(bin_cmd)) if bin_cmd[i] == "-M"]
    assert json_pairs == bin_pairs
    assert "--format=json" in json_cmd
    assert "--format=json" not in bin_cmd
    assert "-O0" in json_cmd and "-O0" in bin_cmd
    assert json_cmd[-3:] == ["-o", "out.json", "bin.orig"]
    assert bin_cmd[-3:] == ["-o", "out.bin", "bin.orig"]


def test_direct_action_expands_mem0():
    """The direct call-site action expands Taosc's $mem0 shell variable to
    the four E9 memory-operand fields (utils/taosc/helpers.in)."""
    trace = binradar_setup.AllocatorTrace(
        "malloc",
        [(0, "40661c"), (1, "404eb4"), (2, "405c4b")],
        ["406621"])
    spec = binradar_setup.build_instrumentation_spec(
        trace, "0x4066d0",
        f"if jnz({binradar_setup.E9_MEM0},0x4066e4)@brpatch goto")
    assert spec.entries[-1] == (
        "0x4066d0",
        "if jnz(mem[0].base,mem[0].index,mem[0].scale,mem[0].disp,"
        "0x4066e4)@brpatch goto")
    cmd = binradar_setup.e9tool_command(
        spec, Path("out.bin"), Path("bin.orig"))
    assert "if jnz(mem[0].base,mem[0].index,mem[0].scale,mem[0].disp," \
        "0x4066e4)@brpatch goto" in cmd


def _real_multipoint_workdir():
    """The libxml2 CVE-2016-1839 workdir-013 artifacts (gitignored)."""
    return ROOT / "benchmarks" / "loftix" / "libxml2" / "CVE-2016-1839" \
        / "workdir-013"


def test_extract_relocated_call_jumps_multipoint_real():
    """Every instrumented original call maps to one relocation record.

    Uses the stored libxml2 CVE-2016-1839 workdir-013 artifacts (latest
    taosc output): 13 realloc call sites + the patch site 0x4d60a5.  The
    set_base hook site (0x486b55, not a call) must not produce a record.
    """
    wd = _real_multipoint_workdir()
    if not (wd / "xmllint.brpatched").exists():
        import pytest
        pytest.skip("workdir-013 artifacts not present")
    jumps = binradar_setup.extract_relocated_call_jumps(
        wd / "xmllint.brpatched", wd / "xmllint.brpatched.json",
        wd / "xmllint.orig", 0x4d60a5)
    sites = {site for _, site, _ in jumps}
    assert 0x4d60a5 in sites  # the requested patch site
    assert 0x486b4f in sites  # first realloc call (set_size hook)
    assert 0x487287 in sites  # later realloc call (mark hook)
    assert 0x486b55 not in sites  # set_base site is not a call
    assert len(sites) == 14  # 13 realloc calls + patch site
    for _, site, ret in jumps:
        assert ret == site + 5 or ret == site + 6  # call length
    # Every record is unique.
    assert len(jumps) == len(set(jumps))


def test_extract_relocated_call_jumps_requires_patch_site():
    """A patch address that resolves to no site fails setup."""
    wd = _real_multipoint_workdir()
    if not (wd / "xmllint.brpatched").exists():
        import pytest
        pytest.skip("workdir-013 artifacts not present")
    try:
        binradar_setup.extract_relocated_call_jumps(
            wd / "xmllint.brpatched", wd / "xmllint.brpatched.json",
            wd / "xmllint.orig", 0x123456)
    except ValueError as e:
        assert "resolves to 0 instrumented site(s)" in str(e)
    else:
        raise AssertionError("missing patch site must fail")


# ---------------------------------------------------------------------------
# Phase E: full-context prefilter (TAOSC_PREDICATE_COMPATIBILITY_PLAN §8)
# ---------------------------------------------------------------------------

def _build_snapshot(clamps, regs, stack, truncated=False):
    """Serialize one CWE-119 snapshot record (mirror of the C layout)."""
    header = binradar_setup.PREFILTER_SNAPSHOT_HEADER.pack(
        binradar_setup.PREFILTER_SNAPSHOT_MAGIC,
        binradar_setup.PREFILTER_SNAPSHOT_VERSION,
        len(stack), 1 if truncated else 0)
    clamp_bytes = b"".join(
        struct.pack("<QQ", begin, end) for begin, end in clamps)
    reg_bytes = struct.pack("<" + "Q" * 16, *regs)
    return header + clamp_bytes + reg_bytes + stack


def test_parse_cwe119_snapshots_roundtrip():
    """A serialized record round-trips through the parser."""
    clamps = [(0x1000, 0x2000)] + [(0, 0)] * 255
    regs = tuple(range(16))
    stack = bytes(range(64))
    data = _build_snapshot(clamps, regs, stack)
    snapshots, truncated = binradar_setup.parse_cwe119_snapshots(data)
    assert truncated is False
    assert len(snapshots) == 1
    snap = snapshots[0]
    assert snap.clamps[0] == (0x1000, 0x2000)
    assert snap.clamps[1] == (0, 0)
    assert snap.registers == regs
    assert snap.stack == stack


def test_parse_cwe119_snapshots_multiple_and_truncation():
    """Many records parse; a truncation marker stops and flags."""
    clamps = [(0x1000, 0x2000)] + [(0, 0)] * 255
    regs = tuple(range(16))
    stack = bytes(64)
    data = (_build_snapshot(clamps, regs, stack)
            + _build_snapshot(clamps, regs, stack)
            + _build_snapshot(clamps, regs, stack, truncated=True))
    snapshots, truncated = binradar_setup.parse_cwe119_snapshots(data)
    assert truncated is True
    assert len(snapshots) == 2  # complete records before the marker


def test_parse_cwe119_snapshots_malformed():
    """Bad magic/version and partial trailing records are not evidence."""
    clamps = [(0x1000, 0x2000)] + [(0, 0)] * 255
    regs = tuple(range(16))
    stack = bytes(64)
    good = _build_snapshot(clamps, regs, stack)
    # Bad magic.
    bad_magic = bytearray(good)
    bad_magic[0:4] = b"XXXX"
    snapshots, truncated = binradar_setup.parse_cwe119_snapshots(bytes(bad_magic))
    assert snapshots == [] and truncated is False
    # Partial trailing record (header + half the clamps).
    partial = good + good[:100]
    snapshots, truncated = binradar_setup.parse_cwe119_snapshots(partial)
    assert len(snapshots) == 1 and truncated is False
    # Bad version after a good record.
    bad_version = bytearray(good + _build_snapshot(clamps, regs, stack))
    bad_version[len(good) + 4:len(good) + 8] = struct.pack("<I", 99)
    snapshots, truncated = binradar_setup.parse_cwe119_snapshots(bytes(bad_version))
    assert len(snapshots) == 1 and truncated is False


def test_cwe119_snapshot_evaluator_matches_branch_taken():
    """The snapshot evaluator uses the same rules as the plain evaluator."""
    clamps = [(0x1000, 0x2000)] + [(0, 0)] * 255
    regs = [0x1000] + [0] * 15  # rax inside the clamp
    stack = bytes(64)
    snap = binradar_setup.Cwe119Snapshot(
        tuple(clamps), tuple(regs), stack)
    predicate = binradar_setup.parse_cwe119_predicate(
        "s->rax >= i->begin && s->rax < i->end")
    assert binradar_setup.cwe119_snapshot_branch_taken(predicate, snap) == 0
    # Outside the clamp -> branch.
    regs_out = [0x3000] + [0] * 15
    snap_out = binradar_setup.Cwe119Snapshot(
        tuple(clamps), tuple(regs_out), stack)
    assert binradar_setup.cwe119_snapshot_branch_taken(predicate, snap_out) == 1
    # Stack cell: uint16_t at index 0 reads the first two stack bytes.
    stack16 = bytes([0x00, 0x05]) + bytes(62)
    snap16 = binradar_setup.Cwe119Snapshot(
        tuple(clamps), tuple([0] * 16), stack16)
    size_pred = binradar_setup.parse_cwe119_predicate(
        "2 * ((uint16_t *)s->rsp)[0] < i->end - i->begin")
    # 2 * 0x500 = 0xa00 < 0x1000 -> no branch.
    assert binradar_setup.cwe119_snapshot_branch_taken(size_pred, snap16) == 0
    # Overflow: 8 * 0x2000000000000000 -> br 2.
    regs_ovf = [0, 0x2000000000000000] + [0] * 14
    snap_ovf = binradar_setup.Cwe119Snapshot(
        tuple(clamps), tuple(regs_ovf), stack)
    ovf_pred = binradar_setup.parse_cwe119_predicate(
        "8 * s->rbx < i->end - i->begin")
    assert binradar_setup.cwe119_snapshot_branch_taken(ovf_pred, snap_ovf) == 2


def _run_c_prefilter_test(tmp_path):
    """Compile and run tests/test_brpatch_prefilter.c, returning output."""
    executable = tmp_path / "test_brpatch_prefilter"
    subprocess.run([
        "cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-Wno-missing-field-initializers", "-Wno-unused-parameter",
        "-Wno-unused-function", "-Wno-implicit-fallthrough",
        "-DBRPATCH_CWE119", "-DBRPATCH_ALLOC_MALLOC",
        f"-I{ROOT / 'utils' / 'e9patch' / 'examples'}",
        str(ROOT / "tests" / "test_brpatch_prefilter.c"),
        "-o", str(executable),
    ], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_c_snapshot_capture_parity():
    """C capture records parse with the Python parser and agree field-wise.

    The C test drives dest() with a constructed STATE and a recorded
    clamp {0x6000, 0x200}; the Python parser must recover the same
    header, clamps, registers, and stack bytes.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        output = _run_c_prefilter_test(Path(tmp))

    results = {}
    for line in output.splitlines():
        if line.startswith("RESULT "):
            fields = line.split()
            results[fields[1]] = fields[2:]
    assert "ALL-PASS" in output, output

    # Header: magic, version 1, stack_size 64, flags 0.
    magic, version, stack_size, flags = results["snap-header"]
    assert int(magic) == binradar_setup.PREFILTER_SNAPSHOT_MAGIC
    assert int(version) == binradar_setup.PREFILTER_SNAPSHOT_VERSION
    assert int(stack_size) == 64
    assert int(flags) == 0

    # Clamp 0 is the recorded allocation {0x6000, 0x200}; clamp 1 is
    # zero-initialized and must never match.
    assert results["snap-clamp0"] == ["6000", "6200"]
    assert results["snap-clamp1"] == ["0", "0"]

    # Registers: rax..r15 bit patterns (rsp is the stack buffer address).
    regs = [int(v, 16) for v in results["snap-regs"]]
    assert regs[0] == 0x1111 and regs[1] == 0x2222 and regs[15] == 0x1000
    assert regs[6] != 0  # rsp points at the stack buffer

    # Stack bytes: 0xa0..0xdf.
    stack = bytes(int(v, 16) for v in results["snap-stack"])
    assert stack == bytes(range(0xa0, 0xe0))

    # Truncation marker: magic, stack_size 0, flags 1.
    assert results["snap-trunc"] == [
        str(binradar_setup.PREFILTER_SNAPSHOT_MAGIC), "0", "1"]

    # Generic path still emits the sbsv line.
    assert results["snap-generic"][0] == "[prefilter-state]"
    assert results["snap-generic"][1] == "[v0"
    assert results["snap-generic"][2] == "66]"


def test_cwe119_prefilter_decision_parity():
    """Prefilter decisions equal the C evaluator on the same snapshots.

    The C test's recorded snapshot (clamp {0x6000, 0x200}, rax 0x1111)
    is evaluated by the Python snapshot evaluator: a pointer predicate on
    rax (0x1111 outside the clamp) branches; a size predicate on rbx
    (0x2222 * 1 = 0x2222 >= 0x200) branches; a pointer predicate on a
    register inside the clamp does not.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        output = _run_c_prefilter_test(Path(tmp))

    results = {}
    for line in output.splitlines():
        if line.startswith("RESULT "):
            fields = line.split()
            results[fields[1]] = fields[2:]

    clamps = [(int(results["snap-clamp0"][0], 16),
               int(results["snap-clamp0"][1], 16))] + [(0, 0)] * 255
    regs = [int(v, 16) for v in results["snap-regs"]]
    stack = bytes(int(v, 16) for v in results["snap-stack"])
    snap = binradar_setup.Cwe119Snapshot(tuple(clamps), tuple(regs), stack)

    # rax = 0x1111 is outside {0x6000, 0x6200} -> branch (br 1).
    ptr_rax = binradar_setup.parse_cwe119_predicate(
        "s->rax >= i->begin && s->rax < i->end")
    assert binradar_setup.cwe119_snapshot_branch_taken(ptr_rax, snap) == 1
    # rbx = 0x2222, scale 1: 0x2222 >= 0x200 -> branch.
    size_rbx = binradar_setup.parse_cwe119_predicate(
        "1 * s->rbx < i->end - i->begin")
    assert binradar_setup.cwe119_snapshot_branch_taken(size_rbx, snap) == 1
    # A register inside the clamp (0x6000) does not branch.
    regs_inside = list(regs)
    regs_inside[0] = 0x6000
    snap_inside = binradar_setup.Cwe119Snapshot(
        tuple(clamps), tuple(regs_inside), stack)
    assert binradar_setup.cwe119_snapshot_branch_taken(ptr_rax, snap_inside) == 0


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
