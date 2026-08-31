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
