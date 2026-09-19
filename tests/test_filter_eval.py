#!/usr/bin/env python3
"""Unit tests for Taosc predicate parsing, evaluation, and filter mapping."""

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "binradar_taosc_predicates",
    ROOT / "fuzzolic" / "binradar_taosc_predicates.py")
binradar_taosc_predicates = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar_taosc_predicates)

eval_patch_str = binradar_taosc_predicates.eval_patch_str
predicate_to_patch_str = binradar_taosc_predicates.predicate_to_patch_str
predicate_to_branch_patch_str = \
    binradar_taosc_predicates.predicate_to_branch_patch_str
load_predicates = binradar_taosc_predicates.load_predicates
load_filter_passed_ids = binradar_taosc_predicates.load_filter_passed_ids
write_filter = binradar_taosc_predicates.write_filter
PredicateTrap = binradar_taosc_predicates.PredicateTrap
INT64_MIN = binradar_taosc_predicates.INT64_MIN
INT64_MAX = (1 << 63) - 1

ZERO_ENV = [0] * 16


def test_c_evaluator():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        executable = Path(tmp) / "test_brpatch_eval"
        subprocess.run([
            "cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-Wno-missing-field-initializers", "-Wno-unused-parameter",
            "-Wno-unused-function", "-Wno-implicit-fallthrough",
            f"-I{ROOT / 'utils' / 'e9patch' / 'examples'}",
            str(ROOT / "tests" / "test_brpatch_eval.c"),
            "-o", str(executable),
        ], check=True)
        subprocess.run([str(executable)], check=True)


def test_positive_constant():
    assert eval_patch_str("p0", ZERO_ENV) == 0
    assert eval_patch_str("p1", ZERO_ENV) == 1
    assert eval_patch_str("p9223372036854775807", ZERO_ENV) == INT64_MAX


def test_negative_constant():
    assert eval_patch_str("n5", ZERO_ENV) == -5
    # n9223372036854775808 encodes INT64_MIN (emit_patch of min64).
    assert eval_patch_str("n9223372036854775808", ZERO_ENV) == INT64_MIN


def test_not_equal():
    assert eval_patch_str("!p0p0", ZERO_ENV) == 0  # 0 != 0
    assert eval_patch_str("!p1p0", ZERO_ENV) == 1  # 1 != 0
    assert eval_patch_str("!p1p1", ZERO_ENV) == 0  # 1 != 1


def test_relational():
    assert eval_patch_str("=p1p1", ZERO_ENV) == 1
    assert eval_patch_str(">p1p0", ZERO_ENV) == 1
    assert eval_patch_str(">=p1p1", ZERO_ENV) == 1
    assert eval_patch_str("<p0p1", ZERO_ENV) == 1
    assert eval_patch_str("<=p1p0", ZERO_ENV) == 0
    # (0 / v0) < 0 with v0 = 1: 0 < 0 -> 0 (division is fine, not by zero)
    assert eval_patch_str("</p0v0p0", [1] + [0] * 15) == 0


def test_division_by_zero_traps():
    for s in ("/p1p0", "%p1p0"):
        try:
            eval_patch_str(s, ZERO_ENV)
        except PredicateTrap:
            pass
        else:
            raise AssertionError(f"{s!r} should raise PredicateTrap")


def test_int64_min_div_minus1_traps():
    for s in ("/n9223372036854775808n1", "%n9223372036854775808n1"):
        try:
            eval_patch_str(s, ZERO_ENV)
        except PredicateTrap:
            pass
        else:
            raise AssertionError(f"{s!r} should raise PredicateTrap")


def test_wraparound():
    # INT64_MAX + 1 wraps to INT64_MIN
    assert eval_patch_str("+p9223372036854775807p1", ZERO_ENV) == INT64_MIN
    # INT64_MIN - 1 wraps to INT64_MAX
    assert eval_patch_str("-n9223372036854775808p1", ZERO_ENV) == INT64_MAX
    # INT64_MAX * 2 wraps to -2
    assert eval_patch_str("*p9223372036854775807p2", ZERO_ENV) == -2


def test_shift_semantics():
    # Zig's std.math helpers saturate large counts and reverse direction for
    # negative counts.
    assert eval_patch_str("lp1p64", ZERO_ENV) == 0
    assert eval_patch_str("lp1p1", ZERO_ENV) == 2
    assert eval_patch_str("lp1p65", ZERO_ENV) == 0
    assert eval_patch_str("lp8n1", ZERO_ENV) == 4
    assert eval_patch_str("ln1n64", ZERO_ENV) == -1
    assert eval_patch_str("rp1p64", ZERO_ENV) == 0
    assert eval_patch_str("rn1p64", ZERO_ENV) == -1
    assert eval_patch_str("rp1n1", ZERO_ENV) == 2
    assert eval_patch_str("rn1p1", ZERO_ENV) == -1  # arithmetic shift
    assert eval_patch_str("rn8p1", ZERO_ENV) == -4


def test_bitwise():
    assert eval_patch_str("~p0", ZERO_ENV) == -1
    assert eval_patch_str("~n1", ZERO_ENV) == 0
    assert eval_patch_str("&p7p3", ZERO_ENV) == 3
    assert eval_patch_str("|p4p3", ZERO_ENV) == 7
    assert eval_patch_str("^p7p3", ZERO_ENV) == 4


def test_truncating_division_and_modulo():
    assert eval_patch_str("/n7p3", ZERO_ENV) == -2  # C: -7 / 3 == -2
    assert eval_patch_str("%n7p3", ZERO_ENV) == -1  # C: -7 % 3 == -1
    assert eval_patch_str("%p7n3", ZERO_ENV) == 1   # C: 7 % -3 == 1


def test_variable_lookup():
    env = list(range(16))
    assert eval_patch_str("v0", env) == 0
    assert eval_patch_str("v15", env) == 15
    assert eval_patch_str("+v1v2", env) == 3


def test_predicate_conversion_and_branch_polarity():
    predicate = "max64 + r10 >= ~max1"
    patch_str = ">=+p9223372036854775807v10~p0"
    assert predicate_to_patch_str(predicate) == patch_str
    assert predicate_to_branch_patch_str(predicate) == f"={patch_str}p0"



def test_load_filter_passed_ids():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        sbsv = Path(tmp) / "filter.sbsv"

        # Done marker must be skipped, not treated as a parse error.
        sbsv.write_text(
            "[filter] [res] [id 1] [pass false] [new-id -1]\n"
            "[filter] [res] [id 2] [pass true] [new-id 1]\n"
            "[filter] [res] [id 3] [pass true] [new-id 2]\n"
            "[filter] [done] [total 3] [survived 2] [time 0.01]\n")
        assert load_filter_passed_ids(sbsv) == {2: 1, 3: 2}

        # Blank lines are fine.
        sbsv.write_text(
            "\n[filter] [res] [id 7] [pass true] [new-id 1]\n\n")
        assert load_filter_passed_ids(sbsv) == {7: 1}

        # A malformed row fails open (None).
        sbsv.write_text(
            "[filter] [res] [id 1] [pass true] [new-id 1]\n"
            "garbage\n")
        assert load_filter_passed_ids(sbsv) is None

        # An unknown-schema row fails open (None).
        sbsv.write_text(
            "[filter] [res] [id 1] [pass true] [new-id 1]\n"
            "[prefilter] [res] [id 2] [pass true] [new-id 2]\n")
        assert load_filter_passed_ids(sbsv) is None

        # The pre-[res] row format remains invalid.
        sbsv.write_text("[filter] [id 1] [pass true]\n")
        assert load_filter_passed_ids(sbsv) is None

        # A passing row must have a positive new-id.
        sbsv.write_text(
            "[filter] [res] [id 1] [pass true] [new-id -1]\n")
        assert load_filter_passed_ids(sbsv) is None

        # A rejected row must have new-id -1.
        sbsv.write_text(
            "[filter] [res] [id 1] [pass false] [new-id 1]\n")
        assert load_filter_passed_ids(sbsv) is None

        # An all-false file yields no survivors.
        sbsv.write_text(
            "[filter] [res] [id 1] [pass false] [new-id -1]\n")
        assert load_filter_passed_ids(sbsv) == {}


def test_predicate_source_and_runtime_ids():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        predicates = Path(tmp) / "predicates"
        predicates.write_text("first\n\nthird\n")
        assert load_predicates(predicates) == [(1, "first"), (3, "third")]

        sbsv = Path(tmp) / "filter.sbsv"
        write_filter(sbsv, [(1, False, "", "first"), (3, True, "", "third"),
                               (8, True, "", "eighth")], 0.0)
        assert "[filter] [res] [id 1] [pass false] [new-id -1]" \
            in sbsv.read_text()
        assert "[filter] [res] [id 3] [pass true] [new-id 1]" \
            in sbsv.read_text()
        assert "[filter] [res] [id 8] [pass true] [new-id 2]" \
            in sbsv.read_text()
        assert load_filter_passed_ids(sbsv) == {3: 1, 8: 2}


def _main():
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
