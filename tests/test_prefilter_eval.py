#!/usr/bin/env python3
"""Unit tests for the Python mirror of brpatch.c::eval
(fuzzolic/binradar-setup.py, `prefilter` subcommand).  Run with pytest or
directly:

    uv run pytest tests/test_prefilter_eval.py
    uv run python tests/test_prefilter_eval.py
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "binradar_setup", ROOT / "fuzzolic" / "binradar-setup.py")
binradar_setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar_setup)

eval_patch_str = binradar_setup.eval_patch_str
evaluate_predicate = binradar_setup.evaluate_predicate
load_prefilter_passed_ids = binradar_setup.load_prefilter_passed_ids
PrefilterTrap = binradar_setup.PrefilterTrap
INT64_MIN = binradar_setup.INT64_MIN
INT64_MAX = (1 << 63) - 1

ZERO_ENV = [0] * 16


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
        except PrefilterTrap:
            pass
        else:
            raise AssertionError(f"{s!r} should raise PrefilterTrap")


def test_int64_min_div_minus1_traps():
    for s in ("/n9223372036854775808n1", "%n9223372036854775808n1"):
        try:
            eval_patch_str(s, ZERO_ENV)
        except PrefilterTrap:
            pass
        else:
            raise AssertionError(f"{s!r} should raise PrefilterTrap")


def test_wraparound():
    # INT64_MAX + 1 wraps to INT64_MIN
    assert eval_patch_str("+p9223372036854775807p1", ZERO_ENV) == INT64_MIN
    # INT64_MIN - 1 wraps to INT64_MAX
    assert eval_patch_str("-n9223372036854775808p1", ZERO_ENV) == INT64_MAX
    # INT64_MAX * 2 wraps to -2
    assert eval_patch_str("*p9223372036854775807p2", ZERO_ENV) == -2


def test_shift_masking():
    # x86 masks the shift count to 6 bits: 64 & 63 == 0
    assert eval_patch_str("lp1p64", ZERO_ENV) == 1
    assert eval_patch_str("lp1p1", ZERO_ENV) == 2
    assert eval_patch_str("lp1p65", ZERO_ENV) == 2  # 65 & 63 == 1
    assert eval_patch_str("rp1p64", ZERO_ENV) == 1
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


def test_evaluate_predicate_keep_discard():
    # DSL predicate "max1 + r10 <= +max1" (max1 == 0); r10 is variable 10,
    # which at runtime reads STATE slot 10.  With slot 10 == 1 the branch
    # is not taken (1 <= 0 is false) -> discarded.
    predicate = "max1 + r10 <= +max1"
    assert evaluate_predicate(predicate, [[1] * 16]) == (
        False, "evaluates to 0 on all captured states")
    # With slot 10 == -1 the branch is taken on the first state -> kept.
    assert evaluate_predicate(predicate, [[-1] * 16]) == (True, "")


def test_evaluate_predicate_fail_open():
    # Division by zero in the predicate would SIGFPE the patch -> kept.
    passed, note = evaluate_predicate("1 / rax", [[0] * 16])
    assert passed is True
    assert "trap" in note
    # Unparseable predicate -> kept (the existing pipeline surfaces the
    # error, same as prepare_patch would).
    passed, _ = evaluate_predicate("??garbage??", [[0] * 16])
    assert passed is True


def test_load_prefilter_passed_ids():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        sbsv = Path(tmp) / "prefilter.sbsv"

        # Done marker must be skipped, not treated as a parse error.
        sbsv.write_text(
            "[prefilter] [res] [id 1] [pass false]\n"
            "[prefilter] [res] [id 2] [pass true]\n"
            "[prefilter] [res] [id 3] [pass true]\n"
            "[prefilter] [done] [total 3] [survived 2] [time 0.01]\n")
        assert load_prefilter_passed_ids(sbsv) == [2, 3]

        # Blank lines are fine.
        sbsv.write_text("\n[prefilter] [res] [id 7] [pass true]\n\n")
        assert load_prefilter_passed_ids(sbsv) == [7]

        # A malformed row fails open (None).
        sbsv.write_text("[prefilter] [res] [id 1] [pass true]\n"
                        "garbage\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # An unknown-schema row fails open (None).
        sbsv.write_text("[prefilter] [res] [id 1] [pass true]\n"
                        "[prefiltter] [id 2] [pass true]\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # The pre-[res] row format ([prefilter] [id ...] as a root schema)
        # is not registered and fails open (None).
        sbsv.write_text("[prefilter] [id 1] [pass true]\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # An all-false file yields no survivors.
        sbsv.write_text("[prefilter] [res] [id 1] [pass false]\n")
        assert load_prefilter_passed_ids(sbsv) == []


def test_parse_state_lines():
    parse_state_lines = binradar_setup.parse_state_lines
    # A full 16-slot line (negative and > 2^31 values) parses; stray,
    # truncated, and non-state lines are skipped.
    data = (
        "[prefilter-state] [v0 512] [v1 0] [v2 8835212096] [v3 -1] "
        "[v4 0] [v5 18] [v6 0] [v7 1] [v8 4667520] [v9 0] [v10 8835335040] "
        "[v11 0] [v12 0] [v13 2] [v14 32] [v15 4]\n"
        "stray output line\n"
        "[prefilter-state] [v0 1] [v1 2]\n"
        "[other] [v0 1]\n"
    )
    assert parse_state_lines(data) == [
        [512, 0, 8835212096, -1, 0, 18, 0, 1, 4667520, 0,
         8835335040, 0, 0, 2, 32, 4]]


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
