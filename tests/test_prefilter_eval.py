#!/usr/bin/env python3
"""Unit tests for the Python mirror of brpatch.c::eval
(fuzzolic/binradar-setup.py, `prefilter` subcommand).  Run with pytest or
directly:

    uv run pytest tests/test_prefilter_eval.py
    uv run python tests/test_prefilter_eval.py
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "binradar_setup", ROOT / "fuzzolic" / "binradar-setup.py")
binradar_setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binradar_setup)

eval_patch_str = binradar_setup.eval_patch_str
evaluate_predicate = binradar_setup.evaluate_predicate
predicate_to_patch_str = binradar_setup.predicate_to_patch_str
predicate_to_branch_patch_str = binradar_setup.predicate_to_branch_patch_str
load_predicates = binradar_setup.load_predicates
load_prefilter_passed_ids = binradar_setup.load_prefilter_passed_ids
write_prefilter = binradar_setup.write_prefilter
PrefilterTrap = binradar_setup.PrefilterTrap
INT64_MIN = binradar_setup.INT64_MIN
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


def test_evaluate_predicate_keep_discard():
    # DSL predicate "max1 + r10 <= +max1" (max1 == 0); r10 is variable 10,
    # which reads canonical register slot 10.  Taosc jumps when the predicate
    # is false, so slot 10 == 1 takes the branch (1 <= 0 is false) -> kept.
    predicate = "max1 + r10 <= +max1"
    assert evaluate_predicate(predicate, [[1] * 16]) == (True, "")
    # With slot 10 == -1 the predicate is true, so no branch is taken.
    assert evaluate_predicate(predicate, [[-1] * 16]) == (
        False, "evaluates to 0 on all captured states")


def test_evaluate_predicate_trap_rejected():
    # Division/modulo by zero (or INT64_MIN / -1) would trap the patch at
    # runtime (reported as `br 2`), so the predicate is rejected.
    for predicate in ("1 / rax", "1 % rax"):
        passed, note = evaluate_predicate(predicate, [[0] * 16])
        assert passed is False
        assert "trap" in note


def test_evaluate_predicate_unparseable_fail_open():
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
            "[prefilter] [res] [id 1] [pass false] [new-id -1]\n"
            "[prefilter] [res] [id 2] [pass true] [new-id 1]\n"
            "[prefilter] [res] [id 3] [pass true] [new-id 2]\n"
            "[prefilter] [done] [total 3] [survived 2] [time 0.01]\n")
        assert load_prefilter_passed_ids(sbsv) == {2: 1, 3: 2}

        # Blank lines are fine.
        sbsv.write_text(
            "\n[prefilter] [res] [id 7] [pass true] [new-id 1]\n\n")
        assert load_prefilter_passed_ids(sbsv) == {7: 1}

        # A malformed row fails open (None).
        sbsv.write_text(
            "[prefilter] [res] [id 1] [pass true] [new-id 1]\n"
            "garbage\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # An unknown-schema row fails open (None).
        sbsv.write_text(
            "[prefilter] [res] [id 1] [pass true] [new-id 1]\n"
            "[prefiltter] [id 2] [pass true]\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # The pre-[res] row format remains invalid.
        sbsv.write_text("[prefilter] [id 1] [pass true]\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # A passing row must have a positive new-id.
        sbsv.write_text(
            "[prefilter] [res] [id 1] [pass true] [new-id -1]\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # A rejected row must have new-id -1.
        sbsv.write_text(
            "[prefilter] [res] [id 1] [pass false] [new-id 1]\n")
        assert load_prefilter_passed_ids(sbsv) is None

        # An all-false file yields no survivors.
        sbsv.write_text(
            "[prefilter] [res] [id 1] [pass false] [new-id -1]\n")
        assert load_prefilter_passed_ids(sbsv) == {}


def test_predicate_source_and_runtime_ids():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        predicates = Path(tmp) / "predicates"
        predicates.write_text("first\n\nthird\n")
        assert load_predicates(predicates) == [(1, "first"), (3, "third")]

        sbsv = Path(tmp) / "prefilter.sbsv"
        write_prefilter(sbsv, [(1, False, "", "first"), (3, True, "", "third"),
                               (8, True, "", "eighth")], 0.0)
        assert "[prefilter] [res] [id 1] [pass false] [new-id -1]" \
            in sbsv.read_text()
        assert "[prefilter] [res] [id 3] [pass true] [new-id 1]" \
            in sbsv.read_text()
        assert "[prefilter] [res] [id 8] [pass true] [new-id 2]" \
            in sbsv.read_text()
        assert load_prefilter_passed_ids(sbsv) == {3: 1, 8: 2}


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
