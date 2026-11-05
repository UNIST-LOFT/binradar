#!/usr/bin/env python3
"""Unit tests for Taosc predicate parsing, evaluation, and filter mapping."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
from binradar import binradar_taosc_predicates

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


def test_logical_truth_precedence_and_parenthesized_scalars():
    examples = {
        "7 && -2": 1, "0 || -9": 1, "0 && 9": 0,
        "1 || 0 && 0": 1, "(1 || 0) && 0": 0,
        "(rax && rbx) + 2": 2, "2 | 0 && 4": 1,
        "2 & 1 || 3": 1, "1 == 1 && 2 < 3": 1,
    }
    for source, expected in examples.items():
        assert eval_patch_str(predicate_to_patch_str(source), ZERO_ENV) == expected
        assert eval_patch_str(predicate_to_branch_patch_str(source), ZERO_ENV) == int(expected == 0)


def test_logical_short_circuit_and_sticky_visited_traps():
    import pytest
    for source, result in (("0 && 1 / 0", 0), ("9 || 1 % 0", 1),
                           ("0 && min64 / -1", 0)):
        assert eval_patch_str(predicate_to_patch_str(source), ZERO_ENV) == result
    for source in ("1 && 1 / 0", "0 || 1 % 0", "(1 / 0) || 1",
                   "0 & (1 / 0)", "1 | (1 / 0)"):
        with pytest.raises(PredicateTrap):
            eval_patch_str(predicate_to_patch_str(source), ZERO_ENV)


def test_logical_cached_branches_and_lazy_register_load():
    api = binradar_taosc_predicates

    class UnreadRegisters:
        def __getitem__(self, index):
            raise AssertionError("short-circuited register must not be loaded")

    assert eval_patch_str("Op1v15", UnreadRegisters()) == 1
    assert eval_patch_str("Ap0v15", UnreadRegisters()) == 0
    snapshot = api.CachedSnapshot(1, 0, tuple(ZERO_ENV))
    assert api.evaluate_cached_branch("O/p1p0p1", snapshot) == 2
    assert api.evaluate_cached_branch("Op1/p1p0", snapshot) == 1
    assert api.evaluate_cached_branch("Ap0/p1p0", snapshot) == 0


def test_strict_descriptor_validation_in_skipped_operands():
    import pytest
    parse = binradar_taosc_predicates.parse_predicate_descriptor
    for descriptor in ("", "p", "n", "v", "v16", "Op1v16", "Ap0?", "p1p0",
                       "p18446744073709551616", "c3c1p0", "c3Ac1p0p0",
                       "c1s64i65536", "c2s64i0q1", "c2p16q1", "c2p0q3"):
        with pytest.raises(ValueError):
            parse(descriptor)
    assert parse("c1s64i65535")
    assert parse("c3Oc1p0c2s32i65535q8")


def test_depth_and_byte_limits_and_wrapped_source_literals():
    import pytest
    parse = binradar_taosc_predicates.parse_predicate_descriptor
    # Python source generation formerly hit its parentheses limit here.
    assert eval_patch_str("~" * 255 + "p0", ZERO_ENV) == -1
    assert eval_patch_str("A" * 255 + "p1" + "p1" * 255, ZERO_ENV) == 1
    with pytest.raises(ValueError):
        parse("~" * 256 + "p0")
    assert predicate_to_patch_str("(" * 256 + "1" + ")" * 256) == "p1"
    with pytest.raises(ValueError):
        predicate_to_patch_str("(" * 257 + "1" + ")" * 257)
    with pytest.raises(ValueError):
        predicate_to_patch_str("1+" * 256 + "1")
    with pytest.raises(ValueError):
        predicate_to_branch_patch_str("~" * 255 + "0")
    assert predicate_to_patch_str("1" + " " * 4095) == "p1"
    with pytest.raises(ValueError):
        predicate_to_patch_str("1" + " " * 4096)
    assert predicate_to_patch_str(str(1 << 64)) == "p0"
    assert predicate_to_patch_str(str((1 << 64) - 1)) == "n1"
    assert eval_patch_str("p18446744073709551615", ZERO_ENV) == -1
    leaves = ["p" + "0" * 14] * 256
    while len(leaves) > 1:
        leaves = ["O" + left + right for left, right in zip(leaves[::2], leaves[1::2])]
    assert len(leaves[0]) == 4095
    assert parse(leaves[0]) == leaves[0]
    assert eval_patch_str("p" + "0" * 4094, ZERO_ENV) == 0
    with pytest.raises(ValueError):
        parse(leaves[0] + "0")


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
