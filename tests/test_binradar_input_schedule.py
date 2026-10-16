"""Immutable wire scores, first-observer reduction, and worker ownership."""
import dataclasses
import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_input_schedule as schedule
import binradar_runtime
from binradar_taosc_predicates import CachedSnapshot, parse_predicate_descriptor


def snapshot(value):
    return CachedSnapshot(0, 0, (value,) + (0,) * 15)


def bitmap(*edges):
    value = bytearray(65536)
    for edge in edges:
        value[edge] = 1
    return bytes(value)


def score(scorer, seq, snapshots=None, coverage=None, check=lambda: None):
    return scorer.score(seq, snapshots, coverage,
                        patch_reason="none" if snapshots is not None else "unsupported",
                        coverage_reason="none" if coverage is not None else "empty-map",
                        check=check)


def test_score_wire_roundtrip_immutable_and_heap():
    original = schedule.InputScore(7, 3, 2, 11)
    assert original.heap_key == (-3, -2, -11, 7)
    assert schedule.InputScore.from_row(original.as_dict()) == original
    baseline = "2026-10-14 - [testcase] [result] [id 2] [file /tmp/input]"
    stripped, decoded = schedule.split_score(baseline + " " + original.serialize() + " [time 9]\n")
    assert stripped == baseline + " [time 9]\n"
    assert decoded == original
    with pytest.raises(dataclasses.FrozenInstanceError):
        original.seq = 8
    legacy = baseline + " [time 9]\n"
    assert schedule.split_score(legacy) == (legacy, None)
    header = "[input-schedule] [schedule-version 1] [schedule-seq 0]"
    assert schedule.split_score(header) == (header, None)


@pytest.mark.parametrize("field,value", [
    ("schedule-version", True), ("schedule-version", 2),
    ("schedule-seq", -1), ("schedule-seq", 1.0), ("schedule-seq", "1"),
    ("score-edges", False), ("score-patch-outcomes", -1),
    ("patch-features", "partial"), ("patch-feature-reason", "broken capture"),
    ("coverage-feature-reason", "empty-map"),
])
def test_score_rejects_invalid_mapping(field, value):
    row = schedule.InputScore(0, 1, 1, 1).as_dict()
    row[field] = value
    with pytest.raises(ValueError):
        schedule.InputScore.from_row(row)


@pytest.mark.parametrize("kwargs", [
    {"seq": True}, {"new_patch_outcomes": 1, "patch_reason": "truncated"},
    {"new_patch_signatures": 1, "patch_reason": "truncated"},
    {"new_edges": 1, "coverage_reason": "cancelled"},
    {"patch_reason": ""}, {"coverage_reason": "not safe"},
])
def test_direct_score_validation(kwargs):
    fields = dict(seq=0, new_patch_outcomes=0, new_patch_signatures=0, new_edges=0)
    fields.update(kwargs)
    with pytest.raises(ValueError):
        schedule.InputScore(**fields)


@pytest.mark.parametrize("suffix", [
    "[schedule-seq 0]", "schedule-seq 0]", "[schedule-seq -1]",
    "[schedule-version 1] garbage", "[score-edges 1",
    "[schedule-seq 0] [schedule-seq 0]", "[schedule-version true]",
])
def test_partial_or_malformed_score_never_falls_back(suffix):
    with pytest.raises(ValueError):
        schedule.split_score("[testcase] [result] [id 0] " + suffix)


@pytest.mark.parametrize("extra", ["[unknown 1]", "[schedule-seq 2]", "[time bad]", "garbage"])
def test_complete_score_rejects_bad_trailing_fields(extra):
    with pytest.raises(ValueError):
        schedule.split_score("[testcase] [result] " + schedule.InputScore(0, 0, 0, 0).serialize() + " " + extra)


def test_legacy_filename_is_not_a_scheduling_field():
    line = "[testcase] [result] [id 0] [file score-edges-schedule-seq.bin] [exit ok]"
    assert schedule.split_score(line) == (line, None)


def test_first_observer_duplicate_hits_and_edges():
    with schedule.NoveltyScorer({3: ">v0p0", 9: ">v0p1"}, "fixed-universe") as scorer:
        first = score(scorer, 0, [snapshot(0), snapshot(0), snapshot(2)], bitmap(2, 60000))
        assert (first.new_patch_outcomes, first.new_patch_signatures, first.new_edges) == (4, 2, 2)
        repeated = score(scorer, 1, [snapshot(2), snapshot(0)], bitmap(2))
        assert repeated.heap_key == (0, 0, 0, 1)
        # This joint vector is new even though both individual outcomes were seen.
        joint = score(scorer, 2, [snapshot(1)], bitmap(60000, 65535))
        assert (joint.new_patch_outcomes, joint.new_patch_signatures, joint.new_edges) == (0, 1, 1)
        assert scorer.counts == {"patch_outcomes": 4, "patch_signatures": 3, "edges": 3}
        assert scorer.highwater == scorer.counts
        worker = scorer._process
        assert scorer.backend == "process"
        assert binradar_runtime.PROCESS_REGISTRY.contains(worker)
    assert worker.poll() is not None
    assert not binradar_runtime.PROCESS_REGISTRY.contains(worker)


def test_all_candidates_and_last_hit_participate():
    predicates = {i: ">v0p0" for i in range(1, 103)}
    predicates[10001] = ">v0p1000"
    with schedule.NoveltyScorer(predicates, "no-sampling") as scorer:
        first = score(scorer, 0, [snapshot(0)] * 1100 + [snapshot(2000)])
        assert first.new_patch_outcomes == 2 * len(predicates)
        assert first.new_patch_signatures == 2
        assert score(scorer, 1, [snapshot(2000)]).new_patch_outcomes == 0


def test_cwe805_register_and_stack_predicates_use_every_hit():
    predicates = {1: parse_predicate_descriptor("c1p0"),
                  2: parse_predicate_descriptor("c1s64i0")}
    inside = CachedSnapshot(0, 0, (110,) + (0,) * 15,
                            ((100, 200),), (120).to_bytes(8, "little"))
    outside = CachedSnapshot(0, 0, (220,) + (0,) * 15,
                             ((100, 200),), (230).to_bytes(8, "little"))
    with schedule.NoveltyScorer(predicates, "cwe805") as scorer:
        result = score(scorer, 0, [inside, inside, outside])
        assert result.new_patch_outcomes == 4
        assert result.new_patch_signatures == 2
        assert score(scorer, 1, [outside]).new_patch_outcomes == 0


def reduced_features(predicates, namespace, snapshots):
    masks, digests = schedule._Reducer(predicates, namespace).reduce(snapshots)
    outcomes = {(patch_id, outcome)
                for patch_id, mask in zip(sorted(predicates), masks)
                for outcome in (0, 1, 2) if mask & (1 << outcome)}
    return outcomes, {digests[offset:offset + 32]
                      for offset in range(0, len(digests), 32)}


def test_joint_signatures_have_stable_order_and_namespace():
    snapshots = [snapshot(0), snapshot(1), snapshot(2), snapshot(2)]
    left = reduced_features({9: ">v0p1", 3: ">v0p0"}, "a", snapshots)
    right = reduced_features({3: ">v0p0", 9: ">v0p1"}, "a", snapshots)
    other = reduced_features({3: ">v0p0", 9: ">v0p1"}, "b", snapshots)
    assert left == right
    assert left[0] == other[0]
    assert left[1].isdisjoint(other[1])


def signature(namespace, packed):
    return hashlib.sha256(hashlib.sha256(namespace.encode()).digest() + bytes(packed)).digest()


def test_generic_traps_wrapping_duplicate_descriptors_and_digest_bytes():
    predicates = {11: "/v0v1", 7: "=+v0p1n9223372036854775808",
                  5: "/v0v1", 2: "p0"}
    states = [CachedSnapshot(0, 0, (2**63 - 1, 0) + (0,) * 14),
              CachedSnapshot(0, 0, (2**63, 2**64 - 1) + (0,) * 14),
              CachedSnapshot(0, 0, (8, 2) + (0,) * 14)]
    expected_outcomes = {(2, 0), (5, 1), (5, 2), (7, 0), (7, 1), (11, 1), (11, 2)}
    expected_signatures = {signature("traps", [value]) for value in (152, 136, 68)}
    assert reduced_features(predicates, "traps", states + states[-1:]) == (
        expected_outcomes, expected_signatures)
    with schedule.NoveltyScorer(predicates, "traps") as scorer:
        first = score(scorer, 0, states + states[-1:])
        assert (first.new_patch_outcomes, first.new_patch_signatures) == (7, 3)
        assert score(scorer, 1, states[::-1]).heap_key == (0, 0, 0, 1)


def test_cwe805_unsigned_clamp_wrap_overflow_and_strict_capacity():
    descriptors = ["c1p0", "c2p1q8", "c1s64i0", "c2s16i4q2", "c1p0"]
    predicates = {index: parse_predicate_descriptor(value)
                  for index, value in enumerate(descriptors, 1)}
    # Inverted clamps do not match pointers, but their capacity wraps u64.
    clamps = ((100, 200), (300, 250)) + ((0, 0),) * 254
    stack = (200).to_bytes(8, "little") + (50).to_bytes(2, "little")
    inside = CachedSnapshot(0, 0, (100, 2**61) + (0,) * 14, clamps, stack)
    outside = CachedSnapshot(0, 0, (200, 25) + (0,) * 14, clamps, stack)
    # [0,2,1,0,0] and [1,0,1,0,1], in ascending candidate order.
    outcomes, digests = reduced_features(predicates, "clamps", [inside, inside, outside])
    assert outcomes == {(1, 0), (1, 1), (2, 2), (2, 0), (3, 1), (4, 0), (5, 0), (5, 1)}
    assert digests == {signature("clamps", [24, 0]), signature("clamps", [17, 1])}
    exact = CachedSnapshot(0, 0, (200, 25) + (0,) * 14,
                           ((100, 300),) + ((0, 0),) * 255, stack)
    # 8*25 equals the sole capacity: strict '<' must take the patch.
    assert reduced_features({2: predicates[2]}, "strict", [exact])[0] == {(2, 1)}


@pytest.mark.parametrize("width", [8, 16, 32])
def test_cwe805_stack_cell_offset_unsigned_load_and_zero_clamps(width):
    size = width // 8
    maximum = (1 << width) - 1
    predicate = parse_predicate_descriptor(f"c2s{width}i1q2")
    stack = bytes(size) + maximum.to_bytes(size, "little")
    state = CachedSnapshot(0, 0, (0,) * 16,
                           ((0, maximum * 2),) + ((0, 0),) * 255, stack)
    # The selected unsigned cell times two equals capacity, not less than it.
    assert reduced_features({8: predicate}, "width", [state])[0] == {(8, 1)}
    zeros = CachedSnapshot(0, 0, (0,) * 16, ((0, 0),) * 256, bytes(size * 2))
    assert reduced_features({8: predicate}, "zero", [zeros])[0] == {(8, 1)}


def test_empty_capture_has_no_patch_features_but_preserves_availability():
    with schedule.NoveltyScorer({1: "p1"}, "empty") as scorer:
        empty = score(scorer, 0, [])
        assert empty.patch_reason == "none"
        assert empty.new_patch_outcomes == empty.new_patch_signatures == 0
        assert score(scorer, 1, [snapshot(0)]).new_patch_outcomes == 1


def test_final_check_failure_does_not_commit_patch_history(monkeypatch):
    scorer = schedule.NoveltyScorer({1: ">v0p0"}, "final-check")
    first = score(scorer, 0, [snapshot(0)])
    assert first.new_patch_outcomes == 1
    worker = scorer._process
    before = scorer.counts
    new_features = schedule._Reducer(scorer.predicates, scorer.namespace).reduce([snapshot(1)])
    monkeypatch.setattr(scorer, "_reduce_managed", lambda snapshots, check: new_features)
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TimeoutError("final check")

    with pytest.raises(TimeoutError, match="final check"):
        score(scorer, 1, [snapshot(1)], bitmap(5), check=check)
    assert scorer.counts == before
    assert worker.poll() is not None
    assert not binradar_runtime.PROCESS_REGISTRY.contains(worker)


def test_coverage_only_never_spawns_and_counter_values_do_not_matter():
    with schedule.NoveltyScorer({}, "coverage") as scorer:
        first = score(scorer, 0, coverage=bitmap(4, 5))
        assert first.new_edges == 2
        changed = bytearray(bitmap(4, 5))
        changed[4] = 255
        assert score(scorer, 1, coverage=bytes(changed)).new_edges == 0
        assert scorer.backend == "coverage-only"
        assert scorer._process is None


def test_unavailable_features_never_reserve_tokens():
    with schedule.NoveltyScorer({1: ">v0p0"}, "history") as scorer:
        unavailable = score(scorer, 0)
        assert unavailable.patch_reason == "unsupported"
        assert unavailable.coverage_reason == "empty-map"
        assert scorer.counts == {"patch_outcomes": 0, "patch_signatures": 0, "edges": 0}
        assert scorer._process is None
        assert score(scorer, 1, [snapshot(1)], bitmap(3)).heap_key == (-1, -1, -1, 1)


def test_cancellation_reaps_inflight_worker_without_history_commit(monkeypatch):
    scorer = schedule.NoveltyScorer({1: ">v0p0"}, "cancel")
    receive = scorer._receive_bytes
    awaiting_response = False
    worker = None

    class Cancelled(Exception):
        pass

    def receive_after_request(size, check):
        nonlocal awaiting_response, worker
        # Both real request frames have been sent. Cancel at the normal
        # response-wait check, independent of evaluator speed or host load.
        awaiting_response = True
        worker = scorer._process
        return receive(size, check)

    def check():
        if awaiting_response:
            raise Cancelled

    monkeypatch.setattr(scorer, "_receive_bytes", receive_after_request)
    with pytest.raises(Cancelled):
        score(scorer, 0, [snapshot(1)], bitmap(2), check=check)
    assert worker is not None and worker.poll() is not None
    assert not binradar_runtime.PROCESS_REGISTRY.contains(worker)
    assert scorer.counts == {"patch_outcomes": 0, "patch_signatures": 0, "edges": 0}
    scorer.close()


def test_final_check_failure_does_not_commit_coverage():
    scorer = schedule.NoveltyScorer({}, "coverage")
    calls = 0

    def check():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TimeoutError

    with pytest.raises(TimeoutError):
        score(scorer, 0, coverage=bitmap(2), check=check)
    assert scorer.counts["edges"] == 0
    assert scorer._closed


@pytest.mark.parametrize("coverage", [b"", b"x" * 65535, bytearray(65536)])
def test_incomplete_bitmap_rejected(coverage):
    with schedule.NoveltyScorer({}, "coverage") as scorer:
        with pytest.raises(ValueError):
            score(scorer, 0, coverage=coverage)
        assert scorer.counts["edges"] == 0
