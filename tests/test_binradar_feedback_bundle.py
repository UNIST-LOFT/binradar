"""Semantic regressions for the producer's normalized Taosc handoff."""
import json
from types import SimpleNamespace

import pytest

from test_binradar_feedback import _commits, _feedback_executor, _full_row
from test_binradar_evidence import _group
from binradar import binradar_feedback_bundle as bundle_reader
from binradar.binradar_feedback_capture import CaptureJournal, decode_ids, unpack_branches
from binradar.binradar_taosc_predicates import CachedSnapshot
from binradar import binradar_verifier as verifier


def _probe(outcome="normal", fault=0):
    return SimpleNamespace(
        exit_info={"normal": "ok", "crash": "crash", "timeout": "timeout"}[outcome],
        concrete_oracle=verifier.CONCRETE_ORACLE,
        concrete_fault_addr=fault if outcome == "crash" else None,
        concrete_fault_source="native" if outcome == "crash" else "unavailable",
        raw_fault_addr=fault if outcome == "crash" else 0)


def _states(patch, values, branches):
    return [CachedSnapshot(patch_id=patch, branch=branch,
                           registers=(value & ((1 << 64) - 1),) + (0,) * 15)
            for value, branch in zip(values, branches)]


class _CaptureRun:
    def __init__(self, tmp_path, candidates=(1, 2)):
        self.executor, self.run_dir, self.progress = _feedback_executor(tmp_path)
        self.candidates = tuple(candidates)
        self.executor.filter_result = list(candidates)
        self.workdir = tmp_path / "workdir"
        # A real generic expression: signed rax > 5. Physical source lines are
        # deliberately distinct from runtime ids.
        (self.workdir / "brpatches.json").write_text(json.dumps({
            "version": 1, "kind": "generic-erm", "predicates": [
                {"id": patch, "source_line": 2 * patch,
                 "descriptor": ">v0p5"} for patch in range(1, max(candidates, default=0) + 1)]}))
        self.baseline = CaptureJournal(str(self.run_dir), "baseline",
                                      workdir=str(self.workdir), candidates=candidates)
        self.verifier = CaptureJournal(str(self.run_dir), "verifier",
                                      workdir=str(self.workdir), candidates=candidates)
        self.rows = []

    def case(self, case, *, outcome="normal", branches=(0,), values=None):
        filename = f"case-{case}"
        (self.run_dir / "minimized" / filename).write_bytes(f"input-{case}".encode())
        fault = 0x1234 if outcome == "crash" else 0
        row = _full_row(case, filename, "crash" if outcome == "crash" else "ok",
                        fault, patch_hit=len(branches))
        row = row.replace("[br [0]]", "[br [" + "] [".join(map(str, branches)) + "]]")
        self.rows.append(row)
        if values is None:
            values = [8] * len(branches)
        self.baseline.record(case, filename, representative=0, members=[],
                             probe=_probe(outcome, fault), branches=branches,
                             artifact=str(self.workdir / "target.orig"),
                             snapshots=_states(0, values, branches))
        self.verifier.start(case, filename)
        return filename

    def trace(self, case, patch, *, branches=(0,), values=None,
              outcome="normal", fault=0, observation="no-crash-pass-same-br",
              captured=True, members=None):
        if values is None:
            values = [8] * len(branches or ())
        return self.verifier.record(
            case, f"case-{case}", representative=patch,
            members=[patch] if members is None else members,
            probe=_probe(outcome, fault), branches=branches,
            artifact=str(self.workdir / "target.orig"),
            snapshots=_states(patch, values, branches) if captured else None,
            observation=observation)

    def export(self):
        self.baseline.finish("completed")
        self.verifier.finish("completed")
        (self.run_dir / "minimizer.sbsv").write_text("".join(self.rows))
        self.executor.run_feedback()
        return bundle_reader.load_bundle(self.run_dir / "feedback")


def test_normalized_round_trip_preserves_order_repetition_and_executed_trace_lengths(tmp_path):
    run = _CaptureRun(tmp_path)
    run.case(0, branches=(0, 0, 0, 0), values=[8, 4, 8, -1])
    first = run.trace(0, 1, branches=(1, 0, 1, 0), values=[8, 4, 8, -1],
                      observation="no-crash-confidence-diff-br")
    second = run.trace(0, 2, branches=(0, 1), values=[4, 8],
                       observation="no-crash-confidence-diff-br")
    bundle = run.export()

    assert bundle.selected == {1, 2}
    assert set(bundle.traces) == {"c0-b1", first, second}
    assert [state.registers[0] for state in bundle.states(first)] == [8, 4, 8, (1 << 64) - 1]
    assert bundle.evaluate(1, first) == [1, 0, 1, 0]
    assert bundle.evaluate(2, first) == [1, 0, 1, 0]
    assert bundle.evaluate(1, second) == [0, 1]
    assert bundle.traces[first]["hits"] == 4
    assert bundle.traces[second]["hits"] == 2
    assert unpack_branches(bundle.traces[first]["hits"], bundle.traces[first]["branches"]) == [1, 0, 1, 0]
    assert bundle.traces[first]["state"] != bundle.traces[second]["state"]
    assert [(row["trace"], row["members"], row["bin"]) for row in bundle.observations] == [
        (first, "1", "no-crash-confidence-diff-br"),
        (second, "2", "no-crash-confidence-diff-br")]
    assert bundle.inputs["c0"]["baseline"] == "c0-b1"
    assert (bundle.root / bundle.inputs["c0"]["file"]).read_bytes() == b"input-0"
    assert bundle.predicates[2]["tid"] == 4
    assert bundle.metadata["state"]["alignment"] == "trace-local-order-only"
    assert bundle.metadata["state"]["offline_evaluation"] == "guard-values-only-not-execution-outcomes"


def test_observed_four_classes_insufficient_and_both_hard_reject_bins(tmp_path):
    run = _CaptureRun(tmp_path, range(1, 8))
    run.case(0, outcome="crash")
    for patch in range(1, 8):
        run.trace(0, patch, observation="crash-pass")
    run.case(1, outcome="crash")
    for patch in (2, 4):
        run.trace(1, patch, outcome="crash", fault=0x1234, observation="crash-fail")
    run.case(2)
    for patch in (1, 2):
        run.trace(2, patch)
    for patch in (3, 4):
        run.trace(2, patch, branches=(1,), observation="no-crash-confidence-diff-br")
    run.trace(2, 6, outcome="crash", fault=0x1234, observation="no-crash-fail")
    run.trace(2, 7, branches=(2,), observation="patch-crashed")
    bundle = run.export()

    assert {patch: row["concrete"] for patch, row in bundle.predicates.items()} == {
        1: "ground-truth-equivalent", 2: "subset", 3: "superset", 4: "mixed",
        5: "insufficient-evidence"}
    assert {patch: row["concrete-counts"] for patch, row in bundle.predicates.items()} == {
        1: "0,1,1,0,0,0", 2: "1,1,1,0,0,0", 3: "0,1,0,1,0,0",
        4: "1,1,0,1,0,0", 5: "0,1,0,0,0,0"}
    assert set(bundle.excluded) == {6, 7}
    assert bundle.excluded[6]["reason"] == bundle.excluded[7]["reason"] == "hard-reject"
    assert bundle.excluded[6]["concrete-counts"] == "0,1,0,0,1,0"
    assert bundle.excluded[7]["concrete-counts"] == "0,1,0,0,0,1"
    # Exclusion is a global decision, not invented executions for missing cases.
    assert all(not (row["input"] == "c1" and set(decode_ids(row["members"])) & {6, 7})
               for row in bundle.observations)
    assert decode_ids(bundle.coverage["c1"]["not-run"]) == [1, 3, 5, 6, 7]


def test_missing_skipped_and_unusable_are_case_scoped_not_synthetic_observations(tmp_path):
    run = _CaptureRun(tmp_path, range(1, 5))
    run.case(0)
    run.trace(0, 1)
    run.verifier.skip(0, "case-0", [2], "security-rejected")
    timeout = run.trace(0, 3, outcome="timeout", branches=None,
                        observation="no-crash-timeout", captured=False)
    run.case(1)
    run.trace(1, 2)
    run.trace(1, 4)
    run.case(2)
    bundle = run.export()

    assert bundle.coverage["c0"] == {
        "input": "c0", "status": "partial", "not-run": "4", "unusable": "3", "skipped": "2"}
    assert bundle.coverage["c1"] == {
        "input": "c1", "status": "partial", "not-run": "1,3", "unusable": "none", "skipped": "none"}
    assert bundle.coverage["c2"] == {
        "input": "c2", "status": "unavailable", "not-run": "1-4", "unusable": "none", "skipped": "none"}
    assert len(bundle.observations) == 4
    assert [(row["trace"], row["bin"]) for row in bundle.observations if row["members"] == "3"] == [(timeout, "unusable")]
    assert not any(row["input"] == "c2" for row in bundle.observations)
    with pytest.raises(ValueError, match="no complete state"):
        bundle.states(timeout)


@pytest.mark.parametrize("stale", ["input", "state"])
def test_stale_capture_is_rejected_before_replacing_published_bundle(tmp_path, stale):
    run = _CaptureRun(tmp_path)
    run.case(0)
    run.trace(0, 1)
    published = run.run_dir / "feedback"
    published.mkdir()
    sentinel = published / "keep"
    sentinel.write_bytes(b"previous publication")
    if stale == "input":
        (run.run_dir / "minimized/case-0").write_bytes(b"changed after capture")
    else:
        payload = next((run.run_dir / "feedback-capture/states").glob("*.brch"))
        payload.write_bytes(payload.read_bytes() + b"corruption")
    with pytest.raises(ValueError, match="checksum mismatch"):
        run.export()
    assert sentinel.read_bytes() == b"previous publication"
    assert not (published / "feedback.sbsv").exists()


def test_concrete_and_mutation_evidence_never_pool_into_sufficient_classification(tmp_path):
    run = _CaptureRun(tmp_path)
    run.case(0, outcome="crash")
    run.trace(0, 1, observation="crash-pass")
    # The mutation domain supplies only a normal-baseline observation; together
    # these would be sufficient if a consumer accidentally pooled the domains.
    _commits(run.run_dir, [(2, [
        _group(0, 1, 0, [0], [0]),
        _group(1, 1, 0, [0], [1])])])
    bundle = run.export()
    candidate = bundle.predicates[1]
    assert candidate["concrete-counts"] == "0,1,0,0,0,0"
    assert candidate["mutation-counts"] == "0,0,1,0,0,0"
    assert candidate["concrete"] == candidate["mutation"] == "insufficient-evidence"
    assert bundle.inputs["c0"]["domain"] == "concrete"
    assert bundle.inputs["m2"]["domain"] == "mutation"
    assert {(row["input"], row["bin"]) for row in bundle.observations} == {
        ("c0", "crash-pass"), ("m2", "no-crash-pass-same-br")}


@pytest.mark.parametrize("channels", [("baseline",), ("verifier",), ("baseline", "verifier")])
@pytest.mark.parametrize("timestamped", [False, True])
def test_missing_capture_headers_do_not_replace_valid_feedback(tmp_path, channels, timestamped):
    run = _CaptureRun(tmp_path)
    run.case(0)
    if timestamped:
        run.rows = ["2026-10-19 00:00:00,000 - " + row for row in run.rows]
    run.trace(0, 1)
    bundle = run.export()
    published = (bundle.root / "feedback.sbsv").read_bytes()
    completed = list(run.progress)
    for channel in channels:
        (run.run_dir / "feedback-capture" / channel / "header.json").unlink()
    with pytest.raises(ValueError, match="Concrete feedback capture missing"):
        run.executor.run_feedback()
    assert (bundle.root / "feedback.sbsv").read_bytes() == published
    assert sum("[done]" in row for row in run.progress) == sum("[done]" in row for row in completed)


def test_nonfeedback_verifier_cannot_publish_feedback_even_with_capture_headers(tmp_path):
    from binradar import binradar_evidence as evidence
    run = _CaptureRun(tmp_path)
    run.case(0)
    run.trace(0, 1)
    bundle = run.export()
    published = (bundle.root / "feedback.sbsv").read_bytes()
    records = [evidence.VerifierPatchResult(
        patch=patch, verified=True, accept_evidences=0, total_evidences=0,
        observations={}, testcase="", has_feedback=False,
        feedback_accepted=False, security_rejected=False) for patch in (1, 2)]
    evidence.write_verifier(run.run_dir / "verifier.br", records, "exhausted")
    with pytest.raises(ValueError, match="did not run in feedback mode"):
        run.executor.run_feedback()
    assert (bundle.root / "feedback.sbsv").read_bytes() == published


def test_mutation_only_export_does_not_require_absent_concrete_workers(tmp_path):
    run = _CaptureRun(tmp_path)
    for channel in ("baseline", "verifier"):
        (run.run_dir / "feedback-capture" / channel / "header.json").unlink()
    _commits(run.run_dir, [(2, [
        _group(0, 1, 0, [0], [0]), _group(1, 1, 0, [0], [1])])])
    bundle = run.export()
    assert {row["domain"] for row in bundle.inputs.values()} == {"mutation"}
    assert bundle.predicates[1]["mutation-counts"] == "0,0,1,0,0,0"
    assert bundle.metadata["capture"] == {"baseline": None, "verifier": None}


@pytest.mark.parametrize("missing", ["identity", "reference"])
def test_unidentified_candidate_crash_remains_unusable_not_export_failure(tmp_path, missing):
    run = _CaptureRun(tmp_path)
    run.case(0)
    result = _probe("crash", 0x9000)
    if missing == "identity":
        result.concrete_fault_addr = None
        result.concrete_fault_source = "unavailable"
    else:
        run.executor.probe_result.concrete_fault_addr = None
    run.verifier.record(0, "case-0", representative=1, members=[1], probe=result,
                        branches=[0], artifact=str(run.workdir / "target.orig"),
                        observation="no-crash-skip-diff-addr")
    bundle = run.export()
    assert bundle.observations[0]["bin"] == "unusable"
    assert bundle.coverage["c0"]["unusable"] == "1"
    assert bundle.predicates[1]["concrete-counts"] == "0,0,0,0,0,0"


def test_terminal_hard_reject_is_excluded_when_its_witness_was_not_published(tmp_path):
    from binradar import binradar_evidence as evidence
    run = _CaptureRun(tmp_path)
    run.case(0)
    records = [evidence.VerifierPatchResult(
        patch=patch, verified=patch == 2, accept_evidences=0, total_evidences=0,
        observations={}, testcase="", has_feedback=True,
        feedback_accepted=patch == 2, security_rejected=patch == 1) for patch in (1, 2)]
    evidence.write_verifier(run.run_dir / "verifier.br", records, "failed")
    bundle = run.export()
    assert bundle.excluded[1]["reason"] == "hard-reject-witness-unavailable"
    assert 1 not in bundle.predicates
    assert bundle.observations == []
    assert bundle.coverage["c0"]["not-run"] == "1-2"


@pytest.mark.parametrize("conflicting_writes", [False, True])
def test_mutation_label_comes_from_baseline_and_write_sets_must_agree(tmp_path, conflicting_writes):
    from test_binradar_feedback import _pair
    run = _CaptureRun(tmp_path)
    _pair(run.run_dir, patch=0, branches=(0,), outcome="crash", fault=0x1234,
          source="guest-signal")
    _, candidate = _pair(run.run_dir, patch=1, branches=(1,), outcome="normal")
    _commits(run.run_dir, [(2, [
        _group(0, 2, 0x1234, [0], [0], source="guest-signal"),
        _group(1, 1, 0, [1], [1])])])
    if conflicting_writes:
        candidate.write_text(candidate.read_text().replace("00100000", "00200000"))
        with pytest.raises(ValueError, match="disagree on write set"):
            run.export()
        return
    bundle = run.export()
    assert bundle.inputs["m2"]["label"] == "target-crash"
    assert bundle.observations[0]["bin"] == "crash-pass"
    assert bundle.predicates[1]["mutation-counts"] == "0,1,0,0,0,0"
    trace = bundle.traces[bundle.observations[0]["trace"]]
    assert trace["state"].startswith("binradar/")
    assert bundle.states(trace["key"])[0].branch == 1


def test_candidate_lookup_preserves_grouped_evidence_and_sparse_counter_boundaries(tmp_path):
    run = _CaptureRun(tmp_path, candidates=(1, 3, 4, 7, 8))
    run.case(0)
    run.trace(0, 1, members=[1, 3, 4], values=[0])
    run.case(1)
    run.trace(1, 3, members=[3, 4, 7], branches=[1],
              observation="no-crash-confidence-diff-br")
    run.case(2, outcome="crash")
    run.trace(2, 1, members=[1, 3, 4, 7, 8], branches=[1], observation="crash-pass")
    run.case(3)
    run.trace(3, 8, outcome="timeout", branches=None,
              observation="no-crash-timeout", captured=False)
    run.case(4)
    run.trace(4, 7, outcome="crash", fault=0x1234, observation="no-crash-fail")
    bundle = run.export()

    def observations(patch):
        return [(row["input"], row["bin"]) for row in bundle.observations_for(patch)]

    assert observations(1) == [("c0", "no-crash-pass-same-br"), ("c2", "crash-pass")]
    assert observations(3) == observations(4) == [
        ("c0", "no-crash-pass-same-br"), ("c1", "no-crash-confidence-diff-br"),
        ("c2", "crash-pass")]
    assert observations(8) == [("c2", "crash-pass"), ("c3", "unusable")]
    assert observations(7) == [("c1", "no-crash-confidence-diff-br"),
                               ("c2", "crash-pass"), ("c4", "no-crash-fail")]
    assert bundle.excluded[7]["concrete-counts"] == "0,1,0,1,1,0"
    assert {patch: row["concrete-counts"] for patch, row in bundle.predicates.items()} == {
        1: "0,1,1,0,0,0", 3: "0,1,1,1,0,0", 4: "0,1,1,1,0,0", 8: "0,1,0,0,0,0"}
    for missing in (0, 2, 5, 6, 9):
        with pytest.raises(ValueError):
            list(bundle.observations_for(missing))


def test_reader_accepts_adjacent_intervals_with_identical_membership(tmp_path):
    run = _CaptureRun(tmp_path, candidates=(1, 3, 4, 7, 8))
    run.case(0)
    run.trace(0, 1, members=[1, 3, 4], values=[0])
    bundle = run.export()
    path = bundle.root / "feedback.sbsv"
    path.write_text(path.read_text()
                    .replace("[members 1,3-4]", "[members 1,3,4]")
                    .replace("[candidates 1,3-4,7-8]", "[candidates 1,3,4,7,8]")
                    .replace("[not-run 7-8]", "[not-run 7,8]"))
    restored = bundle_reader.load_bundle(path)
    assert [(row["input"], row["bin"]) for row in restored.observations_for(4)] == [
        ("c0", "no-crash-pass-same-br")]
    assert restored.predicates[4]["concrete-counts"] == "0,0,1,0,0,0"
    assert list(restored.observations_for(7)) == []


@pytest.mark.parametrize("before,after", [
    ("[members 1,3-4]", "[members 1-4]"),
    ("[members 1,3-4]", "[members 1,3-4,9]"),
    ("[members 1,3-4]", "[members 0,1,3-4]"),
    ("[members 1,3-4]", "[members 1,3-4,4294967296]"),
    ("[members 1,3-4]", "[members 1,3-4,4]"),
    ("[members 1,3-4]", "[members 3-4,1]"),
    ("[members 1,3-4]", "[members 1,4-3]"),
    ("[members 1,3-4]", "[members 01,3-4]"),
    ("[members 1,3-4]", "[members 1,3-04]"),
    ("[members 1,3-4]", "[members 1,3-4,]"),
    ("[members 1,3-4]", "[members 1,,3-4]"),
    ("[members 1,3-4]", "[members 1,3--4]"),
    ("[members 1,3-4]", "[members 1,٣-4]"),
    ("[members 1,3-4]", "[members none]"),
    ("[not-run 7-8]", "[not-run 2,7-8]"),
    ("[not-run 7-8]", "[not-run 4,7-8]"),
    ("[unusable none]", "[unusable 3]"),
    ("[skipped none]", "[skipped 7]"),
])
def test_reader_rejects_range_holes_overlaps_and_invalid_members(tmp_path, before, after):
    run = _CaptureRun(tmp_path, candidates=(1, 3, 4, 7, 8))
    run.case(0)
    run.trace(0, 1, members=[1, 3, 4], values=[0])
    bundle = run.export()
    path = bundle.root / "feedback.sbsv"
    path.write_text(path.read_text().replace(before, after))
    with pytest.raises(ValueError):
        bundle_reader.load_bundle(path)


def test_reader_rejects_duplicate_group_even_with_consistent_row_totals(tmp_path):
    run = _CaptureRun(tmp_path)
    run.case(0)
    run.trace(0, 1)
    bundle = run.export()
    path = bundle.root / "feedback.sbsv"
    rows = path.read_text().splitlines(keepends=True)
    observation = next(row for row in rows if row.startswith("[observation]"))
    rows.insert(-1, observation)
    rows[-1] = rows[-1].replace("[observations 1]", "[observations 2]")
    path.write_text("".join(rows))
    with pytest.raises(ValueError):
        bundle_reader.load_bundle(path)


@pytest.mark.parametrize("damage", ["coverage", "summary", "input-bytes"])
def test_reader_rejects_inconsistent_evidence_not_just_syntax(tmp_path, damage):
    run = _CaptureRun(tmp_path)
    run.case(0)
    run.trace(0, 1)
    bundle = run.export()
    path = bundle.root / "feedback.sbsv"
    if damage == "input-bytes":
        (bundle.root / bundle.inputs["c0"]["file"]).write_bytes(b"changed")
    else:
        text = path.read_text()
        if damage == "coverage":
            text = text.replace("[not-run 2]", "[not-run none]")
        else:
            text = text.replace("[concrete-counts 0,0,1,0,0,0]", "[concrete-counts 0,0,2,0,0,0]")
        path.write_text(text)
    with pytest.raises(ValueError, match="disagrees|checksum mismatch"):
        bundle_reader.load_bundle(path)


def test_fragmented_groups_preserve_counter_carries_and_reject_overlap(tmp_path):
    run = _CaptureRun(tmp_path, candidates=range(1, 130))
    even = list(range(2, 130, 2))
    for case in range(17):
        run.case(case)
        odd = [patch for patch in range(1, 130, 2) if patch % 5 or case < 15]
        run.trace(case, 1, members=odd, values=[0])
        if case < 16:
            run.trace(case, 2, members=even, branches=[1],
                      observation="no-crash-confidence-diff-br")
    run.case(17)
    run.trace(17, 1, members=list(range(1, 65)), values=[0])
    bundle = run.export()
    for patch in bundle.selected:
        same = ((15 if patch % 5 == 0 else 17) if patch % 2 else 0) + (patch <= 64)
        different = 0 if patch % 2 else 16
        assert bundle.predicates[patch]["concrete-counts"] == f"0,0,{same},{different},0,0"
        assert bundle.predicates[patch]["mutation-counts"] == "0,0,0,0,0,0"
        observations = list(bundle.observations_for(patch))
        assert sum(row["bin"] == "no-crash-pass-same-br" for row in observations) == same
        assert sum(row["bin"] == "no-crash-confidence-diff-br" for row in observations) == different

    path = bundle.root / "feedback.sbsv"
    members = ",".join(map(str, even))
    path.write_text(path.read_text().replace(f"[members {members}]", f"[members 1,{members}]", 1))
    with pytest.raises(ValueError, match="duplicate candidate/input"):
        bundle_reader.load_bundle(path)


@pytest.mark.parametrize("selected", [
    tuple(range(1, 131)) + (0xfffffffe, 0xffffffff),
    (1, 17, 0x80000001, 0xffffffff),
])
def test_membership_matches_sets_at_byte_word_and_sparse_id_boundaries(selected):
    pool = bundle_reader._MemberPool(selected)
    subsets = [set(), set(selected), set(selected[::2]), set(selected[1::2]),
               set(selected[:64]), set(selected[-2:]), {selected[0], selected[-1]}]
    for expected in subsets:
        row = {"members": ",".join(map(str, sorted(expected))) or "none"}
        members = pool.intern(row, "members")
        assert members.mask() == sum(1 << index for index, patch in enumerate(selected) if patch in expected)
        for index in range(-1, len(selected) + 2):
            assert members.contains(index) == (0 <= index < len(selected) and selected[index] in expected)
    # Both endpoints exist, but an inclusive ID range must not bridge holes.
    with pytest.raises(ValueError, match="outside candidate universe"):
        pool.intern({"members": f"{selected[0]}-{selected[-1]}"}, "members")


def test_relative_symlink_root_remains_anchored_after_chdir(tmp_path, monkeypatch):
    run = _CaptureRun(tmp_path)
    run.case(0)
    trace = run.trace(0, 1)
    bundle = run.export()
    alias = tmp_path / "bundle-alias"
    alias.symlink_to(bundle.root, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    loaded = bundle_reader.load_bundle("bundle-alias")
    monkeypatch.chdir(tmp_path.parent)
    assert loaded.states(trace)[0].registers[0] == 8
    assert loaded.evaluate(1, trace) == [1]


def test_lazy_state_rechecks_symlink_containment_even_for_identical_bytes(tmp_path):
    run = _CaptureRun(tmp_path)
    run.case(0)
    trace = run.trace(0, 1)
    bundle = run.export()
    payload = bundle.root / bundle.traces[trace]["state"]
    inside = bundle.root / "relocated.brch"
    payload.rename(inside)
    payload.symlink_to(inside)
    assert bundle.states(trace)[0].registers[0] == 8
    outside = tmp_path / "outside.brch"
    outside.write_bytes(inside.read_bytes())
    payload.unlink()
    payload.symlink_to(outside)
    with pytest.raises(ValueError, match="outside bundle"):
        bundle.states(trace)


def test_loader_rejects_input_symlink_escape_even_with_matching_hash(tmp_path):
    run = _CaptureRun(tmp_path)
    run.case(0)
    run.trace(0, 1)
    bundle = run.export()
    payload = bundle.root / bundle.inputs["c0"]["file"]
    outside = tmp_path / "outside-input"
    outside.write_bytes(payload.read_bytes())
    payload.unlink()
    payload.symlink_to(outside)
    with pytest.raises(ValueError, match="outside bundle"):
        bundle_reader.load_bundle(bundle.root)


@pytest.mark.parametrize("damage", ["absent", "wrong-count", "truncated", "trailing", "duplicate-field"])
def test_reader_rejects_malformed_complete_marker(tmp_path, damage):
    run = _CaptureRun(tmp_path)
    run.case(0)
    run.trace(0, 1)
    bundle = run.export()
    path = bundle.root / "feedback.sbsv"
    lines = path.read_text().splitlines(keepends=True)
    assert lines[-1].startswith("[done]")
    if damage == "absent":
        lines.pop()
    elif damage == "wrong-count":
        lines[-1] = lines[-1].replace("[inputs 1]", "[inputs 2]")
    elif damage == "truncated":
        lines[-1] = lines[-1].rstrip("\n")
    elif damage == "trailing":
        lines.append(lines[-1])
    else:
        lines[-1] = lines[-1].rstrip("\n") + " [inputs 1]\n"
    path.write_text("".join(lines))
    with pytest.raises(ValueError):
        bundle_reader.load_bundle(path)
