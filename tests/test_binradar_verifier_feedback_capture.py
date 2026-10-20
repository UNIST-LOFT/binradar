"""Verifier feedback records real executions at whole-vector group boundaries."""


import pytest


from binradar import binradar_evidence
from binradar import binradar_verifier as verifier_module


class RecordingJournal:
    def __init__(self, *args, **kwargs):
        self.starts = set()
        self.records = []
        self.skips = []
        self.terminal = None

    def start(self, case, filename):
        self.starts.add((case, filename))

    def record(self, case, filename, **record):
        self.start(case, filename)
        self.records.append(record)

    def skip(self, case, filename, members, reason):
        self.skips.append((case, filename, members, reason))

    def finish(self, reason):
        self.terminal = reason


def probe(outcome="ok", hits=3):
    return verifier_module.BinRadarProbeResult(
        0x1000, 0x1000, [], outcome, hits, 1, 0x2000, [],
        concrete_oracle=verifier_module.CONCRETE_ORACLE,
        concrete_fault_valid=outcome == "crash",
        concrete_fault_source="native" if outcome == "crash" else "unavailable")


def make_verifier(tmp_path, monkeypatch, patches=(1, 2, 3), feedback=True):
    monkeypatch.setattr(verifier_module, "CaptureJournal", RecordingJournal)
    run = tmp_path / "run"
    run.mkdir()
    runner = verifier_module.BinRadarQemuRunner(
        str(tmp_path), "target", "@@", "0x1000")
    verifier = verifier_module.BinRadarConcreteVerifier(
        str(tmp_path), str(run), runner, probe("crash"),
        str(tmp_path / "target.brpatched"), list(patches), feedback_mode=feedback)
    return verifier


def test_ordered_whole_vector_groups_yield_resume_and_global_skips(tmp_path, monkeypatch):
    verifier = make_verifier(tmp_path, monkeypatch, patches=(1, 2, 3, 4))
    verifier.cache_family = verifier_module.PredicateFamily.GENERIC_ERM
    # p1 and p3 agree on every visit; p2 agrees only on the first visit.
    verifier.cached_predicates = {
        1: "=v0p0", 2: "=p0p0", 3: "=v0p0", 4: "=p0p0"}
    testcase = verifier_module.Testcase(7, "input", "ok", 0, [1, 0, 1])
    sweep = verifier_module.ConcreteInputSweep(4)
    clock = [0.0]
    monkeypatch.setattr(verifier_module.time, "monotonic", lambda: clock[0])
    calls = []

    def execute(patch, case):
        calls.append(patch)
        clock[0] += 1.1
        snapshots = [verifier_module.CachedSnapshot(
            0, branch, (value, 0) + (0,) * 14)
            for value, branch in ((0, 1), (1, 0), (0, 1))]
        return probe(), verifier_module.BinRadarCachedRun(patch, snapshots)

    monkeypatch.setattr(verifier, "run_testcase_cached", execute)
    verifier._test_testcase_quantum((1, 2, 3, 4), testcase, sweep, {1, 2, 3, 4})
    assert calls == [1]
    record = verifier.capture_journal.records[0]
    assert record["representative"] == 1
    assert record["members"] == [1, 3]
    assert record["branches"] == [1, 0, 1]
    assert [snapshot.patch_id for snapshot in record["snapshots"]] == [0, 0, 0]
    assert [snapshot.registers[0] for snapshot in record["snapshots"]] == [0, 1, 0]
    assert record["observation"] == "no-crash-pass-same-br"
    assert verifier.total_evidences == {1: 1, 2: 0, 3: 1, 4: 0}
    # Another input globally rejected p2/p4 before this input resumes.
    verifier._test_testcase_quantum((1, 2, 3, 4), testcase, sweep, {1, 3})
    assert sweep.remaining == 0
    assert calls == [1]
    assert len(verifier.capture_journal.records) == 1
    assert verifier.capture_journal.skips == [
        (7, "input", [2], "not-run-global-reject"),
        (7, "input", [4], "not-run-global-reject")]
    assert verifier.total_evidences == {1: 1, 2: 0, 3: 1, 4: 0}


@pytest.mark.parametrize("branch,baseline,outcome,observation,hard", [
    (0, "crash", "crash", "crash-fail", False),
    (2, "crash", "ok", "patch-crashed", True),
    (0, "ok", "crash", "no-crash-fail", True),
])
def test_feedback_security_rejection_is_not_learning_rejection(
        tmp_path, monkeypatch, branch, baseline, outcome, observation, hard):
    verifier = make_verifier(tmp_path, monkeypatch, patches=(1,))
    testcase = verifier_module.Testcase(0, "input", baseline, 0x2000, [0])
    monkeypatch.setattr(verifier, "run_testcase_patched", lambda *args: (
        probe(outcome), verifier_module.BinRadarPatchResult(1, [branch])))
    rejected = verifier._test_testcase(1, testcase)
    assert rejected is hard
    assert verifier.security_rejected == {1}
    assert (1 in verifier.feedback_hard_rejected) is hard
    assert verifier.capture_journal.records[0]["observation"] == observation
    assert "snapshots" not in verifier.capture_journal.records[0]
    verifier._log_result(1, "rejected" if hard else "verified", "input")
    verifier._write_results()
    record = binradar_evidence.read_verifier(verifier.result_file).patches[1]
    assert not record.verified
    assert record.security_rejected
    assert record.feedback_accepted is not hard
    restored = verifier_module.BinRadarConcreteVerifierResult.from_file(verifier.result_file)
    assert restored.patch_verified == {1: False}
    assert restored.feedback[1]["security-res"] == "rejected"


def test_invalid_capture_fallback_records_only_actual_members(tmp_path, monkeypatch):
    verifier = make_verifier(tmp_path, monkeypatch, patches=(1,))
    verifier.cache_family = verifier_module.PredicateFamily.GENERIC_ERM
    monkeypatch.setattr(verifier, "run_testcase_cached", lambda *args: (probe(), None))
    calls = []

    def patched(*args):
        calls.append(args[0])
        return probe(), verifier_module.BinRadarPatchResult(1, [0, 0, 0])

    monkeypatch.setattr(verifier, "run_testcase_patched", patched)
    testcase = verifier_module.Testcase(0, "input", "ok", 0, [0, 0, 0])
    verifier._test_testcase_quantum((1,), testcase,
        verifier_module.ConcreteInputSweep(1), {1})
    assert calls == [1]
    attempt, observed = verifier.capture_journal.records
    assert attempt["members"] == []
    assert attempt["observation"] == "attempted-unusable"
    assert observed["members"] == [1]
    assert observed["branches"] == [0, 0, 0]
    assert observed["observation"] == "no-crash-pass-same-br"
    assert verifier.total_evidences == {1: 1}


def test_completed_noncached_observation_survives_deadline_crossing(tmp_path, monkeypatch):
    verifier = make_verifier(tmp_path, monkeypatch, patches=(1, 2))
    testcase = verifier_module.Testcase(0, "input", "ok", 0, [0])
    clock = [0.0]
    monkeypatch.setattr(verifier_module.time, "monotonic", lambda: clock[0])

    def execute(*args):
        clock[0] = 2.0
        return probe(), verifier_module.BinRadarPatchResult(1, [0])

    monkeypatch.setattr(verifier, "run_testcase_patched", execute)
    sweep = verifier_module.ConcreteInputSweep(2)
    with pytest.raises(verifier_module._VerifierTimeout):
        verifier._test_testcase_quantum((1, 2), testcase, sweep, {1, 2}, deadline=1.0)
    assert verifier.total_evidences == {1: 1, 2: 0}
    assert sweep.remaining == 1
    assert [record["members"] for record in verifier.capture_journal.records] == [[1]]


def test_cached_only_candidate_never_falls_back_to_uncompiled_artifact(tmp_path, monkeypatch):
    verifier = make_verifier(tmp_path, monkeypatch, patches=(31,))
    verifier.cache_family = verifier_module.PredicateFamily.GENERIC_ERM
    verifier.patched_binary_patches = set(range(1, 31))
    monkeypatch.setattr(verifier, "run_testcase_cached", lambda *args: (probe(), None))

    def forbidden(*args):
        pytest.fail("cached-only id executed on brpatched")

    monkeypatch.setattr(verifier, "run_testcase_patched", forbidden)
    testcase = verifier_module.Testcase(0, "input", "ok", 0, [0])
    verifier._test_testcase_quantum((31,), testcase,
        verifier_module.ConcreteInputSweep(1), {31})
    assert verifier.total_evidences == {31: 0}
    assert verifier.capture_journal.records[0]["members"] == []
    assert verifier.capture_journal.skips == [
        (0, "input", [31], "not-run-no-executable-artifact")]


def test_standalone_soft_failure_keeps_learning_then_rejects_terminal(tmp_path, monkeypatch):
    verifier = make_verifier(tmp_path, monkeypatch, patches=(1,))
    stream = tmp_path / "minimizer.sbsv"
    stream.write_text("".join(
        f"[testcase] [result] [id {case}] [file input-{case}] "
        + probe(baseline, hits=1).serialize() + " [pid 0] [br [0]]\n"
        for case, baseline in enumerate(("crash", "ok")))
        + "[minimizer] [done] [time 1]\n")
    calls = []

    def execute(patch, case):
        calls.append(case.id)
        return (probe("crash" if case.id == 0 else "ok"),
                verifier_module.BinRadarPatchResult(1, [0]))

    monkeypatch.setattr(verifier, "run_testcase_patched", execute)
    assert not verifier.run_verification_streaming(str(stream))
    assert calls == [0, 1]
    assert verifier.verdicts == {1: ("rejected", "")}
    assert verifier.total_evidences == {1: 2}
    assert verifier.capture_journal.terminal == "exhausted"
    assert [record["observation"] for record in verifier.capture_journal.records] == [
        "crash-fail", "no-crash-pass-same-br"]
    restored = verifier_module.BinRadarConcreteVerifierResult.from_file(verifier.result_file)
    assert not restored.patch_verified[1]
    assert restored.feedback[1]["feedback-res"] == "accepted"

