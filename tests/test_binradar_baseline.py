#!/usr/bin/env python3
"""P1 regression coverage: patch-0 baseline validation and E9 identity.

The validator decides whether the BINRADAR phase's unmutated baseline
reproduces the POC under the selected artifact.  These tests pin the
observable contract:

- an artifact crash is only attributed to the patch site when a relocation
  record proves it, never because the pc merely lies in an E9 range;
- a clean normal exit is `normal`, not an unidentified crash;
- a crash at a provably different original instruction is `different-fault`;
- a missing validated reference, a timeout, or an unprovable trampoline pc
  is `unusable`;
- the run environment is stripped of every phase descriptor while keeping
  the phase's crash-detection policy, and the run uses the phase tracer
  configuration.
"""

import signal
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_baseline
import binradar_verifier


REFERENCE = binradar_verifier.TracerFaultReference(0x44eced, "provenance-access")
RECORDS = ["0x6ffffff6:0x4d60a5:0x4d60aa"]


def _log(*rows: str) -> str:
    return "[memcheck] [policy coverage-v1]\n" + "\n".join(rows) + "\n"


def _reference_row(address: int, source: str = "provenance-access",
                   valid: str = "true") -> str:
    return (f"[snapshot] [fault-reference] [version 2] [valid {valid}] "
            f"[source {source}] [address {address:x}]")


NORMAL_ROW = "[snapshot] [exit] [normal] [entrypoint-hit 1]"
CRASH_ROW = ("[snapshot] [crash] [hit-count 1] [reason memcheck] "
             "[guest_pc 401000] [guest_cs_base 0] [fault_addr 401000] "
             "[host_fault_addr 0]")


def _result(success=True, timed_out=False, exit_code=0, stderr=""):
    return SimpleNamespace(success=success, timed_out=timed_out,
                           exit_code=exit_code, stderr=stderr,
                           decode_status=lambda: str(exit_code))


def test_relocated_record_proves_identity_not_the_e9_range():
    """Only a recorded relocated jump maps onto the patch site."""
    assert binradar_verifier.e9_relocated_call_site(
        0x6ffffff6, RECORDS) == 0x4d60a5
    # A pc inside the artifact's own E9 exclude ranges, but not a recorded
    # relocated call, has no proven identity.
    assert binradar_verifier.e9_relocated_call_site(
        0x6ffff123, RECORDS) is None
    assert binradar_verifier.e9_relocated_call_site(0x0, RECORDS) is None


@pytest.mark.parametrize("records", [[], ["malformed"], ["0x1:0x2"]])
def test_unusable_records_never_assert_identity(records):
    assert binradar_verifier.e9_relocated_call_site(0x1, records) is None


def _classify(log, *, reference=REFERENCE, records=RECORDS, ranges="",
              patch_loc=0x4d60a5, result=None):
    return binradar_baseline._classify(
        ".brpatched", result if result is not None else _result(stderr=log),
        reference, records, ranges, patch_loc)


@pytest.mark.parametrize("ack", ["", "[memcheck] [policy old]\n"])
@pytest.mark.parametrize("outcome", [NORMAL_ROW, _reference_row(REFERENCE.address)])
def test_missing_or_mismatched_policy_ack_is_unusable(ack, outcome):
    check = _classify(ack + outcome + "\n")
    assert check.status is binradar_baseline.BaselineStatus.UNUSABLE
    assert check.reference is None


@pytest.mark.parametrize("policy", [None, "old", "unavailable"])
def test_stale_probe_policy_prevents_baseline_execution(tmp_path, monkeypatch, policy):
    calls = []
    monkeypatch.setattr(binradar_baseline, "_run_tracer", lambda *a: calls.append(a))
    with pytest.raises(ValueError, match="--run-id n"):
        binradar_baseline.validate_patch_zero_baseline(
            str(tmp_path), {}, original="guest.orig", probe_reference=REFERENCE,
            selected_binary="guest.brpatched", patch_loc="0x1000", test_cmd="@@",
            testcase="poc", timeout=1, metadata={}, probe_policy=policy)
    assert calls == []


@pytest.mark.parametrize("address", [0, REFERENCE.address])
def test_matching_identity_is_reproduced(address):
    reference = binradar_verifier.TracerFaultReference(address, "guest-signal")
    check = _classify(_log(_reference_row(address), CRASH_ROW), reference=reference)
    assert check.status is binradar_baseline.BaselineStatus.REPRODUCED


def test_relocated_jump_normalizes_onto_the_patch_site_when_it_is_the_reference():
    reference = binradar_verifier.TracerFaultReference(0x4d60a5, "guest-signal")
    check = _classify(_log(_reference_row(0x6ffffff6, "guest-signal"), CRASH_ROW),
                      reference=reference)
    assert check.status is binradar_baseline.BaselineStatus.REPRODUCED


def test_provably_different_instruction_is_different_fault():
    check = _classify(_log(_reference_row(0x403510, "guest-signal"), CRASH_ROW))
    assert check.status is binradar_baseline.BaselineStatus.DIFFERENT_FAULT
    assert "0x44eced" in check.detail


def test_clean_normal_exit_is_normal_not_unusable():
    check = _classify(_log(NORMAL_ROW))
    assert check.status is binradar_baseline.BaselineStatus.NORMAL


def test_unprovable_trampoline_pc_is_unusable():
    """A trampoline pc with no relocation record must never be folded onto
    the patch site; it is explicitly unusable."""
    check = _classify(
        _log(_reference_row(0x6ffff800, "guest-signal"), CRASH_ROW),
        ranges="0x6ffff000-0x70005000")
    assert check.status is binradar_baseline.BaselineStatus.UNUSABLE
    assert "trampoline" in check.detail


def test_missing_reference_makes_crash_unusable():
    check = _classify(_log(_reference_row(0x44eced), CRASH_ROW), reference=None)
    assert check.status is binradar_baseline.BaselineStatus.UNUSABLE


def test_invalid_reference_row_is_not_promoted():
    """A legacy/invalid published row must not become a fault identity."""
    invalid = _reference_row(0x1234, "unavailable", valid="false")
    check = _classify(_log(invalid, CRASH_ROW))
    assert check.status is binradar_baseline.BaselineStatus.UNUSABLE


def test_timeout_is_unusable():
    check = _classify(NORMAL_ROW, result=_result(
        success=False, timed_out=True, exit_code=-9))
    assert check.status is binradar_baseline.BaselineStatus.UNUSABLE
    assert "timeout" in check.detail


def test_external_termination_signal_never_validates_a_baseline():
    """`execute_await` reports success for a process killed by an external
    termination signal, and the tracer can salvage the interrupted guest pc
    as a valid-looking fault reference (or emit a normal row) at its kill PC.
    Neither is this artifact's baseline identity, so both must be `unusable`
    even though the run reports `success`."""
    crash_log = _log(_reference_row(0x44eced), CRASH_ROW)
    for signal_number in sorted(binradar_verifier.TRACER_CANCELLATION_SIGNALS):
        killed = _result(exit_code=-int(signal_number), stderr=crash_log)
        check = _classify(crash_log, result=killed)
        assert check.status is binradar_baseline.BaselineStatus.UNUSABLE
        normal_killed = _result(exit_code=-int(signal_number),
                                stderr=_log(NORMAL_ROW))
        assert _classify(_log(NORMAL_ROW), result=normal_killed).status \
            is binradar_baseline.BaselineStatus.UNUSABLE


def test_genuine_guest_fault_signal_is_not_a_cancellation():
    """QEMU re-raises a genuine guest fault as a negative return code. Those
    must stay usable; only the external termination signals are rejected."""
    for signal_number in (signal.SIGSEGV, signal.SIGBUS, signal.SIGABRT):
        assert not binradar_verifier.tracer_execution_cancelled(-signal_number)
    crash_log = _log(_reference_row(0x44eced), CRASH_ROW)
    check = _classify(
        crash_log,
        result=_result(exit_code=-int(signal.SIGSEGV), stderr=crash_log))
    assert check.status is binradar_baseline.BaselineStatus.REPRODUCED


def test_controlled_environment_keeps_policy_and_drops_descriptors():
    phase = {
        "BINRADAR_MEMCHECK_ENABLE": "0",
        "BINRADAR_MEMCHECK_POLICY": "wrong",
        "PLT_INFO_FILE": "/w/plt_info.txt",
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "SYMBOLIC_TESTCASE_NAME": "/w/poc",
        # phase descriptors and destinations that must not leak
        "BINRADAR_FORKSERVER_CTRL_R": "7",
        "BINRADAR_FORKSERVER_STAT_W": "8",
        "PATCH_FD": "9",
        "BINRADAR_PATCH_FD_R": "10",
        "PATCH_CACHED_FD": "11",
        "BINRADAR_PATCH_CACHE_ENABLE": "1",
        "BINRADAR_PATCH_SHM_KEY": "0x1234",
        "BINRADAR_PATCH_CNT": "30",
        "BINRADAR_EVIDENCE_FILE": "/w/binradar.br",
        "BINRADAR_TRACER_LOG_FILE": "/w/binradar-tracer-msg.log",
        "BINRADAR_PROBE_FILE": "/w/probe.sbsv",
        "AFL_QEMU_INST_RANGES": "0x1-0x2",
        "TAOSC_PRED": "p0",
    }
    env = binradar_baseline._controlled_environment(
        phase, e9_ranges="0x6ffff000-0x70005000",
        relocated_calls="0x6ffffff6:0x4d60a5:0x4d60aa")

    # Checker policy is pinned even when inherited configuration disagrees.
    assert env["BINRADAR_MEMCHECK_ENABLE"] == "1"
    assert env["BINRADAR_MEMCHECK_POLICY"] == "coverage-v1"
    assert env["PLT_INFO_FILE"] == "/w/plt_info.txt"
    assert env["SYMBOLIC_INJECT_INPUT_MODE"] == "FROM_FILE"
    assert env["E9_EXCLUDE_RANGES"] == "0x6ffff000-0x70005000"
    assert env["E9_RELOCATED_CALL_JUMPS"] == "0x6ffffff6:0x4d60a5:0x4d60aa"
    # descriptors and destinations stripped
    for key in ("BINRADAR_FORKSERVER_CTRL_R", "BINRADAR_FORKSERVER_STAT_W",
                "BINRADAR_PATCH_FD_R", "PATCH_CACHED_FD",
                "BINRADAR_PATCH_CACHE_ENABLE", "BINRADAR_PATCH_SHM_KEY",
                "BINRADAR_PATCH_CNT", "BINRADAR_EVIDENCE_FILE",
                "BINRADAR_TRACER_LOG_FILE", "BINRADAR_PROBE_FILE",
                "AFL_QEMU_INST_RANGES", "TAOSC_PRED"):
        assert key not in env, key
    assert env["BINRADAR_FORKSERVER_ENABLE"] == "0"
    assert env["PATCH_ID"] == "0"
    assert "PATCH_FD" not in env  # only added when a drained pipe is passed


def test_controlled_environment_adds_patch_fd_only_when_requested():
    env = binradar_baseline._controlled_environment({}, patch_fd=-1)
    assert env["PATCH_FD"] == "-1"


def test_clean_original_is_normal_not_unusable(tmp_path, monkeypatch):
    original = tmp_path / "guest.orig"
    patched = tmp_path / "guest.brpatched"
    original.touch()
    patched.touch()
    monkeypatch.setattr(
        binradar_baseline, "_run_tracer",
        lambda *args, **kwargs: _result(exit_code=1, stderr=_log(NORMAL_ROW)))

    result = binradar_baseline.validate_patch_zero_baseline(
        str(tmp_path), {}, original=str(original), probe_reference=None,
        selected_binary=str(patched), patch_loc="0x401000",
        test_cmd="@@", testcase=str(tmp_path / "poc"), timeout=1,
        metadata={".orig": ("", ()), ".brpatched": ("", ())},
        probe_policy="coverage-v1")
    assert result.check(".orig").status is binradar_baseline.BaselineStatus.NORMAL


def test_matching_artifacts_do_not_override_a_different_probe(tmp_path, monkeypatch):
    original = tmp_path / "guest.orig"
    patched = tmp_path / "guest.brpatched"
    original.touch()
    patched.touch()
    observed = _log(_reference_row(0x402000), CRASH_ROW)
    monkeypatch.setattr(
        binradar_baseline, "_run_tracer",
        lambda *args, **kwargs: _result(stderr=observed))
    result = binradar_baseline.validate_patch_zero_baseline(
        str(tmp_path), {}, original=str(original), probe_reference=REFERENCE,
        selected_binary=str(patched), patch_loc="0x401000",
        test_cmd="@@", testcase=str(tmp_path / "poc"), timeout=1,
        metadata={".orig": ("", ()), ".brpatched": ("", ())},
        probe_policy="coverage-v1")
    assert result.reference == REFERENCE
    assert result.check(".orig").status is binradar_baseline.BaselineStatus.DIFFERENT_FAULT
    assert result.selected.status is binradar_baseline.BaselineStatus.DIFFERENT_FAULT


def test_artifact_match_cannot_hide_normal_original(tmp_path, monkeypatch):
    original = tmp_path / "guest.orig"
    patched = tmp_path / "guest.brpatched"
    original.touch()
    patched.touch()
    monkeypatch.setattr(
        binradar_baseline, "_run_tracer",
        lambda _w, binary, *_args: _result(stderr=(
            _log(NORMAL_ROW) if binary == str(original)
            else _log(_reference_row(REFERENCE.address), CRASH_ROW))))
    result = binradar_baseline.validate_patch_zero_baseline(
        str(tmp_path), {}, original=str(original), probe_reference=REFERENCE,
        selected_binary=str(patched), patch_loc="0x401000",
        test_cmd="@@", testcase=str(tmp_path / "poc"), timeout=1,
        metadata={".orig": ("", ()), ".brpatched": ("", ())},
        probe_policy="coverage-v1")
    assert result.check(".orig").status is binradar_baseline.BaselineStatus.NORMAL
    assert result.selected.status is binradar_baseline.BaselineStatus.UNUSABLE


def test_preflight_deadline_skips_later_artifact(tmp_path, monkeypatch):
    original = tmp_path / "guest.orig"
    patched = tmp_path / "guest.brpatched"
    original.touch()
    patched.touch()
    calls = []
    def run(_w, binary, _env, _cmd, _poc, remaining):
        calls.append((binary, remaining))
        return _result(stderr=_log(_reference_row(REFERENCE.address), CRASH_ROW))
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(binradar_baseline, "_run_tracer", run)
    monkeypatch.setattr(binradar_baseline.time, "monotonic", lambda: next(ticks))
    result = binradar_baseline.validate_patch_zero_baseline(
        str(tmp_path), {}, original=str(original), probe_reference=REFERENCE,
        selected_binary=str(patched), patch_loc="0x401000",
        test_cmd="@@", testcase=str(tmp_path / "poc"), timeout=10,
        phase_deadline=1.0,
        metadata={".orig": ("", ()), ".brpatched": ("", ())},
        probe_policy="coverage-v1")
    assert calls == [(str(original), 1.0)]
    assert result.check(".orig").status is binradar_baseline.BaselineStatus.REPRODUCED
    assert result.selected.status is binradar_baseline.BaselineStatus.UNUSABLE


def test_selected_check_tracks_the_artifact_the_phase_executes():
    checks = (
        binradar_baseline.BaselineCheck(
            ".orig", binradar_baseline.BaselineStatus.REPRODUCED, REFERENCE, ""),
        binradar_baseline.BaselineCheck(
            ".brpatched", binradar_baseline.BaselineStatus.NORMAL, None, ""),
        binradar_baseline.BaselineCheck(
            ".brcached", binradar_baseline.BaselineStatus.REPRODUCED,
            REFERENCE, ""),
    )
    result = binradar_baseline.BaselineResult(REFERENCE, ".brcached", checks)
    assert result.selected.artifact == ".brcached"
    assert result.check(".brpatched").status is binradar_baseline.BaselineStatus.NORMAL
    assert "[.brpatched normal]" in result.summary()
