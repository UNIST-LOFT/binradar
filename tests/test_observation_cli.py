"""Real isolated CLI fixtures, plus producer-evidence rejection boundaries."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from binradar import paths
from binradar.plan_observations import AnalysisError, _corpus, _read_trace

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def observation_guests(tmp_path_factory):
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for observation CLI integration")
    root = tmp_path_factory.mktemp("observation-cli")
    guests = {}
    for post_read in (False, True):
        read = """
    xor %eax, %eax
    mov %r12, %rdi
    lea value(%rip), %rsi
    mov $1, %edx
    syscall
"""
        source = root / f"guest-{int(post_read)}.S"
        source.write_text("""
.global _start, patch_site, fault_site, value
.section .text
_start:
    mov 16(%rsp), %rdi
    xor %esi, %esi
    mov $2, %eax
    syscall
    mov %rax, %r12
""" + ("" if post_read else read) + """
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %esi, %esi
    xor %edi, %edi
    xor %ebp, %ebp
    xor %r8d, %r8d
    xor %r9d, %r9d
    xor %r10d, %r10d
    xor %r11d, %r11d
    xor %r13d, %r13d
    xor %r14d, %r14d
    xor %r15d, %r15d
    lea stack_end(%rip), %rsp
patch_site:
    nop
""" + (read if post_read else "") + """
    movzbl value(%rip), %ecx
    mov $42, %eax
    xor %edx, %edx
fault_site:
    div %ecx
    xor %edi, %edi
    mov $60, %eax
    syscall
.section .data
value: .byte 0
.section .bss
.balign 16
stack: .skip 4096
stack_end:
.section .note.GNU-stack,"",@progbits
""")
        guest = root / f"guest-{int(post_read)}"
        subprocess.run(["cc", "-nostdlib", "-static", "-no-pie", "-o", str(guest), str(source)],
                       check=True, capture_output=True, timeout=10)
        symbols = {}
        for line in subprocess.check_output(["nm", "-n", str(guest)], text=True).splitlines():
            parts = line.split()
            if len(parts) == 3:
                symbols[parts[2]] = int(parts[0], 16)
        guests[post_read] = (guest, symbols)
    return guests


def _command(tmp_path, guest, symbols):
    crash, normal = tmp_path / "crash", tmp_path / "normal"
    crash.write_bytes(b"\0")
    normal.write_bytes(b"\1")
    return [sys.executable, "-m", "binradar.plan_observations", "--binary", str(guest),
            "--patch-location", hex(symbols["patch_site"]),
            "--fault-reference", hex(symbols["fault_site"]),
            "--crash-input", str(crash), "--normal-input", str(normal),
            "--output-dir", str(tmp_path / "plan"), "--timeout", "5"]


@pytest.mark.parametrize("post_read", [False, True])
def test_real_isolated_observation_command(tmp_path, observation_guests, post_read):
    guest, symbols = observation_guests[post_read]
    command = _command(tmp_path, guest, symbols)
    environment = dict(os.environ, BINRADAR_REPLAY_SERVER="1", BINRADAR_FORKSERVER_ENABLE="1",
                       BINRADAR_OBS_PATCH_LOC="0xbad", E9_EXCLUDE_RANGES="invalid-inherited-state")
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True,
                            text=True, timeout=25, check=False)
    path = tmp_path / "plan/observation-plan.json"
    assert path.is_file(), (result.stdout, result.stderr)
    plan = json.loads(path.read_text())
    assert result.returncode == 0, (plan, result.stdout, result.stderr)
    if post_read:
        assert plan["analysis_status"] == "post_patch_input_read", plan
        assert plan["unobservable_reason"] == "post-patch-input-read"
        assert plan["slots"] == []
    else:
        assert plan["analysis_status"] == "ok", plan
        assert any(slot["kind"] == "global" and int(slot["rva"], 16) == symbols["value"]
                   and slot["width"] == 1 for slot in plan["slots"]), plan
    terminal = json.loads(result.stdout.strip().splitlines()[-1])
    assert terminal["analysis_status"] == plan["analysis_status"]
    assert len(list((tmp_path / "plan/traces").glob("*.jsonl"))) == 4
    assert len(plan["artifact_orig_sha256"]) == 64


def test_wrong_target_fault_never_admits_slots(tmp_path, observation_guests):
    guest, symbols = observation_guests[False]
    wrong = {**symbols, "fault_site": symbols["patch_site"]}
    result = subprocess.run(_command(tmp_path, guest, wrong), cwd=ROOT,
                            capture_output=True, text=True, timeout=15, check=False)
    plan = json.loads((tmp_path / "plan/observation-plan.json").read_text())
    assert result.returncode == 1
    assert plan["analysis_status"] == "execution_error"
    assert plan["slots"] == []
    assert "fault reference mismatch" in plan["diagnostics"][0]["detail"]


def test_incomplete_trace_cannot_be_normal(tmp_path):
    trace = tmp_path / "trace.jsonl"
    trace.write_text('{"kind":"header","schema_version":1}\n')
    with pytest.raises(AnalysisError, match="incomplete"):
        _read_trace(trace, 1000)
    trace.write_text('{"kind":"header","schema_version":1}\n{"kind":"end","status":"ok"}\n')
    with pytest.raises(AnalysisError, match="budget"):
        _read_trace(trace, 1)


def test_changed_corpus_artifact_is_rejected_before_execution(tmp_path):
    (tmp_path / "original-identity.json").write_text(json.dumps({
        "schema_version": 1, "kind": "original-only-minimizer", "original_sha256": "a" * 64,
        "patch_location": "0x401000", "invocation": ["@@"]}))
    with pytest.raises(AnalysisError, match="identity mismatch"):
        _corpus(tmp_path, "b" * 64, 0x401000)


def test_current_concrete_corpus_preserves_outcomes_and_input_identity(tmp_path):
    import hashlib
    from binradar import binradar_verifier as verifier

    minimized = tmp_path / "minimized"
    minimized.mkdir()
    identity = {"schema_version": 1, "kind": "original-only-minimizer",
                "original_sha256": "a" * 64, "patch_location": "0x401000",
                "invocation": ["-x", "@@"]}
    (tmp_path / "original-identity.json").write_text(json.dumps(identity))
    rows = ["[minimizer] [baseline] [version 1] [baseline original]\n"]
    for index, crash in enumerate((True, False)):
        data = bytes([index])
        (minimized / str(index)).write_bytes(data)
        observation = verifier.BinRadarProbeResult(
            0x401000, 0x401000, [], "crash" if crash else "ok", 1, 1,
            0x401010 if crash else 0, [], concrete_oracle=verifier.CONCRETE_ORACLE,
            concrete_fault_valid=crash, concrete_fault_source="native" if crash else "unavailable")
        rows.append(f"[testcase] [original-result] [id {index}] [file {index}] "
                    f"[input-sha256 {hashlib.sha256(data).hexdigest()}] "
                    f"{observation.serialize()} [time 0]\n")
    rows.append("[minimizer] [done]\n")
    (tmp_path / "minimizer.sbsv").write_text("".join(rows))
    cases, invocation = _corpus(tmp_path, "a" * 64, 0x401000)
    assert invocation == ["-x", "@@"]
    assert [case["outcome"] for case in cases] == ["target_crash", "normal"]
    (minimized / "0").write_bytes(b"changed")
    with pytest.raises(AnalysisError, match="input identity changed"):
        _corpus(tmp_path, "a" * 64, 0x401000)


def test_cli_rejects_conflicting_evidence_sources(tmp_path):
    result = subprocess.run([sys.executable, "-m", "binradar.plan_observations",
                             "--binary", "unused", "--patch-location", "0x401000",
                             "--fault-reference", "0x401010", "--concrete-run", str(tmp_path),
                             "--crash-input", "unused", "--output-dir", str(tmp_path / "plan")],
                            cwd=ROOT, capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 2
    assert "not both" in result.stderr
    assert not (tmp_path / "plan").exists()
