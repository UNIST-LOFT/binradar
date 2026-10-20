"""Tests for the Valgrind/QASAN address normalization."""



from binradar import binradar_test


def test_tracer_reference_requires_explicit_valid_v2_row():
    old_row = (
        "[snapshot] [crash] [hit-count 1] [reason memcheck] "
        "[guest_pc dead] [guest_cs_base 0] [fault_addr dead] "
        "[host_fault_addr 0]\n")
    assert binradar_test.extract_tracer_fault_reference(old_row) is None

    normalized = (
        "[snapshot] [fault-reference] [version 2] [valid true] "
        "[source provenance-access] [address 0]\n")
    assert binradar_test.extract_tracer_fault_reference(normalized).identity_key == ("main", 0)


def test_standalone_current_request_reference_and_full_width_finding():
    row = ("[snapshot] [fault-reference] [version 3] [valid true] "
           "[source syscall-request] [address 0] [image none] [image-offset 0]\n")
    reference = binradar_test.extract_tracer_fault_reference(row, require_current=True)
    assert reference.source == "syscall-request"
    assert reference.identity_key == ("main", 0)
    finding = binradar_test.extract_tracer_prov_finding(
        "[prov] [finalize] [finding] [reason out-of-bounds] [origin syscall-request] "
        "[access_pc 0] [actual_pc 0] [access_addr 1000] [width 4294967297] "
        "[obj_id 1] [gen 1] [obj_base 1000] [size 8] [offset 0] "
        "[producer_pc 0] [kind 1] [last_writer 0] [is_uaf 0] [ea_reg 0]\n")
    assert finding["origin"] == "syscall-request"
    assert finding["width"] == 4294967297


def test_standalone_live_probe_requires_current_policy(monkeypatch, tmp_path):
    from binradar import binradar_utils
    from binradar.binradar_verifier import MEMCHECK_POLICY
    (tmp_path / "guest.orig").write_bytes(b"toy")
    (tmp_path / "out").mkdir()
    (tmp_path / "out/plt_info.txt").write_text("malloc free")
    for policy in ("coverage-v4", "coverage-v5", MEMCHECK_POLICY):
        log = (f"[memcheck] [policy {policy}]\n"
               "[snapshot] [fault-reference] [version 3] [valid true] "
               "[source syscall-request] [address 0] [image none] [image-offset 0]\n"
               "[snapshot] [exit] [crash] [entrypoint-hit 1]\n")
        def fake_execute(command, **kwargs):
            assert kwargs["env"]["BINRADAR_MEMCHECK_POLICY"] == MEMCHECK_POLICY
            return binradar_utils.ExecutionResult(
                success=True, exit_code=-11, stdout="", stderr=log)
        monkeypatch.setattr(binradar_test.binradar_utils, "execute", fake_execute)
        reference, exit_str, result, _ = binradar_test.run_tracer_probe(
            str(tmp_path), {"BINARY": "guest", "TEST_CMD": "@@"}, "poc", 5.0)
        assert result.success == (policy == MEMCHECK_POLICY)
        if policy == MEMCHECK_POLICY:
            assert reference.source == "syscall-request"
            assert reference.address == 0
            assert exit_str == "crash"
        else:
            assert reference is None
            assert exit_str == ""


def test_tracer_probe_rejects_an_externally_cancelled_run(monkeypatch, tmp_path):
    """`execute` reports success for a process killed by an external
    termination signal, and the tracer can salvage the interrupted guest pc
    as a valid-looking v2 reference at its kill PC. That is not the subject's
    observed crash, so the probe must report it as failed rather than
    returning the salvaged address."""
    from binradar import binradar_utils
    from binradar.binradar_verifier import tracer_execution_cancelled
    import signal as signal_module

    salvaged = (
        "[snapshot] [fault-reference] [version 2] [valid true] "
        "[source guest-signal] [address 4000affb90]\n")

    def fake_execute(command, **kwargs):
        return binradar_utils.ExecutionResult(
            success=True, exit_code=-int(signal_module.SIGTERM),
            stdout="", stderr=salvaged)

    monkeypatch.setattr(binradar_test.binradar_utils, "execute", fake_execute)
    workdir = str(tmp_path)
    (tmp_path / "guest.orig").write_bytes(b"")
    fault_addr, exit_str, result, _ = binradar_test.run_tracer_probe(
        workdir, {"BINARY": "guest", "TEST_CMD": "@@"}, "poc", 5.0)
    assert fault_addr is None
    assert exit_str == ""
    assert result.success is False
    assert tracer_execution_cancelled(result.exit_code)


def test_overhead_input_defaults_to_configured_poc_and_allows_override(tmp_path):
    configured = tmp_path / "configured input"
    configured.write_bytes(b"configured")
    override = tmp_path / "explicit input"
    override.write_bytes(b"explicit")
    env = {"POC_INPUT": configured.name}
    assert binradar_test._select_overhead_input(str(tmp_path), env, None) == str(configured)
    assert binradar_test._select_overhead_input(
        str(tmp_path), env, override.name) == str(override)
    assert binradar_test._select_overhead_input(
        str(tmp_path), {"POC_INPUT": str(configured)}, None) == str(configured)
    assert binradar_test._select_overhead_input(
        str(tmp_path / "unused"), env, str(override)) == str(override)


def test_overhead_directory_selects_one_file_by_name_not_creation_order(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "z-last").write_bytes(b"created first")
    first = inputs / "b-first file"
    first.write_bytes(b"created second")
    (inputs / "a-directory").mkdir()
    (inputs / "a-directory" / "nested").write_bytes(b"not an immediate file")
    assert binradar_test._select_overhead_input(str(tmp_path), {}, "inputs") == str(first)


def test_overhead_missing_explicit_input_never_falls_back_to_poc(tmp_path):
    import pytest

    configured = tmp_path / "configured"
    configured.write_bytes(b"not a fallback for an explicit path")
    with pytest.raises(FileNotFoundError):
        binradar_test._select_overhead_input(
            str(tmp_path), {"POC_INPUT": str(configured)}, "missing")
    with pytest.raises(FileNotFoundError):
        binradar_test._select_overhead_input(str(tmp_path), {}, None)


def test_overhead_empty_directory_skips_subject_without_poc_fallback(tmp_path):
    from types import SimpleNamespace

    workdir = tmp_path / "workdir"
    workdir.mkdir()
    (workdir / "empty").mkdir()
    (workdir / "configured").write_bytes(b"not used")
    (workdir / "config.env").write_text('BINARY="not-needed"\nPOC_INPUT="configured"\n')
    assert binradar_test._select_overhead_input(
        str(workdir), {"POC_INPUT": "configured"}, "empty") is None
    rows = binradar_test._run_overhead_subject(
        str(tmp_path), "subject", SimpleNamespace(
            workdir="workdir", input="empty", repeats=5, warmup=1, timeout=1))
    assert {row["tool"] for row in rows} == {"orig", "qasan", "tracer", "valgrind"}
    assert all(row["status"] == "skipped" and row["samples"] == []
               and row["slowdown"] == "" for row in rows)
    assert all(row["input"] == str(workdir / "empty") for row in rows)


def test_overhead_medians_exclude_warmup_and_use_native_baseline():
    from types import SimpleNamespace

    rows = binradar_test._overhead_rows(
        "subject", "benign", SimpleNamespace(repeats=3, warmup=1))
    for row, factor in zip(rows, (1, 2, 3, 4)):
        row["samples"] = [
            {"phase": phase, "iteration": index, "seconds": seconds * factor,
             "status": "ok", "exit_code": 0}
            for index, (phase, seconds) in enumerate(
                [("warmup", 1000), ("measure", 1), ("measure", 9), ("measure", 2)], 1)]
    binradar_test._overhead_summarize(rows)
    assert [row["median_seconds"] for row in rows] == [2, 4, 6, 8]
    assert [row["slowdown"] for row in rows] == [1, 2, 3, 4]
    assert [row["overhead_percent"] for row in rows] == [0, 100, 200, 300]
    assert rows[1]["min_seconds"] == 2
    assert rows[1]["max_seconds"] == 18
    assert all(row["completed"] == 3 for row in rows)


def test_overhead_never_reports_ratio_for_failed_or_incomplete_runs():
    from types import SimpleNamespace

    for bad_tool in range(4):
        for bad_phase in ("warmup", "measure"):
            rows = binradar_test._overhead_rows(
                "subject", "benign", SimpleNamespace(repeats=1, warmup=1))
            for index, row in enumerate(rows):
                row["samples"] = [
                    {"phase": phase, "iteration": 1, "seconds": 2,
                     "status": "timeout" if index == bad_tool and phase == bad_phase else "ok",
                     "exit_code": -15 if index == bad_tool and phase == bad_phase else 0}
                    for phase in ("warmup", "measure")]
            binradar_test._overhead_summarize(rows)
            assert rows[bad_tool]["status"] == "timeout"
            assert rows[bad_tool]["median_seconds"] == ""
            assert rows[bad_tool]["slowdown"] == ""
            if bad_tool == 0:
                assert all(row["slowdown"] == "" for row in rows)
                assert rows[1]["status"] == "baseline-unavailable"
            else:
                assert rows[0]["slowdown"] == 1
    rows = binradar_test._overhead_rows(
        "subject", "benign", SimpleNamespace(repeats=2, warmup=0))
    binradar_test._overhead_summarize(rows)
    assert all(row["status"] == "error" and row["slowdown"] == "" for row in rows)


def test_overhead_checker_rows_cannot_mask_timeout_or_nonzero_exit():
    from binradar.binradar_utils import ExecutionResult
    from binradar.binradar_verifier import MEMCHECK_POLICY

    logs = {
        "orig": "",
        "valgrind": "",
        "qasan": "[exit] [result ok]\n",
        "tracer": f"[memcheck] [policy {MEMCHECK_POLICY}]\n"
                  "[snapshot] [exit] [normal] [entrypoint-hit 0]\n",
    }
    for tool, log in logs.items():
        assert binradar_test._overhead_outcome(
            tool, ExecutionResult(True, 0, "", log)) == "ok"
        assert binradar_test._overhead_outcome(
            tool, ExecutionResult(True, 0, "", log, timed_out=True)) == "timeout"
        assert binradar_test._overhead_outcome(
            tool, ExecutionResult(True, -15, "", log)) == "cancelled"
        assert binradar_test._overhead_outcome(
            tool, ExecutionResult(True, 99, "", log)) == "nonzero-exit"
    assert binradar_test._overhead_outcome(
        "qasan", ExecutionResult(True, 0, "", "[exit] [result crash]\n")) == "detected"
    assert binradar_test._overhead_outcome(
        "tracer", ExecutionResult(True, 0, "", logs["tracer"].replace(MEMCHECK_POLICY, "coverage-v1"))) == "invalid-output"


def test_overhead_stdin_is_reopened_and_timeouts_are_not_samples(tmp_path):
    import sys

    testcase = tmp_path / "benign input"
    testcase.write_bytes(b"clean input\n")
    command = [sys.executable, "-c",
               "import sys; sys.exit(0 if sys.stdin.buffer.read() == b'clean input\\n' else 3)"]
    for _ in range(2):
        sample = binradar_test._overhead_sample(
            "orig", command, binradar_test._overhead_environment(),
            str(tmp_path), str(testcase), 5)
        assert sample["status"] == "ok" and sample["exit_code"] == 0
    sample = binradar_test._overhead_sample(
        "orig", [sys.executable, "-c", "import time; time.sleep(5)"],
        binradar_test._overhead_environment(), str(tmp_path), None, 0.02)
    assert sample["status"] == "timeout"
    assert sample["exit_code"] != 0


def test_valgrind_interceptor_uses_target_return_address():
    log = """
==1== Invalid write of size 1
==1==    at 0x484EA13: memmove (vg_replace_strmem.c:1382)
==1==    by 0x42A69B: ??? (in /work/tiffcrop.orig)
==1==    by 0x426F5F: ??? (in /work/tiffcrop.orig)
==1==  Address 0x0 is 1 bytes before a block
"""

    assert binradar_test.extract_valgrind_fault_addr(
        log, "/work/tiffcrop.orig") == 0x42A69C


def test_valgrind_direct_binary_access_keeps_at_address():
    log = """
==1== Invalid read of size 1
==1==    at 0x4066D0: ??? (in /work/tiffcp.orig)
==1==    by 0x404EB5: ??? (in /work/tiffcp.orig)
==1==  Address 0x0 is 0 bytes after a block
"""

    assert binradar_test.extract_valgrind_fault_addr(
        log, "/work/tiffcp.orig") == 0x4066D0


def test_valgrind_signal_uses_target_at_frame():
    log = """
==1== Process terminating with default action of signal 8 (SIGFPE)
==1==    at 0x456845: ??? (in /work/nm.orig)
==1==    by 0x4588C5: ??? (in /work/nm.orig)
==1==    by 0x4881BD6: (below main) (in /gnu/store/libc.so.6)
==1== 
==1== HEAP SUMMARY:
==1==    in use at exit: 0 bytes in 0 blocks
"""

    assert binradar_test.extract_valgrind_signal_addr(
        log, "/work/nm.orig") == 0x456845


def test_valgrind_signal_not_a_memory_error():
    log = """
==1== Process terminating with default action of signal 8 (SIGFPE)
==1==  Integer divide by zero at address 0x1002D052A1
==1==    at 0x42D80C: ??? (in /work/tiffmedian.orig)
==1==    by 0x413EED: ??? (in /work/tiffmedian.orig)
==1== ERROR SUMMARY: 0 errors from 0 contexts
"""

    assert binradar_test.extract_valgrind_fault_addr(
        log, "/work/tiffmedian.orig") is None
    assert binradar_test.extract_valgrind_signal_addr(
        log, "/work/tiffmedian.orig") == 0x42D80C


def test_valgrind_signal_interceptor_uses_target_return_address():
    log = """
==1== Process terminating with default action of signal 8 (SIGFPE)
==1==    at 0x4970184: __mktime_internal (in /gnu/store/libc.so.6)
==1==    by 0x4018AB: ??? (in /work/unzzipcat-mem.orig)
==1==    by 0x401985: ??? (in /work/unzzipcat-mem.orig)
==1== ERROR SUMMARY: 0 errors from 0 contexts
"""

    assert binradar_test.extract_valgrind_signal_addr(
        log, "/work/unzzipcat-mem.orig") == 0x4018AC
