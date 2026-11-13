import os
import re
import select
import stat
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest


from binradar import binradar_runtime
from binradar import paths


@pytest.mark.parametrize("result,stop", [(4, 0), (0, 5), (4, 1)])
def test_capacity_result_and_stop_must_be_paired(
        tmp_path, monkeypatch, fake_script, result, stop):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, statuses=[(1, 1, 2, result, stop)])
    try:
        executor.start()
        with pytest.raises(RuntimeError, match="capacity result/stop pair"):
            executor.run()
    finally:
        stop_executor(executor)


@pytest.mark.parametrize("remaining,stop", [(1, 0), (0, 1)])
def test_binradar_completed_capacity_is_a_real_observation(
        tmp_path, monkeypatch, fake_script, remaining, stop):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, mode="completed_capacity",
        statuses=[(1, 1, remaining, 0, stop)])
    executor.mode = "binradar"
    try:
        executor.start()
        summary = executor.run()
        assert summary.success
        assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        assert summary.terminal == (stop == 1)
        assert summary.collection.capacity
    finally:
        stop_executor(executor)


@pytest.mark.parametrize("mode,error", [
    ("completed_capacity", RuntimeError),
    ("completed_capacity_malformed", ValueError),
])
def test_completed_capacity_requires_binradar_and_valid_status(
        tmp_path, monkeypatch, fake_script, mode, error):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, mode=mode,
        statuses=[(1, 1, 0, 0, 1)])
    if mode.endswith("malformed"):
        executor.mode = "binradar"
    try:
        executor.start()
        with pytest.raises(error):
            executor.run()
    finally:
        stop_executor(executor)


def test_capacity_reply_is_successful_but_incomplete(
        tmp_path, monkeypatch, fake_script):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, statuses=[(1, 1, 2, 4, 5)])
    try:
        executor.start()
        summary = executor.run()
        assert summary.success and summary.terminal
        assert summary.collection.complete is False
        assert summary.attempt_result == binradar_runtime.AttemptResult.CAPACITY
        assert summary.remaining_plans == 2
    finally:
        stop_executor(executor)


def test_pre_entry_capacity_exit_is_not_a_guest_normal_outcome(
        tmp_path, monkeypatch, fake_script):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, mode="capacity_before_banner")
    try:
        # A prior complete file must be removed before starting this process.
        Path(executor.collection_status_path).write_text('{"complete":true}')
        executor.start()
        summary = executor.run()
        assert summary.success and summary.terminal
        assert summary.attempt_result == binradar_runtime.AttemptResult.CAPACITY
        assert summary.stop_reason == binradar_runtime.StopReason.CAPACITY
        assert summary.collection.complete is False
        assert summary.collection.reason == "query-capacity"
        assert summary.collection.queries == 2
        assert summary.attempt == 0 and summary.representative_runs == 0
        assert executor.run_result is None
    finally:
        stop_executor(executor)


def test_pre_entry_capacity_sidecar_cannot_hide_real_exit_error(
        tmp_path, monkeypatch, fake_script):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, mode="capacity_before_banner_error")
    try:
        with pytest.raises(EOFError, match="exit status 1"):
            executor.start()
    finally:
        stop_executor(executor)


def test_partial_banner_cannot_be_reclassified_as_capacity(
        tmp_path, monkeypatch, fake_script):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, mode="capacity_before_banner_partial")
    try:
        with pytest.raises(EOFError, match="forkserver handshake"):
            executor.start()
    finally:
        stop_executor(executor)


def test_transport_keeps_cached_binary_records_off_patch_log():
    env = {"BINRADAR_PATCH_CACHE_ENABLE": "1"}
    pipes = binradar_runtime.ForkserverTransport(env, "binradar")
    pipes.setup()
    try:
        assert env["PATCH_FD"] != env["PATCH_CACHED_FD"]
        os.write(int(env["PATCH_FD"]), b"[patch] [id 7] [br 1] [v 11]\n")
        os.write(int(env["PATCH_CACHED_FD"]), b"BRCH")
        assert os.read(int(env["BINRADAR_PATCH_FD_R"]), 64) == \
            b"[patch] [id 7] [br 1] [v 11]\n"
        assert os.read(int(env["BINRADAR_PATCH_CACHED_FD_R"]), 4) == b"BRCH"
    finally:
        pipes.cleanup()


FAKE_FORKSERVER = r'''#!/usr/bin/env python3
import os
import select
import struct
import time

ctrl = int(os.environ["BINRADAR_FORKSERVER_CTRL_R"])
stat = int(os.environ["BINRADAR_FORKSERVER_STAT_W"])
mode = os.environ.get("FAKE_MODE", "normal")
log_path = os.environ.get("FAKE_LOG")
version = int(os.environ.get("FAKE_VERSION", "0x41464c04"), 0)
wrong_ack = int(os.environ.get("FAKE_WRONG_ACK", "0x12345678"), 0)


def log(row):
    if log_path:
        with open(log_path, "a", encoding="ascii") as stream:
            stream.write(row + "\n")


def read_exact(fd, size):
    data = b""
    while len(data) < size:
        chunk = os.read(fd, size - len(data))
        if not chunk:
            return data
        data += chunk
    return data


def send(value):
    os.write(stat, struct.pack("<I", value))


def run_summaries(summaries):
    for row in summaries:
        attempt, representative_runs, remaining = row[:3]
        attempt_result = row[3] if len(row) > 3 else 0
        stop_reason = row[4] if len(row) > 4 else (0 if remaining else 1)
        command = read_exact(ctrl, 4)
        if len(command) != 4:
            log("parent-eof")
            return
        log("command:" + command.hex())
        if mode == "stall_after_command":
            time.sleep(3)
            return
        if mode == "delayed_summary":
            time.sleep(0.4)
        summary = struct.pack("<IIIII", attempt, representative_runs,
                              remaining, attempt_result, stop_reason)
        if mode in ("partial_summary", "close_during_summary"):
            os.write(stat, summary[:2])
            if mode == "partial_summary":
                time.sleep(3)
            else:
                os.close(stat)
            return
        if mode in ("completed_capacity", "completed_capacity_malformed"):
            import json
            with open(os.environ["SYMBOLIC_COLLECTION_STATUS_FILE"], "w") as stream:
                json.dump({} if mode.endswith("malformed") else {
                    "version": 1, "complete": False, "reason": "query-capacity",
                    "queries": 2, "expr_bytes": 64, "query_capacity": 4,
                    "expr_capacity_bytes": 128}, stream)
        os.write(stat, summary)
        log("summary:%d:%d:%d" %
            (attempt, representative_runs, remaining))
        if mode == "stall_after_summary":
            time.sleep(3)
            return


if mode.startswith("capacity_before_banner"):
    import json
    status_path = os.environ["SYMBOLIC_COLLECTION_STATUS_FILE"]
    with open(status_path, "w", encoding="utf-8") as stream:
        json.dump({"version": 1, "complete": False, "reason": "query-capacity",
                   "queries": 2, "expr_bytes": 64, "query_capacity": 4,
                   "expr_capacity_bytes": 128}, stream)
    if mode.endswith("partial"):
        os.write(stat, bytes([4, 76]))
    os.close(stat)
    raise SystemExit(1 if mode.endswith("error") else 0)
if mode == "close_before_banner":
    os.close(stat)
    raise SystemExit(0)
if mode == "stall_before_banner":
    time.sleep(3)
    raise SystemExit(0)

send(version)
if mode == "close_during_handshake":
    os.close(stat)
    raise SystemExit(0)

reply = read_exact(ctrl, 4)
if len(reply) != 4:
    log("handshake-eof")
    raise SystemExit(0)
reply_value = struct.unpack("<I", reply)[0]
expected_reply = version ^ 0xFFFFFFFF
if mode == "new_server_reject_old_ack":
    if reply_value != expected_reply:
        log("ack-mismatch")
    else:
        log("ack-accepted")
    raise SystemExit(0)
if reply_value != expected_reply:
    log("bad-ack:%08x" % reply_value)
    raise SystemExit(0)

if mode == "wrong_ack":
    send(wrong_ack)
    raise SystemExit(0)

send(version)
if version == 0x41464c07:
    cancel = int(os.environ["BINRADAR_REPLAY_CANCEL_FD"])
    while True:
        header = read_exact(ctrl, 8)
        if len(header) != 8:
            raise SystemExit(0)
        command, request_id = struct.unpack("<II", header)
        log("resident:%d:%d" % (command, request_id))
        if command == 0:
            summary = struct.pack("<8I", 1, request_id, 1, 1, 0, 0, 1, 0)
            if mode == "resident_partial_summary":
                os.write(stat, summary[:11])
                token = struct.unpack("<I", read_exact(cancel, 4))[0]
                log("cancel:%d" % token)
                os.write(stat, summary[11:])
            else:
                os.write(stat, summary)
        elif command == 1:
            os.write(stat, struct.pack("<6I", 2, request_id, 0, 4, request_id, 0))
        elif command in (2, 5):
            mutation, length = struct.unpack("<II", read_exact(ctrl, 8))
            descriptor = read_exact(ctrl, length)
            log("descriptor:" + descriptor.decode("ascii"))
            if command == 5:
                os.write(stat, struct.pack("<3I", 2, request_id,
                                           0 if descriptor == b"p0" else 1))
            elif mode == "resident_capture_identity":
                text = os.environ["FAKE_CASE_TEXT"].encode()
                os.write(stat, struct.pack("<6I", 3, request_id, 1, 0, 0, len(text)) + text)
            elif mode == "resident_case_timeout":
                time.sleep(3)
            else:
                if mode == "resident_case_cancel":
                    token = struct.unpack("<I", read_exact(cancel, 4))[0]
                    log("cancel:%d" % token)
                reply_id = request_id + 1 if mode == "resident_wrong_id" else request_id
                text = ('{"mutation":%d,"capture":null}' % mutation).encode()
                os.write(stat, struct.pack("<6I", 3, reply_id, 0, 3, 4, len(text)) + text)
        elif command == 3:
            if mode == "resident_stall_shutdown":
                time.sleep(3)
            else:
                os.write(stat, struct.pack("<3I", 2, request_id, 0))
                raise SystemExit(0)
        else:
            raise SystemExit(1)
summaries_text = os.environ.get("FAKE_STATUSES", "1,1,5")
summaries = []
for item in summaries_text.split(";"):
    summaries.append(tuple(int(part, 0) for part in item.split(",")))
run_summaries(summaries)
if mode == "check_unread":
    ready, _, _ = select.select([ctrl], [], [], 0.2)
    if ready:
        extra = os.read(ctrl, 4096)
        log("extra:" + (extra.hex() if extra else "none"))
    else:
        log("extra:none")

while True:
    command = read_exact(ctrl, 4)
    if not command:
        log("parent-eof")
        raise SystemExit(0)
    if len(command) != 4:
        log("short-command")
        raise SystemExit(0)
    log("command:" + command.hex())
'''


@pytest.fixture
def reentered_guest(tmp_path):
    """A guest whose entrypoint executes three times in one process."""
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for entrypoint integration")
    source = tmp_path / "reentered.c"
    source.write_text(r'''
#include <fcntl.h>
#include <unistd.h>

static unsigned char visits;

int main(int argc, char **argv)
{
    unsigned char visit = ++visits;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || write(fd, &visit, 1) != 1) return 1;
    close(fd);
    return visit < 3 ? main(argc, argv) : 0;
}
''', encoding="ascii")
    guest = tmp_path / "reentered"
    subprocess.run(
        ["cc", "-O0", "-fno-pie", "-no-pie", "-o", str(guest), str(source)],
        check=True, capture_output=True)
    symbols = subprocess.run(
        ["nm", str(guest)], check=True, capture_output=True, text=True)
    entrypoint = next(line.split()[0] for line in symbols.stdout.splitlines()
                      if line.split()[-1] == "main")
    return guest, entrypoint


@pytest.mark.parametrize("enabled", [False, True])
def test_real_forkserver_starts_before_first_entrypoint_body(
        tmp_path, reentered_guest, enabled):
    """Enable controls snapshotting; re-entry never starts another server."""
    guest, entrypoint = reentered_guest
    marker = tmp_path / "visits"
    env = {
        "PATH": os.environ["PATH"],
        "NO_EXTERNAL_SOLVER": "1",
        "BINRADAR_FORKSERVER_ENABLE": "1" if enabled else "0",
        "BINRADAR_ENTRYPOINT": entrypoint,
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "5",
        "BINRADAR_OSPREY_ENABLE": "0",
        "BINRADAR_TRACE_FILE": "none",
        "BINRADAR_TRACER_LOG_FILE": str(tmp_path / "tracer.log"),
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "SYMBOLIC_TESTCASE_NAME": "/dev/null",
    }
    executor = binradar_runtime.TracerExecutor(
        "directed", env, str(tmp_path), str(tmp_path), str(guest),
        str(marker), "/dev/null", binradar_runtime.Deadline.from_timeout(10))
    try:
        executor.start()
        if enabled:
            # The banner must arrive before *any* entrypoint body runs.
            assert not marker.exists()
        summary = executor.run()
        assert marker.read_bytes() == b"\x01\x02\x03"
        if enabled:
            assert summary.representative_runs == 1
            assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
            assert summary.stop_reason == binradar_runtime.StopReason.EXHAUSTED
        else:
            assert executor.run_result.exit_code == 0
    finally:
        executor.stop()


@pytest.mark.parametrize("family", ["generic-erm", "CWE805-erm"])
def test_real_empty_manifest_executes_patch_zero(tmp_path, reentered_guest, family):
    """An empty candidate list still needs selector space for neutral p0."""
    guest, entrypoint = reentered_guest
    manifest = tmp_path / "brpatches.json"
    manifest.write_text(
        '{"version":1,"kind":"' + family + '","predicates":[]}', encoding="ascii")
    marker = tmp_path / "visits"
    env = {
        "PATH": os.environ["PATH"],
        "NO_EXTERNAL_SOLVER": "1",
        "BINRADAR_FORKSERVER_ENABLE": "1",
        "BINRADAR_ENTRYPOINT": entrypoint,
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "5",
        "BINRADAR_OSPREY_ENABLE": "0",
        "BINRADAR_TRACE_FILE": "none",
        "BINRADAR_TRACER_LOG_FILE": str(tmp_path / "tracer.log"),
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "SYMBOLIC_TESTCASE_NAME": "/dev/null",
        "BINRADAR_PATCH_CNT": "0",
        "BINRADAR_PATCH_CACHE_ENABLE": "1",
        "BINRADAR_PATCH_MANIFEST": str(manifest),
        "BINRADAR_EVIDENCE_FILE": str(tmp_path / "binradar.br"),
        "BRCACHE_STACK_SIZE": "0",
    }
    with binradar_runtime.PhaseSession("binradar", 10) as session:
        session.shared_memory(env, include_patch_key=True)
        executor = session.start_tracer(
            mode="binradar", env=env, workdir=str(tmp_path), rundir=str(tmp_path),
            binary=str(guest), test_cmd=str(marker), testcase="/dev/null")
        summary = executor.run()
        assert marker.read_bytes() == b"\x01\x02\x03"
        assert summary.attempt == 1 and summary.representative_runs == 1
        assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED


def test_real_child_timeout_records_killed_child_cpu(tmp_path):
    """A killed child must report its own CPU time, not a shared total.

    Without this row a CPU-saturated child and a blocked child produce the
    identical `timeout` record, which is what made the TIFF-8128 incident
    ambiguous.  The guest spins forever inside the baseline child, so the
    timeout branch runs and `wait4()` must yield nonzero used CPU.
    """
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for timeout integration")
    source = tmp_path / "spinner.c"
    source.write_text(r'''
static volatile unsigned long spins;

int main(void)
{
    for (;;) {
        spins += 1;
    }
    return 0;
}
''', encoding="ascii")
    guest = tmp_path / "spinner"
    subprocess.run(
        ["cc", "-O0", "-fno-pie", "-no-pie", "-o", str(guest), str(source)],
        check=True, capture_output=True)
    symbols = subprocess.run(
        ["nm", str(guest)], check=True, capture_output=True, text=True)
    entrypoint = next(row.split()[0] for row in symbols.stdout.splitlines()
                      if row.split()[-1] == "main")
    manifest = tmp_path / "brpatches.json"
    manifest.write_text(
        '{"version":1,"kind":"generic-erm","predicates":[]}', encoding="ascii")
    log = tmp_path / "tracer.log"
    env = {
        "PATH": os.environ["PATH"],
        "NO_EXTERNAL_SOLVER": "1",
        "BINRADAR_FORKSERVER_ENABLE": "1",
        "BINRADAR_ENTRYPOINT": entrypoint,
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "1",
        "BINRADAR_OSPREY_ENABLE": "0",
        "BINRADAR_TRACE_FILE": "none",
        "BINRADAR_TRACER_LOG_FILE": str(log),
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "SYMBOLIC_TESTCASE_NAME": "/dev/null",
        "BINRADAR_PATCH_CNT": "0",
        "BINRADAR_PATCH_CACHE_ENABLE": "1",
        "BINRADAR_PATCH_MANIFEST": str(manifest),
        "BINRADAR_EVIDENCE_FILE": str(tmp_path / "binradar.br"),
        "BRCACHE_STACK_SIZE": "0",
    }
    with binradar_runtime.PhaseSession("binradar", 120) as session:
        session.shared_memory(env, include_patch_key=True)
        executor = session.start_tracer(
            mode="binradar", env=env, workdir=str(tmp_path), rundir=str(tmp_path),
            binary=str(guest), test_cmd="", testcase="/dev/null")
        summary = executor.run()
        assert summary.attempt == 1
        assert summary.attempt_result == binradar_runtime.AttemptResult.TIMEOUT
        assert summary.stop_reason == \
            binradar_runtime.StopReason.BASELINE_UNAVAILABLE
    text = log.read_text(encoding="utf-8", errors="replace")
    assert "[forkserver] [child-timeout]" in text
    cpu_rows = [line for line in text.splitlines()
                if "[forkserver] [child-cpu]" in line]
    assert len(cpu_rows) == 1, text
    fields = {}
    for match in re.finditer(r"\[(\S+) ([^\]]*)\]", cpu_rows[0]):
        fields[match.group(1)] = match.group(2).strip()
    assert int(fields["pid"]) > 0
    assert int(fields["user-ms"]) + int(fields["sys-ms"]) > 0


@pytest.fixture
def fake_script(tmp_path):
    path = tmp_path / "fake_forkserver.py"
    path.write_text(FAKE_FORKSERVER, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def make_executor(tmp_path, monkeypatch, fake_script, mode="check_unread", statuses=None):
    log_path = tmp_path / "fake.log"
    env = os.environ.copy()
    env.update(
        {
            "BINRADAR_FORKSERVER_ENABLE": "1",
            "FAKE_MODE": mode,
            "FAKE_LOG": str(log_path),
        }
    )
    if statuses is not None:
        env["FAKE_STATUSES"] = ";".join(",".join(str(x) for x in row) for row in statuses)
    monkeypatch.setattr(paths, "TRACER_BIN", str(fake_script))
    executor = binradar_runtime.TracerExecutor(
        "protocol",
        env,
        str(tmp_path),
        str(tmp_path),
        "ignored",
        "",
        "ignored",
        binradar_runtime.Deadline.from_timeout(1),
    )
    executor.forkserver_init_timeout = 0.5
    monkeypatch.setattr(binradar_runtime.TracerExecutor, "forkserver_timeout", 0.25)
    monkeypatch.setattr(
        binradar_runtime.TracerExecutor, "forkserver_analyze_margin", 0.5)
    return executor, log_path


def stop_executor(executor):
    try:
        executor.stop()
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        if executor.process is not None and executor.process.poll() is None:
            executor.process.kill()
            executor.process.wait(timeout=2)


def read_pipe(fd, size, timeout=1.0):
    deadline = time.monotonic() + timeout
    data = b""
    while len(data) < size:
        wait = deadline - time.monotonic()
        if wait <= 0:
            raise TimeoutError("pipe read timed out")
        ready, _, _ = select.select([fd], [], [], wait)
        if not ready:
            raise TimeoutError("pipe read timed out")
        chunk = os.read(fd, size - len(data))
        if not chunk:
            raise EOFError("pipe EOF")
        data += chunk
    return data


def test_new_protocol_one_run_has_no_payload(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(tmp_path, monkeypatch, fake_script)
    try:
        executor.start()
        summary = executor.run()
        assert summary.elapsed_ms >= 0
        assert summary.success is True
        assert summary.remaining_plans == 5
        assert summary.attempt == 1
        assert summary.representative_runs == 1
        assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        assert summary.stop_reason == binradar_runtime.StopReason.CONTINUE
        assert executor.iter == 1
        assert executor.representative_runs == 1
    finally:
        stop_executor(executor)
    rows = log_path.read_text(encoding="ascii").splitlines()
    assert rows.count("command:00000000") == 1
    assert "summary:1:1:5" in rows
    assert "extra:none" in rows


def test_back_to_back_runs_keep_status_boundaries(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(
        tmp_path,
        monkeypatch,
        fake_script,
        statuses=[(1, 3, 4), (2, 2, 3)],
    )
    try:
        executor.start()
        assert executor.run().remaining_plans == 4
        assert executor.representative_runs == 3
        assert executor.run().remaining_plans == 3
        assert executor.representative_runs == 2
        assert executor.iter == 2
    finally:
        stop_executor(executor)
    rows = log_path.read_text(encoding="ascii").splitlines()
    assert rows.count("command:00000000") == 2
    assert "summary:1:3:4" in rows
    assert "summary:2:2:3" in rows


@pytest.mark.parametrize(
    "mode, phase",
    [
        ("close_before_banner", "start"),
        ("close_during_handshake", "start"),
        ("close_during_summary", "run"),
    ],
)
def test_protocol_eof_is_fatal(monkeypatch, tmp_path, fake_script, mode, phase):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode=mode)
    started = time.monotonic()
    try:
        with pytest.raises(EOFError):
            executor.start()
            if phase == "run":
                executor.run()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 1.5


def test_missing_banner_reports_tracer_state_at_configured_timeout(
        monkeypatch, tmp_path, fake_script):
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, mode="stall_before_banner")
    tracer_log = tmp_path / "binradar-tracer-msg.log"
    tracer_log.write_text(
        "[snapshot] [crash] [pc 403160] [signal 11]\n"
        "[snapshot] [exit] [entrypoint-hit 0] [reason guest-signal]\n",
        encoding="ascii")
    executor.env["BINRADAR_TRACER_LOG_FILE"] = str(tracer_log)
    executor.forkserver_init_timeout = 0.1
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError) as failure:
            executor.start()
    finally:
        stop_executor(executor)
    message = str(failure.value)
    assert "within 0.1s" in message
    assert "BINRADAR_ENTRYPOINT/forkserver handshake" in message
    assert "[entrypoint-hit 0]" in message
    assert "[pc 403160]" in message
    assert time.monotonic() - started < 1.5


def test_idle_parent_close_terminates_tracer(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(tmp_path, monkeypatch, fake_script, mode="normal")
    started = time.monotonic()
    executor.start()
    stop_executor(executor)
    assert time.monotonic() - started < 1.5
    assert "parent-eof" in log_path.read_text(encoding="ascii").splitlines()


def test_summary_arriving_during_response_grace_is_accepted(
        monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(
        tmp_path, monkeypatch, fake_script, mode="delayed_summary",
        statuses=[(1, 1, 0, 0, 1)])
    try:
        executor.start()
        started = time.monotonic()
        summary = executor.run()
        elapsed = time.monotonic() - started
        assert elapsed > executor.forkserver_timeout
        assert summary.success and summary.terminal
        assert summary.attempt == 1
        assert summary.representative_runs == 1
    finally:
        stop_executor(executor)
    assert "summary:1:1:0" in log_path.read_text(encoding="ascii").splitlines()


def test_phase_deadline_wins_over_response_grace(
        monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(
        tmp_path, monkeypatch, fake_script, mode="delayed_summary",
        statuses=[(1, 1, 0, 0, 1)])
    try:
        executor.start()
        executor.deadline = binradar_runtime.Deadline.from_timeout(0.1)
        with pytest.raises(TimeoutError, match="forkserver response"):
            executor.run()
        assert executor.deadline.expired()
        assert "summary:1:1:0" not in log_path.read_text(
            encoding="ascii").splitlines()
    finally:
        stop_executor(executor)


@pytest.mark.parametrize("mode", ["stall_after_command", "partial_summary"])
def test_stalled_peer_hits_bounded_timeout(monkeypatch, tmp_path, fake_script, mode):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode=mode)
    started = time.monotonic()
    try:
        executor.start()
        with pytest.raises(TimeoutError):
            executor.run()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 2.0


@pytest.mark.parametrize("mode", ["wrong_ack"])
def test_wrong_acknowledgement_fails_handshake(monkeypatch, tmp_path, fake_script, mode):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode=mode)
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="Unexpected forkserver ack"):
            executor.start()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 1.5


def test_old_word_tracer_fails_new_runner(monkeypatch, tmp_path, fake_script):
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script, mode="normal")
    executor.env["FAKE_VERSION"] = "0x41464c03"
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="Unexpected forkserver handshake"):
            executor.start()
    finally:
        stop_executor(executor)
    assert time.monotonic() - started < 1.5


def test_old_runner_fails_new_tracer(monkeypatch, tmp_path, fake_script):
    del monkeypatch
    log_path = tmp_path / "old-runner.log"
    ctrl_r, ctrl_w = os.pipe()
    stat_r, stat_w = os.pipe()
    env = os.environ.copy()
    env.update(
        {
            "BINRADAR_FORKSERVER_CTRL_R": str(ctrl_r),
            "BINRADAR_FORKSERVER_STAT_W": str(stat_w),
            "FAKE_MODE": "new_server_reject_old_ack",
            "FAKE_LOG": str(log_path),
        }
    )
    proc = subprocess.Popen(
        [str(fake_script)],
        env=env,
        pass_fds=(ctrl_r, stat_w),
        start_new_session=True,
    )
    os.close(ctrl_r)
    os.close(stat_w)
    try:
        banner = struct.unpack("<I", read_pipe(stat_r, 4))[0]
        assert banner == binradar_runtime.HANDSHAKE_EXPECTED
        old_word = 0x41464C03
        os.write(ctrl_w, struct.pack("<I", old_word ^ 0xFFFFFFFF))
        proc.wait(timeout=1)
    finally:
        os.close(ctrl_w)
        os.close(stat_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
    assert log_path.read_text(encoding="ascii").splitlines() == ["ack-mismatch"]


def test_unknown_attempt_result_is_a_protocol_error(monkeypatch, tmp_path,
                                                    fake_script):
    """An out-of-table reply is never converted into an ordinary miss."""
    executor, _ = make_executor(tmp_path, monkeypatch, fake_script,
                                statuses=[(1, 1, 2, 99, 0)])
    try:
        executor.start()
        with pytest.raises(RuntimeError, match="unknown attempt result"):
            executor.run()
    finally:
        stop_executor(executor)


def test_resource_failure_summary_marks_phase_failed(monkeypatch, tmp_path,
                                                     fake_script):
    """resource-failure must not look like an exhausted mutation sweep."""
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script,
        statuses=[(1, 1, 9,
                   int(binradar_runtime.AttemptResult.UNUSABLE_EXIT),
                   int(binradar_runtime.StopReason.RESOURCE_FAILURE))])
    try:
        executor.start()
        summary = executor.run()
        assert summary.success is False
        assert summary.attempt_result == \
            binradar_runtime.AttemptResult.UNUSABLE_EXIT
        assert summary.stop_reason == \
            binradar_runtime.StopReason.RESOURCE_FAILURE
        assert summary.remaining_plans == 9
    finally:
        stop_executor(executor)


@pytest.mark.parametrize(
    "status, message",
    [
        ((2, 1, 1, 0, 0), "expected 1"),
        ((1, 1, 0, 0, 0), "continue without a queued plan"),
        ((1, 1, 2, 0, 1), "exhaustion with 2 queued plan"),
        ((1, 1, 0, 0, 2), "invalid baseline-unavailable"),
        ((1, 1, 2, 3, 4), "resource-failure with timeout"),
    ],
)
def test_inconsistent_summary_is_a_protocol_error(
        monkeypatch, tmp_path, fake_script, status, message):
    """Known enum values still fail when their packet invariants disagree."""
    executor, _ = make_executor(
        tmp_path, monkeypatch, fake_script, statuses=[status])
    try:
        executor.start()
        with pytest.raises(RuntimeError, match=message):
            executor.run()
    finally:
        stop_executor(executor)


def test_child_timeout_status_has_no_analysis_word(monkeypatch, tmp_path, fake_script):
    executor, log_path = make_executor(
        tmp_path,
        monkeypatch,
        fake_script,
        statuses=[(1, 1, 0)],
    )
    try:
        executor.start()
        summary = executor.run()
        assert summary.success is True
        assert summary.remaining_plans == 0
        assert summary.stop_reason == binradar_runtime.StopReason.EXHAUSTED
        assert executor.iter == 1
    finally:
        stop_executor(executor)
    rows = log_path.read_text(encoding="ascii").splitlines()
    assert "summary:1:1:0" in rows
    assert "extra:none" in rows


def _audit_guest_syscall(number, *args, result=None):
    """Issue a real x86-64 syscall and trap if its observed return differs."""
    registers = ("rdi", "rsi", "rdx", "r10", "r8", "r9")
    instructions = [f"mov {value}, %{register}"
                    for register, value in zip(registers, args)]
    instructions.extend((f"mov ${number}, %eax", "syscall"))
    if result is not None:
        instructions.extend((f"cmp ${result}, %rax", "jne audit_fail"))
    return "\n".join(instructions) + "\n"


def _audit_log_events(text, *event):
    """Decode scalar bracket records rather than matching diagnostic prose."""
    records = []
    for line in text.splitlines():
        fields = [part.split("]", 1)[0] for part in line.split("[")[1:]]
        if fields[:len(event)] == list(event):
            records.append(dict(field.split(" ", 1)
                                for field in fields[len(event):]
                                if " " in field))
    return records


def _assert_resident_audit_supported(text):
    audits = _audit_log_events(text, "replay", "audit")
    assert len(audits) == 1, text
    assert audits[0]["unsupported"] == "false", text
    assert not _audit_log_events(text, "replay", "unsupported-syscall"), text


@pytest.fixture
def resident_audit_guest(tmp_path):
    """Run freestanding native generation without E9, providers or a solver.

    Guest assertions trap on incorrect syscall results.  No payload/output
    channel is added: the normal-exit observation proves those assertions ran.
    The intentionally unpatched guest has no useful retained mutations; patched
    CASE/cache coverage belongs to the independent artifact integration gate.
    """
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for resident syscall integration")

    def run(prefix, body, *, resident=True, testcase="/dev/null"):
        source = tmp_path / "audit-guest.S"
        source.write_text(
            ".text\n.globl _start, audit_entry\n_start:\n" + prefix +
            "\njmp audit_entry\naudit_entry:\n" + body +
            _audit_guest_syscall(60, "$0") +
            "audit_fail:\nud2\n"
            ".data\n.balign 8\n"
            "null_path: .asciz \"/dev/null\"\n"
            "input_path: .asciz \"input\"\n"
            "output_path: .asciz \"output\"\n"
            "iov: .quad buffer, 1\n"
            "\n.bss\n.balign 8\nbuffer: .skip 256\n"
            "before_stat: .skip 144\nafter_stat: .skip 144\n"
            "pipe_fds: .skip 8\n", encoding="ascii")
        guest = tmp_path / "audit-guest"
        subprocess.run(
            ["cc", "-nostdlib", "-static", "-no-pie", "-o", str(guest),
             str(source)], check=True, capture_output=True, timeout=20)
        symbols = subprocess.run(
            ["nm", str(guest)], check=True, capture_output=True, text=True,
            timeout=10)
        entrypoint = next(row.split()[0] for row in symbols.stdout.splitlines()
                          if row.split()[-1] == "audit_entry")
        manifest = tmp_path / "brpatches.json"
        manifest.write_text(
            '{"version":1,"kind":"generic-erm","predicates":[]}',
            encoding="ascii")
        log = tmp_path / "audit-tracer.log"
        env = {
            "PATH": os.environ["PATH"],
            "NO_EXTERNAL_SOLVER": "1",
            "BINRADAR_FORKSERVER_ENABLE": "1",
            "BINRADAR_ENTRYPOINT": entrypoint,
            "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "5",
            "BINRADAR_OSPREY_ENABLE": "0",
            "BINRADAR_TRACE_FILE": "none",
            "BINRADAR_TRACER_LOG_FILE": str(log),
            "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
            "SYMBOLIC_TESTCASE_NAME": testcase,
            "BINRADAR_PATCH_CNT": "0",
            "BINRADAR_PATCH_CACHE_ENABLE": "1",
            "BINRADAR_PATCH_MANIFEST": str(manifest),
            "BINRADAR_EVIDENCE_FILE": str(tmp_path / "binradar.br"),
            "BINRADAR_REPLAY_SERVER": "1" if resident else "0",
            "BINRADAR_REPLAY_DIR": str(tmp_path / "replay"),
            "BRCACHE_STACK_SIZE": "0",
        }
        with binradar_runtime.PhaseSession("binradar", 30) as session:
            session.shared_memory(env, include_patch_key=True)
            executor = session.start_tracer(
                mode="binradar", env=env, workdir=str(tmp_path),
                rundir=str(tmp_path), binary=str(guest), test_cmd="",
                testcase=testcase, replay_mode=resident)
            summary = executor.run()
            assert summary.attempt == 1
            assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
            assert summary.representative_runs == 1
            if resident:
                info = executor.finish_generation()
                assert info["retained_mutations"] == 0
                assert info["mutation_ids"] == []
                assert executor.process.poll() is None
                executor.shutdown_replay()
            executor.process.wait(timeout=10)
            assert executor.process.returncode == 0
        text = log.read_text(encoding="utf-8")
        # Nonzero guest exits are normal too, so check the recorded exit value;
        # a trap must not accidentally pass as a completed baseline crash.
        assert [int(row["exit"]) for row in
                _audit_log_events(text, "analyze", "normal")] == [0], text
        assert not _audit_log_events(text, "analyze", "crash"), text
        return text

    return run


def _audit_open(path, flags=0):
    return (_audit_guest_syscall(2, f"${path}", f"${flags}", "$384") +
            "test %rax, %rax\njs audit_fail\nmov %rax, %r12\n")


@pytest.mark.parametrize("number,args", [
    (0, ("$buffer", "$1")),             # read
    (1, ("$buffer", "$1")),             # write
    (5, ("$after_stat",)),               # fstat
    (8, ("$0", "$0")),                 # lseek
    (16, ("$0x5401", "$buffer")),        # ioctl(TCGETS)
    (17, ("$buffer", "$1", "$0")),      # pread64
    (19, ("$iov", "$1")),               # readv
    (20, ("$iov", "$1")),               # writev
])
def test_real_resident_audit_accepts_invalid_negative_fd_ebadf(
        resident_audit_guest, number, args):
    text = resident_audit_guest(
        "", _audit_guest_syscall(number, "$-1", *args, result=-9))
    _assert_resident_audit_supported(text)


@pytest.mark.parametrize("number", [0, 1])
def test_real_resident_audit_rejects_negative_fd_efault(
        resident_audit_guest, number):
    # QEMU validates these guest buffers before issuing host IO.  A negative
    # fd must not turn the actual EFAULT into an admitted/fabricated EBADF.
    text = resident_audit_guest(
        "", _audit_guest_syscall(number, "$-1", "$0", "$1", result=-14))
    violations = _audit_log_events(text, "replay", "unsupported-syscall")
    assert len(violations) == 1, text
    assert int(violations[0]["nr"]) == number
    assert int(violations[0]["ret"]) == -14
    assert int(violations[0]["errno"]) == 14


@pytest.mark.parametrize("flags,number", [(1, 0), (0, 1)])
def test_real_resident_audit_accepts_wrong_access_only_on_stable_null(
        resident_audit_guest, flags, number):
    text = resident_audit_guest(
        _audit_open("null_path", flags),
        _audit_guest_syscall(number, "%r12", "$buffer", "$1", result=-9))
    _assert_resident_audit_supported(text)


def test_real_resident_failed_read_preserves_symbolic_input(
        tmp_path, resident_audit_guest):
    (tmp_path / "input").write_bytes(b"immutable input")
    prefix = (_audit_open("input_path") +
              _audit_guest_syscall(0, "%r12", "$buffer", "$1", result=1) +
              _audit_open("null_path", 1))
    body = (_audit_guest_syscall(0, "%r12", "$buffer", "$1", result=-9) +
            "cmpb $105, buffer(%rip)\njne audit_fail\n")
    text = resident_audit_guest(prefix, body, testcase="input")
    _assert_resident_audit_supported(text)


def test_real_resident_audit_accepts_null_io_metadata_and_tcgets(
        resident_audit_guest):
    body = (
        _audit_guest_syscall(0, "%r12", "$buffer", "$1", result=0) +
        _audit_guest_syscall(5, "%r12", "$after_stat", result=0) +
        "mov after_stat+24(%rip), %eax\nand $0xf000, %eax\n"
        "cmp $0x2000, %eax\njne audit_fail\n" +
        _audit_guest_syscall(16, "%r12", "$0x5401", "$buffer", result=-25) +
        _audit_guest_syscall(8, "%r12", "$0", "$0", result=0) +
        # TracerExecutor's inherited stdout/stderr really are /dev/null.
        _audit_guest_syscall(5, "$1", "$after_stat", result=0) +
        _audit_guest_syscall(16, "$2", "$0x5401", "$buffer", result=-25))
    text = resident_audit_guest(_audit_open("null_path"), body)
    _assert_resident_audit_supported(text)


@pytest.mark.parametrize("duplicate", [False, True])
@pytest.mark.parametrize("resident", [False, True])
def test_real_resident_audit_regular_stat_snapshot_includes_atime(
        tmp_path, resident_audit_guest, duplicate, resident):
    input_path = tmp_path / "input"
    input_path.write_bytes(b"immutable input")
    # Force relatime filesystems to update atime on the actual guest read.
    os.utime(input_path, ns=(1_000_000_000, 2_000_000_000))
    before_atime = input_path.stat().st_atime_ns
    with input_path.open("rb") as stream:
        stream.read(1)
    if input_path.stat().st_atime_ns == before_atime:
        pytest.skip("filesystem does not advance input atime on reads")
    os.utime(input_path, ns=(1_000_000_000, 2_000_000_000))
    prefix = _audit_open("input_path")
    if duplicate:
        # An inherited guest fd acquired through fcntl must not evade tracking.
        prefix += (_audit_guest_syscall(72, "%r12", "$1030", "$64") +
                   "test %rax, %rax\njs audit_fail\nmov %rax, %r14\n" +
                   _audit_guest_syscall(3, "%r12", result=0) +
                   "mov %r14, %r12\n")
    prefix += _audit_guest_syscall(5, "%r12", "$before_stat", result=0)
    body = (
        _audit_guest_syscall(0, "%r12", "$buffer", "$1", result=1) +
        "cmpb $105, buffer(%rip)\njne audit_fail\n" +
        _audit_guest_syscall(5, "%r12", "$after_stat", result=0))
    if resident:
        body += ("mov $before_stat, %rsi\nmov $after_stat, %rdi\n"
                 "mov $18, %ecx\ncld\nrepe cmpsq\njne audit_fail\n")
    else:
        # Ordinary mode must keep the real host atime instead of projecting
        # the resident-only metadata snapshot.
        body += ("mov before_stat+72(%rip), %rax\n"
                 "cmp after_stat+72(%rip), %rax\nje audit_fail\n")
    body += _audit_guest_syscall(8, "%r12", "$0", "$0", result=0)
    text = resident_audit_guest(prefix, body, resident=resident)
    assert input_path.stat().st_atime_ns != before_atime
    if resident:
        _assert_resident_audit_supported(text)


def test_real_resident_audit_failed_prefix_shared_mmap_is_not_shared_state(
        resident_audit_guest):
    # A failed zero-length MAP_SHARED mapping creates no inherited state.
    prefix = _audit_guest_syscall(
        9, "$0", "$0", "$3", "$0x21", "$-1", "$0", result=-22)
    text = resident_audit_guest(prefix, "")
    _assert_resident_audit_supported(text)


@pytest.mark.parametrize("change", ["flags", "binding"])
def test_real_resident_audit_rejects_changed_input_capability(
        tmp_path, resident_audit_guest, change):
    (tmp_path / "input").write_bytes(b"immutable input")
    prefix = _audit_open("null_path") + "mov %r12, %r14\n"
    prefix += _audit_open("input_path")
    if change == "flags":
        body = _audit_guest_syscall(72, "%r12", "$4", "$0x800", result=0)
        expected_read = 1
    else:
        body = (_audit_guest_syscall(33, "%r14", "%r12") +
                "cmp %r12, %rax\njne audit_fail\n")
        expected_read = 0
    body += _audit_guest_syscall(
        0, "%r12", "$buffer", "$1", result=expected_read)
    text = resident_audit_guest(prefix, body)
    audits = _audit_log_events(text, "replay", "audit")
    assert len(audits) == 1 and audits[0]["unsupported"] == "false", text
    violations = _audit_log_events(text, "replay", "unsupported-syscall")
    reads = [row for row in violations if int(row["nr"]) == 0]
    assert len(reads) == 1, text
    assert int(reads[0]["ret"]) == expected_read
    assert int(reads[0]["errno"]) == 0


@pytest.mark.parametrize("kind,number,expected", [
    ("output-stat", 5, 0),
    ("output-read", 0, -9),
    ("output-seek", 8, 0),
    ("null-bad-stat-pointer", 5, -14),
    ("null-other-ioctl", 16, -25),
    ("pipe-read", 0, 0),
    ("pipe-seek", 8, -29),
    ("socket-stat", 5, 0),
    ("entropy", 318, 1),
])
def test_real_resident_audit_rejects_external_fd_state_and_entropy(
        tmp_path, resident_audit_guest, kind, number, expected):
    (tmp_path / "output").write_bytes(b"mutable output")
    if kind.startswith("output"):
        prefix = _audit_open("output_path", 1)
    elif kind.startswith("null"):
        prefix = _audit_open("null_path")
    elif kind.startswith("pipe"):
        prefix = (_audit_guest_syscall(22, "$pipe_fds", result=0) +
                  "mov pipe_fds(%rip), %r12d\n")
    elif kind.startswith("socket"):
        prefix = (_audit_guest_syscall(41, "$1", "$1", "$0") +
                  "test %rax, %rax\njs audit_fail\nmov %rax, %r12\n")
    else:
        prefix = ""
    if number == 5:
        address = "$0" if kind == "null-bad-stat-pointer" else "$after_stat"
        body = _audit_guest_syscall(5, "%r12", address, result=expected)
    elif number == 8:
        body = _audit_guest_syscall(8, "%r12", "$0", "$0", result=expected)
    elif number == 16:
        body = _audit_guest_syscall(
            16, "%r12", "$0x5413", "$buffer", result=expected)
    elif number == 0:
        # Zero-length pipe IO proves rejection without depending on a peer or
        # blocking. Wrong-access output IO must remain an unaudited EBADF.
        count = "$0" if kind == "pipe-read" else "$1"
        body = _audit_guest_syscall(
            0, "%r12", "$buffer", count, result=expected)
    else:
        body = _audit_guest_syscall(318, "$buffer", "$1", "$0", result=1)
    text = resident_audit_guest(prefix, body)
    violations = _audit_log_events(text, "replay", "unsupported-syscall")
    matched = [row for row in violations if int(row["nr"]) == number]
    assert len(matched) == 1, text
    assert int(matched[0]["ret"]) == expected
    assert int(matched[0]["errno"]) == max(0, -expected)
    assert matched[0].get("reason"), text


@pytest.fixture
def zero_plan_guest(tmp_path):
    """No symbolic planning, external state, or writes after the snapshot."""
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for resident integration")
    # A libc main() return reads exit bookkeeping and creates plans.  Enter a
    # freestanding exit syscall so the first baseline genuinely exhausts.
    source = tmp_path / "zero-plan.S"
    source.write_text(".globl _start\n_start:\n"
                      "xor %edi,%edi\nmov $60,%eax\nsyscall\n", encoding="ascii")
    guest = tmp_path / "zero-plan"
    subprocess.run(["cc", "-nostdlib", "-static", "-no-pie", "-o", str(guest),
                    str(source)], check=True, capture_output=True)
    symbols = subprocess.run(["nm", str(guest)], check=True,
                             capture_output=True, text=True)
    entrypoint = next(row.split()[0] for row in symbols.stdout.splitlines()
                      if row.split()[-1] == "_start")
    return guest, entrypoint


@pytest.mark.parametrize("stale_cancel", [False, True])
def test_real_resident_protocol_reports_ready_after_finish(
        tmp_path, zero_plan_guest, stale_cancel):
    """Exhausted zero-plan parent stays resident; a stale cancel cannot kill it."""
    guest, entrypoint = zero_plan_guest
    manifest = tmp_path / "brpatches.json"
    manifest.write_text(
        '{"version":1,"kind":"generic-erm","predicates":[]}', encoding="ascii")
    marker = tmp_path / "visits"
    env = {
        "PATH": os.environ["PATH"],
        "NO_EXTERNAL_SOLVER": "1",
        "BINRADAR_FORKSERVER_ENABLE": "1",
        "BINRADAR_ENTRYPOINT": entrypoint,
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "5",
        "BINRADAR_OSPREY_ENABLE": "0",
        "BINRADAR_TRACE_FILE": "none",
        "BINRADAR_TRACER_LOG_FILE": str(tmp_path / "tracer.log"),
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "SYMBOLIC_TESTCASE_NAME": "/dev/null",
        "BINRADAR_PATCH_CNT": "0",
        "BINRADAR_PATCH_CACHE_ENABLE": "1",
        "BINRADAR_PATCH_MANIFEST": str(manifest),
        "BINRADAR_EVIDENCE_FILE": str(tmp_path / "binradar.br"),
        "BINRADAR_REPLAY_SERVER": "1",
        "BINRADAR_REPLAY_DIR": str(tmp_path / "replay"),
        "BRCACHE_STACK_SIZE": "0",
    }
    with binradar_runtime.PhaseSession("binradar", 30) as session:
        session.shared_memory(env, include_patch_key=True)
        executor = session.start_tracer(
            mode="binradar", env=env, workdir=str(tmp_path), rundir=str(tmp_path),
            binary=str(guest), test_cmd=str(marker), testcase="/dev/null",
            replay_mode=True)
        if stale_cancel:
            # ID 1 belongs to a prior (noncancellable) validation transaction.
            assert executor.validate_replay_descriptor("invalid", 5) is False
            os.write(executor.transport.cancel_w, struct.pack("<I", 1))
        summary = executor.run()
        assert summary.attempt == 1
        assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        assert summary.stop_reason == binradar_runtime.StopReason.EXHAUSTED
        assert summary.remaining_plans == 0
        # The generation reply is not a service terminal: the parent is alive.
        info = executor.finish_generation()
        assert info["retained_mutations"] == len(info["mutation_ids"])
        assert executor.process is not None and executor.process.poll() is None
        executor.shutdown_replay()
        executor.process.wait(timeout=10)
        assert executor.process.returncode == 0



def make_resident_executor(tmp_path, monkeypatch, fake_script, mode="resident"):
    executor, log_path = make_executor(tmp_path, monkeypatch, fake_script, mode=mode)
    executor.replay_mode = True
    executor.env["FAKE_VERSION"] = "0x41464c07"
    return executor, log_path


@pytest.mark.parametrize("invalid", [None, "mutation", "selector", "path", "digest", "reuse", "malformed"])
def test_resident_capture_identity_is_bounded_and_owned(
        tmp_path, monkeypatch, fake_script, invalid):
    import json
    executor, _ = make_resident_executor(
        tmp_path, monkeypatch, fake_script, "resident_capture_identity")
    root = tmp_path / "replay"
    root.mkdir()
    executor.env["BINRADAR_REPLAY_DIR"] = str(root)
    identity = {"mutation": 7, "path": str(root / "capture.brch"),
                "sha256": "a" * 64, "descriptor": "p0", "patch_id": 0,
                "reuse": "full-vector-equivalent"}
    if invalid == "mutation":
        identity["mutation"] = 8
    elif invalid == "selector":
        identity["patch_id"] = 2
    elif invalid == "path":
        identity["path"] = str(tmp_path / "outside.brch")
    elif invalid == "digest":
        identity["sha256"] = "bad"
    elif invalid == "reuse":
        identity["reuse"] = "fresh"
    executor.env["FAKE_CASE_TEXT"] = "{" if invalid == "malformed" else json.dumps(
        {"mutation": 7, "capture": identity})
    try:
        executor.start()
        if invalid is not None:
            with pytest.raises(RuntimeError):
                executor.request_replay_case(7, "p0", 0.5)
            assert executor.transport.poisoned
        else:
            result = executor.request_replay_case(7, "p0", 0.5)
            assert result.capture == identity
            assert result.capture["patch_id"] == 0
            executor.shutdown_replay(0.5)
    finally:
        stop_executor(executor)


@pytest.mark.parametrize("version", ["0x41464c05", "0x41464c06"])
def test_old_resident_peer_is_rejected(tmp_path, monkeypatch, fake_script, version):
    executor, _ = make_resident_executor(tmp_path, monkeypatch, fake_script)
    executor.env["FAKE_VERSION"] = version
    try:
        with pytest.raises(RuntimeError, match="Unexpected forkserver handshake"):
            executor.start()
    finally:
        stop_executor(executor)


def test_resident_partial_summary_recovers_then_finishes(
        tmp_path, monkeypatch, fake_script):
    executor, log_path = make_resident_executor(
        tmp_path, monkeypatch, fake_script, "resident_partial_summary")
    try:
        executor.start()
        executor.deadline = binradar_runtime.Deadline.from_timeout(0.05)
        summary = executor.run()
        assert summary.attempt == 1 and summary.remaining_plans == 0
        assert not executor._generation_inflight
        executor.cancel_replay_child()  # successful boundary has no active ID
        assert executor.finish_generation()["mutation_ids"] == []
        executor.shutdown_replay(0.5)
        rows = log_path.read_text().splitlines()
        assert rows.count("cancel:1") == 1
        assert "resident:1:2" in rows and "resident:3:3" in rows
    finally:
        stop_executor(executor)


def test_generation_cancel_event_before_admission_keeps_channel_healthy(
        tmp_path, monkeypatch, fake_script):
    executor, _ = make_resident_executor(tmp_path, monkeypatch, fake_script)
    event = threading.Event()
    event.set()
    executor.replay_cancel_event = event
    try:
        executor.start()
        with pytest.raises(InterruptedError):
            executor.run()
        assert executor.transport.request_id == 0
        assert not executor.transport.poisoned
        executor.shutdown_replay(0.5)  # shutdown ignores generation cancel event
    finally:
        stop_executor(executor)


def test_generation_cancel_event_registration_race_is_scoped(
        tmp_path, monkeypatch, fake_script):
    executor, log_path = make_resident_executor(
        tmp_path, monkeypatch, fake_script, "resident_partial_summary")
    event = threading.Event()
    executor.replay_cancel_event = event
    try:
        executor.start()
        original = executor.transport.send_command

        def publish_then_cancel(command):
            original(command)
            if command == binradar_runtime.REPLAY_COMMAND_GENERATE:
                event.set()

        monkeypatch.setattr(executor.transport, "send_command", publish_then_cancel)
        summary = executor.run()
        assert summary.attempt == 1 and not executor._generation_inflight
        executor.cancel_replay_child()
        assert executor.finish_generation()["mutation_ids"] == []
        executor.shutdown_replay(0.5)
        assert log_path.read_text().splitlines().count("cancel:1") == 1
    finally:
        stop_executor(executor)


def test_native_validation_rejects_without_case_or_channel_poison(
        tmp_path, monkeypatch, fake_script):
    executor, log_path = make_resident_executor(tmp_path, monkeypatch, fake_script)
    try:
        executor.start()
        assert executor.validate_replay_descriptor("x" * 4096, 0.5) is False
        assert executor.transport.request_id == 0  # rejected before any bytes
        assert executor.validate_replay_descriptor("invalid", 0.5) is False
        assert executor.validate_replay_descriptor("p0", 0.5) is True
        assert not executor.transport.poisoned
        executor.cancel_replay_child()  # validation is never cancellable
        executor.shutdown_replay(0.5)
        assert not any(row.startswith("resident:2:")
                       for row in log_path.read_text().splitlines())
    finally:
        stop_executor(executor)


@pytest.mark.parametrize("mode,error", [
    ("resident_wrong_id", RuntimeError),
    ("resident_case_timeout", TimeoutError),
])
def test_uncertain_case_poisons_channel_and_forbids_more_commands(
        tmp_path, monkeypatch, fake_script, mode, error):
    executor, _ = make_resident_executor(tmp_path, monkeypatch, fake_script, mode)
    try:
        executor.start()
        with pytest.raises(error):
            executor.request_replay_case(7, "p0", 0.05)
        assert executor.transport.poisoned
        request_id = executor.transport.request_id
        with pytest.raises(RuntimeError, match="poisoned"):
            executor.request_replay_case(8, "p0", 0.05)
        with pytest.raises(RuntimeError, match="poisoned"):
            executor.shutdown_replay(0.05)
        assert executor.transport.request_id == request_id
    finally:
        stop_executor(executor)


def test_cancel_tokens_are_scoped_idempotent_and_inactive_at_boundary():
    transport = binradar_runtime.ForkserverTransport({}, "protocol", True)
    transport.setup()
    try:
        transport.cancel_child()
        assert not select.select([transport.cancel_r], [], [], 0)[0]
        transport.send_command(binradar_runtime.REPLAY_COMMAND_CASE)
        callers = [threading.Thread(target=transport.cancel_child) for _ in range(8)]
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join(1)
        assert read_pipe(transport.cancel_r, 4) == struct.pack("<I", 1)
        assert not select.select([transport.cancel_r], [], [], 0)[0]
        transport.complete_request()
        transport.cancel_child()
        assert not select.select([transport.cancel_r], [], [], 0)[0]
        transport.send_command(binradar_runtime.REPLAY_COMMAND_GENERATE)
        transport.cancel_child()
        assert read_pipe(transport.cancel_r, 4) == struct.pack("<I", 2)
    finally:
        transport.cleanup()


def test_cancel_event_admission_and_registration_race(
        tmp_path, monkeypatch, fake_script):
    executor, log_path = make_resident_executor(
        tmp_path, monkeypatch, fake_script, "resident_case_cancel")
    event = threading.Event()
    try:
        executor.start()
        event.set()
        with pytest.raises(InterruptedError):
            executor.request_replay_case(7, "p0", 0.5, cancel_event=event)
        assert executor.transport.request_id == 0 and not executor.transport.poisoned
        event.clear()
        original = executor.transport.send_replay_case

        def publish_and_disconnect(mutation, descriptor):
            original(mutation, descriptor)
            event.set()

        monkeypatch.setattr(executor.transport, "send_replay_case", publish_and_disconnect)
        result = executor.request_replay_case(7, "p0", 0.5, cancel_event=event)
        assert result.outcome == binradar_runtime.ReplayOutcome.UNAVAILABLE
        assert result.reason == binradar_runtime.ReplayReason.CANCELLED
        assert not executor.transport.poisoned
        executor.cancel_replay_child()
        executor.shutdown_replay(0.5)
        assert log_path.read_text().splitlines().count("cancel:1") == 1
    finally:
        stop_executor(executor)


def test_resident_shutdown_ack_timeout_is_bounded_and_not_swallowed(
        tmp_path, monkeypatch, fake_script):
    executor, _ = make_resident_executor(
        tmp_path, monkeypatch, fake_script, "resident_stall_shutdown")
    try:
        executor.start()
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            executor.shutdown_replay(0.05)
        assert time.monotonic() - started < 0.5
        assert executor.transport.poisoned
    finally:
        stop_executor(executor)


def test_resident_transactions_are_serialized(tmp_path, monkeypatch, fake_script):
    executor, log_path = make_resident_executor(tmp_path, monkeypatch, fake_script)
    first_read, release = threading.Event(), threading.Event()
    errors = []
    results = []
    threads = []
    try:
        executor.start()
        original = executor.transport.read_ack

        def paused_ack(timeout):
            if executor.transport.request_id == 1:
                first_read.set()
                assert release.wait(2)
            return original(timeout)

        monkeypatch.setattr(executor.transport, "read_ack", paused_ack)

        def validate():
            try:
                results.append(executor.validate_replay_descriptor("p0", 0.5))
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=validate) for _ in range(2)]
        threads[0].start()
        assert first_read.wait(1)
        threads[1].start()
        # The first command owns the transaction until its reply is consumed.
        assert executor.transport.request_id == 1
        release.set()
        for thread in threads:
            thread.join(2)
            assert not thread.is_alive()
        assert not errors and results == [True, True]
        assert executor.transport.request_id == 2
        executor.shutdown_replay(0.5)
        rows = log_path.read_text().splitlines()
        assert rows[:4] == ["resident:5:1", "descriptor:p0",
                            "resident:5:2", "descriptor:p0"]
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join(2)
        stop_executor(executor)


def test_resident_shutdown_lock_wait_is_bounded(
        tmp_path, monkeypatch, fake_script):
    executor, _ = make_resident_executor(tmp_path, monkeypatch, fake_script)
    entered, release = threading.Event(), threading.Event()

    def own_channel():
        with executor._resident_lock:
            entered.set()
            release.wait(2)

    owner = threading.Thread(target=own_channel)
    try:
        executor.start()
        owner.start()
        assert entered.wait(1)
        with pytest.raises(TimeoutError, match="execution owner"):
            executor.shutdown_replay(0.01)
        assert executor.transport.request_id == 0
    finally:
        release.set()
        owner.join(2)
        stop_executor(executor)

