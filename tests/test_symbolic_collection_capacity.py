"""Real tracer cutoffs: harmless loops, physical capacities, no fault targets."""

import json
import os
import subprocess
from pathlib import Path

import pytest


from binradar import binradar_runtime
from binradar import paths


@pytest.fixture(scope="module")
def capacity_guest(tmp_path_factory):
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for capacity integration")
    work = tmp_path_factory.mktemp("collection-guest")
    source = work / "capacity.c"
    source.write_text(r'''
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

/* A synthetic, behavior-identical patch family. The records are produced by
 * the actual guest after the capacity loop, not injected by the driver. */
static void emit_patch(void)
{
    const char *fd_text = getenv("PATCH_FD");
    const char *key_text = getenv("BINRADAR_PATCH_SHM_KEY");
    if (fd_text == NULL || key_text == NULL) return;
    int shmid = shmget((key_t)strtoul(key_text, 0, 0), 8, 0600);
    if (shmid < 0) _exit(5);
    uint32_t *selector = shmat(shmid, 0, SHM_RDONLY);
    if (selector == (void *)-1) _exit(6);
    char row[80];
    int n = snprintf(row, sizeof(row), "[patch] [id %u] [br 1] [v %u]\n",
                     selector[0], selector[1]);
    if (write(atoi(fd_text), row, n) != n) _exit(7);
    shmdt(selector);
}

__attribute__((noinline)) void trace_entry(unsigned char input, char mode,
                                          unsigned long count)
{
    if (count == 0) count = 1;
    if (count > 12000000) count = 12000000;
    if (mode == 'q') {
        __asm__ volatile("1: cmp $65, %%rax; jne 2f; 2: dec %%rcx; jne 1b"
                         : "+a" (input), "+c" (count) : : "cc");
    } else if (mode == 'e') {
        /* Unary NOT allocates in generated TCG, without the visit cutoff. */
        unsigned long value = input;
        __asm__ volatile("cmp $65, %%rax; jne 2f; 2: "
                         "1: not %%rax; dec %%rcx; jne 1b"
                         : "+a" (value), "+c" (count) : : "cc");
    } else {
        /* Alternating widths allocate in the C extension helper. */
        unsigned long value = input;
        __asm__ volatile("1: movsbq %%al, %%rax; movzwq %%ax, %%rax; "
                         "dec %%rcx; jne 1b"
                         : "+a" (value), "+c" (count) : : "cc");
    }
}

__attribute__((noinline)) void after_collection(void)
{
    __asm__ volatile("" : : : "memory");
}

int main(int argc, char **argv)
{
    unsigned char input;
    if (argc != 5 && argc != 6) return 2;
    unsigned long count = strtoul(argv[3], 0, 10);
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0 || read(fd, &input, 1) != 1) return 3;
    close(fd);
    trace_entry(input, argv[2][0], count);
    after_collection();
    emit_patch();
    if (argc == 6) {
        /* A deliberate instruction trap, not an out-of-bounds access. */
        __asm__ volatile(".globl capacity_signal\ncapacity_signal: ud2");
    }
    fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "done", 4) != 4) return 4;
    close(fd);
    /* Keep unrelated libc atexit state out of the mutation fixture. */
    _exit(0);
}
''', encoding="ascii")
    guest = work / "capacity"
    subprocess.run([
        "cc", "-O2", "-g", "-fno-pie", "-no-pie", "-fno-builtin",
        "-fno-stack-protector", str(source), "-o", str(guest),
    ], check=True, capture_output=True)
    symbols = subprocess.run(["nm", str(guest)], check=True,
                             capture_output=True, text=True).stdout
    addresses = {line.split()[-1]: line.split()[0]
                 for line in symbols.splitlines() if len(line.split()) == 3}
    return guest, addresses


def collection_environment(tmp_path):
    testcase = tmp_path / "input"
    testcase.write_bytes(b"A")
    return {
        "PATH": os.environ["PATH"],
        "NO_EXTERNAL_SOLVER": "1",
        "BINRADAR_FORKSERVER_ENABLE": "0",
        "BINRADAR_OSPREY_ENABLE": "0",
        "BINRADAR_MEMCHECK_ENABLE": "0",
        "BINRADAR_TRACE_FILE": "none",
        "BINRADAR_TRACER_LOG_FILE": str(tmp_path / "tracer.log"),
        "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE",
        "SYMBOLIC_TESTCASE_NAME": str(testcase),
        "SYMBOLIC_COLLECTION_STATUS_FILE": str(tmp_path / "collection.json"),
    }


@pytest.mark.parametrize("mode,count,reason", [
    ("q", 12000000, "query-capacity"),
    ("e", 8388620, "expr-capacity"),
    ("h", 4194320, "expr-capacity"),
    ("q", 32, "none"),
])
def test_real_collection_capacity(tmp_path, capacity_guest, mode, count, reason):
    guest, _ = capacity_guest
    env = collection_environment(tmp_path)
    marker = tmp_path / "completed"
    result = subprocess.run([
        paths.TRACER_BIN, "-symbolic", "-d", "page", str(guest),
        env["SYMBOLIC_TESTCASE_NAME"], mode, str(count), str(marker),
    ], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=180, check=False)
    log = (tmp_path / "tracer.log").read_text()
    assert result.returncode == 0, log
    status = json.loads(Path(env["SYMBOLIC_COLLECTION_STATUS_FILE"]).read_text())
    assert status["reason"] == reason
    assert status["complete"] is (reason == "none")
    assert 0 <= status["queries"] <= status["query_capacity"] - 2
    assert 0 <= status["expr_bytes"] <= status["expr_capacity_bytes"]
    if reason == "none":
        assert marker.read_bytes() == b"done"
    else:
        assert not marker.exists(), "capacity stop must not resume the guest"
        assert "[snapshot] [exit] [normal]" not in log
        assert "[snapshot] [crash]" not in log
        if reason == "query-capacity":
            assert status["queries"] == status["query_capacity"] - 2
        else:
            assert status["expr_bytes"] == status["expr_capacity_bytes"]


@pytest.mark.parametrize("symbolic", [False, True], ids=["memcheck", "symbolic"])
@pytest.mark.parametrize("metadata", ["missing", "directory", "empty-file", "unset", "empty-path"])
def test_model_metadata_startup(tmp_path, capacity_guest, symbolic, metadata):
    guest, _ = capacity_guest
    env = collection_environment(tmp_path)
    env["BINRADAR_MEMCHECK_ENABLE"] = "1"
    model_file = tmp_path / "models.plt"
    if metadata == "directory":
        model_file.mkdir()
    elif metadata == "empty-file":
        model_file.write_text("")
    if metadata != "unset":
        env["PLT_INFO_FILE"] = "" if metadata == "empty-path" else str(model_file)
    marker = tmp_path / "completed"
    command = [paths.TRACER_BIN]
    if symbolic:
        command.append("-symbolic")
    result = subprocess.run(
        command + [str(guest), env["SYMBOLIC_TESTCASE_NAME"], "q", "1", str(marker)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)
    if metadata in ("missing", "directory"):
        assert result.returncode != 0
        assert not marker.exists(), "unreadable model metadata must stop before guest execution"
        log = (tmp_path / "tracer.log").read_text() if (tmp_path / "tracer.log").exists() else ""
        assert "[snapshot] [exit] [normal]" not in log
        assert "[snapshot] [crash]" not in log
    else:
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert marker.read_bytes() == b"done"


@pytest.mark.parametrize("entry", ["trace_entry", "after_collection"])
def test_capacity_before_and_after_forkserver_banner(
        tmp_path, capacity_guest, entry):
    guest, addresses = capacity_guest
    env = collection_environment(tmp_path)
    env.update({
        "BINRADAR_FORKSERVER_ENABLE": "1",
        "BINRADAR_ENTRYPOINT": addresses[entry],
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "120",
    })
    marker = tmp_path / "completed"
    executor = binradar_runtime.TracerExecutor(
        "directed", env, str(tmp_path), str(tmp_path), str(guest),
        f"@@ q 12000000 {marker}", env["SYMBOLIC_TESTCASE_NAME"],
        binradar_runtime.Deadline.from_timeout(180))
    try:
        executor.start()
        summary = executor.run()
        assert summary.success
        assert summary.attempt_result == binradar_runtime.AttemptResult.CAPACITY
        assert summary.stop_reason == binradar_runtime.StopReason.CAPACITY
        assert not marker.exists()
        status = json.loads(Path(env["SYMBOLIC_COLLECTION_STATUS_FILE"]).read_text())
        assert status["complete"] is False
        assert status["reason"] == "query-capacity"
        assert status["queries"] == status["query_capacity"] - 2
    finally:
        executor.stop()


@pytest.mark.parametrize("entry,mode,count,reason,outcome", [
    ("trace_entry", "q", 12000000, "query-capacity", "normal"),
    ("trace_entry", "e", 8388620, "expr-capacity", "normal"),
    ("trace_entry", "h", 4194320, "expr-capacity", "normal"),
    ("after_collection", "e", 8388620, "expr-capacity", "normal"),
    ("trace_entry", "e", 8388620, "expr-capacity", "crash"),
])
def test_binradar_keeps_guest_outcomes_after_symbolic_capacity(
        tmp_path, capacity_guest, entry, mode, count, reason, outcome):
    from binradar import binradar_evidence

    guest, addresses = capacity_guest
    env = collection_environment(tmp_path)
    evidence = tmp_path / "binradar.br"
    env.update({
        "BINRADAR_FORKSERVER_ENABLE": "1",
        "BINRADAR_ENTRYPOINT": addresses[entry],
        "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "60",
        "BINRADAR_FORKSERVER_ITERATION_TIMEOUT": "120",
        "BINRADAR_MEMCHECK_ENABLE": "1",
        "BINRADAR_MEMCHECK_POLICY": "coverage-v7",
        "BINRADAR_OSPREY_ENABLE": "1",
        "BINRADAR_PATCH_CNT": "2",
        "BINRADAR_EVIDENCE_FILE": str(evidence),
        "PATCH_ID": "123456",
    })
    marker = tmp_path / "completed"
    with binradar_runtime.PhaseSession("binradar", 240) as session:
        session.shared_memory(env, include_patch_key=True)
        tracer = session.start_tracer(
            mode="binradar", env=env, workdir=str(tmp_path),
            rundir=str(tmp_path), binary=str(guest),
            test_cmd=f"@@ {mode} {count} {marker}" + (
                " signal" if outcome == "crash" else ""),
            testcase=env["SYMBOLIC_TESTCASE_NAME"])
        baseline = tracer.run()
        assert baseline.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        assert baseline.collection.complete is False
        assert baseline.collection.reason == reason
        if outcome == "normal":
            assert marker.read_bytes() == b"done"
        else:
            assert not marker.exists()
        frames = list(binradar_evidence.read_binradar(evidence))
        assert [(frame.iteration, tuple(group.outcome for group in frame.groups))
                for frame in frames] == [(1, (outcome,))]
        assert frames[0].groups[0].members == [0]
        assert frames[0].groups[0].branches == [1]
        if outcome == "crash":
            assert frames[0].groups[0].source == "guest-signal"
            assert frames[0].groups[0].fault_addr == int(addresses["capacity_signal"], 16)
        if entry == "trace_entry" and outcome == "normal":
            # A baseline cutoff must not poison the parent's snapshot or stop
            # a later full patch sweep. All candidates really execute here.
            assert baseline.remaining_plans > 0
            marker.unlink()
            following = tracer.run()
            assert following.attempt == 2
            assert following.attempt_result == binradar_runtime.AttemptResult.COMPLETED
            assert following.representative_runs == 3
            assert marker.read_bytes() == b"done"
            frames = list(binradar_evidence.read_binradar(evidence))
            assert [frame.iteration for frame in frames] == [1, 2]
            assert {member for group in frames[1].groups for member in group.members} == {0, 1, 2}
            assert all(group.outcome == "normal" and group.branches == [1]
                       for group in frames[1].groups)
