"""Real native observation broker and resident capture gates (no E9/provider needed)."""
import json
import os
import struct
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from binradar import binradar_runtime, paths


BINDING = {"schema_version": 1, "count": 1,
           "plan_sha256": "a" * 64, "plan_crc32": 1234}

# This harmless freestanding guest has one real program read of a mutable global.
# Its instrumented branch is exactly the descriptor o0. Captured bytes come only
# from the real kernel-mediated pipe copy; no synthetic observation value is used.
GUEST = r'''
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
typedef unsigned long word;
volatile word observed_value;
static int channel[2], other[2];
static long patch_fd, capture_fd;
static volatile unsigned *selector;
static int mode;
extern long brobs_probe_syscall(long, long, long, long);
extern void replay_entry(void);
__asm__(".text\n.globl brobs_probe_syscall, probe_instruction\n"
        "brobs_probe_syscall:\nmov %rdi,%rax\nmov %rsi,%rdi\n"
        "mov %rdx,%rsi\nmov %rcx,%rdx\n"
        ".byte 0x0f,0x1f,0x84,0,0x42,0x52,0x4f,0x42\n"
        "probe_instruction:\nsyscall\nret\n");
static long raw(long nr, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}
static word number(char **environment, const char *name) {
    for (; *environment; ++environment) {
        const char *p = *environment, *n = name;
        while (*n && *p == *n) { ++p; ++n; }
        if (*n || *p++ != '=') continue;
        word value = 0, base = 10;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
        for (;; ++p) {
            unsigned digit = *p >= '0' && *p <= '9' ? *p - '0' :
                *p >= 'a' && *p <= 'f' ? *p - 'a' + 10 :
                *p >= 'A' && *p <= 'F' ? *p - 'A' + 10 : 16;
            if (digit >= base) break;
            value = value * base + digit;
        }
        return value;
    }
    return 0;
}
static void finish(int code) { raw(60, code, 0, 0); __builtin_unreachable(); }
void prepare(char **environment) {
    patch_fd = number(environment, "PATCH_FD");
    capture_fd = number(environment, "PATCH_CACHED_FD");
    mode = number(environment, "TEST_BROBS_MODE");
    long id = raw(29, number(environment, "BINRADAR_PATCH_SHM_KEY"), 1, 0);
    long mapping = id < 0 ? -1 : raw(30, id, 0, 4096);
    if (mapping < 0 || patch_fd < 3 || capture_fd < 3) finish(91);
    selector = (void *)mapping;
    if (brobs_probe_syscall(293, (long)channel, O_NONBLOCK | O_CLOEXEC, 0)) finish(92);
    if (raw(293, (long)other, O_NONBLOCK | O_CLOEXEC, 0)) finish(93);
    replay_entry();
    finish(94);
}
struct capture {
    uint32_t magic, version, patch_id, branch;
    uint64_t stack_size, flags;
    uint32_t count, crc;
    uint64_t regs[16];
    unsigned char status[8];
    uint64_t value;
};
_Static_assert(sizeof(struct capture) == 184, "BRCHv3 fixture ABI");
__attribute__((noinline)) void replay_entry(void) {
    /* The ordinary program read preserves the existing primitive mutation lane. */
    volatile word mutation_source = observed_value;
    (void)mutation_source;
    if (mode == 8) raw(39, 0, 0, 0); /* Unrelated getpid never gains a capability. */
    struct stat st;
    if (brobs_probe_syscall(5, channel[0], (long)&st, 0) ||
        brobs_probe_syscall(72, channel[0], F_GETFD, 0) != FD_CLOEXEC ||
        brobs_probe_syscall(72, channel[1], F_GETFL, 0) != (O_WRONLY | O_NONBLOCK)) finish(95);
    word stale;
    if (brobs_probe_syscall(0, channel[0], (long)&stale, 8) != -11) finish(100);
    int fd = channel[1];
    long len = 8;
    const void *source = (const void *)&observed_value;
    if (mode == 1) fd = other[1];
    if (mode == 2) {
        if (raw(3, fd, 0, 0) || raw(33, other[1], fd, 0) != fd) finish(96);
    }
    if (mode == 4) len = 9;
    if (mode == 5) source = (const void *)0x700000000000UL;
    long written = mode == 3 ? raw(1, fd, (long)source, len) :
        brobs_probe_syscall(1, fd, (long)source, len);
    if (mode == 7 && selector[0] && ((volatile char *)selector)[16] == 'o') {
        const char pending[] = "brobs pending scalar\n";
        raw(1, 2, (long)pending, sizeof(pending) - 1);
        for (;;) __asm__ volatile("" ::: "memory");
    }
    struct capture record = {.magic = 0x48435242, .version = 3,
        .patch_id = selector[0], .flags = 8, .count = 1, .crc = 1234};
    if (written == 8 && mode != 1 && mode != 2) {
        if (brobs_probe_syscall(0, channel[0], (long)&record.value, 8) != 8) finish(97);
    } else {
        record.status[0] = 2;
    }
    record.branch = record.patch_id && ((volatile char *)selector)[16] == 'o'
        ? (record.status[0] ? 2 : record.value != 0) : 0;
    char row[] = "[patch] [id 0] [br 0] [v 0]\n";
    if (record.patch_id > 9 || selector[1] > 9) finish(98);
    row[12] += record.patch_id; row[19] += record.branch; row[25] += selector[1];
    if (raw(1, patch_fd, (long)row, sizeof(row) - 1) != sizeof(row) - 1 ||
        raw(1, capture_fd, (long)&record, sizeof(record)) != sizeof(record)) finish(99);
    if (mode == 6 && brobs_probe_syscall(1, channel[1], (long)&observed_value, 8) != 8)
        finish(101); /* Deliberately leave a scalar for the parent lifecycle drain. */
    finish(0);
}
__asm__(".text\n.globl _start\n_start:\nmov (%rsp),%rdi\n"
        "lea 16(%rsp,%rdi,8),%rdi\ncall prepare\nud2\n"
        ".section .note.GNU-stack,\"\",@progbits\n");
'''


@pytest.fixture
def observation_native(tmp_path):
    if not Path(paths.TRACER_BIN).is_file():
        pytest.skip("built tracer required for observation replay integration")
    source = tmp_path / "observation.c"
    source.write_text(GUEST, encoding="ascii")
    guest = tmp_path / "observation"
    subprocess.run(["cc", "-nostdlib", "-static", "-no-pie", "-fno-stack-protector",
                    "-fno-builtin", "-O0", "-o", str(guest), str(source)],
                   check=True, capture_output=True, timeout=20)
    result = subprocess.run(["nm", str(guest)], check=True, capture_output=True,
                            text=True, timeout=10)
    symbols = {row.split()[-1]: int(row.split()[0], 16)
               for row in result.stdout.splitlines() if len(row.split()) == 3}

    @contextmanager
    def run(mode=0, *, manifest_binding=None, manifest_version=2):
        manifest = tmp_path / "brpatches.json"
        manifest.write_text(json.dumps({"version": manifest_version,
            "kind": "generic-erm", "predicates": [],
            "observation": BINDING if manifest_binding is None else manifest_binding}),
            encoding="ascii")
        feedback = tmp_path / "feedback"
        feedback.mkdir(exist_ok=True)
        log = tmp_path / "tracer.log"
        pc = symbols["probe_instruction"]
        env = {
            "PATH": os.environ["PATH"], "NO_EXTERNAL_SOLVER": "1",
            "BINRADAR_FORKSERVER_ENABLE": "1",
            "BINRADAR_ENTRYPOINT": f"{symbols['replay_entry']:x}",
            "BINRADAR_FORKSERVER_CHILD_TIMEOUT": "2", "BINRADAR_OSPREY_ENABLE": "0",
            "BINRADAR_MEMCHECK_ENABLE": "1", "BINRADAR_MEMCHECK_POLICY": "coverage-v7",
            "BINRADAR_TRACE_FILE": "none", "BINRADAR_TRACER_LOG_FILE": str(log),
            "SYMBOLIC_INJECT_INPUT_MODE": "FROM_FILE", "SYMBOLIC_TESTCASE_NAME": "/dev/null",
            "BINRADAR_PATCH_CNT": "0", "BINRADAR_PATCH_CACHE_ENABLE": "1",
            "BINRADAR_PATCH_MANIFEST": str(manifest),
            "BINRADAR_EVIDENCE_FILE": str(tmp_path / "binradar.br"),
            "BINRADAR_FEEDBACK_DIR": str(feedback),
            "BINRADAR_REPLAY_SERVER": "1", "BINRADAR_REPLAY_DIR": str(tmp_path / "replay"),
            "BRCACHE_STACK_SIZE": "0", "TEST_BROBS_MODE": str(mode),
            # Trusted test supervisor binds this exact readonly text instruction.
            "E9_EXCLUDE_RANGES": f"0x{pc - 8:x}-0x{pc + 3:x}",
            "BINRADAR_BROBS_PC": f"{pc:x}", "BINRADAR_BROBS_COUNT": "1",
            "BINRADAR_BROBS_CRC32": "1234", "BINRADAR_BROBS_SHA256": "a" * 64,
        }
        with binradar_runtime.PhaseSession("binradar", 20) as session:
            session.shared_memory(env, include_patch_key=True)
            executor = session.start_tracer(mode="binradar", env=env,
                workdir=str(tmp_path), rundir=str(tmp_path), binary=str(guest),
                test_cmd="", testcase="/dev/null", replay_mode=True)
            yield executor, log, feedback
    return run


def test_real_observation_channel_preserves_resident_capture(observation_native):
    with observation_native() as (executor, log, feedback):
        assert executor.validate_replay_descriptor("AV0=o0p0", 5)
        assert not executor.validate_replay_descriptor("Op1o1", 5)
        assert not executor.validate_replay_descriptor("OV0V64", 5)
        summary = executor.run()
        assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        assert "[unsupported-syscall]" not in log.read_text()
        assert "[analyze] [crash]" not in log.read_text()
        # Keep generating only until a real ordinary global mutation is retained.
        for _ in range(4):
            if summary.retained_mutations or summary.terminal:
                break
            summary = executor.run()
        info = executor.finish_generation()
        assert info["mutation_ids"], log.read_text()
        replay = executor.request_replay_case(info["mutation_ids"][0], "o0", 5)
        # A harmless normal guest has no immutable target-crash oracle. Native
        # admission still checks its descriptor against actual captured bytes.
        assert replay.reason != binradar_runtime.ReplayReason.UNSUPPORTED_EXTERNAL_STATE
        assert replay.reason != binradar_runtime.ReplayReason.PREDICATE_TRAP
        assert "[unsupported-syscall]" not in log.read_text()
        captures = list(feedback.rglob("*.brch"))
        assert captures, log.read_text()
        for capture in captures:
            data = capture.read_bytes()
            assert len(data) % 184 == 0
            for offset in range(0, len(data), 184):
                header = struct.unpack_from("<IIIIQQII", data, offset)
                assert header[0:2] == (0x48435242, 3)
                assert header[5:] == (8, 1, 1234)
                assert data[offset + 168:offset + 176] == bytes(8)
        executor.shutdown_replay()


@pytest.mark.parametrize("mode", [1, 2, 3, 4],
                         ids=["forged-fd", "reused-fd", "non-thunk", "bad-length"])
def test_real_observation_channel_rejects_noncapability_operations(observation_native, mode):
    with observation_native(mode) as (executor, log, _):
        summary = executor.run()
        assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        text = log.read_text()
        assert "[unsupported-syscall] [nr 1]" in text, text
        executor.finish_generation()
        executor.shutdown_replay()


def test_real_observation_channel_does_not_admit_unrelated_syscalls(observation_native):
    with observation_native(8) as (executor, log, _):
        summary = executor.run()
        for _ in range(4):
            if summary.retained_mutations or summary.terminal:
                break
            summary = executor.run()
        info = executor.finish_generation()
        assert info["mutation_ids"], log.read_text()
        result = executor.request_replay_case(info["mutation_ids"][0], "o0", 5)
        assert result.outcome == binradar_runtime.ReplayOutcome.IGNORED
        assert result.reason == binradar_runtime.ReplayReason.UNSUPPORTED_EXTERNAL_STATE
        assert result.capture is None
        assert "[unsupported-syscall] [nr 39]" in log.read_text()
        executor.shutdown_replay()


def test_real_observation_probe_unmapped_is_unavailable_not_crash(observation_native):
    with observation_native(5) as (executor, log, _):
        summary = executor.run()
        assert summary.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        text = log.read_text()
        assert "[unsupported-syscall]" not in text, text
        assert "[analyze] [crash]" not in text, text
        for _ in range(4):
            if summary.retained_mutations or summary.terminal:
                break
            summary = executor.run()
        info = executor.finish_generation()
        assert info["mutation_ids"], log.read_text()
        result = executor.request_replay_case(info["mutation_ids"][0], "o0", 5)
        assert result.outcome == binradar_runtime.ReplayOutcome.UNAVAILABLE
        assert result.reason == binradar_runtime.ReplayReason.PREDICATE_TRAP
        assert result.capture is None
        assert "[unsupported-syscall]" not in log.read_text()
        executor.shutdown_replay()


def test_real_private_pipe_drains_between_sequential_children(observation_native):
    with observation_native(6) as (executor, log, _):
        first = executor.run()
        assert first.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        assert not first.terminal, log.read_text()
        second = executor.run()
        assert second.attempt_result == binradar_runtime.AttemptResult.COMPLETED
        text = log.read_text()
        assert "[unsupported-syscall]" not in text, text
        assert "[exit 100]" not in text, text
        assert "[exit 101]" not in text, text
        executor.finish_generation()
        executor.shutdown_replay()


def test_real_cancelled_scalar_never_leaks_into_next_replay_child(observation_native):
    with observation_native(7) as (executor, log, _):
        summary = executor.run()
        for _ in range(4):
            if summary.retained_mutations or summary.terminal:
                break
            summary = executor.run()
        info = executor.finish_generation()
        assert info["mutation_ids"], log.read_text()
        mutation = info["mutation_ids"][0]
        cancel = threading.Event()
        results, errors = [], []

        def request():
            try:
                results.append(executor.request_replay_case(mutation, "o0", 5,
                                                            cancel_event=cancel))
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=request)
        worker.start()
        deadline = time.monotonic() + 1.5
        try:
            while time.monotonic() < deadline:
                if "brobs pending scalar" in Path(executor.stderr_path).read_text():
                    break
                time.sleep(0.01)
            else:
                pytest.fail("real child never reached pending observation scalar")
        finally:
            cancel.set()
            # cancel_event covers admission/registration races only. Once the
            # child is running, its caller must emit the scoped native token.
            executor.cancel_replay_child()
            worker.join(timeout=5)
        assert not worker.is_alive() and not errors, errors
        assert len(results) == 1
        assert results[0].reason == binradar_runtime.ReplayReason.CANCELLED
        assert results[0].capture is None
        # p0 does not enter the fixture's deliberate pending-scalar loop. The
        # next child asserts an actual EAGAIN before its new observation write.
        following = executor.request_replay_case(mutation, "p0", 5)
        assert following.reason not in (binradar_runtime.ReplayReason.TIMEOUT,
                                        binradar_runtime.ReplayReason.UNSUPPORTED_EXTERNAL_STATE)
        text = log.read_text()
        assert "[exit 100]" not in text and "[unsupported-syscall]" not in text, text
        executor.shutdown_replay()


@pytest.mark.parametrize("mismatch", ["version", "count", "crc", "sha"])
def test_real_native_manifest_rejects_old_or_unbound_plan(observation_native, mismatch):
    binding = dict(BINDING)
    version = 1 if mismatch == "version" else 2
    if mismatch == "count":
        binding["count"] = 2
    elif mismatch == "crc":
        binding["plan_crc32"] += 1
    elif mismatch == "sha":
        binding["plan_sha256"] = "b" * 64
    with pytest.raises((EOFError, RuntimeError)):
        with observation_native(manifest_binding=binding, manifest_version=version):
            pytest.fail("native startup admitted an unbound manifest")
