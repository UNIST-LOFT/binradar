"""Exercise the real solver with harmless bounded SysV transport records."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))
import binradar_runtime


@pytest.fixture(scope="module")
def collection_producer(tmp_path_factory):
    directory = tmp_path_factory.mktemp("collection-producer")
    source = directory / "producer.c"
    source.write_text(r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include "tracer/tcg/symbolic/symbolic-struct.h"

static void *attach(const char *name, size_t size)
{
    key_t key = strtoul(getenv(name), NULL, 16);
    int id;
    while ((id = shmget(key, size, 0600)) < 0) usleep(1000);
    void *value = shmat(id, NULL, 0);
    if (value == (void *)-1) _exit(3);
    return value;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    alarm(20);
    Expr *expressions = attach("EXPR_POOL_SHM_KEY",
                               sizeof(Expr) * EXPR_POOL_CAPACITY);
    Query *queries = attach("QUERY_SHM_KEY", sizeof(Query) * EXPR_QUERY_CAPACITY);
    while (__atomic_load_n(&queries[0].query, __ATOMIC_ACQUIRE) !=
           (void *)SHM_READY) usleep(1000);
    Expr *remote = (Expr *)EXPR_POOL_ADDR;
    expressions[0] = (Expr){.opkind = IS_SYMBOLIC,
        .op1 = EXPR_CONST_OP(0), .op2 = EXPR_CONST_OP(1),
        .op3 = EXPR_CONST_OP('A'), .op1_is_const = 1,
        .op2_is_const = 1, .op3_is_const = 1};
    expressions[1] = (Expr){.opkind = EQ, .op1 = remote,
        .op2 = EXPR_CONST_OP('A'), .op3 = EXPR_CONST_OP(1),
        .op2_is_const = 1, .op3_is_const = 1};
    queries[1] = (Query){.query = remote + 1, .address = 0x401000,
                         .args8 = {.arg0 = 1, .arg1 = 0}};
    Query terminal = {.query = FINAL_QUERY, .address = 2 * sizeof(Expr),
                       .args64 = SYMBOLIC_COLLECTION_COMPLETE};
    if (!strcmp(argv[1], "expr-capacity")) {
        terminal.query = FINAL_QUERY_CAPACITY;
        terminal.address = EXPR_POOL_CAPACITY * sizeof(Expr);
        terminal.args64 = SYMBOLIC_COLLECTION_EXPR_CAPACITY;
    } else if (!strcmp(argv[1], "invalid-reason")) {
        terminal.query = FINAL_QUERY_CAPACITY;
        terminal.args64 = 99;
    } else if (!strcmp(argv[1], "short-query-capacity")) {
        terminal.query = FINAL_QUERY_CAPACITY;
        terminal.args64 = SYMBOLIC_COLLECTION_QUERY_CAPACITY;
    } else if (!strcmp(argv[1], "invalid-expression")) {
        queries[1].query = remote + EXPR_POOL_CAPACITY;
    } else if (!strcmp(argv[1], "unknown")) {
        memset(&terminal, 0, sizeof(terminal));
    }
    queries[2] = terminal;
    if (!strcmp(argv[1], "unterminated")) {
        for (size_t i = 2; i < EXPR_QUERY_CAPACITY; ++i)
            queries[i] = queries[1];
    }
    __atomic_store_n(&queries[0].query, SHM_DONE, __ATOMIC_RELEASE);
    shmdt(expressions);
    shmdt(queries);
    return 0;
}
''', encoding="ascii")
    producer = directory / "producer"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-DNDEBUG", "-I", str(ROOT),
                    str(source), "-o", str(producer)], check=True,
                   capture_output=True)
    return producer


@pytest.mark.parametrize("mode,engine,boundary", [
    ("original", "smt", "expr-capacity"),
    ("reverse", "smt", "expr-capacity"),
    ("binradar", "smt", "expr-capacity"),
    ("original", "fuzzy", "expr-capacity"),
    ("original", "smt", "complete"),
    ("original", "smt", "unknown"),
    ("original", "smt", "invalid-reason"),
    ("original", "smt", "short-query-capacity"),
    ("original", "smt", "invalid-expression"),
    ("original", "smt", "unterminated"),
])
def test_solver_retains_only_bounded_prefix(
        tmp_path, collection_producer, mode, engine, boundary):
    binary = ROOT / "solver" / "build" / f"solver-{engine}"
    if not binary.is_file():
        pytest.skip("built solver required for transport integration")
    env = os.environ.copy()
    env.update({"BINRADAR_FORKSERVER_ENABLE": "0" if mode == "original" else "1",
                "BINRADAR_REVERSE_DIRECTED": "1" if mode == "reverse" else "0",
                "SOLVER_TIMEOUT": "30000"})
    env.pop("BINRADAR_QUERY_WINDOW_FILE", None)
    manager = binradar_runtime.SharedMemoryManager(env)
    manager.assign_random_keys()
    manager._assign_random_key("MUTATION_REQ_SHM_KEY")
    testcase = tmp_path / "input"
    testcase.write_bytes(b"A")
    output = tmp_path / "cases"
    output.mkdir()
    command = [str(binary), "-i", str(testcase), "-o", str(output)]
    for flag, name in (("-b", "branches"), ("-c", "context"), ("-m", "memory")):
        path = tmp_path / name
        path.write_bytes(b"")
        command.extend((flag, str(path)))
    process = None
    try:
        process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        subprocess.run([str(collection_producer), boundary], env=env,
                       check=True, timeout=25, capture_output=True)
        if mode != "original":
            import signal
            process.send_signal(signal.SIGUSR1)
        data, _ = process.communicate(timeout=45)
        log = data.decode(errors="replace")
        if boundary in {"invalid-reason", "short-query-capacity",
                        "invalid-expression", "unterminated"}:
            assert process.returncode != 0, log
            assert not list(output.glob("test_case_*.dat")), log
            assert "[processed-prefix]" not in log
        else:
            assert process.returncode == 0, log
            reason = "none" if boundary == "complete" else boundary
            assert f"[incomplete {int(boundary != 'complete')}] [reason {reason}]" in log
            cases = [path.read_bytes() for path in output.glob("test_case_*.dat")]
            assert cases and all(len(case) == 1 and case != b"A" for case in cases), log
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        manager.cleanup()
