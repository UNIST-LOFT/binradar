"""Replay server request framing, admission and lifecycle boundaries.

Native protocol behavior is pinned by tests/test_binradar_forkserver_protocol.py
against the real tracer.  These tests cover the trusted host side: strict
request parsing, serialized admission, streaming rows, disconnect recovery and
the guarantee that an idle or broken parent never looks like a successful
batch.
"""

import json
import socket
from pathlib import Path

import pytest

from binradar import binradar_replay
from binradar import binradar_runtime


def request_bytes(payload) -> bytes:
    return json.dumps(payload).encode("utf-8") + b"\n"


def send(sock_path: Path, payload, timeout: float = 10.0):
    """Return every newline-delimited reply object for one request."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    connection.connect(str(sock_path))
    connection.sendall(request_bytes(payload))
    rows = []
    buffer = b""
    try:
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                row = json.loads(line)
                rows.append(row)
                if "done" in row or "error" in row or "accepted" in row:
                    return rows
    finally:
        connection.close()
    return rows


@pytest.mark.parametrize(
    "payload, message",
    [
        ({"op": "status", "extra": 1}, "unexpected request field"),
        ({"op": "unknown"}, "unknown op"),
        ({"op": "evaluate"}, "'patches' must be a non-empty array"),
        ({"op": "evaluate", "patches": []}, "non-empty array"),
        ({"op": "evaluate", "patches": [{"id": 0, "predicate": "rax"}]},
         "positive integer"),
        ({"op": "evaluate", "patches": [{"id": 1, "predicate": "rax"},
                                        {"id": 1, "predicate": "rbx"}]},
         "duplicate patch id"),
        ({"op": "evaluate", "patches": [{"id": 1, "predicate": "rax",
                                         "version": 1}]},
         "unexpected field"),
        ({"op": "evaluate", "patches": [{"id": 1, "predicate": ""}]},
         "non-empty string"),
    ],
)
def test_request_validation_rejects_before_any_native_work(payload, message):
    with pytest.raises(binradar_replay.ReplayProtocolError, match=message):
        binradar_replay.parse_request(request_bytes(payload).rstrip(b"\n"))


def test_request_accepts_sparse_ids_and_requires_no_metadata():
    parsed = binradar_replay.parse_request(json.dumps({
        "op": "evaluate",
        "patches": [{"id": 4, "predicate": "rax <= 0"},
                    {"id": 91, "predicate": "rax == 0"}],
    }).encode())
    patches = parsed["patches"]
    assert isinstance(patches, list)
    assert [patch.id for patch in patches] == [4, 91]


@pytest.mark.parametrize("family, predicate", [
    ("generic-erm", "rax <= 0"),
    ("generic-erm", "rsp > 4096"),
    ("CWE805-erm", "s->rax >= i->begin && s->rax < i->end"),
    ("CWE805-erm", "4 * ((uint32_t *)s->rsp)[2] < i->end - i->begin"),
])
def test_lower_predicate_uses_the_running_family_grammar(family, predicate):
    lowered = binradar_replay.lower_predicate(family, predicate)
    assert isinstance(lowered, str) and lowered


@pytest.mark.parametrize("family, predicate", [
    ("generic-erm", "rax >>>"),
    ("generic-erm", ""),
    ("CWE805-erm", "rax <= 0"),
])
def test_lower_predicate_rejects_malformed_source(family, predicate):
    with pytest.raises(ValueError):
        binradar_replay.lower_predicate(family, predicate)


class FakeTracer:
    """Minimal resident peer: records cases and returns scripted outcomes."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []
        self.cancelled = 0
        self.shut_down = False
        self.env = {"BINRADAR_FORKSERVER_CHILD_TIMEOUT": "5"}
        self.process = type("Process", (), {"poll": staticmethod(lambda: None)})()

    def request_replay_case(self, mutation, descriptor, timeout):
        self.requests.append((mutation, descriptor))
        outcome, reason, source = self.outcomes.pop(0)
        return binradar_runtime.ReplayCaseResult(
            mutation, source, outcome, reason, "{}")

    def cancel_replay_child(self):
        self.cancelled += 1

    def shutdown_replay(self, timeout=None):
        self.shut_down = True


def test_ready_status_reports_generation_stop_and_retention(tmp_path):
    server = binradar_replay.ReplayServer(str(tmp_path), "generic-erm", 0)
    server.start()
    try:
        with server._lock:
            server.update_generation(state="ready", generation_stop="exhausted",
                                     remaining_plans=0, retained_mutations=7)
            assert server._status() == {
                "state": "ready", "generation_stop": "exhausted",
                "remaining_plans": 0, "retained_mutations": 7}
    finally:
        server.close()


def test_evaluate_streams_case_rows_and_a_terminal_coverage_row(tmp_path):
    server = binradar_replay.ReplayServer(str(tmp_path), "generic-erm", 0)
    tracer = FakeTracer([
        (binradar_runtime.ReplayOutcome.NORMAL, binradar_runtime.ReplayReason.NONE, "executed"),
        (binradar_runtime.ReplayOutcome.TARGET_CRASH, binradar_runtime.ReplayReason.NONE, "executed"),
    ])
    server._tracer = tracer
    server._mutation_ids = [2, 3]
    with server._lock:
        server.update_generation(state="ready", generation_stop="exhausted",
                                 remaining_plans=0)
    server.start()
    try:
        rows = send(Path(server.path), {
            "op": "evaluate", "patches": [{"id": 5, "predicate": "rax <= 0"}]})
    finally:
        server.close()
    assert [row.get("patch") for row in rows if "patch" in row] == [5, 5]
    assert rows[-1] == {
        "done": True, "cases": 2, "unavailable": 0, "patches": 1,
        "mutations": 2, "coverage": "complete"}
    assert [row["mutation"] for row in rows if "mutation" in row] == [2, 3]


def test_non_ready_state_refuses_evaluation_without_running_a_case(tmp_path):
    server = binradar_replay.ReplayServer(str(tmp_path), "generic-erm", 0)
    tracer = FakeTracer([])
    server._tracer = tracer
    server.start()
    try:
        with server._lock:
            server.update_generation(state="generating")
        rows = send(Path(server.path), {
            "op": "evaluate", "patches": [{"id": 1, "predicate": "rax"}]})
    finally:
        server.close()
    assert "state generating cannot evaluate" in rows[0]["error"]
    assert tracer.requests == []


def test_zero_retained_mutations_is_explicit_zero_coverage(tmp_path):
    server = binradar_replay.ReplayServer(str(tmp_path), "generic-erm", 0)
    server._tracer = FakeTracer([])
    server._mutation_ids = []
    with server._lock:
        server.update_generation(state="ready", generation_stop="failure-limit",
                                 remaining_plans=3)
    server.start()
    try:
        rows = send(Path(server.path), {
            "op": "evaluate", "patches": [{"id": 1, "predicate": "rax"}]})
    finally:
        server.close()
    assert "no retained mutations" in rows[0]["error"]
    assert not any("done" in row for row in rows)


def test_malformed_batch_does_not_contaminate_the_next_request(tmp_path):
    server = binradar_replay.ReplayServer(str(tmp_path), "generic-erm", 0)
    tracer = FakeTracer([
        (binradar_runtime.ReplayOutcome.NORMAL, binradar_runtime.ReplayReason.NONE, "executed")])
    server._tracer = tracer
    server._mutation_ids = [2]
    with server._lock:
        server.update_generation(state="ready", generation_stop="exhausted",
                                 remaining_plans=0)
    server.start()
    try:
        bad = send(Path(server.path), {
            "op": "evaluate",
            "patches": [{"id": 1, "predicate": "rax >>>"}]})
        good = send(Path(server.path), {
            "op": "evaluate", "patches": [{"id": 1, "predicate": "1 == 1"}]})
    finally:
        server.close()
    assert "error" in bad[0]
    assert good[-1]["coverage"] == "complete"


def test_busy_evaluation_is_refused_instead_of_queued(tmp_path):
    server = binradar_replay.ReplayServer(str(tmp_path), "generic-erm", 0)
    tracer = FakeTracer([])
    server._tracer = tracer
    server._mutation_ids = [2]
    with server._lock:
        server.update_generation(state="evaluating")
    server.start()
    try:
        rows = send(Path(server.path), {
            "op": "evaluate", "patches": [{"id": 1, "predicate": "rax"}]})
    finally:
        server.close()
    assert rows[0]["error"] == "busy"


def test_shutdown_is_acknowledged_and_sets_the_service_flag(tmp_path):
    server = binradar_replay.ReplayServer(str(tmp_path), "generic-erm", 0)
    server.start()
    try:
        rows = send(Path(server.path), {"op": "shutdown"})
        assert server.shutdown_requested.is_set()
    finally:
        server.close()
    assert rows == [{"accepted": True}]


def test_existing_socket_endpoint_is_never_replaced(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    socket_path = run_dir / binradar_replay.SOCKET_NAME
    placeholder = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    placeholder.bind(str(socket_path))
    try:
        server = binradar_replay.ReplayServer(str(run_dir), "generic-erm", 0)
        with pytest.raises(RuntimeError, match="already exists"):
            server.start()
    finally:
        placeholder.close()


def test_overlong_socket_path_is_rejected_before_binding(tmp_path):
    deep = tmp_path / ("x" * 120)
    server = binradar_replay.ReplayServer(str(deep), "generic-erm", 0)
    with pytest.raises(ValueError, match="longer than"):
        server.start()


def test_unsupported_generation_family_is_rejected():
    with pytest.raises(ValueError, match="does not support generation family"):
        binradar_replay.parse_family("CWE805-direct")
