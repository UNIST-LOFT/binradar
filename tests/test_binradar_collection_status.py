"""Strict collection state and harmless subprocess capacity cutoff fixtures."""
import json
import sys

import pytest


from binradar import binradar_runtime as runtime


def status_row(complete=False, reason="expr-capacity"):
    return dict(version=1, complete=complete, reason=reason,
                queries=6 if reason == "query-capacity" else 2,
                expr_bytes=128, query_capacity=8, expr_capacity_bytes=128)


def test_collection_aggregation_retains_first_cutoff_and_unknown():
    unknown = runtime.CollectionStatus()
    complete = runtime.CollectionStatus(True, "none", 1, 32, 8, 128)
    query = runtime.CollectionStatus(False, "query-capacity", 6, 64, 8, 128)
    expr = runtime.CollectionStatus(False, "expr-capacity", 2, 128, 8, 128)
    assert runtime.aggregate_collection_status(None, complete) is complete
    assert runtime.aggregate_collection_status(unknown, complete) is unknown
    assert runtime.aggregate_collection_status(complete, unknown) is unknown
    assert runtime.aggregate_collection_status(unknown, query) is query
    assert runtime.aggregate_collection_status(query, expr) is query
    assert runtime.aggregate_collection_status(query, complete) is query
    assert runtime.aggregate_collection_status(query, unknown) is query


def test_missing_collection_state_is_unknown(tmp_path):
    status = runtime.read_collection_status(str(tmp_path / "missing"))
    assert status.complete is None
    assert status.reason == "unknown"
    assert "[collection-complete unknown]" in status.serialize()


@pytest.mark.parametrize("complete,reason", [
    (True, "none"), (False, "query-capacity"), (False, "expr-capacity")])
def test_valid_collection_status(tmp_path, complete, reason):
    path = tmp_path / "status.json"
    path.write_text(json.dumps(status_row(complete, reason)))
    status = runtime.read_collection_status(str(path))
    assert status.complete is complete and status.reason == reason
    assert status.queries == (6 if reason == "query-capacity" else 2)
    assert status.expr_bytes == 128
    assert status.capacity is (not complete)


@pytest.mark.parametrize("changes", [
    {"version": True}, {"version": 2}, {"complete": 1},
    {"complete": True}, {"reason": "none"}, {"reason": "invalid"},
    {"queries": True}, {"queries": -1}, {"queries": 7},
    {"expr_bytes": 129}, {"query_capacity": 1},
    {"expr_capacity_bytes": 0}, {"extra": 1}, {"expr_bytes": 1.5},
    {"reason": "query-capacity", "queries": 2}])
def test_malformed_collection_state_is_not_complete(tmp_path, changes):
    row = status_row()
    row.update(changes)
    path = tmp_path / "status.json"
    path.write_text(json.dumps(row))
    with pytest.raises(ValueError):
        runtime.read_collection_status(str(path))


@pytest.mark.parametrize("text", ['{}', '{', '{"version":1,"version":1}'])
def test_incomplete_or_duplicate_json_is_rejected(tmp_path, text):
    path = tmp_path / "status.json"
    path.write_text(text)
    with pytest.raises(ValueError):
        runtime.read_collection_status(str(path))


def test_ordinary_guest_signal_preserves_unknown_collection(tmp_path):
    executor = runtime.TracerExecutor(
        "fuzzolic", dict(__import__("os").environ), str(tmp_path), str(tmp_path),
        "unused", "", "unused", runtime.Deadline.from_timeout(5))
    executor.command = [sys.executable, "-c",
        "import os,resource,signal; "
        "resource.setrlimit(resource.RLIMIT_CORE,(0,0)); "
        "os.kill(os.getpid(),signal.SIGSEGV)"]
    try:
        executor.start()
        summary = executor.run()
        assert executor.run_result.exit_code == -11
        assert summary.success
        assert summary.collection.complete is None
        assert summary.collection.reason == "unknown"
        assert summary.attempt_result != runtime.AttemptResult.CAPACITY
    finally:
        executor.stop()


@pytest.mark.parametrize("exit_code", [0, 1])
def test_ordinary_capacity_separates_collection_and_execution(tmp_path, exit_code):
    env = dict(__import__("os").environ)
    executor = runtime.TracerExecutor(
        "fuzzolic", env, str(tmp_path), str(tmp_path), "unused", "", "unused",
        runtime.Deadline.from_timeout(5))
    code = ("import json,os,sys; "
            "json.dump(" + repr(status_row()) + ","
            "open(os.environ['SYMBOLIC_COLLECTION_STATUS_FILE'],'w')); "
            f"sys.exit({exit_code})")
    executor.command = [sys.executable, "-c", code]
    try:
        executor.start()
        summary = executor.run()
        assert summary.success is (exit_code == 0)
        assert summary.collection.complete is False
        assert summary.collection.reason == "expr-capacity"
        assert summary.attempt_result == runtime.AttemptResult.CAPACITY
    finally:
        executor.stop()
