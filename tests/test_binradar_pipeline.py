import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fuzzolic"))

import binradar_pipeline


class RecordingRegistry:
    def __init__(self):
        self.stop_calls = 0

    def stop_all(self):
        self.stop_calls += 1


def test_coordinator_streams_producers_and_joins_independent_worker():
    producer_started = threading.Event()
    release_producer = threading.Event()
    independent_done = threading.Event()
    events = []

    def producer():
        producer_started.set()
        assert release_producer.wait(timeout=2)
        events.append("producer-done")

    def independent():
        assert producer_started.wait(timeout=2)
        assert release_producer.wait(timeout=2)
        events.append("independent-done")
        independent_done.set()

    def stream_concrete(producer_threads, producer_exc_queue):
        assert producer_started.wait(timeout=2)
        assert len(producer_threads) == 1
        assert producer_threads[0].is_alive()
        assert producer_exc_queue.empty()
        events.append("streaming")
        release_producer.set()

    coordinator = binradar_pipeline.PipelineCoordinator(
        less_strict=False,
        record_tolerated_failure=lambda name, exc: None,
        stream_concrete=stream_concrete,
        registry=RecordingRegistry(),
    )

    coordinator.run(
        [binradar_pipeline.Producer("fuzzer", producer)],
        independent=binradar_pipeline.IndependentWorker(
            "binradar", independent))

    assert independent_done.is_set()
    assert events[0] == "streaming"
    assert set(events[1:]) == {"producer-done", "independent-done"}


def test_strict_producer_failure_invalidates_concrete_stream():
    registry = RecordingRegistry()
    failure = RuntimeError("producer failed")

    def producer():
        raise failure

    def stream_concrete(producer_threads, producer_exc_queue):
        for thread in producer_threads:
            thread.join()
        raise producer_exc_queue.get_nowait()

    coordinator = binradar_pipeline.PipelineCoordinator(
        less_strict=False,
        record_tolerated_failure=lambda name, exc: None,
        stream_concrete=stream_concrete,
        registry=registry,
    )

    with pytest.raises(RuntimeError, match="producer failed") as caught:
        coordinator.run([
            binradar_pipeline.Producer("fuzzer", producer),
        ])

    assert caught.value is failure
    assert registry.stop_calls == 1


def test_less_strict_producer_failure_is_recorded_not_streamed():
    recorded = []

    def producer():
        raise RuntimeError("optional failure")

    def stream_concrete(producer_threads, producer_exc_queue):
        for thread in producer_threads:
            thread.join()
        assert producer_exc_queue.empty()

    coordinator = binradar_pipeline.PipelineCoordinator(
        less_strict=True,
        record_tolerated_failure=lambda name, exc: recorded.append(
            (name, str(exc))),
        stream_concrete=stream_concrete,
        registry=RecordingRegistry(),
    )

    coordinator.run([
        binradar_pipeline.Producer("fuzzer", producer),
    ])

    assert recorded == [("fuzzer", "optional failure")]


def test_less_strict_never_tolerates_process_control_events():
    class ControlEvent(BaseException):
        pass

    registry = RecordingRegistry()
    recorded = []
    failure = ControlEvent("stop")

    def producer():
        raise failure

    def stream_concrete(producer_threads, producer_exc_queue):
        for thread in producer_threads:
            thread.join()
        raise producer_exc_queue.get_nowait()

    coordinator = binradar_pipeline.PipelineCoordinator(
        less_strict=True,
        record_tolerated_failure=lambda name, exc: recorded.append(name),
        stream_concrete=stream_concrete,
        registry=registry,
    )

    with pytest.raises(ControlEvent, match="stop") as caught:
        coordinator.run([
            binradar_pipeline.Producer("fuzzer", producer),
        ])

    assert caught.value is failure
    assert recorded == []
    assert registry.stop_calls == 1


def test_independent_failure_does_not_enter_producer_failure_queue():
    registry = RecordingRegistry()
    producer_done = threading.Event()

    def producer():
        producer_done.set()

    def independent():
        raise RuntimeError("binradar failed")

    def stream_concrete(producer_threads, producer_exc_queue):
        for thread in producer_threads:
            thread.join()
        assert producer_done.is_set()
        assert producer_exc_queue.empty()

    coordinator = binradar_pipeline.PipelineCoordinator(
        less_strict=False,
        record_tolerated_failure=lambda name, exc: None,
        stream_concrete=stream_concrete,
        registry=registry,
    )

    with pytest.raises(RuntimeError, match="binradar failed"):
        coordinator.run(
            [binradar_pipeline.Producer("fuzzer", producer)],
            independent=binradar_pipeline.IndependentWorker(
                "binradar", independent))

    assert registry.stop_calls == 1


def test_unjoined_independent_worker_blocks_successful_return():
    registry = RecordingRegistry()
    release = threading.Event()
    worker_thread = []

    def independent():
        worker_thread.append(threading.current_thread())
        release.wait(timeout=2)

    coordinator = binradar_pipeline.PipelineCoordinator(
        less_strict=False,
        record_tolerated_failure=lambda name, exc: None,
        stream_concrete=lambda **kwargs: None,
        registry=registry,
        independent_join_timeout=0.01,
        shutdown_join_timeout=0.01,
    )

    try:
        with pytest.raises(RuntimeError, match="did not stop"):
            coordinator.run(
                [], independent=binradar_pipeline.IndependentWorker(
                    "binradar", independent))
    finally:
        release.set()
        if worker_thread:
            worker_thread[0].join(timeout=2)

    assert registry.stop_calls == 1
