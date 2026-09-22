"""Streaming phase coordination and concrete-worker construction."""

import os
import queue
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Optional

import binradar_fuzzer
import binradar_minimizer
import binradar_runtime
import binradar_verifier
import logger

OPTIONAL_EVIDENCE_PHASES = frozenset({
    "fuzzolic", "directed", "fuzzer", "binradar", "feedback",
})


@dataclass(frozen=True)
class Producer:
    name: str
    target: Callable[[], None]


@dataclass(frozen=True)
class IndependentWorker:
    name: str
    target: Callable[[], None]


@dataclass(frozen=True)
class PhaseFailure:
    name: str
    exception: BaseException
    traceback: Optional[TracebackType]
    producer: bool

    def reraise(self) -> None:
        if self.traceback is not None:
            raise self.exception.with_traceback(self.traceback)
        raise self.exception


class PipelineCoordinator:
    """Own the full/fuzzer-only streaming thread lifecycle."""

    def __init__(
            self, less_strict: bool,
            record_tolerated_failure: Callable[[str, BaseException], None],
            stream_concrete: Callable[..., object],
            registry: binradar_runtime.ProcessRegistry =
            binradar_runtime.PROCESS_REGISTRY,
            independent_join_timeout: float = 60.0,
            shutdown_join_timeout: float = 10.0):
        self.less_strict = less_strict
        self.record_tolerated_failure = record_tolerated_failure
        self.stream_concrete = stream_concrete
        self.registry = registry
        self.independent_join_timeout = independent_join_timeout
        self.shutdown_join_timeout = shutdown_join_timeout

    def run(
            self, producers: Sequence[Producer],
            independent: Optional[IndependentWorker] = None) -> None:
        failures: "queue.Queue[PhaseFailure]" = queue.Queue()
        producer_failures: "queue.Queue[BaseException]" = queue.Queue()

        def run_captured(
                name: str, target: Callable[[], None], producer: bool) -> None:
            try:
                target()
            except BaseException as exc:
                if self._tolerate(name, exc):
                    return
                failure = PhaseFailure(
                    name=name, exception=exc, traceback=exc.__traceback__,
                    producer=producer)
                failures.put(failure)
                if producer:
                    producer_failures.put(exc)
                logger.error(f"[{name}] failed: {exc}")

        independent_thread = None
        if independent is not None:
            independent_thread = threading.Thread(
                target=run_captured,
                args=(independent.name, independent.target, False),
                name=independent.name)
            independent_thread.start()

        producer_threads = [
            threading.Thread(
                target=run_captured,
                args=(producer.name, producer.target, True),
                name=producer.name)
            for producer in producers
        ]
        for thread in producer_threads:
            thread.start()

        try:
            self.stream_concrete(
                producer_threads=producer_threads,
                producer_exc_queue=producer_failures)
        except BaseException:
            self._cancel_and_join(producer_threads, independent_thread)
            raise

        for thread in producer_threads:
            thread.join()

        failure = self._next_failure(failures)
        if failure is not None:
            self._cancel_and_join([], independent_thread)
            failure.reraise()

        if independent_thread is not None:
            independent_thread.join(timeout=self.independent_join_timeout)
            if independent_thread.is_alive():
                logger.error(
                    f"[{independent_thread.name}] did not finish within "
                    f"{self.independent_join_timeout:g}s after concrete "
                    "stream completion; stopping registered processes")
                self.registry.stop_all()
                independent_thread.join(timeout=self.shutdown_join_timeout)
                if independent_thread.is_alive():
                    raise RuntimeError(
                        f"{independent_thread.name} worker did not stop after "
                        "process cleanup")

        failure = self._next_failure(failures)
        if failure is not None:
            failure.reraise()

    def _tolerate(self, name: str, exc: BaseException) -> bool:
        if (not self.less_strict
                or name not in OPTIONAL_EVIDENCE_PHASES
                or not isinstance(exc, Exception)):
            return False
        self.record_tolerated_failure(name, exc)
        return True

    @staticmethod
    def _next_failure(
            failures: "queue.Queue[PhaseFailure]") -> Optional[PhaseFailure]:
        try:
            return failures.get_nowait()
        except queue.Empty:
            return None

    def _cancel_and_join(
            self, producer_threads: Sequence[threading.Thread],
            independent_thread: Optional[threading.Thread]) -> None:
        self.registry.stop_all()
        for thread in producer_threads:
            thread.join(timeout=self.shutdown_join_timeout)
        if independent_thread is not None:
            independent_thread.join(timeout=self.shutdown_join_timeout)


@dataclass(frozen=True)
class ConcreteWorkerFactory:
    """One owner for concrete testcase discovery and worker construction."""

    workdir: str
    run_dir: str
    probe_result: Any
    config: dict[str, str]
    testcase_dirs: tuple[str, ...]
    patches: tuple[int, ...]
    verifier_binary: Optional[str]
    patched_binary_patches: tuple[int, ...]

    @classmethod
    def create(
            cls, workdir: str, run_dir: str, probe_result: Any,
            config: dict[str, str], fuzzer_outdir: str,
            patches: Sequence[int], verifier_binary: Optional[str],
            patched_binary_patches: Sequence[int]) -> "ConcreteWorkerFactory":
        testcase_dirs = [
            os.path.join(run_dir, "fuzzolic-tests"),
            os.path.join(run_dir, "directed-tests"),
        ]
        testcase_dirs.extend(
            binradar_fuzzer.AFLppFuzzer.testcase_dirs_for_outdir(
                fuzzer_outdir))
        for category in ("benign", "malicious"):
            inputs = os.path.join(workdir, "input", category)
            if os.path.exists(inputs):
                testcase_dirs.append(inputs)
        return cls(
            workdir=workdir,
            run_dir=run_dir,
            probe_result=probe_result,
            config=config,
            testcase_dirs=tuple(testcase_dirs),
            patches=tuple(patches),
            verifier_binary=verifier_binary,
            patched_binary_patches=tuple(patched_binary_patches),
        )

    @property
    def minimizer_result_file(self) -> str:
        return os.path.join(self.run_dir, "minimizer.sbsv")

    def build_minimizer(self) -> binradar_minimizer.BinRadarMinimizer:
        logger.info("TESTCASE_DIRS: " + ", ".join(self.testcase_dirs))
        return binradar_minimizer.BinRadarMinimizer(
            self.workdir, self.run_dir, self.probe_result,
            list(self.testcase_dirs), self.config)

    def build_verifier(
            self) -> binradar_verifier.BinRadarConcreteVerifier:
        if self.verifier_binary is None:
            raise RuntimeError("Concrete verifier artifact was not selected")
        runner = binradar_verifier.BinRadarQemuRunner.from_env(
            self.workdir, self.config)
        logger.info(f"[VERIFIER] Verifying {len(self.patches)} patch(es)")
        return binradar_verifier.BinRadarConcreteVerifier(
            self.workdir, self.run_dir, runner, self.probe_result,
            self.verifier_binary, list(self.patches),
            patched_binary_patches=list(self.patched_binary_patches))
