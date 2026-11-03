"""Local replay service for a resident BinRadar generation snapshot.

The orchestrator owns one Unix-domain stream socket at ``<rundir>/replay.sock``.
Requests are newline-delimited JSON, one per connection:

    {"op":"status"}
    {"op":"evaluate","patches":[{"id":1,"predicate":"rax <= 0"}]}
    {"op":"shutdown"}

A patch entry carries exactly ``id`` and ``predicate``.  There is deliberately
no protocol version, hash, digest, manifest or session token: the endpoint
already selects the resident run, and the native tracer performs the
authoritative parsing and lowering of the running family's grammar.  The
service maps caller IDs to request-local work and never lets a caller ID become
a native index.

Guest execution stays in the existing tracer/solver runtime.  This module only
frames requests, serializes evaluation admission, streams case rows from the
native parent and keeps a synchronized, host-owned progress view for status.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import threading
from collections.abc import Iterable
from dataclasses import dataclass

from . import binradar_runtime
from . import binradar_taosc_predicates
from . import logger

SOCKET_NAME = "replay.sock"
# A Unix socket path is bounded by sockaddr_un.sun_path, which is 108 bytes on
# Linux including the terminating NUL.
MAX_SOCKET_PATH = 107
MAX_REQUEST_BYTES = 1 << 20
MAX_PATCHES = 65536
MAX_IDENTIFIER = 2 ** 63 - 1
SOCKET_BACKLOG = 8
CLIENT_READ_TIMEOUT = 30.0
# The longest native case reply text is a short diagnostic; the descriptor
# bound is enforced natively.
MAX_STATES = ("starting", "generating", "ready", "evaluating", "stopping")


class ReplayProtocolError(ValueError):
    """A client request the service refuses without touching tracer state."""


@dataclass(frozen=True)
class Patch:
    id: int
    predicate: str


@dataclass
class GenerationProgress:
    """Synchronized host-owned view; status never waits for the native pipe."""

    state: str = "starting"
    generation_stop: str | None = None
    remaining_plans: int | None = None
    retained_mutations: int = 0
    error: str | None = None

    def snapshot(self) -> dict[str, object]:
        return {
            "state": self.state,
            "generation_stop": self.generation_stop,
            "remaining_plans": self.remaining_plans,
            "retained_mutations": self.retained_mutations,
        }


@dataclass(frozen=True)
class CaseRow:
    patch_id: int
    mutation: int
    source: str
    outcome: str
    reason: str


@dataclass
class _Evaluation:
    patches: list[Patch]
    # Set by the serving thread when the client disconnects.
    cancelled: bool = False


@dataclass
class _CaseFailure:
    mutation: int
    reason: str


def parse_request(data: bytes) -> dict[str, object]:
    """Parse exactly one request object, rejecting unknown/malformed fields."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReplayProtocolError("request is not valid UTF-8") from exc
    if not text.strip():
        raise ReplayProtocolError("empty request")
    try:
        request = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReplayProtocolError(f"malformed JSON: {exc}") from exc
    if not isinstance(request, dict):
        raise ReplayProtocolError("request must be a JSON object")
    op = request.get("op")
    if not isinstance(op, str):
        raise ReplayProtocolError("request field 'op' must be a string")
    if op == "status":
        _reject_extra_keys(request, {"op"})
        return {"op": "status"}
    if op == "shutdown":
        _reject_extra_keys(request, {"op"})
        return {"op": "shutdown"}
    if op == "evaluate":
        _reject_extra_keys(request, {"op", "patches"})
        return {"op": "evaluate", "patches": parse_patches(request.get("patches"))}
    raise ReplayProtocolError(f"unknown op {op!r}")


def _reject_extra_keys(request: dict[str, object], allowed: set) -> None:
    extra = set(request) - allowed
    if extra:
        raise ReplayProtocolError(
            f"unexpected request field(s): {', '.join(sorted(extra))}")


def parse_patches(value: object) -> list[Patch]:
    """Validate the whole batch before any candidate is admitted."""
    if not isinstance(value, list) or not value:
        raise ReplayProtocolError("'patches' must be a non-empty array")
    if len(value) > MAX_PATCHES:
        raise ReplayProtocolError(
            f"'patches' carries more than {MAX_PATCHES} entries")
    patches: list[Patch] = []
    seen = set()
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise ReplayProtocolError(f"patch {index} must be an object")
        extra = set(entry) - {"id", "predicate"}
        if extra:
            raise ReplayProtocolError(
                f"patch {index} has unexpected field(s): "
                f"{', '.join(sorted(extra))}")
        identifier = entry.get("id")
        predicate = entry.get("predicate")
        if not isinstance(identifier, int) or isinstance(identifier, bool) or \
                not 1 <= identifier <= MAX_IDENTIFIER:
            raise ReplayProtocolError(
                f"patch {index} id must be a positive integer")
        if identifier in seen:
            raise ReplayProtocolError(f"duplicate patch id {identifier}")
        if not isinstance(predicate, str) or not predicate.strip():
            raise ReplayProtocolError(
                f"patch {identifier} predicate must be a non-empty string")
        seen.add(identifier)
        patches.append(Patch(identifier, predicate))
    return patches


def lower_predicate(family: str, predicate: str) -> str:
    """Lower one source predicate in the running artifact's existing grammar.

    The native tracer parses and evaluates the result; this call only rejects
    input that is malformed for the selected family before any child forks.
    """
    text = predicate.strip()
    if family == binradar_taosc_predicates.PredicateFamily.GENERIC_ERM.value:
        return binradar_taosc_predicates.predicate_to_branch_patch_str(text)
    if family == binradar_taosc_predicates.PredicateFamily.CWE805_ERM.value:
        parsed = binradar_taosc_predicates.parse_CWE805_predicate(text)
        return binradar_taosc_predicates.predicate_descriptor(parsed)
    raise ReplayProtocolError(f"unsupported predicate family {family!r}")


SUPPORTED_FAMILIES = (
    binradar_taosc_predicates.PredicateFamily.GENERIC_ERM,
    binradar_taosc_predicates.PredicateFamily.CWE805_ERM,
)


def parse_family(name: str) -> binradar_taosc_predicates.PredicateFamily:
    """Reject any family without an existing cached replay grammar."""
    try:
        family = binradar_taosc_predicates.PredicateFamily(name)
    except ValueError as exc:
        raise ValueError(
            f"replay does not support generation family {name!r}") from exc
    if family not in SUPPORTED_FAMILIES:
        raise ValueError(
            f"replay does not support generation family {name!r}")
    return family


class ReplayServer:
    """One serialized evaluation endpoint over a resident tracer session.

    ``serve`` is called only after generation has ended.  ``status`` remains
    responsive from another thread because it reads the progress snapshot,
    never the native command channel.
    """

    def __init__(self, run_dir: str, family: str, stack_size: int = 0):
        self.run_dir = str(run_dir)
        self.path = os.path.join(self.run_dir, SOCKET_NAME)
        self.family = parse_family(family)
        self.stack_size = stack_size
        self.progress = GenerationProgress()
        self.shutdown_requested = threading.Event()
        # Re-entrant: the serving thread updates progress while already
        # holding the lock, and status must keep observing it.
        self._lock = threading.RLock()
        self._socket: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._listener: threading.Thread | None = None
        self._running = False
        self._tracer: binradar_runtime.TracerExecutor | None = None
        self._mutation_ids: list[int] = []

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if len(self.path.encode()) > MAX_SOCKET_PATH:
            raise ValueError(
                f"replay socket path is longer than {MAX_SOCKET_PATH} bytes: "
                f"{self.path}")
        if os.path.lexists(self.path):
            # Never unlink an endpoint another server may still own.
            raise RuntimeError(
                f"replay socket already exists; a server may be running: "
                f"{self.path}")
        os.makedirs(self.run_dir, exist_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(self.path)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            info = os.stat(self.path)
            self._socket_identity = (info.st_dev, info.st_ino)
            listener.listen(SOCKET_BACKLOG)
        except BaseException:
            listener.close()
            raise
        self._socket = listener
        self._running = True
        self._listener = threading.Thread(
            target=self._accept_loop, name="replay-listener", daemon=True)
        self._listener.start()

    def close(self) -> None:
        self._running = False
        self.shutdown_requested.set()
        listener = self._socket
        self._socket = None
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()
        if self._listener is not None:
            self._listener.join(timeout=5)
            self._listener = None
        # Do not wait for an in-flight evaluation here; the tracer cleanup in
        # the caller reaps its children and a joined worker would pin the
        # process to a slow guest exit.  Remove only the endpoint this server
        # created: another live server may have bound the same name after this
        # process lost ownership.
        try:
            info = os.stat(self.path)
            if self._socket_identity == (info.st_dev, info.st_ino):
                os.unlink(self.path)
        except FileNotFoundError:
            pass

    def update_generation(self, **fields: object) -> None:
        with self._lock:
            for name, value in fields.items():
                if not hasattr(self.progress, name):
                    raise AttributeError(f"unknown progress field {name}")
                setattr(self.progress, name, value)

    def attach_tracer(self, tracer: binradar_runtime.TracerExecutor) -> None:
        with self._lock:
            self._tracer = tracer

    @property
    def tracer(self) -> binradar_runtime.TracerExecutor | None:
        with self._lock:
            return self._tracer

    def _status(self) -> dict[str, object]:
        with self._lock:
            return self.progress.snapshot()

    # -- connection framing ------------------------------------------------
    def _accept_loop(self) -> None:
        assert self._socket is not None
        while self._running:
            try:
                connection, _ = self._socket.accept()
            except OSError:
                return
            worker = threading.Thread(
                target=self._connection_thread, args=(connection,),
                name="replay-connection", daemon=True)
            worker.start()

    def _connection_thread(self, connection: socket.socket) -> None:
        try:
            self._handle(connection)
        except BaseException as exc:  # never let one peer end the service
            logger.error(f"[REPLAY] Connection failed: {exc}")
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(CLIENT_READ_TIMEOUT)
        data = bytearray()
        while b"\n" not in data:
            if len(data) > MAX_REQUEST_BYTES:
                raise ReplayProtocolError("request is too large")
            chunk = connection.recv(4096)
            if not chunk:
                if not data:
                    return
                break
            data.extend(chunk)
            if len(data) > MAX_REQUEST_BYTES:
                raise ReplayProtocolError("request is too large")
        line, _, trailing = bytes(data).partition(b"\n")
        if trailing.strip():
            raise ReplayProtocolError("one request per connection is allowed")
        try:
            request = parse_request(line)
        except ReplayProtocolError as exc:
            self._send(connection, {"error": str(exc)})
            return
        operation = request["op"]
        if operation == "status":
            self._send(connection, self._status())
        elif operation == "shutdown":
            self.shutdown_requested.set()
            self._send(connection, {"accepted": True})
        else:
            patches = request["patches"]
            assert isinstance(patches, list)
            self._evaluate(connection, patches)

    @staticmethod
    def _send(connection: socket.socket, payload: dict[str, object]) -> None:
        connection.sendall(json.dumps(payload, separators=(",", ":"))
                           .encode("utf-8") + b"\n")

    # -- evaluation --------------------------------------------------------
    def _evaluate(self, connection: socket.socket,
                  patches: list[Patch]) -> None:
        tracer = self.tracer
        with self._lock:
            state = self.progress.state
        if state not in ("ready", "evaluating"):
            self._send(connection, {"error": f"state {state} cannot evaluate"})
            return
        if state == "evaluating":
            self._send(connection, {"error": "busy"})
            return
        if tracer is None:
            self._send(connection, {"error": "no resident snapshot"})
            return
        lowered: list[tuple[Patch, str]] = []
        try:
            for patch in patches:
                lowered.append((patch, lower_predicate(self.family.value,
                                                        patch.predicate)))
        except (ReplayProtocolError, ValueError) as exc:
            self._send(connection, {"error": str(exc)})
            return
        mutation_ids = list(self._mutation_ids)
        with self._lock:
            if not mutation_ids:
                self._send(connection, {
                    "error": "no retained mutations; zero coverage"})
                return
            self.update_generation(state="evaluating")
        disconnected = threading.Event()

        def watch_disconnect() -> None:
            while not disconnected.wait(0.1):
                try:
                    probe = connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                except (BlockingIOError, TimeoutError, InterruptedError):
                    # Still connected with no new bytes.  ``socket.timeout`` is
                    # an OSError subclass, so it must be matched before the
                    # generic error that means the peer is gone.
                    continue
                except OSError:
                    probe = b""
                if not probe:
                    try:
                        tracer.cancel_replay_child()
                    except (OSError, RuntimeError):
                        pass
                    return

        monitor = threading.Thread(
            target=watch_disconnect, name="replay-disconnect", daemon=True)
        monitor.start()
        try:
            total = 0
            unavailable = 0
            for patch, descriptor in lowered:
                for mutation in mutation_ids:
                    if self.shutdown_requested.is_set():
                        return
                    try:
                        result = tracer.request_replay_case(
                            mutation, descriptor,
                            self._case_timeout(tracer))
                    except (BrokenPipeError, EOFError, TimeoutError, OSError,
                            RuntimeError) as exc:
                        logger.error(
                            f"[REPLAY] Case failed for mutation {mutation}: "
                            f"{exc}")
                        self._send(connection, {
                            "mutation": mutation, "patch": patch.id,
                            "source": "executed", "outcome": "unavailable",
                            "reason": "engine-error"})
                        total += 1
                        unavailable += 1
                        if not self._recover(tracer):
                            return
                        continue
                    outcome = self._outcome_name(result)
                    row = {
                        "mutation": result.mutation,
                        "patch": patch.id,
                        "source": result.source,
                        "outcome": outcome,
                        "reason": self._reason_name(result),
                    }
                    try:
                        self._send(connection, row)
                    except OSError:
                        # The client left; the case already committed and stays
                        # reusable, but this batch produces no done marker.
                        disconnected.set()
                        return
                    total += 1
                    if outcome == "unavailable":
                        unavailable += 1
            try:
                self._send(connection, {
                    "done": True,
                    "cases": total,
                    "unavailable": unavailable,
                    "patches": len(lowered),
                    "mutations": len(mutation_ids),
                    "coverage": "zero" if total == 0 else
                    ("partial" if unavailable else "complete"),
                })
            except OSError:
                pass
        finally:
            disconnected.set()
            monitor.join(timeout=1.0)
            with self._lock:
                if self.progress.state == "evaluating":
                    self.update_generation(state="ready")

    @staticmethod
    def _outcome_name(result: binradar_runtime.ReplayCaseResult) -> str:
        return binradar_runtime.protocol_enum_name(result.outcome)

    @staticmethod
    def _reason_name(result: binradar_runtime.ReplayCaseResult) -> str | None:
        if result.reason == binradar_runtime.ReplayReason.NONE:
            return None
        return binradar_runtime.protocol_enum_name(result.reason)

    @staticmethod
    def _case_timeout(tracer: binradar_runtime.TracerExecutor) -> float:
        child_cap = float(tracer.env.get(
            "BINRADAR_FORKSERVER_CHILD_TIMEOUT",
            binradar_runtime.TracerExecutor.forkserver_timeout))
        # One child plus native kill/reap and reply framing.
        return child_cap + 120.0

    def _recover(self, tracer: binradar_runtime.TracerExecutor) -> bool:
        """Return to ``ready`` after a failed case; a dead parent is fatal."""
        process = tracer.process
        if process is None or process.poll() is not None:
            with self._lock:
                self.update_generation(
                    state="stopping",
                    error="resident parent exited during replay")
            self.shutdown_requested.set()
            return False
        return True

    # -- serving -----------------------------------------------------------
    def serve(self, tracer: binradar_runtime.TracerExecutor,
              mutation_ids: Iterable[int], generation_stop: str,
              remaining_plans: int | None) -> None:
        """Serve until explicit shutdown, signal or fatal engine failure."""
        self._mutation_ids = [int(value) for value in mutation_ids]
        with self._lock:
            self.update_generation(
                state="ready",
                generation_stop=generation_stop,
                remaining_plans=remaining_plans,
                retained_mutations=len(self._mutation_ids),
                error=None)
        logger.info(
            f"[REPLAY] Ready: {len(self._mutation_ids)} retained mutation(s), "
            f"generation stop {generation_stop}")
        try:
            while not self.shutdown_requested.wait(0.2):
                if tracer.process is not None and tracer.process.poll() is not None:
                    with self._lock:
                        self.update_generation(
                            state="stopping",
                            error="resident parent exited")
                    logger.error("[REPLAY] Resident tracer parent exited")
                    # Fatal engine failure: stop admitting requests so a client
                    # observes a closed endpoint instead of a frozen "ready".
                    self._running = False
                    listener, self._socket = self._socket, None
                    if listener is not None:
                        try:
                            listener.close()
                        except OSError:
                            pass
                    self.shutdown_requested.set()
                    return
        finally:
            with self._lock:
                if self.progress.state != "stopping":
                    self.update_generation(state="stopping")
