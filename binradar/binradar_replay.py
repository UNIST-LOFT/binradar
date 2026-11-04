"""Local replay service for a resident BinRadar generation snapshot.

The orchestrator publishes ``<rundir>/replay.sock`` as a symlink to its short,
private Unix-domain socket under ``/tmp``. Clients resolve it before connecting.
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

import errno
import json
import os
import secrets
import select
import socket
import stat
import tempfile
import threading
from collections.abc import Iterable
from dataclasses import dataclass

from . import binradar_runtime
from . import binradar_taosc_predicates
from . import logger

SOCKET_NAME = "replay.sock"
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
    except (json.JSONDecodeError, RecursionError) as exc:
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
    """Host listener with one evaluation owner and independent status reads."""

    control_timeout = 10.0

    def __init__(self, run_dir: str, family: str, stack_size: int = 0):
        self.run_dir = str(run_dir)
        self.path = os.path.join(self.run_dir, SOCKET_NAME)
        self.family = parse_family(family)
        self.stack_size = stack_size
        self.progress = GenerationProgress()
        self.shutdown_requested = threading.Event()
        self._lock = threading.RLock()
        self._evaluation_idle = threading.Event()
        self._evaluation_idle.set()
        self._batch_cancel: threading.Event | None = None
        self._evaluation_connection: socket.socket | None = None
        self._connections: set[socket.socket] = set()
        self._socket: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._public_identity: tuple[int, int] | None = None
        self._private_dir: str | None = None
        self._private_identity: tuple[int, int] | None = None
        self._socket_path: str | None = None
        self._lifecycle_lock = threading.RLock()
        self._listener: threading.Thread | None = None
        self._running = False
        self._tracer: binradar_runtime.TracerExecutor | None = None
        self._mutation_ids: list[int] = []

    def start(self) -> None:
        with self._lifecycle_lock:
            if os.path.lexists(self.path):
                raise RuntimeError(
                    f"replay socket already exists; a server may be running: "
                    f"{self.path}")
            try:
                os.makedirs(self.run_dir, exist_ok=True)
                # TMPDIR may itself exceed sockaddr_un.sun_path.  Always use
                # a short, owner-only directory, even for short public paths.
                self._private_dir = tempfile.mkdtemp(
                    prefix="binradar-replay-", dir="/tmp")
                info = os.lstat(self._private_dir)
                self._private_identity = (info.st_dev, info.st_ino)
                self._socket_path = os.path.join(self._private_dir, SOCKET_NAME)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket = listener
                listener.bind(self._socket_path)
                info = os.lstat(self._socket_path)
                self._socket_identity = (info.st_dev, info.st_ino)
                os.chmod(self._socket_path, stat.S_IRUSR | stat.S_IWUSR)
                listener.listen(SOCKET_BACKLOG)
                # Record the symlink inode before exposing it.  Hard-linking
                # the symlink itself publishes atomically without clobbering,
                # and a concurrent replacement can never become our property.
                # Stage beside the public endpoint so publication also works
                # when the run directory and /tmp are on different mounts.
                staging_path = os.path.join(
                    self.run_dir, f".replay-{secrets.token_hex(16)}")
                os.symlink(self._socket_path, staging_path)
                try:
                    info = os.lstat(staging_path)
                    self._public_identity = (info.st_dev, info.st_ino)
                    try:
                        os.link(staging_path, self.path, follow_symlinks=False)
                    except FileExistsError as exc:
                        raise RuntimeError(
                            f"replay socket already exists; a server may be running: "
                            f"{self.path}") from exc
                finally:
                    os.unlink(staging_path)
                self._running = True
                self._listener = threading.Thread(
                    target=self._accept_loop, args=(listener,),
                    name="replay-listener", daemon=True)
                self._listener.start()
            except BaseException:
                self.close()
                raise

    def request_shutdown(self) -> None:
        """Stop admission and interrupt only the current native request."""
        with self._lock:
            self.progress.state = "stopping"
            self.shutdown_requested.set()
            if self._batch_cancel is not None:
                self._batch_cancel.set()
            tracer = self._tracer
            connection = self._evaluation_connection
        if tracer is not None:
            try:
                tracer.cancel_replay_child()
            except (OSError, RuntimeError):
                # The execution owner propagates channel/parent failure.
                pass
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        with self._lifecycle_lock:
            self.request_shutdown()
            self._running = False
            listener, self._socket = self._socket, None
            if listener is not None:
                try:
                    listener.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                listener.close()
            thread, self._listener = self._listener, None
            # Thread.start() can fail before a thread exists.  Startup rollback
            # must still release every filesystem resource in that case.
            if thread is not None and thread.ident is not None:
                thread.join(timeout=self.control_timeout)
            with self._lock:
                connections = tuple(self._connections)
            for connection in connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            # PhaseSession owns native cleanup, including exceptional exits.
            # Public and private ownership are independent: replacing the link
            # must not prevent retirement of this server's actual socket.
            public_identity, self._public_identity = self._public_identity, None
            socket_identity, self._socket_identity = self._socket_identity, None
            private_identity, self._private_identity = self._private_identity, None
            try:
                self._unlink_owned(
                    self.path, public_identity, link_target=self._socket_path)
            finally:
                try:
                    self._unlink_owned(self._socket_path, socket_identity)
                finally:
                    if self._owns_path(self._private_dir, private_identity):
                        try:
                            os.rmdir(self._private_dir)
                        except OSError as exc:
                            # Never recurse into unexpected replacement data.
                            if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                                raise

    @staticmethod
    def _owns_path(path: str | None, identity: tuple[int, int] | None) -> bool:
        if path is None or identity is None:
            return False
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return False
        return identity == (info.st_dev, info.st_ino)

    @classmethod
    def _unlink_owned(cls, path: str | None,
                      identity: tuple[int, int] | None, *,
                      link_target: str | None = None) -> None:
        if not cls._owns_path(path, identity):
            return
        if link_target is not None:
            # An unlinked public symlink's inode can be reused immediately.
            # Another server's unique private target must still be preserved.
            try:
                if os.readlink(path) != link_target:
                    return
            except OSError as exc:
                if exc.errno in (errno.ENOENT, errno.EINVAL):
                    return
                raise
        os.unlink(path)

    def update_generation(self, **fields: object) -> None:
        with self._lock:
            for name, value in fields.items():
                if not hasattr(self.progress, name):
                    raise AttributeError(f"unknown progress field {name}")
                setattr(self.progress, name, value)

    def attach_tracer(self, tracer: binradar_runtime.TracerExecutor) -> None:
        with self._lock:
            self._tracer = tracer
            tracer.replay_cancel_event = self.shutdown_requested

    @property
    def tracer(self) -> binradar_runtime.TracerExecutor | None:
        with self._lock:
            return self._tracer

    def _status(self) -> dict[str, object]:
        with self._lock:
            return self.progress.snapshot()

    def _fail(self, message: str) -> None:
        with self._lock:
            if self.progress.error is None:
                self.progress.error = message
        logger.error(f"[REPLAY] {message}")
        self.request_shutdown()

    def _accept_loop(self, listener: socket.socket) -> None:
        while self._running:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with self._lock:
                self._connections.add(connection)
            threading.Thread(
                target=self._connection_thread, args=(connection,),
                name="replay-connection", daemon=True).start()

    def _connection_thread(self, connection: socket.socket) -> None:
        try:
            self._handle(connection)
        except ReplayProtocolError as exc:
            try:
                self._send(connection, {"error": str(exc)})
            except OSError:
                pass
        except OSError:
            pass
        except Exception as exc:
            logger.error(f"[REPLAY] Connection failed: {exc}")
        finally:
            with self._lock:
                self._connections.discard(connection)
            connection.close()

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(CLIENT_READ_TIMEOUT)
        data = bytearray()
        while b"\n" not in data:
            chunk = connection.recv(4096)
            if not chunk:
                if not data:
                    return
                raise ReplayProtocolError("request must end with a newline")
            data.extend(chunk)
            if len(data) > MAX_REQUEST_BYTES:
                raise ReplayProtocolError("request is too large")
        line, _, trailing = bytes(data).partition(b"\n")
        if trailing.strip():
            raise ReplayProtocolError("one request per connection is allowed")
        request = parse_request(line)
        operation = request["op"]
        if operation == "status":
            self._send(connection, self._status())
        elif operation == "shutdown":
            with self._lock:
                self.progress.state = "stopping"
            try:
                self._send(connection, {"accepted": True})
            finally:
                self.request_shutdown()
        else:
            patches = request["patches"]
            assert isinstance(patches, list)
            self._evaluate(connection, patches)

    @staticmethod
    def _send(connection: socket.socket, payload: dict[str, object]) -> None:
        connection.sendall(json.dumps(payload, separators=(",", ":"))
                           .encode("utf-8") + b"\n")

    def _evaluate(self, connection: socket.socket, patches: list[Patch]) -> None:
        # Reservation covers both source/native validation and execution.  No
        # second request can pass a stale ready check while lowering a batch.
        with self._lock:
            state = self.progress.state
            tracer = self._tracer
            if state == "evaluating":
                error = "busy"
            elif state != "ready" or self.shutdown_requested.is_set():
                error = f"state {state} cannot evaluate"
            elif tracer is None:
                error = "no resident snapshot"
            else:
                error = None
                self.progress.state = "evaluating"
                self._evaluation_idle.clear()
                cancelled = threading.Event()
                self._batch_cancel = cancelled
                self._evaluation_connection = connection
                mutation_ids = self._mutation_ids
        if error is not None:
            self._send(connection, {"error": error})
            return
        assert tracer is not None
        stopped = threading.Event()

        def watch_disconnect() -> None:
            poller = select.poll()
            poller.register(connection, select.POLLIN | select.POLLHUP |
                            select.POLLERR | select.POLLRDHUP)
            while not stopped.is_set():
                if not poller.poll(100):
                    continue
                # After the newline there is no more legal client input.
                # Poll also observes EOF without a timeout-mode recv() which
                # could keep the old watcher alive after batch completion.
                with self._lock:
                    if stopped.is_set() or self._batch_cancel is not cancelled:
                        return
                    cancelled.set()
                    try:
                        tracer.cancel_replay_child()
                    except (OSError, RuntimeError):
                        pass
                return

        monitor = threading.Thread(
            target=watch_disconnect, name="replay-disconnect", daemon=True)
        monitor.start()

        def release() -> None:
            stopped.set()
            monitor.join()
            with self._lock:
                if self._batch_cancel is cancelled:
                    self._batch_cancel = None
                    self._evaluation_connection = None
                    if self.progress.state == "evaluating":
                        self.progress.state = "ready"
                    self._evaluation_idle.set()

        def terminal(payload: dict[str, object]) -> None:
            # The client may immediately submit another batch on its terminal
            # row; retire this cancellation owner before advertising completion.
            release()
            self._send(connection, payload)

        try:
            try:
                lowered = [(patch, lower_predicate(self.family.value,
                                                   patch.predicate))
                           for patch in patches]
            except (ValueError, RecursionError) as exc:
                terminal({"error": str(exc)})
                return
            for patch, descriptor in lowered:
                if cancelled.is_set() or self.shutdown_requested.is_set():
                    return
                try:
                    accepted = tracer.validate_replay_descriptor(
                        descriptor, self.control_timeout)
                except (OSError, EOFError, RuntimeError) as exc:
                    self._fail(f"Resident validation failed: {exc}")
                    return
                if not accepted:
                    terminal({
                        "error": f"patch {patch.id} exceeds native predicate "
                                 "or capture limits"})
                    return
            if not mutation_ids:
                terminal({
                    "error": "no retained mutations; zero coverage"})
                return
            total = unavailable = 0
            for patch, descriptor in lowered:
                for mutation in mutation_ids:
                    if cancelled.is_set() or self.shutdown_requested.is_set():
                        return
                    try:
                        result = tracer.request_replay_case(
                            mutation, descriptor, self._case_timeout(tracer),
                            cancel_event=cancelled)
                    except InterruptedError:
                        if not cancelled.is_set() and not self.shutdown_requested.is_set():
                            self._fail("Unexpected interruption of resident evaluation")
                        return
                    except (OSError, EOFError, RuntimeError) as exc:
                        # A live parent does not prove the wire is synchronized.
                        self._fail(f"Resident evaluation failed: {exc}")
                        return
                    if cancelled.is_set() or self.shutdown_requested.is_set():
                        return
                    outcome = self._outcome_name(result)
                    self._send(connection, {
                        "mutation": result.mutation, "patch": patch.id,
                        "source": result.source, "outcome": outcome,
                        "reason": self._reason_name(result),
                    })
                    total += 1
                    unavailable += outcome == "unavailable"
            # Retire the watcher before advertising completion.  A normal
            # client close after done must never cancel the next request.
            release()
            if not cancelled.is_set() and not self.shutdown_requested.is_set():
                self._send(connection, {
                    "done": True, "cases": total, "unavailable": unavailable,
                    "patches": len(lowered), "mutations": len(mutation_ids),
                    "coverage": "partial" if unavailable else "complete",
                })
        except OSError:
            # Native I/O is handled at its call site; only the client send can
            # fail here.  Completed cases stay reusable, with no batch marker.
            pass
        except Exception as exc:
            self._fail(f"Resident evaluation failed: {exc}")
        finally:
            release()

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
        return child_cap + 120.0

    def serve(self, tracer: binradar_runtime.TracerExecutor,
              mutation_ids: Iterable[int], generation_stop: str,
              remaining_plans: int | None) -> None:
        self.attach_tracer(tracer)
        with self._lock:
            self._mutation_ids = [int(value) for value in mutation_ids]
            if not self.shutdown_requested.is_set():
                self.update_generation(
                    state="ready", generation_stop=generation_stop,
                    remaining_plans=remaining_plans,
                    retained_mutations=len(self._mutation_ids))
        logger.info(
            f"[REPLAY] Ready: {len(self._mutation_ids)} retained mutation(s), "
            f"generation stop {generation_stop}")
        try:
            while not self.shutdown_requested.wait(0.1):
                if tracer.process is None or tracer.process.poll() is not None:
                    self._fail("Resident tracer parent exited")
            if not self._evaluation_idle.wait(self.control_timeout):
                self._fail("Resident evaluation did not reach its shutdown boundary")
            with self._lock:
                error = self.progress.error
            if error is not None:
                raise RuntimeError(error)
        finally:
            self.update_generation(state="stopping")
