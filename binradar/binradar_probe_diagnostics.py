"""Diagnostic-only archive of the existing PROBE reference execution.

Nothing in this module selects or authenticates a fault reference. In particular,
terminal-looking output from a cancelled process is only an observed log record.
"""

import json
import os
import shutil
import tempfile
from dataclasses import asdict
from pathlib import Path

import sbsv

from . import binradar_verifier
from .binradar_feedback_capture import file_sha256


# Record the effective values of an explicit allowlist, not the inherited
# environment (which can contain credentials and is not a replay manifest).
_SETTINGS = (
    "BINRADAR_FORKSERVER_ENABLE", "BINRADAR_ENTRYPOINT",
    "BINRADAR_MEMCHECK_ENABLE", "BINRADAR_MEMCHECK_POLICY",
    "BINRADAR_OSPREY_ENABLE", "BINRADAR_SYMBOLIC_MUTATION_MODE",
    "BINRADAR_TRACE_FILE", "BINRADAR_TRACER_LOG_FILE", "BINRADAR_PROBE_FILE",
    "PLT_INFO_FILE", "E9_EXCLUDE_RANGES", "E9_RELOCATED_CALL_JUMPS",
    "E9_RELOCATED_INSTRUCTIONS", "QEMU_RAND_SEED", "QEMU_LD_PREFIX",
    "QEMU_CPU", "QEMU_SET_ENV", "QEMU_UNSET_ENV", "LD_PRELOAD",
    "LD_LIBRARY_PATH", "GLIBC_TUNABLES", "MALLOC_PERTURB_",
)


def _file_identity(path, cwd):
    if not path:
        return {"path": None, "sha256": None, "unavailable": "not configured"}
    path = os.path.abspath(os.path.join(cwd, path))
    try:
        return {"path": path, "sha256": file_sha256(path)}
    except OSError as exc:
        return {"path": path, "sha256": None, "unavailable": str(exc)}


def _terminal_kind(result):
    """Describe complete terminal rows, never infer completion from success."""
    parser = sbsv.parser()
    parser.add_schema("[snapshot] [exit] [normal] [entrypoint-hit: int]")
    parser.add_schema(
        "[snapshot] [crash] [hit-count: int] [reason: str] [guest_pc: hex] "
        "[guest_cs_base: hex] [fault_addr: hex] [host_fault_addr: hex]")
    kind = "unknown"
    for line in (result.stderr or "").splitlines(keepends=True):
        # A killed writer may leave a partial last row. It is not a terminal.
        if not line.endswith("\n"):
            continue
        try:
            row = parser.parse_line_detached(line)
        except (ValueError, KeyError, TypeError):
            continue
        if row is None:
            continue
        if row.schema_name == "snapshot$crash":
            return ("signal" if result.exit_code < 0 or
                    "unhandled_target_signal" in row["reason"] else "crash")
        if row.schema_name == "snapshot$exit$normal":
            kind = "normal"
    return kind


class ProbeTraceDiagnostics:
    def __init__(self, run_dir, *, command, cwd, environment, testcase, timeout):
        self.root = Path(run_dir)
        # execute() resolves bare command names using the child's PATH.
        tracer = command[0]
        if os.path.dirname(tracer) == "":
            tracer = shutil.which(tracer, path=environment.get("PATH")) or tracer
        self.record = {
            "version": 1,
            "command": list(command),
            "cwd": os.path.abspath(cwd),
            "timeout_seconds": timeout,
            "elapsed_seconds": None,
            "exit_code": None,
            "success": None,
            "timed_out": None,
            "cancelled": None,
            "memcheck_policy_requested": environment["BINRADAR_MEMCHECK_POLICY"],
            "memcheck_policy_acknowledged": None,
            "entrypoint": environment.get("BINRADAR_ENTRYPOINT"),
            "terminal_kind": "unknown",
            "reference_admission_reason": "missing-or-unusable-terminal",
            "reference": None,
            "error": None,
            "files": {
                "executable": _file_identity(command[1], cwd),
                "poc": _file_identity(testcase, cwd),
                "tracer": _file_identity(tracer, cwd),
                "plt_metadata": _file_identity(environment.get("PLT_INFO_FILE"), cwd),
            },
            "settings": {key: environment.get(key) for key in _SETTINGS},
            "settings_scope": "explicit allowlist; inherited environment not fully recorded",
        }

    def retain_output(self, result):
        # These are the decoded strings returned by execute(), including its
        # post-timeout drain, not a claim of byte-for-byte subprocess capture.
        # Publish neither an admission result nor a successful archive on error.
        for name in ("stdout", "stderr"):
            path = self.root / f"probe-tracer.{name}.log"
            with path.open("w", encoding="utf-8") as stream:
                stream.write(getattr(result, name) or "")
                stream.flush()
                os.fsync(stream.fileno())
        self.record.update(
            exit_code=result.exit_code, success=result.success,
            timed_out=result.timed_out,
            cancelled=binradar_verifier.tracer_execution_cancelled(result.exit_code),
            terminal_kind=_terminal_kind(result))

    def publish(self, *, reason, reference=None, error=None):
        self.record.update(reference_admission_reason=reason,
                           reference=asdict(reference) if reference is not None else None,
                           error=str(error) if error is not None else None)
        # Match the existing capture/evidence fsync + replace publication rule.
        fd, temporary = tempfile.mkstemp(prefix=".probe-tracer-", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.record, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.root / "probe-tracer-result.json")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
