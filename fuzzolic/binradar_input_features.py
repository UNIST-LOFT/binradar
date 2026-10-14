"""Original-flow concrete baseline and private same-execution AFL features."""
from __future__ import annotations

import ctypes
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

import binradar_verifier as verifier
from binradar_taosc_predicates import (
    CachedSnapshot, ParsedPredicate, PredicateFamily, parse_cached_snapshots,
    predicate_descriptor, predicate_stack_bytes,
)

MAP_BYTES = 65536  # checked afl-qemu-trace build: MAP_SIZE_POW2=16
_COVERAGE_KEYS = (
    "AFL_INST_RATIO", "AFL_QEMU_INST_RANGES", "AFL_QEMU_EXCLUDE_RANGES",
    "AFL_QEMU_INST_START", "AFL_QEMU_INST_END", "AFL_INST_LIBS",
    "AFL_QEMU_COMPCOV", "AFL_COMPCOV_LEVEL", "AFL_QEMU_COMPCOV_BINNAME",
    "AFL_QEMU_COMPCOV_IGNORE", "AFL_USE_QASAN",
)


def _reason(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unavailable"


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def descriptor_digest(predicates: Mapping[int, ParsedPredicate]) -> str:
    """Stable identity of ascending runtime ids and their exact descriptors."""
    if not predicates:
        return "none"
    descriptors = [(patch, predicate_descriptor(predicates[patch]))
                   for patch in sorted(predicates)]
    return hashlib.sha256(json.dumps(
        descriptors, separators=(",", ":")).encode()).hexdigest()


class _CoverageMap:
    """Kernel-allocated, owner-only SysV region (never a selector/fuzzer map)."""
    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.shmget.argtypes = (ctypes.c_int, ctypes.c_size_t, ctypes.c_int)
        self.libc.shmget.restype = ctypes.c_int
        self.libc.shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        self.libc.shmat.restype = ctypes.c_void_p
        self.libc.shmdt.argtypes = (ctypes.c_void_p,)
        self.libc.shmdt.restype = ctypes.c_int
        self.libc.shmctl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        self.libc.shmctl.restype = ctypes.c_int
        self.ident = self.libc.shmget(0, MAP_BYTES, 0o1000 | 0o600)
        if self.ident < 0:
            raise OSError(ctypes.get_errno(), "cannot allocate baseline AFL SHM")
        self.address = None
        try:
            address = self.libc.shmat(self.ident, None, 0)
            if address is None or address == ctypes.c_void_p(-1).value:
                raise OSError(ctypes.get_errno(), "cannot attach baseline AFL SHM")
            self.address = address
        except BaseException:
            self.close()
            raise

    def clear(self):
        assert self.address is not None, "baseline map is closed"
        ctypes.memset(self.address, 0, MAP_BYTES)

    def read(self) -> bytes:
        assert self.address is not None, "baseline map is closed"
        return ctypes.string_at(self.address, MAP_BYTES)

    def close(self):
        # Remove even when detach fails; IPC_RMID also cleans up surviving
        # attachments after their last detach.
        error = None
        if self.address is not None:
            if self.libc.shmdt(self.address) < 0:
                error = OSError(ctypes.get_errno(), "cannot detach baseline AFL SHM")
            self.address = None
        if self.ident >= 0:
            if self.libc.shmctl(self.ident, 0, None) < 0 and error is None:
                error = OSError(ctypes.get_errno(), "cannot remove baseline AFL SHM")
            self.ident = -1
        if error is not None:
            raise error


@dataclass(frozen=True)
class BaselineFeatures:
    probe: Optional[verifier.BinRadarProbeResult]
    patch: Optional[verifier.BinRadarPatchResult]
    _snapshots: Optional[tuple[CachedSnapshot, ...]]
    coverage: Optional[bytes]
    patch_reason: str
    coverage_reason: str

    @property
    def snapshots(self) -> Optional[list[CachedSnapshot]]:
        # The scorer's established interface takes a list; never expose our
        # retained container to mutation or alias a following execution.
        return None if self._snapshots is None else list(self._snapshots)


class BaselineFeatureCollector:
    """One selected baseline artifact, one target execution per input.

    Optional BRCH corruption disables only patch scoring. Required artifact
    identity metadata and requested SHM allocation are operational failures.
    The caller still owns concrete fault eligibility and publication.
    """
    def __init__(self, runner: verifier.BinRadarQemuRunner, patches: Sequence[int]):
        self.runner = runner
        if any(type(patch) is not int or patch <= 0 for patch in patches):
            raise ValueError("baseline candidates must be positive integer ids")
        ids = sorted(set(patches))
        selected = verifier.load_cached_predicate_set(
            Path(runner.dir) / "brpatches.json", Path(runner.cached_binary()),
            runner.patch_kind, runner.brcache_stack_size, ids)
        self.family = selected.family
        self.predicates = ({patch: selected.predicates[patch] for patch in ids}
                           if selected.predicates is not None else {})
        self.patch_reason = "none" if self.predicates else _reason(selected.reason)
        self.binary = runner.cached_binary() if self.predicates else runner.patched_binary()
        # Never fallback from corrupt required E9 metadata to another artifact.
        runner.load_instruction_map(self.binary)
        self.descriptor_digest = descriptor_digest(self.predicates)
        self._environment = runner.get_env_for_exec("0", binary=self.binary)
        # Presence-only AFL switches distinguish absent from an empty value.
        settings = {key: self._environment.get(key) for key in _COVERAGE_KEYS}
        self.metadata = {
            "artifact_sha256": _sha256(self.binary),
            "qemu_sha256": _sha256(verifier.QEMU_STACKTRACE_RELEASE),
            "map_bytes": MAP_BYTES,
            "coverage_settings": json.dumps(settings, sort_keys=True, separators=(",", ":")),
            "patch_reason": self.patch_reason,
        }
        self._map: Optional[_CoverageMap] = None

    def __enter__(self):
        if self._map is not None:
            raise RuntimeError("baseline collector already entered")
        self._map = _CoverageMap()
        return self

    def __exit__(self, exc_type, exc, traceback):
        region, self._map = self._map, None
        if region is not None:
            region.close()

    def _patch_snapshots(self, data, probe, patch):
        if data is None:
            return None, "missing-brch"
        snapshots, error = parse_cached_snapshots(data)
        if error is not None:
            return None, _reason(error)
        if len(snapshots) != probe.patch_hit_cnt:
            return None, "brch-hit-mismatch"
        if patch is None or patch.br_selection != [snapshot.branch for snapshot in snapshots]:
            return None, "brch-text-mismatch"
        expected_cwe = self.family == PredicateFamily.CWE805_ERM
        required = max((predicate_stack_bytes(p) for p in self.predicates.values()), default=0)
        for snapshot in snapshots:
            if snapshot.patch_id != 0 or snapshot.branch != 0:
                return None, "nonneutral-brch"
            if snapshot.is_CWE805 != expected_cwe:
                return None, "brch-family-mismatch"
            if expected_cwe and (len(snapshot.stack) != self.runner.brcache_stack_size
                                 or len(snapshot.stack) < required):
                return None, "brch-stack-mismatch"
        return tuple(snapshots), "none"

    def run(self, testcase: str) -> BaselineFeatures:
        if self._map is None:
            raise RuntimeError("baseline collector must be used as a context manager")
        self._map.clear()
        extra_env = {"__AFL_SHM_ID": str(self._map.ident)}
        if self.predicates:
            extra_env["TAOSC_PRED"] = "p0"  # original path for both ERM families
            extra_env["BRCACHE_STACK_SIZE"] = str(self.runner.brcache_stack_size)
        probe, text, binary = self.runner._test_with_capture(
            self.binary, "0", testcase, extra_env=extra_env,
            capture_cached=bool(self.predicates), base_env=self._environment)
        execution = self.runner.run_results
        failure = None
        if execution is None:
            failure = "missing-execution-result"
        elif execution.timed_out:
            failure = "timeout"
        elif verifier.tracer_execution_cancelled(execution.exit_code):
            failure = "cancelled"
        elif not execution.success:
            failure = "execution-failed"
        elif probe is None or probe.is_timeout() or probe.exit_info not in ("ok", "crash"):
            failure = "unusable-baseline"
        if failure is not None:
            return BaselineFeatures(None, None, None, None, failure, failure)
        assert probe is not None
        patch = verifier.BinRadarPatchResult.from_log(text.decode(errors="ignore")) if text is not None else None
        if probe.patch_hit_cnt == 0 and not text:
            patch = verifier.BinRadarPatchResult(0, [])
        # Non-original text branches invalidate the baseline itself, whereas
        # invalid optional binary capture must preserve a valid observation.
        if (patch is None or patch.patch_id != 0
                or len(patch.br_selection) != probe.patch_hit_cnt
                or any(branch != 0 for branch in patch.br_selection)):
            return BaselineFeatures(None, None, None, None,
                                    "invalid-baseline-branches", "unusable-baseline")
        coverage = self._map.read()
        coverage_reason = "none" if any(coverage) else "empty-map"
        if coverage_reason != "none":
            coverage = None
        snapshots, patch_reason = (self._patch_snapshots(binary, probe, patch)
                                   if self.predicates else (None, self.patch_reason))
        return BaselineFeatures(probe, patch, snapshots, coverage, patch_reason, coverage_reason)
