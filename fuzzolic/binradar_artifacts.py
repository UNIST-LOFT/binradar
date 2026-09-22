"""BinRadar candidate-scope and executable-artifact resolution."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import binradar_verifier


@dataclass(frozen=True)
class CandidateSet:
    """Resolved candidate counts without process or executor state."""

    requested_scope: str
    compiled_total: int
    filtered_total: int
    effective_total: int
    status: str
    reason: str

    def environment(self) -> dict[str, str]:
        return {
            "TOTAL_PATCHES": str(self.effective_total),
            "BRPATCHED_TOTAL_PATCHES": str(self.compiled_total),
            "BINRADAR_TARGET_PATCHES": self.requested_scope,
            "BINRADAR_TARGET_PATCHES_STATUS": self.status,
            "BINRADAR_TARGET_PATCHES_REASON": self.reason,
        }


def resolve_candidate_set(
        workdir: str, env: Mapping[str, str], requested_scope: str) -> CandidateSet:
    """Resolve CLI candidate scope against cached-artifact capability."""
    compiled_total = int(env["TOTAL_PATCHES"])
    filtered_total = int(env.get("FILTER_TOTAL_PATCHES", env["TOTAL_PATCHES"]))
    if requested_scope != "all":
        return CandidateSet(
            requested_scope=requested_scope,
            compiled_total=compiled_total,
            filtered_total=filtered_total,
            effective_total=compiled_total,
            status="top-30",
            reason="requested top-30",
        )
    if filtered_total <= compiled_total:
        return CandidateSet(
            requested_scope=requested_scope,
            compiled_total=compiled_total,
            filtered_total=filtered_total,
            effective_total=filtered_total,
            status="all-within-compiled",
            reason="filtered total does not exceed compiled capacity",
        )

    root = Path(workdir)
    coverage = binradar_verifier.load_cached_predicate_set(
        root / "brpatches.json",
        root / f"{env['BINARY']}.brcached",
        env.get("BINRADAR_PATCH_KIND", ""),
        int(env.get("BRCACHE_STACK_SIZE", "0"), 0),
        list(range(1, filtered_total + 1)),
    )
    if coverage.predicates is None:
        return CandidateSet(
            requested_scope=requested_scope,
            compiled_total=compiled_total,
            filtered_total=filtered_total,
            effective_total=compiled_total,
            status="all-clamped",
            reason=coverage.reason,
        )
    return CandidateSet(
        requested_scope=requested_scope,
        compiled_total=compiled_total,
        filtered_total=filtered_total,
        effective_total=filtered_total,
        status="all-expanded",
        reason="cached artifact and manifest cover every filtered patch",
    )


class ArtifactUnavailableError(RuntimeError):
    """Raised when active ids cannot be represented by any safe artifact."""


@dataclass(frozen=True)
class ArtifactSelection:
    """One executable choice and the capability decision behind it."""

    path: str
    metadata_prefix: str
    cache_enabled: bool
    cache_requested: bool
    reason: str


@dataclass(frozen=True)
class ArtifactSet:
    """Artifact paths and immutable cache-validation inputs for one run."""

    workdir: str
    binary: str
    patch_kind: str
    stack_size: int
    compiled_total: int

    @property
    def original(self) -> str:
        return str(Path(self.workdir) / f"{self.binary}.orig")

    @property
    def patched(self) -> str:
        return str(Path(self.workdir) / f"{self.binary}.brpatched")

    @property
    def cached(self) -> str:
        return str(Path(self.workdir) / f"{self.binary}.brcached")

    @property
    def manifest(self) -> str:
        return str(Path(self.workdir) / "brpatches.json")

    def requires_cache(self, patches: Sequence[int]) -> bool:
        return any(patch > self.compiled_total for patch in patches)

    def _cache_requested(self, patches: Sequence[int]) -> bool:
        return len(patches) > 1 or self.requires_cache(patches)

    def cached_predicate_set(self, patches: Sequence[int]):
        """Validate cache coverage with the shared predicate loader."""
        return binradar_verifier.load_cached_predicate_set(
            Path(self.manifest), Path(self.cached), self.patch_kind,
            self.stack_size, list(patches))

    def select_verifier(self, patches: Sequence[int]) -> ArtifactSelection:
        """Choose the verifier artifact; verifier performs runtime fallback."""
        requested = self._cache_requested(patches)
        if requested and Path(self.cached).exists():
            return ArtifactSelection(
                self.cached, "brcached", True, True,
                "cached artifact available for verifier grouping")
        reason = (
            "cached artifact not required" if not requested
            else "cached artifact does not exist")
        return ArtifactSelection(
            self.patched, "brpatched", False, requested, reason)

    def select_tracer(self, patches: Sequence[int]) -> ArtifactSelection:
        """Choose a tracer artifact without exceeding .brpatched capacity."""
        required = self.requires_cache(patches)
        requested = self._cache_requested(patches)
        if not requested:
            return ArtifactSelection(
                self.patched, "brpatched", False, False,
                "cached artifact not required")
        if not Path(self.cached).exists():
            reason = "cached artifact does not exist"
            if required:
                raise ArtifactUnavailableError(reason)
            return ArtifactSelection(
                self.patched, "brpatched", False, True, reason)
        coverage = self.cached_predicate_set(patches)
        if coverage.predicates is None:
            if required:
                raise ArtifactUnavailableError(coverage.reason)
            return ArtifactSelection(
                self.patched, "brpatched", False, True, coverage.reason)
        return ArtifactSelection(
            self.cached, "brcached", True, True,
            "cached artifact and manifest cover active patches")
