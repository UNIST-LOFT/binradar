"""BinRadar progress, run-directory, and invocation records."""

import fcntl
import os
import time
from dataclasses import dataclass
from typing import Optional

import logger
import sbsv


@dataclass(frozen=True)
class BinRadarProgress:
    run_id: int
    run_dir: str
    probe_done: bool
    fuzzolic_done: bool
    directed_done: bool
    fuzzer_done: bool
    minimizer_done: bool
    verifier_done: bool
    done: bool

    @staticmethod
    def from_progress_file(
            run_prefix: str, filename: str) -> "BinRadarProgress | None":
        if not os.path.exists(filename):
            return None
        parser = sbsv.parser()
        parser.add_schema(
            "[rundir] [set] [prefix: str] [id: int] [dir: str]")
        parser.add_schema(
            "[rundir] [done] [prefix: str] [id: int] [dir: str]")
        for phase in (
                "probe", "fuzzolic", "directed", "fuzzer", "minimizer",
                "verifier"):
            parser.add_schema(
                f"[{phase}] [done] [prefix: str] [id: int]")
        parser.add_schema(
            "[final] [done] [prefix: str] [id: int] "
            "[remaining_patches: str] [binradar_remaining_patches: str]")
        with open(filename, "r", encoding="utf-8") as progress_file:
            fcntl.flock(progress_file, fcntl.LOCK_EX)
            parser.load(progress_file)
            fcntl.flock(progress_file, fcntl.LOCK_UN)

        results = parser.get_result()
        run_id = -1
        run_dir = ""
        for item in results["rundir"]["set"]:
            if item["prefix"] == run_prefix and item["id"] > run_id:
                run_id = int(item["id"])
                run_dir = item["dir"]
        if not run_dir:
            return None

        def phase_done(phase: str) -> bool:
            return any(
                int(item["id"]) == run_id and item["prefix"] == run_prefix
                for item in results[phase]["done"])

        return BinRadarProgress(
            run_id=run_id,
            run_dir=run_dir,
            probe_done=phase_done("probe"),
            fuzzolic_done=phase_done("fuzzolic"),
            directed_done=phase_done("directed"),
            fuzzer_done=phase_done("fuzzer"),
            minimizer_done=phase_done("minimizer"),
            verifier_done=phase_done("verifier"),
            done=phase_done("rundir"),
        )


@dataclass(frozen=True)
class RunSettings:
    invocation: str
    execution_mode: str
    workdir: str
    outdir: str
    run_prefix: str
    run_id: int
    timeout: int
    target_patches: str
    target_patches_status: str
    target_patches_reason: str
    compiled_patches: int
    filtered_patches: int
    effective_patches: int
    disable_binradar: bool
    feedback: bool
    symbolic_mutation_mode: str
    fuzzy: bool
    reverse_directed: bool
    less_strict: bool
    forkserver_child_timeout: int
    # Effective advisor budgets (settings v2).  None means the row predates
    # the field or was written without one: an unknown budget is never
    # reported as the built-in default.
    symbolic_max_work: Optional[int] = None
    symbolic_max_bytes: Optional[int] = None
    symbolic_deadline_ms: Optional[int] = None


# Settings row schema version.  Version 1 rows carry no advisor budgets.
RUN_SETTINGS_VERSION = 2


class RunRecordStore:
    """Persist append-only progress and per-run invocation records."""

    def __init__(self, outdir: str, progress_filename: str,
                 start_time: float) -> None:
        self.outdir = outdir
        self.progress_filename = progress_filename
        self.start_time = start_time

    def elapsed_time_ms(self) -> int:
        return int((time.time() - self.start_time) * 1000)

    def save_progress(self, data: str) -> None:
        elapsed = self.elapsed_time_ms()
        logger.info(f"[PROGRESS] {data} [time {elapsed}]")
        with open(self.progress_filename, "a", encoding="utf-8") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.write(f"{data} [time {elapsed}]\n")
            stream.flush()
            fcntl.flock(stream, fcntl.LOCK_UN)

    def select_run_directory(
            self, run_prefix: str, use_last_run_id: bool
    ) -> tuple[BinRadarProgress | None, int, str]:
        previous = BinRadarProgress.from_progress_file(
            run_prefix, self.progress_filename)
        run_id = previous.run_id if previous is not None else 0
        if previous is not None and not use_last_run_id:
            run_id += 1
        run_dir = os.path.join(self.outdir, f"{run_prefix}-{run_id:05d}")
        os.makedirs(run_dir, exist_ok=True)
        self.save_progress(
            f"[rundir] [set] [prefix {run_prefix}] [id {run_id}] "
            f"[dir {run_dir}]")
        return previous, run_id, run_dir

    @staticmethod
    def write_settings(run_dir: str, settings: RunSettings) -> None:
        def field(name: str, value: object) -> str:
            if isinstance(value, bool):
                rendered = "true" if value else "false"
            else:
                rendered = str(value)
            return f"[{name} {sbsv.escape_str(rendered, quote=True)}]"

        fields = [
            "[binradar-setting]",
            f"[version {RUN_SETTINGS_VERSION}]",
            field("invocation", settings.invocation),
            field("execution-mode", settings.execution_mode),
            field("workdir", settings.workdir),
            field("outdir", settings.outdir),
            field("run-prefix", settings.run_prefix),
            field("run-id", settings.run_id),
            field("timeout", settings.timeout),
            field("target-patches", settings.target_patches),
            field("target-patches-status", settings.target_patches_status),
            field("target-patches-reason", settings.target_patches_reason),
            field("compiled-patches", settings.compiled_patches),
            field("filtered-patches", settings.filtered_patches),
            field("effective-patches", settings.effective_patches),
            field("disable-binradar", settings.disable_binradar),
            field("feedback", settings.feedback),
            field("symbolic-mutation-mode", settings.symbolic_mutation_mode),
            field("fuzzy", settings.fuzzy),
            field("reverse-directed", settings.reverse_directed),
            field("less-strict", settings.less_strict),
            field(
                "forkserver-child-timeout",
                settings.forkserver_child_timeout),
        ]
        # Effective budgets, recorded separately from the requested values so
        # a reader can tell "not requested" from "requested as the default".
        for name, value in (
                ("symbolic-max-work", settings.symbolic_max_work),
                ("symbolic-max-bytes", settings.symbolic_max_bytes),
                ("symbolic-deadline-ms", settings.symbolic_deadline_ms)):
            fields.append(field(name, "unknown" if value is None else value))
        output = os.path.join(run_dir, "binradar-setting.sbsv")
        previous = ""
        if os.path.exists(output):
            with open(output, "r", encoding="utf-8") as settings_file:
                previous = settings_file.read()
            if previous and not previous.endswith("\n"):
                previous += "\n"
        temporary = f"{output}.tmp"
        with open(temporary, "w", encoding="utf-8") as settings_file:
            settings_file.write(previous)
            settings_file.write(" ".join(fields) + "\n")
        os.replace(temporary, output)
