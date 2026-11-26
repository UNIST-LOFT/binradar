"""Offline observation planning; never enters an ordinary BinRadar run.

Only local original artifacts and immutable input copies are executed. The
existing concrete-worker Landlock/seccomp launcher is mandatory, not optional.
The output is analysis evidence, not a repair verdict or runtime slot ABI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

import sbsv
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from . import binradar_verifier as verifier, paths
from .observation_analysis import plan_observations

_SYSTEM_READ = ("/usr", "/bin", "/lib", "/lib64", "/gnu/store", "/etc/ld.so.cache")
_MAX_TRACE_BYTES = 256 * 1024 * 1024
_MAX_INPUT_BYTES = 64 * 1024 * 1024


class AnalysisError(ValueError):
    """No slot may be admitted from this execution/evidence."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_frozen(source: Path, destination: Path) -> str:
    if source.is_symlink() or not source.is_file():
        raise AnalysisError(f"not a regular immutable input: {source}")
    before = source.stat()
    shutil.copyfile(source, destination)
    after = source.stat()
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    digest = _sha256(destination)
    if identity(before) != identity(after) or digest != _sha256(source):
        raise AnalysisError(f"input changed during capture: {source}")
    return digest


def _address(text: str) -> int:
    try:
        value = int(text, 16)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an ELF hexadecimal address") from error
    if not 0 < value < 2**64:
        raise argparse.ArgumentTypeError("ELF address is zero or out of range")
    return value


def _corpus(run: Path, digest: str, location: int) -> tuple[list[dict], list[str]]:
    """Read the existing original-only producer contract, not a new corpus ABI."""
    identity_path = run / "original-identity.json"
    if identity_path.is_symlink():
        raise AnalysisError("symlinked concrete identity")
    identity = json.loads(identity_path.read_text())
    invocation = identity.get("invocation")
    if (identity.get("schema_version") != 1
            or identity.get("kind") != "original-only-minimizer"
            or identity.get("original_sha256") != digest
            or int(str(identity.get("patch_location")), 16) != location
            or not isinstance(invocation, list)
            or any(not isinstance(arg, str) for arg in invocation)):
        raise AnalysisError("concrete producer artifact/site/invocation identity mismatch")
    manifest = run / "minimizer.sbsv"
    if manifest.is_symlink():
        raise AnalysisError("symlinked concrete manifest")
    parser = sbsv.parser()
    parser.add_schema("[testcase] [original-result] [id: int] [file: str] [input-sha256: str] "
                      + verifier.PROBE_RESULT_SCHEMA_V4.removeprefix("[probe-info] ")
                      + " [time: int]")
    cases, seen, terminal = [], set(), False
    with manifest.open() as stream:
        if stream.readline() != "[minimizer] [baseline] [version 1] [baseline original]\n":
            raise AnalysisError("concrete corpus is not an original-only v1 baseline")
        for line in stream:
            if not line.endswith("\n"):
                raise AnalysisError("incomplete concrete manifest")
            if "[minimizer] [done]" in line or "[minimizer] [stopped] [reason wall-time-reached]" in line:
                terminal = True
            elif "[original-result" in line:
                if terminal:
                    raise AnalysisError("concrete row follows terminal marker")
                row = parser.parse_line_detached(line)
                if row is None:
                    raise AnalysisError("malformed concrete observation")
                data = dict(row.data)
                case_id, filename = data.get("id"), data.get("file")
                if (type(case_id) is not int or case_id < 0 or case_id in seen
                        or not isinstance(filename, str) or Path(filename).name != filename
                        or filename in ("", ".", "..")
                        or data.get("version") != verifier.CURRENT_PROBE_RESULT_VERSION
                        or data.get("concrete-oracle") != verifier.CONCRETE_ORACLE
                        or data.get("patch-loc") != location
                        or type(data.get("patch-hit")) is not int or data["patch-hit"] <= 0):
                    raise AnalysisError("invalid concrete observation identity")
                source = run / "minimized" / filename
                if source.is_symlink() or not source.is_file() or _sha256(source) != data.get("input-sha256"):
                    raise AnalysisError("concrete input identity changed")
                if data.get("exit") == "crash":
                    if verifier.concrete_fault_addr_from_row(data) is None:
                        raise AnalysisError("concrete crash lacks current QASAN fault identity")
                    outcome = "target_crash"
                elif (data.get("exit") == "ok" and data.get("concrete-fault-valid") is False
                      and data.get("fault-addr") == 0):
                    outcome = "normal"
                else:
                    raise AnalysisError("unknown concrete outcome")
                seen.add(case_id)
                cases.append({"case_id": f"corpus:{case_id}", "path": source,
                              "sha256": data["input-sha256"], "outcome": outcome})
    if not terminal:
        raise AnalysisError("concrete corpus lacks completed minimizer marker")
    return cases, invocation


def _environment(scratch: Path, perturb: int) -> dict[str, str]:
    # Do not inherit preload hooks, credentials, symbolic/replay modes or E9 state.
    return {
        "PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C",
        "HOME": str(scratch), "TMPDIR": str(scratch),
        "MALLOC_PERTURB_": f"{perturb:03d}",
        "BINRADAR_OBS_ANALYSIS": "1",
        "BINRADAR_FORKSERVER_ENABLE": "0", "BINRADAR_REPLAY_SERVER": "0",
        "BINRADAR_MEMCHECK_ENABLE": "1", "BINRADAR_MEMCHECK_POLICY": verifier.MEMCHECK_POLICY,
        "BINRADAR_TRACE_FILE": "none", "BINRADAR_OSPREY_ENABLE": "0",
    }


def _sandbox(command: list[str], scratch: Path, environment: dict[str, str],
             timeout: float, log_prefix: Path, readable: tuple[Path, ...] = ()) -> int:
    launcher = Path(paths.OBSERVATION_SANDBOX_SCRIPT)
    if not launcher.is_file():
        raise AnalysisError("mandatory Landlock/seccomp launcher unavailable")
    argv = [sys.executable, "-I", "-S", str(launcher), "--scratch", str(scratch),
            "--qemu-self-maps", "--timeout", str(max(1, math.ceil(timeout)))]
    for root in (*_SYSTEM_READ, command[0], *readable):
        argv.extend(("--read", str(root)))
    argv.extend(("--", *command))
    with log_prefix.with_suffix(".stdout").open("wb") as output, log_prefix.with_suffix(".stderr").open("wb") as errors:
        process = subprocess.Popen(argv, cwd=scratch, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                   start_new_session=True)
        try:
            result = process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    if result == 125:
        raise AnalysisError("isolation/worker failed (Landlock/seccomp remain mandatory)")
    return result


def _read_trace(path: Path, remaining: int) -> tuple[list[dict], int]:
    if not path.is_file() or path.is_symlink():
        raise AnalysisError("tracer did not publish analysis trace")
    size = path.stat().st_size
    if size > remaining:
        raise AnalysisError("analysis trace byte budget exceeded")
    records = []
    with path.open() as stream:
        for line in stream:
            if not line.endswith("\n"):
                raise AnalysisError("truncated trace record")
            record = json.loads(line)
            if not isinstance(record, dict):
                raise AnalysisError("invalid trace record")
            records.append(record)
    if (not records or records[0] != {"kind": "header", "schema_version": 1}
            or records[-1].get("kind") != "end"):
        raise AnalysisError("incomplete/unsupported native analysis trace")
    return records, remaining - size


def _collect(args, output: Path) -> dict:
    original = args.binary.absolute()
    frozen = output / "artifact.orig"
    digest = _copy_frozen(original, frozen)
    with frozen.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or elf.get_machine_arch() != "x64" or not elf.little_endian:
            raise AnalysisError("observation analysis requires little-endian x86-64 ELF")
        dynamic = any(segment["p_type"] == "PT_INTERP" for segment in elf.iter_segments())
        executable_ranges = [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"])
                             for segment in elf.iter_segments()
                             if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1]
        if not all(any(start <= pc < end for start, end in executable_ranges)
                   for pc in (args.patch_location, args.fault_reference)):
            raise AnalysisError("patch/fault reference must belong to original main executable text")
    if args.concrete_run:
        cases, invocation = _corpus(args.concrete_run.absolute(), digest, args.patch_location)
        if args.test_cmd is not None and shlex.split(args.test_cmd) != invocation:
            raise AnalysisError("command disagrees with concrete producer invocation")
    else:
        invocation = shlex.split(args.test_cmd if args.test_cmd is not None else "@@")
        cases: list[dict] = [{"case_id": f"{outcome}:{index}", "path": path.absolute(), "outcome": outcome}
                 for outcome, inputs in (("target_crash", args.crash_input), ("normal", args.normal_input))
                 for index, path in enumerate(inputs)]
    # Limit by outcome before replay; never silently sample by directory order.
    selected: list[dict] = []
    for outcome in ("target_crash", "normal"):
        group = sorted((case for case in cases if case["outcome"] == outcome), key=lambda case: case["case_id"])
        if not group:
            raise AnalysisError(f"no {outcome} input in contrastive corpus")
        selected.extend(group[:32])
    inputs = output / "inputs"
    traces = output / "traces"
    inputs.mkdir()
    traces.mkdir()
    for index, case in enumerate(selected):
        source = case["path"]
        if source.stat().st_size > _MAX_INPUT_BYTES:
            raise AnalysisError("input byte budget exceeded")
        destination = inputs / f"{index:04d}.input"
        copied = _copy_frozen(source, destination)
        if case.get("sha256", copied) != copied:
            raise AnalysisError("corpus input changed during snapshot")
        case.update(path=destination, sha256=copied)
    tracer = str(Path(paths.TRACER_BIN).resolve(strict=True))
    runs, remaining = [], _MAX_TRACE_BYTES
    with tempfile.TemporaryDirectory(prefix="binradar-observations-") as temporary:
        root = Path(temporary)
        # A stable guest path/argv/environment length keeps full-GPR collisions
        # meaningful across inputs and perturbations; separate seed paths do not.
        scratch = root / "run"
        scratch.mkdir()
        shutil.copyfile(frozen, scratch / "subject.orig")
        os.chmod(scratch / "subject.orig", 0o700)
        plt = scratch / "plt_info.txt"
        if dynamic:
            environment = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C",
                           "HOME": str(scratch), "TMPDIR": str(scratch)}
            result = _sandbox(paths.find_models_command("subject.orig", "plt_info.txt", isolated=True),
                              scratch, environment, args.timeout, output / "models",
                              (Path(paths.FIND_MODELS_SCRIPT),))
            if result != 0 or not plt.is_file():
                raise AnalysisError("allocator/model metadata generation failed; see models.stderr")
        else:
            plt.write_text("")
        plt_bytes = plt.read_bytes()
        (output / "plt_info.txt").write_bytes(plt_bytes)
        for index, case in enumerate(selected):
            for perturb in (85, 170):
                shutil.rmtree(scratch)
                scratch.mkdir(mode=0o700)
                shutil.copyfile(frozen, scratch / "subject.orig")
                os.chmod(scratch / "subject.orig", 0o500)
                shutil.copyfile(case["path"], scratch / "input")
                plt.write_bytes(plt_bytes)
                environment = _environment(scratch, perturb)
                environment.update(BINRADAR_OBS_PATCH_LOC=hex(args.patch_location),
                                   BINRADAR_OBS_TRACE_FILE=str(scratch / "trace.jsonl"),
                                   BINRADAR_OBS_MAX_EVENTS=str(args.max_events), PLT_INFO_FILE=str(plt))
                arguments = [arg.replace("@@", "input") for arg in invocation]
                prefix = traces / f"{index:04d}-{perturb:03d}"
                result = _sandbox([tracer, "-d", "page", "subject.orig", *arguments],
                                  scratch, environment, args.timeout, prefix)
                records, remaining = _read_trace(scratch / "trace.jsonl", remaining)
                shutil.copyfile(scratch / "trace.jsonl", prefix.with_suffix(".jsonl"))
                if _sha256(scratch / "subject.orig") != digest or _sha256(scratch / "input") != case["sha256"]:
                    raise AnalysisError("guest modified original/input during analysis")
                faults = [record for record in records if record.get("kind") == "fault"]
                if records[-1].get("status") == "ok":
                    if case["outcome"] == "normal":
                        if faults or result < 0:
                            raise AnalysisError("normal input did not replay normally")
                    elif not faults or faults[-1].get("pc") != args.fault_reference:
                        raise AnalysisError("target input fault reference mismatch")
                runs.append({"case_id": case["case_id"], "outcome": case["outcome"],
                             "perturb": perturb, "records": records})
    if _sha256(original) != digest:
        raise AnalysisError("original artifact changed during analysis")
    plan = plan_observations(runs, artifact_orig_sha256=digest,
                             patch_location=args.patch_location, fault_reference=args.fault_reference,
                             max_slots=args.max_slots)
    plan["inputs"] = [{"case_id": case["case_id"], "outcome": case["outcome"],
                       "sha256": case["sha256"], "path": str(case["path"].relative_to(output))}
                      for case in selected]
    plan["invocation"] = invocation
    plan["corpus_counts"] = {"available": len(cases), "selected": len(selected)}
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline opt-in fault-to-patch observation planning (no patch execution).")
    parser.add_argument("--binary", type=Path, required=True, help="local original x86-64 ELF")
    parser.add_argument("--patch-location", type=_address, required=True, help="original ELF hexadecimal PC")
    parser.add_argument("--fault-reference", type=_address, required=True, help="expected native tracer main-image fault PC")
    parser.add_argument("--concrete-run", type=Path, help="completed br-gen-con original-only run")
    parser.add_argument("--crash-input", type=Path, action="append", default=[])
    parser.add_argument("--normal-input", type=Path, action="append", default=[])
    parser.add_argument("--test-cmd", help="shell-quoted argv, not a shell command; @@ substitutes the input")
    parser.add_argument("--output-dir", type=Path, default=Path("observation-analysis"), help="new private output directory")
    parser.add_argument("--timeout", type=float, default=30, help="seconds per local worker")
    parser.add_argument("--max-events", type=int, default=2000000)
    parser.add_argument("--max-slots", type=int, default=64)
    args = parser.parse_args(argv)
    if args.concrete_run and (args.crash_input or args.normal_input):
        parser.error("use a concrete run or explicit inputs, not both")
    if not args.concrete_run and not (args.crash_input and args.normal_input):
        parser.error("both crash and normal inputs are required")
    if (not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 3600
            or not 1 <= args.max_events <= 2000000 or not 1 <= args.max_slots <= 64):
        parser.error("invalid timeout/event/slot budget")
    output = args.output_dir.absolute()
    try:
        output.mkdir(parents=True, mode=0o700, exist_ok=False)
    except OSError as error:
        parser.error(f"output directory must be new: {error}")
    failed = False
    plan: dict
    try:
        plan = _collect(args, output)
    except (OSError, ValueError, TypeError, KeyError, ELFError, subprocess.SubprocessError) as error:
        failed = True
        plan = {"schema_version": 1, "artifact_orig_sha256": None,
                "patch_location": hex(args.patch_location), "fault_reference": hex(args.fault_reference),
                "analysis_status": "execution_error", "unobservable_reason": None,
                "diagnostics": [{"reason": type(error).__name__, "detail": str(error)}],
                "alloc_hooks": [], "slots": [], "cooccurrence_groups": []}
    temporary = output / "observation-plan.json.part"
    temporary.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n")
    temporary.replace(output / "observation-plan.json")
    print(json.dumps({"analysis_status": plan["analysis_status"], "slots": len(plan["slots"]),
                      "plan": str(output / "observation-plan.json")}, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
