#!/usr/bin/env python3
import argparse
import enum
import os
import re
import sbsv
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

SCRIPT_DIR = Path(__file__).parent.resolve()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import binradar_taosc_predicates
import binradar_utils
from binradar_taosc_predicates import (
    AllocatorTrace,
    CWE805PointerPredicate,
    CWE805SizePredicate,
    CWE805Snapshot,
    InstrumentationSpec,
    INT64_MIN,
    PREFILTER_SNAPSHOT_HEADER,
    PREFILTER_SNAPSHOT_MAGIC,
    PREFILTER_SNAPSHOT_VERSION,
    PredicateFamily,
    PredicateRecord,
    PrefilterTrap,
    RegisterCell,
    StackCell,
    _MASK64,
    _emit_brpatches_inc,
    _parse_predicate_records,
    build_instrumentation_spec,
    CWE805_branch_taken,
    CWE805_snapshot_branch_taken,
    detect_predicate_family,
    e9tool_command,
    evaluate_predicate,
    load_prefilter_passed_ids,
    load_predicates,
    parse_allocator_trace,
    parse_CWE805_predicate,
    parse_CWE805_snapshots,
    parse_state_lines,
    predicate_to_branch_patch_str,
    predicates_sha256,
    tokenize_generic,
    write_prefilter,
    write_runtime_predicates,
)

ROOT_DIR = SCRIPT_DIR.parent
BENCHMARK_SCRIPTS = ROOT_DIR / "benchmarks" / "scripts"
BRPATCH_SOURCE = ROOT_DIR / "benchmarks" / "loftix" / "brpatch.c"
BRPATCH_PREFILTER_SOURCE = ROOT_DIR / "benchmarks" / "loftix" / "brpatch-prefilter.c"
BRPATCH_CACHED_SOURCE = ROOT_DIR / "benchmarks" / "loftix" / "brpatch-cached.c"
QEMU_STACKTRACE_RELEASE = ROOT_DIR / "utils" / "binradar-aflplusplus" / "afl-qemu-trace"


"""BinRadar workdir setup and patch prefilter (one entry point).

Subcommands:
  setup       - generate <BINARY>.brpatched and binradar.env from
                config.env (previously benchmarks/scripts/binradar_setup.py)
  prefilter   - run the POC once against a capture-instrumented binary
                (<BINARY>.brprefilter, built from
                benchmarks/loftix/brpatch-prefilter.c) under the same QEMU
                configuration used by the FILTER phase, collect the
                patch-site STATE vectors, evaluate every candidate
                predicate offline (mirroring taosc's i64 semantics and its
                false-means-jump branch polarity), and write
                workdir/prefilter.sbsv listing which predicates branch on
                the POC.  `setup` then
                keeps only the surviving predicates before applying the
                top-30 cap, so the expensive binradar pipeline never runs
                on predicates that the FILTER phase would reject anyway.
                (previously fuzzolic/binradar-prefilter.py)

Usage:
  uv run fuzzolic/binradar-setup.py setup -w <workdir>
  uv run fuzzolic/binradar-setup.py prefilter -w <workdir>
"""


PAGE_SIZE = 0x1000
PREFILTER_QEMU_TIMEOUT = 60.0  # same as BinRadarQemuRunner.test_with_patched


def load_env(file: Path) -> Dict[str, str]:
    """
    Loads environment variables from a .env file and returns them as a dictionary.
    """
    env = dict()
    with file.open("r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def save_env(env: Dict[str, str], file: Path):
    """
    Saves environment variables from a dictionary to a .env file.
    """
    with file.open("w") as f:
        for key, value in env.items():
            f.write(f"{key}=\"{value}\"\n")


def _pipe_reader(rfd: int, chunks: List[bytes]):
    try:
        while True:
            chunk = os.read(rfd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        pass
    finally:
        try:
            os.close(rfd)
        except OSError:
            pass


def _kill_process_group(proc: subprocess.Popen):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass


def ensure_original_binary(workdir: Path, configdir: Path, config: dict) -> Path:
    """Return the original binary path, copying it into the workdir from
    the guix store (mirroring the `setup` recipe) when missing, so the
    prefilter can run on a fresh subject before `setup`."""
    binary = config["BINARY"]
    original_binary = workdir / f"{binary}.orig"
    if original_binary.exists():
        return original_binary
    cmd = [sys.executable, str(BENCHMARK_SCRIPTS / "binradar_get_binary.py"),
           "-c", str(configdir)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"cannot locate the original binary: {result.stderr.strip()}")
    src = Path(result.stdout.strip())
    print(f"Copying original binary {src} -> {original_binary}")
    shutil.copy(src, original_binary)
    return original_binary


def resolve_poc(configdir: Path, workdir: Path, poc_input: str) -> Optional[Path]:
    """Resolve the POC input; prefer the workdir (already set up), then the
    configdir (fresh subject), then as-is."""
    path = Path(poc_input)
    candidates = []
    if not path.is_absolute():
        candidates += [workdir / path, configdir / path]
    candidates.append(path)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def compile_capture_plugin(workdir: Path,
                           allocator: Optional[AllocatorTrace] = None) -> None:
    """Copy and compile brpatch-prefilter.c in the workdir (e9compile).

    CWE-805 families compile the allocation tracker and binary snapshot
    capture in (BRPATCH_CWE805 + the allocator kind define); generic
    families keep the sbsv register capture.
    """
    shutil.copy(BRPATCH_PREFILTER_SOURCE, workdir / "brpatch-prefilter.c")
    cmd = ["guix", "shell", "e9patch@1.0.1", "--",
           "e9compile", "brpatch-prefilter.c", "-DTAOSC_DEST=0"]
    if allocator is not None:
        cmd += ["-DBRPATCH_CWE805",
                f"-DBRPATCH_ALLOC_{allocator.kind.upper()}"]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        raise RuntimeError(f"e9compile failed with exit code {result.returncode}")


def build_capture_binary(workdir: Path, configdir: Path, config: dict,
                         patch_loc: str,
                         allocator: Optional[AllocatorTrace] = None) -> Path:
    """Instrument the original binary with the capture plugin.

    CWE-805 families use the same ordered multipoint instrumentation spec
    as the final binary (allocator hooks then the patch site, plan §8);
    generic families patch the single PATCH_LOC site.

    Returns the path of <BINARY>.brprefilter.  Also dumps e9tool JSON
    metadata (needed by extract_e9_runtime_metadata) as
    <BINARY>.brprefilter.json.
    """
    original_binary = ensure_original_binary(workdir, configdir, config)
    brprefilter = workdir / f"{config['BINARY']}.brprefilter"
    metadata = workdir / f"{config['BINARY']}.brprefilter.json"
    if allocator is not None:
        spec = build_instrumentation_spec(
            allocator, patch_loc, "if dest(state)@brpatch-prefilter goto",
            plugin_name="brpatch-prefilter")
    else:
        spec = InstrumentationSpec(
            ((patch_loc, "if dest(state)@brpatch-prefilter goto"),))
    for output, fmt in ((metadata, "json"), (brprefilter, None)):
        cmd = e9tool_command(spec, output, original_binary, fmt=fmt)
        print(" ".join(cmd))
        result = subprocess.run(cmd, cwd=workdir)
        if result.returncode != 0:
            raise RuntimeError(
                f"e9tool failed with exit code {result.returncode}: "
                f"cannot create {output.name}")
    return brprefilter


def build_cached_binary(
    workdir: Path,
    configdir: Path,
    binradar_env: Dict[str, str],
    family: PredicateFamily,
    allocator: Optional[AllocatorTrace],
) -> "E9RuntimeMetadata":
    """Build the verifier's selected-predicate capture artifact.

    Generic ERM instruments only PATCH_LOC.  CWE-805 ERM uses the same
    allocator hooks and ordered multipoint specification as .brpatched.
    The selected predicate is provided per run through TAOSC_PRED.
    """
    if family not in (PredicateFamily.GENERIC_ERM,
                      PredicateFamily.CWE805_ERM):
        raise RuntimeError(f"cannot cache patch family {family.value}")

    binary = binradar_env["BINARY"]
    patch_loc = binradar_env["PATCH_LOC"]
    original_binary = ensure_original_binary(workdir, configdir, binradar_env)
    brcached = workdir / f"{binary}.brcached"
    metadata = workdir / f"{binary}.brcached.json"
    if not (workdir / "brpatch.c").exists() \
            or not (workdir / "brpatches.inc").exists():
        raise RuntimeError("brpatch.c and brpatches.inc must be prepared "
                           "before building .brcached")

    shutil.copy(BRPATCH_CACHED_SOURCE, workdir / "brpatch-cached.c")
    destinations_file = workdir / "destinations"
    if not destinations_file.exists():
        raise RuntimeError(
            f"{destinations_file.name} not found in {workdir}: the cached "
            f"artifact needs the patch destination")
    dest = None
    with destinations_file.open("r") as f:
        for line in f:
            line = line.strip()
            if line:
                dest = f"0x{line}"
                break
    if dest is None:
        raise RuntimeError(f"no destination found in {destinations_file}")

    compile_defines = [f"-DTAOSC_DEST={dest}"]
    if family == PredicateFamily.CWE805_ERM:
        if allocator is None:
            raise RuntimeError("CWE-805 cache requires an allocator trace")
        compile_defines += ["-DBRPATCH_CWE805",
                            f"-DBRPATCH_ALLOC_{allocator.kind.upper()}"]
    cmd = ["guix", "shell", "e9patch@1.0.1", "--",
           "e9compile", "brpatch-cached.c"] + compile_defines
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        raise RuntimeError(
            f"e9compile failed with exit code {result.returncode}")

    if family == PredicateFamily.CWE805_ERM:
        assert allocator is not None
        spec = build_instrumentation_spec(
            allocator, patch_loc,
            "if dest(state)@brpatch-cached goto",
            plugin_name="brpatch-cached")
    else:
        spec = InstrumentationSpec(
            ((patch_loc, "if dest(state)@brpatch-cached goto"),))
    for output, fmt in ((metadata, "json"), (brcached, None)):
        cmd = e9tool_command(spec, output, original_binary, fmt=fmt)
        print(" ".join(cmd))
        result = subprocess.run(cmd, cwd=workdir)
        if result.returncode != 0:
            raise RuntimeError(
                f"e9tool failed with exit code {result.returncode}: "
                f"cannot create {output.name}")

    e9_metadata = extract_e9_runtime_metadata(
        brcached, metadata, original_binary, int(patch_loc, 0))
    persist_e9_metadata(workdir, "brcached", e9_metadata)
    return e9_metadata


def _remove_cached_artifact(workdir: Path,
                            binradar_env: Dict[str, str]) -> None:
    binary = binradar_env["BINARY"]
    for name in (f"{binary}.brcached", f"{binary}.brcached.json",
                 "brpatch-cached.c", "brpatches.json"):
        (workdir / name).unlink(missing_ok=True)
    for key in binradar_utils.e9_metadata_keys("brcached"):
        binradar_env.pop(key, None)
    binradar_env.pop("BRCACHE_STACK_SIZE", None)


def build_cached_artifact(
    workdir: Path,
    configdir: Path,
    binradar_env: Dict[str, str],
    family: PredicateFamily,
    allocator: Optional[AllocatorTrace],
    selected: List[PredicateRecord],
) -> None:
    """Build .brcached only when branch-equivalence can skip executions."""
    _remove_cached_artifact(workdir, binradar_env)
    if family not in (PredicateFamily.GENERIC_ERM,
                      PredicateFamily.CWE805_ERM) or len(selected) <= 1:
        return

    if family == PredicateFamily.CWE805_ERM:
        stack_size_file = workdir / "stack-size"
        try:
            stack_size = int(stack_size_file.read_text().strip(), 0)
        except (OSError, ValueError) as e:
            print(f"Error: CWE-805 cache needs a valid {stack_size_file.name}: "
                  f"{e}")
            exit(1)
        if stack_size <= 0 or stack_size > 0x100000:
            print(f"Error: invalid CWE-805 cache stack size {stack_size}")
            exit(1)
        binradar_env["BRCACHE_STACK_SIZE"] = str(stack_size)
    else:
        binradar_env["BRCACHE_STACK_SIZE"] = "0"

    write_runtime_predicates(
        workdir / "brpatches.json", family, selected)
    try:
        metadata = build_cached_binary(
            workdir, configdir, binradar_env, family, allocator)
    except RuntimeError as e:
        print(f"Error building cached binary: {e}")
        exit(1)
    binradar_utils.set_e9_metadata(
        binradar_env, "brcached",
        metadata.exclude_ranges_str(), metadata.relocated_calls_str())


def capture_states(workdir: Path, configdir: Path, config: dict,
                   patch_loc: str,
                   allocator: Optional[AllocatorTrace] = None,
                   stack_size: Optional[int] = None,
                   ) -> Optional[Union[List[List[int]], List[CWE805Snapshot]]]:
    """Run the POC once against <BINARY>.brprefilter and return the
    captured patch-site states.

    Generic families return a list of 16-slot STATE vectors; CWE-805
    families return a list of CWE805Snapshot records (clamps + registers +
    stack).  Returns None if the run failed (timeout / subprocess error) so
    the caller can fail open.
    """
    if not QEMU_STACKTRACE_RELEASE.exists():
        print(f"Warning: {QEMU_STACKTRACE_RELEASE} not found")
        return None

    compile_capture_plugin(workdir, allocator)
    brprefilter = build_capture_binary(workdir, configdir, config, patch_loc,
                                       allocator)

    metadata = extract_e9_runtime_metadata(
        brprefilter,
        workdir / f"{config['BINARY']}.brprefilter.json",
        ensure_original_binary(workdir, configdir, config),
        int(patch_loc, 0),
    )
    # Persist the prefilter artifact's metadata under its own prefix so
    # later phases never borrow .brpatched layout values.
    persist_e9_metadata(workdir, "prefilter", metadata)
    e9_relocated_calls: List[str] = []
    for record in metadata.relocated_calls_str().split(","):
        record = record.strip()
        if record:
            fields = [f"0x{int(field, 0):x}" for field in record.split(":")]
            e9_relocated_calls.append(":".join(fields))

    poc = resolve_poc(configdir, workdir, config["POC_INPUT"])
    if poc is None:
        print(f"Warning: POC input {config['POC_INPUT']} not found in "
              f"{workdir} or {configdir}")
        return None
    test_cmd = config["TEST_CMD"]

    command = [str(QEMU_STACKTRACE_RELEASE), "--input", str(poc),
               "--patch-loc", patch_loc, "--asan", "host"]
    # --asan-exclude is explicitly ignored by the local afl-qemu-trace
    # compatibility runner; only the active --e9-relocated-call records
    # are passed.
    for record in e9_relocated_calls:
        command += ["--e9-relocated-call", record]
    command += [str(brprefilter), "--"] + shlex.split(test_cmd)

    rfd, wfd = os.pipe()
    env = os.environ.copy()
    env["AFL_USE_QASAN"] = "1"
    env["PATCH_ID"] = "0"
    env["PATCH_FD"] = str(wfd)
    if allocator is not None:
        if stack_size is None:
            print("Warning: CWE-805 prefilter requires stack-size; "
                  "failing open")
            os.close(rfd)
            os.close(wfd)
            return None
        env["PREFILTER_STACK_SIZE"] = str(stack_size)
    # The run is expected to crash: the capture plugin never jumps, so the
    # program follows the original buggy path.  We only need the pipe data.
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=workdir,
                            start_new_session=True, pass_fds=(wfd,), env=env)
    os.close(wfd)
    chunks: List[bytes] = []
    thread = threading.Thread(target=_pipe_reader, args=(rfd, chunks))
    thread.start()
    try:
        proc.communicate(timeout=PREFILTER_QEMU_TIMEOUT)
    except subprocess.TimeoutExpired:
        print("Warning: QEMU prefilter run timed out")
        _kill_process_group(proc)
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc)
            proc.communicate()
        return None
    except Exception as e:
        print(f"Warning: QEMU prefilter run failed: {e}")
        _kill_process_group(proc)
        return None
    finally:
        thread.join()

    data = b"".join(chunks)
    if allocator is not None:
        snapshots, truncated = parse_CWE805_snapshots(data)
        if truncated:
            print("Warning: CWE-805 prefilter capture truncated; "
                  "failing open (partial history is not complete evidence)")
            return None
        return snapshots
    return parse_state_lines(data.decode(errors="ignore"))


class E9MapType(enum.IntEnum):
    TRAMPOLINE = 0
    RESERVE = 1
    REFACTOR = 2


E9_CONFIG_MAGIC = b"E9PATCH\0"
# Taosc's $mem0 shell expansion (utils/taosc/helpers.in): the four E9
# memory-operand fields of the matched instruction.
E9_MEM0 = "mem[0].base,mem[0].index,mem[0].scale,mem[0].disp"
E9_MEM0_ACCESS = f"{E9_MEM0},mem[0].size"
E9_CONFIG_STRUCT = struct.Struct("<8s16sIIqqqqIIII" + "II" * 5 + "I")
E9_MAP_STRUCT = struct.Struct("<iII")


@dataclass(frozen=True, order=True)
class AddressRange:
    """Half-open [start, end) interval of an E9 mapping."""

    start: int
    end: int


@dataclass(frozen=True)
class E9RuntimeMetadata:
    """Exact runtime metadata of one E9 artifact.

    exclude_ranges: the exact union of the loader interval, every RESERVE
        map, and every TRAMPOLINE map (never REFACTOR maps), sorted and
        coalesced (overlap/adjacency only).
    relocated_calls: (jump_addr, call_site, ret_addr) records for every
        instrumented original call relocated into an E9 trampoline.
    """

    exclude_ranges: Tuple[AddressRange, ...]
    relocated_calls: Tuple[Tuple[int, int, int], ...]

    def exclude_ranges_str(self) -> str:
        return serialize_exclude_ranges(self.exclude_ranges)

    def relocated_calls_str(self) -> str:
        return ",".join(
            f"0x{jump:x}:0x{site:x}:0x{ret:x}"
            for jump, site, ret in self.relocated_calls
        )


def normalize_address_ranges(
    ranges: List[Tuple[int, int]],
) -> Tuple[AddressRange, ...]:
    """Validate, sort, and merge overlapping/adjacent half-open intervals.

    Every interval must satisfy start < end.  The result is the exact
    union: disjoint intervals stay disjoint, and only overlapping or
    directly adjacent intervals are coalesced.
    """
    validated = []
    for start, end in ranges:
        if start >= end:
            raise ValueError(
                f"invalid E9 address range 0x{start:x}-0x{end:x}: "
                f"start must be < end")
        validated.append(AddressRange(start, end))
    validated.sort()
    merged: List[AddressRange] = []
    for rng in validated:
        if merged and rng.start <= merged[-1].end:
            if rng.end > merged[-1].end:
                merged[-1] = AddressRange(merged[-1].start, rng.end)
        else:
            merged.append(rng)
    return tuple(merged)


def serialize_exclude_ranges(ranges: Tuple[AddressRange, ...]) -> str:
    """Canonical comma-separated lowercase hex interval list."""
    return ",".join(f"0x{r.start:x}-0x{r.end:x}" for r in ranges)


def parse_exclude_ranges(value: str) -> Tuple[AddressRange, ...]:
    """Parse a canonical E9_EXCLUDE_RANGES value.

    An empty string is the empty list.  Every non-empty token must match
    the exact 0x<hex>-0x<hex> grammar with no trailing data and start <
    end; a malformed non-empty value is a configuration error.
    """
    if value == "":
        return ()
    ranges = []
    for token in value.split(","):
        match = re.fullmatch(r"0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+)", token)
        if match is None:
            raise ValueError(
                f"malformed E9 exclude range {token!r}: expected "
                f"0x<hex>-0x<hex>")
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        if start >= end:
            raise ValueError(
                f"invalid E9 exclude range {token!r}: start must be < end")
        ranges.append((start, end))
    return normalize_address_ranges(ranges)


def persist_e9_metadata(workdir: Path, prefix: str,
                        metadata: E9RuntimeMetadata) -> None:
    """Write one artifact's E9 metadata into binradar.env under its prefix.

    Loads the existing binradar.env (creating it when absent) and updates
    only the prefixed keys, so subject-level fields are preserved.
    """
    env_path = workdir / "binradar.env"
    env_file = load_env(env_path) if env_path.exists() else {}
    binradar_utils.set_e9_metadata(
        env_file, prefix,
        metadata.exclude_ranges_str(), metadata.relocated_calls_str())
    save_env(env_file, env_path)


def _parse_objdump_instructions(data: bytes, address: int) -> List[Tuple[int, bytes, str]]:
    """Disassemble one E9Patch mapping and return (address, bytes, text)."""
    with tempfile.NamedTemporaryFile(prefix="e9patch-map-", delete=False) as f:
        f.write(data)
        map_path = Path(f.name)

    try:
        cmd = [
            "objdump",
            "-D",
            "-b",
            "binary",
            "-m",
            "i386:x86-64",
            "-Mintel",
            f"--adjust-vma=0x{address:x}",
            str(map_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "objdump failed")

        instructions: List[Tuple[int, bytes, str]] = []
        line_re = re.compile(
            r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(.*)$"
        )
        for line in result.stdout.splitlines():
            match = line_re.match(line)
            if match is None:
                continue
            insn_address = int(match.group(1), 16)
            insn_bytes = bytes.fromhex(match.group(2))
            instructions.append((insn_address, insn_bytes, match.group(3).strip()))
        return instructions
    finally:
        map_path.unlink(missing_ok=True)


def _parse_e9tool_patch_metadata(path: Path) -> Tuple[List[int], Dict[int, Tuple[int, int]]]:
    """Read all patch offsets and instruction address/length from e9tool JSON output.

    e9tool's JSON stream contains JSON-RPC instruction messages but the
    metadata payload can contain trailing commas.  Regex parsing therefore
    keeps this independent of whether the whole line is strict JSON.
    """
    patch_offsets: List[int] = []
    instructions: Dict[int, Tuple[int, int]] = {}
    instruction_re = re.compile(
        r'"method"\s*:\s*"instruction".*?'
        r'"address"\s*:\s*"(0x[0-9a-fA-F]+)".*?'
        r'"length"\s*:\s*(\d+).*?'
        r'"offset"\s*:\s*(\d+)'
    )
    patch_re = re.compile(
        r'"method"\s*:\s*"patch".*?"offset"\s*:\s*(\d+)'
    )

    with path.open("r") as f:
        for line in f:
            match = instruction_re.search(line)
            if match is not None:
                address = int(match.group(1), 16)
                length = int(match.group(2))
                offset = int(match.group(3))
                instructions[offset] = (address, length)
                continue
            match = patch_re.search(line)
            if match is not None:
                patch_offsets.append(int(match.group(1)))

    return patch_offsets, instructions


def _find_executed_trampoline_map(cfg: Dict, site_address: int,
                                  brpatched_binary: Path) -> Optional[Dict]:
    """Return the trampoline map that the refactored code at site_address
    jumps to, or None when the site is not in a refactored region.

    E9Patch -O0 rewrites the code containing a patch site into a REFACTOR
    map whose copy of the site is a ``jmp <trampoline-entry>``.  The
    executed call-emulation pair lives in the trampoline map containing
    that entry; the other trampoline copies of the same bytes are dead.
    """
    for mapping in cfg["maps"]:
        if mapping["type"] != E9MapType.REFACTOR:
            continue
        if not (mapping["address"] <= site_address
                < mapping["address"] + mapping["size"]):
            continue
        with brpatched_binary.open("rb") as f:
            f.seek(mapping["file_offset"])
            data = f.read(mapping["size"])
        if len(data) != mapping["size"]:
            raise ValueError("refactor mapping extends past the patched binary")
        for address, _, text in _parse_objdump_instructions(
                data, mapping["address"]):
            if address != site_address:
                continue
            match = re.match(r"jmp\s+(?:0x)?([0-9a-fA-F]+)", text)
            if match is None:
                return None
            entry = int(match.group(1), 16)
            for trampoline in cfg["maps"]:
                if trampoline["type"] != E9MapType.TRAMPOLINE:
                    continue
                if trampoline["address"] <= entry \
                        < trampoline["address"] + trampoline["size"]:
                    return trampoline
            return None
        return None
    return None


def extract_relocated_call_jumps(
    brpatched_binary: Path,
    metadata_path: Path,
    original_binary: Path,
    patch_addr: int,
) -> List[Tuple[int, int, int]]:
    """Find E9Patch's jumps used to emulate every instrumented original call.

    With the default backend option ``-Ocall=false``, a relocated direct call
    is emitted as ``push original_next; jmp target`` inside an E9Patch
    trampoline.  For a direct call the jump target is unambiguous; for an
    indirect call the rewritten instruction is an indirect jmp preceded by
    the return-address setup.

    Every patched original call must map to exactly one trampoline jump
    (the executed copy, identified through the refactored region); the
    requested patch address must resolve to exactly one instrumented site.
    """
    if not metadata_path.exists():
        raise FileNotFoundError(f"e9tool metadata not found: {metadata_path}")

    patch_offsets, instructions = _parse_e9tool_patch_metadata(metadata_path)
    if not patch_offsets:
        raise ValueError("no patch records in e9tool metadata")
    sites: List[Tuple[int, int, int]] = []
    for offset in patch_offsets:
        site = instructions.get(offset)
        if site is None:
            raise ValueError(
                f"patch offset {offset} has no instruction record in "
                f"e9tool metadata")
        sites.append((offset, site[0], site[1]))

    # Require the requested patch address to exist exactly once.
    patch_sites = [site for site in sites if site[1] == patch_addr]
    if len(patch_sites) != 1:
        raise ValueError(
            f"requested patch address 0x{patch_addr:x} resolves to "
            f"{len(patch_sites)} instrumented site(s); expected exactly one")

    # Deduplicate sites: one address may carry several hooks.
    unique_sites: List[Tuple[int, int, int]] = []
    seen = set()
    for site in sites:
        if site[1] not in seen:
            seen.add(site[1])
            unique_sites.append(site)

    cfg = parse_e9patch_config(brpatched_binary)
    trampoline_insns: List[Tuple[Dict, List[Tuple[int, bytes, str]]]] = []
    for mapping in cfg["maps"]:
        if mapping["type"] != E9MapType.TRAMPOLINE:
            continue
        with brpatched_binary.open("rb") as f:
            f.seek(mapping["file_offset"])
            data = f.read(mapping["size"])
        if len(data) != mapping["size"]:
            raise ValueError("trampoline mapping extends past the patched binary")
        trampoline_insns.append(
            (mapping, _parse_objdump_instructions(data, mapping["address"])))

    records: List[Tuple[int, int, int]] = []
    with original_binary.open("rb") as f:
        for offset, address, length in unique_sites:
            f.seek(offset)
            original_instruction = f.read(length)
            call_kind, direct_displacement = _decode_call_site(
                original_instruction)
            if call_kind == "other":
                continue
            ret_addr = address + length
            direct_target: Optional[int] = None
            if call_kind == "direct":
                if direct_displacement is None:
                    raise ValueError("direct call has no rel32 displacement")
                direct_target = ret_addr + direct_displacement

            # The executed copy: the trampoline map the refactored site
            # jumps to (used to prefer the right copy for indirect calls).
            executed = _find_executed_trampoline_map(cfg, address,
                                                     brpatched_binary)

            matches: List[Tuple[int, int, int]] = []
            for mapping, insns in trampoline_insns:
                for index, (jump_addr, _, text) in enumerate(insns):
                    if not text.startswith("jmp"):
                        continue
                    operand = text[len("jmp"):].strip()
                    target_match = re.match(r"(?:0x)?([0-9a-fA-F]+)", operand)
                    jump_target = int(target_match.group(1), 16) \
                        if target_match else None
                    if call_kind == "direct":
                        if jump_target != direct_target:
                            continue
                    elif jump_target is not None:
                        continue
                    # Exact return-address setup: the preceding instruction
                    # pushes the original return address.
                    if index == 0 \
                            or not insns[index - 1][2].startswith("push"):
                        continue
                    push_operand = insns[index - 1][2][len("push"):].strip()
                    push_match = re.match(r"(?:0x)?([0-9a-fA-F]+)",
                                          push_operand)
                    if push_match is None \
                            or int(push_match.group(1), 16) != ret_addr:
                        continue
                    matches.append((jump_addr, address, ret_addr))

            if not matches:
                raise ValueError(
                    f"no relocated call-equivalent jump found for patched "
                    f"original call at 0x{address:x}")

            # Deduplicate by (site, ret): the same trampoline pages can be
            # mapped at several VAs, and relative jumps resolve differently
            # per mapping.  For direct calls the target match already selects
            # the executed copy; for indirect calls prefer the executed map.
            if executed is not None:
                executed_matches = [m for m in matches
                                    if executed["address"] <= m[0]
                                    < executed["address"] + executed["size"]]
                if executed_matches:
                    matches = executed_matches
            records.append(sorted(matches)[0])

    return sorted(set(records))


def _decode_call_site(data: bytes) -> Tuple[str, Optional[int]]:
    """Return (direct/indirect/other, direct target) for an x86-64 call."""
    i = 0
    prefixes = {
        0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65,
        0x66, 0x67, 0xF0, 0xF2, 0xF3,
    }
    while i < len(data) and (data[i] in prefixes or 0x40 <= data[i] <= 0x4F):
        i += 1
    if i >= len(data):
        return "other", None
    if data[i] == 0xE8 and i + 5 <= len(data):
        displacement = struct.unpack_from("<i", data, i + 1)[0]
        return "direct", displacement
    if data[i] == 0xFF and i + 2 <= len(data):
        modrm = data[i + 1]
        if ((modrm >> 3) & 0x7) == 0x2:
            return "indirect", None
    return "other", None


def parse_e9patch_config(path: Path) -> Dict:
    """Parse e9patch's embedded e9_config_s from a patched binary.

    Returns a dict with:
      - loader_base: virtual address of the loader LOAD segment
      - loader_size: size of the loader LOAD segment (page-aligned)
      - entry: original entry point
      - reserves: list of (vaddr, size, prot) for RESERVE type mappings
      - trampolines: list of (vaddr, size, prot) for TRAMPOLINE type mappings
      - refactors: list of (vaddr, size, prot) for REFACTOR type mappings
    """
    with open(path, "rb") as f:
        data = f.read()

    pos = data.find(E9_CONFIG_MAGIC)
    if pos < 0:
        raise ValueError(f"e9patch config magic not found in {path}")

    fields = E9_CONFIG_STRUCT.unpack_from(data, pos)
    magic, version, flags, loader_size, base, entry, fini, mmap, \
        num_maps0, num_maps1, maps0_off, maps1_off, \
        num_preinits, preinits_off, num_postinits, postinits_off, \
        num_inits, inits_off, num_finis, finis_off, \
        num_traps, traps_off, handler = fields

    result = {
        "loader_base": base,
        "loader_size": loader_size,
        "entry": entry,
        "maps": [],
        "reserves": [],
        "trampolines": [],
        "refactors": [],
    }

    for level, num_maps, maps_off in [
        (0, num_maps0, maps0_off),
        (1, num_maps1, maps1_off),
    ]:
        map_start = pos + maps_off
        if map_start + num_maps * 12 > len(data):
            raise ValueError(f"e9patch config maps overflow in {path}")
        for i in range(num_maps):
            addr_s32, file_off_pages, bitfield = E9_MAP_STRUCT.unpack_from(
                data, map_start + i * 12
            )
            size_pages = bitfield & 0xFFFFF
            map_type = (bitfield >> 20) & 0x3
            r = (bitfield >> 28) & 1
            w = (bitfield >> 29) & 1
            x = (bitfield >> 30) & 1
            absolute = bool((bitfield >> 31) & 1)

            vaddr = addr_s32 * PAGE_SIZE
            vsize = size_pages * PAGE_SIZE
            prot = f"{'r' if r else '-'}{'w' if w else '-'}{'x' if x else '-'}"
            mapping = {
                "address": vaddr,
                "file_offset": file_off_pages * PAGE_SIZE,
                "size": vsize,
                "type": E9MapType(map_type),
                "prot": prot,
                "absolute": absolute,
            }
            result["maps"].append(mapping)

            # type_name = ["TRAMPOLINE", "RESERVE", "REFACTOR"][map_type]
            if map_type == E9MapType.RESERVE:
                result["reserves"].append((vaddr, vsize, prot))
            elif map_type == E9MapType.TRAMPOLINE:
                result["trampolines"].append((vaddr, vsize, prot))
            elif map_type == E9MapType.REFACTOR:
                result["refactors"].append((vaddr, vsize, prot))

    return result


def run_fix(configdir: Path, config_path: Path, workdir: Path):
    print(f"Running fix command in {workdir} with config {config_path}")
    result = subprocess.run(["just", "fix", str(workdir)], cwd=configdir, env=os.environ.copy(), capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running fix: {result.stderr}")
    else:
        print(f"Fix output: {result.stdout}")


def extract_e9_runtime_metadata(
    patched_binary: Path,
    metadata_path: Optional[Path] = None,
    original_binary: Optional[Path] = None,
    patch_addr: Optional[int] = None,
) -> E9RuntimeMetadata:
    """Extract the exact E9 runtime metadata of one patched artifact.

    The exclusion list is the exact union of the loader interval, every
    RESERVE map, and every TRAMPOLINE map of the parsed artifact.  REFACTOR
    maps execute relocated original instructions at original virtual
    addresses and are never excluded.  An excluded map with the absolute
    flag set is rejected: the current setup only emits relative mappings,
    and applying load_bias to an absolute address would be wrong.
    """
    cfg = parse_e9patch_config(patched_binary)
    loader_base = cfg["loader_base"]
    loader_size = cfg["loader_size"]
    ranges: List[Tuple[int, int]] = [
        (loader_base, loader_base + loader_size)]
    print(f"E9 loader range: 0x{loader_base:x}-0x{loader_base + loader_size:x}")

    for mapping in cfg["maps"]:
        if mapping["type"] == E9MapType.REFACTOR:
            continue
        if mapping["absolute"]:
            raise ValueError(
                f"absolute E9 {mapping['type'].name} map at "
                f"0x{mapping['address']:x} is not supported: setup only "
                f"emits relative mappings")
        ranges.append((mapping["address"],
                       mapping["address"] + mapping["size"]))
    exclude_ranges = normalize_address_ranges(ranges)
    print(f"E9 exclude ranges: {serialize_exclude_ranges(exclude_ranges)}")

    relocated_calls: Tuple[Tuple[int, int, int], ...] = ()
    if metadata_path is not None and original_binary is not None \
            and patch_addr is not None:
        call_jumps = extract_relocated_call_jumps(
            patched_binary,
            metadata_path,
            original_binary,
            patch_addr,
        )
        relocated_calls = tuple(sorted(set(call_jumps)))
        if relocated_calls:
            print(f"E9 relocated call jump(s): "
                  f"{E9RuntimeMetadata((), relocated_calls).relocated_calls_str()}")
        else:
            print("No relocated call-equivalent jump found for the patch site")

    return E9RuntimeMetadata(exclude_ranges, relocated_calls)


def prepare_patch(configdir: Path, workdir: Path, binradar_env: Dict[str, str]):
    print(f"Preparing patch in {workdir}")
    predicates_file = workdir / "predicates"
    original_binary = workdir / f"{binradar_env['BINARY']}.orig"
    brpatched_binary = workdir / f"{binradar_env['BINARY']}.brpatched"

    if not original_binary.exists():
        print(f"Error: original binary {original_binary.name} not found in {workdir}")
        exit(1)

    # Classify the workdir before any predicate parsing (plan §6.1).
    try:
        family, allocator = detect_predicate_family(workdir)
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)
    binradar_env["BINRADAR_PATCH_KIND"] = family.value

    if family == PredicateFamily.CWE805_DIRECT:
        assert allocator is not None
        binradar_env["PATCH_TYPE"] = family.value
        binradar_env["TAOSC_TOTAL_PATCHES"] = "1"
        binradar_env["PREFILTER_TOTAL_PATCHES"] = "1"
        # The direct call-site metapatch has no predicate list: the E9
        # jnz($mem0,mem[0].size,dest) decision evaluates the complete access
        # against the allocation clamps.  A leftover predicates file is stale Taosc
        # output and must not be compiled in.  The binary is rebuilt with
        # BinRadar patch-id switching and [patch] logging (plan §7.4).
        if predicates_file.exists():
            print(f"Warning: ignoring stale {predicates_file.name} "
                  f"(CWE-805 direct call-site family)")
        binradar_env["TOTAL_PATCHES"] = "1"
        dest = None
        destinations_file = workdir / "destinations"
        if destinations_file.exists():
            with destinations_file.open("r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        dest = f"0x{line}"
                        break
        if dest is None:
            print(f"Error: no destination found in {destinations_file}")
            exit(1)
        brpatch_source = workdir / "brpatch.c"
        shutil.copy(BRPATCH_SOURCE, brpatch_source)
        brpatches_inc = workdir / "brpatches.inc"
        _emit_brpatches_inc(brpatches_inc, [])
        compile_defines = [f"-DTAOSC_DEST={dest}", "-DBRPATCH_CWE805",
                           f"-DBRPATCH_ALLOC_{allocator.kind.upper()}"]
        cmd = ["guix", "shell", "e9patch@1.0.1", "--",
                "e9compile", "brpatch.c"] + compile_defines
        print(" ".join(cmd))
        result = subprocess.run(cmd, cwd=workdir)
        if result.returncode != 0:
            print(f"Error compiling patch: {result.stderr}")
            exit(1)
        else:
            print(f"Patch compiled successfully")

        # Patch the original binary with the allocator hooks and the
        # jnz(mem[0].base,mem[0].index,mem[0].scale,mem[0].disp,
        #     mem[0].size,dest) decision at the patch site. Taosc's $mem0
        # expands to the first four fields; mem[0].size preserves joob's
        # complete-access boundary check.
        patch_addr = binradar_env["PATCH_LOC"]
        metadata_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
        spec = build_instrumentation_spec(
            allocator, patch_addr,
            f"if jnz({E9_MEM0_ACCESS},{dest})@brpatch goto")
        cmd = e9tool_command(spec, metadata_path, original_binary, fmt="json")
        print(" ".join(cmd))
        result = subprocess.run(cmd, cwd=workdir)
        if result.returncode != 0:
            print(f"Error dumping patch metadata: {result.stderr}")
            exit(1)
        else:
            print(f"Patch metadata dumped successfully")
        cmd = e9tool_command(spec, brpatched_binary, original_binary)
        print(" ".join(cmd))
        result = subprocess.run(cmd, cwd=workdir)
        if result.returncode != 0:
            print(f"Error preparing patch: {result.stderr}")
            exit(1)
        else:
            print(f"Prepare patch succeeded, patched binary at {brpatched_binary}")

        metadata = extract_e9_runtime_metadata(
            brpatched_binary,
            metadata_path,
            original_binary,
            int(patch_addr, 0),
        )
        binradar_utils.set_e9_metadata(
            binradar_env, "brpatched",
            metadata.exclude_ranges_str(), metadata.relocated_calls_str())
        print(f"Using CWE-805 direct call-site patch at "
              f"{binradar_env['PATCH_LOC']} (candidate id 1)")
        build_cached_artifact(
            workdir, configdir, binradar_env, family, allocator, [])
        return

    if family == PredicateFamily.TAOSC_SPECIALIZED:
        # No predicates: taosc generated a specialized (CWE-369/476/617)
        # patch.  Reuse the prebuilt binary when present.
        binradar_env["PATCH_TYPE"] = family.value
        binradar_env["TAOSC_TOTAL_PATCHES"] = "1"
        binradar_env["PREFILTER_TOTAL_PATCHES"] = "1"
        if brpatched_binary.exists():
            metadata_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
            patch_addr = int(binradar_env["PATCH_LOC"], 0)
            metadata = extract_e9_runtime_metadata(
                brpatched_binary,
                metadata_path if metadata_path.exists() else None,
                original_binary,
                patch_addr,
            )
            binradar_utils.set_e9_metadata(
                binradar_env, "brpatched",
                metadata.exclude_ranges_str(), metadata.relocated_calls_str())
            binradar_env["TOTAL_PATCHES"] = "1"
            print(f"Using existing brpatched binary at {brpatched_binary} to extract trampoline info.")
            build_cached_artifact(
                workdir, configdir, binradar_env, family, allocator, [])
            return
        # No prebuilt binary and no predicates: build the artifacts with
        # zero candidates (TOTAL_PATCHES=0); binradar.py handles the
        # no-patch case.
        binradar_env["TAOSC_TOTAL_PATCHES"] = "0"
        binradar_env["PREFILTER_TOTAL_PATCHES"] = "0"
        print(f"Warning: no {predicates_file.name} and no prebuilt "
              f"brpatched binary in {workdir}; building with zero "
              f"candidate patches")

    # GENERIC_ERM or CWE805_ERM: parse every line strictly.  A missing
    # predicates file (specialized family without a prebuilt binary) is
    # treated as an empty list.
    predicate_records: List[PredicateRecord] = []
    if predicates_file.exists():
        try:
            predicate_records = _parse_predicate_records(predicates_file,
                                                         family)
        except ValueError as e:
            print(f"Error: {e}")
            exit(1)
    if not predicate_records:
        # Empty predicate list: build the artifacts with zero candidates
        # (TOTAL_PATCHES=0); binradar.py handles the no-patch case.
        print(f"Warning: {predicates_file.name} is empty in {workdir}; "
              f"building with zero candidate patches")

    # PATCH_TYPE and the patch counters describe the pipeline inputs:
    # TAOSC_TOTAL_PATCHES counts the predicates Taosc generated, and
    # PREFILTER_TOTAL_PATCHES the ones that survive the offline prefilter
    # (or all of them when no prefilter ran or it failed open).
    binradar_env["PATCH_TYPE"] = family.value
    binradar_env["TAOSC_TOTAL_PATCHES"] = str(len(predicate_records))
    binradar_env["PREFILTER_TOTAL_PATCHES"] = str(len(predicate_records))

    patch_records = [
        PredicateRecord(patch_id, record.source_line, record.source_text,
                        record.parsed)
        for patch_id, record in enumerate(predicate_records, start=1)
    ]
    # Apply the offline prefilter results, if any (see the `prefilter`
    # subcommand).  Predicates whose prefilter row evaluates to true
    # survive; the rest are discarded before the top-30 cap, so the
    # binradar pipeline never runs on patches that would be filtered out
    # anyway.  Fail open on any parse trouble.  The prefilter metadata
    # (family + predicates-file SHA-256) must match, so a stale prefilter
    # from a different predicate file or family is never applied.
    prefilter_file = workdir / "prefilter.sbsv"
    if prefilter_file.exists():
        passed_ids = load_prefilter_passed_ids(
            prefilter_file,
            expected_kind=family.value,
            expected_sha256=predicates_sha256(predicates_file),
        )
        if passed_ids is None:
            print(f"Warning: failed to parse {prefilter_file.name} "
                  f"(or metadata mismatch); using all predicates (fail-open)")
        else:
            predicate_by_id = {record.source_line: record
                               for record in predicate_records}
            survived = list()
            for source_id, new_id in sorted(
                    passed_ids.items(), key=lambda item: item[1]):
                record = predicate_by_id.get(source_id)
                if record is not None:
                    survived.append(PredicateRecord(
                        new_id, record.source_line, record.source_text,
                        record.parsed))
            print(f"[prefilter] loaded {len(predicate_records)} predicates, "
                  f"{len(survived)} survived")
            binradar_env["PREFILTER_TOTAL_PATCHES"] = str(len(survived))
            patch_records = survived

    # Get patch destination
    destinations_file = workdir / "destinations"
    if not destinations_file.exists():
        print(f"Error: {destinations_file.name} file not found in {workdir}")
        exit(1)
    dest = None
    with destinations_file.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            dest = f"0x{line}" # Use first line
            break
    if dest is None:
        print(f"Error: no destination found in {destinations_file}")
        exit(1)
    # Generate brpatches.inc
    # Currently, we only select top 30 patches.
    # Runtime patch IDs are compact and start at 1.  Each selected record
    # retains the original predicate source line for traceability.
    selected_patch_records = patch_records[:30]
    patch_cnt = len(selected_patch_records)
    binradar_env["TOTAL_PATCHES"] = str(patch_cnt)
    brpatch_source = workdir / "brpatch.c"
    shutil.copy(BRPATCH_SOURCE, brpatch_source)
    brpatches_inc = workdir / "brpatches.inc"
    _emit_brpatches_inc(brpatches_inc, selected_patch_records)
    compile_defines = [f"-DTAOSC_DEST={dest}"]
    if family == PredicateFamily.CWE805_ERM:
        assert allocator is not None
        compile_defines.append("-DBRPATCH_CWE805")
        compile_defines.append(f"-DBRPATCH_ALLOC_{allocator.kind.upper()}")
    cmd = ["guix", "shell", "e9patch@1.0.1", "--",
            "e9compile", "brpatch.c"] + compile_defines
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error compiling patch: {result.stderr}")
        exit(1)
    else:
        print(f"Patch compiled successfully")

    # Patch the original binary.  The JSON-metadata and final-binary e9tool
    # commands use one identical ordered instrumentation specification
    # (plan §6.3): generic ERM patches the single PATCH_LOC site; CWE-805
    # ERM and direct builds add the allocator hooks (mark/set_size/set_base)
    # before the patch site.
    patch_addr = binradar_env["PATCH_LOC"]
    metadata_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
    if family == PredicateFamily.CWE805_ERM:
        assert allocator is not None
        spec = build_instrumentation_spec(
            allocator, patch_addr, "if dest(state)@brpatch goto")
    elif family == PredicateFamily.CWE805_DIRECT:
        spec = build_instrumentation_spec(
            allocator, patch_addr,
            f"if jnz({E9_MEM0_ACCESS},{dest})@brpatch goto")
    else:
        spec = InstrumentationSpec(
            ((patch_addr, "if dest(state)@brpatch goto"),))
    # dump metadata
    cmd = e9tool_command(spec, metadata_path, original_binary, fmt="json")
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error dumping patch metadata: {result.stderr}")
        exit(1)
    else:
        print(f"Patch metadata dumped successfully")
    cmd = e9tool_command(spec, brpatched_binary, original_binary)
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error preparing patch: {result.stderr}")
        exit(1)
    else:
        print(f"Prepare patch succeeded, patched binary at {brpatched_binary}")

    metadata = extract_e9_runtime_metadata(
        brpatched_binary,
        metadata_path,
        original_binary,
        int(patch_addr, 0),
    )
    binradar_utils.set_e9_metadata(
        binradar_env, "brpatched",
        metadata.exclude_ranges_str(), metadata.relocated_calls_str())
    build_cached_artifact(
        workdir, configdir, binradar_env, family, allocator,
        selected_patch_records)


def create_binradar_env(configdir: Path, config_path: Path, workdir: Path) -> Dict[str, str]:
    # Start from the workdir's existing binradar.env (e.g. PREFILTER_* keys
    # persisted by the prefilter phase) so setup's save_env never clobbers
    # other artifacts' metadata; config.env overlays the subject fields.
    env = dict()
    env_path = workdir / "binradar.env"
    if env_path.exists():
        env = load_env(env_path)
        # The removed unprefixed E9 storage keys must not survive.
        env.pop("E9_EXCLUDE_RANGES", None)
        env.pop("E9_RELOCATED_CALL_JUMPS", None)
    env.update(load_env(config_path))
    if "POC_INPUT" not in env:
        print("Error: POC_INPUT not found in config.env")
        exit(1)
    if "POC_DIR" not in env:
        print("Error: POC_DIR not found in config.env")
        exit(1)
    if not (configdir / env["POC_DIR"]).exists():
        shutil.copytree(configdir / env["POC_DIR"], workdir / env["POC_DIR"])

    patch_location_file = workdir / "patch-location"
    if not patch_location_file.exists():
        print(f"Error: {patch_location_file.name} file not found in {workdir}")
        exit(1)
    with patch_location_file.open("r") as f:
        patch_location = f.read().strip()
        env["PATCH_LOC"] = f"0x{patch_location}"
    return env


def cmd_setup(configdir: Path, workdir: Path):
    config_path = configdir / "config.env"
    if not config_path.exists():
        print(f"Error: config.env not found in {configdir}")
        return

    if not workdir.exists():
        print(f"Creating working directory at {workdir}")
        workdir.mkdir(parents=True, exist_ok=True)
        if not (workdir / "patch-location").exists():
            run_fix(configdir, configdir / "config.env", workdir)

    workdir = workdir.resolve()
    binradar_env = create_binradar_env(configdir, config_path, workdir)
    prepare_patch(configdir, workdir, binradar_env)
    binradar_env_path = workdir / "binradar.env"
    save_env(binradar_env, binradar_env_path)
    print(f"binradar environment variables saved to {binradar_env_path}")


def cmd_prefilter(configdir: Path, workdir: Path):
    configdir = configdir.resolve()
    workdir = workdir.resolve()
    prefilter_file = workdir / "prefilter.sbsv"
    start = time.time()

    config_path = configdir / "config.env"
    if not config_path.exists():
        print(f"Error: config.env not found in {configdir}")
        sys.exit(1)
    config = load_env(config_path)

    predicates_file = workdir / "predicates"
    if not predicates_file.exists():
        # No predicates (CWE synth path); nothing to prefilter.
        print(f"No {predicates_file.name} file in {workdir}; skipping prefilter.")
        sys.exit(0)

    # Classify the workdir first (plan §6.1): the CWE-805 direct family
    # has no predicate list to compact, so the prefilter is a no-op and
    # FILTER remains the behavioral gate.
    try:
        family, allocator = detect_predicate_family(workdir)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    if family == PredicateFamily.CWE805_DIRECT:
        print(f"Workdir is {family.value}; prefilter is a no-op "
              "(FILTER is the behavioral gate).")
        sys.exit(0)

    predicate_records = load_predicates(predicates_file)
    if not predicate_records:
        write_prefilter(prefilter_file, [], time.time() - start,
                        kind=family.value,
                        sha256=predicates_sha256(predicates_file))
        print("No predicates; prefilter is a no-op.")
        sys.exit(0)

    for key in ("BINARY", "POC_INPUT", "TEST_CMD"):
        if key not in config:
            print(f"Error: {key} not found in config.env")
            sys.exit(1)
    patch_location_file = workdir / "patch-location"
    if not patch_location_file.exists():
        print(f"Error: {patch_location_file.name} file not found in {workdir}")
        sys.exit(1)
    patch_loc = f"0x{patch_location_file.read_text().strip()}"

    if family == PredicateFamily.CWE805_ERM:
        # Full-context prefilter (plan §8): the capture binary carries the
        # same allocator hooks as the final binary and dumps binary
        # snapshots (clamps + registers + stack) at the patch site.  A
        # candidate passes iff it branches on at least one complete
        # captured state.  Truncation fails open (never rejects).
        assert allocator is not None
        stack_size_file = workdir / "stack-size"
        if not stack_size_file.exists():
            print(f"Error: {stack_size_file.name} file not found in "
                  f"{workdir} (CWE-805 prefilter needs the stack size)")
            sys.exit(1)
        stack_size = int(stack_size_file.read_text().strip())
        snapshots = capture_states(workdir, configdir, config, patch_loc,
                                   allocator, stack_size)
        if snapshots is None:
            print("Warning: CWE-805 prefilter capture failed; keeping all "
                  "predicates (fail-open)")
            results = [(source_id, True, "capture failed (fail-open)",
                        predicate)
                       for source_id, predicate in predicate_records]
            write_prefilter(prefilter_file, results, time.time() - start,
                            kind=family.value,
                            sha256=predicates_sha256(predicates_file))
            sys.exit(0)
        if not snapshots:
            print("Warning: patch site never hit on the POC; discarding "
                  "all predicates")
            results = [(source_id, False, "patch site never hit",
                        predicate)
                       for source_id, predicate in predicate_records]
            write_prefilter(prefilter_file, results, time.time() - start,
                            kind=family.value,
                            sha256=predicates_sha256(predicates_file))
            sys.exit(0)

        print(f"Captured {len(snapshots)} CWE-805 snapshot(s)")
        results = []
        for source_id, predicate in predicate_records:
            parsed = parse_CWE805_predicate(predicate)
            passed = any(
                CWE805_snapshot_branch_taken(parsed, snapshot) == 1
                for snapshot in snapshots)
            note = "" if passed else \
                "evaluates to 0 on all captured snapshots"
            results.append((source_id, passed, note, predicate))
        write_prefilter(prefilter_file, results, time.time() - start,
                        kind=family.value,
                        sha256=predicates_sha256(predicates_file))
        sys.exit(0)

    states = capture_states(workdir, configdir, config, patch_loc)
    if states is None:
        # Fail open, matching run_filter's `result is None -> passed=True`.
        print("Warning: prefilter capture failed; keeping all predicates "
              "(fail-open)")
        results = [(source_id, True, "capture failed (fail-open)", predicate)
                   for source_id, predicate in predicate_records]
        write_prefilter(prefilter_file, results, time.time() - start,
                        kind=family.value,
                        sha256=predicates_sha256(predicates_file))
        sys.exit(0)
    if not states:
        # The patch site is never hit on the POC, so every predicate would
        # be filtered out by the FILTER phase anyway (the patch never
        # activates and the POC still crashes at the original fault).
        print("Warning: patch site never hit on the POC; discarding all "
              "predicates")
        results = [(source_id, False, "patch site never hit", predicate)
                   for source_id, predicate in predicate_records]
        write_prefilter(prefilter_file, results, time.time() - start,
                        kind=family.value,
                        sha256=predicates_sha256(predicates_file))
        sys.exit(0)

    print(f"Captured {len(states)} patch-site state vector(s)")
    results = []
    next_new_id = 0
    for source_id, predicate in predicate_records:
        passed, note = evaluate_predicate(predicate, states)
        if passed:
            next_new_id += 1
        if note:
            new_id = next_new_id if passed else -1
            print(f"[prefilter] [res] [id {source_id}] "
                  f"[pass {str(passed).lower()}] [new-id {new_id}] "
                  f"{predicate!r}: {note}")
        results.append((source_id, passed, note, predicate))
    write_prefilter(prefilter_file, results, time.time() - start,
                    kind=family.value,
                    sha256=predicates_sha256(predicates_file))


def main():
    parser = argparse.ArgumentParser(
        description="binradar-setup: setup the binradar workdir and "
                    "prefilter candidate patches")
    subparsers = parser.add_subparsers(
        dest="command", required=True, metavar="setup|prefilter")

    setup_parser = subparsers.add_parser(
        "setup", help="generate <BINARY>.brpatched and binradar.env")
    setup_parser.add_argument("-c", "--configdir", type=Path, required=False,
                              default=Path.cwd(),
                              help="Config directory (default: current directory)")
    setup_parser.add_argument("-w", "--workdir", type=Path, required=False,
                              default=Path.cwd() / "workdir",
                              help="Working directory (default: ./workdir)")

    prefilter_parser = subparsers.add_parser(
        "prefilter", help="evaluate predicates offline against the POC and "
                          "write prefilter.sbsv")
    prefilter_parser.add_argument("-c", "--configdir", type=Path, required=False,
                                  default=Path.cwd(),
                                  help="Directory containing config.env "
                                       "(default: current directory)")
    prefilter_parser.add_argument("-w", "--workdir", type=Path,
                                  default=Path.cwd() / "workdir",
                                  help="Working directory (default: ./workdir)")

    args = parser.parse_args()
    if args.command == "setup":
        cmd_setup(args.configdir, args.workdir)
    else:
        cmd_prefilter(args.configdir, args.workdir)


if __name__ == "__main__":
    main()
