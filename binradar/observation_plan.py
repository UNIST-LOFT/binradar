"""Validated runtime observation plans, generated tables and artifact binding.

This module never reads guest memory. Runtime authority comes from the exact
original/plan/patched artifact hashes, not from a CRC or an environment FD.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

from . import paths

REGISTERS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
ZERO_SHA256 = "0" * 64
PROBE_MARKER = bytes.fromhex("0f1f840042524f420f05c3")
PROBE_SYSCALL_OFFSET = 8
RUNTIME_ENVIRONMENT_KEYS = ("BINRADAR_BROBS_PC", "BINRADAR_BROBS_COUNT",
                            "BINRADAR_BROBS_CRC32", "BINRADAR_BROBS_SHA256")
_MAX_STACK = 1024 * 1024
_MAX_SLOTS = 64
_KIND = {"reg": 0, "global": 1, "deref_chain": 2, "heap_meta": 3}
_ROOT = {"reg": 0, "stack": 1, "global": 2, "alloc_site": 3}
_META = {"obj_size": 0, "obj_remaining": 1, "is_live": 2, "obj_offset": 3}
_ALLOCATORS = {"malloc": 0, "calloc": 1, "realloc": 2, "free": 3,
               "__libc_malloc": 0, "__libc_calloc": 1, "__libc_realloc": 2,
               "__libc_free": 3}


def zero_observation_binding() -> dict:
    return {"schema_version": 1, "count": 0, "plan_sha256": ZERO_SHA256, "plan_crc32": 0}


def cleared_observation_environment() -> dict[str, str]:
    return dict(zip(RUNTIME_ENVIRONMENT_KEYS, ("0", "0", "0", ZERO_SHA256)))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate observation JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError(f"missing/invalid observation metadata: {path}")
    result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(result, dict):
        raise ValueError("observation metadata must be an object")
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _integer(value, low=0, high=(1 << 64) - 1) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid observation integer/range")
    return value


def _address(value) -> int:
    if type(value) is int:
        return _integer(value)
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value):
        raise ValueError("observation address must be hexadecimal ELF VA")
    return int(value, 16)


def _hash(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid observation SHA-256")
    return value


def _validate_plan(plan: dict) -> list[dict]:
    if plan.get("schema_version") != 1:
        raise ValueError("unsupported observation plan schema")
    slots = plan.get("slots")
    if not isinstance(slots, list) or len(slots) > _MAX_SLOTS:
        raise ValueError("invalid observation slot count")
    if plan.get("analysis_status") not in ("ok", "no_additional_separating_slot"):
        raise ValueError("observation plan is incomplete or diagnostic-only")
    if slots and plan.get("analysis_status") != "ok":
        raise ValueError("non-successful observation plan contains slots")
    _hash(plan.get("artifact_orig_sha256"))
    _address(plan.get("patch_location"))
    for index, slot in enumerate(slots):
        if not isinstance(slot, dict) or slot.get("id") != index or type(slot.get("id")) is not int:
            raise ValueError("observation slot IDs must be consecutive from zero")
        kind = slot.get("kind")
        if kind not in _KIND or slot.get("width") not in (1, 2, 4, 8) or type(slot.get("width")) is not int:
            raise ValueError("unsupported observation slot kind/width")
        if type(slot.get("signed")) is not bool:
            raise ValueError("observation signedness must be explicit")
        offsets = slot.get("offsets", [])
        if not isinstance(offsets, list) or len(offsets) > 4:
            raise ValueError("invalid observation access depth")
        for offset in offsets:
            _integer(offset, -(1 << 31), (1 << 31) - 1)
        if kind == "global":
            _address(slot.get("rva"))
            if offsets:
                raise ValueError("direct global cannot have dereference offsets")
            continue
        root = slot.get("root")
        if not isinstance(root, dict) or root.get("kind") not in _ROOT:
            raise ValueError("invalid observation root")
        root_kind = root["kind"]
        if root_kind == "reg" and root.get("reg") not in REGISTERS:
            raise ValueError("invalid observation register")
        if root_kind == "global":
            _address(root.get("rva"))
        if root_kind == "stack":
            _integer(root.get("offset"), 0, _MAX_STACK - 8)
        if root_kind == "alloc_site":
            _address(root.get("site_pc"))
            if root.get("selection") != "last":
                raise ValueError("only last-allocation site roots are supported")
        if kind == "reg" and (root_kind != "reg" or offsets):
            raise ValueError("direct register slot cannot dereference")
        if kind == "deref_chain" and not offsets:
            raise ValueError("dereference slot requires a leaf offset")
        if kind == "heap_meta" and (slot.get("meta_op") not in _META or slot["width"] != 8 or slot["signed"]):
            raise ValueError("invalid heap metadata operation/type")
    hooks = plan.get("alloc_hooks", [])
    if not isinstance(hooks, list) or len(hooks) > 4096:
        raise ValueError("invalid observation allocator sites")
    for hook in hooks:
        if not isinstance(hook, dict):
            raise ValueError("invalid observation allocator hook")
        _address(hook.get("call_pc"))
    return slots


def load_observation_binding(workdir: Path) -> dict:
    """Return the canonical plan identity; no plan means explicit zero slots."""
    path = Path(workdir) / "observation-plan.json"
    if not path.exists() and not path.is_symlink():
        return zero_observation_binding()
    plan = _read_json(path)
    slots = _validate_plan(plan)
    if not slots:
        return zero_observation_binding()
    import zlib
    encoded = _canonical(plan)
    return {"schema_version": 1, "count": len(slots),
            "plan_sha256": hashlib.sha256(encoded).hexdigest(),
            "plan_crc32": zlib.crc32(encoded) & 0xffffffff}


def _elf_regions(original: Path) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    with original.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 64 or not elf.little_endian or elf.get_machine_arch() != "x64":
            raise ValueError("observation runtime requires little-endian x86-64 ELF")
        executable, writable = [], []
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            interval = (segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"])
            if segment["p_flags"] & 1:
                executable.append(interval)
            if segment["p_flags"] & 2:
                writable.append(interval)
        return executable, writable


def _allocator_calls(original: Path) -> list[tuple[int, int, int]]:
    """Prove direct main-image allocator call/return PCs from disassembly.

    Never invent the return PC from a presumed five-byte CALL. Indirect calls
    and unrecognized wrappers do not satisfy a requested allocator-site root.
    """
    output = subprocess.check_output([paths.OBJDUMP_BIN, "-d", "--wide", "--", str(original)],
                                     text=True, timeout=20)
    found = []
    for line in output.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(callq?)\s+([0-9a-fA-F]+)\s+<([^>]+)>\s*$", line)
        if not match:
            continue
        name = match[5].split("@", 1)[0]
        if name not in _ALLOCATORS:
            continue
        pc = int(match[1], 16)
        found.append((pc, pc + len(match[2].split()), _ALLOCATORS[name]))
    if len(found) > 4096:
        raise ValueError("observation allocator call-site capacity exceeded")
    return sorted(set(found))


def prepare_observation_plan(workdir: Path, original: Path, patch_location: int,
                             *, configdir: Path | None = None) -> dict:
    """Write the mandatory generated table and shared guest runtime header."""
    workdir, original = Path(workdir), Path(original)
    target = workdir / "observation-plan.json"
    if configdir is not None and not target.exists():
        source = Path(configdir) / target.name
        if source.exists() and source.absolute() != target.absolute():
            _read_json(source)
            shutil.copyfile(source, target)
    binding = load_observation_binding(workdir)
    plan = _read_json(target) if target.exists() else None
    if plan is not None and (plan["artifact_orig_sha256"] != _sha256(original)
                             or _address(plan["patch_location"]) != patch_location):
        raise ValueError("observation plan original/patch-site binding mismatch")
    slots = plan["slots"] if plan is not None else []
    stack_path = workdir / "stack-size"
    stack_size = int(stack_path.read_text().strip(), 0) if stack_path.exists() else 0
    _integer(stack_size, 0, _MAX_STACK)
    executable, globals_ = _elf_regions(original) if slots else ([], [])
    if slots and not any(lo <= patch_location < hi for lo, hi in executable):
        raise ValueError("observation patch site is outside main executable text")
    needs_allocator = any(slot["kind"] in ("deref_chain", "heap_meta") for slot in slots)
    calls = _allocator_calls(original) if needs_allocator else []
    sites = {pc: index for index, (pc, _, _) in enumerate(calls)}
    if plan is not None and needs_allocator:
        for hook in plan.get("alloc_hooks", []):
            if _address(hook["call_pc"]) not in sites:
                raise ValueError("observation allocator site lacks a proved direct allocator call")
    rows = []
    for slot in slots:
        kind = slot["kind"]
        root = slot.get("root", {"kind": "global", "rva": slot.get("rva")})
        root_kind = root["kind"]
        root_index, root_rva = 0, 0
        if root_kind == "reg":
            root_index = REGISTERS.index(root["reg"])
        elif root_kind == "global":
            root_rva = _address(root["rva"])
            width = slot["width"] if kind == "global" else 8
            if not any(lo <= root_rva and root_rva + width <= hi for lo, hi in globals_):
                raise ValueError("observation global root is outside writable main ELF segments")
        elif root_kind == "stack":
            root_rva = root["offset"]
            if root_rva + 8 > stack_size:
                raise ValueError("observation stack root exceeds captured stack extent")
        else:
            site = _address(root["site_pc"])
            if site not in sites:
                raise ValueError("observation allocator root lacks a proved hook")
            root_index = sites[site]
        offsets = slot.get("offsets", [])
        fields = (_KIND[kind], _ROOT[root_kind], slot["width"], int(slot["signed"]),
                  len(offsets), _META.get(slot.get("meta_op"), 0), root_index)
        rows.append("    {" + ",".join(map(str, fields)) + f",0x{root_rva:x}ull,{{"
                    + ",".join(map(str, [*offsets, *([0] * (4 - len(offsets)))])) + "}},\n")
    lo = min((start for start, _ in globals_), default=0)
    hi = max((end for _, end in globals_), default=0)
    header = ("/* Generated from a validated, artifact-bound observation plan. */\n"
              f"#define BROBS_COUNT {binding['count']}u\n"
              f"#define BROBS_PLAN_CRC32 {binding['plan_crc32']}u\n"
              f"#define BROBS_PLAN_SHA256 \"{binding['plan_sha256']}\"\n"
              f"#define BROBS_PATCH_LOCATION 0x{patch_location:x}ull\n"
              f"#define BROBS_GLOBAL_BEGIN 0x{lo:x}ull\n"
              f"#define BROBS_GLOBAL_END 0x{hi:x}ull\n"
              f"#define BROBS_STACK_SIZE {stack_size}u\n"
              f"#define BROBS_ALLOC_SITE_COUNT {len(calls)}u\n"
              "static const struct brobs_slot brobs_slots[BROBS_COUNT ? BROBS_COUNT : 1] = {\n"
              + ("".join(rows) if rows else "    {0},\n") + "};\n"
              "static const uint64_t brobs_alloc_sites[BROBS_ALLOC_SITE_COUNT ? BROBS_ALLOC_SITE_COUNT : 1] = {"
              + (",".join(f"0x{pc:x}ull" for pc, _, _ in calls) if calls else "0") + "};\n")
    (workdir / "brobs_plan.inc").write_text(header, encoding="ascii")
    shutil.copyfile(paths.BR_OBSERVATION_SOURCE, workdir / "br-observation.h")
    return binding


def observation_instrumentation(workdir: Path, original: Path, spec, plugin_name: str):
    """Add bounded allocator entry/return hooks before the existing ordered spec."""
    from .binradar_taosc_predicates import InstrumentationSpec
    path = Path(workdir) / "observation-plan.json"
    if not path.exists():
        return spec
    plan = _read_json(path)
    slots = _validate_plan(plan)
    if not any(slot["kind"] in ("deref_chain", "heap_meta") for slot in slots):
        return spec
    entries = []
    for index, (pc, ret, kind) in enumerate(_allocator_calls(Path(original))):
        entries.append((hex(pc), f"brobs_alloc_enter({index},{kind},rdi,rsi,rsp)@{plugin_name}"))
        entries.append((hex(ret), f"brobs_alloc_leave({index},rax,rsp)@{plugin_name}"))
    return InstrumentationSpec(tuple([*entries, *spec.entries]), o0=True)


def _probe_pc(artifact: Path) -> int:
    # Reuse the authoritative E9 mapping parser rather than guessing a plugin
    # base from ELF LOADs (E9 may mmap RESERVE pages outside those LOADs).
    from .binradar_setup import E9MapType, parse_e9patch_config
    mappings = parse_e9patch_config(artifact)["maps"]
    data = artifact.read_bytes()
    found = []
    for mapping in mappings:
        if mapping["type"] != E9MapType.RESERVE:
            continue
        if mapping["absolute"] or mapping["prot"] != "r-x":
            continue
        offset, size = mapping["file_offset"], mapping["size"]
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("invalid observation plugin mapping")
        begin = offset
        while True:
            at = data.find(PROBE_MARKER, begin, offset + size)
            if at < 0:
                break
            found.append(mapping["address"] + at - offset + PROBE_SYSCALL_OFFSET)
            begin = at + 1
    if len(set(found)) != 1:
        raise ValueError("expected exactly one read-only executable observation probe thunk")
    return _integer(found[0])


def publish_artifact_observations(artifact: Path, original: Path) -> None:
    """Bind runtime authority only after the real E9 artifact has been built."""
    artifact, original = Path(artifact), Path(original)
    binding = load_observation_binding(artifact.parent)
    sidecar = Path(str(artifact) + ".brobs.json")
    sidecar.unlink(missing_ok=True)
    payload = {"schema_version": 1, "artifact_sha256": _sha256(artifact),
               "original_sha256": _sha256(original),
               "count": binding["count"], "plan_sha256": binding["plan_sha256"],
               "plan_crc32": binding["plan_crc32"],
               "probe_pc": _probe_pc(artifact) if binding["count"] else 0}
    temporary = sidecar.with_suffix(".json.part")
    temporary.write_bytes(_canonical(payload) + b"\n")
    temporary.replace(sidecar)


def artifact_observation_environment(artifact: Path, *, original: Path | None = None) -> dict[str, str]:
    """Validate selected artifact/plan hashes before enabling native authority."""
    artifact = Path(artifact)
    if artifact.suffix == ".orig":
        return cleared_observation_environment()
    original = Path(original) if original is not None else artifact.with_suffix(".orig")
    sidecar = _read_json(Path(str(artifact) + ".brobs.json"))
    binding = load_observation_binding(artifact.parent)
    if (sidecar.get("schema_version") != 1 or sidecar.get("artifact_sha256") != _sha256(artifact)
            or sidecar.get("original_sha256") != _sha256(original)
            or any(sidecar.get(key) != binding[key] for key in ("count", "plan_sha256", "plan_crc32"))):
        raise ValueError("observation artifact/original/plan identity mismatch")
    if binding["count"]:
        plan = _read_json(artifact.parent / "observation-plan.json")
        if plan["artifact_orig_sha256"] != sidecar["original_sha256"]:
            raise ValueError("observation original identity mismatch")
        pc = _integer(sidecar.get("probe_pc"), 1)
        if _probe_pc(artifact) != pc:
            raise ValueError("observation probe thunk identity mismatch")
    else:
        if sidecar.get("probe_pc") != 0:
            raise ValueError("zero-observation artifact has a probe capability")
        pc = 0
    return {"BINRADAR_BROBS_PC": hex(pc) if pc else "0",
            "BINRADAR_BROBS_COUNT": str(binding["count"]),
            "BINRADAR_BROBS_CRC32": str(binding["plan_crc32"]),
            "BINRADAR_BROBS_SHA256": binding["plan_sha256"]}
