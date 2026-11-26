"""Offline, bounded observation planning from version-1 semantic traces.

This module reads only supplied records. It neither executes a guest nor reads
process memory; an incomplete capture can never produce an accepted slot.
"""
from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass
import json


_REGS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
_WIDTHS = (8, 4, 2, 1)
_MAX_EVENTS = 2_000_000
_MAX_BYTES = 16 * 1024 * 1024
_MAX_REGIONS = 2050
_MAX_WORK = 65536
_MAX_CANDIDATES = 8192
_MAX_SEARCH = 8192
_MAX_POINTER_CELLS = 256
_ROLE = {"direct_fault": 0, "control_dep": 1, "addr_dep": 2}
_U64 = (1 << 64) - 1


class _Reject(Exception):
    def __init__(self, code):
        self.code = code


def _integer(value, minimum=0, maximum=_U64):
    if type(value) is not int or not minimum <= value <= maximum:
        raise _Reject("malformed_trace")
    return value


def _ids(value):
    if not isinstance(value, list) or len(value) > 256:
        raise _Reject("malformed_trace")
    for item in value:
        _integer(item, maximum=65535)
    return value


def _interval(record, key="addr"):
    addr = _integer(record[key])
    size = _integer(record["size"], 1, _MAX_BYTES)
    if addr + size > _U64 + 1:
        raise _Reject("malformed_trace")
    return addr, addr + size


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass
class _Region:
    kind: str
    base: int
    size: int
    data: bytes
    init: bytes
    state: str
    site: int | None
    object_id: int
    generation: int
    pointers: tuple
    ordinal: int = 0

    def initialized(self, offset, width):
        return all(self.init[i >> 3] & (1 << (i & 7))
                   for i in range(offset, offset + width))


@dataclass
class _Visit:
    hit: int
    regs: tuple
    bias: int
    regions: list
    events: list
    outcome: str
    case: str
    perturb: int

    def __post_init__(self):
        if any(r.kind == "global" and r.base < self.bias for r in self.regions):
            raise _Reject("invalid_global_range")
        self._live = sorted((r for r in self.regions if r.state == "live"),
                            key=lambda r: r.base)
        self._bases = [r.base for r in self._live]
        self._retired = sorted((r for r in self.regions if r.state == "freed"),
                               key=lambda r: (r.generation, r.object_id), reverse=True)

    def region(self, addr):
        # Live regions do not overlap; retired allocations can overlap on reuse.
        index = bisect_right(self._bases, addr) - 1
        if index >= 0:
            region = self._live[index]
            if addr < region.base + region.size:
                return region
        return next((r for r in self._retired
                     if r.base <= addr < r.base + r.size), None)

    def identity(self, region, offset, width):
        if region.kind == "global":
            return ("global", region.base + offset - self.bias, width)
        if region.kind == "stack":
            return ("stack", region.base + offset - self.regs[4], width)
        return ("heap", region.site, region.ordinal, offset, width)

    def read(self, addr, width):
        if addr < 0 or addr > _U64 or addr + width > _U64 + 1:
            return "UNMAPPED", None, None
        region = self.region(addr)
        if region is None:
            return "UNMAPPED", None, None
        if region.state == "freed":
            return "FREED", None, None
        off = addr - region.base
        if off + width > region.size:
            return "OOB", None, None
        if not region.initialized(off, width):
            return "UNINIT_OBSERVED", None, None
        return ("OK", int.from_bytes(region.data[off:off + width], "little"),
                self.identity(region, off, width))

    def pointer_leaf(self, addr, width):
        region = self.region(addr)
        if region is None:
            return False
        off = addr - region.base
        for pointer in region.pointers:
            if off < pointer + 8 and pointer < off + width:
                return True
        # Reject fragments of an untagged, aligned live pointer as well.
        start = (addr // 8) * 8
        for cell in range(start, addr + width, 8):
            status, value, _ = self.read(cell, 8)
            if status == "OK" and self.region(value) is not None:
                return True
        return False


def _parse_regions(records):
    if not isinstance(records, list) or len(records) > _MAX_REGIONS:
        raise _Reject("snapshot_capacity")
    regions = []
    total = heaps = 0
    for record in records:
        kind = record["kind"]
        if kind not in ("heap", "global", "stack"):
            raise _Reject("unsupported_region")
        base, end = _interval(record, "base")
        size = end - base
        state = record.get("state", "live")
        if state not in ("live", "freed") or (kind != "heap" and state != "live"):
            raise _Reject("malformed_trace")
        if kind == "stack" and size > 4096:
            raise _Reject("snapshot_capacity")
        heaps += kind == "heap"
        total += size if state == "live" else 0
        if heaps > 2048 or total > _MAX_BYTES:
            raise _Reject("snapshot_capacity")
        data_text, init_text = record["data"], record["init"]
        if not isinstance(data_text, str) or not isinstance(init_text, str):
            raise _Reject("malformed_trace")
        # Validate lengths before decoding, including retired-object records.
        if state == "live" and (len(data_text) != size * 2 or
                                len(init_text) != ((size + 7) // 8) * 2):
            raise _Reject("incomplete_snapshot")
        if state == "freed" and (data_text or init_text):
            if (len(data_text) != size * 2 or
                    len(init_text) != ((size + 7) // 8) * 2):
                raise _Reject("incomplete_snapshot")
            total += size
            if total > _MAX_BYTES:
                raise _Reject("snapshot_capacity")
        data, init = bytes.fromhex(data_text), bytes.fromhex(init_text)
        pointers = record.get("pointer_offsets", [])
        if not isinstance(pointers, list) or len(pointers) > _MAX_BYTES // 8:
            raise _Reject("malformed_trace")
        for pointer in pointers:
            _integer(pointer, maximum=max(size - 8, 0))
            if pointer + 8 > size:
                raise _Reject("malformed_trace")
        site = record.get("alloc_pc")
        if site is not None:
            _integer(site)
        regions.append(_Region(kind, base, size, data, init, state, site,
                               _integer(record.get("object_id", 0)),
                               _integer(record.get("generation", 0)),
                               tuple(sorted(set(pointers)))))
    # Overlap is legitimate only for allocator reuse with distinct generations.
    ordered = sorted(regions, key=lambda r: (r.base, r.size))
    active = []
    for region in ordered:
        active = [other for other in active if other.base + other.size > region.base]
        for other in active:
            if (region.kind != "heap" or other.kind != "heap" or
                    (region.state == "live" and other.state == "live")):
                raise _Reject("overlapping_snapshot_regions")
        active.append(region)
    sites = defaultdict(list)
    for region in regions:
        if region.kind == "heap":
            sites[region.site].append(region)
    for objects in sites.values():
        for ordinal, region in enumerate(sorted(objects, key=lambda r: (
                r.object_id, r.generation))):
            region.ordinal = ordinal
    return regions


def _event(record):
    kind = record["kind"]
    _integer(record["pc"])
    if record.get("status", "ok") != "ok":
        raise _Reject(str(record["status"]))
    if kind == "def":
        _integer(record["dst"], maximum=65535)
        _ids(record["src"])
        width = _integer(record.get("width", 8), 1, 8)
        if width not in _WIDTHS:
            raise _Reject("unsupported_width")
    elif kind == "load":
        _interval(record)
        if record["size"] not in _WIDTHS:
            raise _Reject("unsupported_width")
        _integer(record["dst"], maximum=65535)
        _ids(record["addr_regs"])
    elif kind in ("store", "overwrite", "sys_read"):
        _interval(record)
        _ids(record["src"])
        if kind == "store":
            _ids(record["addr_regs"])
        if kind == "sys_read" and record["src"]:
            raise _Reject("malformed_trace")
    elif kind == "copy":
        _interval(record, "src_addr")
        _interval(record, "dst_addr")
    elif kind == "branch":
        _ids(record["src"])
        if type(record["taken"]) is not bool:
            raise _Reject("malformed_trace")
    elif kind in ("alloc", "free"):
        _integer(record["addr"])
        _integer(record["object_id"])
        _integer(record["generation"])
        _ids(record["src"])
        if kind == "alloc":
            _interval(record)
            if "dst" in record:
                _integer(record["dst"], maximum=65535)
    elif kind == "fault":
        _ids(record["regs"])
        if not isinstance(record["fault_kind"], str):
            raise _Reject("malformed_trace")
        if not isinstance(record["mem"], list) or len(record["mem"]) > 256:
            raise _Reject("malformed_trace")
        for memory in record["mem"]:
            _interval(memory)
        for key in ("object_id", "generation"):
            if key in record:
                _integer(record[key])
    else:
        raise _Reject("unsupported_event")
    if "signed" in record and type(record["signed"]) is not bool:
        raise _Reject("malformed_trace")


def _parse_run(run, patch_location, fault_reference):
    if (not isinstance(run["case_id"], str) or not run["case_id"] or
            run["outcome"] not in ("target_crash", "normal") or
            type(run["perturb"]) is not int or run["perturb"] not in (85, 170)):
        raise _Reject("malformed_run")
    records = run["records"]
    if not isinstance(records, list) or len(records) > _MAX_EVENTS + 1026:
        raise _Reject("window_overflow")
    if not records or records[0] != {"kind": "header", "schema_version": 1}:
        raise _Reject("unsupported_trace_schema")
    if records[-1].get("kind") != "end":
        raise _Reject("incomplete_capture")
    if records[-1].get("status") != "ok":
        raise _Reject(str(records[-1].get("status", "incomplete_capture")))
    visits = []
    fault_count = 0
    events = 0
    for record in records[1:-1]:
        if not isinstance(record, dict):
            raise _Reject("malformed_trace")
        if record.get("status", "ok") != "ok":
            raise _Reject(str(record["status"]))
        if record["kind"] == "patch":
            if fault_count:
                raise _Reject("malformed_event_order")
            hit = _integer(record["hit_id"])
            if visits and hit <= visits[-1].hit:
                raise _Reject("malformed_visit_order")
            if len(visits) >= 1024:
                raise _Reject("visit_capacity")
            if _integer(record["pc"]) != patch_location:
                raise _Reject("patch_location_mismatch")
            regs = record["regs"]
            if not isinstance(regs, list) or len(regs) != 16:
                raise _Reject("malformed_trace")
            for reg in regs:
                _integer(reg)
            visits.append(_Visit(hit, tuple(regs), _integer(record["load_bias"]),
                                 _parse_regions(record["regions"]), [],
                                 run["outcome"], run["case_id"], run["perturb"]))
        else:
            if not visits or fault_count:
                raise _Reject("malformed_event_order")
            _event(record)
            events += 1
            if events > _MAX_EVENTS:
                raise _Reject("window_overflow")
            visits[-1].events.append(record)
            if record["kind"] == "fault":
                fault_count += 1
                if record["pc"] != fault_reference:
                    raise _Reject("fault_reference_mismatch")
    if not visits:
        raise _Reject("patch_not_visited")
    if fault_count != (run["outcome"] == "target_crash"):
        raise _Reject("fault_outcome_mismatch")
    return visits


# Dependency labels retain the consumer's role and expression cooccurrence.
# Memory spans are half-open and are split, not rounded, at overlapping writes.
def _slice(visit, normals):
    events = visit.events
    fault = events[-1]
    labels = lambda role, group, width=8, signed=False: (role, group, width, signed)
    registers = defaultdict(set)
    memory = []
    terminals = []
    postread = set()
    groups = {"fault"}
    fault_label = labels("direct_fault", "fault")
    for reg in fault["regs"]:
        registers[reg].add(fault_label)
    for span in fault["mem"]:
        start, end = _interval(span)
        memory.append((start, end, fault_label))
    branches = [(i, event) for i, event in enumerate(events) if event["kind"] == "branch"]
    selected = {i for i, _ in branches[-16:]}
    divergences = set()
    for normal in normals:
        other = [event for event in normal.events if event["kind"] == "branch"]
        for index, (i, branch) in enumerate(branches):
            if index >= len(other) or (branch["pc"], branch["taken"]) != (
                    other[index]["pc"], other[index]["taken"]):
                selected.add(i)
                divergences.add(i)
                break
    metadata = []

    def add_regs(ids, deps, role=None):
        for reg in ids:
            for label in deps:
                registers[reg].add((role or label[0], *label[1:]))

    for index in range(len(events) - 2, -1, -1):
        event = events[index]
        kind = event["kind"]
        if kind == "branch" and index in selected:
            group = ("divergence:%d" if index in divergences else "branch:%d") % index
            groups.add(group)
            add_regs(event["src"], {labels("control_dep", group)})
        elif kind == "def":
            deps = registers.pop(event["dst"], set())
            deps = {(role, group, event.get("width", width), event.get("signed", signed))
                    for role, group, width, signed in deps}
            add_regs(event["src"], deps)
        elif kind == "load":
            deps = registers.pop(event["dst"], set())
            for role, group, _, _ in deps:
                memory.append((event["addr"], event["addr"] + event["size"],
                               labels(role, group, event["size"], event.get("signed", False))))
            add_regs(event["addr_regs"], deps, "addr_dep")
        elif kind in ("store", "overwrite", "copy", "sys_read", "alloc"):
            start = event["dst_addr"] if kind == "copy" else event["addr"]
            end = start + event["size"]
            remaining, transferred = [], []
            for lo, hi, label in memory:
                a, b = max(lo, start), min(hi, end)
                if a >= b:
                    remaining.append((lo, hi, label))
                    continue
                if lo < a:
                    remaining.append((lo, a, label))
                if b < hi:
                    remaining.append((b, hi, label))
                transferred.append(label)
                if kind == "copy":
                    # Append after the scan: memmove's overlapping input is a
                    # pre-event dependency, never another write in this event.
                    offset = event["src_addr"] - start
                    terminals.append((a + offset, b + offset, label))
                elif kind == "sys_read":
                    postread.add(label[:2])
            memory = remaining
            if kind == "copy":
                memory.extend(terminals)
                terminals.clear()
            elif kind in ("store", "overwrite"):
                add_regs(event["src"], transferred)
                add_regs(event.get("addr_regs", []), transferred, "addr_dep")
            elif kind == "alloc":
                deps = registers.pop(event.get("dst", -1), set())
                if (event["object_id"] == fault.get("object_id") and
                        event["generation"] == fault.get("generation")):
                    deps.add(fault_label)
                deps.update(transferred)
                add_regs(event["src"], deps)
        elif kind == "free" and (event["object_id"], event["generation"]) == (
                fault.get("object_id"), fault.get("generation")):
            add_regs(event["src"], {fault_label}, "addr_dep")
        if len(memory) + sum(map(len, registers.values())) > _MAX_WORK:
            raise _Reject("slice_capacity")
    for reg in registers:
        if reg >= 16 and registers[reg]:
            raise _Reject("undefined_scratch_dependency")
    # A fault object that existed at PATCH_LOC has observable allocator facts.
    for region in visit.regions:
        if region.kind == "heap" and (region.object_id, region.generation) == (
                fault.get("object_id"), fault.get("generation")):
            metadata.append((region.base, fault_label))
    return registers, memory, metadata, postread, groups


def _pointer_cells(visit, region):
    preferred = list(region.pointers[:_MAX_POINTER_CELLS])
    # The bound applies to examined cells, not just successful edges.
    preferred_set = set(preferred)
    offsets = list(preferred)
    for off in range((-region.base) % 8, region.size - 7, 8):
        if len(offsets) >= _MAX_POINTER_CELLS:
            break
        if off not in preferred_set:
            offsets.append(off)
    for off in offsets:
        status, value, _ = visit.read(region.base + off, 8)
        target = visit.region(value) if status == "OK" else None
        if target is not None and target.state == "live" and target.kind in ("heap", "global"):
            yield off, value


def _path_rank(slot):
    kind = slot["kind"]
    if kind in ("global", "reg"):
        return (0, 0, _canonical(slot))
    root = slot["root"]["kind"]
    depth = len(slot["offsets"])
    stack_register = root == "reg" and slot["root"]["reg"] in ("rsp", "rbp")
    tier = (4 if stack_register else
            1 if root == "reg" and depth <= 1 else
            2 if root == "global" and depth <= 1 else
            3 if root in ("reg", "global") else 4 if root == "stack" else 5)
    return tier, depth, _canonical(slot)


def _paths(visit, target, width, signed, *, metadata=False):
    """Yield deterministic bounded root-relative paths, never concrete addresses."""
    region = visit.region(target)
    if region is None:
        return
    if not metadata and region.kind == "global":
        yield {"kind": "global", "rva": hex(target - visit.bias),
               "width": width, "signed": signed}
    roots = []
    for reg, value in enumerate(visit.regs):
        pointed = visit.region(value)
        if pointed is not None and pointed.kind in ("heap", "global", "stack"):
            roots.append(({"kind": "reg", "reg": _REGS[reg]}, value))
    for cell_region in sorted(visit.regions, key=lambda r: (r.kind, r.base)):
        if cell_region.state != "live" or cell_region.kind not in ("global", "stack"):
            continue
        for off, value in _pointer_cells(visit, cell_region):
            if len(roots) >= _MAX_SEARCH:
                raise _Reject("search_capacity")
            if cell_region.kind == "global":
                root = {"kind": "global", "rva": hex(cell_region.base + off - visit.bias)}
            else:
                offset = cell_region.base + off - visit.regs[4]
                if not 0 <= offset < 4096:
                    continue
                root = {"kind": "stack", "rsp_offset": offset}
            roots.append((root, value))
    sites = defaultdict(list)
    for obj in visit.regions:
        if obj.kind == "heap" and obj.site is not None:
            sites[obj.site].append(obj)
    for site, objects in sorted(sites.items()):
        latest = max(objects, key=lambda r: (r.generation, r.object_id))
        if sum((r.generation, r.object_id) == (latest.generation, latest.object_id)
               for r in objects) != 1:
            continue
        roots.append(({"kind": "alloc_site", "site_pc": hex(site),
                       "selection": "last"}, latest.base))
    # Separate visited sets preserve alternative roots for cross-run stability
    # filtering. Within a root, BFS retains the shortest pointer path.
    queue = deque((root, value, [], frozenset()) for root, value in roots)
    searched = 0
    while queue:
        root, pointer, offsets, seen = queue.popleft()
        searched += 1
        if searched > _MAX_SEARCH:
            raise _Reject("search_capacity")
        obj = visit.region(pointer)
        if obj is None:
            continue
        marker = (obj.base, obj.generation, pointer - obj.base)
        if marker in seen:
            continue
        seen = seen | {marker}
        if obj is region and (metadata or target + width <= obj.base + obj.size):
            if metadata:
                # The current pointer, including its interior offset, defines
                # remaining bytes. No synthetic leaf address is dereferenced.
                for operation in ("obj_size", "obj_remaining", "is_live"):
                    yield {"kind": "heap_meta", "root": root, "offsets": offsets,
                           "meta_op": operation, "width": 8, "signed": False}
            else:
                yield {"kind": "deref_chain", "root": root,
                       "offsets": offsets + [target - pointer],
                       "width": width, "signed": signed}
        if len(offsets) >= (4 if metadata else 3) or obj.state != "live":
            continue
        for off, value in _pointer_cells(visit, obj):
            queue.append((root, value, offsets + [obj.base + off - pointer], seen))
            if len(queue) + searched > _MAX_SEARCH:
                raise _Reject("search_capacity")


def _root_pointer(visit, root):
    kind = root["kind"]
    if kind == "reg":
        return "OK", visit.regs[_REGS.index(root["reg"])]
    if kind == "global":
        addr = visit.bias + int(root["rva"], 16)
    elif kind == "stack":
        addr = visit.regs[4] + root["rsp_offset"]
    else:
        objects = [r for r in visit.regions if r.kind == "heap" and
                   r.site == int(root["site_pc"], 16)]
        if not objects:
            return "UNMAPPED", None
        latest = max(objects, key=lambda r: (r.generation, r.object_id))
        if sum((r.generation, r.object_id) == (latest.generation, latest.object_id)
               for r in objects) != 1:
            return "AMBIGUOUS_ALLOC_SITE", None
        return "OK", latest.base
    status, value, _ = visit.read(addr, 8)
    return status, value


def _evaluate(visit, slot):
    width = slot["width"]
    kind = slot["kind"]
    if kind == "reg":
        value = visit.regs[_REGS.index(slot["root"]["reg"])]
        if visit.region(value) is not None:
            return "POINTER_VALUE", None, None
        value &= (1 << (width * 8)) - 1
        identity = ("reg", slot["root"]["reg"], width)
    else:
        if kind == "global":
            addr = visit.bias + int(slot["rva"], 16)
        else:
            status, pointer = _root_pointer(visit, slot["root"])
            if status != "OK":
                return status, None, None
            steps = slot["offsets"] if kind == "heap_meta" else slot["offsets"][:-1]
            for offset in steps:
                if pointer == 0:
                    return "NULL", None, None
                status, pointer, _ = visit.read(pointer + offset, 8)
                if status != "OK":
                    return status, None, None
            if pointer == 0:
                return "NULL", None, None
            if kind == "heap_meta":
                region = visit.region(pointer)
                if region is None or region.kind != "heap":
                    return "UNMAPPED", None, None
                identity = visit.identity(region, 0, 8) + (slot["meta_op"],)
                if slot["meta_op"] == "is_live":
                    return "OK", int(region.state == "live"), identity
                if region.state == "freed":
                    return "FREED", None, None
                value = region.size if slot["meta_op"] == "obj_size" else region.base + region.size - pointer
                return "OK", value, identity
            addr = pointer + slot["offsets"][-1]
        status, value, identity = visit.read(addr, width)
        if status != "OK":
            return status, None, None
        if visit.pointer_leaf(addr, width):
            return "POINTER_VALUE", None, None
    if slot["signed"] and value & (1 << (width * 8 - 1)):
        value -= 1 << (width * 8)
    return "OK", value, identity


def plan_observations(runs: list[dict], *, artifact_orig_sha256: str,
                      patch_location: int, fault_reference: int,
                      max_slots: int = 64) -> dict:
    """Return a schema-1 plan or explicit diagnostics without partial acceptance.

    Cases require both perturbations. Exact-GPR, same-hit, same-perturbation
    opposite-outcome visits form the contrastive pairs; *all* captured visits
    participate in initialization, path-stability and perturbation filtering.
    """
    _integer(patch_location)
    _integer(fault_reference)
    _integer(max_slots, maximum=64)
    if (not isinstance(artifact_orig_sha256, str) or len(artifact_orig_sha256) != 64 or
            any(c not in "0123456789abcdefABCDEF" for c in artifact_orig_sha256)):
        raise ValueError("artifact_orig_sha256 must be a SHA-256 hex digest")
    plan = {"schema_version": 1, "artifact_orig_sha256": artifact_orig_sha256.lower(),
            "patch_location": hex(patch_location), "fault_reference": hex(fault_reference),
            "analysis_status": "no_additional_separating_slot", "unobservable_reason": None,
            "alloc_hooks": [], "slots": [], "cooccurrence_groups": [],
            "diagnostics": [], "rejected_candidates": []}

    def fail(code, **context):
        plan["analysis_status"] = code
        plan["diagnostics"].append({"code": code, **context})
        return plan

    visits = []
    by_case = defaultdict(dict)
    try:
        if not isinstance(runs, list) or not runs or len(runs) > 128:
            raise _Reject("corpus_capacity" if runs else "empty_corpus")
        for run in sorted(runs, key=lambda r: (r.get("case_id", ""), r.get("perturb", 0))):
            parsed = _parse_run(run, patch_location, fault_reference)
            case, perturb = run["case_id"], run["perturb"]
            if perturb in by_case[case]:
                raise _Reject("duplicate_case_perturbation")
            by_case[case][perturb] = parsed
            visits.extend(parsed)
        outcomes = defaultdict(int)
        for case, replays in by_case.items():
            if set(replays) != {85, 170}:
                raise _Reject("missing_perturbation_run")
            left, right = replays[85], replays[170]
            if left[-1].outcome != right[-1].outcome:
                raise _Reject("perturbation_outcome_mismatch")
            if [v.hit for v in left] != [v.hit for v in right]:
                raise _Reject("perturbation_visit_mismatch")
            outcomes[left[-1].outcome] += 1
        if any(count > 32 for count in outcomes.values()):
            raise _Reject("corpus_capacity")
    except _Reject as error:
        return fail(error.code)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return fail("malformed_trace")

    pairs = []
    normals = defaultdict(list)
    for index, visit in enumerate(visits):
        if visit.outcome == "normal":
            normals[(visit.hit, visit.perturb, visit.regs)].append(index)
    for index, visit in enumerate(visits):
        if visit.outcome == "target_crash":
            for other in normals[(visit.hit, visit.perturb, visit.regs)]:
                pairs.append((index, other))
    if not pairs:
        return fail("no_contrastive_pairs")
    paired_normals = defaultdict(list)
    for crash, normal in pairs:
        paired_normals[crash].append(visits[normal])
    candidates = {}
    postread = False
    main_livein = False
    targets = 0
    reachable_targets = 0
    unreachable_targets = 0

    def admit(slot, label, origin):
        key = _canonical(slot)
        entry = candidates.setdefault(key, {"slot": slot, "labels": set(), "origins": set()})
        entry["labels"].add(label)
        entry["origins"].add(origin)
        if len(candidates) > _MAX_CANDIDATES:
            raise _Reject("candidate_capacity")

    try:
        for index, visit in enumerate(visits):
            # Only the final fault window supplies slice seeds. Earlier visits
            # are still evaluated below, including those without matching GPRs.
            if visit.outcome != "target_crash" or not visit.events or visit.events[-1]["kind"] != "fault":
                continue
            registers, memory, metadata, origins, _ = _slice(visit, paired_normals[index])
            postread |= any(role != "addr_dep" for role, _ in origins)
            main_livein |= bool(metadata)
            for reg, labels in sorted(registers.items()):
                for label in labels:
                    slot = {"kind": "reg", "root": {"kind": "reg", "reg": _REGS[reg]},
                            "offsets": [], "width": label[2], "signed": label[3]}
                    admit(slot, label, (visit.case, label[1]))
                    if label[0] != "addr_dep" and visit.region(visit.regs[reg]) is None:
                        main_livein = True
                    region = visit.region(visit.regs[reg])
                    if region is not None and region.kind == "heap":
                        metadata.append((visit.regs[reg], label))
            for start, end, label in sorted(set(memory)):
                targets += 1
                if label[0] != "addr_dep":
                    main_livein = True
                while start < end:
                    # Preserve every byte of a partially overwritten consumer.
                    width = next(w for w in _WIDTHS if w <= end - start)
                    reachable = False
                    for slot in _paths(visit, start, width, label[3] and width == label[2]):
                        reachable = True
                        admit(slot, label, (visit.case, label[1]))
                        pointer_cell = (width == 8 and
                                        (visit.pointer_leaf(start, width) or
                                         any(_evaluate(normal, slot)[0] == "POINTER_VALUE"
                                             for normal in paired_normals[index])))
                        if pointer_cell:
                            root = ({"kind": "global", "rva": slot["rva"]}
                                    if slot["kind"] == "global" else slot["root"])
                            offsets = [] if slot["kind"] == "global" else slot["offsets"]
                            for operation in ("obj_size", "obj_remaining", "is_live"):
                                pointer_slot = {"kind": "heap_meta", "root": root,
                                                "offsets": offsets, "meta_op": operation,
                                                "width": 8, "signed": False}
                                admit(pointer_slot, label, (visit.case, label[1]))
                    reachable_targets += reachable
                    unreachable_targets += not reachable
                    region = visit.region(start)
                    if region is not None and region.kind == "heap":
                        metadata.append((start, label))
                    start += width
            for target, label in metadata:
                for slot in _paths(visit, target, 8, False, metadata=True):
                    admit(slot, label, (visit.case, label[1]))
    except _Reject as error:
        return fail(error.code)
    if unreachable_targets:
        plan["diagnostics"].append({"code": "unreachable_from_patch_roots",
                                    "fragment_count": unreachable_targets,
                                    "max_depth": 4, "max_pointer_cells": _MAX_POINTER_CELLS})
    if postread:
        plan["diagnostics"].append({"code": "ORIGIN_POST_PATCH_SYSCALL"})
    if postread and not main_livein:
        plan["analysis_status"] = "post_patch_input_read"
        plan["unobservable_reason"] = "post-patch-input-read"
        # Address-only facts do not make newly read input observable upstream.
        return plan

    accepted = []
    visit_indexes = {(v.case, v.perturb, v.hit): i for i, v in enumerate(visits)}
    for key, entry in sorted(candidates.items()):
        slot = entry["slot"]
        values = [_evaluate(visit, slot) for visit in visits]
        statuses = {value[0] for value in values}
        reason = None
        if "UNINIT_OBSERVED" in statuses:
            reason = "uninitialized_byte_or_pointer"
        elif "POINTER_VALUE" in statuses:
            reason = "pointer_value_not_scalar"
        elif "AMBIGUOUS_ALLOC_SITE" in statuses:
            reason = "ambiguous_alloc_site"
        else:
            for case, replays in by_case.items():
                for visit in replays[85]:
                    a = values[visit_indexes[(case, 85, visit.hit)]]
                    b = values[visit_indexes[(case, 170, visit.hit)]]
                    if a[:2] != b[:2]:
                        reason = "malloc_perturbation_inconsistent"
                        break
                if reason:
                    break
        separation = sum(values[a][:2] != values[b][:2] for a, b in pairs)
        availability = any(values[a][0] != values[b][0] and
                           "OK" in (values[a][0], values[b][0]) for a, b in pairs)
        identities = {value[2] for value in values if value[0] == "OK"}
        if reason is None:
            if "OK" not in statuses:
                reason = "unavailable_all_visits"
            elif len(identities) > 1:
                reason = "unstable_canonical_leaf"
            elif statuses != {"OK"} and not availability:
                reason = "unstable_availability"
            elif not separation:
                reason = "non_separating_exact_gpr_pairs"
        if reason:
            plan["rejected_candidates"].append({"candidate": slot, "reason": reason})
            continue
        role = min((label[0] for label in entry["labels"]), key=_ROLE.__getitem__)
        entry.update(values=values, separation=separation, availability=availability,
                     divergence=any(label[1].startswith("divergence:") for label in entry["labels"]),
                     role=role, key=key)
        accepted.append(entry)
    accepted.sort(key=lambda e: (-e["separation"], _ROLE[e["role"]], not e["divergence"],
                                *_path_rank(e["slot"])[:2],
                                -e["slot"]["width"], e["key"]))
    seen = set()
    selected = []
    for entry in accepted:
        # Equal resolved leaf vectors (not raw addresses or allocator generation)
        # deduplicate aliases only after cross-run stability has been checked.
        identity = tuple(value[2] if value[0] == "OK" else (value[0],)
                         for value in entry["values"])
        if identity in seen:
            plan["rejected_candidates"].append({"candidate": entry["slot"],
                                                "reason": "canonical_duplicate"})
            continue
        seen.add(identity)
        if len(selected) >= max_slots:
            plan["rejected_candidates"].append({"candidate": entry["slot"], "reason": "slot_cap"})
            continue
        slot = dict(entry["slot"], id=len(selected), slice_role=entry["role"],
                    semantic_kind="size_or_index" if entry["slot"]["kind"] == "heap_meta" else "scalar",
                    nullable_observed=any(v[0] == "NULL" for v in entry["values"]),
                    availability_discriminating=entry["availability"],
                    separated_pair_count=entry["separation"], signedness_source="dynamic-insn")
        plan["slots"].append(slot)
        selected.append(entry)
    groups = defaultdict(set)
    for slot_id, entry in enumerate(selected):
        for origin in entry["origins"]:
            groups[origin].add(slot_id)
    plan["cooccurrence_groups"] = sorted({tuple(sorted(group)) for group in groups.values() if len(group) > 1})
    plan["cooccurrence_groups"] = [list(group) for group in plan["cooccurrence_groups"]]
    sites = {int(entry["slot"]["root"]["site_pc"], 16) for entry in selected
             if entry["slot"].get("root", {}).get("kind") == "alloc_site"}
    for entry in selected:
        for status, _, identity in entry["values"]:
            if status == "OK" and identity[0] == "heap" and identity[1] is not None:
                sites.add(identity[1])
    sites = sorted(sites)
    plan["alloc_hooks"] = [{"site_id": i, "kind": "tracked_allocator", "call_pc": hex(site)}
                           for i, site in enumerate(sites)]
    if selected:
        plan["analysis_status"] = "ok"
    elif targets and not reachable_targets:
        plan["analysis_status"] = "unreachable_from_patch_roots"
    return plan
