import sbsv
import os
import sys
import math
import bisect
from typing import Dict, List, Tuple, Set, Optional
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict
from sortedcontainers import SortedDict, SortedList

class ValueKind(Enum):
    PRIMITIVE = 0  # int
    POINTER = 1
    OTHER = 2

class Role(Enum):
    SCALAR = 3
    FIELD = 4
    ARRAY_ELEM = 5

class RegionType(Enum):
    STACK = 0
    HEAP = 1
    GLOBAL = 2

@dataclass(frozen=True)
class MemoryRegion():
    type: RegionType
    id: int
    region_base: int

    def __repr__(self):
        return f"Region({self.type.name}, id={self.id:x}, base={self.region_base:x})"
    
    def __lt__(self, other):
        return self.region_base < other.region_base

@dataclass(frozen=True)
class MemoryAddress():
    region: MemoryRegion
    offset: int

    def __repr__(self):
        return f"Addr(R={self.region.id:x}, off={self.offset:x})"

    def __lt__(self, other):
        if self.region == other.region:
            return self.offset < other.offset
        return self.region < other.region


@dataclass(frozen=True)
class HomoSegmentRelation():
    a1: MemoryAddress
    a2: MemoryAddress
    size: int

@dataclass(frozen=True)
class ArrayRelation():
    region: MemoryRegion
    lo: int
    hi: int
    elem: int
    
    def valid(self) -> bool:
        return self.lo < self.hi and self.elem > 0 and ((self.hi - self.lo) % self.elem == 0)

@dataclass(frozen=True)
class MemoryChunk():
    region: MemoryRegion
    offset: int
    size: int

    def __repr__(self):
        return f"Chunk(R={self.region.id:x}, off={self.offset:x}, sz={self.size})"
    
    def __lt__(self, other):
        if self.region == other.region:
            return self.offset < other.offset
        return self.region < other.region
    
    def get_address(self) -> MemoryAddress:
        return MemoryAddress(self.region, self.offset)

@dataclass(frozen=True)
class FieldOfRelation():
    field: MemoryChunk
    base: MemoryAddress

    def __repr__(self):
        return f"FieldOf(field={self.field}, base={self.base})"

class LogParser():
    parser: sbsv.parser
    def __init__(self, filepath: str):
        # https://github.com/hsh814/sbsv
        self.parser = sbsv.parser()
        self.parser.add_custom_type("hex", lambda x: int(x, 16))
        self.parser.add_schema("[alloc] [start] [base: hex] [size: hex] [pc: hex]")
        self.parser.add_schema("[calloc] [size: hex] [pc: hex]")
        self.parser.add_schema("[free] [done] [base: hex] [pc: hex]")
        self.parser.add_schema("[stack] [push] [sp: hex] [size: hex] [pc: hex] [depth: int] [sr-base: hex] [sr-size: hex]")
        self.parser.add_schema("[stack] [pop] [sp: hex] [base: hex] [pc: hex] [depth: int]")
        self.parser.add_schema("[global] [add] [base: hex] [size: hex] [name: str]")
        self.parser.add_schema("[loadh] [val] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[loadh] [val-fallback] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[loadh] [inval] [reg: str] [pc: hex] [addr: hex] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[loadh-error] [pc: hex] [addr: hex] [size: hex]")
        self.parser.add_schema("[storeh] [val] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[storeh] [val-fallback] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[storeh] [inval] [reg: str] [pc: hex] [addr: hex] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[memmoveh] [src: hex] [dst: hex] [size: hex] [val: hex] [is-ptr: bool] [src-r: str] [src-rb: hex] [dst-r: str] [dst-rb: hex] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[cov] [base] [from: hex] [to: hex] [cnt: int]")
        self.parser.add_schema("[cov] [update] [from: hex] [to: hex] [cnt: int]")
        # Read access for pointer
        # self.parser.add_schema("[rpo] [addr: hex] [target: hex] [pc: hex] [index: int] [id: int]")
        with open(filepath, 'r') as file:
            self.parser.load(file)

class PrimitiveFactAnalyzer:
    parser: sbsv.parser
    fact_access: Dict[Tuple[int, MemoryChunk], int]
    base_addr: Dict[MemoryChunk, int]
    access_cnt: Dict[MemoryChunk, int]
    fact_pointers: Dict[MemoryChunk, int]
    fact_malloc_size: Dict[int, List[int]]
    fact_mem_copy: Set[Tuple[MemoryChunk, MemoryChunk, int]]  # (src_chunk, dst_chunk, size)
    active_allocs: Dict[int, MemoryRegion]
    stack_frames: List[MemoryRegion]
    global_vars: Dict[int, MemoryRegion]
    addr_to_chunk: SortedDict[int, MemoryChunk]
    all_chunks: Set[MemoryChunk]
    pointer_size: int
    def __init__(self, parser: sbsv.parser):
        self.parser = parser
        
        # OSPREY Primitive Facts Store
        # F01: Access(i, v, k) -> (pc, chunk) : count
        self.fact_access: Dict[Tuple[int, MemoryChunk], int] = defaultdict(int)
        self.access_cnt: Dict[MemoryChunk, int] = defaultdict(int)
        # F02: BaseAddr(v, a) -> chunk : base_addr
        self.base_addr: Dict[MemoryChunk, int] = {}
        
        # F04: Pointers: set of chunks that contains valid addresses (from load/store with is-ptr=true)
        self.fact_pointers: Dict[MemoryChunk, int] = defaultdict(int)
        
        # F05: MallocedSize(i, s)
        self.fact_malloc_size: Dict[int, List[int]] = defaultdict(list)
        
        # F06: MemCopy(src, dst, size)
        self.fact_mem_copy: Set[Tuple[MemoryChunk, MemoryChunk, int]] = set()
        
        # Memory Region Tracking
        self.active_allocs: Dict[int, MemoryRegion] = {} # addr -> Region
        self.stack_frames: List[MemoryRegion] = [] 
        self.global_vars: Dict[int, MemoryRegion] = {}
        self.addr_to_chunk: SortedDict[int, MemoryChunk] = SortedDict() # addr -> chunk (for quick lookup during memmove)
        self.all_chunks: Set[MemoryChunk] = set()
        self.pointer_size = 8  # 64-bit architecture

    def _resolve_memory_region(self, region_type: str, region_base: int) -> Optional[MemoryRegion]:
        if region_type == "stack":
            for region in reversed(self.stack_frames):
                if region.region_base == region_base:
                    return region
        elif region_type == "heap":
            if region_base in self.active_allocs:
                return self.active_allocs[region_base]
        elif region_type == "global":
            if region_base in self.global_vars:
                return self.global_vars[region_base]
        return None
    
    def run_trace_replay(self):
        iterator = self.parser.get_result_in_order()
        
        for row in iterator:
            schema = row.schema_name
            
            if schema == "alloc$start":
                base = row["base"]
                size = row["size"]
                pc = row["pc"]
                region = MemoryRegion(RegionType.HEAP, pc, base)
                self.active_allocs[base] = region
                self.fact_malloc_size[pc].append(size)
            elif schema == "calloc":
                size = row["size"]
                pc = row["pc"]
                # calloc returns a zero-initialized chunk, but we don't have the base address until alloc$start
                # We can track the size and pc for inference, but will need to link it to the actual allocation when we see alloc$start
                self.fact_malloc_size[pc].append(size)
                
            elif schema == "free$done":
                base = row["base"]
                if base in self.active_allocs:
                    del self.active_allocs[base]
            
            elif schema == "stack$push":
                sp = row["sp"]
                pc = row["pc"]
                region = MemoryRegion(RegionType.STACK, pc, sp)
                self.stack_frames.append(region)
            elif schema == "stack$pop":
                if self.stack_frames:
                    self.stack_frames.pop()
            
            elif schema == "global$add":
                base = row["base"]
                region = MemoryRegion(RegionType.GLOBAL, base, base)
                self.global_vars[base] = region

            # --- Memory Access Events (F01, F04) ---
            elif schema in ["loadh$val", "loadh$val-fallback", "loadh$inval", "storeh$val", "storeh$val-fallback", "storeh$inval"]:
                pc = row["pc"]
                addr = row["addr"]
                if schema in ["loadh$inval", "storeh$inval"]:
                    base_addr = addr
                    offset = 0
                else:
                    base_addr = row["base"]
                    offset = row["disp"]
                size = row["size"]
                region = row["reg"]
                region_base = row["reg-base"]
                is_ptr = row["is-ptr"]
                val = row["val"] # If is_ptr is true, val is the dereferenced value, which is a potential pointer target
                memory_region = self._resolve_memory_region(region, region_base)
                if memory_region is None:
                    print(f"Warning: Could not resolve memory region for addr {addr:x} at PC {pc:x}")
                    continue
                chunk = MemoryChunk(memory_region, addr - region_base, size)
                self.base_addr[chunk] = base_addr
                self.addr_to_chunk[addr] = chunk
                self.all_chunks.add(chunk)
                
                # 1. Identify which abstract chunk is being accessed
                # F01: Access Frequency
                self.fact_access[(pc, chunk)] += 1
                self.access_cnt[chunk] += 1
                # F04: PointsTo (if it's a pointer access, we can infer points-to relationships)
                if is_ptr:
                    self.fact_pointers[chunk] = val
            
            elif schema == "memmoveh":
                src = row["src"]
                dst = row["dst"]
                size = row["size"]
                src_region = row["src-r"]
                src_region_base = row["src-rb"]
                dst_region = row["dst-r"]
                dst_region_base = row["dst-rb"]
                src_memory_region = self._resolve_memory_region(src_region, src_region_base)
                dst_memory_region = self._resolve_memory_region(dst_region, dst_region_base)
                if src_memory_region is None or dst_memory_region is None:
                    # print(f"Warning: Could not resolve memory region for memmove")
                    continue
                src_chunk = MemoryChunk(src_memory_region, src - src_region_base, size)
                dst_chunk = MemoryChunk(dst_memory_region, dst - dst_region_base, size)
                self.fact_mem_copy.add((src_chunk, dst_chunk, size))
                self.all_chunks.add(src_chunk)
                self.all_chunks.add(dst_chunk)

class DeterministicInference:
    analyzer: PrimitiveFactAnalyzer
    rel_access_single: List[Tuple[int, MemoryRegion, Set[MemoryChunk]]]
    rel_access_multi: List[Tuple[int, MemoryRegion, Set[MemoryChunk]]]
    rel_alloc_unit: Dict[int, int]
    rel_data_flow_hint: Set[Tuple[MemoryChunk, MemoryChunk, int]] # (src_chunk, dst_chunk, size)
    rel_unified_access_hint: Dict[Tuple[MemoryRegion, MemoryRegion], Set[Tuple[MemoryChunk, MemoryChunk, int, int]]]
    rel_base_addr_access: Set[Tuple[MemoryChunk, MemoryChunk]] # (field, base)
    rel_fieldof: Set[FieldOfRelation]
    rel_homoseg: Dict[HomoSegmentRelation, Tuple[Set[MemoryChunk], Set[MemoryChunk]]]
    rel_may_array: Set[ArrayRelation]
    
    def __init__(self, analyzer: PrimitiveFactAnalyzer):
        self.analyzer = analyzer
        self.rel_access_single = list()
        self.rel_access_multi = list()
        self.rel_alloc_unit = dict()
        self.rel_data_flow_hint = set()
        self.rel_unified_access_hint = defaultdict(set)
        self.rel_base_addr_access = set()
        self.rel_fieldof = set()
        self.rel_homoseg = defaultdict(lambda: (set(), set())) # relation -> (src_chunks, dst_chunks)
        self.rel_may_array = set()

    def _same_region(self, chunk1: MemoryChunk, chunk2: MemoryChunk) -> bool:
        return chunk1.region == chunk2.region

    def _offset(self, chunk1: MemoryChunk, chunk2: MemoryChunk) -> int:
        if self._same_region(chunk1, chunk2):
            return abs(chunk1.offset - chunk2.offset)
        return -1
    
    def _gcd_list(self, nums: List[int]) -> int:
        gcd = nums[0]
        for num in nums[1:]:
            gcd = math.gcd(gcd, num)
        return gcd
    
    def infer_fieldof(self):
        # F02: BaseAddr(v, a) -> chunk : base_addr
        for chunk, base_addr in self.analyzer.base_addr.items():
            if base_addr in self.analyzer.addr_to_chunk:
                base_chunk: MemoryChunk = self.analyzer.addr_to_chunk[base_addr]
                if self._same_region(chunk, base_chunk):
                    if chunk != base_chunk:
                        self.rel_base_addr_access.add((chunk, base_chunk))
                        self.rel_fieldof.add(FieldOfRelation(chunk, base_chunk.get_address()))
            elif base_addr != chunk.region.region_base + chunk.offset:
                off = base_addr - chunk.region.region_base
                base = MemoryAddress(chunk.region, off)
                self.rel_fieldof.add(FieldOfRelation(chunk, base))
    
    def infer_access_patterns(self):
        # R03, R04: Access Pattern Analysis
        # (pc, region) -> set(offsets)
        access_map: Dict[Tuple[int, MemoryRegion], Set[MemoryChunk]] = defaultdict(set)
        for (pc, chunk), count in self.analyzer.fact_access.items():
            access_map[(pc, chunk.region)].add(chunk)
        
        for (pc, region), chunks in access_map.items():
            if len(chunks) == 1: # Single offset access -> scalar
                self.rel_access_single.append((pc, region, chunks))
            else: # Multiple offsets -> likely array
                self.rel_access_multi.append((pc, region, chunks))
    
    def infer_alloc_unit(self):
        # R08, R09: Allocation Unit Inference
        for pc, sizes in self.analyzer.fact_malloc_size.items():
            unique_sizes = sorted(list(set(sizes)))
            if len(unique_sizes) < 2:
                continue
            diffs = [unique_sizes[i+1] - unique_sizes[i] for i in range(len(unique_sizes)-1)]
            alloc_unit = self._gcd_list(diffs)
            if alloc_unit > 0:
                self.rel_alloc_unit[pc] = alloc_unit
    
    def infer_homoseg_from_memcpy(self):
        # R10: MemCpy -> if same offset, it hints same struct
        for src_chunk, dst_chunk, size in self.analyzer.fact_mem_copy:
            if self._same_region(src_chunk, dst_chunk):
                continue
            src_addr = src_chunk.get_address()
            dst_addr = dst_chunk.get_address()
            src_chunks, dst_chunks = self.rel_homoseg[HomoSegmentRelation(src_addr, dst_addr, size)]
            src_chunks.add(src_chunk)
            dst_chunks.add(dst_chunk)
    
    def infer_homoseg_from_unified_access(self):
        # R11: unified access
        # same instruction, different access address -> collect 
        pc_to_chunks: Dict[int, Set[MemoryChunk]] = defaultdict(set)
        for (pc, chunk), count in self.analyzer.fact_access.items():
            pc_to_chunks[pc].add(chunk)
        # analyze offset diff
        # (region1, region2) -> offset diff -> list of (chunk1, chunk2)
        
        # pairs: Dict[Tuple[MemoryRegion, MemoryRegion], Dict[int, Set[Tuple[MemoryChunk, MemoryChunk]]]] = defaultdict(lambda: defaultdict(set))
        layout_matches: Dict[Tuple[MemoryRegion, MemoryRegion], Dict[int, Set[Tuple[MemoryChunk, MemoryChunk]]]] = defaultdict(lambda: defaultdict(set))
        for pc, chunk_set in pc_to_chunks.items():
            chunks = list(chunk_set)
            # by_region: Dict[MemoryRegion, Dict[int, MemoryChunk]] = defaultdict(dict)
            # for c in chunks:
            #     by_region[c.region][c.offset] = c
            # regions = list(by_region.keys())
            # for i in range(len(regions)):
            #     for j in range(i + 1, len(regions)):
            #         r1 = regions[i]
            #         r2 = regions[j]
            #         common_offsets = set(by_region[r1].keys()) & set(by_region[r2].keys())
            #         for off in common_offsets:
            #             c1 = by_region[r1][off]
            #             c2 = by_region[r2][off]
            #             pairs[(r1, r2)][0].add((c1, c2)) # offset diff 0
            for i in range(len(chunks)):
                for j in range(i + 1, len(chunks)):
                    c1 = chunks[i]
                    c2 = chunks[j]
                    if self._same_region(c1, c2):
                        continue
                    # if c1.offset != c2.offset:
                    #     continue
                    if c2 < c1:
                        c1, c2 = c2, c1
                    offset_diff = c2.offset - c1.offset
                    layout_matches[(c1.region, c2.region)][offset_diff].add((c1, c2))
        # Find homosegments
        for (r1, r2), offset_diffs in layout_matches.items():
            for diff, chunk_pairs in offset_diffs.items():
                if len(chunk_pairs) < 2: # At least 2 matching access patterns
                    continue
                pairs = sorted(list(chunk_pairs), key=lambda x: x[0].offset)
                base_c1 = pairs[0][0]
                base_c2 = pairs[0][1]
                last_c1 = pairs[-1][0]
                seg_size = last_c1.offset - base_c1.offset + last_c1.size
                self.rel_unified_access_hint[(r1, r2)].add((base_c1, base_c2, seg_size, len(pairs)))
                c1_chunks, c2_chunks = self.rel_homoseg[HomoSegmentRelation(base_c1.get_address(), base_c2.get_address(), seg_size)]
                for c1, c2 in pairs:
                    c1_chunks.add(c1)
                    c2_chunks.add(c2)
    
    def infer_arrays_from_access(self):
        # multi-chunk -> array
        access_by_pc_region: Dict[Tuple[int, MemoryRegion], List[MemoryChunk]] = defaultdict(list)
        for (pc, chunk), _ in self.analyzer.fact_access.items():
            access_by_pc_region[(pc, chunk.region)].append(chunk)

        for (pc, region), chunks in access_by_pc_region.items():
            offsets = sorted(set(c.offset for c in chunks))
            if len(offsets) < 2:
                continue

            diffs = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
            g = diffs[0]
            for d in diffs[1:]:
                g = math.gcd(g, d)

            any_chunk = chunks[0]
            elem = g if g in (1,2,4,8,16) else any_chunk.size

            lo = offsets[0]
            max_off = offsets[-1]
            max_chunks = [c for c in chunks if c.offset == max_off]
            last_sz = max(c.size for c in max_chunks) if max_chunks else any_chunk.size
            hi = max_off + last_sz

            arr = ArrayRelation(region, lo, hi, elem)
            if arr.valid():
                self.rel_may_array.add(arr)

    def infer(self):
        self.infer_fieldof()
        self.infer_access_patterns()
        self.infer_alloc_unit()
        self.infer_homoseg_from_memcpy()
        self.infer_homoseg_from_unified_access()
        self.infer_arrays_from_access()
        
class ProbabilisticInference:
    deterministic_inference: DeterministicInference
    kind_prob: Dict[MemoryChunk, Dict[ValueKind, float]]
    role_prob: Dict[MemoryChunk, Dict[Role, float]]
    # struct
    fieldof_prob: Dict[FieldOfRelation, float] # (field, base) -> probability of field_of relation
    homoseg_prob: Dict[HomoSegmentRelation, float] # (chunk1, chunk2) -> probability of being in the same struct
    # array
    array_start_prob: Dict[MemoryAddress, float]
    array_prob: Dict[ArrayRelation, float]
    # etc
    region_chunks: Dict[MemoryRegion, SortedList[MemoryChunk]]
    overlapping_chunks: Dict[MemoryChunk, Set[MemoryChunk]]
    
    def __init__(self, deterministic_inference: DeterministicInference):
        self.deterministic_inference = deterministic_inference
        self.kind_prob = defaultdict(lambda: self._uniform_dist(ValueKind))
        self.role_prob = defaultdict(lambda: self._uniform_dist(Role))
        self.fieldof_prob = defaultdict(float)
        self.homoseg_prob = defaultdict(float)
        self.array_start_prob = defaultdict(float)
        self.array_prob = defaultdict(float)
        self.region_chunks = defaultdict(lambda: SortedList(key=lambda c: (c.offset, c.size)))
        self.overlapping_chunks = defaultdict(set)
        
    def _uniform_dist(self, enum_cls: Enum) -> Dict[Enum, float]:
        n = len(enum_cls)
        return {e: 1.0 / n for e in enum_cls}
    
    def _normalize(self, dist: Dict[Enum, float]):
        total = sum(dist.values())
        if total == 0:
            return
        for t in dist:
            dist[t] /= total
    
    def _merge_prob_dist(self, dist1: Dict[Enum, float], dist2: Dict[Enum, float], weight: float = 0.5) -> Dict[Enum, float]:
        epsilon = 1e-9
        merged = {t: dist1[t] * weight + dist2[t] * (1 - weight) + epsilon for t in dist1}
        self._normalize(merged)
        return merged

    def _apply_priors(self):
        primitive_sizes = {1, 2, 4, 8}
        for chunk in self.deterministic_inference.analyzer.all_chunks:
            self.region_chunks[chunk.region].add(chunk)
            kp = self.kind_prob[chunk]
            rp = self.role_prob[chunk]
            if chunk.size in primitive_sizes:
                kp[ValueKind.PRIMITIVE] += 1.0
                if chunk.size == self.deterministic_inference.analyzer.pointer_size:
                    kp[ValueKind.POINTER] += 1.0
            else:
                kp[ValueKind.OTHER] += 1.0
            self._normalize(kp)
            rp[Role.SCALAR] += 0.2
            self._normalize(rp)
    
    def _get_adjacent_chunks(self, chunk: MemoryChunk) -> Tuple[Optional[MemoryChunk], Optional[MemoryChunk]]:
        chunks = self.region_chunks.get(chunk.region)
        if not chunks:
            return None, None
        left = chunks.bisect_left(chunk)
        right = chunks.bisect_right(chunk)
        idx = left
        if left != right:
            for i in range(left, right):
                if chunks[i] == chunk:
                    idx = i
                    break
        prev_chunk = None
        next_chunk = None
        if idx > 0:
            prev_chunk: MemoryChunk = chunks[idx - 1]
            if prev_chunk.offset + prev_chunk.size < chunk.offset:
                prev_chunk = None # Not adjacent
            elif prev_chunk.offset + prev_chunk.size > chunk.offset:
                self.overlapping_chunks[chunk].add(prev_chunk)
                prev_chunk = None # Overlapping
        if idx + 1 < len(chunks):
            next_chunk: MemoryChunk = chunks[idx + 1]
            if next_chunk.offset > chunk.offset + chunk.size:
                next_chunk = None # Not adjacent
            elif next_chunk.offset  < chunk.offset + chunk.size:
                self.overlapping_chunks[chunk].add(next_chunk)
                next_chunk = None # Overlapping
        return prev_chunk, next_chunk
    
    # C_A: Access Patterns for primitive types
    def _apply_rules_CA(self):
        # C_A01: Access(i, v, k) -> PrimitiveVar(v)
        # C_A02: AdjacentChunk(v_1, v_2) && PrimitiveVar(v_1) -> PrimitiveVar(v_2)
        # C_A03: OverlappingChunk(v_1, v_2) -> PrimitiveVar(v_1) and PrimitiveVar(v_2)
        # C_A06: AccessSingleChunk(i, v.a.r) -> PrimitiveVar(v)
        for chunk in self.deterministic_inference.analyzer.all_chunks:
            access_count = self.deterministic_inference.analyzer.access_cnt.get(chunk, 0)
            # C_A01: Frequently accessed chunk is likely primitive
            if access_count > 10:
                self.kind_prob[chunk][ValueKind.PRIMITIVE] *= 1.2
            # C_A02: If adjacent chunk is primitive, this chunk is more likely primitive
            prev_chunk, next_chunk = self._get_adjacent_chunks(chunk)
            if prev_chunk and self.kind_prob[prev_chunk][ValueKind.PRIMITIVE] > 0.5:
                self.kind_prob[chunk][ValueKind.PRIMITIVE] *= 1.2
            if next_chunk and self.kind_prob[next_chunk][ValueKind.PRIMITIVE] > 0.5:
                self.kind_prob[chunk][ValueKind.PRIMITIVE] *= 1.2
        # C_A03: If overlapping chunk is primitive, this chunk is likely primitive
        for chunk in self.overlapping_chunks:
            overlap_chunk = self.overlapping_chunks.get(chunk, [])
            if overlap_chunk:
                self.kind_prob[chunk][ValueKind.PRIMITIVE] *= 1.0 + min(0.2 * len(overlap_chunk), 1.0)
        # C_A06: If accessed with single offset, more likely scalar
        for (pc, region, chunks) in self.deterministic_inference.rel_access_single:
            for chunk in chunks:
                self.role_prob[chunk][Role.SCALAR] *= 1.5
                self.role_prob[chunk][Role.FIELD] *= 0.7
                self.role_prob[chunk][Role.ARRAY_ELEM] *= 0.5
    
    # C_B: Access Patterns for array
    def _apply_rules_CB(self):
        # C_B01: MayArray -> Array, ArrayStart
        for arr in self.deterministic_inference.rel_may_array:
            if not arr.valid():
                continue
            self.array_prob[arr] += 0.8
            head = MemoryAddress(arr.region, arr.lo)
            self.array_start_prob[head] += 0.8
        # C_B01: AllocUnit -> if access pattern matches alloc unit, more likely array
        pc_to_chunks: Dict[int, List[MemoryChunk]] = defaultdict(list)
        for (pc, chunk), _ in self.deterministic_inference.analyzer.fact_access.items():
            pc_to_chunks[pc].append(chunk)
        for pc, alloc_unit in self.deterministic_inference.rel_alloc_unit.items():
            if pc in pc_to_chunks:
                for chunk in pc_to_chunks[pc]:
                    if (chunk.size == alloc_unit) or (chunk.size % alloc_unit == 0):
                        self.role_prob[chunk][Role.ARRAY_ELEM] *= 1.5
                        self.role_prob[chunk][Role.SCALAR] *= 0.5
        # C_B02: AccessMultiChunk(i, v.a.r) -> ArrayVar(v)
        # Accessed with multiple offsets -> more likely array, less likely primitive
        for (pc, region, chunks) in self.deterministic_inference.rel_access_multi:
            for chunk in chunks:
                self.role_prob[chunk][Role.ARRAY_ELEM] *= 1.5
                self.role_prob[chunk][Role.SCALAR] *= 0.5
            # self.array_start_prob
            
        
    # C_C: Heap structure
    def _apply_rules_CC(self):
        # Fold/Unfold
        for chunk, prob in self.role_prob.items():
            if chunk.region.type == RegionType.HEAP:
                # If likely struct, its fields are likely field_of
                prob[Role.FIELD] *= 1.5
                prob[Role.ARRAY_ELEM] *= 1.2
                prob[Role.SCALAR] *= 0.7
                
    # C_D: Struct, Pointer
    def _apply_rules_CD(self):
        # C_D01: DataFlowHint(Memcpy) -> HomoSegment
        # C_D03: UnifiedAccessPntHint -> HomoSegment / FieldOf
        for homoseg, (src_chunks, dst_chunks) in self.deterministic_inference.rel_homoseg.items():
            self.homoseg_prob[homoseg] += 0.8
            # C_D08: HomoSegment -> FieldOf
            for c in src_chunks:
                self.role_prob[c][Role.FIELD] *= 1.2
            for c in dst_chunks:
                self.role_prob[c][Role.FIELD] *= 1.2

        for (r1, r2), hints in self.deterministic_inference.rel_unified_access_hint.items():
            for (c1, c2, seg_size, pair_count) in hints:
                rp1 = self.role_prob[c1]
                rp1[Role.FIELD] *= 1.5
                rp1[Role.ARRAY_ELEM] *= 0.9
                rp1[Role.SCALAR] *= 0.7
                rp2 = self.role_prob[c2]
                rp2[Role.FIELD] *= 1.5
                rp2[Role.ARRAY_ELEM] *= 0.9
                rp2[Role.SCALAR] *= 0.7
        # C_D06: BaseAddr -> FieldOf struct
        for rel in self.deterministic_inference.rel_fieldof:
            self.fieldof_prob[rel] += 0.8
            rp = self.role_prob[rel.field]
            rp[Role.FIELD] *= 1.5
            rp[Role.SCALAR] *= 0.7
            rp[Role.ARRAY_ELEM] *= 0.9
            
        # C_D11: PointsTo(v, a) -> PointerVar(v)
        for chunk, target_addr in self.deterministic_inference.analyzer.fact_pointers.items():
            kp = self.kind_prob[chunk]
            kp[ValueKind.POINTER] *= 1.5
            if target_addr in self.deterministic_inference.analyzer.addr_to_chunk:
                target_chunk: MemoryChunk = self.deterministic_inference.analyzer.addr_to_chunk[target_addr]
                self.array_start_prob[target_chunk.get_address()] += 0.2
            # TODO: C_D02: PointsToHint() -> HomoSegment
    
    def _update_with_deterministic(self):
        self._apply_rules_CA()
        self._apply_rules_CB()
        self._apply_rules_CC()
        self._apply_rules_CD()
        # Finished
        for chunk, prob in self.kind_prob.items():
            self._normalize(prob)
        for chunk, prob in self.role_prob.items():
            self._normalize(prob)
    
    def dump_results(self):
        for region, chunks in self.region_chunks.items():
            for chunk in chunks:
                kind_prob = self.kind_prob[chunk]
                role_prob = self.role_prob[chunk]
                inferred_kind = max(kind_prob, key=kind_prob.get)
                inferred_role = max(role_prob, key=role_prob.get)
                inferred_type = f"{inferred_kind.name}_{inferred_role.name}"
                print(f"[osprey] [reg {region}] [chunk off={chunk.offset:x} sz={chunk.size}] [type {inferred_type}] [kind-prob {kind_prob}] [role-prob {role_prob}]")
        for rel, prob in self.fieldof_prob.items():
            print(f"[osprey] [fieldof] [field {rel.field}] [base {rel.base}] [prob {prob:.2f}]")
        for rel, prob in self.homoseg_prob.items():
            print(f"[osprey] [homoseg] [a1 {rel.a1}] [a2 {rel.a2}] [size {rel.size}] [prob {prob:.2f}]")
        for arr, prob in self.array_prob.items():
            print(f"[osprey] [array] [region {arr.region}] [lo {arr.lo:x}] [hi {arr.hi:x}] [elem {arr.elem}] [prob {prob:.2f}]")
        
    def type_infer(self):
        self._apply_priors()
        self._update_with_deterministic()
        self.dump_results()
        

class OspreyAnalyzer:
    parser: LogParser
    primitive_analyzer: PrimitiveFactAnalyzer
    deterministic_inference: DeterministicInference
    probabilistic_inference: ProbabilisticInference
    def __init__(self, log_file: str):
        self.parser = LogParser(log_file)
    
    def analyze(self):
        self.primitive_analyzer = PrimitiveFactAnalyzer(self.parser.parser)
        self.primitive_analyzer.run_trace_replay()
        self.deterministic_inference = DeterministicInference(self.primitive_analyzer)
        self.deterministic_inference.infer()
        self.probabilistic_inference = ProbabilisticInference(self.deterministic_inference)
        self.probabilistic_inference.type_infer()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        print("Usage: python analyze_type.py <log_file>")
        sys.exit(1)
    if not os.path.exists(log_file):
        print(f"Log file {log_file} does not exist")
        sys.exit(1)
    osprey = OspreyAnalyzer(log_file)
    osprey.analyze()