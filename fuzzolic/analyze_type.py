import sbsv
import os
import sys
import math
from typing import Dict, List, Tuple, Set, Optional
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict
from sortedcontainers import SortedDict, SortedList

# OSPREY-style probabilistic weights
P_UP = 0.8
P_DOWN = 0.2
LOGIT_CLAMP = 8.0


def logit(p: float) -> float:
    p = max(min(p, 0.999), 0.001)
    return math.log(p / (1 - p))


def expit(l: float) -> float:
    return 1 / (1 + math.exp(-l))


def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


W_UP = logit(P_UP)
W_DOWN = logit(P_DOWN)

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
        return f"Chunk([RT {self.region.type.name[0]}] [RB {self.region.region_base:x}] [RI {self.region.id:x}], off={self.offset:x}, sz={self.size})"
    
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
        # loadh/storeh: val - successfully detect base address, val-fallback - fallback to register value, inval - failed to detect base address, only have access addr
        self.parser.add_schema("[loadh] [val] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[loadh] [val-fallback] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[loadh] [inval] [reg: str] [pc: hex] [addr: hex] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[loadh-error] [pc: hex] [addr: hex] [size: hex]")
        self.parser.add_schema("[storeh] [val] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[storeh] [val-fallback] [reg: str] [pc: hex] [addr: hex] [base: hex] [disp: int] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[storeh] [inval] [reg: str] [pc: hex] [addr: hex] [reg-base: hex] [size: hex] [val: hex] [is-ptr: bool] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        # memmoveh: this include register copy, memcpy, memmove, strcpy
        self.parser.add_schema("[memmoveh] [src: hex] [dst: hex] [size: hex] [val: hex] [is-ptr: bool] [src-r: str] [src-rb: hex] [dst-r: str] [dst-rb: hex] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        # cov: edge coverage
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
                    if c2 < c1:
                        c1, c2 = c2, c1
                    offset_diff = c2.offset - c1.offset
                    if offset_diff != 0: # Fix
                        continue
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

class NodeType(Enum):
    PRIMITIVE_VAR = 0
    SCALAR = 1
    POINTER = 2
    ARRAY_ELEM = 3
    ARRAY = 4
    FIELD_OF = 5
    HOMO_SEGMENT = 6

@dataclass(frozen=True)
class Node:
    type: NodeType

@dataclass(frozen=True)
class SingleNode(Node):
    chunk: MemoryChunk

@dataclass(frozen=True)
class ArrayRelNode(Node):
    array_relation: ArrayRelation
    
@dataclass(frozen=True)
class HomoSegNode(Node):
    segment: HomoSegmentRelation

@dataclass(frozen=True)
class PointerNode(Node):
    chunk: MemoryChunk
    target: MemoryAddress

@dataclass(frozen=True)
class FieldOfNode(Node):
    field: MemoryChunk
    base: MemoryAddress

class ProbabilisticInference:
    det: DeterministicInference
    analyzer: PrimitiveFactAnalyzer
    nodes: Set[Node]
    prior_logits: Dict[Node, float]
    edges: Dict[Node, List[Tuple[Node, float]]]
    degree: Dict[Node, int]
    beliefs: Dict[Node, float]
    # cache
    field_nodes: Dict[MemoryChunk, Set[Node]]

    def __init__(self, deterministic_inference: DeterministicInference):
        self.det = deterministic_inference
        self.analyzer = deterministic_inference.analyzer
        self.nodes = set()
        self.prior_logits = defaultdict(float)
        self.edges = defaultdict(list)
        self.degree = defaultdict(int)
        self.beliefs = dict()
        self.field_nodes = defaultdict(set)

    def _add_node(self, node: Node, prior_prob: float):
        if node.type == NodeType.FIELD_OF and isinstance(node, FieldOfNode):
            self.field_nodes[node.field].add(node)
        prior = logit(prior_prob)
        if node in self.nodes:
            self.prior_logits[node] = 0.5 * (self.prior_logits[node] + prior)
        else:
            self.nodes.add(node)
            self.prior_logits[node] = prior

    def _add_edge(self, src: Node, dst: Node, weight: float, bidirectional: bool = False):
        self.nodes.add(src)
        self.nodes.add(dst)
        self.edges[dst].append((src, weight))
        self.degree[src] += 1
        self.degree[dst] += 1
        if bidirectional:
            self.edges[src].append((dst, weight))
            self.degree[src] += 1
            self.degree[dst] += 1

    def _softmax_by_logits(self, logits: List[float]) -> List[float]:
        if not logits:
            return []
        m = max(logits)
        exps = [math.exp(x - m) for x in logits]
        s = sum(exps)
        if s == 0:
            return [1.0 / len(logits)] * len(logits)
        return [x / s for x in exps]

    def _build_factor_graph(self):
        chunks_by_region: Dict[MemoryRegion, List[MemoryChunk]] = defaultdict(list)
        for chunk in self.analyzer.all_chunks:
            chunks_by_region[chunk.region].append(chunk)
        for region in chunks_by_region:
            chunks_by_region[region].sort(key=lambda c: (c.offset, c.size))

        field_candidates_by_chunk: Dict[MemoryChunk, Set[MemoryAddress]] = defaultdict(set)
        for rel in self.det.rel_fieldof:
            field_candidates_by_chunk[rel.field].add(rel.base)
            self._add_node(FieldOfNode(type=NodeType.FIELD_OF, field=rel.field, base=rel.base), 0.6)
            
        for region, chunks in chunks_by_region.items():
            for i, chunk in enumerate(chunks):
                node_prim = SingleNode(type=NodeType.PRIMITIVE_VAR, chunk=chunk)
                node_scalar = SingleNode(type=NodeType.SCALAR, chunk=chunk)
                node_arr_elem = SingleNode(type=NodeType.ARRAY_ELEM, chunk=chunk)

                k = self.analyzer.access_cnt.get(chunk, 0)
                p_k = 0.5 + 0.4 * (1 - math.exp(-0.1 * k))
                self._add_node(node_prim, p_k)
                self._add_node(node_scalar, 0.35)
                self._add_node(node_arr_elem, 0.25)

                for base_addr in field_candidates_by_chunk.get(chunk, set()):
                    node_field = FieldOfNode(type=NodeType.FIELD_OF, field=chunk, base=base_addr)
                    self._add_edge(node_prim, node_field, W_UP)
                    self._add_edge(node_field, node_scalar, W_DOWN)

                for j in range(i + 1, len(chunks)):
                    nxt = chunks[j]
                    node_next_prim = SingleNode(type=NodeType.PRIMITIVE_VAR, chunk=nxt)
                    if nxt.offset < chunk.offset + chunk.size:
                        self._add_edge(node_prim, node_next_prim, W_DOWN, bidirectional=True)
                    elif nxt.offset == chunk.offset + chunk.size:
                        self._add_edge(node_prim, node_next_prim, logit(0.6), bidirectional=True)
                        break
                    else:
                        break

        for _, _, chunks in self.det.rel_access_single:
            for c in chunks:
                self._add_edge(SingleNode(type=NodeType.PRIMITIVE_VAR, chunk=c), SingleNode(type=NodeType.SCALAR, chunk=c), W_UP)

        for arr in self.det.rel_may_array:
            if not arr.valid():
                continue
            node_arr = ArrayRelNode(type=NodeType.ARRAY, array_relation=arr)
            self._add_node(node_arr, 0.7)
            for chunk in chunks_by_region[arr.region]:
                if chunk.offset >= arr.lo and (chunk.offset + chunk.size) <= arr.hi:
                    self._add_edge(node_arr, SingleNode(type=NodeType.ARRAY_ELEM, chunk=chunk), W_UP)
                    self._add_edge(SingleNode(type=NodeType.SCALAR, chunk=chunk), node_arr, W_DOWN, bidirectional=True)

        for rel, (src_chunks, dst_chunks) in self.det.rel_homoseg.items():
            node_h = HomoSegNode(type=NodeType.HOMO_SEGMENT, segment=rel)
            self._add_node(node_h, 0.65)
            src_fields: Dict[MemoryChunk, Set[MemoryAddress]] = defaultdict(set)
            dst_fields: Dict[MemoryChunk, Set[MemoryAddress]] = defaultdict(set)
            for relf in self.det.rel_fieldof:
                if relf.field in src_chunks:
                    src_fields[relf.field].add(relf.base)
                if relf.field in dst_chunks:
                    dst_fields[relf.field].add(relf.base)

            for c1, b1s in src_fields.items():
                for b1 in b1s:
                    n1 = FieldOfNode(type=NodeType.FIELD_OF, field=c1, base=b1)
                    self._add_edge(node_h, n1, logit(0.65))
                    for c2, b2s in dst_fields.items():
                        for b2 in b2s:
                            n2 = FieldOfNode(type=NodeType.FIELD_OF, field=c2, base=b2)
                            self._add_edge(n1, n2, logit(0.65), bidirectional=True)

        for chunk, target_addr in self.analyzer.fact_pointers.items():
            if target_addr in self.analyzer.addr_to_chunk:
                target_key: MemoryAddress = self.analyzer.addr_to_chunk[target_addr].get_address()
                node_ptr = PointerNode(type=NodeType.POINTER, chunk=chunk, target=target_key)
                self._add_node(node_ptr, 0.8)
                self._add_edge(SingleNode(type=NodeType.PRIMITIVE_VAR, chunk=chunk), node_ptr, W_UP)

    def _normalize_local_constraints(self, logits: Dict[Node, float]):

        for c in self.analyzer.all_chunks:
            field_nodes = self.field_nodes[c]

            field_score = logit(0.2)
            if field_nodes:
                field_score = max(logits.get(n, logit(0.2)) for n in field_nodes)

            role_logits = [
                logits.get(SingleNode(type=NodeType.SCALAR, chunk=c), logit(0.34)),
                field_score,
                logits.get(SingleNode(type=NodeType.ARRAY_ELEM, chunk=c), logit(0.33)),
            ]
            probs = self._softmax_by_logits(role_logits)
            logits[SingleNode(type=NodeType.SCALAR, chunk=c)] = clamp(logit(probs[0]), -LOGIT_CLAMP, LOGIT_CLAMP)
            logits[SingleNode(type=NodeType.ARRAY_ELEM, chunk=c)] = clamp(logit(probs[2]), -LOGIT_CLAMP, LOGIT_CLAMP)

            if field_nodes:
                base_logits = [logits.get(n, logit(0.2)) for n in field_nodes]
                base_probs = self._softmax_by_logits(base_logits)
                for n, p in zip(field_nodes, base_probs):
                    logits[n] = clamp(logit(p), -LOGIT_CLAMP, LOGIT_CLAMP)

    def type_infer(self, max_iter: int = 30, tolerance: float = 1e-3, alpha: float = 0.35):
        print("[*] Building Probabilistic Factor Graph...")
        self._build_factor_graph()
        edge_count = sum(len(v) for v in self.edges.values())
        print(f"[*] Starting Inference on {len(self.nodes)} variables and {edge_count} edges...")

        current_logits = {n: self.prior_logits[n] for n in self.nodes}
        for n in self.nodes:
            current_logits[n] = clamp(current_logits[n], -LOGIT_CLAMP, LOGIT_CLAMP)

        for iteration in range(max_iter):
            next_logits: Dict[Node, float] = {}
            max_diff = 0.0
            for target_node in self.nodes:
                msg_sum = 0.0
                deg_t = max(1, self.degree.get(target_node, 1))
                for src_node, weight in self.edges[target_node]:
                    p_src = expit(current_logits[src_node])
                    evidence = p_src - 0.5
                    deg_s = max(1, self.degree.get(src_node, 1))
                    msg_sum += weight * evidence / math.sqrt(deg_s * deg_t)
                target_prior = self.prior_logits[target_node]
                blended = (1 - alpha) * current_logits[target_node] + alpha * (target_prior + msg_sum)
                new_logit = clamp(blended, -LOGIT_CLAMP, LOGIT_CLAMP)
                next_logits[target_node] = new_logit
                max_diff = max(max_diff, abs(new_logit - current_logits[target_node]))

            self._normalize_local_constraints(next_logits)
            current_logits = next_logits

            if max_diff < tolerance:
                print(f"[*] Inference converged at iteration {iteration + 1}")
                break

        self.beliefs = {n: expit(l) for n, l in current_logits.items()}
        self.dump_results()

    def dump_results(self, threshold: float = 0.6):
        print("\n" + "=" * 50)
        print(" OSPREY RECOVERY RESULTS (Confidence > {:.1f}%)".format(threshold * 100))
        print("=" * 50)

        by_type: Dict[NodeType, List[Tuple[Node, float]]] = defaultdict(list)
        for node, prob in self.beliefs.items():
            if prob >= threshold:
                by_type[node.type].append((node, prob))

        if NodeType.FIELD_OF in by_type:
            print("\n[+] Recovered Fields:")
            rows = sorted(by_type[NodeType.FIELD_OF], key=lambda x: (x[0].field.region.id, x[0].field.offset, x[0].base.offset))
            for node, prob in rows:
                chunk = node.field
                base = node.base
                print(f"  - {chunk} base={base} -> Prob: {prob:.4f}")

        if NodeType.ARRAY in by_type:
            print("\n[+] Recovered Arrays:")
            rows = sorted(by_type[NodeType.ARRAY], key=lambda x: (x[0].array_relation.region.id, x[0].array_relation.lo))
            for arr, prob in rows:
                print(f"  - Region:{arr.array_relation.region.id:x}[offset {arr.array_relation.lo:x} ~ {arr.array_relation.hi:x}], element_size:{arr.array_relation.elem} -> Prob: {prob:.4f}")

        if NodeType.SCALAR in by_type:
            print("\n[+] Recovered Scalar Variables:")
            scalar_rows = sorted(by_type[NodeType.SCALAR], key=lambda x: (x[0].chunk.region.id, x[0].chunk.offset))
            for node, prob in scalar_rows:
                print(f"  - {node.chunk} -> Prob: {prob:.4f}")

        if NodeType.POINTER in by_type:
            print("\n[+] Recovered Pointer Candidates:")
            ptr_rows = sorted(by_type[NodeType.POINTER], key=lambda x: (x[0].chunk.region.id, x[0].chunk.offset))
            for node, prob in ptr_rows:
                print(f"  - {node.chunk} -> target={node.target} Prob: {prob:.4f}")
        

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