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

class Type(Enum):
    UNKNOWN = 0
    PRIMITIVE = 1  # int
    POINTER = 2
    STRUCT = 3
    ARRAY = 4

class RegionType(Enum):
    STACK = 0
    HEAP = 1
    GLOBAL = 2

@dataclass(frozen=True)
class MemoryRegion():
    type: RegionType
    id: int
    base_addr: int

    def __repr__(self):
        return f"Region({self.type.name}, id={self.id:x}, base={self.base_addr:x})"
    
    def __lt__(self, other):
        return self.base_addr < other.base_addr

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
    fact_pointers: Set[MemoryChunk]
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
        self.fact_pointers: Set[MemoryChunk] = set()
        
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

    def _resolve_memory_region(self, region_type: str, base_addr: int) -> Optional[MemoryRegion]:
        if region_type == "stack":
            for region in reversed(self.stack_frames):
                if region.base_addr == base_addr:
                    return region
        elif region_type == "heap":
            if base_addr in self.active_allocs:
                return self.active_allocs[base_addr]
        elif region_type == "global":
            if base_addr in self.global_vars:
                return self.global_vars[base_addr]
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
                    self.fact_pointers.add(chunk)
            
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
    rel_access_single: Set[Tuple[int, MemoryRegion]]
    rel_access_multi: Set[Tuple[int, MemoryRegion]]
    rel_alloc_unit: Dict[int, int]
    rel_data_flow_hint: Set[Tuple[MemoryRegion, MemoryRegion]]
    rel_unified_access_hint: Set[Tuple[MemoryRegion, MemoryRegion]]
    def __init__(self, analyzer: PrimitiveFactAnalyzer):
        self.analyzer = analyzer
        self.rel_access_single = set()
        self.rel_access_multi = set()
        self.rel_alloc_unit = dict()
        self.rel_data_flow_hint = set()
        self.rel_unified_access_hint = set()

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
    
    def infer_access_patterns(self):
        # R03, R04: Access Pattern Analysis
        # (pc, region) -> set(offsets)
        access_map: Dict[Tuple[int, MemoryRegion], Set[int]] = defaultdict(set)
        for (pc, chunk), count in self.analyzer.fact_access.items():
            access_map[(pc, chunk.region)].add(chunk.offset)
        
        for (pc, region), offsets in access_map.items():
            if len(offsets) == 1: # Single offset access -> scalar
                self.rel_access_single.add((pc, region))
            else: # Multiple offsets -> likely array
                self.rel_access_multi.add((pc, region))
    
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
    
    def infer_data_flow_memcpy(self):
        # R10: MemCpy -> if same offset, it hints same struct
        for src_chunk, dst_chunk, size in self.analyzer.fact_mem_copy:
            if self._same_region(src_chunk, dst_chunk):
                continue
            if src_chunk.offset == dst_chunk.offset:
                self.rel_data_flow_hint.add((src_chunk.region, dst_chunk.region))
    
    def infer_unified_access(self):
        # R11: different access address, same instruction -> likely same type
        inst_access_map: Dict[Tuple[int, int], Set[MemoryRegion]] = defaultdict(set) # pc -> set(regions)
        for (pc, chunk), count in self.analyzer.fact_access.items():
            inst_access_map[(pc, chunk.offset)].add(chunk.region)
        for (pc, offset), regions in inst_access_map.items():
            if len(regions) > 1:
                for r1 in regions:
                    for r2 in regions:
                        if r1 != r2:
                            self.rel_unified_access_hint.add((r1, r2))
    def infer(self):
        self.infer_access_patterns()
        self.infer_alloc_unit()
        self.infer_data_flow_memcpy()
        self.infer_unified_access()
        
class ProbabilisticInference:
    deterministic_inference: DeterministicInference
    type_prob: Dict[MemoryChunk, Dict[Type, float]]
    region_chunks: Dict[MemoryRegion, SortedList[MemoryChunk]]
    overlapping_chunks: Dict[MemoryChunk, Set[MemoryChunk]]
    def __init__(self, deterministic_inference: DeterministicInference):
        self.deterministic_inference = deterministic_inference
        self.type_prob = defaultdict(lambda: {t: 0.25 for t in [Type.PRIMITIVE, Type.POINTER, Type.STRUCT, Type.ARRAY]})
        self.region_chunks = defaultdict(lambda: SortedList(key=lambda c: c.offset))
        self.overlapping_chunks = defaultdict(set)
    
    def _normalize(self, dist: Dict[Type, float]):
        total = sum(dist.values())
        if total == 0:
            return
        for t in dist:
            dist[t] /= total

    def _apply_priors(self):
        primitive_sizes = {1, 2, 4, 8}
        for chunk in self.deterministic_inference.analyzer.all_chunks:
            self.region_chunks[chunk.region].add(chunk)
            if chunk.size in primitive_sizes:
                self.type_prob[chunk][Type.PRIMITIVE] += 1.0
                if chunk.size == self.deterministic_inference.analyzer.pointer_size:
                    self.type_prob[chunk][Type.POINTER] += 1.0
            else:
                self.type_prob[chunk][Type.STRUCT] += 1.0
                self.type_prob[chunk][Type.ARRAY] += 1.0
                self.type_prob[chunk][Type.POINTER] = 0.0 
            self._normalize(self.type_prob[chunk])
    
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
                prev_chunk = None # Overlapping
                self.overlapping_chunks[chunk].add(prev_chunk)
        elif idx + 1 < len(chunks):
            next_chunk: MemoryChunk = chunks[idx + 1]
            if next_chunk.offset > chunk.offset + chunk.size:
                next_chunk = None # Not adjacent
            elif next_chunk.offset  < chunk.offset + chunk.size:
                next_chunk = None # Overlapping
                self.overlapping_chunks[chunk].add(next_chunk)
        return prev_chunk, next_chunk
    
    # C_A: Access Patterns for primitive types
    def _apply_rules_CA(self, new_type_prob: Dict[MemoryChunk, Dict[Type, float]]):
        # C_A01: Access(i, v, k) -> PrimitiveVar(v)
        # C_A02: AdjacentChunk(v_1, v_2) && PrimitiveVar(v_1) -> PrimitiveVar(v_2)
        # C_A03: OverlappingChunk(v_1, v_2) -> PrimitiveVar(v_1) and PrimitiveVar(v_2)
        # C_A06: AccessSingleChunk(i, v.a.r) -> PrimitiveVar(v)
        for chunk, prob in self.type_prob.items():
            access_count = self.deterministic_inference.analyzer.access_cnt.get(chunk, 0)
            if access_count > 10: # C_A01: Frequently accessed chunk is likely primitive
                new_type_prob[chunk][Type.PRIMITIVE] *= 1.2
            # C_A02: If adjacent chunk is primitive, this chunk is more likely primitive
            prev_chunk, next_chunk = self._get_adjacent_chunks(chunk)
            new_type_prob[chunk][Type.PRIMITIVE] += 0.2 * (self.type_prob[prev_chunk][Type.PRIMITIVE] if prev_chunk else 0)
            new_type_prob[chunk][Type.PRIMITIVE] += 0.2 * (self.type_prob[next_chunk][Type.PRIMITIVE] if next_chunk else 0)
            # C_A06: If accessed with single offset, more likely primitive
            for (pc, region) in self.deterministic_inference.rel_access_single:
                if chunk.region == region:
                    new_type_prob[chunk][Type.PRIMITIVE] *= 1.3
                    new_type_prob[chunk][Type.ARRAY] *= 0.7
                    new_type_prob[chunk][Type.STRUCT] *= 0.7
        # C_A03: If overlapping chunk is primitive, this chunk is likely primitive
        for chunk in self.overlapping_chunks:
            overlap_chunk = self.overlapping_chunks.get(chunk, [])
            new_type_prob[chunk][Type.PRIMITIVE] *= 1.0 + min(0.2 * len(overlap_chunk), 1.0)    
    
    # C_B: Access Patterns for array
    def _apply_rules_CB(self, new_type_prob: Dict[MemoryChunk, Dict[Type, float]]):
        # C_B01: AllocUnit -> if access pattern matches alloc unit, more likely array
        for pc, alloc_unit in self.deterministic_inference.rel_alloc_unit.items():
            for chunk in self.type_prob:
                if chunk.region.type == RegionType.HEAP and chunk.region.id == pc:
                    if chunk.size == alloc_unit:
                        new_type_prob[chunk][Type.STRUCT] *= 1.2
                        new_type_prob[chunk][Type.ARRAY] *= 1.2
                    elif chunk.size % alloc_unit == 0:
                        new_type_prob[chunk][Type.ARRAY] *= 1.3
        # C_B02: AccessMultiChunk(i, v.a.r) -> ArrayVar(v)
        # Accessed with multiple offsets -> more likely array, less likely primitive
        for (pc, region) in self.deterministic_inference.rel_access_multi:
            for (acc_pc, chunk), _ in self.deterministic_inference.analyzer.fact_access.items():
                if acc_pc == pc and chunk.region == region:
                    new_type_prob[chunk][Type.ARRAY] *= 1.5
                    new_type_prob[chunk][Type.PRIMITIVE] *= 0.5
        
    # C_C: Heap structure
    def _apply_rules_CC(self, new_type_prob: Dict[MemoryChunk, Dict[Type, float]]):
        pass
    
    # C_D: Struct, Pointer
    def _apply_rules_CD(self, new_type_prob: Dict[MemoryChunk, Dict[Type, float]]):
        # C_D01: DataFlowHint(Memcpy) -> SameType
        for (src, dst) in self.deterministic_inference.rel_data_flow_hint:
            if src in self.type_prob and dst in self.type_prob:
                for t in Type:
                    if t == Type.UNKNOWN:
                        continue
                    avg_prob = (self.type_prob[src][t] + self.type_prob[dst][t]) / 2
                    new_type_prob[src][t] = avg_prob
                    new_type_prob[dst][t] = avg_prob
        # C_D11: PointsTo(v, a) -> PointerVar(v)
        for chunk in self.deterministic_inference.analyzer.fact_pointers:
            new_type_prob[chunk][Type.POINTER] *= 2.0
            new_type_prob[chunk][Type.PRIMITIVE] *= 0.1
        
    def _update_with_deterministic(self):
        new_type_prob = {c: d.copy() for c, d in self.type_prob.items()}
        self._apply_rules_CA(new_type_prob)
        self._apply_rules_CB(new_type_prob)
        self._apply_rules_CC(new_type_prob)
        self._apply_rules_CD(new_type_prob)
        # Finished
        for chunk in new_type_prob:
            self._normalize(new_type_prob[chunk])
        self.type_prob = new_type_prob
    
    def dump_results(self):
        for region, chunks in self.region_chunks.items():
            for chunk in chunks:
                prob = self.type_prob[chunk]
                inferred_type = max(prob, key=prob.get)
                print(f"[osprey] [reg {region}] [chunk off={chunk.offset:x} sz={chunk.size}] [type {inferred_type.name}] [prob {prob}]")

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