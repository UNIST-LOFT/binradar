import sbsv
import os

class Parser():
    filepath: str
    parser: sbsv.parser
    chunks: dict
    access_counts: dict
    base_addrs: dict
    memcpy: dict
    malloced_sizes: dict
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.chunks = dict()
        self.access_counts = dict()
        self.base_addrs = dict()
        self.memcpy = dict()
        self.malloced_sizes = dict()

    def parse(self):
        # https://github.com/hsh814/sbsv
        self.parser = sbsv.parser()
        self.parser.add_custom_type("hex", lambda x: int(x, 16))
        self.parser.add_schema("[alloc] [start] [base: hex] [size: hex] [pc: hex]")
        self.parser.add_schema("[free] [done] [base: hex] [pc: hex]")
        self.parser.add_schema("[stack] [push] [sp: hex] [size: hex] [pc: hex] [depth: int] [sr-base: hex] [sr-size: hex]")
        self.parser.add_schema("[stack] [pop] [sp: hex] [base: hex] [pc: hex] [depth: int]")
        self.parser.add_schema("[global] [add] [base: hex] [size: hex] [name: str]")
        self.parser.add_schema("[loadh] [reg: str] [pc: hex] [addr: hex] [reg-base: hex] [size: hex] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[storeh] [reg: str] [pc: hex] [addr: hex] [reg-base: hex] [size: hex] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        self.parser.add_schema("[memmoveh] [src: hex] [dst: hex] [size: hex] [r0: hex] [r1: hex] [r2: hex] [r3: hex] [r4: hex] [r5: hex] [r6: hex] [r7: hex] [r8: hex] [r9: hex] [r10: hex] [r11: hex] [r12: hex] [r13: hex] [r14: hex] [r15: hex]")
        with open(self.filepath, 'r') as file:
            self.parser.load(file)

    def analyze_chunks(self):
        # data = self.parser.get_result_in_order(["[loadh]", "[storeh]"])
        data = self.parser.get_result()
        chunks = dict()
        for access in data["loadh"] + data["storeh"]:
            region = access["reg"]
            pc = access["pc"]
            addr = access["addr"]
            size = access["size"]
            reg_base = access["reg-base"]
            key = (addr, size)
            if key not in chunks:
                chunks[key] = len(chunks)
        self.chunks = chunks

    def analyze_primitive_facts(self):
        data = self.parser.get_result()
        for alloc in data["alloc"]["start"]:
            base = alloc["base"]
            size = alloc["size"]
            pc = alloc["pc"]
            if pc not in self.malloced_sizes:
                self.malloced_sizes[pc] = list()
            self.malloced_sizes[pc].append((base, size))
        for access in data["loadh"] + data["storeh"]:
            addr = access["addr"]
            size = access["size"]
            key = (addr, size)
            if key not in self.access_counts:
                self.access_counts[key] = 0
            self.access_counts[key] += 1
    
    def analyze(self):
        data = self.parser.get_result()
        for alloc in data["alloc"]["start"]:
            print(f"Allocation at PC {hex(alloc['pc'])}: Base {hex(alloc['base'])}, Size {hex(alloc['size'])}")
        for free in data["free"]["done"]:
            print(f"Free at PC {hex(free['pc'])}: Base {hex(free['base'])}")
        for stack_push in data["stack"]["push"]:
            print(f"Stack Push at PC {hex(stack_push['pc'])}: SP {hex(stack_push['sp'])}, Size {hex(stack_push['size'])}, Depth {stack_push['depth']}")
        for stack_pop in data["stack"]["pop"]:
            print(f"Stack Pop at PC {hex(stack_pop['pc'])}: SP {hex(stack_pop['sp'])}, Base {hex(stack_pop['base'])}, Depth {stack_pop['depth']}")
        for global_add in data["global"]["add"]:
            print(f"Global Variable '{global_add['name']}': Base {hex(global_add['base'])}, Size {hex(global_add['size'])}")
        for loadh in data["loadh"]:
            regs = {f"r{i}": loadh[f"r{i}"] for i in range(16)}
            print(f"LoadH at PC {hex(loadh['pc'])}: Reg {loadh['reg']}, Addr {hex(loadh['addr'])}, Size {hex(loadh['size'])}")
        for storeh in data["storeh"]:
            print(f"StoreH at PC {hex(storeh['pc'])}: Reg {storeh['reg']}, Addr {hex(storeh['addr'])}, Size {hex(storeh['size'])}")
        return data

if __name__ == "__main__":
    parser = Parser("/root/fuzzolic/tests/example5/workdir/tracer-forkserver.log")
    parser.parse()
    parser.analyze()