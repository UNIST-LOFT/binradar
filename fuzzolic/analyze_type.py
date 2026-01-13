import sbsv
import os

class Parser():
    filepath: str
    parser: sbsv.parser
    def __init__(self, filepath):
        self.filepath = filepath

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
        with open(self.filepath, 'r') as file:
            self.parser.load(file)
        return self.parser

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
            print(f"LoadH at PC {hex(loadh['pc'])}: Reg {loadh['reg']}, Addr {hex(loadh['addr'])}, Size {hex(loadh['size'])}")
        for storeh in data["storeh"]:
            print(f"StoreH at PC {hex(storeh['pc'])}: Reg {storeh['reg']}, Addr {hex(storeh['addr'])}, Size {hex(storeh['size'])}")
        return data

parser = Parser("/root/fuzzolic/tests/example5/workdir/tracer-forkserver.log")
parser.parse()
parser.analyze()