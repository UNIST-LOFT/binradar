#!/usr/bin/env python3
import os
import argparse
import subprocess
import struct
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Union, Tuple, cast
import shutil
import re
import enum

SCRIPT_DIR = Path(__file__).parent.resolve()
BRPATCH_SOURCE = SCRIPT_DIR.parent / "loftix" / "brpatch.c"


CONSTANTS: Dict[str, int] = {
    "max1": 0,
    "min2": -2,
    "max2": 1,
    "min3": -4,
    "max3": 3,
    "min4": -8,
    "max4": 7,
    "min5": -16,
    "max5": 15,
    "min6": -32,
    "max6": 31,
    "min7": -64,
    "max7": 63,
    "min8": -128,
    "max8": 127,
    "min9": -256,
    "min16": -32768,
    "max16": 32767,
    "min17": -65536,
    "min32": -2147483648,
    "max32": 2147483647,
    "min33": -4294967296,
    "min64": -9223372036854775808,
    "max64": 9223372036854775807,
}

REGISTER_TO_VAR: Dict[str, int] = {
    "rax": 0,
    "rbx": 1,
    "rcx": 2,
    "rdx": 3,
    "rsi": 4,
    "rdi": 5,
    "rsp": 6,
    "rbp": 7,
    "r8": 8,
    "r9": 9,
    "r10": 10,
    "r11": 11,
    "r12": 12,
    "r13": 13,
    "r14": 14,
    "r15": 15,
}

TOKEN_RE = re.compile(
    r"<=|>=|==|!=|<<|>>|[()~+\-*/%&|^<>]|[A-Za-z_][A-Za-z0-9_]*|\d+"
)

AstNode = Union[
    Tuple[str, int],              # ("const", value) | ("var", index)
    Tuple[str, "AstNode"],        # unary
    Tuple[str, "AstNode", "AstNode"],  # binary
]

class Parser:
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def pop(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None:
            raise ValueError("unexpected end of predicate")
        if expected is not None and tok != expected:
            raise ValueError(f"expected {expected!r}, got {tok!r}")
        self.pos += 1
        return tok

    def parse(self) -> AstNode:
        node = self.parse_bitor()
        if self.peek() is not None:
            raise ValueError(f"unexpected trailing token: {self.peek()!r}")
        return node

    def parse_bitor(self) -> AstNode:
        node = self.parse_xor()
        while self.peek() == "|":
            self.pop("|")
            node = ("|", node, self.parse_xor())
        return node

    def parse_xor(self) -> AstNode:
        node = self.parse_bitand()
        while self.peek() == "^":
            self.pop("^")
            node = ("^", node, self.parse_bitand())
        return node

    def parse_bitand(self) -> AstNode:
        node = self.parse_equality()
        while self.peek() == "&":
            self.pop("&")
            node = ("&", node, self.parse_equality())
        return node

    def parse_equality(self) -> AstNode:
        node = self.parse_relational()
        while self.peek() in ("==", "!="):
            op = self.pop()
            node = (op, node, self.parse_relational())
        return node

    def parse_relational(self) -> AstNode:
        node = self.parse_shift()
        while self.peek() in ("<", "<=", ">", ">="):
            op = self.pop()
            node = (op, node, self.parse_shift())
        return node

    def parse_shift(self) -> AstNode:
        node = self.parse_additive()
        while self.peek() in ("<<", ">>"):
            op = self.pop()
            node = (op, node, self.parse_additive())
        return node

    def parse_additive(self) -> AstNode:
        node = self.parse_multiplicative()
        while self.peek() in ("+", "-"):
            op = self.pop()
            node = (op, node, self.parse_multiplicative())
        return node

    def parse_multiplicative(self) -> AstNode:
        node = self.parse_unary()
        while self.peek() in ("*", "/", "%"):
            op = self.pop()
            node = (op, node, self.parse_unary())
        return node

    def parse_unary(self) -> AstNode:
        tok = self.peek()
        if tok == "+":
            self.pop("+")
            return ("u+", self.parse_unary())
        if tok == "-":
            self.pop("-")
            return ("u-", self.parse_unary())
        if tok == "~":
            self.pop("~")
            return ("u~", self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> AstNode:
        tok = self.peek()
        if tok == "(":
            self.pop("(")
            node = self.parse_bitor()
            self.pop(")")
            return node

        tok = self.pop()
        if tok.isdigit():
            return ("const", int(tok))
        if tok in CONSTANTS:
            return ("const", CONSTANTS[tok])
        if tok in REGISTER_TO_VAR:
            return ("var", REGISTER_TO_VAR[tok])
        raise ValueError(f"unknown identifier: {tok}")

def emit_patch(node: AstNode) -> str:
    kind = node[0]

    if kind == "const":
        value = node[1]
        if type(value) != int:
            raise ValueError(f"invalid constant value: {value!r}")
        return f"p{value}" if value >= 0 else f"n{-value}"

    if kind == "var":
        value = node[1]
        if type(value) != int:
            raise ValueError(f"invalid variable value: {value!r}")
        return f"v{value}"

    if kind == "u+":
        return emit_patch(cast(AstNode, node[1]))

    if kind == "u-":
        return f"-p0{emit_patch(cast(AstNode, node[1]))}"

    if kind == "u~":
        return f"~{emit_patch(cast(AstNode, node[1]))}"

    op_map = {
        "+": "+",
        "-": "-",
        "*": "*",
        "/": "/",
        "%": "%",
        "&": "&",
        "|": "|",
        "^": "^",
        "<<": "l",
        ">>": "r",
        "<": "<",
        "<=": "<=",
        "==": "=",
        ">=": ">=",
        ">": ">",
        "!=": "!",
    }

    if len(node) != 3 or kind not in op_map:
        raise ValueError(f"unsupported AST node: {node!r}")

    _, lhs, rhs = node
    return f"{op_map[kind]}{emit_patch(lhs)}{emit_patch(rhs)}"

def predicate_to_patch_str(predicate: str) -> str:
    tokens = TOKEN_RE.findall(predicate)
    if not tokens:
        raise ValueError("empty predicate")
    ast = Parser(tokens).parse()
    return emit_patch(ast)

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

PAGE_SIZE = 0x1000

class E9MapType(enum.IntEnum):
    TRAMPOLINE = 0
    RESERVE = 1
    REFACTOR = 2

E9_CONFIG_MAGIC = b"E9PATCH\0"
E9_CONFIG_STRUCT = struct.Struct("<8s16sIIqqqqIIII" + "II" * 5 + "I")
E9_MAP_STRUCT = struct.Struct("<iII")


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


def _parse_e9tool_patch_metadata(path: Path) -> Tuple[Optional[int], Dict[int, Tuple[int, int]]]:
    """Read patch offset and instruction address/length from e9tool JSON output.

    e9tool's JSON stream contains JSON-RPC instruction messages but the
    metadata payload can contain trailing commas.  Regex parsing therefore
    keeps this independent of whether the whole line is strict JSON.
    """
    patch_offset: Optional[int] = None
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
                patch_offset = int(match.group(1))

    return patch_offset, instructions


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


def extract_relocated_call_jumps(
    brpatched_binary: Path,
    metadata_path: Path,
    original_binary: Path,
    patch_addr: int,
) -> List[Tuple[int, int, int]]:
    """Find E9Patch's jump used to emulate the selected original call.

    With the default backend option ``-Ocall=false``, a relocated direct call
    is emitted as ``push original_next; jmp target``.  The jump is inside an
    E9Patch trampoline, not at the original patch address.  For a direct call
    the target is unambiguous; for an indirect call this returns indirect-jump
    candidates preceded by the return-address setup sequence.
    """
    if not metadata_path.exists():
        raise FileNotFoundError(f"e9tool metadata not found: {metadata_path}")

    patch_offset, instructions = _parse_e9tool_patch_metadata(metadata_path)
    site: Optional[Tuple[int, int]] = None
    if patch_offset is not None:
        site = instructions.get(patch_offset)
    if site is None:
        for address, length in instructions.values():
            if address == patch_addr:
                site = (address, length)
                break
    if site is None or patch_offset is None:
        raise ValueError("could not resolve patched instruction from e9tool metadata")

    _, instruction_length = site
    with original_binary.open("rb") as f:
        f.seek(patch_offset)
        original_instruction = f.read(instruction_length)
    call_kind, direct_displacement = _decode_call_site(original_instruction)
    if call_kind == "other":
        return []

    direct_target: Optional[int] = None
    if call_kind == "direct":
        if direct_displacement is None:
            raise ValueError("direct call has no rel32 displacement")
        direct_target = patch_addr + instruction_length + direct_displacement

    cfg = parse_e9patch_config(brpatched_binary)
    original_call_site = site[0]
    ret_addr = original_call_site + instruction_length
    candidates: List[Tuple[int, int, int]] = []
    for mapping in cfg["maps"]:
        if mapping["type"] != E9MapType.TRAMPOLINE:
            continue
        with brpatched_binary.open("rb") as f:
            f.seek(mapping["file_offset"])
            data = f.read(mapping["size"])
        if len(data) != mapping["size"]:
            raise ValueError("trampoline mapping extends past the patched binary")

        instructions_in_map = _parse_objdump_instructions(data, mapping["address"])
        for index, (address, _, text) in enumerate(instructions_in_map):
            if not text.startswith("jmp"):
                continue

            operand = text[len("jmp"):].strip()
            target_match = re.match(r"(?:0x)?([0-9a-fA-F]+)", operand)
            jump_target = int(target_match.group(1), 16) if target_match else None

            if direct_target is not None:
                if jump_target == direct_target:
                    candidates.append((address, original_call_site, ret_addr))
                continue

            # For an indirect call the rewritten instruction is an indirect
            # jmp.  It follows the push/lea/xchg return-address setup.  The
            # short look-back avoids treating E9Patch's conditional-goto
            # ``jmp *%fs:0x40`` as a call-equivalent jump.
            if jump_target is None:
                previous = instructions_in_map[max(0, index - 6):index]
                if any(item[2].startswith("push") for item in previous):
                    candidates.append((address, original_call_site, ret_addr))

    return sorted(set(candidates))

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


def extract_trampoline_info(
    brpatched_binary: Path,
    metadata_path: Optional[Path] = None,
    original_binary: Optional[Path] = None,
    patch_addr: Optional[int] = None,
) -> Dict[str, str]:
    # Parse e9patch embedded config from the patched binary to compute ASAN exclude ranges
    binradar_env: Dict[str, str] = dict()
    try:
        cfg = parse_e9patch_config(brpatched_binary)
        loader_base = cfg["loader_base"]
        loader_size = cfg["loader_size"]
        binradar_env["E9_LOADER_RANGE"] = f"0x{loader_base:x}-0x{loader_base + loader_size:x}"
        print(f"E9 loader range: 0x{loader_base:x}-0x{loader_base + loader_size:x}")

        reserves = cfg["reserves"]
        if reserves:
            reserve_start = min(r[0] for r in reserves)
            reserve_end = max(r[0] + r[1] for r in reserves)
            binradar_env["PATCH_RESERVE_RANGE"] = f"0x{reserve_start:x}-0x{reserve_end:x}"
            print(f"Full reserve range: 0x{reserve_start:x}-0x{reserve_end:x}")
            # for addr, size, prot in sorted(reserves, key=lambda x: x[0]):
            #     if 'x' in prot and "PATCH_RESERVE_ADDR" not in binradar_env:
            #         binradar_env["PATCH_RESERVE_ADDR"] = f"0x{addr:x}"
            #         print(f"Patch reserve addr: 0x{addr:x} prot={prot}")
            #         break
        trampolines = cfg["trampolines"]
        if trampolines:
            tramp_start = min(t[0] for t in trampolines)
            tramp_end = max(t[0] + t[1] for t in trampolines)
            binradar_env["E9_TRAMPOLINE_RANGE"] = f"0x{tramp_start:x}-0x{tramp_end:x}"
            print(f"E9 trampoline range: 0x{tramp_start:x}-0x{tramp_end:x}")

        if metadata_path is not None and original_binary is not None and patch_addr is not None:
            call_jumps = extract_relocated_call_jumps(
                brpatched_binary,
                metadata_path,
                original_binary,
                patch_addr,
            )
            if call_jumps:
                records = ",".join(
                    f"0x{jump_addr:x}:0x{call_site:x}:0x{ret_addr:x}"
                    for jump_addr, call_site, ret_addr in call_jumps
                )
                binradar_env["E9_RELOCATED_CALL_JUMPS"] = records
                # binradar_env["E9_RELOCATED_CALL_JUMP_COUNT"] = str(len(call_jumps))
                print(f"E9 relocated call jump(s): {records}")
            else:
                print("No relocated call-equivalent jump found for the patch site")
    except Exception as e:
        print(f"Warning: could not parse e9patch config: {e}")
    return binradar_env

def prepare_patch(configdir: Path, workdir: Path, binradar_env: Dict[str, str]):
    print(f"Preparing patch in {workdir}")
    # Read predicates
    predicates = list()
    predicates_file = workdir / "predicates"
    original_binary = workdir / f"{binradar_env['BINARY']}.orig"
    brpatched_binary = workdir / f"{binradar_env['BINARY']}.brpatched"
    
    if not original_binary.exists():
        print(f"Error: original binary {original_binary.name} not found in {workdir}")
        exit(1)
    
    if not predicates_file.exists():
        # In certain bug types, taosc may not generate predicates
        if brpatched_binary.exists():
            metadata_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
            patch_addr = int(binradar_env["PATCH_LOC"], 0)
            extracted_env = extract_trampoline_info(
                brpatched_binary,
                metadata_path if metadata_path.exists() else None,
                original_binary,
                patch_addr,
            )
            binradar_env.update(extracted_env)
            binradar_env["TOTAL_PATCHES"] = "1"
            print(f"Using existing brpatched binary at {brpatched_binary} to extract trampoline info.")
            return
        print(f"Error: {predicates_file.name} file not found in {workdir}")
        exit(1)
    
    with predicates_file.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            predicates.append(line)
    
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
    # Currently, we only select top 10 patches.
    patch_cnt = min(10, len(predicates))
    binradar_env["TOTAL_PATCHES"] = str(patch_cnt)
    brpatch_source = workdir / "brpatch.c"
    shutil.copy(BRPATCH_SOURCE, brpatch_source)
    brpatches_inc = workdir / "brpatches.inc"
    with brpatches_inc.open("w") as f:
        f.write("case 0:\n\treturn \"p0\";\n")
        for i in range(1, patch_cnt + 1):
            patch_str = predicate_to_patch_str(predicates[i - 1])
            f.write(f"case {i}:\n\treturn \"{patch_str}\";\n")
        f.write("default:\n\treturn \"p0\";\n")
    cmd = ["guix", "shell", "e9patch@1.0.0", "--", 
            "e9compile", "brpatch.c", f"-DTAOSC_DEST={dest}"]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error compiling patch: {result.stderr}")
        exit(1)
    else:
        print(f"Patch compiled successfully")
    
    # Patch the original binary
    patch_addr = binradar_env["PATCH_LOC"]
    metadata_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
    # dump metadata
    cmd = ["guix", "shell", "e9patch@1.0.0", "--", "e9tool", "--format=json", "-100", "-M", f"addr={patch_addr}", 
            "-P", "if dest(state)@brpatch goto", "-o", str(metadata_path), str(original_binary)]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error dumping patch metadata: {result.stderr}")
        exit(1)
    else:
        print(f"Patch metadata dumped successfully")
    cmd = ["guix", "shell", "e9patch@1.0.0", "--", "e9tool", "-100", "-M", f"addr={patch_addr}", 
            "-P", "if dest(state)@brpatch goto", "-o", str(brpatched_binary), str(original_binary)]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error preparing patch: {result.stderr}")
        exit(1)
    else:
        print(f"Prepare patch succeeded, patched binary at {brpatched_binary}")

    extracted_env = extract_trampoline_info(
        brpatched_binary,
        metadata_path,
        original_binary,
        int(patch_addr, 0),
    )
    binradar_env.update(extracted_env)


def create_binradar_env(configdir: Path, config_path: Path, workdir: Path) -> Dict[str, str]:    
    env = load_env(config_path)
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

def main():
    parser = argparse.ArgumentParser(
        description="binradar_setup: setup config files for binradar")
    parser.add_argument("-c", "--configdir", type=Path, required=False, default=Path.cwd(), help="Config directory (default: current directory)")
    parser.add_argument("-w", "--workdir", type=Path, required=False, default=Path.cwd() / "workdir", help="Working directory for the benchmark (default: ./workdir)")
    args = parser.parse_args()
    configdir: Path = args.configdir
    config_path = configdir / "config.env"
    if not config_path.exists():
        print(f"Error: config.env not found in {configdir}")
        return
    
    workdir: Path = args.workdir
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
    

if __name__ == "__main__":
    main()