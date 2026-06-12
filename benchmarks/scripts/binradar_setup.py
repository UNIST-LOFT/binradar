#!/usr/bin/env python3
import os
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Union, Tuple
import shutil
import re
import json

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
        return emit_patch(node[1])

    if kind == "u-":
        return f"-p0{emit_patch(node[1])}"

    if kind == "u~":
        return f"~{emit_patch(node[1])}"

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

def run_fix(configdir: Path, config_path: Path, workdir: Path):
    print(f"Running fix command in {workdir} with config {config_path}")
    result = subprocess.run(["just", "fix", str(workdir)], cwd=configdir, env=os.environ.copy(), capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running fix: {result.stderr}")
    else:
        print(f"Fix output: {result.stdout}")

def prepare_patch(configdir: Path, workdir: Path, binradar_env: Dict[str, str]):
    print(f"Preparing patch in {workdir}")
    # Read predicates
    predicates = list()
    predicates_file = workdir / "predicates"
    if not predicates_file.exists():
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
    cmd = ["guix", "shell", "e9patch", "--", 
            "e9compile", "brpatch.c", f"-DTAOSC_DEST={dest}"]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error compiling patch: {result.stderr}")
        exit(1)
    else:
        print(f"Patch compiled successfully")
    # Patch the original binary
    original_binary = workdir / f"{binradar_env['BINARY']}.orig"
    if not original_binary.exists():
        print(f"Error: original binary {original_binary.name} not found in {workdir}")
        exit(1)
    brpatch_binary = workdir / f"{binradar_env['BINARY']}.brpatched"
    patch_addr = binradar_env["PATCH_LOC"]
    # dump metadata
    cmd = ["guix", "shell", "e9patch", "--", "e9tool", "--format=json", "-100", "-M", f"addr={patch_addr}", 
            "-P", "if dest(state)@brpatch goto", "-o", str(brpatch_binary), str(original_binary)]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error dumping patch metadata: {result.stderr}")
        exit(1)
    else:
        print(f"Patch metadata dumped successfully")
    json_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
    if not json_path.exists():
        print(f"Error: patch metadata {json_path.name} not found in {workdir}")
        exit(1)
    with json_path.open("r") as f:
        for line in f:
            data = json.loads(line)
            if data.get("method", "") == "reserve":
                params = data.get("params", {})
                if params.get("protection", "") == "r-x":
                    addr = params.get("address", None)
                    if addr is None:
                        print(f"Error: reserve patch metadata does not contain address")
                        exit(1)
                    binradar_env["PATCH_RESERVE_ADDR"] = f"0x{addr:x}"
                    print(f"Patch reserve metadata: addr=0x{addr:x}")
                    break
    cmd = ["guix", "shell", "e9patch", "--", "e9tool", "-100", "-M", f"addr={patch_addr}", 
            "-P", "if dest(state)@brpatch goto", "-o", str(brpatch_binary), str(original_binary)]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        print(f"Error preparing patch: {result.stderr}")
        exit(1)
    else:
        print(f"Prepare patch succeeded, patched binary at {brpatch_binary}")

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