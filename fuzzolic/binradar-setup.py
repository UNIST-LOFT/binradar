#!/usr/bin/env python3
import argparse
import enum
import hashlib
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
from typing import Dict, List, Optional, Tuple, Union, cast

SCRIPT_DIR = Path(__file__).parent.resolve()
ROOT_DIR = SCRIPT_DIR.parent
BENCHMARK_SCRIPTS = ROOT_DIR / "benchmarks" / "scripts"
BRPATCH_SOURCE = ROOT_DIR / "benchmarks" / "loftix" / "brpatch.c"
BRPATCH_PREFILTER_SOURCE = ROOT_DIR / "benchmarks" / "loftix" / "brpatch-prefilter.c"
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

INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1
_MASK64 = (1 << 64) - 1

# sbsv schemas for the rows this module parses:
#   [prefilter-state] [v0 N] [v1 N] ... [v15 N]  (written by
#     brpatch-prefilter.c::dest to the PATCH_FD pipe)
#   [prefilter] [res] [id N] [pass true|false] [new-id N|-1] (prefilter.sbsv)
#   [prefilter] [done] [total N] [survived N] [time T]  (prefilter.sbsv marker)
PREFILTER_STATE_SCHEMA = (
    "[prefilter-state] " + " ".join(f"[v{i}: int]" for i in range(16))
)

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

# Taosc predicate families (see agent-docs/info/TAOSC_PREDICATE_COMPATIBILITY_PLAN.md).
class PredicateFamily(enum.Enum):
    GENERIC_ERM = "generic-erm"
    CWE119_ERM = "cwe119-erm"
    CWE119_DIRECT = "cwe119-direct"
    TAOSC_SPECIALIZED = "taosc-specialized"


@dataclass(frozen=True)
class RegisterCell:
    register_index: int


@dataclass(frozen=True)
class StackCell:
    width_bits: int  # 8, 16, 32 or 64
    index: int       # element index, not byte offset


StateCell = Union[RegisterCell, StackCell]


@dataclass(frozen=True)
class Cwe119PointerPredicate:
    cell: StateCell


@dataclass(frozen=True)
class Cwe119SizePredicate:
    scale: int  # 1, 2, 4 or 8
    cell: StateCell


Cwe119Predicate = Union[Cwe119PointerPredicate, Cwe119SizePredicate]


@dataclass(frozen=True)
class PredicateRecord:
    runtime_id: int
    source_line: int
    source_text: str
    parsed: Union[str, Cwe119Predicate]  # generic: encoded patch string


# The closed CWE-119 grammar emitted by utils/taosc/cwe119/filter.zig
# (revision 61f9f3a).  Pointer predicates require both textual cell
# occurrences to be identical; size predicates use scales 1/2/4/8.
_CWE119_POINTER_RE = re.compile(
    r"^(?P<c1>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint64_t \*\)s->rsp\)\[[0-9]+\]) >= i->begin && "
    r"(?P<c2>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint64_t \*\)s->rsp\)\[[0-9]+\]) < i->end$")
_CWE119_SIZE_RE = re.compile(
    r"^(?P<scale>[1-9][0-9]*) \* "
    r"(?P<cell>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint(?:8|16|32)_t \*\)s->rsp\)\[[0-9]+\]) < i->end - i->begin$")
_CWE119_STACK_CELL_RE = re.compile(r"\(\(uint(?P<width>8|16|32|64)_t \*\)s->rsp\)\[(?P<index>[0-9]+)\]")


def _parse_cwe119_cell(text: str) -> StateCell:
    """Parse one CWE-119 cell (register or typed stack cell)."""
    if text.startswith("s->"):
        return RegisterCell(REGISTER_TO_VAR[text[3:]])
    match = _CWE119_STACK_CELL_RE.match(text)
    if match is None:
        raise ValueError(f"invalid CWE-119 cell: {text!r}")
    return StackCell(int(match.group("width")), int(match.group("index")))


def parse_cwe119_predicate(line: str) -> Cwe119Predicate:
    """Parse one CWE-119 predicate line into a typed descriptor.

    Raises ValueError with a reason on any line outside the closed
    filter.zig grammar.
    """
    match = _CWE119_POINTER_RE.match(line)
    if match is not None:
        if match.group("c1") != match.group("c2"):
            raise ValueError(
                "pointer predicate cells differ: "
                f"{match.group('c1')!r} vs {match.group('c2')!r}")
        return Cwe119PointerPredicate(_parse_cwe119_cell(match.group("c1")))
    match = _CWE119_SIZE_RE.match(line)
    if match is not None:
        scale = int(match.group("scale"))
        if scale not in (1, 2, 4, 8):
            raise ValueError(f"unsupported CWE-119 size scale: {scale}")
        return Cwe119SizePredicate(scale, _parse_cwe119_cell(match.group("cell")))
    raise ValueError("not a CWE-119 predicate")


def classify_predicate_line(line: str) -> Optional[str]:
    """Return the family of one non-empty predicate line, or None if it is
    neither a generic nor a CWE-119 predicate."""
    if "i->begin" in line or "i->end" in line or "s->" in line:
        return PredicateFamily.CWE119_ERM.value
    return PredicateFamily.GENERIC_ERM.value


def predicates_sha256(predicates_file: Path) -> str:
    """SHA-256 of the exact predicates file bytes (prefilter identity)."""
    return hashlib.sha256(predicates_file.read_bytes()).hexdigest()

# Strict generic lexer: every input byte must be consumed as a token or
# whitespace.  Unknown punctuation is an error, never silently skipped.
_GENERIC_TOKEN_RE = re.compile(
    r"\s+|<=|>=|==|!=|<<|>>|[()~+\-*/%&|^<>]|[A-Za-z_][A-Za-z0-9_]*|\d+"
)


def tokenize_generic(predicate: str) -> List[str]:
    """Tokenize a generic predicate, rejecting any unrecognized byte."""
    tokens: List[str] = []
    pos = 0
    while pos < len(predicate):
        match = _GENERIC_TOKEN_RE.match(predicate, pos)
        if match is None:
            raise ValueError(
                f"unexpected character {predicate[pos]!r} at column {pos + 1}")
        token = match.group(0)
        if not token.isspace():
            tokens.append(token)
        pos = match.end()
    return tokens

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
    tokens = tokenize_generic(predicate)
    if not tokens:
        raise ValueError("empty predicate")
    ast = Parser(tokens).parse()
    return emit_patch(ast)


def predicate_to_branch_patch_str(predicate: str) -> str:
    """Encode taosc's predicate as BinRadar's branch condition.

    Taosc's generic patch jumps when its generated predicate is zero, while
    brpatch.c jumps when the encoded expression is non-zero.
    """
    return f"={predicate_to_patch_str(predicate)}p0"


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


def load_predicates(file: Path) -> List[Tuple[int, str]]:
    """Load non-empty predicates with their physical source line numbers."""
    predicates: List[Tuple[int, str]] = list()
    with file.open("r") as f:
        for line_number, line in enumerate(f, start=1):
            predicate = line.strip()
            if predicate:
                predicates.append((line_number, predicate))
    return predicates


# Taosc allocator trace artifacts (utils/taosc/cwe119/synth.in): the
# allocator kind is detected from exactly one complete supported set of
# trace/<fn>.calls and trace/<fn>.returns files.
ALLOCATOR_KINDS = ("malloc", "calloc", "realloc")


@dataclass(frozen=True)
class AllocatorTrace:
    kind: str  # "malloc" | "calloc" | "realloc"
    calls: List[Tuple[int, str]]  # (bit-index, hex address), in order
    returns: List[str]            # hex addresses, in order


@dataclass(frozen=True)
class InstrumentationSpec:
    """Ordered E9 instrumentation: (address, plugin-action) pairs.

    The same spec renders the JSON-metadata and final-binary e9tool
    commands, so both describe identical instrumentation (plan §6.3).
    """
    entries: Tuple[Tuple[str, str], ...]
    o0: bool = False


def build_instrumentation_spec(allocator: AllocatorTrace, patch_loc: str,
                               patch_action: str,
                               plugin_name: str = "brpatch") -> InstrumentationSpec:
    """Build the CWE-119 multipoint instrumentation spec.

    Mirrors utils/taosc/cwe119/synth.in::e9trace: the first call address
    receives set_size(rdi,rsi), later call entries receive mark(bit), the
    first return address receives set_base(rax), then the patch site.

    The allocator hooks and the patch action all use the same e9compile
    plugin (``plugin_name``); the prefilter uses ``brpatch-prefilter`` so
    its capture plugin is not confused with the final binary's brpatch.
    """
    entries = [(f"0x{allocator.calls[0][1]}", f"set_size(rdi,rsi)@{plugin_name}")]
    for bit, address in allocator.calls[1:]:
        entries.append((f"0x{address}", f"mark({bit})@{plugin_name}"))
    entries.append((f"0x{allocator.returns[0]}", f"set_base(rax)@{plugin_name}"))
    entries.append((patch_loc, patch_action))
    return InstrumentationSpec(tuple(entries), o0=True)


def e9tool_command(spec: InstrumentationSpec, out_path: Path,
                   original_binary: Path,
                   fmt: Optional[str] = None) -> List[str]:
    """Render the e9tool command for one instrumentation spec.

    The JSON-metadata and final-binary commands differ only in
    ``--format=json`` and the output path.
    """
    cmd = ["guix", "shell", "e9patch@1.0.1", "--", "e9tool"]
    if fmt is not None:
        cmd.append(f"--format={fmt}")
    cmd.append("-100")
    if spec.o0:
        cmd.append("-O0")
    for address, action in spec.entries:
        cmd += ["-M", f"addr={address}", "-P", action]
    cmd += ["-o", str(out_path), str(original_binary)]
    return cmd


def parse_allocator_trace(trace_dir: Path) -> Optional[AllocatorTrace]:
    """Parse the allocator trace artifacts in a workdir trace directory.

    Returns None when no complete supported artifact set is present.
    Raises ValueError on ambiguous or malformed artifacts.
    """
    present = [kind for kind in ALLOCATOR_KINDS
               if (trace_dir / f"{kind}.calls").exists()
               or (trace_dir / f"{kind}.returns").exists()]
    if not present:
        return None
    if len(present) > 1:
        raise ValueError(
            "ambiguous allocator trace: multiple of "
            f"{', '.join(present)} present in {trace_dir}")
    kind = present[0]
    calls_path = trace_dir / f"{kind}.calls"
    returns_path = trace_dir / f"{kind}.returns"
    if not calls_path.exists() or not returns_path.exists():
        raise ValueError(
            f"incomplete allocator trace for {kind}: need both "
            f"{calls_path.name} and {returns_path.name} in {trace_dir}")

    calls: List[Tuple[int, str]] = []
    with calls_path.open("r") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            fields = line.split()
            if len(fields) != 2 or not fields[0].isdigit() \
                    or not re.fullmatch(r"[0-9a-fA-F]+", fields[1]):
                raise ValueError(
                    f"{calls_path.name}:{line_number}: expected "
                    f"'<bit-index> <hex-address>', got {line!r}")
            bit_index = int(fields[0])
            if bit_index >= 64:
                raise ValueError(
                    f"{calls_path.name}:{line_number}: bit index {bit_index} "
                    "does not fit Taosc's 64-bit trace mask")
            calls.append((bit_index, fields[1].lower()))

    returns: List[str] = []
    with returns_path.open("r") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            if not re.fullmatch(r"[0-9a-fA-F]+", line):
                raise ValueError(
                    f"{returns_path.name}:{line_number}: expected a hex "
                    f"address, got {line!r}")
            returns.append(line.lower())

    if not calls:
        raise ValueError(f"{calls_path.name} is empty")
    if not returns:
        raise ValueError(f"{returns_path.name} is empty")
    return AllocatorTrace(kind, calls, returns)


def detect_predicate_family(workdir: Path) -> Tuple[PredicateFamily, Optional[AllocatorTrace]]:
    """Classify the workdir's patch family (plan §6.1).

    Returns (family, allocator_trace).  Raises ValueError with a
    predicates:<line>: <reason> diagnostic on malformed predicate files.
    """
    predicates_file = workdir / "predicates"
    trace_dir = workdir / "trace"
    allocator = parse_allocator_trace(trace_dir) if trace_dir.is_dir() else None

    if allocator is not None:
        crash_address = (trace_dir / "crash.address").read_text().strip() \
            if (trace_dir / "crash.address").exists() else ""
        patch_location = (workdir / "patch-location").read_text().strip() \
            if (workdir / "patch-location").exists() else ""
        if crash_address == patch_location:
            return PredicateFamily.CWE119_DIRECT, allocator
        if not predicates_file.exists():
            raise ValueError(
                f"{predicates_file.name} not found in {workdir} "
                "(CWE-119 ERM requires non-empty predicates)")
        records = load_predicates(predicates_file)
        if not records:
            raise ValueError(
                f"{predicates_file.name} is empty in {workdir} "
                "(CWE-119 ERM requires non-empty predicates)")
        for source_line, predicate in records:
            if classify_predicate_line(predicate) != PredicateFamily.CWE119_ERM.value:
                raise ValueError(
                    f"predicates:{source_line}: not a CWE-119 predicate: "
                    f"{predicate!r}")
            try:
                parse_cwe119_predicate(predicate)
            except ValueError as e:
                raise ValueError(
                    f"predicates:{source_line}: {e}") from e
        return PredicateFamily.CWE119_ERM, allocator

    if not predicates_file.exists():
        return PredicateFamily.TAOSC_SPECIALIZED, None
    records = load_predicates(predicates_file)
    if not records:
        return PredicateFamily.TAOSC_SPECIALIZED, None
    for source_line, predicate in records:
        if classify_predicate_line(predicate) != PredicateFamily.GENERIC_ERM.value:
            raise ValueError(
                f"predicates:{source_line}: not a generic predicate: "
                f"{predicate!r}")
        try:
            predicate_to_branch_patch_str(predicate)
        except ValueError as e:
            raise ValueError(
                f"predicates:{source_line}: {e}") from e
    return PredicateFamily.GENERIC_ERM, None


def load_prefilter_passed_ids(prefilter_file: Path,
                              expected_kind: Optional[str] = None,
                              expected_sha256: Optional[str] = None,
                              ) -> Optional[Dict[int, int]]:
    """Read source predicate IDs and their compact runtime patch IDs.

    Each passing row must contain a positive, unique ``new-id``.  A false
    row must contain ``new-id -1``.  Returns ``None`` on malformed input so
    setup fails open and keeps every predicate.

    A ``[prefilter] [meta]`` row (written by write_prefilter) pins the
    predicate family and the exact predicates-file SHA-256.  When
    ``expected_kind``/``expected_sha256`` are given, a mismatching or
    missing metadata row fails open (returns None) so a stale prefilter
    from a different predicate file or family is never applied.
    """
    parser = sbsv.parser()
    parser.add_schema(
        "[prefilter] [res] [id: int] [pass: bool] [new-id: int]")
    parser.add_schema(
        "[prefilter] [done] [total: int] [survived: int] [time: float]")
    parser.add_schema(
        "[prefilter] [meta] [version: int] [kind: str] [sha256: str]")
    passed_ids: Dict[int, int] = dict()
    used_new_ids = set()
    meta_seen = False
    with prefilter_file.open("r") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = parser.parse_line_detached(line, line_number)
            except Exception:
                return None
            if row is None:
                return None
            if row.schema_name == "prefilter$done":
                continue
            if row.schema_name == "prefilter$meta":
                if meta_seen or row["version"] != 1:
                    return None
                meta_seen = True
                if expected_kind is not None and row["kind"] != expected_kind:
                    return None
                if expected_sha256 is not None \
                        and row["sha256"] != expected_sha256:
                    return None
                continue
            if row.schema_name != "prefilter$res":
                return None
            source_id = row["id"]
            new_id = row["new-id"]
            if row["pass"]:
                if source_id <= 0 or new_id <= 0:
                    return None
                if source_id in passed_ids or new_id in used_new_ids:
                    return None
                passed_ids[source_id] = new_id
                used_new_ids.add(new_id)
            elif new_id != -1:
                return None
    if expected_kind is not None and not meta_seen:
        return None
    if sorted(used_new_ids) != list(range(1, len(used_new_ids) + 1)):
        return None
    return passed_ids


class PrefilterTrap(Exception):
    """Arithmetic that would raise SIGFPE in C (div/mod by zero, INT64_MIN / -1)."""


def wrap64(v: int) -> int:
    """Reinterpret v as a signed 64-bit two's-complement integer."""
    v &= _MASK64
    return v - (1 << 64) if v >= (1 << 63) else v


def _parse_int(s: str, pos: List[int]) -> int:
    """Parse decimal digits; accumulate with the same wraparound as the
    int64_t arithmetic in brpatch.c::scani."""
    i = 0
    n = len(s)
    while pos[0] < n and "0" <= s[pos[0]] <= "9":
        i = wrap64(i * 10 + (ord(s[pos[0]]) - 48))
        pos[0] += 1
    return i


def _trunc_div(a: int, b: int) -> int:
    """C truncating division (round toward zero), not Python floor division."""
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _shift_left(a: int, b: int) -> int:
    """Mirror Zig std.math.shl(i64), including negative shift counts."""
    if b >= 64:
        return 0
    if b <= -64:
        return -1 if a < 0 else 0
    if b >= 0:
        return wrap64(a << b)
    return a >> -b


def _shift_right(a: int, b: int) -> int:
    """Mirror Zig std.math.shr(i64), including negative shift counts."""
    if b >= 64:
        return -1 if a < 0 else 0
    if b <= -64:
        return 0
    if b >= 0:
        return a >> b
    return wrap64(a << -b)


def eval_patch_str(s: str, env: List[int]) -> int:
    """Evaluate a prefix-Polish patch string with taosc's i64 semantics.

    Mirrors brpatch.c::eval exactly: constants p<N>/n<N>, variable lookup
    v<N> into env (16 captured STATE slots), unary ~, and the binary prefix
    operators + - * / % & | ^ l r = ! > >= < <=.  env must have at least
    16 entries.

    Raises PrefilterTrap on arithmetic that would SIGFPE in C.
    """
    pos = [0]

    def ev() -> int:
        op = s[pos[0]]
        pos[0] += 1
        if op == "n":  # negative integer
            return wrap64(-_parse_int(s, pos))
        if op == "p":  # positive integer
            return _parse_int(s, pos)
        if op == "v":  # variable lookup
            return env[_parse_int(s, pos)]
        if op == "~":  # bitwise not
            return wrap64(~ev())

        eq = pos[0] < len(s) and s[pos[0]] == "=" and op in "<>"
        if eq:
            pos[0] += 1

        a = ev()
        b = ev()

        if op == "=":
            return 1 if a == b else 0
        if op == "!":
            return 1 if a != b else 0
        if op == ">":
            return 1 if (a >= b if eq else a > b) else 0
        if op == "<":
            return 1 if (a <= b if eq else a < b) else 0
        if op == "+":
            return wrap64(a + b)
        if op == "-":
            return wrap64(a - b)
        if op == "*":
            return wrap64(a * b)
        if op == "&":
            return wrap64(a & b)
        if op == "|":
            return wrap64(a | b)
        if op == "^":
            return wrap64(a ^ b)
        if op == "l":  # Zig std.math.shl
            return _shift_left(a, b)
        if op == "r":  # Zig std.math.shr
            return _shift_right(a, b)
        if op == "/":
            if b == 0:
                raise PrefilterTrap("division by zero")
            if a == INT64_MIN and b == -1:
                raise PrefilterTrap("INT64_MIN / -1")
            return _trunc_div(a, b)
        if op == "%":
            if b == 0:
                raise PrefilterTrap("modulo by zero")
            if a == INT64_MIN and b == -1:
                raise PrefilterTrap("INT64_MIN % -1")
            q = _trunc_div(a, b)
            return wrap64(a - q * b)
        raise ValueError(f"unknown patch operator {op!r}")

    return ev()


def evaluate_predicate(predicate: str, states: List[List[int]]) -> Tuple[bool, str]:
    """Return (keep, note) for one predicate line.

    Taosc's generic patch jumps when a generated predicate evaluates to zero.
    The predicate is encoded as ``predicate == 0`` for brpatch.c, then kept
    iff that branch condition is non-zero on at least one captured state.

    A predicate that would trap in C on any captured state (division or
    modulo by zero, INT64_MIN / -1) is rejected: brpatch.c reports it as
    `br 2` and returns NULL, so the patch follows the original path and is
    filtered out by the FILTER phase.
    """
    try:
        patch_str = predicate_to_branch_patch_str(predicate)
    except Exception as e:
        # prepare_patch would crash on this predicate anyway; keep it so
        # the existing pipeline surfaces the error.
        return True, f"unparseable predicate kept ({e})"
    # Reject on any trap first, regardless of what other states evaluate to.
    for state in states:
        try:
            eval_patch_str(patch_str, state)
        except PrefilterTrap as e:
            return False, f"patch would trap in C ({e})"
    for state in states:
        if eval_patch_str(patch_str, state) != 0:
            return True, ""
    return False, "evaluates to 0 on all captured states"


def cwe119_branch_taken(predicate: Cwe119Predicate,
                        registers: List[int], stack: bytes,
                        clamps: List[Tuple[int, int]]) -> int:
    """Mirror brpatch.c::cwe119_branch_taken (plan §7.3).

    Returns 0 (no jump: some clamp matches), 1 (jump: no clamp matches) or
    2 (checked-multiply overflow: conservative no-jump, reported as br 2).
    Cells use the unsigned 64-bit bit-domain; stack loads are x86-64
    little-endian.  Zero-initialized clamps never match.
    """
    cell = predicate.cell
    if isinstance(cell, RegisterCell):
        value = registers[cell.register_index] & _MASK64
    else:
        width = cell.width_bits // 8
        offset = cell.index * width
        value = int.from_bytes(stack[offset:offset + width], "little")

    if isinstance(predicate, Cwe119PointerPredicate):
        for begin, end in clamps:
            if begin <= value < end:
                return 0
        return 1

    size = predicate.scale * value
    if size > _MASK64:
        return 2
    for begin, end in clamps:
        if size < (end - begin) & _MASK64:
            return 0
    return 1


# ---------------------------------------------------------------------------
# CWE-119 full-context prefilter snapshots (plan §8)
# ---------------------------------------------------------------------------

# Binary record written by brpatch-prefilter.c::capture_snapshot:
#   header:  magic u32, version u32, stack_size u64, flags u64
#   clamps:  256 * {begin u64, end u64}
#   regs:    16 * u64 (rax..r15)
#   stack:   stack_size bytes starting at state->rsp
PREFILTER_SNAPSHOT_MAGIC = 0x42525046  # "BRPF"
PREFILTER_SNAPSHOT_VERSION = 1
PREFILTER_SNAPSHOT_FLAG_TRUNCATED = 1
PREFILTER_SNAPSHOT_HEADER = struct.Struct("<IIQQ")
PREFILTER_SNAPSHOT_CLAMPS = struct.Struct("<" + "QQ" * 256)
PREFILTER_SNAPSHOT_REGS = struct.Struct("<" + "Q" * 16)


@dataclass(frozen=True)
class Cwe119Snapshot:
    """One captured patch-site full context (plan §8)."""
    clamps: Tuple[Tuple[int, int], ...]  # 256 (begin, end) pairs
    registers: Tuple[int, ...]           # 16 u64 bit patterns, rax..r15
    stack: bytes                         # exactly stack-size bytes
    truncated: bool = False              # capture hit the bound


def parse_cwe119_snapshots(data: bytes) -> Tuple[List[Cwe119Snapshot], bool]:
    """Parse the binary snapshot stream from the capture pipe.

    Returns (snapshots, truncated).  A header-only record with the
    truncation flag set marks the end of complete evidence; any trailing
    partial record is dropped.  Malformed records (bad magic/version,
    truncated body) stop parsing at the first bad record.
    """
    snapshots: List[Cwe119Snapshot] = []
    truncated = False
    offset = 0
    while offset + PREFILTER_SNAPSHOT_HEADER.size <= len(data):
        magic, version, stack_size, flags = \
            PREFILTER_SNAPSHOT_HEADER.unpack_from(data, offset)
        if magic != PREFILTER_SNAPSHOT_MAGIC or version != \
                PREFILTER_SNAPSHOT_VERSION:
            break
        offset += PREFILTER_SNAPSHOT_HEADER.size
        if flags & PREFILTER_SNAPSHOT_FLAG_TRUNCATED:
            truncated = True
            break
        body = PREFILTER_SNAPSHOT_CLAMPS.size + PREFILTER_SNAPSHOT_REGS.size \
            + stack_size
        if offset + body > len(data):
            break  # partial trailing record: not complete evidence
        clamps_raw = PREFILTER_SNAPSHOT_CLAMPS.unpack_from(data, offset)
        offset += PREFILTER_SNAPSHOT_CLAMPS.size
        regs = PREFILTER_SNAPSHOT_REGS.unpack_from(data, offset)
        offset += PREFILTER_SNAPSHOT_REGS.size
        stack = data[offset:offset + stack_size]
        offset += stack_size
        snapshots.append(Cwe119Snapshot(
            tuple((clamps_raw[i], clamps_raw[i + 1])
                  for i in range(0, len(clamps_raw), 2)),
            regs, stack))
    return snapshots, truncated


def cwe119_snapshot_branch_taken(predicate: Cwe119Predicate,
                                snapshot: Cwe119Snapshot) -> int:
    """Evaluate one CWE-119 descriptor against one captured snapshot.

    Same cell, unsigned comparison, checked-multiply, and !any_match rules
    as brpatch.c::cwe119_branch_taken (plan §8): 0 = no jump, 1 = jump,
    2 = checked-multiply overflow (conservative no-jump).
    """
    return cwe119_branch_taken(predicate, list(snapshot.registers),
                               snapshot.stack, list(snapshot.clamps))


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

    CWE-119 families compile the allocation tracker and binary snapshot
    capture in (BRPATCH_CWE119 + the allocator kind define); generic
    families keep the sbsv register capture.
    """
    shutil.copy(BRPATCH_PREFILTER_SOURCE, workdir / "brpatch-prefilter.c")
    cmd = ["guix", "shell", "e9patch@1.0.1", "--",
           "e9compile", "brpatch-prefilter.c", "-DTAOSC_DEST=0"]
    if allocator is not None:
        cmd += ["-DBRPATCH_CWE119",
                f"-DBRPATCH_ALLOC_{allocator.kind.upper()}"]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        raise RuntimeError(f"e9compile failed with exit code {result.returncode}")


def build_capture_binary(workdir: Path, configdir: Path, config: dict,
                         patch_loc: str,
                         allocator: Optional[AllocatorTrace] = None) -> Path:
    """Instrument the original binary with the capture plugin.

    CWE-119 families use the same ordered multipoint instrumentation spec
    as the final binary (allocator hooks then the patch site, plan §8);
    generic families patch the single PATCH_LOC site.

    Returns the path of <BINARY>.brprefilter.  Also dumps e9tool JSON
    metadata (needed by extract_trampoline_info) as
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


def capture_states(workdir: Path, configdir: Path, config: dict,
                   patch_loc: str,
                   allocator: Optional[AllocatorTrace] = None,
                   stack_size: Optional[int] = None,
                   ) -> Optional[Union[List[List[int]], List[Cwe119Snapshot]]]:
    """Run the POC once against <BINARY>.brprefilter and return the
    captured patch-site states.

    Generic families return a list of 16-slot STATE vectors; CWE-119
    families return a list of Cwe119Snapshot records (clamps + registers +
    stack).  Returns None if the run failed (timeout / subprocess error) so
    the caller can fail open.
    """
    if not QEMU_STACKTRACE_RELEASE.exists():
        print(f"Warning: {QEMU_STACKTRACE_RELEASE} not found")
        return None

    compile_capture_plugin(workdir, allocator)
    brprefilter = build_capture_binary(workdir, configdir, config, patch_loc,
                                       allocator)

    extracted = extract_trampoline_info(
        brprefilter,
        workdir / f"{config['BINARY']}.brprefilter.json",
        ensure_original_binary(workdir, configdir, config),
        int(patch_loc, 0),
        strict=(allocator is not None),
    )
    try:
        exclude_addrs = [extracted["PATCH_RESERVE_RANGE"],
                         extracted["E9_TRAMPOLINE_RANGE"],
                         extracted["E9_LOADER_RANGE"]]
    except KeyError as e:
        print(f"Warning: could not extract trampoline info from brprefilter: {e}")
        return None
    e9_relocated_calls: List[str] = []
    for record in extracted.get("E9_RELOCATED_CALL_JUMPS", "").split(","):
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
    for addr_range in exclude_addrs:
        command += ["--asan-exclude", addr_range]
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
            print("Warning: CWE-119 prefilter requires stack-size; "
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
        snapshots, truncated = parse_cwe119_snapshots(data)
        if truncated:
            print("Warning: CWE-119 prefilter capture truncated; "
                  "failing open (partial history is not complete evidence)")
            return None
        return snapshots
    return parse_state_lines(data.decode(errors="ignore"))


def parse_state_lines(data: str) -> List[List[int]]:
    """Parse [prefilter-state] sbsv lines from the capture pipe, one 16-slot
    STATE vector per line.  Non-state and malformed lines are skipped."""
    parser = sbsv.parser()
    parser.add_schema(PREFILTER_STATE_SCHEMA)
    states: List[List[int]] = []
    for line in data.splitlines():
        line = line.strip()
        if not line.startswith("[prefilter-state]"):
            continue
        try:
            row = parser.parse_line_detached(line)
        except ValueError:
            continue
        if row is None:
            continue
        states.append([row[f"v{i}"] for i in range(16)])
    return states


def write_prefilter(prefilter_file: Path, results: List[Tuple[int, bool, str, str]],
                    elapsed: float, kind: Optional[str] = None,
                    sha256: Optional[str] = None) -> None:
    """Write source predicate IDs and compact runtime patch IDs.

    Passing predicates receive consecutive ``new-id`` values starting at 1;
    rejected predicates receive ``new-id -1``.  Runtime patch IDs therefore
    remain compatible with ``range(1, TOTAL_PATCHES + 1)`` while ``id``
    preserves the predicate source line.

    A ``[prefilter] [meta]`` row pins the predicate family and the exact
    predicates-file SHA-256 so a stale prefilter can never be applied to a
    different predicate file or family (plan §6.2).
    """
    survived = 0
    with prefilter_file.open("w", encoding="utf-8") as f:
        if kind is not None and sha256 is not None:
            f.write(f"[prefilter] [meta] [version 1] [kind {kind}] "
                    f"[sha256 {sha256}]\n")
        for idx, passed, note, predicate in results:
            new_id = survived + 1 if passed else -1
            f.write(f"[prefilter] [res] [id {idx}] "
                    f"[pass {str(passed).lower()}] [new-id {new_id}] "
                    f"{predicate} ({(' ' + note) if note else ''})\n")
            if passed:
                survived += 1
        f.write(f"[prefilter] [done] [total {len(results)}] "
                f"[survived {survived}] [time {elapsed:.2f}]\n")
    print(f"[prefilter] [done] [total {len(results)}] "
          f"[survived {survived}] [time {elapsed:.2f}]")


class E9MapType(enum.IntEnum):
    TRAMPOLINE = 0
    RESERVE = 1
    REFACTOR = 2


E9_CONFIG_MAGIC = b"E9PATCH\0"
# Taosc's $mem0 shell expansion (utils/taosc/helpers.in): the four E9
# memory-operand fields of the matched instruction.
E9_MEM0 = "mem[0].base,mem[0].index,mem[0].scale,mem[0].disp"
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


def extract_trampoline_info(
    brpatched_binary: Path,
    metadata_path: Optional[Path] = None,
    original_binary: Optional[Path] = None,
    patch_addr: Optional[int] = None,
    strict: bool = False,
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
        if strict:
            raise
        print(f"Warning: could not parse e9patch config: {e}")
    return binradar_env


def _emit_brpatches_inc(brpatches_inc: Path,
                        selected: List[PredicateRecord]) -> None:
    """Write the typed brpatches.inc table (plan §5.2).

    Entry 0 is BR_PRED_FALSE.  Generic entries retain the current encoded
    ``predicate == 0`` prefix string; CWE-119 entries contain only validated
    enum/integer fields, never source text.
    """
    with brpatches_inc.open("w") as f:
        f.write("case 0:\n\treturn \"p0\";\n")
        for record in selected:
            if isinstance(record.parsed, str):
                f.write(f"case {record.runtime_id}:\n"
                        f"\treturn \"{record.parsed}\"; "
                        f"/* predicate line {record.source_line} */\n")
            elif isinstance(record.parsed, Cwe119PointerPredicate):
                cell = record.parsed.cell
                if isinstance(cell, RegisterCell):
                    f.write(f"case {record.runtime_id}:\n"
                            f"\treturn \"c1p{cell.register_index}\"; "
                            f"/* predicate line {record.source_line}: "
                            f"pointer register */\n")
                else:
                    f.write(f"case {record.runtime_id}:\n"
                            f"\treturn \"c1s{cell.width_bits}i{cell.index}\"; "
                            f"/* predicate line {record.source_line}: "
                            f"pointer stack cell */\n")
            else:
                size = cast(Cwe119SizePredicate, record.parsed)
                cell = size.cell
                if isinstance(cell, RegisterCell):
                    f.write(f"case {record.runtime_id}:\n"
                            f"\treturn \"c2p{cell.register_index}q{size.scale}\"; "
                            f"/* predicate line {record.source_line}: "
                            f"size register */\n")
                else:
                    f.write(f"case {record.runtime_id}:\n"
                            f"\treturn \"c2s{cell.width_bits}i{cell.index}"
                            f"q{size.scale}\"; "
                            f"/* predicate line {record.source_line}: "
                            f"size stack cell */\n")
        f.write("default:\n\treturn \"p0\";\n")


def _parse_predicate_records(predicates_file: Path,
                             family: PredicateFamily) -> List[PredicateRecord]:
    """Parse every non-empty predicate line into a PredicateRecord.

    Raises ValueError with a predicates:<line>: <reason> diagnostic on any
    malformed or mixed-family line.
    """
    records: List[PredicateRecord] = []
    with predicates_file.open("r") as f:
        for line_number, line in enumerate(f, start=1):
            predicate = line.strip()
            if not predicate:
                continue
            if family == PredicateFamily.CWE119_ERM:
                try:
                    parsed = parse_cwe119_predicate(predicate)
                except ValueError as e:
                    raise ValueError(
                        f"predicates:{line_number}: {e}") from e
            else:
                try:
                    parsed = predicate_to_branch_patch_str(predicate)
                except ValueError as e:
                    raise ValueError(
                        f"predicates:{line_number}: {e}") from e
            records.append(PredicateRecord(0, line_number, predicate, parsed))
    return records


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

    if family == PredicateFamily.CWE119_DIRECT:
        # The direct call-site metapatch has no predicate list: the E9
        # jnz($mem0,dest) decision is evaluated against the allocation
        # clamps at runtime.  A leftover predicates file is stale Taosc
        # output and must not be compiled in.  The binary is rebuilt with
        # BinRadar patch-id switching and [patch] logging (plan §7.4).
        if predicates_file.exists():
            print(f"Warning: ignoring stale {predicates_file.name} "
                  f"(CWE-119 direct call-site family)")
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
        compile_defines = [f"-DTAOSC_DEST={dest}", "-DBRPATCH_CWE119",
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
        # jnz(mem[0].base,mem[0].index,mem[0].scale,mem[0].disp,dest)
        # decision at the patch site.  Taosc's synth.in expands the shell
        # variable $mem0 to those four E9 memory-operand fields
        # (utils/taosc/helpers.in); e9tool zeroes them when the site has
        # no memory operand (e.g. a jne), matching Taosc's own output.
        patch_addr = binradar_env["PATCH_LOC"]
        metadata_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
        spec = build_instrumentation_spec(
            allocator, patch_addr,
            f"if jnz({E9_MEM0},{dest})@brpatch goto")
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

        extracted_env = extract_trampoline_info(
            brpatched_binary,
            metadata_path,
            original_binary,
            int(patch_addr, 0),
            strict=True,
        )
        binradar_env.update(extracted_env)
        print(f"Using CWE-119 direct call-site patch at "
              f"{binradar_env['PATCH_LOC']} (candidate id 1)")
        return

    if family == PredicateFamily.TAOSC_SPECIALIZED:
        # No predicates: taosc generated a specialized (CWE-369/476/617)
        # patch.  Reuse the prebuilt binary when present.
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

    # GENERIC_ERM or CWE119_ERM: parse every line strictly.
    try:
        predicate_records = _parse_predicate_records(predicates_file, family)
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)
    if not predicate_records:
        print(f"Error: {predicates_file.name} is empty in {workdir}")
        exit(1)

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
    if family == PredicateFamily.CWE119_ERM:
        compile_defines.append("-DBRPATCH_CWE119")
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
    # (plan §6.3): generic ERM patches the single PATCH_LOC site; CWE-119
    # ERM and direct builds add the allocator hooks (mark/set_size/set_base)
    # before the patch site.
    patch_addr = binradar_env["PATCH_LOC"]
    metadata_path = workdir / f"{binradar_env['BINARY']}.brpatched.json"
    if family == PredicateFamily.CWE119_ERM:
        spec = build_instrumentation_spec(
            allocator, patch_addr, "if dest(state)@brpatch goto")
    elif family == PredicateFamily.CWE119_DIRECT:
        spec = build_instrumentation_spec(
            allocator, patch_addr,
            f"if jnz({E9_MEM0},{dest})@brpatch goto")
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

    extracted_env = extract_trampoline_info(
        brpatched_binary,
        metadata_path,
        original_binary,
        int(patch_addr, 0),
        strict=(family == PredicateFamily.CWE119_ERM),
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

    # Classify the workdir first (plan §6.1): the CWE-119 direct family
    # has no predicate list to compact, so the prefilter is a no-op and
    # FILTER remains the behavioral gate.
    try:
        family, allocator = detect_predicate_family(workdir)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    if family == PredicateFamily.CWE119_DIRECT:
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

    if family == PredicateFamily.CWE119_ERM:
        # Full-context prefilter (plan §8): the capture binary carries the
        # same allocator hooks as the final binary and dumps binary
        # snapshots (clamps + registers + stack) at the patch site.  A
        # candidate passes iff it branches on at least one complete
        # captured state.  Truncation fails open (never rejects).
        assert allocator is not None
        stack_size_file = workdir / "stack-size"
        if not stack_size_file.exists():
            print(f"Error: {stack_size_file.name} file not found in "
                  f"{workdir} (CWE-119 prefilter needs the stack size)")
            sys.exit(1)
        stack_size = int(stack_size_file.read_text().strip())
        snapshots = capture_states(workdir, configdir, config, patch_loc,
                                   allocator, stack_size)
        if snapshots is None:
            print("Warning: CWE-119 prefilter capture failed; keeping all "
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

        print(f"Captured {len(snapshots)} CWE-119 snapshot(s)")
        results = []
        for source_id, predicate in predicate_records:
            parsed = parse_cwe119_predicate(predicate)
            passed = any(
                cwe119_snapshot_branch_taken(parsed, snapshot) == 1
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
