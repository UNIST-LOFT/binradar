#!/usr/bin/env python3
"""
Taosc predicate management for BinRadar workdir setup.
Parsing, classification, evaluation, and lowering of the Taosc predicate
families (generic ERM, CWE-805 ERM, CWE-805 direct, taosc-specialized),
plus the allocator-trace instrumentation spec shared by the prefilter
and final binaries.  Split out of fuzzolic/binradar-setup.py.
"""

import enum
import hashlib
import json
import re
import struct
import sbsv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, cast

INT64_MIN = -(1 << 63)
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

# Taosc predicate families
class PredicateFamily(enum.Enum):
    GENERIC_ERM = "generic-erm"
    CWE805_ERM = "CWE805-erm"
    CWE805_DIRECT = "CWE805-direct"
    TAOSC_SPECIALIZED = "taosc-specialized"


# The exact strings Taosc writes to workdir/patch-format (utils/taosc/*/synth.in)
# and the BinRadar predicate family each one denotes.
PATCH_FORMAT_TO_FAMILY: Dict[str, PredicateFamily] = {
    "Single CWE-369": PredicateFamily.TAOSC_SPECIALIZED,
    "Single CWE-617": PredicateFamily.TAOSC_SPECIALIZED,
    "Single CWE-823": PredicateFamily.TAOSC_SPECIALIZED,
    "Single CWE-805": PredicateFamily.CWE805_DIRECT,
    "ERM CWE-805": PredicateFamily.CWE805_ERM,
    "ERM generic": PredicateFamily.GENERIC_ERM,
}


def read_patch_format(workdir: Path) -> Optional[str]:
    """Return the raw workdir/patch-format string, or None when absent."""
    patch_format_file = workdir / "patch-format"
    if not patch_format_file.exists():
        return None
    value = patch_format_file.read_text().strip()
    return value or None


def parse_patch_format(workdir: Path) -> Optional[PredicateFamily]:
    """Read workdir/patch-format and map it to a predicate family.

    Returns None when the file is absent or holds an unrecognized value, so
    callers can fall back to artifact-based classification.
    """
    value = read_patch_format(workdir)
    if value is None:
        return None
    return PATCH_FORMAT_TO_FAMILY.get(value)


@dataclass(frozen=True)
class RegisterCell:
    register_index: int


@dataclass(frozen=True)
class StackCell:
    width_bits: int  # 8, 16, 32 or 64
    index: int       # element index, not byte offset


StateCell = Union[RegisterCell, StackCell]


@dataclass(frozen=True)
class CWE805PointerPredicate:
    cell: StateCell


@dataclass(frozen=True)
class CWE805SizePredicate:
    scale: int  # 1, 2, 4 or 8
    cell: StateCell


CWE805Predicate = Union[CWE805PointerPredicate, CWE805SizePredicate]
ParsedPredicate = Union[str, CWE805Predicate]


@dataclass(frozen=True)
class PredicateRecord:
    runtime_id: int
    source_line: int
    source_text: str
    parsed: ParsedPredicate  # generic: encoded branch expression


# The closed CWE-805 grammar emitted by utils/taosc/CWE805/filter.zig
# (revision 61f9f3a).  Pointer predicates require both textual cell
# occurrences to be identical; size predicates use scales 1/2/4/8.
_CWE805_POINTER_RE = re.compile(
    r"^(?P<c1>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint64_t \*\)s->rsp\)\[[0-9]+\]) >= i->begin && "
    r"(?P<c2>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint64_t \*\)s->rsp\)\[[0-9]+\]) < i->end$")
_CWE805_SIZE_RE = re.compile(
    r"^(?P<scale>[1-9][0-9]*) \* "
    r"(?P<cell>s->(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)"
    r"|\(\(uint(?:8|16|32)_t \*\)s->rsp\)\[[0-9]+\]) < i->end - i->begin$")
_CWE805_STACK_CELL_RE = re.compile(r"\(\(uint(?P<width>8|16|32|64)_t \*\)s->rsp\)\[(?P<index>[0-9]+)\]")


def _parse_CWE805_cell(text: str) -> StateCell:
    """Parse one CWE-805 cell (register or typed stack cell)."""
    if text.startswith("s->"):
        return RegisterCell(REGISTER_TO_VAR[text[3:]])
    match = _CWE805_STACK_CELL_RE.match(text)
    if match is None:
        raise ValueError(f"invalid CWE-805 cell: {text!r}")
    return StackCell(int(match.group("width")), int(match.group("index")))


def parse_CWE805_predicate(line: str) -> CWE805Predicate:
    """Parse one CWE-805 predicate line into a typed descriptor.

    Raises ValueError with a reason on any line outside the closed
    filter.zig grammar.
    """
    match = _CWE805_POINTER_RE.match(line)
    if match is not None:
        if match.group("c1") != match.group("c2"):
            raise ValueError(
                "pointer predicate cells differ: "
                f"{match.group('c1')!r} vs {match.group('c2')!r}")
        return CWE805PointerPredicate(_parse_CWE805_cell(match.group("c1")))
    match = _CWE805_SIZE_RE.match(line)
    if match is not None:
        scale = int(match.group("scale"))
        if scale not in (1, 2, 4, 8):
            raise ValueError(f"unsupported CWE-805 size scale: {scale}")
        return CWE805SizePredicate(scale, _parse_CWE805_cell(match.group("cell")))
    raise ValueError("not a CWE-805 predicate")


def classify_predicate_line(line: str) -> Optional[str]:
    """Return the family of one non-empty predicate line, or None if it is
    neither a generic nor a CWE-805 predicate."""
    if "i->begin" in line or "i->end" in line or "s->" in line:
        return PredicateFamily.CWE805_ERM.value
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


def load_predicates(file: Path) -> List[Tuple[int, str]]:
    """Load non-empty predicates with their physical source line numbers."""
    predicates: List[Tuple[int, str]] = list()
    with file.open("r") as f:
        for line_number, line in enumerate(f, start=1):
            predicate = line.strip()
            if predicate:
                predicates.append((line_number, predicate))
    return predicates


# Taosc allocator trace artifacts (utils/taosc/CWE805/synth.in): the
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
    """Build the CWE-805 multipoint instrumentation spec.

    Mirrors utils/taosc/CWE805/synth.in::e9trace: the first call address
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


def _family_from_patch_format(
    family: PredicateFamily,
    predicates_file: Path,
    allocator: Optional[AllocatorTrace],
) -> Tuple[PredicateFamily, Optional[AllocatorTrace]]:
    """Validate a patch-format-derived family against the workdir artifacts.

    Taosc's patch-format is the authoritative classifier, but the artifacts
    must still be consistent so a stale or mismatched patch-format is caught
    rather than silently mis-classified.
    """
    if family in (PredicateFamily.CWE805_DIRECT,
                  PredicateFamily.CWE805_ERM):
        if allocator is None:
            raise ValueError(
                f"patch-format says {family.value} but no allocator trace "
                "found in trace/")
        return family, allocator
    if family == PredicateFamily.GENERIC_ERM:
        if not predicates_file.exists():
            raise ValueError(
                "patch-format says ERM generic but no predicates file found")
        records = load_predicates(predicates_file)
        if not records:
            raise ValueError(
                "patch-format says ERM generic but predicates is empty")
        for source_line, predicate in records:
            if classify_predicate_line(predicate) \
                    != PredicateFamily.GENERIC_ERM.value:
                raise ValueError(
                    f"predicates:{source_line}: not a generic predicate: "
                    f"{predicate!r}")
            try:
                predicate_to_branch_patch_str(predicate)
            except ValueError as e:
                raise ValueError(
                    f"predicates:{source_line}: {e}") from e
        return PredicateFamily.GENERIC_ERM, None
    # TAOSC_SPECIALIZED (Single CWE-369/617/823): no predicates, no
    # allocator trace.
    return PredicateFamily.TAOSC_SPECIALIZED, None


def detect_predicate_family(workdir: Path) -> Tuple[PredicateFamily, Optional[AllocatorTrace]]:
    """Classify the workdir's patch family (plan §6.1).

    The Taosc ``patch-format`` file is the primary classifier when present;
    otherwise the workdir artifacts (allocator trace, crash/patch addresses,
    predicates grammar) are used.  Returns (family, allocator_trace).  Raises
    ValueError with a predicates:<line>: <reason> diagnostic on malformed
    predicate files.
    """
    predicates_file = workdir / "predicates"
    trace_dir = workdir / "trace"

    patch_format_family = parse_patch_format(workdir)
    if patch_format_family is not None:
        # Only the CWE-805 families use the allocator trace.  Generic ERM
        # and taosc-specialized patches ignore it: taosc may leave an empty
        # or malformed trace/ artifact behind (e.g. a POC that crashes
        # inside the very first allocator call, so no call/return pair is
        # recorded), and that must not abort a generic classification
        # (zziplib/CVE-2017-5979).
        if patch_format_family in (PredicateFamily.CWE805_DIRECT,
                                   PredicateFamily.CWE805_ERM):
            allocator = parse_allocator_trace(trace_dir) \
                if trace_dir.is_dir() else None
        else:
            allocator = None
        return _family_from_patch_format(
            patch_format_family, predicates_file, allocator)

    allocator = parse_allocator_trace(trace_dir) if trace_dir.is_dir() else None
    if allocator is not None:
        crash_address = (trace_dir / "crash.address").read_text().strip() \
            if (trace_dir / "crash.address").exists() else ""
        patch_location = (workdir / "patch-location").read_text().strip() \
            if (workdir / "patch-location").exists() else ""
        if crash_address == patch_location:
            return PredicateFamily.CWE805_DIRECT, allocator
        # Missing or empty predicates are valid: setup still builds the
        # artifacts with zero candidates (TOTAL_PATCHES=0) and binradar.py
        # handles the no-patch case.
        if not predicates_file.exists():
            return PredicateFamily.CWE805_ERM, allocator
        records = load_predicates(predicates_file)
        if not records:
            return PredicateFamily.CWE805_ERM, allocator
        for source_line, predicate in records:
            if classify_predicate_line(predicate) != PredicateFamily.CWE805_ERM.value:
                raise ValueError(
                    f"predicates:{source_line}: not a CWE-805 predicate: "
                    f"{predicate!r}")
            try:
                parse_CWE805_predicate(predicate)
            except ValueError as e:
                raise ValueError(
                    f"predicates:{source_line}: {e}") from e
        return PredicateFamily.CWE805_ERM, allocator

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


def CWE805_branch_taken(predicate: CWE805Predicate,
                        registers: List[int], stack: bytes,
                        clamps: List[Tuple[int, int]]) -> int:
    """Mirror brpatch.c::CWE805_branch_taken (plan §7.3).

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

    if isinstance(predicate, CWE805PointerPredicate):
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
# CWE-805 full-context prefilter snapshots (plan §8)
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
class CWE805Snapshot:
    """One captured patch-site full context (plan §8)."""
    clamps: Tuple[Tuple[int, int], ...]  # 256 (begin, end) pairs
    registers: Tuple[int, ...]           # 16 u64 bit patterns, rax..r15
    stack: bytes                         # exactly stack-size bytes
    truncated: bool = False              # capture hit the bound


def parse_CWE805_snapshots(data: bytes) -> Tuple[List[CWE805Snapshot], bool]:
    """Parse the binary snapshot stream from the capture pipe.

    Returns (snapshots, truncated).  A header-only record with the
    truncation flag set marks the end of complete evidence; any trailing
    partial record is dropped.  Malformed records (bad magic/version,
    truncated body) stop parsing at the first bad record.
    """
    snapshots: List[CWE805Snapshot] = []
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
        snapshots.append(CWE805Snapshot(
            tuple((clamps_raw[i], clamps_raw[i + 1])
                  for i in range(0, len(clamps_raw), 2)),
            regs, stack))
    return snapshots, truncated


def CWE805_snapshot_branch_taken(predicate: CWE805Predicate,
                                snapshot: CWE805Snapshot) -> int:
    """Evaluate one CWE-805 descriptor against one captured snapshot.

    Same cell, unsigned comparison, checked-multiply, and !any_match rules
    as brpatch.c::CWE805_branch_taken (plan §8): 0 = no jump, 1 = jump,
    2 = checked-multiply overflow (conservative no-jump).
    """
    return CWE805_branch_taken(predicate, list(snapshot.registers),
                               snapshot.stack, list(snapshot.clamps))


# Binary records emitted by brpatch-cached.c.  Each record contains the
# selected predicate's branch plus enough pre-branch state to evaluate every
# other predicate offline.  CWE-805 records additionally contain all clamps
# and the measured stack prefix.
CACHED_SNAPSHOT_MAGIC = 0x48435242  # little-endian bytes "BRCH"
CACHED_SNAPSHOT_VERSION = 1
CACHED_SNAPSHOT_FLAG_TRUNCATED = 1
CACHED_SNAPSHOT_FLAG_CWE805 = 2
CACHED_SNAPSHOT_FLAG_INVALID = 4
CACHED_SNAPSHOT_HEADER = struct.Struct("<IIIIQQ")
CACHED_SNAPSHOT_CLAMPS = PREFILTER_SNAPSHOT_CLAMPS
CACHED_SNAPSHOT_REGS = PREFILTER_SNAPSHOT_REGS


@dataclass(frozen=True)
class CachedSnapshot:
    """One brpatch-cached record (patch_id is the captured runtime id)."""
    patch_id: int
    branch: int
    registers: Tuple[int, ...]
    clamps: Tuple[Tuple[int, int], ...] = ()
    stack: bytes = ""

    @property
    def is_CWE805(self) -> bool:
        return bool(self.clamps)


def parse_cached_snapshots(
    data: bytes,
) -> Tuple[List[CachedSnapshot], Optional[str]]:
    """Parse a complete brpatch-cached binary stream.

    Returns ``(snapshots, error)``.  An empty stream is valid and means that
    the patch site was not reached.  Any malformed, invalid, truncated, or
    partial record disables cache inference for the run.
    """
    snapshots: List[CachedSnapshot] = []
    offset = 0
    expected_patch_id: Optional[int] = None
    known_flags = CACHED_SNAPSHOT_FLAG_TRUNCATED \
        | CACHED_SNAPSHOT_FLAG_CWE805 | CACHED_SNAPSHOT_FLAG_INVALID
    while offset < len(data):
        if offset + CACHED_SNAPSHOT_HEADER.size > len(data):
            return [], "partial cached snapshot header"
        magic, version, patch_id, branch, stack_size, flags = \
            CACHED_SNAPSHOT_HEADER.unpack_from(data, offset)
        offset += CACHED_SNAPSHOT_HEADER.size
        if magic != CACHED_SNAPSHOT_MAGIC:
            return [], f"bad cached snapshot magic 0x{magic:x}"
        if version != CACHED_SNAPSHOT_VERSION:
            return [], f"unsupported cached snapshot version {version}"
        if flags & ~known_flags:
            return [], f"unknown cached snapshot flags 0x{flags:x}"
        if flags & CACHED_SNAPSHOT_FLAG_TRUNCATED:
            return [], "cached snapshot capture truncated"
        if flags & CACHED_SNAPSHOT_FLAG_INVALID:
            return [], "cached runtime rejected the selected predicate"
        if branch not in (0, 1, 2):
            return [], f"invalid cached branch value {branch}"
        if expected_patch_id is None:
            expected_patch_id = patch_id
        elif patch_id != expected_patch_id:
            return [], "cached snapshot patch ids differ within one run"

        is_CWE805 = bool(flags & CACHED_SNAPSHOT_FLAG_CWE805)
        if not is_CWE805 and stack_size != 0:
            return [], "generic cached snapshot has a stack payload"
        if stack_size > 0x100000:
            return [], f"cached stack payload too large: {stack_size}"

        clamps: Tuple[Tuple[int, int], ...] = ()
        if is_CWE805:
            if offset + CACHED_SNAPSHOT_CLAMPS.size > len(data):
                return [], "partial cached clamp payload"
            raw = CACHED_SNAPSHOT_CLAMPS.unpack_from(data, offset)
            offset += CACHED_SNAPSHOT_CLAMPS.size
            clamps = tuple((raw[i], raw[i + 1])
                           for i in range(0, len(raw), 2))

        if offset + CACHED_SNAPSHOT_REGS.size + stack_size > len(data):
            return [], "partial cached state payload"
        registers = CACHED_SNAPSHOT_REGS.unpack_from(data, offset)
        offset += CACHED_SNAPSHOT_REGS.size
        stack = data[offset:offset + stack_size]
        offset += stack_size
        snapshots.append(CachedSnapshot(
            patch_id=patch_id,
            branch=branch,
            registers=registers,
            clamps=clamps,
            stack=stack,
        ))
    return snapshots, None


def evaluate_cached_predicate(
    predicate: ParsedPredicate,
    snapshots: List[CachedSnapshot],
) -> List[int]:
    """Evaluate one runtime predicate over every captured pre-branch state."""
    branches: List[int] = []
    for snapshot in snapshots:
        if isinstance(predicate, str):
            if snapshot.is_CWE805:
                raise ValueError("generic predicate with a CWE-805 snapshot")
            env = [wrap64(value) for value in snapshot.registers]
            try:
                branch = int(eval_patch_str(predicate, env) != 0)
            except PrefilterTrap:
                branch = 2
        else:
            if not snapshot.is_CWE805:
                raise ValueError("CWE-805 predicate with a generic snapshot")
            branch = CWE805_branch_taken(
                predicate,
                list(snapshot.registers),
                snapshot.stack,
                list(snapshot.clamps),
            )
        branches.append(branch)
    return branches


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


RUNTIME_PREDICATES_VERSION = 1


def predicate_descriptor(predicate: ParsedPredicate) -> str:
    """Encode one validated runtime predicate for brpatches.inc/JSON."""
    if isinstance(predicate, str):
        return predicate
    cell = predicate.cell
    if isinstance(cell, RegisterCell):
        encoded_cell = f"p{cell.register_index}"
    else:
        encoded_cell = f"s{cell.width_bits}i{cell.index}"
    if isinstance(predicate, CWE805PointerPredicate):
        return f"c1{encoded_cell}"
    return f"c2{encoded_cell}q{predicate.scale}"


def parse_predicate_descriptor(descriptor: str) -> ParsedPredicate:
    """Parse the compact descriptor accepted by brpatch.c."""
    if not descriptor.startswith("c"):
        if not descriptor:
            raise ValueError("empty generic predicate descriptor")
        return descriptor

    match = re.fullmatch(r"c1p([0-9]+)", descriptor)
    if match is not None:
        index = int(match.group(1))
        if index > 15:
            raise ValueError(f"register index out of range: {index}")
        return CWE805PointerPredicate(RegisterCell(index))
    match = re.fullmatch(r"c1s64i([0-9]+)", descriptor)
    if match is not None:
        return CWE805PointerPredicate(StackCell(64, int(match.group(1))))
    match = re.fullmatch(r"c2p([0-9]+)q([0-9]+)", descriptor)
    if match is not None:
        index, scale = int(match.group(1)), int(match.group(2))
        if index > 15:
            raise ValueError(f"register index out of range: {index}")
        if scale not in (1, 2, 4, 8):
            raise ValueError(f"invalid size scale: {scale}")
        return CWE805SizePredicate(scale, RegisterCell(index))
    match = re.fullmatch(r"c2s(8|16|32)i([0-9]+)q([0-9]+)", descriptor)
    if match is not None:
        width, index, scale = map(int, match.groups())
        if scale not in (1, 2, 4, 8):
            raise ValueError(f"invalid size scale: {scale}")
        return CWE805SizePredicate(scale, StackCell(width, index))
    raise ValueError(f"invalid CWE-805 predicate descriptor: {descriptor!r}")


def write_runtime_predicates(
    path: Path,
    family: PredicateFamily,
    selected: List[PredicateRecord],
) -> None:
    """Persist the exact compact runtime-id mapping used by both binaries."""
    if family not in (PredicateFamily.GENERIC_ERM, PredicateFamily.CWE805_ERM):
        raise ValueError(f"predicate cache does not support {family.value}")
    expected_ids = list(range(1, len(selected) + 1))
    if [record.runtime_id for record in selected] != expected_ids:
        raise ValueError("runtime predicate ids must be consecutive from 1")
    data = {
        "version": RUNTIME_PREDICATES_VERSION,
        "kind": family.value,
        "predicates": [
            {
                "id": record.runtime_id,
                "source_line": record.source_line,
                "descriptor": predicate_descriptor(record.parsed),
            }
            for record in selected
        ],
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_runtime_predicates(
    path: Path,
) -> Tuple[PredicateFamily, Dict[int, ParsedPredicate]]:
    """Load and validate the runtime-id mapping emitted by setup."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read runtime predicates: {e}") from e
    if not isinstance(data, dict) or data.get("version") != \
            RUNTIME_PREDICATES_VERSION:
        raise ValueError("unsupported runtime predicate manifest")
    try:
        family = PredicateFamily(data["kind"])
    except (KeyError, ValueError) as e:
        raise ValueError("invalid runtime predicate family") from e
    if family not in (PredicateFamily.GENERIC_ERM, PredicateFamily.CWE805_ERM):
        raise ValueError(f"predicate cache does not support {family.value}")
    rows = data.get("predicates")
    if not isinstance(rows, list):
        raise ValueError("runtime predicates must be a list")

    predicates: Dict[int, ParsedPredicate] = {}
    for expected_id, row in enumerate(rows, start=1):
        if not isinstance(row, dict) or row.get("id") != expected_id \
                or not isinstance(row.get("source_line"), int) \
                or not isinstance(row.get("descriptor"), str):
            raise ValueError(
                f"invalid runtime predicate row at index {expected_id}")
        parsed = parse_predicate_descriptor(row["descriptor"])
        if family == PredicateFamily.GENERIC_ERM and not isinstance(parsed, str):
            raise ValueError("CWE-805 descriptor in generic manifest")
        if family == PredicateFamily.CWE805_ERM and isinstance(parsed, str):
            raise ValueError("generic descriptor in CWE-805 manifest")
        predicates[expected_id] = parsed
    return family, predicates


def _emit_brpatches_inc(brpatches_inc: Path,
                        selected: List[PredicateRecord]) -> None:
    """Write the compact predicate table included by the C runtimes."""
    with brpatches_inc.open("w") as f:
        f.write("case 0:\n\treturn \"p0\";\n")
        for record in selected:
            descriptor = predicate_descriptor(record.parsed)
            detail = ""
            if isinstance(record.parsed, CWE805PointerPredicate):
                detail = "pointer register" if isinstance(
                    record.parsed.cell, RegisterCell) else "pointer stack cell"
            elif isinstance(record.parsed, CWE805SizePredicate):
                detail = "size register" if isinstance(
                    record.parsed.cell, RegisterCell) else "size stack cell"
            suffix = f": {detail}" if detail else ""
            f.write(f"case {record.runtime_id}:\n"
                    f"\treturn \"{descriptor}\"; "
                    f"/* predicate line {record.source_line}{suffix} */\n")
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
            if family == PredicateFamily.CWE805_ERM:
                try:
                    parsed = parse_CWE805_predicate(predicate)
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
