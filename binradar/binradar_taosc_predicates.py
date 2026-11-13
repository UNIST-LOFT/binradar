#!/usr/bin/env python3
"""
Taosc predicate management for BinRadar workdir setup.
Parsing, classification, evaluation, and lowering of the Taosc predicate
families (generic ERM, CWE-805 ERM, CWE-805 direct, taosc-specialized),
plus the allocator-trace instrumentation spec shared by patched artifacts.  Shared with binradar.binradar_setup.
"""

import ast
import enum
import functools
import hashlib
import io
import json
import re
import struct
import sbsv
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union, cast

from . import paths

INT64_MIN = -(1 << 63)
_MASK64 = (1 << 64) - 1
MAX_SOURCE_BYTES = 4096
MAX_DESCRIPTOR_BYTES = 4095
MAX_EXPR_DEPTH = 256


def _check_source(source: str) -> None:
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("predicate source exceeds 4096 UTF-8 bytes")

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


@dataclass(frozen=True)
class CWE805LogicalPredicate:
    op: str
    left: "CWE805Predicate"
    right: "CWE805Predicate"


CWE805Predicate = Union[CWE805PointerPredicate, CWE805SizePredicate,
                        CWE805LogicalPredicate]
ParsedPredicate = Union[str, CWE805Predicate]


def predicate_stack_bytes(predicate: ParsedPredicate) -> int:
    """Minimum captured stack bytes, including every skipped subtree."""
    if isinstance(predicate, str):
        return 0
    pending = [(predicate, 1)]
    required = 0
    while pending:
        node, depth = pending.pop()
        if depth > MAX_EXPR_DEPTH:
            raise ValueError("predicate depth exceeds 256")
        if isinstance(node, CWE805LogicalPredicate):
            if node.op not in ("&&", "||"):
                raise ValueError("invalid CWE-805 logical operator")
            pending.extend(((node.left, depth + 1), (node.right, depth + 1)))
            continue
        cell = node.cell
        if isinstance(cell, RegisterCell):
            if not 0 <= cell.register_index <= 15:
                raise ValueError("register index out of range")
        else:
            widths = (64,) if isinstance(node, CWE805PointerPredicate) else (8, 16, 32)
            if cell.width_bits not in widths or not 0 <= cell.index <= 65535:
                raise ValueError("invalid CWE-805 stack cell")
            required = max(required, (cell.index + 1) * (cell.width_bits // 8))
        if isinstance(node, CWE805SizePredicate) and node.scale not in (1, 2, 4, 8):
            raise ValueError("invalid CWE-805 size scale")
    return required


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


def _parse_CWE805_atom(line: str) -> CWE805Predicate:
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


def parse_CWE805_predicate(line: str) -> CWE805Predicate:
    """Parse typed leaves before interpreting their internal pointer &&."""
    _check_source(line)
    # Regexes retain the closed atom grammar; remove only their end anchor
    # so a leaf can precede a logical operator or grouping delimiter.
    pointer = re.compile(_CWE805_POINTER_RE.pattern[:-1])
    size = re.compile(_CWE805_SIZE_RE.pattern[:-1])
    pos = 0

    def whitespace() -> None:
        nonlocal pos
        while pos < len(line) and line[pos].isspace():
            pos += 1

    def primary(depth: int) -> CWE805Predicate:
        nonlocal pos
        if depth > MAX_EXPR_DEPTH:
            raise ValueError("predicate source nesting exceeds 256")
        whitespace()
        for regex in (pointer, size):
            match = regex.match(line[pos:])
            if match is not None:
                pos += match.end()
                return _parse_CWE805_atom(match.group(0))
        if pos < len(line) and line[pos] == "(":
            pos += 1
            result = logical_or(depth + 1)
            whitespace()
            if pos >= len(line) or line[pos] != ")":
                raise ValueError("expected closing CWE-805 parenthesis")
            pos += 1
            return result
        raise ValueError("not a CWE-805 predicate")

    def logical_and(depth: int) -> CWE805Predicate:
        nonlocal pos
        node = primary(depth)
        whitespace()
        while line.startswith("&&", pos):
            pos += 2
            node = CWE805LogicalPredicate("&&", node, primary(depth))
            whitespace()
        return node

    def logical_or(depth: int) -> CWE805Predicate:
        nonlocal pos
        node = logical_and(depth)
        whitespace()
        while line.startswith("||", pos):
            pos += 2
            node = CWE805LogicalPredicate("||", node, logical_and(depth))
            whitespace()
        return node

    try:
        result = logical_or(0)
    except RecursionError as e:
        raise ValueError("predicate source nesting exceeds parser limit") from e
    whitespace()
    if pos != len(line):
        raise ValueError("trailing CWE-805 source data")
    predicate_descriptor(result)  # Entire tree admission, not just visited leaves.
    return result





def predicates_sha256(predicates_file: Path) -> str:
    """SHA-256 of the exact predicates file bytes (filter identity)."""
    return hashlib.sha256(predicates_file.read_bytes()).hexdigest()

# Strict generic lexer: every input byte must be consumed as a token or
# whitespace.  Unknown punctuation is an error, never silently skipped.
_GENERIC_TOKEN_RE = re.compile(
    r"\s+|&&|\|\||<=|>=|==|!=|<<|>>|[()~+\-*/%&|^<>]|[A-Za-z_][A-Za-z0-9_]*|[0-9]+"
)


def tokenize_generic(predicate: str) -> List[str]:
    """Tokenize a generic predicate, rejecting any unrecognized byte."""
    _check_source(predicate)
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
    """Iterative precedence parser; source nesting never consumes Python stack."""
    _precedence = {op: level for level, group in enumerate((
        ("||",), ("&&",), ("|",), ("^",), ("&",), ("==", "!="),
        ("<", "<=", ">", ">="), ("<<", ">>"), ("+", "-"),
        ("*", "/", "%"), ("u+", "u-", "u~"))) for op in group}

    def __init__(self, tokens: List[str]):
        self.tokens = tokens

    def parse(self) -> AstNode:
        values = []
        operators = []
        expect_value = True
        nesting = 0

        def reduce() -> None:
            op = operators.pop()
            arity = 1 if op.startswith("u") else 2
            if len(values) < arity:
                raise ValueError("missing predicate operand")
            if arity == 1:
                values.append((op, values.pop()))
            else:
                right, left = values.pop(), values.pop()
                values.append((op, left, right))

        for token in self.tokens:
            if token == "(" and expect_value:
                nesting += 1
                if nesting > MAX_EXPR_DEPTH:
                    raise ValueError("predicate source nesting exceeds 256")
                operators.append(token)
            elif token == ")" and not expect_value:
                while operators and operators[-1] != "(":
                    reduce()
                if not operators:
                    raise ValueError("unexpected closing parenthesis")
                operators.pop()
                nesting -= 1
            elif expect_value:
                if token in ("+", "-", "~"):
                    operators.append("u" + token)
                    if len(operators) > MAX_SOURCE_BYTES:
                        raise ValueError("predicate operator budget exceeded")
                    continue
                if token.isdigit():
                    values.append(("const", int(token)))
                elif token in CONSTANTS:
                    values.append(("const", CONSTANTS[token]))
                elif token in REGISTER_TO_VAR:
                    values.append(("var", REGISTER_TO_VAR[token]))
                else:
                    raise ValueError(f"unknown identifier or operand: {token}")
                expect_value = False
            elif token in self._precedence and not token.startswith("u"):
                while operators and operators[-1] != "(" and self._precedence[operators[-1]] >= self._precedence[token]:
                    reduce()
                operators.append(token)
                expect_value = True
            else:
                raise ValueError(f"unexpected token: {token}")
        if expect_value or nesting:
            raise ValueError("incomplete predicate")
        while operators:
            reduce()
        if len(values) != 1:
            raise ValueError("invalid predicate")
        node = values[0]
        pending = [(node, 1)]
        while pending:
            current, depth = pending.pop()
            if depth > MAX_EXPR_DEPTH:
                raise ValueError("predicate depth exceeds 256")
            if current[0] not in ("const", "var"):
                pending.extend((child, depth + 1) for child in current[1:])
        return node


def emit_patch(node: AstNode) -> str:
    kind = node[0]

    if kind == "const":
        value = node[1]
        if type(value) != int:
            raise ValueError(f"invalid constant value: {value!r}")
        value = wrap64(value)
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
        "&&": "A",
        "||": "O",
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
    node = Parser(tokens).parse()
    descriptor = emit_patch(node)
    _parse_generic_descriptor(descriptor)
    return descriptor


def predicate_to_branch_patch_str(predicate: str) -> str:
    """Encode taosc's predicate as BinRadar's branch condition.

    Taosc's generic patch jumps when its generated predicate is zero, while
    brpatch.c jumps when the encoded expression is non-zero.
    """
    descriptor = f"={predicate_to_patch_str(predicate)}p0"
    _parse_generic_descriptor(descriptor)
    return descriptor


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
class SetupPredicates:
    """One validated source snapshot shared by all setup stages."""
    family: PredicateFamily
    allocator: Optional[AllocatorTrace]
    records: List[PredicateRecord]
    sha256: Optional[str]


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
    plugin (``plugin_name``), preserving one ordered instrumentation spec.
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
    cmd = [paths.e9tool()]
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





def load_setup_predicates(workdir: Path) -> SetupPredicates:
    """Classify artifacts and validate/lower each source predicate once.

    The digest and records describe the same input bytes. Runtime IDs are
    consecutive; source lines retain their physical positions, including gaps.
    Direct and specialized families ignore stale predicate expressions.
    """
    predicates_file = workdir / "predicates"
    trace_dir = workdir / "trace"
    declared = parse_patch_format(workdir)
    # Generic/specialized formats must ignore leftover allocator traces.
    allocator = None
    if declared not in (PredicateFamily.GENERIC_ERM,
                        PredicateFamily.TAOSC_SPECIALIZED):
        allocator = parse_allocator_trace(trace_dir) if trace_dir.is_dir() else None
    if declared in (PredicateFamily.CWE805_DIRECT, PredicateFamily.CWE805_ERM) \
            and allocator is None:
        raise ValueError(
            f"patch-format says {declared.value} but no allocator trace found in trace/")

    family = declared
    if family is None:
        if allocator is None:
            family = PredicateFamily.GENERIC_ERM
        else:
            crash_file = trace_dir / "crash.address"
            location_file = workdir / "patch-location"
            crash = crash_file.read_text().strip() if crash_file.exists() else ""
            location = location_file.read_text().strip() if location_file.exists() else ""
            family = (PredicateFamily.CWE805_DIRECT if crash == location
                      else PredicateFamily.CWE805_ERM)

    records = []
    digest = None
    if predicates_file.exists():
        data = predicates_file.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if family in (PredicateFamily.GENERIC_ERM, PredicateFamily.CWE805_ERM):
            records = _parse_predicate_records(data.decode("utf-8"), family)
    elif declared == PredicateFamily.GENERIC_ERM:
        raise ValueError("patch-format says ERM generic but no predicates file found")
    if family == PredicateFamily.GENERIC_ERM and not records:
        if declared == PredicateFamily.GENERIC_ERM:
            raise ValueError("patch-format says ERM generic but predicates is empty")
        family = PredicateFamily.TAOSC_SPECIALIZED
    return SetupPredicates(family, allocator, records, digest)


def load_filter_passed_ids(filter_file: Path,
                              expected_kind: Optional[str] = None,
                              expected_sha256: Optional[str] = None,
                              ) -> Optional[Dict[int, int]]:
    """Read source predicate IDs and their compact runtime patch IDs.

    Each passing row must contain a positive, unique ``new-id``.  A false
    row must contain ``new-id -1``.  Returns ``None`` on malformed input so
    setup fails open and keeps every predicate.

    A ``[filter] [meta]`` row (written by write_filter) pins the
    predicate family and the exact predicates-file SHA-256.  When
    ``expected_kind``/``expected_sha256`` are given, a mismatching or
    missing metadata row fails open (returns None) so a stale filter
    from a different predicate file or family is never applied.
    """
    parser = sbsv.parser()
    parser.add_schema(
        "[filter] [res] [id: int] [pass: bool] [new-id: int]")
    parser.add_schema(
        "[filter] [done] [total: int] [survived: int] [time: float]")
    parser.add_schema(
        "[filter] [meta] [version: int] [kind: str] [sha256: str]")
    passed_ids: Dict[int, int] = dict()
    used_new_ids = set()
    meta_seen = False
    with filter_file.open("r") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = parser.parse_line_detached(line, line_number)
            except Exception:
                return None
            if row is None:
                return None
            if row.schema_name == "filter$done":
                continue
            if row.schema_name == "filter$meta":
                if meta_seen or row["version"] != 1:
                    return None
                meta_seen = True
                if expected_kind is not None and row["kind"] != expected_kind:
                    return None
                if expected_sha256 is not None \
                        and row["sha256"] != expected_sha256:
                    return None
                continue
            if row.schema_name != "filter$res":
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


class PredicateTrap(Exception):
    """Arithmetic that would raise SIGFPE in C (div/mod by zero, INT64_MIN / -1)."""


def wrap64(v: int) -> int:
    """Reinterpret v as a signed 64-bit two's-complement integer."""
    v &= _MASK64
    return v - (1 << 64) if v >= (1 << 63) else v



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


PatchEvaluator = Callable[[Sequence[int]], int]


def _checked_div(a: int, b: int) -> int:
    if b == 0:
        raise PredicateTrap("division by zero")
    if a == INT64_MIN and b == -1:
        raise PredicateTrap("INT64_MIN / -1")
    return _trunc_div(a, b)


def _checked_mod(a: int, b: int) -> int:
    if b == 0:
        raise PredicateTrap("modulo by zero")
    if a == INT64_MIN and b == -1:
        raise PredicateTrap("INT64_MIN % -1")
    return wrap64(a - _trunc_div(a, b) * b)


_PATCH_EVAL_GLOBALS = {
    "__builtins__": {},
    "_w": wrap64,
    "_sl": _shift_left,
    "_sr": _shift_right,
    "_div": _checked_div,
    "_mod": _checked_mod,
    "int": int,
}


def _check_descriptor(s: str) -> None:
    if not s or len(s.encode("utf-8")) > MAX_DESCRIPTOR_BYTES:
        raise ValueError("empty or oversized predicate descriptor")


@functools.cache
def _parse_generic_descriptor(s: str) -> AstNode:
    """Validate the entire prefix tree, including unreachable operands."""
    _check_descriptor(s)
    pos = 0

    def parse(depth: int) -> AstNode:
        nonlocal pos
        if depth > MAX_EXPR_DEPTH:
            raise ValueError("predicate depth exceeds 256")
        if pos >= len(s):
            raise ValueError("unexpected end of encoded predicate")
        op = s[pos]
        pos += 1
        if op in "pnv":
            start = pos
            while pos < len(s) and "0" <= s[pos] <= "9":
                pos += 1
            if start == pos:
                raise ValueError("missing encoded integer digits")
            digits = s[start:pos].lstrip("0") or "0"
            if len(digits) > 20:
                raise ValueError("encoded integer out of range")
            value = int(digits)
            if op == "v":
                if value > 15:
                    raise ValueError("register index out of range")
                return ("var", value)
            if value > _MASK64:
                raise ValueError("encoded integer out of range")
            return ("const", wrap64(-value if op == "n" else value))
        if op == "~":
            return ("u~", parse(depth + 1))
        if op in "<>" and pos < len(s) and s[pos] == "=":
            pos += 1
            op += "="
        if op not in ("=", "!", ">", "<", ">=", "<=", "+", "-", "*", "/", "%", "&", "|", "^", "l", "r", "A", "O"):
            raise ValueError(f"unknown patch operator {op!r}")
        return (op, parse(depth + 1), parse(depth + 1))

    node = parse(1)
    if pos != len(s):
        raise ValueError("trailing data in encoded predicate")
    return node


@functools.cache
def _compile_patch_str(s: str) -> PatchEvaluator:
    """Compile Python AST directly, avoiding the source-parentheses limit."""
    tree = _parse_generic_descriptor(s)

    def call(name: str, *args: ast.expr) -> ast.expr:
        return ast.Call(func=ast.Name(id=name, ctx=ast.Load()), args=list(args), keywords=[])

    def compile_node(node: AstNode) -> ast.expr:
        op = node[0]
        if op == "const":
            return ast.Constant(value=node[1])
        if op == "var":
            return ast.Subscript(value=ast.Name(id="env", ctx=ast.Load()), slice=ast.Constant(value=node[1]), ctx=ast.Load())
        left = compile_node(node[1])
        if op == "u~":
            return call("_w", ast.UnaryOp(op=ast.Invert(), operand=left))
        right = compile_node(node[2])
        if op in ("A", "O"):
            return call("int", ast.BoolOp(op=ast.And() if op == "A" else ast.Or(), values=[
                ast.Compare(left=left, ops=[ast.NotEq()], comparators=[ast.Constant(value=0)]),
                ast.Compare(left=right, ops=[ast.NotEq()], comparators=[ast.Constant(value=0)])]))
        comparison = {"=": ast.Eq, "!": ast.NotEq, ">": ast.Gt, "<": ast.Lt, ">=": ast.GtE, "<=": ast.LtE}.get(op)
        if comparison is not None:
            return call("int", ast.Compare(left=left, ops=[comparison()], comparators=[right]))
        binary = {"+": ast.Add, "-": ast.Sub, "*": ast.Mult, "&": ast.BitAnd, "|": ast.BitOr, "^": ast.BitXor}.get(op)
        if binary is not None:
            return call("_w", ast.BinOp(left=left, op=binary(), right=right))
        return call({"l": "_sl", "r": "_sr", "/": "_div", "%": "_mod"}[op], left, right)

    try:
        expression = ast.Expression(body=ast.Lambda(
            args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="env")], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=compile_node(tree)))
        for item in ast.walk(expression):
            if "lineno" in item._attributes:
                item.lineno = item.end_lineno = 1
                item.col_offset = item.end_col_offset = 0
        code = compile(expression, "<taosc-predicate>", "eval", optimize=2)
    except (RecursionError, SyntaxError) as e:
        raise ValueError("predicate exceeds Python compilation limit") from e
    return cast(PatchEvaluator, eval(code, _PATCH_EVAL_GLOBALS))


def eval_patch_str(s: str, env: Sequence[int]) -> int:
    """Evaluate a cached prefix predicate with Taosc's i64 semantics."""
    return _compile_patch_str(s)(env)


def CWE805_branch_taken(predicate: CWE805Predicate,
                        registers: Sequence[int], stack: bytes,
                        clamps: Sequence[Tuple[int, int]]) -> int:
    """Mirror brpatch.c::CWE805_branch_taken (plan §7.3).

    Returns 0 (no jump: some clamp matches), 1 (jump: no clamp matches) or
    2 (checked-multiply overflow: conservative no-jump, reported as br 2).
    Cells use the unsigned 64-bit bit-domain; stack loads are x86-64
    little-endian.  Zero-initialized clamps never match.
    """
    required = predicate_stack_bytes(predicate)
    if len(stack) < required:
        raise ValueError(f"insufficient captured stack: need {required} bytes")

    def evaluate(node: CWE805Predicate, begin: int, end: int) -> bool:
        if isinstance(node, CWE805LogicalPredicate):
            left = evaluate(node.left, begin, end)
            if node.op == "&&":
                return left and evaluate(node.right, begin, end)
            return left or evaluate(node.right, begin, end)
        cell = node.cell
        if isinstance(cell, RegisterCell):
            value = registers[cell.register_index] & _MASK64
        else:
            width = cell.width_bits // 8
            offset = cell.index * width
            value = int.from_bytes(stack[offset:offset + width], "little")
        if isinstance(node, CWE805PointerPredicate):
            return begin <= value < end
        size = node.scale * value
        if size > _MASK64:
            raise PredicateTrap("CWE-805 size multiplication overflow")
        return size < ((end - begin) & _MASK64)

    try:
        previous = None
        for clamp in reversed(clamps):
            # Empty allocator slots repeat. Evaluate the first occurrence,
            # including its lazy overflow checks, before skipping duplicates.
            if clamp == previous:
                continue
            previous = clamp
            begin, end = clamp
            if evaluate(predicate, begin, end):
                return 0
    except PredicateTrap:
        return 2
    return 1


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
CACHED_SNAPSHOT_CLAMPS = struct.Struct("<" + "QQ" * 256)
CACHED_SNAPSHOT_REGS = struct.Struct("<" + "Q" * 16)


@dataclass(frozen=True)
class CachedSnapshot:
    """One brpatch-cached record (patch_id is the captured runtime id)."""
    patch_id: int
    branch: int
    registers: Tuple[int, ...]
    clamps: Tuple[Tuple[int, int], ...] = ()
    stack: bytes = b""

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


GenericEnvironments = List[Tuple[int, ...]]


def prepare_generic_environments(
    snapshots: List[CachedSnapshot],
) -> Optional[GenericEnvironments]:
    """Normalize immutable generic registers once per captured execution."""
    if any(snapshot.is_CWE805 for snapshot in snapshots):
        return None
    return [tuple(wrap64(value) for value in snapshot.registers)
            for snapshot in snapshots]


def _evaluate_CWE805_snapshot(
    predicate: CWE805Predicate,
    snapshot: CachedSnapshot,
) -> int:
    if not snapshot.is_CWE805:
        raise ValueError("CWE-805 predicate with a generic snapshot")
    return CWE805_branch_taken(
        predicate,
        snapshot.registers,
        snapshot.stack,
        snapshot.clamps,
    )


def evaluate_cached_branch(
    predicate: ParsedPredicate,
    snapshot: CachedSnapshot,
    generic_environment: Optional[Sequence[int]] = None,
) -> int:
    """Evaluate one predicate at one captured pre-branch state."""
    if isinstance(predicate, str):
        if snapshot.is_CWE805:
            raise ValueError("generic predicate with a CWE-805 snapshot")
        environment = generic_environment
        if environment is None:
            environment = tuple(wrap64(value) for value in snapshot.registers)
        evaluator = _compile_patch_str(predicate)
        try:
            return int(evaluator(environment) != 0)
        except PredicateTrap:
            return 2
    return _evaluate_CWE805_snapshot(predicate, snapshot)


def evaluate_cached_predicate(
    predicate: ParsedPredicate,
    snapshots: List[CachedSnapshot],
    generic_environments: Optional[GenericEnvironments] = None,
) -> List[int]:
    """Evaluate one runtime predicate over every captured pre-branch state."""
    if isinstance(predicate, str):
        environments = generic_environments
        if environments is None:
            environments = prepare_generic_environments(snapshots)
        if environments is None:
            raise ValueError("generic predicate with a CWE-805 snapshot")
        if len(environments) != len(snapshots):
            raise ValueError("generic environment count does not match snapshots")
        evaluator = _compile_patch_str(predicate)
        branches = []
        for environment in environments:
            try:
                branches.append(int(evaluator(environment) != 0))
            except PredicateTrap:
                branches.append(2)
        return branches
    return [_evaluate_CWE805_snapshot(predicate, snapshot)
            for snapshot in snapshots]


def cached_predicate_matches(
    predicate: ParsedPredicate,
    snapshots: List[CachedSnapshot],
    expected: List[int],
    generic_environments: Optional[GenericEnvironments] = None,
    start_index: int = 0,
) -> bool:
    """Test a branch-vector suffix, stopping at the first difference."""
    if len(snapshots) != len(expected):
        return False
    if not 0 <= start_index <= len(snapshots):
        raise ValueError("cached predicate start index is out of range")
    if isinstance(predicate, str):
        environments = generic_environments
        if environments is None:
            environments = prepare_generic_environments(snapshots)
        if environments is None:
            raise ValueError("generic predicate with a CWE-805 snapshot")
        if len(environments) != len(snapshots):
            raise ValueError("generic environment count does not match snapshots")
        evaluator = _compile_patch_str(predicate)
        for environment, branch in zip(
                environments[start_index:], expected[start_index:]):
            try:
                actual = int(evaluator(environment) != 0)
            except PredicateTrap:
                actual = 2
            if actual != branch:
                return False
        return True
    return all(
        _evaluate_CWE805_snapshot(predicate, snapshot) == branch
        for snapshot, branch in zip(
            snapshots[start_index:], expected[start_index:])
    )


_WORKER_PREDICATES: Dict[int, ParsedPredicate] = {}


def precompile_generic_predicates(
    predicates: Dict[int, ParsedPredicate],
) -> None:
    """Compile generic predicates before forking match workers."""
    for predicate in predicates.values():
        if isinstance(predicate, str):
            _compile_patch_str(predicate)


def initialize_predicate_match_worker(
    predicates: Dict[int, ParsedPredicate],
) -> None:
    global _WORKER_PREDICATES
    _WORKER_PREDICATES = predicates


def match_cached_predicate_ids(
    task: Tuple[List[int], List[CachedSnapshot], List[int],
                Optional[GenericEnvironments], int],
) -> List[int]:
    """Return ids whose full cached branch-vector suffix matches."""
    patch_ids, snapshots, expected, environments, start_index = task
    matches = []
    for patch_id in patch_ids:
        predicate = _WORKER_PREDICATES[patch_id]
        try:
            if cached_predicate_matches(
                    predicate, snapshots, expected, environments,
                    start_index):
                matches.append(patch_id)
        except (IndexError, ValueError):
            pass
    return matches


def write_filter(filter_file: Path, results: List[Tuple[int, bool, str, str]],
                    elapsed: float, kind: Optional[str] = None,
                    sha256: Optional[str] = None) -> None:
    """Write source predicate IDs and compact runtime patch IDs.

    Passing predicates receive consecutive ``new-id`` values starting at 1;
    rejected predicates receive ``new-id -1``.  Runtime patch IDs therefore
    remain compatible with ``range(1, TOTAL_PATCHES + 1)`` while ``id``
    preserves the predicate source line.

    A ``[filter] [meta]`` row pins the predicate family and the exact
    predicates-file SHA-256 so a stale filter can never be applied to a
    different predicate file or family (plan §6.2).
    """
    survived = 0
    with filter_file.open("w", encoding="utf-8") as f:
        if kind is not None and sha256 is not None:
            f.write(f"[filter] [meta] [version 1] [kind {kind}] "
                    f"[sha256 {sha256}]\n")
        for idx, passed, note, predicate in results:
            new_id = survived + 1 if passed else -1
            f.write(f"[filter] [res] [id {idx}] "
                    f"[pass {str(passed).lower()}] [new-id {new_id}] "
                    f"{predicate} ({(' ' + note) if note else ''})\n")
            if passed:
                survived += 1
        f.write(f"[filter] [done] [total {len(results)}] "
                f"[survived {survived}] [time {elapsed:.2f}]\n")
    print(f"[filter] [done] [total {len(results)}] "
          f"[survived {survived}] [time {elapsed:.2f}]")


RUNTIME_PREDICATES_VERSION = 1


def predicate_descriptor(predicate: ParsedPredicate) -> str:
    """Encode one fully validated predicate, retaining ordered tree shape."""
    if isinstance(predicate, str):
        _parse_generic_descriptor(predicate)
        return predicate
    predicate_stack_bytes(predicate)

    def encode(node: CWE805Predicate) -> str:
        if isinstance(node, CWE805LogicalPredicate):
            return ("A" if node.op == "&&" else "O") + encode(node.left) + encode(node.right)
        cell = node.cell
        encoded_cell = (f"p{cell.register_index}" if isinstance(cell, RegisterCell)
                        else f"s{cell.width_bits}i{cell.index}")
        if isinstance(node, CWE805PointerPredicate):
            return f"c1{encoded_cell}"
        return f"c2{encoded_cell}q{node.scale}"

    descriptor = ("c3" if isinstance(predicate, CWE805LogicalPredicate) else "") + encode(predicate)
    _check_descriptor(descriptor)
    return descriptor


def parse_predicate_descriptor(descriptor: str) -> ParsedPredicate:
    """Parse the closed descriptor grammar, validating skipped subtrees too."""
    _check_descriptor(descriptor)
    if not descriptor.startswith("c"):
        _parse_generic_descriptor(descriptor)
        return descriptor
    pos = 2 if descriptor.startswith("c3") else 0
    composite = pos == 2

    def parse(depth: int) -> CWE805Predicate:
        nonlocal pos
        if depth > MAX_EXPR_DEPTH:
            raise ValueError("predicate depth exceeds 256")
        if pos < len(descriptor) and descriptor[pos] in "AO":
            op = descriptor[pos]
            pos += 1
            return CWE805LogicalPredicate("&&" if op == "A" else "||", parse(depth + 1), parse(depth + 1))
        match = re.match(r"c([12])(?:p([0-9]+)|s(8|16|32|64)i([0-9]+))(?:q([0-9]+))?", descriptor[pos:])
        if match is None:
            raise ValueError("invalid CWE-805 predicate descriptor")
        kind, register, width, index, scale = match.groups()
        pos += match.end()
        cell = RegisterCell(int(register)) if register is not None else StackCell(int(width), int(index))
        if kind == "1" and scale is None:
            return CWE805PointerPredicate(cell)
        if kind == "2" and scale is not None:
            return CWE805SizePredicate(int(scale), cell)
        raise ValueError("invalid CWE-805 atom scale")

    result = parse(1)
    if pos != len(descriptor) or composite != isinstance(result, CWE805LogicalPredicate):
        raise ValueError("invalid CWE-805 descriptor envelope or trailing data")
    predicate_stack_bytes(result)
    return result


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
    """Emit immutable file-scope ASTs; no parsing or allocation on a hit."""
    # E9 call plugins cannot contain relocations: construct node pointers in
    # the dispatch function, never in file-scope pointer-bearing metadata.
    lines = []
    cases = []
    for record in selected:
        predicate = record.parsed
        # Admission is shared with the JSON/cached runtime descriptor boundary.
        parsed = parse_predicate_descriptor(predicate_descriptor(predicate))
        nodes = []

        def add(node) -> int:
            fields = {}
            if isinstance(node, tuple):
                op = node[0]
                if op == "const":
                    fields = {"op": "'p'", "literal": f"UINT64_C({node[1] & _MASK64})"}
                elif op == "var":
                    fields = {"op": "'v'", "cell_index": node[1]}
                elif op == "u~":
                    fields = {"op": "'~'", "left": add(node[1])}
                else:
                    fields = {"op": repr({">=": "G", "<=": "L"}.get(op, op)),
                              "left": add(node[1]), "right": add(node[2])}
            elif isinstance(node, CWE805LogicalPredicate):
                fields = {"op": "'A'" if node.op == "&&" else "'O'",
                          "left": add(node.left), "right": add(node.right)}
            else:
                cell = node.cell
                fields = {"op": "'P'" if isinstance(node, CWE805PointerPredicate) else "'S'"}
                if isinstance(cell, RegisterCell):
                    fields.update(cell_kind=0, cell_index=cell.register_index)
                else:
                    fields.update(cell_kind={8: 1, 16: 2, 32: 3, 64: 4}[cell.width_bits], cell_index=cell.index)
                if isinstance(node, CWE805SizePredicate):
                    fields["scale"] = node.scale
            index = len(nodes)
            nodes.append("    { " + ", ".join(f".{key} = {value}" for key, value in fields.items()) + " },\n")
            return index

        root = add(_parse_generic_descriptor(parsed) if isinstance(parsed, str) else parsed)
        name = f"br_pred_{record.runtime_id}"
        lines.append(f"static const struct br_node {name}_nodes[] = {{\n")
        lines.extend(nodes)
        lines.append("};\n")
        kind = "BR_PRED_GENERIC" if isinstance(parsed, str) else "BR_PRED_CWE805"
        cases.append(f"    case {record.runtime_id}: *out = (struct br_predicate){{ .kind = {kind}, "
                     f".nodes = {name}_nodes, .count = {len(nodes)}, .root = {root}, "
                     f".stack_bytes = {predicate_stack_bytes(parsed)} }}; return; /* predicate line {record.source_line} */\n")
    lines.append("static void get_patch_pred(uint32_t id, struct br_predicate *out)\n{\n    switch (id) {\n")
    lines.extend(cases)
    lines.append("    default: *out = (struct br_predicate){ .kind = BR_PRED_FALSE }; return;\n    }\n}\n")
    brpatches_inc.write_text("".join(lines), encoding="utf-8")


def _parse_predicate_records(text: str, family: PredicateFamily) -> List[PredicateRecord]:
    """Validate every nonempty line and assign compact initial runtime IDs."""
    records: List[PredicateRecord] = []
    for line_number, line in enumerate(io.StringIO(text, newline=None), start=1):
        predicate = line.strip()
        if not predicate:
            continue
        try:
            parsed = (parse_CWE805_predicate(predicate)
                      if family == PredicateFamily.CWE805_ERM
                      else predicate_to_branch_patch_str(predicate))
        except ValueError as e:
            raise ValueError(f"predicates:{line_number}: {e}") from e
        records.append(PredicateRecord(
            len(records) + 1, line_number, predicate, parsed))
    return records
