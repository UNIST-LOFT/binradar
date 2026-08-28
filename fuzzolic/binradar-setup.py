#!/usr/bin/env python3
import argparse
import enum
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


def load_prefilter_passed_ids(prefilter_file: Path) -> Optional[Dict[int, int]]:
    """Read source predicate IDs and their compact runtime patch IDs.

    Each passing row must contain a positive, unique ``new-id``.  A false
    row must contain ``new-id -1``.  Returns ``None`` on malformed input so
    setup fails open and keeps every predicate.
    """
    parser = sbsv.parser()
    parser.add_schema(
        "[prefilter] [res] [id: int] [pass: bool] [new-id: int]")
    parser.add_schema(
        "[prefilter] [done] [total: int] [survived: int] [time: float]")
    passed_ids: Dict[int, int] = dict()
    used_new_ids = set()
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


def compile_capture_plugin(workdir: Path) -> None:
    """Copy and compile brpatch-prefilter.c in the workdir (e9compile)."""
    shutil.copy(BRPATCH_PREFILTER_SOURCE, workdir / "brpatch-prefilter.c")
    cmd = ["guix", "shell", "e9patch@1.0.0", "--",
           "e9compile", "brpatch-prefilter.c", "-DTAOSC_DEST=0"]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=workdir)
    if result.returncode != 0:
        raise RuntimeError(f"e9compile failed with exit code {result.returncode}")


def build_capture_binary(workdir: Path, configdir: Path, config: dict,
                         patch_loc: str) -> Path:
    """Instrument the original binary with the capture plugin at PATCH_LOC.

    Returns the path of <BINARY>.brprefilter.  Also dumps e9tool JSON
    metadata (needed by extract_trampoline_info) as
    <BINARY>.brprefilter.json.
    """
    original_binary = ensure_original_binary(workdir, configdir, config)
    brprefilter = workdir / f"{config['BINARY']}.brprefilter"
    metadata = workdir / f"{config['BINARY']}.brprefilter.json"
    for output, fmt in ((metadata, ["--format=json"]), (brprefilter, [])):
        cmd = ["guix", "shell", "e9patch@1.0.0", "--", "e9tool"] + fmt + [
            "-100", "-M", f"addr={patch_loc}",
            "-P", "if dest(state)@brpatch-prefilter goto",
            "-o", str(output), str(original_binary)]
        print(" ".join(cmd))
        result = subprocess.run(cmd, cwd=workdir)
        if result.returncode != 0:
            raise RuntimeError(
                f"e9tool failed with exit code {result.returncode}: "
                f"cannot create {output.name}")
    return brprefilter


def capture_states(workdir: Path, configdir: Path, config: dict,
                   patch_loc: str) -> Optional[List[List[int]]]:
    """Run the POC once against <BINARY>.brprefilter and return the
    captured STATE vectors (each a list of 16 signed ints).

    Returns None if the run failed (timeout / subprocess error) so the
    caller can fail open.
    """
    if not QEMU_STACKTRACE_RELEASE.exists():
        print(f"Warning: {QEMU_STACKTRACE_RELEASE} not found")
        return None

    compile_capture_plugin(workdir)
    brprefilter = build_capture_binary(workdir, configdir, config, patch_loc)

    extracted = extract_trampoline_info(
        brprefilter,
        workdir / f"{config['BINARY']}.brprefilter.json",
        ensure_original_binary(workdir, configdir, config),
        int(patch_loc, 0),
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

    data = b"".join(chunks).decode(errors="ignore")
    return parse_state_lines(data)


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
                    elapsed: float) -> None:
    """Write source predicate IDs and compact runtime patch IDs.

    Passing predicates receive consecutive ``new-id`` values starting at 1;
    rejected predicates receive ``new-id -1``.  Runtime patch IDs therefore
    remain compatible with ``range(1, TOTAL_PATCHES + 1)`` while ``id``
    preserves the predicate source line.
    """
    survived = 0
    with prefilter_file.open("w", encoding="utf-8") as f:
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
    predicate_records: List[Tuple[int, str]] = list()
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
    predicate_records = load_predicates(predicates_file)

    patch_records = [
        (patch_id, source_id, predicate)
        for patch_id, (source_id, predicate)
        in enumerate(predicate_records, start=1)
    ]
    # Apply the offline prefilter results, if any (see the `prefilter`
    # subcommand).  Predicates whose prefilter row evaluates to true
    # survive; the rest are discarded before the top-30 cap, so the
    # binradar pipeline never runs on patches that would be filtered out
    # anyway.  Fail open on any parse trouble.
    prefilter_file = workdir / "prefilter.sbsv"
    if prefilter_file.exists():
        passed_ids = load_prefilter_passed_ids(prefilter_file)
        if passed_ids is None:
            print(f"Warning: failed to parse {prefilter_file.name}; "
                  f"using all predicates (fail-open)")
        else:
            predicate_by_id = dict(predicate_records)
            survived = list()
            for source_id, new_id in sorted(
                    passed_ids.items(), key=lambda item: item[1]):
                predicate = predicate_by_id.get(source_id)
                if predicate is not None:
                    survived.append((new_id, source_id, predicate))
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
    with brpatches_inc.open("w") as f:
        f.write("case 0:\n\treturn \"p0\";\n")
        for patch_id, source_id, predicate in selected_patch_records:
            patch_str = predicate_to_branch_patch_str(predicate)
            f.write(f"case {patch_id}:\n"
                    f"\treturn \"{patch_str}\"; "
                    f"/* predicate line {source_id} */\n")
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
    predicate_records = load_predicates(predicates_file)
    if not predicate_records:
        write_prefilter(prefilter_file, [], time.time() - start)
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

    states = capture_states(workdir, configdir, config, patch_loc)
    if states is None:
        # Fail open, matching run_filter's `result is None -> passed=True`.
        print("Warning: prefilter capture failed; keeping all predicates "
              "(fail-open)")
        results = [(source_id, True, "capture failed (fail-open)", predicate)
                   for source_id, predicate in predicate_records]
        write_prefilter(prefilter_file, results, time.time() - start)
        sys.exit(0)
    if not states:
        # The patch site is never hit on the POC, so every predicate would
        # be filtered out by the FILTER phase anyway (the patch never
        # activates and the POC still crashes at the original fault).
        print("Warning: patch site never hit on the POC; discarding all "
              "predicates")
        results = [(source_id, False, "patch site never hit", predicate)
                   for source_id, predicate in predicate_records]
        write_prefilter(prefilter_file, results, time.time() - start)
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
    write_prefilter(prefilter_file, results, time.time() - start)


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
