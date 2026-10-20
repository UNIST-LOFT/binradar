"""Deployment paths: checkout defaults, patchable in one place by packagers.

E9 lookup is lazy so importing the library does not require native tools or
Guix. E9TOOL/E9COMPILE select individual executables, never shell commands.
"""

import os
import shutil
import subprocess
from functools import cache
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_CHECKOUT = _PACKAGE_DIR.parent

TRACER_BIN = str(_CHECKOUT / "tracer/build/x86_64-linux-user/qemu-x86_64")
SOLVER_SMT_BIN = str(_CHECKOUT / "solver/build/solver-smt")
SOLVER_FUZZY_BIN = str(_CHECKOUT / "solver/build/solver-fuzzy")
AFL_FUZZ_BIN = str(_CHECKOUT / "utils/AFLplusplus/afl-fuzz")
AFL_SUPPORT_DIR = str(_CHECKOUT / "utils/AFLplusplus")
QASAN_QEMU_BIN = str(_CHECKOUT / "utils/binradar-aflplusplus/afl-qemu-trace")
TARGETED_FUZZER_BIN = str(_CHECKOUT / "LibAFL/fuzzers/binary_only/qemu_targeted_simple/target/release/qemu_targeted_simple")
LEGACY_AFL_SUPPORT_DIR = str(_CHECKOUT.parent / "AFLplusplus")

FIND_MODELS_SCRIPT = str(_PACKAGE_DIR / "find_models_addrs.py")
LOFTIX_DIR = str(_CHECKOUT / "benchmarks/loftix")
BENCHMARK_SCRIPTS = _CHECKOUT / "benchmarks/scripts"
BRPATCH_SOURCE = _CHECKOUT / "benchmarks/loftix/brpatch.c"
BRPATCH_CACHED_SOURCE = _CHECKOUT / "benchmarks/loftix/brpatch-cached.c"

E9_GUIX_SPEC = "e9patch@1.0.1"


@cache
def _guix_e9_bin_dir() -> Path:
    output = subprocess.check_output(
        ["guix", "build", E9_GUIX_SPEC], text=True).strip()
    root = Path(output)
    if not root.is_absolute() or "\n" in output:
        raise RuntimeError(
            f"guix build {E9_GUIX_SPEC} did not return one absolute store path: "
            f"{output!r}")
    return root / "bin"


def _e9_executable(name: str) -> str:
    variable = name.upper()
    override = os.environ.get(variable)
    if override:
        executable = shutil.which(override)
        if executable is None:
            raise FileNotFoundError(
                f"{variable} does not name an executable: {override!r}")
        return os.path.abspath(executable)

    executable = _guix_e9_bin_dir() / name
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise FileNotFoundError(
            f"{E9_GUIX_SPEC} does not provide executable {executable}; "
            f"set {variable} to an executable path")
    return str(executable)


def e9tool() -> str:
    """Return E9TOOL's executable, or the absolute Guix e9tool path."""
    return _e9_executable("e9tool")


def e9compile() -> str:
    """Return E9COMPILE's executable, or the absolute Guix e9compile path."""
    return _e9_executable("e9compile")
