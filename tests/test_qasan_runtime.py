"""Exercise the installed guest runtime and host shadow checker together."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from binradar import paths


@pytest.fixture(scope="module")
def qasan_guest(tmp_path_factory):
    qemu = Path(paths.QASAN_QEMU_BIN)
    if not qemu.is_file() or not (qemu.parent / "libqasan.so").is_file():
        pytest.skip("built BinRadar QEMU and libqasan required")
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler required")
    guest = tmp_path_factory.mktemp("qasan-runtime") / "guest"
    subprocess.run(
        [compiler, "-O0", "-g", "-fno-builtin", "-fno-pie", "-no-pie",
         "-I", str(Path(__file__).resolve().parents[1]
                   / "utils/binradar-aflplusplus/qemu_mode/qemuafl/qemuafl"),
         str(Path(__file__).parent / "fixtures" / "qasan_runtime.c"),
         "-o", str(guest)],
        check=True, capture_output=True,
    )
    return qemu, guest


def run_guest(qasan_guest, *arguments):
    qemu, guest = qasan_guest
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("AFL_", "__AFL_", "QASAN_", "BINRADAR_"))
           and key not in ("LD_PRELOAD", "QEMU_SET_ENV", "QEMU_UNSET_ENV")}
    return subprocess.run(
        [str(qemu), "--asan", "host", str(guest), *arguments],
        env=env, text=True, capture_output=True, timeout=20, check=False,
    )


def test_memory_contents_overlap_and_exact_boundaries(qasan_guest):
    # The guest checks complete bytes, guard bytes, overlapping copies in both
    # directions, zero-length boundaries, and all short word tails/alignments.
    result = run_guest(qasan_guest)
    assert result.returncode == 0, result.stderr
    assert "[exit] [result ok]" in result.stderr


@pytest.mark.parametrize("operation", ["oob-load", "oob-store", "interior-poison", "uaf"])
def test_range_checks_still_reject_invalid_memory(qasan_guest, operation):
    result = run_guest(qasan_guest, operation)
    assert result.returncode == 1, result.stderr
    assert "[qemu-exit] [kind crash]" in result.stderr
    assert "[fault-addr]" in result.stderr
