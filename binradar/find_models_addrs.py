#!/usr/bin/env python3

import argparse
from contextlib import closing
import os
import re
import subprocess
import sys
import tempfile

MODELS_LIBC = ["malloc", "free", "realloc", "calloc", "printf", "fprintf", "vfprintf", "fputc", "_IO_printf"]
MODELS = [
    # PLT entries and ordinary T/W definitions are usable.  IFUNC resolver
    # offsets are deliberately excluded by process_plt_libc.
    "strcmp",
    "strncmp",
    "strlen",
    "strnlen",
    "memchr",
    "memcmp",
    "memmove",
    "__printf_chk",
    "__memmove_chk",
    "memset",
    "__memset_chk",
    "memcpy",
    "__memcpy_chk",
    "strcpy",
    "strncpy",
    "atoi",
    "atol",
    "atoll",
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
]

_LABEL = re.compile(r"^([0-9a-fA-F]+) <([^>]+)>:$")


def _labels(binary, objdump):
    """Stream labels once; closing early stops disassembly after the base PC."""
    command = [objdump, "-d", "--", binary]
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True,
                          encoding="utf-8", errors="replace",
                          env={**os.environ, "LC_ALL": "C"}) as process:
        try:
            for line in process.stdout:
                match = _LABEL.match(line.strip())
                if match:
                    yield int(match[1], 16), match[2]
            status = process.wait()
            if status:
                raise subprocess.CalledProcessError(status, command)
        finally:
            # libc needs only the first label. Close the pipe so the producer
            # gets SIGPIPE, then let Popen reap it; explicit kill is forbidden
            # in the observation sandbox.
            process.stdout.close()


def process_plt_libc(binary, outfile=None, *, objdump, nm):
    with closing(_labels(binary, objdump)) as labels:
        first = next(labels, None)
    if first is None:
        raise ValueError(f"No disassembly base found: {binary}")
    base_address = first[0]
    symbols = subprocess.check_output(
        [nm, "-D", "--", binary], text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LC_ALL": "C"})
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[1] not in ("T", "W"):
            continue
        name = fields[2].split("@", 1)[0]
        # GNU IFUNC values designate resolvers, not implementations. The
        # tracer learns actual implementations from guest PLT/GOT resolution.
        if name in MODELS_LIBC or name in MODELS:
            address = int(fields[0], 16) - base_address
            print(f"{os.path.basename(binary)},{name},0x{address:x}", file=outfile)


def process_plt(binary, outfile=None, *, objdump):
    base_address = None
    with closing(_labels(binary, objdump)) as labels:
        for address, label in labels:
            if base_address is None:
                base_address = address
            if not label.endswith("@plt"):
                continue
            name = label.split("@", 1)[0]
            if name in MODELS or name in MODELS_LIBC:
                print(f"{os.path.basename(binary)},{name},0x{address - base_address:x}",
                      file=outfile)
    if base_address is None:
        raise ValueError(f"No disassembly base found: {binary}")


def _libraries(binary, ldd):
    command = [ldd, binary]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace",
                            env={**os.environ, "LC_ALL": "C"})
    diagnostic = result.stdout + result.stderr
    if result.returncode and not any(message in diagnostic for message in (
            "not a dynamic executable", "statically linked")):
        raise subprocess.CalledProcessError(
            result.returncode, command, result.stdout, result.stderr)
    libraries = []
    for line in result.stdout.splitlines():
        if "=> not found" in line:
            raise ValueError(f"Unresolved dependency: {line.strip()}")
        match = re.match(r"\s*\S+ => (.+) \(0x[0-9a-fA-F]+\)\s*$", line)
        if match and "libdl.so" not in match[1]:
            libraries.append(match[1])
    return libraries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', help='output path')
    # Standalone CLI defaults use PATH. BinRadar always supplies paths.py's
    # tool choices explicitly, including when this file runs under -I -S.
    parser.add_argument('--objdump', default="objdump", help='objdump executable')
    parser.add_argument('--nm', default="nm", help='nm executable')
    parser.add_argument('--ldd', default="ldd", help='ldd executable')
    parser.add_argument('binary', help='path to the binary to inspect')
    args = parser.parse_args()
    binary = os.path.abspath(args.binary)
    temporary = None
    try:
        if not os.path.isfile(binary):
            raise ValueError(f"Invalid binary: {args.binary}")
        binaries = [binary, *_libraries(binary, args.ldd)]

        def emit(outfile):
            for image in binaries:
                if "libc.so" in os.path.basename(image):
                    process_plt_libc(image, outfile, objdump=args.objdump, nm=args.nm)
                else:
                    process_plt(image, outfile, objdump=args.objdump)

        if args.output:
            # Publish only the complete table. A failing tool must neither
            # replace an existing table nor leave a partial one for a reader.
            destination = os.path.abspath(args.output)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                             dir=os.path.dirname(destination),
                                             prefix=os.path.basename(destination) + ".",
                                             suffix=".part", delete=False) as outfile:
                temporary = outfile.name
                emit(outfile)
            os.replace(temporary, destination)
            temporary = None
        else:
            emit(sys.stdout)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Failed to find model addresses: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr.rstrip(), file=sys.stderr)
        return 1
    finally:
        if temporary is not None:
            os.unlink(temporary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
