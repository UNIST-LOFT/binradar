#!/usr/bin/env python3
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
import os


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build taoscadh@<CVE> from the current directory name and copy its Guix store output."
    )
    parser.add_argument("-w", "--workdir", required=True, type=Path,
                        help="Destination directory")
    args = parser.parse_args()

    cwd = Path.cwd()
    match = re.search(r"CVE-\d{4}-\d+", cwd.name, re.IGNORECASE)
    if not match:
        if cwd.name.lower().startswith("bugzilla-2633"):
            cve = "Maptools-2633"
        else:
            parser.error(f"No CVE ID found in current directory name: {cwd.name}")
    else:
        cve = match.group(0).upper()

    try:
        result = subprocess.run(
            ["guix", "build", f"taoscadh@{cve}"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
    except FileNotFoundError:
        print("error: guix executable was not found in PATH", file=sys.stderr)
        return 127
    except subprocess.CalledProcessError as exc:
        print(f"error: guix build failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode

    store_paths = [Path(line) for line in result.stdout.splitlines() if line.startswith("/gnu/store/")]
    if len(store_paths) != 1:
        print(f"error: expected exactly one Guix output path, got: {store_paths}", file=sys.stderr)
        return 1

    source = store_paths[0]
    if not source.is_dir():
        print(f"error: Guix output is not a directory: {source}", file=sys.stderr)
        return 1

    destination = args.workdir.resolve() / source.name
    args.workdir.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        print(f"error: destination already exists: {destination}", file=sys.stderr)
        return 1
    for name in os.listdir(source):
        src = os.path.join(source, name)
        dst = os.path.join(destination, name)
        if os.path.isdir(src) and not os.path.islink(src):
            shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst, follow_symlinks=False)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())