#!/usr/bin/env python3

import argparse
import re
import tarfile
from pathlib import Path


def find_latest_run(base_dir: Path, workdir: str, run_prefix: str) -> Path | None:
    out_dir = base_dir / workdir / "out"

    if not out_dir.is_dir():
        print(f"[WARN] out directory not found: {out_dir}")
        return None

    pattern = re.compile(rf"^{re.escape(run_prefix)}-(\d+)$")

    candidates = []

    for entry in out_dir.iterdir():
        if not entry.is_dir():
            continue

        match = pattern.fullmatch(entry.name)
        if match:
            candidates.append((int(match.group(1)), entry))

    if not candidates:
        print(f"[WARN] no matching run found: {out_dir}/{run_prefix}-*")
        return None

    _, latest = max(candidates, key=lambda x: x[0])
    return latest


def main():
    parser = argparse.ArgumentParser(
        description="Archive the latest run directory for each entry in exp.list"
    )

    parser.add_argument(
        "--list",
        default="exp.list",
        help="Experiment list file (default: exp.list)",
    )
    parser.add_argument(
        "--workdir",
        required=True,
        help="Workdir name, e.g. workdir-0.1.17",
    )
    parser.add_argument(
        "--run-prefix",
        required=True,
        help="Run directory prefix, e.g. br-feedback",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="latest-runs.tar.gz",
        help="Output archive (default: latest-runs.tar.gz)",
    )

    args = parser.parse_args()

    list_path = Path(args.list)

    if not list_path.is_file():
        raise SystemExit(f"List file not found: {list_path}")

    targets = []

    with list_path.open() as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            base_dir = Path(line)
            latest = find_latest_run(
                base_dir,
                args.workdir,
                args.run_prefix,
            )

            if latest is not None:
                targets.append(latest)
                print(f"[SELECT] {latest}")

    if not targets:
        raise SystemExit("No matching directories found.")

    output = Path(args.output)

    mode = "w:gz" if output.name.endswith((".tar.gz", ".tgz")) else "w"

    with tarfile.open(output, mode) as tar:
        for target in targets:
            # Preserve the complete relative directory structure.
            tar.add(target, arcname=target)

    print(f"[DONE] created: {output}")
    print(f"[DONE] archived {len(targets)} directories")


if __name__ == "__main__":
    main()