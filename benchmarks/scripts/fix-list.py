from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).parent.resolve()
BENCHMARKS_DIR = SCRIPT_DIR.parent.resolve() / "loftix"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <list_file>", file=sys.stderr)
        sys.exit(1)

    file = Path(sys.argv[1])
    if not file.exists():
        print(f"Error: {file} not found", file=sys.stderr)
        sys.exit(1)

    bug_map = {}
    for project_dir in BENCHMARKS_DIR.iterdir():
        if not project_dir.is_dir() or project_dir.name.startswith("."):
            continue
        for bug_dir in project_dir.iterdir():
            if bug_dir.is_dir() and (bug_dir / "config.env").exists():
                bug_map[bug_dir.name] = f"./{project_dir.name}/{bug_dir.name}"

    fixed = []
    missing = []
    seen = set()

    for line in file.read_text().splitlines():
        entry = line.strip()
        if not entry:
            continue

        if "/" in entry:
            key = entry.removeprefix("./")
            full = f"./{key}"
        else:
            if entry in bug_map:
                full = bug_map[entry]
            else:
                missing.append(entry)
                continue

        if full not in seen:
            seen.add(full)
            fixed.append(full)

    file.write_text("\n".join(fixed) + "\n")

    if missing:
        print(
            f"Skipped {len(missing)} entries not found:\n  "
            + "\n  ".join(missing),
            file=sys.stderr,
        )
    print(f"Fixed {file.name}: {len(fixed)} entries")


if __name__ == "__main__":
    main()
