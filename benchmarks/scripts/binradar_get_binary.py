#!/usr/bin/env python3
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Optional
import sys

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

def print_error(msg: str):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)

def print_stdout(msg: str):
    print(msg, file=sys.stdout, flush=True, end="")

def main():
    parser = argparse.ArgumentParser(description="Get binary path")
    parser.add_argument("-c", "--configdir", type=Path, required=False, default=Path.cwd(), help="Directory containing configuration files (default: .)")
    args = parser.parse_args()
    
    configdir = args.configdir.absolute()
    config_path = configdir / "config.env"
    if not config_path.exists():
        print_error(f"config.env not found in {configdir}")

    env = load_env(config_path)
    binary = env.get("BINARY")
    if binary is None:
        print_error("BINARY not found in config.env")
        return
    guix_spec = env.get("GUIX_SPEC")
    final_binary_path = configdir / binary
    if guix_spec is not None and guix_spec != "":
        proc = subprocess.run(["guix", "build", guix_spec], check=True, stdout=subprocess.PIPE, text=True)
        guix_path = proc.stdout.strip()
        final_binary_path = Path(guix_path) / "bin" / binary
    if not final_binary_path.exists():
        print_error(f"Binary not found at {final_binary_path}")
    print_stdout(str(final_binary_path))


if __name__ == "__main__":
    main()
