#!/usr/bin/env python3
import os
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import shutil

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

def run_fix(configdir: Path, config_path: Path, workdir: Path):
    print(f"Running fix command in {workdir} with config {config_path}")
    result = subprocess.run(["just", "fix", workdir], cwd=configdir, env=os.environ.copy(), capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running fix: {result.stderr}")
    else:
        print(f"Fix output: {result.stdout}")

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
    
    predicates_file = workdir / "predicates"
    if not predicates_file.exists():
        print(f"Error: {predicates_file.name} file not found in {workdir}")
        exit(1)
    with predicates_file.open("r") as f:
        num = 0
        for line in f:
            line = line.strip()
            if not line:
                continue
            num += 1
    env["TOTAL_PATCHES"] = str(num)
    return env

def main():
    parser = argparse.ArgumentParser(
        description="binradar_setup: setup config files for binradar")
    parser.add_argument("-c", "--configdir", type=Path, required=False, default=Path.cwd(), help="Config directory (default: current directory)")
    parser.add_argument("-w", "--workdir", type=Path, required=False, default=Path.cwd() / "workdir", help="Working directory for the benchmark (default: ./workdir)")
    args = parser.parse_args()
    configdir: Path = args.configdir
    config_path = configdir / "config.env"
    if not config_path.exists():
        print(f"Error: config.env not found in {configdir}")
        return
    
    workdir: Path = args.workdir
    if not workdir.exists():
        print(f"Creating working directory at {workdir}")
        workdir.mkdir(parents=True, exist_ok=True)
        if not (workdir / "patch-location").exists():
            run_fix(configdir, configdir / "config.env", workdir)
    
    binradar_env = create_binradar_env(configdir, config_path, workdir)
    binradar_env_path = workdir / "binradar.env"
    save_env(binradar_env, binradar_env_path)
    print(f"binradar environment variables saved to {binradar_env_path}")
    

if __name__ == "__main__":
    main()