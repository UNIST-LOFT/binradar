#!/usr/bin/env python3

import os
import sys
import shutil

LOFTIX = os.environ.get(
    "LOFTIX",
    "/root/binradar/benchmarks/loftix-tmp/bugs"
)

def main():
    cve_list = sys.argv[1:]
    if not cve_list:
        cve_list = os.listdir()
    print(f"[+] Processing CVEs: {', '.join(cve_list)}")
    for cve in cve_list:
        try:
            _, year, cve_id = cve.split("-", 2)
        except ValueError:
            print(f"[!] Invalid CVE format: {cve}")
            continue

        src = os.path.join(LOFTIX, "cve", year, cve_id)
        dst = os.path.join(cve, "poc")

        if not os.path.isdir(src):
            print(f"[!] Source not found: {src}")
            continue

        if os.path.exists(dst):
            print(f"[-] Removing existing: {dst}")
            shutil.rmtree(dst)

        print(f"[+] Copying {src} -> {dst}")
        shutil.copytree(src, dst)

    print("[+] Done")

if __name__ == "__main__":
    main()