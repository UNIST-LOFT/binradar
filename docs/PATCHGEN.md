# Patch Generation with TAOSC
This document describes how to use TAOSC to generate patches for the vulnerable program, and how to check the generated patches.

## Patch generation
```sh
# Install Guix
cd /tmp
wget https://guix.gnu.org/guix-install.sh
chmod +x guix-install.sh
./guix-install.sh
# Pull the latest guix
cp ./utils/channels.scm ~/.config/guix/channels.scm
guix pull
# Install taosc
guix build taosc
# Build buggy binary
guix build binutils@2.29
cd benchmarks/loftix/binutils/CVE-2017-14940
# Use just (https://github.com/casey/just)
just taosc
# Or run directly
guix shell taosc -- taosc-fix 1 workdir poc "$(guix build binutils@2.29)/bin/nm" -l @@
```

## Check generated patches
You can check the generated predicates in `workdir/predicates`.
It will looks like this:
```
max1 / rax < +max1
max1 / rax <= +max1
max1 / rax == +max1
```

These predicates should be converted into the patch string that can be evaluated by `eval()` in `benchmarks/loftix/brpatch.c`.
Conversion can be done by
```shell
just setup
# python3 /path/to/binradar/benchmarks/scripts/binradar_setup.py -w workdir
```
This setup script will generate `workdir/binradar.env` file with the necessary configuration for binradar, and also generate `workdir/brpatch.inc` file with the patch strings hard-coded.
The generated patch string will be like this:
```c
case 0:
	return "p0";
case 1:
	return "</p0v0p0";
case 2:
	return "<=/p0v0p0";
case 3:
	return "=/p0v0p0";
default:
	return "p0";
```