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

## Patch families

TAOSC generates three predicate families that BinRadar classifies automatically
during `setup` (written as `BINRADAR_PATCH_KIND` in `binradar.env`):

### Generic ERM (`generic-erm`)

Scalar signed-i64 expressions over the 16 captured register slots.
You can check the generated predicates in `workdir/predicates`:
```
max1 / rax < +max1
max1 / rax <= +max1
max1 / rax == +max1
```

TAOSC jumps when a generated predicate is false, while `brpatch.c` jumps when
its encoded expression is nonzero, so setup encodes each candidate as
`predicate == 0` and stores the prefix string in `brpatches.inc`:
```c
case 0:
	return "p0";
case 1:
	return "=</p0v0p0p0";
default:
	return "p0";
```

### CWE-119 ERM (`cwe119-erm`)

Heap-buffer-overflow predicates over typed cells (registers and stack slots)
quantified against 256 tracked allocation clamps.  The closed grammar emitted
by `utils/taosc/cwe119/filter.zig` is:
```
pointer := CELL >= i->begin && CELL < i->end
size    := {1|2|4|8} * CELL < i->end - i->begin
```
where `CELL` is a register (`s->rax`..`s->r15`) or a typed stack cell
(`((uint64_t *)s->rsp)[N]` for pointers, `((uint{8,16,32}_t *)s->rsp)[N]` for
sizes).  The branch jumps when no tracked clamp satisfies the predicate.

These require allocation-history hooks (`mark`, `set_size`, `set_base`)
instrumented before the patch site; the clamp values are history-dependent and
cannot be reconstructed from patch-site registers alone.  Setup emits compact
typed descriptors in `brpatches.inc` (never source text):
```c
case 1:
	return "c1p0";          /* pointer predicate, register rax */
case 17:
	return "c1s64i0";       /* pointer predicate, uint64_t stack[0] */
case 29:
	return "c2p1q1";        /* size predicate, register rbx, scale 1 */
case 45:
	return "c2s8i16q1";     /* size predicate, uint8_t stack[16], scale 1 */
```

### CWE-119 direct call-site (`cwe119-direct`)

When the crash address equals the patch location, Taosc emits a direct
call-site metapatch with no predicate list.  The decision is
`jnz($mem0,dest)`: branch when the computed effective address lies outside
every tracked clamp.  This uses the same allocation tracker as CWE-119 ERM
but exposes exactly one candidate (id 1).  Setup rebuilds the binary with
BinRadar patch-id switching and `[patch]` logging instead of reusing Taosc's
incompatible `no_call`/`jnz` output.

### Taosc specialized (`taosc-specialized`)

No predicates and no allocator trace: Taosc generated a CWE-369/476/617 patch.
Setup reuses the prebuilt `.brpatched` binary when present.

## Setup and prefilter
```shell
just setup
# uv run /path/to/binradar/fuzzolic/binradar-setup.py setup -w workdir
```
This setup script classifies the workdir, generates `workdir/binradar.env` with
the necessary configuration (including `BINRADAR_PATCH_KIND`), and generates
`workdir/brpatches.inc` with the typed predicate table.

Before `setup`, run the patch prefilter to evaluate all candidate predicates
offline against the POC:
```shell
just prefilter <workdir>
# uv run fuzzolic/binradar-setup.py prefilter -w <workdir>
```
The prefilter keeps only predicates that branch on the POC, so the expensive
pipeline never runs on patches the FILTER phase would reject.  For CWE-119
ERM it captures full-context snapshots (clamps + registers + stack) and
evaluates descriptors offline; for CWE-119 direct it is a no-op (FILTER is the
behavioral gate).  `just binradar` runs the prefilter automatically on fresh
workdirs.