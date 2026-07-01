# BinRadar qemu_stacktrace Compatibility Mode

`afl-qemu-trace` accepts a small set of `qemu_stacktrace`-compatible options for BinRadar crash triage. The mode is implemented inside QEMU user-mode, so it does not rely on LibAFL QEMU or an ASAN `LD_PRELOAD` DSO.

## Supported Options

- `--input <path>`: input file used to replace target argument `@@`.
- `--patch-loc <addr>`: exact guest instruction address to report as patch coverage.
- `--patch-func-entry <addr>`: optional function entry address for function-entry coverage and file tracing.
- `--asan host|guest|none`: accepted for CLI compatibility and printed in output. It intentionally does not enable AFL++ QASAN.
- `--asan-include <range>` and `--asan-exclude <range>`: accepted and ignored for compatibility.
- `--trace-basic-blocks`: records translated basic block execution counts and prints `[bb]` lines at exit.

The Rust-style separator after the target binary is accepted and removed:

```sh
afl-qemu-trace --input ./poc/crash_1 --patch-loc 0x45eded --asan host ./objdump.orig -- -d @@
```

## Output

The output uses the existing `qemu_stacktrace` line format with elapsed milliseconds:

```text
[qemu-exit] [kind crash] [detail target crash] [time N]
[exit] [result crash] [time N]
[stacktrace] [idx 0] [addr 0x...] [symbol  (/path+0x...)] [time N]
[fault-addr] [idx ...] [addr 0x...] [symbol  (/path+0x...)] [time N]
[patch-cov] [location 0x45eded] [covered true] [hits 1] [time N]
[patch-func] [location 0x45eded] [entry 0x403130] [hits 1] [time N]
```

For the CVE-2017-14745 `objdump.orig` benchmark, the expected command is:

```sh
cd /workspace/binradar/benchmarks/loftix/binutils/CVE-2017-14745/workdir
/workspace/binradar/utils/AFLplusplus/afl-qemu-trace \
  --input /workspace/binradar/benchmarks/loftix/binutils/CVE-2017-14745/workdir/poc/crash_1 \
  --patch-loc 0x45eded \
  --asan host \
  /workspace/binradar/benchmarks/loftix/binutils/CVE-2017-14745/workdir/objdump.orig -- -d @@
```

Expected key lines:

```text
[fault-addr] [idx 2] [addr 0x45edf2] ...
[patch-cov] [location 0x45eded] [covered true] [hits 1] ...
[patch-func] [location 0x45eded] [entry 0x403130] [hits 1] ...
```

## Implementation Notes

- Runtime state and output formatting live in `qemuafl/linux-user/binradar-trace.c`.
- Public hooks are declared in `qemuafl/qemuafl/binradar-trace.h`.
- Exact patch hits are emitted from `accel/tcg/translator.c` at instruction translation time.
- Basic block hits are emitted from `accel/tcg/translate-all.c` when `--trace-basic-blocks` is enabled.
- x86/x86_64 function attribution is emitted from `target/i386/tcg/translate.c` for direct calls, indirect calls, and returns.
- File tracing is emitted from `linux-user/syscall.c` after successful `open`, `openat`, `read`, `lseek`, `dup`, `dup2`, `dup3`, `fcntl`, and `close` syscalls.
- Crash reporting is emitted from `linux-user/signal.c`; in compatibility mode it exits immediately after printing to avoid QEMU target core dumps.

## ASAN Policy

`--asan host` and `--asan guest` are intentionally compatibility labels only. AFL++ QASAN uses `libqasan.so` via `LD_PRELOAD`, which can reintroduce the allocator/glibc compatibility problem this migration avoids. To explicitly use AFL++ QASAN anyway, set `AFL_USE_QASAN=1` outside this compatibility mode and expect different runtime behavior.

## Build Note

This local tree includes small Meson compatibility fixes in `target/hexagon/meson.build` so `NO_CHECKOUT=1 CPU_TARGET=x86_64 ./build_qemu_support.sh` works with Meson 0.61 without resetting local changes.
