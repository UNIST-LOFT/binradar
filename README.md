# BinRadar: Patch Verification for Binary Patching Tools

## Build
```
git clone https://github.com/hsh814/fuzzolic.git
cd fuzzolic
git submodule update --init --recursive
docker build -t fuzzolic:2204 -f docker/fuzzolic-runner/Dockerfile.Ubuntu2204 .
```

## Usage
### Test configuration
Prepare the patched program and config.env file in same directory.
```
POC_INPUT="poc/3899.crashes.bin"
BINARY="nm"
TEST_CMD="-l @@"
PATCH_LOC="0x456845"
TOTAL_PATCHES=2
```
You need to provide:
- POC_INPUT: a test case that triggers the vulnerability (e.g., a crashing input)
- BINARY: the target binary to be patched and verified. Original binary should be named as `nm.orig` and patched binary should be named as `nm.patched` in the same directory.
- TEST_CMD: the command to run the test case with the binary. Use `@@` as a placeholder for the test case file path.
- PATCH_LOC: the location of the patch (e.g., the address of the instruction to be patched)
- TOTAL_PATCHES: the total number of patches to be verified (e.g., if you have 2 candidate patches, set it to 2). Patch id 0 will be original program, and patch id 1, 2 will be candidate patches.

### Quickstart
```shell
uv run /root/fuzzolic/fuzzolic/binradar.py -w /root/fuzzolic/tests/example7/CVE-2017-15025
```
Entrypoint is `fuzzolic/binradar.py`. It will automatically read the config.env file in the specified working directory and run the verification process. You can also specify other options as needed.
Timeout can be given as `-t` or `--timeout` option (default: 3600 seconds).

Output will be saved in the `out` directory in the working directory. You can check the logs and results in the output directory.

Check `out/progress.log` for the progress of the verification process. `[final] [done] [id {run_id}] [remaining_patches {remaining_patches}] [binradar_remaining_patches {binradar_remaining_patches}]` indicates the final result of the verification process.

## Structure
### Orchestrator
- `fuzzolic/binradar.py`: main entry point for the verification process
- `fuzzolic/binradar_verifier.py`: implementation of the verification logic.
- `fuzzolic/analyze_type.py`: type inference used for binradar.

These are main phases:
1. PROBE: run the test cases with original binary to confirm the crash and collect information about the crash (e.g., fault address, patch function entrypoint, patch function hit count, etc.)
2. FUZZOLIC: run fuzzolic (concolic execution) with the original binary and the test cases to collect more concrete test cases.
3. DIRECTED: run modified fuzzolic with the original binary and the test cases to collect more directed test cases.
4. FUZZER: run simple binary-only fuzzer with the original binary and the test cases to collect more fuzzed test cases.
5. MINIMIZER: remove redundant or non-reachable concrete test cases.
6. VERIFIER: run patched binary with the collected test cases to check if the patch is correct. If any test case fails, the patch is rejected. If all test cases pass, the patch is verified.
7. BINRADAR: binradar - directly mutate the memory state and check if the patch is correct.
8. DONE: finalize the verification process and save the results.


### tracer
Used for concolic execution (`fuzzolic`, `directed`) and `binradar`. Based on QEMU `4.1.1` with modifications for symbolic execution and type inference.

`type-infer` branch
- Main modified files:
  * tracer/linux-user/snapshot.c, h
  * tracer/linux-user/i386/signal.c
  * tracer/linux-user/syscall.c
  * tracer/tcg/symbolic/symbolic.c, h
  * tracer/tcg/symbolic/models.c
  * tracer/tcg/symbolic-i386.c
- Forkserver: Implemented
- Type Analyzer
  * Logging memory accesses with region info: (trace_mem())
    + Heap: hook into malloc()/free()
    + Stack: hook for callq/ret
    + Global: hook into program segments in elf load
    + Other: ignored
  * Post-processing analyzer: python script (fuzzolic/analyze_type.py)
    + Recover base addresses of each memory chunk using heuristic
- Memory modification
  * Implemented in tracer/tcg

### solver
Used for solving path constraints and producing concrete test cases in `fuzzolic` and `directed`.

### LibAFL
`LibAFL/fuzzers/binary_only/qemu_stacktrace`: Used for `probe`, `minimizer`, and `verifier` phases. Run original or patched binary with the concrete test cases and get the results.

`LibAFL/fuzzers/binary_only/qemu_targeted_simple`: Used for fuzzing in `fuzzer` phase. Collect test cases that can reach the patch location, using simple coverage-based fuzzing strategies.


