# Justfile for variable definitions and common commands
FUZZOLIC_ROOT := source_directory()
LIBAFL_PATH := FUZZOLIC_ROOT + "/LibAFL"
QEMU_STACKTRACE := LIBAFL_PATH + "/fuzzers/binary_only/qemu_stacktrace"
FUZZOLIC_SCRIPT := FUZZOLIC_ROOT + "/fuzzolic/fuzzolic.py"
FUZZOLIC_BASE_ARGS := "--symbolic-models --keep-run-dirs --address-reasoning --optimistic-solving --timeout 60000"