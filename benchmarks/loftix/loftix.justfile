import "../../Justfile"
import? 'dev.justfile'

poc_input := env("POC_INPUT")
poc_dir := env("POC_DIR", "poc")
binary := env("BINARY")
guix_spec := env("GUIX_SPEC")
test_cmd := env("TEST_CMD")
patch_source := source_directory() + "/brpatch.c"

default:
    just --list

build:
    guix build --no-substitutes {{guix_spec}}

taosc workdir="workdir":
    mkdir -p {{workdir}}
    BINARY_PATH=$(python3 {{BENCHMARK_PATH}}/scripts/binradar_get_binary.py) && \
    guix shell taosc -- taosc-fix 1 {{workdir}} {{poc_dir}} "$BINARY_PATH" {{test_cmd}}

setup workdir="workdir":
    [ -f {{workdir}}/{{binary}}.orig ] || cp $(python3 {{BENCHMARK_PATH}}/scripts/binradar_get_binary.py) {{workdir}}/{{binary}}.orig
    python3 {{BENCHMARK_PATH}}/scripts/binradar_setup.py -w {{workdir}}

@_ensure_binradar_is_ready workdir="workdir":
    [ -d "{{workdir}}" ] || just taosc {{workdir}}
    [ -f "{{workdir}}/binradar.env" ] || just setup {{workdir}}

binradar workdir="workdir" binradar_image="fuzzolic:2204": (_ensure_binradar_is_ready workdir)
    ABS_WORKDIR=$(cd "{{workdir}}" && pwd); \
    docker run --user $(id -u):$(id -g) -v $ABS_WORKDIR:/workdir -v /gnu/store:/gnu/store:ro -v /var/guix:/var/guix:ro --rm {{binradar_image}} /workspace/fuzzolic/.venv/bin/python /workspace/fuzzolic/fuzzolic/binradar.py -w /workdir

binradar-dev workdir="workdir" binradar_image="fuzzolic:2204":
    ABS_WORKDIR=$(cd "{{workdir}}" && pwd); \
    docker run --user $(id -u):$(id -g) -v $ABS_WORKDIR:/workdir -v {{FUZZOLIC_ROOT}}/fuzzolic:/workspace/fuzzolic/fuzzolic:ro -v {{FUZZOLIC_ROOT}}/tracer/build:/workspace/fuzzolic/tracer/build:ro -v {{FUZZOLIC_ROOT}}/solver/build:/workspace/fuzzolic/solver/build:ro -v {{FUZZOLIC_ROOT}}/LibAFL:/workspace/fuzzolic/LibAFL:ro -v /gnu/store:/gnu/store:ro -v /var/guix:/var/guix:ro --rm {{binradar_image}} /workspace/fuzzolic/.venv/bin/python /workspace/fuzzolic/fuzzolic/binradar.py -w /workdir

binradar-guix workdir="workdir":
    guix shell binradar -- binradar -w {{workdir}}


# Run inside docker container
br workdir="workdir":
    uv run {{FUZZOLIC_ROOT}}/fuzzolic/binradar.py -w {{workdir}} --timeout 21600

eval workdir="workdir" fuzzer="sdfuzz" fuzz_out="/workspace/binradar/benchmarks/sdfuzz":
    uv run {{FUZZOLIC_ROOT}}/fuzzolic/binradar-evaluation.py -w {{workdir}} --fuzzer {{fuzzer}} --fuzz-out {{fuzz_out}}

