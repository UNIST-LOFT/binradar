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
    guix build {{guix_spec}}

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
    docker run -v $ABS_WORKDIR:/workdir -v /gnu/store:/gnu/store:ro -v /var/guix:/var/guix:ro --rm {{binradar_image}} uv run /root/fuzzolic/fuzzolic/binradar.py -w /workdir

binradar-dev workdir="workdir" binradar_image="fuzzolic:2204":
    ABS_WORKDIR=$(cd "{{workdir}}" && pwd); \
    docker run -v $ABS_WORKDIR:/workdir -v {{FUZZOLIC_ROOT}}/fuzzolic:/root/fuzzolic/fuzzolic:ro -v {{FUZZOLIC_ROOT}}/tracer/build:/root/fuzzolic/tracer/build:ro -v {{FUZZOLIC_ROOT}}/solver/build:/root/fuzzolic/solver/build:ro -v {{FUZZOLIC_ROOT}}/LibAFL:/root/fuzzolic/LibAFL:ro -v /gnu/store:/gnu/store:ro -v /var/guix:/var/guix:ro --rm {{binradar_image}} uv run /root/fuzzolic/fuzzolic/binradar.py -w /workdir