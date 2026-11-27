"""Real local runtime captures and artifact-bound plan preparation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from binradar import binradar_setup, paths
from binradar import binradar_taosc_predicates as predicates
from binradar.binradar_verifier import BinRadarQemuRunner
from binradar.observation_plan import (
    artifact_observation_environment, cleared_observation_environment,
    load_observation_binding, prepare_observation_plan,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("cwe", [False, True])
def test_shared_guest_capture_contract(tmp_path, cwe):
    binary = tmp_path / "runtime-contract"
    command = ["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-function", "-Wno-unused-parameter",
               "-Wno-missing-field-initializers", "-Wno-implicit-fallthrough",
               "-Iutils/e9patch/examples", "-Itests/fixtures/brobs"]
    if cwe:
        command += ["-DBRPATCH_CWE805", "-DBRPATCH_ALLOC_MALLOC"]
    command += ["tests/test_br_observation.c", "-o", str(binary)]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=15)
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run([str(binary)], cwd=tmp_path, capture_output=True,
                            start_new_session=True, timeout=5)
    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.fixture(scope="module", params=[False, True], ids=["fixed-image", "pie-image"])
def runtime_artifact(tmp_path_factory, request):
    work = tmp_path_factory.mktemp("real-observation-runtime")
    source = work / "fixture.c"
    source.write_text(r'''
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
struct item { struct item *next; uint32_t value; };
unsigned char guarded_page[8192] __attribute__((aligned(4096)));
extern void observe(struct item *);
int main(int argc, char **argv) {
    struct item *root = malloc(sizeof(*root));
    struct item *leaf = calloc(1, sizeof(*leaf));
    if (!root || !leaf) return 3;
    root->next = leaf; root->value = 9; leaf->value = 42;
    guarded_page[0] = 7;
    char mode = argc > 1 ? argv[1][0] : 'l';
    if (mode == 'f') free(leaf);
    if (mode == 'o') root->next = (struct item *)((char *)leaf + sizeof(*leaf) - 4);
    if (mode == 'n') root = 0;
    if (mode == 'u') root = (struct item *)0x12345000;
    if (mode == 'p' && mprotect(guarded_page, 4096, PROT_NONE)) return 4;
    observe(root);
    return 0;
}
__asm__(".text\n.globl observe,patch_site\nobserve:\npatch_site:\n"
        "mov $0,%eax\nret\n");
''')
    original = work / "fixture.orig"
    relocation = ["-fPIE", "-pie"] if request.param else ["-fno-pie", "-no-pie"]
    subprocess.run(["cc", "-O0", *relocation, "-fno-builtin",
                    str(source), "-o", str(original)], check=True, capture_output=True, timeout=10)
    symbols = {}
    for line in subprocess.check_output(["nm", "-n", str(original)], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    plan = {
        "schema_version": 1, "analysis_status": "ok",
        "artifact_orig_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "patch_location": hex(symbols["patch_site"]), "alloc_hooks": [],
        "slots": [
            {"id": 0, "kind": "global", "rva": hex(symbols["guarded_page"]), "width": 1, "signed": False},
            {"id": 1, "kind": "deref_chain", "root": {"kind": "reg", "reg": "rdi"},
             "offsets": [0, 8], "width": 4, "signed": False},
            {"id": 2, "kind": "heap_meta", "root": {"kind": "reg", "reg": "rdi"},
             "offsets": [], "meta_op": "obj_size", "width": 8, "signed": False},
        ],
    }
    (work / "observation-plan.json").write_text(json.dumps(plan))
    (work / "stack-size").write_text("128\n")
    (work / "patch-destination").write_text("0\n")
    (work / "patch-location").write_text(f"{symbols['patch_site']:x}\n")
    shutil.copyfile(paths.BRPATCH_SOURCE, work / "brpatch.c")
    env = {"BINARY": "fixture", "PATCH_LOC": hex(symbols["patch_site"]),
           "TEST_CMD": "@@", "BRCACHE_STACK_SIZE": "128"}
    descriptor = "AV1>o1p0"
    (work / "predicates").write_text(descriptor + "\n")
    selected = predicates.SetupPredicates(predicates.PredicateFamily.GENERIC_ERM, None,
                                          [predicates.PredicateRecord(1, 1, descriptor, descriptor)], None)
    binradar_setup.prepare_patch(work, work, env, selected)
    metadata = binradar_setup.build_cached_binary(work, work, env, predicates.PredicateFamily.GENERIC_ERM,
                                                 None, persist_metadata=False)
    binding = load_observation_binding(work)
    predicates.write_runtime_predicates(work / "brpatches.json", predicates.PredicateFamily.GENERIC_ERM,
                                         [], observation=binding)
    env.update(BRCACHED_E9_EXCLUDE_RANGES=metadata.exclude_ranges_str(),
               BRCACHED_E9_RELOCATED_CALL_JUMPS=metadata.relocated_calls_str(),
               BINRADAR_PATCH_KIND="generic-erm")
    subprocess.run(paths.find_models_command(str(original), str(work / "models.plt")),
                   check=True, capture_output=True, timeout=15)
    return work, env, binding


def _capture(tmp_path, runtime_artifact, engine, mode="l", descriptor="p0"):
    work, settings, binding = runtime_artifact
    artifact = work / "fixture.brcached"
    environment = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C",
                   "HOME": str(tmp_path), "TMPDIR": str(tmp_path),
                   "PATCH_ID": "1", "TAOSC_PRED": descriptor, "PATCH_FD": "2",
                   "BRCACHE_STACK_SIZE": "128", "BINRADAR_FORKSERVER_ENABLE": "0",
                   "BINRADAR_REPLAY_SERVER": "0", "BINRADAR_OSPREY_ENABLE": "0",
                   "BINRADAR_TRACE_FILE": "none", "BINRADAR_MEMCHECK_ENABLE": "1",
                   "BINRADAR_MEMCHECK_POLICY": "coverage-v7",
                   "PLT_INFO_FILE": str(work / "models.plt")}
    environment.update(artifact_observation_environment(artifact))
    if engine == "native":
        command = [str(artifact), mode]
    elif engine == "tracer":
        runner = BinRadarQemuRunner.from_env(str(work), settings)
        environment.update(E9_EXCLUDE_RANGES=settings["BRCACHED_E9_EXCLUDE_RANGES"],
                           E9_RELOCATED_CALL_JUMPS=settings["BRCACHED_E9_RELOCATED_CALL_JUMPS"],
                           E9_RELOCATED_INSTRUCTIONS=runner.tracer_instruction_pairs(str(artifact)),
                           E9_ORIGINAL_ENTRYPOINT=runner.tracer_original_entrypoint(str(artifact)))
        command = [paths.TRACER_BIN, "-d", "page", str(artifact), mode]
    else:
        qemu = Path(paths.QASAN_QEMU_BIN).resolve(strict=True)
        library = qemu.with_name("libqasan.so")
        assert library.is_file(), "QASAN library is required; no unsanitized fallback"
        command = [sys.executable, "-I", "-S", paths.OBSERVATION_SANDBOX_SCRIPT,
                   "--scratch", str(tmp_path), "--qemu-self-maps", "--timeout", "5"]
        for root in ("/usr", "/bin", "/lib", "/lib64", "/gnu/store", "/etc/ld.so.cache",
                     str(work), str(qemu), str(library)):
            command += ["--read", root]
        command += ["--", str(qemu), "--asan", "host", str(artifact), "--", mode]
    with (tmp_path / "capture.brch").open("wb") as capture:
        environment["PATCH_CACHED_FD"] = str(capture.fileno())
        result = subprocess.run(command, cwd=tmp_path, env=environment,
                                pass_fds=(capture.fileno(),), capture_output=True,
                                start_new_session=True, timeout=8, check=False)
    assert result.returncode in (0, 128), (
        f"{engine}: exit {result.returncode}\n"
        + result.stdout.decode("utf-8", errors="replace")
        + result.stderr.decode("utf-8", errors="replace"))
    snapshots, error = predicates.parse_cached_snapshots(
        (tmp_path / "capture.brch").read_bytes(), expected_observation_count=binding["count"],
        expected_observation_plan_crc32=binding["plan_crc32"])
    assert error is None and len(snapshots) == 1, (error, result.stdout, result.stderr)
    return snapshots[0]


@pytest.mark.parametrize("engine", ["native", "tracer", "qasan-sandbox"])
@pytest.mark.parametrize("mode,expected", [
    ("l", ((0, 0, 0), (7, 42, 16))),
    ("n", ((0, 1, 1), (7, 0, 0))),
    ("u", ((0, 2, 2), (7, 0, 0))),
    ("f", ((0, 3, 0), (7, 0, 16))),
    ("o", ((0, 4, 0), (7, 0, 16))),
    ("p", ((2, 0, 0), (0, 42, 16))),
])
def test_real_capture_is_equal_across_engines(tmp_path, runtime_artifact, engine, mode, expected):
    captured = _capture(tmp_path, runtime_artifact, engine, mode)
    assert captured.observation_status == expected[0]
    assert captured.observation_values == expected[1]
    assert captured.branch == 0


@pytest.mark.parametrize("engine", ["native", "tracer", "qasan-sandbox"])
@pytest.mark.parametrize("descriptor,expected", [("o1", 2), ("AV1>o1p0", 0)])
def test_real_unavailable_observation_requires_guard(tmp_path, runtime_artifact, engine, descriptor, expected):
    captured = _capture(tmp_path, runtime_artifact, engine, "f", descriptor)
    assert captured.branch == expected
    assert predicates.evaluate_cached_branch(descriptor, captured) == expected


@pytest.mark.parametrize("mode", ["l", "f", "n", "u", "o", "p"])
def test_static_standalone_matches_cached_guard(tmp_path, runtime_artifact, mode):
    work, _, _ = runtime_artifact
    captured = _capture(tmp_path, runtime_artifact, "native", mode, "AV1>o1p0")
    result = subprocess.run([str(work / "fixture.brpatched"), mode], cwd=tmp_path,
                            env={"PATCH_ID": "1", "PATCH_FD": "2"},
                            capture_output=True, start_new_session=True, timeout=5)
    assert result.returncode == (128 if captured.branch == 1 else 0), result.stderr
    assert captured.branch == (1 if mode in ("l", "p") else 0)


def test_runtime_identity_rejects_plan_artifact_and_original_changes(tmp_path, runtime_artifact):
    source, _, _ = runtime_artifact
    work = tmp_path / "copy"
    shutil.copytree(source, work)
    artifact = work / "fixture.brcached"
    environment = artifact_observation_environment(artifact)
    assert environment["BINRADAR_BROBS_COUNT"] == "3"
    original = work / "fixture.orig"
    original.write_bytes(original.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="identity mismatch"):
        artifact_observation_environment(artifact)
    shutil.copyfile(source / "fixture.orig", original)
    plan_path = work / "observation-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["slots"][1]["offsets"] = [0, 12]
    plan_path.write_text(json.dumps(plan))
    with pytest.raises(ValueError, match="identity mismatch"):
        artifact_observation_environment(artifact)
    shutil.copyfile(source / "observation-plan.json", plan_path)
    artifact.write_bytes(artifact.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="identity mismatch"):
        artifact_observation_environment(artifact)


def test_plain_original_runs_with_cleared_observation_authority(tmp_path, runtime_artifact):
    work, _, _ = runtime_artifact
    environment = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C",
                   "BINRADAR_MEMCHECK_ENABLE": "1", "BINRADAR_TRACE_FILE": "none",
                   "BINRADAR_FORKSERVER_ENABLE": "0", "BINRADAR_REPLAY_SERVER": "0",
                   "BINRADAR_OSPREY_ENABLE": "0", "PLT_INFO_FILE": str(work / "models.plt"),
                   **cleared_observation_environment()}
    result = subprocess.run([paths.TRACER_BIN, "-d", "page", str(work / "fixture.orig"), "l"],
                            cwd=tmp_path, env=environment, capture_output=True,
                            start_new_session=True, timeout=5)
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_legacy_artifact_without_bound_sidecar_is_rejected(tmp_path):
    artifact = tmp_path / "old.brcached"
    artifact.write_bytes(b"old cache")
    (tmp_path / "old.orig").write_bytes(b"old original")
    with pytest.raises(ValueError, match="metadata"):
        artifact_observation_environment(artifact)


def test_plan_codegen_rejects_foreign_original_and_out_of_bounds_root(tmp_path, runtime_artifact):
    source, settings, _ = runtime_artifact
    work = tmp_path / "copy"
    shutil.copytree(source, work)
    plan_path = work / "observation-plan.json"
    plan = json.loads(plan_path.read_text())
    plan["artifact_orig_sha256"] = "0" * 64
    plan_path.write_text(json.dumps(plan))
    with pytest.raises(ValueError, match="binding mismatch"):
        prepare_observation_plan(work, work / "fixture.orig", int(settings["PATCH_LOC"], 0))
    plan["artifact_orig_sha256"] = hashlib.sha256((work / "fixture.orig").read_bytes()).hexdigest()
    plan["slots"][0]["rva"] = "0x1"
    plan_path.write_text(json.dumps(plan))
    with pytest.raises(ValueError, match="outside writable"):
        prepare_observation_plan(work, work / "fixture.orig", int(settings["PATCH_LOC"], 0))
