"""Exercise PROBE admission through real subprocesses, not forwarded results.

Protocol emitters isolate malformed/cancelled output; optional static guests also
exercise the built tracer. Only the unrelated QASAN/filetrace boundary is stubbed.
"""

import hashlib
import json
import platform
import resource
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from binradar import binradar_verifier as verifier
from binradar import cli
from binradar.binradar_probe_diagnostics import ProbeTraceDiagnostics

POLICY = f"[memcheck] [policy {verifier.MEMCHECK_POLICY}]\n"
NORMAL = "[snapshot] [exit] [normal] [entrypoint-hit 1]\n"
CRASH = ("[snapshot] [crash] [hit-count 1] [reason unhandled_target_signal] "
         "[guest_pc 401234] [guest_cs_base 0] [fault_addr 0] "
         "[host_fault_addr 0]\n")
REFERENCE = ("[snapshot] [fault-reference] [version 3] [valid true] "
             "[source guest-signal] [address 401234] [image none] "
             "[image-offset 0]\n")
UNAVAILABLE = ("[snapshot] [fault-reference] [version 3] [valid false] "
               "[source unavailable] [address 0] [image none] "
               "[image-offset 0]\n")
PENDING = ("[prov] [pending-finding] [version 1] [origin syscall-request] "
           "[quality tagged] [site_kind main] [site_image none] [site_offset 0] "
           "[access_pc 401111] [actual_pc 401111] [access_addr 10000] "
           "[width 12] [obj_id 1] [gen 1] [obj_base 10000] [size 8] [offset 0] "
           "[producer_pc 401100] [kind 1] [last_writer 0] [is_uaf 0] "
           "[ea_reg -1] [ea_base_reg_val 10000] [query_cursor -1] [expr_cursor -1]\n")


@pytest.fixture
def probe(tmp_path, monkeypatch):
    work = tmp_path / "work"
    run = tmp_path / "run"
    work.mkdir()
    run.mkdir()
    (work / "guest.orig").write_bytes(b"controlled executable input")
    (work / "poc").write_bytes(b"controlled poc")
    (work / "plt.txt").write_bytes(b"controlled PLT metadata")
    instance = object.__new__(cli.BinRadarExecutor)
    instance.workdir = str(work)
    instance.binary = "guest"
    instance.poc_input = "poc"
    instance.test_cmd = "@@"
    instance.run_dir = str(run)
    instance.run_prefix = "diagnostics"
    instance.run_id = 0
    instance.config = {"PLT_INFO_FILE": str(work / "plt.txt")}
    instance._worker_environment = dict
    instance.forkserver_child_timeout = 5.0
    instance.artifacts = SimpleNamespace(original=str(work / "guest.orig"))
    instance.save_progress = lambda _row: None
    instance.probe_result = None
    result = verifier.BinRadarProbeResult(
        patch_loc=0x401000, patch_func_entry=0x401000, stacktrace=[],
        exit_info="crash", patch_hit_cnt=1, patch_func_hit_cnt=1,
        fault_addr=0x402000, patch_func_candidates=[])
    calls = []

    def original(_input):
        calls.append("qasan")
        return result

    def filetrace(_input, **_kwargs):
        calls.append("filetrace")
        return result

    runner = SimpleNamespace(test_with_original=original,
                             test_with_file_trace=filetrace)
    monkeypatch.setattr(verifier.BinRadarQemuRunner, "from_env",
                        lambda *_args: runner)
    monkeypatch.setattr(cli, "PROBE_TRACER_TIMEOUT_MIN", 0.0)
    return SimpleNamespace(instance=instance, work=work, run=run,
                           result=result, calls=calls)


def _launcher(probe, monkeypatch, body):
    launcher = probe.work / "reference-launcher"
    launcher.write_text(
        f"#!{sys.executable}\n"
        "import os, resource, signal, sys, time\n"
        "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n" + body,
        encoding="utf-8")
    launcher.chmod(0o755)
    monkeypatch.setattr(cli.paths, "TRACER_BIN", str(launcher))
    return launcher


def _emit(probe, monkeypatch, stderr, tail=""):
    return _launcher(
        probe, monkeypatch,
        f"sys.stdout.write('reference stdout\\n'); sys.stdout.flush()\n"
        f"sys.stderr.write({stderr!r}); sys.stderr.flush()\n" + tail)


def _record(probe):
    return json.loads((probe.run / "probe-tracer-result.json").read_text())


def _assert_archive(probe, record, reason, *, stderr=None):
    assert record["version"] == 1
    assert record["reference_admission_reason"] == reason
    assert record["cwd"] == str(probe.work)
    assert record["command"][1:] == [str(probe.work / "guest.orig"),
                                       str(probe.work / "poc")]
    assert record["elapsed_seconds"] >= 0
    assert record["timeout_seconds"] == probe.instance.forkserver_child_timeout
    assert record["memcheck_policy_requested"] == verifier.MEMCHECK_POLICY
    assert record["entrypoint"] == hex(probe.result.patch_func_entry)
    assert (probe.run / "probe-tracer.stdout.log").is_file()
    actual_stderr = (probe.run / "probe-tracer.stderr.log").read_text()
    if stderr is not None:
        assert actual_stderr == stderr
    assert not list(probe.run.glob(".probe-tracer-*"))


@pytest.mark.parametrize("stderr,tail,reason,terminal,address", [
    (POLICY + NORMAL, "", "normal-without-reference", "normal", None),
    (POLICY + PENDING + NORMAL, "", "normal-without-reference", "normal", None),
    (POLICY + PENDING + CRASH + REFERENCE,
     "os.kill(os.getpid(), signal.SIGSEGV)\n",
     "validated-reference", "signal", 0x401234),
    (POLICY + CRASH + REFERENCE,
     "os.kill(os.getpid(), signal.SIGSEGV)\n",
     "validated-reference", "signal", 0x401234),
    (POLICY + CRASH + UNAVAILABLE,
     "os.kill(os.getpid(), signal.SIGSEGV)\n",
     "signal-with-unavailable-identity", "signal", None),
    (POLICY + PENDING + CRASH + REFERENCE,
     "os.kill(os.getpid(), signal.SIGTERM)\n",
     "external-cancellation", "signal", None),
    (POLICY + PENDING, "", "missing-or-unusable-terminal", "unknown", None),
    (POLICY + NORMAL.rstrip("\n"), "",
     "missing-or-unusable-terminal", "unknown", None),
])
def test_reference_subprocess_admission(
        probe, monkeypatch, stderr, tail, reason, terminal, address):
    _emit(probe, monkeypatch, stderr, tail)
    probe.instance.run_probe()
    record = _record(probe)
    _assert_archive(probe, record, reason, stderr=stderr)
    assert (probe.run / "probe-tracer.stdout.log").read_text() == "reference stdout\n"
    if tail:
        assert record["exit_code"] == (-signal.SIGTERM if reason == "external-cancellation"
                                       else -signal.SIGSEGV)
    assert record["success"] is True  # communicate completed, not guest success
    assert record["timed_out"] is False
    assert record["cancelled"] is (reason == "external-cancellation")
    assert record["terminal_kind"] == terminal
    assert record["memcheck_policy_acknowledged"] is True
    assert record["error"] is None
    if address is None:
        assert record["reference"] is None
        assert probe.result.tracer_fault_reference is None
    else:
        assert probe.result.tracer_fault_reference == verifier.TracerFaultReference(
            address, "guest-signal")
        assert record["reference"]["address"] == address
        assert record["reference"]["source"] == "guest-signal"
    assert probe.calls == ["qasan", "filetrace"]


@pytest.mark.parametrize("pending", [False, True], ids=["clean-loop", "pending-loop"])
def test_managed_timeout_retains_drained_kill_pc_but_rejects_reference(probe, monkeypatch, pending):
    # Install the handler before publishing readiness/output; the deadline is
    # deliberately generous for interpreter startup but far shorter than sleep.
    probe.instance.forkserver_child_timeout = 1.0
    salvage = CRASH + REFERENCE + "drained after SIGTERM\n"
    prefix = POLICY + (PENDING if pending else "")
    body = (
        "def terminate(signum, frame):\n"
        f"    sys.stderr.write({salvage!r}); sys.stderr.flush()\n"
        "    signal.signal(signum, signal.SIG_DFL)\n"
        "    os.kill(os.getpid(), signum)\n"
        "signal.signal(signal.SIGTERM, terminate)\n"
        f"sys.stderr.write({prefix!r}); sys.stderr.flush()\n"
        "sys.stdout.write('before timeout\\n'); sys.stdout.flush()\n"
        "time.sleep(60)\n")
    _launcher(probe, monkeypatch, body)
    probe.instance.run_probe()
    record = _record(probe)
    _assert_archive(probe, record, "managed-timeout", stderr=prefix + salvage)
    assert record["timed_out"] is True
    assert record["success"] is False
    assert record["reference"] is None
    assert probe.result.tracer_fault_reference is None
    assert record["exit_code"] == -signal.SIGTERM
    assert record["elapsed_seconds"] < 10


@pytest.mark.parametrize("stderr,reason,exception", [
    ("[memcheck] [policy wrong]\n" + CRASH + REFERENCE,
     "policy-error", SystemExit),
    ("[memcheck] [policy]\n" + NORMAL, "policy-error", (Exception, SystemExit)),
    (POLICY + CRASH + REFERENCE.replace("version 3", "version 999"),
     "reference-error", ValueError),
    (POLICY + CRASH + REFERENCE.replace("address 401234", "address not-hex"),
     "reference-error", Exception),
])
def test_protocol_errors_preserve_logs_before_raising(probe, monkeypatch, stderr, reason, exception):
    _emit(probe, monkeypatch, stderr)
    with pytest.raises(exception):
        probe.instance.run_probe()
    record = _record(probe)
    _assert_archive(probe, record, reason, stderr=stderr)
    assert record["error"]
    assert (probe.run / "probe-tracer.stdout.log").read_text() == "reference stdout\n"
    if reason == "policy-error":
        assert record["memcheck_policy_acknowledged"] in (False, None)
    else:
        assert record["memcheck_policy_acknowledged"] is True
    assert record["reference"] is None
    assert probe.result.tracer_fault_reference is None
    assert probe.calls == ["qasan"]
    assert not (probe.run / "probe-results.sbsv").exists()


def test_provenance_hashes_and_effective_settings_are_not_inherited_environment(probe, monkeypatch):
    launcher = _emit(probe, monkeypatch, POLICY + NORMAL)
    monkeypatch.setenv("PROBE_DIAGNOSTIC_TEST_SECRET", "do-not-persist")
    monkeypatch.setenv("BINRADAR_OSPREY_ENABLE", "1")
    monkeypatch.setenv("BINRADAR_SYMBOLIC_MUTATION_MODE", "boundary")
    monkeypatch.setenv("BINRADAR_MEMCHECK_POLICY", "wrong")
    monkeypatch.setenv("QEMU_RAND_SEED", "1234")
    probe.instance.run_probe()
    record = _record(probe)
    for name, path in {
        "executable": probe.work / "guest.orig", "poc": probe.work / "poc",
        "tracer": launcher, "plt_metadata": probe.work / "plt.txt",
    }.items():
        assert record["files"][name]["path"] == str(path)
        assert record["files"][name]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    settings = record["settings"]
    assert settings["BINRADAR_OSPREY_ENABLE"] == "0"
    assert settings["BINRADAR_SYMBOLIC_MUTATION_MODE"] == "off"
    assert settings["BINRADAR_MEMCHECK_POLICY"] == verifier.MEMCHECK_POLICY
    assert settings["BINRADAR_FORKSERVER_ENABLE"] == "0"
    assert settings["BINRADAR_TRACE_FILE"] == "none"
    assert settings["QEMU_RAND_SEED"] == "1234"
    assert "PROBE_DIAGNOSTIC_TEST_SECRET" not in settings
    assert "do-not-persist" not in json.dumps(record)


@pytest.mark.parametrize("plt", [None, "missing-plt.txt"])
def test_unavailable_metadata_is_explicit_not_a_fake_hash(probe, monkeypatch, plt):
    _emit(probe, monkeypatch, POLICY + NORMAL)
    if plt is None:
        probe.instance.config.clear()
    else:
        probe.instance.config["PLT_INFO_FILE"] = plt
    probe.instance.run_probe()
    metadata = _record(probe)["files"]["plt_metadata"]
    assert metadata["sha256"] is None
    assert metadata["unavailable"]
    assert metadata["path"] == (None if plt is None else str(probe.work / plt))


def test_restored_probe_is_read_only_and_diagnostics_are_not_backfilled(probe, monkeypatch):
    _emit(probe, monkeypatch, POLICY + NORMAL)
    probe.instance.run_probe()
    saved = (probe.run / "probe-results.sbsv").read_bytes()
    for name in ("probe-tracer.stdout.log", "probe-tracer.stderr.log", "probe-tracer-result.json"):
        (probe.run / name).unlink()
    probe.calls.clear()
    probe.instance.run_probe()
    assert probe.calls == []
    assert (probe.run / "probe-results.sbsv").read_bytes() == saved
    assert not list(probe.run.glob("probe-tracer*"))


def test_successful_retry_replaces_logs_and_result_as_one_unit(probe, monkeypatch):
    # A later PROBE stage failure leaves diagnostics but no authoritative
    # probe-results.sbsv, so run_probe() retries the reference execution.
    monkeypatch.setenv("QEMU_RAND_SEED", "1234")
    _emit(probe, monkeypatch, POLICY + NORMAL)
    probe.instance.run_probe()
    first = _record(probe)
    (probe.run / "probe-results.sbsv").unlink()
    (probe.run / "probe-tracer.stdout.log").unlink()

    monkeypatch.setenv("QEMU_RAND_SEED", "5678")
    _emit(probe, monkeypatch, POLICY + CRASH + REFERENCE,
          "os.kill(os.getpid(), signal.SIGSEGV)\n")
    probe.instance.run_probe()
    record = _record(probe)
    assert first["settings"]["QEMU_RAND_SEED"] == "1234"
    assert record["settings"]["QEMU_RAND_SEED"] == "5678"
    assert record["exit_code"] == -signal.SIGSEGV
    assert record["reference_admission_reason"] == "validated-reference"
    assert (probe.run / "probe-tracer.stdout.log").read_text() == "reference stdout\n"
    assert verifier.read_snapshot_fault_reference(
        (probe.run / "probe-tracer.stderr.log").read_text(),
        require_current=True).address == 0x401234
    assert not list(probe.run.glob(".probe-tracer-*"))


def test_failed_result_publication_leaves_previous_unit_intact(probe, monkeypatch):
    _emit(probe, monkeypatch, POLICY + NORMAL)
    probe.instance.run_probe()
    old = _record(probe)
    old_logs = {name: (probe.run / name).read_bytes()
                for name in ("probe-tracer.stdout.log", "probe-tracer.stderr.log")}

    # Real process-local EMFILE inside atomic publication, matching the observed
    # retry failure: no production seam is patched.
    diag = ProbeTraceDiagnostics(
        str(probe.run), command=old["command"],
        cwd=str(probe.work),
        environment={key: value for key, value in old["settings"].items()
                     if value is not None} | {
                         "BINRADAR_MEMCHECK_POLICY": verifier.MEMCHECK_POLICY},
        testcase=str(probe.work / "poc"), timeout=5.0)
    diag.retain_output(SimpleNamespace(stdout="new stdout\n", stderr=CRASH,
                                       exit_code=-signal.SIGSEGV, success=True,
                                       timed_out=False))
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (0, limits[1]))
        with pytest.raises(OSError):
            diag.publish(reason="validated-reference")
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, limits)
    assert _record(probe) == old
    assert {name: (probe.run / name).read_bytes() for name in old_logs} == old_logs
    assert not list(probe.run.glob(".probe-tracer-*"))


def test_failed_retry_never_leaves_stale_result_beside_new_logs(probe, monkeypatch):
    _emit(probe, monkeypatch, POLICY + NORMAL)
    probe.instance.run_probe()
    (probe.run / "probe-results.sbsv").unlink()
    # stdout is installed first. Fail the stderr rename only after the retry's
    # distinguishable stdout has replaced the previous execution's output.
    (probe.run / "probe-tracer.stderr.log").unlink()
    (probe.run / "probe-tracer.stderr.log").mkdir()

    _emit(probe, monkeypatch, POLICY + CRASH + REFERENCE,
          "sys.stdout.write('retry stdout\\n'); sys.stdout.flush()\n"
          "os.kill(os.getpid(), signal.SIGSEGV)\n")
    with pytest.raises(IsADirectoryError):
        probe.instance.run_probe()
    assert (probe.run / "probe-tracer.stdout.log").read_text() == (
        "reference stdout\nretry stdout\n")
    assert not (probe.run / "probe-tracer-result.json").exists()
    assert not (probe.run / "probe-results.sbsv").exists()
    assert not list(probe.run.glob(".probe-tracer-*"))

    (probe.run / "probe-tracer.stderr.log").rmdir()
    _emit(probe, monkeypatch, POLICY + NORMAL)
    probe.instance.run_probe()
    record = _record(probe)
    assert record["reference_admission_reason"] == "normal-without-reference"
    assert record["exit_code"] == 0
    assert (probe.run / "probe-tracer.stdout.log").read_text() == "reference stdout\n"


@pytest.mark.parametrize("failure", ["raw-log", "atomic-result"])
def test_persistence_failure_is_surfaced_not_successful_probe(probe, monkeypatch, failure):
    _emit(probe, monkeypatch, POLICY + NORMAL)
    if failure == "raw-log":
        (probe.run / "probe-tracer.stderr.log").mkdir()
    else:
        # A directory at the final filename makes the real atomic replace fail.
        (probe.run / "probe-tracer-result.json").mkdir()
    with pytest.raises(OSError):
        probe.instance.run_probe()
    assert probe.calls == ["qasan"]
    assert not (probe.run / "probe-results.sbsv").exists()
    assert not list(probe.run.glob(".probe-tracer-*"))


@pytest.mark.parametrize("crash", [False, True], ids=["normal", "genuine-sigsegv"])
def test_real_tracer_static_guest_admission(probe, monkeypatch, crash):
    tracer = Path(cli.paths.TRACER_BIN)
    if platform.machine() != "x86_64" or not tracer.is_file():
        pytest.skip("requires built x86_64 BinRadar tracer")
    compiler = shutil.which("cc")
    nm = shutil.which("nm")
    if compiler is None or nm is None:
        pytest.skip("requires cc and nm for a static assembly guest")
    source = probe.work / "guest.S"
    source.write_text(
        ".global _start\n.text\n_start:\n" +
        ("mov $0, %rax\nmov (%rax), %rax\n" if crash else "") +
        "mov $60, %rax\nxor %rdi, %rdi\nsyscall\n")
    subprocess.run([compiler, "-nostdlib", "-static", "-no-pie", str(source),
                    "-o", str(probe.work / "guest.orig")],
                   check=True, capture_output=True, timeout=30)
    symbols = subprocess.run([nm, str(probe.work / "guest.orig")],
                             check=True, capture_output=True, text=True, timeout=10)
    entry = next(int(row.split()[0], 16) for row in symbols.stdout.splitlines()
                 if row.split()[-1] == "_start")
    probe.result.patch_func_entry = entry
    probe.instance.forkserver_child_timeout = 15.0
    # Disable cores in the child only, then exec the actual tracer unchanged.
    _launcher(probe, monkeypatch,
              f"os.execv({str(tracer.resolve())!r}, [{str(tracer.resolve())!r}] + sys.argv[1:])\n")
    probe.instance.run_probe()
    record = _record(probe)
    _assert_archive(probe, record,
                    "validated-reference" if crash else "normal-without-reference")
    assert record["timed_out"] is False
    assert record["cancelled"] is False
    assert record["memcheck_policy_acknowledged"] is True
    assert record["terminal_kind"] == ("signal" if crash else "normal")
    if crash:
        assert record["exit_code"] == -signal.SIGSEGV
        assert probe.result.tracer_fault_reference is not None
        assert probe.result.tracer_fault_reference.source == "guest-signal"
    else:
        assert probe.result.tracer_fault_reference is None
