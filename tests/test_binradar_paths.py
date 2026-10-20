"""E9 deployment overrides and Guix discovery must not silently switch tools."""

import subprocess
import sys

import pytest

from binradar import paths


@pytest.fixture(autouse=True)
def isolated_lookup(monkeypatch):
    monkeypatch.delenv("E9TOOL", raising=False)
    monkeypatch.delenv("E9COMPILE", raising=False)
    paths._guix_e9_bin_dir.cache_clear()
    yield
    paths._guix_e9_bin_dir.cache_clear()


def no_guix(*args, **kwargs):
    pytest.fail("an explicit E9 override must not invoke Guix")


@pytest.mark.parametrize("name", ["e9tool", "e9compile"])
def test_explicit_relative_executable_survives_child_cwd(name, tmp_path, monkeypatch):
    executable = tmp_path / "selected tool"
    executable.symlink_to(sys.executable)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(name.upper(), "./selected tool")
    monkeypatch.setattr(paths.subprocess, "check_output", no_guix)
    assert getattr(paths, name)() == str(executable)


def test_explicit_command_name_resolves_on_path(tmp_path, monkeypatch):
    executable = tmp_path / "selected-e9tool"
    executable.symlink_to(sys.executable)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("E9TOOL", executable.name)
    monkeypatch.setattr(paths.subprocess, "check_output", no_guix)
    assert paths.e9tool() == str(executable)


def test_invalid_override_does_not_fall_back(tmp_path, monkeypatch):
    not_executable = tmp_path / "e9tool"
    not_executable.write_text("not an executable")
    monkeypatch.setenv("E9TOOL", str(not_executable))
    monkeypatch.setattr(paths.subprocess, "check_output", no_guix)
    with pytest.raises(FileNotFoundError):
        paths.e9tool()


def test_guix_lookup_does_not_freeze_environment_overrides(tmp_path, monkeypatch):
    store = tmp_path / "e9patch"
    binaries = store / "bin"
    binaries.mkdir(parents=True)
    for name in ("e9tool", "e9compile"):
        (binaries / name).symlink_to(sys.executable)
    monkeypatch.setattr(paths.subprocess, "check_output", lambda *a, **kw: f"{store}\n")
    monkeypatch.setenv("E9TOOL", "")
    assert paths.e9tool() == str(binaries / "e9tool")

    # Resolution of the other tool must still work from the cached store path,
    # but a later explicit override must take precedence over that cache.
    monkeypatch.setattr(paths.subprocess, "check_output", no_guix)
    monkeypatch.setenv("E9TOOL", sys.executable)
    assert paths.e9tool() == sys.executable
    assert paths.e9compile() == str(binaries / "e9compile")
    monkeypatch.delenv("E9TOOL")
    assert paths.e9tool() == str(binaries / "e9tool")


@pytest.mark.parametrize("output", ["", "relative-store\n", "/store/one\n/store/two\n"])
def test_invalid_guix_output_cannot_become_a_local_command(output, monkeypatch):
    monkeypatch.setattr(paths.subprocess, "check_output", lambda *a, **kw: output)
    with pytest.raises(RuntimeError):
        paths.e9tool()


def test_failed_guix_lookup_can_be_retried(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(23, ["guix", "build"])

    monkeypatch.setattr(paths.subprocess, "check_output", fail)
    with pytest.raises(subprocess.CalledProcessError) as error:
        paths.e9compile()
    assert error.value.returncode == 23

    store = tmp_path / "e9patch"
    (store / "bin").mkdir(parents=True)
    executable = store / "bin/e9compile"
    executable.symlink_to(sys.executable)
    monkeypatch.setattr(paths.subprocess, "check_output", lambda *a, **kw: f"{store}\n")
    assert paths.e9compile() == str(executable)


def test_missing_store_executable_does_not_use_path(tmp_path, monkeypatch):
    ambient = tmp_path / "ambient"
    ambient.mkdir()
    (ambient / "e9tool").symlink_to(sys.executable)
    monkeypatch.setenv("PATH", str(ambient))
    monkeypatch.setattr(paths.subprocess, "check_output", lambda *a, **kw: f"{tmp_path}\n")
    with pytest.raises(FileNotFoundError):
        paths.e9tool()
