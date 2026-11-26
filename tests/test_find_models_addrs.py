"""Model metadata must survive an empty PATH and preserve dispatch offsets."""

import os
from pathlib import Path
import shutil
import subprocess

from elftools.elf.elffile import ELFFile
import pytest

from binradar import paths


@pytest.fixture
def native_tools(monkeypatch):
    for name in ("objdump", "nm", "ldd"):
        executable = shutil.which(name)
        assert executable is not None, f"test requires {name}"
        monkeypatch.setattr(paths, name.upper() + "_BIN", executable)


@pytest.fixture(scope="module")
def images(tmp_path_factory):
    root = tmp_path_factory.mktemp("model-images")
    source = root / "guest.c"
    source.write_text("""
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    void *p = malloc(32);
    free(p);
    return strlen(argv[0]) == argc;
}
""")
    guest = root / "-guest space;$(touch injected)"
    subprocess.run(["cc", "-fno-builtin", "-no-pie", str(source), "-o", str(guest)],
                   check=True, capture_output=True, timeout=10)
    with guest.open("rb") as stream:
        elf = ELFFile(stream)
        base = elf.get_section_by_name(".init")["sh_addr"]
        plt = elf.get_section_by_name(".plt.sec")
        resolver_entries = 0
        if plt is None:
            plt = elf.get_section_by_name(".plt")
            resolver_entries = 1
        dynsym = elf.get_section_by_name(".dynsym")
        expected = {
            dynsym.get_symbol(relocation["r_info_sym"]).name:
                plt["sh_addr"] + (index + resolver_entries) * plt["sh_entsize"] - base
            for index, relocation in enumerate(
                elf.get_section_by_name(".rela.plt").iter_relocations())
        }

    source = root / "libc.c"
    source.write_text("""
void *malloc(unsigned long n) { return (void *)n; }
__attribute__((weak)) void free(void *p) {}
static unsigned long implementation(const char *s) { return 0; }
static void *resolver(void) { return implementation; }
unsigned long strlen(const char *) __attribute__((ifunc("resolver")));
int strcmp;
""")
    versions = root / "versions"
    versions.write_text("TEST_1 { global: malloc; free; strlen; strcmp; local: *; };\n")
    library = root / "libc.so.models"
    subprocess.run(["cc", "-fno-builtin", "-shared", "-nostdlib", "-fPIC",
                    str(source), f"-Wl,--version-script={versions}", "-o", str(library)],
                   check=True, capture_output=True, timeout=10)
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        base = elf.get_section_by_name(".text")["sh_addr"]
        definitions = {
            symbol.name: symbol["st_value"] - base
            for symbol in elf.get_section_by_name(".dynsym").iter_symbols()
            if symbol.name in ("malloc", "free")
        }
    return guest, expected, library, definitions


def _rows(text):
    return {(image, name): int(address, 16)
            for image, name, address in (line.split(",") for line in text.splitlines())}


@pytest.mark.parametrize("isolated", [False, True])
def test_cli_without_path_preserves_plt_and_libc_models(
        tmp_path, native_tools, images, isolated):
    guest, expected, _, _ = images
    target = tmp_path / guest.name
    shutil.copyfile(guest, target)
    table = tmp_path / "models.txt"
    result = subprocess.run(paths.find_models_command(target.name, str(table), isolated=isolated),
                            cwd=tmp_path, env={**os.environ, "PATH": ""},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    rows = _rows(table.read_text())
    assert {name: rows[(target.name, name)] for name in expected} == expected
    assert any(image.startswith("libc.so") and name == "malloc" for image, name in rows)
    assert not (tmp_path / "injected").exists()


def test_versioned_weak_symbols_but_not_ifunc_resolvers(tmp_path, native_tools, images):
    _, _, library, expected = images
    table = tmp_path / "models.txt"
    command = paths.find_models_command(str(library), str(table))
    result = subprocess.run(command, env={**os.environ, "PATH": ""},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert _rows(table.read_text()) == {(library.name, name): address
                                      for name, address in expected.items()}
    # The standalone stdout interface uses the same record format.
    index = command.index("-o")
    del command[index:index + 2]
    result = subprocess.run(command, env={**os.environ, "PATH": ""},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == table.read_text()


@pytest.mark.parametrize("tool", ["OBJDUMP_BIN", "NM_BIN", "LDD_BIN"])
def test_tool_failure_preserves_published_table(tmp_path, native_tools, images, monkeypatch, tool):
    library = images[2]
    table = tmp_path / "models.txt"
    table.write_text("previous complete table\n")
    monkeypatch.setattr(paths, tool, str(tmp_path / "missing-tool"))
    result = subprocess.run(paths.find_models_command(str(library), str(table)),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert "missing-tool" in result.stderr
    assert table.read_text() == "previous complete table\n"
    assert not list(tmp_path.glob("*.part"))


def test_no_modeled_plt_is_successful_empty_table(tmp_path, native_tools):
    source = tmp_path / "static.S"
    source.write_text('.global _start\n.text\n_start: ret\n.section .note.GNU-stack,"",@progbits\n')
    guest = tmp_path / "static"
    subprocess.run(["cc", "-nostdlib", "-static", "-no-pie", str(source), "-o", str(guest)],
                   check=True, capture_output=True, timeout=10)
    table = tmp_path / "models.txt"
    result = subprocess.run(paths.find_models_command(str(guest), str(table)),
                            env={**os.environ, "PATH": ""}, capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert table.read_text() == ""


def test_metadata_generation_inside_observation_sandbox(tmp_path, native_tools, images):
    from binradar.plan_observations import _sandbox

    guest, expected, _, _ = images
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    shutil.copyfile(guest, scratch / "subject.orig")
    command = paths.find_models_command("subject.orig", "models.txt", isolated=True)
    status = _sandbox(command, scratch,
                      {"PATH": "", "HOME": str(scratch), "TMPDIR": str(scratch)},
                      10, tmp_path / "models", (Path(paths.FIND_MODELS_SCRIPT),))
    assert status == 0, (tmp_path / "models.stderr").read_text()
    rows = _rows((scratch / "models.txt").read_text())
    assert {name: rows[("subject.orig", name)] for name in expected} == expected
