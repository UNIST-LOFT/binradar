"""Linux x86-64 child launcher: Landlock filesystem rules and seccomp.

Invoked with isolated Python (-I -S), before exec. No silent unsandboxed fallback.
This is not a VM: system runtime files remain readable and stat metadata is not
hidden by Landlock ABI1. Private files, proc contents, network and process control
are denied; only the supplied scratch tree is writable. Fixture replay can
explicitly allow self-tgkill, coupled to a ban on all process/thread creation.
"""

import argparse
import ctypes
import errno
import os
import platform
import resource
import sys
from pathlib import Path


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class FilterProgram(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]


def _checked(result: int, operation: str) -> int:
    if result < 0:
        raise OSError(ctypes.get_errno(), operation)
    return result


def restrict(scratch: Path, readable: list[Path], timeout: int, *, self_signals: bool) -> None:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("native isolation requires Linux x86-64")
    libc = ctypes.CDLL(None, use_errno=True)
    abi = _checked(libc.syscall(444, None, 0, 1), "Landlock unavailable")
    if abi < 1:
        raise RuntimeError("Landlock ABI1 or newer is required")
    # ABI1 lacks path-based truncate mediation; seccomp denies truncate below.
    handled = (1 << 13) - 1
    if abi >= 2:
        handled |= 1 << 13  # REFER: retain rename support within allowed scratch.
    if abi >= 3:
        handled |= 1 << 14  # TRUNCATE
    ruleset = Ruleset(handled)
    descriptor = _checked(libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0),
                          "create Landlock ruleset")
    try:
        read = (1 << 0) | (1 << 2) | (1 << 3)
        # No device/socket creation, even inside scratch.
        writable = handled & ~((1 << 6) | (1 << 9) | (1 << 11))
        entries = [(scratch, writable), *((path, read) for path in readable)]
        entries += [(Path("/dev/null"), (1 << 1) | (1 << 2)),
                    (Path("/dev/urandom"), 1 << 2)]
        for path, access in entries:
            if not path.exists():
                continue
            if not path.is_dir():
                access &= (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14)
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(access, fd)
                _checked(libc.syscall(445, descriptor, 1, ctypes.byref(rule), 0),
                         "add Landlock rule")
            finally:
                os.close(fd)
        _checked(libc.prctl(38, 1, 0, 0, 0), "set no_new_privs")
        _checked(libc.syscall(446, descriptor, 0), "restrict Landlock")
    finally:
        os.close(descriptor)

    # Restrict cross-process/kernel interfaces not covered by filesystem rules.
    # Architecture check rejects compat/x32 syscalls instead of misinterpreting
    # their syscall numbers. Network includes local sockets and inherited socket
    # operations; the launcher receives only stdin/stdout/stderr descriptors.
    denied = {
        *range(41, 56), 29, 30, 31, 62, 64, 65, 66, 67, 68, 69, 70, 71,
        76, 101, 155, 161, 163, 165, 166, 167, 168, 169, 175, 176, 179, 200,
        *range(240, 247), 272, 298, 299, 300, 303, 304, 308, 310, 311,
        312, 313, 321, 323, 424, 425, 426, 427, 438, 440, 448,
    }
    instructions = [
        Filter(0x20, 0, 0, 4),                   # load seccomp_data.arch
        Filter(0x15, 1, 0, 0xC000003E),          # AUDIT_ARCH_X86_64
        Filter(0x06, 0, 0, 0x80000000),          # kill wrong architecture
        Filter(0x20, 0, 0, 0),                   # load syscall number
        Filter(0x35, 0, 1, 0x40000000),          # reject x32 syscall bit
        Filter(0x06, 0, 0, 0x80000000),
    ]
    if self_signals:
        # Childless fixture replay only: no descendant may retain a rule for
        # this TGID after its owner exits and the numeric PID can be reused.
        denied.update((56, 57, 58, 435))          # clone, fork, vfork, clone3
        # exec preserves this TGID; Linux verifies target TID membership.
        # Denying self-tgkill changes libc abort() from SIGABRT to SIGSEGV.
        instructions.extend((
            Filter(0x15, 0, 4, 234),             # tgkill
            Filter(0x20, 0, 0, 16),              # args[0]: target TGID (pid_t)
            Filter(0x15, 1, 0, os.getpid()),
            Filter(0x06, 0, 0, 0x00050000 | errno.EPERM),
            Filter(0x06, 0, 0, 0x7FFF0000),
        ))
    else:
        denied.add(234)
    for number in sorted(denied):
        instructions.extend((Filter(0x15, 0, 1, number),
                             Filter(0x06, 0, 0, 0x00050000 | errno.EPERM)))
    instructions.append(Filter(0x06, 0, 0, 0x7FFF0000))
    array = (Filter * len(instructions))(*instructions)
    program = FilterProgram(len(instructions), array)
    _checked(libc.prctl(22, 2, ctypes.byref(program), 0, 0), "install seccomp")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    os.umask(0o077)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--read", type=Path, action="append", default=[])
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--qemu-self-maps", action="store_true")
    parser.add_argument("--self-signals", action="store_true", help="allow self-tgkill but forbid process/thread creation")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.timeout < 1:
        parser.error("command and positive timeout required")
    try:
        scratch = args.scratch.resolve(strict=True)
        if not scratch.is_dir():
            raise ValueError("scratch must be a directory")
        readable = [path.resolve() for path in args.read]
        if args.qemu_self_maps:
            # Resolve in the child, not the parent; exec preserves this PID.
            # QEMU requires its own mappings, never environ/mem/other processes.
            readable.extend((Path(f"/proc/{os.getpid()}/maps"),
                             Path("/proc/sys/vm/mmap_min_addr")))
        restrict(scratch, readable, args.timeout, self_signals=args.self_signals)
        os.chdir(scratch)
        os.execve(command[0], command, os.environ)
    except (OSError, ValueError, RuntimeError) as error:
        # Never include command contents or arbitrary file contents in errors.
        print(f"native isolation failed: {type(error).__name__}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
