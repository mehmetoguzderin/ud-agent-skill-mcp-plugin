"""Effective controls for provider VMs whose CLIs lack Docker security flags.

The fixed provider entrypoint calls this before dispatch. A profile label in a
public operation's arguments never grants authority or bypasses these checks.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import platform
import resource
import socket
import struct


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _checked(result: int, reason: str) -> int:
    if result < 0:
        raise RuntimeError(reason + ": " + os.strerror(ctypes.get_errno()))
    return result


def protect_runtime() -> None:
    """Landlock confines all filesystem writes to the noexec scratch mount."""
    libc = _libc()
    _checked(libc.prctl(38, 1, 0, 0, 0), "VM_NO_NEW_PRIVILEGES_UNAVAILABLE")
    # These syscall numbers are shared by the supported amd64/arm64 ABIs.
    abi = _checked(libc.syscall(444, 0, 0, 1), "VM_LANDLOCK_UNAVAILABLE")
    if abi < 3:
        raise RuntimeError("VM_LANDLOCK_TRUNCATE_CONTROL_REQUIRED")
    # EXECUTE/READ_FILE/READ_DIR remain unrestricted. Every mutation, including
    # REFER and TRUNCATE, is handled. No writable runtime/input exception exists.
    writes = sum(1 << bit for bit in (1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14))

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    ruleset = Ruleset(writes)
    descriptor = _checked(libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0), "VM_LANDLOCK_CREATE_FAILED")
    temporary = os.open("/tmp", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        rule = ctypes.create_string_buffer(struct.pack("=Qi", writes, temporary))
        _checked(libc.syscall(445, descriptor, 1, ctypes.byref(rule), 0), "VM_LANDLOCK_RULE_FAILED")
        _checked(libc.syscall(446, descriptor, 0), "VM_LANDLOCK_ENFORCEMENT_FAILED")
    finally:
        os.close(temporary)
        os.close(descriptor)


def install_seccomp() -> None:
    """Deny privilege/namespace/kernel escape APIs, including VM host sockets."""
    machine = platform.machine()
    if machine in ("x86_64", "amd64"):
        audit_arch, socket_number = 0xC000003E, 41
        denied = (101, 155, 165, 166, 169, 172, 173, 174, 175, 176, 246, 248, 249, 250, 272, 298, 303, 304, 308, 310, 311, 312, 313, 321, 323, 425, 426, 427)
    elif machine in ("aarch64", "arm64"):
        audit_arch, socket_number = 0xC00000B7, 198
        denied = (39, 40, 41, 97, 104, 105, 106, 117, 142, 218, 219, 224, 225, 241, 264, 265, 268, 270, 271, 272, 273, 280, 282, 425, 426, 427)
    else:
        raise RuntimeError("VM_SECCOMP_ARCHITECTURE_UNSUPPORTED")

    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

    class Program(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

    # Audit architecture is checked before syscall numbers (also excludes x32).
    code = [(0x20, 0, 0, 4), (0x15, 1, 0, audit_arch), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    if machine in ("x86_64", "amd64"):
        code.extend(((0x45, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)))
    for number in denied:
        code.extend(((0x15, 0, 1, number), (0x06, 0, 0, 0x00050000 | errno.EPERM)))
    # AF_VSOCK can cross the VM boundary. Only AF_UNIX and AF_NETLINK sockets
    # are needed by built-ins/rendering; ordinary IP sockets are disabled too.
    code.extend(((0x15, 0, 4, socket_number), (0x20, 0, 0, 16), (0x15, 2, 0, 1), (0x15, 1, 0, 16), (0x06, 0, 0, 0x00050000 | errno.EPERM), (0x06, 0, 0, 0x7FFF0000)))
    instructions = (Filter * len(code))(*(Filter(*item) for item in code))
    program = Program(len(code), instructions)
    libc = _libc()
    _checked(libc.prctl(38, 1, 0, 0, 0), "VM_NO_NEW_PRIVILEGES_UNAVAILABLE")
    _checked(libc.prctl(22, 2, ctypes.byref(program), 0, 0), "VM_SECCOMP_UNAVAILABLE")


def verify_vm_confinement(provider: str) -> None:
    if provider not in ("apple-container", "wslc") or os.geteuid() != 10001 or os.getegid() != 10001:
        raise RuntimeError("VM_WORKER_IDENTITY_INVALID")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines() if ":" in line)
    if any(status.get(key, "").strip() != "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise RuntimeError("VM_WORKER_CAPABILITIES_UNVERIFIED")
    for _, name in socket.if_nameindex():
        if name != "lo" and int((Path("/sys/class/net") / name / "flags").read_text().strip(), 16) & 1:
            raise RuntimeError("VM_WORKER_NETWORK_UNVERIFIED")
    if Path("/proc/net/route").read_text().splitlines()[1:]:
        raise RuntimeError("VM_WORKER_NETWORK_UNVERIFIED")
    if any(line.split()[-1] != "lo" for line in Path("/proc/net/ipv6_route").read_text().splitlines() if line.split()):
        raise RuntimeError("VM_WORKER_NETWORK_UNVERIFIED")
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split(" - ", 1)[0].split()
        if len(fields) >= 6:
            mounts[fields[4]] = fields[5].split(",")
    if "ro" not in mounts.get("/input", []) or "noexec" not in mounts.get("/tmp", []):
        raise RuntimeError("VM_WORKER_MOUNTS_UNVERIFIED")
    # Enforced per-identity process limits apply to every descendant. Apple uses
    # its dedicated VM CPU/memory boundary; WSL also supplies container cgroups.
    for kind, maximum in ((resource.RLIMIT_NPROC, 128), (resource.RLIMIT_NOFILE, 1024), (resource.RLIMIT_CPU, 300)):
        soft, hard = resource.getrlimit(kind)
        bounded_hard = maximum if hard == resource.RLIM_INFINITY else min(hard, maximum)
        bounded_soft = bounded_hard if soft == resource.RLIM_INFINITY else min(soft, bounded_hard)
        resource.setrlimit(kind, (bounded_soft, bounded_hard))
    # Both providers expose the container's private cgroup root. Check its
    # effective workload bounds separately from the enclosing VM. Apple1.7.1
    # adds128MiB of kernel/vminit memory and one vCPU (containerization0.54.0,
    # VMResources.guestMemoryOverhead); that is not worker memory/CPU authority.
    if Path("/proc/self/cgroup").read_text().strip() != "0::/":
        raise RuntimeError("VM_RESOURCE_BOUNDARY_UNVERIFIED")
    memory = Path("/sys/fs/cgroup/memory.max").read_text().strip()
    cpu = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    if not memory.isascii() or not memory.isdecimal() or not 0 < int(memory) <= 2147483648 or len(cpu) != 2 or any(not value.isascii() or not value.isdecimal() for value in cpu) or not 0 < int(cpu[0]) <= 2 * int(cpu[1]) or not 0 < int(cpu[1]) <= 1000000:
        raise RuntimeError("VM_RESOURCE_BOUNDARY_UNVERIFIED")
    memory_kib = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:")))
    cpus = os.cpu_count() or 0
    if memory_kib <= 0 or cpus <= 0 or provider == "apple-container" and (memory_kib * 1024 > 2147483648 + 134217728 or cpus > 3):
        raise RuntimeError("VM_RESOURCE_BOUNDARY_UNVERIFIED")
    protect_runtime()
    install_seccomp()
    current = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if current.get("NoNewPrivs", "").strip() != "1" or current.get("Seccomp", "").strip() != "2":
        raise RuntimeError("VM_WORKER_PROTECTIONS_UNVERIFIED")
