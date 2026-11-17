"""Verify a read-only OCI input volume before running trusted built-in work."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
from contextlib import nullcontext

from .snapshot_receiver import MAX_FILE, _manifest
from .wire import MAX_REQUEST_BYTES, encode, process
from .dispatch import _NAMES
from .contexts import resolve_snapshot_context


def verify_snapshot(root: str, files: object, expected: str) -> None:
    """Verify exact staged bytes and inventory without following symlinks."""
    manifest = _manifest(files, expected)
    if not stat.S_ISDIR(os.lstat(root).st_mode):
        raise ValueError("OCI_SNAPSHOT_INVENTORY_INVALID")
    expected_files = {item["path"]: item for item in manifest}
    expected_dirs = {"."}
    for name in expected_files:
        parts = name.split("/")
        expected_dirs.update("/".join(parts[:index]) for index in range(1, len(parts)))
    found = set()
    for base, directories, names in os.walk(root, followlinks=False):
        relative = os.path.relpath(base, root)
        if relative not in expected_dirs:
            raise ValueError("OCI_SNAPSHOT_INVENTORY_INVALID")
        for name in directories:
            full = os.path.join(base, name)
            item = os.lstat(full)
            child = name if relative == "." else f"{relative}/{name}"
            if not stat.S_ISDIR(item.st_mode) or child not in expected_dirs:
                raise ValueError("OCI_SNAPSHOT_INVENTORY_INVALID")
        for name in names:
            relative_name = name if relative == "." else f"{relative}/{name}"
            item = expected_files.get(relative_name)
            if item is None or relative_name in found:
                raise ValueError("OCI_SNAPSHOT_INVENTORY_INVALID")
            descriptor = os.open(os.path.join(base, name), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size != item["size"] or info.st_size > MAX_FILE:
                    raise ValueError("OCI_SNAPSHOT_INVENTORY_INVALID")
                digest = hashlib.sha256()
                with os.fdopen(descriptor, "rb", closefd=False) as source:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                if digest.hexdigest() != item["sha256"]:
                    raise ValueError("OCI_SNAPSHOT_DIGEST_MISMATCH")
            finally:
                os.close(descriptor)
            found.add(relative_name)
    if found != set(expected_files):
        raise ValueError("OCI_SNAPSHOT_INVENTORY_INVALID")


def verify_confinement() -> None:
    """Observe effective worker isolation; engine flags alone are insufficient."""
    if os.geteuid() != 10001 or os.getegid() != 10001:
        raise RuntimeError("OCI_WORKER_IDENTITY_INVALID")
    status = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            status[key] = value.strip()
    if (status.get("NoNewPrivs") != "1" or status.get("Seccomp") != "2"
            or any(status.get(name) != "0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))):
        raise RuntimeError("OCI_WORKER_PRIVILEGES_UNVERIFIED")
    try:
        interfaces = socket.if_nameindex()
        if not any(name == "lo" for _, name in interfaces):
            raise ValueError("loopback is missing")
        for _, name in interfaces:
            # Linux may expose dormant tunnel devices even in a network-none
            # namespace. Only a non-loopback device marked UP is a violation.
            if name != "lo" and int((Path("/sys/class/net") / name / "flags").read_text().strip(), 16) & 1:
                raise ValueError("external interface is up")
        if Path("/proc/net/route").read_text().splitlines()[1:]:
            raise ValueError("IPv4 route is present")
        if any(line.split()[-1] != "lo" for line in Path("/proc/net/ipv6_route").read_text().splitlines() if line.split()):
            raise ValueError("non-loopback IPv6 route is present")
    except (OSError, ValueError, IndexError) as exc:
        raise RuntimeError("OCI_WORKER_NETWORK_UNVERIFIED") from exc
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split(" - ", 1)[0].split()
        if len(fields) >= 6 and fields[4] in ("/", "/input"):
            mounts[fields[4]] = fields[5].split(",")
    if any("ro" not in mounts.get(name, []) for name in ("/", "/input")):
        raise RuntimeError("OCI_WORKER_MOUNTS_UNVERIFIED")
    cgroup = Path("/sys/fs/cgroup")
    try:
        memory = (cgroup / "memory.max").read_text().strip()
        pids = (cgroup / "pids.max").read_text().strip()
        cpu_quota, cpu_period = (cgroup / "cpu.max").read_text().split()
        if (memory == "max" or not 0 < int(memory) <= 2 * 1024 * 1024 * 1024
                or pids == "max" or not 0 < int(pids) <= 128
                or cpu_quota == "max" or int(cpu_period) <= 0 or not 0 < int(cpu_quota) <= int(cpu_period) * 2):
            raise ValueError("resource limits are too broad")
    except (OSError, ValueError) as exc:
        raise RuntimeError("OCI_WORKER_LIMITS_UNVERIFIED") from exc


def main(*, provider: str | None = None) -> int:
    if provider is None:
        verify_confinement()
    else:
        from .vm_confinement import verify_vm_confinement
        verify_vm_confinement(provider)
    raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
        raise RuntimeError("OCI_WORKER_REQUEST_INVALID")
    request = json.loads(raw)
    if (not isinstance(request, dict) or set(request) - {"operation", "arguments", "snapshot_sha256", "files", "broker_evidence"} or not {"operation", "arguments", "snapshot_sha256", "files"}.issubset(request)
            or not isinstance(request["operation"], str) or request["operation"] not in {*_NAMES, "_project_rules"} or not isinstance(request["arguments"], dict)):
        raise RuntimeError("OCI_WORKER_REQUEST_INVALID")
    verify_snapshot("/input/data", request["files"], request["snapshot_sha256"])
    args = request["arguments"]
    args["working_tree_path"] = "/input/data"
    args["ud_context_path"] = resolve_snapshot_context("/input/data", args.get("ud_context_path"), "/opt/ud-agent/context/context.json")
    from .evidence import broker_evidence
    with (broker_evidence(request["broker_evidence"], request["snapshot_sha256"]) if "broker_evidence" in request else nullcontext()):
        if request["operation"] == "_project_rules":
            from .errors import WorkerError
            from .project_rules import run_project_rules
            try:
                response = {"ok": True, "result": run_project_rules(args)}
            except WorkerError as exc:
                response = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
        else:
            response = process({"operation": request["operation"], "arguments": args})
    sys.stdout.buffer.write(encode(response))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
