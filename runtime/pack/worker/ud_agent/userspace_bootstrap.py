"""Fixed userspace validation entry point; the broker authenticates its inputs.

This is not a sandbox for arbitrary project code. The broker chooses this entry
point only for built-in validation and separately verifies the runtime pack.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _verify_windows_job() -> None:
    """Verify the effective native job; a command-line flag is not authority."""
    import ctypes
    from ctypes import wintypes
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
                    ("maximum_working_set", ctypes.c_size_t), ("processes", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                    ("scheduling", wintypes.DWORD)]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", ctypes.c_uint64 * 6),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.QueryInformationJobObject
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    query.restype = wintypes.BOOL
    info = Extended()
    if not query(None, 9, ctypes.byref(info), ctypes.sizeof(info), None):
        raise RuntimeError("WORKER_PROCESS_CONTAINMENT_UNVERIFIED")
    required = 0x2000 | 0x100 | 0x200 | 8 | 2 | 4
    if (info.basic.flags & required != required or not 0 < info.basic.processes <= 128
            or not 0 < info.process_memory <= 2 * 1024**3
            or not 0 < info.job_memory <= 2 * 1024**3
            or not 0 < info.basic.process_time <= 300 * 10_000_000
            or not 0 < info.basic.job_time <= 300 * 10_000_000):
        raise RuntimeError("WORKER_RESOURCE_LIMIT_UNAVAILABLE")
    cpu = (wintypes.DWORD * 2)()
    if not query(None, 15, ctypes.byref(cpu), ctypes.sizeof(cpu), None) or cpu[0] & 5 != 5 or not 0 < cpu[1] <= 10000:
        raise RuntimeError("WORKER_RESOURCE_LIMIT_UNAVAILABLE")


def main() -> int:
    framed = len(sys.argv) == 7 and sys.argv[-1] == "--framed-stdin"
    if len(sys.argv) != 6 and not framed:
        raise RuntimeError("WORKER_REQUEST_INVALID")
    if sys.platform == "win32" and not framed:
        raise RuntimeError("WORKER_PROCESS_CONTAINMENT_UNVERIFIED")
    worker, upstream, context, expected, staging = sys.argv[1:6]
    sys.path[0:0] = [worker, upstream]
    if sys.platform == "win32":
        _verify_windows_job()
    else:
        import resource
        limits = [(resource.RLIMIT_CPU, 300), (resource.RLIMIT_NOFILE, 256),
                  (resource.RLIMIT_FSIZE, 64 * 1024 * 1024)]
        if sys.platform.startswith("linux"):
            limits.append((resource.RLIMIT_AS, 2 * 1024 * 1024 * 1024))
        for kind, ceiling in limits:
            _soft, hard = resource.getrlimit(kind)
            maximum = ceiling if hard == resource.RLIM_INFINITY else min(ceiling, hard)
            resource.setrlimit(kind, (maximum, hard))
            if resource.getrlimit(kind)[0] > ceiling:
                raise RuntimeError("WORKER_RESOURCE_LIMIT_UNAVAILABLE")
    from ud_agent.snapshot_receiver import receive_snapshot
    from ud_agent.contexts import resolve_snapshot_context
    from ud_agent.wire import MAX_REQUEST_BYTES, encode, process
    def execute(snapshot, raw=None):
        if raw is None:
            raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
            raise RuntimeError("WORKER_REQUEST_INVALID")
        request = json.loads(raw)
        permitted = json.loads((Path(worker) / "ud_agent" / "userspace_operations.json").read_text(encoding="utf-8"))
        if (not isinstance(permitted, list) or not all(isinstance(name, str) for name in permitted)
                or not isinstance(request, dict) or set(request) not in ({"operation", "arguments"}, {"operation", "arguments", "broker_evidence"})
                or request["operation"] not in permitted
                or not isinstance(request["arguments"], dict)):
            raise RuntimeError("WORKER_REQUEST_INVALID")
        request["arguments"]["working_tree_path"] = snapshot.path
        request["arguments"]["ud_context_path"] = resolve_snapshot_context(snapshot.path, request["arguments"].get("ud_context_path"), context)
        has_metadata = "broker_evidence" in request
        metadata = request.pop("broker_evidence", None)
        if has_metadata:
            from ud_agent.evidence import broker_evidence
            with broker_evidence(metadata, expected):
                response = process(request)
        else:
            response = process(request)
        sys.stdout.buffer.write(encode(response))
        sys.stdout.buffer.flush()
    if framed:
        with receive_snapshot(sys.stdin.buffer, expected, staging, stop_at_end=True) as snapshot:
            execute(snapshot)
    else:
        # Preserve the original POSIX ordering: request on stdin, frames on fd3.
        request = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not request or len(request) > MAX_REQUEST_BYTES or not request.endswith(b"\n"):
            raise RuntimeError("WORKER_REQUEST_INVALID")
        with os.fdopen(3, "rb", closefd=True) as stream:
            with receive_snapshot(stream, expected, staging) as snapshot:
                execute(snapshot, request)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
