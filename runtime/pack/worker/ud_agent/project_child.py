"""Private subprocess for separately collecting official or project checks."""
from __future__ import annotations

import json
import os
import sys


def main() -> int:
    if len(sys.argv) != 5 or sys.argv[4] not in ("official", "project"):
        raise RuntimeError("PROJECT_CHILD_INVALID")
    worker, upstream, descriptor, mode = sys.argv[1:5]
    if descriptor == "stdout":
        # Retain only this private binary result pipe; ordinary project prints
        # are discarded before any project or upstream module can execute.
        fd = os.dup(sys.stdout.fileno())
        os.set_inheritable(fd, False)
        if os.name == "nt":
            import msvcrt
            msvcrt.setmode(fd, os.O_BINARY)
        with open(os.devnull, "wb", buffering=0) as discard:
            os.dup2(discard.fileno(), sys.stdout.fileno())
        if os.name == "nt":
            # Windows subprocess inheritance reads the process standard
            # handle, independently of the CRT descriptor used by print().
            import ctypes
            from ctypes import wintypes
            set_stdout = ctypes.WinDLL("kernel32", use_last_error=True).SetStdHandle
            set_stdout.argtypes = [wintypes.DWORD, wintypes.HANDLE]
            set_stdout.restype = wintypes.BOOL
            if not set_stdout(wintypes.DWORD(-11), wintypes.HANDLE(msvcrt.get_osfhandle(sys.stdout.fileno()))):
                raise ctypes.WinError(ctypes.get_last_error())
    else:
        fd = int(descriptor)
    sys.path[0:0] = [worker, upstream]
    ceiling = 32 * 1024 * 1024
    if os.name != "nt":
        import resource
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling if hard == resource.RLIM_INFINITY else min(ceiling, hard), hard))
    from ud_agent.errors import WorkerError
    from ud_agent.wire import MAX_REQUEST_BYTES, encode
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise RuntimeError("PROJECT_CHILD_INVALID")
    args = json.loads(raw)
    if not isinstance(args, dict):
        raise RuntimeError("PROJECT_CHILD_INVALID")
    try:
        if mode == "official":
            from ud_agent.domain.validation import validation_report
            result = validation_report(args)
        else:
            from ud_agent.project_rules import run_project_rules
            result = run_project_rules(args)
        payload = {"ok": True, "result": result}
    except WorkerError as exc:
        payload = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
    except Exception:
        payload = {"ok": False, "error": {"code": "PROJECT_CHILD_FAILED", "message": "validation subprocess failed"}}
    data = memoryview(encode(payload))
    while data:
        count = os.write(fd, data)
        if count <= 0:
            raise RuntimeError("PROJECT_CHILD_OUTPUT_FAILED")
        data = data[count:]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
