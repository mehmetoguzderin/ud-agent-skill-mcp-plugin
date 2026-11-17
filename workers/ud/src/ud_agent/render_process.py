"""Own and reap exactly one Linux Chromium process tree within existing limits."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def _subreaper() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "renderer child adoption failed")
    selected = ctypes.c_int()
    if library.prctl(37, ctypes.byref(selected), 0, 0, 0) != 0 or selected.value != 1:
        raise RuntimeError("renderer child adoption was not verified")


def _affinity() -> None:
    available = os.sched_getaffinity(0)
    if not available:
        raise RuntimeError("renderer CPU affinity is empty")
    selected = set(sorted(available)[:2])
    os.sched_setaffinity(0, selected)
    if os.sched_getaffinity(0) != selected:
        raise RuntimeError("renderer CPU affinity was not verified")


def _kill_children() -> None:
    """Use pidfds so a reused numeric PID can never target another process."""
    parent = os.getpid()
    children = Path(f"/proc/self/task/{parent}/children").read_text(encoding="ascii").split()
    if len(children) > 1024 or any(not value.isdecimal() for value in children):
        raise RuntimeError("renderer child inventory is invalid")
    for child in children:
        descriptor = None
        try:
            descriptor = os.pidfd_open(int(child), 0)
            fields = Path(f"/proc/{child}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            if int(fields[1]) == parent:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError):
            continue
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _cleanup(seconds: float = 5) -> None:
    deadline = time.monotonic() + seconds
    while True:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if child:
            continue
        _kill_children()
        if time.monotonic() >= deadline:
            raise RuntimeError("renderer owned process cleanup was not verified")
        time.sleep(0.01)


def run(command: list[str], timeout: float = 50, library_dirs: list[str] | None = None) -> int:
    if (sys.platform != "linux" or not isinstance(command, list) or not 1 <= len(command) <= 256
            or any(not isinstance(value, str) or "\x00" in value for value in command)
            or not os.path.isabs(command[0]) or not 0 < timeout <= 50):
        raise ValueError("renderer process request is invalid")
    if library_dirs is not None and (not isinstance(library_dirs, list) or not 1 <= len(library_dirs) <= 64
            or any(not isinstance(value, str) for value in library_dirs)
            or len(set(library_dirs)) != len(library_dirs)
            or any(not isinstance(value, str) or not os.path.isabs(value) or "\x00" in value
                   or os.pathsep in value or ".." in Path(value).parts or not Path(value).is_dir() for value in library_dirs)):
        raise ValueError("renderer private library directories are invalid")
    environment = {key: value for key, value in os.environ.items() if key not in {"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"}}
    if library_dirs is not None:
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(library_dirs)
    _subreaper()
    _affinity()
    cancelled = False
    def cancel(_signum, _frame):
        nonlocal cancelled
        cancelled = True
    previous = {number: signal.signal(number, cancel) for number in (signal.SIGTERM, signal.SIGINT)}
    child = None
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 close_fds=True, env=environment)
        deadline = time.monotonic() + timeout
        while child.poll() is None and not cancelled and time.monotonic() < deadline:
            try:
                child.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                continue
        timed_out = child.poll() is None and not cancelled
        if child.poll() is None:
            child.kill()
        code = child.wait(timeout=2)
        return 125 if cancelled else 124 if timed_out else code if code >= 0 else 128 - code
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        _cleanup()
        for number, handler in previous.items():
            signal.signal(number, handler)


def main() -> int:
    try:
        if len(sys.argv) != 2 or len(sys.argv[1]) > 1024 * 1024:
            raise ValueError("renderer command framing is invalid")
        command = json.loads(sys.argv[1])
        if isinstance(command, dict):
            if set(command) != {"command", "library_dirs"} or not isinstance(command["library_dirs"], list):
                raise ValueError("renderer command framing is invalid")
            return run(command["command"], library_dirs=command["library_dirs"])
        return run(command)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("RENDER_PROCESS_FAILED: " + str(error)[:1024], file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
