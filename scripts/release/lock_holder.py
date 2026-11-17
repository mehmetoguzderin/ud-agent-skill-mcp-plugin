#!/usr/bin/env python3
"""Hold an OS advisory release-tooling lock until the controlling pipe closes."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time


def hold(filename: str, timeout: float) -> None:
    if not os.path.isabs(filename) or not 0 < timeout <= 300:
        raise ValueError("invalid release lock request")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(filename, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1 or (os.name != "nt" and (info.st_mode & 0o077 or info.st_uid != os.getuid())):
            raise ValueError("release lock is not private and owned")
        if info.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        if os.name == "nt":
            import msvcrt

            def acquire() -> None:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)

            def release() -> None:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            def acquire() -> None:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

            def release() -> None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        deadline = time.monotonic() + timeout
        while True:
            try:
                acquire()
                break
            except (BlockingIOError, OSError) as error:
                if getattr(error, "errno", None) not in (11, 13, 35, 36):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError("release lock acquisition timed out") from error
                time.sleep(0.025)
        try:
            print(json.dumps({"schema_version": 1, "locked": True, "pid": os.getpid()}), flush=True)
            while sys.stdin.buffer.read(1024):
                pass
        finally:
            release()
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("filename")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    hold(args.filename, args.timeout)


if __name__ == "__main__":
    main()
