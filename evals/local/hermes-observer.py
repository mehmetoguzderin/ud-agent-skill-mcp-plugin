# SPDX-License-Identifier: MIT
"""Passive native Hermes lifecycle plugin; never alters calls or responses."""
import fcntl
import json
import os
import stat
import threading

_lock = threading.Lock()
_fields = ("tool_call_id", "tool_name", "args", "status", "result", "session_id",
           "turn_id", "api_request_id", "error_type", "error_message")


def _append(record):
    data = (json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    if len(data) > 4 * 1024**2:
        raise ValueError("HERMES_NATIVE_EVIDENCE_EVENT_TOO_LARGE")
    destination = os.environ["UD_LOCAL_HERMES_OBSERVATIONS"]
    if not os.path.isabs(destination):
        raise ValueError("HERMES_NATIVE_EVIDENCE_PATH_INVALID")
    with _lock:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size + len(data) > 32 * 1024**2:
                raise ValueError("HERMES_NATIVE_EVIDENCE_PATH_INVALID")
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("HERMES_NATIVE_EVIDENCE_WRITE_FAILED")
                remaining = remaining[written:]
        finally:
            os.close(fd)
    # Both native hooks are observational. Never return a transform, context
    # injection, replacement response, or tool choice.
    return None


def observe(**event):
    return _append({"type": "hermes.post_tool_call", "schema_version": 1,
                    **{key: event.get(key) for key in _fields}})


def observe_final(**event):
    # Pinned agent.turn_finalizer fires this after output transformations with
    # the same final_response it returns to cli.py for printing. Its caller
    # ignores hook return values. Omit user/history content we do not need.
    fields = ("session_id", "task_id", "turn_id", "assistant_response", "model", "platform")
    return _append({"type": "hermes.post_llm_call", "schema_version": 1,
                    **{key: event.get(key) for key in fields}})


def register(ctx):
    ctx.register_hook("post_tool_call", observe)
    ctx.register_hook("post_llm_call", observe_final)
