"""Bounded JSON-lines transport for the isolated worker process."""
from __future__ import annotations
import json
from typing import Any

from . import dispatch
from .errors import InvalidInput, WorkerError

MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def process(request: Any) -> dict[str, Any]:
    try:
        if not isinstance(request, dict) or set(request) != {"operation", "arguments"}:
            raise InvalidInput("request must contain exactly operation and arguments")
        return {"ok": True, "result": dispatch.call(request["operation"], request["arguments"])}
    except WorkerError as exc:
        return {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
    except Exception:
        # Project data and tracebacks can contain sensitive material. Detailed diagnostics
        # belong in the separately controlled worker error stream.
        return {"ok": False, "error": {"code": "WORKER_FAILED", "message": "worker operation failed"}}


def encode(value: dict[str, Any]) -> bytes:
    try:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkerError("INVALID_WORKER_RESULT", "worker result is not valid JSON") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise WorkerError("RESULT_TOO_LARGE", "worker result exceeds the configured size limit")
    return data + b"\n"
