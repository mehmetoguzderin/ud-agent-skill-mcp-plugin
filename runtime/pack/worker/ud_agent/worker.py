"""Entry point for one-request-per-line worker transport."""
from __future__ import annotations
import json
import sys

from .errors import WorkerError
from .wire import MAX_REQUEST_BYTES, encode, process


def main() -> int:
    while True:
        raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            return 0
        if len(raw) > MAX_REQUEST_BYTES:
            sys.stdout.buffer.write(encode({"ok": False, "error": {"code": "REQUEST_TOO_LARGE", "message": "worker request exceeds the size limit"}}))
            sys.stdout.buffer.flush()
            # Stop: remaining bytes belong to the rejected request.
            return 1
        try:
            response = process(json.loads(raw))
        except (UnicodeError, json.JSONDecodeError):
            response = {"ok": False, "error": {"code": "INVALID_JSON", "message": "worker request is not valid JSON"}}
        try:
            out = encode(response)
        except WorkerError as exc:
            out = encode({"ok": False, "error": {"code": exc.code, "message": str(exc)}})
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    raise SystemExit(main())
