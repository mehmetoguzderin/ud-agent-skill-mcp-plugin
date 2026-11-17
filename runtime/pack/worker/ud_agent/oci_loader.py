"""Transfer a verified snapshot into one product-owned OCI volume."""
from __future__ import annotations

import json
import os
import sys

from .snapshot_receiver import receive_snapshot


def main() -> int:
    if len(sys.argv) != 2 or os.geteuid() != 10001 or os.getegid() != 10001:
        raise RuntimeError("OCI_LOADER_IDENTITY_INVALID")
    expected = sys.argv[1]
    with receive_snapshot(sys.stdin.buffer, expected, "/input") as snapshot:
        snapshot.promote("data")
    print(json.dumps({"status": "loaded", "snapshot_sha256": expected}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
