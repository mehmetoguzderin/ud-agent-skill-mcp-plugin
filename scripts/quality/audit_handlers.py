#!/usr/bin/env python3
"""Reject catalog entries that do not resolve to real callable worker handlers."""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/ud/src"))
catalog = json.loads((ROOT / "contracts/ud-interfaces.json").read_text(encoding="utf-8"))
missing = []
for operation in catalog:
    module, name = operation["handler"].split(":", 1)
    try:
        handler = getattr(importlib.import_module(module), name, None)
    except ImportError as exc:
        missing.append(f'{operation["id"]} {operation["name"]}: {exc}')
        continue
    if not callable(handler):
        missing.append(f'{operation["id"]} {operation["name"]}: missing handler')
if missing:
    print("Incomplete operation implementations:\n" + "\n".join(missing), file=sys.stderr)
    raise SystemExit(1)
print(f"Validated {len(catalog)} callable worker handlers")
