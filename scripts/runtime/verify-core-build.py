#!/usr/bin/env python3
"""Reconstruct and verify an offline core build context against current locks."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ud_agent_core_build", ROOT / "scripts/runtime/prepare-core-build.py")
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load core build preparation module")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


def verify(root: Path, cache: Path, context: Path) -> dict:
    if context.is_symlink() or not context.is_dir():
        raise ValueError("build context must be an ordinary directory")
    manifest_path = context / "input-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("build context manifest is missing or unsafe")
    receipt = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict) or receipt.get("qualification") != "unbuilt" or receipt.get("release_qualified") is not False:
        raise ValueError("context must be explicitly marked unbuilt and unqualified")
    with tempfile.TemporaryDirectory(prefix="ud-core-verification-") as tmp:
        expected = core.prepare(root, cache, Path(tmp) / "expected", False,receipt.get('build_platforms'))
    if receipt != expected:
        raise ValueError("build context receipt does not match current source and lock inputs")
    addressed = core.content_addressed_manifest(context)
    expected_files = set(expected["files"]) | {"input-manifest.json", addressed}
    expected_dirs = set()
    for value in expected_files:
        parent = Path(value).parent
        while parent != Path("."):
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    found_files = set()
    found_dirs = set()
    for directory, dirs, files in os.walk(context, followlinks=False):
        base = Path(directory)
        for name in dirs:
            item = base / name
            if item.is_symlink() or not item.is_dir():
                raise ValueError("build context contains unsafe directories")
            found_dirs.add(item.relative_to(context).as_posix())
        for name in files:
            item = base / name
            if item.is_symlink() or not item.is_file():
                raise ValueError("build context contains unsafe files")
            relative = item.relative_to(context).as_posix()
            found_files.add(relative)
            if relative not in ("input-manifest.json", addressed) and core.hash_file(item) != expected["files"].get(relative):
                raise ValueError(f"build context file does not match its locked input: {relative}")
    if found_files != expected_files or found_dirs != expected_dirs:
        raise ValueError("build context contains missing or unexpected paths")
    return {"verified": True, "qualification": "unbuilt", "release_qualified": False,
            "file_count": len(found_files), "rule_context_sha256": expected["rule_context_sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("context", type=Path)
    parser.add_argument("--wheel-cache", type=Path, default=ROOT / ".artifacts/wheels")
    args = parser.parse_args()
    try:
        result = verify(ROOT, args.wheel_cache, args.context)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"core build verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
