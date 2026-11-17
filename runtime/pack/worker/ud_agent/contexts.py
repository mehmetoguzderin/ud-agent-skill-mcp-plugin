"""Resolve only complete hash-bound contexts inside an authenticated snapshot."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

_RULES = ("data.json", "deprels.json", "edeprels.json", "feats.json", "tospace.json", "udeprels.json", "upos.json")

def _relative(value: object, *, dot: bool = False) -> str:
    if value == "." and dot:
        return "."
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\0" in value:
        raise ValueError("CONTEXT_PATH_INVALID")
    parts = value.split("/")
    if PurePosixPath(value).is_absolute() or any(part in ("", ".", "..") for part in parts):
        raise ValueError("CONTEXT_PATH_INVALID")
    return value

def _file(root: Path, relative: str) -> Path:
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise ValueError("CONTEXT_PATH_INVALID")
    if not current.is_file() or current.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("CONTEXT_FILE_INVALID")
    current.resolve(strict=True).relative_to(root.resolve(strict=True))
    return current

def resolve_snapshot_context(snapshot_root: str, selected: object, installed_context: str) -> str:
    if selected is None or selected == "":
        return installed_context
    root = Path(snapshot_root)
    manifest_path = _file(root, _relative(selected))
    if manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("CONTEXT_MANIFEST_TOO_LARGE")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("rules"), dict) or set(manifest["rules"]) != set(_RULES):
        raise ValueError("CONTEXT_RULES_INCOMPLETE")
    rule_dir = _relative(manifest.get("rule_dir"), dot=True)
    rules = manifest["rules"]
    for name in _RULES:
        expected = rules[name]
        if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise ValueError("CONTEXT_HASH_INVALID")
        relative = name if rule_dir == "." else f"{rule_dir}/{name}"
        file = _file(manifest_path.parent, relative)
        if hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError("CONTEXT_RULE_HASH_MISMATCH")
    identity = hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if manifest.get("context_sha256") != identity:
        raise ValueError("CONTEXT_IDENTITY_MISMATCH")
    return str(manifest_path)
