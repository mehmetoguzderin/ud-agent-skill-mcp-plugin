"""Request-scoped evidence installed only by the verified worker transport.

Application arguments never populate this context. The coordinator owns the
control channel, independently reads Git objects, and binds evidence to the
same snapshot manifest the worker verifies before invoking a handler.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import copy
import json
import re
from typing import Any

from .errors import InvalidInput

_CURRENT: ContextVar[dict[str, Any] | None] = ContextVar("ud_broker_evidence", default=None)
_SHA = re.compile(r"^[0-9a-f]{64}$")
_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


@contextmanager
def broker_evidence(metadata: Any, verified_snapshot_sha256: str):
    """Install transport-owned metadata after snapshot verification, then clear."""
    try:
        raw = json.dumps(metadata, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise InvalidInput("broker evidence is not bounded JSON") from exc
    if (len(raw) > 8 * 1024 * 1024 or not isinstance(metadata, dict) or metadata.get("schema_version") != 1
            or not isinstance(verified_snapshot_sha256, str) or not _SHA.fullmatch(verified_snapshot_sha256)
            or metadata.get("snapshot_sha256") != verified_snapshot_sha256):
        raise InvalidInput("broker evidence does not match the verified snapshot")
    if "git_base" in metadata:
        base = metadata["git_base"]
        if (not isinstance(base, dict) or not isinstance(base.get("requested_revision"), str)
                or not isinstance(base.get("resolved_commit"), str) or not _OID.fullmatch(base["resolved_commit"])
                or not isinstance(base.get("tree_oid"), str) or not _OID.fullmatch(base["tree_oid"])
                or not isinstance(base.get("files"), dict) or len(base["files"]) > 10000):
            raise InvalidInput("broker Git evidence is incomplete")
        for name, item in base["files"].items():
            if (not isinstance(name, str) or not isinstance(item, dict) or not isinstance(item.get("sha256"), str)
                    or not _SHA.fullmatch(item["sha256"]) or not isinstance(item.get("size_bytes"), int)
                    or isinstance(item["size_bytes"], bool) or item["size_bytes"] < 0
                    or not isinstance(item.get("blob_oid"), str) or not _OID.fullmatch(item["blob_oid"])):
                raise InvalidInput("broker Git file inventory is invalid")
    if "plan_state" in metadata:
        state = metadata["plan_state"]
        if (not isinstance(state, dict) or set(state) != {"manifest_path", "sha256"}
                or state.get("manifest_path") != ".ud-agent-inputs/plan-state/manifest.json"
                or not isinstance(state.get("sha256"), str) or not _SHA.fullmatch(state["sha256"])):
            raise InvalidInput("broker plan state evidence is invalid")
    token = _CURRENT.set(copy.deepcopy(metadata))
    try:
        yield
    finally:
        _CURRENT.reset(token)


def git_base(revision: str, files: dict[str, tuple[str, int]], *, snapshot_path: str | None = None,
             snapshot_sha256: str | None = None, directory_path: str | None = None) -> dict[str, Any] | None:
    metadata = _CURRENT.get()
    if metadata is None or "git_base" not in metadata:
        return None
    base = metadata["git_base"]
    if (not isinstance(base, dict) or base.get("requested_revision") != revision
            or not isinstance(base.get("resolved_commit"), str) or not _OID.fullmatch(base["resolved_commit"])
            or not isinstance(base.get("tree_oid"), str) or not _OID.fullmatch(base["tree_oid"])
            or not isinstance(base.get("files"), dict) or set(base["files"]) != set(files)):
        raise InvalidInput("broker Git evidence does not match the requested revision or file inventory")
    for name, (sha256, size) in files.items():
        item = base["files"][name]
        if (not isinstance(item, dict) or item.get("sha256") != sha256 or item.get("size_bytes") != size
                or not isinstance(item.get("blob_oid"), str) or not _OID.fullmatch(item["blob_oid"])):
            raise InvalidInput("broker Git evidence does not match the staged base bytes")
    if snapshot_path is not None and (base.get("base_snapshot_path") != snapshot_path or base.get("base_snapshot_sha256") != snapshot_sha256):
        raise InvalidInput("broker Git snapshot document does not match its receipt")
    if directory_path is not None and base.get("base_directory_path") != directory_path:
        raise InvalidInput("broker Git base directory does not match its receipt")
    return {"requested_revision": revision, "resolved_commit": base["resolved_commit"], "tree_oid": base["tree_oid"],
            "snapshot_sha256": metadata["snapshot_sha256"], "method": "broker-verified Git object bytes"}


def staged_git_base(revision: str) -> dict[str, Any] | None:
    """Return a copy of transport paths; callers must still verify base bytes."""
    metadata = _CURRENT.get()
    if metadata is None or not isinstance(metadata.get("git_base"), dict):
        return None
    base = metadata["git_base"]
    if base.get("requested_revision") != revision:
        raise InvalidInput("broker Git evidence belongs to a different requested revision")
    return copy.deepcopy(base)


def staged_plan_state() -> dict[str, Any] | None:
    """Only the verified transport can authorize staged absence observations."""
    metadata = _CURRENT.get()
    if metadata is None or "plan_state" not in metadata:
        return None
    return copy.deepcopy(metadata["plan_state"])
