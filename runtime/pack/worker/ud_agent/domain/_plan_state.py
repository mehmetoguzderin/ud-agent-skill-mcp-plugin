"""Prove explicit whole-file dependency postconditions without executing actions."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from ._common import scoped_path
from ..evidence import staged_plan_state
from ..errors import InvalidInput
from ..unicode_paths import path_key, validate_path

_HASH = re.compile(r"^[0-9a-f]{64}$")


def _name(value: Any) -> str:
    try:
        validate_path(value)
    except ValueError as exc:
        raise InvalidInput("dependency postcondition path is invalid") from exc
    if value == ".ud-agent-inputs" or value.startswith(".ud-agent-inputs/"):
        raise InvalidInput("dependency postcondition path is invalid")
    return value


def _hash(value: Any) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise InvalidInput("dependency postcondition is unprovable")
    return value


def _content_hash(action: dict[str, Any]) -> str:
    content = action.get("content")
    if not isinstance(content, str):
        raise InvalidInput("dependency content is unprovable")
    try:
        data = content.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InvalidInput("dependency content must be UTF-8") from exc
    expected = _hash(action.get("after_sha256"))
    if len(data) > 64 * 1024 * 1024 or sha256(data).hexdigest() != expected:
        raise InvalidInput("dependency content fingerprint is invalid")
    return expected


def rename_paths(action: dict[str, Any]) -> tuple[str, str]:
    if ("file_path" in action and "source" in action and action["file_path"] != action["source"]
            or "target_file_path" in action and "destination" in action and action["target_file_path"] != action["destination"]):
        raise InvalidInput("plan rename aliases conflict")
    source = _name(action.get("file_path", action.get("source")))
    target = _name(action.get("target_file_path", action.get("destination")))
    if path_key(source) == path_key(target):
        raise InvalidInput("plan rename paths collide")
    return source, target


def postconditions(action: dict[str, Any]) -> dict[str, str | None]:
    kind = action.get("type")
    fields = {
        "create_file": {"file_path", "before_sha256", "after_sha256", "content"},
        "replace_file": {"file_path", "before_sha256", "after_sha256", "content", "diff"},
        "delete_file": {"file_path", "before_sha256", "after_sha256"},
        "rename_file": {"file_path", "source", "target_file_path", "destination", "before_sha256", "target_before_sha256", "content", "after_sha256", "conflict"},
    }
    if not isinstance(kind, str) or kind not in fields or set(action) - fields[kind] - {"id", "type", "depends_on", "input_fingerprints"}:
        raise InvalidInput("dependency postcondition is unsupported or unprovable")
    fingerprints = action.get("input_fingerprints", {})
    if not isinstance(fingerprints, dict):
        raise InvalidInput("dependency input fingerprints are invalid")
    for key, value in fingerprints.items():
        _name(key)
        _hash(value)
    if kind in {"create_file", "replace_file"}:
        if kind == "create_file" and action.get("before_sha256", False) is not None:
            raise InvalidInput("dependency create postcondition is unprovable")
        if kind == "replace_file":
            _hash(action.get("before_sha256"))
        result = {_name(action.get("file_path")): _content_hash(action)}
    elif kind == "delete_file":
        _hash(action.get("before_sha256"))
        if action.get("after_sha256", False) is not None:
            raise InvalidInput("dependency deletion postcondition is unprovable")
        result = {_name(action.get("file_path")): None}
    elif kind == "rename_file":
        source, target = rename_paths(action)
        before = _hash(action.get("before_sha256"))
        if source == target or action.get("target_before_sha256", False) is not None or action.get("conflict", False) is not False:
            raise InvalidInput("dependency rename postcondition is unprovable")
        if "content" in action:
            after = _content_hash(action)
        else:
            after = before
        if action.get("after_sha256", after) != after:
            raise InvalidInput("dependency rename fingerprint is contradictory")
        result = {source: None, target: after}
    else:
        raise InvalidInput("dependency postcondition is unsupported or unprovable")
    if "postconditions" in action:
        raise InvalidInput("caller-declared postconditions do not prove a completed action")
    return result


def verify_satisfied(root: Path, plan_path: str, plan_bytes: bytes, selected: list[str], satisfied: list[str], actions: dict[str, Any]) -> None:
    if not satisfied:
        return
    descriptor = staged_plan_state()
    if descriptor is None:
        raise InvalidInput("unselected dependencies require verified broker plan state evidence")
    receipt_bytes = scoped_path(root, descriptor["manifest_path"]).read_bytes()
    if len(receipt_bytes) > 1024 * 1024 or sha256(receipt_bytes).hexdigest() != descriptor["sha256"]:
        raise InvalidInput("broker plan state receipt fingerprint does not match")
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeError) as exc:
        raise InvalidInput("broker plan state receipt is invalid") from exc
    if (not isinstance(receipt, dict) or set(receipt) - {"schema_version", "plan_path", "plan_sha256", "selected_action_ids", "satisfied_action_ids", "states", "completed_batches"}
            or receipt.get("schema_version") != 1 or receipt.get("plan_path") != plan_path
            or receipt.get("plan_sha256") != sha256(plan_bytes).hexdigest()
            or receipt.get("selected_action_ids") != selected or receipt.get("satisfied_action_ids") != satisfied
            or not isinstance(receipt.get("states"), list) or len(receipt["states"]) > 10000):
        raise InvalidInput("broker plan state does not match the requested plan selection")
    states = {}
    for item in receipt["states"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise InvalidInput("broker plan state entry is invalid")
        name = _name(item["path"])
        if name in states or item["sha256"] is not None and not _HASH.fullmatch(_hash(item["sha256"])):
            raise InvalidInput("broker plan state entry is invalid")
        states[name] = item["sha256"]
    batches = receipt.get("completed_batches", [])
    if not isinstance(batches, list) or len(batches) > 1000:
        raise InvalidInput("broker completed batch evidence is invalid")
    for batch in batches:
        if (not isinstance(batch, dict) or batch.get("schema_version") != 1 or batch.get("plan_path") != plan_path
                or batch.get("plan_sha256") != receipt["plan_sha256"] or not isinstance(batch.get("action_ids"), list)
                or not batch["action_ids"] or any(not isinstance(ident, str) or ident not in actions for ident in batch["action_ids"])
                or len(set(batch["action_ids"])) != len(batch["action_ids"])
                or batch.get("validation") not in {"passed", "context-publication"}
                or not isinstance(batch.get("outputs"), list) or len(batch["outputs"]) > 1000
                or not isinstance(batch.get("contexts"), list) or len(batch["contexts"]) > 100
                or not batch["outputs"] and not batch["contexts"]):
            raise InvalidInput("broker completed batch evidence is invalid")
        for reference in batch["contexts"]:
            if (not isinstance(reference, dict) or reference.get("action_id") not in batch["action_ids"]
                    or actions[reference["action_id"]].get("type") != "prepare_context"
                    or reference.get("context_sha256") != actions[reference["action_id"]].get("context_sha256")
                    or not isinstance(reference.get("uri"), str) or not reference["uri"].startswith("ud://contexts/")):
                raise InvalidInput("broker context publication evidence is invalid")
            _hash(reference.get("sha256"))
    for ident in satisfied:
        batch = next((item for item in batches if ident in item["action_ids"]), None)
        conditions = postconditions(actions[ident]) if batch is None else {
            _name(item.get("path")): item.get("sha256") for item in batch["outputs"] if isinstance(item, dict)}
        if batch is not None and len(conditions) != len(batch["outputs"]):
            raise InvalidInput("completed batch file inventory is invalid")
        for name, expected in conditions.items():
            if expected is not None:
                _hash(expected)
            if name not in states or states[name] != expected:
                raise InvalidInput("dependency postcondition is not proven by the broker")
            target = root / name
            if expected is None:
                if target.exists() or target.is_symlink():
                    raise InvalidInput("dependency absence postcondition does not match staged state")
            elif sha256(scoped_path(root, name).read_bytes()).hexdigest() != expected:
                raise InvalidInput("dependency postcondition does not match staged bytes")
