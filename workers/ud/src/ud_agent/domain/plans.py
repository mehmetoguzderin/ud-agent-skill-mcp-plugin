"""Constrained mechanical repair plans and candidate-only application."""
from __future__ import annotations
import difflib
import base64
from hashlib import sha256
import json
from typing import Any

from ._common import files_for, require_no_options, root_path, scoped_path
from ._artifacts import MAX_BYTES, relative_name
from ..conllu.core import StaleInputError
from ..errors import InvalidInput


def _hash(data: bytes) -> str:
    return sha256(data).hexdigest()


def _destination(root: Any, value: Any) -> str:
    """Validate an absent workspace destination without following links."""
    name = relative_name(value)
    if name != value or any(not part for part in value.split("/")):
        raise InvalidInput("plan destination must be a canonical relative path")
    current = root
    for part in name.split("/"):
        current = current / part
        if current.is_symlink():
            raise InvalidInput("plan destination contains a symbolic link")
        if current.exists() and current != root / name and not current.is_dir():
            raise InvalidInput("plan destination parent is not a directory")
    if current.exists():
        raise StaleInputError("plan destination must still be absent")
    return name


def _content(item: dict[str, Any]) -> bytes:
    content = item.get("content")
    if not isinstance(content, str):
        raise InvalidInput("plan content must be UTF-8 text")
    try:
        data = content.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InvalidInput("plan content must be UTF-8 text") from exc
    if len(data) > MAX_BYTES or item.get("after_sha256") != _hash(data):
        raise InvalidInput("plan action content does not match its fingerprint or byte limit")
    return data


def _fingerprints(root: Any, item: dict[str, Any]) -> None:
    values = item.get("input_fingerprints", {})
    if not isinstance(values, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()):
        raise InvalidInput("plan input fingerprints must be a path-to-hash object")
    for input_path, expected_hash in values.items():
        if _hash(scoped_path(root, input_path).read_bytes()) != expected_hash:
            raise StaleInputError("plan input fingerprint does not match current file")


def fix_plan(args: dict[str, Any]) -> dict[str, Any]:
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    fix_ids = args.get("fix_ids")
    if not isinstance(fix_ids, list) or not fix_ids or any(item != "final_blank_line" for item in fix_ids) or len(set(fix_ids)) != len(fix_ids):
        raise InvalidInput("fix_ids must contain supported unique fix identifiers")
    require_no_options(args)
    actions = []
    for path in paths:
        before = path.read_bytes()
        try:
            text = before.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise InvalidInput("input must be UTF-8") from exc
        if not before:
            continue
        newline = "\r\n" if b"\r\n" in before else "\n"
        if text.endswith("\n\n") or text.endswith("\r\n\r\n"):
            continue
        after_text = text + (newline if text.endswith("\n") else newline + newline)
        after = after_text.encode("utf-8")
        path_name = path.relative_to(root).as_posix()
        actions.append({"id": f"final_blank_line:{path_name}", "type": "replace_file", "file_path": path_name,
                        "before_sha256": _hash(before), "after_sha256": _hash(after), "content": after_text,
                        "depends_on": [], "diff": "".join(difflib.unified_diff(text.splitlines(keepends=True), after_text.splitlines(keepends=True), fromfile=path_name, tofile=path_name))})
    return {"schema_version": "ud-plan-v1", "plan_type": "mechanical_fix", "actions": actions,
            "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"},
            "limitations": ["A formatting fix does not establish overall treebank validity."]}


def plan_apply(args: dict[str, Any]) -> dict[str, Any]:
    """Verify selected declarative actions and return candidates for the host broker."""
    root = root_path(args)
    path = scoped_path(root, args.get("plan_path"))
    if path.stat().st_size > 16 * 1024 * 1024:
        raise InvalidInput("plan exceeds its byte limit")
    try:
        plan_bytes = path.read_bytes()
        plan = json.loads(plan_bytes.decode("utf-8", errors="strict"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise InvalidInput("plan must be a UTF-8 JSON document") from exc
    if (not isinstance(plan, dict) or plan.get("schema_version") != "ud-plan-v1" or not isinstance(plan.get("actions"), list)
            or len(plan["actions"]) > 1000):
        raise InvalidInput("unsupported plan format")
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"mode"} or options.get("mode", "preview") not in ("preview", "apply"):
        raise InvalidInput("unsupported plan application options")
    actions = {}
    for item in plan["actions"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"] or item["id"] in actions:
            raise InvalidInput("plan actions must have unique nonempty IDs")
        if item.get("type") == "rename_file":
            from ._plan_state import rename_paths
            rename_paths(item)
        actions[item["id"]] = item
    selected = args.get("selected_action_ids")
    if not isinstance(selected, list) or len(selected) > 1000 or any(not isinstance(item, str) for item in selected) or len(selected) != len(set(selected)):
        raise InvalidInput("selected_action_ids must contain unique IDs")
    if any(item not in actions for item in selected):
        raise InvalidInput("selected action does not exist")
    selected_set = set(selected)
    ordered: list[str] = []
    state: dict[str, int] = {}

    closure: list[str] = []
    for ident in selected:
        stack = [(ident, False)]
        while stack:
            current, done = stack.pop()
            if done:
                state[current] = 2
                closure.append(current)
                continue
            if state.get(current) == 2:
                continue
            if state.get(current) == 1:
                raise InvalidInput("selected action dependencies contain a cycle")
            dependencies = actions[current].get("depends_on")
            if (not isinstance(dependencies, list) or len(dependencies) > 1000
                    or any(not isinstance(value, str) or value not in actions for value in dependencies)):
                raise InvalidInput("selected actions do not include their complete dependency closure")
            state[current] = 1
            stack.append((current, True))
            stack.extend((dependency, False) for dependency in reversed(dependencies))
    satisfied = [ident for ident in closure if ident not in selected_set]
    ordered = [ident for ident in closure if ident in selected_set]
    from ._plan_state import verify_satisfied
    verify_satisfied(root, args["plan_path"], plan_bytes, selected, satisfied, actions)
    details = {"selected_action_ids": selected, **({"satisfied_action_ids": satisfied} if satisfied else {})}
    structural_actions = {"token_split", "tokens_merge", "tree_split", "trees_merge", "tokenization_reconcile"}
    unresolved = []
    for ident in ordered:
        item = actions[ident]
        if item.get("type") in structural_actions:
            arguments = item.get("arguments")
            if not isinstance(arguments, dict) or not isinstance(arguments.get("annotation_map", item.get("annotation_map")), dict):
                unresolved.append({"action_id": ident, "required": ["arguments", "annotation_map"],
                                   "reason": "explicit target annotations and source references are required"})
    if unresolved:
        return {"status": "needs_annotation", "requested_mode": options.get("mode", "preview"),
                "requires_host_commit": False, "changes": [], "context_changes": [], "file_operations": [],
                "missing_decisions": unresolved, "details": details}
    structural_fields = {"id", "type", "arguments", "annotation_map", "input_fingerprints", "depends_on",
                         "source_tokens", "target_tokens", "requires_annotation_map", "character_offset", "desired_after", "current_after",
                         "temporary_id", "temporary_ids", "temporary_tree_ids"}
    if ordered and all(actions[ident].get("type") in structural_actions for ident in ordered):
        entries = []
        for ident in ordered:
            item = actions[ident]
            if set(item) - structural_fields:
                raise InvalidInput("structural plan action contains unsupported fields")
            _fingerprints(root, item)
            arguments = {**item["arguments"], "working_tree_path": str(root)}
            if "annotation_map" not in arguments:
                arguments["annotation_map"] = item["annotation_map"]
            operation = item["type"]
            if operation == "tokenization_reconcile":
                operation = arguments.pop("operation", "_tokenization_reconcile")
                if operation == "tokenization_reconcile":
                    operation = "_tokenization_reconcile"
            if operation not in structural_actions | {"_tokenization_reconcile"}:
                raise InvalidInput("tokenization reconciliation must name a supported structural operation")
            for field in ("temporary_id", "temporary_ids", "temporary_tree_ids"):
                if field in item:
                    arguments[field] = item[field]
            entries.append((arguments, operation))
        from ._sentence_batch import compose
        result = compose({"working_tree_path": str(root), "edit_options": {"mode": options.get("mode", "preview")}},
                         entries, structural_actions | {"_tokenization_reconcile"})
        result["details"].update(details)
        result["context_changes"] = []
        result["file_operations"] = []
        return result
    changes = []
    context_changes = []
    file_operations = []
    seen_paths = set()
    for ident in ordered:
        item = actions[ident]
        _fingerprints(root, item)
        kind = item.get("type")
        if kind in structural_actions:
            if set(item) - structural_fields:
                raise InvalidInput("structural plan action contains unsupported fields")
            arguments = {**item["arguments"], "working_tree_path": str(root)}
            if "annotation_map" not in arguments:
                arguments["annotation_map"] = item["annotation_map"]
            if kind == "tokenization_reconcile":
                operation = arguments.pop("operation", "_tokenization_reconcile")
                if operation == "tokenization_reconcile":
                    operation = "_tokenization_reconcile"
                if operation not in {"token_split", "tokens_merge", "tree_split", "trees_merge", "_tokenization_reconcile"}:
                    raise InvalidInput("tokenization reconciliation must name a supported structural operation")
            else:
                operation = kind
            from . import structural
            result = getattr(structural, operation)(arguments)
            if result.get("status") == "needs_annotation":
                return {**result, "requested_mode": options.get("mode", "preview"), "requires_host_commit": False,
                        "context_changes": [], "file_operations": [], "details": {"selected_action_ids": selected, "action_id": ident}}
            replacements = result.get("changes")
            if not isinstance(replacements, list):
                raise InvalidInput("structural action did not produce candidate changes")
            if len(replacements) == 0:
                continue
            # Expand to the same constrained replacement actions consumed by
            # ordinary plans; this does not execute host commands or commits.
            if len(replacements) > 1:
                for index, candidate in enumerate(replacements[1:], 1):
                    extra_id = ident + f":candidate:{index}"
                    if extra_id in actions:
                        raise InvalidInput("expanded structural action identity conflicts")
                    actions[extra_id] = {"id": extra_id, "type": "replace_file", **candidate, "depends_on": [],
                                         "input_fingerprints": item.get("input_fingerprints", {})}
                    ordered.append(extra_id)
            item = {"id": ident, "type": "replace_file", **replacements[0], "depends_on": [],
                    "input_fingerprints": item.get("input_fingerprints", {})}
            kind = "replace_file"
        if kind == "replace_file":
            allowed = {"id", "type", "file_path", "before_sha256", "after_sha256", "content", "depends_on", "diff", "input_fingerprints"}
        elif kind == "prepare_context":
            allowed = {"id", "type", "language_code", "files", "file_hashes", "base_hashes", "context_sha256", "input_fingerprints", "depends_on"}
        elif kind == "create_file":
            allowed = {"id", "type", "file_path", "before_sha256", "after_sha256", "content", "depends_on", "input_fingerprints"}
        elif kind == "delete_file":
            allowed = {"id", "type", "file_path", "before_sha256", "after_sha256", "depends_on", "input_fingerprints"}
        elif kind == "rename_file":
            allowed = {"id", "type", "file_path", "source", "target_file_path", "destination", "before_sha256", "target_before_sha256", "content", "after_sha256", "conflict", "depends_on", "input_fingerprints"}
        elif kind == "replace_text":
            allowed = {"id", "type", "file_path", "before_sha256", "old_text", "new_text", "diff", "depends_on", "input_fingerprints"}
        else:
            raise InvalidInput("selected plan action type is not supported")
        if set(item) - allowed:
            raise InvalidInput("selected plan action type is not supported")
        if kind == "prepare_context":
            from .rules import _RULES
            files = item.get("files")
            file_hashes = item.get("file_hashes")
            base_hashes = item.get("base_hashes")
            language = item.get("language_code")
            names = set(_RULES.values())
            if (not isinstance(files, dict) or set(files) != names or
                not isinstance(file_hashes, dict) or set(file_hashes) != names or
                not isinstance(base_hashes, dict) or set(base_hashes) != names or
                not isinstance(language, str) or not language):
                raise InvalidInput("context action requires seven files, hashes and a language")
            for key, name in _RULES.items():
                content = files[name]
                if (not isinstance(content, str) or file_hashes[name] != _hash(content.encode("utf-8")) or
                    not isinstance(base_hashes[name], str) or len(base_hashes[name]) != 64 or
                    any(c not in "0123456789abcdef" for c in base_hashes[name])):
                    raise InvalidInput("context action contains an invalid file or hash")
                try:
                    parsed = json.loads(content)
                except ValueError as exc:
                    raise InvalidInput("context action contains invalid rule JSON") from exc
                if not isinstance(parsed, dict) or key not in parsed or not isinstance(parsed[key], (dict, list)):
                    raise InvalidInput("context action contains an invalid rule family")
            context_hash = _hash(json.dumps(file_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            if item.get("context_sha256") != context_hash:
                raise InvalidInput("context action fingerprint mismatch")
            context_changes.append({"language_code": language, "files": files, "file_hashes": file_hashes,
                                    "base_hashes": base_hashes, "context_sha256": context_hash})
            continue
        if kind == "create_file":
            name = _destination(root, item.get("file_path"))
            if item.get("before_sha256") is not None or name in seen_paths:
                raise InvalidInput("create action has a conflicting source precondition or destination")
            data = _content(item)
            seen_paths.add(name)
            file_operations.append({"operation": "create", "file_path": name, "before_sha256": None,
                                    "after_sha256": _hash(data), "content": item["content"]})
            continue
        if kind in ("delete_file", "rename_file"):
            name = item.get("file_path", item.get("source"))
            source = scoped_path(root, name)
            before = source.read_bytes()
            if item.get("before_sha256") != _hash(before):
                raise StaleInputError("plan source fingerprint does not match current file")
            if name in seen_paths:
                raise InvalidInput("multiple selected actions affect one file")
            seen_paths.add(name)
            if kind == "delete_file":
                if item.get("after_sha256") is not None:
                    raise InvalidInput("delete action must have an absent after fingerprint")
                file_operations.append({"operation": "delete", "file_path": name,
                                        "before_sha256": _hash(before), "after_sha256": None})
            else:
                target = _destination(root, item.get("target_file_path", item.get("destination")))
                if item.get("target_before_sha256") is not None or item.get("conflict") or target in seen_paths:
                    raise InvalidInput("rename destination conflicts with another action")
                seen_paths.add(target)
                if "content" in item:
                    data = _content(item)
                    file_operations.extend([
                        {"operation": "create", "file_path": target, "before_sha256": None,
                         "after_sha256": _hash(data), "content": item["content"]},
                        {"operation": "delete", "file_path": name, "before_sha256": _hash(before), "after_sha256": None}])
                else:
                    file_operations.append({"operation": "rename", "file_path": name, "target_file_path": target,
                                            "before_sha256": _hash(before), "target_before_sha256": None,
                                            "after_sha256": _hash(before), "content_base64": base64.b64encode(before).decode("ascii")})
            continue
        file = scoped_path(root, item.get("file_path"))
        name = file.relative_to(root).as_posix()
        if name in seen_paths:
            raise InvalidInput("multiple selected replacements for one file are not supported")
        seen_paths.add(name)
        before = file.read_bytes()
        if item.get("before_sha256") != _hash(before):
            raise StaleInputError("plan source fingerprint does not match current file")
        if kind == "replace_text":
            old, new = item.get("old_text"), item.get("new_text")
            if not isinstance(old, str) or not old or not isinstance(new, str):
                raise InvalidInput("replace_text requires a nonempty old_text and string new_text")
            try:
                content = before.decode("utf-8", errors="strict").replace(old, new)
            except UnicodeError as exc:
                raise InvalidInput("replace_text source must be UTF-8") from exc
            _content({"content": content, "after_sha256": _hash(content.encode("utf-8"))})
        else:
            _content(item)
            content = item["content"]
        if before != content.encode("utf-8"):
            changes.append({"file_path": file.relative_to(root).as_posix(), "before_sha256": _hash(before),
                            "after_sha256": _hash(content.encode("utf-8")), "content": content})
    result = {"status": "candidate", "requested_mode": options.get("mode", "preview"),
            "requires_host_commit": bool(changes or context_changes or file_operations), "changes": changes,
            "context_changes": context_changes, "file_operations": file_operations, "details": details,
            "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"}}
    return result
