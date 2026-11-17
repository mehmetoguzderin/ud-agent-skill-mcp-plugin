"""Conservative plans for UD README machine-readable metadata."""
from __future__ import annotations
import difflib
from hashlib import sha256
import json
import re
from typing import Any

from ._common import root_path, scoped_path
from ..errors import InvalidInput

_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9 _/\-]*$")


def metadata_change_plan(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    proposed_path = scoped_path(root, args.get("proposed_metadata_path"))
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"readme_path"}:
        raise InvalidInput("unsupported metadata planning options")
    readme = scoped_path(root, options.get("readme_path", "README.md"))
    try:
        proposed = json.loads(proposed_path.read_text(encoding="utf-8"))
        before = readme.read_bytes()
        text = before.decode("utf-8", errors="strict")
    except (OSError, UnicodeError, ValueError) as exc:
        raise InvalidInput("metadata proposal must be JSON and README must be UTF-8") from exc
    if not isinstance(proposed, dict) or not proposed:
        raise InvalidInput("metadata proposal must be a nonempty field object")
    for key, value in proposed.items():
        if not isinstance(key, str) or not _FIELD.fullmatch(key) or (value is not None and (not isinstance(value, str) or any(ord(c) < 32 for c in value))):
            raise InvalidInput("metadata fields must have simple names and one-line string or null values")
    if len({key.casefold() for key in proposed}) != len(proposed):
        raise InvalidInput("metadata proposal contains duplicate field names")
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("=== Machine-readable metadata")]
    if len(starts) != 1:
        raise InvalidInput("README must contain exactly one machine-readable metadata block")
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines)) if re.fullmatch(r"={3,}\s*", lines[i])), None)
    if end is None:
        raise InvalidInput("README metadata block has no terminating marker")
    current: dict[str, tuple[int, str, str]] = {}
    for index in range(start + 1, end):
        body = lines[index].rstrip("\r\n")
        if not body.strip():
            continue
        key, separator, value = body.partition(":")
        if not separator or not _FIELD.fullmatch(key):
            raise InvalidInput("README contains an unsupported metadata line")
        identity = key.casefold()
        if identity in current:
            raise InvalidInput("README contains duplicate metadata fields")
        current[identity] = (index, key, value.lstrip(" "))
    newline = "\r\n" if lines[start].endswith("\r\n") else "\n"
    replacements: dict[int, str | None] = {}
    additions = []
    changes = []
    for key, value in proposed.items():
        existing = current.get(key.casefold())
        old_value = existing[2] if existing else None
        if existing and old_value == value:
            continue
        if not existing and value is None:
            continue
        changes.append({"field": existing[1] if existing else key, "before": old_value, "after": value})
        if existing:
            replacements[existing[0]] = None if value is None else f"{existing[1]}: {value}{newline}"
        else:
            additions.append(f"{key}: {value}{newline}")
    output = []
    for index, line in enumerate(lines):
        if index == end:
            output.extend(additions)
        if index in replacements:
            if replacements[index] is not None:
                output.append(replacements[index])
        else:
            output.append(line)
    after_text = "".join(output)
    after = after_text.encode("utf-8")
    path_name = readme.relative_to(root).as_posix()
    actions = []
    if after != before:
        actions.append({"id": "metadata:" + path_name, "type": "replace_file", "file_path": path_name,
                        "before_sha256": sha256(before).hexdigest(), "after_sha256": sha256(after).hexdigest(),
                        "content": after_text, "input_fingerprints": {proposed_path.relative_to(root).as_posix(): sha256(proposed_path.read_bytes()).hexdigest()},
                        "depends_on": [], "diff": "".join(difflib.unified_diff(text.splitlines(keepends=True), after_text.splitlines(keepends=True), fromfile=path_name, tofile=path_name))})
    return {"schema_version": "ud-plan-v1", "plan_type": "metadata_change", "changes": changes, "actions": actions,
            "validation": {"status": "not_run", "reason": "candidate requires broker and UD metadata validation before apply"},
            "limitations": ["The plan changes local metadata only and does not register or certify release metadata."]}
