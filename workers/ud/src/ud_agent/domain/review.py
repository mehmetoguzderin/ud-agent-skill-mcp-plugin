"""Compare explicitly supplied base snapshots and prepare safe patch candidates."""
from __future__ import annotations
import difflib
from hashlib import sha256
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any

from ._common import files_for, require_no_options, root_path, scoped_path
from ..errors import InvalidInput
from ..evidence import git_base, staged_git_base


def _hash(data: bytes) -> str:
    return sha256(data).hexdigest()


def _relative(value: str) -> str:
    if not isinstance(value, str) or not value or PurePosixPath(value).is_absolute() or PureWindowsPath(value).drive:
        raise InvalidInput("patch paths must be relative")
    if any(part in (".", "..") for part in PurePosixPath(value).parts) or "\\" in value or "\x00" in value:
        raise InvalidInput("patch paths cannot contain traversal")
    return value


def changes_review(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    revision = args.get("base_revision")
    if not isinstance(revision, str) or not revision:
        raise InvalidInput("base_revision must be a nonempty string")
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"base_snapshot_path", "file_paths"}:
        raise InvalidInput("options require a broker-supplied base snapshot path")
    trusted = staged_git_base(revision)
    snapshot_name = options.get("base_snapshot_path", trusted.get("base_snapshot_path") if trusted else None)
    snapshot_path = scoped_path(root, snapshot_name)
    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeError) as exc:
        raise InvalidInput("base snapshot must be a UTF-8 JSON document") from exc
    if not isinstance(snapshot, dict) or set(snapshot) != {"revision", "files"} or snapshot["revision"] != revision or not isinstance(snapshot["files"], dict):
        raise InvalidInput("base snapshot does not match the requested revision")
    base_files = {}
    for name, item in snapshot["files"].items():
        _relative(name)
        if not name.endswith(".conllu") or not isinstance(item, dict) or set(item) != {"sha256", "content"} or not isinstance(item["content"], str):
            raise InvalidInput("base snapshot contains an unsupported file entry")
        if item["sha256"] != _hash(item["content"].encode("utf-8")):
            raise InvalidInput("base snapshot content fingerprint mismatch")
        base_files[name] = item["content"]
    attestation = git_base(revision, {name: (_hash(content.encode("utf-8")), len(content.encode("utf-8"))) for name, content in base_files.items()},
                           snapshot_path=snapshot_name, snapshot_sha256=_hash(snapshot_path.read_bytes()))
    selection = options.get("file_paths")
    _, files = files_for({"working_tree_path": str(root), "file_paths": selection})
    current = {path.relative_to(root).as_posix(): path.read_bytes().decode("utf-8", errors="strict") for path in files}
    if selection is not None:
        base_files = {name: content for name, content in base_files.items() if name in selection}
    changes = []
    for name in sorted(set(base_files) | set(current)):
        before, after = base_files.get(name), current.get(name)
        if before == after:
            continue
        change_type = "added" if before is None else "deleted" if after is None else "modified"
        changes.append({"file_path": name, "change": change_type,
                        "base_sha256": _hash(before.encode("utf-8")) if before is not None else None,
                        "current_sha256": _hash(after.encode("utf-8")) if after is not None else None,
                        "diff": "".join(difflib.unified_diff((before or "").splitlines(keepends=True), (after or "").splitlines(keepends=True), fromfile="base/" + name, tofile="current/" + name))})
    return {"base_revision": revision, "changes": changes,
            "coverage": {"scope": "CoNLL-U files", "base_identity_verified": attestation is not None},
            "provenance": {"base_snapshot_sha256": _hash(snapshot_path.read_bytes()), "base_identity": attestation or "caller supplied"},
            "limitations": ([] if attestation else ["The broker must verify that the supplied snapshot corresponds to the requested Git revision."])
                            + ["Validation and non-CoNLL-U repository changes are not included in this comparison."]}


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)\n?$")


def contribution_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Prepare exact, fingerprinted candidates for ordinary unified patches."""
    from .plans import _destination
    root = root_path(args)
    patch_path = scoped_path(root, args.get("patch_path"))
    require_no_options(args)
    patch_bytes = patch_path.read_bytes()
    if len(patch_bytes) > 16 * 1024 * 1024:
        raise InvalidInput("patch exceeds the bounded plan size")
    try:
        raw_lines = patch_bytes.decode("utf-8", errors="strict").splitlines(keepends=True)
    except UnicodeError as exc:
        raise InvalidInput("patch must be UTF-8") from exc
    # Unified diff's marker describes the preceding content line. Preserve its
    # exact newline state before matching either side of a hunk.
    lines = []
    for line in raw_lines:
        if line.rstrip("\r\n") == "\\ No newline at end of file":
            if not lines or not lines[-1].startswith((" ", "+", "-")) or lines[-1].startswith(("--- ", "+++ ")) or not lines[-1].endswith("\n"):
                raise InvalidInput("misplaced patch missing-newline marker")
            lines[-1] = lines[-1][:-2] if lines[-1].endswith("\r\n") else lines[-1][:-1]
        else:
            lines.append(line)
    actions = []
    seen = set()
    fingerprint = {patch_path.relative_to(root).as_posix(): _hash(patch_bytes)}
    pending = {}
    def reserve(old, new):
        names = {name for name in (old, new) if name is not None}
        if names & seen:
            raise InvalidInput("patch repeats a source or destination path")
        seen.update(names)
        if len(seen) > 2000:
            raise InvalidInput("patch exceeds the file action limit")
    def original_file(name):
        target = scoped_path(root, name)
        if target.stat().st_size > 64 * 1024 * 1024:
            raise InvalidInput("patched file exceeds the size limit")
        return target.read_bytes()
    def append_action(old, new, before, content=None):
        common = {"id": "apply_patch:" + (old or new), "input_fingerprints": fingerprint, "depends_on": []}
        if old is None:
            actions.append({**common, "type": "create_file", "file_path": new, "before_sha256": None,
                            "after_sha256": _hash(content.encode("utf-8")), "content": content})
        elif new is None:
            actions.append({**common, "type": "delete_file", "file_path": old,
                            "before_sha256": _hash(before), "after_sha256": None})
        elif old != new:
            action = {**common, "type": "rename_file", "file_path": old, "target_file_path": new,
                      "before_sha256": _hash(before), "target_before_sha256": None}
            if content is not None and content.encode("utf-8") != before:
                action.update(after_sha256=_hash(content.encode("utf-8")), content=content)
            actions.append(action)
        else:
            original = before.decode("utf-8", errors="strict")
            actions.append({**common, "type": "replace_file", "file_path": old,
                            "before_sha256": _hash(before), "after_sha256": _hash(content.encode("utf-8")),
                            "content": content, "diff": "".join(difflib.unified_diff(original.splitlines(keepends=True), content.splitlines(keepends=True), fromfile=old, tofile=old))})
    def flush_rename():
        if not pending:
            return
        if set(pending) - {"old", "new", "similarity"} or not pending.get("old") or not pending.get("new") or pending.get("similarity") != 100:
            raise InvalidInput("rename metadata requires an exact unchanged source or complete hunks")
        old, new = pending["old"], pending["new"]
        if old == new:
            raise InvalidInput("rename source and destination must differ")
        reserve(old, new)
        _destination(root, new)
        append_action(old, new, original_file(old))
        pending.clear()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git "):
            flush_rename()
            i += 1
            continue
        if line.startswith("index "):
            i += 1
            continue
        if line.startswith("similarity index "):
            value = re.fullmatch(r"similarity index (\d+)%\r?\n?", line)
            if value is None or int(value.group(1)) > 100 or "similarity" in pending:
                raise InvalidInput("invalid patch similarity metadata")
            pending["similarity"] = int(value.group(1))
            i += 1
            continue
        if line.startswith(("rename from ", "rename to ")):
            key, offset = ("old", 12) if line.startswith("rename from ") else ("new", 10)
            if key in pending:
                raise InvalidInput("duplicate patch rename metadata")
            pending[key] = _relative(line[offset:].rstrip("\r\n"))
            i += 1
            continue
        if line.startswith(("new file mode ", "deleted file mode ")):
            # New regular files receive broker-owned private permissions;
            # executable/mode changes require a separate metadata contract.
            mode = line.rstrip("\r\n").rsplit(" ", 1)[-1]
            if mode != "100644":
                raise InvalidInput("patch file modes require the ordinary non-executable file profile")
            i += 1
            continue
        if not line.startswith("--- ") or i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
            raise InvalidInput("unsupported patch header or mode change")
        old_header = line[4:].rstrip("\r\n").split("\t", 1)[0]
        new_header = lines[i + 1][4:].rstrip("\r\n").split("\t", 1)[0]
        old_path = None if old_header == "/dev/null" else _relative(old_header[2:] if old_header.startswith("a/") else old_header)
        new_path = None if new_header == "/dev/null" else _relative(new_header[2:] if new_header.startswith("b/") else new_header)
        if old_path is None and new_path is None:
            raise InvalidInput("patch cannot have two absent file paths")
        if pending and (pending.get("old") != old_path or pending.get("new") != new_path):
            raise InvalidInput("patch rename metadata disagrees with file headers")
        pending.clear()
        reserve(old_path, new_path)
        if old_path is None or old_path != new_path:
            _destination(root, new_path) if new_path is not None else None
        original_bytes = b"" if old_path is None else original_file(old_path)
        try:
            original = original_bytes.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise InvalidInput("patched file must be UTF-8") from exc
        source_lines = original.splitlines(keepends=True)
        result = []
        cursor = 0
        i += 2
        hunk_count = 0
        while i < len(lines) and lines[i].startswith("@@ "):
            match = _HUNK.match(lines[i])
            if not match:
                raise InvalidInput("invalid unified diff hunk header")
            old_start = int(match.group(1))
            old_count = int(match.group(2) or "1")
            new_start = int(match.group(3))
            new_count = int(match.group(4) or "1")
            start = old_start if old_count == 0 else old_start - 1
            if start < cursor or start > len(source_lines):
                raise InvalidInput("patch hunks overlap or have an invalid location")
            result.extend(source_lines[cursor:start])
            expected_new_start = len(result) + (1 if new_count else 0)
            if new_start != expected_new_start:
                raise InvalidInput("patch hunk new-file location is inconsistent")
            cursor = start
            i += 1
            observed_old = observed_new = 0
            while i < len(lines) and (observed_old < old_count or observed_new < new_count):
                part = lines[i]
                if not part or part[0] not in " +-":
                    raise InvalidInput("unsupported patch line or missing newline marker")
                content = part[1:]
                if part[0] in " -":
                    if cursor >= len(source_lines) or source_lines[cursor] != content:
                        raise InvalidInput("patch does not match the exact current file")
                    cursor += 1
                    observed_old += 1
                if part[0] in " +":
                    result.append(content)
                    observed_new += 1
                if observed_old > old_count or observed_new > new_count:
                    raise InvalidInput("patch hunk exceeds its declared line counts")
                i += 1
            if observed_old != old_count or observed_new != new_count:
                raise InvalidInput("patch hunk line counts do not match its header")
            hunk_count += 1
        if not hunk_count:
            raise InvalidInput("patch file has no hunks")
        result.extend(source_lines[cursor:])
        content = "".join(result)
        if len(content.encode("utf-8")) > 64 * 1024 * 1024:
            raise InvalidInput("patched result exceeds the size limit")
        if new_path is None and content != "":
            raise InvalidInput("a deletion patch must remove the complete original file")
        append_action(old_path, new_path, original_bytes, content)
    flush_rename()
    if not actions:
        raise InvalidInput("patch contains no file changes")
    return {"schema_version": "ud-plan-v1", "plan_type": "contribution", "actions": actions,
            "external_requirements": ["Any upstream contribution or publication requires its separate authorized workflow."],
            "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"},
            "limitations": ["Unified text hunks and exact byte-preserving renames are supported; binary patches and filesystem mode changes require a separate metadata contract."]}
