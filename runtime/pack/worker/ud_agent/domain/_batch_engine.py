"""Compose focused edits in a bounded private scratch snapshot.

All external references bind to the initial snapshot. Intermediate files are
worker-owned scratch; only final fingerprinted candidates leave this module.
"""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
from typing import Any

from ..conllu.core import Document, EMPTY, MWT, WORD, digest, require_preconditions, tree_ref

MAX_BATCH_FILES = 1000
MAX_BATCH_BYTES = 512 * 1024 * 1024
ROW_FIELDS = {"head_id", "dependent_id", "first_word_id", "last_word_id", "after_word_id", "before_word_id", "empty_node_id", "range_id"}


def compose(args: dict[str, Any], entries: list[tuple[dict[str, Any], str]], allowed: set[str]) -> dict[str, Any]:
    documents = {}
    bound = []
    identities = {}
    row_maps = {}
    total = 0
    for supplied, name in entries:
        if name not in allowed:
            raise ValueError(f"unsupported batch operation: {name}")
        ref = tree_ref(supplied)
        file = ref.get("file_path")
        if file not in documents:
            if len(documents) >= MAX_BATCH_FILES:
                raise ValueError("edit batch exceeds the file limit")
            doc = Document(args["working_tree_path"], file)
            total += len(doc.before)
            if total > MAX_BATCH_BYTES:
                raise ValueError("edit batch exceeds its byte limit")
            documents[file] = doc
        doc = documents[file]
        index, sentence = doc.find(ref)
        require_preconditions(supplied, doc, sentence)
        key = (file, index)
        identities[key] = ref
        row_maps.setdefault(key, {row[0]: row[0] for _, row in sentence.rows()})
        bound.append((supplied, name, key))
    aliases = {}
    results = []

    def resolve_id(value: Any, key: tuple[str, int]) -> str:
        value = str(value)
        if value == "0":
            return value
        if value.startswith("$"):
            target = aliases.get((key, value))
        else:
            target = row_maps[key].get(value)
        if not isinstance(target, str):
            raise ValueError(f"batch row reference was removed, ambiguous or not created: {value}")
        return target

    def translate(value: Any, key: tuple[str, int], field: str = "") -> Any:
        if field in ROW_FIELDS:
            return resolve_id(value, key)
        if field in {"token_ids"}:
            if not isinstance(value, list):
                raise ValueError("batch token_ids must be an array")
            return [resolve_id(item, key) for item in value]
        if field == "dependent_heads":
            if not isinstance(value, dict):
                raise ValueError("dependent_heads must be an object")
            return {resolve_id(old, key): resolve_id(new, key) for old, new in value.items()}
        if isinstance(value, list):
            return [translate(item, key) for item in value]
        if isinstance(value, dict):
            return {name: translate(item, key, name) for name, item in value.items()}
        return value

    def remapped(value: str, mapping: dict[str, str], removed: set[str]) -> str | None:
        if value in removed:
            return None
        if match := EMPTY.fullmatch(value):
            base, number = match.groups()
            if base in removed:
                return None
            return f"{mapping.get(base, base)}.{number}"
        if match := MWT.fullmatch(value):
            first, last = match.groups()
            if any(str(index) in removed for index in range(int(first), int(last) + 1)):
                return None
            return f"{mapping.get(first, first)}-{mapping.get(last, last)}"
        return mapping.get(value, value)

    with tempfile.TemporaryDirectory(prefix="ud-edit-batch-") as temporary:
        root = Path(temporary)
        for file, doc in documents.items():
            target = root / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(doc.before)
        from ..dispatch import call
        for supplied, name, key in bound:
            current = Document(str(root), key[0])
            _, current_sentence = current.find(identities[key])
            canonical_ref = {"file_path": key[0]}
            ids = current_sentence.metadata("sent_id")
            if len(ids) == 1:
                canonical_ref["sent_id"] = ids[0]
            else:
                canonical_ref.update(ordinal=key[1], fingerprint=digest(current_sentence.original.encode("utf-8")))
            entry = copy.deepcopy(supplied)
            entry["working_tree_path"] = str(root)
            entry["tree_ref"] = canonical_ref
            if isinstance(entry.get("token_ref"), dict):
                token = entry["token_ref"]
                original = token.get("token_id", token.get("word_id", token.get("id")))
                entry["token_ref"] = {"tree_ref": canonical_ref, "token_id": resolve_id(original, key)}
            for field in ROW_FIELDS | {"token_ids", "incoming_edges", "enhanced_edges", "edge_operations", "attachment_spec", "insertion_point", "removal_spec"}:
                if field in entry:
                    entry[field] = translate(entry[field], key, field)
            if isinstance(entry.get("token_patch"), dict):
                patch = entry["token_patch"]
                if "head" in patch and patch["head"] is not None:
                    patch["head"] = resolve_id(patch["head"], key)
                if isinstance(patch.get("deps"), list):
                    patch["deps"] = translate(patch["deps"], key)
            if isinstance(entry.get("empty_node_patch"), dict) and isinstance(entry["empty_node_patch"].get("deps"), list):
                entry["empty_node_patch"]["deps"] = translate(entry["empty_node_patch"]["deps"], key)
            if name in {"token_split", "tokens_merge"} and isinstance(entry.get("annotation_map"), dict):
                if len(ids) != 1:
                    raise ValueError("batch structural edit requires an unambiguous sentence ID")
                annotation = entry["annotation_map"]
                if isinstance(annotation.get("id_mapping"), dict):
                    translated = {}
                    for source, destinations in annotation["id_mapping"].items():
                        sentence_id, separator, row_id = source.partition("#")
                        if not separator or sentence_id != ids[0]:
                            raise ValueError("batch structural map must identify the bound source sentence")
                        translated[f"{sentence_id}#{resolve_id(row_id, key)}"] = destinations
                    annotation["id_mapping"] = translated
            # Preconditions were checked against the starting snapshot. The
            # scratch files intentionally contain earlier edits in this batch.
            entry["edit_options"] = {**(entry.get("edit_options") or {}), "mode": "preview"}
            for field in ("expected_file_sha256", "expected_fingerprint", "expected_sentence_sha256"):
                entry["edit_options"].pop(field, None)
            result = call(name, entry)
            if result.get("status") == "needs_annotation":
                return {**result, "details": {"operation": name, "completed_operations": results}, "changes": []}
            if result.get("status") != "candidate":
                raise ValueError("batch edit did not return candidate files")
            for candidate in result.get("changes", []):
                file = candidate.get("file_path")
                if file not in documents:
                    raise ValueError("batch edit attempted to change an unbound file")
                target = root / file
                if digest(target.read_bytes()) != candidate.get("before_sha256"):
                    raise ValueError("batch intermediate fingerprint mismatch")
                content = candidate.get("content")
                if not isinstance(content, str) or digest(content.encode("utf-8")) != candidate.get("after_sha256"):
                    raise ValueError("batch intermediate content fingerprint mismatch")
                encoded = content.encode("utf-8")
                if len(encoded) > 64 * 1024 * 1024:
                    raise ValueError("batch intermediate file exceeds its byte limit")
                target.write_bytes(encoded)
            if sum((root / file).stat().st_size for file in documents) > MAX_BATCH_BYTES:
                raise ValueError("batch intermediate snapshot exceeds its byte limit")
            detail = result.get("details", {})
            mapping = detail.get("id_mapping", {})
            if not isinstance(mapping, dict):
                raise ValueError("batch operation returned an invalid reference map")
            removed = {str(detail[field]) for field in ("removed_token_id", "removed_empty_node_id", "removed_range_id") if field in detail}
            ordinary_mapping = {old: new for old, new in mapping.items() if isinstance(old, str) and isinstance(new, str) and "#" not in old}
            structural_mapping = {old.split("#", 1)[1]: destinations[0].split("#", 1)[1] if len(destinations) == 1 else None
                                  for old, destinations in mapping.items() if isinstance(old, str) and "#" in old and isinstance(destinations, list)}
            if ordinary_mapping or removed:
                row_maps[key] = {old: remapped(now, ordinary_mapping, removed) if now is not None else None for old, now in row_maps[key].items()}
                for alias_key, value in list(aliases.items()):
                    if alias_key[0] == key:
                        aliases[alias_key] = remapped(value, ordinary_mapping, removed) if value is not None else None
            if structural_mapping:
                row_maps[key] = {old: structural_mapping.get(now) if now is not None else None for old, now in row_maps[key].items()}
                for alias_key, value in list(aliases.items()):
                    if alias_key[0] == key:
                        aliases[alias_key] = structural_mapping.get(value) if value is not None else None
            temporary_id = supplied.get("temporary_id")
            if temporary_id is not None:
                if not isinstance(temporary_id, str) or not temporary_id.startswith("$") or (key, temporary_id) in aliases:
                    raise ValueError("temporary_id must be a unique $-prefixed identifier")
                created = next((detail[field] for field in ("token_id", "empty_node_id", "range_id") if field in detail), None)
                if name not in {"token_add", "empty_node_add", "multiword_token_add"} or not isinstance(created, str):
                    raise ValueError("temporary_id is only supported for an operation creating a row")
                aliases[key, temporary_id] = created
            temporary_ids = supplied.get("temporary_ids", {})
            if not isinstance(temporary_ids, dict):
                raise ValueError("temporary_ids must map aliases to created target row IDs")
            current_rows = {row[0] for _, row in Document(str(root), key[0]).find(canonical_ref)[1].rows()}
            for alias, target in temporary_ids.items():
                if (not isinstance(alias, str) or not alias.startswith("$") or (key, alias) in aliases
                        or not isinstance(target, str) or target not in current_rows):
                    raise ValueError("temporary_ids contains a duplicate alias or missing target row")
                aliases[key, alias] = target
            results.append({"operation": name, "result": detail})
        changes = []
        for file, doc in documents.items():
            after = (root / file).read_bytes()
            if after != doc.before:
                changes.append({"file_path": file, "before_sha256": digest(doc.before), "after_sha256": digest(after), "content": after.decode("utf-8")})
    return {"status": "candidate", "requested_mode": (args.get("edit_options") or {}).get("mode", "preview"),
            "requires_host_commit": bool(changes), "changes": changes, "details": {"operations": results},
            "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"}}
