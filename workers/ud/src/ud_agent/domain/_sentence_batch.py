"""Snapshot-bound sentence and structural edits composed in private scratch."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
from typing import Any

from ..conllu.core import Document, EMPTY, MWT, digest, parse_edges, format_edges, require_preconditions, tree_ref
from ._common import files_for
from ._batch_engine import MAX_BATCH_BYTES, MAX_BATCH_FILES, ROW_FIELDS

SENTENCE_OPERATIONS = {"tree_add", "tree_replace", "tree_remove", "tree_copy", "tree_move", "tree_id_set", "tree_split", "trees_merge"}


def compose(args: dict[str, Any], entries: list[tuple[dict[str, Any], str]], allowed: set[str]) -> dict[str, Any]:
    documents, states, bound, tree_aliases, row_aliases = {}, {}, [], {}, {}
    total = 0

    def document(file):
        nonlocal total
        if file not in documents:
            if len(documents) >= MAX_BATCH_FILES:
                raise ValueError("edit batch exceeds the file limit")
            value = Document(args["working_tree_path"], file)
            total += len(value.before)
            if total > MAX_BATCH_BYTES:
                raise ValueError("edit batch exceeds its byte limit")
            documents[file] = value
        return documents[file]

    def bind(ref, supplied):
        if not isinstance(ref, dict):
            raise ValueError("batch tree reference must be an object")
        if set(ref) == {"temporary_id"}:
            if not isinstance(ref["temporary_id"], str) or not ref["temporary_id"].startswith("$"):
                raise ValueError("temporary tree reference must start with $")
            return ("temporary", ref["temporary_id"])
        value = document(ref.get("file_path"))
        index, sentence = value.find(ref)
        require_preconditions(supplied, value, sentence)
        key = (value.file_path, index)
        states.setdefault(key, {"file": value.file_path, "index": index, "alive": True,
                                "original_sent_id": sentence.metadata("sent_id")[0] if len(sentence.metadata("sent_id")) == 1 else None,
                                "rows": {row[0]: row[0] for _, row in sentence.rows()}})
        return key

    for supplied, name in entries:
        if name not in allowed:
            raise ValueError(f"unsupported batch operation: {name}")
        if name == "tree_add":
            document(supplied.get("file_path"))
            sources = []
        elif name == "trees_merge":
            refs = supplied.get("tree_refs")
            if not isinstance(refs, list) or len(refs) < 2:
                raise ValueError("trees_merge requires at least two references")
            sources = [bind(ref, supplied) for ref in refs]
        else:
            sources = [bind(tree_ref(supplied), supplied)]
        target_file = supplied.get("target_file_path") if name in {"tree_move", "tree_copy"} else supplied.get("file_path") if name == "tree_add" else None
        insertion = None
        if target_file is not None:
            target = document(target_file)
            point = supplied.get("insertion_point")
            if isinstance(point, dict) and ("before_sent_id" in point or "after_sent_id" in point):
                after = "after_sent_id" in point
                value = point["after_sent_id" if after else "before_sent_id"]
                insertion = (bind({"file_path": target_file, "sent_id": value}, supplied), after)
            elif isinstance(point, int) and not isinstance(point, bool) and 0 <= point < len(target.sentences):
                sentence = target.sentences[point]
                insertion = (bind({"file_path": target_file, "ordinal": point, "fingerprint": digest(sentence.original.encode())}, supplied), False)
        bound.append((supplied, name, sources, insertion))
    # Structural collision checking must see the complete captured corpus.
    if any(name in {"tree_split", "trees_merge"} for _, name in entries):
        root, paths = files_for({"working_tree_path": args["working_tree_path"]})
        for path in paths:
            document(path.relative_to(root).as_posix())

    def key_for(key):
        if key[0] == "temporary":
            key = tree_aliases.get(key[1])
        if key not in states or not states[key]["alive"]:
            raise ValueError("batch sentence reference was removed, split or not created")
        return key

    def same_location(key):
        state = states[key]
        return [other for other, value in states.items() if value["alive"] and value["file"] == state["file"] and value["index"] == state["index"]]

    def remove_at(file, index, preserved=()):
        for key, state in states.items():
            if not state["alive"] or state["file"] != file or key in preserved:
                continue
            if state["index"] == index:
                state["alive"] = False
            elif state["index"] > index:
                state["index"] -= 1

    def insert_at(file, index, count=1, preserved=()):
        for key, state in states.items():
            if state["alive"] and state["file"] == file and key not in preserved and state["index"] >= index:
                state["index"] += count

    def resolve_id(value, key):
        value = str(value)
        if value == "0":
            return value
        result = row_aliases.get((key, value)) if value.startswith("$") else states[key]["rows"].get(value)
        if not isinstance(result, str):
            raise ValueError(f"batch row reference was removed, split or not created: {value}")
        return result

    def translate(value, key, field=""):
        if field in ROW_FIELDS:
            return resolve_id(value, key)
        if field == "dependent_heads":
            if not isinstance(value, dict):
                raise ValueError("dependent_heads must be an object")
            return {resolve_id(old, key): resolve_id(new, key) for old, new in value.items()}
        if field == "token_ids":
            return [resolve_id(item, key) for item in value]
        if isinstance(value, list):
            return [translate(item, key) for item in value]
        if isinstance(value, dict):
            return {name: translate(item, key, name) for name, item in value.items()}
        return value

    details = []
    with tempfile.TemporaryDirectory(prefix="ud-sentence-batch-") as temporary:
        root = Path(temporary)
        for file, value in documents.items():
            target = root / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value.before)

        def current_ref(key):
            state = states[key]
            value = Document(str(root), state["file"])
            if not 0 <= state["index"] < len(value.sentences):
                raise ValueError("batch sentence location is inconsistent")
            sentence = value.sentences[state["index"]]
            result = {"file_path": state["file"], "ordinal": state["index"], "fingerprint": digest(sentence.original.encode("utf-8"))}
            ids = sentence.metadata("sent_id")
            if len(ids) == 1:
                result["sent_id"] = ids[0]
            return result, sentence

        def new_state(file, index):
            key = ("created", len(states), "state")
            sentence = Document(str(root), file).sentences[index]
            states[key] = {"file": file, "index": index, "alive": True,
                           "original_sent_id": sentence.metadata("sent_id")[0] if len(sentence.metadata("sent_id")) == 1 else None,
                           "rows": {row[0]: row[0] for _, row in sentence.rows()}}
            return key

        from ..dispatch import call
        for supplied, name, references, insertion in bound:
            keys = [key_for(key) for key in references]
            locations = [(states[key]["file"], states[key]["index"]) for key in keys]
            refs_sentences = [current_ref(key) for key in keys]
            entry = copy.deepcopy(supplied)
            entry["working_tree_path"] = str(root)
            if keys:
                entry["tree_ref"] = refs_sentences[0][0]
            if name == "trees_merge":
                entry["tree_refs"] = [pair[0] for pair in refs_sentences]
            elif keys and isinstance(entry.get("token_ref"), dict):
                token = entry["token_ref"]
                entry["token_ref"] = {"tree_ref": entry["tree_ref"], "token_id": resolve_id(token.get("token_id", token.get("word_id", token.get("id"))), keys[0])}
            if insertion is not None:
                anchor = states[key_for(insertion[0])]
                target_file = entry.get("target_file_path", entry.get("file_path"))
                if anchor["file"] != target_file:
                    raise ValueError("batch insertion anchor moved outside its target file")
                entry["insertion_point"] = anchor["index"] + int(insertion[1])
            if keys:
                for field in ROW_FIELDS | {"token_ids", "incoming_edges", "enhanced_edges", "edge_operations", "attachment_spec", "removal_spec"}:
                    if field in entry:
                        entry[field] = translate(entry[field], keys[0], field)
                if name not in SENTENCE_OPERATIONS and "insertion_point" in entry:
                    entry["insertion_point"] = translate(entry["insertion_point"], keys[0])
                for patch_name in ("token_patch", "empty_node_patch"):
                    patch = entry.get(patch_name)
                    if isinstance(patch, dict):
                        if patch.get("head") is not None:
                            patch["head"] = resolve_id(patch["head"], keys[0])
                        if isinstance(patch.get("deps"), list):
                            patch["deps"] = translate(patch["deps"], keys[0])
                if name in {"token_split", "tokens_merge", "tree_split", "trees_merge", "_tokenization_reconcile"} and isinstance(entry.get("annotation_map"), dict):
                    annotation = entry["annotation_map"]
                    if isinstance(annotation.get("id_mapping"), dict):
                        source_keys = {}
                        for key, pair in zip(keys, refs_sentences, strict=True):
                            ids = pair[1].metadata("sent_id")
                            if len(ids) != 1:
                                raise ValueError("batch structural edits require unambiguous sentence IDs")
                            source_keys[ids[0]] = (key, ids[0])
                            if states[key]["original_sent_id"] is not None:
                                source_keys[states[key]["original_sent_id"]] = (key, ids[0])
                        translated = {}
                        for source, targets in annotation["id_mapping"].items():
                            source_id, separator, row = source.partition("#")
                            if not separator or source_id not in source_keys:
                                raise ValueError("batch structural map refers to an unbound sentence")
                            key, current_id = source_keys[source_id]
                            translated[f"{current_id}#{resolve_id(row, key)}"] = targets
                        annotation["id_mapping"] = translated
            entry["edit_options"] = {**(entry.get("edit_options") or {}), "mode": "preview"}
            for field in ("expected_file_sha256", "expected_fingerprint", "expected_sentence_sha256"):
                entry["edit_options"].pop(field, None)
            if name == "_tokenization_reconcile":
                from .structural import _tokenization_reconcile
                result = _tokenization_reconcile(entry)
            else:
                result = call(name, entry)
            if result.get("status") == "needs_annotation":
                return {**result, "changes": [], "details": {"completed_operations": details, "operation": name}}
            if result.get("status") != "candidate":
                raise ValueError("batch edit did not return candidate files")
            for candidate in result.get("changes", []):
                file = candidate.get("file_path")
                if file not in documents or digest((root / file).read_bytes()) != candidate.get("before_sha256"):
                    raise ValueError("batch intermediate source is unbound or changed")
                content = candidate.get("content")
                if not isinstance(content, str) or len(content.encode("utf-8")) > 64 * 1024 * 1024 or digest(content.encode("utf-8")) != candidate.get("after_sha256"):
                    raise ValueError("batch intermediate candidate is invalid")
                (root / file).write_bytes(content.encode("utf-8"))
            if sum((root / file).stat().st_size for file in documents) > MAX_BATCH_BYTES:
                raise ValueError("batch intermediate snapshot exceeds its byte limit")
            detail = result.get("details", {})
            affected = same_location(keys[0]) if keys else []
            created_key = None
            if name == "tree_add":
                file, index = entry["file_path"], detail["inserted_ordinal"]
                insert_at(file, index)
                created_key = new_state(file, index)
            elif name == "tree_remove":
                remove_at(*locations[0])
            elif name in {"tree_move", "tree_copy"}:
                file, index = entry["target_file_path"], detail["target_ordinal"]
                if name == "tree_move":
                    remove_at(*locations[0], preserved=affected)
                    insert_at(file, index, preserved=affected)
                    for key in affected:
                        states[key].update(file=file, index=index)
                    created_key = keys[0]
                else:
                    insert_at(file, index)
                    created_key = new_state(file, index)
            elif name in {"tree_split", "trees_merge"}:
                source_names = [sentence.metadata("sent_id")[0] for _, sentence in refs_sentences]
                physical = sorted(set(locations), reverse=True)
                first_file, first_index = locations[0]
                destination = first_index - sum(file == first_file and index < first_index for file, index in physical)
                for file, index in physical:
                    remove_at(file, index)
                target_ids = detail["target_sentence_ids"]
                insert_at(first_file, destination, len(target_ids))
                created = [new_state(first_file, destination + index) for index in range(len(target_ids))]
                created_key = created[0] if len(created) == 1 else None
                if name == "trees_merge":
                    for key, source_id in zip(keys, source_names, strict=True):
                        state = states[key]
                        state.update(alive=True, file=first_file, index=destination)
                        state["rows"] = {old: (values[0].split("#", 1)[1] if len(values := detail["id_mapping"].get(f"{source_id}#{now}", [])) == 1 else None)
                                         for old, now in state["rows"].items()}
            elif keys:
                mapping = detail.get("id_mapping", {})
                removed = {str(detail[field]) for field in ("removed_token_id", "removed_empty_node_id", "removed_range_id") if field in detail}
                structural = any("#" in old for old in mapping)
                def remap(value):
                    if value is None or value in removed:
                        return None
                    if structural:
                        source_id = refs_sentences[0][1].metadata("sent_id")[0]
                        values = mapping.get(f"{source_id}#{value}", [])
                        return values[0].split("#", 1)[1] if len(values) == 1 else None
                    if match := EMPTY.fullmatch(value):
                        base, suffix = match.groups()
                        return None if base in removed else f"{mapping.get(base, base)}.{suffix}"
                    if match := MWT.fullmatch(value):
                        first, last = match.groups()
                        return None if any(str(i) in removed for i in range(int(first), int(last) + 1)) else f"{mapping.get(first, first)}-{mapping.get(last, last)}"
                    return mapping.get(value, value)
                if name == "tree_replace":
                    old_rows = {row[0]: row[1] for _, row in refs_sentences[0][1].rows()}
                    new_rows = {row[0]: row[1] for _, row in current_ref(keys[0])[1].rows()}
                    removed.update(row for row, form in old_rows.items() if new_rows.get(row) != form)
                for key in affected:
                    states[key]["rows"] = {old: remap(now) for old, now in states[key]["rows"].items()}
                    for alias_key in list(row_aliases):
                        if alias_key[0] == key:
                            row_aliases[alias_key] = remap(row_aliases[alias_key])
            temporary = supplied.get("temporary_id")
            if temporary is not None:
                if not isinstance(temporary, str) or not temporary.startswith("$"):
                    raise ValueError("temporary_id must start with $")
                if name in {"tree_add", "tree_copy", "tree_move", "trees_merge"}:
                    if created_key is None or temporary in tree_aliases:
                        raise ValueError("temporary tree identity is missing or duplicated")
                    tree_aliases[temporary] = created_key
                elif name in {"token_add", "empty_node_add", "multiword_token_add"}:
                    value = next((detail[field] for field in ("token_id", "empty_node_id", "range_id") if field in detail), None)
                    if (keys[0], temporary) in row_aliases or not isinstance(value, str):
                        raise ValueError("temporary row identity is missing or duplicated")
                    row_aliases[keys[0], temporary] = value
                else:
                    raise ValueError("temporary_id must name an operation creating an object")
            temporary_trees = supplied.get("temporary_tree_ids", {})
            if not isinstance(temporary_trees, dict):
                raise ValueError("temporary_tree_ids must map aliases to resulting sentence IDs")
            for alias, target in temporary_trees.items():
                if not isinstance(alias, str) or not alias.startswith("$") or alias in tree_aliases:
                    raise ValueError("temporary tree identity is invalid or duplicated")
                matches = [(file, index) for file in documents for index, sentence in enumerate(Document(str(root), file).sentences) if target in sentence.metadata("sent_id")]
                if len(matches) != 1:
                    raise ValueError("temporary tree target is missing or ambiguous")
                tree_aliases[alias] = new_state(*matches[0])
            row_key = created_key if created_key is not None else keys[0] if keys and states[keys[0]]["alive"] else None
            temporary_rows = supplied.get("temporary_ids", {})
            if not isinstance(temporary_rows, dict) or (temporary_rows and row_key is None):
                raise ValueError("temporary row aliases require one resulting sentence")
            for alias, target in temporary_rows.items():
                rows = {row[0] for _, row in current_ref(row_key)[1].rows()}
                if not isinstance(alias, str) or not alias.startswith("$") or (row_key, alias) in row_aliases or target not in rows:
                    raise ValueError("temporary row identity is invalid or absent")
                row_aliases[row_key, alias] = target
            details.append({"operation": name, "result": detail})
        changes = []
        for file, value in documents.items():
            after = (root / file).read_bytes()
            if after != value.before:
                changes.append({"file_path": file, "before_sha256": digest(value.before), "after_sha256": digest(after), "content": after.decode("utf-8")})
    return {"status": "candidate", "requested_mode": (args.get("edit_options") or {}).get("mode", "preview"), "requires_host_commit": bool(changes),
            "changes": changes, "details": {"operations": details}, "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"}}
