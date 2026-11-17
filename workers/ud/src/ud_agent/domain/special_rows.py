"""Multiword ranges, empty nodes, and global ID reindexing."""
from __future__ import annotations

import re
from typing import Any
from ..conllu.core import (COLUMNS, EMPTY, MWT, WORD, as_edge, edit_sentence, format_attrs,
                           format_edges, parse_edges, row_from_data)
from ..conllu.remap import ensure_no_opaque_references, remap_sentence
from .dependencies import _node_exists


def multiword_token_add(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        first, last = int(args["first_word_id"]), int(args["last_word_id"])
        if first < 1 or last <= first:
            raise ValueError("multiword token requires at least two word IDs")
        words = {int(row[0]) for _, row in sent.rows() if WORD.fullmatch(row[0])}
        if not set(range(first, last + 1)) <= words:
            raise ValueError("all multiword component words must exist")
        for _, row in sent.rows():
            match = MWT.fullmatch(row[0])
            if match and first <= int(match.group(2)) and last >= int(match.group(1)):
                raise ValueError("overlapping multiword ranges are not allowed")
        index, _ = sent.get_row(str(first), "word")
        row = [f"{first}-{last}", str(args["form"]), "_", "_", "_", "_", "_", "_", "_", format_attrs(args.get("misc_entries", {}), allow_opaque=True)]
        sent.insert_row(index, row)
        return {"range_id": row[0]}
    return edit_sentence(args, apply)


def multiword_token_edit(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ident = str(args["range_id"])
        index, row = sent.get_row(ident, "multiword")
        patch = args["multiword_token_patch"]
        if not isinstance(patch, dict) or not patch or not set(patch) <= {"form", "misc"}:
            raise ValueError("multiword patch accepts form and misc")
        if "form" in patch:
            row[1] = str(patch["form"])
        if "misc" in patch:
            row[9] = format_attrs(patch["misc"], allow_opaque=True)
        sent.set_row(index, row)
        return {"range_id": ident}
    return edit_sentence(args, apply)


def multiword_token_remove(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ident = str(args["range_id"])
        index, _ = sent.get_row(ident, "multiword")
        sent.lines.pop(index)
        sent.changed = True
        return {"removed_range_id": ident}
    return edit_sentence(args, apply)


def empty_node_add(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        after = str(args["after_word_id"])
        if after != "0":
            sent.get_row(after, "word")
        data = dict(args["empty_node_data"])
        existing = [int(m.group(2)) for _, row in sent.rows() if (m := EMPTY.fullmatch(row[0])) and m.group(1) == after]
        ident = str(data.pop("id", f"{after}.{max(existing, default=0) + 1}"))
        match = EMPTY.fullmatch(ident)
        if not match or match.group(1) != after or int(match.group(2)) in existing:
            raise ValueError("invalid or duplicate empty-node ID")
        edges = [as_edge(edge) for edge in args["enhanced_edges"]]
        if any(not _node_exists(sent, h) for h, _ in edges):
            raise ValueError("enhanced head does not exist")
        data["deps"] = format_edges(edges)
        data["head"] = data["deprel"] = "_"
        row = row_from_data(data, ident)
        index = len(sent.lines)
        for candidate_index, cells in sent.rows():
            candidate = cells[0]
            empty_match = EMPTY.fullmatch(candidate)
            multi_match = MWT.fullmatch(candidate)
            if WORD.fullmatch(candidate) and int(candidate) > int(after):
                index = candidate_index
                break
            if multi_match and int(multi_match.group(1)) > int(after):
                index = candidate_index
                break
            if empty_match and (int(empty_match.group(1)) > int(after) or (empty_match.group(1) == after and int(empty_match.group(2)) > int(match.group(2)))):
                index = candidate_index
                break
        sent.insert_row(index, row)
        return {"empty_node_id": ident}
    return edit_sentence(args, apply)


def empty_node_edit(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ident = str(args["empty_node_id"])
        index, row = sent.get_row(ident, "empty")
        patch = args["empty_node_patch"]
        allowed = {"form", "lemma", "upos", "xpos", "feats", "deps", "misc"}
        if not isinstance(patch, dict) or not patch or not set(patch) <= allowed:
            raise ValueError("invalid empty-node patch")
        for key, value in patch.items():
            if key in ("feats", "misc"):
                value = format_attrs(value, allow_opaque=key == "misc")
            elif key == "deps" and isinstance(value, list):
                edges = [as_edge(edge) for edge in value]
                if any(not _node_exists(sent, h) or h == ident for h, _ in edges):
                    raise ValueError("invalid enhanced head")
                value = format_edges(edges)
            else:
                value = "_" if value is None else str(value)
            row[COLUMNS.index(key)] = value
        sent.set_row(index, row)
        return {"empty_node_id": ident}
    return edit_sentence(args, apply)


def empty_node_remove(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ident = str(args["empty_node_id"])
        index, _ = sent.get_row(ident, "empty")
        incoming_refs = [(i, row) for i, row in sent.rows() if i != index and any(h == ident for h, _ in parse_edges(row[8]))]
        policy = args["incident_edge_policy"]
        if incoming_refs and policy != "remove":
            raise ValueError("incident enhanced edges require explicit remove policy")
        for i, row in incoming_refs:
            row[8] = format_edges([(h, rel) for h, rel in parse_edges(row[8]) if h != ident])
            sent.set_row(i, row)
        sent.lines.pop(index)
        sent.changed = True
        return {"removed_empty_node_id": ident, "removed_incident_edges": len(incoming_refs)}
    return edit_sentence(args, apply)


def tree_reindex(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ensure_no_opaque_references(sent)
        old_ids = [row[0] for _, row in sent.rows() if WORD.fullmatch(row[0])]
        mapping = {old: str(index + 1) for index, old in enumerate(old_ids)}
        remap_sentence(sent, mapping)
        return {"id_mapping": mapping}
    return edit_sentence(args, apply)
