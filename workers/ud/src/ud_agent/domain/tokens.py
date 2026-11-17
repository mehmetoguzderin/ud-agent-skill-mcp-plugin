"""Word-level CoNLL-U operations; writes are returned as broker candidates."""
from __future__ import annotations

from typing import Any
from ..conllu.core import (COLUMNS, WORD, doc_for, edit_sentence, format_attrs, parse_attrs,
                           row_dict, row_from_data, token_id, tree_ref)
from ..conllu.remap import ensure_no_opaque_references, remap_sentence, replacement_heads


def token_list(args: dict[str, Any]) -> dict[str, Any]:
    doc = doc_for(args)
    _, sent = doc.find(tree_ref(args))
    return {"tokens": [row_dict(cells) for _, cells in sent.rows() if WORD.fullmatch(cells[0])]}


def token_get(args: dict[str, Any]) -> dict[str, Any]:
    doc = doc_for(args)
    _, sent = doc.find(tree_ref(args))
    _, cells = sent.get_row(token_id(args), "word")
    return {"token": row_dict(cells)}


def patch_token(sent: Any, ident: str, patch: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(patch, dict) or not patch:
        raise ValueError("token_patch must be a nonempty object")
    index, row = sent.get_row(ident, "word")
    allowed = set(COLUMNS[1:])
    if not set(patch) <= allowed:
        raise ValueError("token patch contains unsupported fields")
    for key, value in patch.items():
        if key in ("feats", "misc"):
            value = format_attrs(value, allow_opaque=key == "misc")
        elif value is None:
            value = "_"
        else:
            value = str(value)
        row[COLUMNS.index(key)] = value
    sent.set_row(index, row)
    return {"token_id": ident, "token": row_dict(row)}


def _set(args: dict[str, Any], key: str, value: Any) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: patch_token(sent, token_id(args), {key: value}))


def token_form_set(args: dict[str, Any]) -> dict[str, Any]:
    return _set(args, "form", args["form"])


def token_lemma_set(args: dict[str, Any]) -> dict[str, Any]:
    return _set(args, "lemma", args["lemma"])


def token_upos_set(args: dict[str, Any]) -> dict[str, Any]:
    return _set(args, "upos", args["upos"])


def token_xpos_set(args: dict[str, Any]) -> dict[str, Any]:
    return _set(args, "xpos", args["xpos"])


def token_features_replace(args: dict[str, Any]) -> dict[str, Any]:
    return _set(args, "feats", args["features"])


def token_misc_replace(args: dict[str, Any]) -> dict[str, Any]:
    return _set(args, "misc", args["misc_entries"])


def _attribute(args: dict[str, Any], column: str, name: str, value: Any, remove: bool = False) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ident = token_id(args)
        index, row = sent.get_row(ident, "word")
        attrs = parse_attrs(row[COLUMNS.index(column)], allow_opaque=column == "misc")
        if not isinstance(name, str) or not name:
            raise ValueError("attribute name required")
        if remove:
            attrs.pop(name, None)
        else:
            attrs[name] = ",".join(map(str, value)) if isinstance(value, list) else str(value)
        row[COLUMNS.index(column)] = format_attrs(attrs, allow_opaque=column == "misc")
        sent.set_row(index, row)
        return {"token_id": ident, "token": row_dict(row)}
    return edit_sentence(args, apply)


def token_feature_set(args: dict[str, Any]) -> dict[str, Any]:
    return _attribute(args, "feats", args["feature_name"], args["feature_values"])


def token_feature_remove(args: dict[str, Any]) -> dict[str, Any]:
    return _attribute(args, "feats", args["feature_name"], None, True)


def token_misc_set(args: dict[str, Any]) -> dict[str, Any]:
    return _attribute(args, "misc", args["attribute_name"], args["attribute_values"])


def token_misc_remove(args: dict[str, Any]) -> dict[str, Any]:
    return _attribute(args, "misc", args["attribute_name"], None, True)


def token_add(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ensure_no_opaque_references(sent)
        words = [int(row[0]) for _, row in sent.rows() if WORD.fullmatch(row[0])]
        position = args.get("insertion_point")
        if isinstance(position, dict):
            if "before_word_id" in position:
                position = int(position["before_word_id"])
            elif "after_word_id" in position:
                position = int(position["after_word_id"]) + 1
            else:
                raise ValueError("insertion_point needs before_word_id or after_word_id")
        if position is None:
            position = len(words) + 1
        position = int(position)
        if position < 1 or position > len(words) + 1 or sorted(words) != list(range(1, len(words) + 1)):
            raise ValueError("insertion requires contiguous word IDs and a valid insertion point")
        mapping = {str(i): str(i + 1) for i in words if i >= position}
        remap_sentence(sent, mapping)
        data = dict(args["token_data"])
        attachment = args.get("attachment_spec")
        if not isinstance(attachment, dict) or "head_id" not in attachment or "deprel" not in attachment:
            raise ValueError("attachment_spec requires an explicit head_id and deprel")
        head = str(attachment["head_id"])
        data["head"] = mapping.get(head, head)
        data["deprel"] = attachment["deprel"]
        row = row_from_data(data, str(position))
        rows = sent.rows()
        insert_at = next((index for index, cells in rows if WORD.fullmatch(cells[0]) and int(cells[0]) > position), len(sent.lines))
        sent.insert_row(insert_at, row)
        from .dependencies import set_basic
        set_basic(sent, str(position), str(data["head"]), str(data["deprel"]))
        return {"token_id": str(position), "id_mapping": mapping}
    return edit_sentence(args, apply)


def token_remove(args: dict[str, Any]) -> dict[str, Any]:
    def apply(sent: Any) -> dict[str, Any]:
        ensure_no_opaque_references(sent)
        ident = token_id(args)
        sent.get_row(ident, "word")
        spec = args.get("removal_spec")
        if not isinstance(spec, dict):
            raise ValueError("removal_spec is required")
        words = [int(row[0]) for _, row in sent.rows() if WORD.fullmatch(row[0])]
        if sorted(words) != list(range(1, len(words) + 1)):
            raise ValueError("word IDs must be contiguous before removal")
        mapping = {str(i): str(i - 1) for i in words if i > int(ident)}
        heads = replacement_heads(spec.get("dependent_heads", {}))
        remap_sentence(sent, mapping, {ident}, heads, spec.get("enhanced_edges") == "remove", spec.get("multiword_tokens") == "remove")
        return {"removed_token_id": ident, "id_mapping": mapping}
    return edit_sentence(args, apply)
