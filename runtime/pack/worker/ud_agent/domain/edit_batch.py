"""Shared broad edit adapters operating on the same candidate primitives."""
from __future__ import annotations

from typing import Any
from ..conllu.core import Document, as_edge, candidate_result, doc_for, edit_sentence, format_attrs, parse_attrs, parse_edges, require_preconditions, token_id, tree_ref
from .dependencies import edit_edges, set_basic
from .tokens import patch_token


def _patch(sent: Any, ident: str, patch: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(patch, dict) or not patch:
        raise ValueError("token_patch must be a nonempty object")
    patch = dict(patch)
    has_head = "head" in patch
    has_relation = "deprel" in patch
    head = patch.pop("head", None)
    relation = patch.pop("deprel", None)
    if (has_head and head is None) or (has_relation and relation is None):
        raise ValueError("basic dependency fields cannot be removed")
    has_deps = "deps" in patch
    deps = patch.pop("deps", None)
    result = patch_token(sent, ident, patch) if patch else {"token_id": ident}
    if head is not None or relation is not None:
        _, row = sent.get_row(ident, "word")
        result.update(set_basic(sent, ident, str(head) if head is not None else None, str(relation) if relation is not None else row[7]))
    if has_deps:
        if deps is None:
            edges = []
        elif isinstance(deps, list):
            edges = [as_edge(edge) for edge in deps]
        elif isinstance(deps, str):
            edges = parse_edges(deps)
        else:
            raise ValueError("deps must be a string, list or null")
        result.update(edit_edges(sent, ident, "replace", edges))
    return result


def token_edit(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: _patch(sent, token_id(args), args["token_patch"]))


def _metadata(sent: Any, patch: Any) -> dict[str, Any]:
    if not isinstance(patch, dict) or not patch:
        raise ValueError("metadata_patch must be a nonempty object")
    if "sent_id" in patch:
        raise ValueError("use tree_id_set to change sentence identity")
    for key, value in patch.items():
        if value is not None and not isinstance(value, str):
            raise ValueError("comment values must be strings or null")
        sent.set_metadata(key, value)
    return {"metadata_fields": list(patch)}


def tree_metadata_edit(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: _metadata(sent, args["metadata_patch"]))


def _graph(sent: Any, operations: Any) -> dict[str, Any]:
    if not isinstance(operations, list) or not operations:
        raise ValueError("edge_operations must be a nonempty array")
    results = []
    for op in operations:
        if not isinstance(op, dict) or op.get("action") not in {"add", "remove", "replace"}:
            raise ValueError("edge operation action must be add, remove or replace")
        action = op["action"]
        dep = str(op["dependent_id"])
        edges = [as_edge(edge) for edge in op.get("incoming_edges", [])] if action == "replace" else [as_edge(op)]
        results.append(edit_edges(sent, dep, action, edges))
    return {"edges": results}


def enhanced_graph_edit(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: _graph(sent, args["edge_operations"]))


def _entry(args: dict[str, Any], entry: Any, default_ref: dict[str, Any] | None = None) -> tuple[dict[str, Any], str]:
    if not isinstance(entry, dict):
        raise ValueError("each batch operation must be an object")
    operation = entry.get("operation", entry.get("type"))
    if not isinstance(operation, str):
        raise ValueError("batch operation name is required")
    supplied = entry.get("arguments", entry)
    if not isinstance(supplied, dict):
        raise ValueError("operation arguments must be an object")
    merged = {**args, **supplied}
    if "temporary_id" in entry:
        merged["temporary_id"] = entry["temporary_id"]
    if "temporary_ids" in entry:
        merged["temporary_ids"] = entry["temporary_ids"]
    if "temporary_tree_ids" in entry:
        merged["temporary_tree_ids"] = entry["temporary_tree_ids"]
    nested = supplied.get("token_ref")
    if "tree_ref" not in supplied and isinstance(nested, dict) and isinstance(nested.get("tree_ref"), dict):
        merged["tree_ref"] = nested["tree_ref"]
    elif "tree_ref" not in supplied and isinstance(nested, dict) and "file_path" in nested:
        merged["tree_ref"] = {key: nested[key] for key in ("file_path", "sent_id", "ordinal", "fingerprint") if key in nested}
    elif default_ref is not None and "tree_ref" not in supplied:
        merged["tree_ref"] = default_ref
    return merged, operation


SIMPLE_FIELDS = {
    "token_form_set": ("form", "form"),
    "token_lemma_set": ("lemma", "lemma"),
    "token_upos_set": ("upos", "upos"),
    "token_xpos_set": ("xpos", "xpos"),
    "token_features_replace": ("feats", "features"),
    "token_misc_replace": ("misc", "misc_entries"),
}
ATTRIBUTES = {
    "token_feature_set": ("feats", "feature_name", "feature_values", False),
    "token_feature_remove": ("feats", "feature_name", None, True),
    "token_misc_set": ("misc", "attribute_name", "attribute_values", False),
    "token_misc_remove": ("misc", "attribute_name", None, True),
}
EDGE_OPERATIONS = {"enhanced_edge_add", "enhanced_edge_remove", "enhanced_dependencies_replace"}
COMMENT_OPERATIONS = {"tree_text_set", "tree_comment_set", "tree_comment_remove"}
BASE_OPERATIONS = {"token_edit", "tree_metadata_edit", "enhanced_graph_edit", "basic_dependency_set", "basic_dependency_label_set"}
ROW_OPERATIONS = {"token_add", "token_remove", "multiword_token_add", "multiword_token_edit", "multiword_token_remove",
                  "empty_node_add", "empty_node_edit", "empty_node_remove", "tree_reindex", "token_split", "tokens_merge"}


def _run_batch(args: dict[str, Any], entries: Any, default_ref: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(entries, list) or not entries:
        raise ValueError("edit batch must be a nonempty array")
    if len(entries) > 1000:
        raise ValueError("edit batch exceeds the operation limit")
    expanded = [_entry(args, entry, default_ref) for entry in entries]
    from ._sentence_batch import SENTENCE_OPERATIONS
    if any(name in SENTENCE_OPERATIONS for _, name in expanded):
        from ._sentence_batch import compose
        return compose(args, expanded, BASE_OPERATIONS | ROW_OPERATIONS | SENTENCE_OPERATIONS | set(SIMPLE_FIELDS) | set(ATTRIBUTES) | EDGE_OPERATIONS | COMMENT_OPERATIONS)
    if any(name in ROW_OPERATIONS or "temporary_id" in merged for merged, name in expanded):
        from ._batch_engine import compose
        return compose(args, expanded, BASE_OPERATIONS | ROW_OPERATIONS | set(SIMPLE_FIELDS) | set(ATTRIBUTES) | EDGE_OPERATIONS | COMMENT_OPERATIONS)
    docs: dict[str, Document] = {}
    resolved = []
    for entry in entries:
        merged, name = _entry(args, entry, default_ref)
        if name not in BASE_OPERATIONS | set(SIMPLE_FIELDS) | set(ATTRIBUTES) | EDGE_OPERATIONS | COMMENT_OPERATIONS:
            raise ValueError(f"unsupported batch operation: {name}")
        ref = tree_ref(merged)
        path = ref.get("file_path")
        if path not in docs:
            docs[path] = Document(args["working_tree_path"], path)
        doc = docs[path]
        _, sent = doc.find(ref)
        require_preconditions(merged, doc, sent)
        if name in {"token_edit", "basic_dependency_set", "basic_dependency_label_set"} | set(SIMPLE_FIELDS) | set(ATTRIBUTES):
            sent.get_row(token_id(merged), "word")
        resolved.append((sent, name, merged))
    details = []
    for sent, name, merged in resolved:
        if name == "token_edit":
            result = _patch(sent, token_id(merged), merged["token_patch"])
        elif name == "tree_metadata_edit":
            result = _metadata(sent, merged["metadata_patch"])
        elif name == "enhanced_graph_edit":
            result = _graph(sent, merged["edge_operations"])
        elif name == "basic_dependency_set":
            result = set_basic(sent, token_id(merged), str(merged["head_id"]), merged["deprel"])
        elif name == "basic_dependency_label_set":
            result = set_basic(sent, token_id(merged), None, merged["deprel"])
        elif name in SIMPLE_FIELDS:
            field, parameter = SIMPLE_FIELDS[name]
            result = _patch(sent, token_id(merged), {field: merged[parameter]})
        elif name in ATTRIBUTES:
            field, key_param, value_param, remove = ATTRIBUTES[name]
            ident = token_id(merged)
            _, row = sent.get_row(ident, "word")
            column = 5 if field == "feats" else 9
            attrs = parse_attrs(row[column], allow_opaque=field == "misc")
            key = merged[key_param]
            if remove:
                attrs.pop(key, None)
            else:
                value = merged[value_param]
                attrs[key] = ",".join(map(str, value)) if isinstance(value, list) else str(value)
            result = _patch(sent, ident, {field: format_attrs(attrs, allow_opaque=field == "misc")})
        elif name in EDGE_OPERATIONS:
            action = {"enhanced_edge_add": "add", "enhanced_edge_remove": "remove", "enhanced_dependencies_replace": "replace"}[name]
            edges = [as_edge(edge) for edge in merged["incoming_edges"]] if action == "replace" else [as_edge(merged)]
            result = edit_edges(sent, str(merged["dependent_id"]), action, edges)
        elif name == "tree_text_set":
            result = _metadata(sent, {"text": merged["text"]})
        elif name == "tree_comment_set":
            result = _metadata(sent, {merged["comment_key"]: merged["comment_value"]})
        else:
            result = _metadata(sent, {merged["comment_key"]: None})
        details.append({"operation": name, "result": result})
    return candidate_result(args, list(docs.values()), {"operations": details})


def tree_edit(args: dict[str, Any]) -> dict[str, Any]:
    return _run_batch(args, args["edit_operations"], tree_ref(args))


def treebank_edit(args: dict[str, Any]) -> dict[str, Any]:
    return _run_batch(args, args["edit_batch"])
