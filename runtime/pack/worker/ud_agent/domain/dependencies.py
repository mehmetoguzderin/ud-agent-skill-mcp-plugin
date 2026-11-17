"""Basic dependency and enhanced graph candidate edits."""
from __future__ import annotations

from typing import Any
from ..conllu.core import EMPTY, WORD, edit_sentence, format_edges, parse_edges, token_id, as_edge


def _node_exists(sent: Any, ident: str) -> bool:
    return ident == "0" or any(row[0] == ident and (WORD.fullmatch(ident) or EMPTY.fullmatch(ident)) for _, row in sent.rows())


def set_basic(sent: Any, ident: str, head_id: str | None, deprel: str) -> dict[str, Any]:
    if not isinstance(deprel, str) or not deprel or any(c in deprel for c in "|\t\r\n"):
        raise ValueError("invalid dependency relation")
    index, row = sent.get_row(ident, "word")
    head = row[6] if head_id is None else str(head_id)
    if head != "0" and (not WORD.fullmatch(head) or not _node_exists(sent, head)):
        raise ValueError("basic head must name an existing word or root")
    if head == ident:
        raise ValueError("a word cannot be its own head")
    if (head == "0") != (deprel == "root"):
        raise ValueError("root relation and zero head must be used together")
    parents = {cells[0]: cells[6] for _, cells in sent.rows() if WORD.fullmatch(cells[0])}
    parents[ident] = head
    current, seen = head, {ident}
    while current != "0" and current in parents:
        if current in seen:
            raise ValueError("basic dependency would create a cycle")
        seen.add(current)
        current = parents[current]
    row[6], row[7] = head, deprel
    sent.set_row(index, row)
    return {"token_id": ident, "head_id": head, "deprel": deprel}


def basic_dependency_set(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: set_basic(sent, token_id(args), str(args["head_id"]), args["deprel"]))


def basic_dependency_label_set(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: set_basic(sent, token_id(args), None, args["deprel"]))


def edit_edges(sent: Any, dependent: str, action: str, edges: list[tuple[str, str]]) -> dict[str, Any]:
    index, row = sent.get_row(dependent)
    if not WORD.fullmatch(dependent) and not EMPTY.fullmatch(dependent):
        raise ValueError("enhanced dependent must be a word or empty node")
    old = parse_edges(row[8])
    if any(not _node_exists(sent, head) or head == dependent for head, _ in edges):
        raise ValueError("enhanced head must exist and differ from dependent")
    if action == "replace":
        new = edges
    elif action == "add":
        if any(edge in old for edge in edges):
            raise ValueError("enhanced edge already exists")
        new = old + edges
    elif action == "remove":
        if any(edge not in old for edge in edges):
            raise ValueError("enhanced edge does not exist")
        new = [edge for edge in old if edge not in edges]
    else:
        raise ValueError("unknown edge action")
    if len(new) != len(set(new)):
        raise ValueError("duplicate enhanced edge")
    row[8] = format_edges(new)
    sent.set_row(index, row)
    return {"dependent_id": dependent, "edges": [{"head_id": h, "deprel": r} for h, r in new]}


def enhanced_edge_add(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: edit_edges(sent, str(args["dependent_id"]), "add", [as_edge(args)]))


def enhanced_edge_remove(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: edit_edges(sent, str(args["dependent_id"]), "remove", [as_edge(args)]))


def enhanced_dependencies_replace(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: edit_edges(sent, str(args["dependent_id"]), "replace", [as_edge(edge) for edge in args["incoming_edges"]]))
