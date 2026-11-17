"""Reference remapping for changed word IDs."""
from __future__ import annotations

from typing import Any
from .core import EMPTY, MWT, WORD, Sentence, format_edges, parse_edges


def remap_sentence(sent: Sentence, mapping: dict[str, str], removed: set[str] | None = None,
                   dependent_heads: dict[str, str] | None = None, drop_incident: bool = False,
                   remove_mwts: bool = False) -> None:
    removed = removed or set()
    dependent_heads = dependent_heads or {}
    original = sent.rows()
    result = []
    for _, cells in original:
        old = cells[0]
        if old in removed:
            continue
        multi = MWT.fullmatch(old)
        empty = EMPTY.fullmatch(old)
        if multi:
            first, last = multi.groups()
            members = {str(i) for i in range(int(first), int(last) + 1)}
            if members & removed:
                if remove_mwts:
                    continue
                raise ValueError("removing a word within a multiword token requires explicit removal policy")
            mapped = [int(mapping.get(str(i), str(i))) for i in range(int(first), int(last) + 1)]
            if mapped != list(range(mapped[0], mapped[-1] + 1)):
                raise ValueError("remapping would make a multiword range noncontiguous")
            cells[0] = f"{mapped[0]}-{mapped[-1]}"
        elif empty:
            base, decimal = empty.groups()
            if base in removed:
                raise ValueError("removing a word hosting an empty node requires an explicit structural map")
            cells[0] = f"{mapping.get(base, base)}.{decimal}"
        elif WORD.fullmatch(old):
            cells[0] = mapping.get(old, old)
        head = cells[6]
        if head in removed:
            if old not in dependent_heads:
                raise ValueError(f"dependent {old} needs explicit replacement head")
            head = str(dependent_heads[old])
            if head in removed:
                raise ValueError("replacement head is being removed")
        if head in mapping:
            cells[6] = mapping[head]
        else:
            cells[6] = head
        edges = []
        for edge_head, relation in parse_edges(cells[8]):
            base = edge_head.split(".", 1)[0]
            if edge_head in removed or base in removed:
                if not drop_incident:
                    raise ValueError("affected enhanced edges require an explicit removal policy")
                continue
            if "." in edge_head:
                edge_head = mapping.get(base, base) + "." + edge_head.split(".", 1)[1]
            else:
                edge_head = mapping.get(edge_head, edge_head)
            edges.append((edge_head, relation))
        cells[8] = format_edges(edges)
        result.append("\t".join(cells))
    iterator = iter(result)
    new_lines = []
    for line in sent.lines:
        if line.startswith("#"):
            new_lines.append(line)
        else:
            old_id = line.split("\t", 1)[0]
            if old_id in removed:
                continue
            multi = MWT.fullmatch(old_id)
            if multi and remove_mwts and any(str(i) in removed for i in range(int(multi.group(1)), int(multi.group(2)) + 1)):
                continue
            new_lines.append(next(iterator))
    sent.lines = new_lines
    sent.changed = True
    sent._validate_rows()


def ensure_no_opaque_references(sent: Sentence) -> None:
    """Reject known reference-bearing metadata that cannot safely be remapped."""
    keys = {"coref", "entity", "bridge", "splitante", "anaphora", "ref"}
    for _, row in sent.rows():
        for item in row[9].split("|"):
            key = item.split("=", 1)[0].lower()
            if key in keys:
                raise ValueError(f"cannot safely remap reference-bearing MISC field {key}")


def replacement_heads(spec: Any) -> dict[str, str]:
    if not isinstance(spec, dict):
        raise ValueError("dependent_heads must be an object")
    return {str(k): str(v) for k, v in spec.items()}
