"""Analysis of explicitly annotated enhanced dependency edges."""
from collections import deque
from typing import Any
from ..errors import InvalidInput
from ._common import files_for, parse_sentences, require_no_options
from ..graph_backend import inspect_graphs


def enhanced_graph_report(args: dict[str, Any]) -> dict[str, Any]:
    require_no_options(args)
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    reports, node_sets = [], []
    for sentence in parse_sentences(root, paths):
        nodes = {row["id"] for row in sentence.rows if "-" not in row["id"]}
        edges = []
        for row in sentence.rows:
            if row["id"] not in nodes or row["deps"] == "_":
                continue
            for item in row["deps"].split("|"):
                head, sep, relation = item.partition(":")
                if not sep or not relation or head not in nodes | {"0"}:
                    raise InvalidInput(f"invalid enhanced edge {item!r}")
                edge = {"head_id": head, "dependent_id": row["id"], "deprel": relation}
                edges.append(edge)
        node_sets.append(nodes)
        graph_present = bool(edges) or any("." in node for node in nodes)
        reports.append({"location": sentence.location, "nodes": len(nodes), "edges": edges,
                        "graph_present": graph_present})
    adjacencies, backend = inspect_graphs([report["edges"] for report in reports])
    for report, nodes, adjacency in zip(reports, node_sets, adjacencies):
        visited = {"0"}
        queue = deque(["0"])
        while queue:
            for neighbor in adjacency[queue.popleft()] - visited:
                visited.add(neighbor)
                queue.append(neighbor)
        report["unreachable_from_root"] = sorted(nodes - visited) if report["graph_present"] else None
    return {"sentences": reports, "backend": backend, "definition": "directed reachability from root along head-to-dependent DEPS edges; absent enhanced graphs are not applicable"}


def enhanced_edge_explanations(args: dict[str, Any]) -> dict[str, Any]:
    """Describe explicit enhanced edges and whether each repeats a basic edge."""
    import json
    from .conversion import _artifact, _export_destination
    destination = _export_destination(args.get("output_dir_path"))
    require_no_options(args)
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    explanations = []
    for sentence in parse_sentences(root, paths):
        rows = {row["id"]: row for row in sentence.rows if "-" not in row["id"]}
        for dependent in rows.values():
            if dependent["deps"] == "_":
                continue
            for item in dependent["deps"].split("|"):
                head, separator, relation = item.partition(":")
                if not separator or not relation or (head != "0" and head not in rows):
                    raise InvalidInput("invalid enhanced edge")
                explanations.append({"location": sentence.location, "head_id": head,
                                     "head_form": "ROOT" if head == "0" else rows[head]["form"],
                                     "dependent_id": dependent["id"], "dependent_form": dependent["form"],
                                     "relation": relation,
                                     "matches_basic": dependent["head"] == head and dependent["deprel"] == relation,
                                     "evidence": "explicit DEPS annotation"})
    content = json.dumps({"explanations": explanations}, ensure_ascii=False, indent=2) + "\n"
    return {"status": "candidate", "requires_host_export": True, "output_dir_path": destination,
            "artifacts": [_artifact("enhanced-edges.json", content, "application/json")],
            "edge_count": len(explanations),
            "limitations": ["The report describes annotated edges; it does not infer the annotator's linguistic rationale."]}


def enhanced_empty_node_collapse_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Plan explicit removal of empty nodes and report every lost enhanced edge."""
    import difflib
    import json
    from ._common import digest, scoped_path
    from ..conllu.core import Document, EMPTY, format_edges, parse_edges
    from ..conllu.remap import ensure_no_opaque_references

    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    spec_path = scoped_path(root, args.get("transformation_spec_path"))
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InvalidInput("transformation specification must be UTF-8 JSON") from exc
    if not isinstance(spec, dict) or set(spec) != {"mode", "allow_information_loss"} or spec.get("mode") != "drop" or spec.get("allow_information_loss") is not True:
        raise InvalidInput("specification must explicitly select drop mode and allow_information_loss")
    require_no_options(args)
    actions = []
    losses = []
    for path in paths:
        document = Document(str(root), path.relative_to(root).as_posix())
        for ordinal, sentence in enumerate(document.sentences):
            old_rows = sentence.rows()
            empty = {row[0] for _, row in old_rows if EMPTY.fullmatch(row[0])}
            if not empty:
                continue
            ensure_no_opaque_references(sentence)
            for _, row in old_rows:
                if row[0] in empty:
                    losses.append({"file_path": document.file_path, "sentence_ordinal": ordinal, "empty_node_id": row[0],
                                   "lost_annotation": row})
            remove_indices = []
            for index, row in old_rows:
                if row[0] in empty:
                    remove_indices.append(index)
                    continue
                original = parse_edges(row[8])
                kept = []
                for head, relation in original:
                    if head in empty:
                        losses.append({"file_path": document.file_path, "sentence_ordinal": ordinal,
                                       "lost_edge": {"head_id": head, "dependent_id": row[0], "deprel": relation}})
                    else:
                        kept.append((head, relation))
                if len(kept) != len(original):
                    row[8] = format_edges(kept)
                    sentence.set_row(index, row)
            for index in reversed(remove_indices):
                sentence.lines.pop(index)
                sentence.changed = True
        candidate = document.candidate()
        if candidate:
            old = document.before.decode("utf-8")
            new = candidate["content"]
            actions.append({"id": "empty_node_drop:" + document.file_path, "type": "replace_file", **candidate,
                            "input_fingerprints": {spec_path.relative_to(root).as_posix(): digest(spec_path)},
                            "depends_on": [], "diff": "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                                                                   fromfile=document.file_path, tofile=document.file_path))})
    return {"schema_version": "ud-plan-v1", "plan_type": "enhanced_empty_node_collapse", "actions": actions,
            "losses": losses, "transformation": spec,
            "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"},
            "limitations": ["Drop mode removes the specified node annotations and incident enhanced edges; it does not infer replacement structure."]}
