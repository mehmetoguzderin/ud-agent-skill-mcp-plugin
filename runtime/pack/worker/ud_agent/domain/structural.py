"""Explicit, reference-checked structural split and merge candidate construction."""
from __future__ import annotations

from typing import Any
from ..conllu.core import COLUMNS, EMPTY, MWT, WORD, Document, candidate_result, parse_edges, row_from_data, require_preconditions, token_id, tree_ref
from .sentences import _new_sentence


REQUIRED_DECISIONS = ("basic", "enhanced", "surface", "metadata")


def _typed_sentence(raw: dict[str, Any]) -> tuple[Any, dict[str, str]]:
    """Compile explicit target rows and temporary identities into CoNLL-U."""
    rows, ident = raw.get("rows"), raw.get("sent_id")
    comments, text = raw.get("comments"), raw.get("text")
    if (not isinstance(ident, str) or not ident or "#" in ident or "\n" in ident or "\r" in ident
            or not isinstance(rows, list) or not rows or not isinstance(comments, list)
            or any(not isinstance(line, str) or not line.startswith("#") or "\n" in line or "\r" in line for line in comments)
            or not isinstance(text, str) or "\n" in text or "\r" in text):
        raise ValueError("typed target requires sent_id, explicit text, comments and nonempty rows")
    if any(line.lstrip("# ").startswith(("sent_id", "text =")) for line in comments):
        raise ValueError("typed target comments cannot duplicate sent_id or text")
    symbols = {}
    word_number = 0
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"] or row["id"] in symbols:
            raise ValueError("typed target row identities must be unique nonempty strings")
        if row.get("kind") == "word":
            word_number += 1
            symbols[row["id"]] = str(word_number)
        elif row.get("kind") in ("empty", "multiword"):
            symbols[row["id"]] = None
        else:
            raise ValueError("typed row kind must be word, empty or multiword")
    empty_numbers = {}
    for row in rows:
        if row["kind"] == "empty":
            anchor = row.get("after_word_id")
            if not isinstance(anchor, str):
                raise ValueError("typed empty node needs a string word anchor")
            base = "0" if anchor == "0" else symbols.get(anchor)
            if not isinstance(base, str) or not (base == "0" or WORD.fullmatch(base)):
                raise ValueError("typed empty node needs an existing word anchor")
            number = empty_numbers.get(base, 0) + 1
            empty_numbers[base] = number
            symbols[row["id"]] = f"{base}.{number}"
        elif row["kind"] == "multiword":
            components = row.get("components")
            if not isinstance(components, list) or len(components) < 2 or any(not isinstance(value, str) for value in components):
                raise ValueError("typed multiword row requires explicit components")
            mapped = [symbols.get(value) for value in components]
            if any(not isinstance(value, str) or not WORD.fullmatch(value) for value in mapped):
                raise ValueError("typed multiword components must identify words")
            numbers = list(map(int, mapped))
            if numbers != list(range(numbers[0], numbers[-1] + 1)):
                raise ValueError("typed multiword components must be contiguous and ordered")
            symbols[row["id"]] = f"{numbers[0]}-{numbers[-1]}"
    rendered = []
    for row in rows:
        data = {key: row[key] for key in COLUMNS[1:] if key in row}
        if row["kind"] == "word" and set(COLUMNS[1:]) - set(data):
            raise ValueError("typed word rows require every annotation field, including explicit empty values")
        if row["kind"] == "multiword":
            if "form" not in data or "misc" not in data:
                raise ValueError("typed multiword rows require form and misc")
            data = {"form": data["form"], "misc": data["misc"]}
        else:
            if row["kind"] == "empty":
                required = set(COLUMNS[1:]) - {"head", "deprel"}
                if required - set(data):
                    raise ValueError("typed empty rows require every enhanced annotation field")
                data["head"] = data["deprel"] = "_"
            elif data.get("head") != "0":
                head = symbols.get(str(data.get("head")))
                if not isinstance(head, str) or not WORD.fullmatch(head):
                    raise ValueError("typed basic head must identify a word in the target sentence")
                data["head"] = head
            deps = data.get("deps")
            if not isinstance(deps, list):
                raise ValueError("typed enhanced dependencies must be an explicit edge array")
            edges = []
            for edge in deps:
                if not isinstance(edge, dict) or set(edge) != {"head_id", "deprel"}:
                    raise ValueError("typed enhanced edge requires head_id and deprel")
                if not isinstance(edge["head_id"], str) or not isinstance(edge["deprel"], str) or not edge["deprel"]:
                    raise ValueError("typed enhanced edge fields must be nonempty strings")
                head = "0" if edge["head_id"] == "0" else symbols.get(edge["head_id"])
                if not isinstance(head, str) or MWT.fullmatch(head):
                    raise ValueError("typed enhanced head must identify a target node")
                edges.append({"head_id": head, "deprel": edge["deprel"]})
            data["deps"] = edges
        rendered.append("\t".join(row_from_data(data, symbols[row["id"]])))
    def order(row):
        value = row.split("\t", 1)[0]
        if match := MWT.fullmatch(value):
            return (int(match.group(1)), 0, 0)
        if match := EMPTY.fullmatch(value):
            return (int(match.group(1)), 2, int(match.group(2)))
        return (int(value), 1, 0)
    rendered.sort(key=order)
    conllu = "\n".join([*comments, f"# sent_id = {ident}", f"# text = {text}", *rendered]) + "\n\n"
    return _new_sentence(conllu), {f"{ident}#{key}": f"{ident}#{value}" for key, value in symbols.items()}


def _need(missing: list[str]) -> dict[str, Any]:
    return {"status": "needs_annotation", "missing_decisions": missing, "changes": [],
            "plan": {"complete": False, "required_fields": missing}}


def _source_refs(args: dict[str, Any], operation: str) -> list[dict[str, Any]]:
    if operation == "trees_merge":
        refs = args.get("tree_refs")
        if not isinstance(refs, list) or len(refs) < 2 or not all(isinstance(x, dict) for x in refs):
            raise ValueError("trees_merge requires at least two tree_refs")
        return refs
    return [tree_ref(args)]


def _load_sources(args: dict[str, Any], refs: list[dict[str, Any]]) -> tuple[list[Document], list[tuple[Document, int, Any, str]]]:
    docs: dict[str, Document] = {}
    sources = []
    for ref in refs:
        path = ref.get("file_path")
        if not isinstance(path, str):
            raise ValueError("tree reference needs file_path")
        if path not in docs:
            docs[path] = Document(args["working_tree_path"], path)
        doc = docs[path]
        index, sent = doc.find(ref)
        require_preconditions(args, doc, sent)
        ids = sent.metadata("sent_id")
        if len(ids) != 1 or not ids[0] or "#" in ids[0]:
            raise ValueError("structural source requires one unambiguous sent_id without #")
        sources.append((doc, index, sent, ids[0]))
    if len({(doc.file_path, index) for doc, index, _, _ in sources}) != len(sources):
        raise ValueError("source sentences must be distinct")
    if len({ident for _, _, _, ident in sources}) != len(sources):
        raise ValueError("source sent_ids must be distinct")
    return list(docs.values()), sources


def _validate_graph(sent: Any) -> None:
    rows = [row for _, row in sent.rows()]
    ids = {row[0] for row in rows}
    words = {row[0] for row in rows if WORD.fullmatch(row[0])}
    word_order = [int(row[0]) for row in rows if WORD.fullmatch(row[0])]
    if word_order != list(range(1, len(word_order) + 1)):
        raise ValueError("target word IDs must be contiguous and ordered")
    roots = 0
    parents = {}
    multiword_components = set()
    empty_numbers = {}
    order = []
    for row in rows:
        match = MWT.fullmatch(row[0])
        if match:
            start, end = map(int, match.groups())
            members = set(range(start, end + 1))
            if start >= end or not all(str(i) in words for i in members) or multiword_components & members:
                raise ValueError("target multiword range is invalid")
            multiword_components.update(members)
            order.append((start, 0, 0))
            continue
        if WORD.fullmatch(row[0]):
            order.append((int(row[0]), 1, 0))
            head, relation = row[6], row[7]
            if head not in words | {"0"} or (head == "0") != (relation == "root"):
                raise ValueError("target basic dependency is invalid")
            roots += head == "0"
            parents[row[0]] = head
        elif match := EMPTY.fullmatch(row[0]):
            base, number = match.groups()
            if base not in words | {"0"} or row[6] != "_" or row[7] != "_":
                raise ValueError("empty node must have a valid anchor and no basic dependency")
            empty_numbers.setdefault(base, []).append(int(number))
            order.append((int(base), 2, int(number)))
        for head, _ in parse_edges(row[8]):
            if head not in ids | {"0"} or MWT.fullmatch(head):
                raise ValueError("target enhanced edge references a missing node")
    if order != sorted(order) or any(numbers != list(range(1, len(numbers) + 1)) for numbers in empty_numbers.values()):
        raise ValueError("target rows or empty-node subindices are not in canonical order")
    if roots != 1:
        raise ValueError("target sentence must have exactly one root")
    for ident in parents:
        seen = set()
        current = ident
        while current != "0":
            if current in seen or current not in parents:
                raise ValueError("target basic graph must be an acyclic tree")
            seen.add(current)
            current = parents[current]


def _prepare_map(annotation: Any, sources: list[tuple[Document, int, Any, str]]) -> tuple[list[Any], dict[str, list[str]]] | dict[str, Any]:
    if not isinstance(annotation, dict):
        return _need(["annotation_map"])
    missing = []
    typed = isinstance(annotation.get("sentences"), list) and bool(annotation["sentences"]) and all(isinstance(item, dict) and "rows" in item for item in annotation["sentences"])
    for key in ("id_mapping", "sentences") + (() if typed else ("decisions",)):
        if not isinstance(annotation.get(key), (dict if key != "sentences" else list)):
            missing.append(key)
    decisions = annotation.get("decisions")
    if isinstance(decisions, dict):
        missing.extend("decisions." + key for key in REQUIRED_DECISIONS if decisions.get(key) != "explicit")
    if annotation.get("unresolved"):
        missing.extend(str(item) for item in annotation["unresolved"])
    if missing:
        return _need(missing)
    mapping = annotation["id_mapping"]
    originals = {f"{ident}#{row[0]}" for _, _, sent, ident in sources for _, row in sent.rows()}
    missing_ids = sorted(originals - set(mapping))
    if missing_ids:
        return _need([f"id_mapping.{key}" for key in missing_ids])
    if set(mapping) != originals:
        raise ValueError("annotation map contains nonexistent source row")
    targets = []
    symbols = {}
    for raw in annotation["sentences"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("sent_id"), str):
            raise ValueError("each target sentence requires sent_id and conllu")
        if "rows" in raw:
            sent, local_symbols = _typed_sentence(raw)
            symbols.update(local_symbols)
        else:
            sent = _new_sentence(raw.get("conllu"))
        ids = sent.metadata("sent_id")
        if ids != [raw["sent_id"]] or "#" in ids[0]:
            raise ValueError("target sent_id must match exactly one sentence comment")
        _validate_graph(sent)
        targets.append(sent)
    if not targets:
        raise ValueError("annotation map must contain target sentences")
    if len({sent.metadata("sent_id")[0] for sent in targets}) != len(targets):
        raise ValueError("target sentence IDs must be unique")
    target_ids = {f"{sent.metadata('sent_id')[0]}#{row[0]}" for sent in targets for _, row in sent.rows()}
    mapped = []
    normalized_mapping = {}
    for key, values in mapping.items():
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError("id_mapping values must be arrays of target IDs")
        normalized_mapping[key] = [symbols.get(value, value) for value in values]
        mapped.extend(normalized_mapping[key])
    created = annotation.get("created", [])
    if not isinstance(created, list) or not all(isinstance(v, str) for v in created):
        raise ValueError("created must be an array of target IDs")
    created = [symbols.get(value, value) for value in created]
    if set(mapped) | set(created) != target_ids:
        raise ValueError("mapping and created must account for all and only target rows")
    return targets, normalized_mapping


def _forms(sentences: list[Any]) -> dict[str, str]:
    return {f"{sent.metadata('sent_id')[0]}#{row[0]}": row[1] for sent in sentences for _, row in sent.rows() if WORD.fullmatch(row[0])}


def _requested_form(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("form"), str):
        return value["form"]
    raise ValueError("replacement words require a form")


def _run(args: dict[str, Any], operation: str) -> dict[str, Any]:
    refs = _source_refs(args, operation)
    docs, sources = _load_sources(args, refs)
    prepared = _prepare_map(args.get("annotation_map"), sources)
    if isinstance(prepared, dict):
        return prepared
    targets, mapping = prepared
    forms = _forms(targets)
    source_id = sources[0][3]
    directly_changed: set[str] = set()
    if operation in ("token_split", "tokens_merge", "tokenization_reconcile"):
        if len(targets) != 1 or targets[0].metadata("sent_id") != [source_id]:
            raise ValueError("word edits must preserve the source sentence identity")
    if operation == "token_split":
        old_id = token_id(args)
        directly_changed.add(f"{source_id}#{old_id}")
        sources[0][2].get_row(old_id, "word")
        replacements = args.get("replacement_words")
        if not isinstance(replacements, list) or len(replacements) < 2:
            raise ValueError("token_split requires at least two replacement words")
        ids = mapping[f"{source_id}#{old_id}"]
        if len(ids) != len(replacements) or [forms.get(i) for i in ids] != [_requested_form(x) for x in replacements]:
            raise ValueError("token split mapping must match replacement word forms and order")
    elif operation == "tokens_merge":
        tokens = [str(x) for x in args.get("token_ids", [])]
        if len(tokens) < 2 or len(tokens) != len(set(tokens)) or any(not WORD.fullmatch(x) for x in tokens):
            raise ValueError("tokens_merge needs at least two distinct word IDs")
        if [int(x) for x in tokens] != list(range(int(tokens[0]), int(tokens[-1]) + 1)):
            raise ValueError("tokens to merge must be contiguous and ordered")
        for ident in tokens:
            sources[0][2].get_row(ident, "word")
            directly_changed.add(f"{source_id}#{ident}")
        destinations = [mapping[f"{source_id}#{ident}"] for ident in tokens]
        if any(len(x) != 1 for x in destinations) or len({x[0] for x in destinations}) != 1:
            raise ValueError("all merged words must map to the same target word")
        if forms.get(destinations[0][0]) != _requested_form(args["merged_word"]):
            raise ValueError("merged word form does not match target")
    elif operation == "tree_split":
        ids = args.get("new_sent_ids")
        boundaries = args.get("split_boundaries")
        if not isinstance(ids, list) or len(ids) < 2 or [s.metadata("sent_id")[0] for s in targets] != ids:
            raise ValueError("target sentence IDs must exactly match new_sent_ids")
        if not isinstance(boundaries, list) or len(boundaries) != len(ids) - 1:
            raise ValueError("split_boundaries must contain one boundary between each target")
        boundaries = [int(x) for x in boundaries]
        word_ids = [int(row[0]) for _, row in sources[0][2].rows() if WORD.fullmatch(row[0])]
        if boundaries != sorted(set(boundaries)) or any(x < 1 or x >= len(word_ids) for x in boundaries):
            raise ValueError("invalid split boundaries")
        for old_id in word_ids:
            part = sum(old_id > boundary for boundary in boundaries)
            if any(not dest.startswith(ids[part] + "#") for dest in mapping[f"{source_id}#{old_id}"]):
                raise ValueError("word mapping conflicts with split boundaries")
    elif operation == "trees_merge":
        if len(targets) != 1 or targets[0].metadata("sent_id") != [args["new_sent_id"]]:
            raise ValueError("merged target must have the requested sentence ID")
    elif operation == "tokenization_reconcile":
        replacements = args.get("replacement_words")
        if not isinstance(replacements, list) or not replacements:
            raise ValueError("tokenization reconciliation requires explicit resulting replacement_words")
        actual = [row[1] for _, row in targets[0].rows() if WORD.fullmatch(row[0])]
        if actual != [_requested_form(value) for value in replacements]:
            raise ValueError("reconciled target forms must match explicit replacement_words")
        directly_changed.update(f"{source_id}#{row[0]}" for _, row in sources[0][2].rows() if WORD.fullmatch(row[0]))
    for _, _, source, source_sent_id in sources:
        for _, row in source.rows():
            key = f"{source_sent_id}#{row[0]}"
            if not WORD.fullmatch(row[0]) or key in directly_changed:
                continue
            mapped = mapping[key]
            if len(mapped) != 1 or forms.get(mapped[0]) != row[1]:
                raise ValueError("unchanged words must map once to the same form")
    if operation in ("tree_split", "trees_merge"):
        mapped_words = {destination for _, _, source, source_ident in sources for _, row in source.rows()
                        if WORD.fullmatch(row[0]) for destination in mapping[f"{source_ident}#{row[0]}"]}
        if set(forms) != mapped_words:
            raise ValueError("sentence split/merge cannot create unmapped words")
    first_doc, first_index, _, _ = sources[0]
    selected = {(d.file_path, i) for d, i, _, _ in sources}
    target_ids = {s.metadata("sent_id")[0] for s in targets}
    introduced_ids = target_ids - {ident for _, _, _, ident in sources}
    for doc in docs:
        for index, sent in enumerate(doc.sentences):
            if (doc.file_path, index) not in selected and introduced_ids.intersection(sent.metadata("sent_id")):
                raise ValueError("target sentence ID conflicts with an existing sentence")
    from ._common import files_for
    root, scope_paths = files_for({"working_tree_path": args["working_tree_path"]})
    selected_files = {doc.file_path for doc in docs}
    for file in scope_paths:
        relative = file.relative_to(root).as_posix()
        if relative in selected_files:
            continue
        other = Document(str(root), relative)
        if any(introduced_ids.intersection(sentence.metadata("sent_id")) for sentence in other.sentences):
            raise ValueError("target sentence ID conflicts with an existing sentence in the workspace")
    for doc in docs:
        indices = sorted([i for d, i, _, _ in sources if d is doc], reverse=True)
        for index in indices:
            doc.sentences.pop(index)
    insertion = first_index - sum(1 for d, i, _, _ in sources if d is first_doc and i < first_index)
    first_doc.sentences[insertion:insertion] = targets
    return candidate_result(args, docs, {"operation": operation, "id_mapping": mapping, "target_sentence_ids": [s.metadata("sent_id")[0] for s in targets]})


def token_split(args: dict[str, Any]) -> dict[str, Any]:
    return _run(args, "token_split")


def tokens_merge(args: dict[str, Any]) -> dict[str, Any]:
    return _run(args, "tokens_merge")


def tree_split(args: dict[str, Any]) -> dict[str, Any]:
    return _run(args, "tree_split")


def trees_merge(args: dict[str, Any]) -> dict[str, Any]:
    return _run(args, "trees_merge")


def _tokenization_reconcile(args: dict[str, Any]) -> dict[str, Any]:
    """Internal plan primitive for explicitly annotated many-to-many changes."""
    return _run(args, "tokenization_reconcile")
