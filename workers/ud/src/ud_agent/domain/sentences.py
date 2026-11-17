"""Sentence inspection and byte-preserving candidate edits."""
from __future__ import annotations

import re
from typing import Any
from ..conllu.core import Document, Sentence, candidate_result, digest, doc_for, edit_sentence, require_preconditions, tree_ref

BOUNDARY = re.compile(r"^#\s*(newdoc|newpar)(?:\s+id\s*=\s*.*)?\s*$")


def _boundaries(sent: Sentence) -> list[str]:
    result = []
    for line in sent.lines:
        if re.match(r"^#\s*(?:newdoc|newpar)\b", line):
            if not BOUNDARY.fullmatch(line):
                raise ValueError("unrecognized document or paragraph boundary metadata")
            result.append(line)
    kinds = [BOUNDARY.fullmatch(line).group(1) for line in result]
    if len(kinds) != len(set(kinds)):
        raise ValueError("duplicate document or paragraph boundary metadata")
    return result


def _strip_boundaries(sent: Sentence) -> None:
    lines = [line for line in sent.lines if not BOUNDARY.fullmatch(line)]
    if lines != sent.lines:
        sent.lines = lines
        sent.changed = True


def _boundary_policy(args: dict[str, Any], sent: Sentence, operation: str) -> str | None:
    if not _boundaries(sent):
        return None
    value = (args.get("edit_options") or {}).get("boundary_policy")
    if isinstance(value, dict):
        if set(value) != {"action"}:
            raise ValueError("boundary_policy object requires only an action")
        value = value["action"]
    allowed = {"remove": {"transfer_to_next", "drop", "preserve"},
               "move": {"move_with_sentence", "transfer_to_next", "drop", "preserve"},
               "copy": {"copy_with_sentence", "drop", "preserve"}}[operation]
    if value not in allowed:
        raise ValueError("boundary sentence requires a supported explicit boundary_policy")
    if value == "preserve":
        return {"remove": "transfer_to_next", "move": "move_with_sentence", "copy": "copy_with_sentence"}[operation]
    return value


def _transfer_boundary_to_next(doc: Document, index: int, sent: Sentence) -> None:
    boundaries = _boundaries(sent)
    if index + 1 >= len(doc.sentences):
        raise ValueError("cannot transfer a boundary without a following source sentence")
    target = doc.sentences[index + 1]
    existing = {BOUNDARY.fullmatch(line).group(1): line for line in _boundaries(target)}
    additions = []
    for line in boundaries:
        kind = BOUNDARY.fullmatch(line).group(1)
        if kind in existing and existing[kind] != line:
            raise ValueError("boundary transfer conflicts with the following sentence")
        if kind not in existing:
            additions.append(line)
    if additions:
        target.lines[0:0] = additions
        target.changed = True


def _new_sentence(value: str) -> Sentence:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("sentence_conllu must contain one sentence")
    if re.search(r"\r?\n[ \t]*\r?\n\s*\S", value):
        raise ValueError("sentence_conllu must contain exactly one sentence")
    sent = Sentence(value)
    if not sent.rows():
        raise ValueError("sentence must contain at least one row")
    if len(sent.metadata("sent_id")) > 1:
        raise ValueError("sentence has duplicate sent_id comments")
    sent.changed = True
    return sent


def _check_identity(doc: Document, sent: Sentence, excluding: int | None = None) -> None:
    ids = sent.metadata("sent_id")
    if ids and any(ids[0] in item.metadata("sent_id") for i, item in enumerate(doc.sentences) if i != excluding):
        raise ValueError("sentence ID already exists in target file")


def _index(doc: Document, position: Any) -> int:
    if position is None or position == "end":
        return len(doc.sentences)
    if isinstance(position, int) and not isinstance(position, bool) and 0 <= position <= len(doc.sentences):
        return position
    if isinstance(position, dict):
        if "ordinal" in position:
            return _index(doc, position["ordinal"])
        if "before_sent_id" in position or "after_sent_id" in position:
            before = "before_sent_id" in position
            key = "before_sent_id" if before else "after_sent_id"
            matches = [i for i, sent in enumerate(doc.sentences) if str(position[key]) in sent.metadata("sent_id")]
            if len(matches) != 1:
                raise ValueError("insertion reference is missing or ambiguous")
            return matches[0] + (0 if before else 1)
    raise ValueError("invalid insertion_point")


def tree_list(args: dict[str, Any]) -> dict[str, Any]:
    files = args.get("file_paths")
    if not isinstance(files, list) or not files:
        raise ValueError("file_paths must be a nonempty list")
    results = []
    for path in files:
        doc = Document(args["working_tree_path"], str(path))
        for ordinal, sent in enumerate(doc.sentences):
            ids = sent.metadata("sent_id")
            results.append({"file_path": path, "sent_id": ids[0] if len(ids) == 1 else None,
                            "ordinal": ordinal, "fingerprint": digest(sent.original.encode("utf-8")),
                            "text": next(iter(sent.metadata("text")), None)})
    return {"trees": results}


def tree_get(args: dict[str, Any]) -> dict[str, Any]:
    doc = doc_for(args)
    ordinal, sent = doc.find(tree_ref(args))
    return {"file_path": doc.file_path, "ordinal": ordinal, "conllu": sent.original,
            "fingerprint": digest(sent.original.encode("utf-8"))}


def tree_add(args: dict[str, Any]) -> dict[str, Any]:
    doc = Document(args["working_tree_path"], args["file_path"])
    require_preconditions(args, doc)
    sent = _new_sentence(args["sentence_conllu"])
    _check_identity(doc, sent)
    index = _index(doc, args.get("insertion_point"))
    doc.sentences.insert(index, sent)
    return candidate_result(args, [doc], {"inserted_ordinal": index})


def tree_replace(args: dict[str, Any]) -> dict[str, Any]:
    doc = doc_for(args)
    index, old = doc.find(tree_ref(args))
    require_preconditions(args, doc, old)
    new = _new_sentence(args["sentence_conllu"])
    _check_identity(doc, new, index)
    doc.sentences[index] = new
    return candidate_result(args, [doc], {"replaced_ordinal": index})


def tree_remove(args: dict[str, Any]) -> dict[str, Any]:
    doc = doc_for(args)
    index, sent = doc.find(tree_ref(args))
    require_preconditions(args, doc, sent)
    policy = _boundary_policy(args, sent, "remove")
    if policy == "transfer_to_next":
        _transfer_boundary_to_next(doc, index, sent)
    doc.sentences.pop(index)
    return candidate_result(args, [doc], {"removed_ordinal": index, "boundary_policy": policy})


def _transfer(args: dict[str, Any], move: bool) -> dict[str, Any]:
    source = doc_for(args)
    index, original = source.find(tree_ref(args))
    require_preconditions(args, source, original)
    policy = _boundary_policy(args, original, "move" if move else "copy")
    same = args["target_file_path"] == source.file_path
    target = source if same else Document(args["working_tree_path"], args["target_file_path"])
    sent = Sentence(original.serialize())
    sent.changed = True
    if policy == "transfer_to_next":
        _transfer_boundary_to_next(source, index, original)
        _strip_boundaries(sent)
    elif policy == "drop":
        _strip_boundaries(sent)
    if not move:
        if not args.get("new_sent_id"):
            raise ValueError("copy requires new_sent_id")
        sent.set_metadata("sent_id", str(args["new_sent_id"]))
    _check_identity(target, sent, index if same and move else None)
    dest = _index(target, args.get("insertion_point"))
    if move:
        source.sentences.pop(index)
        if same and dest > index:
            dest -= 1
    target.sentences.insert(dest, sent)
    return candidate_result(args, [source] if same else [source, target], {"source_ordinal": index, "target_ordinal": dest, "boundary_policy": policy})


def tree_copy(args: dict[str, Any]) -> dict[str, Any]:
    return _transfer(args, False)


def tree_move(args: dict[str, Any]) -> dict[str, Any]:
    return _transfer(args, True)


def tree_id_set(args: dict[str, Any]) -> dict[str, Any]:
    doc = doc_for(args)
    index, sent = doc.find(tree_ref(args))
    require_preconditions(args, doc, sent)
    ident = str(args["new_sent_id"])
    if not ident:
        raise ValueError("new_sent_id cannot be empty")
    if any(ident in other.metadata("sent_id") for i, other in enumerate(doc.sentences) if i != index):
        raise ValueError("new sentence ID already exists")
    sent.set_metadata("sent_id", ident)
    return candidate_result(args, [doc], {"sent_id": ident})


def tree_text_set(args: dict[str, Any]) -> dict[str, Any]:
    return edit_sentence(args, lambda sent: (sent.set_metadata("text", str(args["text"])), {"text": args["text"]})[1])


def tree_comment_set(args: dict[str, Any]) -> dict[str, Any]:
    if args["comment_key"] == "sent_id":
        raise ValueError("use tree_id_set to change sentence identity")
    return edit_sentence(args, lambda sent: (sent.set_metadata(str(args["comment_key"]), str(args["comment_value"])), {})[1])


def tree_comment_remove(args: dict[str, Any]) -> dict[str, Any]:
    if args["comment_key"] == "sent_id":
        raise ValueError("removing sentence identity requires a draft-specific operation")
    return edit_sentence(args, lambda sent: (sent.set_metadata(str(args["comment_key"]), None), {})[1])
