"""Lossless CoNLL-U blocks and worker-side candidate generation.

This module never writes workspace files. The host broker must authorize paths,
check hashes, validate candidates, and commit them transactionally.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Callable

COLUMNS = ("id", "form", "lemma", "upos", "xpos", "feats", "head", "deprel", "deps", "misc")
WORD = re.compile(r"^[1-9][0-9]*$")
EMPTY = re.compile(r"^((?:0|[1-9][0-9]*))\.([1-9][0-9]*)$")
MWT = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")
COMMENT = re.compile(r"^#\s*([^=]+?)\s*=\s*(.*)$")


class StaleInputError(ValueError):
    """The input changed after the caller captured its preconditions."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(root: str, relative: str) -> Path:
    base = Path(root)
    if not base.is_absolute():
        raise ValueError("working_tree_path must be absolute")
    base = base.resolve(strict=True)
    rel = Path(relative)
    if rel.is_absolute() or not relative or any(p in ("..", ".") for p in rel.parts):
        raise ValueError("file_path must be a confined relative path")
    path = base
    for part in rel.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("symlink paths are not accepted by the worker")
    if not path.is_file():
        raise ValueError(f"not a regular file: {relative}")
    return path


def id_kind(value: str) -> str:
    if WORD.fullmatch(value):
        return "word"
    if MWT.fullmatch(value):
        return "multiword"
    if EMPTY.fullmatch(value):
        return "empty"
    raise ValueError(f"invalid CoNLL-U id: {value}")


def parse_attrs(value: str, allow_opaque: bool = False) -> dict[str, str | None]:
    if value in ("_", ""):
        return {}
    attrs: dict[str, str | None] = {}
    for field in value.split("|"):
        name, sep, data = field.partition("=")
        if (not sep and not allow_opaque) or not name or name in attrs:
            raise ValueError(f"invalid attribute entry: {field}")
        attrs[name] = data if sep else None
    return attrs


def format_attrs(value: Any, allow_opaque: bool = False) -> str:
    if value is None or value == {} or value == []:
        return "_"
    if isinstance(value, str):
        return "|".join(k if v is None else f"{k}={v}" for k, v in parse_attrs(value, allow_opaque).items()) or "_"
    if isinstance(value, list):
        result: dict[str, Any] = {}
        for item in value:
            if isinstance(item, str):
                k, sep, v = item.partition("=")
                if not sep or not k or k in result:
                    raise ValueError("invalid or duplicated attribute")
                result[k] = v
            elif isinstance(item, dict):
                k = item.get("name")
                if not isinstance(k, str) or not k or k in result:
                    raise ValueError("invalid or duplicated attribute")
                result[k] = item.get("values", item.get("value"))
            else:
                raise ValueError("attribute entries must be strings or objects")
        value = result
    if not isinstance(value, dict):
        raise ValueError("attribute replacement must be an object or list")
    fields = []
    for key, raw in value.items():
        if not isinstance(key, str) or not key or any(c in key for c in "|=\t\r\n"):
            raise ValueError("invalid attribute name")
        if isinstance(raw, list):
            raw = ",".join(map(str, raw))
        if raw is None and allow_opaque:
            fields.append(key)
            continue
        if raw is None or any(c in str(raw) for c in "|\t\r\n"):
            raise ValueError("invalid attribute value")
        fields.append(f"{key}={raw}")
    return "|".join(fields) or "_"


def parse_edges(value: str) -> list[tuple[str, str]]:
    if value in ("_", ""):
        return []
    result = []
    for item in value.split("|"):
        head, sep, rel = item.partition(":")
        if not sep or not rel or (head != "0" and not WORD.fullmatch(head) and not EMPTY.fullmatch(head)):
            raise ValueError(f"invalid enhanced edge: {item}")
        edge = (head, rel)
        if edge in result:
            raise ValueError(f"duplicate enhanced edge: {item}")
        result.append(edge)
    return result


def format_edges(edges: list[tuple[str, str]]) -> str:
    return "|".join(f"{head}:{rel}" for head, rel in edges) or "_"


def as_edge(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise ValueError("edge must be an object")
    head = str(value.get("head_id", value.get("head", "")))
    rel = value.get("deprel", value.get("relation"))
    if (head != "0" and not WORD.fullmatch(head) and not EMPTY.fullmatch(head)) or not isinstance(rel, str) or not rel:
        raise ValueError("edge requires a valid head_id and deprel")
    return head, rel


class Sentence:
    def __init__(self, raw: str):
        self.original = raw
        self.newline = "\r\n" if "\r\n" in raw else "\n"
        self.lines = [line for line in raw.splitlines() if line.strip()]
        self.changed = False
        self._validate_rows()

    def _validate_rows(self) -> None:
        seen: set[str] = set()
        for line in self.lines:
            if line.startswith("#"):
                continue
            cells = line.split("\t")
            if len(cells) != 10:
                raise ValueError("CoNLL-U row must contain ten tab-separated fields")
            id_kind(cells[0])
            if cells[0] in seen:
                raise ValueError(f"duplicate row ID: {cells[0]}")
            seen.add(cells[0])

    def serialize(self) -> str:
        if not self.changed:
            return self.original
        self._validate_rows()
        return self.newline.join(self.lines) + self.newline * 2

    def metadata(self, key: str) -> list[str]:
        out = []
        for line in self.lines:
            match = COMMENT.match(line)
            if match and match.group(1).strip() == key:
                out.append(match.group(2))
        return out

    def set_metadata(self, key: str, value: str | None) -> None:
        if not key or any(c in key for c in "=\r\n") or (value is not None and any(c in value for c in "\r\n")):
            raise ValueError("invalid comment key or value")
        indexes = [i for i, line in enumerate(self.lines) if (m := COMMENT.match(line)) and m.group(1).strip() == key]
        if value is None:
            for index in reversed(indexes):
                self.lines.pop(index)
        else:
            new = f"# {key} = {value}"
            if indexes:
                self.lines[indexes[0]] = new
                for index in reversed(indexes[1:]):
                    self.lines.pop(index)
            else:
                index = next((i for i, line in enumerate(self.lines) if not line.startswith("#")), len(self.lines))
                self.lines.insert(index, new)
        self.changed = True

    def rows(self) -> list[tuple[int, list[str]]]:
        return [(i, line.split("\t")) for i, line in enumerate(self.lines) if not line.startswith("#")]

    def get_row(self, row_id: str, kind: str | None = None) -> tuple[int, list[str]]:
        row_id = str(row_id)
        if kind is not None and id_kind(row_id) != kind:
            raise ValueError(f"expected {kind} id")
        rows = [(index, cols) for index, cols in self.rows() if cols[0] == row_id]
        if len(rows) != 1:
            raise ValueError(f"row not uniquely found: {row_id}")
        return rows[0]

    def set_row(self, index: int, cells: list[str]) -> None:
        if len(cells) != 10 or any(not isinstance(v, str) or any(c in v for c in "\t\r\n") for v in cells):
            raise ValueError("invalid row fields")
        self.lines[index] = "\t".join(cells)
        self.changed = True

    def insert_row(self, index: int, cells: list[str]) -> None:
        if len(cells) != 10 or any(not isinstance(v, str) or any(c in v for c in "\t\r\n") for v in cells):
            raise ValueError("invalid row fields")
        self.lines.insert(index, "\t".join(cells))
        self.changed = True


class Document:
    def __init__(self, root: str, file_path: str):
        self.file_path = file_path
        self.path = safe_path(root, file_path)
        self.before = self.path.read_bytes()
        text = self.before.decode("utf-8")
        blocks: list[str] = []
        block = ""
        for line in text.splitlines(keepends=True):
            block += line
            if not line.strip():
                if block.strip():
                    blocks.append(block)
                    block = ""
        if block:
            if block.strip():
                blocks.append(block)
            elif blocks:
                blocks[-1] += block
        self.sentences = [Sentence(raw) for raw in blocks]
        self.trailing = block if block and not block.strip() and not blocks else ""

    def find(self, ref: dict[str, Any]) -> tuple[int, Sentence]:
        sent_id = ref.get("sent_id")
        ordinal = ref.get("ordinal")
        fingerprint = ref.get("fingerprint")
        if sent_id is None and (ordinal is None or not fingerprint):
            raise ValueError("a sentence without sent_id requires an ordinal and fingerprint")
        matches = [(i, sent) for i, sent in enumerate(self.sentences) if sent_id is None or sent_id in sent.metadata("sent_id")]
        if ordinal is not None:
            if not isinstance(ordinal, int) or ordinal < 0:
                raise ValueError("ordinal must be a zero-based nonnegative integer")
            matches = [(i, sent) for i, sent in matches if i == ordinal]
            if not fingerprint:
                raise ValueError("ordinal locators require a fingerprint")
        if (len(matches) > 1 or any(len(sent.metadata("sent_id")) != 1 for _, sent in matches)) and (ordinal is None or not fingerprint):
            raise ValueError("ambiguous sentence reference requires ordinal and fingerprint")
        if fingerprint:
            matches = [(i, sent) for i, sent in matches if digest(sent.original.encode("utf-8")) == fingerprint]
        if not matches and sent_id is not None and not fingerprint:
            # Name the identifiers that do exist so the caller can retry with one of them.
            known = [value for sent in self.sentences for value in sent.metadata("sent_id")][:10]
            raise ValueError(f"sentence reference is missing: no sentence has sent_id {sent_id!r}; sent_id values in this file: {', '.join(known) or 'none'}")
        if len(matches) != 1:
            raise ValueError("sentence reference is missing or ambiguous")
        return matches[0]

    def candidate(self) -> dict[str, Any] | None:
        chunks: list[str] = []
        for sent in self.sentences:
            if chunks and not re.search(r"\r?\n[ \t]*\r?\n$", chunks[-1]):
                chunks.append(sent.newline if chunks[-1].endswith("\n") else sent.newline * 2)
            chunks.append(sent.serialize())
        after = ("".join(chunks) + self.trailing).encode("utf-8")
        if after == self.before:
            return None
        return {"file_path": self.file_path, "before_sha256": digest(self.before), "after_sha256": digest(after), "content": after.decode("utf-8")}


def tree_ref(args: dict[str, Any]) -> dict[str, Any]:
    explicit = args.get("tree_ref")
    token = args.get("token_ref")
    nested = token.get("tree_ref") if isinstance(token, dict) else None
    if isinstance(explicit, dict) and isinstance(nested, dict) and explicit != nested:
        raise ValueError("tree_ref and token_ref point to different sentences")
    ref = explicit or token
    if not isinstance(ref, dict):
        raise ValueError("tree_ref or token_ref is required")
    nested = ref.get("tree_ref")
    if isinstance(nested, dict):
        return nested
    return ref


def token_id(args: dict[str, Any]) -> str:
    ref = args.get("token_ref")
    if not isinstance(ref, dict):
        raise ValueError("token_ref is required")
    value = ref.get("token_id", ref.get("word_id", ref.get("id")))
    if value is None or id_kind(str(value)) != "word":
        raise ValueError("token_ref requires an integer word id")
    return str(value)


def doc_for(args: dict[str, Any], ref: dict[str, Any] | None = None) -> Document:
    ref = ref or tree_ref(args)
    path = ref.get("file_path")
    if not isinstance(path, str):
        raise ValueError("reference requires file_path")
    return Document(args["working_tree_path"], path)


def require_preconditions(args: dict[str, Any], doc: Document, sent: Sentence | None = None) -> None:
    opts = args.get("edit_options") or {}
    expected = opts.get("expected_file_sha256", opts.get("expected_fingerprint"))
    if expected and expected != digest(doc.before):
        raise StaleInputError("stale file fingerprint")
    expected_sentence = opts.get("expected_sentence_sha256")
    if expected_sentence and (sent is None or expected_sentence != digest(sent.original.encode("utf-8"))):
        raise StaleInputError("stale sentence fingerprint")


def candidate_result(args: dict[str, Any], docs: list[Document], details: dict[str, Any] | None = None) -> dict[str, Any]:
    changes = [c for doc in docs if (c := doc.candidate()) is not None]
    return {"status": "candidate", "requested_mode": (args.get("edit_options") or {}).get("mode", "preview"), "requires_host_commit": bool(changes), "changes": changes, "details": details or {}, "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"}}


def edit_sentence(args: dict[str, Any], callback: Callable[[Sentence], dict[str, Any] | None]) -> dict[str, Any]:
    doc = doc_for(args)
    _, sent = doc.find(tree_ref(args))
    require_preconditions(args, doc, sent)
    details = callback(sent)
    return candidate_result(args, [doc], details)


def row_dict(cells: list[str]) -> dict[str, str]:
    return dict(zip(COLUMNS, cells))


def row_from_data(data: dict[str, Any], row_id: str) -> list[str]:
    if not isinstance(data, dict):
        raise ValueError("row data must be an object")
    row = [row_id]
    for column in COLUMNS[1:]:
        value = data.get(column, "_")
        if column in ("feats", "misc") and not isinstance(value, str):
            value = format_attrs(value, allow_opaque=column == "misc")
        if column == "deps" and isinstance(value, list):
            value = format_edges([as_edge(item) for item in value])
        if value is None:
            value = "_"
        row.append(str(value))
    return row
