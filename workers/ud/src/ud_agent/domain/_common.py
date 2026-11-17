"""Bounded, read-only corpus primitives for the staged worker workspace."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import os
import re
from typing import Any

from ..conllu.core import id_kind
from ..errors import InvalidInput

_COLUMNS = ("id", "form", "lemma", "upos", "xpos", "feats", "head", "deprel", "deps", "misc")


def require_no_options(args: dict[str, Any]) -> None:
    """Reject unsupported options rather than silently ignoring caller input."""
    value = args.get("options")
    if value is not None and (not isinstance(value, dict) or value):
        raise InvalidInput("operation does not support these options")

@dataclass(frozen=True)
class Sentence:
    file: str
    ordinal: int
    sent_id: str | None
    text: str | None
    comments: tuple[str, ...]
    rows: tuple[dict[str, str], ...]
    raw: str

    @property
    def location(self) -> dict[str, Any]:
        return {"file_path": self.file, "sent_id": self.sent_id, "ordinal": self.ordinal}

def root_path(args: dict[str, Any]) -> Path:
    value = args.get("working_tree_path")
    if not isinstance(value, str) or not value:
        raise InvalidInput("working_tree_path must be a nonempty absolute path")
    root = Path(value)
    if not root.is_absolute() or not root.is_dir():
        raise InvalidInput("working_tree_path must be an existing absolute directory")
    return root.resolve(strict=True)

def scoped_path(root: Path, value: str, *, allow_directory: bool = False) -> Path:
    if not isinstance(value, str) or not value:
        raise InvalidInput("path must be a nonempty string")
    path = Path(value)
    if path.is_absolute() or any(part in ("..", ".") for part in path.parts):
        raise InvalidInput("file paths must be repository-relative and cannot contain traversal")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise InvalidInput("symbolic links are not allowed in the worker workspace")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InvalidInput(f"path does not exist inside the workspace: {value}") from exc
    if not resolved.is_file() and not (allow_directory and resolved.is_dir()):
        raise InvalidInput("path must identify an ordinary file")
    return resolved

def files_for(args: dict[str, Any], key: str = "file_paths", *, default_all: bool = True) -> tuple[Path, list[Path]]:
    root = root_path(args)
    selection = args.get(key)
    if selection is None:
        if not default_all:
            raise InvalidInput(f"{key} is required")
        paths = []
        peer_paths = args.get("peer_treebank_paths")
        excluded_peers = {Path(value).as_posix().rstrip("/") for value in peer_paths if isinstance(value, str)} if isinstance(peer_paths, list) else set()
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(base) / d).is_symlink() and d not in {".git", ".ud-agent-inputs"}
                             and (Path(base) / d).relative_to(root).as_posix() not in excluded_peers)
            for filename in sorted(files):
                path = Path(base) / filename
                if filename.endswith(".conllu") and not path.is_symlink() and path.is_file():
                    paths.append(path)
    else:
        if not isinstance(selection, list) or any(not isinstance(x, str) for x in selection):
            raise InvalidInput(f"{key} must be an array of repository-relative file paths")
        paths = [scoped_path(root, item) for item in selection]
    if len(paths) != len(set(paths)):
        raise InvalidInput("duplicate input file path")
    return root, paths

def parse_sentences(root: Path, files: list[Path]) -> Iterator[Sentence]:
    for path in files:
        try:
            text = path.read_bytes().decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise InvalidInput(f"file is not UTF-8: {path.relative_to(root)}") from exc
        blocks = []
        current = []
        for line in text.splitlines(keepends=True):
            if not line.strip():
                if current:
                    blocks.append("".join(current))
                    current = []
            else:
                current.append(line)
        if current:
            blocks.append("".join(current))
        ordinal = -1
        for block in blocks:
            if not block.strip():
                continue
            ordinal += 1
            comments: list[str] = []
            rows: list[dict[str, str]] = []
            row_ids: set[str] = set()
            sent_id = None
            sentence_text = None
            for line in block.splitlines():
                if line.startswith("#"):
                    comments.append(line)
                    if re.match(r"^#\s*sent_id\s*=", line):
                        sent_id = line.split("=", 1)[1].strip()
                    if re.match(r"^#\s*text\s*=", line):
                        sentence_text = line.split("=", 1)[1].strip()
                elif line:
                    values = line.split("\t")
                    if len(values) != 10:
                        raise InvalidInput(f"invalid CoNLL-U column count in {path.relative_to(root)} sentence {ordinal}")
                    try:
                        id_kind(values[0])
                    except ValueError as exc:
                        raise InvalidInput(f"invalid CoNLL-U row ID in {path.relative_to(root)} sentence {ordinal}") from exc
                    if values[0] in row_ids:
                        raise InvalidInput(f"duplicate CoNLL-U row ID in {path.relative_to(root)} sentence {ordinal}")
                    row_ids.add(values[0])
                    rows.append(dict(zip(_COLUMNS, values, strict=True)))
            yield Sentence(path.relative_to(root).as_posix(), ordinal, sent_id, sentence_text, tuple(comments), tuple(rows), block)

def words(sentence: Sentence) -> list[dict[str, str]]:
    return [row for row in sentence.rows if row["id"].isdigit()]

def attributes(value: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    if value in ("", "_"):
        return result
    for item in value.split("|"):
        key, separator, raw = item.partition("=")
        if not separator or not key or key in result:
            raise InvalidInput("invalid attribute list")
        result[key] = raw.split(",")
    return result

def digest(path: Path) -> str:
    result = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()

def occurrences(sentence: Sentence, token: dict[str, str]) -> dict[str, Any]:
    return {**sentence.location, "token_id": token["id"]}
