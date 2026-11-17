"""Parallel-material reports with explicit references and coverage."""
from __future__ import annotations
from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Any

from ._common import files_for, parse_sentences, require_no_options, root_path, scoped_path
from ..errors import InvalidInput


def _selector(root: Path, reference: Any, peers: set[str]) -> tuple[Path, str, str]:
    if not isinstance(reference, dict) or set(reference) != {"treebank", "file_path", "sent_id"}:
        raise InvalidInput("alignment references require treebank, file_path and sent_id")
    treebank, file_path, sent_id = reference["treebank"], reference["file_path"], reference["sent_id"]
    if not isinstance(treebank, str) or not isinstance(file_path, str) or not isinstance(sent_id, str) or not sent_id:
        raise InvalidInput("alignment reference fields must be nonempty strings")
    if treebank == ".":
        corpus_root = root
    else:
        if treebank not in peers:
            raise InvalidInput("alignment references an undeclared peer treebank")
        corpus_root = scoped_path(root, treebank, allow_directory=True)
        if not corpus_root.is_dir():
            raise InvalidInput("peer treebank must be a directory")
    file = scoped_path(corpus_root, file_path)
    return corpus_root, file.relative_to(corpus_root).as_posix(), sent_id


def parallel_corpus_report(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    peer_paths = args.get("peer_treebank_paths") or []
    if not isinstance(peer_paths, list) or any(not isinstance(p, str) for p in peer_paths):
        raise InvalidInput("peer_treebank_paths must be an array of paths")
    require_no_options(args)
    spec_path = scoped_path(root, args.get("alignment_spec_path"))
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeError) as exc:
        raise InvalidInput("alignment specification must be UTF-8 JSON") from exc
    if not isinstance(spec, dict) or set(spec) != {"alignments"} or not isinstance(spec["alignments"], list):
        raise InvalidInput("alignment specification must contain alignments")
    resolved = []
    missing = []
    for index, item in enumerate(spec["alignments"]):
        if not isinstance(item, dict) or set(item) != {"source", "targets"} or not isinstance(item["targets"], list) or not item["targets"]:
            raise InvalidInput("each alignment requires one source and nonempty targets")
        group = []
        for reference in [item["source"], *item["targets"]]:
            corpus_root, file_name, sent_id = _selector(root, reference, set(peer_paths))
            matches = [sentence for sentence in parse_sentences(corpus_root, [scoped_path(corpus_root, file_name)]) if sentence.sent_id == sent_id]
            if len(matches) > 1:
                raise InvalidInput("alignment sentence identity is ambiguous")
            if not matches:
                missing.append({"alignment": index, "reference": reference})
                group.append(None)
            else:
                group.append({"reference": reference, "text": matches[0].text, "location": matches[0].location})
        resolved.append({"source": group[0], "targets": group[1:]})
    return {"alignments": resolved, "missing_references": missing,
            "coverage": {"requested": len(resolved), "complete": sum(1 for item in resolved if item["source"] is not None and all(x is not None for x in item["targets"]))},
            "limitations": ["Only explicitly supplied sentence correspondences are reported."]}


_REFERENCE = re.compile(r"(?:^|[._:-])([1-3]?[A-Za-z]{3})[._:-]([0-9]+)[._:-]([0-9]+)(?:[._:-]|$)")


def bible_passage_concordance(args: dict[str, Any]) -> dict[str, Any]:
    root, files = files_for(args, "file_paths", default_all=False)
    _, peer_files = files_for(args, "peer_file_paths", default_all=False)
    if not files or not peer_files:
        raise InvalidInput("source and peer file lists must be nonempty")
    if set(files) & set(peer_files):
        raise InvalidInput("source and peer file lists must not overlap")
    require_no_options(args)
    passages = defaultdict(lambda: {"source": [], "peer": []})
    missing = []
    for role, paths in (("source", files), ("peer", peer_files)):
        for sentence in parse_sentences(root, paths):
            match = _REFERENCE.search(sentence.sent_id or "")
            if not match:
                missing.append({"role": role, **sentence.location})
                continue
            key = (match.group(1).upper(), int(match.group(2)), int(match.group(3)))
            passages[key][role].append({**sentence.location, "text": sentence.text})
    results = []
    for (book, chapter, verse), group in sorted(passages.items()):
        results.append({"book": book, "chapter": chapter, "verse": verse, **group,
                        "correspondence_complete": bool(group["source"] and group["peer"])})
    return {"passages": results, "unparsed_references": missing,
            "definition": "three-letter book, chapter and verse parsed from sentence IDs using period, colon, hyphen or underscore separators",
            "limitations": ["Corpus-specific IDs outside this reference grammar are reported as unparsed; absent matches are not inferred."]}
