"""Exact, evidence-preserving comparisons over staged treebanks."""
from collections import Counter, defaultdict
from hashlib import sha256
import json
from typing import Any

from ._common import attributes, files_for, parse_sentences, require_no_options, scoped_path, words
from ..errors import InvalidInput


def _corpora(args: dict[str, Any]):
    require_no_options(args)
    root, selected = files_for(args)
    if not selected:
        raise InvalidInput("at least one CoNLL-U file is required")
    yield ".", list(parse_sentences(root, selected))
    peers = args.get("peer_treebank_paths") or []
    if not isinstance(peers, list) or any(not isinstance(peer, str) for peer in peers):
        raise InvalidInput("peer_treebank_paths must be an array of paths")
    for peer in peers:
        path = scoped_path(root, peer, allow_directory=True)
        if not path.is_dir():
            raise InvalidInput("peer treebank must be a staged directory")
        peer_root, peer_files = files_for({"working_tree_path": str(path)})
        if not peer_files:
            raise InvalidInput(f"peer treebank contains no CoNLL-U files: {peer}")
        yield peer, list(parse_sentences(peer_root, peer_files))


def _options(args: dict[str, Any]) -> tuple[bool, bool]:
    options = args.get("matching_options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"casefold", "normalize_whitespace"}:
        raise InvalidInput("unsupported matching_options")
    if any(not isinstance(value, bool) for value in options.values()):
        raise InvalidInput("matching options must be boolean")
    return options.get("casefold", False), options.get("normalize_whitespace", False)


def _key(text: str, casefold: bool, normalize_whitespace: bool) -> str:
    if normalize_whitespace:
        text = " ".join(text.split())
    return text.casefold() if casefold else text


def duplicate_report(args: dict[str, Any]) -> dict[str, Any]:
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    casefold, normalize_whitespace = _options(args)
    groups = defaultdict(list)
    missing = []
    for sentence in parse_sentences(root, paths):
        if sentence.text is None:
            missing.append(sentence.location)
        else:
            groups[_key(sentence.text, casefold, normalize_whitespace)].append(sentence.location)
    return {"groups": [{"text": text, "occurrences": locations} for text, locations in sorted(groups.items()) if len(locations) > 1],
            "missing_text": missing, "method": {"source": "text metadata", "casefold": casefold, "normalize_whitespace": normalize_whitespace},
            "limitations": ["Exact text matching does not establish plagiarism or semantic contamination."]}


def overlap_report(args: dict[str, Any]) -> dict[str, Any]:
    casefold, normalize_whitespace = _options(args)
    corpora = list(_corpora(args))
    split_spec = args.get("split_spec_path")
    if len(corpora) < 2 and split_spec is None:
        raise InvalidInput("at least one peer treebank is required")
    indexed = []
    missing = []
    for label, sentences in corpora:
        texts = defaultdict(list)
        for sentence in sentences:
            if sentence.text is None:
                missing.append({"treebank": label, **sentence.location})
            else:
                texts[_key(sentence.text, casefold, normalize_whitespace)].append(sentence.location)
        indexed.append((label, texts))
    left = indexed[0][1]
    pairs = []
    for label, right in indexed[1:]:
        for text in sorted(left.keys() & right.keys()):
            pairs.append({"peer_treebank": label, "text": text, "left": left[text], "right": right[text]})
    split_evidence = {}
    if split_spec is not None:
        # Split membership is explicit evidence; file naming conventions alone
        # do not prove a train/dev/test assignment.
        root, _ = files_for(args)
        path = scoped_path(root, split_spec)
        raw = path.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise InvalidInput("split specification exceeds the size limit")
        try:
            spec = json.loads(raw.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeError) as exc:
            raise InvalidInput("overlap split specification must be UTF-8 JSON") from exc
        if not isinstance(spec, dict) or set(spec) != {"splits"} or not isinstance(spec["splits"], dict) or len(spec["splits"]) < 2:
            raise InvalidInput("overlap split specification requires at least two named selector arrays")
        current = corpora[0][1]
        grouped = []
        selected_count = 0
        for label, selectors in spec["splits"].items():
            if not isinstance(label, str) or not label or not isinstance(selectors, list) or not selectors:
                raise InvalidInput("each overlap split needs a name and nonempty selector array")
            selected = {}
            for selector in selectors:
                if isinstance(selector, str):
                    name = selector
                    sent_id = None
                elif isinstance(selector, dict) and set(selector) == {"file_path", "sent_id"} and isinstance(selector["sent_id"], str) and selector["sent_id"]:
                    name, sent_id = selector["file_path"], selector["sent_id"]
                else:
                    raise InvalidInput("split selectors must be file paths or file_path/sent_id objects")
                name = scoped_path(root, name).relative_to(root).as_posix()
                matches = [sentence for sentence in current if sentence.file == name and (sent_id is None or sentence.sent_id == sent_id)]
                if not matches or (sent_id is not None and len(matches) != 1):
                    raise InvalidInput("split sentence selection is absent or ambiguous in the current corpus")
                for sentence in matches:
                    identity = (sentence.file, sentence.ordinal)
                    if identity in selected:
                        raise InvalidInput("a split repeats a sentence selector")
                    selected[identity] = sentence
                    selected_count += 1
                    if selected_count > 1_000_000:
                        raise InvalidInput("split selection exceeds the sentence limit")
            texts = defaultdict(list)
            for sentence in selected.values():
                if sentence.text is None:
                    missing.append({"treebank": ".", "split": label, **sentence.location})
                else:
                    texts[_key(sentence.text, casefold, normalize_whitespace)].append(sentence.location)
            grouped.append((label, texts, len(selected)))
        split_matches = []
        for index, (left_label, left_texts, _) in enumerate(grouped):
            for right_label, right_texts, _ in grouped[index + 1:]:
                for text in sorted(left_texts.keys() & right_texts.keys()):
                    split_matches.append({"left_split": left_label, "right_split": right_label, "text": text,
                                          "left": left_texts[text], "right": right_texts[text]})
        split_evidence = {"split_matches": split_matches,
                          "splits": [{"name": label, "sentence_count": count} for label, _, count in grouped],
                          "split_spec_sha256": sha256(raw).hexdigest()}
    return {"matches": pairs, "missing_text": missing, **split_evidence, "method": {"source": "text metadata", "casefold": casefold, "normalize_whitespace": normalize_whitespace},
            "limitations": ["Exact text matching does not establish plagiarism or semantic contamination."]}


def feature_value_report(args: dict[str, Any]) -> dict[str, Any]:
    feature = args.get("feature_name")
    if not isinstance(feature, str) or not feature:
        raise InvalidInput("feature_name must be a nonempty string")
    corpora = []
    for label, sentences in _corpora(args):
        values = Counter()
        total = missing = 0
        for sentence in sentences:
            for row in words(sentence):
                total += 1
                found = attributes(row["feats"]).get(feature, [])
                if not found:
                    missing += 1
                values.update(found)
        corpora.append({"treebank": label, "words": total, "missing_feature": missing,
                        "values": [{"value": value, "count": count} for value, count in sorted(values.items())]})
    return {"feature": feature, "corpora": corpora, "definition": "counts individual feature values on integer-ID words"}


def conventions_compare(args: dict[str, Any]) -> dict[str, Any]:
    dimensions = args.get("dimensions")
    supported = {"upos", "deprel", "features"}
    if not isinstance(dimensions, list) or not dimensions or any(not isinstance(d, str) or d not in supported for d in dimensions):
        raise InvalidInput("dimensions must be a nonempty array of upos, deprel or features")
    corpora = []
    for label, sentences in _corpora(args):
        counts = {key: Counter() for key in dimensions}
        for sentence in sentences:
            for row in words(sentence):
                for dimension in dimensions:
                    if dimension == "features":
                        for feature, values in attributes(row["feats"]).items():
                            counts[dimension].update(f"{feature}={value}" for value in values)
                    else:
                        counts[dimension][row[dimension]] += 1
        corpora.append({"treebank": label, "dimensions": {key: dict(sorted(value.items())) for key, value in counts.items()}})
    return {"corpora": corpora, "dimensions": dimensions,
            "limitations": ["Counts describe observed annotation; they do not establish registered language rules."]}
