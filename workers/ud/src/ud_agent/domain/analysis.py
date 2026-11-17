"""Evidence-oriented corpus analyses over staged CoNLL-U files."""
from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any
import unicodedata

from ._common import Sentence, attributes, files_for, occurrences, parse_sentences, require_no_options, scoped_path, words
from ..errors import InvalidInput


def _sentences(args: dict[str, Any]) -> list[Sentence]:
    require_no_options(args)
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    return list(parse_sentences(root, paths))


def _report(counter: Counter, denominator: int) -> list[dict[str, Any]]:
    return [{"value": value, "count": count, "denominator": denominator,
             "proportion": count / denominator if denominator else None}
            for value, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))]


def _filter(value: Any, fields: set[str]) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - fields or any(not isinstance(v, str) for v in value.values()):
        raise InvalidInput("filter contains unsupported fields or non-string values")
    return value


def _matches(row: dict[str, str], filters: dict[str, str]) -> bool:
    return all(row[key] == value for key, value in filters.items())


def treebank_profile(args: dict[str, Any]) -> dict[str, Any]:
    sentences = _sentences(args)
    token_rows = [row for sentence in sentences for row in words(sentence)]
    counts = Counter(row["upos"] for row in token_rows)
    return {"sentence_count": len(sentences), "word_count": len(token_rows),
            "multiword_token_count": sum("-" in row["id"] for sentence in sentences for row in sentence.rows),
            "empty_node_count": sum("." in row["id"] for sentence in sentences for row in sentence.rows),
            "upos": _report(counts, len(token_rows)), "scope": sorted({s.file for s in sentences}),
            "definition": "ordinary integer-ID words; no Unicode normalization"}


def lexeme_pos_report(args: dict[str, Any]) -> dict[str, Any]:
    filters = _filter(args.get("lexeme_filter"), {"lemma", "upos", "form", "xpos"})
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for sentence in _sentences(args):
        for row in words(sentence):
            if _matches(row, filters):
                grouped[row["lemma"], row["upos"]].append(occurrences(sentence, row))
    return {"entries": [{"lemma": lemma, "upos": pos, "count": len(locations), "occurrences": locations}
                        for (lemma, pos), locations in sorted(grouped.items())], "filter": filters}


def observed_paradigms(args: dict[str, Any]) -> dict[str, Any]:
    filters = _filter(args.get("paradigm_filter"), {"lemma", "upos", "form", "xpos"})
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for sentence in _sentences(args):
        for row in words(sentence):
            if _matches(row, filters):
                grouped[row["lemma"], row["upos"], row["feats"], row["form"]].append(occurrences(sentence, row))
    return {"forms": [{"lemma": lemma, "upos": pos, "features": feats, "form": form,
                       "count": len(found), "occurrences": found}
                      for (lemma, pos, feats, form), found in sorted(grouped.items())],
            "limitations": ["Paradigms contain observed forms only; missing forms are not inferred."]}


def _head_order(row: dict[str, str]) -> str:
    if not row["head"].isdigit() or row["head"] == "0":
        return "no_word_head"
    return "before_head" if int(row["id"]) < int(row["head"]) else "after_head"


def _sentence_metadata(sentence: Sentence) -> dict[str, str]:
    """`# key = value` comments other than sent_id and text (for example genre)."""
    found = {}
    for comment in sentence.comments:
        key, sep, value = comment.lstrip("#").strip().partition("=")
        key = key.strip()
        if sep and key and key not in ("sent_id", "text") and " " not in key:
            found[key] = value.strip()
    return found


def relation_profile(args: dict[str, Any]) -> dict[str, Any]:
    filters = _filter(args.get("relation_filter"), {"deprel", "upos", "head"})
    entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
    orders: dict[str, Counter] = defaultdict(Counter)
    by_metadata: dict[str, dict[str, dict[str, Counter]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))
    examples: dict[str, dict[str, str]] = defaultdict(dict)
    metadata_examples: dict[str, dict[str, dict[str, dict[str, str]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
    total = 0
    for sentence in _sentences(args):
        metadata = _sentence_metadata(sentence)
        for row in words(sentence):
            if _matches(row, filters):
                total += 1
                order = _head_order(row)
                entries[row["deprel"]].append(occurrences(sentence, row))
                orders[row["deprel"]][order] += 1
                example = f'{sentence.file} sent_id {sentence.sent_id} token {row["id"]}'
                examples[row["deprel"]].setdefault(order, example)
                for key, value in metadata.items():
                    by_metadata[row["deprel"]][key][value]["count"] += 1
                    by_metadata[row["deprel"]][key][value][order] += 1
                    metadata_examples[row["deprel"]][key][value].setdefault(order, example)
    def entry(relation: str, found: list[dict[str, Any]]) -> dict[str, Any]:
        value = {"relation": relation, "count": len(found), "occurrences": found,
                 "order_counts": {name: orders[relation][name] for name in ("before_head", "after_head", "no_word_head")},
                 "order_examples": dict(sorted(examples[relation].items()))}
        if by_metadata.get(relation):
            value["by_sentence_metadata"] = {key: {item: {**{name: counts[name] for name in ("count", "before_head", "after_head", "no_word_head")},
                                                          **{f"{name}_example": text for name, text in sorted(metadata_examples[relation][key][item].items())}}
                                                   for item, counts in sorted(values.items())} for key, values in sorted(by_metadata[relation].items())}
        return value
    return {"denominator": total, "relations": [entry(relation, found) for relation, found in sorted(entries.items())], "filter": filters,
            "order_definition": "before_head/after_head compare the word ID with its basic HEAD ID; no_word_head is HEAD 0 or non-numeric; by_sentence_metadata groups by # key = value comments"}


def feature_agreement_report(args: dict[str, Any]) -> dict[str, Any]:
    feature = args.get("feature_name")
    if not isinstance(feature, str) or not feature:
        raise InvalidInput("feature_name must be a nonempty string")
    filters = _filter(args.get("relation_filter"), {"deprel", "upos", "head"})
    comparisons = []
    skipped = Counter()
    for sentence in _sentences(args):
        by_id = {row["id"]: row for row in words(sentence)}
        for child in by_id.values():
            if not _matches(child, filters):
                continue
            parent = by_id.get(child["head"])
            if parent is None:
                skipped["no_word_head"] += 1
                continue
            a = attributes(child["feats"]).get(feature)
            b = attributes(parent["feats"]).get(feature)
            if not a or not b:
                skipped["missing_feature"] += 1
                continue
            comparisons.append({"dependent": occurrences(sentence, child), "head_id": parent["id"],
                                "relation": child["deprel"], "dependent_values": a, "head_values": b,
                                "agrees": bool(set(a) & set(b))})
    return {"feature": feature, "comparisons": comparisons, "compared": len(comparisons),
            "agreeing": sum(item["agrees"] for item in comparisons),
            "disagreeing": sum(not item["agrees"] for item in comparisons), "skipped": dict(skipped),
            "definition": "feature values agree when the explicitly annotated value sets intersect"}


def dependency_order_profile(args: dict[str, Any]) -> dict[str, Any]:
    counts = Counter()
    occurrences_by_order: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sentence in _sentences(args):
        for row in words(sentence):
            if row["head"].isdigit() and row["head"] != "0":
                order = "before_head" if int(row["id"]) < int(row["head"]) else "after_head" if int(row["id"]) > int(row["head"]) else "self"
                counts[order] += 1
                occurrences_by_order[order].append(occurrences(sentence, row))
    return {"orders": _report(counts, sum(counts.values())), "occurrences": dict(occurrences_by_order),
            "definition": "integer word position relative to its non-root basic head"}


def multiword_token_patterns(args: dict[str, Any]) -> dict[str, Any]:
    patterns: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = defaultdict(list)
    for sentence in _sentences(args):
        by_id = {int(row["id"]): row for row in words(sentence)}
        for row in sentence.rows:
            if "-" not in row["id"]:
                continue
            first, sep, last = row["id"].partition("-")
            if not sep or not first.isdigit() or not last.isdigit() or int(first) > int(last):
                raise InvalidInput("invalid multiword token range")
            components = tuple(by_id[i]["upos"] if i in by_id else "MISSING" for i in range(int(first), int(last) + 1))
            patterns[row["form"], components].append(occurrences(sentence, row))
    return {"patterns": [{"form": form, "component_upos": list(pos), "count": len(found), "occurrences": found}
                         for (form, pos), found in sorted(patterns.items())]}


def proper_name_sequences(args: dict[str, Any]) -> dict[str, Any]:
    sequences = []
    for sentence in _sentences(args):
        group: list[dict[str, str]] = []
        def flush() -> None:
            if group:
                sequences.append({"location": sentence.location, "token_ids": [x["id"] for x in group],
                                  "forms": [x["form"] for x in group]})
                group.clear()
        for row in words(sentence):
            if row["upos"] == "PROPN":
                group.append(row)
            else:
                flush()
        flush()
    return {"sequences": sequences, "limitations": ["Consecutive PROPN runs are not named-entity recognition."]}


def _script(char: str) -> str:
    name = unicodedata.name(char, "")
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "DEVANAGARI", "HIRAGANA", "KATAKANA", "HANGUL", "THAI", "GEORGIAN", "ARMENIAN", "ETHIOPIC", "BENGALI", "TAMIL", "TELUGU"):
        if script in name:
            return script
    if "CJK" in name or "IDEOGRAPH" in name:
        return "HAN"
    return "OTHER"


def script_composition_report(args: dict[str, Any]) -> dict[str, Any]:
    root, _ = files_for(args)
    peers = args.get("peer_treebank_paths") or []
    if not isinstance(peers, list):
        raise InvalidInput("peer_treebank_paths must be an array")
    corpora = [(".", args)]
    for peer in peers:
        path = scoped_path(root, peer, allow_directory=True)
        if not path.is_dir():
            raise InvalidInput("peer paths must be directories")
        corpora.append((peer, {"working_tree_path": str(path)}))
    reports = []
    for label, params in corpora:
        counts = Counter(_script(ch) for sentence in _sentences(params) for row in words(sentence)
                         for ch in row["form"] if ch.isalpha())
        reports.append({"treebank": label, "scripts": _report(counts, sum(counts.values()))})
    return {"corpora": reports, "limitations": ["Scripts are estimated from Unicode character names; unclassified letters are OTHER."]}


def english_relative_clause_classify(args: dict[str, Any]) -> dict[str, Any]:
    """Describe English relative-clause annotations using explicit UD labels."""
    import json
    from .conversion import _artifact, _export_destination
    destination = _export_destination(args.get("output_dir_path"))
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"language_code"} or options.get("language_code", "en") != "en":
        raise InvalidInput("this classifier accepts only English language data")
    matches = []
    for sentence in _sentences({**args, "options": {}}):
        rows = words(sentence)
        by_id = {row["id"]: row for row in rows}
        children: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            children[row["head"]].append(row)
        for row in rows:
            relation = row["deprel"]
            if not relation.endswith(":relcl"):
                continue
            queue = [row["id"]]
            visited = set()
            relatives = []
            while queue:
                ident = queue.pop()
                if ident in visited:
                    continue
                visited.add(ident)
                node = by_id[ident]
                if "Rel" in attributes(node["feats"]).get("PronType", []):
                    relatives.append({"token_id": ident, "form": node["form"], "upos": node["upos"]})
                queue.extend(child["id"] for child in children.get(ident, []))
            category = "adnominal" if relation == "acl:relcl" else "adverbial" if relation == "advcl:relcl" else "other"
            matches.append({"location": sentence.location, "token_id": row["id"], "form": row["form"],
                            "relation": relation, "category": category, "head_id": row["head"],
                            "relative_markers": sorted(relatives, key=lambda item: int(item["token_id"]))})
    payload = json.dumps({"language": "en", "clauses": matches}, ensure_ascii=False, indent=2) + "\n"
    return {"status": "candidate", "requires_host_export": True, "output_dir_path": destination,
            "artifacts": [_artifact("english-relative-clauses.json", payload, "application/json")], "clause_count": len(matches),
            "definition": "explicit :relcl dependency labels and PronType=Rel markers among basic-tree descendants",
            "limitations": ["This English-oriented annotation heuristic does not classify unlabeled clauses or imply a universal linguistic rule."]}
