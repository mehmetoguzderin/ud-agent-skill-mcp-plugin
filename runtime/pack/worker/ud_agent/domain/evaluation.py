"""Official UD evaluation with explicit gold/system roles and count aggregation."""
from __future__ import annotations
from collections import defaultdict
from typing import Any

from ._common import files_for, root_path, scoped_path
from ..errors import InvalidInput, PrerequisiteMissing, WorkerError


def _options(args: dict[str, Any]) -> tuple[dict[str, bool], bool]:
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"enhanced", "treebank_type"}:
        raise InvalidInput("unsupported scoring options")
    enhanced = options.get("enhanced", False)
    treebank_type = options.get("treebank_type", {})
    allowed = {"no_gapping", "no_shared_parents_in_coordination", "no_shared_dependents_in_coordination",
               "no_control", "no_external_arguments_of_relative_clauses", "no_case_info", "no_empty_nodes", "multiple_roots_okay"}
    if not isinstance(enhanced, bool) or not isinstance(treebank_type, dict) or set(treebank_type) - allowed or any(not isinstance(v, bool) for v in treebank_type.values()):
        raise InvalidInput("invalid enhanced or treebank_type scoring options")
    return treebank_type, enhanced


def _evaluate(pairs, treebank_type: dict[str, bool], enhanced: bool) -> dict[str, Any]:
    try:
        from udtools import udeval
    except ImportError as exc:
        raise PrerequisiteMissing("the official udtools scorer is not installed") from exc
    totals = defaultdict(lambda: {"correct": 0, "gold_total": 0, "system_total": 0, "aligned_total": 0, "has_alignment": False})
    try:
        for gold, system in pairs:
            # The upstream convenience filename loader leaves its file handle
            # open. Use its official stream API and own both handle lifetimes.
            with gold.open("r", encoding="utf-8") as gold_stream, system.open("r", encoding="utf-8") as system_stream:
                gold_data = udeval.load_conllu(gold_stream, str(gold), treebank_type)
                system_data = udeval.load_conllu(system_stream, str(system), treebank_type)
            scores = udeval.evaluate(gold_data, system_data)
            for name, score in scores.items():
                if name in ("ELAS", "EULAS") and not enhanced:
                    continue
                entry = totals[name]
                entry["correct"] += score.correct
                entry["gold_total"] += score.gold_total
                entry["system_total"] += score.system_total
                if score.aligned_total is not None:
                    entry["aligned_total"] += score.aligned_total
                    entry["has_alignment"] = True
    except Exception as exc:
        raise WorkerError("SCORER_FAILED", str(exc)) from exc
    result = {}
    for name, values in sorted(totals.items()):
        correct = values["correct"]
        gold = values["gold_total"]
        system = values["system_total"]
        aligned = values["aligned_total"] if values["has_alignment"] else None
        result[name] = {"correct": correct, "gold_total": gold, "system_total": system,
                        "aligned_total": aligned, "precision": correct / system if system else 0.0,
                        "recall": correct / gold if gold else 0.0,
                        "f1": 2 * correct / (gold + system) if gold + system else 0.0,
                        "aligned_accuracy": correct / aligned if aligned else None}
    return {"scores": result, "pair_count": len(pairs), "enhanced": enhanced, "treebank_type": treebank_type,
            "definition": "official scorer counts summed across file pairs before metric calculation"}


MAX_MISMATCHES = 50


def _sentences(path) -> list[tuple[str | None, list[list[str]]]]:
    """Syntactic words (integer IDs) per sentence, with sent_id; multiword ranges and empty nodes are skipped."""
    sentences, sent_id, words = [], None, []
    for line in path.read_text(encoding="utf-8").splitlines() + [""]:
        if not line.strip():
            if words or sent_id is not None:
                sentences.append((sent_id, words))
            sent_id, words = None, []
        elif line.startswith("#"):
            if line.startswith("# sent_id = "):
                sent_id = line[len("# sent_id = "):].strip()
        else:
            columns = line.split("\t")
            if len(columns) == 10 and columns[0].isdigit():
                words.append(columns)
    return sentences


def _mismatches(pairs) -> dict[str, Any]:
    """Word-level HEAD/DEPREL differences where both files tokenize a sentence identically (same word FORMs)."""
    rows, total, unaligned = [], 0, []
    for gold, system in pairs:
        gold_sentences, system_sentences = _sentences(gold), _sentences(system)
        for index, (expected, actual) in enumerate(zip(gold_sentences, system_sentences)):
            sent_id = expected[0] or f"#{index + 1}"
            if [word[1] for word in expected[1]] != [word[1] for word in actual[1]]:
                unaligned.append({"file": gold.name, "sent_id": sent_id})
                continue
            for want, got in zip(expected[1], actual[1]):
                attachment, relation = want[6] != got[6], want[7] != got[7]
                if not attachment and not relation:
                    continue
                total += 1
                if len(rows) < MAX_MISMATCHES:
                    rows.append({"file": gold.name, "sent_id": sent_id, "token_id": int(want[0]), "form": want[1],
                                 "kind": "attachment and relation" if attachment and relation else "attachment" if attachment else "relation",
                                 "gold_head": want[6], "system_head": got[6], "gold_deprel": want[7], "system_deprel": got[7]})
        if len(gold_sentences) != len(system_sentences):
            unaligned.append({"file": gold.name, "sent_id": f"{min(len(gold_sentences), len(system_sentences)) + 1}+ (sentence counts differ)"})
    return {"mismatch_count": total, "mismatches": rows, "unaligned_sentences": unaligned[:MAX_MISMATCHES],
            "mismatch_definition": "gold vs system HEAD and DEPREL per syntactic word, for sentences with identical word FORMs; not part of official scoring"}


def predictions_evaluate(args: dict[str, Any]) -> dict[str, Any]:
    _, gold = files_for(args, "gold_file_paths", default_all=False)
    _, prediction = files_for(args, "prediction_file_paths", default_all=False)
    if not gold or len(gold) != len(prediction):
        raise InvalidInput("gold and prediction file lists must have equal nonzero length")
    settings, enhanced = _options(args)
    pairs = list(zip(gold, prediction, strict=True))
    result = _evaluate(pairs, settings, enhanced)
    result.update(_mismatches(pairs))
    result["roles"] = {"gold": args["gold_file_paths"], "system": args["prediction_file_paths"]}
    return result


def annotation_pair_scores(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    reference = scoped_path(root, args.get("reference_annotation_path"))
    comparison = scoped_path(root, args.get("comparison_annotation_path"))
    settings, enhanced = _options(args)
    result = _evaluate([(reference, comparison)], settings, enhanced)
    result["roles"] = {"gold": args["reference_annotation_path"], "system": args["comparison_annotation_path"]}
    result["limitations"] = ["These directional scores are not chance-corrected annotator agreement."]
    return result
