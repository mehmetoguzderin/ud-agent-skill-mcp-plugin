"""Bounded, explicit conversion and alignment reports."""
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from ..errors import InvalidInput
from ._common import files_for, parse_sentences, require_no_options, root_path, scoped_path, words


def _text(root: Path, path: str, fmt: str) -> tuple[str, list[dict[str, Any]]]:
    selected = scoped_path(root, path)
    if fmt == "text":
        return selected.read_bytes().decode("utf-8", errors="strict"), []
    if fmt == "conllu":
        sentences = list(parse_sentences(root, [selected]))
        missing = [s.location for s in sentences if s.text is None]
        return "\n".join(s.text for s in sentences if s.text is not None), missing
    raise InvalidInput("text comparison supports text and conllu inputs")


def text_content_compare(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    left, left_missing = _text(root, args.get("left_path"), args.get("left_format"))
    right, right_missing = _text(root, args.get("right_path"), args.get("right_format"))
    complete = not left_missing and not right_missing
    return {"equal": left == right if complete else None, "left_length": len(left), "right_length": len(right),
            "left_missing_text": left_missing, "right_missing_text": right_missing,
            "complete": complete, "definition": "exact Unicode code-point comparison without normalization"}


def token_alignment_report(args: dict[str, Any]) -> dict[str, Any]:
    root, source_paths = files_for(args, "source_file_paths", default_all=False)
    _, target_paths = files_for(args, "target_file_paths", default_all=False)
    if not source_paths or not target_paths:
        raise InvalidInput("both source and target file lists must be nonempty")
    require_no_options(args)
    def collect(paths):
        return [(row["form"], {**sentence.location, "token_id": row["id"]})
                for sentence in parse_sentences(root, paths) for row in words(sentence)]
    source = collect(source_paths)
    target = collect(target_paths)
    matcher = SequenceMatcher(None, [x[0] for x in source], [x[0] for x in target], autojunk=False)
    segments = []
    for kind, i1, i2, j1, j2 in matcher.get_opcodes():
        segments.append({"kind": kind, "source": [{"form": f, **loc} for f, loc in source[i1:i2]],
                         "target": [{"form": f, **loc} for f, loc in target[j1:j2]]})
    exact = sum(min(len(s["source"]), len(s["target"])) for s in segments if s["kind"] == "equal")
    return {"segments": segments, "source_count": len(source), "target_count": len(target), "exact_matches": exact,
            "method": "exact token-form sequence alignment, no Unicode normalization", "complete": True}


def dataset_split_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic document-aware assignment, without editing files."""
    import json
    import math
    import random
    from ._common import digest

    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    spec_path = scoped_path(root, args.get("split_spec_path"))
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InvalidInput("split specification must be a UTF-8 JSON object") from exc
    if not isinstance(spec, dict) or set(spec) - {"splits", "output_paths"} or not isinstance(spec.get("splits"), dict) or not spec["splits"]:
        raise InvalidInput("split specification must contain a nonempty splits object")
    weights = spec["splits"]
    if any(not isinstance(name, str) or not name or not isinstance(value, (int, float)) or isinstance(value, bool)
           or not math.isfinite(value) or value <= 0 for name, value in weights.items()):
        raise InvalidInput("split names must be nonempty and weights must be finite positive numbers")
    from ._artifacts import relative_name
    outputs = spec.get("output_paths", {name: f"splits/{name}.conllu" for name in weights})
    if not isinstance(outputs, dict) or set(outputs) != set(weights):
        raise InvalidInput("output_paths must name exactly one relative destination for each split")
    for name, destination in outputs.items():
        if relative_name(destination) != destination or not destination.endswith(".conllu"):
            raise InvalidInput("split output paths must be canonical relative CoNLL-U paths")
    if len(set(outputs.values())) != len(outputs) or any(path.relative_to(root).as_posix() in outputs.values() for path in paths):
        raise InvalidInput("split output paths must be distinct and cannot overwrite source files")
    seed = args.get("seed")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise InvalidInput("seed must be an integer")
    require_no_options(args)
    groups = []
    for path in paths:
        current = []
        group_number = 0
        for sentence in parse_sentences(root, [path]):
            starts_document = any(comment == "# newdoc" or comment.startswith("# newdoc id =") for comment in sentence.comments)
            if starts_document and current:
                groups.append((path.relative_to(root).as_posix(), group_number, current))
                current = []
                group_number += 1
            current.append(sentence.location)
        if current:
            groups.append((path.relative_to(root).as_posix(), group_number, current))
    if not groups:
        raise InvalidInput("at least one sentence is required for a split plan")
    shuffled = list(groups)
    random.Random(seed).shuffle(shuffled)
    total_sentences = sum(len(group) for _, _, group in shuffled)
    weight_sum = math.fsum(weights.values())
    expected = {name: total_sentences * weight / weight_sum for name, weight in weights.items()}
    counts = {name: 0 for name in weights}
    assignments = []
    for file, group_number, sentences in shuffled:
        name = max(sorted(weights), key=lambda item: expected[item] - counts[item])
        counts[name] += len(sentences)
        assignments.append({"split": name, "source_file": file, "document_ordinal": group_number,
                            "sentences": sentences})
    from ..conllu.core import Document
    documents = {path.relative_to(root).as_posix(): Document(str(root), path.relative_to(root).as_posix()) for path in paths}
    pieces = {name: [] for name in weights}
    for assignment in assignments:
        for location in assignment["sentences"]:
            raw = documents[location["file_path"]].sentences[location["ordinal"]].original
            if not raw.endswith(("\n\n", "\r\n\r\n")):
                newline = "\r\n" if "\r\n" in raw else "\n"
                raw += newline if raw.endswith("\n") else newline * 2
            pieces[assignment["split"]].append(raw)
    fingerprints = {path.relative_to(root).as_posix(): digest(path) for path in paths}
    fingerprints[spec_path.relative_to(root).as_posix()] = digest(spec_path)
    from hashlib import sha256
    actions = []
    for name in sorted(weights):
        content = "".join(pieces[name])
        actions.append({"id": f"dataset_split:{name}", "type": "create_file", "file_path": outputs[name],
                        "before_sha256": None, "after_sha256": sha256(content.encode("utf-8")).hexdigest(),
                        "content": content, "depends_on": [], "input_fingerprints": fingerprints})
    return {"schema_version": "ud-plan-v1", "plan_type": "dataset_split", "seed": seed, "assignments": assignments,
            "counts": counts, "actions": actions, "source_fingerprints": fingerprints,
            "limitations": ["Document groups remain intact; actual proportions may differ from requested weights."]}


def annotation_import_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Create fingerprinted file-replacement plans for fully aligned annotations."""
    import difflib
    from ..conllu.core import COLUMNS, Document, WORD
    from ._common import digest

    root, sources = files_for(args, "source_annotation_paths", default_all=False)
    _, targets = files_for(args, "target_file_paths", default_all=False)
    if not sources or len(sources) != len(targets):
        raise InvalidInput("source and target annotation file lists must have equal nonzero length")
    if set(sources) & set(targets):
        raise InvalidInput("source and target annotation files must be distinct")
    columns = args.get("columns")
    supported = {"LEMMA", "UPOS", "XPOS", "FEATS", "MISC"}
    if not isinstance(columns, list) or not columns or any(not isinstance(column, str) or column not in supported for column in columns) or len(set(columns)) != len(columns):
        raise InvalidInput("columns must be a nonempty unique selection of LEMMA, UPOS, XPOS, FEATS, and MISC")
    require_no_options(args)
    actions = []
    pairs = []
    for source, target in zip(sources, targets, strict=True):
        source_sentences = list(parse_sentences(root, [source]))
        target_doc = Document(str(root), target.relative_to(root).as_posix())
        if len(source_sentences) != len(target_doc.sentences):
            raise InvalidInput("source and target must have identical sentence counts")
        compared = 0
        for source_sentence, target_sentence in zip(source_sentences, target_doc.sentences, strict=True):
            source_words = words(source_sentence)
            target_words = [(index, row) for index, row in target_sentence.rows() if WORD.fullmatch(row[0])]
            if [row["form"] for row in source_words] != [row[1] for _, row in target_words]:
                raise InvalidInput("source and target token forms must align exactly in each sentence")
            for source_word, (index, target_row) in zip(source_words, target_words, strict=True):
                row = list(target_row)
                for column in columns:
                    field = column.lower()
                    row[COLUMNS.index(field)] = source_word[field]
                if row != target_row:
                    target_sentence.set_row(index, row)
                compared += 1
        candidate = target_doc.candidate()
        if candidate:
            old = target_doc.before.decode("utf-8")
            new = candidate["content"]
            actions.append({"id": "annotation_import:" + candidate["file_path"], "type": "replace_file", **candidate,
                            "input_fingerprints": {source.relative_to(root).as_posix(): digest(source)},
                            "depends_on": [], "diff": "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                                                                   fromfile=candidate["file_path"], tofile=candidate["file_path"]))})
        pairs.append({"source": source.relative_to(root).as_posix(), "target": target_doc.file_path, "aligned_words": compared})
    return {"schema_version": "ud-plan-v1", "plan_type": "annotation_import", "actions": actions, "pairs": pairs,
            "columns": columns, "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"},
            "limitations": ["Imports only exactly aligned sentence/token sequences; dependency-bearing columns require explicit remapping."]}


def tagset_conversion_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Plan explicit caller-supplied tag mappings without guessing unknown tags."""
    import difflib
    from ..conllu.core import COLUMNS, Document, WORD

    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("at least one CoNLL-U file is required")
    source = args.get("source_tagset")
    target = args.get("target_tagset")
    if not isinstance(source, str) or not source or not isinstance(target, str) or not target:
        raise InvalidInput("source_tagset and target_tagset must be nonempty strings")
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"mapping", "source_column", "target_column"}:
        raise InvalidInput("unsupported tagset conversion options")
    source_column = options.get("source_column", "XPOS")
    target_column = options.get("target_column", "UPOS")
    if source_column not in ("UPOS", "XPOS") or target_column not in ("UPOS", "XPOS"):
        raise InvalidInput("tagset columns must be UPOS or XPOS")
    mapping = options.get("mapping")
    identity = source == target and source_column == target_column
    if mapping is None and identity:
        mapping = {}
    if not isinstance(mapping, dict) or (not mapping and not identity) or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v for k, v in mapping.items()):
        raise InvalidInput("a nonempty explicit tag mapping is required")
    unmapped = []
    candidates = []
    for path in paths:
        document = Document(str(root), path.relative_to(root).as_posix())
        for sentence_index, sentence in enumerate(document.sentences):
            for index, cells in sentence.rows():
                if not WORD.fullmatch(cells[0]):
                    continue
                value = cells[COLUMNS.index(source_column.lower())]
                mapped = value if identity and not mapping else mapping.get(value)
                if mapped is None:
                    unmapped.append({"file_path": document.file_path, "sentence_ordinal": sentence_index, "token_id": cells[0], "tag": value})
                    continue
                if mapped != cells[COLUMNS.index(target_column.lower())]:
                    cells[COLUMNS.index(target_column.lower())] = mapped
                    sentence.set_row(index, cells)
        candidate = document.candidate()
        if candidate:
            old = document.before.decode("utf-8")
            new = candidate["content"]
            candidates.append({"id": "tagset_conversion:" + document.file_path, "type": "replace_file", **candidate,
                               "depends_on": [], "diff": "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                                                                      fromfile=document.file_path, tofile=document.file_path))})
    return {"schema_version": "ud-plan-v1", "plan_type": "tagset_conversion", "status": "needs_annotation" if unmapped else "ready",
            "source_tagset": source, "target_tagset": target, "source_column": source_column, "target_column": target_column,
            "unmapped": unmapped, "actions": [] if unmapped else candidates,
            "validation": {"status": "not_run", "reason": "candidate requires broker validation before apply"},
            "limitations": ["Only the supplied tag mapping is used; unknown tags are not guessed."]}


def tokenization_change_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Describe exact tokenization differences and required annotation decisions."""
    require_no_options(args)
    report = token_alignment_report({"working_tree_path": args.get("working_tree_path"),
                                     "source_file_paths": args.get("source_tokenization_paths"),
                                     "target_file_paths": args.get("target_file_paths")})
    from ._common import digest
    root, sources = files_for(args, "source_tokenization_paths", default_all=False)
    _, targets = files_for(args, "target_file_paths", default_all=False)
    source_fingerprints = {path.relative_to(root).as_posix(): digest(path) for path in sources}
    target_fingerprints = {path.relative_to(root).as_posix(): digest(path) for path in targets}
    actions = []
    for segment in report["segments"]:
        if segment["kind"] == "equal":
            continue
        desired, current = segment["source"], segment["target"]
        if len(current) == 1 and len(desired) > 1:
            action = "token_split"
        elif len(current) > 1 and len(desired) == 1:
            action = "tokens_merge"
        else:
            action = "tokenization_reconcile"
        actions.append({"id": f"tokenization:{len(actions)}", "type": action, "source_tokens": desired,
                        "target_tokens": current, "requires_annotation_map": True})
    for action in actions:
        action["depends_on"] = []
        action["input_fingerprints"] = {**source_fingerprints, **target_fingerprints}
    return {"schema_version": "ud-plan-v1", "plan_type": "tokenization_change", "status": "needs_annotation" if actions else "ready",
            "actions": actions, "alignment": report, "source_fingerprints": source_fingerprints,
            "target_fingerprints": target_fingerprints,
            "limitations": ["Affected dependency, enhanced graph, surface, and boundary annotations require explicit reconstruction."]}


def sentence_segmentation_change_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Compare boundaries over an identical concatenated token-character stream."""
    root, sources = files_for(args, "source_segmentation_paths", default_all=False)
    _, targets = files_for(args, "target_file_paths", default_all=False)
    if not sources or not targets:
        raise InvalidInput("source and target file lists must be nonempty")
    require_no_options(args)
    from ._common import digest
    source_fingerprints = {path.relative_to(root).as_posix(): digest(path) for path in sources}
    target_fingerprints = {path.relative_to(root).as_posix(): digest(path) for path in targets}
    def segments(paths):
        result = []
        offset = 0
        pieces = []
        for sentence in parse_sentences(root, paths):
            sentence_words = words(sentence)
            if not sentence_words:
                raise InvalidInput("cannot align a sentence without ordinary word rows")
            text = "".join(row["form"] for row in sentence_words)
            pieces.append(text)
            offset += len(text)
            result.append({"offset": offset, "location": sentence.location})
        return "".join(pieces), result
    source_text, desired = segments(sources)
    target_text, current = segments(targets)
    if source_text != target_text:
        return {"schema_version": "ud-plan-v1", "plan_type": "sentence_segmentation_change", "status": "conflict", "actions": [],
                "reason": "source and target token-character streams differ",
                "coverage": {"source_characters": len(source_text), "target_characters": len(target_text)},
                "source_fingerprints": source_fingerprints, "target_fingerprints": target_fingerprints}
    source_boundaries = {item["offset"]: item["location"] for item in desired[:-1]}
    target_boundaries = {item["offset"]: item["location"] for item in current[:-1]}
    actions = []
    for offset in sorted(source_boundaries.keys() - target_boundaries.keys()):
        actions.append({"id": f"sentence_split:{offset}", "type": "tree_split", "character_offset": offset,
                        "desired_after": source_boundaries[offset], "requires_annotation_map": True})
    for offset in sorted(target_boundaries.keys() - source_boundaries.keys()):
        actions.append({"id": f"sentence_merge:{offset}", "type": "trees_merge", "character_offset": offset,
                        "current_after": target_boundaries[offset], "requires_annotation_map": True})
    for action in actions:
        action["depends_on"] = []
        action["input_fingerprints"] = {**source_fingerprints, **target_fingerprints}
    return {"schema_version": "ud-plan-v1", "plan_type": "sentence_segmentation_change", "status": "needs_annotation" if actions else "ready",
            "actions": actions, "coverage": {"source_sentences": len(desired), "target_sentences": len(current)},
            "source_fingerprints": source_fingerprints, "target_fingerprints": target_fingerprints,
            "definition": "sentence boundaries over identical concatenated FORM code points, without Unicode normalization",
            "limitations": ["Changing boundaries requires explicit sentence IDs, dependency reconstruction and metadata ownership."]}


def _export_destination(value: Any) -> str:
    from pathlib import PurePosixPath, PureWindowsPath
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InvalidInput("output_dir_path must be a nonempty absolute host path")
    if not PurePosixPath(value).is_absolute() and not PureWindowsPath(value).is_absolute():
        raise InvalidInput("output_dir_path must be a nonempty absolute host path")
    return value


def _export_name(name: Any) -> str:
    from pathlib import PurePosixPath, PureWindowsPath
    if not isinstance(name, str) or not name or name in (".", "..") or PurePosixPath(name).name != name or PureWindowsPath(name).name != name or any(c in name for c in "\x00\r\n"):
        raise InvalidInput("output filename must be a single safe path component")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if name.endswith((".", " ")) or any(c in name for c in '<>:"|?*') or name.split(".", 1)[0].upper() in reserved or any(ord(c) < 32 for c in name):
        raise InvalidInput("output filename is not portable to supported platforms")
    return name


def _artifact(name: str, content: str, mime: str) -> dict[str, Any]:
    from hashlib import sha256
    data = content.encode("utf-8")
    return {"filename": _export_name(name), "content": content, "mime_type": mime, "size_bytes": len(data),
            "sha256": sha256(data).hexdigest()}


def format_convert(args: dict[str, Any]) -> dict[str, Any]:
    """Prepare explicit text or CoNLL-X exports for a host-authorized destination."""
    root, paths = files_for(args, "input_paths", default_all=False)
    if not paths:
        raise InvalidInput("at least one input file is required")
    target = args.get("target_format")
    if target not in ("text", "conllx", "conllu"):
        raise InvalidInput("target_format must be text, conllx or conllu")
    destination = _export_destination(args.get("output_dir_path"))
    require_no_options(args)
    artifacts = []
    seen = set()
    for path in paths:
        extension = {"text": ".txt", "conllx": ".conllx", "conllu": ".conllu"}[target]
        name = _export_name(path.stem + extension)
        if name.casefold() in seen:
            raise InvalidInput("output filename collision")
        seen.add(name.casefold())
        if target == "conllu":
            content = path.read_bytes().decode("utf-8", errors="strict")
        elif target == "text":
            sentences = list(parse_sentences(root, [path]))
            if any(sentence.text is None for sentence in sentences):
                raise InvalidInput("text export requires text metadata for every sentence")
            content = "".join(sentence.text + "\n" for sentence in sentences)
        else:
            sentences = list(parse_sentences(root, [path]))
            chunks = []
            for sentence in sentences:
                for row in words(sentence):
                    chunks.append("\t".join(row[field] for field in ("id", "form", "lemma", "upos", "xpos", "feats", "head", "deprel")) + "\t_\t_\n")
                chunks.append("\n")
            content = "".join(chunks)
        artifacts.append(_artifact(name, content, "text/plain; charset=utf-8"))
    loss = {"conllu": [], "text": ["all structured annotations and comments other than text"],
            "conllx": ["multiword tokens", "empty nodes", "enhanced dependencies", "MISC", "comments"]}[target]
    return {"status": "candidate", "requires_host_export": True, "output_dir_path": destination,
            "artifacts": artifacts, "losses": loss,
            "limitations": ["Artifacts require authorized host export and an existing-file conflict check."]}


def sentence_batch_extract(args: dict[str, Any]) -> dict[str, Any]:
    """Prepare a single sentence batch for an authorized host destination."""
    import json
    from ..conllu.core import Document
    root = root_path(args)
    selection = scoped_path(root, args.get("selection_path"))
    destination = _export_destination(args.get("output_dir_path"))
    options = args.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict) or set(options) - {"output_filename"}:
        raise InvalidInput("unsupported sentence extraction options")
    filename = _export_name(options.get("output_filename", "sentences.conllu"))
    try:
        spec = json.loads(selection.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InvalidInput("selection must be a UTF-8 JSON document") from exc
    if not isinstance(spec, dict) or set(spec) != {"sentences"} or not isinstance(spec["sentences"], list) or not spec["sentences"]:
        raise InvalidInput("selection must contain a nonempty sentences array")
    documents = {}
    seen = set()
    chunks = []
    selected = []
    for ref in spec["sentences"]:
        if not isinstance(ref, dict) or set(ref) - {"file_path", "sent_id", "ordinal", "fingerprint"} or not isinstance(ref.get("file_path"), str):
            raise InvalidInput("invalid sentence selection reference")
        file_path = ref["file_path"]
        if file_path not in documents:
            documents[file_path] = Document(str(root), file_path)
        document = documents[file_path]
        index, sentence = document.find(ref)
        identity = (file_path, index)
        if identity in seen:
            raise InvalidInput("duplicate sentence selection")
        seen.add(identity)
        raw = sentence.original
        if not raw.endswith("\n\n") and not raw.endswith("\r\n\r\n"):
            newline = "\r\n" if "\r\n" in raw else "\n"
            raw += newline if raw.endswith("\n") else newline * 2
        chunks.append(raw)
        selected.append({"file_path": file_path, "ordinal": index, "sent_id": ref.get("sent_id")})
    return {"status": "candidate", "requires_host_export": True, "output_dir_path": destination,
            "artifacts": [_artifact(filename, "".join(chunks), "text/plain; charset=utf-8")], "selected": selected,
            "limitations": ["The host must authorize and export the artifact with an explicit conflict policy."]}
