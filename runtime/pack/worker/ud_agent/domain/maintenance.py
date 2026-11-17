"""Bounded maintenance, handover, rename, and UD star reports."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from difflib import unified_diff
from hashlib import sha256
import math
import os
from pathlib import Path
import re
from typing import Any

from ..errors import InvalidInput, WorkerError
from . import validation
from ._artifacts import artifact, archive, collect, json_bytes, manifest, output_destination, parse_json
from ._common import files_for, parse_sentences, root_path, scoped_path, words
from .release import _release_inputs
from ._release_provenance import provenance


def maintenance_report(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    policy = parse_json(scoped_path(root, args.get("maintenance_policy_path")))
    allowed = {"required_files", "max_file_bytes", "remote_evidence", "require_remote_evidence", "max_evidence_age_seconds"}
    unknown = set(policy) - allowed
    if unknown:
        raise InvalidInput("unsupported maintenance policy fields: " + ", ".join(sorted(unknown)))
    checks = []
    required = policy.get("required_files", [])
    if not isinstance(required, list) or any(not isinstance(x, str) for x in required):
        raise InvalidInput("required_files must be an array of paths")
    for name in required:
        try:
            path = scoped_path(root, name)
        except InvalidInput:
            checks.append({"check": "required_file", "path": name, "passed": False})
        else:
            checks.append({"check": "required_file", "path": name, "passed": path.is_file()})
    max_bytes = policy.get("max_file_bytes")
    if max_bytes is not None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
            raise InvalidInput("max_file_bytes must be a nonnegative integer")
        _, paths = files_for(args)
        checks.extend({"check": "file_size", "path": p.relative_to(root).as_posix(), "size_bytes": p.stat().st_size,
                       "passed": p.stat().st_size <= max_bytes} for p in paths)
    evidence = policy.get("remote_evidence")
    if policy.get("require_remote_evidence", False):
        if not isinstance(evidence, dict) or not isinstance(evidence.get("retrieved_at"), str):
            checks.append({"check": "remote_evidence", "status": "incomplete", "reason": "evidence is missing"})
        else:
            try:
                when = datetime.fromisoformat(evidence["retrieved_at"].replace("Z", "+00:00"))
                if when.tzinfo is None:
                    raise ValueError("timezone required")
                age = (datetime.now(timezone.utc) - when.astimezone(timezone.utc)).total_seconds()
            except ValueError as exc:
                raise InvalidInput("remote evidence timestamp must be timezone-aware ISO format") from exc
            limit = policy.get("max_evidence_age_seconds", 86400)
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                raise InvalidInput("max_evidence_age_seconds must be a nonnegative integer")
            if age < -60 or age > limit:
                checks.append({"check": "remote_evidence", "status": "incomplete", "reason": "evidence is stale or future-dated"})
            else:
                checks.append({"check": "remote_evidence", "status": "completed", "passed": True, "age_seconds": age})
    if not checks:
        raise InvalidInput("maintenance policy must request at least one supported check")
    complete = all(c.get("status") != "incomplete" for c in checks)
    return {"status": "complete" if complete else "incomplete", "passed": all(c.get("passed") is True for c in checks) if complete else None,
            "checks": checks, "policy_sha256": sha256(json_bytes(policy)).hexdigest(),
            "limitations": ["No remote services or repositories were queried."]}


def handover_package_build(args: dict[str, Any]) -> dict[str, Any]:
    _, files = _release_inputs(args)
    name = "handover-manifest.json"
    if name in files:
        raise InvalidInput("input collides with the reserved handover manifest")
    evidence = provenance(files, args)
    inventory = {"schema_version": "1", "files": manifest(files),
                 "context": evidence["context"]["identity"], "provenance": evidence,
                 "limitations": ["Only explicitly selected or standard treebank files are included.",
                                 "Remote permissions, credentials, and account transfers are not included."]}
    handover = archive({**files, name: json_bytes(inventory)})
    return {"status": "complete", "output_dir_path": output_destination(args), "requires_broker_export": True,
            "manifest": inventory,
            "artifacts": [artifact("handover.tar", handover, "application/x-tar"),
                          artifact(name, json_bytes(inventory), "application/json")]}


def treebank_rename_plan(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    identity = parse_json(scoped_path(root, args.get("new_identity_path")))
    old, new = identity.get("old_name"), identity.get("new_name")
    if any(not isinstance(v, str) or not v or any(c in v for c in "/\\\r\n\0") for v in (old, new)) or old == new:
        raise InvalidInput("identity requires distinct safe old_name and new_name strings")
    related = args.get("related_repository_paths") or []
    if not isinstance(related, list):
        raise InvalidInput("related_repository_paths must be an array")
    roots = [root]
    for value in related:
        path = scoped_path(root, value, allow_directory=True)
        if not path.is_dir():
            raise InvalidInput("related repository paths must be directories")
        if path not in roots:
            roots.append(path)
    actions = []
    seen = set()
    for base_root in roots:
        for base, dirs, names in os.walk(base_root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in {".git", ".ud-agent-inputs"} and not (Path(base) / d).is_symlink())
            for name in sorted(names):
                path = Path(base) / name
                relative = path.relative_to(root).as_posix()
                if relative in seen or path.is_symlink() or not path.is_file():
                    continue
                seen.add(relative)
                replacement = None
                before_bytes = path.read_bytes()
                if name in {"README.md", "README.txt", "CONTRIBUTING.md"} and len(before_bytes) <= 1024 * 1024:
                    try:
                        before_text = before_bytes.decode("utf-8", errors="strict")
                    except UnicodeError:
                        before_text = None
                    if before_text is not None and old in before_text:
                        replacement = before_text.replace(old, new)
                if old in name:
                    destination = path.with_name(name.replace(old, new))
                    action = {"id": f"rename-{len(actions)+1}", "type": "rename_file", "source": relative,
                              "destination": destination.relative_to(root).as_posix(), "before_sha256": sha256(before_bytes).hexdigest(),
                              "target_before_sha256": None, "depends_on": [],
                              "conflict": destination.exists() or destination.is_symlink()}
                    if replacement is not None:
                        action.update(content=replacement, after_sha256=sha256(replacement.encode("utf-8")).hexdigest())
                    actions.append(action)
                elif replacement is not None:
                    actions.append({"id": f"edit-{len(actions)+1}", "type": "replace_file", "file_path": relative,
                                    "before_sha256": sha256(before_bytes).hexdigest(), "after_sha256": sha256(replacement.encode("utf-8")).hexdigest(),
                                    "content": replacement, "depends_on": [],
                                    "diff": "".join(unified_diff(before_text.splitlines(True), replacement.splitlines(True), fromfile=relative, tofile=relative))})
    fingerprints = {args["new_identity_path"]: sha256(scoped_path(root, args["new_identity_path"]).read_bytes()).hexdigest()}
    for action in actions:
        action["input_fingerprints"] = fingerprints
    return {"schema_version": "ud-plan-v1", "plan_type": "treebank_rename", "status": "complete", "old_name": old, "new_name": new, "actions": actions,
            "external_requirements": ["Rename remote repositories and update external references through authorized administrative workflows."],
            "limitations": ["The plan does not rename directories, execute commands, or access remote repositories."]}


def _metadata(root: Path) -> dict[str, str]:
    path = root / "README.md"
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise InvalidInput("README.md is not UTF-8") from exc
    result = {}
    for line in content.splitlines():
        match = re.match(r"^\s*(?:[*-]\s*)?([^:]+):\s*(.*?)\s*$", line)
        if match:
            result[match.group(1).strip()] = match.group(2).strip()
    return result


def _source(value: str, *, extended: bool) -> float:
    scales = {"manual native": 1.0, "converted with corrections": 0.9, "converted from manual": 0.8}
    if extended:
        scales["automatic with corrections"] = 0.5
    return scales.get(value, 0.4 if extended else 0.1)


def star_rating_report(args: dict[str, Any]) -> dict[str, Any]:
    """Reproduce evaluate_treebank.pl's weighted dimensions with mandatory validation."""
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("star rating requires at least one CoNLL-U file")
    options = args.get("options") or {}
    if not isinstance(options, dict):
        raise InvalidInput("options must be an object")
    metadata = _metadata(root)
    required = ("Lemmas", "UPOS", "Features", "Relations", "Genre", "Includes text")
    missing = [field for field in required if field not in metadata]
    counts = {"train": 0, "dev": 0, "test": 0}
    forms: Counter[str] = Counter()
    lemmas: Counter[str] = Counter()
    tags: set[str] = set()
    relations: set[str] = set()
    feature_count = 0
    n = 0
    for sentence in parse_sentences(root, paths):
        for token in words(sentence):
            n += 1
            if "ud-train" in sentence.file:
                counts["train"] += 1
            elif "ud-dev" in sentence.file:
                counts["dev"] += 1
            elif "ud-test" in sentence.file:
                counts["test"] += 1
            forms[token["form"]] += 1
            lemmas[token["lemma"]] += 1
            tags.add(token["upos"])
            relations.add(token["deprel"].split(":", 1)[0])
            feature_count += token["feats"] != "_"
    dimensions: dict[str, float] = {}
    if not missing:
        common_form = forms.most_common(1)[0][0] if forms else None
        common_lemma = lemmas.most_common(1)[0][0] if lemmas else None
        def underscore_tie(counts: Counter[str]) -> bool:
            return bool(counts and counts.get("_") == max(counts.values()) and sum(value == max(counts.values()) for value in counts.values()) > 1)
        if underscore_tie(forms) or underscore_tie(lemmas):
            missing.append("deterministic tie resolution for most-frequent '_' form or lemma")
        size = max(min(n, 1_000_000), 1)
        dimensions["size"] = max(math.log((size / 1000) ** 2), 0) / math.log(1_000_000)
        dimensions["split"] = 0.01 + 0.33 * (counts["train"] > 10000) + 0.33 * (counts["dev"] >= 10000) + 0.33 * (counts["test"] >= 10000)
        dimensions["lemmas"] = 0.01 if not lemmas or common_lemma == "_" else _source(metadata["Lemmas"], extended=True)
        dimensions["tags"] = max(0.01, len(tags) / 17 * _source(metadata["UPOS"], extended=False))
        fsource = _source(metadata["Features"], extended=True)
        dimensions["features"] = 0.01 if feature_count == 0 else (0.3 if feature_count < n / 3 else 0.5 if feature_count < n / 2 else 1) * fsource
        dimensions["udeprels"] = max(0.01, len(relations) / 37 * _source(metadata["Relations"], extended=False))
        official = {"academic", "bible", "blog", "email", "fiction", "government", "grammar-examples", "learner-essays", "legal", "medical", "news", "nonfiction", "poetry", "reviews", "social", "spoken", "web", "wiki"}
        dimensions["genres"] = max(1, sum(x in official for x in metadata["Genre"].split())) / len(official)
        availability = 1.0 if metadata["Includes text"].lower() == "yes" and forms and common_form != "_" else 0.1
    else:
        availability = None
    try:
        report = validation.validation_report({**args, "options": {"language_code": options.get("language_code")}})
        validation_result = {"status": "completed", "passed": report["passed"]}
    except WorkerError as exc:
        validation_result = {"status": "incomplete", "passed": None, "reason": str(exc), "code": exc.code}
    complete = not missing and validation_result["status"] == "completed"
    score = stars = None
    weights = {"size": 10, "split": 2, "lemmas": 3, "tags": 3, "features": 3, "udeprels": 3, "genres": 3}
    if complete:
        validity = 1.0 if validation_result["passed"] else 0.01
        score = sum(weights[k] * dimensions[k] for k in weights) / sum(weights.values()) * availability * validity if n > 1 else 0.0
        stars = math.floor(score * 10 + 0.5) / 2
    return {"status": "complete" if complete else "incomplete", "score": score, "stars": stars,
            "word_count": n, "split_counts": counts, "dimensions": dimensions, "weights": weights,
            "availability": availability, "validation": validation_result, "missing_metadata": missing,
            "method": "UD evaluate_treebank.pl weighted heuristic on staged bytes",
            "limitations": ["Heuristic compares treebanks within a language, not across languages.",
                            "No branch switch or remote lookup was performed."]}
