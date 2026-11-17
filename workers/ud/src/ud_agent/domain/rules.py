"""Inspect and compare complete, explicit language-rule contexts."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from ._common import digest, require_no_options, root_path, scoped_path
from . import validation
from ..errors import InvalidInput

_RULES = {"upos": "upos.json", "features": "feats.json", "udeprels": "udeprels.json", "deprels": "deprels.json",
          "edeprels": "edeprels.json", "auxiliaries": "data.json", "expressions": "tospace.json"}


def language_rules_report(args: dict[str, Any]) -> dict[str, Any]:
    root_path(args)
    lang = args.get("language_code")
    if not isinstance(lang, str) or not lang:
        raise InvalidInput("language_code must be a nonempty string")
    require_no_options(args)
    settings, _ = validation._settings({**args, "options": {"language_code": lang}})
    rule_dir = Path(settings["datapath"])
    entries = {}
    for key, filename in _RULES.items():
        try:
            content = json.loads((rule_dir / filename).read_text(encoding="utf-8"))
            value = content[key]
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
            raise InvalidInput(f"invalid rule data: {filename}") from exc
        if isinstance(value, dict):
            entries[key] = value.get(lang)
        elif isinstance(value, list):
            entries[key] = value
        else:
            raise InvalidInput(f"invalid rule data: {filename}")
    result = {"language_code": lang, "rules": entries,
              "source_hashes": {filename: digest(rule_dir / filename) for filename in _RULES.values()},
              "limitations": ["Local rule snapshots are not proof of the currently registered online UD conventions."]}
    peers = args.get("peer_treebank_paths") or []
    if peers:
        from .comparison import conventions_compare
        result["observed_peer_counts"] = conventions_compare({**args, "dimensions": ["upos", "deprel", "features"]})
    return result


def language_rule_impact_report(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    proposed = scoped_path(root, args.get("proposed_rules_path"), allow_directory=True)
    if not proposed.is_dir():
        raise InvalidInput("proposed_rules_path must be a directory containing a complete rule context")
    treebanks = args.get("affected_treebank_paths")
    if not isinstance(treebanks, list) or not treebanks or any(not isinstance(item, str) for item in treebanks):
        raise InvalidInput("affected_treebank_paths must be a nonempty array")
    results = []
    for item in treebanks:
        path = scoped_path(root, item, allow_directory=True)
        if not path.is_dir():
            raise InvalidInput("affected treebank paths must be directories")
        request = {"working_tree_path": str(path), "ud_context_path": args.get("ud_context_path"), "options": args.get("options")}
        before = validation.validation_report(request)
        after = validation.validation_report({**request, "ud_context_path": str(proposed)})
        results.append({"treebank": item, "before": before, "after": after})
    return {"comparisons": results,
            "definition": "same staged files and options, independently initialized official validator per context",
            "limitations": ["Local rule changes do not register official UD conventions."]}


def language_rule_change_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Prepare a complete immutable rule-context candidate, never edit official files."""
    from hashlib import sha256
    root = root_path(args)
    language = args.get("language_code")
    if not isinstance(language, str) or not language:
        raise InvalidInput("language_code must be a nonempty string")
    require_no_options(args)
    settings, _ = validation._settings({**args, "options": {"language_code": language}})
    base_dir = Path(settings["datapath"])
    proposed_dir = scoped_path(root, args.get("proposed_rules_path"), allow_directory=True)
    if not proposed_dir.is_dir():
        raise InvalidInput("proposed_rules_path must be a complete rule directory")
    files = {}
    input_fingerprints = {}
    base_hashes = {}
    candidate_hashes = {}
    for key, name in _RULES.items():
        file = scoped_path(root, (proposed_dir / name).relative_to(root).as_posix())
        try:
            content = file.read_bytes().decode("utf-8", errors="strict")
            parsed = json.loads(content)
            if not isinstance(parsed, dict) or key not in parsed or not isinstance(parsed[key], (dict, list)):
                raise ValueError("invalid rule family")
        except (OSError, UnicodeError, ValueError) as exc:
            raise InvalidInput(f"proposed rule data is invalid: {name}") from exc
        files[name] = content
        input_fingerprints[file.relative_to(root).as_posix()] = sha256(content.encode("utf-8")).hexdigest()
        base_hashes[name] = digest(base_dir / name)
        candidate_hashes[name] = input_fingerprints[file.relative_to(root).as_posix()]
    manifest_bytes = json.dumps(candidate_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    context_sha256 = sha256(manifest_bytes).hexdigest()
    changed = [name for name in sorted(files) if base_hashes[name] != candidate_hashes[name]]
    action = {"id": "prepare_context:" + context_sha256, "type": "prepare_context", "language_code": language,
              "files": files, "file_hashes": candidate_hashes, "base_hashes": base_hashes,
              "context_sha256": context_sha256, "input_fingerprints": input_fingerprints, "depends_on": []}
    return {"schema_version": "ud-plan-v1", "plan_type": "language_rule_change", "actions": [action] if changed else [],
            "changed_files": changed, "language_code": language,
            "validation": {"status": "not_run", "reason": "candidate context requires validator and host-broker verification"},
            "limitations": ["This plans a local context; it does not register or change official UD conventions."]}
