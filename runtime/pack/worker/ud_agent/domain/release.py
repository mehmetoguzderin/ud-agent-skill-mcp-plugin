"""Local release plans and byte-verified candidate and deposit artifacts."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import tempfile
from typing import Any

from ..errors import InvalidInput, WorkerError
from ._artifacts import artifact, archive, collect, json_bytes, manifest, output_destination, parse_json, read_archive
from ._common import files_for, root_path, scoped_path
from . import validation
from ._release_provenance import provenance, verify_manifest_provenance

MANIFEST_NAME = ".ud-agent-release-manifest.json"


def _release_inputs(args: dict[str, Any]) -> tuple[Path, dict[str, bytes]]:
    root = root_path(args)
    options = args.get("options") or {}
    if not isinstance(options, dict):
        raise InvalidInput("options must be an object")
    selection = options.get("file_paths")
    if selection is None:
        _, paths = files_for(args)
        selection = [path.relative_to(root).as_posix() for path in paths]
        for name in ("README.md", "LICENSE.txt", "LICENSE", "CONTRIBUTING.md"):
            if (root / name).is_file() and not (root / name).is_symlink():
                selection.append(name)
    files = collect(root, selection)
    if not files:
        raise InvalidInput("release input selection cannot be empty")
    if MANIFEST_NAME in files:
        raise InvalidInput("release input collides with reserved manifest")
    return root, files


def _validation(files: dict[str, bytes], args: dict[str, Any], language: Any) -> dict[str, Any]:
    selected = sorted(name for name in files if name.endswith(".conllu"))
    if not selected:
        return {"status": "incomplete", "passed": None, "reason": "candidate contains no CoNLL-U files"}
    if not isinstance(language, str) or not language:
        return {"status": "incomplete", "passed": None, "reason": "explicit language_code is required"}
    with tempfile.TemporaryDirectory(prefix="ud-agent-release-validation-") as temp:
        root = Path(temp)
        for name, content in files.items():
            target = root.joinpath(*name.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        request = {"working_tree_path": str(root), "file_paths": selected,
                   "ud_context_path": args.get("ud_context_path"), "options": {"language_code": language}}
        try:
            result = validation.validation_report(request)
        except WorkerError as exc:
            return {"status": "incomplete", "passed": None, "reason": str(exc), "code": exc.code}
        return {"status": "completed", "passed": result["passed"], "report": result}


def release_plan(args: dict[str, Any]) -> dict[str, Any]:
    root, files = _release_inputs(args)
    target = args.get("target_release")
    if not isinstance(target, str) or not target or any(c in target for c in "\r\n\0"):
        raise InvalidInput("target_release must be a nonempty release identifier")
    previous = None
    if args.get("previous_release_path") is not None:
        previous_path = scoped_path(root, args["previous_release_path"])
        previous = {"path": args["previous_release_path"], "sha256": sha256(previous_path.read_bytes()).hexdigest()}
    options = args.get("options") or {}
    language = options.get("language_code")
    checks = _validation(files, args, language)
    evidence = provenance(files, args)
    return {"schema_version": "1", "target_release": target, "files": manifest(files),
            "previous_release": previous, "language_code": language, "validation": checks, "provenance": evidence, "context": evidence["context"]["identity"],
            "status": "complete" if checks["status"] == "completed" else "incomplete",
            "ready": checks["status"] == "completed" and checks["passed"] is True,
            "external_requirements": ["Official release and registry publication require separate authority."],
            "limitations": ["A local plan does not certify official release acceptance."]}


def _planned_inputs(root: Path, plan: dict[str, Any]) -> dict[str, bytes]:
    entries = plan.get("files")
    if not isinstance(entries, list) or not entries or any(not isinstance(item, dict) or not isinstance(item.get("path"), str) for item in entries):
        raise InvalidInput("release plan must contain file paths and hashes")
    files = collect(root, [item["path"] for item in entries])
    actual = {item["path"]: item for item in manifest(files)}
    for entry in entries:
        if actual[entry["path"]]["sha256"] != entry.get("sha256") or actual[entry["path"]]["size_bytes"] != entry.get("size_bytes"):
            raise WorkerError("CONFLICT", f"release input changed since planning: {entry['path']}")
    return files


def release_candidate_build(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    plan = parse_json(scoped_path(root, args.get("release_plan_path")))
    files = _planned_inputs(root, plan)
    if MANIFEST_NAME in files:
        raise InvalidInput("reserved release manifest path is not permitted")
    if not isinstance(plan.get("target_release"), str) or not plan["target_release"]:
        raise InvalidInput("release plan requires target_release")
    evidence = provenance(files, args)
    if "provenance" in plan and plan["provenance"] != evidence:
        raise WorkerError("CONFLICT", "release source, context or license provenance changed since planning")
    release_manifest = {"schema_version": "1", "target_release": plan["target_release"], "files": manifest(files),
                        "context": evidence["context"]["identity"], "language_code": plan.get("language_code"), "provenance": evidence}
    candidate = archive({**files, MANIFEST_NAME: json_bytes(release_manifest)})
    extracted = read_archive(candidate)
    if set(extracted) != set(files) | {MANIFEST_NAME}:
        raise WorkerError("PACKAGE_INCOMPLETE", "package members differ from the input manifest")
    packaged_files = {name: extracted[name] for name in files}
    if manifest(packaged_files) != manifest(files):
        raise WorkerError("PACKAGE_MISMATCH", "packaged bytes differ from the release plan")
    checks = _validation(packaged_files, args, plan.get("language_code"))
    return {"status": "complete" if checks["status"] == "completed" else "incomplete",
            "ready": checks["status"] == "completed" and checks["passed"] is True,
            "validation": checks, "manifest": release_manifest,
            "output_dir_path": output_destination(args), "requires_broker_export": True,
            "artifacts": [artifact("release-candidate.tar", candidate, "application/x-tar"),
                          artifact("release-manifest.json", json_bytes(release_manifest), "application/json")],
            "limitations": ["Validation was run against bytes read back from the candidate archive.",
                            "Output artifacts require authorization and export by the host broker."]}


def release_deposit_prepare(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    candidate_path = scoped_path(root, args.get("release_candidate_path"))
    metadata = parse_json(scoped_path(root, args.get("deposit_metadata_path")))
    if not isinstance(metadata.get("title"), str) or not metadata["title"]:
        raise InvalidInput("deposit metadata requires a nonempty title")
    if not isinstance(metadata.get("license"), str) or not metadata["license"]:
        raise InvalidInput("deposit metadata requires a nonempty license")
    candidate_bytes = candidate_path.read_bytes()
    entries = read_archive(candidate_bytes)
    if MANIFEST_NAME not in entries:
        raise InvalidInput("candidate archive has no release manifest")
    import json
    try:
        info = json.loads(entries.pop(MANIFEST_NAME).decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise InvalidInput("candidate release manifest is invalid") from exc
    if not isinstance(info, dict) or info.get("files") != manifest(entries):
        raise InvalidInput("candidate contents do not match the release manifest")
    verify_manifest_provenance(info, entries)
    current = provenance(entries, args)
    if "provenance" in info and info["provenance"]["context"] != current["context"]:
        raise WorkerError("CONFLICT", "deposit validation context differs from the candidate rule snapshot")
    checks = _validation(entries, args, info.get("language_code"))
    deposit = {"schema_version": "1", "metadata": metadata, "candidate_sha256": sha256(candidate_bytes).hexdigest(),
               "candidate_manifest": info, "validation": checks,
               "external_action": "Submit using the deposit service's own workflow; this operation does not upload."}
    return {"status": "complete" if checks["status"] == "completed" else "incomplete",
            "ready": checks["status"] == "completed" and checks["passed"] is True,
            "output_dir_path": output_destination(args), "requires_broker_export": True,
            "artifacts": [artifact("deposit-preparation.json", json_bytes(deposit), "application/json")],
            "validation": checks, "limitations": ["Preparation does not assert repository, registry, or deposit acceptance."]}
