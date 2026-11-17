"""Portable identities for the exact selected bytes, runtime sources and UD rules."""
from __future__ import annotations

from hashlib import sha256
import importlib
import json
from pathlib import Path
import re

from ..errors import InvalidInput, WorkerError
from ._artifacts import MAX_BYTES, json_bytes, manifest

_RULES = ("data.json", "deprels.json", "edeprels.json", "feats.json", "tospace.json", "udeprels.json", "upos.json")
_REVISION = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")
_LICENSE = re.compile(r"^(?:licen[sc]e|copying|copyright|notice)(?:[._-].*)?$", re.I)


def _read(file: Path, maximum: int = MAX_BYTES) -> bytes:
    if file.is_symlink() or not file.is_file() or not 0 <= file.stat().st_size <= maximum:
        raise InvalidInput("release provenance requires bounded ordinary source/rule files")
    data = file.read_bytes()
    if len(data) > maximum:
        raise InvalidInput("release provenance source exceeds its bound")
    return data


def _code(root: Path) -> dict:
    files = {}
    for file in sorted(root.rglob("*")):
        if file.suffix not in {".py", ".pl", ".pm", ".json"}:
            continue
        if len(files) >= 10000:
            raise InvalidInput("release runtime source inventory exceeds its bound")
        files[file.relative_to(root).as_posix()] = _read(file)
        if sum(map(len, files.values())) > MAX_BYTES:
            raise InvalidInput("release runtime source inventory exceeds its byte bound")
    entries = manifest(files)
    return {"files": entries, "sha256": sha256(json_bytes(entries)).hexdigest()}


def provenance(files: dict[str, bytes], args: dict) -> dict:
    selected = manifest(files)
    context_path = args.get("ud_context_path")
    if not isinstance(context_path, str) or not context_path:
        raise InvalidInput("release provenance requires the selected complete UD context")
    path = Path(context_path)
    if not path.is_absolute():
        raise InvalidInput("release context must be a verified absolute runtime or snapshot path")
    context = {}
    context_manifest = None
    if path.is_file():
        raw = _read(path, 1024 * 1024)
        try:
            context = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise InvalidInput("release context manifest is invalid") from exc
        rule_dir = context.get("rule_dir") if isinstance(context, dict) else None
        if not isinstance(rule_dir, str) or not rule_dir or ".." in Path(rule_dir).parts:
            raise InvalidInput("release context rule directory is invalid")
        context_manifest = sha256(raw).hexdigest()
        path = Path(rule_dir) if Path(rule_dir).is_absolute() else path.parent / rule_dir
    if path.is_symlink() or not path.is_dir():
        raise InvalidInput("release context rule directory is missing")
    rules = manifest({name: _read(path / name) for name in _RULES})
    hashes = {item["path"]: item["sha256"] for item in rules}
    context_hash = sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if context.get("rules") is not None and context.get("rules") != hashes or context.get("context_sha256") is not None and context.get("context_sha256") != context_hash:
        raise WorkerError("CONTEXT_RULE_HASH_MISMATCH", "release context bytes differ from their manifest")
    declarations = []
    if isinstance(context.get("tools_commit"), str):
        if not _REVISION.fullmatch(context["tools_commit"]):
            raise InvalidInput("release context tools revision is invalid")
        declarations.append({"repository": "UniversalDependencies/tools", "commit": context["tools_commit"], "evidence": "context-manifest declaration; source bytes identified separately"})
    checks = context.get("repository_checks", {})
    sources = checks.get("source_receipts", {}) if isinstance(checks, dict) else {}
    if isinstance(sources, dict):
        for name, record in sorted(sources.items()):
            if not isinstance(record, dict):
                continue
            source = record.get("source", record)
            if not isinstance(source, dict):
                raise InvalidInput("release upstream source declaration is invalid")
            commit = source.get("commit")
            if isinstance(commit, str) and _REVISION.fullmatch(commit):
                repository = source.get("repository", name)
                if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
                    raise InvalidInput("release upstream declaration requires a portable owner/repository identity")
                declaration = {"repository": repository, "commit": commit, "evidence": "context-manifest declaration"}
                if source.get("archive_sha256") is not None:
                    digest = source["archive_sha256"]
                    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                        raise InvalidInput("release upstream archive identity is invalid")
                    declaration["archive_sha256"] = digest
                declarations.append(declaration)
    implementation = _code(Path(__file__).resolve().parents[1])
    validator = {"status": "unavailable", "reason": "official validator source is not installed"}
    try:
        module = importlib.import_module("udtools")
    except ImportError:
        pass
    else:
        filename = getattr(module, "__file__", None)
        if isinstance(filename, str) and Path(filename).is_file():
            validator = {"status": "identified", "source": _code(Path(filename).resolve().parent)}
    licenses = [entry for entry in selected if _LICENSE.fullmatch(Path(entry["path"]).name)]
    return {"schema_version": 1, "selected_files_sha256": sha256(json_bytes(selected)).hexdigest(),
            "source_identity_method": "SHA-256 of canonical selected-file manifest; no Git commit inferred",
            "implementation": {"name": "ud-agent-skill-mcp-plugin", "version": "0.1.0-beta.1", "new_code_license": "MIT", "source": implementation},
            "validator": validator, "upstream_revision_declarations": declarations,
            "context": {"identity": "urn:ud-agent:context:sha256:" + context_hash, "sha256": context_hash, "rules": rules,
                        **({"manifest_sha256": context_manifest} if context_manifest else {})},
            "licenses": {"status": "present" if licenses else "not_selected", "files": licenses,
                         "interpretation": "Exact selected license/notice bytes; no license compatibility or publisher approval inferred"}}


def verify_manifest_provenance(value: dict, files: dict[str, bytes]) -> None:
    """Legacy archives remain readable; new identities must match actual bytes."""
    evidence = value.get("provenance")
    if evidence is None:
        return
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1 or evidence.get("selected_files_sha256") != sha256(json_bytes(manifest(files))).hexdigest():
        raise InvalidInput("candidate portable source provenance does not match packaged bytes")
    licenses = evidence.get("licenses")
    expected = [entry for entry in manifest(files) if _LICENSE.fullmatch(Path(entry["path"]).name)]
    if not isinstance(licenses, dict) or licenses.get("files") != expected or licenses.get("status") != ("present" if expected else "not_selected"):
        raise InvalidInput("candidate license inventory does not match packaged bytes")
    context = evidence.get("context")
    if (not isinstance(context, dict) or not isinstance(context.get("rules"), list) or len(context["rules"]) != len(_RULES)
            or any(not isinstance(row, dict) or set(row) != {"path", "sha256", "size_bytes"}
                   or type(row.get("size_bytes")) is not int or not 0 <= row["size_bytes"] <= MAX_BYTES for row in context["rules"])
            or {row["path"] for row in context["rules"]} != set(_RULES)):
        raise InvalidInput("candidate portable rule provenance is incomplete")
    hashes = {row["path"]: row.get("sha256") for row in context["rules"]}
    if any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{64}", item) for item in hashes.values()):
        raise InvalidInput("candidate rule hashes are invalid")
    identity = sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if context.get("sha256") != identity or context.get("identity") != "urn:ud-agent:context:sha256:" + identity or value.get("context") != context["identity"]:
        raise InvalidInput("candidate portable context identity differs")
