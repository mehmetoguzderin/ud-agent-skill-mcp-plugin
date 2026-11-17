"""Read-only inspection of the staged workspace."""
from pathlib import Path
import os
from typing import Any

from ._common import digest, root_path, scoped_path
from ..errors import InvalidInput
from ..evidence import git_base, staged_git_base


def workspace_inspect(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    files = []
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {".git", ".ud-agent-inputs"} and not (Path(base) / d).is_symlink())
        for name in sorted(names):
            path = Path(base) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                files.append({"path": rel, "kind": "symlink", "included": False})
            elif path.is_file():
                files.append({"path": rel, "kind": "file", "size_bytes": path.stat().st_size, "sha256": digest(path)})
            else:
                files.append({"path": rel, "kind": "special", "included": False})
    related = args.get("related_repository_paths") or []
    if not isinstance(related, list):
        raise InvalidInput("related_repository_paths must be an array")
    verified = [str(scoped_path(root, value, allow_directory=True).relative_to(root)) for value in related]
    return {"files": files, "related_repository_paths": verified,
            "limitations": ["Inventory reflects staged workspace bytes; Git history and remote status require broker evidence."]}


def treebank_create(args: dict[str, Any]) -> dict[str, Any]:
    """Create a local treebank scaffold as a broker-applied candidate."""
    import base64
    import json
    from hashlib import sha256
    from ._artifacts import MAX_BYTES, MAX_FILES, collect, manifest

    root = root_path(args)
    metadata_file = scoped_path(root, args.get("metadata_path"))
    try:
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InvalidInput("metadata_path must contain a JSON object") from exc
    if not isinstance(metadata, dict) or any(not isinstance(metadata.get(k), str) or not metadata[k] for k in ("treebank_name", "language_code")):
        raise InvalidInput("metadata requires treebank_name and language_code")
    name, language = metadata["treebank_name"], metadata["language_code"]
    if any(c in name + language for c in "\r\n\0/\\"):
        raise InvalidInput("treebank_name and language_code must be single safe values")
    template_path = args.get("template_path")
    if template_path is None:
        files = {"README.md": f"# {name}\n\nLanguage code: {language}\n".encode("utf-8"),
                 "CONTRIBUTING.md": b"Describe annotation and contribution practices here.\n"}
    else:
        template = scoped_path(root, template_path, allow_directory=True)
        if not template.is_dir():
            raise InvalidInput("template_path must identify a directory")
        selected = []
        for base, dirs, names in os.walk(template, followlinks=False):
            if any((Path(base) / d).is_symlink() for d in dirs):
                raise InvalidInput("template must not contain symlink directories")
            dirs.sort()
            for filename in sorted(names):
                path = Path(base) / filename
                if path.is_symlink() or not path.is_file():
                    raise InvalidInput("template must contain ordinary files only")
                selected.append(path.relative_to(root).as_posix())
        if len(selected) > MAX_FILES:
            raise InvalidInput("template has too many files")
        sources = collect(root, selected)
        files = {}
        for source, content in sources.items():
            relative = Path(source).relative_to(template.relative_to(root)).as_posix()
            try:
                text = content.decode("utf-8")
            except UnicodeError:
                files[relative] = content
            else:
                files[relative] = text.replace("{{treebank_name}}", name).replace("{{language_code}}", language).encode("utf-8")
        if sum(len(value) for value in files.values()) > MAX_BYTES:
            raise InvalidInput("expanded scaffold exceeds the size limit")
    conflicts = [item["path"] for item in manifest(files) if (root / item["path"]).exists() or (root / item["path"]).is_symlink()]
    if conflicts:
        return {"status": "conflict", "conflicts": conflicts, "changes": []}
    changes = [{"file_path": item["path"], "before_sha256": None, "after_sha256": item["sha256"],
                "size_bytes": item["size_bytes"], "content_base64": base64.b64encode(files[item["path"]]).decode("ascii")}
               for item in manifest(files)]
    return {"status": "candidate", "requires_host_commit": True, "changes": changes, "metadata": metadata,
            "limitations": ["Candidate scaffold requires broker authorization and user-supplied annotation."]}


def workspace_sync_plan(args: dict[str, Any]) -> dict[str, Any]:
    """Compare supplied, timestamped evidence; never fetch or alter a repository."""
    from datetime import datetime, timezone
    root = root_path(args)
    specs = args.get("repository_specs")
    if not isinstance(specs, list) or not specs or any(not isinstance(s, dict) for s in specs):
        raise InvalidInput("repository_specs must be a nonempty array of objects")
    options = args.get("options") or {}
    max_age = options.get("max_evidence_age_seconds", 86400)
    if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
        raise InvalidInput("max_evidence_age_seconds must be a nonnegative integer")
    now = datetime.now(timezone.utc)
    results = []
    for spec in specs:
        path = scoped_path(root, spec.get("path"), allow_directory=True)
        if not path.is_dir():
            raise InvalidInput("repository path must identify a directory")
        local = spec.get("local_revision")
        remote = spec.get("remote_snapshot")
        record = {"path": spec["path"], "local_revision": local, "status": "incomplete"}
        if not isinstance(local, str) or not local:
            record["reason"] = "local revision evidence is absent"
        elif not isinstance(remote, dict) or not isinstance(remote.get("revision"), str) or not remote.get("retrieved_at"):
            record["reason"] = "remote revision evidence is absent"
        else:
            try:
                retrieved = datetime.fromisoformat(remote["retrieved_at"].replace("Z", "+00:00"))
                if retrieved.tzinfo is None:
                    raise ValueError("timezone required")
                age = (now - retrieved.astimezone(timezone.utc)).total_seconds()
            except (ValueError, TypeError, AttributeError) as exc:
                raise InvalidInput("remote retrieved_at must be an ISO timestamp with timezone") from exc
            record.update({"remote_revision": remote["revision"], "retrieved_at": remote["retrieved_at"], "age_seconds": age})
            if age < -60:
                record["reason"] = "remote evidence timestamp is in the future"
            elif age > max_age:
                record["reason"] = "remote evidence is stale"
            elif local == remote["revision"]:
                record["status"] = "matching_snapshots"
            else:
                record["status"] = "comparison_required"
                record["action"] = "Inspect ancestry and reconcile under authorized repository policy."
        results.append(record)
    complete = all(item["status"] != "incomplete" for item in results)
    return {"status": "complete" if complete else "incomplete", "repositories": results,
            "limitations": ["Only supplied local and remote evidence was compared; no network or repository changes occurred."]}


def treebank_snapshot(args: dict[str, Any]) -> dict[str, Any]:
    from ._artifacts import artifact, collect, json_bytes, manifest, output_destination
    from ._common import files_for
    root, paths = files_for(args)
    if not paths:
        raise InvalidInput("snapshot requires at least one input file")
    files = collect(root, [path.relative_to(root).as_posix() for path in paths])
    inventory = manifest(files)
    return {"status": "complete", "output_dir_path": output_destination(args), "requires_broker_export": True,
            "manifest": inventory,
            "artifacts": [artifact(name, data, "application/octet-stream") for name, data in sorted(files.items())]
                         + [artifact("snapshot-manifest.json", json_bytes({"files": inventory}), "application/json")],
            "limitations": ["Snapshot input is the staged current content; no simultaneous filesystem snapshot is claimed."]}


def treebank_review(args: dict[str, Any]) -> dict[str, Any]:
    from hashlib import sha256
    from ._artifacts import collect
    from ._common import files_for
    root, paths = files_for(args)
    current = collect(root, [path.relative_to(root).as_posix() for path in paths])
    peers = args.get("peer_treebank_paths") or []
    if not isinstance(peers, list):
        raise InvalidInput("peer_treebank_paths must be an array")
    peer_inventory = []
    for item in peers:
        path = scoped_path(root, item, allow_directory=True)
        if not path.is_dir():
            raise InvalidInput("peer treebank path must identify a directory")
        peer_inventory.append({"path": item, "conllu_files": sum(1 for p in path.glob("*.conllu") if p.is_file() and not p.is_symlink())})
    revision = args.get("base_revision")
    if not isinstance(revision, str) or not revision:
        raise InvalidInput("base_revision must be a nonempty revision")
    options = args.get("options") or {}
    receipt = options.get("base_snapshot")
    trusted = staged_git_base(revision)
    if receipt is None and trusted is not None:
        receipt = {"revision": revision, "path": trusted.get("base_directory_path"),
                   "files": {name: item.get("sha256") for name, item in trusted.get("files", {}).items()}}
    # Base and peer material are staged alongside the treebank; they must not
    # silently become current treebank inputs during the comparison.
    excluded = [p for p in peers if isinstance(p, str)]
    if isinstance(receipt, dict) and isinstance(receipt.get("path"), str):
        excluded.append(receipt["path"])
    current = {name: content for name, content in current.items()
               if not any(name == prefix or name.startswith(prefix.rstrip("/") + "/") for prefix in excluded)}
    if not isinstance(receipt, dict) or receipt.get("revision") != revision or not isinstance(receipt.get("files"), dict):
        return {"status": "incomplete", "base_revision": revision, "current_file_count": len(current), "peers": peer_inventory,
                "reason": "a broker-attested base snapshot matching the requested revision is required"}
    base_dir = scoped_path(root, receipt.get("path"), allow_directory=True)
    if not base_dir.is_dir():
        raise InvalidInput("base snapshot path must identify a directory")
    base_names = list(receipt["files"])
    inventory = []
    for base_path, directories, files in os.walk(base_dir, followlinks=False):
        if any((Path(base_path) / name).is_symlink() for name in directories):
            raise InvalidInput("base snapshot contains symbolic links")
        inventory.extend((Path(base_path) / name).relative_to(base_dir).as_posix() for name in files)
    if set(inventory) != set(base_names):
        raise InvalidInput("base snapshot inventory does not match its receipt")
    base = collect(base_dir, base_names)
    if any(sha256(content).hexdigest() != receipt["files"][name] for name, content in base.items()):
        raise InvalidInput("base snapshot does not match its receipt")
    attestation = git_base(revision, {name: (sha256(content).hexdigest(), len(content)) for name, content in base.items()}, directory_path=receipt["path"])
    changes = []
    for name in sorted(set(base) | set(current)):
        before, after = base.get(name), current.get(name)
        if before != after:
            changes.append({"file_path": name, "kind": "added" if before is None else "removed" if after is None else "modified",
                            "before_sha256": sha256(before).hexdigest() if before is not None else None,
                            "after_sha256": sha256(after).hexdigest() if after is not None else None})
    return {"status": "complete" if attestation else "incomplete", "base_revision": revision, "changes": changes, "peers": peer_inventory,
            "revision_attestation": attestation or "unverified",
            **({} if attestation else {"reason": "caller-supplied hashes do not prove the base bytes belong to the requested revision"}),
            "limitations": ["Peer scope reports inventory only; no remote revision or official release status was queried."]}
