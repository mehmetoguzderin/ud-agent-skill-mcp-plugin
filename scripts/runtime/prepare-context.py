#!/usr/bin/env python3
"""Create an immutable local rule context from a hash-verified source archive."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    source_lock = json.loads((ROOT / "runtime/ud-sources.lock.json").read_text(encoding="utf-8"))
    source = next(item for item in source_lock["sources"] if item["repository"] == "UniversalDependencies/tools")
    archive = ROOT / ".artifacts/sources" / f'tools-{source["commit"]}.tar.gz'
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != source["archive_sha256"]:
            raise ValueError("tools source archive hash mismatch")
    expected = source_lock["tools_rule_sha256"]
    if set(expected) != {"upos.json", "feats.json", "udeprels.json", "deprels.json", "edeprels.json", "data.json", "tospace.json"}:
        raise ValueError("incomplete rule lock")
    context_hash = digest(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode())
    root = ROOT / ".artifacts/context"
    root.mkdir(parents=True, exist_ok=True)
    destination = root / context_hash
    manifest = {"schema_version": 1, "context_sha256": context_hash, "rule_dir": "rules",
                "rules": expected, "tools_commit": source["commit"]}
    if destination.exists():
        manifest_path = destination / "context.json"
        if destination.is_symlink() or manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("existing context contains an unsafe manifest")
        if json.loads(manifest_path.read_text(encoding="utf-8")) != manifest:
            raise ValueError("existing context manifest failed verification")
        for name, expected_hash in expected.items():
            path = destination / "rules" / name
            if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != expected_hash:
                raise ValueError("existing context failed verification")
        print(destination / "context.json")
        return
    temporary = Path(tempfile.mkdtemp(prefix=".context-", dir=root))
    try:
        rules = temporary / "rules"
        rules.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            for name, expected_hash in expected.items():
                member = tar.getmember(f'tools-{source["commit"]}/data/{name}')
                if not member.isfile() or member.size > 8 * 1024 * 1024:
                    raise ValueError(f"invalid rule member: {name}")
                content = tar.extractfile(member)
                if content is None:
                    raise ValueError(f"unreadable rule member: {name}")
                data = content.read()
                if digest(data) != expected_hash:
                    raise ValueError(f"rule checksum mismatch: {name}")
                target = rules / name
                target.write_bytes(data)
                target.chmod(0o444)
        (temporary / "context.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (temporary / "context.json").chmod(0o444)
        try:
            os.rename(temporary, destination)
        except FileExistsError as exc:
            raise ValueError("context was concurrently created; retry verification") from exc
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    print(destination / "context.json")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, StopIteration, tarfile.TarError) as exc:
        print(f"context preparation failed: {exc}", file=sys.stderr)
        sys.exit(1)
