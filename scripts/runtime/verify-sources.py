#!/usr/bin/env python3
"""Verify the immutable upstream archives and complete rule snapshot."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def digest_stream(stream) -> str:
    digest = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def verify(cache: Path) -> list[dict[str, str]]:
    lock = json.loads((ROOT / "runtime/ud-sources.lock.json").read_text(encoding="utf-8"))
    if lock.get("schema_version") != 1 or len(lock.get("sources", [])) != 5:
        raise ValueError("invalid source lock")
    receipts = []
    for source in lock["sources"]:
        repo = source["repository"].split("/")[-1]
        sha = source["commit"]
        archive = cache / f"{repo}-{sha}.tar.gz"
        with archive.open("rb") as stream:
            actual = digest_stream(stream)
        if actual != source["archive_sha256"]:
            raise ValueError(f"source archive hash mismatch: {repo}")
        if repo == "tools":
            with tarfile.open(archive, "r:gz") as tar:
                for name, expected in lock["tools_rule_sha256"].items():
                    member = tar.getmember(f"tools-{sha}/data/{name}")
                    if not member.isfile():
                        raise ValueError(f"rule is not a regular file: {name}")
                    content = tar.extractfile(member)
                    if content is None or digest_stream(content) != expected:
                        raise ValueError(f"rule hash mismatch: {name}")
        receipts.append({"repository": source["repository"], "commit": sha, "archive_sha256": actual})
    return receipts


if __name__ == "__main__":
    import sys
    try:
        print(json.dumps({"sources": verify(ROOT / ".artifacts/sources")}, indent=2))
    except (OSError, ValueError, KeyError, tarfile.TarError) as exc:
        print(f"source verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
