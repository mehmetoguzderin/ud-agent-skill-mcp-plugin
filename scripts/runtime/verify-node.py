#!/usr/bin/env python3
"""Authenticate the Node checksum list and verify every published platform archive."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    lock = json.loads((ROOT / "runtime/node-distributions.lock.json").read_text(encoding="utf-8"))
    cache = ROOT / ".artifacts/node"
    keys = cache / "nodejs-release-keys.kbx"
    manifest = cache / "SHASUMS256.txt.asc"
    if sha(keys) != lock["release_keyring_sha256"] or sha(manifest) != lock["signed_manifest_sha256"]:
        raise ValueError("Node signing keyring or checksum manifest hash mismatch")
    result = subprocess.run(["gpgv", "--status-fd", "1", "--keyring", str(keys), str(manifest)],
                            capture_output=True, text=True, check=False)
    expected = lock["checksum_signer_fingerprint"]
    if result.returncode or f"[GNUPG:] VALIDSIG {expected} " not in result.stdout:
        raise ValueError("Node checksum manifest signature or signer is invalid")
    checks = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+|win-(?:arm64|x64)/node\.exe)", line)
        if match:
            digest, name = match.groups()
            if name in checks:
                raise ValueError("duplicate name in signed Node checksum manifest")
            checks[name] = digest
    platforms = json.loads((ROOT / "packages/npm-distribution/platforms.json").read_bytes())
    windows = json.loads((ROOT / "packages/launcher/src/windows-node.json").read_bytes())
    if not platforms.keys() <= lock["platforms"].keys():
        raise ValueError("Node distribution platform inventory is incomplete")
    for platform in platforms:
        entry = lock["platforms"][platform]
        if checks.get(entry["filename"]) != entry["sha256"]:
            raise ValueError(f"Node distribution verification failed: {platform}")
        if platform.startswith("win32-"):
            standalone = windows["platforms"][platform]["sha256"]
            file = f'{platform.replace("win32-", "win-")}/node.exe'
            if windows["schema_version"] != 1 or windows["version"] != lock["version"] or checks.get(file) != standalone:
                raise ValueError(f"Standalone Node checksum verification failed: {platform}")
        elif sha(cache / entry["filename"]) != entry["sha256"]:
            raise ValueError(f"Node distribution verification failed: {platform}")
    print(f'Verified the Node {lock["version"]} publisher signature, packaged archives and Windows standalone executable pins.')


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Node verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
