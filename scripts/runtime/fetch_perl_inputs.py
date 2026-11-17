#!/usr/bin/env python3
"""Fetch only pinned Debian/Interset build inputs, or verify an offline cache."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import perl_build

ROOT = Path(__file__).resolve().parents[2]
HOSTS = {"snapshot.debian.org", "codeload.github.com"}


def safe_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise ValueError("untrusted Perl input URL")
    return url


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def cached_file(path: Path, size: int, digest: str) -> bool:
    if path.exists() or path.is_symlink():
        perl_build._read(path, size, digest, 100 * 1024 * 1024)
        return True
    return False


def acquire(url: str, path: Path, size: int, digest: str, download: bool) -> None:
    if cached_file(path, size, digest):
        return
    if not download:
        raise ValueError(f"offline Perl input missing: {path.name}")
    safe_url(url)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".perl-fetch-", dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            request = Request(url, headers={"User-Agent": "ud-agent-perl-inputs/0.1"})
            with build_opener(SafeRedirect()).open(request, timeout=90) as response:
                remaining = size
                hasher = sha256()
                while remaining:
                    block = response.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("truncated Perl input download")
                    output.write(block)
                    hasher.update(block)
                    remaining -= len(block)
                if response.read(1) or hasher.hexdigest() != digest:
                    raise ValueError("Perl input download checksum or size mismatch")
        try:
            os.link(temporary, path)
        except FileExistsError:
            perl_build._read(path, size, digest, 100 * 1024 * 1024)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def safe_package_path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("pool/") or "\\" in value:
        raise ValueError("unsafe Debian package path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")) or not re.fullmatch(r"[A-Za-z0-9+_.:/~%-]+", value):
        raise ValueError("unsafe Debian package path")
    return value


def fetch(root: Path, *, download: bool, pack: str = "perl") -> None:
    if pack not in ("perl", "render"):
        raise ValueError("unknown dependency pack")
    lock = json.loads((root / f"runtime/{pack}-deps.lock.json").read_text(encoding="utf-8"))
    debian = lock["debian"]
    stamp = debian["timestamp"]
    if lock.get("schema_version") != 1 or lock.get("state") != "frozen-inputs" or debian.get("suite") != "trixie" or not re.fullmatch(r"\d{8}T\d{6}Z", stamp) or set(debian["architectures"]) != {"amd64", "arm64"}:
        raise ValueError("invalid Perl dependency lock")
    prefixes = {"main": f"https://snapshot.debian.org/archive/debian/{stamp}/",
                "security": f"https://snapshot.debian.org/archive/debian-security/{stamp}/"}
    for arch, config in debian["architectures"].items():
        base = root / ".artifacts" / f"{pack}-debs" / arch
        evidence = base / "evidence"
        key = next((x for x in config["evidence"] if x["file"] == "debian-archive-keyring.gpg"), None)
        if key is None:
            raise ValueError("Debian keyring receipt is missing")
        source_key = root / "runtime/debian-archive-keyring.gpg"
        key_data = perl_build._read(source_key, key["size"], key["sha256"], 1024 * 1024)
        evidence.mkdir(parents=True, exist_ok=True)
        target_key = evidence / "debian-archive-keyring.gpg"
        if not cached_file(target_key, key["size"], key["sha256"]):
            with target_key.open("xb") as output:
                output.write(key_data)
        releases = {}
        for source in ("main", "security"):
            pattern = "_debian-security_" if source == "security" else "_debian_"
            release = [x for x in config["evidence"] if pattern in x["file"] and x["file"].endswith("_InRelease")]
            if len(release) != 1:
                raise ValueError("Debian release receipt is incomplete")
            item = release[0]
            name = perl_build._safe_filename(item["file"])
            suite = "trixie-security" if source == "security" else "trixie"
            target = evidence / name
            acquire(prefixes[source] + "dists/" + suite + "/InRelease", target, item["size"], item["sha256"], download)
            perl_build._verify_release(target, target_key, debian["signed_by"][source])
            releases[source] = perl_build._release_hashes(target.read_bytes())
        for index in config["indexes"]:
            source = index["source"]
            if source not in prefixes or index["release_path"] != f"main/binary-{arch}/Packages":
                raise ValueError("invalid Debian package index")
            if releases[source].get(index["release_path"]) != (index["sha256"], index["size"]):
                raise ValueError("Debian index is not bound to the signed release")
            output = root / ".artifacts/perl-index" / arch / perl_build._safe_filename(index["file"])
            if cached_file(output, index["size"], index["sha256"]):
                continue
            if not download:
                raise ValueError(f"offline Debian index missing: {output.name}")
            compressed_path = index["release_path"] + ".xz"
            compressed = releases[source].get(compressed_path)
            if not compressed:
                raise ValueError("signed Debian release has no compressed index")
            suite = "trixie-security" if source == "security" else "trixie"
            compressed_file = output.with_name(output.name + ".xz")
            acquire(prefixes[source] + "dists/" + suite + "/" + compressed_path,
                    compressed_file, compressed[1], compressed[0], True)
            data = lzma.decompress(compressed_file.read_bytes(), memlimit=perl_build._MAX_INDEX * 3)
            if len(data) != index["size"] or sha256(data).hexdigest() != index["sha256"]:
                raise ValueError("decompressed Debian index differs from signed release")
            output.parent.mkdir(parents=True, exist_ok=True)
            try:
                with output.open("xb") as stream:
                    stream.write(data)
            except FileExistsError:
                perl_build._read(output, index["size"], index["sha256"], perl_build._MAX_INDEX)
        for package in config["packages"]:
            source = package["source"]
            if source not in prefixes:
                raise ValueError("invalid Debian package source")
            name = perl_build._safe_filename(package["file"], deb=True)
            acquire(prefixes[source] + safe_package_path(package["repository_path"]),
                    base / "debs" / name, package["size"], package["sha256"], download)
        perl_build._verify_debian(root, arch, config, debian["signed_by"], cache_name=f"{pack}-debs")
    if pack == "render":
        return
    source = lock["interset"]
    commit = source["commit"]
    if source["repository"] != "https://github.com/dan-zeman/interset" or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid Interset source identity")
    acquire("https://codeload.github.com/dan-zeman/interset/tar.gz/" + commit,
            root / ".artifacts/perl-sources" / perl_build._safe_filename(source["archive"]),
            source["archive_size"], source["archive_sha256"], download)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true", help="fetch missing frozen inputs from their pinned HTTPS origins")
    parser.add_argument("--render", action="store_true", help="verify or acquire the frozen render dependency pack")
    args = parser.parse_args()
    try:
        fetch(ROOT, download=args.download, pack="render" if args.render else "perl")
    except (OSError, ValueError, KeyError, TypeError, lzma.LZMAError) as exc:
        print(f"Perl input preparation failed: {exc}", file=sys.stderr)
        return 1
    print("Frozen Debian inputs verified." if args.render else "Frozen Debian and Interset inputs verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
