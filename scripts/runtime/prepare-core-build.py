#!/usr/bin/env python3
"""Prepare a hash-verified, offline build context for an unqualified core candidate.

Wheel acquisition is disabled unless --download is explicitly supplied. This
script prepares bytes only; it never runs a container engine or publishes an
image. The candidate is not qualified until the complete release gates pass.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile
import tomllib
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
_unicode_spec = importlib.util.spec_from_file_location("ud_agent_build_unicode", ROOT / "workers/ud/src/ud_agent/unicode_paths.py")
_unicode = importlib.util.module_from_spec(_unicode_spec)
_unicode_spec.loader.exec_module(_unicode)
_perl_spec = importlib.util.spec_from_file_location("ud_agent_perl_build", Path(__file__).with_name("private_perl.py"))
if _perl_spec is None or _perl_spec.loader is None:
    raise RuntimeError("cannot load Perl build preparation module")
perl_build = importlib.util.module_from_spec(_perl_spec)
_perl_spec.loader.exec_module(perl_build)
_timestamp_spec = importlib.util.spec_from_file_location('ud_context_timestamps', Path(__file__).with_name('context_timestamps.py'))
context_timestamps = importlib.util.module_from_spec(_timestamp_spec)
_timestamp_spec.loader.exec_module(context_timestamps)
SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
PLATFORMS = {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}
RULES = {"upos.json", "feats.json", "udeprels.json", "deprels.json", "edeprels.json", "data.json", "tospace.json"}


def hash_file(path: Path) -> str:
    with path.open("rb") as stream:
        return sha256(stream.read()).hexdigest()


def content_addressed_manifest(context: Path) -> str:
    """Bind the COPY path to bytes, including equal-size/mtime receipt changes."""
    source = context / 'input-manifest.json'
    if source.is_symlink() or not source.is_file():
        raise ValueError('ordinary core input manifest required')
    fingerprint = hash_file(source)
    relative = 'build-input/' + fingerprint + '.json'
    selected = context / relative
    if (context / 'build-input').is_symlink() or not (context / 'build-input').is_dir() or selected.is_symlink() or not selected.is_file() or selected.read_bytes() != source.read_bytes():
        raise ValueError('content-addressed core input manifest differs from its exact bytes')
    return relative


def read_locks(root: Path = ROOT):
    source = json.loads((root / "runtime/ud-sources.lock.json").read_text(encoding="utf-8"))
    image = json.loads((root / "runtime/core-image.lock.json").read_text(encoding="utf-8"))
    packages = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    if source.get("schema_version") != 1 or not isinstance(source.get("sources"), list):
        raise ValueError("invalid UD source lock")
    tools = [item for item in source["sources"] if item.get("repository") == "UniversalDependencies/tools"]
    if len(tools) != 1 or not re.fullmatch(r"[0-9a-f]{40}", tools[0].get("commit", "")) or not re.fullmatch(r"[0-9a-f]{64}", tools[0].get("archive_sha256", "")):
        raise ValueError("invalid UD tools source receipt")
    rules = source.get("tools_rule_sha256")
    if not isinstance(rules, dict) or set(rules) != RULES or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in rules.values()):
        raise ValueError("invalid UD rule hashes")
    if image.get("schema_version") != 1 or not isinstance(image.get("image"), str) or not SHA.fullmatch(image.get("index_digest", "")):
        raise ValueError("invalid Python base image lock")
    if set(image.get("platforms", {})) != set(PLATFORMS) or any(not SHA.fullmatch(value) for value in image["platforms"].values()):
        raise ValueError("incomplete Python base image platform locks")
    if image.get("python_version") != "3.15.2":
        raise ValueError("worker wheel selector requires the locked Python 3.15 runtime")
    containerfile = (root / "runtime/Containerfile.core").read_text(encoding="utf-8")
    locked_base = f'FROM {image["image"]}@{image["index_digest"]}'
    if not {locked_base, locked_base + ' AS build'}.intersection(containerfile.splitlines()):
        raise ValueError("Containerfile base does not match image lock")
    return source, image, packages


def dependency_wheels(lock: dict, tools_commit: str) -> list[dict]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError("invalid Python dependency lock")
    by_name = {}
    for package in packages:
        name = package.get("name")
        if name in by_name:
            raise ValueError(f"ambiguous duplicate locked package: {name}")
        by_name[name] = package
    upstream = by_name.get("udtools")
    if not upstream or not str(upstream.get("source", {}).get("git", "")).endswith("#" + tools_commit):
        raise ValueError("udtools dependency does not match the locked upstream commit")
    names = set()
    pending = ["udtools"]
    while pending:
        name = pending.pop()
        if name in names:
            continue
        if name not in by_name:
            raise ValueError(f"missing locked Python package: {name}")
        names.add(name)
        for dependency in by_name[name].get("dependencies", []):
            if set(dependency) != {"name"}:
                raise ValueError(f"conditional or ambiguous dependency requires review: {name}")
            pending.append(dependency["name"])
    names.remove("udtools")
    selected = []
    for name in sorted(names):
        package = by_name[name]
        version = package.get("version", "")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!-]*", version):
            raise ValueError("invalid locked package identity")
        if package.get("source") != {"registry": "https://pypi.org/simple"}:
            raise ValueError(f"unexpected package source: {name}")
        wheels = package.get("wheels", [])
        per_platform = {}
        for platform, architecture in PLATFORMS.items():
            compatible = []
            for wheel in wheels:
                parsed = urlsplit(wheel.get("url", ""))
                filename = unquote(parsed.path.rsplit("/", 1)[-1])
                pure = bool(re.search(r"-(?:py3|py2\.py3)-none-any\.whl$", filename))
                native = bool(re.search(rf"-cp315-cp315-manylinux[^/]*_{architecture}\.whl$", filename))
                if pure or native:
                    if (parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org" or
                        parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443) or
                        parsed.query or parsed.fragment or "/" in filename or "\\" in filename or
                        not SHA.fullmatch(wheel.get("hash", "")) or not isinstance(wheel.get("size"), int) or
                        not 0 < wheel["size"] <= 128 * 1024 * 1024):
                        raise ValueError(f"invalid wheel receipt: {name}")
                    compatible.append({"filename": filename, "url": wheel["url"], "hash": wheel["hash"], "size": wheel["size"]})
            if len(compatible) != 1:
                raise ValueError(f"expected exactly one Python 3.15 wheel for {name} on {platform}")
            per_platform[platform] = compatible[0]
        selected.append({"name": name, "version": version, "platforms": per_platform})
    return selected


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if target.scheme != "https" or target.hostname != "files.pythonhosted.org":
            raise ValueError("wheel download redirected outside the trusted source")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def ensure_wheel(cache: Path, wheel: dict, download: bool) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / wheel["filename"]
    def verify(path: Path) -> None:
        if path.is_symlink() or not path.is_file() or path.stat().st_size != wheel["size"] or "sha256:" + hash_file(path) != wheel["hash"]:
            raise ValueError(f'wheel verification failed: {wheel["filename"]}')
    if target.exists() or target.is_symlink():
        verify(target)
        return target
    if not download:
        raise ValueError(f'wheel missing from offline cache: {wheel["filename"]}')
    opener = build_opener(SafeRedirect())
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".wheel-", dir=cache, delete=False) as output:
            temporary = Path(output.name)
            request = Request(wheel["url"], headers={"User-Agent": "ud-agent-build-preparation/1"})
            with opener.open(request, timeout=30) as response:
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > wheel["size"]:
                        raise ValueError("wheel exceeds locked size")
                    output.write(chunk)
        verify(temporary)
        try:
            os.link(temporary, target)
        except FileExistsError:
            verify(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


class SourceRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("locked source download must not redirect")


def ensure_source_archive(root: Path, receipt: dict, download: bool) -> None:
    """With --download, acquire a missing locked UD source archive; bytes must match its lock."""
    name = receipt["repository"].rsplit("/", 1)[-1]
    if not re.fullmatch(r"[0-9a-f]{40}", receipt.get("commit", "")) or not re.fullmatch(r"[0-9a-f]{64}", receipt.get("archive_sha256", "")):
        raise ValueError("invalid locked source receipt")
    target = root / ".artifacts/sources" / f'{name}-{receipt["commit"]}.tar.gz'
    if not download or target.exists() or target.is_symlink():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    url = f'https://codeload.github.com/{receipt["repository"]}/tar.gz/{receipt["commit"]}'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".source-", dir=target.parent, delete=False) as output:
            temporary = Path(output.name)
            with build_opener(SourceRedirect()).open(Request(url, headers={"User-Agent": "ud-agent-build-preparation/1"}), timeout=120) as response:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
        if hash_file(temporary) != receipt["archive_sha256"]:
            raise ValueError(f"locked source archive checksum mismatch: {name}")
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def extract_verified_tools(archive: Path, tools: dict, destination: Path) -> dict[str, bytes]:
    if archive.is_symlink() or not archive.is_file() or hash_file(archive) != tools["archive_sha256"]:
        raise ValueError("upstream tools archive checksum mismatch")
    prefix = "tools-" + tools["commit"] + "/"
    seen = set()
    rules = {}
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if member.name.rstrip("/") == prefix.rstrip("/") and member.isdir():
                continue
            if not member.name.startswith(prefix):
                raise ValueError("archive member outside the expected source root")
            relative = member.name[len(prefix):]
            if not relative:
                continue
            path = PurePosixPath(relative)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("unsafe upstream archive path")
            selected = (relative.startswith("udtools/src/udtools/") and relative.endswith(".py")) or ("/" not in relative and relative.endswith((".pl", ".pm"))) or relative in {"LICENSE.txt", "udtools/LICENSE.txt"} or (relative.startswith("data/") and relative[5:] in RULES)
            if not selected:
                continue
            if relative in seen or not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError("invalid or duplicate selected archive member")
            seen.add(relative)
            total += member.size
            if total > 128 * 1024 * 1024:
                raise ValueError("upstream source exceeds extraction limit")
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError("upstream source member cannot be read")
            data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("upstream source member has an invalid size")
            if relative.startswith("data/"):
                rules[relative[5:]] = data
            else:
                output = destination / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(data)
    if set(rules) != RULES or "udtools/src/udtools/__init__.py" not in seen or "udtools/LICENSE.txt" not in seen or "LICENSE.txt" not in seen:
        raise ValueError("upstream source archive is incomplete")
    return rules


def copy_worker(root: Path, destination: Path) -> None:
    source = root / "workers/ud/src/ud_agent"
    if not source.is_dir() or source.is_symlink():
        raise ValueError("worker source directory is missing")
    for directory, dirs, files in os.walk(source, followlinks=False):
        base = Path(directory)
        for name in dirs:
            if (base / name).is_symlink():
                raise ValueError("worker source contains a directory symlink")
        dirs[:] = sorted(name for name in dirs if name != "__pycache__")
        for name in sorted(files):
            path = base / name
            if path.is_symlink():
                raise ValueError("worker source contains a file symlink")
            relative = path.relative_to(source)
            if not name.endswith(".py") and relative.as_posix() not in {"perl/graph_bridge.pl", "perl/repository_bridge.pl", "unicode_casefold.json", "userspace_operations.json"}:
                continue
            target = destination / "ud_agent" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    if not (destination / "ud_agent/worker.py").is_file():
        raise ValueError("worker entrypoint is missing")


def stage_repository_sources(root: Path, source_lock: dict, context: Path) -> dict:
    """Stage exactly the pinned metadata consumed by repository checks."""
    staged = {}
    for name in ("docs-automation", "docs"):
        matches = [item for item in source_lock["sources"] if item.get("repository") == f"UniversalDependencies/{name}"]
        if len(matches) != 1:
            raise ValueError(f"missing pinned repository-check source: {name}")
        receipt = matches[0]
        if not re.fullmatch(r"[0-9a-f]{40}", receipt.get("commit", "")) or not re.fullmatch(r"[0-9a-f]{64}", receipt.get("archive_sha256", "")):
            raise ValueError("invalid repository-check source receipt")
        archive = root / ".artifacts/sources" / f'{name}-{receipt["commit"]}.tar.gz'
        if archive.is_symlink() or not archive.is_file() or hash_file(archive) != receipt["archive_sha256"]:
            raise ValueError("repository-check source archive checksum mismatch")
        prefix = f'{name}-{receipt["commit"]}/'
        seen = set()
        files = {}
        total = 0
        with tarfile.open(archive, "r:gz") as stream:
            for number, member in enumerate(stream):
                if member.name.rstrip("/") == prefix.rstrip("/") and member.isdir():
                    continue
                if number >= 100_000 or not member.name.startswith(prefix):
                    raise ValueError("repository source exceeds its inventory or prefix bound")
                relative = member.name[len(prefix):]
                if not relative:
                    if not member.isdir():
                        raise ValueError("invalid repository source root")
                    continue
                logical = PurePosixPath(relative)
                if logical.is_absolute() or ".." in logical.parts or "\\" in relative:
                    raise ValueError("unsafe repository source path")
                selected = (relative in {"codes_and_flags.yaml", "genre_symbols.json", "valdan/releases.json", "LICENSE"}) if name == "docs-automation" else (relative in {"LICENSE.txt", "README.md"} or re.fullmatch(r"_[A-Za-z0-9_-]+/index\.md", relative) is not None)
                if not selected:
                    continue
                key = _unicode.path_key(relative)
                if key in seen or not member.isfile() or member.size > 16 * 1024 * 1024:
                    raise ValueError("unsafe, duplicate or oversized repository source member")
                seen.add(key)
                total += member.size
                if total > 64 * 1024 * 1024:
                    raise ValueError("repository-check source exceeds its size bound")
                data = stream.extractfile(member).read(member.size + 1)
                if len(data) != member.size:
                    raise ValueError("truncated repository-check source member")
                target = context / name / logical
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                files[relative] = sha256(data).hexdigest()
        required = {"codes_and_flags.yaml", "valdan/releases.json", "LICENSE"} if name == "docs-automation" else {"LICENSE.txt"}
        if not required.issubset(files) or (name == "docs" and not any(value.endswith("/index.md") for value in files)):
            raise ValueError("repository-check source subset is incomplete")
        staged[name] = {"source": receipt, "files": files}
    return staged


def prepare(root: Path, cache: Path, output: Path, download: bool = False, platforms=None) -> dict:
    source_lock, image, uv = read_locks(root)
    tools = next(item for item in source_lock["sources"] if item["repository"] == "UniversalDependencies/tools")
    selected = dependency_wheels(uv, tools["commit"])
    if output.exists() or output.is_symlink():
        raise ValueError("build context destination already exists; choose a new path")
    output.parent.mkdir(parents=True, exist_ok=True)
    for receipt in source_lock["sources"]:
        if receipt.get("repository") in {"UniversalDependencies/tools", "UniversalDependencies/docs-automation", "UniversalDependencies/docs"}:
            ensure_source_archive(root, receipt, download)
    wheel_paths = {}
    for package in selected:
        for wheel in package["platforms"].values():
            wheel_paths[wheel["filename"]] = ensure_wheel(cache, wheel, download)
    with tempfile.TemporaryDirectory(prefix=".core-context-", dir=output.parent) as temp:
        context = Path(temp) / "context"
        context.mkdir()
        copy_worker(root, context / "worker")
        archive = root / ".artifacts/sources" / f'tools-{tools["commit"]}.tar.gz'
        rules = extract_verified_tools(archive, tools, context / "upstream")
        repository_sources = stage_repository_sources(root, source_lock, context)
        for name, content in rules.items():
            if sha256(content).hexdigest() != source_lock["tools_rule_sha256"][name]:
                raise ValueError(f"rule checksum mismatch: {name}")
            path = context / "context/rules" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        hashes = source_lock["tools_rule_sha256"]
        context_hash = sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        repository_hash = sha256(json.dumps(repository_sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        repository_assets = {f"{name}/{relative}": {"sha256": value, "size_bytes": (context / name / relative).stat().st_size} for name, receipt in repository_sources.items() for relative, value in receipt["files"].items()}
        manifest = {"schema_version": 1, "context_sha256": context_hash, "rule_dir": "rules", "rules": hashes, "tools_commit": tools["commit"],
                    "repository_context_sha256": repository_hash,
                    "repository_checks": {"tools_path": "/opt/ud-agent/upstream", "languages_path": "/opt/ud-agent/docs-automation/codes_and_flags.yaml", "docs_path": "/opt/ud-agent/docs", "source_receipts": repository_sources, "assets": repository_assets}}
        (context / "context/context.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        wheels_dir = context / "wheels"
        wheels_dir.mkdir()
        for name, path in sorted(wheel_paths.items()):
            shutil.copyfile(path, wheels_dir / name)
        lines = []
        for package in selected:
            hashes = sorted({wheel["hash"] for wheel in package["platforms"].values()})
            lines.append(f'{package["name"]}=={package["version"]} ' + " ".join("--hash=" + value for value in hashes))
        (context / "requirements.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        licenses = context / "licenses"
        licenses.mkdir()
        shutil.copyfile(root / "LICENSE", licenses / "project-LICENSE")
        shutil.copyfile(root / "NOTICE", licenses / "project-NOTICE")
        shutil.copyfile(root / "licenses/Unicode-3.0.txt", licenses / "Unicode-3.0.txt")
        perl = perl_build.stage(root, context / "perl", platforms) if platforms else perl_build.stage(root, context / "perl")
        shutil.copyfile(root / "runtime/Containerfile.core", context / "Containerfile")
        file_hashes = {path.relative_to(context).as_posix(): hash_file(path) for path in sorted(context.rglob("*")) if path.is_file()}
        receipt = {"schema_version": 1, "qualification": "unbuilt", "release_qualified": False,
                   "base_image": image, "upstream_tools": tools, "rule_context_sha256": context_hash,
                   "packages": selected, "perl": perl, "repository_sources": repository_sources, "files": file_hashes,
                   "limitations": ["Image has not been built or accepted on either platform.",
                                   "Full core-pack capability verification is pending."]}
        if platforms:
            receipt['build_platforms']=platforms
            receipt['limitations'].append('Other architecture builds are explicitly deferred; this context is not a complete release candidate.')
        (context / "input-manifest.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        addressed = context / 'build-input' / (hash_file(context / 'input-manifest.json') + '.json')
        addressed.parent.mkdir()
        shutil.copyfile(context / 'input-manifest.json', addressed)
        for path in sorted(context.rglob("*"), reverse=True):
            context_timestamps.set_epoch(path)
        context_timestamps.set_epoch(context)
        os.rename(context, output)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-cache", type=Path, default=ROOT / ".artifacts/wheels")
    parser.add_argument("--output", type=Path, default=ROOT / ".artifacts/core-build-context")
    parser.add_argument("--download", action="store_true", help="acquire missing locked wheels from the trusted HTTPS source")
    parser.add_argument("--platform",action="append",choices=sorted(PLATFORMS),help="explicit development build subset; omitted platforms remain deferred")
    args = parser.parse_args()
    try:
        receipt = prepare(ROOT, args.wheel_cache, args.output, args.download,args.platform)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        print(f"core build preparation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"output": str(args.output), "qualification": receipt["qualification"], "release_qualified": False,
                      "context_sha256": receipt["rule_context_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
