#!/usr/bin/env python3
"""Verify candidate archive contents and native architecture without extracting files."""
from __future__ import annotations

import argparse
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('ud_release_unicode_paths', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
_paths = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_paths)
_support_spec = importlib.util.spec_from_file_location('ud_release_skill_support', Path(__file__).with_name('skill_support.py'))
_support = importlib.util.module_from_spec(_support_spec)
_support_spec.loader.exec_module(_support)

MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024


def architecture(data: bytes) -> str:
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        endian = "<" if data[5] == 1 else ">" if data[5] == 2 else None
        if endian:
            return {183: "linux-arm64", 62: "linux-x64"}.get(struct.unpack_from(endian + "H", data, 18)[0], "unknown")
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") and len(data) >= 8:
        endian = "<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">"
        return {0x100000C: "darwin-arm64", 0x1000007: "darwin-x64"}.get(struct.unpack_from(endian + "I", data, 4)[0], "unknown")
    if data[:2] == b"MZ" and len(data) >= 64:
        position = struct.unpack_from("<I", data, 60)[0]
        if position + 6 <= len(data) and data[position:position + 4] == b"PE\0\0":
            return {0xAA64: "win32-arm64", 0x8664: "win32-x64"}.get(struct.unpack_from("<H", data, position + 4)[0], "unknown")
    return "unknown"


def inspect(filename: Path, kind: str, platform: str, source_hash: str, runtime_hash: str, require_candidate=False, details=False, archive_stream=None, contracts=False) -> dict:
    if filename.is_symlink() or not filename.is_file() or kind not in ("native", "npm", "skills", "source"):
        raise ValueError("invalid package archive or kind")
    records, metadata, binaries, seen, total = {}, {}, {}, set(), 0
    metadata_total = 0

    def member(name: str, size: int, mode: int, stream):
        nonlocal total, metadata_total
        if kind == "npm":
            if not name.startswith("package/"):
                raise ValueError("npm member is outside its package root")
            name = name[8:]
        try:
            _paths.validate_path(name)
        except ValueError:
            raise ValueError("unsafe package member path")
        key = _paths.path_key(name)
        if key in seen or len(seen) >= 50000 or not 0 <= size <= MAX_FILE:
            raise ValueError("duplicate or oversized package member")
        seen.add(key)
        total += size
        if total > MAX_TOTAL:
            raise ValueError("package exceeds its expanded size limit")
        digest = hashlib.sha256()
        captured, prefix, read = bytearray(), bytearray(), 0
        keep = name in ("PACKAGE-INVENTORY.json", "BUILD-RECEIPT.json", "SOURCE-MANIFEST.json", "SKILL-SUPPORT.json", "runtime/runtime.lock.json", "runtime/userspace.lock.json", "runtime/engine-distributions.lock.json", "runtime/windows-node.json", "runtime/pack/context/context.json", "package.json", "platforms.json", "manifest.json", ".mcp.json", "mcp.json", "gemini-extension.json", "kimi.plugin.json") or re.fullmatch(r'runtime/contexts/[a-f0-9]{64}/context\.json', name) is not None or contracts and (name == 'contracts/ud-interfaces.json' or re.fullmatch(r'runtime/pack/native/[^/]+/perl/[^/]+\.json', name) is not None)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            read += len(chunk)
            if read > size:
                raise ValueError("package member exceeds its size")
            digest.update(chunk)
            if len(prefix) < 65536:
                prefix.extend(chunk[:65536 - len(prefix)])
            if keep:
                if read > (32 if name == 'runtime/userspace.lock.json' else 8) * 1024 * 1024:
                    raise ValueError("package metadata exceeds its size limit")
                metadata_total += len(chunk)
                if metadata_total > 48 * 1024 * 1024:
                    raise ValueError("package metadata exceeds its aggregate size limit")
                captured.extend(chunk)
        if read != size:
            raise ValueError("truncated package member")
        records[name] = {"path": name, "sha256": digest.hexdigest(), "size": size, "executable": bool(mode & 0o111)}
        if keep:
            metadata[name] = json.loads(captured)
        if prefix[:4] in (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf') or prefix[:2] == b'MZ' or name.startswith("bin/") or re.fullmatch(r"platforms/[^/]+/ud-agent(?:-guard)?(?:\.exe)?", name) or name in ("runtime/node/bin/node", "runtime/node/bin/node.exe"):
            binaries[name] = architecture(prefix)

    if archive_stream is not None: archive_stream.seek(0)
    if filename.suffix in (".zip", ".mcpb"):
        with zipfile.ZipFile(filename if archive_stream is None else archive_stream) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    continue
                mode = item.external_attr >> 16
                if mode & 0o170000 not in (0, 0o100000):
                    raise ValueError("package contains a link or special file")
                with archive.open(item) as data:
                    member(item.filename, item.file_size, mode, data)
    else:
        with tarfile.open(filename if archive_stream is None else None, "r:gz", fileobj=archive_stream) as archive:
            for item in archive:
                if item.isdir():
                    continue
                if not item.isfile():
                    raise ValueError("package contains a link or special file")
                member(item.name, item.size, item.mode, archive.extractfile(item))
    if kind == "source":
        source = metadata.get("SOURCE-MANIFEST.json")
        if not isinstance(source, dict) or source.get("algorithm") != "sha256-json-file-inventory-v1" or source.get("sha256") != source_hash or not isinstance(source.get("files"), list) or not source["files"]:
            raise ValueError("source archive lacks its exact source manifest")
        expected = {item["path"]: item for item in source["files"]}
        actual = {name: item for name, item in records.items() if name != "SOURCE-MANIFEST.json"}
        canonical = json.dumps(source["files"], ensure_ascii=False, separators=(",", ":")).encode()
        if len(expected) != len(source["files"]) or expected != actual or hashlib.sha256(canonical).hexdigest() != source_hash:
            raise ValueError("source archive differs from its frozen file inventory")
        return {"verified": True, "kind": kind, "platform": platform, "files": len(records), "expanded_size": total, **({'members': records, 'binary_components': binaries, 'metadata': metadata} if details else {})}
    inventory = metadata.get("PACKAGE-INVENTORY.json")
    if not isinstance(inventory, dict) or inventory.get("schema_version") != 1 or not isinstance(inventory.get("files"), list):
        raise ValueError("package has no complete content inventory")
    expected = {item["path"]: item for item in inventory["files"]}
    actual = {name: item for name, item in records.items() if name != "PACKAGE-INVENTORY.json"}
    if len(expected) != len(inventory["files"]) or expected != actual:
        raise ValueError("package content differs from its inventory")
    _support.verify(ROOT, _paths, records, metadata.get('SKILL-SUPPORT.json'))
    receipt = metadata.get("BUILD-RECEIPT.json", {})
    if receipt.get("schema_version") != 1 or receipt.get("product_version") != "0.1.0-beta.1" or receipt.get("source_tree_sha256") != source_hash or receipt.get("runtime_lock_sha256") != runtime_hash or receipt.get("kind") != kind or receipt.get("platform") != platform:
        raise ValueError("package build receipt does not match its accepted subjects")
    if require_candidate and (receipt.get('qualification') != 'preacceptance_candidate' or 'UNACCEPTED.md' in records or 'RELEASE-CANDIDATE.md' not in records):
        raise ValueError('accepted package was not assembled as an immutable preacceptance candidate')
    if kind in ("native", "npm"):
        if records.get("runtime/runtime.lock.json", {}).get("sha256") != runtime_hash or "lib/coordinator.mjs" not in records:
            raise ValueError("package coordinator or runtime lock is missing")
    if kind == "native":
        suffix = ".exe" if platform.startswith("win32-") else ""
        for name in ("bin/ud-agent" + suffix, "bin/ud-agent-guard" + suffix):
            if binaries.get(name) != platform:
                raise ValueError("native package contains a missing or wrong-architecture executable")
        if suffix:
            lock = json.loads((ROOT / 'packages/launcher/src/windows-node.json').read_bytes())
            pin = lock['platforms'][platform]
            version = lock['version']
            expected = {'schema_version': 1, 'version': version, 'platform': platform,
                        'sha256': 'sha256:' + pin['sha256'], 'size_bytes': pin['size_bytes'],
                        'url': f"https://nodejs.org/dist/v{version}/{platform.replace('win32-', 'win-')}/node.exe"}
            if metadata.get('runtime/windows-node.json') != expected or any(name.startswith('runtime/node/') for name in records):
                raise ValueError('Windows native package must use the pinned vendor Node acquisition')
            expected_server = {'type': 'binary', 'entry_point': 'bin/ud-agent.exe', 'mcp_config': {
                'command': '${__dirname}/bin/ud-agent.exe', 'args': ['--mcpb-workspace', '${user_config.workspace}']}}
            if metadata.get('manifest.json', {}).get('server') != expected_server:
                raise ValueError('Windows MCPB must select the native vendor-bootstrap launcher')
        elif binaries.get('runtime/node/bin/node') != platform:
            raise ValueError('native package contains a missing or wrong-architecture Node executable')
        if filename.suffix == ".mcpb" and metadata.get("manifest.json", {}).get("version") != "0.1.0-beta.1":
            raise ValueError("MCPB manifest identity is wrong")
    if kind == "npm":
        package = metadata.get("package.json", {})
        if package.get("name") != "@mehmetoguzderin/ud-agent-skill-mcp-plugin" or package.get("version") != "0.1.0-beta.1":
            raise ValueError("npm package identity is wrong")
        if package.get('private') is True or package.get('publishConfig') != {'access': 'public'} or package.get('bin') != {'ud-agent': 'cli.cjs'} or package.get('engines', {}).get('node') != '>=24 <27':
            raise ValueError('npm package is not a public executable distribution')
        targets = json.loads((ROOT / 'packages/npm-distribution/platforms.json').read_bytes())
        if metadata.get('platforms.json') != targets:
            raise ValueError('npm launcher platform manifest differs from source')
        members = {name.split('/')[1] for name in records if name.startswith('platforms/')}
        if members != targets.keys():
            raise ValueError('npm native helper platforms differ from source')
        for target in targets:
            for executable in ("ud-agent", "ud-agent-guard"):
                name = f"platforms/{target}/{executable}" + (".exe" if target.startswith("win32-") else "")
                if binaries.get(name) != target:
                    raise ValueError("npm package contains a wrong-architecture native helper")
    contract_names = {'BUILD-RECEIPT.json', 'contracts/ud-interfaces.json', 'runtime/runtime.lock.json', 'runtime/userspace.lock.json', 'runtime/windows-node.json'} | {name for name in metadata if re.fullmatch(r'runtime/pack/native/[^/]+/perl/[^/]+\.json', name)}
    contract = {'metadata': {name: metadata[name] for name in sorted(contract_names & metadata.keys())}, 'members': {name: records[name] for name in sorted(contract_names & records.keys())}, 'release_candidate': 'RELEASE-CANDIDATE.md' in records, 'unaccepted': 'UNACCEPTED.md' in records}
    return {"verified": True, "kind": kind, "platform": platform, "files": len(records), "expanded_size": total, 'inventory_sha256': records['PACKAGE-INVENTORY.json']['sha256'], 'build_receipt_sha256': records['BUILD-RECEIPT.json']['sha256'], **({'contracts': contract} if contracts else {}), **({'members': records, 'binary_components': binaries, 'metadata': metadata} if details else {})}


def extract_verified(filename: Path, destination: Path, kind: str, platform: str, source_hash: str, runtime_hash: str, *, archive_sha256: str, archive_size: int, max_output_bytes: int, require_candidate=False) -> dict:
    """Inspect one exact package, then stream it into a new private directory."""
    if not re.fullmatch(r'[a-f0-9]{64}', archive_sha256 or '') or type(archive_size) is not int or archive_size < 0 or type(max_output_bytes) is not int or not 0 < max_output_bytes <= MAX_TOTAL:
        raise ValueError('package extraction requires exact bounded archive and output receipts')
    filename = filename.absolute()
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    if destination.exists() or destination.is_symlink() or filename.is_symlink(): raise ValueError('package extraction requires a new private destination and ordinary archive')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(filename, flags)
    created = False
    def identity(info): return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    try:
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != archive_size: raise ValueError('package archive differs from its exact receipt')
            fingerprint = hashlib.file_digest(stream, 'sha256').hexdigest()
            if fingerprint != archive_sha256 or identity(before) != identity(os.fstat(stream.fileno())): raise ValueError('package archive differs from its exact receipt')
            result = inspect(filename, kind, platform, source_hash, runtime_hash, require_candidate, details=True, archive_stream=stream)
            if identity(before) != identity(os.fstat(stream.fileno())): raise ValueError('package archive changed during inspection')
            if result['expanded_size'] > max_output_bytes: raise ValueError('package extraction exceeds its output budget')
            if shutil.disk_usage(parent).free - result['expanded_size'] < 10_000_000_000: raise ValueError('package extraction would consume the free-space reserve')
            destination.mkdir(mode=0o700); created = True
            members = result['members']; seen = set(); written = 0
            def unpack(name, body):
                nonlocal written
                if kind == 'npm':
                    if not name.startswith('package/'): raise ValueError('npm member is outside its package root')
                    name = name[8:]
                _paths.validate_path(name)
                expected = members.get(name)
                if expected is None or name in seen: raise ValueError('package extraction member differs from inspected inventory')
                target = destination.joinpath(*name.split('/')); target.parent.mkdir(parents=True, exist_ok=True)
                digest, size = hashlib.sha256(), 0
                with target.open('xb') as output:
                    while chunk := body.read(1024 * 1024):
                        size += len(chunk); written += len(chunk)
                        if size > expected['size'] or written > max_output_bytes: raise ValueError('package extraction exceeded its inventory')
                        output.write(chunk); digest.update(chunk)
                if size != expected['size'] or digest.hexdigest() != expected['sha256']: raise ValueError('package extraction bytes differ from inspected inventory')
                target.chmod(0o755 if expected['executable'] else 0o644); seen.add(name)
            stream.seek(0)
            if filename.suffix in ('.zip', '.mcpb'):
                with zipfile.ZipFile(stream) as archive:
                    for entry in archive.infolist():
                        if not entry.is_dir():
                            with archive.open(entry) as body: unpack(entry.filename, body)
            else:
                with tarfile.open(fileobj=stream, mode='r:gz') as archive:
                    for entry in archive:
                        if not entry.isdir():
                            if not entry.isfile(): raise ValueError('package extraction contains a link or special file')
                            with archive.extractfile(entry) as body: unpack(entry.name, body)
            named = filename.stat(follow_symlinks=False)
            if seen != set(members) or written != result['expanded_size'] or identity(before) != identity(os.fstat(stream.fileno())) or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('package archive or extraction changed during verification')
            return {key: value for key, value in result.items() if key not in ('members', 'binary_components', 'metadata')} | {'qualification': 'verified-original-package-extraction', 'archive_sha256': archive_sha256, 'archive_size_bytes': archive_size}
    except BaseException:
        if created: shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--kind", choices=("native", "npm", "skills", "source"), required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument('--require-candidate', action='store_true')
    parser.add_argument('--contracts', action='store_true', help='Return bounded package contracts from verified archive members')
    parser.add_argument('--extract-to', type=Path)
    parser.add_argument('--archive-sha256')
    parser.add_argument('--archive-size', type=int)
    parser.add_argument('--max-output-bytes', type=int)
    args = parser.parse_args()
    if args.extract_to is not None:
        if args.contracts: parser.error('contract output and extraction are separate operations')
        result = extract_verified(args.archive, args.extract_to, args.kind, args.platform, args.source_sha256, args.runtime_sha256, archive_sha256=args.archive_sha256, archive_size=args.archive_size, max_output_bytes=args.max_output_bytes, require_candidate=args.require_candidate)
    else:
        if any(value is not None for value in (args.archive_sha256, args.archive_size, args.max_output_bytes)): parser.error('extraction receipts require --extract-to')
        result = inspect(args.archive, args.kind, args.platform, args.source_sha256, args.runtime_sha256, args.require_candidate, contracts=args.contracts)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
