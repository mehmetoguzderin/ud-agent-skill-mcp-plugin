#!/usr/bin/env python3
"""Replay Linux Node's exact signed Red Hat Rust source correspondence.

This inspects original archives as data and does not execute either Node
binary. The compiler version embedded in a binary establishes a producer
identity; it does not assert that the binary was reproduced from source.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from threading import Timer
from contextlib import closing

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_node_linux_materials', Path(__file__).with_name('source-bundle.py'))
materials = importlib.util.module_from_spec(spec); spec.loader.exec_module(materials)
spec = importlib.util.spec_from_file_location('ud_node_linux_rust_collection', Path(__file__).with_name('collect-rust-runtime-sources.py'))
rust_collection = importlib.util.module_from_spec(spec); spec.loader.exec_module(rust_collection)


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(root, record):
    stream, _, receipt = materials.opened(root, record)
    stream.close()
    return root / record['path'], receipt


class VerifiedStage:
    """Copy checked inputs into a private directory before path-based tools use them."""
    def __init__(self, original, private, *, maximum_bytes=4 * 1024 ** 3, source_parts=None, recorder=None):
        self.original, self.private, self.records = Path(original), Path(private), {}
        self.source_parts, self.recorder = source_parts, recorder
        if type(maximum_bytes) is not int or maximum_bytes < 1: raise ValueError('Invalid source staging size bound')
        self.maximum_bytes, self.total_bytes = maximum_bytes, 0

    def add(self, record):
        name = materials.safe(record.get('path'))
        previous = self.records.get(name)
        if previous is not None:
            if previous['sha256'] != record.get('sha256') or record.get('size_bytes', previous['size_bytes']) != previous['size_bytes']:
                raise ValueError('Conflicting source staging identities')
            return
        original = self.original / name
        streamed = self.source_parts is not None and not original.exists() and not original.is_symlink()
        if streamed:
            # Only an exact recipe-bound blob may stand in for a deliberately
            # omitted source input; path-based signature tools get a private
            # copy for this family and its TemporaryDirectory removes it.
            size = record.get('size_bytes', record.get('size')); fingerprint = record.get('sha256')
            if type(size) is not int or size < 0 or not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint): raise ValueError('Streamed source staging identity is invalid')
            for parent in (original, *original.parents):
                if parent == self.original.parent: break
                if parent.is_symlink(): raise ValueError('Source material contains a link')
            context = self.source_parts.open_blob(fingerprint, size)
            verified = {'path': name, 'sha256': fingerprint, 'size_bytes': size}
            identity = None
        else:
            stream, identity, verified = materials.opened(self.original, record)
            context = closing(stream)
        target = self.private / name; target.parent.mkdir(parents=True, exist_ok=True)
        with context as stream:
            if self.total_bytes + verified['size_bytes'] > self.maximum_bytes: raise ValueError('Source staging exceeds its total size bound')
            with target.open('xb') as destination:
                shutil.copyfileobj(stream, destination, 1024 * 1024)
                destination.flush(); os.fsync(destination.fileno())
            if identity is not None:
                after = os.fstat(stream.fileno())
                if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('Source material changed during private staging')
            if target.stat().st_size != verified['size_bytes'] or digest(target) != verified['sha256']:
                raise ValueError('Private source material differs from verified bytes')
            if streamed and self.recorder is not None: self.recorder.source_blob(original, fingerprint, size)
            target.chmod(0o400); self.records[name] = verified; self.total_bytes += verified['size_bytes']

    def receipt(self, name):
        # The collection itself is untrusted: bound its receipt, then replay all
        # of its signed manifests and member hashes inside the private stage.
        name = materials.safe(name); current = self.original
        for part in name.split('/'):
            current /= part
            if current.is_symlink(): raise ValueError('Source collection receipt contains a link')
        fd = os.open(current, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 16 * 1024 * 1024: raise ValueError('Source collection receipt exceeds its bound')
            body = stream.read(16 * 1024 * 1024 + 1); after = os.fstat(fd)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if len(body) != before.st_size or identity(before) != identity(after): raise ValueError('Source collection receipt changed during staging')
        receipt = json.loads(body)
        target = self.private / name; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body); target.chmod(0o400)
        return receipt


def stage_inputs(root, assets, private, source_parts=None, recorder=None):
    lock = json.loads((root / 'runtime/materials/node-linux-rust.lock.json').read_bytes())
    node = json.loads((root / 'runtime/node-distributions.lock.json').read_bytes())
    stage = VerifiedStage(assets, private, source_parts=source_parts, recorder=recorder)
    for key in ('source_rpm', 'redhat_key', 'rust_key', 'upstream_signature'): stage.add(lock[key])
    for row in lock['source_rpm_members']:
        stage.add({'path': '.artifacts/source-materials-data/redhat-rust-1.88-node-linux/extracted/' + row['name'], 'sha256': row['sha256'], 'size_bytes': row['size_bytes']})
    stage.add({'path': '.artifacts/node/SHASUMS256.txt.asc', 'sha256': node['signed_manifest_sha256']})
    stage.add({'path': '.artifacts/node/nodejs-release-keys.kbx', 'sha256': node['release_keyring_sha256']})
    for arch in ('arm64', 'x64'):
        row = node['platforms']['linux-' + arch]
        stage.add({'path': '.artifacts/node/' + row['filename'], 'sha256': row['sha256']})
    prefix = '.artifacts/source-materials-data/rust-runtime-sources-node-v4/'
    receipt = stage.receipt(prefix + 'receipt.json')
    rows = receipt.get('files')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10000: raise ValueError('Rust source collection member inventory exceeds its bound')
    for row in rows:
        if row.get('family') == 'rust-stdlib-crate':
            if lock['rust_version'] not in row.get('supported_target_consumers', []): continue
        elif row.get('version') not in (lock['rust_version'], 'publisher-key'):
            continue
        for item in [row, *row.get('notices', [])]:
            stage.add({'path': prefix + materials.safe(item['path']), 'sha256': item['sha256'], 'size_bytes': item['size_bytes']})
    return stage


def invoke(argv, *, env=None, limit=1024 * 1024):
    result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=300, env=env)
    if result.returncode or len(result.stdout) > limit or len(result.stderr) > limit:
        raise ValueError('Signed source verification failed: ' + result.stderr.decode('utf-8', 'replace')[-1000:])
    return result.stdout.decode('utf-8', 'strict')


def required_tool(name):
    found = shutil.which(name, path='/usr/bin:/bin:/opt/homebrew/bin')
    if not found: raise ValueError('Source verification requires the ' + name + ' executable')
    # Preserve the selected argv[0]: rpm2cpio may be a symlink to the
    # multi-call rpm2archive executable, whose output format depends on it.
    selected = Path(found).absolute()
    if not selected.is_file(): raise ValueError('Source verification tool is not an ordinary executable')
    return selected


def verify_signatures(assets, lock, node):
    rpm = required_tool('rpm'); gpg = required_tool('gpg')
    package, package_record = checked(assets, lock['source_rpm'])
    redhat, redhat_record = checked(assets, lock['redhat_key'])
    rust_key, rust_key_record = checked(assets, lock['rust_key'])
    signature, signature_record = checked(assets, lock['upstream_signature'])
    upstream = next(row for row in lock['source_rpm_members'] if row['name'] == 'rustc-1.88.0-src.tar.xz')
    upstream_file, _ = checked(assets, {'path': '.artifacts/source-materials-data/redhat-rust-1.88-node-linux/extracted/' + upstream['name'], **{key: upstream[key] for key in ('sha256', 'size_bytes')}})
    with tempfile.TemporaryDirectory(prefix='ud-node-rust-signatures-') as temporary:
        home = Path(temporary) / 'gnupg'; home.mkdir(mode=0o700)
        db = Path(temporary) / 'rpmdb'; db.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin:/opt/homebrew/bin', 'HOME': temporary, 'LC_ALL': 'C'}
        invoke([rpm, '--dbpath', db, '--initdb'], env=env)
        invoke([rpm, '--dbpath', db, '--import', redhat], env=env)
        verified = invoke([rpm, '--dbpath', db, '-Kv', package], env=env).lower()
        if lock['source_rpm']['signer_fingerprint'].lower() not in verified or 'signature' not in verified or verified.count('ok') < 3 or 'nokey' in verified or 'not ok' in verified:
            raise ValueError('Red Hat source RPM signature or payload digest is not verified')
        fields = invoke([rpm, '--dbpath', db, '-qp', '--qf', '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{VENDOR}\n', package], env=env).splitlines()
        if fields != ['rust', lock['rust_version'], '1.module+el8.10.0+23326+3c6ade25', 'Red Hat, Inc.']:
            raise ValueError('Red Hat source RPM package identity differs')
        invoke([gpg, '--batch', '--no-autostart', '--homedir', home, '--import', rust_key], env=env)
        status = invoke([gpg, '--batch', '--no-autostart', '--homedir', home, '--status-fd', '1', '--verify', signature, upstream_file], env=env)
        if '[GNUPG:] VALIDSIG ' + lock['rust_key']['signer_fingerprint'] + ' ' not in status:
            raise ValueError('Rust upstream source signature has another signer')
        manifest, manifest_record = checked(assets, {'path': '.artifacts/node/SHASUMS256.txt.asc', 'sha256': node['signed_manifest_sha256']})
        keyring, keyring_record = checked(assets, {'path': '.artifacts/node/nodejs-release-keys.kbx', 'sha256': node['release_keyring_sha256']})
        status = invoke([gpg, '--batch', '--no-autostart', '--homedir', home, '--status-fd', '1', '--no-default-keyring', '--keyring', keyring, '--verify', manifest], env=env)
        if '[GNUPG:] VALIDSIG ' + node['checksum_signer_fingerprint'] + ' ' not in status:
            raise ValueError('Node binary checksum manifest has another signer')
    return package_record, [redhat_record, rust_key_record, signature_record, manifest_record, keyring_record], [rpm, gpg]


def read_exact(stream, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(size - len(chunks))
        if not part: raise ValueError('Red Hat source RPM payload is truncated')
        chunks.extend(part)
    return bytes(chunks)


def verify_cpio(stream, expected):
    """Hash the entire closed newc member set, without extracting paths."""
    pending = {row['name']: row for row in expected}; seen = set()
    if len(pending) != len(expected) or not pending: raise ValueError('Duplicate or empty locked source RPM inventory')
    while True:
        header = read_exact(stream, 110)
        if header[:6] not in (b'070701', b'070702') or not re.fullmatch(rb'[0-9A-Fa-f]{104}', header[6:]): raise ValueError('Invalid source RPM cpio header')
        fields = [int(header[6+i*8:14+i*8], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        if not 1 <= namesize <= 4096: raise ValueError('Invalid source RPM cpio name length')
        raw = read_exact(stream, namesize)
        if raw[-1:] != b'\0' or b'\0' in raw[:-1]: raise ValueError('Invalid source RPM cpio name')
        name = raw[:-1].decode('utf-8', 'strict').removeprefix('./')
        read_exact(stream, (-(110 + namesize)) % 4)
        if name == 'TRAILER!!!':
            if size or seen != set(pending): raise ValueError('Source RPM omits or adds locked members')
            break
        if name not in pending or name in seen or '/' in name or '\\' in name or not stat.S_ISREG(mode) or size != pending[name]['size_bytes']:
            raise ValueError('Source RPM member is unsafe, duplicate, or differs from its lock')
        seen.add(name); sha = hashlib.sha256(); remaining = size
        while remaining:
            block = read_exact(stream, min(1024 * 1024, remaining)); sha.update(block); remaining -= len(block)
        if sha.hexdigest() != pending[name]['sha256']: raise ValueError('Source RPM member hash differs')
        read_exact(stream, (-size) % 4)
    return seen


def verify_rpm_members(package, expected):
    tool = required_tool('rpm2cpio')
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([str(tool), str(package)], stdout=subprocess.PIPE, stderr=errors, env={'PATH': '/usr/bin:/bin:/opt/homebrew/bin', 'LC_ALL': 'C'})
        def stop():
            try: process.kill()
            except ProcessLookupError: pass
        timer = Timer(300, stop); timer.start()
        try:
            verify_cpio(process.stdout, expected)
            # rpm2cpio may add cpio zero padding after TRAILER; drain it before wait.
            while process.stdout.read(1024 * 1024): pass
            if process.wait(timeout=300) != 0: raise ValueError('Red Hat source RPM decompression failed')
        except BaseException:
            process.kill(); process.wait(); raise
        finally: timer.cancel(); process.stdout.close()
    return tool


def derive(root, assets_root, source_parts=None, recorder=None):
    root, assets_root = Path(root).resolve(), Path(assets_root).resolve()
    with tempfile.TemporaryDirectory(prefix='ud-node-linux-source-stage-') as temporary:
        stage_inputs(root, assets_root, Path(temporary), source_parts, recorder)
        return derive_staged(root, Path(temporary))


def derive_staged(root, assets_root):
    root, assets_root = Path(root).resolve(), Path(assets_root).resolve()
    lock_file = root / 'runtime/materials/node-linux-rust.lock.json'; lock = json.loads(lock_file.read_bytes())
    node_file = root / 'runtime/node-distributions.lock.json'; node = json.loads(node_file.read_bytes())
    if lock.get('schema_version') != 1 or lock.get('qualification') != 'exact-red-hat-node-linux-rust-source-provenance-input-lock' or node.get('version') != lock.get('node_version') or lock.get('rust_commit') != '6b00bc3880198600130e1cf62b8f8a93494488cc':
        raise ValueError('Exact Linux Node/Rust source lock required')
    package_record, verification, tools = verify_signatures(assets_root, lock, node)
    package = assets_root / lock['source_rpm']['path']; tools.append(verify_rpm_members(package, lock['source_rpm_members']))
    sources = [package_record]
    for row in lock['source_rpm_members']:
        _, receipt = checked(assets_root, {'path': '.artifacts/source-materials-data/redhat-rust-1.88-node-linux/extracted/' + row['name'], **{key: row[key] for key in ('sha256', 'size_bytes')}})
        sources.append(receipt)
    rust_receipt = assets_root / '.artifacts/source-materials-data/rust-runtime-sources-node-v4/receipt.json'
    tools.append(required_tool('gpgv'))
    inventory = rust_collection.verify_collection(rust_receipt.parent, versions=[lock['rust_version']])
    matching = [row for row in inventory['files'] if row.get('family') == 'rust-runtime-source' and row.get('version') == lock['rust_version'] and row.get('commit') == lock['rust_commit']]
    if len(matching) != 1: raise ValueError('Rust standard-library source notice inventory is missing')
    _, standard_source = checked(assets_root, {'path': '.artifacts/source-materials-data/rust-runtime-sources-node-v4/' + matching[0]['path'], **{key: matching[0][key] for key in ('sha256', 'size_bytes')}})
    sources.append(standard_source)
    for row in inventory['files']:
        if row.get('family') == 'rust-publisher-metadata' and row.get('version') == lock['rust_version']:
            _, receipt = checked(assets_root, {'path': '.artifacts/source-materials-data/rust-runtime-sources-node-v4/' + row['path'], **{key: row[key] for key in ('sha256', 'size_bytes')}})
            verification.append(receipt)
    notices = []
    for row in matching[0]['notices']:
        _, receipt = checked(assets_root, {'path': '.artifacts/source-materials-data/rust-runtime-sources-node-v4/' + row['path'], **{key: row[key] for key in ('sha256', 'size_bytes')}})
        notices.append({**receipt, 'source_path': row['source_path']})
    bindings = []
    signed_lines = (assets_root / '.artifacts/node/SHASUMS256.txt.asc').read_text().splitlines()
    for arch in ('arm64', 'x64'):
        item = node['platforms']['linux-' + arch]
        archive, archive_record = checked(assets_root, {'path': '.artifacts/node/' + item['filename'], 'sha256': item['sha256']})
        if signed_lines.count(item['sha256'] + '  ' + item['filename']) != 1: raise ValueError('Node archive is absent from its signed manifest')
        with tarfile.open(archive, 'r:xz') as tar:
            name = 'node-v' + node['version'] + '-linux-' + arch + '/bin/node'; rows = [member for member in tar if member.name == name]
            if len(rows) != 1 or not rows[0].isfile() or rows[0].size > 256 * 1024 ** 2: raise ValueError('Node archive has no unique bounded binary')
            body = tar.extractfile(rows[0]).read(rows[0].size + 1)
        if len(body) != rows[0].size or lock['embedded_compiler_string'].encode() not in body: raise ValueError('Node binary does not identify the locked Red Hat compiler')
        bindings.append({'platform': 'linux/' + arch, 'binary': {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}, 'node_archive': archive_record, 'embedded_compiler_string': lock['embedded_compiler_string'], 'rust_commit': lock['rust_commit'], 'sources': sources, 'notices': notices, 'verification_materials': verification})
    return {'schema_version': 1, 'qualification': 'signed-redhat-node-linux-rust-source-correspondence-not-binary-reproduction', 'target_execution': False, 'bindings': bindings, 'pending_declarations': [], 'generator_sha256': digest(Path(__file__)), 'input_lock_sha256': digest(lock_file), 'tools': [{'name': tool.name, 'sha256': digest(tool)} for tool in tools], 'limitations': ['Embedded compiler identity and signed source packages establish a source correspondence, not a reproduced Node binary.', 'Publisher entitlement, Windows runtime declarations, and other components remain separate gates.']}


def write_collection(assets_root, binding, output):
    """Retain exactly the verified original sources and public verification data."""
    assets_root, output = Path(assets_root).resolve(), Path(output).resolve()
    if output.exists() or not output.is_relative_to(assets_root / '.artifacts'):
        raise ValueError('Source collection must be a new product-owned artifact directory')
    if binding.get('qualification') != 'signed-redhat-node-linux-rust-source-correspondence-not-binary-reproduction' or binding.get('target_execution') is not False or binding.get('pending_declarations') != []:
        raise ValueError('Verified data-only Node Linux source binding required')
    subjects = binding.get('bindings')
    if not isinstance(subjects, list) or {row.get('platform') for row in subjects} != {'linux/arm64', 'linux/x64'} or len(subjects) != 2:
        raise ValueError('Both exact Linux Node source bindings are required')
    records, origins = {}, []
    try:
        (output / 'blobs').mkdir(parents=True)
        for subject in subjects:
            for kind in ('sources', 'notices', 'verification_materials'):
                rows = subject.get(kind)
                if not isinstance(rows, list) or not rows: raise ValueError('Source binding omits a required original material family')
                for row in rows:
                    stream, identity, original = materials.opened(assets_root, row)
                    fingerprint, size = original['sha256'], original['size_bytes']; target = output / 'blobs' / fingerprint
                    try:
                        if fingerprint in records:
                            if records[fingerprint]['size_bytes'] != size: raise ValueError('Original material identity has conflicting sizes')
                        else:
                            with target.open('xb') as destination:
                                shutil.copyfileobj(stream, destination, 1024 * 1024); destination.flush(); os.fsync(destination.fileno())
                            if target.stat().st_size != size or digest(target) != fingerprint: raise ValueError('Retained original material differs')
                            records[fingerprint] = {'family': 'node-linux-rust-original-material', 'path': 'blobs/' + fingerprint, 'sha256': fingerprint, 'size_bytes': size}
                        after = os.fstat(stream.fileno())
                        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('Original material changed during retention')
                    finally: stream.close()
                    origins.append({'platform': subject['platform'], 'kind': kind, 'original_path': original['path'], 'sha256': fingerprint, 'size_bytes': size})
        receipt = {'schema_version': 1, 'qualification': 'pinned-source-and-notices', 'status': 'passed', 'target_execution': False, 'files': sorted(records.values(), key=lambda row: row['path']), 'original_inputs': origins, 'binding_generator_sha256': binding['generator_sha256'], 'binding_input_lock_sha256': binding['input_lock_sha256'], 'limitations': binding['limitations']}
        target = output / 'receipt.json'; target.write_text(json.dumps(receipt, indent=2) + '\n')
        return receipt
    except BaseException:
        if output.exists(): shutil.rmtree(output)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--assets-root', type=Path); parser.add_argument('--output', type=Path, required=True); parser.add_argument('--collection-output', type=Path); args = parser.parse_args()
    if args.output.exists(): raise ValueError('new Node Linux Rust evidence output required')
    result = derive(args.root, args.assets_root or args.root)
    collection = write_collection(args.assets_root or args.root, result, args.collection_output) if args.collection_output else None
    args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'bindings': len(result['bindings']), 'target_execution': result['target_execution'], 'retained_materials': len(collection['files']) if collection else None}))
