#!/usr/bin/env python3
"""Collect signed exact Rust standard-library sources used by shipped binaries."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_rust_source_acquire', Path(__file__).with_name('collect-debian-sources.py'))
acquisition = importlib.util.module_from_spec(spec); spec.loader.exec_module(acquisition)
spec = importlib.util.spec_from_file_location('ud_std_supported_scope', Path(__file__).with_name('rust-stdlib-scope.py'))
stdlib_scope = importlib.util.module_from_spec(spec); spec.loader.exec_module(stdlib_scope)
SIGNER = '108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE'
KEY_SHA = 'e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b'
COMMITS = {'1.88.0': '6b00bc3880198600130e1cf62b8f8a93494488cc', '1.94.1': 'e408947bfd200af42db322daf0fadfe7e26d3bd1', '1.99.0': 'b940084d7eb6a299eb4bfeb8e34901bc051e7ac4', '1.99.1': '58cf8f9c35b355199727627d07ae34a4e2846d67'}


def stdlib_requirements(archive):
    """Read dependencies from the publisher-signed source's actual std lock."""
    with tarfile.open(archive, 'r:xz') as source:
        locks = [row for row in source if row.name.endswith('/rust/library/Cargo.lock')]
        if len(locks) != 1 or not locks[0].isfile() or locks[0].size > 4 * 1024 ** 2: raise ValueError('signed Rust std dependency lock is missing or ambiguous')
        with source.extractfile(locks[0]) as stream: raw = stream.read(locks[0].size + 1)
    if len(raw) != locks[0].size: raise ValueError('signed Rust std dependency lock is truncated')
    rows = []
    for item in tomllib.loads(raw.decode())['package']:
        if 'source' not in item: continue
        if item['source'] != 'registry+https://github.com/rust-lang/crates.io-index' or not re.fullmatch(r'[a-zA-Z0-9_-]+', item['name']) or not re.fullmatch(r'[0-9A-Za-z.+-]+', item['version']) or not re.fullmatch('[a-f0-9]{64}', item.get('checksum', '')): raise ValueError('signed Rust std dependency has no exact supported original registry identity')
        rows.append({'name': item['name'], 'version': item['version'], 'sha256': item['checksum']})
    if len({(row['name'], row['version']) for row in rows}) != len(rows): raise ValueError('signed Rust std dependency lock is duplicated')
    return sorted(rows, key=lambda row: (row['name'], row['version']))


def crate_notices(archive, name, version):
    """Verify actual original crate metadata and inventory its license bytes."""
    notices = []; manifest = None; seen = set(); total = 0; prefix = name + '-' + version + '/'
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            if not member.name.startswith(prefix) or member.name in seen or '\\' in member.name or any(part in ('', '.', '..') for part in member.name.rstrip('/').split('/')) or not (member.isfile() or member.isdir()) or not 0 <= member.size <= 64 * 1024 ** 2: raise ValueError('Rust std crate has unsafe, duplicate or oversized members')
            seen.add(member.name); total += member.size
            if len(seen) > 50000 or total > 256 * 1024 ** 2: raise ValueError('Rust std crate expansion exceeds bound')
            if not member.isfile(): continue
            if member.name == prefix + 'Cargo.toml':
                with source.extractfile(member) as stream: manifest = tomllib.loads(stream.read().decode())['package']
            basename = member.name.rsplit('/', 1)[-1].lower()
            if basename.startswith(('license', 'copying', 'notice', 'copyright')) or basename == 'authors':
                if member.size > 8 * 1024 ** 2: raise ValueError('Rust std crate license exceeds bound')
                with source.extractfile(member) as stream: body = stream.read()
                if basename == 'authors' and not (b'LICENSE:' in body and (b'Permission is hereby granted' in body or b'Licensed under' in body)): continue
                notices.append({'source_path': member.name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'body': body})
    if manifest and not notices and manifest.get('license') == 'MPL-2.0':
        # Some original Fortanix packages carry the publisher's MPL notice in
        # their sole implementation file rather than a separate LICENSE file.
        # Preserve that actual source notice; Cargo's license string alone
        # cannot issue this relationship.
        with tarfile.open(archive, 'r:gz') as source:
            for member in source:
                if member.isfile() and member.name.endswith('.rs') and member.size <= 8 * 1024 ** 2:
                    with source.extractfile(member) as stream: body = stream.read()
                    if b'Copyright' in body[:4096] and b'This Source Code Form is subject to the terms of the Mozilla Public' in body[:4096] and b'mozilla.org/MPL/2.0/' in body[:4096]: notices.append({'source_path': member.name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'body': body})
    if not manifest or manifest.get('name') != name or manifest.get('version') != version or not notices: raise ValueError('Rust std crate name/version or original license notices differ: ' + name + '@' + version)
    return notices


def supported_scopes(output, files):
    crates = {(row['name'], row['version']): output / row['path'] for row in files if row.get('family') == 'rust-stdlib-crate'}
    return [{'version': row['version'], 'commit': row['commit'], **stdlib_scope.derive(output / row['path'], crates)} for row in files if row.get('family') == 'rust-runtime-source']


def verify_collection(output, versions=None):
    """Replay publisher signatures and actual source membership read-only."""
    proof = json.loads((output / 'receipt.json').read_bytes())
    selected_versions = set(COMMITS if versions is None else versions)
    if not selected_versions or not selected_versions <= COMMITS.keys(): raise ValueError('selected Rust runtime version is outside the fixed signed identities')
    if proof.get('qualification') != 'exact-locked-source-subinventory' or proof.get('status') != 'passed': raise ValueError('complete signed Rust source collection required')
    records = {(row['name'], row['version']): row for row in proof['files'] if row.get('family') != 'rust-stdlib-crate'}
    expected = {('rust-publisher-key.asc', 'publisher-key')} | {(name, version) for version in COMMITS for name in ('rust-src', 'channel-rust-' + version + '.toml', 'channel-rust-' + version + '.toml.asc')}
    if len(records) != len([row for row in proof['files'] if row.get('family') != 'rust-stdlib-crate']) or set(records) != expected: raise ValueError('Rust source metadata is duplicated or incomplete')
    for row in proof['files']:
        expected_path = 'blobs/' + row['sha256'] if row['name'] == 'rust-src' or row.get('family') == 'rust-stdlib-crate' else row['name']
        if row['path'] != expected_path: raise ValueError('Rust source material path is not content-bound')
        current = output
        for part in expected_path.split('/'):
            current /= part
            if current.is_symlink(): raise ValueError('Rust source material path contains a link')
        if row.get('family') == 'rust-stdlib-crate' or row['version'] not in selected_versions and row['version'] != 'publisher-key': continue
        file = output / row['path']
        if file.is_symlink() or not file.is_file() or file.stat().st_size != row['size_bytes'] or acquisition.digest(file) != row['sha256']: raise ValueError('Rust source material bytes differ')
    key = output / 'rust-publisher-key.asc'
    if acquisition.digest(key) != KEY_SHA: raise ValueError('Rust publisher key identity differs')
    with tempfile.TemporaryDirectory(prefix='ud-rust-source-replay-') as temporary:
        home = Path(temporary); ring = home / 'publisher.gpg'; env = {'PATH': '/usr/bin:/bin:/opt/homebrew/bin', 'LC_ALL': 'C', 'GNUPGHOME': str(home)}
        result = subprocess.run(['gpg', '--batch', '--dearmor', '--output', str(ring), str(key.resolve())], env=env, capture_output=True, timeout=30)
        if result.returncode: raise ValueError('Rust publisher key replay failed')
        dependencies = {}
        for version, commit in COMMITS.items():
            if version not in selected_versions: continue
            manifest = output / ('channel-rust-' + version + '.toml'); signature = manifest.with_suffix('.toml.asc')
            verified = subprocess.run(['gpgv', '--status-fd', '1', '--keyring', str(ring), str(signature), str(manifest)], env=env, capture_output=True, timeout=30)
            if verified.returncode or ('[GNUPG:] VALIDSIG ' + SIGNER + ' ').encode() not in verified.stdout: raise ValueError('Rust signed source manifest replay failed')
            package = tomllib.loads(manifest.read_text())['pkg']['rust-src']; descriptor = package['target']['*']
            selected = [row for row in proof['files'] if row.get('family') == 'rust-runtime-source' and row['version'] == version]
            if len(selected) != 1 or package.get('git_commit_hash') != commit or selected[0].get('commit') != commit or selected[0]['sha256'] != descriptor['xz_hash'] or selected[0]['url'] != descriptor['xz_url']: raise ValueError('Rust source archive differs from signed release')
            with tarfile.open(output / selected[0]['path'], 'r:xz') as archive: members = [row.name for row in archive if row.isfile()]
            required = stdlib_requirements(output / selected[0]['path'])
            for row in required:
                key = row['name'], row['version']
                if key in dependencies and dependencies[key]['sha256'] != row['sha256']: raise ValueError('signed Rust std locks disagree on original crate identity')
                dependencies.setdefault(key, {**row, 'consumers': []})['consumers'].append(version)
            builtin = any('compiler-builtins' in name or 'compiler_builtins' in name for name in members) or any(row['name'] == 'compiler_builtins' for row in required)
            if len(members) > 100000 or not all(any(fragment in name for name in members) for fragment in ('/library/std/src/', '/library/core/src/', '/library/unwind/', '/libunwind/src/')) or not builtin: raise ValueError('Rust source archive omits exact runtime implementation closure')
        actual = {(row['name'], row['version']): row for row in proof['files'] if row.get('family') == 'rust-stdlib-crate'}
        if len(actual) != len([row for row in proof['files'] if row.get('family') == 'rust-stdlib-crate']) or not set(dependencies) <= set(actual) or versions is None and set(actual) != set(dependencies): raise ValueError('Rust std original dependency inventory is missing, extra or duplicate')
        scopes = supported_scopes(output, [row for row in proof['files'] if row.get('family') == 'rust-stdlib-crate' or row['version'] in selected_versions])
        if scopes != [row for row in proof.get('supported_target_scopes', []) if row['version'] in selected_versions]: raise ValueError('Rust std supported-target dependency reachability differs from actual original manifests')
        for key, original in dependencies.items():
            row = actual[key]
            if row['sha256'] != original['sha256'] or [value for value in row.get('consumers', []) if value in selected_versions] != original['consumers'] or row.get('url') != f"https://static.crates.io/crates/{row['name']}/{row['name']}-{row['version']}.crate": raise ValueError('Rust std original crate differs from the signed lock')
            selected = [scope['version'] for scope in scopes if any((value['name'], value['version']) == key for value in scope['selected_registry_packages'])]
            if [value for value in row.get('supported_target_consumers', []) if value in selected_versions] != selected: raise ValueError('Rust std selected source consumers differ from target reachability')
            if not selected:
                if not row.get('supported_target_consumers') and row.get('notices'): raise ValueError('unselected foreign/dev std source has unexpected selected notice materials')
                continue
            notices = crate_notices(output / row['path'], *key)
            if [{k: v for k, v in item.items() if k != 'body'} for item in notices] != [{k: v for k, v in item.items() if k != 'path'} for item in row.get('notices', [])]: raise ValueError('Rust std crate original notice inventory differs')
            for notice in row['notices']:
                file = output / notice['path']
                if notice['path'] != 'notices/' + notice['sha256'] or file.is_symlink() or not file.is_file() or acquisition.digest(file) != notice['sha256'] or file.stat().st_size != notice['size_bytes']: raise ValueError('Rust std original crate notice bytes differ')
    return proof


def collect(root, output):
    output.mkdir(parents=True, exist_ok=True); publisher_key = root / '.artifacts/mutation-rust-assets/rust-key.gpg.ascii'
    if publisher_key.is_symlink() or acquisition.digest(publisher_key) != KEY_SHA: raise ValueError('Rust publisher key differs from independently pinned identity')
    files = []; releases = []; notices = []; dependencies = {}
    with tempfile.TemporaryDirectory(prefix='ud-rust-source-auth-') as temporary:
        home = Path(temporary); ring = home / 'publisher.gpg'; env = {'PATH': '/usr/bin:/bin:/opt/homebrew/bin', 'LC_ALL': 'C', 'GNUPGHOME': str(home)}
        result = subprocess.run(['gpg', '--batch', '--dearmor', '--output', str(ring), str(publisher_key.resolve())], env=env, capture_output=True, timeout=30)
        if result.returncode: raise ValueError('Rust publisher key cannot be read independently')
        for version, commit in COMMITS.items():
            manifest = output / ('channel-rust-' + version + '.toml'); signature = manifest.with_suffix('.toml.asc')
            for target in (manifest, signature): acquisition.acquire('https://static.rust-lang.org/dist/' + target.name, target, maximum=4 * 1024 ** 2)
            verified = subprocess.run(['gpgv', '--status-fd', '1', '--keyring', str(ring), str(signature), str(manifest)], env=env, capture_output=True, timeout=30)
            if verified.returncode or ('[GNUPG:] VALIDSIG ' + SIGNER + ' ').encode() not in verified.stdout: raise ValueError('Rust release manifest signature differs')
            data = tomllib.loads(manifest.read_text()); package = data['pkg']['rust-src']
            if package.get('git_commit_hash') != commit or not package['version'].startswith(version + ' '): raise ValueError('Rust signed release source commit differs from actual binary identity')
            descriptor = package['target']['*']; file = output / 'blobs' / descriptor['xz_hash']; acquisition.acquire(descriptor['xz_url'], file, sha256=descriptor['xz_hash'], maximum=512 * 1024 ** 2)
            source_members = []; source_notices = []
            with tarfile.open(file, 'r:xz') as bundle:
                for member in bundle:
                    if not member.isfile(): continue
                    name = member.name; source_members.append(name)
                    if name.rsplit('/', 1)[-1].lower().startswith(('license', 'notice', 'copyright')):
                        if member.size > 8 * 1024 ** 2: raise ValueError('Rust source notice exceeds bound')
                        body = bundle.extractfile(member).read(member.size + 1); fingerprint = hashlib.sha256(body).hexdigest(); target = output / 'notices' / fingerprint; target.parent.mkdir(exist_ok=True)
                        if target.exists() and target.read_bytes() != body: raise ValueError('Rust notice bytes conflict')
                        if not target.exists(): target.write_bytes(body)
                        row = {'source_path': name, 'path': target.relative_to(output).as_posix(), 'sha256': fingerprint, 'size_bytes': len(body)}; notices.append(row); source_notices.append(row)
            if not any('/library/std/src/' in name for name in source_members) or not any('/library/core/src/' in name for name in source_members): raise ValueError('Rust source archive omits actual standard library implementation')
            row = {'family': 'rust-runtime-source', 'name': 'rust-src', 'version': version, 'commit': commit, 'url': descriptor['xz_url'], 'path': file.relative_to(output).as_posix(), 'sha256': descriptor['xz_hash'], 'size_bytes': file.stat().st_size, 'notices': source_notices}; files.append(row)
            for dependency in stdlib_requirements(file):
                key = dependency['name'], dependency['version']
                if key in dependencies and dependencies[key]['sha256'] != dependency['sha256']: raise ValueError('signed Rust std locks disagree on original crate identity')
                dependencies.setdefault(key, {**dependency, 'consumers': []})['consumers'].append(version)
            for target in (manifest, signature): files.append({'family': 'rust-publisher-metadata', 'name': target.name, 'version': version, 'path': target.name, 'sha256': acquisition.digest(target), 'size_bytes': target.stat().st_size})
            releases.append({'version': version, 'commit': commit, 'manifest_sha256': acquisition.digest(manifest), 'signer': SIGNER, 'source_sha256': descriptor['xz_hash'], 'members': len(source_members), 'compiler_builtins_source_present': any('compiler-builtins' in name or 'compiler_builtins' in name for name in source_members), 'unwind_source_present': any('/library/unwind/' in name for name in source_members), 'llvm_libunwind_source_present': any('/libunwind/src/' in name for name in source_members)})
    for (name, version), row in sorted(dependencies.items()):
        url = f'https://static.crates.io/crates/{name}/{name}-{version}.crate'; file = output / 'blobs' / row['sha256']; acquisition.acquire(url, file, sha256=row['sha256'], maximum=256 * 1024 ** 2)
        files.append({'family': 'rust-stdlib-crate', **row, 'url': url, 'path': file.relative_to(output).as_posix(), 'size_bytes': file.stat().st_size, 'notices': []})
    scopes = supported_scopes(output, files)
    for row in files:
        if row['family'] != 'rust-stdlib-crate': continue
        name, version = row['name'], row['version']; file = output / row['path']; original_notices = []
        row['supported_target_consumers'] = [scope['version'] for scope in scopes if any((value['name'], value['version']) == (name, version) for value in scope['selected_registry_packages'])]
        if not row['supported_target_consumers']: continue
        for item in crate_notices(file, name, version):
            target = output / 'notices' / item['sha256']; target.parent.mkdir(exist_ok=True)
            if target.exists() and target.read_bytes() != item['body']: raise ValueError('Rust std crate notice hash conflicts')
            if not target.exists(): target.write_bytes(item['body'])
            original_notices.append({**{key: value for key, value in item.items() if key != 'body'}, 'path': target.relative_to(output).as_posix()})
        row['notices'] = original_notices; notices.extend(original_notices)
    target = output / 'rust-publisher-key.asc'; shutil.copyfile(publisher_key, target); files.append({'family': 'rust-publisher-metadata', 'name': target.name, 'version': 'publisher-key', 'path': target.name, 'sha256': KEY_SHA, 'size_bytes': target.stat().st_size})
    report = {'schema_version': 1, 'qualification': 'exact-locked-source-subinventory', 'status': 'passed', 'target_execution': False, 'families': ['rust-runtime-source', 'rust-publisher-metadata', 'rust-stdlib-crate'], 'files': files, 'releases': releases, 'supported_target_scopes': scopes, 'notices': notices, 'scope_limitation': 'Exact signed Rust language/std sources; all original registry archives inspected, source selection follows conservative normal/build reachability across the six supported targets. Foreign/dev-only inspection subjects stay local. Not reproduced binary identity or publisher redistribution authority.'}
    (output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n'); return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args(); result = collect(args.root.resolve(), args.output); print(json.dumps({'status': result['status'], 'releases': result['releases']}))
