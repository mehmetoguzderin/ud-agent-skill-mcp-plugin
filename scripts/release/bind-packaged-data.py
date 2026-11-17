"""Exact fixed packaged-data joins; no binary reproduction or publisher grant."""
from __future__ import annotations
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


materials = module('ud_packaged_materials', 'source-bundle.py')
locked = module('ud_packaged_locked', 'collect-locked-sources.py')
source_tools = module('ud_packaged_source_tools', 'source_materials.py')
userspace = module('ud_packaged_userspace', '../runtime/prepare-userspace.py')
inspector = module('ud_packaged_inspector', 'collect-shipped-components.py').inspector


def digest(body): return hashlib.sha256(body).hexdigest()
def content(body): return {'sha256': digest(body), 'size_bytes': len(body)}
def file_identity(stream):
    value = os.fstat(stream.fileno())
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
def read(root, name, limit=8 * 1024 ** 2):
    file = Path(root)
    for part in materials.safe(name).split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('packaged input contains a symlink')
    with os.fdopen(os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit: raise ValueError('packaged input exceeds ordinary-file bound')
        body = stream.read(limit + 1); after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or len(body) != before.st_size: raise ValueError('packaged input changed during same-FD read')
        return body, {'path': name, **content(body)}


def captured(discovery, path, expected, artifact=None):
    rows = [row for subject in discovery['subjects'] if artifact is None or subject['id'] == artifact for row in subject['members'] if row.get('path') == path]
    for row in rows:
        if any(row[key] != expected[key] for key in ('sha256', 'size_bytes')): raise ValueError('packaged member differs from its exact source/build input')
    return bool(rows)


def fixture_binding(root, discovery, name):
    body, archive = read(root, name, 1024 ** 2)
    proof, descriptor = read(root, name.rsplit('.', 1)[0] + '.json')
    proof = json.loads(proof)
    if any(proof.get(key) != archive[key] for key in ('sha256', 'size_bytes')): raise ValueError('authored fixture archive differs from its retained descriptor')
    if not captured(discovery, name, archive, 'source-archive'): return None
    notices = []; members = []
    if name.endswith('.zip'):
        if proof.get('module') != 'github.com/docker/go-units' or proof.get('version') != 'v0.5.0' or proof.get('url') != 'https://proxy.golang.org/github.com/docker/go-units/@v/v0.5.0.zip': raise ValueError('Go fixture source identity differs')
        if source_tools.go_zip_hash(io.BytesIO(body), proof['module'], proof['version']) != proof.get('h1'): raise ValueError('Go fixture module checksum differs')
        license_body = None
        with zipfile.ZipFile(io.BytesIO(body)) as bundle:
            for entry in bundle.infolist():
                if entry.is_dir(): continue
                value = bundle.read(entry); value.decode('utf-8', errors='strict')
                members.append({'member_path': entry.filename, **content(value)})
                if entry.filename == 'github.com/docker/go-units@v0.5.0/LICENSE': notices.append({'container_sha256': archive['sha256'], **members[-1]}); license_body = value
        if len(notices) != 1 or b'Apache License' not in (license_body or b''): raise ValueError('original Go fixture license is absent')
        source = {'form': 'exact-original-Go-module-preferred-source-archive', **archive, 'module': proof['module'], 'version': proof['version'], 'url': proof['url'], 'h1': proof['h1']}
    else:
        if proof.get('qualification') != 'actual-offline-npm-pack-first-party-fixture' or proof.get('command') != ['npm', 'pack', '--offline', '--ignore-scripts', '--json']: raise ValueError('authored npm fixture recipe differs')
        expected = {'package/cli.cjs', 'package/package.json', 'package/cache/_update-notifier-last-checked', 'package/cache/_logs/2026-11-09T10_07_07_879Z-debug-0.log'}
        with tarfile.open(fileobj=io.BytesIO(body), mode='r:*') as bundle:
            seen = set()
            for entry in bundle:
                if entry.name not in expected or entry.name in seen or not entry.isfile() or not 0 <= entry.size <= 65536: raise ValueError('authored npm fixture has an unknown, binary or special member')
                seen.add(entry.name); value = bundle.extractfile(entry).read(); value.decode('utf-8', errors='strict')
                if b'\0' in value: raise ValueError('authored npm fixture is not preferred readable source')
                if entry.name == 'package/cli.cjs' and value != b'#!/usr/bin/env node\n': raise ValueError('authored npm fixture entry source differs')
                if entry.name == 'package/package.json' and json.loads(value) != proof['manifest']: raise ValueError('authored npm fixture manifest differs')
                members.append({'member_path': entry.name, **content(value)})
        if seen != expected: raise ValueError('authored npm fixture omits original source members')
        _, license = read(root, 'LICENSE'); notices = [license]
        source = {'form': 'first-party-authored-readable-packaging-fixture-not-reproduced-npm-pack', **archive, 'original_recipe': descriptor, 'original_members': members}
    return {'content': {key: archive[key] for key in ('sha256', 'size_bytes')}, 'sources': [source], 'notices': notices, 'required_materials': []}


def plugin_binding(root, discovery):
    generator = 'scripts/release/host-adapters.mjs'
    _, original = read(root, generator); _, fixed = read(ROOT, generator)
    if original != fixed: raise ValueError('npm plugin generator differs from candidate-own source')
    rows = [original]
    for name in ['release/identity.yaml', 'release/product.yaml']:
        _, row = read(root, name); rows.append(row)
    code = 'import{pathToFileURL}from"node:url";const m=await import(pathToFileURL(process.argv[1]));process.stdout.write(m.npmHostFiles(m.loadDistributionIdentity(process.argv[2]))["plugin.json"]);'
    result = subprocess.run(['node', '--input-type=module', '-e', code, str(ROOT / generator), str(root)], capture_output=True, timeout=30)
    if result.returncode or len(result.stdout) > 1024 ** 2: raise ValueError('original npm plugin metadata generator failed')
    generated = content(result.stdout)
    if not captured(discovery, 'plugin.json', generated, 'npm'): return None
    _, license = read(root, 'LICENSE')
    return {'content': generated, 'sources': [{'form': 'exact-authored-npm-host-metadata-generation', 'inputs': rows}], 'notices': [license], 'required_materials': []}


def regex_bindings(root, assets, discovery, wanted):
    uv = tomllib.loads((root / 'uv.lock').read_text()); package = next(row for row in uv['package'] if row['name'] == 'regex')
    recipe = json.loads((root / 'runtime/materials/component-source-replay.json').read_bytes())
    families = [row for row in recipe['families'] if row['kind'] == 'python-wheels']
    if len(families) != 1: raise ValueError('one exact Python source family is required')
    source_file = assets / materials.safe(families[0]['sources']); inventory = json.loads(source_file.read_bytes())
    matches = [row for row in inventory['files'] if row.get('family') == 'python-package' and row.get('name') == 'regex' and row.get('version') == package['version']]
    if inventory.get('qualification') != 'exact-locked-source-subinventory' or inventory.get('status') != 'passed' or len(matches) != 1 or matches[0]['sha256'] != package['sdist']['hash'].removeprefix('sha256:') or matches[0]['url'] != package['sdist']['url'] or matches[0]['size_bytes'] != package['sdist']['size']: raise ValueError('regex original source differs from exact uv lock')
    source_row = matches[0]; stream, source_identity, source = materials.opened(source_file.parent, source_row)
    build_inputs = []
    try:
        with tarfile.open(fileobj=stream, mode='r:*') as archive:
            expected = {f'regex-{package["version"]}/' + name for name in ['pyproject.toml', 'setup.py', 'src/_regex.c', 'src/_regex.h', 'src/_regex_unicode.c', 'src/_regex_unicode.h']}
            for entry in archive:
                if entry.name not in expected: continue
                if not entry.isfile() or not 0 <= entry.size <= 16 * 1024 ** 2: raise ValueError('regex actual build input is special or oversized')
                value = archive.extractfile(entry).read(); build_inputs.append({'member_path': entry.name, **content(value)})
            if {row['member_path'] for row in build_inputs} != expected or len(build_inputs) != len(expected): raise ValueError('regex actual setup/C source input closure differs')
        if file_identity(stream) != source_identity: raise ValueError('regex original source changed during member inspection')
    finally: stream.close()
    source_notices = locked.source_notices(source_file.parent / source_row['path'])
    if source_notices != source_row.get('notice_files') or not source_notices: raise ValueError('regex original source notices differ')
    result = []
    paths = {row.get('path', '') for subject in discovery['subjects'] for row in subject['members']}
    wheels = []
    for architecture, platform_tag in (('win32-arm64', 'win_arm64'), ('win32-x64', 'win_amd64')):
        directory = f'runtime/pack/wheels/{architecture}/'
        if any(name.startswith(directory + 'regex-') for name in paths):
            platform = architecture.replace('-', '/', 1)
            wheels.extend((platform, architecture, platform_tag, directory, wheel) for wheel in userspace.select_wheels(package, platform))
    for platform, architecture, platform_tag, directory, wheel in wheels:
        filename = wheel['filename']; path = directory + filename; expected = {'sha256': wheel['sha256'].removeprefix('sha256:'), 'size_bytes': wheel['size']}
        if not captured(discovery, path, expected): continue
        abi = next((value for value in ('cp314', 'cp315') if f'-{value}-{value}-' in filename), None)
        if abi is None or not filename.endswith(f'-{platform_tag}.whl'): raise ValueError('regex wheel ABI/platform differs')
        file = assets / '.artifacts/userspace-inputs/cache' / expected['sha256']; stream, archive_identity, archive_record = materials.opened(file.parent, {'path': file.name, **expected})
        notices = []; metadata = []; wheel_metadata = []; publisher_metadata = []; pe = []; seen = set(); expanded = 0
        try:
            with zipfile.ZipFile(stream) as archive:
                for entry in archive.infolist():
                    name = inspector._paths.validate_path(entry.filename.rstrip('/') if entry.is_dir() else entry.filename); key = inspector._paths.path_key(name)
                    if key in seen or (entry.external_attr >> 16) & 0o170000 not in (0, 0o100000, 0o040000) or entry.file_size > 16 * 1024 ** 2: raise ValueError('regex wheel contains duplicate, special or oversized members')
                    seen.add(key); expanded += entry.file_size
                    if expanded > 64 * 1024 ** 2 or len(seen) > 10000: raise ValueError('regex wheel expansion exceeds bounds')
                    if entry.is_dir(): continue
                    value = archive.read(entry); row = {'container_sha256': expected['sha256'], 'member_path': name, **content(value)}
                    member_architecture = inspector.architecture(value[:65536])
                    if member_architecture not in ('data', 'unknown') or value.startswith((b'MZ', b'\x7fELF')) or name.lower().endswith(('.pyd', '.dll', '.exe', '.so', '.a', '.lib')):
                        if name != f'regex/_regex.{abi}-{platform_tag}.pyd' or member_architecture != architecture: raise ValueError('regex wheel contains an unknown compiled member or wrong PE architecture')
                        pe.append(row)
                    if name.endswith('.dist-info/METADATA'): metadata.append(BytesParser().parsebytes(value)); publisher_metadata.append(row)
                    if name.endswith('.dist-info/WHEEL'): wheel_metadata.append(BytesParser().parsebytes(value)); publisher_metadata.append(row)
                    if '.dist-info/licenses/' in name: notices.append(row)
            if len(pe) != 1 or len(metadata) != 1 or metadata[0].get_all('Name') != ['regex'] or metadata[0].get_all('Version') != [package['version']] or len(wheel_metadata) != 1 or wheel_metadata[0].get_all('Tag') != [f'{abi}-{abi}-{platform_tag}'] or wheel_metadata[0].get('Root-Is-Purelib') != 'false' or not notices: raise ValueError('regex publisher wheel metadata, native ABI or notices differ')
            if file_identity(stream) != archive_identity: raise ValueError('regex original wheel changed during member inspection')
        finally: stream.close()
        result.append({'content': expected, 'sources': [source, {'form': 'exact-locked-publisher-regex-wheel-source-correspondence-not-binary-reproduction', 'wheel_url': wheel['url'], 'version': package['version'], 'abi': abi, 'platform': platform, 'actual_PE_members': pe, 'source_build_inputs': build_inputs, 'publisher_metadata': publisher_metadata, 'declared_generator': wheel_metadata[0].get('Generator'), 'limitations': 'No compiler/CRT provenance or reproduction is inferred. Publisher redistribution authority and any separately applicable component duties remain independent.'}], 'notices': notices + source_notices, 'required_materials': [source]})
    return result


def derive(source_root, assets_root, runtime_root, discovery, wanted, recorder=None):
    root = Path(source_root); assets = Path(assets_root); bindings = []
    paths = {row['path'] for subject in discovery['subjects'] for row in subject['members'] if 'path' in row}
    if any(subject['id'] == 'npm' for subject in discovery['subjects']):
        row = plugin_binding(root, discovery)
        if row: bindings.append(row)
    for name in ['tests/fixtures/source-materials/go-units-v0.5.0.zip', 'tests/fixtures/source-materials/npm-public-fixture.tgz']:
        if name in paths:
            row = fixture_binding(root, discovery, name)
            if row: bindings.append(row)
    if any(name.startswith(('runtime/pack/wheels/win32-arm64/regex-', 'runtime/pack/wheels/win32-x64/regex-')) for name in paths): bindings.extend(regex_bindings(root, assets, discovery, wanted))
    return {'schema_version': 1, 'status': 'passed', 'qualification': 'independently-derived-finite-packaged-content-bindings-not-product-completeness', 'bindings': [row for row in bindings if (row['content']['sha256'], row['content']['size_bytes']) in wanted], 'generator_sha256': digest(Path(__file__).read_bytes()), 'unresolved': [], 'limitations': 'Only fixed authored metadata/fixture archives and exact uv-locked Windows regex wheels are handled. Unknown compiled payloads remain outside this binder; no publisher grant or reproduced binary is asserted.'}
