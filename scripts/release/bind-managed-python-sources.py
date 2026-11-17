#!/usr/bin/env python3
"""Replay managed-interpreter recipe/source/notices joins without target execution."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
import posixpath
from pathlib import Path
import re
import tarfile
from urllib.parse import unquote, urlparse
import zipfile

ROOT = Path(__file__).resolve().parents[2]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
materials = module('ud_python_source_files', Path(__file__).with_name('source-bundle.py'))
paths = module('ud_python_source_paths', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
inspector = module('ud_python_source_arch', Path(__file__).with_name('inspect-package.py'))
PLATFORMS = {'darwin/arm64': 'aarch64-apple-darwin', 'darwin/x64': 'x86_64-apple-darwin', 'linux/arm64': 'aarch64-unknown-linux-gnu', 'linux/x64': 'x86_64-unknown-linux-gnu', 'win32/arm64': 'aarch64-pc-windows-msvc', 'win32/x64': 'x86_64-pc-windows-msvc'}
SHA = re.compile('[a-f0-9]{64}\\Z')

def digest(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

@contextmanager
def opened_original(root, row, source_parts=None, recorder=None):
    """Use an exact staged original or stream it from verified source parts."""
    root = Path(root); name = materials.safe(row['path']); file = root
    for part in name.split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('source-material path contains a link')
    fingerprint = row['sha256'].removeprefix('sha256:'); size = row.get('size_bytes', row.get('size'))
    if file.exists() or source_parts is None:
        stream, identity, actual = materials.opened(root, {**row, 'sha256': fingerprint})
        try:
            yield stream, identity, actual
            try: materials.verify_held_path(stream, file, identity)
            except (OSError, ValueError) as error: raise ValueError('managed Python archive changed during source inspection') from error
        finally: stream.close()
    else:
        if not SHA.fullmatch(fingerprint) or type(size) is not int or size < 0: raise ValueError('streamed managed source identity is invalid')
        with source_parts.open_blob(fingerprint, size) as stream:
            if recorder is not None: recorder.source_blob(file, fingerprint, size)
            yield stream, None, {'path': name, 'sha256': fingerprint, 'size_bytes': size}


def checked(root, row, source_parts=None, recorder=None):
    with opened_original(root, row, source_parts, recorder) as (_, _, actual): return actual
def original_notice(row, data):
    if len(data) != row['size_bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']: raise ValueError('managed Python notice does not match the original recipe bytes')

@contextmanager
def verified_tar(root, row, source_parts=None, recorder=None):
    with opened_original(root, row, source_parts, recorder) as (stream, identity, actual):
        with tarfile.open(fileobj=stream, mode='r:gz') as archive: yield archive
        if identity is not None:
            try: materials.verify_held_path(stream, Path(root) / actual['path'], identity)
            except (OSError, ValueError) as error: raise ValueError('managed Python archive changed during source inspection') from error

def inspect_binary(file, descriptor, platform):
    """Inspect only data: the interpreter header, archive inventory and notices."""
    checked(file.parent, {'path': file.name, 'sha256': descriptor['sha256'], 'size_bytes': descriptor['size']})
    expected = 'python/python.exe' if platform.startswith('win32/') else 'python/bin/python' + '.'.join(descriptor['version'].split('.')[:2])
    executable = None; notices = []; names = set(); folded = {}; case_variants = []; links = {}; total = 0
    with verified_tar(file.parent, {'path': file.name, 'sha256': descriptor['sha256'], 'size_bytes': descriptor['size']}) as archive:
        for entry in archive:
            name = paths.validate_path(entry.name); key = paths.path_key(name)
            if name in names or len(names) >= 50000 or not (entry.isfile() or entry.isdir() or entry.issym() or entry.islnk()) or entry.size < 0 or entry.size > 128 * 1024 ** 2: raise ValueError('managed Python binary archive inventory is unsafe')
            if key in folded:
                # Linux terminfo deliberately includes distinct names such as
                # 2621A/2621a. This is data-only inspection, never host extraction.
                if not platform.startswith('linux/'): raise ValueError('managed Python archive aliases a native case-insensitive path')
                case_variants.append([folded[key], name])
            folded[key] = name; names.add(name); total += entry.size
            if total > 1024 ** 3: raise ValueError('managed Python binary archive exceeds bounds')
            if entry.issym() or entry.islnk():
                target = entry.linkname
                if not target or target.startswith('/') or '\\' in target: raise ValueError('managed Python archive link escapes its runtime')
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target) if entry.issym() else target)
                if not resolved.startswith('python/'): raise ValueError('managed Python archive link escapes its runtime')
                paths.validate_path(resolved); links[name] = resolved
            if name == expected:
                if executable is not None or not entry.isfile(): raise ValueError('managed Python executable identity is ambiguous')
                with archive.extractfile(entry) as source: header = source.read(65536)
                if inspector.architecture(header) != platform.replace('/', '-'): raise ValueError('managed Python executable architecture differs')
                executable = {'path': name, 'size_bytes': entry.size, 'architecture': platform}
            if entry.isfile() and (name.rsplit('/', 1)[-1].startswith(('LICENSE', 'COPYING', 'NOTICE'))):
                if entry.size > 8 * 1024 ** 2: raise ValueError('managed Python notice exceeds bound')
                with archive.extractfile(entry) as source: data = source.read(8 * 1024 ** 2 + 1)
                notices.append({'member_path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data), 'container_sha256': descriptor['sha256'].removeprefix('sha256:')})
    for name, target in links.items():
        seen = {name}
        while target in links:
            if target in seen: raise ValueError('managed Python archive link cycle')
            seen.add(target); target = links[target]
        if target not in names: raise ValueError('managed Python archive link target is missing')
    if executable is None or not notices: raise ValueError('managed Python interpreter or original notices are missing')
    return {'archive_inspected': True, 'executable': executable, 'notices': notices, 'case_sensitive_name_pairs': case_variants, 'target_execution': False}

def derive(root, collection_receipt, binary_archives=(), *, source_parts=None, recorder=None):
    root = Path(root); collection_receipt = Path(collection_receipt); base = collection_receipt.parent
    lock_file = root / 'runtime/managed-python-source.lock.json'; lock = json.loads(lock_file.read_bytes())
    data = json.loads(collection_receipt.read_bytes()); proof = data.get('build_source', {})
    if lock.get('schema_version') != 1 or lock.get('repository') != 'astral-sh/python-build-standalone' or not re.fullmatch('[a-f0-9]{40}', lock.get('commit', '')) or not re.fullmatch('[0-9]{8}', lock.get('tag', '')) or data.get('schema_version') != 1 or data.get('status') != 'passed' or data.get('qualification') != 'frozen-managed-interpreter-runtime-source-subinventory' or any(proof.get(key) != lock.get(key) for key in ('repository', 'commit', 'tag', 'source')): raise ValueError('managed Python collection is not the frozen source recipe')
    source = lock['source']
    if source.get('url') != 'https://codeload.github.com/' + lock['repository'] + '/tar.gz/' + lock['commit'] or not SHA.fullmatch(source.get('sha256', '')): raise ValueError('managed Python build source authority differs')
    recipe = checked(base, {'path': 'build-recipe.tar.gz', **source}, source_parts, recorder); prefix = 'python-build-standalone-' + lock['commit'] + '/'; table = None; original_notices = {}
    with verified_tar(base, {'path': recipe['path'], **source}, source_parts, recorder) as archive:
        for entry in archive:
            if entry.name == prefix[:-1] and entry.isdir(): continue
            if not entry.name.startswith(prefix): raise ValueError('managed Python build source prefix differs')
            relative = entry.name[len(prefix):]
            if not relative or not entry.isfile(): continue
            paths.validate_path(relative)
            if relative == 'pythonbuild/downloads.json':
                if table is not None or not 0 < entry.size <= 2 * 1024 ** 2: raise ValueError('managed Python source table is duplicate or oversized')
                with archive.extractfile(entry) as stream: raw_table = stream.read(2 * 1024 ** 2 + 1)
                table = json.loads(raw_table)
            if '/licenses/' in entry.name or relative.rsplit('/', 1)[-1].startswith(('LICENSE.', 'LICENSE')):
                if entry.size > 8 * 1024 ** 2 or entry.name in original_notices: raise ValueError('managed Python original notice is duplicate or oversized')
                with archive.extractfile(entry) as stream: original_notices[entry.name] = stream.read(8 * 1024 ** 2 + 1)
    if not isinstance(table, dict) or not isinstance(lock.get('python_versions'), dict): raise ValueError('managed Python source table is missing')
    for series, version in lock['python_versions'].items():
        if table.get('cpython-' + series, {}).get('version') != version: raise ValueError('managed Python declared source version differs')
    required = {name: item for name, item in table.items() if 'library_names' in item or name in ('cpython-3.14', 'cpython-3.15', 'pip', 'setuptools', 'linux-uapi', 'musl', 'musl-static', 'zstd')}
    rows = data.get('files', []); supplied = {row['name']: row for row in rows}
    if len(rows) != len(supplied) or set(supplied) != set(required) | {'python-build-standalone'}: raise ValueError('managed Python source inventory adds or omits a runtime recipe input')
    sources = []; collection_hash = digest(collection_receipt)
    for name, expected in sorted(required.items()):
        row = supplied[name]
        if row.get('version') != expected['version'] or row.get('url') != expected['url'] or row.get('sha256') != expected['sha256'] or row.get('size_bytes') != expected['size'] or row.get('acquired') is not True: raise ValueError('managed Python runtime source differs from recipe')
        sources.append({**checked(base, row, source_parts, recorder), 'name': name, 'version': expected['version'], 'url': expected['url'], 'collection_sha256': collection_hash, 'declared_licenses': expected.get('licenses', []), 'declared_public_domain': expected.get('license_public_domain', False)})
    build_row = supplied['python-build-standalone']
    if build_row.get('sha256') != source['sha256'] or build_row.get('version') != lock['commit'] or build_row.get('url') != source['url']: raise ValueError('managed Python build recipe is omitted from source inventory')
    checked(base, build_row, source_parts, recorder)
    licenses = []; noticed = set()
    for row in data.get('notices', []):
        name = row.get('source_path')
        if name not in original_notices or name in noticed: raise ValueError('managed Python original notice inventory differs')
        checked(base, row, source_parts, recorder); original_notice(row, original_notices[name]); noticed.add(name); licenses.append({**row, 'collection_sha256': collection_hash})
    if noticed != set(original_notices): raise ValueError('managed Python original recipe notices are incomplete')
    for expected in required.values():
        if expected.get('license_file') and prefix + expected['license_file'] not in noticed: raise ValueError('managed Python source license file is missing')
    # pip/setuptools universal wheels contain their actual source and vendored
    # notices. Retain those exact nested originals, rather than infer an umbrella license.
    for name in ('pip', 'setuptools'):
        row = supplied[name]
        if not urlparse(row['url']).path.endswith('-py3-none-any.whl'): raise ValueError('managed Python packaging source is not a universal source wheel')
        count = 0
        with opened_original(base, row, source_parts, recorder) as (stream, _, _):
            with zipfile.ZipFile(stream) as archive:
                for entry in archive.infolist():
                    if entry.is_dir(): continue
                    paths.validate_path(entry.filename)
                    if entry.filename.rsplit('/', 1)[-1].startswith(('LICENSE', 'COPYING', 'NOTICE')):
                        if entry.file_size > 8 * 1024 ** 2: raise ValueError('managed Python packaging notice exceeds bound')
                        body = archive.read(entry); licenses.append({'member_path': entry.filename, 'container_sha256': row['sha256'], 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'collection_sha256': collection_hash}); count += 1
        if count == 0: raise ValueError('managed Python packaging original licenses are absent')
    inputs = json.loads((root / 'runtime/userspace-inputs.lock.json').read_bytes())
    if set(inputs.get('platforms', {})) != set(PLATFORMS): raise ValueError('managed Python six-platform acquisition inventory differs')
    archives = dict(binary_archives)
    if len(archives) != len(binary_archives) or set(archives) - set(PLATFORMS): raise ValueError('managed Python binary inspection inputs are duplicated or foreign')
    binaries = []
    for platform, triple in PLATFORMS.items():
        row = inputs['platforms'][platform]['python_download']; version = row.get('version'); filename = 'cpython-' + str(version) + '+' + lock['tag'] + '-' + triple + '-install_only_stripped.tar.gz'
        if version not in lock['python_versions'].values() or not re.fullmatch('sha256:[a-f0-9]{64}', row.get('sha256', '')) or type(row.get('size')) is not int or not 1 <= row['size'] <= 512 * 1024 ** 2 or unquote(row.get('url', '')) != 'https://github.com/' + lock['repository'] + '/releases/download/' + lock['tag'] + '/' + filename: raise ValueError('managed Python binary acquisition descriptor differs from source recipe')
        item = {'platform': platform, 'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row['size'], 'url': row['url'], 'version': version, 'build_source_commit': lock['commit'], 'redistribution': 'vendor-direct-not-redistributed', 'archive_inspected': False, 'target_execution': False}
        if platform in archives: item.update(inspect_binary(Path(archives[platform]), row, platform))
        binaries.append(item)
    return {'schema_version': 1, 'qualification': 'derived-managed-python-source-recipe-license-bindings', 'status': 'passed', 'complete_component_coverage': True, 'complete_product_coverage': False, 'coverage': 'Exact locked vendor acquisition descriptors and build-recipe runtime source overapproximation; binary inspection covers only explicitly supplied archives, never target execution.', 'binary_inputs': binaries, 'sources': sources, 'licenses': licenses, 'build_recipes': [{**recipe, 'repository': lock['repository'], 'commit': lock['commit'], 'table': {'member_path': prefix + 'pythonbuild/downloads.json', 'sha256': hashlib.sha256(raw_table).hexdigest(), 'size_bytes': len(raw_table)}}], 'source_collections': [{'sha256': collection_hash, 'size_bytes': collection_receipt.stat().st_size}], 'source_lock_sha256': digest(lock_file), 'runtime_input_lock_sha256': digest(root / 'runtime/userspace-inputs.lock.json'), 'generator_sha256': digest(Path(__file__))}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--collection', type=Path, required=True); parser.add_argument('--binary', action='append', default=[]); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args(); pairs = []
    for value in args.binary:
        platform, separator, file = value.partition('=')
        if not separator: parser.error('--binary requires PLATFORM=PATH')
        pairs.append((platform, Path(file)))
    result = derive(args.root, args.collection, pairs)
    with args.output.open('x') as output: output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'source_bindings': len(result['sources']), 'original_notices': len(result['licenses']), 'inspected_archives': sum(item['archive_inspected'] for item in result['binary_inputs']), 'target_execution': False}))
