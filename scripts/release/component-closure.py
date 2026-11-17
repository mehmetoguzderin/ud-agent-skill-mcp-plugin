#!/usr/bin/env python3
"""Replay fixed source-family binders and reconcile actual shipped member bytes.

The recipe selects original inputs, never a component list, coverage result or
exception. Missing native builds and unresolved bytes in available artifacts are
separate sets. This module performs data inspection; it runs no target binaries.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import shutil
import tarfile
import tempfile
import tomllib
import zipfile
from contextlib import ExitStack, nullcontext
from email.parser import BytesParser

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    location = Path(file)
    if not location.is_absolute(): location = Path(__file__).with_name(file)
    spec = importlib.util.spec_from_file_location(name, location); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
shipped = module('ud_closure_shipped', 'collect-shipped-components.py')
node = module('ud_closure_node', 'bind-node-sources.py')
perl = module('ud_closure_perl', 'bind-private-perl-sources.py')
packages = module('ud_closure_packages', 'bind-package-sources.py')
rust = module('ud_closure_rust', 'bind-rust-binary-sources.py')
managed = module('ud_closure_python', 'bind-managed-python-sources.py')
binary_sources = module('ud_closure_dpkg', 'bind-binary-sources.py')
locked = module('ud_closure_locked', 'collect-locked-sources.py')
runtime_only = module('ud_closure_perl_filter', ROOT / 'scripts/runtime/prepare-perl-runtime-only.py')
perl_vendor = module('ud_closure_perl_vendor_filter', ROOT / 'scripts/runtime/prepare-perl-vendor-runtime.py')
oci_packages = module('ud_closure_oci_packages', 'bind-oci-package-files.py')
oci_python = module('ud_closure_oci_python', 'bind-oci-python-runtime.py')
pip_components = module('ud_closure_pip_components', 'bind-pip-components.py')
provider_components = module('ud_closure_provider_components', 'bind-provider-components.py')
packaged_data = module('ud_closure_packaged_data', 'bind-packaged-data.py')
render_components = module('ud_closure_render_components', 'bind-render-sources.py')
worker_metadata = module('ud_closure_worker_metadata', 'bind-worker-metadata.py')
retained_inputs = module('ud_closure_retained_inputs', 'retain-component-inspection-inputs.py')
stl_bindings = module('ud_closure_stl_bindings', 'stl-source-bindings.py')
component_duties = module('ud_closure_component_duties', 'component-source-duties.py')
inspection = module('ud_closure_inspection_inputs', 'replay-inspection-inputs.py')


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
REPORT_LIMIT = 192 * 1024 ** 2


def compact_report(report):
    """Losslessly intern repeated multi-fact lists; retain every physical row."""
    groups = sorted({tuple(row['facts']) for subject in report['subjects'] for row in subject['bindings'] if len(row['facts']) > 1})
    indexes = {group: index for index, group in enumerate(groups)}
    subjects = [{**subject, 'bindings': [{**row, 'facts': indexes[tuple(row['facts'])] if len(row['facts']) > 1 else row['facts']} for row in subject['bindings']]} for subject in report['subjects']]
    return {**report, 'format_revision': 2, 'binding_fact_sets': [list(group) for group in groups], 'subjects': subjects}


def expanded_report(report):
    """Read legacy arrays and revision 2 indexes without changing their facts."""
    revision = report.get('format_revision', 1)
    if type(revision) is not int or revision not in (1, 2): raise ValueError('unsupported component report format revision')
    if revision == 1:
        if 'binding_fact_sets' in report: raise ValueError('component fact table requires format revision 2')
        return report
    groups = report.get('binding_fact_sets')
    if not isinstance(groups, list) or len(groups) > 100000: raise ValueError('component binding fact table is absent or oversized')
    tuples = []
    for group in groups:
        if not isinstance(group, list) or not 2 <= len(group) <= 10000 or any(not isinstance(value, str) or not shipped.re.fullmatch('[a-f0-9]{64}', value) for value in group) or group != sorted(set(group)): raise ValueError('component binding fact set is invalid')
        tuples.append(tuple(group))
    if tuples != sorted(set(tuples)): raise ValueError('component binding fact table is not canonical or is duplicated')
    used = set(); subjects = []
    for subject in report['subjects']:
        bindings = []
        for row in subject['bindings']:
            values = row.get('facts')
            if type(values) is int:
                if not 0 <= values < len(groups): raise ValueError('component binding fact index is outside its table')
                used.add(values); values = groups[values]
            elif not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str) or not shipped.re.fullmatch('[a-f0-9]{64}', values[0]): raise ValueError('component revision 2 inline fact list is invalid')
            bindings.append({**row, 'facts': values})
        subjects.append({**subject, 'bindings': bindings})
    if used != set(range(len(groups))): raise ValueError('component binding fact table contains unused sets')
    return {key: subjects if key == 'subjects' else value for key, value in report.items() if key not in ('format_revision', 'binding_fact_sets')}


def report_bytes(report):
    encoded = canonical(compact_report(report)) + b'\n'
    if len(encoded) > REPORT_LIMIT: raise ValueError('component source report exceeds its bounded reader limit')
    return encoded


def digest(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()
def record(file): return {'sha256': digest(file), 'size_bytes': file.stat().st_size}
def content_identity(value):
    if isinstance(value, list): return [content_identity(row) for row in value]
    if isinstance(value, dict):
        # Developer/CI absolute cache locations are not a content identity.
        # All receipt bytes are independently reopened and hashed first.
        receipt = 'sha256' in value and ('size' in value or 'size_bytes' in value)
        normalized = {key: '<verified-local-content>' if receipt and key == 'path' and isinstance(item, str) and item.startswith('/') else content_identity(item) for key, item in value.items()}
        if 'source_binding_sha256' in value and 'package_source_binding' in value:
            # The OCI package binder also hashes its proof before normalizing
            # the verified receipt paths. Bind the same proof after relocation.
            normalized['source_binding_sha256'] = hashlib.sha256(canonical(normalized['package_source_binding'])).hexdigest()
        return normalized
    return value
def selected(root, name, directory=False):
    name = shipped.inspector._paths.validate_path(name); file = root
    for part in name.split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('component source input contains a link')
    if directory and not file.is_dir() or not directory and not file.is_file(): raise ValueError('component source input is absent or special')
    return file


class Facts:
    def __init__(self): self.rows = {}; self.by_content = {}; self.relationships = {}; self.materials = {}
    def require_materials(self, materials):
        required = set()
        for row in materials:
            material = {'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row.get('size_bytes', row.get('size'))}
            if not shipped.re.fullmatch('[a-f0-9]{64}', material['sha256']) or type(material['size_bytes']) is not int or material['size_bytes'] < 0: raise ValueError('original required source material receipt is invalid')
            if material['sha256'] in self.materials and self.materials[material['sha256']] != material: raise ValueError('required original source material size conflicts')
            self.materials[material['sha256']] = material; required.add(material['sha256'])
        return required
    def add(self, family, content, sources, notices, recipe, materials=()):
        size = content.get('size_bytes', content.get('size')); fingerprint = content['sha256'].removeprefix('sha256:')
        if not isinstance(size, int) or size < 0 or not shipped.re.fullmatch('[a-f0-9]{64}', fingerprint) or not sources or not notices:
            raise ValueError('derived source fact is missing an exact content/source/notice relation')
        source_key = hashlib.sha256(canonical(sources)).hexdigest(); notice_key = hashlib.sha256(canonical(notices)).hexdigest()
        self.relationships[source_key] = sources; self.relationships[notice_key] = notices
        required = self.require_materials(materials)
        definition = {'family': family, 'sha256': fingerprint, 'size_bytes': size, 'sources_sha256': source_key, 'notices_sha256': notice_key, 'recipe_sha256': recipe, 'required_material_sha256': sorted(required)}
        identifier = hashlib.sha256(canonical(definition)).hexdigest(); self.rows[identifier] = definition
        self.by_content.setdefault((fingerprint, size), set()).add(identifier)


def source_inventory(root):
    code = "import{sourceReceipt}from'./scripts/release/candidate.mjs';console.log(JSON.stringify(sourceReceipt(process.argv[1])))"
    result = subprocess.run(['node', '--input-type=module', '-e', code, str(root)], cwd=ROOT, capture_output=True, timeout=120)
    if result.returncode or len(result.stdout) > 64 * 1024 ** 2: raise ValueError('actual source inventory could not be reconstructed')
    return json.loads(result.stdout)


def preferred_source_file(row, prefix):
    if prefix.startswith((b'\x7fELF', b'MZ', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\0asm', b'!<arch>\n', b'Microsoft C/C++ MSF')): return False
    # A vendored prebuilt archive/object is not first-party source merely
    # because it was copied into a source-inventoried path. Original license
    # DOCX documents remain actual source-form evidence, not software bundles.
    lower = row['path'].lower()
    if lower.endswith(('.whl', '.zip', '.gz', '.xz', '.bz2', '.zst', '.tar', '.tgz', '.conda', '.msi', '.pkg', '.crate', '.pyc', '.class', '.o', '.obj', '.a', '.lib', '.pdb', '.wasm')): return False
    if prefix.startswith((b'PK\x03\x04', b'\x1f\x8b', b'\xfd7zXZ\0', b'BZh', b'\x28\xb5\x2f\xfd')) and not (row['path'].startswith('licenses/') and lower.endswith('.docx')): return False
    return True


def proprietary_declarations(root):
    """The exact source-duty review resolves attribution, never legal authority."""
    name = 'runtime/materials/msvc-static-components.lock.json'; file = root / name
    if not file.is_file(): return {}
    data = json.loads(file.read_bytes()); review_file = root / 'quality/reviews/msvc-source-duty-root-review.json'
    if not review_file.is_file(): return {}
    review = json.loads(review_file.read_bytes())
    if data.get('qualification') != 'exact-proprietary-component-declarations-no-publisher-grant' or review.get('qualification') != 'independent-exact-source-duty-review-not-publisher-license-authority' or review.get('component_declaration', {}).get('sha256') != digest(file) or review.get('component_declaration', {}).get('size') != file.stat().st_size or review.get('cross_build_receipt_sha256') != data.get('cross_build_receipt_sha256') or len(review.get('components', [])) != len(data.get('components', [])):
        raise ValueError('exact independent proprietary source-duty review is stale')
    result = {}
    for item in data['components']:
        definition = {key: value for key, value in item.items() if key != 'definition_sha256'}
        if hashlib.sha256(canonical(definition)).hexdigest() != item.get('definition_sha256'): raise ValueError('proprietary component definition differs')
        rows = [row for row in review['components'] if row['id'] == item['id']]
        if len(rows) != 1 or any(rows[0].get(key) != item[key] for key in ('definition_sha256', 'binary_sha256')) or rows[0].get('decision') != 'source-unavailable-proprietary-declaration-accepted' or rows[0].get('terms') != [{key: value[key] for key in ('path', 'sha256', 'size')} for value in item['terms']]: raise ValueError('proprietary component is outside the exact source-duty review')
        for term in item['terms']:
            if record(selected(root, term['path'])) != {'sha256': term['sha256'], 'size_bytes': term['size']}: raise ValueError('original proprietary terms differ')
        if item['binary_sha256'] in result: raise ValueError('proprietary component binary is duplicated')
        result[item['binary_sha256']] = item
    return result


def source_member_facts(archive, source, notices, facts, wanted, generator, *, stream=None):
    """Match original source/resource bytes without extracting member paths."""
    sizes = {size for _, size in wanted}; seen = set(); total = 0
    own_stream = stream is None
    if own_stream: stream, identity, _ = shipped.materials.opened(archive.parent, {'path': archive.name, 'sha256': source['sha256'], 'size_bytes': source.get('size_bytes', source.get('size'))})
    else: stream.seek(0)
    try:
        with tarfile.open(fileobj=stream, mode='r:*') as bundle:
            for member in bundle:
                name = member.name.removeprefix('./').rstrip('/')
                if not name or name.startswith('/') or '\\' in name or any(part in ('', '.', '..') for part in name.split('/')) or name in seen or len(seen) >= 200000: raise ValueError('original source has unsafe or duplicate member paths')
                seen.add(name); total += member.size
                if member.size < 0 or member.size > 512 * 1024 ** 2 or total > 4 * 1024 ** 3: raise ValueError('original source expansion exceeds bounds')
                if not member.isfile() or member.size not in sizes: continue
                with bundle.extractfile(member) as body:
                    prefix = body.read(65536)
                    if not preferred_source_file({'path': name}, prefix): continue
                    fingerprint = hashlib.sha256(prefix); size = len(prefix)
                    while chunk := body.read(1024 ** 2): fingerprint.update(chunk); size += len(chunk)
                if size != member.size: raise ValueError('original source member is truncated')
                content = {'sha256': fingerprint.hexdigest(), 'size_bytes': size}
                if (content['sha256'], size) in wanted: facts.add('exact-original-source-member', content, [{**source, 'member_path': name}], notices, generator, [source])
        if own_stream:
            current = stream.fileno(); info = __import__('os').fstat(current)
            if identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError('original source archive changed during member inspection')
    finally:
        if own_stream: stream.close()


def zip_source_member_facts(archive, source, notices, facts, wanted, generator, *, stream=None):
    """Match source/data members of original universal wheels, not PE stubs."""
    sizes = {size for _, size in wanted}; seen = set(); total = 0
    own_stream = stream is None
    if own_stream: stream, identity, _ = shipped.materials.opened(archive.parent, {'path': archive.name, 'sha256': source['sha256'], 'size_bytes': source.get('size_bytes', source.get('size'))})
    else: stream.seek(0)
    try:
        with zipfile.ZipFile(stream) as bundle:
            for entry in bundle.infolist():
                name = shipped.inspector._paths.validate_path(entry.filename.rstrip('/') if entry.is_dir() else entry.filename)
                key = shipped.inspector._paths.path_key(name)
                if key in seen or len(seen) >= 100000 or (entry.external_attr >> 16) & 0o170000 not in (0, 0o100000, 0o040000): raise ValueError('original universal source wheel has linked or duplicate members')
                seen.add(key); total += entry.file_size
                if not 0 <= entry.file_size <= 512 * 1024 ** 2 or total > 4 * 1024 ** 3: raise ValueError('original universal source wheel expansion exceeds bound')
                if entry.is_dir() or entry.file_size not in sizes: continue
                with bundle.open(entry) as body:
                    prefix = body.read(65536)
                    if not preferred_source_file({'path': name}, prefix): continue
                    fingerprint = hashlib.sha256(prefix); size = len(prefix)
                    while chunk := body.read(1024 ** 2): fingerprint.update(chunk); size += len(chunk)
                if size != entry.file_size: raise ValueError('original universal source wheel member is truncated')
                content = {'sha256': fingerprint.hexdigest(), 'size_bytes': size}
                if (content['sha256'], size) in wanted: facts.add('exact-original-source-member', content, [{**source, 'member_path': name}], notices, generator, [source])
        if own_stream:
            info = __import__('os').fstat(stream.fileno())
            if identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError('original universal source wheel changed during inspection')
    finally:
        if own_stream: stream.close()


def original_runtime_notices(archive, source, *, stream=None):
    own_stream = stream is None
    if own_stream: stream, identity, _ = shipped.materials.opened(archive.parent, {'path': archive.name, 'sha256': source['sha256'], 'size_bytes': source['size_bytes']})
    else: stream.seek(0)
    records = []; seen = set(); total = 0
    def notice(name, size, body):
        nonlocal total
        name = shipped.inspector._paths.validate_path(name)
        if name in seen or len(seen) >= 200000 or size > 512 * 1024 ** 2: raise ValueError('original runtime source member is duplicate or oversized')
        seen.add(name); total += size
        if total > 4 * 1024 ** 3: raise ValueError('original runtime source expansion exceeds bound')
        if shipped.re.match(r'^(license|copying|notice|copyright)(?:[._-].*)?$', name.rsplit('/', 1)[-1].lower()):
            if size > 8 * 1024 ** 2: raise ValueError('original runtime source notice exceeds bound')
            content = body.read(size + 1)
            if len(content) != size: raise ValueError('original runtime source notice is truncated')
            records.append({'source_archive_sha256': source['sha256'], 'member_path': name, 'sha256': hashlib.sha256(content).hexdigest(), 'size_bytes': size})
    try:
        if zipfile.is_zipfile(stream):
            stream.seek(0)
            with zipfile.ZipFile(stream) as bundle:
                for entry in bundle.infolist():
                    if entry.is_dir(): continue
                    if (entry.external_attr >> 16) & 0o170000 not in (0, 0o100000): continue
                    with bundle.open(entry) as body: notice(entry.filename, entry.file_size, body)
        else:
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r:*') as bundle:
                for entry in bundle:
                    if not entry.isfile(): continue
                    with bundle.extractfile(entry) as body: notice(entry.name.removeprefix('./'), entry.size, body)
        if own_stream:
            info = __import__('os').fstat(stream.fileno())
            if identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError('original runtime source changed while reading notices')
    finally:
        if own_stream: stream.close()
    return records


def verify_npm_program_inputs(source_file, bindings, inputs, recorder=None, assets_root=None):
    """Reopen original npm members used by the actual bundle/tool program."""
    groups = {}
    for content in inputs:
        choices = [(consumer, row) for row in bindings if row['family'] == 'npm' for consumer in row['consumers'] if content['path'].startswith(consumer + '/')]
        if not choices: raise ValueError('bundle input has no exact locked npm source consumer')
        consumer, row = max(choices, key=lambda value: len(value[0])); name = 'package/' + content['path'][len(consumer) + 1:]
        group = groups.setdefault(row['source']['sha256'], {'binding': row, 'members': {}})
        if name in group['members'] and group['members'][name] != content: raise ValueError('bundle source member identity conflicts')
        group['members'][name] = content
    for group in groups.values():
        row = group['binding']; found = set()
        stream, identity, _ = shipped.materials.opened(source_file.parent, row['source'])
        try:
            with tarfile.open(fileobj=stream, mode='r:*') as bundle:
                for entry in bundle:
                    name = entry.name.removeprefix('./')
                    if name not in group['members']: continue
                    if name in found or not entry.isfile() or entry.size > 128 * 1024 ** 2: raise ValueError('actual bundled npm member is duplicate, special or oversized')
                    with bundle.extractfile(entry) as body: actual = {'sha256': hashlib.file_digest(body, 'sha256').hexdigest(), 'size': entry.size}
                    wanted = group['members'][name]
                    if actual != {key: wanted[key] for key in ('sha256', 'size')}: raise ValueError('actual bundle/compiler input differs from its locked original npm archive')
                    if recorder is not None: recorder.source_member(assets_root / wanted['path'], row['source']['sha256'], name)
                    found.add(name)
            info = __import__('os').fstat(stream.fileno())
            if identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError('original npm member source changed during same-FD inspection')
        finally: stream.close()
        if found != set(group['members']): raise ValueError('locked npm archive omits an actual bundle/compiler input')
    return [group['binding'] for _, group in sorted(groups.items())]


def record_package_notices(recorder, source_file, bindings):
    if recorder is None: return
    for binding in bindings:
        for notice in binding['notices']:
            recorder.source_member(source_file.parent / notice['path'], binding['source']['sha256'], notice['source_path'])


def wheel_facts(root, assets_root, source_file, facts, wanted, wheel_roots=()):
    """Bind actually shipped wheels to their exact locked release source."""
    uv = tomllib.loads((root / 'uv.lock').read_text()); locks = json.loads((root / 'runtime/ud-sources.lock.json').read_bytes()); tools = next(row for row in locks['sources'] if row['repository'] == 'UniversalDependencies/tools')
    source_data = json.loads(source_file.read_bytes()); reports = []; pending = []; observed = set()
    if source_data.get('qualification') != 'exact-locked-source-subinventory' or source_data.get('status') != 'passed': raise ValueError('original Python source collection is incomplete')
    for package in rust.userspace.core_packages(uv, tools['commit']):
        sdist = package.get('sdist'); sources = [row for row in source_data['files'] if row.get('family') == 'python-package' and row['name'] == package['name'] and row['version'] == package['version']]
        if not sdist or len(sources) != 1 or sources[0]['sha256'] != sdist['hash'].removeprefix('sha256:') or sources[0]['url'] != sdist['url']: raise ValueError('wheel release has no exact locked corresponding source')
        source_row = sources[0]; stream, _, source = shipped.materials.opened(source_file.parent, source_row); stream.close()
        original_notices = locked.source_notices(source_file.parent / source_row['path'])
        if original_notices != source_row.get('notice_files') or not original_notices: raise ValueError('Python source original notice inventory is missing or changed')
        for host in sorted(rust.userspace.HOSTS):
            for wheel in rust.userspace.select_wheels(package, host):
                key = (wheel['sha256'][7:], wheel['size'])
                if key in observed: continue
                archive = assets_root / '.artifacts/userspace-inputs/cache' / key[0]
                if not archive.exists():
                    candidates = [directory / wheel['filename'] for directory in wheel_roots if (directory / wheel['filename']).exists()]
                    if candidates:
                        for candidate in candidates:
                            stream, _, _ = shipped.materials.opened(candidate.parent, {'path': candidate.name, 'sha256': key[0], 'size_bytes': key[1]}); stream.close()
                        archive = candidates[0]
                if key not in wanted and not archive.exists(): continue
                observed.add(key)
                stream, _, content = shipped.materials.opened(archive.parent, {'path': archive.name, 'sha256': key[0], 'size_bytes': key[1]}); stream.close()
                notices = []; metadata = []; compiled_windows = False; names = set(); expanded = 0; members = []
                with zipfile.ZipFile(archive) as bundle:
                    for entry in bundle.infolist():
                        name = shipped.inspector._paths.validate_path(entry.filename.rstrip('/') if entry.is_dir() else entry.filename)
                        if name in names or len(names) >= 50000 or entry.file_size > 128 * 1024 ** 2 or (entry.external_attr >> 16) & 0o170000 not in (0, 0o040000, 0o100000): raise ValueError('wheel member inventory is linked, duplicate or oversized')
                        names.add(name); expanded += entry.file_size
                        if expanded > 512 * 1024 ** 2: raise ValueError('wheel expansion exceeds bound')
                        if entry.is_dir(): continue
                        with bundle.open(entry) as body:
                            prefix = body.read(65536); fingerprint = hashlib.sha256(prefix); size = len(prefix)
                            while chunk := body.read(1024 ** 2): fingerprint.update(chunk); size += len(chunk)
                        if size != entry.file_size: raise ValueError('original wheel member is truncated')
                        members.append({'sha256': fingerprint.hexdigest(), 'size_bytes': size, 'member_path': name, 'architecture': shipped.inspector.architecture(prefix)})
                        if prefix.startswith(b'MZ'): compiled_windows = True
                        if '.dist-info/' in name and name.endswith('/METADATA'):
                            if entry.file_size > 4 * 1024 ** 2: raise ValueError('wheel metadata exceeds bound')
                            metadata.append(BytesParser().parsebytes(bundle.read(entry)))
                        if '.dist-info/' in name and ('/licenses/' in name or name.rsplit('/', 1)[-1].lower().startswith(('license', 'copying', 'notice'))):
                            if entry.file_size > 8 * 1024 ** 2: raise ValueError('wheel notice exceeds bound')
                            body = bundle.read(entry); notices.append({'container_sha256': key[0], 'member_path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)})
                normalized = lambda value: value.lower().replace('_', '-').replace('.', '-')
                if len(metadata) != 1 or metadata[0].get_all('Name') is None or len(metadata[0].get_all('Name')) != 1 or normalized(metadata[0]['Name']) != normalized(package['name']) or metadata[0].get_all('Version') != [package['version']] or not notices: raise ValueError('wheel publisher name/version/original notices differ')
                row = {'platform': host, 'package': {'name': package['name'], 'version': package['version']}, 'wheel': content, 'source': source, 'original_wheel_notices': notices, 'original_source_notices': original_notices}
                reports.append(row)
                for member in members:
                    if (member['sha256'], member['size_bytes']) not in wanted or member['architecture'].startswith('win32-'): continue
                    facts.add('locked-python-wheel-member', member, [source, {'original_wheel_sha256': key[0], 'member_path': member['member_path']}], notices + original_notices, digest(Path(__file__)), [source])
                if compiled_windows:
                    pending.append({'code': 'WINDOWS_WHEEL_COMPILER_RUNTIME_DECLARATION_REQUIRED', 'sha256': key[0], 'size_bytes': key[1], 'name': package['name'], 'version': package['version']}); continue
                facts.add('locked-python-wheel', content, [source], notices + original_notices, digest(Path(__file__)), [source])
    return {'status': 'incomplete' if pending else 'passed', 'generator_sha256': digest(Path(__file__)), 'bindings': reports, 'pending_declarations': pending}



def replay_perl_filters(root, assets_root, selection, definition, recorder=None):
    derivation = definition['runtime_only_derivation']
    if derivation['generator_sha256'] != digest(selected(root, 'scripts/runtime/prepare-perl-runtime-only.py')):
        raise ValueError('runtime-only Perl filter recipe is stale')
    input_pack = selected(assets_root, selection['input_pack'], True)
    input_receipt = selected(assets_root, selection['input_receipt'])
    with tempfile.TemporaryDirectory(prefix='ud-perl-filter-replay-') as temporary:
        filtered = Path(temporary) / 'runtime'
        replayed = runtime_only.prepare(input_pack, input_receipt, filtered)
        if 'vendor_supplier_removed' in definition:
            lock_file = selected(root, 'runtime/windows-perl-distributions.lock.json')
            lock = json.loads(lock_file.read_bytes())['platforms'][replayed['platform'].split('/')[1]]
            provider, = lock['redistributables']
            vendor_cache = '.artifacts/native-perl/cache/windows/'
            archive = selected(assets_root, vendor_cache + provider['filename'])
            supplier = selected(assets_root, vendor_cache + lock['perl']['filename'])
            replayed = perl_vendor.prepare(
                filtered, filtered.with_name('runtime-receipt.json'), archive, Path(temporary) / 'vendor',
                lock_file=lock_file, supplier_archive=supplier)
    if canonical(replayed) != canonical(definition):
        raise ValueError('runtime-only Perl exact input/filter inventory does not replay')
    if recorder is not None and 'vendor_supplier_removed' in definition:
        # Originals used to verify the excluded vendor binaries stay private.
        # Record them only after the exact two-stage filter replay succeeds.
        for file, role, descriptor in (
            (supplier, 'windows-perl-supplier-archive', lock['perl']),
            (archive, 'windows-perl-vc-archive', provider),
        ):
            recorder.private_vendor_input(file, role, {
                'sha256': descriptor['sha256'].removeprefix('sha256:'), 'size_bytes': descriptor['size_bytes']})
        removed = (*derivation['removed'], *definition['vendor_supplier_removed'], *definition['vendor_runtime_removed'])
        for row in removed:
            recorder.private_vendor_input(input_pack / inspection.safe(row['path']), 'windows-perl-build-input-member', {
                'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row.get('size_bytes', row.get('size'))})
    return replayed


def replay(root, recipe, facts, assets_root=None, wanted=(), artifact_ids=(), platforms=(), node_platforms=None, recorder=None, runtime_root=None, provider_artifacts=(), discovery=None, source_parts=None, start_perl_family=None):
    """Only these versioned original-input contracts can issue content facts."""
    if recipe.get('schema_version') != 1 or set(recipe) != {'schema_version', 'families'} or not isinstance(recipe['families'], list): raise ValueError('component closure requires a closed original-input recipe')
    assets_root = root if assets_root is None else assets_root
    reports = []; external = []; seen = set(); wheel_packages = {}; pip_original = None; packaged_keys = set(); font_sources = []
    input_file = lambda name: selected(assets_root, name)
    def original_pip():
        nonlocal pip_original
        if pip_original is None:
            recipes = [row for row in recipe['families'] if row.get('kind') == 'pip-runtime']
            if len(recipes) != 1 or set(recipes[0]) != {'kind', 'original_sources', 'wheel_base'}: raise ValueError('installed source forms require one exact pip source recipe')
            value = recipes[0]
            pip_original = pip_components.derive(root, selected(assets_root, value['original_sources'], True), selected(assets_root, value['wheel_base'], True))
        return pip_original
    duties = component_duties.derive(root, assets_root, {fingerprint for fingerprint, _ in wanted})
    for item in recipe['families']:
        family_stage = None
        kind = item.get('kind'); identity = canonical(item)
        if identity in seen: raise ValueError('source family input is duplicated')
        seen.add(identity)
        if kind == 'node':
            if not {'kind', 'sources'} <= set(item) or set(item) - {'kind', 'sources', 'rust_sources'}: raise ValueError('unexpected Node source recipe fields')
            if node_platforms is not None and not node_platforms: continue
            result = node.derive(root, input_file(item['sources']), assets_root, input_file(item['rust_sources']) if 'rust_sources' in item else None, node_platforms, recorder, source_parts)
            for binary in result['binary_inputs']:
                for content in binary['binary_files']:
                    runtime = binary['rust_standard_library']
                    duty = duties.get(content['sha256'])
                    if content['executable'] and (runtime['pending'] or binary['producer_static_runtime_declaration_pending'] and not (duty and duty['complete_component_source_duties'])): continue
                    sources = [*result['sources'], *([runtime['source'], *runtime['dependencies'], *runtime.get('verification_materials', []), *runtime.get('producer_sources', []), *runtime.get('producer_verification_materials', [])] if content['executable'] else [])]
                    notices = [*result['licenses'], *(runtime.get('producer_notices', []) if content['executable'] else [])]
                    if content['executable'] and duty:
                        sources.append({'qualification': 'independently-reviewed-component-source-duties-not-publisher-authority', 'groups': duty['groups']}); notices.extend(duty['notices'])
                    facts.add('node', content, sources, notices, result['generator_sha256'], [row for row in sources if 'sha256' in row] + result.get('inspection_inputs', []) + (duty['required_materials'] if content['executable'] and duty else []))
        elif kind == 'private-perl':
            if not {'kind', 'pack', 'receipt', 'sources'} <= set(item) or set(item) - {'kind', 'pack', 'receipt', 'sources', 'elf', 'runtime_only', 'platform'}: raise ValueError('unexpected private Perl source recipe fields')
            if 'platform' in item:
                if item['platform'] not in rust.userspace.HOSTS: raise ValueError('unsupported private Perl source platform')
                if item['platform'] not in platforms: continue
            if start_perl_family is not None: family_stage = start_perl_family(item)
            definition = json.loads(input_file(item['receipt']).read_bytes())
            if 'platform' in item and perl.receipt_platform(definition.get('platform', item['platform'])) != item['platform']: raise ValueError('private Perl source platform differs from its actual receipt')
            if 'runtime_only_derivation' in definition:
                selection = item.get('runtime_only')
                if not isinstance(selection, dict) or set(selection) != {'input_pack', 'input_receipt'}: raise ValueError('runtime-only Perl requires its preserved original input recipe')
                replay_perl_filters(root, assets_root, selection, definition, recorder)
            elif 'runtime_only' in item: raise ValueError('runtime-only Perl replay selected for an unfiltered input')
            elf_file = None; elf_components = {}
            if 'elf' in item:
                value = item['elf']
                if not {'inventory', 'sources', 'private_runtime', 'keyring', 'proof'} <= set(value) or set(value) - {'inventory', 'sources', 'private_runtime', 'keyring', 'gpgv', 'proof'}: raise ValueError('unexpected private ELF source recipe fields')
                verifier = input_file(value['gpgv']) if 'gpgv' in value else Path(shutil.which('gpgv') or '').resolve()
                checked = binary_sources.derive(input_file(value['inventory']), input_file(value['sources']), input_file(value['private_runtime']), keyring=input_file(value['keyring']), gpgv=verifier, source_parts=source_parts, recorder=recorder)
                elf_file = input_file(value['proof'])
                if canonical(content_identity(checked)) != canonical(content_identity(json.loads(elf_file.read_bytes()))): raise ValueError('private ELF source proof does not replay exactly')
                for component in checked['bindings']:
                    for binary in component['binary_files']: elf_components.setdefault(binary['sha256'], []).append(component)
            result = perl.derive(root, selected(assets_root, item['pack'], True), input_file(item['receipt']), [input_file(name) for name in item['sources']], elf_file, assets_root=assets_root, source_parts=source_parts, recorder=recorder)
            pending = {row['sha256'] for row in result['pending_declarations']}
            for content in result['binary_files']:
                duty = duties.get(content['sha256'])
                if content['sha256'] in pending and not (duty and duty['complete_component_source_duties']): continue
                if content['sha256'] in elf_components:
                    origins = elf_components[content['sha256']]; sources = [row for component in origins for row in component['sources']]; originals = [row for source in sources for row in source['files']]; notices = []
                    for component in origins:
                        stream, _, notice = shipped.materials.opened(input_file(item['elf']['inventory']).parent, component['notice']); stream.close(); notices.append(notice)
                    facts.add('private-perl-provider-image-library', content, sources, notices, checked['generator_sha256'], originals + notices)
                else:
                    sources = result['sources'] + ([{'qualification': 'independently-reviewed-component-source-duties-not-publisher-authority', 'groups': duty['groups']}] if duty else [])
                    notices = result['licenses'] + (duty['notices'] if duty else [])
                    materials = [row['source'] for row in result['sources']] + (duty['required_materials'] if duty else [])
                    open_xs = result.get('open_xs', {}).get(content['path'])
                    if open_xs:
                        sources.append(open_xs)
                        notices.extend(open_xs['notices'])
                        materials.extend([*open_xs['sources'], open_xs['link_map']])
                    facts.add('private-perl', content, sources, notices, result['generator_sha256'], materials)
        elif kind == 'packages':
            if set(item) != {'kind', 'sources', 'cargo_locks'}: raise ValueError('unexpected package source recipe fields')
            result = packages.derive(root, input_file(item['sources']), [input_file(name) for name in item['cargo_locks']])
            # Package source receipts authorize direct original notice/source
            # bytes, never arbitrary prebuilt binaries inside npm tarballs.
            for binding in result['bindings']:
                for content in binding['notices']: facts.add('dependency-notice', content, [binding['source']], binding['notices'], result['generator_sha256'], [binding['source']])
        elif kind == 'coordinator-bundle':
            if set(item) != {'kind', 'package_sources', 'cargo_locks'}: raise ValueError('unexpected coordinator source recipe fields')
            source_file = input_file(item['package_sources']); cargo_locks = [input_file(name) for name in item['cargo_locks']]
            program = ROOT / 'scripts/release/replay-coordinator-bundle.mjs'
            environment = {'PATH': __import__('os').environ.get('PATH', ''), 'LC_ALL': 'C', **({'SystemRoot': __import__('os').environ['SystemRoot']} if 'SystemRoot' in __import__('os').environ else {})}
            inventory = subprocess.run(['node', str(program), '--tool-inputs', str(assets_root)], capture_output=True, timeout=30, env=environment)
            if inventory.returncode or len(inventory.stdout) > 65536: raise ValueError('coordinator original tool input inventory is unavailable')
            tool_inputs = json.loads(inventory.stdout)
            package_result = packages.derive_npm_inputs(root, source_file, tool_inputs, cargo_locks)
            # This precedes loading main.js or executing its native compiler.
            verify_npm_program_inputs(source_file, package_result['bindings'], tool_inputs, recorder, assets_root)
            checked = subprocess.run(['node', str(program), str(root), str(assets_root), json.dumps(tool_inputs)], capture_output=True, timeout=300, env=environment)
            if checked.returncode or len(checked.stdout) > 8 * 1024 ** 2: raise ValueError('original coordinator source bundle did not replay: ' + checked.stderr.decode('utf-8', 'replace')[-2000:])
            result = json.loads(checked.stdout)
            if recorder is not None:
                for content in [*result['inputs'], *result['tool_inputs']]:
                    if content['path'].startswith('node_modules/'): recorder.note(assets_root / content['path'])
            if result.get('source_inventory_sha256') != source_inventory(root)['sha256']: raise ValueError('coordinator replay used another source snapshot')
            originals = {row['path']: row for row in source_inventory(root)['files']}
            for content in result['inputs']:
                if content['path'].startswith('node_modules/'): continue
                if originals.get(content['path']) != content: raise ValueError('coordinator replay source input is not in the exact original snapshot')
            npm_inputs = [row for row in result['inputs'] if row['path'].startswith('node_modules/')]
            package_result = packages.derive_npm_inputs(root, source_file, [*npm_inputs, *result['tool_inputs']], cargo_locks)
            record_package_notices(recorder, source_file, package_result['bindings'])
            dependencies = verify_npm_program_inputs(source_file, package_result['bindings'], npm_inputs, recorder, assets_root)
            # Compiler binaries are verified build inputs, not software being
            # redistributed as corresponding-source material.
            tool_dependencies = verify_npm_program_inputs(source_file, package_result['bindings'], result['tool_inputs'], recorder, assets_root)
            if result['tool_inputs'] != tool_inputs: raise ValueError('coordinator inspection tools changed during replay')
            sources = [{'source_inventory_sha256': result['source_inventory_sha256']}, *[row['source'] for row in dependencies]]
            notices = [notice for row in dependencies for notice in row['notices']]
            if not notices: raise ValueError('coordinator dependency notices are missing')
            # Original compiler inputs are retained for independent replay.
            # Their presence is not a claim that a prebuilt npm tool archive
            # is corresponding source for the shipped coordinator.
            facts.add('reproduced-coordinator-bundle', result['bundle'], sources, notices, digest(program), [row['source'] for row in [*dependencies, *tool_dependencies]])
            result['generator_sha256'] = digest(program); result['status'] = 'passed'
        elif kind == 'locked-source-members':
            if not any(identifier.endswith('-oci-index') or __import__('re').match(r'^(core|render)-linux-', identifier) for identifier in artifact_ids): continue
            if set(item) != {'kind', 'sources'}: raise ValueError('unexpected original source-member recipe fields')
            file = input_file(item['sources']); inventory = json.loads(file.read_bytes()); expected, locks = locked.plan(root, assets_root)
            if inventory.get('schema_version') != 1 or inventory.get('qualification') != 'exact-locked-source-subinventory' or inventory.get('status') != 'passed': raise ValueError('complete original locked source collection required')
            rows = inventory['files']; joined = []
            for value in expected:
                selected_rows = [row for row in rows if all(row.get(key) == value.get(key) for key in ('family', 'name', 'version', 'url', 'sha256'))]
                if len(selected_rows) != 1: raise ValueError('original locked source inventory omitted or changed a required component')
                row = selected_rows[0]
                if source_parts is None:
                    archive = selected(file.parent, row['path']); stream, _, content = shipped.materials.opened(file.parent, row); stream.close()
                    notices = locked.source_notices(archive)
                    if notices != row.get('notice_files'): raise ValueError('original source member notices differ')
                    if notices: source_member_facts(archive, {**content, 'family': row['family'], 'name': row['name'], 'version': row['version']}, notices, facts, wanted, digest(Path(locked.__file__)))
                else:
                    # The locked receipt names the original blob. Inspect it in
                    # its verified source parts rather than staging another file.
                    shipped.materials.safe(row['path'])
                    with source_parts.open_blob(row['sha256'], row['size_bytes']) as stream:
                        notices = locked.source_notices(stream)
                        if notices != row.get('notice_files'): raise ValueError('original source member notices differ')
                        content = {'path': row['path'], 'sha256': row['sha256'], 'size_bytes': row['size_bytes']}
                        if notices: source_member_facts(None, {**content, 'family': row['family'], 'name': row['name'], 'version': row['version']}, notices, facts, wanted, digest(Path(locked.__file__)), stream=stream)
                    if recorder is not None: recorder.source_blob(file.parent / row['path'], row['sha256'], row['size_bytes'])
                joined.append(content)
            result = {'status': 'passed', 'generator_sha256': digest(Path(locked.__file__)), 'sources': joined, 'locks': locks}
        elif kind in ('packaged-data', 'native-render'):
            if set(item) != {'kind'} or discovery is None: raise ValueError('fixed packaged-data replay requires actual discovered subjects')
            binder = packaged_data if kind == 'packaged-data' else render_components
            result = binder.derive(root, assets_root, assets_root if runtime_root is None else runtime_root, discovery, wanted, recorder)
            for binding in result['bindings']:
                facts.add(kind, binding['content'], binding['sources'], binding['notices'], result['generator_sha256'], binding['required_materials'])
                if kind == 'packaged-data': packaged_keys.add((binding['content']['sha256'], binding['content']['size_bytes']))
        elif kind == 'authored-worker-metadata':
            if set(item) != {'kind', 'contexts'} or discovery is None: raise ValueError('authored worker metadata requires its actual discovered image/context inputs')
            result = worker_metadata.derive(root, assets_root, assets_root if runtime_root is None else runtime_root, discovery, wanted, recorder, contexts=item['contexts'], font_sources=font_sources)
            for binding in result['bindings']:
                forms = {row.get('form') for row in binding['sources']}
                if 'exact-standalone-font-zero-derived-from-authenticated-original-collection' in forms:
                    family = 'generated-render-font'
                elif forms & {'exact-authored-readable-build-metadata', 'exact-authored-readable-render-inventory'}:
                    family = 'colocated-readable-configuration-source'
                else: raise ValueError('authored worker binding has an unknown source form')
                facts.add(family, binding['content'], binding['sources'], binding['notices'], result['generator_sha256'], binding['required_materials'])
        elif kind == 'python-wheels':
            if not {'kind', 'sources'} <= set(item) or set(item) - {'kind', 'sources', 'wheel_roots'} or not isinstance(item.get('wheel_roots', []), list) or len(item.get('wheel_roots', [])) > 16: raise ValueError('unexpected Python wheel source recipe fields')
            result = wheel_facts(root, assets_root, input_file(item['sources']), facts, wanted, [selected(assets_root, name, True) for name in item.get('wheel_roots', [])])
            for binding in result['bindings']:
                key = (binding['package']['name'].lower().replace('_', '-').replace('.', '-'), binding['package']['version'])
                wheel_packages.setdefault(key, []).append(binding)
        elif kind == 'runtime-source-members':
            if not any(identifier.endswith('-oci-index') or __import__('re').match(r'^(core|render)-linux-', identifier) for identifier in artifact_ids): continue
            if set(item) != {'kind', 'sources'}: raise ValueError('unexpected original runtime source-member recipe fields')
            source_file = input_file(item['sources']); result = managed.derive(root, source_file, source_parts=source_parts, recorder=recorder)
            result['opaque_provider_packages_not_source_forms'] = []
            for source in result['sources']:
                with managed.opened_original(source_file.parent, source, source_parts, recorder) as (stream, _, _):
                    if source.get('url', '').endswith('.deb'):
                        if stream.read(8) != b'!<arch>\n': raise ValueError('runtime provider Debian package has another format')
                        result['opaque_provider_packages_not_source_forms'].append({'sha256': source['sha256'], 'size_bytes': source['size_bytes'], 'reason': 'Original binary provider package is not asserted to be corresponding source.'})
                        continue
                    notices = original_runtime_notices(None, source, stream=stream)
                    if not notices: continue
                    stream.seek(0)
                    function = zip_source_member_facts if zipfile.is_zipfile(stream) else source_member_facts
                    function(None, source, notices, facts, wanted, result['generator_sha256'], stream=stream)
        elif kind == 'rust':
            if not {'kind', 'rust_sources', 'package_sources', 'provider_sources'} <= set(item) or set(item) - {'kind', 'rust_sources', 'package_sources', 'provider_sources', 'native_inputs', 'stl_binding'}: raise ValueError('unexpected Rust source recipe fields')
            declarations = proprietary_declarations(root)
            result = rust.derive(root, input_file(item['rust_sources']), input_file(item['package_sources']), input_file(item['provider_sources']), assets_root, input_file(item['native_inputs']) if 'native_inputs' in item else None, wanted, platforms, recorder, owned_uv_declarations=declarations, source_parts=source_parts)
            record_package_notices(recorder, input_file(item['package_sources']), result['cargo_bindings'])
            selected_stl = [value for value in declarations.values() if value.get('other_static_components') and any((row['binary']['sha256'], row['binary']['size_bytes']) in wanted and row['binary']['sha256'] == value['binary_sha256'] for row in result['bindings'])]
            if selected_stl:
                if 'stl_binding' not in item: raise ValueError('shipped owned-UV STL correspondence binding is missing')
                joined_stl = stl_bindings.derive(root, assets_root, {'path': item['stl_binding'], **record(selected(root, item['stl_binding']))}, list(declarations.values()), replay_objects=False)
                result['independently_reviewed_STL_correspondence'] = joined_stl
            for binding in result['bindings']:
                source = binding['binary']['rust_source']
                notices = [{'source_archive_sha256': source['sha256'], 'scope': 'original Rust runtime and locked crate notices verified by the fixed binder'}]
                source_rows = [source]
                open_windows = binding['binary'].get('open_windows_linkage')
                open_sources = []
                if open_windows:
                    source_rows.append(open_windows)
                    open_sources = open_windows['sources']
                    notices.extend(open_windows['notices'])
                duty = duties.get(binding['binary']['sha256'])
                if binding['binary']['proprietary_static_runtime_declaration_required']:
                    declaration = declarations.get(binding['binary']['sha256'])
                    if not declaration: continue
                    if declaration.get('other_static_components') and not (duty and duty['complete_component_source_duties']): continue
                    source_rows.append({'component_id': declaration['id'], 'definition_sha256': declaration['definition_sha256'], 'source_availability': 'proprietary-source-unavailable', 'publisher_redistribution_authority': 'unverified-external'})
                    notices.extend(declaration['terms'])
                source_rows.extend(binding['binary']['rust_std_dependencies'])
                if duty:
                    source_rows.append({'qualification': 'independently-reviewed-component-source-duties-not-publisher-authority', 'groups': duty['groups']}); notices.extend(duty['notices'])
                facts.add('rust-binary', binding['binary'], source_rows, notices, result['generator_sha256'], [source, *binding['binary']['rust_std_dependencies'], *binding['binary']['rust_verification_materials'], *result['cargo_sources'][binding['kind']], *([binding['uv_source']] if 'uv_source' in binding else []), *(duty['required_materials'] if duty else []), *open_sources])
        elif kind == 'managed-python':
            if set(item) != {'kind', 'sources', 'binary_archives'}: raise ValueError('unexpected managed Python source recipe fields')
            result = managed.derive(root, input_file(item['sources']), [(value['platform'], input_file(value['archive'])) for value in item['binary_archives']], source_parts=source_parts, recorder=recorder)
            external.extend({'kind': 'vendor-direct-not-redistributed', **value} for value in result['binary_inputs'])
        elif kind == 'provider-runtime':
            if set(item) != {'kind'}: raise ValueError('unexpected provider source recipe fields')
            if not provider_artifacts: continue
            result = provider_components.derive(root, assets_root, assets_root if runtime_root is None else runtime_root, provider_artifacts, recorder=recorder, source_parts=source_parts)
            for binding in result['bindings']:
                facts.add('actual-provider-component', binding['content'], binding['sources'], binding['notices'], result['generator_sha256'], binding['required_materials'])
        elif kind == 'pip-runtime':
            if set(item) != {'kind', 'original_sources', 'wheel_base'}: raise ValueError('unexpected pip/distlib source recipe fields')
            if not any(identifier.endswith('-oci-index') or __import__('re').match(r'^(core|render)-linux-', identifier) for identifier in artifact_ids): continue
            if discovery is not None and not any(
                oci_python.installer_member(member['path'].split('/', 3)[-1], '3.15.2')
                for subject in discovery['subjects'] if subject['id'].endswith('-oci-index') or __import__('re').match(r'^(core|render)-linux-', subject['id'])
                for member in subject['members']
            ):
                continue
            result = original_pip()
            launcher_hashes = {row['sha256'] for row in result['foreign_launchers']}
            for content in [*result['members'], result['wheel']]:
                is_foreign = content['sha256'] in launcher_hashes or content['sha256'] == result['wheel']['sha256']
                duty = duties.get(content['sha256']) if is_foreign else None
                if is_foreign and not (duty and duty['complete_component_source_duties']): continue
                origins = [*result['sources'], {'component': 'pip26.2.2-vendored-distlib0.4.2', 'foreign_launcher_source_identity': result['foreign_launchers'], 'static_runtime_condition': result['static_runtime_condition']}]
                if duty: origins.append({'qualification': 'independently-reviewed-component-source-duties-not-publisher-authority', 'groups': duty['groups']})
                facts.add('exact-original-pip-distlib-component', content, origins, result['notices'] + (duty['notices'] if duty else []), result['generator_sha256'], result['sources'])
        elif kind == 'oci-python-provider':
            if set(item) != {'kind', 'pack', 'platform', 'sources', 'provenance'} or item['pack'] not in ('core', 'render') or item['platform'] not in ('linux/arm64', 'linux/amd64'): raise ValueError('unexpected OCI CPython provider recipe fields')
            if item['pack'] + '-oci-index' not in artifact_ids: continue
            runtime_input = assets_root if runtime_root is None else runtime_root
            runtime = json.loads((runtime_input / 'runtime/runtime.lock.json').read_bytes())
            pack = runtime['packs'][item['pack']]
            if pack.get('images') and item['platform'] not in pack['images']: continue
            result = oci_python.derive(root, runtime_input, pack, item['platform'], input_file(item['sources']), input_file(item['provenance']), source_parts=source_parts, recorder=recorder)
            flattened = result.get('flattened_provider')
            sources = [result['source'], {'provider': result['provider'], 'component_build_recipe': result['component'], 'config_digest': result['config_digest'], **({'flattened_provider': flattened} if flattened else {})}]
            for binding in result['bindings']: facts.add('publisher-CPython-build-layer-component', binding['content'], sources, result['notices'], result['generator_sha256'], [result['source'], *result['metadata_materials']])
            for form in result.get('provider_source_forms', []):
                original = {'image_path': form['image_path'], **form['content'], 'scope': 'Original readable source/comments preserved; no SPDX, authorship or license assignment inferred.'}
                facts.add('colocated-readable-configuration-source', form['content'], [{'provider': result['provider'], 'config_digest': result['config_digest'], 'original_source_form': form}], [original], result['generator_sha256'], result['metadata_materials'])
            if result.get('installed_source_forms'):
                if flattened:
                    notice = root / 'licenses/vendor/pip-26.2.2/LICENSE.txt'
                    pip = {'sources': [], 'notices': [{'path': notice.relative_to(root).as_posix(), 'sha256': digest(notice), 'size_bytes': notice.stat().st_size}]}
                else:
                    pip = original_pip()
                pip_version = next(row['version'] for row in json.loads((root / 'runtime/materials/pip-distlib-sources.lock.json').read_bytes())['components'] if row['name'] == 'pip')
                for form in result['installed_source_forms']:
                    package = form['package']; key = (package['name'].lower().replace('_', '-').replace('.', '-'), package['version'])
                    originals = wheel_packages.get(key, [])
                    if (flattened or key != ('pip', pip_version)) and not originals: raise ValueError('installed source form has no exact original package notices')
                    notices = [*pip['notices'], *[notice for row in originals for notice in row['original_wheel_notices'] + row['original_source_notices']]]
                    facts.add('colocated-readable-configuration-source', form['content'], [{'provider': result['provider'], 'installed_source_form': form, 'original_pip_generator': result['installed_script_generator']}, *pip['sources'], *[row['source'] for row in originals]], notices, result['generator_sha256'], [*pip['sources'], *[row['source'] for row in originals]])
        elif kind == 'oci-os-packages':
            if not {'kind', 'pack', 'platform', 'inventory', 'sources', 'keyring'} <= set(item) or set(item) - {'kind', 'runtime_root', 'pack', 'platform', 'inventory', 'sources', 'keyring'} or item['pack'] not in ('core', 'render') or item['platform'] not in ('linux/arm64', 'linux/amd64'): raise ValueError('unexpected OCI package source recipe fields')
            if item['pack'] + '-oci-index' not in artifact_ids: continue
            runtime_input = selected(assets_root, item['runtime_root'], True) if 'runtime_root' in item else assets_root if runtime_root is None else runtime_root
            runtime = json.loads((runtime_input / 'runtime/runtime.lock.json').read_bytes()); source_file = input_file(item['sources']); gpgv = shutil.which('gpgv')
            if not gpgv: raise ValueError('the original source signature verifier is unavailable')
            result = oci_packages.derive(runtime_input, runtime['packs'][item['pack']], item['platform'], input_file(item['inventory']), source_file, keyring=input_file(item['keyring']), gpgv=Path(gpgv).resolve(), single=True, source_parts=source_parts, recorder=recorder)
            components = {tuple(row['binary_component'][field] for field in ('name', 'version', 'architecture')): row for row in result['components']}
            for binding in result['bindings']:
                origins = [components[tuple(row[field] for field in ('name', 'version', 'architecture'))] for row in binding['components']]
                sources = [source for row in origins for source in row['sources']]; notices = []
                for row in origins:
                    stream, _, notice = shipped.materials.opened(input_file(item['inventory']).parent, row['notice']); stream.close(); notices.append(notice)
                source_materials = [content for row in sources for content in row['files']]
                if not source_materials or not notices: raise ValueError('actual OCI package files lack original sources or notices')
                facts.add('publisher-oci-package-file', binding['content'], sources, notices, result['generator_sha256'], source_materials + notices)
                name = binding['content'].get('image_path', '')
                if name.startswith('usr/share/fonts/') and name.rsplit('/', 1)[-1] == 'NotoSansCJK-Regular.ttc':
                    font_sources.append({'content': binding['content'], 'sources': sources, 'notices': notices, 'required_materials': source_materials + notices})
        else:
            raise ValueError('unsupported component source replayer: ' + str(kind))
        if family_stage is not None: family_stage.close()
        details = result.get('independently_reviewed_STL_correspondence')
        reports.append({'kind': kind, 'input_recipe': item, 'replayed_result_sha256': hashlib.sha256(canonical(content_identity(result))).hexdigest(), 'generator_sha256': result['generator_sha256'], 'status': result['status'], **({'pending_declarations': result['pending_declarations']} if kind == 'python-wheels' else {}), **({'reviewed_STL_components': [{'id': row['component_id'], 'binary_sha256': row['binary_sha256'], 'source_correspondence': row['effective_open_source_correspondence'], 'pending_header_obligations': len(row['pending_declarations'])} for row in details['bindings']], 'pending_declarations': details['pending_declarations']} if details else {})})
    for report in reports:
        if report['kind'] != 'python-wheels': continue
        pending = report['pending_declarations']
        report['handled_by_exact_packaged_data'] = [row for row in pending if (row['sha256'], row['size_bytes']) in packaged_keys]
        report['pending_declarations'] = [row for row in pending if (row['sha256'], row['size_bytes']) not in packaged_keys]
        report['status'] = 'incomplete' if report['pending_declarations'] else 'passed'
    return reports, external


def reconcile(discovery, facts, source):
    """Derive coverage over the actual complete archive-member universe."""
    subjects = []; unresolved = []; used_facts = set(); metadata_roles = {'metadata', 'component-declarations'}
    for subject in discovery['subjects']:
        bindings = []
        for member in subject['members']:
            if subject['role'] in metadata_roles: continue
            key = (member['sha256'], member['size_bytes']); matches = sorted(facts.by_content.get(key, ()))
            if not matches: unresolved.append({'artifact': subject['id'], 'path': member['path'], 'platform': member.get('platform'), 'sha256': member['sha256'], 'size_bytes': member['size_bytes'], 'architecture': member['architecture'], 'code': 'SHIPPED_MEMBER_SOURCE_RECIPE_UNRESOLVED'})
            else:
                # All matching declared origins remain visible. Their material
                # requirements are a union, never an arbitrary selected origin.
                used_facts.update(matches); bindings.append({'path': member['path'], 'platform': member.get('platform'), 'sha256': member['sha256'], 'size_bytes': member['size_bytes'], 'facts': matches})
        subjects.append({'id': subject['id'], 'artifact_sha256': subject['sha256'], 'member_inventory_sha256': hashlib.sha256(canonical(subject['members'])).hexdigest(), 'members': len(subject['members']), 'bindings': bindings})
    missing = [value for value in discovery['blockers'] if value['code'] in ('REQUIRED_DISTRIBUTION_MISSING', 'UNCLASSIFIED_DISTRIBUTION_FORMAT')]
    available = bool(subjects) and not unresolved and not any(value['code'] == 'UNCLASSIFIED_DISTRIBUTION_FORMAT' for value in missing)
    required = set()
    for subject in subjects:
        for binding in subject['bindings']:
            origins = [facts.rows[key] for key in binding['facts']]
            provided_source_form = any(row['family'] in ('exact-retained-source-file', 'colocated-readable-configuration-source') for row in origins)
            if not provided_source_form: required.update(value for row in origins for value in row['required_material_sha256'])
    return {'subjects': subjects, 'unresolved_shipped_members': unresolved, 'missing_distribution_subjects': missing, 'complete_available_shipped_component_coverage': available, 'complete_product_coverage': available and not missing, 'required_materials': [facts.materials[key] for key in sorted(required)], 'source_inventory_sha256': source['sha256']}


def _derive(root, candidate, recipe, *, diagnostic=False, assets_root=None, runtime_root=None, candidate_root=None, available_targets=False, recorder=None, source_parts=None, family_report=None):
    before = source_inventory(root); generator = digest(Path(__file__))
    if candidate['source_tree_sha256'] != before['sha256']: raise ValueError('component source replay requires the retained exact candidate source snapshot')
    facts = Facts(); license_file = root / 'LICENSE'
    if not license_file.is_file(): raise ValueError('authored source license is missing')
    license_record = {'path': 'LICENSE', **record(license_file)}
    root_notices = [{'path': row['path'], 'sha256': row['sha256'], 'size_bytes': row['size']} for row in before['files'] if row['path'] in ('LICENSE', 'NOTICE') or row['path'].startswith('licenses/')]
    for row in before['files']:
        with selected(root, row['path']).open('rb') as stream: prefix = stream.read(65536)
        # A compiled binary being present in a source checkout is not a source
        # relationship. It must be admitted by its fixed binary-family binder.
        if not preferred_source_file(row, prefix): continue
        notices = [{key: row[key] for key in ('path', 'sha256', 'size')}] if row['path'].startswith('licenses/') else root_notices
        facts.add('exact-retained-source-file', row, [{'path': row['path'], 'sha256': row['sha256'], 'size_bytes': row['size']}], notices, generator)
    assets_root = root if assets_root is None else assets_root
    # Post-build attestations/checksums cannot be inside their own subject hash.
    # Their signatures and exact-byte bindings have separate production gates.
    projection = {**candidate, 'artifacts': [row for row in candidate['artifacts'] if row['id'] not in ('component-source-coverage', 'publisher-authority', 'checksum-manifest')]}
    candidate_root = assets_root if candidate_root is None else candidate_root
    discovery = shipped.collect(candidate_root, projection, diagnostic=diagnostic, runtime_root=runtime_root, available_targets=available_targets)
    for artifact in projection['artifacts']:
        recorder.separately_verified(candidate_root / artifact['path'], artifact['sha256'], artifact['size'])
    if runtime_root is not None and runtime_root != assets_root:
        # Runtime aliases are matched to exact protected source or descriptor
        # bytes. An unlisted file under the same directory gains no exemption.
        for row in before['files']:
            recorder.separately_verified(runtime_root / row['path'], row['sha256'], row['size'])
        def runtime_descriptors(value):
            if isinstance(value, list):
                for item in value: runtime_descriptors(item)
            elif isinstance(value, dict):
                if isinstance(value.get('path'), str) and isinstance(value.get('sha256'), str) and type(value.get('size_bytes', value.get('size'))) is int:
                    recorder.separately_verified(runtime_root / shipped.inspector._paths.validate_path(value['path']), value['sha256'], value.get('size_bytes', value.get('size')))
                for item in value.values(): runtime_descriptors(item)
        runtime_descriptors(json.loads((runtime_root / 'runtime/runtime.lock.json').read_bytes()))
    for subject in discovery['subjects']:
        if subject['role'] in ('metadata', 'component-declarations'):
            continue
        for member in subject['members']:
            if member['path'] in subject['colocated_preferred_sources']:
                facts.add('colocated-readable-configuration-source', member, [{'form': 'preferred-source-form-shipped-as-readable-data', 'artifact': subject['id'], 'artifact_sha256': subject['sha256'], 'member_path': member['path'], 'sha256': member['sha256'], 'size_bytes': member['size_bytes']}], root_notices, generator)
    wanted = {(member['sha256'], member['size_bytes']) for subject in discovery['subjects'] if subject['role'] != 'component-declarations' for member in subject['members']}
    platforms = set(); node_platforms = set()
    for subject in discovery['subjects']:
        match = __import__('re').fullmatch(r'(?:native|mcpb)-(macos|linux|windows)-(arm64|amd64)', subject['id'])
        if match:
            host = {'macos': 'darwin', 'linux': 'linux', 'windows': 'win32'}[match[1]] + '/' + ('x64' if match[2] == 'amd64' else 'arm64'); platforms.add(host)
            if any(row['path'] in ('runtime/node/bin/node', 'runtime/node/bin/node.exe') for row in subject['members']): node_platforms.add(host)
        for member in subject['members']:
            if member.get('platform') in ('linux/arm64', 'linux/amd64'): platforms.add(member['platform'].replace('amd64', 'x64'))
        for prefix in ('userspace-core-', 'render-assets-'):
            if subject['id'].startswith(prefix): platforms.add(subject['id'].removeprefix(prefix).replace('-', '/'))
        if subject['id'] == 'npm':
            published = json.loads((root / 'packages/npm-distribution/platforms.json').read_bytes())
            platforms.update(host.replace('-', '/') for host in published)
    providers = [{**row, 'file': str(candidate_root / row['path'])} for row in projection['artifacts'] if row['id'].startswith('provider-assets-')]
    with ExitStack() as cleanup:
        start_perl_family = None
        if family_report is not None:
            if source_parts is None: raise ValueError('family source replay requires verified source parts')
            materializer = module('ud_closure_family_inputs', 'materialize-replay-inputs.py')
            catalog = family_report.get('inspection_inputs', {}); rows = catalog.get('inputs')
            subjects = projection['artifacts']
            if catalog.get('schema_version') != 1 or catalog.get('qualification') != inspection.QUALIFICATION or catalog.get('source_inventory_sha256') != before['sha256'] or not isinstance(rows, list) or len(rows) > inspection.MAX_FILES or catalog.get('inventory_sha256') != hashlib.sha256(inspection.canonical(rows)).hexdigest() or catalog.get('subjects') != [{'id': row['id'], 'sha256': row['sha256']} for row in subjects] or catalog.get('unretained_inputs') != []: raise ValueError('family inspection inputs differ from candidate')
            groups = materializer.deferred_perl_families(root, subjects, catalog)
            def start_perl_family(item):
                pack = item['pack']; family = groups.get(pack)
                if family is None: return None
                lifetime = ExitStack(); cleanup.enter_context(lifetime)
                input_pack = item.get('runtime_only', {}).get('input_pack')
                lifetime.enter_context(materializer.staged_perl_family(root, candidate, candidate_root, assets_root, pack, family, source_parts, family_report['required_materials'], recorder, input_pack=input_pack))
                return lifetime
        reports, external = replay(root, recipe, facts, assets_root, wanted, {row['id'] for row in discovery['subjects']}, platforms, node_platforms, recorder, runtime_root, providers, discovery, source_parts, start_perl_family)
    retention = retained_inputs.retain_inspected_originals(root, assets_root, recipe, frozenset(recorder.paths), recorder)
    retained_materials = facts.require_materials(retention['required_materials'])
    result = reconcile(discovery, facts, before)
    required = {row['sha256'] for row in result['required_materials']} | retained_materials
    result['required_materials'] = [facts.materials[key] for key in sorted(required)]
    if source_inventory(root)['sha256'] != before['sha256'] or digest(Path(__file__)) != generator: raise ValueError('source closure changed during replay')
    inputs = recorder.finish(before, discovery, result['required_materials'], projection['artifacts'])
    inspection.verify(inputs, assets_root, before['sha256'], inputs['subjects'], require_retained=False, required_materials=result['required_materials'], discovered_subjects=discovery['subjects'], streamed_sources=recorder.streamed_sources, observations=recorder.observations)
    return {'schema_version': 1, 'qualification': 'replayed-actual-shipped-component-source-license-closure', 'status': 'passed' if result['complete_product_coverage'] else 'available-passed-product-incomplete' if result['complete_available_shipped_component_coverage'] else 'incomplete', **result, 'inspection_inputs': inputs, 'inspection_original_retention': retention, 'runtime_lock_sha256': candidate['runtime_lock_sha256'], 'replayed_families': reports, 'source_facts': [{'id': key, **value} for key, value in sorted(facts.rows.items())], 'source_relationships': [{'sha256': key, 'members': value} for key, value in sorted(facts.relationships.items())], 'external_vendor_inputs_not_redistributed': external, 'generator_sha256': generator, 'publisher_redistribution_authority': 'separate-production-gate-never-inferred-from-source-coverage'}


def derive(root, candidate, recipe, *, diagnostic=False, assets_root=None, runtime_root=None, candidate_root=None, available_targets=False, source_parts=None, family_report=None):
    selected_assets = root if assets_root is None else assets_root
    with inspection.Recorder(root, selected_assets) as recorder:
        return _derive(root, candidate, recipe, diagnostic=diagnostic, assets_root=selected_assets, runtime_root=runtime_root, candidate_root=candidate_root, available_targets=available_targets, recorder=recorder, source_parts=source_parts, family_report=family_report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, required=True); parser.add_argument('--assets-root', type=Path); parser.add_argument('--runtime-root', type=Path); parser.add_argument('--candidate-root', type=Path); parser.add_argument('--candidate', type=Path, required=True); parser.add_argument('--recipe', type=Path, required=True); group = parser.add_mutually_exclusive_group(required=True); group.add_argument('--output', type=Path); group.add_argument('--verify-report', type=Path); parser.add_argument('--diagnostic', action='store_true'); parser.add_argument('--available-targets', action='store_true'); parser.add_argument('--stream-source', action='store_true'); args = parser.parse_args()
    if args.output and args.output.exists(): raise ValueError('new component source closure output required')
    root = args.root.resolve(); candidate = json.loads(args.candidate.read_bytes()); candidate_root = args.candidate_root.resolve() if args.candidate_root else root
    parts = module('ud_closure_streamed_sources', 'materialize-replay-inputs.py').SourceParts(root, candidate, candidate_root=candidate_root) if args.stream_source else nullcontext(None)
    reported = None
    if args.verify_report:
        if args.verify_report.is_symlink() or args.verify_report.stat().st_size > REPORT_LIMIT: raise ValueError('component source report is linked or oversized')
        reported = expanded_report(json.loads(args.verify_report.read_bytes()))
    with parts as source_parts:
        value = derive(root, candidate, json.loads(args.recipe.read_bytes()), diagnostic=args.diagnostic, assets_root=args.assets_root.resolve() if args.assets_root else None, runtime_root=args.runtime_root.resolve() if args.runtime_root else None, candidate_root=candidate_root, available_targets=args.available_targets, source_parts=source_parts, family_report=reported if args.stream_source else None)
    if args.verify_report:
        if value['inspection_inputs']['unretained_inputs']: raise ValueError('component source replay still requires unretained inspection inputs: ' + ', '.join(value['inspection_inputs']['unretained_inputs'][:8]))
        if canonical(reported) != canonical(value): raise ValueError('actual component source closure does not replay exactly')
    else: args.output.write_bytes(report_bytes(value))
    print(json.dumps({key: value[key] for key in ('status', 'complete_available_shipped_component_coverage', 'complete_product_coverage')}))
