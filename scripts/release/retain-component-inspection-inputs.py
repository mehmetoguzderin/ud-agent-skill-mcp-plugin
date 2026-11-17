"""Retain exact originals already read by the fixed component replayer.

This issues no component/source/license facts. It joins observed inputs only to
the existing selected source subinventories, exact locked bootstrap archives,
or original supplier members needed to replay the Windows runtime-only filter.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/release' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


materials = module('ud_inspection_original_materials', 'source-bundle.py')
inspection = module('ud_inspection_original_files', 'replay-inspection-inputs.py')


def identity(stream):
    row = os.fstat(stream.fileno())
    return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns


def document(root, name, recorder=None):
    try: stream, row = inspection.opened(root, {'path': name})
    except FileNotFoundError:
        if recorder is None or Path(root).resolve() != recorder.assets_root: raise
        body = recorder.observed_bytes(Path(root) / name)
        if len(body) > 32 * 1024**2: raise ValueError('inspection original inventory exceeds bound')
        return json.loads(body)
    try:
        if row['size_bytes'] > 32 * 1024**2: raise ValueError('inspection original inventory exceeds bound')
        before = identity(stream); result = json.load(stream)
        if identity(stream) != before: raise ValueError('inspection original inventory changed during parsing')
    finally: stream.close()
    if recorder is not None: recorder.note(root / name)
    return result


def collection_paths(recipe):
    """Only the existing fixed family's declared source/inventory slots."""
    result = set()
    for row in recipe['families']:
        kind = row['kind']
        fields = {
            'node': ('sources', 'rust_sources'), 'rust': ('rust_sources', 'package_sources', 'provider_sources'),
            'packages': ('sources',), 'coordinator-bundle': ('package_sources',),
            'locked-source-members': ('sources',), 'python-wheels': ('sources',),
            'runtime-source-members': ('sources',), 'oci-python-provider': ('sources', 'provenance'),
            'oci-os-packages': ('sources', 'inventory'),
        }.get(kind, ())
        for field in fields:
            if field in row: result.add(materials.safe(row[field]))
        if kind == 'private-perl':
            result.update(materials.safe(name) for name in row['sources'])
            if 'elf' in row:
                result.update(materials.safe(row['elf'][key]) for key in ('inventory', 'sources'))
    return sorted(result)


def retain_inspected_originals(source_root, assets_root, recipe, observed_paths, recorder=None):
    source_root = Path(source_root); assets_root = Path(assets_root)
    if len(observed_paths) > inspection.MAX_FILES: raise ValueError('inspection original path count exceeds bound')
    private_vendor = getattr(recorder, 'private_vendor_inputs', {}) if recorder is not None else {}
    observed = frozenset(materials.safe(name) for name in observed_paths if name not in private_vendor)
    required = {}; joins = []; source_candidates = {}

    def retain(row, form, inventory=None):
        staged = assets_root / row['path']; observed = getattr(recorder, 'streamed_sources', {}).get(row['path']) if recorder is not None else None
        if observed is not None and not staged.exists() and not staged.is_symlink():
            if observed['sha256'] != row['sha256'] or observed['size_bytes'] != row.get('size_bytes', row.get('size')): raise ValueError('streamed inspection original differs from its collection')
            actual = {key: observed[key] for key in ('path', 'sha256', 'size_bytes')}
        elif recorder is not None and not staged.exists() and not staged.is_symlink():
            observed = recorder.observed_receipt(staged, row)
            actual = {key: observed[key] for key in ('path', 'sha256', 'size_bytes')}
        else:
            stream, _, actual = materials.opened(assets_root, row); stream.close()
        key = actual['sha256']
        if key in required and required[key]['size_bytes'] != actual['size_bytes']: raise ValueError('inspection original digest has conflicting sizes')
        required.setdefault(key, actual)
        joins.append({'input': actual, 'form': form, **({'inventory': inventory} if inventory else {})})
        return actual

    for name in collection_paths(recipe):
        base = Path(name).parent.as_posix()
        if not any(path.startswith(base + '/') for path in observed): continue
        value = document(assets_root, name, recorder)
        for row in materials.selected(value):
            candidate = {**row, 'path': base + '/' + materials.safe(row['path'])}
            source_candidates.setdefault(row['sha256'], []).append(candidate)
            if candidate['path'] in observed: retain(candidate, 'existing-selected-original-subinventory-input', name)

    # Rule acquisition and source inspection keep exact aliases of the same
    # original UD archives. Match the locked repository/commit and source row;
    # arbitrary same-looking cache paths are never eligible.
    ud_paths = {name for name in observed if name.startswith('.artifacts/sources/')}
    if ud_paths:
        lock = document(source_root, 'runtime/ud-sources.lock.json')
        for row in lock['sources']:
            name = '.artifacts/sources/' + row['repository'].rsplit('/', 1)[-1] + '-' + row['commit'] + '.tar.gz'
            if name not in ud_paths: continue
            choices = source_candidates.get(row['archive_sha256'], [])
            if not choices: raise ValueError('observed UD archive has no existing selected original source')
            sizes = {value.get('size_bytes', value.get('size')) for value in choices}
            if len(sizes) != 1: raise ValueError('observed UD archive source sizes conflict')
            retain({'path': name, 'sha256': row['archive_sha256'], 'size_bytes': sizes.pop()}, 'exact-locked-UD-original-archive-alias')

    # Existing bootstrap receipts inspect foreign platforms as data. Their
    # original containers are replay inputs, never corresponding-source or
    # native-execution claims. Only actual observed locked archives are added.
    if any(name.startswith('.artifacts/userspace-inputs/cache/') for name in observed):
        uv_lock = document(source_root, 'runtime/userspace-inputs.lock.json')
        for row in uv_lock['platforms'].values():
            archive = row['uv_archive']; fingerprint = archive['sha256'].removeprefix('sha256:')
            name = '.artifacts/userspace-inputs/cache/' + fingerprint
            if name in observed: retain({'path': name, 'sha256': fingerprint, 'size_bytes': archive['size']}, 'exact-locked-bootstrap-original-inspection-archive')

    ubuntu_keyring = '.artifacts/lima-product/ubuntu/ubuntu-archive-keyring.gpg'
    if ubuntu_keyring in observed:
        authentication = document(source_root, 'runtime/lima-guest.lock.json')['package_authentication']
        fingerprint = authentication['keyring_sha256'].removeprefix('sha256:')
        retain({'path': ubuntu_keyring, 'sha256': fingerprint}, 'exact-locked-ubuntu-archive-keyring')

    for family in recipe['families']:
        if family.get('kind') != 'private-perl' or family.get('platform') != 'win32/arm64' or 'runtime_only' not in family: continue
        selection = family['runtime_only']; prefix = materials.safe(selection['input_pack']) + '/'
        names = [name for name in observed if name.startswith(prefix) and (name.endswith('.pdb') or name == prefix + 'lib/CORE/perl544.lib')]
        if not names: continue
        raw = document(assets_root, materials.safe(selection['input_receipt']), recorder)
        if raw.get('platform') != 'win32/arm64': raise ValueError('inspection original Perl input platform differs')
        rows = {row['path']: row for row in raw['files']}
        if len(rows) != len(raw['files']): raise ValueError('inspection original Perl input inventory duplicates')
        lock = document(source_root, 'runtime/windows-perl-distributions.lock.json')
        supplier = lock['platforms']['arm64']['perl']; fingerprint = supplier['sha256'].removeprefix('sha256:')
        archive = {'path': '.artifacts/native-perl/cache/windows/' + materials.safe(supplier['filename']), 'sha256': fingerprint, 'size_bytes': supplier['size_bytes']}
        actual_archive = retain(archive, 'exact-locked-original-Perl-supplier-inspection-container')
        if recorder is not None: recorder.note(assets_root / archive['path'])
        wanted = {}
        for name in names:
            relative = name[len(prefix):]; row = rows.get(relative)
            if row is None: raise ValueError('observed Perl inspection member has no original input receipt')
            expected = {'path': name, 'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row['size']}
            staged = assets_root / name
            if recorder is not None and not staged.exists() and not staged.is_symlink():
                captured = recorder.observed_receipt(staged, expected)
                actual = {key: captured[key] for key in ('path', 'sha256', 'size_bytes')}
            else:
                stream, _, actual = materials.opened(assets_root, expected); stream.close()
            wanted['Library/' + relative] = actual
        stream, before, _ = materials.opened(assets_root, archive); found = set()
        try:
            with tarfile.open(fileobj=stream, mode='r:*') as bundle:
                for member in bundle:
                    if member.name not in wanted: continue
                    target = wanted[member.name]
                    if member.name in found or not member.isfile() or not 0 <= member.size <= 32 * 1024**2: raise ValueError('original Perl inspection member is duplicate, special or oversized')
                    with bundle.extractfile(member) as body: actual_hash = hashlib.file_digest(body, 'sha256').hexdigest()
                    if actual_hash != target['sha256'] or member.size != target['size_bytes']: raise ValueError('observed Perl inspection member differs from exact original supplier bytes')
                    if recorder is not None: recorder.source_member(assets_root / target['path'], fingerprint, member.name)
                    joins.append({'input': target, 'form': 'exact-original-supplier-inspection-member', 'archive': actual_archive, 'member': member.name})
                    found.add(member.name)
            if identity(stream) != before: raise ValueError('original Perl archive changed during member inspection')
        finally: stream.close()
        if found != set(wanted): raise ValueError('original Perl supplier omits an observed inspection member')

    return {'schema_version': 1, 'status': 'passed', 'qualification': 'exact-observed-original-inspection-input-retention-not-component-or-license-authority', 'required_materials': [required[key] for key in sorted(required)], 'joins': joins, 'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'limitations': 'No source facts, publisher rights, binary reproduction or native execution are inferred. Unsupported observed inputs remain subject to the existing unretained-input rejection.'}
