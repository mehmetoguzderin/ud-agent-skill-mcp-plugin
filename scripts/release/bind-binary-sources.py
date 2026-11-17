#!/usr/bin/env python3
"""Derive binary/package/source/notice bindings from authenticated inventories."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlsplit


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file)); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
materials = module('ud_component_materials', 'source_materials.py')
bundle = module('ud_component_bundle', 'source-bundle.py')
debian = module('ud_component_debian', 'collect-debian-sources.py')
ROOT = Path(__file__).resolve().parents[2]


def identity(row): return row['name'], row['version']
def receipt(file): return {'path': str(file.resolve()), 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'size_bytes': file.stat().st_size}


def authenticated_sources(source_file, sources, keyring, gpgv):
    if keyring is None or gpgv is None or receipt(keyring)['sha256'] != sources.get('keyring_sha256') or receipt(gpgv)['sha256'] != sources.get('gpgv_sha256'):
        raise ValueError('original source authentication tools or publisher keyring differ')
    # Original Ubuntu source collections predate the explicit publisher field.
    # Their pinned Ubuntu signing identity still has to verify independently.
    publisher = sources.get('publisher', 'ubuntu')
    if publisher not in ('ubuntu', 'debian'): raise ValueError('unsupported source publisher')
    if publisher == 'ubuntu':
        pinned = json.loads((ROOT / 'runtime/lima-guest.lock.json').read_bytes())['package_authentication']['signer_fingerprint']
        if sources.get('signer') != pinned: raise ValueError('publisher source signing identity differs')
    metadata = sources['metadata']; signed_catalog = {}; used = set()
    for release in (row for row in metadata if row['url'].endswith('/InRelease')):
        file = source_file.parent / release['path']; stream, _, _ = bundle.opened(source_file.parent, release); stream.close()
        result = subprocess.run([str(gpgv), '--status-fd', '1', '--keyring', str(keyring), str(file)], capture_output=True, timeout=30, env={'PATH': str(gpgv.parent), 'LC_ALL': 'C'})
        if result.returncode or len(result.stdout) > 1024 ** 2 or (('[GNUPG:] VALIDSIG ' + sources['signer'] + ' ').encode() not in result.stdout if publisher == 'ubuntu' else b'[GNUPG:] VALIDSIG ' not in result.stdout):
            raise ValueError('publisher source index signature failed independent replay')
        base = release['url'].removesuffix('/InRelease'); suite = urlsplit(base).path.rsplit('/', 1)[-1]
        indexes = debian.release_indexes(file.read_bytes(), suite); used.add(release['path'])
        for name, entry in indexes.items():
            url = base + '/' + name.rsplit('/', 1)[0] + '/by-hash/SHA256/' + entry['sha256']
            matches = [row for row in metadata if row['url'] == url and row['sha256'] == entry['sha256'] and row['size_bytes'] == entry['size_bytes']]
            if len(matches) != 1: raise ValueError('signed source index material is omitted or changed')
            index = matches[0]; stream, _, _ = bundle.opened(source_file.parent, index); stream.close(); used.add(index['path'])
            with lzma.open(source_file.parent / index['path'], 'rb') as compressed: raw = compressed.read(128 * 1024 ** 2 + 1)
            if len(raw) > 128 * 1024 ** 2: raise ValueError('source index expansion exceeds bound')
            for key, value in materials.source_index(raw).items():
                content = sorted((Path(row['path']).name, row['sha256'], row['size_bytes']) for row in value['files'])
                if key in signed_catalog and signed_catalog[key] != content: raise ValueError('authenticated indexes disagree on source bytes')
                signed_catalog[key] = content
    if used != {row['path'] for row in metadata}: raise ValueError('source authentication metadata is incomplete or contains unbound inputs')
    for row in sources['sources']:
        if signed_catalog.get(row['name'] + '\0' + row['version']) != sorted((Path(entry['path']).name, entry['sha256'], entry['size_bytes']) for entry in row['files']):
            raise ValueError('corresponding source definitions differ from publisher signed indexes')


def derive(inventory_file, source_file, private_runtime=None, *, keyring=None, gpgv=None, source_parts=None, recorder=None):
    inventory = json.loads(inventory_file.read_bytes()); sources = json.loads(source_file.read_bytes())
    if inventory.get('schema_version') != 1 or inventory.get('status') != 'passed' or inventory.get('qualification') not in ('image-bound-publisher-package-and-notice-inventory', 'oci-bound-publisher-package-and-notice-inventory', 'image-bound-installed-package-and-notice-inventory'):
        raise ValueError('verified binary package inventory required')
    if sources.get('schema_version') != 1 or sources.get('qualification') != 'publisher-authenticated-exact-corresponding-source-closure' or sources.get('status') != 'passed' or sources.get('missing'):
        raise ValueError('complete authenticated exact source inventory required')
    current = receipt(inventory_file)
    if not any(subject.get('sha256') == current['sha256'] for subject in sources.get('subjects', [])):
        raise ValueError('source closure is not bound to this exact binary inventory')
    authenticated_sources(source_file, sources, keyring, gpgv)
    # Every selected byte is rehashed; receipt flags alone cannot admit sources.
    source_blobs = {(bundle.safe(row['path']), row['sha256'], row['size_bytes']) for row in sources['files']}
    for file, data in ((inventory_file, inventory), (source_file, sources)):
        for row in bundle.selected(data):
            source_identity = (bundle.safe(row['path']), row['sha256'], row.get('size_bytes', row.get('size')))
            if source_parts is not None and file == source_file and source_identity in source_blobs:
                with source_parts.open_blob(source_identity[1], source_identity[2]): pass
                if recorder is not None: recorder.source_blob(file.parent / source_identity[0], source_identity[1], source_identity[2])
            else:
                stream, _, _ = bundle.opened(file.parent, row); stream.close()
    # Reconstruct the component universe from the actual retained package
    # database snapshots. A shortened packages[] list cannot define coverage.
    observed = {}
    snapshots = inventory.get('status_files', [inventory.get('status_file')])
    architecture = inventory.get('platform', inventory.get('guest_architecture', 'arm64')).split('/')[-1]
    selected_names = {row['package'] for row in inventory.get('library_mappings', [])} or None
    for snapshot in snapshots:
        if not snapshot: raise ValueError('actual binary package database is missing')
        raw = (inventory_file.parent / snapshot['path']).read_bytes()
        records = [row for row in materials.control_records(raw) if row.get('Status') == 'install ok installed']
        manifest = ''.join(row['Package'] + '\t' + row['Version'] + '\n' for row in records).encode()
        for row in materials.installed_packages(raw, manifest, architecture):
            if selected_names is not None and row['name'] not in selected_names: continue
            observed[(row['name'], row['version'], row['architecture'])] = row
    provided = {(row['name'], row['version'], row['architecture']): row for row in inventory['packages']}
    if not observed or set(observed) != set(provided) or len(provided) != len(inventory['packages']) or any(any(observed[key][field] != provided[key][field] for field in ('source', 'built_using')) for key in observed):
        raise ValueError('binary component inventory omits or changes actual package database entries')
    required = materials.source_requirements(inventory['packages'])
    actual = {identity(row): row for row in sources['sources']}
    if len(actual) != len(sources['sources']) or set(actual) != {identity(row) for row in required} or sources.get('required_sources') != len(required):
        raise ValueError('exact package source inventory adds or omits a required source')
    archive_files = {row['sha256']: row for row in sources['files']}
    for row in required:
        source = actual[identity(row)]
        if source.get('consumers') != row['consumers'] or not source.get('files'):
            raise ValueError('binary source consumers differ from actual package requirements')
        for entry in source['files']:
            if entry['sha256'] not in archive_files or archive_files[entry['sha256']]['size_bytes'] != entry['size_bytes']:
                raise ValueError('exact corresponding source component is missing')
    package_map = {row['name']: row for row in inventory['packages']}
    if len(package_map) != len(inventory['packages']): raise ValueError('binary package inventory is duplicated')
    libraries = inventory.get('library_mappings', [])
    if private_runtime is not None:
        private = json.loads(private_runtime.read_bytes()); expected = private.get('elf_origin', {}).get('libraries')
        if not expected or inventory.get('private_runtime_receipt_sha256') != receipt(private_runtime)['sha256'] or {row['library']: row['sha256'] for row in libraries} != expected:
            raise ValueError('private runtime/library source origin is stale or incomplete')
    bindings = []
    for package in inventory['packages']:
        requirements = materials.source_requirements([package]); selected = [actual[identity(row)] for row in requirements]
        bindings.append({'binary_component': {key: package[key] for key in ('name', 'version', 'architecture')}, 'binary_files': [{'name': row['library'], 'sha256': row['sha256'], 'image_path': row['resolved_image_path'], 'package_list': row['package_list']} for row in libraries if row['package'] == package['name']], 'notice': package['notice'], 'sources': [{'name': row['name'], 'version': row['version'], 'files': row['files']} for row in selected]})
    return {'schema_version': 1, 'qualification': 'derived-binary-package-source-license-bindings', 'status': 'passed', 'coverage_scope': 'exact-observed-binary-package-components', 'complete_product_coverage': False, 'inventory': current, 'corresponding_sources': receipt(source_file), 'private_runtime': receipt(private_runtime) if private_runtime is not None else None, 'image_sha256': inventory.get('image', {}).get('sha256', inventory.get('oci_image_digest')), 'bindings': bindings, 'license_declaration': 'Exact original package notices retained; no inferred redistribution authority or SPDX conclusion.', 'generator_sha256': receipt(Path(__file__))['sha256']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--inventory', type=Path, required=True); parser.add_argument('--sources', type=Path, required=True); parser.add_argument('--private-runtime', type=Path); parser.add_argument('--keyring', type=Path, required=True); parser.add_argument('--gpgv', type=Path, default=Path(shutil.which('gpgv'))); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): raise ValueError('new component binding output required')
    result = derive(args.inventory, args.sources, args.private_runtime, keyring=args.keyring.resolve(), gpgv=args.gpgv.resolve()); args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'status': result['status'], 'binary_components': len(result['bindings']), 'product_coverage': False}))
