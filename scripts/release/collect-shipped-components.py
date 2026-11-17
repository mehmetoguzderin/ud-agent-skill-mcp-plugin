#!/usr/bin/env python3
"""Discover actual distribution members before deriving source/license coverage.

Inventories come from verified archives, never a caller's component list. This
does not infer a source or redistribution right from a binary filename/license
guess. Every unresolved binary-to-recipe binding remains an explicit blocker.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
inspector = module('ud_component_inspector', Path(__file__).with_name('inspect-package.py'))
materials = module('ud_shipped_materials', Path(__file__).with_name('source-bundle.py'))
oci = module('ud_component_oci', ROOT / 'scripts/runtime/oci_filesystem.py')
worker_export = module('ud_component_worker_export', ROOT / 'scripts/runtime/export-workers.py')
MAX_AUX_FILE = 512 * 1024 ** 2
MAX_PROVIDER_IMAGE = 2 * 1024 ** 3
MAX_AUX_TOTAL = 4 * 1024 ** 3


def sha(file):
    with file.open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def provider_image_members(runtime_root, artifact, runtime_sha256):
    """Only selected, frozen Lima guest images can exceed the ordinary bound."""
    match = re.fullmatch(r'provider-assets-lima-nerdctl-darwin-(arm64|x64)', artifact.get('id', ''))
    if not match:
        return {}
    raw = (runtime_root / 'runtime/runtime.lock.json').read_bytes()
    if len(raw) > 32 * 1024 ** 2 or hashlib.sha256(raw).hexdigest() != runtime_sha256:
        raise ValueError('provider image runtime lock differs from its candidate')
    runtime = json.loads(raw)
    profile = runtime.get('provider_receipts', {}).get('lima-nerdctl/darwin/' + match[1], {})
    lazy = profile.get('lazy_assets', {})
    if runtime.get('state') != 'frozen' or lazy.get('sha256') != 'sha256:' + artifact['sha256'] or lazy.get('size') != artifact['size']:
        raise ValueError('provider image archive differs from its frozen descriptor')
    images = [row for row in profile.get('provisioning', {}).get('assets', []) if row.get('key') == 'image']
    expected_name = 'runtime/providers/lima-nerdctl/darwin-' + match[1] + '/guest/ubuntu.img'
    if len(images) != 1:
        raise ValueError('provider image descriptor is missing or duplicated')
    image = images[0]
    same = [row for row in lazy.get('files', []) if row.get('path') == expected_name]
    if image.get('path') != expected_name or type(image.get('size_bytes')) is not int or not 0 <= image['size_bytes'] <= MAX_PROVIDER_IMAGE or not re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('sha256', '')) or len(same) != 1 or any(same[0].get(key) != image[key] for key in ('path', 'sha256', 'size_bytes')):
        raise ValueError('provider image member differs from its exact frozen identities')
    return {expected_name: {'sha256': image['sha256'][7:], 'size_bytes': image['size_bytes']}}


def archive_members(file, *, provider_images=None):
    provider_images = {} if provider_images is None else provider_images
    records, keys, total = [], set(), 0
    found_images = set()
    with tarfile.open(file, 'r:gz') as archive:
        for member in archive:
            name = inspector._paths.validate_path(member.name.rstrip('/') if member.isdir() else member.name)
            key = inspector._paths.path_key(name)
            pinned = provider_images.get(name)
            if key in keys or len(keys) >= 100000 or not (member.isfile() or member.isdir()) or not 0 <= member.size <= (MAX_PROVIDER_IMAGE if pinned else MAX_AUX_FILE):
                raise ValueError('auxiliary component archive has unsafe, duplicate or oversized member: ' + name)
            if pinned and (not member.isfile() or member.size != pinned['size_bytes']):
                raise ValueError('provider image member size differs from its frozen descriptor')
            keys.add(key)
            if member.isdir(): continue
            total += member.size
            if total > MAX_AUX_TOTAL: raise ValueError('auxiliary component archive exceeds bound')
            with archive.extractfile(member) as source:
                fingerprint = hashlib.sha256(); size = 0; prefix = b''
                while chunk := source.read(1024 ** 2):
                    if not prefix: prefix = chunk[:65536]
                    size += len(chunk); fingerprint.update(chunk)
                if size != member.size: raise ValueError('auxiliary component archive is truncated')
            if pinned:
                if fingerprint.hexdigest() != pinned['sha256']: raise ValueError('provider image member hash differs from its frozen descriptor')
                found_images.add(name)
            records.append({'path': name, 'sha256': fingerprint.hexdigest(), 'size_bytes': size, 'architecture': inspector.architecture(prefix)})
    if found_images != set(provider_images): raise ValueError('auxiliary archive omits its frozen provider image')
    return records


def transport_members(root, file, artifact, runtime, pack_name, platform, format, number, *, member_observer=None):
    """Inspect a real per-architecture transport; normalization executes no image."""
    image = runtime['packs'][pack_name]['images'][platform]
    transports = image.get('transports', [])
    if number >= len(transports): raise ValueError('worker transport index is absent from the runtime lock')
    transport = transports[number]
    if transport.get('format') != format or transport.get('sha256') != 'sha256:' + artifact['sha256'] or transport.get('size_bytes') != artifact['size']:
        raise ValueError('worker transport differs from its actual frozen descriptor')
    members = []
    with tempfile.TemporaryDirectory(prefix='ud-component-transport-') as temporary:
        directory = Path(temporary); layout = directory / 'layout'; blobs = layout / 'blobs/sha256'
        staged = worker_export.stage_image(file, platform, image['config_digest'], blobs, strict_inventory=True, expected_wrappers=image.get('engine_descriptor_digests', []))
        if format == 'oci-archive' and transport.get('index_digest') not in staged['engine_descriptor_digests']:
            raise ValueError('worker OCI transport index identity differs from its frozen descriptor')
        if staged['config_digest'] != image['config_digest'] or staged['diff_ids'] != image['diff_ids'] or staged['descriptor']['digest'] != image['digest']:
            raise ValueError('worker transport image graph differs from the exact selected image')
        # This local index is an inspection projection, never a published
        # RepoDigest or a substitute for an unavailable architecture image.
        normalized = directory / 'inspection.oci.tar'
        inspection_index = worker_export.platform_archive(layout, staged['descriptor'], staged, normalized)
        projection = {'index_digest': inspection_index, 'platforms': {platform: staged['descriptor']['digest']}, 'images': {platform: {'digest': staged['descriptor']['digest'], **{key: staged[key] for key in ('config_digest', 'diff_ids', 'engine_descriptor_digests')}}}, 'index_transport': {'path': normalized.name, 'sha256': worker_export.file_sha(normalized), 'size_bytes': normalized.stat().st_size}}
        def observe(name, opaque, serial, layer, index):
            with opaque.open('rb') as source: prefix = source.read(65536)
            row = {'path': 'layers/' + layer['digest'][7:] + '/' + str(serial) + '/' + name, 'image_path': name, 'layer_digest': layer['digest'], 'layer_index': index, 'sha256': sha(opaque), 'size_bytes': opaque.stat().st_size, 'architecture': inspector.architecture(prefix), 'platform': platform}
            members.append(row)
            if member_observer is not None: member_observer(row['path'], opaque)
        oci.verified_filesystem(directory, projection, platform, directory / 'opaque', True, file_observer=observe)
    stream, _, _ = materials.opened(root, {**artifact, 'size_bytes': artifact['size']}); stream.close()
    return members


def collect(root, candidate, *, diagnostic=False, runtime_root=None, available_targets=False):
    runtime_root = root if runtime_root is None else runtime_root
    if available_targets and (diagnostic or candidate.get('qualification') != 'available-target-preacceptance' or candidate.get('scope', {}).get('kind') != 'available-target-subset'): raise ValueError('available-target inspection requires its explicit immutable subset authority')
    required = json.loads((ROOT / 'quality/requirements.json').read_bytes())['required_artifacts']
    version = candidate.get('schema_version')
    supported = (1, 2) if available_targets else (1,)
    if type(version) is not int or version not in supported or not re.fullmatch('[a-f0-9]{64}', candidate.get('source_tree_sha256', '')) or not re.fullmatch('[a-f0-9]{64}', candidate.get('runtime_lock_sha256', '')) or not isinstance(candidate.get('artifacts'), list):
        raise ValueError('exact source/runtime-bound artifact manifest required')
    seen = set(); subjects = []; blockers = []
    for artifact in candidate['artifacts']:
        identifier = artifact['id']
        if identifier in seen: raise ValueError('distribution artifact identity duplicated')
        seen.add(identifier); stream, _, _ = materials.opened(root, {**artifact, 'size_bytes': artifact['size']}); stream.close()
        file = root / artifact['path']; members = []; role = 'metadata'; preferred_sources = []
        match = re.fullmatch(r'(?:native|mcpb)-(linux|macos|windows)-(amd64|arm64)', identifier)
        if match or identifier in ('npm', 'standalone-skills'):
            platform = {'linux': 'linux', 'macos': 'darwin', 'windows': 'win32'}[match[1]] + '-' + ('x64' if match[2] == 'amd64' else 'arm64') if match else 'all'
            kind = 'native' if match else 'npm' if identifier == 'npm' else 'skills'
            data = inspector.inspect(file, kind, platform, candidate['source_tree_sha256'], candidate['runtime_lock_sha256'], require_candidate=not diagnostic, details=True)
            members = [{'path': name, 'sha256': row['sha256'], 'size_bytes': row['size'], 'architecture': data['binary_components'].get(name, 'data')} for name, row in sorted(data['members'].items())]
            # These are the actual readable source forms of configuration and
            # receipt data, not compiled implementation or third-party code.
            # Runtime binaries/bundles/wheels remain separate recipe subjects.
            preferred_sources = [name for name in data['metadata'] if name != 'SOURCE-MANIFEST.json']
            preferred_sources.extend(name for name in data['members'] if name in ('UNACCEPTED.md', 'RELEASE-CANDIDATE.md') or re.fullmatch(r'runtime/pack/requirements/(?:darwin|linux|win32)-(?:arm64|x64)\.txt', name))
            role = 'installed-runtime' if kind != 'skills' else 'self-contained-skills'
        elif identifier.endswith('-oci-index'):
            pack_name = identifier.removesuffix('-oci-index'); runtime = json.loads((runtime_root / 'runtime/runtime.lock.json').read_bytes()); pack = runtime['packs'][pack_name]
            if sha(runtime_root / 'runtime/runtime.lock.json') != candidate['runtime_lock_sha256']: raise ValueError('actual worker runtime lock differs')
            if artifact['sha256'] != pack['index_transport']['sha256'].removeprefix('sha256:'): raise ValueError('worker archive differs from actual frozen graph')
            for platform in sorted(pack['images']):
                with tempfile.TemporaryDirectory(prefix='ud-component-oci-') as temporary:
                    def observe(name, opaque, serial, layer, index):
                        with opaque.open('rb') as source: prefix = source.read(65536)
                        members.append({'path': 'layers/' + layer['digest'][7:] + '/' + str(serial) + '/' + name, 'image_path': name, 'layer_digest': layer['digest'], 'layer_index': index, 'sha256': sha(opaque), 'size_bytes': opaque.stat().st_size, 'architecture': inspector.architecture(prefix), 'platform': platform})
                    oci.verified_filesystem(runtime_root, pack, platform, Path(temporary) / 'opaque', diagnostic or available_targets, file_observer=observe)
            role = 'worker-runtime'
        elif match := re.fullmatch(r'(core|render)-(linux)-(arm64|amd64)-(oci-archive|docker-archive)-([0-9]+)', identifier):
            runtime = json.loads((runtime_root / 'runtime/runtime.lock.json').read_bytes())
            if sha(runtime_root / 'runtime/runtime.lock.json') != candidate['runtime_lock_sha256']: raise ValueError('actual worker runtime lock differs')
            members = transport_members(root, file, artifact, runtime, match[1], 'linux/' + match[3], match[4], int(match[5])); role = 'worker-runtime'
        elif identifier.startswith(('userspace-core-', 'render-assets-', 'provider-assets-')):
            members = archive_members(file, provider_images=provider_image_members(runtime_root, artifact, candidate['runtime_lock_sha256'])); role = 'lazy-runtime'
        elif identifier == 'sbom':
            data = json.loads(file.read_bytes())
            if data.get('spdxVersion') != 'SPDX-2.3' or not data.get('packages'): raise ValueError('actual SBOM component inventory missing')
            members = [{'spdx_id': row['SPDXID'], 'name': row['name'], 'version': row.get('versionInfo'), 'source_location': row.get('downloadLocation'), 'license_declared': row.get('licenseDeclared'), 'checksums': row.get('checksums', [])} for row in data['packages']]; role = 'component-declarations'
        elif identifier == 'source-archive':
            data = inspector.inspect(file, 'source', 'all', candidate['source_tree_sha256'], candidate['runtime_lock_sha256'], details=True)
            members = [{'path': name, 'sha256': row['sha256'], 'size_bytes': row['size'], 'architecture': data['binary_components'].get(name, 'data')} for name, row in sorted(data['members'].items())]
            preferred_sources = ['SOURCE-MANIFEST.json']; role = 'source-snapshot'
        elif identifier.startswith('uv-'):
            with file.open('rb') as source: prefix = source.read(65536)
            members = [{'path': file.name, 'sha256': artifact['sha256'], 'size_bytes': artifact['size'], 'architecture': inspector.architecture(prefix)}]; role = 'bootstrap-runtime'
        elif identifier not in ('checksum-manifest', 'mcp-registry-record', 'catalog-claude', 'catalog-codex', 'catalog-grok', 'catalog-grok-index', 'corresponding-source-index') and not re.fullmatch(r'corresponding-source-[0-9]{4}', identifier):
            role = 'unclassified-runtime'; blockers.append({'code': 'UNCLASSIFIED_DISTRIBUTION_FORMAT', 'artifact': identifier})
        subjects.append({'id': identifier, 'sha256': artifact['sha256'], 'size_bytes': artifact['size'], 'role': role, 'members': members, 'colocated_preferred_sources': sorted(preferred_sources)})
    for identifier in sorted(set(required) - seen): blockers.append({'code': 'REQUIRED_DISTRIBUTION_MISSING', 'artifact': identifier})
    # Discovery establishes the exact universe. Source binding is a separate
    # derived relation: a self-declared complete flag cannot fill it in.
    for subject in subjects:
        if subject['role'] in ('installed-runtime', 'worker-runtime', 'lazy-runtime', 'bootstrap-runtime', 'unclassified-runtime'):
            blockers.append({'code': 'SOURCE_RECIPE_AND_LICENSE_BINDING_REQUIRED', 'artifact': subject['id'], 'member_inventory_sha256': hashlib.sha256(json.dumps(subject['members'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()})
    return {'schema_version': 1, 'qualification': 'actual-shipped-component-discovery-no-source-waiver', 'status': 'incomplete' if blockers else 'discovered', 'complete_product_coverage': False, 'source_tree_sha256': candidate['source_tree_sha256'], 'runtime_lock_sha256': candidate['runtime_lock_sha256'], 'required_distributions': required, 'subjects': subjects, 'blockers': blockers, 'generator_sha256': sha(Path(__file__))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, required=True); parser.add_argument('--candidate', type=Path, required=True); parser.add_argument('--output', type=Path, required=True); parser.add_argument('--diagnostic', action='store_true'); args = parser.parse_args()
    if args.output.exists(): raise ValueError('new component discovery output required')
    result = collect(args.root.resolve(), json.loads(args.candidate.read_bytes()), diagnostic=args.diagnostic); args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'status': result['status'], 'distributions': len(result['subjects']), 'blockers': len(result['blockers'])}))
