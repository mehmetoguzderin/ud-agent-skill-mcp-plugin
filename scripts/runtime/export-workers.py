#!/usr/bin/env python3
"""Export local immutable workers into verified OCI indexes and offline transports."""
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
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
_unicode_spec = importlib.util.spec_from_file_location('ud_agent_export_unicode', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
_unicode = importlib.util.module_from_spec(_unicode_spec)
_unicode_spec.loader.exec_module(_unicode)
INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
SHA = re.compile(r'^sha256:[a-f0-9]{64}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as source:
        return 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest()


def transport(root, path, kind):
    return {'format': kind, 'path': path.relative_to(root).as_posix(), 'sha256': file_sha(path), 'size_bytes': path.stat().st_size}


def archive_inventory(bundle):
    entries, seen, total = {}, set(), 0
    for member in bundle:
        name = member.name.removeprefix('./').rstrip('/') if member.isdir() else member.name.removeprefix('./')
        if not name or name.startswith('/') or '\\' in name or ':' in name or any(part in ('', '.', '..') for part in name.split('/')):
            raise ValueError('worker export archive has an unsafe member')
        key = _unicode.path_key(name)
        if key in seen or len(seen) >= 50000 or not (member.isdir() or member.isfile()) or member.size < 0 or member.size > 8 * 1024**3:
            raise ValueError('worker export archive has a duplicate, link or excessive member')
        seen.add(key)
        total += member.size
        if total > 32 * 1024**3:
            raise ValueError('worker export archive exceeds its size bound')
        if member.isfile():
            entries[name] = member
    return entries


def stage_image(archive, platform, engine_id, blob_directory, *, strict_inventory=False, expected_wrappers=()):
    """Normalize Docker's OCI-layout/legacy transport without trusting its tags."""
    if archive.is_symlink() or not archive.is_file() or not SHA.fullmatch(engine_id):
        raise ValueError('worker export image identity is invalid')
    blob_directory.mkdir(parents=True, exist_ok=True)
    with archive.open('rb') as held, tarfile.open(fileobj=held, mode='r:') as bundle:
        before = os.fstat(held.fileno())
        entries = archive_inventory(bundle)
        consumed = set()

        def read(name):
            member = entries.get(name)
            if member is None or member.size > 16 * 1024**2:
                raise ValueError('worker export metadata is absent or oversized')
            consumed.add(name)
            with bundle.extractfile(member) as source:
                return source.read(member.size + 1)

        def stage(name, expected=None):
            member = entries.get(name)
            if member is None:
                raise ValueError('worker export lacks a referenced blob')
            consumed.add(name)
            with tempfile.NamedTemporaryFile(prefix='.blob-', dir=blob_directory, delete=False) as target, bundle.extractfile(member) as source:
                temporary = Path(target.name)
                digest = hashlib.sha256()
                count = 0
                for data in iter(lambda: source.read(1024**2), b''):
                    count += len(data)
                    digest.update(data)
                    target.write(data)
            identifier = 'sha256:' + digest.hexdigest()
            if count != member.size or (expected is not None and identifier != expected):
                temporary.unlink()
                raise ValueError('worker export blob integrity differs from its descriptor')
            final = blob_directory / digest.hexdigest()
            if final.exists():
                if file_sha(final) != identifier:
                    raise ValueError('worker export content-addressed blob collision')
                temporary.unlink()
            else:
                temporary.rename(final)
            return {'digest': identifier, 'size': count}

        def store(data):
            identifier = sha(data)
            target = blob_directory / identifier[7:]
            if target.exists() and target.read_bytes() != data:
                raise ValueError('worker export content-addressed metadata collision')
            target.write_bytes(data)
            return {'digest': identifier, 'size': len(data)}

        wrappers = []
        if 'index.json' in entries and 'oci-layout' in entries:
            if json.loads(read('oci-layout')).get('imageLayoutVersion') != '1.0.0':
                raise ValueError('worker export OCI layout version is unsupported')
            root_bytes = read('index.json')
            root = json.loads(root_bytes)
            root_digest = store(root_bytes)['digest']

            def select(value, identifier, depth=0):
                if depth > 8:
                    raise ValueError('worker export index nesting exceeds its bound')
                if value.get('mediaType') in (MANIFEST, 'application/vnd.docker.distribution.manifest.v2+json'):
                    return value, identifier
                children = value.get('manifests')
                if value.get('schemaVersion') != 2 or value.get('mediaType') not in (INDEX, 'application/vnd.docker.distribution.manifest.list.v2+json') or not isinstance(children, list) or len(children) != 1:
                    raise ValueError('worker export must contain one platform without attestations; rebuild with --provenance=false')
                wrappers.append(identifier)
                child = children[0]
                digest = child.get('digest', '')
                if not SHA.fullmatch(digest):
                    raise ValueError('worker export index descriptor is invalid')
                staged = stage('blobs/sha256/' + digest[7:], digest)
                if staged['size'] != child.get('size'):
                    raise ValueError('worker export index descriptor size mismatch')
                return select(json.loads((blob_directory / digest[7:]).read_bytes()), digest, depth + 1)

            manifest, manifest_digest = select(root, root_digest)
            config_descriptor = manifest.get('config', {})
            config_digest = config_descriptor.get('digest', '')
            if not SHA.fullmatch(config_digest):
                raise ValueError('worker export image config identity is invalid')
            checked = stage('blobs/sha256/' + config_digest[7:], config_digest)
            if checked['size'] != config_descriptor.get('size'):
                raise ValueError('worker export image config size mismatch')
            config = json.loads((blob_directory / config_digest[7:]).read_bytes())
            for layer in manifest.get('layers', []):
                if not SHA.fullmatch(layer.get('digest', '')):
                    raise ValueError('worker export image layer identity is invalid')
                checked = stage('blobs/sha256/' + layer['digest'][7:], layer['digest'])
                if checked['size'] != layer.get('size'):
                    raise ValueError('worker export image layer size mismatch')
            media_type = manifest['mediaType']
        else:
            records = json.loads(read('manifest.json'))
            if not isinstance(records, list) or len(records) != 1:
                raise ValueError('worker export Docker archive must select one image')
            record = records[0]
            config_bytes = read(record['Config'])
            config = json.loads(config_bytes)
            config_receipt = store(config_bytes)
            config_digest = config_receipt['digest']
            layers = []
            for name in record['Layers']:
                layer = stage(name)
                layers.append({'mediaType': 'application/vnd.oci.image.layer.v1.tar', **layer})
            manifest = {'schemaVersion': 2, 'mediaType': MANIFEST, 'config': {'mediaType': CONFIG, **config_receipt}, 'layers': layers}
            manifest_digest = store(canonical(manifest))['digest']
            media_type = MANIFEST
        if f"{config.get('os')}/{config.get('architecture')}" != platform or config.get('rootfs', {}).get('type') != 'layers' or not isinstance(config['rootfs'].get('diff_ids'), list) or not all(isinstance(item, str) and SHA.fullmatch(item) for item in config['rootfs']['diff_ids']) or len(config['rootfs']['diff_ids']) != len(manifest['layers']):
            raise ValueError('worker export config platform or rootfs identity is invalid')
        if engine_id != config_digest and engine_id != manifest_digest and engine_id not in wrappers:
            raise ValueError('engine identity is not present in the verified exported descriptor graph')
        if strict_inventory:
            def include_wrapper(identifier, ancestors=()):
                if identifier == manifest_digest or identifier in wrappers: return
                if not SHA.fullmatch(identifier) or identifier in ancestors or len(ancestors) >= 8: raise ValueError('worker transport expected wrapper is invalid or cyclic')
                name = 'blobs/sha256/' + identifier[7:]
                value = json.loads(read(name)); stage(name, identifier)
                if value.get('schemaVersion') != 2 or value.get('mediaType') not in (INDEX, 'application/vnd.docker.distribution.manifest.list.v2+json') or not isinstance(value.get('manifests'), list) or len(value['manifests']) != 1:
                    raise ValueError('worker transport expected wrapper is not a single selected image')
                child = value['manifests'][0]
                include_wrapper(child.get('digest', ''), (*ancestors, identifier))
                if child.get('digest') != manifest_digest and child.get('digest') not in wrappers: raise ValueError('worker transport expected wrapper selects another image')
                wrappers.append(identifier)
            for identifier in expected_wrappers: include_wrapper(identifier)
            # Docker's OCI-layout export also includes a compatibility
            # manifest. It may describe only the same verified config/layers;
            # no otherwise-unreferenced blob can disappear from source scope.
            if 'manifest.json' in entries and 'manifest.json' not in consumed:
                compatibility = json.loads(read('manifest.json'))
                if not isinstance(compatibility, list) or len(compatibility) != 1 or compatibility[0].get('Config') != 'blobs/sha256/' + config_digest[7:] or compatibility[0].get('Layers') != ['blobs/sha256/' + layer['digest'][7:] for layer in manifest['layers']]:
                    raise ValueError('Docker compatibility manifest selects a different verified image')
            if consumed != set(entries):
                raise ValueError('worker transport contains unreferenced archive members')
        after = os.fstat(held.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('worker export archive changed during verification')
    return {'descriptor': {'mediaType': media_type, 'digest': manifest_digest, 'size': (blob_directory / manifest_digest[7:]).stat().st_size, 'platform': dict(zip(('os', 'architecture'), platform.split('/')))}, 'config_digest': config_digest, 'diff_ids': config['rootfs']['diff_ids'], 'engine_descriptor_digests': sorted(set(wrappers + ([manifest_digest] if engine_id == manifest_digest else [])))}


def oci_archive(layout, destination):
    with tarfile.open(destination, 'w', format=tarfile.USTAR_FORMAT) as target:
        for file in sorted(layout.rglob('*')):
            if not file.is_file():
                continue
            info = target.gettarinfo(str(file), arcname=file.relative_to(layout).as_posix())
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ''
            info.mode = 0o644
            with file.open('rb') as source:
                target.addfile(info, source)


def platform_archive(layout, descriptor, item, destination):
    """A closed single-platform OCI transport for engines without index import."""
    blobs = layout / 'blobs/sha256'
    wanted = set()
    def include(identifier):
        if not SHA.fullmatch(identifier):
            raise ValueError('platform transport contains an invalid descriptor')
        file = blobs / identifier[7:]
        if file.is_symlink() or not file.is_file() or file_sha(file) != identifier:
            raise ValueError('platform transport descriptor bytes are damaged')
        wanted.add(identifier)
        return file
    manifest = json.loads(include(descriptor['digest']).read_text())
    include(manifest['config']['digest'])
    for layer in manifest['layers']:
        include(layer['digest'])
    def wrapper(identifier, ancestors=()):
        include(identifier)
        if identifier == descriptor['digest']:
            return
        if identifier in ancestors or len(ancestors) >= 8:
            raise ValueError('platform transport engine descriptor is cyclic')
        node = json.loads((blobs / identifier[7:]).read_text())
        if node.get('schemaVersion') != 2 or node.get('mediaType') not in (INDEX, 'application/vnd.docker.distribution.manifest.list.v2+json') or len(node.get('manifests', [])) != 1:
            raise ValueError('platform transport engine descriptor is not a single selected image')
        wrapper(node['manifests'][0]['digest'], (*ancestors, identifier))
    for identifier in item.get('engine_descriptor_digests', []):
        wrapper(identifier)
    index = canonical({'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [descriptor]})
    with tempfile.TemporaryDirectory(prefix='.platform-oci-', dir=destination.parent) as temporary:
        selected = Path(temporary)
        (selected / 'blobs/sha256').mkdir(parents=True)
        (selected / 'index.json').write_bytes(index)
        (selected / 'oci-layout').write_bytes(canonical({'imageLayoutVersion': '1.0.0'}))
        for identifier in sorted(wanted):
            os.link(blobs / identifier[7:], selected / 'blobs/sha256' / identifier[7:])
        oci_archive(selected, destination)
    return sha(index)


def export(root, output, images, diagnostic_platforms=None):
    selected=set(diagnostic_platforms or ['linux/arm64','linux/amd64'])
    if not selected or not selected<={'linux/arm64','linux/amd64'}or output.exists() or output.is_symlink() or set(images) != {'core', 'render'} or any(set(value) != selected for value in images.values()):
        raise ValueError('worker export requires a new output and both packs/architectures')
    output.mkdir(parents=True, mode=0o700)
    receipt = {'schema_version': 1, 'qualification': 'local-build-unaccepted', 'packs': {}}
    if diagnostic_platforms:receipt['deferred_platforms']=sorted({'linux/arm64','linux/amd64'}-selected)
    try:
        for pack, platforms in images.items():
            layout = output / ('.' + pack + '-layout')
            blobs = layout / 'blobs/sha256'
            blobs.mkdir(parents=True)
            records, descriptors = {}, []
            for platform, reference in platforms.items():
                inspect = json.loads(subprocess.check_output(['docker', 'image', 'inspect', reference], timeout=30))
                if len(inspect) != 1 or not SHA.fullmatch(inspect[0].get('Id', '')):
                    raise ValueError('local worker image inspection did not identify one immutable image')
                engine = inspect[0]['Id']
                archive = output / f"ud-agent-{pack}-{platform.replace('/', '-')}.docker.tar"
                subprocess.run(['docker', 'image', 'save', '--platform', platform, '--output', str(archive), engine], check=True, timeout=600)
                item = stage_image(archive, platform, engine, blobs)
                if inspect[0].get('RootFS', {}).get('Layers') != item['diff_ids']:
                    raise ValueError('local engine rootfs differs from its exported image')
                descriptor = item.pop('descriptor')
                descriptors.append(descriptor)
                per_arch = output / f"ud-agent-{pack}-{platform.replace('/', '-')}.oci.tar"
                single_index = platform_archive(layout, descriptor, item, per_arch)
                records[platform] = {'digest': descriptor['digest'], 'reference': f"ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin-{pack}@{descriptor['digest']}", **item, 'transports': [transport(root, archive, 'docker-archive'), {**transport(root, per_arch, 'oci-archive'), 'index_digest': single_index}]}
                script = 'import {verifyOciArchive} from ' + json.dumps((root / 'scripts/release/oci.mjs').as_uri()) + '; const image=JSON.parse(process.argv[1]); verifyOciArchive(process.argv[2],process.argv[3],{[process.argv[4]]:image.digest},undefined,{[process.argv[4]]:image},{diagnosticSinglePlatform:true});'
                subprocess.run(['node', '--input-type=module', '-e', script, json.dumps(records[platform]), str(per_arch), single_index, platform], check=True, timeout=900)
            index = {'schemaVersion': 2, 'mediaType': INDEX, 'manifests': sorted(descriptors, key=lambda item: item['platform']['architecture'])}
            data = canonical(index)
            (layout / 'index.json').write_bytes(data)
            (layout / 'oci-layout').write_bytes(canonical({'imageLayoutVersion': '1.0.0'}))
            archive = output / f'ud-agent-{pack}.oci.tar'
            oci_archive(layout, archive)
            index_transport = transport(root, archive, 'oci-archive')
            record = {'index_digest': sha(data), 'platforms': {platform: item['digest'] for platform, item in records.items()}, 'images': records, 'index_transport': index_transport}
            # Recompute every layer's uncompressed diff ID with the independent
            # release verifier before emitting an admission receipt.
            script = 'import {verifyOciArchive} from ' + json.dumps((root / 'scripts/release/oci.mjs').as_uri()) + '; const r=JSON.parse(process.argv[1]); verifyOciArchive(process.argv[2],r.index_digest,r.platforms,undefined,r.images,'+json.dumps({'diagnosticSinglePlatform':bool(diagnostic_platforms)})+');'
            subprocess.run(['node', '--input-type=module', '-e', script, json.dumps(record), str(archive)], check=True, timeout=900)
            receipt['packs'][pack] = record
            shutil.rmtree(layout)
        (output / 'worker-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    except Exception:
        # Keep interrupted exports clearly unaccepted and reviewable. A retry
        # uses a new owned output; no shared Docker object or cache is removed.
        (output / 'INCOMPLETE').write_text('No admission receipt was completed.\n')
        raise
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--platform',action='append',choices=['linux/arm64','linux/amd64'],help='explicit diagnostic worker subset; omitted builds remain deferred')
    for pack in ('core', 'render'):
        for arch in ('arm64', 'amd64'):
            parser.add_argument(f'--{pack}-{arch}')
    args = parser.parse_args()
    selected=args.platform or ['linux/arm64','linux/amd64']
    images = {pack: {platform:getattr(args, f'{pack}_{platform.split("/")[1]}') for platform in selected} for pack in ('core', 'render')}
    if any(not value for platforms in images.values()for value in platforms.values()):parser.error('every selected worker platform requires both core and render image references')
    result = export(ROOT, args.output.resolve(), images,args.platform)
    print(json.dumps({'qualification': result['qualification'], 'packs': {key: value['index_digest'] for key, value in result['packs'].items()}}))


if __name__ == '__main__':
    main()
