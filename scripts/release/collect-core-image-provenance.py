#!/usr/bin/env python3
"""Acquire immutable official Python OCI build provenance as bounded data only."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')


def subjects(index, lock):
    selected = {}
    for platform, fingerprint in lock['platforms'].items():
        os_name, architecture = platform.split('/')
        rows = [row for row in index.get('manifests', []) if row.get('platform', {}).get('os') == os_name and row.get('platform', {}).get('architecture') == architecture]
        if len(rows) != 1 or rows[0]['digest'] != fingerprint: raise ValueError('official Python platform manifest differs from its exact lock')
        selected[platform] = rows[0]
    attestations = [row for row in index['manifests'] if row.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest' and row.get('annotations', {}).get('vnd.docker.reference.digest') in lock['platforms'].values()]
    return selected, attestations


def collect(root, output, *, with_layers=False):
    if output.exists(): raise ValueError('new official-image provenance output required')
    lock = json.loads((root / 'runtime/core-image.lock.json').read_bytes())
    if lock.get('schema_version') != 1 or lock.get('image') != 'docker.io/library/python:3.15.2-slim' or set(lock['platforms']) != {'linux/arm64', 'linux/amd64'} or not all(DIGEST.fullmatch(value) for value in [lock['index_digest'], *lock['platforms'].values()]): raise ValueError('exact official Python image contract required')
    output.mkdir(parents=True); (output / 'INCOMPLETE').write_text('Metadata acquisition incomplete.\n')
    with urlopen('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull', timeout=30) as source:
        raw = source.read(65537)
        if len(raw) > 65536: raise ValueError('anonymous registry token response exceeds bound')
        token = json.loads(raw)['token']
    if not isinstance(token, str) or len(token) > 16384: raise ValueError('anonymous registry pull token invalid')
    records = {}
    donor_layers = {}
    def acquire(kind, fingerprint, size=None):
        if kind not in ('manifests', 'blobs') or not DIGEST.fullmatch(fingerprint) or size is not None and (type(size) is not int or not 0 < size <= 32 * 1024 ** 2): raise ValueError('official image metadata descriptor is unsafe')
        url = 'https://registry-1.docker.io/v2/library/python/' + kind + '/' + fingerprint
        request = Request(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'})
        with urlopen(request, timeout=45) as source:
            body = source.read((size if size is not None else 32 * 1024 ** 2) + 1)
        if len(body) > 32 * 1024 ** 2 or size is not None and len(body) != size or 'sha256:' + hashlib.sha256(body).hexdigest() != fingerprint: raise ValueError('official immutable image metadata hash/size differs')
        file = output / 'blobs' / fingerprint[7:]; file.parent.mkdir(exist_ok=True)
        if file.exists() and file.read_bytes() != body: raise ValueError('official metadata content address conflicts')
        if not file.exists(): file.write_bytes(body); file.chmod(0o444)
        records[fingerprint] = {'path': file.relative_to(output).as_posix(), 'sha256': fingerprint[7:], 'size_bytes': len(body), 'url': url}
        return json.loads(body)
    def collect_layer(descriptor):
        identifier, size = descriptor['digest'], descriptor['size']
        if not DIGEST.fullmatch(identifier) or type(size) is not int or not 0 < size <= 1024**3:
            raise ValueError('official Python donor layer descriptor is unsafe')
        if descriptor['mediaType'] not in ('application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'):
            raise ValueError('official Python donor layer is not an admitted gzip transport')
        if identifier in donor_layers:
            if donor_layers[identifier]['size_bytes'] != size:
                raise ValueError('official Python donor layer size conflicts')
            return
        url = 'https://registry-1.docker.io/v2/library/python/blobs/' + identifier
        target = output / 'layers' / identifier[7:]
        target.parent.mkdir(exist_ok=True)
        request = Request(url, headers={'Authorization': 'Bearer ' + token})
        digest = hashlib.sha256()
        total = 0
        with urlopen(request, timeout=120) as incoming, target.open('xb') as destination:
            while block := incoming.read(1024**2):
                total += len(block)
                if total > size:
                    raise ValueError('official Python donor layer exceeds its locked size')
                digest.update(block)
                destination.write(block)
        if total != size or 'sha256:' + digest.hexdigest() != identifier:
            raise ValueError('official Python donor layer bytes differ')
        target.chmod(0o444)
        donor_layers[identifier] = {'path': target.relative_to(output).as_posix(), 'sha256': identifier[7:], 'size_bytes': size}

    index = acquire('manifests', lock['index_digest']); selected, attestations = subjects(index, lock); images = []
    for platform, row in selected.items():
        manifest = acquire('manifests', row['digest'], row['size']); config = acquire('blobs', manifest['config']['digest'], manifest['config']['size'])
        if with_layers:
            for layer in manifest['layers']:
                collect_layer(layer)
        if config.get('os') != 'linux' or config.get('architecture') != platform.split('/')[1]: raise ValueError('official Python image config architecture differs')
        environments = config.get('config', {}).get('Env', []); python = [value for value in environments if value.startswith('PYTHON_VERSION=')]; source_sha = [value for value in environments if value.startswith('PYTHON_SHA256=')]
        if python != ['PYTHON_VERSION=' + lock['python_version']] or len(source_sha) != 1 or not re.fullmatch('PYTHON_SHA256=[a-f0-9]{64}', source_sha[0]): raise ValueError('official Python source version/hash declaration missing')
        images.append({'platform': platform, 'manifest_digest': row['digest'], 'config_digest': manifest['config']['digest'], 'layers': manifest['layers'], 'python_version': lock['python_version'], 'python_source_sha256': source_sha[0].split('=', 1)[1], 'environment': environments, 'history': config.get('history', [])})
    statements = []
    for row in attestations:
        manifest = acquire('manifests', row['digest'], row['size'])
        for layer in manifest.get('layers', []):
            if layer.get('mediaType') != 'application/vnd.in-toto+json': raise ValueError('unknown official image attestation layer')
            statement = acquire('blobs', layer['digest'], layer['size']); subject = row['annotations']['vnd.docker.reference.digest']
            if not any(value.get('digest', {}).get('sha256') == subject[7:] for value in statement.get('subject', [])): raise ValueError('official image attestation subject differs')
            statements.append({'image_digest': subject, 'blob_sha256': layer['digest'], 'predicate_type': statement.get('predicateType'), 'statement': statement})
    result = {'schema_version': 1, 'qualification': 'immutable-publisher-oci-source-build-metadata-not-reproduced-build', 'target_execution': False, 'emulation': False, 'index_digest': lock['index_digest'], 'images': images, 'statements': statements, 'files': list(records.values()), 'source_lock_sha256': hashlib.sha256((root / 'runtime/core-image.lock.json').read_bytes()).hexdigest(), 'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    if with_layers:
        result['private_donor_layers'] = sorted(donor_layers.values(), key=lambda row: row['path'])
    (output / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n'); (output / 'INCOMPLETE').unlink(); return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=ROOT)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--with-donor-layers', action='store_true', help='acquire exact official provider blobs as private verification inputs')
    a = p.parse_args()
    value = collect(a.root.resolve(), a.output.resolve(), with_layers=a.with_donor_layers)
    print(json.dumps({'images': len(value['images']), 'statements': len(value['statements']), 'files': len(value['files']), 'private_donor_layers': len(value.get('private_donor_layers', [])), 'target_execution': False}))
