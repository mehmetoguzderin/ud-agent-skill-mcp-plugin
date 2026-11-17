#!/usr/bin/env python3
"""Prepare offline Apple/WSLc provider closures from frozen public inputs.

This never installs a host engine or starts a VM. Windows binaries are inspected,
not executed. The emitted native acceptance states remain pending.
"""
from __future__ import annotations
import argparse
from compression import zstd
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from windows_pe import inspect_pe, system_dll

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def file_sha(filename):
    with filename.open('rb') as source:
        return 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest()


def verified(filename, expected, size=None):
    if filename.is_symlink() or not filename.is_file() or size is not None and filename.stat().st_size != size or file_sha(filename) != expected:
        raise ValueError('provider input integrity mismatch: ' + filename.name)
    return filename


def command(arguments, **options):
    return subprocess.run(arguments, check=True, timeout=180, capture_output=True, **options)


def safe_zip_member(bundle, name, maximum=256 * 1024**2):
    entries = [entry for entry in bundle.infolist() if entry.filename == name]
    if len(entries) != 1 or entries[0].file_size > maximum or (entries[0].external_attr >> 16) & 0o170000 == 0o120000:
        raise ValueError('provider ZIP member is absent, duplicated, linked or oversized')
    body = bundle.read(entries[0])
    if len(body) != entries[0].file_size:
        raise ValueError('provider ZIP member was truncated')
    return body


def copy_regular(source, target):
    if source.is_symlink() or not source.is_file():
        raise ValueError('provider payload must contain ordinary files')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def extract_kernel(archive, member, target):
    found = False
    with archive.open('rb') as raw, zstd.ZstdFile(raw) as decoded, tarfile.open(fileobj=decoded, mode='r|') as bundle:
        for index, entry in enumerate(bundle):
            if index >= 100000:
                raise ValueError('kernel archive inventory exceeds bound')
            if entry.name.removeprefix('./') != member:
                continue
            if found or not entry.isfile() or not 64 <= entry.size <= 256 * 1024**2:
                raise ValueError('kernel archive has an invalid selected member')
            with bundle.extractfile(entry) as stream:
                body = stream.read(entry.size + 1)
            if len(body) != entry.size:
                raise ValueError('kernel archive member was truncated')
            # Kata's vmlinux is an AArch64 Linux Image with an EFI PE stub,
            # not an ELF despite its filename (Linux arm64 boot protocol).
            pe = int.from_bytes(body[60:64], 'little')
            if body[:2] != b'MZ' or body[56:60] != b'ARMd' or not 64 <= pe <= len(body) - 24 or body[pe:pe + 6] != b'PE\0\0\x64\xaa' or not len(body) <= int.from_bytes(body[16:24], 'little') <= 256 * 1024**2:
                raise ValueError('kernel is not the expected AArch64 Linux Image')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            found = True
    if not found:
        raise ValueError('kernel archive lacks the frozen member')


def prepare_init(lock, cache, output):
    record = lock['apple_container']['init_image']
    manifest_file = verified(cache / 'apple-init-manifest.json', record['manifest_digest'])
    index_file = verified(cache / 'apple-init-index.json', record['index_digest'])
    index = json.loads(index_file.read_bytes())
    if len(index['manifests']) != 1 or index['manifests'][0]['digest'] != record['manifest_digest'] or index['manifests'][0]['platform']['architecture'] != 'arm64':
        raise ValueError('Apple init index platform differs')
    manifest = json.loads(manifest_file.read_bytes())
    if manifest.get('schemaVersion') != 2 or manifest['config']['digest'] != record['config_digest'] or len(manifest['layers']) != 1:
        raise ValueError('Apple init manifest differs')
    blobs = {}
    for descriptor in [manifest['config'], *manifest['layers']]:
        if descriptor['size'] > 512 * 1024**2 or not descriptor['digest'].startswith('sha256:'):
            raise ValueError('Apple init descriptor exceeds bounds')
        source = verified(cache / descriptor['digest'][7:], descriptor['digest'], descriptor['size'])
        blobs['blobs/sha256/' + descriptor['digest'][7:]] = source.read_bytes()
    config = json.loads(blobs['blobs/sha256/' + record['config_digest'][7:]])
    if config.get('architecture') != 'arm64' or config.get('os') != 'linux' or config.get('rootfs', {}).get('type') != 'layers':
        raise ValueError('Apple init config differs')
    layer = manifest['layers'][0]
    if layer['mediaType'] != 'application/vnd.oci.image.layer.v1.tar+gzip':
        raise ValueError('Apple init layer encoding differs')
    with gzip.GzipFile(fileobj=io.BytesIO(blobs['blobs/sha256/' + layer['digest'][7:]])) as decoded:
        uncompressed = hashlib.sha256()
        count = 0
        while chunk := decoded.read(1024**2):
            count += len(chunk)
            if count > 512 * 1024**2:
                raise ValueError('Apple init layer expansion exceeds bounds')
            uncompressed.update(chunk)
    actual_diff_id = 'sha256:' + uncompressed.hexdigest()
    # Apple vminit 0.34.0 records the compressed digest as its OCI diff_id.
    # Preserve its exact layer, but publish a separately named local normalized
    # config/manifest. Never claim this derived digest exists in Apple's GHCR.
    if config['rootfs']['diff_ids'] not in ([layer['digest']], [actual_diff_id]):
        raise ValueError('Apple init source rootfs identity differs')
    config['rootfs']['diff_ids'] = [actual_diff_id]
    encoded_config = json.dumps(config, sort_keys=True, separators=(',', ':')).encode()
    del blobs['blobs/sha256/' + record['config_digest'][7:]]
    config_digest = sha(encoded_config)
    blobs['blobs/sha256/' + config_digest[7:]] = encoded_config
    manifest['config'] = {**manifest['config'], 'digest': config_digest, 'size': len(encoded_config)}
    encoded_manifest = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    manifest_digest = sha(encoded_manifest)
    reference = 'localhost/ud-agent-skill-mcp-plugin-init@' + manifest_digest
    blobs['blobs/sha256/' + manifest_digest[7:]] = encoded_manifest
    blobs['index.json'] = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [{'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': manifest_digest, 'size': len(encoded_manifest), 'platform': {'os': 'linux', 'architecture': 'arm64'}, 'annotations': {'org.opencontainers.image.ref.name': reference, 'io.containerd.image.name': reference, 'com.apple.containerization.image.name': reference}}]}, sort_keys=True, separators=(',', ':')).encode()
    blobs['oci-layout'] = b'{"imageLayoutVersion":"1.0.0"}'
    target = output / 'runtime/images/init-linux-arm64.tar'
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, 'w', format=tarfile.USTAR_FORMAT) as bundle:
        for name, body in sorted(blobs.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(body)
            entry.mode = 0o644
            bundle.addfile(entry, io.BytesIO(body))
    return {'reference': reference, 'digest': manifest_digest,
            'config_digest': config_digest, 'diff_ids': config['rootfs']['diff_ids'],
            'context_sha256': sha(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()),
            'transport_sha256': file_sha(target), 'transport_size_bytes': target.stat().st_size}


def prepare(lock, cache, output):
    if lock.get('schema_version') != 1 or lock.get('state') != 'frozen' or output.exists():
        raise ValueError('provider preparation requires a frozen lock and a new output')
    inputs = {name: verified(cache / name, item['sha256'], item['size_bytes']) for name, item in lock['downloads'].items()}
    # The Apple installer was already acquired as an exact frozen input.
    output.mkdir(parents=True, mode=0o700)
    records, evidence = {}, {}
    with tempfile.TemporaryDirectory(prefix='ud-provider-build-', dir=output.parent) as temporary:
        work = Path(temporary)
        apple = lock['apple_container']
        expanded = work / 'apple'
        command(['/usr/sbin/pkgutil', '--expand-full', str(inputs[apple['package']]), str(expanded)])
        package_signature = command(['/usr/sbin/pkgutil', '--check-signature', str(inputs[apple['package']])])
        payload = expanded / 'Payload'
        destination = output / 'runtime/providers/apple-container/darwin-arm64'
        signatures = []
        for source in sorted(payload.rglob('*')):
            if source.is_symlink():
                raise ValueError('Apple payload contains a link')
            if source.is_file():
                copy_regular(source, destination / source.relative_to(payload))
                if source.open('rb').read(4) == b'\xcf\xfa\xed\xfe':
                    command(['/usr/bin/codesign', '--verify', '--strict', str(source)])
                    signatures.append(source.relative_to(payload).as_posix())
        executable = destination / 'bin/container'
        for name in ['apple-LICENSE.txt', 'apple-NOTICE.md', 'linux-GPL-2.0.txt']:
            copy_regular(inputs[name], destination / name)
        details = command(['/usr/bin/codesign', '-d', '--verbose=4', str(executable)]).stderr.decode()
        if f"TeamIdentifier={apple['publisher_team_id']}\n" not in details or f"Identifier={apple['signing_identifier']}\n" not in details:
            raise ValueError('Apple publisher identity differs')
        kernel = destination / 'kernel/vmlinux'
        extract_kernel(inputs[apple['kernel']['archive']], apple['kernel']['member'], kernel)
        init = prepare_init(lock, cache, output)
        records['apple-container/darwin/arm64'] = {'schema_version': 1, 'executable_sha256': file_sha(executable), 'kernel': {'path': kernel.relative_to(output).as_posix(), 'sha256': file_sha(kernel)}, 'init_image': init}
        evidence['apple-container/darwin/arm64'] = {'init_source': apple['init_image'], 'init_transformation': {'kind': 'normalize-oci-diff-id', 'preserved_layer_digest': 'sha256:03ccd1183364cde222f8302d0db0d6fa270ba07d31c32c24a1dbb1f50bd508db', 'derived_manifest_digest': init['digest'], 'derived_config_digest': init['config_digest'], 'derived_diff_ids': init['diff_ids'], 'reference': init['reference']}, 'package_signature': package_signature.stdout.decode(), 'codesign_verified_files': signatures, 'publisher_team_id': apple['publisher_team_id'], 'native_probe': {'status': 'pending_native', 'reason': 'provider VM execution has not run'}}
        engine_lock = {'schema_version': 1, 'state': 'frozen', 'engines': {'apple-container': {'darwin/arm64': {'version': apple['version'], 'binary_sha256': file_sha(executable), 'publisher_team_id': apple['publisher_team_id'], 'signing_identifier': apple['signing_identifier']}}}}
        (output / 'runtime/engine-distributions.lock.json').write_text(json.dumps(engine_lock, indent=2) + '\n')
        # These are documented Windows OS/WSL prerequisite DLLs, not copied
        # from an ambient DLL search path or misrepresented as owned assets.
        wsl_system = {'computecore.dll', 'computenetwork.dll', 'icu.dll', 'msi.dll', 'virtdisk.dll'}
        with zipfile.ZipFile(inputs[lock['wslc']['sdk']]) as sdk:
            for architecture, selected in lock['wslc']['architectures'].items():
                extracted = work / ('wsl-' + architecture)
                extracted.mkdir()
                command(['docker', 'run', '--rm', '--pull=never', '--network', 'none', '--read-only', '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,nosuid,nodev,size=536870912', '--mount', f'type=bind,source={cache},target=/input,readonly', '--mount', f'type=bind,source={extracted},target=/output', lock['wslc']['extractor_image'], '-C', '/output', '/input/' + selected['installer']])
                destination = output / ('runtime/providers/wslc/win32-' + architecture)
                binary = destination / 'bin/wslc.exe'
                copy_regular(extracted / 'PFiles64/WSL/wslc.exe', binary)
                sdk_file = destination / 'bin/wslcsdk.dll'
                sdk_file.write_bytes(safe_zip_member(sdk, f'runtimes/win-{architecture}/native/wslcsdk.dll'))
                (destination / 'NOTICE.txt').write_bytes(safe_zip_member(sdk, 'NOTICE.txt'))
                copy_regular(inputs['wsl-LICENSE.txt'], destination / 'LICENSE.txt')
                copy_regular(extracted / 'PFiles64/WSL/NOTICE.txt', destination / 'WSL-NOTICE.txt')
                (destination / 'include').mkdir()
                (destination / 'include/wslcsdk.h').write_bytes(safe_zip_member(sdk, 'include/wslcsdk.h'))
                closure = [dict(path=item.relative_to(output).as_posix(), **inspect_pe(item.read_bytes(), architecture)) for item in (binary, sdk_file)]
                if any(not system_dll(name) and name not in wsl_system for item in closure for name in item['imports']):
                    raise ValueError('WSLc has an unresolved private DLL import')
                records['wslc/win32/' + architecture] = {'schema_version': 1, 'executable_sha256': file_sha(binary), 'sdk': sdk_file.relative_to(output).as_posix(), 'sdk_sha256': file_sha(sdk_file)}
                evidence['wslc/win32/' + architecture] = {'pe_closure': closure, 'os_prerequisite_imports': sorted(wsl_system), 'native_probe': {'status': 'pending_native', 'reason': 'Windows service, Authenticode and VM execution require native Windows'}}
    files = [{'path': item.relative_to(output).as_posix(), 'size_bytes': item.stat().st_size, 'sha256': file_sha(item)} for item in sorted(output.rglob('*')) if item.is_file()]
    result = {'schema_version': 1, 'qualification': 'locally_prepared_unaccepted', 'inputs_sha256': sha(json.dumps(lock, sort_keys=True, separators=(',', ':')).encode()), 'provider_receipts': records, 'evidence': evidence, 'files': files}
    (output / 'provider-receipts.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=ROOT / '.artifacts/provider-assets/cache')
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    result = prepare(json.loads((ROOT / 'runtime/provider-assets.lock.json').read_text()), arguments.cache.resolve(strict=True), arguments.output.resolve())
    print(json.dumps({'provider_receipts': list(result['provider_receipts']), 'files': len(result['files'])}))
