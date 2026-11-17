#!/usr/bin/env python3
"""Join shipped Apple/WSL bytes to frozen vendor declarations and source/notices.

This is data inspection, not target execution, an installation, or a claim of a
reproduced upstream build. System services and OS frameworks remain prerequisites.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import xml.etree.ElementTree as ET
import zipfile


def insist(value, message):
    if not value:
        raise ValueError(message)


def safe(root: Path, relative: str) -> Path:
    insist(isinstance(relative, str) and relative and not re.search(r'[\\\x00:]', relative)
           and not relative.startswith('/') and all(part not in ('', '.', '..') for part in relative.split('/')), 'Unsafe provider material path')
    file = root
    for part in relative.split('/'):
        file = file / part
        insist(not file.is_symlink(), 'Linked provider material is not ordinary provenance')
    return file


def checked(root: Path, row: dict) -> Path:
    file = safe(root, row['path'])
    before = file.stat()
    insist(file.is_file() and before.st_nlink >= 1 and before.st_size == row.get('size_bytes', row.get('size')), 'Provider material size/type differs')
    with file.open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    after = file.stat()
    insist((before.st_dev, before.st_ino, before.st_size, before.st_nlink, before.st_mtime_ns, before.st_ctime_ns) ==
           (after.st_dev, after.st_ino, after.st_size, after.st_nlink, after.st_mtime_ns, after.st_ctime_ns)
           and actual == row['sha256'].removeprefix('sha256:'), 'Provider material identity/hash differs')
    return file


def receipt(file: Path, relative: str | None = None) -> dict:
    with file.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'path': relative or file.name, 'sha256': digest, 'size_bytes': file.stat().st_size}


def source_members(file: Path, suffixes: list[str]) -> dict:
    result = {}
    with tarfile.open(file, 'r:*') as archive:
        for member in archive:
            for suffix in suffixes:
                if member.name.endswith('/' + suffix):
                    insist(suffix not in result and member.isfile() and 0 <= member.size <= 4 * 1024**2, 'Source declaration is duplicate, special or oversized')
                    data = archive.extractfile(member).read(member.size + 1)
                    insist(len(data) == member.size, 'Source declaration is truncated')
                    result[suffix] = {'source_path': member.name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data), 'bytes': data}
    insist(set(result) == set(suffixes), 'Required source declaration is absent')
    return result


def sdk_declarations(file: Path, version: str) -> dict:
    names = ['Microsoft.WSL.Containers.nuspec', 'NOTICE.txt', 'include/wslcsdk.h']
    names += [f'runtimes/win-{arch}/native/wslcsdk.dll' for arch in ['arm64', 'x64']]
    result = {}
    with zipfile.ZipFile(file) as archive:
        for name in names:
            matches = [entry for entry in archive.infolist() if entry.filename == name]
            insist(len(matches) == 1 and not matches[0].is_dir() and matches[0].file_size <= 64 * 1024**2, 'SDK member is duplicate, special or oversized')
            data = archive.read(matches[0]); insist(len(data) == matches[0].file_size, 'SDK member is truncated')
            result[name] = {'member': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}
            if name.endswith('.nuspec'):
                document = ET.fromstring(data)
                def field(tag):
                    found = [element for element in document.iter() if element.tag.rsplit('}', 1)[-1] == tag]
                    insist(len(found) == 1, 'SDK declaration is ambiguous')
                    return found[0]
                insist(field('id').text == 'Microsoft.WSL.Containers' and field('version').text == version
                       and field('license').attrib == {'type': 'expression'} and field('license').text == 'MIT'
                       and field('repository').attrib.get('url') == 'https://github.com/microsoft/WSL', 'SDK license/project/version declaration differs')
    return result


def collect(provider_root: Path, source_root: Path, cache: Path, runtime_lock: dict, lock: dict, *, extracted_root: Path, binary_sources: dict, kernel_source_root: Path) -> dict:
    provider_receipt = json.loads((provider_root / 'provider-receipts.json').read_text())
    source_receipt = json.loads((source_root / 'receipt.json').read_text())
    insist(provider_receipt.get('schema_version') == source_receipt.get('schema_version') == lock.get('schema_version') == 1, 'Provider/source receipt format differs')
    wanted = {key: row for key, row in runtime_lock.get('provider_receipts', {}).items() if key.startswith(('apple-container/', 'wslc/'))}
    insist(set(wanted) == {'apple-container/darwin/arm64', 'wslc/win32/arm64', 'wslc/win32/x64'}, 'Apple/WSL frozen provider inventory is incomplete')
    sources = source_receipt['files']; source_records = {}
    releases = {(row['repository'], row['role']): row for row in binary_sources['sources']}
    wsl_source = releases[('microsoft/WSL', 'binary-release-source')]['commit']
    for name, commit, members in [
        ('apple/container', lock['apple_container']['source_commit'], ['LICENSE', 'NOTICE.md']),
        ('apple/containerization', releases[('apple/containerization', 'binary-init-release-source')]['commit'], ['LICENSE']),
        ('microsoft/WSL', wsl_source, ['LICENSE', 'NOTICE.txt', 'src/windows/wslc/CMakeLists.txt', 'src/windows/WslcSDK/CMakeLists.txt', 'src/windows/WslcSDK/wslcsdk.h', 'nuget/Microsoft.WSL.Containers.nuspec.in'])]:
        rows = [row for row in sources if row.get('name') == name and row.get('version') == commit]
        insist(len(rows) <= 1, 'Exact declared upstream source is ambiguous')
        if rows:
            row = rows[0]; file = checked(source_root, row)
            notices = [{**notice, 'verified': bool(checked(source_root, notice))} for notice in row['notices']]
        else:
            declared = releases[(name, 'binary-release-source')]
            row = {'path': 'wsl-source-' + commit + '.tar.gz', 'sha256': declared['archive_sha256'], 'size_bytes': declared['archive_size_bytes']}
            file = checked(cache, row); notices = []
        source_records[name] = {'repository': name, 'commit': commit, 'archive': {key: row[key] for key in ['path', 'sha256', 'size_bytes']}, 'notices': notices, 'members': source_members(file, members)}
    for name, row in lock['downloads'].items():
        if name in [lock['apple_container']['package'], lock['wslc']['sdk'], 'apple-LICENSE.txt', 'apple-NOTICE.md', 'wsl-LICENSE.txt'] or name in [item['installer'] for item in lock['wslc']['architectures'].values()]:
            checked(cache, {'path': name, **row})
    sdk = sdk_declarations(cache / lock['wslc']['sdk'], lock['wslc']['version'])
    with zipfile.ZipFile(cache / lock['wslc']['sdk']) as package:
        distributed_header = package.read('include/wslcsdk.h')
    original_header = source_records['microsoft/WSL']['members']['src/windows/WslcSDK/wslcsdk.h']['bytes']
    insist(original_header.replace(b'\r\n', b'\n') == distributed_header.replace(b'\r\n', b'\n'), 'SDK header differs from declared upstream source after exact newline transform')
    header_transform = {'kind': 'LF-to-CRLF-only', 'source_sha256': hashlib.sha256(original_header).hexdigest(), 'distributed_sha256': hashlib.sha256(distributed_header).hexdigest(), 'source_size_bytes': len(original_header), 'distributed_size_bytes': len(distributed_header)}
    with zipfile.ZipFile(cache / lock['wslc']['sdk']) as package:
        distributed_notice = package.read('NOTICE.txt')
    original_notice = source_records['microsoft/WSL']['members']['NOTICE.txt']['bytes']
    insist(original_notice.replace(b'\r\n', b'\n') == distributed_notice.replace(b'\r\n', b'\n'), 'SDK notice differs from exact release source notice')
    notice_transform = {'kind': 'LF-to-CRLF-only', 'source_sha256': hashlib.sha256(original_notice).hexdigest(), 'distributed_sha256': hashlib.sha256(distributed_notice).hexdigest(), 'source_size_bytes': len(original_notice), 'distributed_size_bytes': len(distributed_notice)}
    kernel_receipt = json.loads((kernel_source_root / 'receipt.json').read_text())
    insist(kernel_receipt.get('qualification') == 'pinned-apple-kernel-corresponding-source-inputs' and kernel_receipt.get('status') == 'passed', 'Kernel source/config receipt is unavailable')
    for field in ['kernel_source', 'kernel_config', 'kata_source']:
        checked(kernel_source_root, kernel_receipt[field])
    payload = {row['path']: row for row in provider_receipt['files']}
    insist(len(payload) == len(provider_receipt['files']), 'Provider payload paths are duplicated')
    joins = []
    for profile, record in sorted(wanted.items()):
        files = record.get('lazy_assets', {}).get('files')
        insist(isinstance(files, list) and files, 'Frozen selected provider lacks its exact shipped asset inventory')
        engine, platform, arch = profile.split('/')
        for row in files:
            insist(row['path'] in payload and row['sha256'] == payload[row['path']]['sha256'] and row['size_bytes'] == payload[row['path']]['size_bytes'], 'Frozen runtime/provider payload inventory differs')
            checked(provider_root, row)
            name = row['path']; item = {'profile': profile, 'shipped': row, 'target_execution': False}
            if engine == 'wslc':
                source = source_records['microsoft/WSL']; prefix = f'runtime/providers/wslc/{platform}-{arch}/'
                insist(name.startswith(prefix), 'WSL provider crosses its platform closure')
                relative = name[len(prefix):]
                if relative == 'bin/wslcsdk.dll':
                    member = sdk[f'runtimes/win-{arch}/native/wslcsdk.dll']; insist(member['sha256'] == row['sha256'].removeprefix('sha256:') and member['size_bytes'] == row['size_bytes'], 'Shipped SDK differs from exact NuGet member')
                    item['origin'] = {'artifact': lock['downloads'][lock['wslc']['sdk']], 'member': member, 'license_declaration': sdk['Microsoft.WSL.Containers.nuspec']}
                elif relative in ['include/wslcsdk.h', 'NOTICE.txt']:
                    member = sdk[relative]; insist(member['sha256'] == row['sha256'].removeprefix('sha256:'), 'Shipped SDK declaration differs')
                    item['origin'] = {'artifact': lock['downloads'][lock['wslc']['sdk']], 'member': member}
                elif relative in ['bin/wslc.exe', 'WSL-NOTICE.txt']:
                    selected = extracted_root / f'wsl-{arch}-extracted'
                    member = 'PFiles64/WSL/' + ('wslc.exe' if relative.startswith('bin/') else 'NOTICE.txt')
                    checked(selected, {'path': member, 'sha256': row['sha256'], 'size_bytes': row['size_bytes']})
                    item['origin'] = {'artifact': lock['downloads'][lock['wslc']['architectures'][arch]['installer']], 'member': member, 'extraction': 'data-only frozen MSI extraction; exact output byte join, no installer execution'}
                elif relative == 'LICENSE.txt':
                    insist(row['sha256'].removeprefix('sha256:') == source['members']['LICENSE']['sha256'], 'Shipped MIT text differs from declared source')
                else:
                    raise ValueError('Unclassified WSL shipped member: ' + name)
                item.update({'classification': 'redistributed-open-source-object-or-notice', 'declared_license': 'MIT', 'source_repository': source['repository'], 'source_commit': source['commit'], 'source_archive': source['archive'], 'notice_files': [prefix + 'LICENSE.txt', prefix + 'NOTICE.txt', prefix + 'WSL-NOTICE.txt'], 'source_relationship': 'vendor release tag declares upstream source; not a reproduced build', 'header_transform': header_transform, 'notice_transform': notice_transform})
            else:
                prefix = 'runtime/providers/apple-container/darwin-arm64/'
                if name.endswith('/linux-GPL-2.0.txt'):
                    item.update({'classification': 'redistributed-kernel-license-document', 'declared_license': 'GPL-2.0-only'})
                elif name.endswith('/kernel/vmlinux'):
                    insist(kernel_receipt['kernel_sha256'] == row['sha256'], 'Kernel corresponding source is bound to different shipped bytes')
                    item.update({'classification': 'redistributed-GPL-kernel', 'declared_license': 'GPL-2.0-only', 'origin': {'artifact': lock['downloads'][lock['apple_container']['kernel']['archive']], 'member': lock['apple_container']['kernel']['member']}, 'corresponding_source': {key: kernel_receipt[key] for key in ['kernel_source', 'kernel_config', 'kata_source']}, 'source_obligation': 'Distribute the exact kernel source, actual config, and pinned Kata build/patch archive together; signature verification remains independently replayed by source assembly'})
                elif name == 'runtime/images/init-linux-arm64.tar':
                    insist(record['init_image']['transport_sha256'] == row['sha256'] and record['init_image']['transport_size_bytes'] == row['size_bytes'], 'Apple init transport differs from runtime identity')
                    item.update({'classification': 'redistributed-derived-OCI-init', 'declared_license': 'Apache-2.0', 'origin': lock['apple_container']['init_image'], 'transformation': 'Only OCI config diffID/manifest normalization; preserved filesystem layer is verified by prepare-provider-assets.py', 'source_repository': 'apple/containerization', 'source_commit': source_records['apple/containerization']['commit'], 'source_archive': source_records['apple/containerization']['archive'], 'source_notice_receipts': source_records['apple/containerization']['notices'], 'source_obligation': 'Linked Swift/compiler/runtime dependency closure is joined independently; the exact release source alone is not a dependency inventory'})
                elif name == 'runtime/engine-distributions.lock.json':
                    item.update({'classification': 'authored-provider-metadata', 'declared_license': 'MIT'})
                else:
                    insist(name.startswith(prefix), 'Apple provider contains an unknown foreign member')
                    source = source_records['apple/container']
                    item.update({'classification': 'redistributed-open-source-object-or-notice', 'declared_license': 'Apache-2.0', 'origin': lock['downloads'][lock['apple_container']['package']], 'source_repository': source['repository'], 'source_commit': source['commit'], 'source_archive': source['archive'], 'notice_files': [prefix+'apple-LICENSE.txt', prefix+'apple-NOTICE.md'], 'source_relationship': 'signed vendor release declares upstream source; not a reproduced build'})
            joins.append(item)
    return {'schema_version': 1, 'qualification': 'exact-provider-byte-source-and-license-declaration-joins', 'target_execution': False, 'joins': joins,
            'sources': [{**row, 'members': {key: {field: value for field, value in member.items() if field != 'bytes'} for key, member in row['members'].items()}} for row in source_records.values()],
            'prerequisites_not_redistributed': {'wslc': ['Windows servicing/WSL service', 'Hyper-V/WSL containment components', 'documented Windows system DLLs; no ambient DLL copies'], 'apple-container': ['macOS frameworks and service manager', 'Apple silicon virtualization entitlement/provider availability']},
            'limits': ['A repository license does not establish an exact linked dependency inventory; third-party/compiler/runtime and GPL kernel closures are independently required.', 'Data-only MSI extraction output is joined to the frozen installer recipe; this report does not execute or authenticate Windows binaries.', 'No publisher approval, production signature or complete product/source certification is inferred.']}


def main():
    parser = argparse.ArgumentParser()
    for name in ['provider-root', 'source-root', 'vendor-cache', 'runtime-lock', 'output']:
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--kernel-source-root', type=Path, required=True)
    parser.add_argument('--binary-source-lock', type=Path, default=Path('runtime/materials/provider-binary-sources.lock.json'))
    parser.add_argument('--provider-lock', type=Path, default=Path('runtime/provider-assets.lock.json'))
    parser.add_argument('--extracted-root', type=Path, default=Path('.artifacts/provider-assets'))
    args = parser.parse_args()
    report = collect(args.provider_root, args.source_root, args.vendor_cache, json.loads(args.runtime_lock.read_text()), json.loads(args.provider_lock.read_text()), extracted_root=args.extracted_root, binary_sources=json.loads(args.binary_source_lock.read_text()), kernel_source_root=args.kernel_source_root)
    report['inputs'] = [receipt(file, str(file)) for file in [args.provider_root/'provider-receipts.json', args.source_root/'receipt.json', args.runtime_lock, args.provider_lock, args.binary_source_lock, args.kernel_source_root/'receipt.json']]
    with args.output.open('x') as output:
        output.write(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'joins': len(report['joins']), 'output': str(args.output)}))
if __name__ == '__main__':
    main()
