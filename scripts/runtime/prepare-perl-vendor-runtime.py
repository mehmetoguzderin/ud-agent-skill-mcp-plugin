#!/usr/bin/env python3
"""Remove VC DLL payloads from distributable Perl and bind vendor-direct setup."""
from __future__ import annotations
import argparse
from compression.zstd import ZstdFile
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_vendor_runtime_builder', ROOT / 'workers/ud/src/ud_agent/vendor_runtime.py')
vendor = importlib.util.module_from_spec(spec); spec.loader.exec_module(vendor)


def fingerprint(file): return hashlib.sha256(file.read_bytes()).hexdigest()


def supplier_inventory(archive, provider, platform):
    descriptor = {'url': provider['url'], 'sha256': provider['sha256'].removeprefix('sha256:'), 'size_bytes': provider['size_bytes']}
    source, _ = vendor.verified_archive(archive, descriptor)
    prefix = 'Library/' if platform == 'win32/arm64' else ''
    members = {}
    with source:
        for tar, member in vendor.archive_members(source, bzip2=platform == 'win32/arm64'):
            name = vendor.validate_path(member.name)
            if not name.startswith(prefix):
                continue
            relative = name.removeprefix(prefix)
            if not re.fullmatch(r'(?:bin|lib)/.+\.(?:dll|exe|lib)', relative, re.I):
                continue
            if relative in members or not member.isfile() or not 0 < member.size <= vendor.MAX_FILE:
                raise ValueError('Perl supplier binary inventory is invalid')
            with tar.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            members[relative] = {'source': name, 'path': relative, 'sha256': digest, 'size_bytes': member.size}
    if 'bin/perl.exe' not in members:
        raise ValueError('Perl supplier executable is missing')
    return descriptor, members


def prepare(pack, receipt_file, archive, output, lock_file=ROOT / 'runtime/windows-perl-distributions.lock.json', supplier_archive=None):
    if output.exists() or output.is_symlink(): raise ValueError('new deferred Perl output required')
    original = json.loads(receipt_file.read_bytes()); platform = original['platform']
    if platform not in ('win32/arm64', 'win32/x64'): raise ValueError('Windows Perl receipt required')
    lock = json.loads(lock_file.read_bytes()); selected = lock['platforms'][platform.split('/')[1]]; providers = selected['redistributables']
    if len(providers) != 1: raise ValueError('one exact vendor dependency required')
    provider = providers[0]; vendor.verify(archive, {'sha256': provider['sha256'].removeprefix('sha256:'), 'size_bytes': provider['size_bytes']})
    recipe = {'schema_version': 1, 'provider': 'conda-vc-runtime', 'platform': platform, 'version': provider['version'], 'executable': 'bin/perl.exe', 'archive': {'url': provider['url'], 'sha256': provider['sha256'].removeprefix('sha256:'), 'size_bytes': provider['size_bytes']}, 'base_files': [], 'files': [], 'declaration': {'mode': 'vendor-direct-private-acquisition', 'redistribution_authority': 'not-asserted', 'installer_execution': False, 'license_acceptance_automation': False, 'documentation': ['https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170', 'https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist/']}}
    supplier = {}
    if supplier_archive is not None:
        descriptor, supplier = supplier_inventory(supplier_archive, selected['perl'], platform)
        recipe['supplier'] = {'archive': descriptor, 'files': []}
    output.mkdir(parents=True); removed = []
    try:
        seen = set()
        for row in original['files']:
            name = vendor.validate_path(row['path']); key = vendor.path_key(name)
            if key in seen: raise ValueError('Perl base inventory collision')
            seen.add(key); source = vendor.regular(pack, name)
            record = {'sha256': row['sha256'].removeprefix('sha256:'), 'size_bytes': row['size']}; vendor.verify(source, record)
            if re.fullmatch(r'vcruntime[0-9_a-z]*\.dll', source.name, re.I): removed.append({'path': name, **record}); continue
            if name in supplier:
                supplied = supplier[name]
                if any(supplied[key] != value for key, value in record.items()):
                    raise ValueError('Perl supplier binary differs from the build receipt: ' + name)
                # Import libraries are only used while building XS.
                if not name.lower().endswith('.lib'):
                    recipe['supplier']['files'].append(supplied)
                continue
            target = output / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
            target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
            selected_base = name.startswith(('bin/', 'lib/')) if supplier else name.startswith('bin/') and name.endswith(('.exe', '.dll'))
            if selected_base:
                recipe['base_files'].append({'source': name, 'path': name, **record})
        if not removed or not recipe['base_files']: raise ValueError('provider bytes not found in exact Perl inventory')
        if supplier:
            expected = {name for name in supplier if not name.lower().endswith('.lib')}
            if {row['path'] for row in recipe['supplier']['files']} != expected:
                raise ValueError('Perl supplier binaries do not match the closed runtime')
            recipe['supplier']['files'].sort(key=lambda row: row['path'])
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                if not re.fullmatch(r'(?:pkg|info)-[A-Za-z0-9_.-]+\.tar\.zst', item.filename): continue
                with bundle.open(item) as compressed, ZstdFile(compressed) as expanded, tarfile.open(fileobj=expanded, mode='r|') as tar:
                    for member in tar:
                        required_dll = member.name.startswith('Library/bin/') and any(member.name.rsplit('/', 1)[-1].lower() == row['path'].rsplit('/', 1)[-1].lower() for row in removed)
                        if required_dll or member.name.startswith('info/licenses/'):
                            if not member.isfile() or member.size > 32 * 1024 ** 2: raise ValueError('vendor selected file is unsafe')
                            body = tar.extractfile(member).read(member.size + 1)
                            destination = 'bin/' + member.name.rsplit('/', 1)[-1] if member.name.startswith('Library/') else 'licenses/vendor/' + member.name.removeprefix('info/licenses/')
                            recipe['files'].append({'source': member.name, 'path': destination, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)})
        recipe['files'].sort(key=lambda row: row['path']); recipe['base_files'].sort(key=lambda row: row['path'])
        (output / 'vendor-runtime.json').write_text(json.dumps(recipe, indent=2) + '\n')
        result = {**original, 'deferred_runtime': {'provider': 'conda-vc-runtime', 'recipe': 'vendor-runtime.json'}, 'vendor_runtime_removed': removed, 'original_receipt_sha256': fingerprint(receipt_file), 'vendor_lock_sha256': fingerprint(lock_file), 'files': []}
        if supplier:
            result['vendor_supplier_removed'] = [{key: row[key] for key in ('path', 'sha256', 'size_bytes')} for row in recipe['supplier']['files']]
        for file in sorted(output.rglob('*')):
            if file.is_file(): result['files'].append({'path': file.relative_to(output).as_posix(), 'sha256': 'sha256:' + fingerprint(file), 'size': file.stat().st_size})
        receipt = output.with_name(output.name + '-receipt.json'); receipt.write_text(json.dumps(result, indent=2) + '\n'); return result
    except BaseException: shutil.rmtree(output); raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('pack', 'receipt', 'archive', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--supplier-archive', type=Path)
    args = parser.parse_args(); result = prepare(args.pack, args.receipt, args.archive, args.output, supplier_archive=args.supplier_archive); print(json.dumps({'platform': result['platform'], 'files': len(result['files']), 'deferred': result['deferred_runtime'], 'removed_vendor_payloads': len(result['vendor_runtime_removed']) + len(result.get('vendor_supplier_removed', []))}))
