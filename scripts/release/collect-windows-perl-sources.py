#!/usr/bin/env python3
"""Retain the exact Windows Perl source, provider patches and build recipes."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
acquisition = module('ud_windows_sources_acquisition', Path(__file__).with_name('collect-debian-sources.py'))
notices = module('ud_windows_sources_notices', Path(__file__).with_name('collect-locked-sources.py'))
windows = module('ud_windows_sources_reader', ROOT / 'scripts/runtime/prepare-windows-perl.py')


def collect(root, output, xs_receipts=()):
    output.mkdir(parents=True, exist_ok=True); lock = json.loads((root / 'runtime/windows-perl-distributions.lock.json').read_bytes()); files = []; providers = []
    upstream = {'family': 'perl', 'name': 'perl-5.44.0-windows-provider-source', 'version': '5.44.0', 'url': 'https://www.cpan.org/src/5.0/perl-5.44.0.tar.xz', 'sha256': '505cf43912e9480495c344c70260452e32aa2a73c546a026b3f100053b23ce91'}
    source = output / 'blobs' / upstream['sha256']; acquisition.acquire(upstream['url'], source, sha256=upstream['sha256'], maximum=64 * 1024 ** 2)
    files.append({**upstream, 'path': source.relative_to(output).as_posix(), 'size_bytes': source.stat().st_size, 'notice_files': notices.source_notices(source)})
    for architecture, selected in lock['platforms'].items():
        provider = selected['perl']; archive = windows.verified(root / '.artifacts/native-perl/cache/windows' / provider['filename'], provider); selected_files = []
        for tar, member in windows.entries(archive):
            name = member.name
            if not (name.startswith('info/recipe/') or name in ('info/about.json', 'info/hash_input.json', 'info/index.json')): continue
            windows.PurePosixPath(name)
            if not member.isfile() or member.size > 8 * 1024 ** 2 or name.startswith('/') or '\\' in name or any(part in ('', '.', '..') for part in name.split('/')): raise ValueError('provider recipe member is not bounded ordinary data')
            body = tar.extractfile(member).read(member.size + 1)
            if len(body) != member.size: raise ValueError('provider recipe member is truncated')
            fingerprint = hashlib.sha256(body).hexdigest(); file = output / 'blobs' / fingerprint; file.parent.mkdir(exist_ok=True)
            if file.exists() and file.read_bytes() != body: raise ValueError('source recipe digest conflict')
            file.write_bytes(body); files.append({'family': 'windows-perl-provider-recipe', 'name': name, 'version': provider['version'], 'platform': 'win32/' + architecture, 'path': file.relative_to(output).as_posix(), 'sha256': fingerprint, 'size_bytes': len(body), 'provider_archive_sha256': provider['sha256'].removeprefix('sha256:')}); selected_files.append({'source_path': name, 'sha256': fingerprint, 'size_bytes': len(body)})
        if not selected_files: raise ValueError('provider archive omits its source build recipe')
        providers.append({'platform': 'win32/' + architecture, 'archive': provider, 'recipe_files': selected_files})
    xs_platforms = set()
    for receipt_file in xs_receipts:
        receipt = json.loads(receipt_file.read_bytes())
        platform = receipt['platform']
        if platform in xs_platforms or platform not in ('win32/arm64', 'win32/x64') or receipt.get('toolchain', {}).get('profile') != 'llvm-mingw-ucrt':
            raise ValueError('one open XS link receipt per native platform is required')
        xs_platforms.add(platform)
        linkage = receipt_file.parent / windows.PurePosixPath(receipt['linkage_root']).name
        maps = receipt['compiled_xs']
        if len(maps) != 9 or len({row['module'] for row in maps}) != len(maps):
            raise ValueError('open Windows link receipt does not cover all nine XS extensions')
        for row in maps:
            item = row['map']
            relative = windows.PurePosixPath(item['path'])
            if relative.is_absolute() or len(relative.parts) != 2 or '..' in relative.parts or relative.name != 'link.map':
                raise ValueError('invalid open XS link-map path')
            original = windows.verified(linkage.joinpath(*relative.parts), item)
            fingerprint = item['sha256'].removeprefix('sha256:')
            target = output / 'blobs' / fingerprint
            if not target.exists(): target.write_bytes(original.read_bytes())
            windows.verified(target, item)
            files.append({'family': 'windows-perl-open-link-map', 'name': row['module'], 'version': platform, 'path': target.relative_to(output).as_posix(), 'sha256': fingerprint, 'size_bytes': item['size_bytes']})
    report = {'schema_version': 1, 'qualification': 'exact-locked-source-subinventory', 'status': 'passed', 'target_execution': False, 'families': ['perl', 'windows-perl-provider-recipe'], 'locks': {'runtime/windows-perl-distributions.lock.json': acquisition.digest(root / 'runtime/windows-perl-distributions.lock.json')}, 'providers': providers, 'files': files, 'scope_limitation': 'Exact Perl source and provider patches/recipes; vendor VC DLLs are acquired privately and are not redistributed.'}
    (output / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n'); return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); parser.add_argument('--output', type=Path, required=True); parser.add_argument('--xs-receipt', action='append', type=Path, default=[]); args = parser.parse_args(); result = collect(args.root.resolve(), args.output, args.xs_receipt); print(json.dumps({'status': result['status'], 'files': len(result['files']), 'providers': len(result['providers'])}))
