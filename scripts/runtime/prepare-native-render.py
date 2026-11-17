#!/usr/bin/env python3
"""Build an offline native browser/font pack from exact publisher receipts."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_native_render_fonts', Path(__file__).with_name('render_manifest.py'))
font_manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(font_manifest)

_path_spec = importlib.util.spec_from_file_location('ud_native_render_paths', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
_paths = importlib.util.module_from_spec(_path_spec)
_path_spec.loader.exec_module(_paths)
path_key, validate_path = _paths.path_key, _paths.validate_path


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def safe_name(name):
    return validate_path(name)


def prepare(root, record, archive, output, transport, linux_closure=None):
    edge = record.get('provider') == 'microsoft-edge' and record.get('platform') == 'win32/arm64'
    if record.get('schema_version') != 1 or not edge and (record.get('state') != 'frozen-inputs' or record.get('platform') not in ('darwin/arm64', 'darwin/x64', 'linux/arm64', 'linux/x64', 'win32/x64')):
        raise ValueError('native browser publisher receipt is invalid')
    platforms = {'darwin/arm64': 'mac-arm64', 'darwin/x64': 'mac-x64', 'linux/arm64': 'linux-arm64', 'linux/x64': 'linux64', 'win32/x64': 'win64'}
    slug = None if edge else platforms[record['platform']]
    source = record['archive'] if edge else record
    expected_url = source['url'] if edge else f"https://storage.googleapis.com/chrome-for-testing-public/{record['version']}/{slug}/chrome-headless-shell-{slug}.zip"
    if (edge and not re.fullmatch(r'https://msedge\.sf\.dl\.delivery\.mp\.microsoft\.com/filestreamingservice/files/[a-f0-9-]+/MicrosoftEdgeEnterpriseARM64\.msi', source.get('url', ''))
            or source.get('url') != expected_url or not re.fullmatch(r'[a-f0-9]{64}', source.get('sha256', '')) or archive.is_symlink() or not archive.is_file() or archive.stat().st_size != source['size_bytes'] or digest(archive) != source['sha256']):
        raise ValueError('native browser archive differs from its fixed publisher receipt')
    if output.exists() or output.is_symlink() or transport.exists() or transport.is_symlink():
        raise ValueError('native render output and transport must be new')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-render-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'pack'
        stage.mkdir()
        if edge:
            decoder = root / '.artifacts/native-decoder/windows-arm64/7zdec.exe'
            if decoder.is_symlink() or not decoder.is_file() or decoder.stat().st_size != record['decoder']['size_bytes'] or digest(decoder) != record['decoder']['sha256']:
                raise ValueError('native Edge decoder differs from its source-built receipt')
            (stage / 'decoder').mkdir()
            (stage / 'decoder/7zdec.exe').write_bytes(decoder.read_bytes())
            (stage / 'decoder/7zdec.exe').chmod(0o555)
            (stage / 'licenses').mkdir()
            for name in ['7zip-License.txt', 'LGPL-2.1.txt', 'Zig-MIT.txt', 'LLVM-libcxx.txt', 'LLVM-libcxxabi.txt', 'LLVM-libunwind.txt', 'mingw-w64-COPYING.txt']:
                (stage / 'licenses' / name).write_bytes((root / 'licenses' / name).read_bytes())
            # Accompany the standalone LGPL executable with its exact complete
            # source and our reproducible recipe, rather than an external offer.
            (stage / 'decoder/7z2606-src.tar.xz').write_bytes((root / 'runtime/sources/7z2606-src.tar.xz').read_bytes())
            (stage / 'decoder/build-native-decoder.py').write_bytes((root / 'scripts/runtime/build-native-decoder.py').read_bytes())
            (stage / 'decoder/native-decoder.lock.json').write_bytes((root / 'runtime/native-decoder.lock.json').read_bytes())
            (stage / 'windows-browser-recipe.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
        else:
            vendor_spec = importlib.util.spec_from_file_location('ud_native_render_vendor', root / 'workers/ud/src/ud_agent/vendor_browser.py')
            vendor = importlib.util.module_from_spec(vendor_spec)
            vendor_spec.loader.exec_module(vendor)
            with zipfile.ZipFile(archive) as bundle:
                inventory = vendor.ClosedZip(bundle, 'chrome-headless-shell-' + slug).inventory
            executable_name = 'chrome-headless-shell' + ('.exe' if record['platform'].startswith('win32/') else '')
            if executable_name not in {item['path'] for item in inventory}:
                raise ValueError('native browser executable is missing from publisher inventory')
            recipe = {'schema_version': 1, 'provider': vendor.PROVIDER, 'platform': record['platform'], 'version': record['version'],
                      'archive': {'url': record['url'], 'sha256': record['sha256'], 'size_bytes': record['size_bytes']},
                      'source_root': 'chrome-headless-shell-' + slug, 'files': inventory}
            if record['platform'].startswith('linux/'):
                if linux_closure is None:
                    raise ValueError('native Linux browser needs a verified private OS dependency closure')
                closure_record = json.loads(linux_closure.read_text())
                if closure_record.get('schema_version') != 1 or closure_record.get('platform') != record['platform']:
                    raise ValueError('native browser closure platform differs')
                closure_root = root / safe_name(closure_record['root'])
                closure_inventory = {}
                for item in closure_record['files']:
                    name = safe_name(item['path'])
                    file = closure_root / name
                    if name in closure_inventory or file.is_symlink() or not file.is_file() or file.stat().st_size != item['size'] or 'sha256:' + digest(file) != item['sha256']:
                        raise ValueError('native browser closure differs from its exact receipt')
                    closure_inventory[name] = item
                actual = {file.relative_to(closure_root).as_posix() for file in closure_root.rglob('*') if file.is_file()}
                if actual != set(closure_inventory):
                    raise ValueError('native browser closure inventory is not closed')
                closure = json.loads((closure_root / 'elf-closure.json').read_text())
                if any(not isinstance(origin, dict) or 'image_path' not in origin or 'browser_path' in origin for origin in closure['libraries'].values()):
                    raise ValueError('native OS library closure contains vendor browser bytes')
                original_manifest = json.loads((closure_root / 'manifest.json').read_text())
                recipe['linux_loader'] = {**original_manifest['loader'], 'materialization': 'elf-interpreter-v1'}
                for name in closure_inventory:
                    if name.startswith('elf/') or name.startswith('licenses/oci/') or name == 'elf-closure.json':
                        target = stage / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(closure_root / name, target)
                        target.chmod(0o555 if (closure_root / name).stat().st_mode & 0o111 else 0o444)
                (stage / 'fontconfig').mkdir()
                (stage / 'fontconfig/fonts.conf').write_text('<?xml version="1.0"?>\n<fontconfig><dir prefix="relative">../fonts</dir><cachedir prefix="xdg">fontconfig</cachedir><config><rescan><int>0</int></rescan></config></fontconfig>\n')
                for name in [recipe['linux_loader']['executable'], *closure['libraries']]:
                    if name not in closure_inventory or not (stage / name).is_file():
                        raise ValueError('native OS library closure omitted a required file')
            # Published base packs carry fonts, OS libraries and an exact vendor
            # acquisition recipe. Google-branded browser bytes come directly
            # from the publisher at setup time and are never redistributed here.
            (stage / 'vendor-browser-recipe.json').write_text(json.dumps(recipe, sort_keys=True, indent=2) + '\n')
        render_lock = json.loads((root / 'runtime/render-deps.lock.json').read_text())
        font_receipts = []
        # Architecture-independent Noto data is the same verified closure used
        # by OCI render workers. Native browsers use the pack's explicit fonts.
        for package in render_lock['debian']['architectures']['arm64']['packages']:
            if not package['name'].startswith('fonts-noto-'):
                continue
            deb = root / '.artifacts/render-debs/arm64/debs' / package['file']
            if deb.is_symlink() or not deb.is_file() or deb.stat().st_size != package['size'] or digest(deb) != package['sha256']:
                raise ValueError('native render font package differs from its verified lock')
            listed = subprocess.check_output(['ar', 't', str(deb)], text=True).splitlines()
            data_members = [name for name in listed if re.fullmatch(r'data\.tar(?:\.(?:xz|gz|zst|bz2))?', name)]
            if len(data_members) != 1:
                raise ValueError('native font package has an invalid data archive')
            data = subprocess.check_output(['ar', 'p', str(deb), data_members[0]], timeout=30)
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as source:
                for member in source:
                    logical = member.name.removeprefix('./')
                    if not (logical.startswith('usr/share/fonts/') or logical.startswith('usr/share/doc/' + package['name'] + '/copyright')) or member.isdir():
                        continue
                    safe_name(logical)
                    if not member.isfile() or member.size > 64 * 1024 * 1024:
                        raise ValueError('native font package has an unsafe member')
                    target = stage / ('fonts/' + logical[len('usr/share/fonts/'):] if logical.startswith('usr/share/fonts/') else 'licenses/' + package['name'] + '-copyright')
                    if target.exists():
                        raise ValueError('native render font asset is duplicated')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.extractfile(member).read(member.size + 1))
                    target.chmod(0o444)
            font_receipts.append(package)
        (stage / 'dependency-lock.json').write_text(json.dumps({'browser': record, 'fonts': font_receipts}, sort_keys=True, indent=2) + '\n')
        executable = 'browser/msedge.exe' if edge else 'browser/chrome-headless-shell' + ('.exe' if record['platform'].startswith('win32/') else '')
        fonts = font_manifest.pinned_fonts(stage / 'fonts', stage / 'fonts/generated/NotoSansCJK-Regular.otf')
        files = [{'path': path.relative_to(stage).as_posix(), 'sha256': digest(path), 'size_bytes': path.stat().st_size} for path in sorted(stage.rglob('*')) if path.is_file()]
        manifest = {'schema_version': 1, 'executable': executable, 'files': files, 'fonts': [path.relative_to(stage).as_posix() for path in fonts]}
        if record['platform'].startswith('linux/'):
            manifest['fontconfig'] = 'fontconfig/fonts.conf'
        if edge:
            manifest['deferred_browser'] = {'provider': 'microsoft-edge', 'recipe': 'windows-browser-recipe.json', 'decoder': 'decoder/7zdec.exe', 'directory': 'browser'}
        else:
            manifest['deferred_browser'] = {'provider': vendor.PROVIDER, 'recipe': 'vendor-browser-recipe.json', 'directory': 'browser'}
        (stage / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        (stage / 'manifest.json').chmod(0o444)
        transport.parent.mkdir(parents=True, exist_ok=True)
        with transport.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as zipped, tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as target:
            for path in sorted(stage.rglob('*')):
                if not path.is_file():
                    continue
                info = target.gettarinfo(str(path), arcname=path.relative_to(stage).as_posix())
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                with path.open('rb') as source:
                    target.addfile(info, source)
        os.rename(stage, output)
    return {'schema_version': 1, 'state': 'frozen-inputs', 'platform': record['platform'], 'root': output.relative_to(root).as_posix(), 'manifest': 'manifest.json', 'files': [{'path': path.relative_to(output).as_posix(), 'sha256': 'sha256:' + digest(path), 'size': path.stat().st_size} for path in sorted(output.rglob('*')) if path.is_file()], 'transport': {'path': transport.relative_to(root).as_posix(), 'sha256': 'sha256:' + digest(transport), 'size': transport.stat().st_size}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--transport', type=Path, required=True)
    parser.add_argument('--linux-closure', type=Path, help='verified native Linux OS/ELF closure receipt')
    args = parser.parse_args()
    result = prepare(ROOT, json.loads(args.receipt.read_text()), args.archive, args.output.resolve(), args.transport.resolve(), args.linux_closure)
    (args.output.parent / (args.output.name + '-receipt.json')).write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'platform': result['platform'], 'files': len(result['files']), 'transport': result['transport']}))


if __name__ == '__main__':
    main()
