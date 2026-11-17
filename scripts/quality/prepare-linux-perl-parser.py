#!/usr/bin/env python3
"""Assemble a frozen Linux ARM PPI closure from verified sources and existing XS."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def prepare(product, product_receipt, output, cache, lock_file=ROOT / 'quality/perl-parser.lock.json'):
    product, output = Path(product).resolve(strict=True), Path(output)
    lock = json.loads(Path(lock_file).read_text())
    native = json.loads(Path(product_receipt).read_text())
    modules = json.loads((ROOT / 'runtime/native-perl-modules.lock.json').read_text())
    if (lock.get('schema_version') != 1 or lock.get('state') != 'frozen-inputs' or lock.get('parser_release') != 'PPI-1.291'
            or native.get('platform') != 'linux/arm64' or native.get('probe', {}).get('version') != 'v5.44.0'
            or native.get('probe', {}).get('ambient_modules') is not False or native.get('probe', {}).get('ambient_elf') is not False
            or native.get('modules_sha256') != sha(canonical(modules))):
        raise ValueError('frozen native Linux ARM Perl ABI and dependency proof required')
    for name in ('Clone-0.51', 'Params-Util-1.102'):
        if modules['releases'][name]['sha256'] != lock['releases'][name]['sha256']:
            raise ValueError('parser XS source differs from private Perl source lock')
    if output.exists() or output.is_symlink():
        raise ValueError('parser output must be a new owned directory')
    archives = {}
    for name, record in lock['releases'].items():
        file = Path(cache) / (record['sha256'] + '.tar.gz')
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 64*1024**2 or sha(file.read_bytes()) != record['sha256']:
            raise ValueError('parser source cache integrity failure: ' + name)
        archives[name] = file
    inventory = {item['path']: item for item in native['files']}
    if len(inventory) != len(native['files']):
        raise ValueError('native Perl inventory contains duplicates')
    borrowed = ['lib/perl5/aarch64-linux/Clone.pm', 'lib/perl5/aarch64-linux/auto/Clone/Clone.so',
                'lib/perl5/aarch64-linux/Params/Util.pm', 'lib/perl5/aarch64-linux/Params/Util/PP.pm',
                'lib/perl5/aarch64-linux/auto/Params/Util/Util.so']
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.linux-ppi-', dir=output.parent) as temporary:
        target = Path(temporary) / 'parser'
        target.mkdir(mode=0o700)
        for name in borrowed:
            selected = product / name
            expected = inventory.get(name)
            if not expected or selected.is_symlink() or not selected.is_file() or selected.stat().st_size != expected['size'] or 'sha256:' + sha(selected.read_bytes()) != expected['sha256']:
                raise ValueError('verified native parser XS dependency is missing or changed')
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(selected, destination)
        for name, archive in archives.items():
            if name.startswith(('Clone-', 'Params-Util-')):
                continue
            seen, total, copied = set(), 0, 0
            with tarfile.open(archive, 'r:gz') as stream:
                for member in stream:
                    raw = member.name.rstrip('/')
                    parts = PurePosixPath(raw).parts
                    if not parts or parts[0] != name or raw.startswith('/') or '\\' in raw or any(part in ('', '.', '..') for part in raw.split('/')) or member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                        raise ValueError('parser source contains an unsafe archive member')
                    if raw in seen or len(seen) >= 50000:
                        raise ValueError('parser source contains duplicate or excessive members')
                    seen.add(raw)
                    if member.isdir():
                        continue
                    total += member.size
                    if member.size > 16*1024**2 or total > 128*1024**2:
                        raise ValueError('parser source exceeds its bounds')
                    if len(parts) < 3 or parts[1] != 'lib':
                        continue
                    destination = target / 'lib/perl5' / Path(*parts[2:])
                    if destination.exists():
                        raise ValueError('parser sources contain colliding installed files')
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(stream.extractfile(member).read(member.size + 1))
                    if destination.stat().st_size != member.size:
                        raise ValueError('parser source member changed while reading')
                    copied += 1
            if not copied:
                raise ValueError('parser release contains no installed library files')
        (target / 'parser-inputs.json').write_text(json.dumps({'schema_version': 1, 'platform': 'linux/arm64',
            'native_receipt_sha256': sha(Path(product_receipt).read_bytes()), 'lock_sha256': sha(canonical(lock)),
            'borrowed_xs': borrowed, 'source_archives': {name: lock['releases'][name]['sha256'] for name in archives}}, sort_keys=True, indent=2) + '\n')
        files = [{'path': file.relative_to(target).as_posix(), 'sha256': sha(file.read_bytes()), 'size': file.stat().st_size}
                 for file in sorted(target.rglob('*')) if file.is_file()]
        receipt = {'schema_version': 1, 'lock_sha256': sha(canonical(lock)), 'parser_release': lock['parser_release'], 'perl_version': 'v5.44.0', 'files': files}
        (target / 'parser-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        target.rename(output)
    return receipt

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--perl-pack', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=ROOT / '.artifacts/perl-mutation/cache')
    args = parser.parse_args()
    value = prepare(args.perl_pack, args.receipt, args.output, args.cache)
    print(json.dumps({'schema_version': 1, 'output': str(args.output), 'files': len(value['files']), 'perl_version': value['perl_version'], 'lock_sha256': value['lock_sha256']}))

if __name__ == '__main__':
    main()
