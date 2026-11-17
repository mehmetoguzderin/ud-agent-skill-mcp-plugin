#!/usr/bin/env python3
"""Cross-build the pinned 7-Zip standalone decoder with native long-path APIs."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def build(archive: Path, compiler: Path, output: Path, target: str):
    lock = json.loads((ROOT / 'runtime/native-decoder.lock.json').read_text())
    raw = archive.read_bytes()
    if archive.is_symlink() or len(raw) != lock['source']['size_bytes'] or hashlib.sha256(raw).hexdigest() != lock['source']['sha256']:
        raise ValueError('decoder source differs from its pinned receipt')
    if output.exists() or output.is_symlink() or target not in ('aarch64-windows-gnu', 'native'):
        raise ValueError('decoder target must be new and supported')
    version = subprocess.check_output([str(compiler), 'version'], text=True, timeout=10).strip()
    if compiler.is_symlink() or version != lock['compiler']['version']:
        raise ValueError('decoder compiler differs from its frozen toolchain')
    compiler_sha = hashlib.sha256(compiler.read_bytes()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-decoder-', dir=output.parent) as temporary:
        root = Path(temporary)
        with tarfile.open(archive) as source:
            for member in source:
                name = Path(member.name)
                if member.name in ('.', './'): continue
                if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()) or member.size > 16 * 1024**2:
                    raise ValueError('decoder source has an unsafe member')
                source.extract(member, root, filter='data')
        # Alone7z contains the 7z/LZMA/BCJ decoders; no RAR/unRAR objects are linked.
        bundle = root / 'CPP/7zip/Bundles/Alone7z'
        if not bundle.is_dir() or b'#define Z7_LONG_PATH 1' not in (root / 'C/Precomp.h').read_bytes():
            raise ValueError('decoder long-path source closure is incomplete')
        objects = root / 'objects'; objects.mkdir()
        cc = shlex.quote(str(compiler))
        target_flags = '' if target == 'native' else ' -target ' + target
        args = ['/usr/bin/make', '-f', 'makefile.gcc', '-j2', 'ST_MODE=1', 'O=' + str(objects),
                'CC=' + cc + ' cc' + target_flags, 'CXX=' + cc + ' c++' + target_flags,
                'MY_ARCH=', 'FLAGS_FLTO=', 'CFLAGS_WARN=-ffile-prefix-map=' + str(root) + '=/usr/src/7zip']
        if target != 'native':
            args += ['IS_MINGW=1', 'SYS_OBJS=' + ' '.join(str(objects / (name + '.o')) for name in ['FileSystem', 'Registry', 'MemoryLock', 'DLL', 'DllSecur'])]
        environment = {'PATH': '/usr/bin:/bin', 'ZIG_GLOBAL_CACHE_DIR': str(ROOT / '.artifacts/zig-cache'), 'SOURCE_DATE_EPOCH': '0', 'ZERO_AR_DATE': '1', 'LANG': 'C'}
        result = subprocess.run(args, cwd=bundle, capture_output=True, text=True, timeout=600, env=environment, check=False)
        if result.returncode != 0:
            raise RuntimeError('native decoder cross-build failed: ' + result.stderr[-4096:])
        binary = objects / ('7zr.exe' if target != 'native' else '7zr')
        data = binary.read_bytes()
        if target != 'native':
            nt = struct.unpack_from('<I', data, 60)[0]
            if data[:2] != b'MZ' or data[nt:nt + 4] != b'PE\0\0' or struct.unpack_from('<H', data, nt + 4)[0] != 0xaa64:
                raise ValueError('decoder cross-build produced the wrong architecture')
        with output.open('xb') as destination: destination.write(data)
        output.chmod(0o555)
    return {'schema_version': 1, 'source': lock['source'], 'target': target, 'compiler': {'name': 'Zig', 'version': version, 'sha256': compiler_sha}, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data), 'license': lock['license'], 'build_profile': 'Alone7z/ST_MODE/Unicode/long-path/no-RAR'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--target', choices=['aarch64-windows-gnu', 'native'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = build(ROOT / 'runtime/sources/7z2606-src.tar.xz', args.compiler.resolve(strict=True), args.output.resolve(), args.target)
    args.output.with_suffix(args.output.suffix + '.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__': main()
