#!/usr/bin/env python3
"""Prepare verified offline browser inputs; output is not a qualified image."""
from __future__ import annotations
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import perl_build
import context_timestamps

ROOT = Path(__file__).resolve().parents[2]


def prepare(root: Path, output: Path) -> dict:
    lock_path = root / 'runtime/render-deps.lock.json'
    if lock_path.is_symlink() or not lock_path.is_file():
        raise ValueError('render input lock unavailable')
    lock = json.loads(lock_path.read_text(encoding='utf-8'))
    debian = lock['debian']
    if lock.get('schema_version') != 1 or lock.get('state') != 'frozen-inputs' or lock.get('qualification') != 'unbuilt' or set(debian['architectures']) != {'arm64', 'amd64'}:
        raise ValueError('invalid render dependency lock')
    checked = {arch: perl_build._verify_debian(root, arch, config, debian['signed_by'], cache_name='render-debs') for arch, config in debian['architectures'].items()}
    if output.exists() or output.is_symlink():
        raise ValueError('render context already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.render-context-', dir=output.parent) as temporary:
        context = Path(temporary) / 'context'
        context.mkdir()
        for arch, packages in checked.items():
            target = context / 'render/debs' / arch
            target.mkdir(parents=True)
            lines = []
            for record, source in packages:
                shutil.copyfile(source, target / record['file'])
                lines.append(f"{record['sha256']}  {record['file']}")
            (target / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        shutil.copyfile(root / 'runtime/Containerfile.render', context / 'Containerfile')
        shutil.copyfile(root / 'scripts/runtime/render_manifest.py', context / 'render_manifest.py')
        shutil.copyfile(lock_path, context / 'render/dependency-lock.json')
        files = {p.relative_to(context).as_posix(): sha256(p.read_bytes()).hexdigest() for p in sorted(context.rglob('*')) if p.is_file()}
        receipt = {'schema_version': 1, 'qualification': 'unbuilt', 'release_qualified': False,
                   'render_lock_sha256': sha256(lock_path.read_bytes()).hexdigest(),
                   'packages': {arch: len(packages) for arch, packages in checked.items()}, 'files': files,
                   'limitations': ['Core image identity must be independently verified at build and acceptance.', 'Image build and browser sandbox acceptance are pending.']}
        (context / 'input-manifest.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        for entry in sorted(context.rglob('*'), reverse=True): context_timestamps.set_epoch(entry)
        context_timestamps.set_epoch(context)
        os.rename(context, output)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / '.artifacts/render-build-context')
    args = parser.parse_args()
    try:
        receipt = prepare(ROOT, args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'render build preparation failed: {error}', file=sys.stderr)
        return 1
    print(json.dumps({'output': str(args.output), 'qualification': receipt['qualification'], 'release_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
