#!/usr/bin/env python3
"""Derive a closed Windows Perl runtime without PDB/linker-only artifacts.

The supplier/build tree is retained unchanged for source and symbol attribution.
Headers, Config/ExtUtils data, executables, DLLs and module data remain present.
This is a byte-copy/filter recipe, not a rebuild or native execution claim.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_perl_runtime_paths', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py'); paths = importlib.util.module_from_spec(spec); spec.loader.exec_module(paths)


def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(pack, receipt_file, output):
    if output.exists() or output.is_symlink() or pack.resolve() == output.resolve() or output.resolve().is_relative_to(pack.resolve()) or output.with_name(output.name + '-receipt.json').exists(): raise ValueError('new independent runtime-only Perl output required')
    original = json.loads(receipt_file.read_bytes())
    if original.get('schema_version') != 1 or original.get('platform') not in ('win32/arm64', 'win32/x64') or not original.get('files'): raise ValueError('complete Windows Perl source inventory required')
    expected = {}; folded = set()
    for row in original['files']:
        name = paths.validate_path(row['path']); key = paths.path_key(name)
        if name in expected or key in folded: raise ValueError('Windows Perl source inventory collision')
        expected[name] = row; folded.add(key); file = pack
        for part in name.split('/'):
            file /= part
            if file.is_symlink(): raise ValueError('Windows Perl source contains a link')
        if not file.is_file() or file.stat().st_size != row['size'] or 'sha256:' + sha(file) != row['sha256']: raise ValueError('Windows Perl source inventory bytes differ')
    actual = set()
    for file in pack.rglob('*'):
        if file.is_symlink() or not (file.is_file() or file.is_dir()): raise ValueError('Windows Perl source contains a linked or special entry')
        if file.is_file(): actual.add(file.relative_to(pack).as_posix())
    if actual != set(expected): raise ValueError('Windows Perl source has missing or unlisted bytes')
    removed = []; kept = []; output.mkdir(parents=True)
    try:
        for name, row in sorted(expected.items()):
            if Path(name).suffix.lower() in {'.pdb', '.lib', '.exp'}:
                removed.append(row); continue
            source = pack / name; target = output / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target); target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
            if sha(target) != row['sha256'][7:] or target.stat().st_size != row['size']: raise ValueError('runtime-only Perl copy differs')
            kept.append(row)
        if original['executable'] not in {row['path'] for row in kept}: raise ValueError('runtime-only filter removed the interpreter')
        recipe = {'kind': 'windows-runtime-build-artifact-filter', 'version': 1, 'suffixes': ['.pdb', '.lib', '.exp'], 'input_receipt_sha256': sha(receipt_file), 'generator_sha256': sha(Path(__file__)), 'removed': removed, 'headers_and_config_retained': True, 'target_execution': False, 'compiler_provenance_resolved_by_filter': False}
        result = {**original, 'runtime_only_derivation': recipe, 'files': kept}
        output.with_name(output.name + '-receipt.json').write_text(json.dumps(result, indent=2) + '\n'); return result
    except BaseException:
        shutil.rmtree(output); raise


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('pack', 'receipt', 'output'): p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args(); value = prepare(a.pack, a.receipt, a.output); print(json.dumps({'platform': value['platform'], 'files': len(value['files']), 'removed_build_artifacts': len(value['runtime_only_derivation']['removed']), 'target_execution': False}))
