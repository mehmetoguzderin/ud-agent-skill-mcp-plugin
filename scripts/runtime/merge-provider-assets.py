#!/usr/bin/env python3
"""Merge verified disjoint provider closures before lazy transport generation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_merge_provider_paths', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paths)


def digest(file):
    with file.open('rb') as source:
        return 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest()


def merge(sources, output):
    roots = [source.resolve(strict=True) for source in sources]
    output = output.resolve()
    if len(roots) < 2 or len(set(roots)) != len(roots) or output.exists() or any(output.is_relative_to(root) for root in roots):
        raise ValueError('provider merge requires disjoint sources and a new separate output')
    providers, files, origins, selected, portable = {}, {}, [], {}, set()
    for root in roots:
        manifest = root / 'provider-receipts.json'
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 16 * 1024**2:
            raise ValueError('provider merge receipt is not a bounded ordinary file')
        value = json.loads(manifest.read_bytes())
        if value.get('schema_version') != 1 or not isinstance(value.get('provider_receipts'), dict) or not value['provider_receipts'] or not isinstance(value.get('files'), list) or not value['files']:
            raise ValueError('provider merge source is incomplete')
        for name, record in value['provider_receipts'].items():
            parts = name.split('/')
            if len(parts) != 3 or parts[0] not in ('apple-container', 'wslc', 'lima-nerdctl') or parts[1] not in ('darwin', 'win32', 'linux') or parts[2] not in ('arm64', 'x64') or name in providers or not isinstance(record, dict):
                raise ValueError('provider merge identity is duplicate or unsupported')
            providers[name] = record
        for item in value['files']:
            name = item['path']
            paths.validate_path(name)
            key = paths.path_key(name)
            if key in portable or len(portable) >= 50000:
                raise ValueError('provider merge file collision')
            portable.add(key)
            file = root / name
            # Every parent is inspected; an ordinary leaf cannot authorize
            # reading through a substituted directory link.
            parent = root
            for part in Path(name).parts[:-1]:
                parent /= part
                if parent.is_symlink() or not parent.is_dir():
                    raise ValueError('provider merge parent is not an ordinary directory')
            if file.is_symlink() or not file.is_file() or file.stat().st_size != item['size_bytes'] or digest(file) != item['sha256']:
                raise ValueError('provider merge source bytes differ')
            files[name] = item
            selected[name] = file
        origins.append({'receipt_sha256': digest(manifest), 'providers': sorted(value['provider_receipts'])})
    output.mkdir(parents=True, mode=0o700)
    marker = output / 'INCOMPLETE'
    marker.write_text('Provider merge has not completed.\n')
    for name, source in sorted(selected.items()):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o555 if source.stat().st_mode & 0o111 else 0o444)
        if target.stat().st_size != files[name]['size_bytes'] or digest(target) != files[name]['sha256']:
            raise ValueError('provider source changed during merge')
    result = {'schema_version': 1, 'qualification': 'verified-provider-assets-only; execution evidence is separate', 'provider_receipts': providers, 'files': [files[name] for name in sorted(files)], 'origins': origins, 'builder_sha256': digest(Path(__file__))}
    (output / 'provider-receipts.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    marker.unlink()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', action='append', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = merge(args.assets, args.output)
    print(json.dumps({'providers': sorted(result['provider_receipts']), 'files': len(result['files'])}))
