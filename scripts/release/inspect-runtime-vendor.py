#!/usr/bin/env python3
"""Read a vendor acquisition recipe from a closed verified lazy render pack."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_vendor_receipt_paths', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
paths = importlib.util.module_from_spec(spec); spec.loader.exec_module(paths)


def inspect(archive, manifest_name):
    paths.validate_path(manifest_name); files = {}; captured = {}; keys = set(); total = 0
    with tarfile.open(archive, 'r:gz') as bundle:
        for row in bundle:
            name = paths.validate_path(row.name.rstrip('/') if row.isdir() else row.name); key = paths.path_key(name)
            if key in keys or len(keys) >= 20000 or not (row.isfile() or row.isdir()) or not 0 <= row.size <= 512 * 1024 ** 2: raise ValueError('vendor base archive has an unsafe member')
            keys.add(key)
            if row.isdir(): continue
            total += row.size
            if total > 2 * 1024 ** 3: raise ValueError('vendor base archive exceeds bound')
            fingerprint = hashlib.sha256(); count = 0; capture = name.endswith('.json') and row.size <= 4 * 1024 ** 2; body = bytearray()
            with bundle.extractfile(row) as source:
                while chunk := source.read(1024 ** 2):
                    count += len(chunk); fingerprint.update(chunk)
                    if capture: body.extend(chunk)
            if count != row.size: raise ValueError('vendor base archive truncated')
            files[name] = {'sha256': fingerprint.hexdigest(), 'size_bytes': count}
            if capture:
                if sum(len(value) for value in captured.values()) + len(body) > 16 * 1024 ** 2: raise ValueError('vendor base JSON exceeds bound')
                captured[name] = body
    manifest = json.loads(captured[manifest_name]); expected = {row['path']: {'sha256': row['sha256'], 'size_bytes': row['size_bytes']} for row in manifest['files']}
    if manifest.get('schema_version') != 1 or len(expected) != len(manifest['files']) or {name: row for name, row in files.items() if name != manifest_name} != expected: raise ValueError('vendor base content inventory differs')
    deferred = manifest.get('deferred_browser')
    if deferred is None: return None
    if deferred.get('provider') not in ('google-chrome-for-testing', 'microsoft-edge'): raise ValueError('unknown vendor provider')
    name = paths.validate_path(deferred['recipe']); recipe = json.loads(captured[name])
    if recipe.get('schema_version') != 1 or recipe.get('provider') != deferred['provider']: raise ValueError('vendor base recipe provider differs')
    return {'provider': recipe['provider'], 'platform': recipe['platform'], 'recipe_sha256': files[name]['sha256'], 'archive': recipe.get('archive', recipe.get('msi'))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--archive', type=Path, required=True); parser.add_argument('--manifest', required=True); args = parser.parse_args(); print(json.dumps(inspect(args.archive, args.manifest)))
