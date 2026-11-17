"""Independent archive-side verification of all canonical skill resources."""
import hashlib
import json


def expected(root, paths):
    contract_raw = (root / 'quality/skills.json').read_bytes()
    contract = json.loads(contract_raw)
    names = ['ud-validate', 'ud-edit', 'ud-investigate', 'ud-compare', 'ud-rules-docs', 'ud-release']
    if contract.get('schema_version') != 1 or [row.get('name') for row in contract.get('skills', [])] != names:
        raise ValueError('independent six-skill contract differs')
    files, seen = [], set()
    if sorted(item.name for item in (root / 'skills').iterdir()) != sorted(names):
        raise ValueError('canonical skill folders differ')
    for row in contract['skills']:
        base = root / 'skills' / row['name']
        required = row.get('required_files', [])
        if not required or len(required) != len(set(required)) or 'SKILL.md' not in required:
            raise ValueError('independent required skill resources are invalid')
        found = set()
        for file in sorted(base.rglob('*')):
            if file.is_symlink():
                raise ValueError('canonical skill support contains a link')
            if file.is_dir():
                continue
            if not file.is_file():
                raise ValueError('canonical skill support contains a special file')
            relative = file.relative_to(root).as_posix()
            paths.validate_path(relative)
            key = paths.path_key(relative)
            if key in seen:
                raise ValueError('canonical skill support has a Unicode collision')
            seen.add(key)
            body = file.read_bytes()
            if len(body) > 2 * 1024 ** 2 or len(files) >= 1024:
                raise ValueError('canonical skill support exceeds bounds')
            files.append({'path': relative, 'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body), 'executable': False})
            found.add(file.relative_to(base).as_posix())
        if not set(required) <= found:
            raise ValueError('independently required skill resource is missing')
    if sum(row['size'] for row in files) > 16 * 1024 ** 2:
        raise ValueError('canonical skill support exceeds total bound')
    return {'schema_version': 1, 'policy': 'frozen-unicode-16', 'contract_sha256': hashlib.sha256(contract_raw).hexdigest(), 'skills': contract['skills'], 'files': sorted(files, key=lambda row: row['path'])}


def verify(root, paths, records, support):
    required = expected(root, paths)
    if support != required:
        raise ValueError('package skill support differs from independent required closure')
    actual = {name: row for name, row in records.items() if name.startswith('skills/')}
    if actual != {row['path']: row for row in required['files']}:
        raise ValueError('package omits, changes or adds skill support bytes')
