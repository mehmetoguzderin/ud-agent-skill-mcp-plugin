"""Reconstruct the complete Perl inventory from saved pre-outcome PPI tokens."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def prove(source, state, subject):
    artifacts = {}

    def read(file, record=False, maximum=64 * 1024**2):
        file = Path(file)
        if record:
            file.relative_to(state)
        # Every component is checked before the final no-follow open. Generation
        # lives in the stopped, owned OCI volume exported by the trusted parent.
        for parent in [file.parent, *file.parents]:
            if parent == state or parent == source:
                break
            if parent.is_symlink() or not parent.is_dir():
                raise ValueError('ordinary generation parents are required')
        def named_identity(info):
            # Windows lstat ctime is birthtime; fstat ctime is ChangeTime.
            return info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns
        def identity(info):
            return (*named_identity(info), info.st_ctime_ns)
        def ordinary(info):
            return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum and not getattr(info, 'st_file_attributes', 0) & 0x400
        named = os.lstat(file)
        if not ordinary(named):
            raise ValueError('bounded ordinary generation input required')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open(file, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if named_identity(before) != named_identity(named):
                raise ValueError('actual generation artifact changed before read')
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            current = os.lstat(file)
            if len(raw) != before.st_size or identity(before) != identity(after) or not ordinary(current) or named_identity(before) != named_identity(current):
                raise ValueError('actual generation artifact changed during read')
            check = os.open(file, flags)
            try:
                current = os.lstat(file)
                if not ordinary(current) or named_identity(before) != named_identity(current) or identity(before) != identity(os.fstat(check)) or identity(before) != identity(os.fstat(stream.fileno())):
                    raise ValueError('actual generation artifact changed during read')
            finally:
                os.close(check)
        if record:
            name = file.relative_to(state).as_posix()
            artifacts[name] = {'path': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
        return raw

    receipt = json.loads(read(subject))
    hashes = {item['path']: item['sha256'] for item in receipt['files']}
    source_names = sorted(name for name in hashes if name.split('/')[0] in ('packages', 'workers', 'scripts') and name.endswith(('.pl', '.pm')))
    plan = json.loads(read(state / 'perl-schedule.json', True))
    manifest = json.loads(read(state / 'perl-generation/manifest.json', True))
    if plan.get('scope_complete') is not True or plan.get('source_tree_sha256') != receipt['sha256'] or plan.get('outcomes') != [] or plan.get('baseline') != {}:
        raise ValueError('complete pre-outcome Perl schedule is required')
    if manifest.get('schema_version') != 1 or manifest.get('qualification') != 'complete-ppi-token-materialization-no-outcomes' or manifest.get('source_tree_sha256') != receipt['sha256']:
        raise ValueError('complete actual PPI materialization is required')
    operators_raw = read(source / 'quality/perl-operators.json')
    operator_sha = hashlib.sha256(operators_raw).hexdigest()
    if plan.get('operator_sha256') != operator_sha or manifest.get('operator_sha256') != operator_sha or manifest.get('parser_release') != 'PPI-1.291':
        raise ValueError('actual parser or operator identity differs')
    script = source / 'scripts/quality/perl-mutation.py'
    if hashlib.sha256(read(script)).hexdigest() != hashes.get('scripts/quality/perl-mutation.py'):
        raise ValueError('frozen Perl generator source changed')
    spec = importlib.util.spec_from_file_location('ud_ppi_generation_reconstruction', script)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    tests = {name: fingerprint for name, fingerprint in hashes.items()
             if name.startswith('tests/domain/perl/') and Path(name).name.startswith('test_') and name.endswith('.py')
             or name.startswith('tests/mutation/test_perl_') and name.endswith('.py')}
    for name, fingerprint in tests.items():
        if hashlib.sha256(read(source / name)).hexdigest() != fingerprint:
            raise ValueError('frozen Perl test source changed')
    if plan.get('tests') != tests or plan.get('case_inventory') != generator.test_cases(source, tests):
        raise ValueError('Perl test inventory differs from independent source discovery')
    rows = manifest.get('sources')
    if not isinstance(rows, list) or len(rows) != len(source_names) or any(not isinstance(item, dict) or item.get('source') not in source_names for item in rows) or len({item['source'] for item in rows}) != len(rows):
        raise ValueError('per-source PPI materializations are omitted, duplicated or unexpected')
    # The original discoverer visits packages/workers/scripts, whereas the
    # independent receipt sorts names. Check the complete unique closed set
    # before canonicalizing; traversal order cannot substitute for coverage.
    rows = sorted(rows, key=lambda item: item['source'])
    inventory, materializations, definitions, coverage = [], [], set(), {}
    for row in rows:
        name = row['source']
        raw = read(source / name)
        if hashlib.sha256(raw).hexdigest() != hashes[name] or row.get('source_sha256') != hashes[name] or plan.get('sources', {}).get(name) != hashes[name]:
            raise ValueError('PPI source identity differs')
        token_receipt = row['tokens']
        expected_name = 'tokens/' + name + '.json'
        if token_receipt.get('path') != expected_name:
            raise ValueError('PPI materialization path differs from its source')
        token_file = state / 'perl-generation' / expected_name
        tokens_raw = read(token_file, True)
        if len(tokens_raw) != token_receipt.get('size') or hashlib.sha256(tokens_raw).hexdigest() != token_receipt.get('sha256'):
            raise ValueError('actual PPI token bytes differ from their receipt')
        parsed = json.loads(tokens_raw)
        if parsed.get('schema_version') != 1 or parsed.get('parser_version') != '1.291':
            raise ValueError('actual PPI token format differs')
        coverage[name] = []
        generated = generator.inventory(raw, name, parsed, json.loads(operators_raw), coverage[name])
        if any(item['classification']=='unimplemented'for item in coverage[name]):
            raise ValueError('Perl generation has unimplemented live token semantics')
        ids = sorted(item['id'] for item in generated)
        if row.get('mutant_ids') != ids:
            raise ValueError('PPI generated identities differ from the materialized token inventory')
        for item in generated:
            identity = (name, item['definition_sha256'])
            if identity in definitions:
                raise ValueError('actual PPI generation repeats an applicable definition')
            definitions.add(identity)
            inventory.append(item)
        materializations.append({'source': name, 'source_sha256': hashes[name], 'mutant_ids': ids,
                                 'artifacts': [artifacts[token_file.relative_to(state).as_posix()]]})
    inventory.sort(key=lambda item: item['id'].encode('utf-16-be', errors='surrogatepass'))
    scheduled = sorted(plan.get('inventory', []), key=lambda item: item['id'].encode('utf-16-be', errors='surrogatepass'))
    if plan.get('operator_coverage')!=coverage or manifest.get('operator_coverage')!=coverage:
        raise ValueError('Perl per-token operator classification differs from actual PPI materializations')
    if not inventory or scheduled != inventory or plan.get('scheduled') != len(inventory) or set(plan.get('sources', {})) != set(source_names):
        raise ValueError('schedule differs from the complete independently reconstructed PPI definitions')
    compact = [{key: item[key] for key in ('id', 'file', 'source_sha256', 'definition_sha256')} for item in inventory]
    return {'schema_version': 1, 'qualification': 'reconstructed-actual-generated-definitions-no-outcomes',
            'source_tree_sha256': receipt['sha256'], 'inventory': compact,
            'inventory_sha256': hashlib.sha256(canonical(compact)).hexdigest(),
            'source_materializations': materializations, 'raw_artifacts': list(artifacts.values())}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'state', 'source-receipt', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = prove(args.source_root.resolve(strict=True), args.state.resolve(strict=True), args.source_receipt.resolve(strict=True))
    with args.output.open('x') as destination:
        json.dump(result, destination, ensure_ascii=False, separators=(',', ':'))
        destination.write('\n')
    print(json.dumps({'mutants': len(result['inventory']), 'sources': len(result['source_materializations'])}))
