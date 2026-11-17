"""Reconcile data-only original generators with protected pre-outcome plans."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def module(root, name):
    spec = importlib.util.spec_from_file_location('ud_original_generation_' + Path(name).stem.replace('-', '_'), root / name)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def reconstruct(root, state, backend):
    if backend == 'rust':
        literal = module(root, 'scripts/quality/rust-literal.py')
        contract = module(root, 'scripts/quality/rust-test-runtime.py')
        inventory = []
        for manifest, selected in contract.WORKSPACES.items():
            raw = json.loads((state / ('discovery-' + selected['id'] + '.json')).read_bytes())
            if not isinstance(raw, list) or not raw:
                raise ValueError('empty Rust workspace discovery')
            for item in raw:
                normalized = literal.normalize_definition(item, manifest, contract.WORKSPACES)
                name = normalized['file']; data = (root / name).read_bytes()
                repaired = literal.definition(normalized, data)
                definition = {'tool': 'cargo-mutants', 'version': '27.1.0', **repaired}
                inventory.append({'id': repaired['name'], 'file': name, 'source_sha256': hashlib.sha256(data).hexdigest(), 'definition': definition, 'definition_sha256': hashlib.sha256(canonical(definition)).hexdigest(), 'mutant': repaired, 'workspace_manifest': manifest})
        return inventory
    if backend == 'python-static':
        return module(root, 'tests/mutation/python_static.py').enumerate_mutants(root)
    if backend != 'faults':
        raise ValueError('unsupported original source generator')
    manifest = json.loads((root / 'tests/mutation/fault-cases.json').read_bytes())
    cases = manifest['cases']
    inventory = []
    for case in cases:
        name = case['file']; data = (root / name).read_bytes(); find = case['find'].encode()
        if not find or data.count(find) != 1:
            raise ValueError('ambiguous fault source anchor')
        start = data.index(find)
        definition = {'tool': 'fault-canary', 'version': '1.0.0', 'operator': case['id'], 'start': start, 'end': start + len(find), 'original_hex': find.hex(), 'replacement_hex': case['replace'].encode().hex(), 'runner': case['runner'], 'test': case['test'], 'assertion': case['assertion']}
        if manifest.get('profile') == 'bounded':
            definition.update(file=name, language=case['language'], category=case['category'])
        inventory.append({'id': case['id'], 'file': name, 'source_sha256': hashlib.sha256(data).hexdigest(), 'definition': definition, 'definition_sha256': hashlib.sha256(canonical(definition)).hexdigest()})
    return inventory


def prove(root, state, backend, plan):
    expected = reconstruct(root, state, backend)
    actual = plan.get('inventory')
    order = lambda item: item['id'].encode('utf-16-be', errors='surrogatepass')
    if not expected or not isinstance(actual, list) or len({item['id'] for item in expected}) != len(expected) or sorted(actual, key=order) != sorted(expected, key=order) or plan.get('scheduled') != len(expected) or plan.get('scope_complete') is not True:
        raise ValueError('protected plan differs from complete original source generation')
    return expected


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'state', 'plan', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--backend', choices=('rust', 'python-static', 'faults'), required=True)
    args = parser.parse_args()
    inventory = prove(args.root, args.state, args.backend, json.loads(args.plan.read_bytes()))
    with args.output.open('x') as target:
        json.dump({'schema_version': 1, 'inventory': inventory}, target, ensure_ascii=False, separators=(',', ':'))
        target.write('\n')
