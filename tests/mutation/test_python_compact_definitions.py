"""Original data contracts: no projected/generated program executes on host."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/quality' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

projection = load('ud_original_compact_definition', 'python-runtime-projection.py')
operators = load('ud_original_raw_identity_repairs', 'python-operators.py')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def sha(value):
    return hashlib.sha256(value).hexdigest()


class CompactDefinitionTests(unittest.TestCase):
    def fixture(self, state):
        profile = {'version': 'authored-data-only'}
        modules, items, definitions = [], [], []
        for module, value in [('scripts/first.py', 2), ('scripts/second.py', 3)]:
            original = 'def f(value):\n    return value + 1\n'
            replacement = f'def f(value):\n    return value + {value}\n'
            control = original.replace('def f(', 'def x_f__mutmut_orig(') + replacement.replace('def f(', 'def x_f__mutmut_1(')
            source_hash = sha(original.encode())
            file = state / projection.CONTROL / module
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(control, newline="")
            index = Path(str(file) + '.spans')
            index.write_text(json.dumps({'version': 1, 'spans': {'x_f__mutmut_orig': [1, 2], 'x_f__mutmut_1': [3, 4]}}), newline="")
            mutant = module.removesuffix('.py').replace('/', '.') + '.x_f__mutmut_1'
            modules.append({'path': module, 'source_sha256': source_hash,
                            'control': {'path': file.relative_to(state).as_posix(), 'sha256': sha(file.read_bytes()), 'size_bytes': file.stat().st_size},
                            'spans': {'path': index.relative_to(state).as_posix(), 'sha256': sha(index.read_bytes()), 'size_bytes': index.stat().st_size},
                            'mutants': [{'id': mutant, 'name': 'x_f__mutmut_1'}]})
            definition = {'tool': 'mutmut', 'version': '3.8.1', 'generation_profile': profile, 'generation_repairs': [],
                          'file': module, 'location': {'line': 1, 'end_line': 2, 'column': 0},
                          'original_function': original, 'replacement_function': replacement,
                          'diff': f'--- {module}\n+++ {module}\n@@ -1,2 +1,2 @@\n def f(value):\n-    return value + 1\n+    return value + {value}'}
            definitions.append(definition)
            items.append({'id': mutant, 'file': module, 'source_sha256': source_hash,
                          'definition_sha256': sha(canonical(definition).encode()),
                          'definition_ref': {'kind': 'mutmut-control-spans-v1', 'module': module,
                                             'location': {'line': 1, 'end_line': 2, 'column': 0}, 'generation_repairs': []}})
        manifest = {'schema_version': 1, 'version': projection.VERSION, 'source_tree_sha256': 'a' * 64,
                    'helper_sha256': sha(Path(projection.__file__).read_bytes()), 'files': modules}
        file = state / projection.MANIFEST
        file.write_text(canonical(manifest) + '\n', newline="")
        header = {'definition_representation': 'mutmut-control-spans-v1', 'source_tree_sha256': 'a' * 64,
                  'generation_profile': profile, 'runtime_representation': {'version': projection.VERSION,
                  'manifest_path': projection.MANIFEST.as_posix(), 'manifest_sha256': sha(file.read_bytes())}}
        return header, items, definitions

    def test_full_canonical_definitions_resolve_one_module_at_a_time_without_inline_plan_bodies(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            header, items, definitions = self.fixture(state)
            reader = projection.ControlDefinitionReader(state, header)
            for item, expected in zip(items, definitions):
                actual = reader.resolve(item)
                self.assertEqual(actual, {key: value for key, value in item.items() if key != 'definition_ref'} | {'definition': expected})
                self.assertEqual(reader.module, item['file'])
                self.assertNotIn('definition', item)
                self.assertNotIn('original_function', canonical(item))
            self.assertIn('return value + 3', ''.join(reader.lines))
            self.assertNotIn('return value + 2', ''.join(reader.lines))
            self.assertEqual(reader.resolve(items[0])['definition'], definitions[0])

    def test_tampered_control_manifest_span_hash_and_mixed_or_unknown_references_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            header, items, _ = self.fixture(state)
            for mutation in ('mixed', 'unknown', 'digest', 'rawid', 'path'):
                row = copy.deepcopy(items[0])
                if mutation == 'mixed': row['definition'] = {}
                if mutation == 'unknown': row['definition_ref']['kind'] = 'unreviewed-kind'
                if mutation == 'digest': row['definition_sha256'] = '0' * 64
                if mutation == 'rawid': row['id'] = 'scripts.first.x_f__mutmut_999'
                if mutation == 'path': row['definition_ref']['module'] = '../outside.py'
                with self.assertRaises(ValueError):
                    projection.ControlDefinitionReader(state, header).resolve(row)
            file = state / projection.CONTROL / 'scripts/first.py'
            file.write_text(file.read_text().replace('return value + 2', 'return value + 4'), newline="")
            with self.assertRaisesRegex(ValueError, 'CONTROL/index bytes changed'):
                projection.ControlDefinitionReader(state, header).resolve(items[0])
            changed = copy.deepcopy(header)
            changed['runtime_representation']['manifest_sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                projection.ControlDefinitionReader(state, changed)

    def test_typed_reference_replays_exact_approved_body_and_rejects_changed_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            header, items, definitions = self.fixture(state)
            row, upstream = items[0], definitions[0]
            control = state / projection.CONTROL / row['file']
            control.write_text(control.read_text().replace('return value + 2', 'return value + 4'), newline="")
            manifest_file = state / projection.MANIFEST
            manifest = json.loads(manifest_file.read_bytes())
            manifest['files'][0]['control']['sha256'] = sha(control.read_bytes())
            manifest_file.write_text(canonical(manifest) + '\n', newline="")
            header['runtime_representation']['manifest_sha256'] = sha(manifest_file.read_bytes())
            evidence = {'version': 'authored-typed-fixture', 'upstream_definition': upstream,
                        'upstream_definition_sha256': sha(canonical(upstream).encode()),
                        'exact_change': {'before': 'return value + 2', 'after': 'return value + 4'}}
            row['definition_ref']['operator_repair'] = evidence
            expected = {**upstream, 'replacement_function': 'def f(value):\n    return value + 4\n',
                        'diff': '--- scripts/first.py\n+++ scripts/first.py\n@@ -1,2 +1,2 @@\n def f(value):\n-    return value + 1\n+    return value + 4',
                        'operator_repair': evidence}
            row['definition_sha256'] = sha(canonical(expected).encode())
            self.assertEqual(projection.ControlDefinitionReader(state, header).resolve(row)['definition'], expected)
            row['definition_ref']['operator_repair']['exact_change']['after'] = 'return value + 5'
            with self.assertRaisesRegex(ValueError, 'typed repair differs'):
                projection.ControlDefinitionReader(state, header).resolve(row)

    def test_exact_raw_id_distinguishes_identical_invalid_operators_without_dropping_either(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'quality/reviews').mkdir(parents=True)
            upstream = {'tool': 'mutmut', 'version': '3.8.1', 'file': 'scripts/fixture.py',
                        'location': {'line': 1, 'end_line': 2, 'column': 0},
                        'original_function': 'def f(value):\n    return call(value, value)\n',
                        'replacement_function': 'def f(value):\n    return call(value)\n', 'diff': 'authored fixture delta'}
            rows, reviewed = [], []
            for number, after in [(1, 'call(value + 1, value)'), (2, 'call(value, value + 1)')]:
                changed = upstream['replacement_function'].replace('call(value)', after)
                row = {'id': f'scripts.fixture.x_f__mutmut_{number}', 'file': 'scripts/fixture.py', 'source_sha256': 'a' * 64,
                       'upstream_definition': upstream, 'upstream_definition_sha256': sha(canonical(upstream).encode()),
                       'replacement_function_sha256': sha(upstream['replacement_function'].encode()),
                       'before': 'call(value)', 'after': after, 'type_contract': 'authored two-integer-argument contract'}
                rows.append(row)
                reviewed.append({**{key: row[key] for key in ('id', 'source_sha256', 'upstream_definition_sha256', 'before', 'after')},
                                 'decision': 'valid_operator', 'repaired_function_sha256': sha(changed.encode())})
            registry = {'schema_version': 1, 'version': 'authored-data-fixture', 'rows': rows}
            file = root / 'quality/python-operator-repairs.json'
            file.write_text(canonical(registry), newline="")
            (root / 'quality/reviews/python-operator-repairs-domain-review.json').write_text(canonical({'registry_sha256': sha(file.read_bytes()), 'registry_version': registry['version'], 'reviewer': 'domain_completion', 'rows': reviewed}), newline="")
            repair = operators._project_typed_repairs(root, {'scripts/fixture.py': 'a' * 64})
            with self.assertRaisesRegex(ValueError, 'exact raw identity'):
                repair('scripts/fixture.py', upstream['replacement_function'], upstream)
            values = [repair('scripts/fixture.py', upstream['replacement_function'], upstream, raw_id=row['id'])[0] for row in rows]
            self.assertEqual(values, ['def f(value):\n    return call(value + 1, value)\n', 'def f(value):\n    return call(value, value + 1)\n'])
            self.assertIsNone(repair('scripts/fixture.py', upstream['replacement_function'], upstream, raw_id='scripts.fixture.x_f__mutmut_3'))
            repair.complete({row['id'] for row in rows})

    def test_activated_packets_preserve_each_independent_reviewer_and_reject_changed_packet(self):
        registry = json.loads((ROOT / 'quality/python-operator-repairs.json').read_bytes())
        wrapper = json.loads((ROOT / 'quality/reviews/python-operator-repairs-domain-review.json').read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ['quality/python-operator-repairs.json', 'quality/reviews/python-operator-repairs-domain-review.json',
                         *[item['path'] for item in wrapper['packets']]]:
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, file)
            try:
                repair = operators._project_typed_repairs(root, wrapper['dependency_source_sha256'])
            except Exception as error:
                self.fail('Valid original independent review packets must authorize exact regeneration: ' + repr(error))
            identities = []
            for row in registry['rows']:
                definition = row['upstream_definition']
                _, evidence = repair(row['file'], definition['replacement_function'], definition, raw_id=row['id'])
                identities.append(evidence['review']['reviewer'])
            self.assertEqual(identities[:30], ['domain_completion'] * 30)
            self.assertEqual(identities[30:], ['root'] * 6)
            repair.complete({row['id'] for row in registry['rows']})
            packet = next(item for item in wrapper['packets'] if item['reviewer'] == 'root')
            file = root / packet['path']
            file.write_bytes(file.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'packet bytes changed'):
                operators._project_typed_repairs(root, wrapper['dependency_source_sha256'])
            forged = json.loads((ROOT / packet['path']).read_bytes())
            forged['author'] = 'root'
            file.write_text(canonical(forged), newline="")
            packet['sha256'], packet['size_bytes'] = sha(file.read_bytes()), file.stat().st_size
            wrapper['dependency_source_sha256'][packet['path']] = packet['sha256']
            (root / 'quality/reviews/python-operator-repairs-domain-review.json').write_text(canonical(wrapper), newline="")
            with self.assertRaisesRegex(ValueError, 'independent approval'):
                operators._project_typed_repairs(root, wrapper['dependency_source_sha256'])


if __name__ == '__main__':
    unittest.main()
