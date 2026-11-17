"""Compact definitions remain data; no generated function is executed here."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


fixtures = load('compact_connection_proof_fixture', 'tests/mutation/test_python_generation_projection_proof.py')
native = load('compact_connection_control_fixture', 'tests/mutation/test_python_compact_definitions.py')
streamer = load('compact_connection_stream', 'scripts/quality/stream-plan.py')
entry = load('compact_connection_entry', 'scripts/quality/oci-mutation.py')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def compact_proof_plan(fixture):
    fixture.plan.update(schema_version=1, tool='mutmut', tool_version='3.8.1',
                        definition_representation='mutmut-control-spans-v1',
                        runtime_representation={'version': fixtures.projection.VERSION,
                                                'manifest_path': 'control/python-projection/manifest.json',
                                                'manifest_sha256': hashlib.sha256(fixture.manifest_bytes).hexdigest(), 'jobs': 1})
    for row in fixture.plan['inventory']:
        definition = row.pop('definition')
        row['definition_ref'] = {'kind': 'mutmut-control-spans-v1', 'module': row['file'],
                                 'location': definition['location'], 'generation_repairs': definition['generation_repairs']}
    (fixture.state / 'schedule.json').write_bytes(canonical(fixture.plan))


def streamed_plan(state):
    header, rows, definitions = native.CompactDefinitionTests().fixture(state)
    return {**header, 'schema_version': 1, 'scope_complete': True, 'tool': 'mutmut', 'tool_version': '3.8.1',
            'scheduled': len(rows), 'inventory': rows,
            'tests': [{'id': 'tests/test_value.py::test_original', 'source': 'tests/test_value.py', 'source_sha256': 'b' * 64}]}, definitions


class CompactPythonConnectionsTests(unittest.TestCase):
    def test_proof_independently_reconstructs_same_full_hashes_from_compact_and_legacy_plans(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = fixtures.Fixture(Path(temporary))
            legacy = fixture.prove()
            compact_proof_plan(fixture)
            compact = fixture.prove()
            self.assertEqual(compact['inventory'], legacy['inventory'])
            self.assertEqual(compact['inventory_sha256'], legacy['inventory_sha256'])
            self.assertEqual(compact['source_materializations'], legacy['source_materializations'])
            self.assertTrue(all('definition' not in row for row in fixture.plan['inventory']))
            self.assertNotIn('original_function', canonical(fixture.plan).decode())

    def test_proof_rejects_unknown_mixed_tampered_refs_and_wrong_manifest_without_falling_back(self):
        for change in ('kind', 'mixed', 'location', 'digest', 'manifest', 'unversioned'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fixture = fixtures.Fixture(Path(temporary)); compact_proof_plan(fixture)
                row = fixture.plan['inventory'][0]
                if change == 'kind': row['definition_ref']['kind'] = 'caller-asserted-reference'
                elif change == 'mixed': row['definition'] = {}
                elif change == 'location': row['definition_ref']['location']['line'] += 1
                elif change == 'digest': row['definition_sha256'] = 'b' * 64
                elif change == 'manifest': fixture.plan['runtime_representation']['manifest_sha256'] = 'b' * 64
                else: fixture.plan.pop('definition_representation')
                (fixture.state / 'schedule.json').write_bytes(canonical(fixture.plan))
                with self.assertRaises(ValueError): fixture.prove()

    def test_stream_resolves_one_complete_definition_per_frame_and_preserves_exact_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary); plan, definitions = streamed_plan(state)
            path = state / 'schedule.json'; path.write_bytes(canonical(plan)); before = path.read_bytes()
            output = io.StringIO(); streamer.stream(str(path), output)
            frames = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(frames[0]['count'], 2)
            self.assertNotIn('inventory', frames[0]['plan'])
            expected = [{key: value for key, value in row.items() if key != 'definition_ref'} | {'definition': definition}
                        for row, definition in zip(plan['inventory'], definitions)]
            self.assertEqual([frame['value'] for frame in frames[1:-1]], expected)
            self.assertEqual(frames[-1], {'type': 'end', 'count': 2,
                             'definition_stream_sha256': hashlib.sha256(b''.join(canonical(row) + b'\n' for row in expected)).hexdigest()})
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue(all('definition' not in row for row in json.loads(before)['inventory']))

    def test_pre_outcome_binding_validates_control_before_emitting_existing_compact_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary); plan, definitions = streamed_plan(state)
            legacy = copy.deepcopy(plan); legacy.pop('definition_representation')
            legacy['inventory'] = [{key: value for key, value in row.items() if key != 'definition_ref'} | {'definition': definition}
                                   for row, definition in zip(plan['inventory'], definitions)]
            expected = entry.schedule_identity(legacy, 'python')
            self.assertEqual(entry.schedule_identity(plan, 'python', state), expected)
            with self.assertRaisesRegex(ValueError, 'actual CONTROL state'): entry.schedule_identity(plan, 'python')
            with self.assertRaisesRegex(ValueError, 'actual CONTROL state'): entry.schedule_identity(plan, 'typescript', state)
            bad = copy.deepcopy(plan); bad['inventory'][0]['definition_sha256'] = 'c' * 64
            with self.assertRaises(ValueError): entry.schedule_identity(bad, 'python', state)
            self.assertFalse((state / 'pre-outcome-plan.json').exists())

    def test_legacy_stream_avoids_new_control_dependency_and_unversioned_refs_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary); definition = {'operator': 'literal', 'replacement': 'false'}
            row = {'id': 'legacy', 'file': 'scripts/value.py', 'source_sha256': 'a' * 64,
                   'definition': definition, 'definition_sha256': hashlib.sha256(canonical(definition)).hexdigest()}
            file = state / 'schedule.json'; file.write_bytes(canonical({'inventory': [row]}))
            output = io.StringIO(); streamer.stream(str(file), output)
            self.assertEqual(json.loads(output.getvalue().splitlines()[1])['value'], row)
            row.pop('definition'); row['definition_ref'] = {'kind': 'mutmut-control-spans-v1'}
            file.write_bytes(canonical({'inventory': [row]}))
            with self.assertRaisesRegex(ValueError, 'versioned representation'): streamer.stream(file, io.StringIO())


if __name__ == '__main__':
    unittest.main()
