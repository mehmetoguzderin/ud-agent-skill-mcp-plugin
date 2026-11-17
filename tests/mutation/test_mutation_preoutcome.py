"""Portable original-code checks for discovery fences; no host variants run."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts/quality' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


entry, secondary, generation = load('oci-mutation'), load('oci-secondary'), load('prove-source-generation')
sha = lambda raw: hashlib.sha256(raw).hexdigest()
canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


class MutationPreoutcomeTests(unittest.TestCase):
    def plan(self):
        definition = {'operator': 'BooleanLiteral', 'original': 'true', 'replacement': 'false'}
        return {'tool': 'fixture', 'scope_complete': True, 'source_tree_sha256': 'a' * 64,
                'inventory': [{'id': 'source#7', 'file': 'packages/example/src/value.mjs', 'source_sha256': 'b' * 64, 'definition': definition, 'definition_sha256': sha(canonical(definition))}],
                'tests': [{'id': 'tests/value.test.mjs#one', 'source': 'tests/value.test.mjs', 'source_sha256': 'c' * 64, 'name': 'specified result', 'occurrence': 0}]}

    def test_frozen_schedule_mismatch_fails_before_a_completion_record_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / 'state'; state.mkdir()
            runtime = root / 'runtime.json'; runtime.write_bytes(b'{"fixture":"SDK"}')
            frozen = root / 'frozen.json'; plan = self.plan()
            frozen.write_bytes(canonical({'schema_version': 1, 'runtime_sha256': sha(runtime.read_bytes()), 'plan': entry.schedule_identity(plan, 'typescript')}))
            self.assertEqual(entry.bind_schedule(plan, 'typescript', state, frozen, runtime), entry.schedule_identity(plan, 'typescript'))
            (state / 'pre-outcome-plan.json').unlink()
            plan['tests'][0]['occurrence'] = 1
            with self.assertRaisesRegex(ValueError, 'frozen'):
                entry.bind_schedule(plan, 'typescript', state, frozen, runtime)
            self.assertFalse((state / 'pre-outcome-plan.json').exists())
            plan['tests'][0]['occurrence'] = 0; runtime.write_bytes(b'{"fixture":"other SDK"}')
            with self.assertRaisesRegex(ValueError, 'SDK'):
                entry.bind_schedule(plan, 'typescript', state, frozen, runtime)

    def test_partial_diagnostic_is_allowed_only_without_frozen_authority_and_never_issues_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / 'state'; state.mkdir(); frozen = root / 'frozen.json'
            plan = {**self.plan(), 'scope_complete': False}
            self.assertIsNone(entry.bind_schedule(plan, 'python', state, frozen))
            self.assertEqual(json.loads((state / 'selected-diagnostic.json').read_bytes())['scope_complete'], False)
            self.assertFalse((state / 'pre-outcome-plan.json').exists())
            frozen.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'complete mutation schedules'):
                entry.bind_schedule(plan, 'python', state, frozen)
            self.assertFalse((state / 'pre-outcome-plan.json').exists())

    def test_fault_discovery_collects_required_cases_and_never_runs_a_baseline_or_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); work = root / 'work'; state = root / 'state'; state.mkdir()
            (work / 'tests/mutation').mkdir(parents=True); (work / 'packages/example/src').mkdir(parents=True)
            (work / 'packages/example/src/value.mjs').write_bytes(b'export default true;')
            (work / 'tests/mutation/fault-cases.json').write_bytes(canonical({'schema_version': 1, 'cases': [{'id': 'boolean', 'file': 'packages/example/src/value.mjs', 'find': 'true', 'replace': 'false', 'runner': 'pytest', 'test': 'tests/test_value.py::Case::test_result', 'assertion': 'test_result'}]}))
            class DiscoveryOnly:
                def __init__(self): self.calls = []
                def run(self, runner, *args):
                    self.calls.append(runner)
                    if runner != 'pytest-collect': raise AssertionError('outcome execution before freeze')
                    return {'status': 0, 'timed_out': False}, canonical([{'id': 'tests/test_value.py::Case::test_result', 'source': 'tests/test_value.py', 'source_sha256': 'd' * 64}])
            jobs = DiscoveryOnly(); bound = []
            self.assertEqual(secondary.run_faults(work, state, {'source_tree_sha256': 'a' * 64}, jobs, inventory_only=True, verify_schedule=bound.append), 0)
            self.assertEqual(jobs.calls, ['pytest-collect'])
            self.assertEqual(bound[0]['scheduled'], 1)
            self.assertEqual(bound[0]['tests'][0]['id'], 'tests/test_value.py::Case::test_result')
            replayed = generation.prove(work, state, 'faults', bound[0])
            self.assertEqual(replayed[0]['definition']['original_hex'], b'true'.hex())
            self.assertEqual(replayed[0]['definition']['replacement_hex'], b'false'.hex())
            with self.assertRaisesRegex(ValueError, 'complete original'):
                generation.prove(work, state, 'faults', {**bound[0], 'inventory': [], 'scheduled': 0})
            self.assertFalse((state / 'fault-outcomes.json').exists())

    def test_secondary_handoff_requires_both_exact_source_and_resulting_inventory_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); work = root / 'work'; work.mkdir(); state = root / 'state'; state.mkdir()
            (work / 'source.py').write_bytes(b'VALUE = True\n')
            receipt = {'files': [{'path': 'source.py', 'sha256': sha((work / 'source.py').read_bytes())}]}
            runtime = {'node_dependencies': {'path': 'node-dependencies.json', 'sha256': 'a' * 64, 'size_bytes': 1}}
            def execute(argv, **options):
                fingerprint = sha(json.dumps(options['workspace'], sort_keys=True, separators=(',', ':')).encode())
                return {'status': 0, 'handoff': {'cwd': '.', 'files': 1, 'inventory_sha256': fingerprint, 'source_inventory_sha256': fingerprint, 'readonly_tree': True}}
            jobs = secondary.Jobs(work, state, receipt, execute, runtime)
            result, content = jobs.run('pytest-collect')
            self.assertEqual(result['status'], 0)
            self.assertIsNone(content)
            for damage in ['source_inventory_sha256', 'inventory_sha256']:
                def broken(argv, **options):
                    result = execute(argv, **options); result['handoff'][damage] = 'f' * 64; return result
                with self.assertRaisesRegex(ValueError, 'sealed source handoff'):
                    secondary.Jobs(work, state, receipt, broken, runtime).run('pytest-collect')

    def test_static_master_replays_all_original_module_literals_and_detects_an_omitted_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'tests/mutation').mkdir(parents=True); (root / 'scripts').mkdir()
            (root / 'tests/mutation/python_static.py').write_bytes((ROOT / 'tests/mutation/python_static.py').read_bytes())
            (root / 'scripts/example.py').write_text('ENABLED = True\ndef callable_body():\n    return False\n')
            expected = generation.reconstruct(root, root, 'python-static')
            self.assertEqual(len(expected), 1)
            self.assertEqual(expected[0]['file'], 'scripts/example.py')
            self.assertEqual(expected[0]['definition']['original_hex'], b'True'.hex())
            self.assertEqual(expected[0]['replacement'], 'False')
            plan = {'scope_complete': True, 'scheduled': 1, 'inventory': expected}
            self.assertEqual(generation.prove(root, root, 'python-static', plan), expected)
            (root / 'scripts/second.py').write_text('OTHER = False\n')
            with self.assertRaisesRegex(ValueError, 'complete original'):
                generation.prove(root, root, 'python-static', plan)

    def test_rust_master_reconstructs_both_workspace_paths_and_rejects_missing_upstream_definitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / 'state'; state.mkdir()
            for name in ('rust-literal.py', 'rust-test-runtime.py'):
                file = root / 'scripts/quality' / name; file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes((ROOT / 'scripts/quality' / name).read_bytes())
            code = b'fn answer() -> bool { true }\n'; start = code.index(b'true') + 1
            cases = [('launcher', 'ud-agent-launcher', 'packages/launcher'), ('assertion-parser', 'ud-rust-assertion-parser', 'scripts/quality/rust-assertion-parser')]
            for label, package, prefix in cases:
                file = root / prefix / 'src/main.rs'; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(code)
                upstream_file = prefix + '/src/main.rs' if label == 'launcher' else 'src/main.rs'
                raw = {'file': upstream_file, 'package': package, 'name': upstream_file + ':1:4: answer bool', 'diff': '--- ' + upstream_file + '\n', 'replacement': 'false', 'genre': 'FnValue', 'function': {'return_type': '-> bool'}, 'span': {'start': {'line': 1, 'column': start}, 'end': {'line': 1, 'column': start + 4}}}
                (state / ('discovery-' + label + '.json')).write_bytes(canonical([raw]))
            expected = generation.reconstruct(root, state, 'rust')
            self.assertEqual([item['file'] for item in expected], ['packages/launcher/src/main.rs', 'scripts/quality/rust-assertion-parser/src/main.rs'])
            self.assertEqual([item['definition']['replacement'] for item in expected], ['false', 'false'])
            plan = {'scope_complete': True, 'scheduled': 2, 'inventory': expected}
            self.assertEqual(generation.prove(root, state, 'rust', plan), expected)
            with self.assertRaisesRegex(ValueError, 'complete original'):
                generation.prove(root, state, 'rust', {**plan, 'scheduled': 1, 'inventory': expected[:1]})


if __name__ == '__main__':
    unittest.main()
