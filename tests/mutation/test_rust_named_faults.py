"""Named Rust control/data policies; native programs run only in protected OCI."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location('ud_named_test_' + name.replace('-', '_'), ROOT / 'scripts/quality' / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


runner, literal = load('rust-protected'), load('rust-literal')
SOURCE = 'packages/launcher/src/fs_guard.rs'
TEST_SOURCE = 'packages/launcher/tests/fs_guard.rs'


def cases():
    return [
        {'id': 'rust_path_confinement', 'runner': 'rust', 'language': 'rust', 'category': 'native-safety', 'file': SOURCE,
         'find': '_ => return Err(fail("path must contain only relative normal components")),', 'replace': '_ => continue,',
         'test': TEST_SOURCE + '::rejects_escaping_paths_and_oversized_files_without_output', 'assertion': 'rejects_escaping_paths_and_oversized_files_without_output'},
        {'id': 'rust_transfer_limits', 'runner': 'rust', 'language': 'rust', 'category': 'native-safety', 'file': SOURCE,
         'find': 'if before.len() > max_bytes {\n        return Err(fail("input exceeds requested limit"));',
         'replace': 'if before.len() >= max_bytes {\n        return Err(fail("input exceeds requested limit"));',
         'test': TEST_SOURCE + '::native_transfer_limits_include_exact_boundaries_and_reject_invalid_fingerprints', 'assertion': 'native_transfer_limits_include_exact_boundaries_and_reject_invalid_fingerprints'},
    ]


class Fixture:
    """Models original coordinator records; never compiles or calls emitted Rust."""
    def __init__(self, directory):
        self.source, self.state = Path(directory) / 'source', Path(directory) / 'state'
        self.state.mkdir(); self.source.mkdir()
        texts = {'Cargo.toml': '[workspace]\nmembers=["packages/launcher"]\n',
                 'packages/launcher/Cargo.toml': '[package]\nname="ud-agent-launcher"\nversion="0.1.0"\n',
                 SOURCE: '// Unicode byte prefix: 雪\n' + '\n'.join(case['find'] for case in cases()) + '\n',
                 TEST_SOURCE: '// Immutable original test source fixture.\n'}
        for name, content in texts.items():
            target = self.source / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(content, newline="")
        self.original = (self.source / SOURCE).read_bytes()
        self.receipt = {'source_tree_sha256': 'a' * 64, 'files': [
            {'path': name, 'sha256': runner.sha((self.source / name).read_bytes()), 'size': (self.source / name).stat().st_size, 'executable': False} for name in texts]}
        self.calls, self.statuses = [], {}
        self.production_error, self.wrong_assertion, self.raise_during, self.clean_survivor = False, False, None, False
        self.baseline_error = False
        fixture = self

        class Protected:
            def __init__(self, receipt, output, schedule):
                self.schedule = schedule
                self.inventories = {TEST_SOURCE: [case['assertion'] for case in cases()] + ['unrelated_original_test']}

            def execute(self, command, work, environment, log, timeout):
                kind = 'build' if '--no-run' in command else 'list' if '--list' in command else 'test'
                data = (work / SOURCE).read_bytes()
                fixture.calls.append({'kind': kind, 'label': log.stem, 'source': data, 'command': list(command)})
                if fixture.raise_during == log.stem:
                    raise ValueError('original boundary model failure')
                pristine = data == fixture.original
                default = {'Failure': 101} if kind == 'test' and not pristine else 'Success'
                phase = {'process_status': fixture.statuses.get(log.stem, default), 'artifacts_complete': True}
                log.write_text('original baseline passed' if pristine or fixture.clean_survivor else 'captured candidate test output', newline="")
                return phase

        self.Protected = Protected

    def assertion(self, log, item=None, source=None, phase=None):
        if item is None:
            return {'valid': False, 'artifacts_complete': not self.baseline_error, 'failures': []}
        name = 'unrelated_original_test' if self.wrong_assertion else runner.NAMED_FAULTS[item['definition']['operator']][2]
        return {'valid': not self.production_error, 'artifacts_complete': not self.production_error,
                'failures': [{'artifact_id': TEST_SOURCE, 'test': name, 'source': TEST_SOURCE, 'source_sha256': self.receipt['files'][-1]['sha256'], 'line': 1, 'column': 1, 'macro': 'assert'}]}

    def prepare(self):
        # copy_source is original data-only code. Protected is a control model,
        # not an alternate executor or a native containment claim.
        helper = SimpleNamespace(copy_source=literal.copy_source, assertion_evidence=self.assertion,
                                 baseline_evidence=lambda log: log == 'original baseline passed')
        self.mocks = patch.multiple(runner, ProtectedRust=self.Protected, module=lambda name: helper)
        self.mocks.start()
        try:
            return runner.prepare_named_faults(self.source, self.state, self.receipt, cases())
        except BaseException:
            self.mocks.stop(); raise

    def arguments(self, case):
        row = runner.named_fault(case, self.original); program = row['program']
        mutation = {'path': SOURCE, 'before_sha256': runner.sha(self.original), 'after_sha256': runner.sha(program),
                    'size': len(program), 'content_base64': base64.b64encode(program).decode()}
        return row['definition'], mutation


class NamedRustFaultTests(unittest.TestCase):
    def test_reviewed_cases_derive_exact_byte_spans_and_reject_other_or_ambiguous_edits(self):
        source = ('// 雪\n' + '\n'.join(case['find'] for case in cases()) + '\n').encode()
        for case in cases():
            row = runner.named_fault(case, source)
            self.assertEqual(row['program'], source.replace(case['find'].encode(), case['replace'].encode(), 1))
            start, end = literal.offsets(source, row['auxiliary']['span'])
            self.assertEqual(source[start:end], case['find'].encode())
            self.assertEqual(row['definition']['file'], SOURCE)
            self.assertEqual(row['auxiliary']['named_fault_definition_sha256'], hashlib.sha256(runner.canonical(row['definition'])).hexdigest())
            for changed in [{**case, 'id': 'cpu_policy'}, {**case, 'file': '../fs_guard.rs'}, {**case, 'runner': 'pytest'}, {**case, 'replace': 'unreviewed'}, {**case, 'language': 'data'}, {**case, 'category': ''}, {**case, 'test': TEST_SOURCE + '::other'}]:
                with self.subTest(changed=changed), self.assertRaises(ValueError): runner.named_fault(changed, source)
            with self.assertRaises(ValueError): runner.named_fault(case, source + case['find'].encode())

    def test_discovery_precedes_one_shared_baseline_and_each_full_workspace_variant(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary); controller = fixture.prepare()
            try:
                self.assertEqual([call['kind'] for call in fixture.calls], ['build', 'list'])
                self.assertIsNone(controller.baseline)
                self.assertEqual([test['name'] for test in controller.tests], sorted([case['assertion'] for case in cases()] + ['unrelated_original_test']))
                for case in cases():
                    definition, mutation = fixture.arguments(case)
                    result = controller.run(case, definition, mutation)
                    self.assertEqual((result['status'], result['failure_kind']), ('Killed', 'assertion'))
                    self.assertEqual(result['definition_sha256'], runner.sha(runner.canonical(definition)))
                    self.assertEqual(result['killed_by'], [next(test['id'] for test in controller.tests if test['name'] == case['assertion'])])
                    self.assertEqual((controller.work / SOURCE).read_bytes(), fixture.original)
                self.assertEqual([call['kind'] for call in fixture.calls], ['build', 'list', 'test', 'build', 'list', 'test', 'build', 'list', 'test'])
                self.assertEqual(sum(call['label'] == 'baseline-test' for call in fixture.calls), 1)
                self.assertTrue(all(call['command'][-2:] == ['--', '--test-threads=1'] for call in fixture.calls if call['kind'] == 'test'))
                self.assertEqual((fixture.source / SOURCE).read_bytes(), fixture.original)
                self.assertEqual(controller.preparation['baseline_executed'], False)
                self.assertFalse(controller.preparation['exhaustive'])
            finally: fixture.mocks.stop()

    def test_definition_and_closed_materialization_must_match_before_any_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary); controller = fixture.prepare()
            try:
                case = cases()[0]; definition, mutation = fixture.arguments(case)
                for changed_definition, changed_mutation in [({**definition, 'category': 'different'}, mutation), (definition, {**mutation, 'after_sha256': 'b' * 64}), (definition, {**mutation, 'path': 'Cargo.toml'}), (definition, {**mutation, 'size': True}), (definition, {**mutation, 'extra': True})]:
                    with self.subTest(changed_definition=changed_definition, changed_mutation=changed_mutation), self.assertRaises(ValueError): controller.run(case, changed_definition, changed_mutation)
                self.assertEqual([call['kind'] for call in fixture.calls], ['build', 'list'])
                self.assertEqual((controller.work / SOURCE).read_bytes(), fixture.original)
                with self.assertRaises(ValueError): runner.prepare_named_faults(fixture.source, fixture.state / 'other', fixture.receipt, [cases()[0]])
            finally: fixture.mocks.stop()

    def test_compile_timeout_runtime_unknown_assertions_and_survivors_never_become_kills(self):
        case = cases()[0]
        scenarios = [('build', {'Failure': 101}, 'RunnerError'), ('build', 'Timeout', 'Timeout'),
                     ('list', {'Failure': 125}, 'RunnerError'), ('test', 'Timeout', 'Timeout'),
                     ('test', {'Failure': 125}, 'RunnerError'), ('test', 'Success', 'RunnerError'),
                     ('production', None, 'RunnerError'), ('wrong-assertion', None, 'RunnerError'), ('survivor', None, 'Survived')]
        for phase, status, expected in scenarios:
            with self.subTest(phase=phase, status=status), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(temporary); controller = fixture.prepare()
                try:
                    if phase == 'production': fixture.production_error = True
                    elif phase == 'wrong-assertion': fixture.wrong_assertion = True
                    elif phase == 'survivor': fixture.clean_survivor = True; fixture.statuses[case['id'] + '-test'] = 'Success'
                    else: fixture.statuses[case['id'] + '-' + phase] = status
                    result = controller.run(case, *fixture.arguments(case))
                    self.assertEqual(result['status'], expected)
                    self.assertEqual(result['killed_by'], [])
                    self.assertNotEqual(result['failure_kind'], 'assertion')
                    self.assertEqual((controller.work / SOURCE).read_bytes(), fixture.original)
                finally: fixture.mocks.stop()

    def test_actual_baseline_failure_and_child_errors_restore_or_refuse_variant(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary); controller = fixture.prepare()
            try:
                fixture.baseline_error = True
                with self.assertRaises(ValueError): controller.run(cases()[0], *fixture.arguments(cases()[0]))
                self.assertEqual([call['kind'] for call in fixture.calls], ['build', 'list', 'test'])
                self.assertEqual((controller.work / SOURCE).read_bytes(), fixture.original)
            finally: fixture.mocks.stop()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary); controller = fixture.prepare()
            try:
                fixture.raise_during = cases()[0]['id'] + '-build'
                with self.assertRaises(ValueError): controller.run(cases()[0], *fixture.arguments(cases()[0]))
                self.assertEqual((controller.work / SOURCE).read_bytes(), fixture.original)
            finally: fixture.mocks.stop()


if __name__ == '__main__': unittest.main()
