"""Original lifecycle/data models; no emitted program or privilege boundary runs."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('python_projection_lifecycle', ROOT / 'scripts/quality/oci-isolation.py')
isolation = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'fcntl': types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *args: None)} if os.name == 'nt' else {}):
    spec.loader.exec_module(isolation)


class ProjectionLifecycleTests(unittest.TestCase):
    def setUp(self):
        # The SDK is Linux-only. Windows executes these same data/lifecycle
        # branches with explicit POSIX metadata/flag models, never containment.
        if os.name == 'nt':
            for name, value in [('geteuid', lambda: 501), ('chown', lambda *args: None), ('O_NOFOLLOW', 0), ('O_CLOEXEC', 0)]:
                if not hasattr(isolation.os, name):
                    model = patch.object(isolation.os, name, value, create=True)
                    model.start()
                    self.addCleanup(model.stop)

    def fixture(self, root):
        work, state, jobs = root / 'work', root / 'state', root / 'jobs'
        for directory in (work, state, jobs):
            directory.mkdir()
        isolation.control(state)
        return work, state, jobs, state / 'events.jsonl'

    def witness(self, mode='baseline', key=None):
        return {'schema_version': 1, 'version': 'ud-python-inert-projection-1', 'mode': mode, 'active_key': key,
                'manifest_sha256': 'a' * 64, 'guard_exit_code': 125,
                'files': [{'path': 'src/example.py', 'control_sha256': 'b' * 64, 'spans_sha256': 'c' * 64,
                           'projected_sha256': 'd' * 64, 'size_bytes': 19, 'active_name': None}]}

    def test_upstream_states_have_explicit_distinct_admission_modes(self):
        for params, active, expected in [
            (['--collect-only'], '', ('collection', None)),
            (['--collect-only'], 'mutant_generation', ('collection', None)),
            (['--collect-only'], 'list_all_tests', ('collection', None)),
            (['-q'], '', ('baseline', None)),
            (['-q'], 'stats', ('stats', None)),
            (['-q'], 'fail', ('forced-fail', None)),
            (['tests/test_example.py'], 'example.x_f__mutmut_1', ('active', 'example.x_f__mutmut_1')),
        ]:
            with self.subTest(active=active, params=params):
                self.assertEqual(isolation.projection_selection(params, active), expected)
        for params, active in [(['--collect-only'], 'stats'), (['--collect-only'], 'fail'),
                               (['--collect-only'], 'example.x_f__mutmut_1'), ([], 'list_all_tests'),
                               ([], 'mutant_generation'), ([], None), ([], 'bad\0key')]:
            with self.subTest(active=active), self.assertRaisesRegex(ValueError, 'projection'):
                isolation.projection_selection(params, active)

    def test_full_suite_options_follow_upstream_exitfirst_and_only_stats_are_verbose(self):
        # Evaluate only the actual fixed launch-argument expressions as data;
        # never call the isolated runner, pytest or an emitted function here.
        tree = ast.parse((ROOT / 'scripts/quality/oci-isolation.py').read_text())
        isolated = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'isolated')
        options = next(node.value for node in ast.walk(isolated) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'baseline_options' for target in node.targets))
        invocation = next(node for node in ast.walk(isolated) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Name) and node.func.id == 'execute')
        for active in ('', 'stats', 'fail', 'example.x_f__mutmut_1', 'list_all_tests'):
            with self.subTest(active=active):
                work = Path('/state/work')
                scope = {'active': active, 'absolute': ['-x', '-q', 'tests/test_example.py'], 'str': str, 'work': work}
                scope['baseline_options'] = eval(compile(ast.Expression(options), 'original-argument-model', 'eval'), {}, scope)
                actual = eval(compile(ast.Expression(invocation.args[1]), 'original-argument-model', 'eval'), {}, scope)
                self.assertEqual(actual[:3], ['-x', '-q', 'tests/test_example.py'])
                self.assertEqual(actual.count('--maxfail=0'), 1)
                self.assertGreater(actual.index('--maxfail=0'), actual.index('-x'))
                self.assertEqual(actual[-2:] if active == 'stats' else actual[-1:], ['--maxfail=0', '-v'] if active == 'stats' else ['--maxfail=0'])
                self.assertEqual('-v' in actual, active == 'stats')

    def test_projection_requires_the_shared_fixed_protected_sdk_module(self):
        module = types.SimpleNamespace(__file__=str(Path('/opt/mutation/harness/python-runtime-projection.py')),
                                       VERSION='ud-python-inert-projection-1', prepare_runtime=Mock(), issue_runtime_context=Mock())
        ordinary = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_nlink=1)
        with patch.object(isolation.Path, 'lstat', return_value=ordinary):
            self.assertIs(isolation.validate_runtime_projection(module), module)
        for field, value in [('__file__', '/ambient/python-runtime-projection.py'), ('VERSION', 'foreign'), ('prepare_runtime', None), ('issue_runtime_context', None)]:
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'shared fixed SDK'):
                isolation.validate_runtime_projection(types.SimpleNamespace(**{**module.__dict__, field: value}))
        for change in ({'st_mode': stat.S_IFLNK | 0o444}, {'st_uid': 100001}, {'st_nlink': 2}, {'st_mode': stat.S_IFREG | 0o466}):
            with self.subTest(change=change), patch.object(isolation.Path, 'lstat', return_value=types.SimpleNamespace(**{**ordinary.__dict__, **change})), \
                    self.assertRaisesRegex(RuntimeError, 'protected ordinary file'):
                isolation.validate_runtime_projection(module)

    def test_pre_drop_admission_collects_first_then_binds_exact_witness_to_private_record(self):
        with tempfile.TemporaryDirectory() as directory:
            work, state, jobs, events = self.fixture(Path(directory))
            order = []
            def prepare(*args):
                self.assertEqual(args, (work, state, 'active', 'example.x_f__mutmut_1'))
                self.assertEqual(order, ['collected'])
                self.assertEqual(isolation.os.geteuid(), 0)
                order.append('projected')
                return self.witness('active', 'example.x_f__mutmut_1')
            context_receipt = {'path': 'work/mutants/.ud-runtime-projection.json', 'sha256': 'e' * 64, 'size_bytes': 451}
            def issue(actual_work, actual_state, uid, witness):
                self.assertEqual((actual_work, actual_state), (work, state))
                self.assertEqual(witness['projection_sequence'], uid)
                self.assertEqual(order, ['collected', 'projected'])
                self.assertEqual(list((state / 'control/jobs').glob('*.json')), [])
                order.append('context-issued')
                return context_receipt
            projector = types.SimpleNamespace(prepare_runtime=Mock(side_effect=prepare), issue_runtime_context=Mock(side_effect=issue))
            identity = {'pid': 206, 'uid': 0, 'start_ticks': 91}
            with patch.object(isolation.os, 'geteuid', return_value=0), patch.object(isolation.os, 'chown'), \
                    patch.object(isolation, 'process_identity', return_value=identity), \
                    patch.object(isolation.os, 'open', wraps=os.open) as opened, \
                    patch.object(isolation, 'collect_finished', side_effect=lambda *args: order.append('collected')):
                uid, job = isolation.admit_projection_job(work, state, events, jobs, projector, ['-q'], 'example.x_f__mutmut_1')
            self.assertEqual(order, ['collected', 'projected', 'context-issued'])
            records = list((state / 'control/jobs').glob('*.json'))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text())
            expected = {**self.witness('active', 'example.x_f__mutmut_1'), 'projection_sequence': uid}
            self.assertEqual(record['projection'], expected)
            self.assertEqual(record['projection_sha256'], hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest())
            self.assertEqual(record['projection_sequence'], uid)
            self.assertEqual(record['projection_context'], context_receipt)
            self.assertEqual(record['identity'], identity)
            self.assertIs(record['collected'], False)
            record_open = next(call for call in opened.call_args_list if call.args[0] == records[0])
            self.assertEqual(record_open.args[2], 0o600)
            self.assertTrue(job.is_dir() and (job / 'tmp').is_dir())

    def test_live_peer_or_collected_uid_that_is_not_quiescent_never_reprojects(self):
        for collected in (False, True):
            with self.subTest(collected=collected), tempfile.TemporaryDirectory() as directory:
                work, state, jobs, events = self.fixture(Path(directory))
                identity = {'pid': 207, 'uid': 100001, 'start_ticks': 92}
                previous = {'identity': identity, 'uid': 100001, 'directory': str(jobs / 'prior'), 'collected': collected}
                (state / 'control/jobs/prior.json').write_text(json.dumps(previous))
                projector = types.SimpleNamespace(prepare_runtime=Mock())
                with patch.object(isolation.os, 'geteuid', return_value=0), \
                        patch.object(isolation, 'process_identity', return_value=identity), \
                        patch.object(isolation, 'uid_processes', return_value=[identity]), \
                        self.assertRaisesRegex(RuntimeError, 'not quiescent'):
                    isolation.admit_projection_job(work, state, events, jobs, projector, [], '')
                projector.prepare_runtime.assert_not_called()

    def test_dead_prior_owner_with_leaked_uid_is_collected_but_admission_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            work, state, jobs, events = self.fixture(Path(directory))
            prior = jobs / 'prior'; prior.mkdir()
            identity = {'pid': 208, 'uid': 0, 'start_ticks': 93}
            record = state / 'control/jobs/prior.json'
            record.write_text(json.dumps({'identity': identity, 'uid': 100002, 'directory': str(prior), 'collected': False}))
            leftover = {'pid': 209, 'uid': 100002, 'start_ticks': 94}
            projector = types.SimpleNamespace(prepare_runtime=Mock())
            with patch.object(isolation.os, 'geteuid', return_value=0), \
                    patch.object(isolation, 'process_identity', side_effect=ProcessLookupError), \
                    patch.object(isolation, 'uid_processes', side_effect=[[leftover], []]), \
                    patch.object(isolation, 'cancel_exact') as cancel, \
                    self.assertRaisesRegex(RuntimeError, 'leaked owned descendants'):
                isolation.admit_projection_job(work, state, events, jobs, projector, [], 'stats')
            cancel.assert_called_once_with(leftover)
            self.assertEqual(json.loads(record.read_text())['owned_descendants_cancelled'], [leftover])
            self.assertFalse(prior.exists())
            projector.prepare_runtime.assert_not_called()

    def test_busy_admission_and_inconsistent_helper_witness_fail_before_uid_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            work, state, jobs, events = self.fixture(Path(directory))
            projector = types.SimpleNamespace(prepare_runtime=Mock())
            with patch.object(isolation.os, 'geteuid', return_value=0), \
                    patch.object(isolation.fcntl, 'flock', side_effect=BlockingIOError), \
                    self.assertRaisesRegex(RuntimeError, 'another mutation projection admission'):
                isolation.admit_projection_job(work, state, events, jobs, projector, [], '')
            projector.prepare_runtime.assert_not_called()
        for change in ({'mode': 'stats'}, {'active_key': 'other.x_f__mutmut_2'}, {'guard_exit_code': 1}, {'schema_version': 2}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                work, state, jobs, events = self.fixture(Path(directory))
                projector = types.SimpleNamespace(prepare_runtime=Mock(return_value={**self.witness(), **change}))
                with patch.object(isolation.os, 'geteuid', return_value=0), self.assertRaisesRegex(RuntimeError, 'inconsistent admission witness'):
                    isolation.admit_projection_job(work, state, events, jobs, projector, [], '')
                self.assertEqual(list((state / 'control/jobs').glob('*.json')), [])
                self.assertEqual(list(jobs.iterdir()), [])

    def test_wrong_context_receipt_or_changed_stamped_witness_never_launches(self):
        receipt = {'path': 'work/mutants/.ud-runtime-projection.json', 'sha256': 'e' * 64, 'size_bytes': 451}
        for scenario in ('path', 'hash', 'size', 'witness', 'writer-error'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                work, state, jobs, events = self.fixture(Path(directory))
                def issue(actual_work, actual_state, uid, witness):
                    actual = dict(receipt)
                    if scenario == 'path': actual['path'] = '../foreign.json'
                    elif scenario == 'hash': actual['sha256'] = 'not-a-digest'
                    elif scenario == 'size': actual['size_bytes'] = True
                    elif scenario == 'witness': witness['active_key'] = 'different.x_f__mutmut_1'
                    else: raise RuntimeError('context parent identity changed')
                    return actual
                projector = types.SimpleNamespace(prepare_runtime=Mock(return_value=self.witness()), issue_runtime_context=Mock(side_effect=issue))
                with patch.object(isolation.os, 'geteuid', return_value=0), patch.object(isolation.os, 'chown') as chown, \
                        self.assertRaisesRegex(RuntimeError, 'context .*changed'):
                    isolation.admit_projection_job(work, state, events, jobs, projector, [], '')
                chown.assert_not_called()
                self.assertEqual(list((state / 'control/jobs').glob('*.json')), [])
                self.assertEqual(list(jobs.iterdir()), [])

    def test_child_guard_exit_125_is_a_transport_failure_not_a_json_result(self):
        # Original process-result model only: no fork, child or emitted code runs.
        with patch.object(isolation.os, 'fork', return_value=231, create=True), \
                patch.object(isolation.select, 'select', return_value=([1], [], [])), \
                patch.object(isolation.os, 'read', return_value=b''), \
                patch.object(isolation.os, 'waitpid', return_value=(231, 125 << 8), create=True), \
                self.assertRaisesRegex(ChildProcessError, 'mutation child execution failed'):
            isolation.bounded_json_fork(lambda: self.fail('host child must never execute'))


if __name__ == '__main__':
    unittest.main()
