"""Protocol tests do not execute mutant code or stand in for kernel evidence."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ud_stryker_controller_test', ROOT / 'scripts/quality/stryker-exec.py')
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


def request():
    return {'schema_version': 1, 'id': '1', 'kind': 'dry-run', 'workspace': {'root': '/state/work/sandbox', 'files': []},
            'options': {'timeout': 1000, 'disableBail': True, 'coverageAnalysis': 'off'}}


def compiled():
    return {'schema_version': 1, 'normalization': 'ud-job-root-and-inline-map-1', 'child_root': '/tmp/ud-mutation-jobs/' + 'a' * 32 + '/tree', 'entries': [{'source': 'tests/original.test.mjs'}]}


class StrykerControllerTests(unittest.TestCase):
    def test_variants_require_bounded_original_compilation_authority_and_cannot_supply_it_for_a_dry_run(self):
        value = request(); value['assertion_compiled_sources'] = compiled()
        with self.assertRaisesRegex(ValueError, 'unknown or missing'):
            CONTROLLER.parse_frame(json.dumps(value).encode() + b'\n')
        for invalid in [None, {}, {**compiled(), 'entries': []}, {**compiled(), 'child_root': '/another/tree'}, {**compiled(), 'schema_version': True}, {**compiled(), 'untrusted': True}]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                CONTROLLER.compiled_sources(invalid)
        self.assertEqual(CONTROLLER.compiled_sources(compiled()), compiled())

    def test_requires_bounded_complete_unambiguous_frames(self):
        value = request()
        encoded = json.dumps(value).encode() + b'\n'
        self.assertEqual(CONTROLLER.parse_frame(encoded), value)
        for frame in [encoded[:-1], b'\n', b'{}\n', b'{"id":"1","id":"2"}\n', b'\xff\n']:
            with self.subTest(frame=frame), self.assertRaises((ValueError, UnicodeError)):
                CONTROLLER.parse_frame(frame)
        for key, invalid in [('schema_version', True), ('id', '0'), ('id', '../other'), ('kind', 'shell')]:
            changed = request(); changed[key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError):
                CONTROLLER.parse_frame(json.dumps(changed).encode() + b'\n')

    def test_forbids_filtering_extra_commands_and_unbounded_timeouts(self):
        for change in [lambda value: value['options'].update(command=['sh']), lambda value: value['options'].update(disableBail=False),
                       lambda value: value['options'].update(timeout=True), lambda value: value['options'].update(timeout=540001),
                       lambda value: value['options'].update(testFilter=['one']), lambda value: value['options'].update(coverageAnalysis='all')]:
            value = request(); change(value)
            with self.assertRaises(ValueError):
                CONTROLLER.parse_frame(json.dumps(value).encode() + b'\n')

    def test_mutant_identity_source_and_activation_are_closed_contracts(self):
        value = request(); value['kind'] = 'mutant'
        value['assertion_compiled_sources'] = compiled()
        value['options'] = {'timeout': 1000, 'disableBail': True, 'activeMutant': {'id': '123'}, 'mutantActivation': 'runtime', 'reloadEnvironment': True, 'sandboxFileName': 'packages/source.ts'}
        content = b'export const answer = 41;\n'
        value['mutation'] = {'path': 'packages/source.ts', 'before_sha256': 'a' * 64, 'after_sha256': hashlib.sha256(content).hexdigest(), 'definition_sha256': 'b' * 64, 'materializer_version': 'stryker-ast-materializer-v1', 'serialized_replacement': '41', 'size': len(content), 'content_base64': base64.b64encode(content).decode()}
        self.assertEqual(CONTROLLER.parse_frame(json.dumps(value).encode() + b'\n'), value)
        grader = json.loads(json.dumps(value))
        grader['options']['sandboxFileName'] = 'evals/graders/workflow.mjs'
        grader['mutation']['path'] = 'evals/graders/workflow.mjs'
        self.assertEqual(CONTROLLER.parse_frame(json.dumps(grader).encode() + b'\n'), grader)
        for key, invalid in [('size', len(content) + 1), ('after_sha256', '0' * 64), ('content_base64', 'invalid!'), ('path', 'scripts/another.py')]:
            changed = json.loads(json.dumps(value)); changed['mutation'][key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                CONTROLLER.parse_frame(json.dumps(changed).encode() + b'\n')
        for source in ['../outside', '/absolute', 'a\\b', 'a/../b', 'C:file', 'a//b']:
            changed = json.loads(json.dumps(value)); changed['options']['sandboxFileName'] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                CONTROLLER.parse_frame(json.dumps(changed).encode() + b'\n')
        value['options']['activeMutant']['command'] = 'arbitrary'
        with self.assertRaises(ValueError):
            CONTROLLER.parse_frame(json.dumps(value).encode() + b'\n')

    def test_handoff_uses_only_the_fixed_node_child_and_the_pinned_dependency_receipt(self):
        calls = []
        body = b'{"schema_version":1}'
        def execute(command, **kwargs):
            calls.append((command, kwargs))
            return {'status': 0, 'timed_out': False, 'owned_descendants_cancelled': [], 'result_bytes': body,
                    'result_size': len(body), 'result_sha256': hashlib.sha256(body).hexdigest()}
        runtime = {'node_dependencies': {'path': 'node-dependencies.json', 'sha256': 'a' * 64, 'size_bytes': 20}}
        with patch.dict(os.environ, {}, clear=True):
            result = CONTROLLER.handle(request(), state=PurePosixPath('/state'), source_root=PurePosixPath('/state/work/sandbox'), runtime=runtime, execute=execute)
        command, kwargs = calls[0]
        self.assertEqual(command, ['/opt/mutation/node/bin/node', '/opt/mutation/harness/stryker-child.mjs', '{request}', '{result}'])
        self.assertEqual(kwargs['timeout'], 31)
        self.assertEqual(kwargs['workspace']['readonly_links'][0], {'path': 'node_modules', 'target': '/opt/mutation/node_modules',
            'closure_receipt': {'path': '/opt/mutation/node-dependencies.json', 'sha256': 'a' * 64, 'size_bytes': 20}})
        self.assertIs(kwargs['workspace']['readonly_tree'], True)
        self.assertIs(json.loads(kwargs['request']['bytes'])['readonly_tree'], True)
        self.assertEqual(json.loads(kwargs['request']['bytes'])['options']['disableBail'], True)
        self.assertEqual(base64.b64decode(result['result_base64']), body)
        self.assertNotIn('result_bytes', result['execution'])
        self.assertNotIn('SSH_AUTH_SOCK', kwargs['environment'])

    def test_exact_mutation_is_prepared_as_data_before_sealing_without_writing_the_parent(self):
        value = request(); value['kind'] = 'mutant'
        value['assertion_compiled_sources'] = compiled()
        target = 'packages/example/src/source.ts'
        value['workspace']['files'] = [{'path': target, 'sha256': 'c' * 64, 'size': 512, 'mode': 0o644}]
        value['options'] = {'timeout': 1000, 'disableBail': True, 'activeMutant': {'id': '123'}, 'mutantActivation': 'runtime', 'reloadEnvironment': True, 'sandboxFileName': target}
        content = b'export const answer = false;\n'
        value['mutation'] = {'path': target, 'before_sha256': 'a' * 64, 'after_sha256': hashlib.sha256(content).hexdigest(), 'definition_sha256': 'b' * 64, 'materializer_version': 'stryker-ast-materializer-v1', 'serialized_replacement': 'false', 'size': len(content), 'content_base64': base64.b64encode(content).decode()}
        original = json.dumps(value, sort_keys=True)
        calls = []
        def execute(command, **kwargs):
            calls.append(kwargs)
            return {'status': 0, 'result_bytes': b'{}', 'result_size': 2, 'result_sha256': hashlib.sha256(b'{}').hexdigest()}
        runtime = {'node_dependencies': {'path': 'node-dependencies.json', 'sha256': 'd' * 64, 'size_bytes': 20}}
        with patch.dict(os.environ, {}, clear=True):
            CONTROLLER.handle(value, state=PurePosixPath('/state'), source_root=PurePosixPath('/state/work/sandbox'), runtime=runtime, execute=execute)
        self.assertEqual(calls[0]['workspace']['materializations'], [{'path': target, 'before_sha256': 'c' * 64,
            'after_sha256': hashlib.sha256(content).hexdigest(), 'size': len(content), 'bytes': content}])
        self.assertIs(calls[0]['workspace']['readonly_tree'], True)
        self.assertEqual(json.loads(calls[0]['request']['bytes'])['mutation']['before_sha256'], 'a' * 64)
        self.assertEqual(json.loads(calls[0]['request']['bytes'])['assertion_compiled_sources'], compiled())
        self.assertEqual(json.dumps(value, sort_keys=True), original)
        for members in [[], value['workspace']['files'] * 2]:
            value['workspace']['files'] = members
            with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'one closed sandbox member'):
                CONTROLLER.handle(value, state=PurePosixPath('/state'), source_root=PurePosixPath('/state/work/sandbox'), runtime=runtime, execute=execute)
        self.assertEqual(len(calls), 1)

    def test_refuses_another_sandbox_and_mismatched_harvested_result_bytes(self):
        def never(*args, **kwargs):
            self.fail('boundary must not be invoked for another sandbox')
        with self.assertRaisesRegex(ValueError, 'source root'):
            CONTROLLER.handle(request(), state=PurePosixPath('/state'), source_root=PurePosixPath('/state/another'), runtime={}, execute=never)
        def invalid(*args, **kwargs):
            return {'result_bytes': b'changed', 'result_size': 7, 'result_sha256': '0' * 64}
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'byte contract'):
            CONTROLLER.handle(request(), state=PurePosixPath('/state'), source_root=PurePosixPath('/state/work/sandbox'),
                runtime={'node_dependencies': {'path': 'node-dependencies.json', 'sha256': 'a' * 64, 'size_bytes': 20}}, execute=invalid)


if __name__ == '__main__':
    unittest.main()
