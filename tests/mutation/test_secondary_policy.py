"""Fixed command, exact mutation and strict report contracts without host mutants."""
import base64
import hashlib
from html import escape
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import shutil
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/quality' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


child = module('secondary_child_policy', 'secondary-child.py')
supervisor = module('secondary_supervisor_policy', 'oci-secondary.py')
model_spec = importlib.util.spec_from_file_location('secondary_policy_posix_model', Path(__file__).with_name('posix_file_model.py'))
model = importlib.util.module_from_spec(model_spec); model_spec.loader.exec_module(model)


def origin_property(source,digest,test_id):
    origin={'contract':'python-test-source-origin-v2','source':source,'source_sha256':digest,'line':2,'test_id':test_id,'test_source':source,'test_source_sha256':digest,'test_line':2}
    return '<property name="ud-assertion-origin" value="'+escape(json.dumps(origin),quote=True)+'"/>'


class SecondaryPolicyTests(unittest.TestCase):
    def test_named_faults_freeze_before_outcomes_and_reuse_only_identical_pristine_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); work = root / 'work'; state = root / 'state'; work.mkdir(); state.mkdir()
            (work / 'tests/mutation').mkdir(parents=True); (work / 'packages').mkdir()
            source = b'first second'; (work / 'packages/source.mjs').write_bytes(source)
            test_source = 'tests/test_contract.py'; test_id = test_source + '::Case::test_result'
            test_bytes = b'def test_result():\n    assert False\n'; (work / test_source).write_bytes(test_bytes)
            digest = hashlib.sha256(test_bytes).hexdigest()
            cases = [{'id': name, 'file': 'packages/source.mjs', 'find': name, 'replace': 'changed', 'runner': 'pytest', 'test': test_id, 'assertion': 'test_result'} for name in ('first', 'second')]
            (work / 'tests/mutation/fault-cases.json').write_text(json.dumps({'schema_version': 1, 'cases': cases}))
            expected = [{'id': test_id, 'source': test_source, 'source_sha256': digest}]
            properties = '<properties><property name="ud-test-id" value="' + test_id + '"/><property name="ud-source" value="' + test_source + '"/><property name="ud-source-sha256" value="' + digest + '"/><property name="ud-failure-kind" value="assertion"/><property name="ud-exception-type" value="builtins.AssertionError"/>' + origin_property(test_source, digest, test_id) + '</properties>'
            calls, frozen = [], []
            class RecordedJobs:
                def run(self, runner, selection='all', mutation=None):
                    calls.append((runner, selection, mutation is not None))
                    if runner == 'pytest-collect': return {'status': 0, 'timed_out': False}, json.dumps(expected).encode()
                    if not frozen: raise AssertionError('outcomes were consumed before the complete schedule')
                    failure = '<failure message="wrong independently expected value"/>' if mutation is not None else ''
                    raw = ('<testsuites><testcase name="test_result">' + properties + failure + '</testcase></testsuites>').encode()
                    return {'status': 1 if mutation is not None else 0, 'timed_out': False}, raw
            receipt = {'source_tree_sha256': 'a' * 64, 'files': [{'path': test_source, 'sha256': digest}]}
            self.assertEqual(supervisor.run_faults(work, state, receipt, RecordedJobs(), verify_schedule=frozen.append), 0)
            self.assertEqual(calls, [('pytest-collect', 'all', False), ('pytest', test_id, False), ('pytest', test_id, True), ('pytest', test_id, True)])
            report = json.loads((state / 'fault-outcomes.json').read_bytes())
            self.assertTrue(report['complete']); self.assertEqual([item['killed_by'] for item in report['outcomes']], [[test_id], [test_id]])
            self.assertEqual((work / 'packages/source.mjs').read_bytes(), source)

    def test_vitest_reporter_uses_the_pinned_testcase_result_api_and_preserves_error_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory).resolve()/'reporter.mjs';file.write_text(child.vitest_reporter_source())
            program="""const{default:Reporter}=await import(process.argv[1]);const r=new Reporter();const a={},b={};r.onTestCaseResult({meta:()=>a,result:()=>({state:'passed',errors:undefined})});r.onTestCaseResult({meta:()=>b,result:()=>({state:'failed',errors:[{name:'TypeError',code:'ERR_ASSERTION',message:'misleading runtime code'}]})});if(a.ud_assertion_errors.length!==0||b.ud_assertion_errors[0].name!=='TypeError'||b.ud_assertion_errors[0].code!=='ERR_ASSERTION')throw Error('wrong structured identity');console.log('pinned-result-api');"""
            result=subprocess.run([shutil.which('node'),'--input-type=module','-e',program,file.as_uri()],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'pinned-result-api\n')

    def test_exact_materialization_preserves_neighbor_and_rejects_wrong_identity_or_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / 'packages').mkdir(); (root / 'tests').mkdir()
            target = root / 'packages/source.mjs'; target.write_bytes(b'export default true;\r\n')
            neighbor = root / 'packages/neighbor'; neighbor.write_bytes(b'unchanged')
            (root / 'tests/fixture.test.mjs').write_bytes(b'// closed test')
            original, replacement = target.read_bytes(), b'export default false;\r\n'
            mutation = {'path': 'packages/source.mjs', 'before_sha256': hashlib.sha256(original).hexdigest(),
                        'after_sha256': hashlib.sha256(replacement).hexdigest(), 'size': len(replacement), 'content_base64': base64.b64encode(replacement).decode()}
            request = {'schema_version': 1, 'runner': 'vitest', 'selection': 'tests/fixture.test.mjs', 'mutation': mutation}
            for change in ({'path': '../outside'}, {'before_sha256': '0' * 64}, {'after_sha256': '0' * 64}, {'size': len(replacement) + 1}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    child.prepare({**request, 'mutation': {**mutation, **change}}, root)
                self.assertEqual(target.read_bytes(), original)
            with self.assertRaisesRegex(ValueError, 'trusted coordinator'):
                child.prepare(request, root)
            self.assertEqual(child.prepare({**request, 'mutation': None}, root), ('vitest', 'tests/fixture.test.mjs'))
            self.assertEqual(target.read_bytes(), original); self.assertEqual(neighbor.read_bytes(), b'unchanged')
            with self.assertRaises(ValueError):
                child.prepare({**request, 'schema_version': True}, root)
            with self.assertRaises(ValueError):
                child.prepare({**request, 'runner': 'shell'}, root)

    def test_reports_never_treat_runtime_errors_or_missing_cases_as_assertion_kills(self):
        junit = b'<testsuites><testsuite><testcase name="expected_contract"><properties><property name="ud-failure-kind" value="assertion"/><property name="ud-exception-type" value="builtins.AssertionError"/></properties><failure message="AssertionError: wrong value">assert 1 == 2</failure></testcase></testsuite></testsuites>'
        source,test_id='tests/test_contract.py','tests/test_contract.py::expected_contract'
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name)
        (root/'tests').mkdir();body=b'def expected_contract():\n    assert False\n';(root/source).write_bytes(body);digest=hashlib.sha256(body).hexdigest()
        binding='<property name="ud-test-id" value="'+test_id+'"/><property name="ud-source" value="'+source+'"/><property name="ud-source-sha256" value="'+digest+'"/>'+origin_property(source,digest,test_id)
        junit=junit.replace(b'</properties>',binding.encode()+b'</properties>');hashes={source:digest}
        self.assertTrue(supervisor.junit(junit, 'expected_contract', True,source_hashes=hashes,source_root=root))
        self.assertFalse(supervisor.junit(junit, 'different_contract', True,source_hashes=hashes,source_root=root))
        self.assertFalse(supervisor.junit(junit.replace(b'failure', b'error'), 'expected_contract', True,source_hashes=hashes,source_root=root))
        self.assertFalse(supervisor.junit(junit.replace(b'value="assertion"', b'value="runtime"').replace(b'AssertionError: wrong value', b'TypeError: expected numeric').replace(b'assert 1 == 2', b'TypeError'), 'expected_contract', True,source_hashes=hashes,source_root=root))
        self.assertFalse(supervisor.junit(junit.replace(b'ud-failure-kind', b'foreign-failure-kind'), 'expected_contract', True,source_hashes=hashes,source_root=root))
        self.assertFalse(supervisor.junit(junit.replace(b'ud-assertion-origin',b'foreign-origin'),failed=True,source_hashes=hashes,source_root=root))
        self.assertFalse(supervisor.junit(junit,failed=True,source_hashes={source:'b'*64},source_root=root))
        def report(message):
            return json.dumps({'numTotalTests': 1, 'numPendingTests': 0, 'numTodoTests': 0, 'numFailedTests': 1, 'success': False,
                               'testResults': [{'assertionResults': [{'fullName': 'suite expected contract', 'status': 'failed', 'failureMessages': [message], 'ud_errors':[{'name':message.partition(':')[0], 'code':None}]}]}]}).encode()
        self.assertTrue(supervisor.vitest(report('AssertionError: expected true'), 'expected contract', True))
        self.assertFalse(supervisor.vitest(report('TypeError: expected callable'), 'expected contract', True))
        self.assertFalse(supervisor.vitest(report('AssertionError: expected true'), 'absent assertion', True))
        for error in ({'name':'TypeError','code':'ERR_ASSERTION'},{'name':'AssertionError','code':'ERR_MODULE_NOT_FOUND'}):
            raw=json.loads(report('AssertionError: expected true'));raw['testResults'][0]['assertionResults'][0]['ud_errors']=[error]
            self.assertFalse(supervisor.vitest(json.dumps(raw).encode(),'expected contract',True))

    def test_exact_test_inventory_rejects_missing_duplicate_or_forged_cases(self):
        source='tests/test_contract.py';temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name)
        (root/'tests').mkdir();body=b'def test_result():\n    assert False\n';(root/source).write_bytes(body);digest=hashlib.sha256(body).hexdigest()
        expected = [{'id': source + '::Case::test_result', 'source': source, 'source_sha256': digest}]
        properties = '<properties><property name="ud-test-id" value="' + expected[0]['id'] + '"/><property name="ud-source" value="' + source + '"/><property name="ud-source-sha256" value="' + digest + '"/></properties>'
        case = '<testcase name="test_result">' + properties.replace('</properties>', '<property name="ud-failure-kind" value="assertion"/><property name="ud-exception-type" value="builtins.AssertionError"/></properties>') + '<failure message="AssertionError: wrong">assert 1 == 2</failure></testcase>'
        case=case.replace('</properties>',origin_property(source,digest,expected[0]['id'])+'</properties>')
        raw = ('<testsuites>' + case + '</testsuites>').encode()
        self.assertTrue(supervisor.junit(raw, 'test_result', True, expected,source_hashes={source:digest},source_root=root))
        for invalid in (b'<testsuites/>', ('<testsuites>' + case + case + '</testsuites>').encode(), raw.replace(digest.encode(), b'b' * 64), raw.replace(b'ud-test-id', b'foreign-test-id')):
            self.assertFalse(supervisor.junit_inventory(invalid, expected))
        test = {'fullName': 'suite result', 'status': 'failed', 'failureMessages': ['AssertionError: wrong'],
                'ud_source': 'tests/contract.test.ts', 'ud_source_sha256': digest, 'ud_name': 'suite > result', 'ud_occurrence': 0,'ud_errors':[{'name':'AssertionError','code':None}]}
        vitest_expected = [{'source': test['ud_source'], 'source_sha256': digest, 'name': test['ud_name'], 'occurrence': 0}]
        def report(tests, count):
            return json.dumps({'numTotalTests': count, 'numFailedTests': count, 'success': False, 'testResults': [{'assertionResults': tests}]}).encode()
        self.assertTrue(supervisor.vitest(report([test], 1), 'result', True, vitest_expected))
        for rows, count in (([], 1), ([test, test], 2), ([{**test, 'ud_source_sha256': 'b' * 64}], 1), ([test], 2)):
            self.assertFalse(supervisor.vitest(report(rows, count), 'result', True, vitest_expected))

    def test_child_cannot_be_started_as_an_ordinary_host_process(self):
        with self.assertRaises(ValueError):
            child.fresh_job(Path('/untrusted/request.json'), Path('/untrusted/result.data'), Path.cwd())

    def test_jobs_require_closed_inputs_and_harvest_exact_bounded_result_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); work = root / 'source'; state = root / 'state'; work.mkdir(); state.mkdir()
            original = b'private source'; (work / 'input').write_bytes(original); (work / 'input').chmod(0o644)
            receipt = {'files': [{'path': 'input', 'sha256': hashlib.sha256(original).hexdigest()}]}
            runtime = {'node_dependencies': {'path': 'node-dependencies.json', 'sha256': 'a' * 64, 'size_bytes': 123}}
            calls = []
            def execute(command, **kwargs):
                calls.append((command, kwargs)); value = b'<testsuites><testcase name="passed"/></testsuites>'
                handoff = {'cwd': '.', 'files': len(kwargs['workspace']['files']), 'readonly_tree': True, 'inventory_sha256': hashlib.sha256(json.dumps(kwargs['workspace'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
                handoff['source_inventory_sha256'] = handoff['inventory_sha256']
                return {'status': 0, 'timed_out': False, 'stdout': '', 'stderr': '', 'handoff': handoff, 'result_bytes': value, 'result_size': len(value), 'result_sha256': hashlib.sha256(value).hexdigest()}
            jobs = supervisor.Jobs(work, state, receipt, execute, runtime)
            outcome, raw = jobs.run('pytest')
            self.assertEqual(outcome['status'], 0); self.assertTrue(supervisor.junit(raw))
            command, call = calls[0]
            self.assertEqual(command[-3:], ['/opt/mutation/harness/secondary-child.py', '{request}', '{result}'])
            self.assertEqual(json.loads(call['request']['bytes']), {'schema_version': 1, 'runner': 'pytest', 'selection': 'all', 'mutation': None})
            self.assertEqual(call['workspace']['files'], [{'path': 'input', 'sha256': receipt['files'][0]['sha256'], 'size': len(original), 'mode': (work / 'input').stat().st_mode & 0o777}])
            self.assertEqual(call['workspace']['readonly_links'][0]['target'], '/opt/mutation/node_modules')
            self.assertIs(call['workspace']['readonly_tree'], True)
            self.assertEqual(call['result']['max_bytes'], 32 * 1024**2)
            self.assertEqual((work / 'input').read_bytes(), original)
            jobs.execute = lambda *arguments, **keywords: {'status': 0, 'handoff': {'readonly_tree': False}}
            with self.assertRaisesRegex(ValueError, 'exact sealed source handoff'):
                jobs.run('pytest')
            jobs.execute = execute
            (work / 'input').write_bytes(b'foreign source')
            with self.assertRaises(ValueError):
                jobs.run('pytest')
            self.assertEqual(len(calls), 1)

    def test_precreated_result_requires_empty_owned_single_link_and_preserves_file_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.enterContext(model.posix_files(child, root))
            file = root / 'result'; file.touch(mode=0o600); file.chmod(0o600)
            before = file.stat(); child.write_result(file, b'bounded structured result')
            self.assertEqual(file.read_bytes(), b'bounded structured result')
            self.assertEqual((file.stat().st_dev, file.stat().st_ino), (before.st_dev, before.st_ino))
            with self.assertRaises(ValueError):
                child.write_result(file, b'replace existing evidence')
            file.write_bytes(b''); file.chmod(0o644)
            with self.assertRaises(ValueError):
                child.write_result(file, b'wrong mode')
            file.chmod(0o600); os.link(file, root / 'alias')
            with self.assertRaises(ValueError):
                child.write_result(file, b'linked result')
            (root / 'alias').unlink(); file.unlink(); file.symlink_to('outside')
            with self.assertRaises(OSError):
                child.write_result(file, b'alias result')

    def test_trusted_materialization_is_sealed_then_restored_even_if_boundary_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); work = root / 'source'; state = root / 'state'; work.mkdir(); state.mkdir()
            target = work / 'source.py'; original = b'answer = True\r\n'; after = b'answer = False\r\n'; target.write_bytes(original)
            receipt = {'files': [{'path': target.name, 'sha256': hashlib.sha256(original).hexdigest()}]}
            runtime = {'node_dependencies': {'path': 'node-dependencies.json', 'sha256': 'a' * 64, 'size_bytes': 123}}
            mutation = {'path': target.name, 'before_sha256': hashlib.sha256(original).hexdigest(), 'after_sha256': hashlib.sha256(after).hexdigest(), 'size': len(after), 'content_base64': base64.b64encode(after).decode()}
            def execute(command, **kwargs):
                self.assertEqual(target.read_bytes(), after)
                self.assertIs(kwargs['workspace']['readonly_tree'], True)
                self.assertEqual(kwargs['workspace']['files'][0]['sha256'], mutation['after_sha256'])
                self.assertIsNone(json.loads(kwargs['request']['bytes'])['mutation'])
                raise RuntimeError('boundary failed before execution')
            with self.assertRaisesRegex(RuntimeError, 'boundary failed'):
                supervisor.Jobs(work, state, receipt, execute, runtime).run('pytest', mutation=mutation)
            self.assertEqual(target.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
