import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import types
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


class MutmutDriverTests(unittest.TestCase):
    def test_metadata_adapter_preserves_real_main_identity_without_calling_target(self):
        import mutmut.mutation.trampoline as trampoline
        adapter_spec = importlib.util.spec_from_file_location('ud_original_metadata_adapter', ROOT/'tests/mutation/mutmut_adapter.py')
        adapter = importlib.util.module_from_spec(adapter_spec); adapter_spec.loader.exec_module(adapter)
        def original_metadata_fixture():
            raise RuntimeError('this target must never execute on host')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file=root/'mutants/scripts/rule.py'; file.parent.mkdir(parents=True); file.write_bytes(b'# metadata identity only\n')
            globals_={'__name__':'__main__'}
            function=types.FunctionType(original_metadata_fixture.__code__.replace(co_filename=str(file)),globals_)
            with mock.patch.object(trampoline,'wrap_in_trampoline',lambda *args,**kwargs:lambda target:target):
                adapter.install(root)
                result=trampoline.wrap_in_trampoline({})(function)
            self.assertIs(result,function)
            self.assertEqual(function.__module__,'scripts.rule')
            self.assertEqual(globals_['__name__'],'__main__')

    def test_streamed_plan_preserves_exact_unicode_definitions_without_materializing_the_iterator(self):
        spec = importlib.util.spec_from_file_location('ud_driver_writer_test', ROOT/'scripts/quality/mutmut-driver.py')
        driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary)/'schedule.json'; rows = [{'id':'α', 'definition':{'replacement':'return "世界"\n'}}, {'id':'β','definition':{'replacement':'return 0\r\n'}}]
            def records():
                yield from rows
            driver.write_schedule(file, {'scheduled':2,'inventory_only':True}, records())
            self.assertEqual(json.loads(file.read_bytes()), {'scheduled':2,'inventory_only':True,'inventory':rows})
            self.assertTrue(file.read_bytes().endswith(b'\n'))
            driver.write_schedule(file, {}, iter(()))
            self.assertEqual(json.loads(file.read_bytes()), {'inventory':[]})
            with self.assertRaises(ValueError):
                driver.write_schedule(file, {'inventory':[]}, records())

    def test_host_variant_generation_collection_and_execution_are_refused_before_any_generated_tree(self):
        with tempfile.TemporaryDirectory(prefix='ud-mutmut-driver-') as temporary:
            root = Path(temporary)
            scripts = root / 'scripts/runtime'
            scripts.mkdir(parents=True)
            (root / 'src/ud_agent').mkdir(parents=True)
            (root / 'src/ud_agent/__init__.py').write_text('')
            (root / 'src/ud_agent/policy.py').write_text('def accepted(value):\n    return value > 2\n')
            source = scripts / 'rule-check.py'
            source.write_text('def allowed(value):\n    return value > 2\n')
            tests = root / 'tests/mutation'
            tests.mkdir(parents=True)
            (tests / 'mutmut_adapter.py').write_bytes((ROOT / 'tests/mutation/mutmut_adapter.py').read_bytes())
            (root / 'tests/test_rule.py').write_text("""import importlib.util
from pathlib import Path
from ud_agent.policy import accepted
spec = importlib.util.spec_from_file_location('arbitrary_test_alias', Path(__file__).resolve().parents[1] / 'scripts/runtime/rule-check.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def test_rule():
    assert module.allowed(2) is False
    assert module.allowed(3) is True
    assert accepted(2) is False
    assert accepted(3) is True
""")
            (root / 'pyproject.toml').write_text('[tool.mutmut]\nsource_paths=["src/ud_agent", "scripts"]\npytest_add_cli_args_test_selection=["tests/test_rule.py"]\nuse_git_change_detection=false\nmutate_only_covered_lines=false\n')
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'qualification': 'trusted-runner-fixture', 'source': str(ROOT), 'source_tree_sha256': 'a' * 64,
                'files': [{'path':'workers/ud/src/ud_agent/__init__.py','sha256':hashlib.sha256(b'').hexdigest()},{'path':'workers/ud/src/ud_agent/policy.py','sha256':hashlib.sha256((root/'src/ud_agent/policy.py').read_bytes()).hexdigest()},{'path': 'scripts/runtime/rule-check.py', 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}, {'path':'tests/test_rule.py','sha256':hashlib.sha256((root/'tests/test_rule.py').read_bytes()).hexdigest()}]}))
            schedule = root / 'schedule.json'
            outcomes = root / 'outcomes.json'
            inventory_command = [sys.executable, str(ROOT / 'scripts/quality/mutmut-driver.py'), '--source-receipt', str(receipt), '--schedule', str(schedule), '--outcomes', str(outcomes), '--jobs', '1', '--inventory-only']
            environment = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTEST_PLUGINS', 'MUTANT_UNDER_TEST', 'UD_MUTATION_OCI_GUARD', 'UD_MUTATION_PYTEST_EVIDENCE')}
            # Collection imports instrumented programs too. A fixture label may
            # never authorize either that import or variant execution on host.
            for command in (inventory_command, inventory_command[:-1]):
                result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, env=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'kernel-confined OCI coordinator', result.stderr)
                self.assertFalse((root/'mutants').exists())
                self.assertFalse(schedule.exists())
                self.assertFalse(outcomes.exists())
            self.assertEqual(source.read_text(), 'def allowed(value):\n    return value > 2\n')



if __name__ == '__main__':
    unittest.main()
