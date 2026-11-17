"""Original unittest-origin fixtures; no generated mutation is executed here."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_original_perl_origin_consumer', ROOT / 'scripts/quality/perl-mutation.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PerlAssertionOriginTests(unittest.TestCase):
    def test_actual_unittest_traceback_distinguishes_test_and_helper_assertions_from_production_invariants(self):
        cases = [
            ('self.assertEqual(1, 2)', 'Killed', None),
            ('from helper import check; check()', 'Killed', 'tests/helper.py'),
            ('from production import check; check()', 'RuntimeError', None),
            ('from framework_in_production import check; check()', 'RuntimeError', None),
        ]
        for statement, wanted, helper_source in cases:
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                bridge = root / 'tests/domain/perl/test_origin.py'
                tool = root / 'tests/mutation/test_perl_fixture.py'
                for file in (bridge, tool):
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text('import unittest\nclass Suite(unittest.TestCase):\n def test_one(self): pass\n')
                (root / 'scripts').mkdir()
                (root / 'scripts/production.py').write_text('def check():\n raise AssertionError("production invariant")\n')
                (root / 'scripts/framework_in_production.py').write_text('import unittest\ndef check():\n unittest.TestCase().assertEqual(1, 2)\n')
                (root / 'tests/helper.py').write_text('def check():\n assert 1 == 2\n')
                bridge.write_text('import unittest,sys\nsys.path[:0]=' + repr([str(root / 'scripts'), str(root / 'tests')]) + '\nclass Suite(unittest.TestCase):\n def test_one(self): ' + statement + '\n')
                tests = {file.relative_to(root).as_posix(): runner.sha(file.read_bytes()) for file in (bridge, tool)}
                expected = runner.test_cases(root, tests)['bridge']
                inventory = [{'path': file.relative_to(root).as_posix(), 'sha256': runner.sha(file.read_bytes())} for file in root.rglob('*.py')]
                output = root / 'result.json'
                completed = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/quality/perl-test-evidence.py'),
                    '--root', str(root), '--suite', 'bridge', '--output', str(output)], capture_output=True, timeout=15,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                self.assertEqual(completed.returncode, 1, completed.stderr)
                completed.unittest_evidence = json.loads(output.read_bytes())
                self.assertEqual(runner.typed_classification(completed, expected, root, inventory)[0], wanted)
                event = completed.unittest_evidence['cases'][0]['events'][0]
                if wanted == 'RuntimeError':
                    self.assertEqual(event['kind'], 'error')
                    self.assertIsNone(event['assertion_origin'])
                else:
                    origin = event['assertion_origin']
                    self.assertEqual(origin['test_id'], expected[0]['id'])
                    self.assertEqual(origin['source'], helper_source or expected[0]['source'])
                    origin['test_line'] = 999
                    self.assertEqual(runner.typed_classification(completed, expected, root, inventory)[0], 'RuntimeError')


if __name__ == '__main__':
    unittest.main()
