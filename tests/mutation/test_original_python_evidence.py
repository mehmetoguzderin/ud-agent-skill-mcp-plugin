import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('original_python_evidence', ROOT / 'scripts/quality/original-python.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class OriginalPythonEvidenceTests(unittest.TestCase):
    def test_real_unittest_events_preserve_failure_and_skip_instead_of_successful_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tests'
            directory.mkdir()
            (directory / 'test_original_probe.py').write_text('''import unittest
class Probe(unittest.TestCase):
 def test_pass(self): self.assertEqual(2+2,4)
 def test_fail(self): self.assertEqual(2+2,5)
 @unittest.skip("required case cannot be skipped")
 def test_skip(self): pass
 @unittest.expectedFailure
 def test_expected(self): self.assertEqual(1,2)
 def test_subtest(self):
  with self.subTest(value=1): self.assertEqual(1,2)
''')
            output = root / 'result.json'
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(evidence.run(root, 'tests', output), 1)
            report = json.loads(output.read_bytes())
            self.assertFalse(report['successful'])
            self.assertEqual(report['tests_run'], 5)
            self.assertTrue(all(case['completed'] for case in report['cases']))
            actual = {case['id'].rsplit('.', 1)[-1]: [event['kind'] for event in case['events']] for case in report['cases']}
            self.assertEqual(actual, {'test_pass': ['success'], 'test_fail': ['failure'], 'test_skip': ['skip'], 'test_expected': ['expected-failure'], 'test_subtest': ['subtest-failure']})
            with self.assertRaises(FileExistsError):
                with contextlib.redirect_stderr(io.StringIO()):
                    evidence.run(root, 'tests', output)

    def test_runner_rejects_non_test_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'other').mkdir()
            with self.assertRaisesRegex(ValueError, 'outside tests'):
                evidence.run(root, 'other', root / 'report.json')


if __name__ == '__main__':
    unittest.main()
