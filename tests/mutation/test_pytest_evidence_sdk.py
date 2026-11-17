"""Original SDK-copy checks; candidate and grader source remain unexecuted data."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_original_pytest_evidence_sdk_producer', ROOT / 'scripts/quality/prepare-mutation-runtime.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class PytestEvidenceSdkTests(unittest.TestCase):
    def test_fixed_sdk_copy_uses_exact_original_test_source_despite_candidate_and_quality_decoys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'tests/mutation/pytest_evidence.py'
            source.parent.mkdir(parents=True)
            original = b'# exact original evidence classifier data\nORIGIN = "original"\n'
            source.write_bytes(original)
            for relative in ('scripts/quality/pytest_evidence.py', 'mutants/tests/mutation/pytest_evidence.py'):
                decoy = root / relative
                decoy.parent.mkdir(parents=True)
                decoy.write_bytes(b'# modified candidate must not grade its own result\n')
            harness = root / 'harness'
            harness.mkdir()
            producer.copy_pytest_evidence(root, harness)
            self.assertEqual((harness / 'pytest_evidence.py').read_bytes(), original)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(producer.digest(harness / 'pytest_evidence.py'), producer.digest(source))
            self.assertEqual(sorted(path.name for path in harness.iterdir()), ['pytest_evidence.py'])

    def test_absent_original_cannot_fall_back_to_candidate_or_quality_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in ('scripts/quality/pytest_evidence.py', 'mutants/tests/mutation/pytest_evidence.py'):
                file = root / relative
                file.parent.mkdir(parents=True)
                file.write_bytes(b'# only a decoy exists\n')
            harness = root / 'harness'
            harness.mkdir()
            with self.assertRaisesRegex(ValueError, 'original pytest evidence source'):
                producer.copy_pytest_evidence(root, harness)
            self.assertFalse((harness / 'pytest_evidence.py').exists())


if __name__ == '__main__':
    unittest.main()
