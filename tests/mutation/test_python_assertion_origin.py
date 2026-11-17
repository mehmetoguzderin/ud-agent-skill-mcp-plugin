"""Real original exception traces; no mutated/projected programs execute."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_original_assertion_origins',Path(__file__).with_name('pytest_evidence.py'))
origins_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(origins_module)


class AssertionOriginTests(unittest.TestCase):
    def classify(self,error,phase='call',test_callable=None):
        callback=test_callable or getattr(self,self._testMethodName)
        return origins_module.AssertionOrigins(ROOT).classify_exception(type(error),error.__traceback__,test_id=self.id(),test_file=__file__,test_callable=callback,phase=phase)

    def test_test_body_assertion_has_current_test_source_line_and_hash(self):
        try:
            raise AssertionError('authored original test failure')
        except AssertionError as error:
            origin=self.classify(error)
        self.assertIsNotNone(origin)
        self.assertEqual(origin['source'],'tests/mutation/test_python_assertion_origin.py')
        self.assertEqual(origin['test_source'],origin['source'])
        self.assertEqual(origin['test_id'],self.id())
        self.assertEqual(origin['line'],origin['test_line'])
        self.assertEqual(len(origin['source_sha256']),64)

    def test_unittest_pytest_fail_and_pytest_raises_assertion_helpers_are_supported(self):
        failures=[]
        try:self.assertEqual(1,2)
        except AssertionError as error:failures.append(self.classify(error))
        try:pytest.fail('authored ordinary assertion helper')
        except pytest.fail.Exception as error:failures.append(self.classify(error))
        try:
            with pytest.raises(ValueError,match='expected'):
                raise ValueError('different')
        except AssertionError as error:failures.append(self.classify(error))
        try:Mock().assert_called_once()
        except AssertionError as error:failures.append(self.classify(error))
        self.assertEqual(len(failures),4)
        self.assertTrue(all(origin and origin['source']=='tests/mutation/test_python_assertion_origin.py' for origin in failures))

    def test_production_assertion_with_outer_test_frame_is_runtime_error(self):
        # Authored ORIGINAL calibration fixture, not a generated mutation.
        with tempfile.TemporaryDirectory(prefix='original-assertion-origin-')as temp:
            file=Path(temp)/'production.py';file.write_text('from unittest.mock import Mock\ndef production_fault():\n    raise AssertionError("ordinary production runtime error")\ndef production_mock_fault():\n    Mock().assert_called_once()\n')
            spec=importlib.util.spec_from_file_location('ud_authored_original_runtime_failure',file)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            for function in(module.production_fault,module.production_mock_fault):
                try:function()
                except AssertionError as error:
                    self.assertIsNone(self.classify(error))

    def test_wrong_phase_type_or_test_ancestry_never_qualifies(self):
        try:raise AssertionError('authored original')
        except AssertionError as error:
            self.assertIsNone(self.classify(error,'setup'))
            self.assertIsNone(self.classify(error,test_callable=self.classify))
        try:raise TypeError('AssertionError: misleading message')
        except TypeError as error:self.assertIsNone(self.classify(error))


if __name__=='__main__':unittest.main()
