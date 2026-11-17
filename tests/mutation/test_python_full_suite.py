"""Full dispatch is policy, not a fabricated test-to-function coverage claim."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_original_full_suite_driver', ROOT/'scripts/quality/mutmut-driver.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class PythonFullSuiteTests(unittest.TestCase):
    def test_observed_and_unobserved_functions_both_receive_every_real_discovered_test(self):
        mutants = ['example.x_observed__mutmut_1', 'example.x_unobserved__mutmut_1', 'example.x_unobserved__mutmut_2']
        observed = {'example.x_observed': {'tests/test_rules.py::test_first'}}
        durations = {'tests/test_rules.py::test_first': .01, 'tests/test_rules.py::test_second': .02}
        result = driver.full_suite_dispatch(mutants, list(reversed(durations)), observed, durations)
        self.assertEqual(result['strategy'], 'full-discovered-original-suite-not-coverage-selection')
        self.assertEqual(result['function_names'], ['example.x_observed', 'example.x_unobserved'])
        self.assertEqual(result['tests'], list(durations))
        self.assertEqual(result['observed_associations'], {'example.x_observed': ['tests/test_rules.py::test_first']})
        self.assertEqual(observed, {'example.x_observed': {'tests/test_rules.py::test_first'}})
        self.assertEqual(result['observed_durations'], durations)

    def test_missing_unknown_duplicate_and_nonfinite_baseline_ids_fail_before_dispatch(self):
        mutants=['example.x_rule__mutmut_1'];tests=['tests/test_rules.py::test_first']
        for durations in ({}, {'other': .01}, {tests[0]: float('nan')}, {tests[0]: -1}, {tests[0]: True}):
            with self.assertRaises(ValueError):
                driver.full_suite_dispatch(mutants, tests, {}, durations)
        with self.assertRaises(ValueError):
            driver.full_suite_dispatch(mutants, tests, {'example.x_rule': {'other'}}, {tests[0]: .01})
        with self.assertRaises(ValueError):
            driver.full_suite_dispatch(mutants, tests*2, {}, {tests[0]: .01})
        with self.assertRaises(ValueError):
            driver.full_suite_dispatch(mutants*2, tests, {}, {tests[0]: .01})


if __name__ == '__main__':
    unittest.main()
