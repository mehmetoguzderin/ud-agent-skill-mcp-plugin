from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("ud_mutation_evidence", Path(__file__).with_name("pytest_evidence.py"))
assert spec and spec.loader
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTests(unittest.TestCase):
    def test_assertions_are_distinct_from_errors_and_skips(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "events.jsonl"
            def report(message, phase="call", failed=True, skipped=False, exception_type=AssertionError):
                crash = types.SimpleNamespace(message=message)
                return types.SimpleNamespace(when=phase, failed=failed, skipped=skipped, nodeid="test::one",
                                             longrepr=types.SimpleNamespace(reprcrash=crash), ud_assertion_failure=evidence.assertion_failure(exception_type, phase),
                                             ud_exception_type=exception_type.__module__+'.'+exception_type.__qualname__,
                                             ud_assertion_origin={'contract':evidence.CONTRACT})
            with patch.object(evidence, "_OUTPUT", str(output)), patch("mutmut.mutation.trampoline.get_mutant_under_test", return_value="m.x__mutmut_1"):
                evidence.pytest_runtest_logreport(report("assert False"))
                evidence.pytest_runtest_logreport(report("AssertionError: nope"))
                evidence.pytest_runtest_logreport(report("TypeError: crash",exception_type=TypeError))
                evidence.pytest_runtest_logreport(report("AssertionError", phase="setup"))
                evidence.pytest_runtest_logreport(report("", failed=False, skipped=True))
            events = [json.loads(line)["event"] for line in output.read_text().splitlines()]
            self.assertEqual(events, ["failure", "failure", "error", "error", "skipped"])

    def test_runtime_message_or_code_cannot_masquerade_as_an_assertion(self):
        import pytest
        self.assertTrue(evidence.assertion_failure(AssertionError,'call'))
        self.assertTrue(evidence.assertion_failure(pytest.fail.Exception,'call'))
        class Misleading(TypeError):
            code='ERR_ASSERTION'
        for exception_type in (TypeError,ValueError,Misleading,RuntimeError,None,'AssertionError'):
            self.assertFalse(evidence.assertion_failure(exception_type,'call'))
        for phase in ('setup','teardown','collection'):
            self.assertFalse(evidence.assertion_failure(AssertionError,phase))

    def test_report_hook_binds_real_exception_ancestry_and_missing_binding_fails_closed(self):
        actual=types.SimpleNamespace(when='call')
        hook=evidence.pytest_runtest_makereport(None,types.SimpleNamespace(excinfo=types.SimpleNamespace(type=TypeError)))
        next(hook)
        with self.assertRaises(StopIteration):
            hook.send(types.SimpleNamespace(get_result=lambda:actual))
        self.assertFalse(actual.ud_assertion_failure)
        self.assertEqual(actual.ud_exception_type,'builtins.TypeError')
        event=types.SimpleNamespace(failed=True,skipped=False,when='call',nodeid='test::hostile',longrepr=types.SimpleNamespace(reprcrash=types.SimpleNamespace(message='AssertionError: misleading runtime message')))
        with patch.object(evidence,'_write')as write:
            evidence.pytest_runtest_logreport(event)
        self.assertEqual(write.call_args.args[0]['event'],'error')


if __name__ == "__main__":
    unittest.main()
