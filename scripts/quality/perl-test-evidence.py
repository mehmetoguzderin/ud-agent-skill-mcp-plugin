#!/usr/bin/env python3
"""Run the closed Perl unittest suites with typed, source-bound outcomes."""
from __future__ import annotations

import argparse
import hashlib
import inspect
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest


def assertion_origins(root):
    fixed = Path('/opt/mutation/harness/pytest_evidence.py')
    source = fixed if fixed.is_file() else Path(__file__).resolve().parents[2] / 'tests/mutation/pytest_evidence.py'
    if os.environ.get('UD_MUTATION_OCI_GUARD') == '1' and source != fixed:
        raise ValueError('protected Perl evidence requires the fixed original SDK classifier')
    spec = importlib.util.spec_from_file_location('ud_perl_original_assertion_origins', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AssertionOrigins(root)


def flatten(suite):
    for value in suite:
        if isinstance(value, unittest.TestSuite):
            yield from flatten(value)
        else:
            yield value


def identity(root, test):
    source = Path(inspect.getsourcefile(type(test))).resolve(strict=True)
    name = source.relative_to(root).as_posix()
    return {"id": test.id(), "source": name,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args, root, **kwargs):
        super().__init__(*args, **kwargs)
        self.root = root
        self.origins = assertion_origins(root)
        self.cases = []
        self.current = None
        self.current_test = None

    def startTest(self, test):
        super().startTest(test)
        self.current = {**identity(self.root, test), "completed": False, "events": []}
        self.current_test = test
        self.cases.append(self.current)

    def stopTest(self, test):
        self.current["completed"] = True
        self.current = None
        self.current_test = None
        super().stopTest(test)

    def event(self, kind, err=None):
        if self.current is None:
            raise ValueError("test event has no active case")
        event = {"kind": kind}
        if err is not None:
            exception, _, trace = err
            method = getattr(self.current_test, self.current_test._testMethodName)
            origin = self.origins.classify_exception(exception, trace, test_id=self.current["id"],
                test_file=inspect.getsourcefile(method), test_callable=method)
            if kind == "failure" and origin is None:
                event["kind"] = "error"
            event.update(exception_type=exception.__module__ + "." + exception.__qualname__,
                         assertion=origin is not None, assertion_origin=origin)
        self.current["events"].append(event)

    def addSuccess(self, test):
        self.event("success")
        super().addSuccess(test)

    def addFailure(self, test, err):
        self.event("failure", err)
        super().addFailure(test, err)

    def addError(self, test, err):
        self.event("error", err)
        super().addError(test, err)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.event("failure" if issubclass(err[0], AssertionError) else "error", err)
        super().addSubTest(test, subtest, err)

    def addSkip(self, test, reason):
        self.event("skip")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self.event("expected-failure", err)
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self.event("unexpected-success")
        super().addUnexpectedSuccess(test)


def write_result(output, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("typed Perl test evidence exceeds its bound")
    if os.name == 'nt':
        # Windows originals use the existing exclusive, handle-verified private
        # ACL creator; mode bits and POSIX descriptor flags are not authority.
        import importlib.util
        spec = importlib.util.spec_from_file_location('ud_perl_evidence_windows_acl', Path(__file__).with_name('windows-storage-acl.py'))
        native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
        native.WindowsStorage().create(str(Path(output).absolute()), 'file', raw)
        return
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError("typed test result is not a private ordinary file")
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ValueError("typed test result write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(root, suite_name, output):
    root = root.resolve(strict=True)
    if suite_name not in ("bridge", "tool"):
        raise ValueError("unknown closed Perl test suite")
    start = root / ("tests/domain/perl" if suite_name == "bridge" else "tests/mutation")
    pattern = "test_*.py" if suite_name == "bridge" else "test_perl_*.py"
    sys.path.insert(0, str(root / "workers/ud/src"))
    suite = unittest.TestLoader().discover(str(start), pattern=pattern)
    expected = [identity(root, test) for test in flatten(suite)]
    if not expected or len({item["id"] for item in expected}) != len(expected):
        raise ValueError("typed test collection is empty or duplicated")
    result = unittest.TextTestRunner(resultclass=lambda *args, **kwargs: EvidenceResult(*args, root=root, **kwargs)).run(suite)
    value = {"schema_version": 1, "contract": "python-test-source-origin-v2", "suite": suite_name,
             "expected": expected, "cases": result.cases, "tests_run": result.testsRun,
             "successful": result.wasSuccessful()}
    write_result(output, value)
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--suite", choices=("bridge", "tool"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return run(args.root, args.suite, args.output)


if __name__ == "__main__":
    sys.exit(main())
