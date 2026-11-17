#!/usr/bin/env python3
"""Execute an independently selected original unittest directory with typed outcomes."""
import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import unittest


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, root, **kwargs):
        super().__init__(*args, **kwargs)
        self.root, self.cases, self.current = root, [], None

    def startTest(self, test):
        super().startTest(test)
        source = Path(inspect.getsourcefile(type(test))).resolve(strict=True)
        self.current = {'id': test.id(), 'source': source.relative_to(self.root).as_posix(),
                        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                        'completed': False, 'events': []}
        self.cases.append(self.current)

    def stopTest(self, test):
        self.current['completed'] = True
        self.current = None
        super().stopTest(test)

    def event(self, kind):
        if self.current is None:
            raise ValueError('test outcome has no active case')
        self.current['events'].append({'kind': kind})

    def addSuccess(self, test):
        self.event('success'); super().addSuccess(test)

    def addFailure(self, test, error):
        self.event('failure'); super().addFailure(test, error)

    def addError(self, test, error):
        self.event('error'); super().addError(test, error)

    def addSkip(self, test, reason):
        self.event('skip'); super().addSkip(test, reason)

    def addExpectedFailure(self, test, error):
        self.event('expected-failure'); super().addExpectedFailure(test, error)

    def addUnexpectedSuccess(self, test):
        self.event('unexpected-success'); super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, error):
        if error is not None:
            self.event('subtest-failure' if issubclass(error[0], AssertionError) else 'subtest-error')
        super().addSubTest(test, subtest, error)


def run(root, directory, output):
    root = root.resolve(strict=True)
    start = (root / directory).resolve(strict=True)
    if not start.is_relative_to(root / 'tests') or not start.is_dir():
        raise ValueError('original unittest directory is outside tests')
    sys.path.insert(0, str(root / 'workers/ud/src'))
    suite = unittest.TestLoader().discover(str(start), pattern='test_*.py')
    result = unittest.TextTestRunner(resultclass=lambda *args, **kwargs: ObservedResult(*args, root=root, **kwargs)).run(suite)
    value = {'schema_version': 1, 'kind': 'original-unittest-execution', 'directory': directory,
             'successful': result.wasSuccessful(), 'tests_run': result.testsRun, 'cases': result.cases}
    raw = json.dumps(value, sort_keys=True).encode() + b'\n'
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError('unittest observations exceed report bound')
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    clean = all(case['completed'] and case['events'] == [{'kind': 'success'}] for case in result.cases)
    return 0 if result.wasSuccessful() and result.testsRun > 0 and clean else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.root, args.directory, args.output))
