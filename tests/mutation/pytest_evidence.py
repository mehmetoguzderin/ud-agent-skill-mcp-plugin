"""Record per-mutant pytest outcomes; mutmut's aggregate treats internal errors as kills."""
from __future__ import annotations
import json
import os
import hashlib
import inspect
from pathlib import Path
import stat
import unittest.case
import unittest.mock
import pytest
import _pytest.outcomes
import _pytest.raises

_OUTPUT = os.environ.get("UD_MUTATION_PYTEST_EVIDENCE")
_ORIGINS = None
CONTRACT = 'python-test-source-origin-v2'


def assertion_failure(exception_type, phase):
    return phase == 'call' and isinstance(exception_type, type) and issubclass(exception_type, (AssertionError, pytest.fail.Exception))


class AssertionOrigins:
    """Use live tracebacks and ordinary immutable test inputs, never messages."""
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.libraries = frozenset(Path(module.__file__).resolve(strict=True)
                                   for module in (unittest.case, unittest.mock, _pytest.outcomes, _pytest.raises))

    def source(self, filename):
        file = Path(filename)
        if not file.is_absolute():
            raise ValueError('assertion source is not absolute')
        file = file.resolve(strict=True)
        name = file.relative_to(self.root).as_posix()
        if not name.startswith('tests/') or not name.endswith('.py'):
            raise ValueError('assertion source is not an immutable test/helper')
        with file.open('rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 4 * 1024**2:
                raise ValueError('assertion source is not bounded ordinary data')
            content = stream.read(4 * 1024**2 + 1)
            after = os.fstat(stream.fileno())
        if len(content) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('assertion source changed during read')
        return name, hashlib.sha256(content).hexdigest(), len(content.splitlines())

    def classify(self, item, call, phase):
        exception = call.excinfo
        if exception is None or not assertion_failure(exception.type, phase):
            return None
        return self.classify_exception(exception.type, exception.value.__traceback__, test_id=item.nodeid,
                                       test_file=item.path, test_callable=item.obj, phase=phase)

    def classify_exception(self, exception_type, traceback, *, test_id, test_file, test_callable, phase='call'):
        """The same traceback rule also serves unittest's original error tuple."""
        if not assertion_failure(exception_type, phase):
            return None
        try:
            code = inspect.unwrap(test_callable).__code__
            trace, frames = traceback, []
            while trace is not None:
                frames.append((trace.tb_frame.f_code, trace.tb_lineno))
                trace = trace.tb_next
            ancestry = [(frame, line) for frame, line in frames if frame is code]
            if not ancestry or not isinstance(test_id, str) or not test_id:
                return None
            test_source, test_hash, test_lines = self.source(str(Path(test_file).resolve(strict=True)))
            test_code_source, _, _ = self.source(code.co_filename)
            if test_code_source != test_source:
                return None
            while frames and Path(frames[-1][0].co_filename).resolve(strict=True) in self.libraries:
                frames.pop()
            if not frames:
                return None
            source, source_hash, lines = self.source(frames[-1][0].co_filename)
            line, test_line = frames[-1][1], ancestry[-1][1]
            if not 1 <= line <= lines or not 1 <= test_line <= test_lines:
                return None
            return {'contract': CONTRACT, 'source': source, 'source_sha256': source_hash, 'line': line,
                    'test_id': test_id, 'test_source': test_source,
                    'test_source_sha256': test_hash, 'test_line': test_line}
        except (AttributeError, OSError, ValueError, TypeError):
            return None


def pytest_configure(config):
    global _ORIGINS
    _ORIGINS = AssertionOrigins(config.rootpath)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    result = yield
    report = result.get_result()
    exception_type = call.excinfo.type if call.excinfo is not None else None
    origin = _ORIGINS.classify(item, call, report.when) if _ORIGINS is not None else None
    report.ud_assertion_failure = origin is not None
    report.ud_assertion_origin = origin
    report.ud_exception_type = None if exception_type is None else exception_type.__module__ + '.' + exception_type.__qualname__


def _write(payload):
    if not _OUTPUT:
        return
    from mutmut.mutation.trampoline import get_mutant_under_test
    mutant = get_mutant_under_test()
    if "__mutmut_" not in mutant:
        return
    payload["mutant"] = mutant
    data = (json.dumps(payload, ensure_ascii=True) + "\n").encode("utf-8")
    fd = os.open(_OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def pytest_runtest_logreport(report):
    if report.failed:
        detail = getattr(getattr(report, "longrepr", None), "reprcrash", None)
        message = getattr(detail, "message", "")
        origin=getattr(report,'ud_assertion_origin',None)
        is_assertion = report.when == "call" and getattr(report, 'ud_assertion_failure', False) is True and isinstance(origin,dict) and origin.get('contract')==CONTRACT
        _write({"event": "failure" if is_assertion else "error", "phase": report.when, "nodeid": report.nodeid, "message": message,
                "assertion_contract": CONTRACT if is_assertion else None,
                "exception_type": getattr(report, 'ud_exception_type', None),
                "assertion_origin": getattr(report, 'ud_assertion_origin', None)})
    elif report.skipped:
        _write({"event": "skipped", "phase": report.when, "nodeid": report.nodeid})


def pytest_collectreport(report):
    if report.failed or report.skipped:
        _write({"event": "error" if report.failed else "skipped", "phase": "collection", "nodeid": report.nodeid})
