"""Fixed test commands for secondary mutation backends inside a private UID job."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def fresh_job(request_file, result, root):
    if sys.platform != 'linux' or os.getuid() < 100001 or os.getuid() != os.geteuid() or os.getgid() != os.getuid() or os.getgroups():
        raise ValueError('fresh private mutation UID required')
    status = Path('/proc/self/status').read_text()
    if any(next(line for line in status.splitlines() if line.startswith(key + ':')).split()[1] != '0000000000000000' for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd')) or 'NoNewPrivs:\t1' not in status:
        raise ValueError('secondary child retained capabilities or privilege acquisition')
    if root.name != 'tree' or root.parent.parent != Path('/tmp/ud-mutation-jobs') or not re.fullmatch('[a-f0-9]{32}', root.parent.name) or request_file != root.parent / 'request.json' or result != root.parent / 'result.data':
        raise ValueError('secondary files are outside the exact private job')
    info = request_file.lstat()
    tree, parent, output = root.lstat(), root.parent.lstat(), result.lstat()
    if request_file.is_symlink() or not request_file.is_file() or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o777 != 0o444 or root.is_symlink() or tree.st_uid != 0 or tree.st_mode & 0o222 or parent.st_uid != 0 or parent.st_mode & 0o022 or result.is_symlink() or not stat.S_ISREG(output.st_mode) or output.st_uid != os.getuid() or output.st_nlink != 1 or stat.S_IMODE(output.st_mode) != 0o600 or output.st_size != 0:
        raise ValueError('secondary request or result identity differs')


def write_result(result, raw):
    if not isinstance(raw, bytes) or len(raw) > 32 * 1024**2:
        raise ValueError('secondary result is not bounded bytes')
    before = result.lstat()
    descriptor = os.open(result, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        actual = os.fstat(descriptor)
        if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(actual.st_mode) or actual.st_uid != os.getuid() or actual.st_nlink != 1 or stat.S_IMODE(actual.st_mode) != 0o600 or actual.st_size != 0:
            raise ValueError('secondary result is not the empty private precreated file')
        remaining = memoryview(raw)
        while remaining:
            count = os.write(descriptor, remaining)
            if count <= 0:
                raise ValueError('secondary result write made no progress')
            remaining = remaining[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def relative(name):
    if not isinstance(name, str) or name.startswith('/') or any(value in name for value in ('\\', '\0', ':')) or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('safe closed test path required')
    return name


def vitest_reporter_source():
    return "export default class {onTestCaseResult(test){test.meta().ud_assertion_errors=(test.result().errors??[]).map(error=>({name:typeof error.name==='string'?error.name:null,code:error.code??null,message:String(error.message??'').slice(0,8192)}));}}\n"


def prepare(request, root):
    if not isinstance(request, dict) or set(request) != {'schema_version', 'runner', 'selection', 'mutation'} or type(request['schema_version']) is not int or request['schema_version'] != 1 or request['runner'] not in ('pytest', 'pytest-collect', 'vitest', 'vitest-collect', 'acceptance-collect'):
        raise ValueError('fixed secondary test request required')
    selection = request['selection']
    if request['runner'].endswith('-collect') and (selection != 'all' or request['mutation'] is not None):
        raise ValueError('complete pristine test collection required')
    if selection != 'all':
        test = selection.split('::', 1)[0]
        relative(test)
        if not test.startswith('tests/') or not (root / test).is_file():
            raise ValueError('test is outside the closed source handoff')
    mutation = request['mutation']
    if mutation is not None:
        raise ValueError('only the trusted coordinator may materialize a sealed candidate')
    return request['runner'], selection


def main():
    if len(sys.argv) != 3:
        raise ValueError('fixed request and result paths required')
    request_file, result = map(Path, sys.argv[1:])
    root = Path.cwd().resolve(strict=True)
    fresh_job(request_file, result, root)
    raw = request_file.read_bytes()
    if len(raw) > 32 * 1024**2:
        raise ValueError('request exceeds its bound')
    runner, selection = prepare(json.loads(raw), root)
    cache = Path(os.environ['TMPDIR']).resolve(strict=True)
    if cache != root.parent / 'cache' or cache.lstat().st_uid != os.getuid() or stat.S_IMODE(cache.lstat().st_mode) != 0o700:
        raise ValueError('secondary cache is outside its private writable job')
    environment = dict(os.environ)
    environment.update(PYTHONPATH=str(root / 'workers/ud/src'), PYTHONDONTWRITEBYTECODE='1', PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    for name in ('PYTEST_PLUGINS', 'PYTEST_ADDOPTS', 'UD_MUTATION_PYTEST_EVIDENCE', 'MUTANT_UNDER_TEST', 'NODE_OPTIONS'):
        environment.pop(name, None)
    if runner in ('acceptance-collect', 'vitest-collect'):
        environment['PATH'] = '/opt/mutation/git/bin:' + environment.get('PATH', '')
        arguments = ['/opt/mutation/node/bin/node', '/opt/mutation/harness/collect-mutation-tests.mjs', '--python', sys.executable, '--result', str(result)]
        if runner == 'vitest-collect': arguments.extend(['--result-format', 'vitest-tests'])
        completed = subprocess.run(arguments, env=environment, check=False)
        return completed.returncode
    if runner == 'vitest':
        configurations = [name for name in ('vitest.config.mts', 'vitest.config.mjs', 'vitest.config.ts', 'vitest.config.js') if (root / name).is_file()]
        if len(configurations) != 1:
            raise ValueError('one declared Vitest configuration required')
        config = cache / 'secondary-vitest.config.mjs'
        with config.open('x') as destination:
            destination.write('import original from ' + json.dumps((root / configurations[0]).as_uri()) + ';\nexport default {...original,root:' + json.dumps(str(root)) + ',cacheDir:' + json.dumps(str(cache / 'vite-cache')) + ',test:{...original.test,cache:false,fsModuleCache:false}};\n')
    if runner == 'vitest':
        if selection == 'all':
            raise ValueError('fault canary requires its declared test file')
        node = '/opt/mutation/node/bin/node'
        reporter = cache / 'secondary-reporter.mjs'
        with reporter.open('x') as destination:
            destination.write(vitest_reporter_source())
        raw_file = cache / 'vitest-run.raw.json'
        completed = subprocess.run([node, '/opt/mutation/node_modules/vitest/vitest.mjs', 'run', selection, '--config', str(config), '--configLoader=runner', '--reporter', str(reporter), '--reporter=json', '--outputFile=' + str(raw_file)], env=environment, check=False)
        if not raw_file.is_file() or raw_file.stat().st_size > 32 * 1024**2:
            return 2
        data = json.loads(raw_file.read_bytes())
        occurrences = {}
        for suite in data.get('testResults', []):
            source = Path(suite['name']).resolve(strict=True).relative_to(root).as_posix()
            for test in suite.get('assertionResults', []):
                name = ' > '.join([*test['ancestorTitles'], test['title']])
                key = (source, name); occurrence = occurrences.get(key, 0); occurrences[key] = occurrence + 1
                test.update(ud_source=source, ud_source_sha256=hashlib.sha256((root / source).read_bytes()).hexdigest(), ud_name=name, ud_occurrence=occurrence, ud_errors=test.get('meta', {}).get('ud_assertion_errors'))
        write_result(result, json.dumps(data).encode())
        return completed.returncode
    os.environ.clear(); os.environ.update(environment)
    sys.path.insert(0, str(root / 'workers/ud/src'))
    import pytest
    if runner == 'pytest':
        origin_spec=importlib.util.spec_from_file_location('ud_fixed_python_assertion_origin','/opt/mutation/harness/pytest_evidence.py')
        origin_module=importlib.util.module_from_spec(origin_spec);origin_spec.loader.exec_module(origin_module)
        origins=origin_module.AssertionOrigins(root)
        class Binder:
            def pytest_collection_modifyitems(self, items):
                for item in items:
                    source = Path(item.path).resolve(strict=True).relative_to(root).as_posix()
                    item.user_properties.extend([('ud-test-id', item.nodeid), ('ud-source', source), ('ud-source-sha256', hashlib.sha256((root / source).read_bytes()).hexdigest())])
            @pytest.hookimpl(hookwrapper=True)
            def pytest_runtest_makereport(self, item, call):
                yield
                if call.excinfo is not None:
                    exception = call.excinfo.type
                    origin = origins.classify(item, call, call.when)
                    assertion = origin is not None
                    item.user_properties.extend([('ud-failure-kind', 'assertion' if assertion else 'runtime'), ('ud-exception-type', exception.__module__ + '.' + exception.__qualname__)])
                    if origin is not None:item.user_properties.append(('ud-assertion-origin',json.dumps(origin,sort_keys=True,separators=(',',':'))))
        raw_file = cache / 'pytest-run.raw.xml'
        status = pytest.main(['tests' if selection == 'all' else selection, '-q', '-p', 'no:cacheprovider', '--junitxml', str(raw_file)], plugins=[Binder()])
        if not raw_file.is_file() or raw_file.stat().st_size > 32 * 1024**2:
            return 2
        write_result(result, raw_file.read_bytes())
        return status
    rows = []
    class Collector:
        def pytest_collection_finish(self, session):
            for item in session.items:
                source = Path(item.path).resolve(strict=True).relative_to(root).as_posix()
                rows.append({'id': item.nodeid, 'source': source, 'source_sha256': hashlib.sha256((root / source).read_bytes()).hexdigest(), 'runner': 'python'})
    status = pytest.main(['tests', '--collect-only', '-q', '-p', 'no:cacheprovider'], plugins=[Collector()])
    if status == 0 and rows:
        write_result(result, json.dumps(rows).encode())
        return 0
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
