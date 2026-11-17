"""Portable bounded fault-canary runner for any native development host.

Runs the reviewed bounded corpus (tests/mutation/fault-cases.json) with the
same definitions, test reports and kill criteria as the protected OCI runner
(oci-secondary.py, secondary-child.py), but with the host's locked development
toolchains instead of the protected Linux SDK image. It provides no kernel
confinement; the gate records it as the `portable-host` runner.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def outcome(status, timed_out=False):
    return {'status': status, 'timed_out': timed_out, 'cancelled': False, 'owned_descendants_cancelled': []}


class Portable:
    def __init__(self, work, output, python, node, cargo, guard, timeout):
        self.work, self.output, self.python, self.node, self.cargo, self.guard, self.timeout = work, output, python, node, cargo, guard, timeout
        # Scratch (Rust target, Vite caches) stays in the private TMPDIR, not the
        # retained output directory.
        self.cache = Path(tempfile.mkdtemp(prefix='fault-portable-'))
        self.secondary = load('ud_portable_secondary', HERE / 'oci-secondary.py')
        self.child = load('ud_portable_secondary_child', HERE / 'secondary-child.py')
        self.environment = {key: value for key, value in os.environ.items() if key not in ('PYTEST_PLUGINS', 'PYTEST_ADDOPTS', 'UD_MUTATION_PYTEST_EVIDENCE', 'MUTANT_UNDER_TEST', 'NODE_OPTIONS', 'PYTHONPATH')}
        self.environment.update(PYTHONPATH=str(work / 'workers/ud/src'), PYTHONDONTWRITEBYTECODE='1', PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', UD_AGENT_PYTHON=python, UD_RELEASE_PYTHON=python, CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(self.cache / 'rust-target'))
        self.count = 0
        if guard:
            target = work / 'target/debug/ud-agent-guard'
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(guard, target); target.chmod(0o755)

    def process(self, label, arguments, **options):
        self.count += 1
        log = self.output / f'job-{self.count:04d}-{label}.log'
        try:
            with log.open('wb') as destination:
                completed = subprocess.run(arguments, cwd=self.work, env=self.environment, stdout=destination, stderr=subprocess.STDOUT, timeout=self.timeout, check=False, **options)
            return outcome(completed.returncode), log.read_bytes()
        except subprocess.TimeoutExpired:
            return outcome(None, True), log.read_bytes()

    def mutated(self, mutation):
        """Apply one exact named defect and always restore the original bytes."""
        class Applied:
            def __enter__(inner):
                if mutation is None:
                    return
                inner.file = self.work / mutation['path']; inner.original = inner.file.read_bytes()
                content = base64.b64decode(mutation['content_base64'], validate=True)
                sha = self.secondary.sha
                if sha(inner.original) != mutation['before_sha256'] or sha(content) != mutation['after_sha256'] or len(content) != mutation['size']:
                    raise ValueError('named defect differs from its exact source identities')
                inner.file.write_bytes(content)
            def __exit__(inner, *_):
                if mutation is not None:
                    inner.file.write_bytes(inner.original)
                    if self.secondary.sha(inner.file.read_bytes()) != mutation['before_sha256']:
                        raise ValueError('mutated source was not restored')
        return Applied()

    def vitest(self, selection, mutation=None):
        configurations = [name for name in ('vitest.config.mts', 'vitest.config.mjs', 'vitest.config.ts', 'vitest.config.js') if (self.work / name).is_file()]
        if len(configurations) != 1:
            raise ValueError('one declared Vitest configuration required')
        self.count += 1
        job = self.cache / f'vitest-{self.count:04d}'; job.mkdir()
        config = job / 'config.mjs'
        config.write_text('import original from ' + json.dumps((self.work / configurations[0]).as_uri()) + ';\nexport default {...original,root:' + json.dumps(str(self.work)) + ',cacheDir:' + json.dumps(str(job / 'vite-cache')) + ',test:{...original.test,cache:false,fsModuleCache:false}};\n')
        reporter = job / 'reporter.mjs'; reporter.write_text(self.child.vitest_reporter_source())
        raw_file = job / 'vitest-run.raw.json'
        with self.mutated(mutation):
            status, _ = self.process('vitest', [self.node, str(self.work / 'node_modules/vitest/vitest.mjs'), 'run', selection, '--config', str(config), '--configLoader=runner', '--reporter', str(reporter), '--reporter=json', '--outputFile=' + str(raw_file)])
        if not raw_file.is_file():
            return status, None
        data = json.loads(raw_file.read_bytes()); occurrences = {}
        for suite in data.get('testResults', []):
            source = Path(suite['name']).resolve(strict=True).relative_to(self.work).as_posix()
            for test in suite.get('assertionResults', []):
                name = ' > '.join([*test['ancestorTitles'], test['title']])
                key = (source, name); occurrence = occurrences.get(key, 0); occurrences[key] = occurrence + 1
                test.update(ud_source=source, ud_source_sha256=hashlib.sha256((self.work / source).read_bytes()).hexdigest(), ud_name=name, ud_occurrence=occurrence, ud_errors=test.get('meta', {}).get('ud_assertion_errors'))
        return status, json.dumps(data).encode()

    def vitest_collect(self, selection):
        status, raw = self.vitest(selection)
        if raw is None:
            raise ValueError('portable fault test discovery failed')
        return [{'id': f"{test['ud_source']}::{test['ud_name']}::{test['ud_occurrence']}", 'source': test['ud_source'], 'source_sha256': test['ud_source_sha256'], 'name': test['ud_name'], 'occurrence': test['ud_occurrence'], 'runner': 'vitest'}
                for suite in json.loads(raw)['testResults'] for test in suite['assertionResults']]

    def pytest(self, selection, mutation=None, collect=False):
        self.count += 1
        result = self.cache / f'pytest-{self.count:04d}.{"json" if collect else "xml"}'
        with self.mutated(mutation):
            status, _ = self.process('pytest', [self.python, '-B', str(Path(__file__).resolve()), '--pytest-child', 'collect' if collect else 'run', selection, str(result), str(self.work / 'tests/mutation/pytest_evidence.py')])
        return status, result.read_bytes() if result.is_file() else None

    def rust_tests(self, test_file):
        stem = Path(test_file).stem
        status, raw = self.process('rust-list', [self.cargo, 'test', '--offline', '--locked', '--test', stem, '--', '--list', '--format=terse'])
        if status['status'] != 0:
            raise ValueError('portable Rust test discovery failed')
        source_sha256 = hashlib.sha256((self.work / test_file).read_bytes()).hexdigest()
        names = [line[:-len(': test')] for line in raw.decode('utf-8', 'replace').splitlines() if line.endswith(': test')]
        return [{'id': f'{test_file}::{name}', 'source': test_file, 'source_sha256': source_sha256, 'name': name, 'runner': 'rust'} for name in names]

    def rust_phase(self, label, arguments):
        status, raw = self.process(label, arguments)
        code = status['status']
        return {'phase': label, 'process_status': 'Success' if code == 0 else 'Timeout' if status['timed_out'] else {'Failure': code}, 'artifacts_complete': not status['timed_out']}, raw.decode('utf-8', 'replace')

    def rust(self, case, definition, mutation, tests):
        test_file, name = case['test'].split('::', 1)
        stem = Path(test_file).stem
        baseline, text = self.rust_phase('baseline', [self.cargo, 'test', '--offline', '--locked', '--test', stem, '--', '--exact', name])
        if baseline['process_status'] != 'Success' or f'test {name} ... ok' not in text:
            raise ValueError('fault baseline failed: ' + case['id'])
        with self.mutated(mutation):
            phases = [self.rust_phase('compile-library', [self.cargo, 'build', '--offline', '--locked'])[0],
                      self.rust_phase('compile-tests', [self.cargo, 'test', '--offline', '--locked', '--test', stem, '--no-run'])[0]]
            third, text = self.rust_phase('run-tests', [self.cargo, 'test', '--offline', '--locked', '--test', stem])
            phases.append(third)
        restored = hashlib.sha256((self.work / mutation['path']).read_bytes()).hexdigest() == mutation['before_sha256']
        failed = re.findall(r'^test (\S+) \.\.\. FAILED$', text, re.M)
        known = {test['name']: test['id'] for test in tests if test.get('runner') == 'rust'}
        killed_by = [known[item] for item in failed if item in known]
        section = re.search(r'^---- ' + re.escape(name) + r' stdout ----\n(.*?)(?=^---- |^failures:$)', text, re.M | re.S)
        # The named test must panic at an assertion macro in its own test source
        # (the location libtest prints), not at an unwrap or a harness error.
        location = section and re.search(r"panicked at " + re.escape(test_file) + r":(\d+):(\d+):", section.group(1))
        lines = (self.work / test_file).read_text().splitlines()
        assertion_valid = bool(location) and 0 < int(location.group(1)) <= len(lines) and re.match(r'(?:debug_)?assert(?:_eq|_ne)?!', lines[int(location.group(1)) - 1][int(location.group(2)) - 1:]) is not None
        complete = 'test result:' in text
        killed = phases[0]['process_status'] == 'Success' and phases[1]['process_status'] == 'Success' and phases[2]['process_status'] == {'Failure': 101} and name in failed and assertion_valid and restored and complete
        third['artifacts_complete'] = complete
        return {'id': case['id'], 'definition_sha256': definition['definition_sha256'], 'status': 'Killed' if killed else 'Survived' if phases[2]['process_status'] == 'Success' else 'RunnerError',
                'failure_kind': 'assertion' if killed else None, 'killed_by': killed_by if killed else [],
                'evidence': {'baseline': {'phase': baseline}, 'phase_results': phases, 'source_restored': restored, 'assertion_evidence': {'valid': assertion_valid, 'artifacts_complete': complete, 'test': name}}}


def pytest_child(mode, selection, result, evidence):
    root = Path.cwd().resolve(strict=True)
    sys.path.insert(0, str(root / 'workers/ud/src'))
    import pytest
    if mode == 'collect':
        rows = []
        class Collector:
            def pytest_collection_finish(self, session):
                for item in session.items:
                    source = Path(item.path).resolve(strict=True).relative_to(root).as_posix()
                    rows.append({'id': item.nodeid, 'source': source, 'source_sha256': hashlib.sha256((root / source).read_bytes()).hexdigest(), 'runner': 'python'})
        status = pytest.main([selection, '--collect-only', '-q', '-p', 'no:cacheprovider'], plugins=[Collector()])
        Path(result).write_text(json.dumps(rows))
        return status
    origins = load('ud_portable_assertion_origin', evidence).AssertionOrigins(root)
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
                item.user_properties.extend([('ud-failure-kind', 'assertion' if origin is not None else 'runtime'), ('ud-exception-type', exception.__module__ + '.' + exception.__qualname__)])
                if origin is not None: item.user_properties.append(('ud-assertion-origin', json.dumps(origin, sort_keys=True, separators=(',', ':'))))
    return pytest.main([selection, '-q', '-p', 'no:cacheprovider', '--junitxml', result], plugins=[Binder()])


def run(work, output, python, node, cargo, guard, timeout):
    runner = Portable(work, output, python, node, cargo, guard, timeout)
    secondary = runner.secondary; sha, canonical = secondary.sha, secondary.canonical
    manifest = json.loads((work / 'tests/mutation/fault-cases.json').read_bytes())
    metadata = {key: manifest[key] for key in ('profile', 'policy', 'qualification', 'exhaustive')}
    if metadata != {'profile': 'bounded', 'policy': 'bounded-reviewed-v1', 'qualification': 'bounded-reviewed-corpus', 'exhaustive': False} or len(manifest.get('cases', [])) != 18:
        raise ValueError('bounded mutation corpus must contain its exact 18 reviewed cases')
    receipt_files = {}
    inventory, planned = [], []
    for case in manifest['cases']:
        name = case['file']; raw = (work / name).read_bytes(); find = case['find'].encode(); replacement = case['replace'].encode()
        if not find or raw.count(find) != 1 or find == replacement:
            raise ValueError('fault anchor is missing or ambiguous')
        start = raw.index(find); program = raw[:start] + replacement + raw[start + len(find):]
        language = 'python' if name.endswith('.py') else 'perl' if name.endswith(('.pl', '.pm')) else 'rust' if name.endswith('.rs') else 'typescript' if re.search(r'\.[cm]?[jt]sx?$', name) else 'data'
        definition = {'tool': 'fault-canary', 'version': '1.0.0', 'operator': case['id'], 'start': start, 'end': start + len(find), 'original_hex': find.hex(), 'replacement_hex': replacement.hex(), 'runner': case['runner'], 'test': case['test'], 'assertion': case['assertion'], 'file': name, 'language': language, 'category': case['category']}
        inventory.append({'id': case['id'], 'file': name, 'source_sha256': sha(raw), 'definition': definition, 'definition_sha256': sha(canonical(definition))})
        planned.append((case, {'path': name, 'before_sha256': sha(raw), 'after_sha256': sha(program), 'size': len(program), 'content_base64': base64.b64encode(program).decode()}))
        receipt_files[name] = sha(raw)
    tests = {}
    for case, _ in planned:
        filename = case['test'].split('::', 1)[0]
        if case['runner'] == 'rust':
            discovered = runner.rust_tests(filename)
        elif case['runner'] == 'vitest':
            discovered = runner.vitest_collect(filename)
        else:
            status, raw = runner.pytest(case['test'], collect=True)
            if status['status'] != 0 or raw is None:
                raise ValueError('portable fault test discovery failed')
            discovered = json.loads(raw)
        selected = [item for item in discovered if item['source'] == filename and (case['runner'] == 'vitest' or case['runner'] == 'rust' and item.get('name') == case['assertion'] or item['id'] == case['test'] or item['id'].startswith(case['test'] + '::'))]
        if not selected:
            raise ValueError('fault test is absent from portable discovery: ' + case['id'])
        for item in (discovered if case['runner'] == 'rust' else selected):
            tests[item['id']] = item
    source_sha256 = os.environ['UD_FAULT_SOURCE_SHA256']
    plan = {'schema_version': 1, 'tool': 'fault-canary', 'tool_version': '1.0.0', 'inventory_only': True, 'scope_complete': True, 'source_tree_sha256': source_sha256, 'inventory': inventory, 'scheduled': len(inventory), 'tests': list(tests.values()), **metadata}
    (output / 'fault-schedule.json').write_bytes(canonical(plan) + b'\n')
    outcomes, baselines = [], {}
    def save():
        (output / 'fault-outcomes.json').write_bytes(canonical({'schema_version': 1, 'tool': 'fault-canary', 'source_tree_sha256': source_sha256, 'outcomes': outcomes, 'complete': len(outcomes) == len(planned), 'runner': 'portable-host', **metadata}) + b'\n')
    for case, mutation in planned:
        definition = next(item for item in inventory if item['id'] == case['id'])
        if case['runner'] == 'rust':
            outcomes.append(runner.rust(case, definition, mutation, list(tests.values()))); save(); continue
        checker = secondary.vitest if case['runner'] == 'vitest' else secondary.junit
        bindings = {} if case['runner'] == 'vitest' else {'source_hashes': {**receipt_files, **{item['source']: item['source_sha256'] for item in tests.values()}, **{str(path.relative_to(work).as_posix()): sha(path.read_bytes()) for path in (work / 'tests').rglob('*.py')}}, 'source_root': work}
        selected_tests = [item for item in tests.values() if item['source'] == case['test'].split('::', 1)[0] and (case['runner'] == 'vitest' or item['id'] == case['test'] or item['id'].startswith(case['test'] + '::'))]
        execute = runner.vitest if case['runner'] == 'vitest' else runner.pytest
        key = (case['runner'], case['test'])
        if key not in baselines:
            baselines[key] = execute(case['test'])
        baseline, raw = baselines[key]
        if baseline['status'] != 0 or baseline['timed_out'] or raw is None or not checker(raw, case['assertion'], False, expected=selected_tests, **bindings):
            raise ValueError('fault baseline failed: ' + case['id'])
        executed, raw = execute(case['test'], mutation)
        status = 'Timeout' if executed['timed_out'] else 'Survived' if executed['status'] == 0 else 'RunnerError'
        if executed['status'] == 1 and not executed['timed_out'] and raw is not None and checker(raw, case['assertion'], True, expected=selected_tests, **bindings):
            status = 'Killed'
        if raw is not None:
            (output / ('fault-' + case['id'] + '.result')).write_bytes(raw)
        killed_by = secondary.fault_killed_by(raw, case['runner'], selected_tests) if status == 'Killed' else []
        if status == 'Killed' and not killed_by:
            status = 'RunnerError'
        outcomes.append({'id': case['id'], 'definition_sha256': definition['definition_sha256'], 'status': status, 'failure_kind': 'assertion' if status == 'Killed' else None, 'killed_by': killed_by,
                         'evidence': {'baseline': baseline, 'baseline_selection_sha256': sha(canonical(selected_tests)), 'execution': executed}})
        save()
    save()
    (output / 'secondary-runner.json').write_bytes(canonical({'schema_version': 1, 'backend': 'faults', 'runner': 'portable-host', 'status': 'executed-not-reconciled', 'source_tree_sha256': source_sha256, 'jobs': runner.count}) + b'\n')
    shutil.rmtree(runner.cache, ignore_errors=True)
    return 0 if all(item['status'] == 'Killed' for item in outcomes) else 1


def main():
    if len(sys.argv) == 6 and sys.argv[1] == '--pytest-child':
        raise SystemExit(pytest_child(*sys.argv[2:]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--python', required=True); parser.add_argument('--node', required=True); parser.add_argument('--cargo', required=True)
    parser.add_argument('--guard'); parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    raise SystemExit(run(args.source_root.resolve(strict=True), args.output.resolve(strict=True), args.python, args.node, args.cargo, args.guard, args.timeout))


if __name__ == '__main__':
    main()
