"""Trusted full static/canary inventories with fresh kernel-confined test jobs."""
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def junit_inventory(raw, expected):
    tests = ET.fromstring(raw).findall('.//testcase')
    wanted = {item['id']: item for item in expected}
    if not wanted or len(wanted) != len(expected) or len(tests) != len(wanted):
        return False
    seen = set()
    for test in tests:
        properties = test.findall('./properties/property')
        bound = [item for item in properties if item.get('name') in ('ud-test-id', 'ud-source', 'ud-source-sha256')]
        if len(bound) != 3 or len({item.get('name') for item in bound}) != 3:
            return False
        values = {item.get('name'): item.get('value') for item in bound}
        selected = wanted.get(values['ud-test-id'])
        if not selected or values['ud-test-id'] in seen or values['ud-source'] != selected['source'] or values['ud-source-sha256'] != selected['source_sha256']:
            return False
        seen.add(values['ud-test-id'])
    return seen == set(wanted)


def junit_assertion_source(test, source_hashes, source_root):
    try:
        properties=test.findall('./properties/property')
        def one(name):
            values=[entry.get('value') for entry in properties if entry.get('name')==name]
            if len(values)!=1:raise ValueError('missing or duplicate origin binding')
            return values[0]
        origin=json.loads(one('ud-assertion-origin'))
        if origin['contract']!='python-test-source-origin-v2' or origin['test_id']!=one('ud-test-id') or origin['test_source']!=one('ud-source') or origin['test_source_sha256']!=one('ud-source-sha256'):
            return False
        for field,digest,line in [('source','source_sha256','line'),('test_source','test_source_sha256','test_line')]:
            name=origin[field]
            if not isinstance(name,str) or not name.startswith('tests/') or not name.endswith('.py') or any(value in name for value in ('\\','\0',':')) or any(part in ('','.','..') for part in name.split('/')) or not source_hashes or source_hashes.get(name)!=origin[digest] or type(origin[line])is not int or origin[line]<1:return False
            if source_root is None:return False
            file=Path(source_root)/name
            if file.is_symlink() or not file.is_file() or file.stat().st_size>4*1024**2:return False
            content=file.read_bytes()
            if sha(content)!=origin[digest] or origin[line]>len(content.splitlines()):return False
        return True
    except (ValueError,TypeError,KeyError):return False


def junit(raw, assertion=None, failed=False, expected=None, source_hashes=None, source_root=None):
    root = ET.fromstring(raw)
    tests = root.findall('.//testcase')
    if not tests or expected is not None and not junit_inventory(raw, expected) or any(test.findall('error') or test.findall('skipped') for test in tests):
        return False
    failures = [(test, item) for test in tests for item in test.findall('failure')]
    if not failed:
        return not failures
    if not failures or not all(
        [(entry.get('name'), entry.get('value')) for entry in test.findall('./properties/property') if entry.get('name') == 'ud-failure-kind'] == [('ud-failure-kind', 'assertion')]
        and len([entry for entry in test.findall('./properties/property') if entry.get('name') == 'ud-exception-type' and entry.get('value')]) == 1
        and junit_assertion_source(test,source_hashes,source_root)
        for test, _ in failures):
        return False
    return assertion is None or any(assertion in test.get('name', '') for test, _ in failures)


def vitest(raw, assertion, failed, expected=None):
    data = json.loads(raw)
    tests = [test for suite in data.get('testResults', []) for test in suite.get('assertionResults', [])]
    selected = [test for test in tests if assertion in test.get('fullName', '')]
    if type(data.get('numTotalTests')) is not int or data['numTotalTests'] < 1 or len(tests) != data['numTotalTests'] or data.get('numPendingTests') or data.get('numTodoTests') or len(selected) != 1:
        return False
    if expected is not None:
        wanted = {(item['source'], item['name'], item.get('occurrence', 0)): item['source_sha256'] for item in expected}
        actual = [(item.get('ud_source'), item.get('ud_name'), item.get('ud_occurrence')) for item in tests]
        if not wanted or len(wanted) != len(expected) or len(actual) != len(wanted) or len(set(actual)) != len(actual) or set(actual) != set(wanted) or any(item.get('ud_source_sha256') != wanted.get(key) for item, key in zip(tests, actual)):
            return False
    failures = [test for test in tests if test.get('status') == 'failed']
    if not failed:
        return data.get('success') is True and data.get('numFailedTests') == 0 and selected[0].get('status') == 'passed'
    return data.get('success') is False and data.get('numFailedTests') == len(failures) and len(failures) > 0 and selected[0].get('status') == 'failed' and all(
        isinstance(test.get('ud_errors'), list) and len(test['ud_errors']) > 0 and all(
            isinstance(error, dict) and error.get('name') in ('AssertionError', 'AssertionError [ERR_ASSERTION]', 'VitestAssertionError') and error.get('code') in (None, 'ERR_ASSERTION') for error in test['ud_errors']) for test in failures)


def stage_native_fixture(work, runtime, sdk=Path('/opt/mutation')):
    """Add the existing SDK's normal helper as an immutable, hashed test input."""
    expected = runtime.get('native_guard', {})
    if expected.get('path') != 'bin/ud-agent-guard' or expected.get('architecture') != 'arm64' or type(expected.get('size_bytes')) is not int or not 0 < expected['size_bytes'] <= 64 * 1024**2:
        raise ValueError('secondary native fixture receipt is missing')
    native = sdk / expected['path']
    descriptor = os.open(native, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o222 or info.st_size != expected['size_bytes']:
            raise ValueError('secondary native fixture is not an immutable SDK file')
        with os.fdopen(os.dup(descriptor), 'rb') as source:
            content = source.read(64 * 1024**2 + 1)
        if len(content) != expected['size_bytes'] or sha(content) != expected.get('sha256'):
            raise ValueError('secondary native fixture differs from its SDK receipt')
    finally:
        os.close(descriptor)
    directory = work
    for name in ('target', 'debug'):
        directory = directory / name
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('secondary native fixture directory was substituted')
    target = directory / 'ud-agent-guard'
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, 'wb') as destination:
            destination.write(content); destination.flush(); os.fchmod(destination.fileno(), 0o555); os.fsync(destination.fileno())
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o555:
            raise ValueError('secondary native fixture handoff differs from its immutable SDK input')
        with os.fdopen(os.dup(descriptor), 'rb') as source:
            actual = source.read(64 * 1024**2 + 1)
        if actual != content:
            raise ValueError('secondary native fixture handoff differs from its immutable SDK input')
    finally:
        os.close(descriptor)
    return {'path': 'target/debug/ud-agent-guard', 'sha256': expected['sha256'], 'size': len(content), 'mode': 0o555}


class Jobs:
    def __init__(self, work, state, receipt, execute, runtime):
        self.work, self.state, self.receipt, self.execute, self.runtime = work, state, receipt, execute, runtime
        self.count = 0

    def run(self, runner, selection='all', mutation=None, timeout=120, allow_changed=False):
        files = []
        for item in self.receipt['files']:
            name = item['path']
            file = self.work / name
            info = file.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('secondary input must be an independent ordinary source')
            content = file.read_bytes()
            if not allow_changed and sha(content) != item['sha256']:
                raise ValueError('secondary immutable source identity changed')
            files.append({'path': name, 'sha256': sha(content), 'size': len(content), 'mode': stat.S_IMODE(info.st_mode)})
        if runner == 'vitest' or os.path.lexists(self.work / 'target/debug/ud-agent-guard'):
            if any(item['path'] == 'target/debug/ud-agent-guard' for item in files):
                raise ValueError('secondary native fixture collides with source')
            files.append(stage_native_fixture(self.work, self.runtime))
        descriptor = self.runtime['node_dependencies']
        workspace = {'root': str(self.work), 'files': files, 'readonly_tree': True, 'readonly_links': [{'path': 'node_modules', 'target': '/opt/mutation/node_modules', 'closure_receipt': {**descriptor, 'path': '/opt/mutation/node-dependencies.json'}}]}
        environment = {'PATH': '/opt/mutation/bin:/opt/mutation/rust/bin:/opt/mutation/node/bin:/opt/mutation/python/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
                       'SOURCE_DATE_EPOCH': '315532800', 'UD_AGENT_PYTHON': sys.executable, 'UD_RELEASE_PYTHON': sys.executable,
                       'UD_AGENT_PERL': '/opt/mutation/bin/perl', 'UD_PERL_PARSER_ROOT': '/opt/mutation/perl-parser',
                       'UD_MUTATION_GUARD': '/opt/mutation/bin/ud-agent-guard', 'PYTHONDONTWRITEBYTECODE': '1'}
        # Only this trusted parent applies a named defect. The test process gets
        # a root-owned sealed snapshot and cannot rewrite any source or oracle.
        target, original, materialized = None, None, None
        try:
            if mutation is not None:
                if not isinstance(mutation, dict) or set(mutation) != {'path', 'before_sha256', 'after_sha256', 'size', 'content_base64'}:
                    raise ValueError('closed named-defect materialization required')
                selected = next((item for item in files if item['path'] == mutation['path']), None)
                content = base64.b64decode(mutation['content_base64'], validate=True)
                if selected is None or mutation['before_sha256'] != selected['sha256'] or type(mutation['size']) is not int or not 0 <= mutation['size'] <= 16 * 1024**2 or len(content) != mutation['size'] or sha(content) != mutation['after_sha256']:
                    raise ValueError('named defect differs from its exact source identities')
                target = self.work / selected['path']; original = target.read_bytes()
                target.write_bytes(content)
                selected.update(sha256=sha(content), size=len(content))
                materialized = {key: mutation[key] for key in ('path', 'before_sha256', 'after_sha256', 'size')}
            payload = canonical({'schema_version': 1, 'runner': runner, 'selection': selection, 'mutation': None})
            outcome = self.execute([sys.executable, '/opt/mutation/harness/secondary-child.py', '{request}', '{result}'], state=self.state,
                                   environment=environment, timeout=timeout, workspace=workspace,
                                   request={'basename': 'request.json', 'bytes': payload}, result={'basename': 'result.data', 'max_bytes': 32 * 1024**2})
        finally:
            if target is not None and original is not None:
                target.write_bytes(original)
        expected_handoff = sha(json.dumps(workspace, sort_keys=True, separators=(',', ':')).encode())
        if outcome.get('handoff') != {'cwd': '.', 'files': len(files), 'inventory_sha256': expected_handoff, 'source_inventory_sha256': expected_handoff, 'readonly_tree': True}:
            raise ValueError('secondary boundary did not prove the exact sealed source handoff')
        content = outcome.pop('result_bytes', None)
        if content is not None and (not isinstance(content, bytes) or len(content) != outcome.get('result_size') or sha(content) != outcome.get('result_sha256')):
            raise ValueError('secondary result differs from its harvested identity')
        self.count += 1
        with (self.state / ('secondary-execution-' + str(self.count).zfill(6) + '.json')).open('x') as destination:
            json.dump({'schema_version': 1, 'runner': runner, 'selection': selection, 'request_sha256': sha(payload), 'materialization': materialized, 'execution': outcome}, destination)
        return outcome, content


def run_static(work, state, receipt, jobs, inventory_only=False, verify_schedule=None):
    spec = importlib.util.spec_from_file_location('ud_closed_static_generator', work / 'tests/mutation/python_static.py')
    backend = importlib.util.module_from_spec(spec); spec.loader.exec_module(backend)
    cases = backend.enumerate_mutants(work)
    source_hashes={row['path']:row['sha256'] for row in receipt['files']}
    if not cases:
        raise ValueError('static generation scheduled no applicable definitions')
    collected, raw_tests = jobs.run('pytest-collect')
    if collected['status'] != 0 or collected['timed_out'] or raw_tests is None:
        raise ValueError('protected static test discovery failed')
    tests = json.loads(raw_tests)
    if not isinstance(tests, list) or not tests or len({item['id'] for item in tests}) != len(tests):
        raise ValueError('protected static test inventory is empty or duplicated')
    plan = {'schema_version': 1, 'tool': 'python-static', 'tool_version': '1.0.0', 'inventory_only': True, 'scope_complete': True,
            'source_tree_sha256': receipt['source_tree_sha256'], 'scheduled': len(cases), 'inventory': cases, 'tests': tests}
    (state / 'python-static-schedule.json').write_bytes(canonical(plan) + b'\n')
    materializations = []
    for file in backend.source_files(work):
        name = file.relative_to(work).as_posix(); raw = file.read_bytes()
        generated = {'schema_version': 1, 'source': name, 'source_sha256': sha(raw), 'ast': ast.dump(ast.parse(raw), include_attributes=True), 'mutant_ids': sorted(item['id'] for item in cases if item['file'] == name)}
        target = state / 'static-generation' / (name + '.json'); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(canonical(generated) + b'\n')
        materializations.append({'source': name, 'source_sha256': sha(raw), 'path': target.relative_to(state).as_posix(), 'sha256': sha(target.read_bytes()), 'size': target.stat().st_size})
    (state / 'static-generation/manifest.json').write_bytes(canonical(materializations) + b'\n')
    if verify_schedule is not None:
        verify_schedule(plan)
    if inventory_only:
        return 0
    baseline, baseline_xml = jobs.run('pytest')
    if baseline['status'] != 0 or baseline['timed_out'] or baseline_xml is None or not junit(baseline_xml, expected=tests):
        raise ValueError('complete protected static baseline failed')
    (state / 'python-static-baseline.xml').write_bytes(baseline_xml)
    original = {item['path']: (work / item['path']).read_bytes() for item in receipt['files']}
    expected = {}
    for item in cases:
        content = original[item['file']]; program = content[:item['start']] + item['replacement'].encode() + content[item['end']:]
        expected.setdefault(item['file'], {})[sha(program)] = item['id']
    def execute(command, **options):
        changed = []
        for name, before in original.items():
            raw = (work / name).read_bytes()
            if raw != before:
                identity = expected.get(name, {}).get(sha(raw))
                if not identity:
                    raise ValueError('static candidate differs from every scheduled exact program')
                changed.append(identity)
        if len(changed) != 1:
            raise ValueError('static invocation must contain exactly one scheduled program')
        outcome, result = jobs.run('pytest', timeout=options['timeout'], allow_changed=True)
        if outcome['timed_out']:
            raise subprocess.TimeoutExpired(command, options['timeout'])
        if result is not None:
            if not junit_inventory(result, tests):
                raise ValueError('static mutant omitted, duplicated or changed required test identities')
            if outcome['status'] not in (0,1) or not junit(result,failed=outcome['status']==1,expected=tests,source_hashes=source_hashes,source_root=work):
                raise ValueError('static mutant lacks clean source-bound assertion evidence')
            Path(command[-1]).write_bytes(result)
        return subprocess.CompletedProcess(command, outcome['status'], outcome['stdout'], outcome['stderr'])
    os.environ['UD_MUTATION_ORIGINAL_ROOT'] = '/input/source'
    status = backend.run(work, state / 'python-static.json', sys.executable, 120, None, execute=execute)
    return status


def run_faults(work, state, receipt, jobs, inventory_only=False, verify_schedule=None):
    manifest = json.loads((work / 'tests/mutation/fault-cases.json').read_bytes())
    cases = manifest.get('cases')
    if manifest.get('schema_version') != 1 or not isinstance(cases, list) or not cases:
        raise ValueError('complete fault manifest required')
    bounded = manifest.get('profile') == 'bounded'
    metadata = {key: manifest[key] for key in ('profile', 'policy', 'qualification', 'exhaustive')} if bounded else {}
    if bounded and (metadata != {'profile': 'bounded', 'policy': 'bounded-reviewed-v1', 'qualification': 'bounded-reviewed-corpus', 'exhaustive': False}
                    or len(cases) != 18 or not {'typescript', 'python', 'rust', 'perl'} <= {case.get('language') for case in cases}):
        raise ValueError('bounded mutation corpus must contain its exact 18 reviewed cases and four languages')
    inventory, planned, ids = [], [], set()
    for case in cases:
        if not isinstance(case.get('id'), str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}', case['id']) or case['id'] in ids or case.get('runner') not in ('vitest', 'pytest', 'rust') or case.get('unavailable') or not case.get('assertion') or not case.get('test'):
            raise ValueError('invalid, duplicate or unavailable required fault definition')
        ids.add(case['id']); name = case['file']
        if name.startswith('/') or any(value in name for value in ('\\', '\0', ':')) or any(part in ('', '.', '..') for part in name.split('/')):
            raise ValueError('fault source escapes its closed handoff')
        raw = (work / name).read_bytes(); find = case['find'].encode(); replacement = case['replace'].encode()
        if not find or raw.count(find) != 1 or find == replacement:
            raise ValueError('fault anchor is missing or ambiguous')
        start = raw.index(find); program = raw[:start] + replacement + raw[start + len(find):]
        definition = {'tool': 'fault-canary', 'version': '1.0.0', 'operator': case['id'], 'start': start, 'end': start + len(find), 'original_hex': find.hex(), 'replacement_hex': replacement.hex(), 'runner': case['runner'], 'test': case['test'], 'assertion': case['assertion']}
        if bounded:
            language = 'python' if name.endswith('.py') else 'perl' if name.endswith(('.pl', '.pm')) else 'rust' if name.endswith('.rs') else 'typescript' if re.search(r'\.[cm]?[jt]sx?$', name) else 'data'
            if case.get('language') != language or (language == 'rust') != (case['runner'] == 'rust') or not isinstance(case.get('category'), str) or not re.fullmatch('[a-z][a-z-]*', case['category']):
                raise ValueError('bounded fault language, category or runner differs from its source')
            definition.update(file=name, language=language, category=case['category'])
        inventory.append({'id': case['id'], 'file': name, 'source_sha256': sha(raw), 'definition': definition, 'definition_sha256': sha(canonical(definition))})
        planned.append((case, {'path': name, 'before_sha256': sha(raw), 'after_sha256': sha(program), 'size': len(program), 'content_base64': base64.b64encode(program).decode()}))
    discovered = []
    rust_cases = [case for case, _ in planned if case['runner'] == 'rust']
    rust = None
    if rust_cases:
        spec = importlib.util.spec_from_file_location('ud_bounded_rust_faults', '/opt/mutation/harness/rust-protected.py')
        backend = importlib.util.module_from_spec(spec); spec.loader.exec_module(backend)
        rust = backend.prepare_named_faults(work, state, receipt, rust_cases)
        discovered.extend(rust.tests)
    for runner in sorted({item['runner'] for item, _ in planned} - {'rust'}):
        completed, raw = jobs.run('vitest-collect' if runner == 'vitest' else 'pytest-collect')
        if completed['status'] != 0 or completed['timed_out'] or raw is None:
            raise ValueError('protected fault test discovery failed')
        discovered.extend(json.loads(raw))
    tests = {}
    for case, _ in planned:
        filename = case['test'].split('::', 1)[0]
        selected = [item for item in discovered if item['source'] == filename and (case['runner'] == 'vitest' or case['runner'] == 'rust' and item.get('name') == case['assertion'] or item['id'] == case['test'] or item['id'].startswith(case['test'] + '::'))]
        if not selected:
            raise ValueError('fault test is absent from independent protected discovery')
        for item in selected:
            if item['id'] in tests and tests[item['id']] != item:
                raise ValueError('fault test identity is ambiguous')
            tests[item['id']] = item
    plan = {'schema_version': 1, 'tool': 'fault-canary', 'tool_version': '1.0.0', 'inventory_only': True, 'scope_complete': True,
            'source_tree_sha256': receipt['source_tree_sha256'], 'inventory': inventory, 'scheduled': len(inventory), 'tests': list(tests.values()), **metadata}
    # Rust executes its complete launcher suite, so retain every independently
    # listed Rust case, including any additional assertion that detects a fault.
    if rust is not None:
        plan['tests'] = list({item['id']: item for item in [*plan['tests'], *rust.tests]}.values())
    (state / 'fault-schedule.json').write_bytes(canonical(plan) + b'\n')
    if verify_schedule is not None:
        verify_schedule(plan)
    if inventory_only:
        return 0
    outcomes, baselines = [], {}
    source_hashes={row['path']:row['sha256'] for row in receipt['files']}
    for case, mutation in planned:
        definition = next(item for item in inventory if item['id'] == case['id'])
        if case['runner'] == 'rust':
            outcomes.append(rust.run(case, definition['definition'], mutation))
            (state / 'fault-outcomes.json').write_bytes(canonical({'schema_version': 1, 'tool': 'fault-canary', 'source_tree_sha256': receipt['source_tree_sha256'], 'outcomes': outcomes, 'complete': len(outcomes) == len(planned), **metadata}) + b'\n')
            continue
        checker = vitest if case['runner'] == 'vitest' else junit
        bindings={} if case['runner']=='vitest' else {'source_hashes':source_hashes,'source_root':work}
        selected_tests = [item for item in tests.values() if item['source'] == case['test'].split('::', 1)[0] and (case['runner'] == 'vitest' or item['id'] == case['test'] or item['id'].startswith(case['test'] + '::'))]
        baseline_key = (case['runner'], case['test'], sha(canonical(selected_tests)))
        if baseline_key not in baselines:
            baselines[baseline_key] = jobs.run(case['runner'], case['test'])
        baseline, raw = baselines[baseline_key]
        if baseline['status'] != 0 or baseline['timed_out'] or raw is None or not checker(raw, case['assertion'], False, expected=selected_tests,**bindings):
            raise ValueError('fault baseline failed: ' + case['id'])
        executed, raw = jobs.run(case['runner'], case['test'], mutation)
        status = 'Timeout' if executed['timed_out'] else 'Survived' if executed['status'] == 0 else 'RunnerError'
        if executed['status'] == 1 and not executed['timed_out'] and raw is not None and checker(raw, case['assertion'], True, expected=selected_tests,**bindings):
            status = 'Killed'
        if raw is not None:
            (state / ('fault-' + case['id'] + '.result')).write_bytes(raw)
        killed_by = fault_killed_by(raw, case['runner'], selected_tests) if status == 'Killed' else []
        if status == 'Killed' and not killed_by:
            status = 'RunnerError'
        outcomes.append({'id': case['id'], 'definition_sha256': definition['definition_sha256'], 'status': status, 'failure_kind': 'assertion' if status == 'Killed' else None, 'killed_by': killed_by,
                         'evidence': {'baseline': baseline, 'baseline_selection_sha256': baseline_key[2], 'execution': executed}})
        (state / 'fault-outcomes.json').write_bytes(canonical({'schema_version': 1, 'tool': 'fault-canary', 'source_tree_sha256': receipt['source_tree_sha256'], 'outcomes': outcomes, 'complete': len(outcomes) == len(planned), **metadata}) + b'\n')
    return 0 if all(item['status'] == 'Killed' for item in outcomes) else 1


def fault_killed_by(raw, runner, expected):
    """Extract only actual failed cases from an already validated report."""
    if runner == 'vitest':
        wanted = {(item['source'], item['name'], item.get('occurrence', 0)): item['id'] for item in expected}
        return [wanted[(item['ud_source'], item['ud_name'], item['ud_occurrence'])]
                for suite in json.loads(raw)['testResults'] for item in suite['assertionResults'] if item['status'] == 'failed']
    return [next(item.get('value') for item in test.findall('./properties/property') if item.get('name') == 'ud-test-id')
            for test in ET.fromstring(raw).findall('.//testcase') if test.findall('failure')]


def run(work, state, receipt, selected, inventory_only=False, verify_schedule=None):
    if sys.platform != 'linux' or os.geteuid() != 0 or state != Path('/state') or not work.is_relative_to(state) or selected not in ('python-static', 'faults'):
        raise ValueError('trusted native OCI secondary coordinator required')
    spec = importlib.util.spec_from_file_location('ud_secondary_exec', '/opt/mutation/harness/oci-exec.py')
    boundary = importlib.util.module_from_spec(spec); spec.loader.exec_module(boundary)
    runtime = json.loads(Path('/opt/mutation/input-receipt.json').read_bytes())
    admission_spec = importlib.util.spec_from_file_location('ud_secondary_admission', '/opt/mutation/harness/oci-stryker.py')
    admission = importlib.util.module_from_spec(admission_spec); admission_spec.loader.exec_module(admission)
    admission.verify_inputs(work, receipt, runtime)
    for name in ('oci-secondary.py', 'secondary-child.py', 'oci-exec.py'):
        expected = next((item for item in runtime['harness'] if item['path'] == name), None)
        file = Path('/opt/mutation/harness') / name
        if not expected or file.stat().st_mode & 0o222 or sha(file.read_bytes()) != expected['sha256']:
            raise ValueError('secondary harness differs from its immutable image receipt')
    jobs = Jobs(work, state, receipt, boundary.execute, runtime)
    def cancel(signum, frame):
        raise InterruptedError('protected secondary coordinator cancelled')
    previous = {number: signal.signal(number, cancel) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        runner = run_static if selected == 'python-static' else run_faults
        status = runner(work, state, receipt, jobs, inventory_only, verify_schedule)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    (state / 'secondary-runner.json').write_bytes(canonical({'schema_version': 1, 'backend': selected, 'status': 'executed-not-reconciled', 'source_tree_sha256': receipt['source_tree_sha256'], 'jobs': jobs.count, 'exit_code': status}) + b'\n')
    return status
