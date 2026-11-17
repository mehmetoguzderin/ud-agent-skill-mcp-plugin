"""Trusted compilation and fresh-UID dispatch for every Cargo test artifact."""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import shutil
import io
import tarfile
import stat
import subprocess
import time
import uuid

TARGET = 'aarch64-unknown-linux-gnu'
HARNESSES = ('oci-exec.py', 'oci-isolation.py', 'rust-test-runtime.py', 'rust-protected.py', 'rust-compile-child.py', 'rust-literal.py')
_spec=importlib.util.spec_from_file_location('ud_rust_workspace_contract',Path(__file__).with_name('rust-test-runtime.py'))
contract=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(contract)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def required_artifacts(receipt,manifest='Cargo.toml'):
    selected=contract.workspace(manifest)
    source = {selected['cwd']+'/'+name for name in selected['products'].values()}
    tests = {item['path'] for item in receipt['files'] if re.fullmatch(re.escape(selected['cwd'])+r'/tests/[^/]+\.rs', item['path'])}
    if not tests:raise ValueError('Rust integration test inventory is empty')
    return {(name, kind) for name in source for kind in ('product', 'test')} | {(name, 'test') for name in tests}


def invocation_evidence(record, artifact, arguments, status, captured, expected):
    """Only coordinator-written outcomes can attest a completed test job."""
    if not isinstance(record, dict) or set(record) != {'schema_version', 'artifact', 'arguments', 'outcome'} or type(record['schema_version']) is not int or record['schema_version'] != 1 or record['artifact'] != artifact or record['arguments'] != arguments:
        raise ValueError('Rust root invocation record is absent, substituted or unbound')
    outcome = record['outcome']
    if not isinstance(outcome, dict) or type(outcome.get('status')) is not int or outcome['status'] not in (0, 101) or type(status) is not int or status != outcome['status'] or outcome.get('timed_out') is not False or outcome.get('cancelled', False) is not False or outcome.get('owned_descendants_cancelled') != [] or type(outcome.get('uid')) is not int or outcome['uid'] < 100001 or not isinstance(outcome.get('handoff'), dict) or outcome['handoff'].get('readonly_tree') is not True or not isinstance(captured, bytes) or outcome.get('stderr') != captured.decode('utf-8', errors='replace'):
        raise ValueError('Rust artifact did not complete with clean confined execution')
    return {'artifact_id': artifact['id'], 'artifact_sha256': artifact['sha256'], 'expected_tests': expected,
            'status': outcome['status'], 'timed_out': False, 'cancelled': False, 'owned_descendants_cancelled': False,
            'cleanup_verified': True, 'log': outcome['stderr']}


def module(name):
    spec = importlib.util.spec_from_file_location('ud_protected_' + name.replace('-', '_'), Path('/opt/mutation/harness') / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def decode_bundle(content):
    """Harvest only the complete closed native executable set after quiescence."""
    if not isinstance(content, bytes) or len(content) > 32 * 1024**2:
        raise ValueError('Rust compiled bundle is absent or unbounded')
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:') as archive:
        members = archive.getmembers()
        if not members or len(members) > 64 or members[0].name != 'build.json' or len({item.name for item in members}) != len(members) or any(not item.isfile() or item.size < 0 or item.size > 32 * 1024**2 for item in members):
            raise ValueError('Rust compiled bundle is not an ordinary closed archive')
        if members[0].size > 2 * 1024**2:raise ValueError('Rust compiled control manifest is unbounded')
        control = json.loads(archive.extractfile(members[0]).read())
        if not isinstance(control, dict) or set(control) not in ({'schema_version', 'status', 'argv', 'source_root', 'artifacts'},{'schema_version', 'status', 'argv', 'source_root', 'artifacts','workspace_manifest'}) or type(control['schema_version']) is not int or control['schema_version'] != 1 or type(control['status']) is not int or not 0 <= control['status'] <= 255 or not isinstance(control['artifacts'], list):
            raise ValueError('Rust compiled control manifest is invalid')
        selected=contract.workspace(control.get('workspace_manifest','Cargo.toml'))
        if len(members) != len(control['artifacts']) + 1 or [item.name for item in members[1:]] != [f'binaries/{index}' for index in range(len(control['artifacts']))]:
            raise ValueError('Rust compiled archive omits or adds executable payloads')
        seen, data = set(), []
        for item, member in zip(control['artifacts'], members[1:]):
            if not isinstance(item, dict) or set(item) != {'path', 'id', 'kind', 'sha256', 'size'} or item['kind'] not in ('test', 'product') or type(item['size']) is not int or item['size'] != member.size or not isinstance(item['path'], str) or not re.fullmatch(r'target/aarch64-unknown-linux-gnu/debug/(?:deps/)?[A-Za-z0-9_-]+', item['path']) or item['path'] in seen or not isinstance(item['id'], str) or not re.fullmatch(re.escape(selected['cwd'])+r'/(?:src|tests)/[A-Za-z0-9_/-]+\.rs', item['id']):
                raise ValueError('Rust compiled executable record is invalid or duplicate')
            seen.add(item['path']);raw = archive.extractfile(member).read()
            if raw[:6] != b'\x7fELF\x02\x01' or int.from_bytes(raw[18:20], 'little') != 183 or sha(raw) != item['sha256']:
                raise ValueError('Rust compiled native identity differs from its harvested manifest')
            data.append(raw)
        if control['status'] == 0:
            if {item['id'] for item in control['artifacts'] if item['kind'] == 'product'} != {selected['cwd']+'/'+name for name in selected['products'].values()} or not any(item['kind'] == 'test' for item in control['artifacts']):
                raise ValueError('Rust compiled bundle omitted required products or tests')
        elif control['artifacts']:
            raise ValueError('Rust failed compilation supplied executable payloads')
        return control, data


def validate_build_source(receipt, work, schedule):
    """Permit only exact scheduled source bytes and frozen Cargo contracts."""
    hashes = {item['path']: item['sha256'] for item in receipt['files']}
    allowed = {}
    for item in schedule['inventory']:
        name = item['file']
        if not any(name.startswith(row['cwd']+'/src/')for row in contract.WORKSPACES.values())or not name.endswith('.rs')or name.endswith('/build.rs'):
            raise ValueError('Rust definition can affect build-phase executable code')
        original = Path(receipt['copy'], name).read_bytes()
        if sha(original) != hashes.get(name):
            raise ValueError('Rust immutable source differs from discovery')
        definition = item['mutant']; lines = original.splitlines(keepends=True)
        def offset(point):
            return sum(map(len, lines[:point['line'] - 1])) + point['column'] - 1
        start, end = offset(definition['span']['start']), offset(definition['span']['end'])
        allowed.setdefault(name, set()).add(sha(original[:start] + definition['replacement'].encode() + original[end:]))
    changed = []
    for name, expected in hashes.items():
        file = work / name; info = file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError('Rust compiler source is not an ordinary coordinator-owned snapshot')
        raw = file.read_bytes()
        digest = sha(raw)
        if digest != expected:
            if digest not in allowed.get(name, set()):
                raise ValueError('Rust compiler source differs from every exact scheduled program')
            changed.append(name)
    if len(changed) > 1:
        raise ValueError('Rust compilation contains more than one scheduled mutation')
    # The package manifests are immutable inputs. Reject build.rs even when
    # Cargo would discover it implicitly rather than through a manifest field.
    if any((work / item['path']).name == 'build.rs' for item in receipt['files'] if any(item['path'].startswith(row['cwd']+'/')for row in contract.WORKSPACES.values())):
        raise ValueError('Rust workspace build scripts change the frozen build contract')
    for manifest in (work / name for name in ['Cargo.toml',*[row['cwd']+'/Cargo.toml'for row in contract.WORKSPACES.values()]]):
        if not manifest.exists():continue
        content = manifest.read_text()
        if re.search(r'(?m)^\s*(?:build\s*=|proc-macro\s*=\s*true)', content):
            raise ValueError('Rust workspace build-phase code is unsupported by this compiler authority')


class ProtectedRust:
    def __init__(self, receipt, output, schedule):
        if os.geteuid() != 0 or os.uname().sysname != 'Linux' or os.uname().machine not in ('aarch64', 'arm64') or os.environ.get('UD_MUTATION_OCI_GUARD') != '1':
            raise ValueError('Rust tests may execute only inside the native ARM protected OCI coordinator')
        self.runtime = module('rust-test-runtime')
        inputs = self.runtime.read_json('/opt/mutation/input-receipt.json')
        descriptor = inputs['rust']
        if self.runtime.file_hash('/opt/mutation/rust-input-receipt.json', immutable=True) != (descriptor['sha256'], descriptor['size_bytes']):
            raise ValueError('Rust compiler receipt differs from the image input contract')
        for name in HARNESSES:
            expected = [item for item in inputs['harness'] if item['path'] == name]
            if len(expected) != 1 or self.runtime.file_hash('/opt/mutation/harness/' + name, immutable=True)[0] != expected[0]['sha256']:
                raise ValueError('Rust executor is not the immutable image-bound harness')
        lock = self.runtime.read_json('/opt/mutation/rust-input-receipt.json')
        if lock['product_vendor']['cargo_lock_sha256'] != sha(Path(receipt['copy'], 'Cargo.lock').read_bytes()):
            raise ValueError('Rust dependency closure is stale')
        self.receipt, self.output, self.schedule = receipt, output, schedule
        self.candidates, self.inventories = {}, {}
        self.base_env = {'PATH': '/opt/mutation/rust/bin:/opt/mutation/python/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'CARGO_NET_OFFLINE': 'true', 'CARGO_BUILD_JOBS': '2', 'CARGO_HOME': '/state/rust-cargo-home', 'RUSTC': '/opt/mutation/rust/bin/rustc', 'RUSTC_WRAPPER': '/opt/mutation/harness/rust-test-runtime.py', 'CARGO_INCREMENTAL': '0', 'SOURCE_DATE_EPOCH': '315532800'}
        self.boundary = module('oci-exec')

    def discard(self, work, manifest):
        previous = self.candidates.pop((str(work),manifest), None)
        if previous is not None:
            raw = self.runtime.candidate(self.runtime.read_json(previous))
            shutil.rmtree(raw['source_root'])

    def compile(self, command, work, log, timeout):
        manifest=command[command.index('--manifest-path')+1]if'--manifest-path'in command else'Cargo.toml'
        contract.workspace(manifest)
        validate_build_source(self.receipt, work, self.schedule)
        self.discard(work,manifest)
        files = []
        for item in self.receipt['files']:
            file = work / item['path'];info = file.lstat();data = file.read_bytes()
            files.append({'path': item['path'], 'sha256': sha(data), 'size': len(data), 'mode': stat.S_IMODE(info.st_mode)})
        workspace = {'root': str(work), 'files': files, 'readonly_links': [], 'readonly_tree': True}
        request = {'schema_version': 1, 'target': TARGET, 'workspace_manifest':manifest}
        invocation = ['/opt/mutation/python/bin/python3', '-I', '-B', '/opt/mutation/harness/rust-compile-child.py', '{request}', '{result}', '{workspace}']
        started = time.monotonic()
        outcome = self.boundary.execute(invocation, state='/state', environment={'PATH': self.base_env['PATH'], 'LANG': 'C.UTF-8'}, timeout=max(1, int(timeout)), workspace=workspace,
                                        request={'basename': 'compile-request.json', 'bytes': canonical(request)}, result={'basename': 'compiled.tar', 'max_bytes': 32 * 1024**2})
        content = outcome.pop('result_bytes', None)
        log.write_text(outcome['stderr'])
        record = {**outcome, 'source_inventory_sha256': sha(canonical(files))}
        log.with_suffix('.execution.json').write_bytes(canonical(record))
        if outcome['timed_out']:
            status = 'Timeout'
        elif outcome.get('cancelled') or outcome['owned_descendants_cancelled'] or outcome['status'] != 0 or content is None:
            raise ValueError('Rust compilation boundary failed without a complete clean result')
        else:
            control, compiled = decode_bundle(content)
            if control.get('workspace_manifest')!=manifest:raise ValueError('Rust compilation returned a different workspace')
            execution_id = outcome.get('execution_id')
            if not isinstance(execution_id, str) or not re.fullmatch('[a-f0-9]{32}', execution_id):raise ValueError('Rust compile source has no trusted execution identity')
            issued = self.runtime.read_json(Path('/state/control/jobs') / (execution_id + '.exec.json'))
            if issued.get('uid') != outcome['uid'] or issued.get('collected') is not True or issued.get('command', [])[:-3] != invocation[:-3] or len(issued.get('command', [])) != len(invocation) or issued['command'][-1] != control['source_root']:
                raise ValueError('Rust compiled source path differs from the coordinator-issued handoff')
            status = 'Success' if control['status'] == 0 else {'Failure': control['status']}
            if status == 'Success':self.candidates[(str(work),manifest)] = self.stage(work, control, compiled)
        return {'process_status': status, 'duration': time.monotonic() - started, 'argv': invocation, 'authority': 'fresh-UID-immutable-source-private-compiler-cache', 'execution': record,'workspace_manifest':manifest}

    def stage(self, work, control, compiled):
        manifest=control['workspace_manifest'];selected=contract.workspace(manifest)
        expected = required_artifacts(self.receipt,manifest)
        actual = [(item['id'], item['kind']) for item in control['artifacts']]
        if len(actual) != len(expected) or set(actual) != expected:
            raise ValueError('Cargo executable set differs from independent source target discovery')
        phase = uuid.uuid4().hex;root = Path('/state/rust-candidates') / phase;root.mkdir(parents=True, mode=0o755)
        files, artifacts = [], []
        try:
            for item in self.receipt['files']:
                name = item['path'];source = work / name;info = source.lstat();data = source.read_bytes()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:raise ValueError('Rust candidate source is not coordinator-owned')
                target = root / name;target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(data)
                mode = 0o555 if info.st_mode & 0o111 else 0o444;target.chmod(mode)
                files.append({'path': name, 'sha256': sha(data), 'size': len(data), 'mode': mode})
            for item, data in zip(control['artifacts'], compiled):
                target = root / item['path'];target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(data);target.chmod(0o555)
                files.append({'path': item['path'], 'sha256': item['sha256'], 'size': item['size'], 'mode': 0o555})
                artifacts.append({**item, 'source_path': str(target)})
            raw = {'schema_version': 1, 'source_root': str(root), 'cwd': selected['cwd'], 'files': files, 'artifacts': artifacts, 'phase_id': phase, 'compile_source_root': control['source_root'],'workspace_manifest':manifest}
            self.runtime.candidate(raw)
            descriptor = Path('/state/rust-candidate-receipts') / (phase + '.json');descriptor.parent.mkdir(mode=0o700, exist_ok=True);descriptor.write_bytes(canonical(raw));descriptor.chmod(0o600)
            return descriptor
        except BaseException:
            shutil.rmtree(root);raise

    def execute(self, command, cwd, _environment, log, timeout):
        work = Path(cwd)
        if '--no-run' in command: return self.compile(command, work, log, timeout)
        if command[:2] != ['cargo', 'test'] or '--' not in command or command[command.index('--') + 1:] not in (['--test-threads=1'], ['--list', '--format', 'terse']):
            raise ValueError('Rust protected executor rejects unscheduled commands')
        manifest=command[command.index('--manifest-path')+1]if'--manifest-path'in command else'Cargo.toml';selected=contract.workspace(manifest)
        receipt_file = self.candidates.get((str(work),manifest))
        if receipt_file is None: raise ValueError('Rust tests have no successful same-variant compilation')
        raw = self.runtime.candidate(self.runtime.read_json(receipt_file))
        listing = command[-3:] == ['--list', '--format', 'terse']
        started = time.monotonic(); failures = []; inventories = {}; invocations = []; records = []; invalid = []
        directory = Path('/state/rust-invocations') / raw['phase_id']
        with log.open('xb') as target:
            for artifact in [item for item in raw['artifacts'] if item['kind'] == 'test']:
                args = ['--list', '--format', 'terse'] if listing else ['--test-threads=1']
                environment = {**self.base_env, 'UD_MUTATION_RUST_CANDIDATE': str(receipt_file)}
                command_line = ['/opt/mutation/python/bin/python3', '-I', '-B', '/opt/mutation/harness/rust-test-runtime.py', '--runner', artifact['source_path'], *args]
                before = set(directory.glob('*.json'))
                child = subprocess.Popen(command_line, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                try:
                    captured, _ = child.communicate(timeout=timeout + 15)
                    target.write(captured)
                    if child.returncode: failures.append(child.returncode)
                    new = set(directory.glob('*.json')) - before
                    try:
                        if len(new) != 1:raise ValueError('Rust artifact has missing or duplicate root outcomes')
                        record_file = new.pop();record = self.runtime.read_json(record_file)
                        bound = invocation_evidence(record, artifact, args, child.returncode, captured, self.inventories.get(artifact['id'], []))
                        invocations.append(bound);records.append({'artifact_id': artifact['id'], 'record_path': record_file.relative_to('/state').as_posix(), 'record_sha256': sha(record_file.read_bytes())})
                    except (ValueError, OSError, KeyError, TypeError) as error:
                        invalid.append({'artifact_id': artifact['id'], 'error': str(error)})
                    if listing and not invalid and child.returncode == 0:
                        names = re.findall(rb'^(.+): test$', captured, re.M); inventories[artifact['id']] = [name.decode() for name in names]
                except subprocess.TimeoutExpired:
                    # The immutable runner's SIGTERM handler unwinds fixedexec
                    # through exact-UID cancellation/quiescence. Do not use
                    # subprocess.run's immediate SIGKILL and strand its job.
                    child.send_signal(signal.SIGTERM)
                    captured, _ = child.communicate(timeout=15)
                    target.write(captured)
                    failures.append('Timeout');invalid.append({'artifact_id': artifact['id'], 'error': 'root supervisor timeout'})
            if listing and not failures and not invalid:
                if not any(inventories.values()) or any(len(names) != len(set(names)) for names in inventories.values()): raise ValueError('Rust required test inventory is empty or duplicate')
                previous={name:values for name,values in self.inventories.items()if name.startswith(selected['cwd']+'/')}
                if previous and previous != inventories: raise ValueError('Rust candidate omits or changes required tests')
                self.inventories.update(inventories)
        expected = [{'artifact_id': item['id'], 'artifact_sha256': item['sha256'], 'expected_tests': self.inventories.get(item['id'], [])} for item in raw['artifacts'] if item['kind'] == 'test']
        complete = not invalid and len(invocations) == len(expected) and {item['artifact_id'] for item in invocations} == {item['artifact_id'] for item in expected}
        return {'process_status': 'Timeout' if 'Timeout' in failures else {'Failure': 125} if not complete else {'Failure': failures[0]} if failures else 'Success', 'duration': time.monotonic() - started, 'argv': command, 'authority': 'fresh-UID-immutable-tests-no-parent-FDs', 'artifacts_complete': complete, 'expected_artifacts': expected, 'invocations': invocations, 'invocation_records': records, 'compile_source_root': raw['compile_source_root'], 'errors': invalid,'workspace_manifest':manifest}


NAMED_FAULTS = {
    'rust_path_confinement': (
        '_ => return Err(fail("path must contain only relative normal components")),',
        '_ => continue,',
        'rejects_escaping_paths_and_oversized_files_without_output',
    ),
    'rust_transfer_limits': (
        'if before.len() > max_bytes {\n        return Err(fail("input exceeds requested limit"));',
        'if before.len() >= max_bytes {\n        return Err(fail("input exceeds requested limit"));',
        'native_transfer_limits_include_exact_boundaries_and_reject_invalid_fingerprints',
    ),
}


def named_fault(case, source):
    """Derive byte spans only for the two reviewed named defects, not operators."""
    expected = NAMED_FAULTS.get(case.get('id'))
    if expected is None or case.get('runner') != 'rust' or case.get('language') != 'rust' or not isinstance(case.get('category'), str) or not case['category'] or case.get('file') != 'packages/launcher/src/fs_guard.rs' or case.get('find') != expected[0] or case.get('replace') != expected[1] or case.get('test') != 'packages/launcher/tests/fs_guard.rs::' + expected[2] or case.get('assertion') != expected[2]:
        raise ValueError('Rust named defect is outside the two reviewed fault cases')
    before = expected[0].encode(); after = expected[1].encode()
    if not isinstance(source, bytes) or source.count(before) != 1:
        raise ValueError('Rust named defect has a missing or ambiguous exact source anchor')
    start = source.index(before); end = start + len(before)
    def point(offset):
        return {'line': source[:offset].count(b'\n') + 1, 'column': offset - source.rfind(b'\n', 0, offset)}
    definition = {'tool': 'fault-canary', 'version': '1.0.0', 'operator': case['id'], 'start': start, 'end': end,
                  'original_hex': before.hex(), 'replacement_hex': after.hex(), 'runner': 'rust', 'test': case['test'],
                  'assertion': case['assertion'], 'language': case['language'], 'category': case['category'], 'file': case['file']}
    auxiliary = {'tool': 'fault-canary', 'version': '1.0.0', 'operator': case['id'], 'file': case['file'],
                 'span': {'start': point(start), 'end': point(end)}, 'replacement': expected[1],
                 'named_fault_definition_sha256': sha(canonical(definition))}
    return {'case': dict(case), 'definition': definition, 'definition_sha256': sha(canonical(definition)),
            'file': case['file'], 'source_sha256': sha(source), 'program': source[:start] + after + source[end:],
            'auxiliary': auxiliary, 'auxiliary_sha256': sha(canonical(auxiliary))}


class NamedFaults:
    """Compile/list before freeze; run one baseline and two sealed native cases."""
    def __init__(self, work, state, receipt, cases):
        self.source, self.state = Path(work), Path(state)
        self.output = self.state / 'rust-named-faults'
        if not isinstance(cases, list) or len(cases) != len(NAMED_FAULTS) or {case.get('id') for case in cases} != set(NAMED_FAULTS):
            raise ValueError('Rust bounded corpus must contain exactly the two reviewed defects')
        self.output.mkdir(mode=0o700)
        hashes = {row['path']: row['sha256'] for row in receipt['files']}
        source = (self.source / 'packages/launcher/src/fs_guard.rs').read_bytes()
        if sha(source) != hashes.get('packages/launcher/src/fs_guard.rs'):
            raise ValueError('Rust named defect source differs from the frozen source receipt')
        self.rows = {case['id']: named_fault(case, source) for case in cases}
        self.original, self.finished, self.baseline = source, set(), None
        bound = {**receipt, 'copy': str(self.source)}
        schedule = {'inventory': [{'file': row['file'], 'mutant': row['auxiliary']} for row in self.rows.values()]}
        self.protected = ProtectedRust(bound, self.output, schedule)
        self.literal = module('rust-literal')
        self.work = self.output / 'work'
        self.literal.copy_source(bound, self.work)
        base = ['cargo', 'test', '--workspace', '--manifest-path', 'Cargo.toml', '--locked', '--offline']
        self.build_command, self.list_command, self.test_command = [*base, '--no-run'], [*base, '--', '--list', '--format', 'terse'], [*base, '--', '--test-threads=1']
        self.build = self._phase('pristine-build', self.build_command, 300)
        if self.build['process_status'] != 'Success':
            raise ValueError('Rust named fault pristine compilation failed')
        self.listing = self._phase('pristine-list', self.list_command, 120)
        if self.listing['process_status'] != 'Success' or self.listing.get('artifacts_complete') is not True:
            raise ValueError('Rust named fault pristine test discovery failed')
        self.tests = [{'id': 'rust:' + artifact + '#' + sha(canonical([name, 0]))[:24], 'source': artifact,
                       'source_sha256': hashes[artifact], 'name': name, 'occurrence': 0, 'runner': 'rust'}
                      for artifact, names in self.protected.inventories.items() for name in names]
        self.tests.sort(key=lambda row: (row['source'], row['name']))
        if not self.tests or len({row['id'] for row in self.tests}) != len(self.tests):
            raise ValueError('Rust named fault discovered test inventory is empty or duplicated')
        for row in self.rows.values():
            artifact, name = row['case']['test'].split('::', 1)
            if sum(test['source'] == artifact and test['name'] == name for test in self.tests) != 1:
                raise ValueError('Rust named fault expected assertion test is absent from actual discovery')
        self.preparation = {'schema_version': 1, 'profile': 'bounded', 'policy': 'bounded-reviewed-v1',
                            'qualification': 'bounded-reviewed-corpus', 'exhaustive': False,
                            'source_tree_sha256': receipt['source_tree_sha256'], 'tests': self.tests,
                            'definitions': [{'id': key, 'definition_sha256': row['definition_sha256'], 'rust_auxiliary': row['auxiliary'], 'rust_auxiliary_sha256': row['auxiliary_sha256']} for key, row in self.rows.items()],
                            'phase_results': [self.build, self.listing], 'baseline_executed': False}
        (self.output / 'preparation.json').write_bytes(canonical(self.preparation) + b'\n')

    def _phase(self, label, command, timeout):
        return self.protected.execute(command, self.work, {}, self.output / (label + '.log'), timeout)

    def _baseline(self):
        if self.baseline is not None:
            return
        phase = self._phase('baseline-test', self.test_command, 180)
        log = (self.output / 'baseline-test.log').read_text()
        evidence = self.literal.assertion_evidence(log, source=self.source, phase=phase)
        if phase['process_status'] != 'Success' or phase.get('artifacts_complete') is not True or evidence.get('artifacts_complete') is not True or not self.literal.baseline_evidence(log):
            raise ValueError('Rust named fault baseline has failed, missing, ignored or runtime outcomes')
        self.baseline = {'phase': phase, 'assertion_evidence': evidence}
        (self.output / 'baseline.json').write_bytes(canonical(self.baseline) + b'\n')

    def run(self, case, definition, mutation):
        row = self.rows.get(case.get('id'))
        if row is None or case != row['case'] or definition != row['definition'] or case['id'] in self.finished:
            raise ValueError('Rust named fault invocation differs from its scheduled exact definition')
        if not isinstance(mutation, dict) or set(mutation) != {'path', 'before_sha256', 'after_sha256', 'size', 'content_base64'}:
            raise ValueError('Rust named fault needs the closed source materialization')
        content = base64.b64decode(mutation['content_base64'], validate=True)
        if mutation['path'] != row['file'] or mutation['before_sha256'] != row['source_sha256'] or content != row['program'] or mutation['after_sha256'] != sha(content) or type(mutation['size']) is not int or mutation['size'] != len(content):
            raise ValueError('Rust named fault bytes differ from the frozen exact replacement')
        self._baseline()
        target = self.work / row['file']
        if target.read_bytes() != self.original:
            raise ValueError('Rust named fault source was not pristine before materialization')
        self.finished.add(case['id'])
        status, failure_kind, killed_by, assertion = 'RunnerError', None, [], None
        phases = []
        try:
            target.write_bytes(content)
            build = self._phase(case['id'] + '-build', self.build_command, 180); phases.append(build)
            if build['process_status'] != 'Success':
                status = 'Timeout' if build['process_status'] == 'Timeout' else 'RunnerError'; failure_kind = 'compile'
            else:
                listing = self._phase(case['id'] + '-list', self.list_command, 120); phases.append(listing)
                if listing['process_status'] != 'Success' or listing.get('artifacts_complete') is not True:
                    status = 'Timeout' if listing['process_status'] == 'Timeout' else 'RunnerError'; failure_kind = 'discovery'
                else:
                    test = self._phase(case['id'] + '-test', self.test_command, 180); phases.append(test)
                    log = (self.output / (case['id'] + '-test.log')).read_text()
                    item = {'file': row['file'], 'source_sha256': row['source_sha256'], 'definition': row['auxiliary'], 'definition_sha256': row['auxiliary_sha256']}
                    assertion = self.literal.assertion_evidence(log, item, self.source, phase=test)
                    if test['process_status'] == 'Timeout':
                        status, failure_kind = 'Timeout', 'timeout'
                    elif test.get('artifacts_complete') is not True or assertion.get('artifacts_complete') is not True:
                        failure_kind = 'runtime'
                    elif test['process_status'] == 'Success':
                        status = 'Survived' if self.literal.baseline_evidence(log) else 'RunnerError'
                    elif test['process_status'] == {'Failure': 101} and assertion.get('valid') is True:
                        ids = {(entry['source'], entry['name']): entry['id'] for entry in self.tests}
                        failures = assertion.get('failures', [])
                        expected = tuple(case['test'].split('::', 1))
                        keys = [(entry.get('artifact_id'), entry.get('test')) for entry in failures]
                        if expected in keys and all(key in ids for key in keys):
                            status, failure_kind, killed_by = 'Killed', 'assertion', sorted({ids[key] for key in keys})
                    else:
                        failure_kind = 'runtime'
        finally:
            target.write_bytes(self.original)
            if target.read_bytes() != self.original:
                raise ValueError('Rust named fault source restoration failed')
        outcome = {'id': case['id'], 'definition_sha256': row['definition_sha256'], 'status': status,
                   'failure_kind': failure_kind, 'killed_by': killed_by,
                   'evidence': {'qualification': 'bounded-reviewed-corpus', 'exhaustive': False,
                                'baseline': self.baseline, 'rust_auxiliary': row['auxiliary'], 'rust_auxiliary_sha256': row['auxiliary_sha256'],
                                'phase_results': phases, 'assertion_evidence': assertion, 'source_restored': True}}
        (self.output / (case['id'] + '.json')).write_bytes(canonical(outcome) + b'\n')
        return outcome


def prepare_named_faults(work, state, receipt, cases):
    return NamedFaults(work, state, receipt, cases)


def run(work, state, receipt, files=(), inventory_only=False, verify_schedule=None):
    """Entrypoint called only by the immutable protected OCI coordinator."""
    import sys
    bound = {**receipt, 'qualification': 'mutation-source-copy', 'source': '/input/source', 'copy': str(work)}
    snapshot = state / 'rust-source.json';snapshot.write_bytes(canonical(bound))
    backend = module('rust-literal')
    original = sys.argv
    try:
        sys.argv = ['rust-literal.py', '--snapshot', str(snapshot), '--cargo-mutants', '/opt/mutation/rust/bin/cargo-mutants', '--output', str(state / 'rust'), '--jobs', '1', '--timeout', '180', *(['--inventory-only'] if inventory_only else []), *[argument for name in files for argument in ('--file', name)]]
        return backend.main(verify_schedule=verify_schedule)
    finally:
        sys.argv = original
