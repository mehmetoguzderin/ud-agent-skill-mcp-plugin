"""Trusted Stryker coordinator; only the fixed exec boundary runs test code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import struct
import subprocess
import sys
import importlib.util


def digest(file):
    with file.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def verify_inputs(work, receipt, runtime):
    if runtime.get('platform') != 'linux/arm64':
        raise ValueError('Stryker execution requires the native ARM64 OCI input closure')
    files = receipt.get('files')
    if not isinstance(files, list) or not files:
        raise ValueError('source discovery receipt is empty')
    seen = set()
    for item in files:
        name = item.get('path')
        if not isinstance(name, str) or name.startswith('/') or any(character in name for character in '\\\0:') or any(part in ('', '.', '..') for part in name.split('/')) or name in seen:
            raise ValueError('source discovery path is unsafe or repeated')
        seen.add(name)
        file = work / name
        if file.is_symlink() or not file.is_file() or file.stat().st_size != item['size'] or digest(file) != item['sha256']:
            raise ValueError('source differs from its immutable pre-outcome snapshot')
    guard = runtime.get('native_guard', {})
    if guard.get('path') != 'bin/ud-agent-guard' or guard.get('architecture') != 'arm64':
        raise ValueError('verified Linux ARM64 native helper is missing')
    native = Path('/opt/mutation') / guard['path']
    if native.is_symlink() or not native.is_file() or native.stat().st_size != guard['size_bytes'] or digest(native) != guard['sha256']:
        raise ValueError('native helper differs from image receipt')
    with native.open('rb') as source:
        header = source.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or len(header) != 20 or struct.unpack_from('<H', header, 18)[0] != 183:
        raise ValueError('native helper has the wrong executable architecture')
    return native


def diagnostic_configuration(work, receipt, diagnostic_range=None):
    config = "import original from './stryker.config.mjs';\nexport default {...original, testRunner: 'ud-protected-vitest', concurrency: 1, disableTypeChecks: false, plugins: [...original.plugins, '/opt/mutation/harness/stryker-protected-runner.mjs'], jsonReporter: {fileName: '/state/stryker-report.json'}"
    if diagnostic_range is None:
        return config + '};\n', None
    pattern = r'((?:packages|scripts|workers|evals)/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:ts|tsx|mts|cts|js|mjs|cjs)):([1-9][0-9]{0,5}):([1-9][0-9]{0,5})-([1-9][0-9]{0,5}):([1-9][0-9]{0,5})'
    match = re.fullmatch(pattern, diagnostic_range) if isinstance(diagnostic_range, str) else None
    if not match or not re.fullmatch(r'[a-f0-9]{64}', receipt.get('source_tree_sha256', '')):
        raise ValueError('diagnostic Stryker range is not a canonical closed source range')
    name = match[1]
    entries = [item for item in receipt.get('files', []) if item.get('path') == name]
    if len(entries) != 1:
        raise ValueError('diagnostic Stryker source is absent or duplicated in its snapshot')
    current = work
    for part in name.split('/'):
        current = current / part
        if current.is_symlink():
            raise ValueError('diagnostic Stryker source contains a symbolic link')
    entry = entries[0]
    if not current.is_file() or current.stat().st_size > 16 * 1024 ** 2:
        raise ValueError('diagnostic Stryker source is not an ordinary bounded file')
    data = current.read_bytes()
    if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('diagnostic Stryker source differs from its snapshot')
    lines = [line.removesuffix('\r') for line in data.decode('utf-8', errors='strict').split('\n')]
    start = {'line': int(match[2]), 'column': int(match[3])}
    end = {'line': int(match[4]), 'column': int(match[5])}
    for position in (start, end):
        if position['line'] > len(lines) or position['column'] > len(lines[position['line'] - 1].encode('utf-16-le')) // 2 + 1:
            raise ValueError('diagnostic Stryker range is outside its source')
    if (end['line'], end['column']) <= (start['line'], start['column']):
        raise ValueError('diagnostic Stryker range is empty or reversed')
    scope = {'schema_version': 1, 'kind': 'selected-stryker-diagnostic', 'scope_complete': False,
             'source_tree_sha256': receipt['source_tree_sha256'], 'range': diagnostic_range,
             'file': name, 'source_sha256': entry['sha256'], 'source_size_bytes': len(data),
             'start': start, 'end': end}
    return config + ", mutate: " + json.dumps([diagnostic_range]) + ", coverageAnalysis: 'perTest'};\n", scope


def run(work, state, receipt, diagnostic_range=None, inventory_only=False, verify_schedule=None):
    if sys.platform != 'linux' or platform.machine().lower() not in ('aarch64', 'arm64') or os.geteuid() != 0:
        raise ValueError('the native OCI supervisor is required; host Stryker execution is refused')
    if state != Path('/state') or not work.is_relative_to(state) or work == state:
        raise ValueError('Stryker source must belong to the owned state volume')
    runtime_file = Path('/opt/mutation/input-receipt.json')
    runtime = json.loads(runtime_file.read_bytes())
    guard = verify_inputs(work, receipt, runtime)
    for name in ['stryker-protected-runner.mjs', 'stryker-child.mjs', 'stryker-exec.py', 'oci-exec.py']:
        expected = next((item for item in runtime['harness'] if item['path'] == name), None)
        file = Path('/opt/mutation/harness') / name
        if not expected or digest(file) != expected['sha256'] or file.stat().st_mode & 0o222:
            raise ValueError('trusted Stryker harness differs from immutable image receipt')
    configuration = work / '.ud-protected-stryker.config.mjs'
    config, diagnostic_scope = diagnostic_configuration(work, receipt, diagnostic_range)
    environment = {'PATH': '/opt/mutation/bin:/opt/mutation/rust/bin:/opt/mutation/node/bin:/opt/mutation/python/bin:/usr/bin:/bin', 'HOME': str(state / 'coordinator-home'),
        'LANG': 'C.UTF-8', 'SOURCE_DATE_EPOCH': '315532800', 'CARGO_NET_OFFLINE': 'true', 'PYTHONDONTWRITEBYTECODE': '1',
        'UD_MUTATION_PARENT': '1', 'UD_MUTATION_OCI_GUARD': '1', 'UD_MUTATION_GUARD': str(guard),
        'UD_AGENT_PYTHON': sys.executable, 'UD_RELEASE_PYTHON': sys.executable,
        'UD_STRYKER_SOURCE_ROOT': str(work), 'UD_STRYKER_EVIDENCE': str(state), 'UD_MUTATION_SNAPSHOT_SHA256': receipt['source_tree_sha256'],
        'NODE_OPTIONS': '--import=' + (work / 'scripts/quality/stryker-compat.mjs').as_uri()}
    Path(environment['HOME']).mkdir(mode=0o700)
    if diagnostic_range is None and (inventory_only or verify_schedule is not None):
        generated = state / 'stryker-generation.json'
        subprocess.run(['/opt/mutation/node/bin/node', str(work / 'scripts/quality/discover-stryker.mjs'), '--output', str(generated)], cwd=work, env=environment, check=True, timeout=300)
        raw = json.loads(generated.read_bytes())
        spec = importlib.util.spec_from_file_location('ud_stryker_discovery_jobs', '/opt/mutation/harness/oci-secondary.py')
        secondary = importlib.util.module_from_spec(spec); spec.loader.exec_module(secondary)
        exec_spec = importlib.util.spec_from_file_location('ud_stryker_discovery_exec', '/opt/mutation/harness/oci-exec.py')
        boundary = importlib.util.module_from_spec(exec_spec); exec_spec.loader.exec_module(boundary)
        jobs = secondary.Jobs(work, state, receipt, boundary.execute, runtime)
        collected, content = jobs.run('vitest-collect', timeout=540)
        if collected['status'] != 0 or collected['timed_out'] or content is None:
            raise ValueError('protected pristine Stryker test discovery failed')
        plan = {**raw, 'scope_complete': True, 'tests': json.loads(content)}
        (state / 'stryker-discovery-plan.json').write_text(json.dumps(plan, separators=(',', ':')) + '\n')
        if verify_schedule is not None:
            verify_schedule(plan)
            environment['UD_MUTATION_FROZEN_PLAN'] = '1'
        if inventory_only:
            return 0
    with configuration.open('x') as destination:
        destination.write(config)
    if diagnostic_scope is not None:
        scope_path = state / 'stryker-diagnostic-scope.json'
        with scope_path.open('x') as stream:
            json.dump(diagnostic_scope, stream, sort_keys=True)
            stream.write('\n')
        scope_path.chmod(0o400)
        environment['UD_STRYKER_DIAGNOSTIC_SCOPE'] = str(scope_path)
    command = ['/opt/mutation/node/bin/node', '/opt/mutation/node_modules/@stryker-mutator/core/bin/stryker.js', 'run', str(configuration)]
    journal = {'schema_version': 1, 'qualification': 'kernel-confined-stryker-execution-not-release-certification', 'source_tree_sha256': receipt['source_tree_sha256'],
        'runtime_input_sha256': digest(runtime_file), 'configuration_sha256': digest(configuration), 'command': command,
        'host': {'os': 'linux', 'process_arch': 'arm64'}, 'worker': {'os': 'linux', 'architecture': 'arm64', 'emulated': False},
        'mutant_execution': 'fresh-UID-exact-source-materialization', 'status': 'running',
        'scope_complete': diagnostic_scope is None}
    if diagnostic_scope is not None:
        journal.update(qualification='selected-diagnostic', diagnostic_scope=diagnostic_scope)
    report = state / 'stryker-runner.json'
    def save():
        report.write_text(json.dumps(journal, indent=2) + '\n')
    save()
    child = None
    def cancel(signum, frame):
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)
        raise InterruptedError('owned Stryker coordinator cancelled')
    previous = {number: signal.signal(number, cancel) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        with (state / 'stryker.log').open('xb') as output:
            child = subprocess.Popen(command, cwd=work, env=environment, stdout=output, stderr=subprocess.STDOUT)
            status = child.wait()
        journal.update(status='executed-not-reconciled' if status in (0, 1) else 'runner-error', exit_code=status)
        return status
    except BaseException as error:
        journal.update(status='runner-error', error=str(error))
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()
                journal['status'] = 'runner-error'
                journal['forced_coordinator_exit'] = True
        save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--source-receipt', type=Path, required=True)
    parser.add_argument('--diagnostic-stryker-range')
    args = parser.parse_args()
    return run(args.source_root.resolve(strict=True), args.state.resolve(strict=True), json.loads(args.source_receipt.read_bytes()), diagnostic_range=args.diagnostic_stryker_range)


if __name__ == '__main__':
    raise SystemExit(main())
