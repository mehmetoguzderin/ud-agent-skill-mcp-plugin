"""Persistent trusted stdio controller; each test job receives a fresh UID."""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import sys

MAX_FRAME = 64 * 1024**2
MAX_RESULT = 32 * 1024**2


def compiled_sources(value):
    """The trusted parent supplies a bounded original compiled-source inventory.

    Actual script/map/source replay belongs to the fixed Node verifier; this
    controller only transports the closed data contract, never executable code.
    """
    if not isinstance(value, dict) or set(value) != {'schema_version', 'normalization', 'child_root', 'entries'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['normalization'] != 'ud-job-root-and-inline-map-1' or not isinstance(value['child_root'], str) or not re.fullmatch(r'/tmp/ud-mutation-jobs/[a-f0-9]{32}/tree', value['child_root']) or not isinstance(value['entries'], list) or not 1 <= len(value['entries']) <= 20000:
        raise ValueError('original compiled-source authority is missing or unbounded')
    if len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()) > 24 * 1024**2:
        raise ValueError('original compiled-source authority exceeds its byte bound')
    return value


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate protocol key')
        result[key] = value
    return result


def selection(value):
    fields = {'schema_version', 'contract', 'mutant_id', 'cases', 'all_cases', 'sha256', 'baseline_sha256', 'coverage_sha256'} | ({'strategy'} if isinstance(value, dict) and 'strategy' in value else set())
    if not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['contract'] != 'pristine-per-test-selection-v1' or not isinstance(value['mutant_id'], str) or not re.fullmatch(r'0|[1-9][0-9]*', value['mutant_id']) or any(not isinstance(value[key], str) or not re.fullmatch(r'[a-f0-9]{64}', value[key]) for key in ('sha256', 'baseline_sha256', 'coverage_sha256')):
        raise ValueError('invalid source-bound test selection')
    if 'strategy' in value and value['strategy'] not in ('observed-original-coverage', 'unattributed-original-full-suite', 'observed-original-coverage-plus-opaque-cases', 'opaque-original-full-suite'):
        raise ValueError('unknown source-bound selection strategy')
    inventory = {}
    keys = {'id', 'source', 'source_sha256', 'name', 'occurrence', 'upstream_id'}
    for label in ('all_cases', 'cases'):
        rows = value[label]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 50000:
            raise ValueError('selected test inventory is empty or unbounded')
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != keys or any(not isinstance(row[key], str) for key in ('id', 'source', 'source_sha256', 'name', 'upstream_id')) or type(row['occurrence']) is not int or row['occurrence'] < 0 or not row['name'] or len(row['name']) > 65536 or '\0' in row['name'] or not re.fullmatch(r'[a-f0-9]{64}', row['source_sha256']):
                raise ValueError('selected test case is malformed')
            source = row['source']
            identity = hashlib.sha256(json.dumps([row['name'], row['occurrence']], ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()[:24]
            if not source.startswith('tests/') or any(char in source for char in '\\\0:') or any(part in ('', '.', '..') for part in source.split('/')) or row['id'] != source + '#ud-case-' + identity or row['upstream_id'] != source + '#' + row['name'] or row['id'] in seen:
                raise ValueError('selected test case is unbound or duplicated')
            seen.add(row['id'])
            if label == 'all_cases':
                inventory[row['id']] = row
            elif inventory.get(row['id']) != row:
                raise ValueError('selected case differs from its complete original inventory')
    identities = [[row[key] for key in ('id', 'source', 'source_sha256', 'name', 'occurrence', 'upstream_id')] for row in value['cases']]
    expected = hashlib.sha256(json.dumps(identities, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    chosen = {row['id'] for row in value['cases']}
    if expected != value['sha256'] or [row for row in value['all_cases'] if row['id'] in chosen] != value['cases']:
        raise ValueError('selected test fingerprint/order differs')
    if value.get('strategy') in ('unattributed-original-full-suite', 'opaque-original-full-suite') and value['cases'] != value['all_cases']:
        raise ValueError('unattributed coverage requires the complete original catalog')
    return value


def parse_frame(frame):
    if not isinstance(frame, bytes) or not frame.endswith(b'\n') or len(frame) > MAX_FRAME:
        raise ValueError('bounded newline-terminated request required')
    request = json.loads(frame, object_pairs_hook=unique_keys)
    if not isinstance(request, dict) or type(request.get('schema_version')) is not int or request.get('schema_version') != 1 or not isinstance(request.get('id'), str) or not re.fullmatch(r'[1-9][0-9]{0,15}', request['id']) or request.get('kind') not in ('dry-run', 'selection-baseline', 'mutant'):
        raise ValueError('invalid protected runner request')
    keys = {'schema_version', 'id', 'kind', 'workspace', 'options'} | ({'mutation'} if request['kind'] == 'mutant' else set()) | ({'assertion_compiled_sources'} if request['kind'] != 'dry-run' else set())
    if set(request) != keys:
        raise ValueError('protected runner request has unknown or missing fields')
    if request['kind'] != 'dry-run':
        compiled_sources(request['assertion_compiled_sources'])
    options = request['options']
    common = {'timeout', 'disableBail'}
    if request['kind'] == 'dry-run':
        extra = {'coverageAnalysis'}
    elif request['kind'] == 'selection-baseline':
        extra = {'selection'}
    else:
        extra = {'activeMutant', 'mutantActivation', 'reloadEnvironment', 'sandboxFileName'}
        if isinstance(options, dict) and 'selection' in options:
            extra.add('selection')
    if not isinstance(options, dict) or set(options) != common | extra or options['disableBail'] is not True or type(options['timeout']) is not int or not 1 <= options['timeout'] <= 540000:
        raise ValueError('filtered, unbounded or malformed execution options')
    if request['kind'] == 'dry-run':
        if options['coverageAnalysis'] not in ('off', 'perTest'):
            raise ValueError('complete unfiltered discovery required')
    elif request['kind'] == 'selection-baseline':
        selection(options['selection'])
    else:
        if 'selection' in options:
            selection(options['selection'])
        active = options['activeMutant']
        source = options['sandboxFileName']
        if not isinstance(active, dict) or set(active) != {'id'} or not isinstance(active['id'], str) or not 1 <= len(active['id']) <= 1024 or options['mutantActivation'] not in ('static', 'runtime') or options['reloadEnvironment'] is not True or not isinstance(source, str) or any(value in source for value in ('\\', '\0', ':')) or source.startswith('/') or any(part in ('', '.', '..') for part in source.split('/')):
            raise ValueError('invalid mutant identity or source path')
        if 'selection' in options and options['selection']['mutant_id'] != active['id']:
            raise ValueError('test selection belongs to another mutant')
        mutation = request['mutation']
        fields = {'path', 'before_sha256', 'after_sha256', 'definition_sha256', 'materializer_version', 'serialized_replacement', 'size', 'content_base64'}
        if not isinstance(mutation, dict) or set(mutation) != fields or mutation['path'] != source or not source.startswith(('packages/', 'scripts/', 'workers/', 'evals/')) or type(mutation['size']) is not int or not 0 <= mutation['size'] <= 16 * 1024**2 or not isinstance(mutation['content_base64'], str) or mutation['materializer_version'] != 'stryker-ast-materializer-v1' or not isinstance(mutation['serialized_replacement'], str) or len(mutation['serialized_replacement'].encode('utf-8')) > 16 * 1024**2 or not all(isinstance(mutation[key], str) and re.fullmatch(r'[a-f0-9]{64}', mutation[key]) for key in ('before_sha256', 'after_sha256', 'definition_sha256')):
            raise ValueError('invalid exact source materialization contract')
        content = base64.b64decode(mutation['content_base64'], validate=True)
        if len(content) != mutation['size'] or hashlib.sha256(content).hexdigest() != mutation['after_sha256']:
            raise ValueError('exact materialized source bytes differ')
    return request


def handle(request, *, state, source_root, runtime, execute, cancel_fd=None):
    workspace = request['workspace']
    if not isinstance(workspace, dict) or set(workspace) != {'root', 'files'} or workspace['root'] != str(source_root):
        raise ValueError('sandbox differs from the controller-bound source root')
    descriptor = runtime['node_dependencies']
    if descriptor['path'] != 'node-dependencies.json':
        raise ValueError('dependency closure is not the immutable image receipt')
    handoff = {**workspace, 'readonly_links': [{'path': 'node_modules', 'target': '/opt/mutation/node_modules',
        'closure_receipt': {**descriptor, 'path': '/opt/mutation/node-dependencies.json'}}], 'readonly_tree': True}
    if request['kind'] == 'mutant':
        change = request['mutation']
        matches = [item for item in workspace['files'] if item.get('path') == change['path']]
        if len(matches) != 1:
            raise ValueError('materialization target is not one closed sandbox member')
        handoff['materializations'] = [{'path': change['path'], 'before_sha256': matches[0]['sha256'],
            'after_sha256': change['after_sha256'], 'size': change['size'],
            'bytes': base64.b64decode(change['content_base64'], validate=True)}]
    test_sources = {item['path']: item['sha256'] for item in workspace['files'] if item['path'].startswith('tests/')}
    sdk_context = {'schema_version': 1, 'root': '/opt/mutation/node_modules', 'receipt_sha256': descriptor['sha256']}
    payload = json.dumps({'schema_version': 1, 'kind': request['kind'], 'options': request['options'], 'readonly_tree': True, 'source_inventory': test_sources, 'assertion_sdk_context': sdk_context, **({'assertion_compiled_sources': request['assertion_compiled_sources']} if request['kind'] != 'dry-run' else {}), **({'mutation': request['mutation']} if request['kind'] == 'mutant' else {})}, separators=(',', ':'), sort_keys=True).encode()
    environment = {'PATH': '/opt/mutation/bin:/opt/mutation/rust/bin:/opt/mutation/node/bin:/opt/mutation/python/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1', 'UD_AGENT_PYTHON': '/opt/mutation/python/bin/python3', 'UD_RELEASE_PYTHON': '/opt/mutation/python/bin/python3'}
    guard = os.environ.get('UD_MUTATION_GUARD')
    if guard:
        candidate = Path(guard).resolve(strict=True)
        pinned = Path('/opt/mutation/bin/ud-agent-guard')
        if candidate == pinned:
            expected = runtime.get('native_guard', {})
            if expected.get('path') != 'bin/ud-agent-guard' or candidate.stat().st_size != expected.get('size_bytes') or hashlib.sha256(candidate.read_bytes()).hexdigest() != expected.get('sha256'):
                raise ValueError('immutable native helper differs from image receipt')
        elif not candidate.is_relative_to('/state') or not candidate.is_file():
            raise ValueError('native helper is outside the owned immutable input state')
        environment['UD_MUTATION_GUARD'] = str(candidate)
    result = execute(['/opt/mutation/node/bin/node', '/opt/mutation/harness/stryker-child.mjs', '{request}', '{result}'],
        state=state, environment=environment, timeout=math.ceil(request['options']['timeout'] / 1000) + 30,
        workspace=handoff, request={'basename': 'request.json', 'bytes': payload}, result={'basename': 'result.json', 'max_bytes': MAX_RESULT}, cancel_fd=cancel_fd)
    data = result.pop('result_bytes', None)
    response = {'schema_version': 1, 'id': request['id'], 'execution': result}
    if data is None:
        response['error'] = 'Isolated test invocation produced no verified result manifest.'
    else:
        if not isinstance(data, bytes) or len(data) > MAX_RESULT or type(result['result_size']) is not int or len(data) != result['result_size'] or hashlib.sha256(data).hexdigest() != result['result_sha256']:
            raise ValueError('isolated manifest exceeds its byte contract')
        response.update(result_base64=base64.b64encode(data).decode('ascii'), result_sha256=result['result_sha256'], result_size=result['result_size'])
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('trusted native OCI supervisor required')
    state, source = args.state.resolve(strict=True), args.source_root.resolve(strict=True)
    if state != Path('/state') or not source.is_relative_to(state) or source == state:
        raise ValueError('controller is not bound to owned source state')
    runtime = json.loads(Path('/opt/mutation/input-receipt.json').read_bytes())
    spec = importlib.util.spec_from_file_location('ud_stryker_exec', Path(__file__).with_name('oci-exec.py'))
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    def cancel(signum, frame):
        # Unwind through execute's exact-identity/UID cleanup before exiting.
        raise InterruptedError('protected Stryker controller cancelled')
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    seen = set()
    while frame := sys.stdin.buffer.readline(MAX_FRAME + 1):
        request = None
        try:
            request = parse_frame(frame)
            if request['id'] in seen:
                raise ValueError('duplicate controller sequence')
            seen.add(request['id'])
            response = handle(request, state=state, source_root=source, runtime=runtime, execute=boundary.execute, cancel_fd=sys.stdin.fileno())
        except Exception as error:
            response = {'schema_version': 1, 'id': request.get('id') if request else None, 'error': str(error)[:65536]}
        encoded = json.dumps(response, separators=(',', ':')).encode() + b'\n'
        if len(encoded) > MAX_FRAME:
            raise ValueError('controller response exceeded frame bound')
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        if response.get('error'):
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
