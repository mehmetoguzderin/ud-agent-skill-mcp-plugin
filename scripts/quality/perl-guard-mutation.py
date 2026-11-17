#!/usr/bin/env python3
"""Retain guard discovery through the protected native OCI mutation backend.

This is targeted evidence, not a complete Perl mutation backend: it only
negates postfix fail guards. Compile errors, execution errors, and timeouts are
never kills. Direct host execution is forbidden.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

BRIDGE = 'workers/ud/src/ud_agent/perl/graph_bridge.pl'
TEST = 'tests/domain/perl/test_graph_bridge.py'
GUARDS = re.compile(rb"\bfail\('[a-z_]+'\)\s+(if|unless)\b")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inventory(source: bytes) -> list[dict]:
    """Enumerate each recognized source occurrence exactly once."""
    source_hash = sha(source)
    found = []
    for match in GUARDS.finditer(source):
        start, end = match.span(1)
        original = match.group(1).decode('ascii')
        replacement = 'unless' if original == 'if' else 'if'
        definition = {'operator': 'postfix_fail_guard_negation', 'start': start,
                      'end': end, 'original': original, 'replacement': replacement}
        fingerprint = sha(json.dumps(definition, sort_keys=True, separators=(',', ':')).encode())
        found.append({'id': f'{BRIDGE}#{start}', 'file': BRIDGE, 'source_sha256': source_hash,
                      'definition_sha256': fingerprint, 'definition': definition})
    return found


def classify(result: dict) -> tuple[str, str]:
    """Only Python unittest assertion failures are clean mutation kills."""
    if result.get('timeout'):
        return 'Timeout', 'test runner timed out'
    if result.get('error') or result.get('status') is None:
        return 'RunnerError', 'test runner could not execute'
    output = result['stdout'] + '\n' + result['stderr']
    count = re.search(r'(?m)^Ran (\d+) tests? in ', output)
    if not count or int(count.group(1)) < 1:
        return 'RunnerError', 'test run was empty or missing its summary'
    if re.search(r'\b(?:skipped|expected failures|unexpected successes)=', output):
        return 'RunnerError', 'test run was incomplete'
    if result['status'] == 0 and re.search(r'(?m)^OK\s*$', output):
        return 'Survived', 'all tests passed'
    failures = re.search(r'(?m)^FAILED \(failures=(\d+)\)\s*$', output)
    assertion_count = len(re.findall(r'(?m)^AssertionError(?::.*)?$', output))
    if (result['status'] == 1 and failures and int(failures.group(1)) > 0
            and assertion_count == int(failures.group(1))
            and not re.search(r'(?m)^ERROR:', output)
            and "UD_COMPONENT_UNEXPECTED_EXIT:" not in output
            and "self.assertEqual(result.stderr, b'')" not in output):
        return 'Killed', 'assertion failure'
    return 'RuntimeError', 'test or bridge failed without clean assertions'


def project_protected(source: bytes, tests: bytes, full: dict) -> dict:
    """Reconcile every retained guard against actual complete PPI definitions."""
    guards = inventory(source)
    if (not guards or full.get('tool') != 'ppi-perl' or full.get('scope_complete') is not True
            or full.get('complete') is not True or full.get('sources', {}).get(BRIDGE) != sha(source)
            or set(full.get('baseline', {})) != {'bridge', 'tool'} or not all(value.get('status') == 0 and value.get('passed') is True for value in full['baseline'].values())):
        raise ValueError('complete protected Perl execution and pristine guard identity are required')
    raw = full.get('inventory', [])
    outcomes = full.get('outcomes', [])
    if len(raw) != full.get('scheduled') or len(outcomes) != len(raw) or len({item['id'] for item in raw}) != len(raw) or len({item['id'] for item in outcomes}) != len(outcomes):
        raise ValueError('complete Perl inventory or outcome reconciliation is missing')
    results = {item['id']: item for item in outcomes}
    projected = []
    for guard in guards:
        definition = guard['definition']
        matches = [item for item in raw if item.get('file') == BRIDGE and item.get('source_sha256') == guard['source_sha256'] and all(item.get('definition', {}).get(key) == definition[key] for key in ('start', 'end', 'original', 'replacement'))]
        if len(matches) != 1:
            raise ValueError('retained guard is absent or ambiguous in actual PPI discovery')
        selected = matches[0]; outcome = results.get(selected['id'])
        expected = {'tool':'ppi-perl','version':'1.0.0','operator':'keyword_'+definition['original'],**{key:definition[key]for key in('start','end','original','replacement')}}
        if selected['definition'] != expected or sha(json.dumps(expected,sort_keys=True,separators=(',',':')).encode()) != selected['definition_sha256']:
            raise ValueError('retained guard PPI definition fingerprint differs')
        if not outcome or outcome.get('definition_sha256') != selected['definition_sha256'] or outcome.get('file') != BRIDGE or outcome.get('status') == 'Killed' and (outcome.get('failure_kind') != 'assertion' or not outcome.get('tests')):
            raise ValueError('retained guard has no exact structured outcome')
        projected.append({'id': guard['id'], 'definition_sha256': guard['definition_sha256'], 'status': outcome['status'], 'reason': 'assertion failure' if outcome['status']=='Killed' else 'unresolved full-backend outcome', 'tests': outcome.get('tests', []), 'full_id': selected['id'], 'full_definition_sha256': selected['definition_sha256']})
    return {'schema_version': 1, 'tool': 'perl-guard-negation', 'qualification': 'protected-retained-guard-regression-not-full-language-acceptance',
            'scope_complete': False, 'source_tree_sha256': full['source_tree_sha256'], 'scheduled': len(guards), 'inventory': guards,
            'test_sha256': sha(tests), 'baseline': {'status': 0, 'passed': True}, 'outcomes': projected,
            'passed': all(item['status'] == 'Killed' for item in projected)}


def run(root: Path, python: str, timeout: int = 30) -> dict:
    raise ValueError('host product mutations are forbidden; use the protected OCI compatibility CLI')


def run_protected(root: Path, python: str, output: Path, image: str | None = None) -> dict:
    """Keep the old CLI as an explicit local-container compatibility route."""
    import uuid
    root = root.resolve(strict=True)
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise ValueError('protected guard report destination must be new')
    execution = root / '.artifacts' / ('perl-guard-protected-' + uuid.uuid4().hex)
    node = os.environ.get('UD_RELEASE_NODE') or shutil.which('node')
    if not node:
        raise ValueError('Node24 or26 and local native ARM64 Docker are required for this developer check')
    command = [node, str(root / 'scripts/quality/oci-python-diagnostic.mjs'), str(execution), '--source-root', str(root), '--backend', 'perl']
    if image is not None:
        command += ['--image', image]
    invoked = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12 * 60 * 60, check=False)
    runner = json.loads((execution / 'runner.json').read_bytes())
    if invoked.returncode not in (0, 1) or runner.get('backend') != 'perl' or runner.get('worker') != {'platform': 'linux', 'architecture': 'arm64', 'provider': 'local-docker', 'emulation': False} or runner.get('container_state', {}).get('OOMKilled') is not False or runner.get('container_state', {}).get('Running') is not False or len(runner.get('cleanup', [])) != 4 or any(item.get('status') != 'removed-owned' for item in runner['cleanup']):
        raise ValueError('native protected guard execution or owned cleanup did not complete')
    full = json.loads((execution / 'perl-full.json').read_bytes())
    if runner.get('source_tree_sha256') != full.get('source_tree_sha256'):
        raise ValueError('guard execution source differs from its full backend report')
    report = project_protected((root / BRIDGE).read_bytes(), (root / TEST).read_bytes(), full)
    report.update(execution={'path': str(execution), 'image': runner['image'], 'requested_python': python, 'interpreter': 'verified-image-private-python'})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as destination:
        json.dump(report, destination, indent=2); destination.write('\n')
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--python', required=True, help='retained compatibility label; execution uses the verified image interpreter')
    parser.add_argument('--image', help='explicit local native ARM64 mutation-runner image')
    args = parser.parse_args()
    run_protected(args.root, args.python, args.output, args.image)
    # This restricted operator inventory is deliberately never full acceptance.
    return 1


if __name__ == '__main__':
    sys.exit(main())
