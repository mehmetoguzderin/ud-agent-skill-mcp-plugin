"""Original protocol data only; no mutation or candidate process is executed."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ud_selection_protocol', ROOT / 'scripts/quality/stryker-exec.py')
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def case(name, occurrence=0):
    source = 'tests/unicode.test.mjs'
    identity = digest(json.dumps([name, occurrence], ensure_ascii=False, separators=(',', ':')).encode())[:24]
    return {'id': source + '#ud-case-' + identity, 'source': source,
            'source_sha256': digest(b'// unicode source\n'), 'name': name,
            'occurrence': occurrence, 'upstream_id': source + '#' + name}


def fingerprint(cases):
    fields = ('id', 'source', 'source_sha256', 'name', 'occurrence', 'upstream_id')
    return digest(json.dumps([[row[key] for key in fields] for row in cases], ensure_ascii=False, separators=(',', ':')).encode())


def selection():
    rows = [case('suite > 漢字 [a-z].*'), case('suite > duplicate'), case('suite > duplicate', 1)]
    return {'schema_version': 1, 'contract': 'pristine-per-test-selection-v1', 'mutant_id': '7',
            'cases': [copy.deepcopy(rows[0]), copy.deepcopy(rows[2])], 'all_cases': rows,
            'sha256': fingerprint([rows[0], rows[2]]), 'baseline_sha256': 'b' * 64, 'coverage_sha256': 'c' * 64}


def request(kind='selection-baseline'):
    value = {'schema_version': 1, 'id': '1', 'kind': kind, 'workspace': {'root': '/state/sandbox', 'files': []},
             'assertion_compiled_sources': {'schema_version': 1, 'normalization': 'ud-job-root-and-inline-map-1', 'child_root': '/tmp/ud-mutation-jobs/' + 'a' * 32 + '/tree', 'entries': [{'source': 'tests/unicode.test.mjs'}]},
             'options': {'timeout': 1000, 'disableBail': True, 'selection': selection()}}
    if kind == 'mutant':
        content = b'export const answer = false;\n'
        value['options'].update(activeMutant={'id': '7'}, mutantActivation='runtime', reloadEnvironment=True,
                                sandboxFileName='packages/example/src/source.ts')
        value['mutation'] = {'path': 'packages/example/src/source.ts', 'before_sha256': 'a' * 64,
                             'after_sha256': digest(content), 'definition_sha256': 'd' * 64,
                             'materializer_version': 'stryker-ast-materializer-v1', 'serialized_replacement': 'false',
                             'size': len(content), 'content_base64': base64.b64encode(content).decode()}
    return value


def parse(value):
    return CONTROLLER.parse_frame(json.dumps(value, ensure_ascii=False).encode() + b'\n')


class StrykerSelectionTests(unittest.TestCase):
    def test_opaque_execution_strategies_preserve_complete_suite_when_uncertain(self):
        value = selection()
        value['strategy'] = 'observed-original-coverage-plus-opaque-cases'
        self.assertEqual(CONTROLLER.selection(value), value)
        value['strategy'] = 'opaque-original-full-suite'
        with self.assertRaisesRegex(ValueError, 'complete original catalog'):
            CONTROLLER.selection(value)
        value['cases'] = copy.deepcopy(value['all_cases'])
        value['sha256'] = fingerprint(value['cases'])
        self.assertEqual(CONTROLLER.selection(value), value)

    def test_opaque_child_fallback_requires_complete_catalog_and_a_known_explicit_strategy(self):
        value = selection()
        value['strategy'] = 'unattributed-original-full-suite'
        with self.assertRaisesRegex(ValueError, 'complete original catalog'):
            CONTROLLER.selection(value)
        value['cases'] = copy.deepcopy(value['all_cases'])
        value['sha256'] = fingerprint(value['cases'])
        self.assertEqual(CONTROLLER.selection(value), value)
        for strategy in ('invented', True, None, 'unattributed-original-full-suite '):
            changed = copy.deepcopy(value); changed['strategy'] = strategy
            with self.subTest(strategy=strategy), self.assertRaises(ValueError):
                CONTROLLER.selection(changed)
        value['strategy'] = 'observed-original-coverage'
        value['cases'] = [value['all_cases'][0]]
        value['sha256'] = fingerprint(value['cases'])
        self.assertEqual(CONTROLLER.selection(value), value)

    def test_utf8_fingerprint_matches_independent_cross_language_golden(self):
        row = case('suite > 漢字 [a-z].*')
        self.assertEqual(row['id'], 'tests/unicode.test.mjs#ud-case-1a70a0f0304e2161195048e9')
        self.assertEqual(fingerprint([row]), '0cd2c8cf4b43cde15b95918ea59bdd699fe68c71bc388ee7a8fc6246246abe04')
        value = selection()
        self.assertEqual(CONTROLLER.selection(value), value)
        self.assertEqual(parse(request()), request())
        self.assertEqual(parse(request('mutant')), request('mutant'))

    def test_schema_and_each_identity_field_are_closed_and_typed(self):
        changes = [lambda value: value.update(schema_version=True), lambda value: value.update(extra='foreign'),
                   lambda value: value.update(mutant_id='07'), lambda value: value.update(cases=[]),
                   lambda value: value['all_cases'][0].update(extra=True),
                   lambda value: value['all_cases'][0].update(occurrence=True),
                   lambda value: value['all_cases'][0].update(name=''),
                   lambda value: value['all_cases'][0].update(name='bad\0name'),
                   lambda value: value['all_cases'][0].update(source='../outside'),
                   lambda value: value['all_cases'][0].update(source='tests/../outside'),
                   lambda value: value['all_cases'][0].update(source_sha256='bad'),
                   lambda value: value['all_cases'][0].update(id='foreign'),
                   lambda value: value['all_cases'][0].update(upstream_id='tests/unicode.test.mjs#foreign')]
        for change in changes:
            value = selection(); change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROLLER.selection(value)

    def test_omissions_duplicates_reordering_and_fingerprint_changes_are_rejected(self):
        changes = [lambda value: value['all_cases'].append(value['all_cases'][0]),
                   lambda value: value['cases'].append(value['cases'][0]),
                   lambda value: value['all_cases'].pop(0),
                   lambda value: value['cases'][0].update(source_sha256='f' * 64),
                   lambda value: value.update(sha256='0' * 64)]
        for change in changes:
            value = selection(); change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                CONTROLLER.selection(value)
        value = selection(); value['cases'].reverse(); value['sha256'] = fingerprint(value['cases'])
        with self.assertRaisesRegex(ValueError, 'order'):
            CONTROLLER.selection(value)
        # Keep both copies and the complete fingerprint coherent: only the
        # upstream-name binding can reject this otherwise source-bound row.
        value = selection()
        value['all_cases'][0]['upstream_id'] = value['all_cases'][0]['source'] + '#different'
        value['cases'][0] = copy.deepcopy(value['all_cases'][0])
        value['sha256'] = fingerprint(value['cases'])
        with self.assertRaisesRegex(ValueError, 'unbound'):
            CONTROLLER.selection(value)

    def test_baseline_and_mutant_requests_cannot_accept_caller_filters_or_cross_mutant_selection(self):
        for kind in ('selection-baseline', 'mutant'):
            for key, data in [('testFilter', ['one']), ('testFiles', ['tests/one']), ('coverageAnalysis', 'off'), ('command', ['sh'])]:
                value = request(kind); value['options'][key] = data
                with self.subTest(kind=kind, key=key), self.assertRaises(ValueError):
                    parse(value)
        value = request('mutant'); value['options']['selection']['mutant_id'] = '8'
        with self.assertRaisesRegex(ValueError, 'another mutant'):
            parse(value)
        value = request(); value['mutation'] = request('mutant')['mutation']
        with self.assertRaises(ValueError):
            parse(value)
        value = request(); del value['options']['selection']
        with self.assertRaises(ValueError):
            parse(value)


if __name__ == '__main__':
    unittest.main()
