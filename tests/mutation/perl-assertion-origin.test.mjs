import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { assessPerlTestEvidence } from '../../scripts/quality/perl-assess.mjs';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function fixture() {
  const source = 'tests/domain/perl/test_origin.py', helper = 'tests/helpers/assertions.py';
  const bytes = Buffer.from('import unittest\nclass Suite(unittest.TestCase):\n def test_one(self):\n  check_observed()\n');
  const helperBytes = Buffer.from('def check_observed():\n assert observed == expected\n');
  const expected = [{ id: 'test_origin.Suite.test_one', source, source_sha256: sha(bytes) }];
  const origin = { contract: 'python-test-source-origin-v2', source: helper, source_sha256: sha(helperBytes), line: 2,
    test_id: expected[0].id, test_source: source, test_source_sha256: sha(bytes), test_line: 4 };
  const value = { schema_version: 1, contract: 'python-test-source-origin-v2', expected, tests_run: 1, successful: false,
    cases: [{ ...expected[0], completed: true, events: [{ kind: 'failure', assertion: true, exception_type: 'builtins.AssertionError', assertion_origin: origin }] }] };
  const hashes = { [source]: sha(bytes), [helper]: sha(helperBytes) };
  const read = name => name === source ? bytes : name === helper ? helperBytes : null;
  return { expected, value, hashes, read };
}

test('Perl accepts an exact test/helper origin bound to its scheduled test and frozen bytes', () => {
  const f = fixture();
  assert.deepEqual(assessPerlTestEvidence(f.value, f.expected, f.hashes, f.read), { valid: true, failures: ['test_origin.Suite.test_one'] });
});

test('Perl refuses production assertions, ancestry-only claims and altered origin bindings', () => {
  const f = fixture();
  const invalid = [
    value => { value.cases[0].events[0].kind = 'error'; value.cases[0].events[0].assertion_origin = null; },
    value => { value.contract = 'unittest-exception-ancestry-v1'; },
    value => { delete value.cases[0].events[0].assertion_origin; value.cases[0].events[0].assertion_sites = [{ source: f.expected[0].source, source_sha256: f.expected[0].source_sha256, line: 4 }]; },
    value => { value.cases[0].events[0].assertion_origin.source = 'scripts/production.py'; },
    value => { value.cases[0].events[0].assertion_origin.test_id = 'foreign.Suite.test_one'; },
    value => { value.cases[0].events[0].assertion_origin.source_sha256 = 'f'.repeat(64); },
    value => { value.cases[0].events[0].assertion_origin.line = 3; },
    value => { value.cases[0].events[0].assertion_origin.test_line = 5; },
  ];
  for (const alter of invalid) {
    const value = structuredClone(f.value); alter(value);
    assert.deepEqual(assessPerlTestEvidence(value, f.expected, f.hashes, f.read), { valid: false, failures: [] });
  }
  assert.deepEqual(assessPerlTestEvidence(f.value, f.expected, f.hashes, () => Buffer.from('changed source\n')), { valid: false, failures: [] });
});
