import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { assessPerlGuards } from '../../scripts/quality/perl-guard-assess.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const file = 'workers/ud/src/ud_agent/perl/graph_bridge.pl';
const testFile = 'tests/domain/perl/test_graph_bridge.py';

test('Perl targeted mutation reconciliation requires exact source, definitions, outcomes and assertions', () => {
  const source = Buffer.from("fail('first') if $a;\n");
  const start = source.indexOf('if');
  const definition = { end: start + 2, operator: 'postfix_fail_guard_negation', original: 'if', replacement: 'unless', start };
  const mutant = { id: `${file}#${start}`, file, source_sha256: hash(source), definition_sha256: hash(JSON.stringify(definition)), definition };
  const hashes = { [file]: hash(source), [testFile]: hash('tests') };
  const outcome = { id: mutant.id, definition_sha256: mutant.definition_sha256, status: 'Killed', reason: 'assertion failure', tests: ['test_graph'] };
  const report = { tool: 'perl-guard-negation', scope_complete: false, scheduled: 1, inventory: [mutant], outcomes: [outcome], test_sha256: hashes[testFile], baseline: { status: 0, passed: true } };
  assert.deepEqual(assessPerlGuards(report, source, hashes), { total: 1, killed: 1, equivalent: 0, errors: [] });
  for (const status of ['Survived', 'Timeout', 'RuntimeError', 'CompileError', 'RunnerError']) {
    assert.ok(assessPerlGuards({ ...report, outcomes: [{ ...outcome, status }] }, source, hashes).errors.length);
  }
  assert.ok(assessPerlGuards({ ...report, outcomes: [{ ...outcome, tests: [] }] }, source, hashes).errors.length);
  assert.ok(assessPerlGuards({ ...report, outcomes: [] }, source, hashes).errors.length);
  assert.ok(assessPerlGuards({ ...report, outcomes: [outcome, outcome] }, source, hashes).errors.length);
  assert.ok(assessPerlGuards({ ...report, inventory: [{ ...mutant, definition_sha256: '0'.repeat(64) }] }, source, hashes).errors.length);
  assert.ok(assessPerlGuards({ ...report, test_sha256: '0'.repeat(64) }, source, hashes).errors.length);
  assert.ok(assessPerlGuards({ ...report, scope_complete: true }, source, hashes).errors.length);
});
