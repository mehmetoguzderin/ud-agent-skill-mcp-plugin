import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { assessPerl, assessPerlTestEvidence } from '../../scripts/quality/perl-assess.mjs';
const sha = value => createHash('sha256').update(value).digest('hex');

test('full Perl reconciliation binds independent schedule, exact bytes and assertion evidence', () => {
  const file = 'scripts/example.pl', test = 'tests/mutation/test_perl_inventory.py', bridgeTest = 'tests/domain/perl/test_bridge.py';
  const source = Buffer.from('if $value;\n');
  const testBytes = Buffer.from('import unittest\nclass Suite(unittest.TestCase):\n def test_expected(self):\n  self.assertEqual(1, 2)\n');
  const definition = { end: 2, operator: 'keyword_if', original: 'if', replacement: 'unless', start: 0, tool: 'ppi-perl', version: '1.0.0' };
  const item = { id: `${file}#0:keyword_if`, file, source_sha256: sha(source), definition_sha256: sha(JSON.stringify(definition)), definition };
  const operatorBytes = readFileSync(new URL('../../quality/perl-operators.json', import.meta.url));
  const hashes = { [file]: sha(source), [test]: sha(testBytes), [bridgeTest]: sha(testBytes), 'quality/perl-operators.json': sha(operatorBytes) };
  const frozen = {sha256:'d'.repeat(64),files:Object.entries(hashes).map(([path,sha256])=>({path,sha256,size:0,executable:false}))};
  const assess = (...args) => { while(args.length<7) args.push(undefined); const read = args[6] ?? (() => null); args[6] = name => name === 'quality/perl-operators.json' ? operatorBytes : [test, bridgeTest].includes(name) ? testBytes : read(name); return assessPerl(...args,frozen); };
  const coverage = [{ start: 0, end: 2, class: 'PPI::Token::Word', content: 'if', classification: 'scheduled', reason: 'Declared token rule', mutant_ids: [item.id] }, ...[[' ', 2, 3, 'Whitespace'], ['$value', 3, 9, 'Symbol'], [';', 9, 10, 'Structure'], ['\n', 10, 11, 'Whitespace']].map(([content, start, end, kind]) => ({ start, end, class: 'PPI::Token::' + kind, content, classification: 'outside-selected-family', reason: 'PPI syntax outside selected family', mutant_ids: [] }))];
  const plan = { scope_complete: true, operator_coverage: { [file]: coverage }, source_tree_sha256:frozen.sha256,source_inventory:frozen.files,tool: 'ppi-perl', parser_release: 'PPI-1.291', sources: { [file]: hashes[file] }, tests: { [test]: hashes[test], [bridgeTest]: hashes[bridgeTest] }, case_inventory: { bridge: [{ id: 'test_bridge.Suite.test_expected', source: bridgeTest, source_sha256: hashes[bridgeTest] }], tool: [{ id: 'test_perl_inventory.Suite.test_expected', source: test, source_sha256: hashes[test] }] }, operator_sha256: hashes['quality/perl-operators.json'], scheduled: 1, inventory: [item] };
  const typed = (expected, failed = false) => ({ schema_version: 1, contract: 'python-test-source-origin-v2', suite: expected[0].source === test ? 'tool' : 'bridge', expected, tests_run: expected.length, successful: !failed, cases: expected.map(item => ({ ...item, completed: true, events: failed ? [{ kind: 'failure', assertion: true, exception_type: 'builtins.AssertionError', assertion_origin: { contract: 'python-test-source-origin-v2', source: item.source, source_sha256: item.source_sha256, line: 4, test_id: item.id, test_source: item.source, test_source_sha256: item.source_sha256, test_line: 4 } }] : [{ kind: 'success' }] })) });
  const outcome = { id: item.id, file, definition_sha256: item.definition_sha256, status: 'Killed', failure_kind: 'assertion', tests: ['test_perl_inventory.Suite.test_expected'], evidence: { phase: 'test', status: 1, unittest: typed(plan.case_inventory.tool, true), stdout: '', stderr: 'FAIL: test_expected (Suite)\nAssertionError: observed changed behavior\nRan 1 test in 0.1s\nFAILED (failures=1)\n' } };
  const report = { ...plan, tool_version: '1.0.0', scope_complete: true, complete: true, baseline: { bridge: { passed: true, status: 0, unittest: typed(plan.case_inventory.bridge) }, tool: { passed: true, status: 0, unittest: typed(plan.case_inventory.tool) } }, outcomes: [outcome] };
  assert.deepEqual(assess(report, plan, { [file]: source }, hashes), { total: 1, killed: 1, equivalent: 0, errors: [] });
  for (const status of ['Survived', 'RuntimeError', 'CompileError', 'Timeout', 'RunnerError']) assert.ok(assess({ ...report, outcomes: [{ ...outcome, status }] }, plan, { [file]: source }, hashes).errors.length);
  for (const changed of [{ ...report, outcomes: [] }, { ...report, outcomes: [outcome, outcome] }, { ...report, complete: false }, { ...report, sources: {} }, { ...report, inventory: [] }, { ...report, tests: {} }, { ...report, source_tree_sha256:'f'.repeat(64) }, { ...report, source_inventory:[] }]) assert.ok(assess(changed, plan, { [file]: source }, hashes).errors.length);
  assert.ok(assess({ ...report, outcomes: [{ ...outcome, evidence: { ...outcome.evidence, stderr: outcome.evidence.stderr.replace('AssertionError', 'ValueError') } }] }, plan, { [file]: source }, hashes).errors.length);
  assert.ok(assess(report, { ...plan, inventory: [{ ...item, definition: { ...definition, replacement: 'if' } }] }, { [file]: source }, hashes).errors.length);
  const reviewPath = 'quality/reviews/fixture.json';
  const proof = 'Independent proof binds every observable input and side effect to this exact replacement.';
  const review = Buffer.from(JSON.stringify({ reviewer: 'independent-reviewer', reviews: [{ id: item.id, source_sha256: item.source_sha256, definition_sha256: item.definition_sha256, definition, equivalent: true, reason: proof }] }));
  const exception = { tool: 'ppi-perl', id: item.id, file, source_sha256: item.source_sha256, definition_sha256: item.definition_sha256, author: 'implementer', reviewed_by: 'independent-reviewer', proof, review: { path: reviewPath, sha256: sha(review) } };
  const used = new Set();
  const survived = { ...report, outcomes: [{ ...outcome, status: 'Survived', tests: [], failure_kind: null, evidence: { phase: 'test', status: 0, stdout: '', stderr: 'Ran 1 test in 0.1s\nOK\n', unittest: typed(plan.case_inventory.tool) } }] };
  for (const alter of [value => { delete value.unittest; }, value => { value.unittest.cases.pop(); }, value => { value.unittest.cases[0].completed = false; }, value => { value.unittest.cases[0].events[0].assertion = false; }, value => { value.unittest.cases[0].events[0].kind = 'error'; }, value => { value.unittest.cases[0].events[0].assertion_origin = null; }, value => { value.unittest.expected[0].source_sha256 = 'f'.repeat(64); }]) {
    const evidence = structuredClone(outcome.evidence); alter(evidence);
    assert.ok(assess({ ...report, outcomes: [{ ...outcome, evidence }] }, plan, { [file]: source }, hashes).errors.length);
  }
  assert.deepEqual(assessPerlTestEvidence(null, plan.case_inventory.tool), { valid: false, failures: [] });
  const assessed = assess(survived, plan, { [file]: source }, { ...hashes, [reviewPath]: sha(review) }, [exception], used, () => review);
  assert.deepEqual(assessed, { total: 1, killed: 0, equivalent: 1, errors: [] });
  assert.ok(used.has(`ppi-perl\0${item.id}`));
  assert.ok(assess(survived, plan, { [file]: source }, { ...hashes, [reviewPath]: sha(review) }, [{ ...exception, definition_sha256: 'f'.repeat(64) }], new Set(), () => review).errors.length);
});
