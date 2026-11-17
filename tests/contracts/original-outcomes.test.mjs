import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { originalPythonOutcomes, originalRustOutcomes, originalVitestOutcomes, reconcileOriginalOutcomes } from '../../scripts/quality/original-outcomes.mjs';

const python = () => ({ schema_version: 1, kind: 'original-unittest-execution', successful: true, tests_run: 1, cases: [{ id: 'test_case.Case.test_behavior', source: 'tests/test_case.py', source_sha256: 'a'.repeat(64), completed: true, events: [{ kind: 'success' }] }] });
function vitest(root) {
  return { success: true, numFailedTests: 0, numPendingTests: 0, numTodoTests: 0, numFailedTestSuites: 0, numPendingTestSuites: 0, numTotalTestSuites: 1, numPassedTestSuites: 1, numTotalTests: 1, numPassedTests: 1, testResults: [{ name: path.join(root, 'tests/example.test.mjs'), status: 'passed', assertionResults: [{ fullName: 'independent behavior', title: 'independent behavior', ancestorTitles: [], status: 'passed', failureMessages: [] }] }] };
}
test('original Vitest observations require clean individual cases and exact complete totals', () => {
  const root = path.resolve('/tmp/original-tests'), data = vitest(root);
  assert.deepEqual(originalVitestOutcomes(root, data), [{ runner: 'vitest', source: 'tests/example.test.mjs', name: 'independent behavior', status: 'passed' }]);
  for (const change of [x => { x.success = false; }, x => { x.numPendingTests = 1; }, x => { delete x.numTodoTests; }, x => { x.numTotalTests = 2; }, x => { x.testResults = []; }, x => { x.testResults[0].assertionResults[0].failureMessages.push('outside error'); }, x => { x.testResults[0].name = path.resolve('/outside/test.mjs'); }]) {
    const changed = structuredClone(data); change(changed); assert.throws(() => originalVitestOutcomes(root, changed));
  }
  for (const key of ['numTotalTestSuites', 'numPassedTestSuites', 'numTotalTests', 'numPassedTests']) for (const value of [undefined, null, -1, 0, 1.5, '1', Number.MAX_SAFE_INTEGER + 1]) {
    const changed = structuredClone(data); changed[key] = value;
    assert.throws(() => originalVitestOutcomes(root, changed), /totals|inventory/);
  }
  const missing = structuredClone(data); delete missing.numTotalTestSuites; delete missing.numPassedTestSuites;
  assert.throws(() => originalVitestOutcomes(root, missing), /totals/);
});
test('nested Vitest identities use actual title ancestry instead of guessing from display separators', () => {
  const root = path.resolve('/tmp/original-tests'), data = vitest(root), test = data.testResults[0].assertionResults[0];
  test.ancestorTitles = ['outer > literal', 'nested']; test.title = 'inner > literal'; test.fullName = 'outer > literal nested inner > literal';
  assert.equal(originalVitestOutcomes(root, data)[0].name, 'outer > literal > nested > inner > literal');
  test.fullName += ' forged'; assert.throws(() => originalVitestOutcomes(root, data), /names disagree/);
});
test('Python expected failures, skipped tests, missing teardown and subtest errors cannot become passes', () => {
  assert.equal(originalPythonOutcomes(python()).length, 1);
  for (const kind of ['failure', 'error', 'skip', 'expected-failure', 'unexpected-success', 'subtest-error', 'subtest-failure']) {
    const changed = python(); changed.cases[0].events = [{ kind }]; assert.throws(() => originalPythonOutcomes(changed));
  }
  const missing = python(); missing.cases[0].completed = false; assert.throws(() => originalPythonOutcomes(missing));
  const extra = python(); extra.tests_run = 2; assert.throws(() => originalPythonOutcomes(extra));
});
test('stable Rust output must contain every listed case and no filtered, ignored or failed results', () => {
  const text = 'running 2 tests\ntest behavior::first ... ok\ntest behavior::second ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n';
  assert.deepEqual(originalRustOutcomes('packages/example/src/main.rs', text, 2).map(row => row.name), ['behavior::first', 'behavior::second']);
  for (const changed of [text.replace('0 ignored', '1 ignored'), text.replace('0 filtered', '1 filtered'), text.replace('second ... ok', 'second ... FAILED'), text.replace('test behavior::first ... ok\n', ''), text + text]) assert.throws(() => originalRustOutcomes('packages/example/src/main.rs', changed, 2));
  assert.equal(originalRustOutcomes('packages/example/src/main.rs', 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n', 0).length, 0);
});
test('independent discovery preserves duplicate display names and rejects omissions, extras and stale files', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-original-outcomes-'));
  try {
    writeFileSync(path.join(root, 'test.mjs'), 'original');
    const fingerprint = fileReceipt(root, 'test.mjs').sha256;
    const tests = [0, 1].map(occurrence => ({ runner: 'vitest', source: 'test.mjs', source_sha256: fingerprint, name: 'parameterized same display name', occurrence, id: `test-${occurrence}` }));
    const catalog = { kind: 'acceptance-discovery', tests }, observations = tests.map(({ source_sha256, occurrence, id, ...rest }) => ({ ...rest, status: 'passed' }));
    assert.deepEqual(reconcileOriginalOutcomes(root, catalog, observations).map(item => item.id), ['test-0', 'test-1']);
    assert.throws(() => reconcileOriginalOutcomes(root, catalog, observations.slice(1)), /missing/);
    assert.throws(() => reconcileOriginalOutcomes(root, catalog, [...observations, observations[0]]), /unexpected/);
    assert.throws(() => reconcileOriginalOutcomes(root, { ...catalog, tests: [tests[0], tests[0]] }, observations), /duplicate/);
    writeFileSync(path.join(root, 'test.mjs'), 'changed'); assert.throws(() => reconcileOriginalOutcomes(root, catalog, observations), /changed/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
