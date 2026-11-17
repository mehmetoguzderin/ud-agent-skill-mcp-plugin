import { test } from 'vitest';
import assert from 'node:assert/strict';
import { validateAcceptanceInventory, reconcileSuiteInventory } from '../../scripts/release/acceptance.mjs';

test('requires complete frozen suites and reconciles every test and mutation identity', () => {
  const source = 'a'.repeat(64), definition = 'b'.repeat(64);
  const suite = { id: 'mutation-python', tests: [{ id: 'test-a', source: 'tests/a.py' }], mutants: [{ id: 'm1', file: 'workers/a.py', source_sha256: source, definition_sha256: definition }, { id: 'm2', file: 'workers/a.py', source_sha256: source, definition_sha256: definition }] };
  const inventory = { schema_version: 1, state: 'frozen', suites: [suite] };
  const report = { suite_id: suite.id, tests: [{ ...suite.tests[0], status: 'passed' }], mutants: suite.mutants.map(item => ({ ...item, status: 'killed' })) };
  assert.equal(validateAcceptanceInventory(inventory, [suite.id]).size, 1);
  assert.doesNotThrow(() => reconcileSuiteInventory(suite, report));
  assert.throws(() => validateAcceptanceInventory({ ...inventory, state: 'incomplete' }, [suite.id]), /frozen/);
  assert.throws(() => validateAcceptanceInventory(inventory, [suite.id, 'unit']), /requirements/);
  assert.throws(() => reconcileSuiteInventory(suite, { ...report, mutants: report.mutants.slice(0, 1) }), /incomplete/);
  assert.throws(() => reconcileSuiteInventory(suite, { ...report, mutants: [report.mutants[0], report.mutants[0]] }), /unexpected mutation/);
  assert.throws(() => reconcileSuiteInventory(suite, { ...report, mutants: [{ ...report.mutants[0], definition_sha256: source }, report.mutants[1]] }), /unexpected mutation/);
  assert.throws(() => reconcileSuiteInventory(suite, { ...report, tests: [{ ...report.tests[0], source: 'tests/other.py' }] }), /unexpected test/);
  const policy = { ...suite, id: 'mutation-policies', mutants: [{ ...suite.mutants[0], file: '.github/workflows/ci.yml' }] };
  assert.equal(validateAcceptanceInventory({ schema_version: 1, state: 'frozen', suites: [policy] }, [policy.id]).size, 1);
  assert.throws(() => validateAcceptanceInventory({ schema_version: 1, state: 'frozen', suites: [{ ...policy, mutants: [{ ...policy.mutants[0], definition_sha256: '' }] }] }, [policy.id]), /invalid mutation inventory/);
});

test('native acceptance requires matching non-emulated host evidence', () => {
  const suite = { id: 'install-macos-arm64', native_platform: 'macos-arm64', tests: [{ id: 'install', source: 'tests/install.mjs' }] };
  validateAcceptanceInventory({ schema_version: 1, state: 'frozen', suites: [suite] }, [suite.id]);
  const report = { suite_id: suite.id, tests: [{ ...suite.tests[0], status: 'passed' }], environment: { native_platform: 'macos-arm64', emulated: false } };
  assert.doesNotThrow(() => reconcileSuiteInventory(suite, report));
  assert.throws(() => reconcileSuiteInventory(suite, { ...report, environment: { native_platform: 'linux-arm64', emulated: false } }), /native platform/);
  assert.throws(() => reconcileSuiteInventory(suite, { ...report, environment: { native_platform: 'macos-arm64', emulated: true } }), /native platform/);
});
