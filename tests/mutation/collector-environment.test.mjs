import { test } from 'vitest';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { discoveryEnvironment, rustPreparationCommands } from '../../scripts/release/discover-acceptance.mjs';
import { secondaryVitestTests } from '../../scripts/quality/collect-mutation-tests.mjs';
import { reserveStorage } from '../../scripts/quality/storage-lifecycle.mjs';

test('collection forwards only its explicit Python selection to imported original fixtures', () => {
  const root = path.resolve('immutable-source-fixture'), selected = path.resolve('verified-python/bin/python3');
  const supplied = { PATH: '/verified/bin', UD_AGENT_PYTHON: '/ambient/python', UD_RELEASE_PYTHON: '/different/python', NODE_OPTIONS: '--import=/foreign.mjs', PYTEST_ADDOPTS: '-k omitted' };
  const environment = discoveryEnvironment(root, supplied, { python: selected });
  assert.equal(environment.UD_AGENT_PYTHON, selected);
  assert.equal(environment.UD_RELEASE_PYTHON, selected);
  assert.equal('NODE_OPTIONS' in environment, false);
  assert.equal('PYTEST_ADDOPTS' in environment, false);
  assert.equal('UD_AGENT_PYTHON' in discoveryEnvironment(root, supplied), false);
  for (const python of ['relative/python', '../outside', '', null]) assert.throws(() => discoveryEnvironment(root, {}, { python }), /absolute executable/);
});

test('supervised collection inherits only a live lease with private temporary files', () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-original-env-')));
  const lease = reserveStorage({ root, plannedBytes: 1024 });
  try {
    const temporary = path.join(lease.directory, 'tmp'); mkdirSync(temporary);
    const environment = discoveryEnvironment(root, { ...lease.env, TMPDIR: temporary });
    assert.equal(environment.UD_STORAGE_LEASE, lease.env.UD_STORAGE_LEASE);
    assert.equal(environment.PYTHONDONTWRITEBYTECODE, '1');
    assert.throws(() => discoveryEnvironment(root, { ...lease.env, TMPDIR: root }), /private storage reservation/);
  } finally { lease.cleanup(); rmSync(root, { recursive: true, force: true }); }
});

test('original CLI preparation builds all normal launcher binaries without running test bodies', () => {
  assert.deepEqual(rustPreparationCommands(), [['build', '--locked', '--bins', '-p', 'ud-agent-launcher', '--message-format=json']]);
});

test('secondary collection preserves every Vitest occurrence and its existing backend identity', () => {
  const tests = [0, 1].map(occurrence => ({ id: 'vitest:tests/a.test.mjs#' + String(occurrence).repeat(24), source: 'tests/a.test.mjs', source_sha256: 'a'.repeat(64), name: 'same name', occurrence, runner: 'vitest' }));
  const result = secondaryVitestTests({ qualification: 'inventory-only-no-outcomes', tests: [...tests, { runner: 'rust' }] });
  assert.deepEqual(result.map(row => row.id), ['tests/a.test.mjs#' + '0'.repeat(24), 'tests/a.test.mjs#' + '1'.repeat(24)]);
  assert.deepEqual(result.map(row => row.occurrence), [0, 1]);
  assert.throws(() => secondaryVitestTests({ qualification: 'supplied-outcomes', tests }), /inventory-only/);
  assert.throws(() => secondaryVitestTests({ qualification: 'inventory-only-no-outcomes', tests: [{ ...tests[0], id: 'foreign' }] }), /identity differs/);
});
