/** Public study CLI contract; no provider or native process is started. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { parseArguments, main } from '../../scripts/quality/run-local-model-evals.mjs';
import { createStudy } from '../../evals/local/study.mjs';
const bindings = Object.fromEntries(['evaluator', 'oracle', 'fixtures', 'product', 'models', 'clients', 'runtimes', 'interventions', 'analysis'].map(key => [key, 'a'.repeat(64)]));

test('iteration CLI requires an explicit session and keeps prepare/run/report options separate', () => {
  const session = path.resolve('.artifacts/local-evals/iterations/example');
  assert.deepEqual(parseArguments(['iterate-prepare', '--opt-in', '--session', session]), { command: 'iterate-prepare', options: { optIn: true, session } });
  assert.deepEqual(parseArguments(['iterate', '--opt-in', '--session', session]), { command: 'iterate', options: { optIn: true, round: 'baseline', session } });
  for (const round of ['baseline', 'transfer', 'claude-transfer']) assert.equal(parseArguments(['iterate', '--session', session, '--round', round]).options.round, round);
  const repair = parseArguments(['iterate', '--session', session, '--round', 'repair', '--evidence', './repair-evidence.json']);
  assert.equal(repair.options.evidence, path.resolve('repair-evidence.json'));
  assert.deepEqual(parseArguments(['iterate-report', '--session', session, '--output', './iteration-report']).options, { optIn: false, session, output: path.resolve('iteration-report') });
  for (const args of [
    ['iterate-prepare'], ['iterate'], ['iterate-report', '--session', session],
    ['iterate', '--session', session, '--round', 'repair'],
    ['iterate', '--session', session, '--evidence', './evidence.json'],
    ['iterate', '--session', session, '--round', 'transfer', '--evidence', './evidence.json'],
    ['iterate', '--session', session, '--round', 'unknown'],
    ['iterate', '--session', session, '--round'], ['iterate', '--session'],
    ['iterate', '--session', session, '--session', session],
    ['iterate', '--session', session, '--round', 'baseline', '--round', 'repair'],
    ['iterate-prepare', '--session', session, '--opt-in', '--opt-in'],
    ['iterate-prepare', '--session', session, '--round', 'baseline'],
    ['iterate-report', '--session', session, '--output', './report', '--opt-in'],
    ['iterate', '--session', session, '--output', './report'],
  ]) assert.throws(() => parseArguments(args), /requires|Incomplete|Unknown|only accepted/);
});

test('iteration commands reject campaign, study, full-window and qualification switches', () => {
  for (const command of ['iterate-prepare', 'iterate', 'iterate-report']) {
    const args = [command, '--session', '/private/iteration', ...(command === 'iterate-report' ? ['--output', '/private/report'] : [])];
    for (const extra of [
      ['--campaign', '/private/campaign'], ['--study', '/private/study'], ['--windows', '1'], ['--windows', '3'], ['--require-qualified'],
      ['--baseline', '/private/baseline'], ['--patches', '/private/patches'], ['--no-controls'], ['--repair-runtime'], ['--clients'],
      ['--admission-restart-from', '/private/prior'], ['--mechanical-rebaseline-from', '/private/prior'],
    ]) assert.throws(() => parseArguments([...args, ...extra]), /unsupported iteration option/);
  }
  for (const command of ['inventory', 'prepare', 'run', 'report', 'study-prepare', 'study-run', 'study-report']) assert.throws(() => parseArguments([command, '--session', '/private/iteration']), /Unknown/);
});

test('study CLI selects explicit prepare/run/report without accepting qualification campaign flags', () => {
  assert.equal(parseArguments(['study-prepare', '--opt-in']).options.optIn, true);
  assert.equal(parseArguments(['study-run', '--opt-in', '--study', '/private/study']).options.study, path.resolve('/private/study'));
  assert.equal(parseArguments(['study-report', '--study', '/private/study', '--output', '/private/report']).command, 'study-report');
  for (const args of [
    ['study-run'], ['study-report', '--study', '/private/study'], ['study-prepare', '--output', '/private/out'],
    ['study-run', '--study', '/private/study', '--windows', '3'], ['study-prepare', '--repair-runtime'], ['study-prepare', '--clients'],
    ['study-report', '--study', '/private/study', '--output', '/private/out', '--require-qualified'],
    ['study-run', '--study', '/private/study', '--study', '/private/other'], ['study-prepare', '--no-controls'],
    ['inventory', '--study', '/private/study'], ['run', '--study', '/private/study'],
  ]) assert.throws(() => parseArguments(args), /requires|only|Unknown/);
  assert.equal(parseArguments(['run', '--opt-in', '--windows', '3']).options.windows, 3);
  assert.equal(parseArguments(['report', '--campaign', '/private/campaign', '--output', '/private/report', '--require-qualified']).options.requireQualified, true);
});
test('study reporting retains every unattempted obligation without starting the clock or mutating the study', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-study-cli-'));
  try {
    const directory = path.join(root, '.artifacts/local-evals/studies/one'), output = path.join(root, 'report');
    createStudy({ root, directory, optIn: true, environment: {}, bindings });
    const before = readFileSync(path.join(directory, 'manifest.json'));
    const result = await main(['study-report', '--study', directory, '--output', output], root);
    const report = JSON.parse(readFileSync(result.report, 'utf8'));
    assert.equal(report.rows.length, 432); assert.equal(report.clock.started_at, null); assert.equal(report.qualification_evidence, false);
    assert.deepEqual(report.counts, { probe: { expected: 252, recorded: 0, unfinished: 252 }, native: { expected: 108, recorded: 0, unfinished: 108 }, forward: { expected: 72, recorded: 0, unfinished: 72 } });
    assert.deepEqual(readFileSync(path.join(directory, 'manifest.json')), before);
    await assert.rejects(main(['study-report', '--study', directory, '--output', output], root), /new output directory/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
for (const command of ['study-prepare', 'study-run']) {
  for (const { reason, options, environment, diagnostic } of [
    { reason: 'missing opt-in', options: [], environment: {}, diagnostic: 'opt-in' },
    { reason: 'CI', options: ['--opt-in'], environment: { CI: 'true' }, diagnostic: 'CI' },
  ]) {
    test(`${command} rejects ${reason} before touching inputs`, () => {
      const entry = path.resolve('scripts/quality/run-local-model-evals.mjs');
      const args = [entry, command, ...(command === 'study-run' ? ['--study', '/private/nonexistent-study'] : []), ...options];
      const result = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 5000, env: { PATH: process.env.PATH, ...environment } });
      assert.equal(result.status, 1); assert.ok(result.stderr.includes(diagnostic), result.stderr);
    });
  }
}
