import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { assertOptIn, privateEnvironment } from '../../evals/local/preparation.mjs';
import { forecast, deriveSeed, campaignPolicy, validateMechanicalRebaseline, assertReplayBaseline, frozenHashes } from '../../evals/local/campaign.mjs';
import { buildMatrix } from '../../evals/local/registry.mjs';
import { buildReport } from '../../evals/local/report.mjs';
import { parseArguments } from '../../scripts/quality/run-local-model-evals.mjs';

test('frozen evaluator binds shared execution and oracle helpers independently of product skills', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-frozen-helper-'));
  try {
    for (const name of ['scripts/quality', 'scripts/release', 'skills/example']) mkdirSync(path.join(root, name), { recursive: true });
    const put = (name, text) => writeFileSync(path.join(root, name), text);
    put('scripts/quality/storage-lifecycle.mjs', 'storage-v1');
    put('scripts/quality/workflow-grader.mjs', 'oracle-v1');
    put('scripts/release/candidate.mjs', 'receipts-v1');
    put('skills/example/SKILL.md', 'product-v1');
    const initial = frozenHashes(root, {});
    put('skills/example/SKILL.md', 'product-v2');
    assert.deepEqual(frozenHashes(root, {}), initial);
    put('scripts/quality/storage-lifecycle.mjs', 'storage-v2');
    const storage = frozenHashes(root, {});
    assert.notEqual(storage.evaluator, initial.evaluator); assert.equal(storage.oracle, initial.oracle);
    put('scripts/quality/workflow-grader.mjs', 'oracle-v2');
    const oracle = frozenHashes(root, {});
    assert.notEqual(oracle.evaluator, storage.evaluator); assert.notEqual(oracle.oracle, storage.oracle);
    put('scripts/release/candidate.mjs', 'receipts-v2');
    assert.notEqual(frozenHashes(root, {}).evaluator, oracle.evaluator);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('live acquisition and inference require explicit opt-in and reject CI', () => {
  assert.throws(() => assertOptIn({}, {}), /opt-in/);
  for (const key of ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILD_BUILDID', 'JENKINS_URL']) assert.throws(() => assertOptIn({ optIn: true }, { [key]: 'true' }), /CI/);
  assert.doesNotThrow(() => assertOptIn({ optIn: true }, {}));
  assert.equal(parseArguments(['inventory']).options.optIn, false);
  assert.throws(() => parseArguments(['run', '--opt-in', '--opt-in']), /duplicate/);
  assert.throws(() => parseArguments(['report']), /requires/);
});
test('forecast admits whole control block and never assumes ceiling throughput fits paired replay', () => {
  const slow = forecast({ rows: buildMatrix(), episodeSeconds: 90, controls: true });
  assert.equal(slow.mode, 'diagnostic'); assert.equal(slow.controls_admitted, false);
  const quick = forecast({ rows: buildMatrix(), episodeSeconds: 10, startupSeconds: 5, accountingSeconds: 0, controls: true });
  assert.equal(quick.mode, 'paired'); assert.equal(quick.controls_admitted, true);
  assert.equal(quick.baselineSeconds - quick.replaySeconds, 18 * 21);
});
test('request seeds are repeatable across models and remain within supported integer range', () => {
  assert.equal(deriveSeed(17, 1), deriveSeed(17, 1));
  assert.notEqual(deriveSeed(17, 1), deriveSeed(23, 1));
  assert.notEqual(deriveSeed(17, 1), deriveSeed(17, 2));
  assert.throws(() => deriveSeed(42, 0));
});
test('normal replay accepts fully attempted unresolved grades without treating them as success', () => {
  const manifest = { snapshot: 'baseline', mode: 'paired', rows: buildMatrix() };
  const episodes = manifest.rows.map(row => ({ row_id: row.id, outcome: 'incomplete' }));
  const report = buildReport(manifest, episodes);
  assert.equal(report.status, 'incomplete');
  assert.equal(report.execution_complete, true); assert.equal(report.grading_complete, false);
  assert.equal(report.gates.complete_starter_campaign.status, 'unmet');
  assert.doesNotThrow(() => assertReplayBaseline(manifest, report));
  assert.throws(() => assertReplayBaseline(manifest, buildReport(manifest, episodes.slice(1))), /fully executed/);
  assert.throws(() => assertReplayBaseline(manifest, buildReport(manifest, episodes.map((row, index) => index ? row : { ...row, outcome: 'not_run' }))), /fully executed/);
  assert.throws(() => assertReplayBaseline({ ...manifest, mode: 'diagnostic' }, report), /paired/);
  assert.throws(() => assertReplayBaseline(manifest, { ...report, status: 'passed' }), /nonpassing/);
  assert.throws(() => assertReplayBaseline(manifest, buildReport({ ...manifest, rows: [manifest.rows[0]] }, [episodes[0]])), /fully executed/);
});
test('three windows share one twelve-hour policy and can fit the complete paired inventory', () => {
  const policy = campaignPolicy(3);
  assert.equal(policy.duration_ms, 12 * 60 * 60_000);
  assert.equal(Object.values(policy.phases).reduce((sum, value) => sum + value, 0), policy.duration_ms);
  const full = forecast({ rows: buildMatrix(), episodeSeconds: 90, startupSeconds: 5, accountingSeconds: 0, controls: true, windows: 3 });
  assert.equal(full.mode, 'paired'); assert.equal(full.controls_admitted, false);
  assert.equal(full.baselineSeconds, full.replaySeconds);
  assert.equal(parseArguments(['run', '--opt-in', '--windows', '3']).options.windows, 3);
  assert.equal(parseArguments(['report', '--campaign', '/private/campaign', '--output', '/private/report', '--require-qualified']).options.requireQualified, true);
  for (const args of [['run', '--windows', '2'], ['run', '--windows', '3', '--windows', '1'], ['inventory', '--windows', '3'], ['run', '--require-qualified']]) assert.throws(() => parseArguments(args));
  assert.throws(() => campaignPolicy(4));
});
test('conservative forecast accounts for setup, full storage/source checks and every blocked row', () => {
  const timing = forecast({ rows: buildMatrix().slice(0, 36), blockedRows: 135, episodeSeconds: 90, windows: 3 });
  assert.equal(timing.baselineSeconds, 36 * 176 + 135 * 22 + 90);
  assert.equal(timing.replaySeconds, timing.baselineSeconds); assert.equal(timing.mode, 'paired');
  assert.equal(timing.blocked_row_reconciliation_seconds, 135 * 22);
  assert.equal(forecast({ rows: buildMatrix(), episodeSeconds: 90, windows: 3 }).mode, 'diagnostic');
});
test('private runtime environment excludes ambient credentials and puts caches in repo', () => {
  const repository = path.resolve('/repository'), env = privateEnvironment(repository, path.resolve('/private/profile'));
  assert.equal(env.OPENAI_API_KEY, undefined); assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(env.UV_CACHE_DIR, path.join(repository, '.artifacts/local-evals/uv-cache'));
});
test('mechanical rebaseline retains spent rows and permits neither product nor oracle changes', () => {
  const hashes = { evaluator: 'corrected', oracle: 'oracle', tasks: 'tasks', model_configuration: 'models' };
  const preparation = { models: ['exact'] }, files = [{ path: 'src/mcp.ts', sha256: 'product' }, { path: 'evals/local/budget.mjs', sha256: 'old' }];
  const prior = { snapshot: 'baseline', deadline: 100, rows: buildMatrix(), preparation, hashes: { ...hashes, evaluator: 'old' }, product: { files } };
  const input = { prior, product: { files: [files[0], { ...files[1], sha256: 'fixed' }] }, hashes, preparation, episodes: Array.from({ length: 8 }, () => ({})), now: 1 };
  const result = validateMechanicalRebaseline(input);
  assert.equal(result.previous_scored_episodes, 8); assert.equal(result.remaining_after_complete_pair, 10);
  assert.equal(result.calibration_allowance_replenished, false); assert.equal(result.deadline_replenished, false);
  assert.throws(() => validateMechanicalRebaseline({ ...input, episodes: Array(19).fill({}) }), /360/);
  assert.throws(() => validateMechanicalRebaseline({ ...input, prior: { ...prior, mechanical_rebaseline: {} } }), /Only one/);
  assert.throws(() => validateMechanicalRebaseline({ ...input, now: 100 }), /deadline/);
  assert.throws(() => validateMechanicalRebaseline({ ...input, hashes: { ...hashes, oracle: 'changed' } }), /oracle/);
  assert.throws(() => validateMechanicalRebaseline({ ...input, product: { files: [{ ...files[0], sha256: 'changed' }, input.product.files[1]] } }), /UD product/);
  assert.throws(() => validateMechanicalRebaseline({ ...input, prior: { ...prior, rows: buildMatrix({ controls: true }) } }), /assignment/);
  assert.ok(parseArguments(['run', '--opt-in', '--no-controls', '--mechanical-rebaseline-from', '/private/prior']).options['mechanical-rebaseline-from']);
  assert.throws(() => parseArguments(['inventory', '--mechanical-rebaseline-from', '/private/prior']), /only accepted by run/);
});
