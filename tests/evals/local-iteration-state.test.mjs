// SPDX-License-Identifier: MIT
/** Inert file receipts only: these tests provide no model or workflow evidence. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { buildIterationRows, createIterationSession, openIterationSession, ITERATION_POLICY } from '../../evals/local/iteration-state.mjs';

const identities = Object.fromEntries(['evaluator', 'oracle', 'tasks', 'model_configuration'].map(key => [key, 'a'.repeat(64)]));
function fixture() {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-iteration-state-'))), directory = path.join(root, '.artifacts/local-evals/iterations/inert');
  let clock = 1_000_000, serial = 0;
  createIterationSession({ root, directory, identities, optIn: true, environment: {}, now: clock });
  const f = { root, directory, get clock() { return clock; }, set clock(value) { clock = value; },
    open: extra => openIterationSession({ root, directory, identities, optIn: true, environment: {}, now: () => clock, ...extra }),
    file(value) { const file = path.join(directory, `inert-${serial++}.json`), bytes = JSON.stringify(value); writeFileSync(file, bytes, { mode: 0o400 }); return { path: file, sha256: sha256(bytes) }; },
    cleanup: () => rmSync(root, { recursive: true, force: true }) };
  return f;
}
const product = byte => ({ sha256: byte.repeat(64) });
const installation = byte => ({ sha256: byte.repeat(64), root: '/inert/installation' });
function baseline(store) { return store.freezeRound({ kind: 'baseline', product: product('b'), installation: installation('c') }); }
function start(f, store, modelId = 'lfm3') {
  store.beginAdmission({ modelId, optIn: true }); store.recordAdmission(modelId, f.file({ status: 'admitted', admission_kind: 'mechanical', model: { id: modelId }, fixture_only: true }));
}
function release(f, store, modelId = 'lfm3') { store.releaseModel(modelId, { ...f.file({ cleanupVerified: true, fixture_only: true }), owned_cleanup_verified: true }); }
function episode(row, round, extra = {}) {
  return { ...row, outcome: 'passed', reason: 'Inert state-contract fixture, not execution evidence.', owned_cleanup_verified: true,
    candidate_installation_sha256: round.installation.sha256, final_answer: 'Inert final response', verification: { status: 'passed' },
    observations: { real_inference: true, native_loop: true, model_attribution: true, independent_verification: true, budget_enforced: true,
      final_answer_verified: true, no_user_hints: true, skill_activation: false },
    metrics: { counters: { inference: 1, tools: row.scenario_id === 'S7' ? 0 : 1, ud_operations: row.scenario_id === 'S7' ? 0 : 1, input: 100, output: 20 }, total_elapsed_ms: 300 }, fixture_only: true, ...extra };
}
function record(f, store, round, row, extra) { store.claimEpisode(round.id, row.id); const ref = f.file(episode(row, round, extra)); store.recordEpisode(round.id, row.id, ref); return ref; }
function finish(f, store, round, { firstFailure = false } = {}) {
  for (const [index, row] of round.rows.entries()) {
    if (store.state.active_model !== row.model_id) { if (store.state.active_model) release(f, store, store.state.active_model); start(f, store, row.model_id); }
    record(f, store, round, row, firstFailure && index === 0 ? { outcome: 'failed', reason: 'Inert discovery failure', stages: { exposure: true, discovery: false }, observations: { skill_activation: false } } : {});
  }
  store.finishRound(round.id);
}
function repair(f, store, previous, byte) { return store.freezeRound({ kind: 'repair', product: product(byte), installation: installation(byte), parentRound: previous.id,
  repairEvidence: { reason: 'Inert shared discovery defect reproduction', evidence: [f.file({ fixture_only: true, parent: previous.id })] } }); }
function decide(f, store, round, retained = true) {
  if (store.state.active_model) release(f, store, store.state.active_model);
  return store.decideRound(round.id, { retained, reason: 'Inert reviewed paired evidence', evidence: [f.file({ fixture_only: true, round: round.id })] });
}

test('iteration schedule crosses both harnesses, all seeds and exact69 maximum obligations', () => {
  const all = [buildIterationRows(), buildIterationRows({ kind: 'repair', roundId: 'repair-1' }), buildIterationRows({ kind: 'repair', roundId: 'repair-2' }), buildIterationRows({ kind: 'transfer' }), buildIterationRows({ kind: 'claude-transfer' })];
  assert.deepEqual(all.map(rows => rows.length), [12, 12, 12, 30, 3]);
  assert.equal(new Set(all.flat().map(row => row.id)).size, 69);
  assert.deepEqual([...new Set(all[0].map(row => row.seed))], [17, 23, 47]);
  for (const harness of ['qwen-code', 'mini-swe-agent']) for (const scenario of ['S3', 'S7']) assert.equal(all[0].filter(row => row.harness_id === harness && row.scenario_id === scenario).length, 3);
  assert.deepEqual([...new Set(all[3].map(row => row.model_id))], ['lfm3', 'minicpm', 'bonsai']);
  assert.equal(all[3].filter(row => row.model_id === 'lfm3' && row.scenario_id === 'S2').length, 6);
  assert.equal(ITERATION_POLICY.maximum_scored_episodes, all.flat().length);
  assert.equal(ITERATION_POLICY.maximum_total_inference_requests, 69 * 10 + 12);
});

test('preparation and freeze do not start the clock; opt-in, CI and immutable identities are enforced', () => {
  const f = fixture();
  try {
    const store = f.open(); baseline(store); assert.equal(store.clock_started, false); assert.equal(store.report().deadline, null);
    assert.equal(store.report().harness_inventory.length, 18); assert.equal(store.report().model_inventory.length, 3);
    assert.throws(() => f.open({ identities: { ...identities, oracle: 'd'.repeat(64) } }), /identity changed/);
    assert.throws(() => f.open({ optIn: false }).beginAdmission({ modelId: 'lfm3' }), /opt-in/);
    assert.throws(() => f.open({ environment: { CI: 'true' } }).beginAdmission({ modelId: 'lfm3', optIn: true }), /CI/);
    assert.throws(() => createIterationSession({ root: f.root, directory: f.directory, identities, optIn: true, environment: {} }), /already exists/);
    const file = path.join(f.directory, 'manifest.json'); chmodSync(file, 0o600); writeFileSync(file, readFileSync(file, 'utf8').replace('1800000', '1800001') + ' ');
    assert.throws(() => f.open(), /manifest bytes changed/);
  } finally { f.cleanup(); }
});

test('resume retains fixed180min deadline, claims and counters; no repeated seed or refund', () => {
  const f = fixture();
  try {
    let store = f.open(), round = baseline(store); f.clock += 5000; start(f, store);
    const deadline = f.clock + 180 * 60_000; assert.equal(store.state.deadline, deadline); assert.equal(store.state.execution_deadline, deadline - 15 * 60_000);
    const row = round.rows[0]; store.claimEpisode(round.id, row.id);
    store = f.open(); assert.equal(store.state.reserved.episodes, 1); assert.equal(store.state.reserved.inference, 10); assert.equal(store.state.reserved.output, 2048);
    assert.throws(() => store.claimEpisode(round.id, row.id), /cannot be repeated/);
    assert.throws(() => release(f, store), /active work/);
    store.recordEpisode(round.id, row.id, f.file(episode(row, round)));
    assert.throws(() => store.claimEpisode(round.id, row.id), /cannot be repeated/);
    release(f, store); f.clock += 1000; start(f, store); assert.equal(store.state.deadline, deadline);
    f.clock = deadline - 15 * 60_000 - 94_999;
    assert.throws(() => store.claimEpisode(round.id, round.rows[1].id), /execution deadline/);
    assert.equal(store.state.reserved.episodes, 1); assert.equal(store.state.reserved.inference, 10);
  } finally { f.cleanup(); }
});

test('positive completion does not require skill activation; S7 activation remains a regression', () => {
  const f = fixture();
  try {
    const store = f.open(), round = baseline(store); start(f, store);
    record(f, store, round, round.rows[0]);
    record(f, store, round, round.rows[1], { observations: { ...episode(round.rows[1], round).observations, skill_activation: true } });
    const report = store.report(), [positive, negative] = report.rounds[0].rows;
    assert.equal(positive.outcome, 'passed'); assert.equal(positive.stages.activation, false); assert.equal(positive.first_failure.stage, null);
    assert.equal(negative.outcome, 'incomplete'); assert.equal(negative.negative_activation_cost, true);
    assert.equal(report.qualification_evidence, false); assert.equal(report.full_starter_qualification, false);
    assert.equal(report.actual_counters.inference, 2);
  } finally { f.cleanup(); }
});

test('unknown counters and missing pass observations stay unknown; modified episode receipts cannot pass', () => {
  const f = fixture();
  try {
    const store = f.open(), round = baseline(store); start(f, store);
    record(f, store, round, round.rows[0], { metrics: { counters: { inference: 1, tools: 0, ud_operations: 0, input: 100, output: null } } });
    const ref = record(f, store, round, round.rows[1]);
    assert.equal(store.report().rounds[0].rows[0].outcome, 'incomplete'); assert.equal(store.report().actual_counters.output, null);
    chmodSync(ref.path, 0o600); writeFileSync(ref.path, '{}');
    const report = store.report(); assert.equal(report.evidence_verification.status, 'invalid'); assert.equal(report.rounds[0].rows[1].outcome, 'incomplete');
    assert.equal(report.actual_counters.inference, null);
  } finally { f.cleanup(); }
});

test('repair eligibility uses completed failures; paired first failure preserves unknown earlier stages', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store); start(f, store);
    assert.throws(() => repair(f, store, initial, 'd'), /preceding round/);
    finish(f, store, initial, { firstFailure: true });
    assert.throws(() => store.freezeRound({ kind: 'transfer', product: initial.product, installation: initial.installation, parentRound: initial.id }), /milestones/);
    const next = repair(f, store, initial, 'd');
    for (const row of next.rows) record(f, store, next, row);
    store.finishRound(next.id);
    const pair = store.report().paired[0].rows[0]; assert.equal(pair.complete, true); assert.equal(pair.before, 'failed'); assert.equal(pair.after, 'passed');
    assert.equal(pair.first_failure_before.stage, 'discovery'); assert.deepEqual(pair.first_failure_before.earlier_unknown_stages, []);
    assert.equal(pair.stages.discovery.before, false); assert.equal(pair.stages.discovery.after, null); assert.equal(pair.stages.discovery.difference, null);
    decide(f, store, next);
    const transfer = store.freezeRound({ kind: 'transfer', product: next.product, installation: next.installation, parentRound: next.id }); assert.equal(transfer.rows.length, 30);
    assert.equal(store.report().paired[0].independent_seed_samples, false);
  } finally { f.cleanup(); }
});

test('exact two repairs and69 rows are ceilings; no unnecessary repairs or unbound transfer product', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store); start(f, store); finish(f, store, initial, { firstFailure: true });
    const one = repair(f, store, initial, 'd'); finish(f, store, one, { firstFailure: true }); decide(f, store, one, false);
    const two = repair(f, store, initial, 'e'); finish(f, store, two); decide(f, store, two);
    assert.throws(() => repair(f, store, two, 'f'), /At most two/);
    assert.throws(() => store.freezeRound({ kind: 'transfer', product: product('a'), installation: two.installation, parentRound: two.id }), /latest frozen product/);
    const transfer = store.freezeRound({ kind: 'transfer', product: two.product, installation: two.installation, parentRound: two.id }); finish(f, store, transfer);
    const claude = store.freezeRound({ kind: 'claude-transfer', product: two.product, installation: two.installation, parentRound: two.id }); finish(f, store, claude);
    assert.equal(store.state.reserved.episodes, 69); assert.equal(store.state.reserved.inference, 690); assert.equal(store.report().counts.scheduled, 69);
    assert.throws(() => store.freezeRound({ kind: 'claude-transfer', product: two.product, installation: two.installation, parentRound: two.id }), /cannot be repeated/);
    release(f, store); store.close('Inert fully completed state contract'); assert.equal(store.report().status, 'completed_with_failures_or_blockers');
    assert.throws(() => store.beginAdmission({ modelId: 'lfm3' }), /closed/);
  } finally { f.cleanup(); }
  const g = fixture();
  try { const store = g.open(), initial = baseline(store); start(g, store); finish(g, store, initial); assert.throws(() => repair(g, store, initial, 'd'), /needs no repair/); }
  finally { g.cleanup(); }
}, process.platform === 'win32' ? 0 : 30_000);

test('rejected repair remains immutable and repair2 compares against the last retained baseline', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store); start(f, store); finish(f, store, initial, { firstFailure: true });
    const one = repair(f, store, initial, 'd'); finish(f, store, one, { firstFailure: true });
    assert.throws(() => repair(f, store, one, 'e'), /retention decision/);
    release(f, store);
    const evidence = [f.file({ fixture_only: true, unchanged_results: true })];
    assert.throws(() => store.decideRound(one.id, { retained: true, reason: 'No observed benefit', evidence }), /completion gain or action-stage advance/);
    store.decideRound(one.id, { retained: false, reason: 'No measured improvement; rolled back outside state', evidence });
    assert.throws(() => store.decideRound(one.id, { retained: true, reason: 'Cannot rewrite decision', evidence }), /immutable/);
    assert.throws(() => repair(f, store, one, 'e'), /last retained/);
    const two = repair(f, store, initial, 'e'); finish(f, store, two); decide(f, store, two);
    const report = store.report();
    assert.equal(report.retained_product_round, two.id); assert.equal(report.decisions[one.id].retained, false);
    assert.equal(report.paired[1].before_round, initial.id); assert.equal(report.paired[1].after_round, two.id);
    assert.equal(report.rounds.find(value => value.id === one.id).rows[0].outcome, 'failed');
    assert.equal(f.open().report().retained_product_round, two.id);
  } finally { f.cleanup(); }
}, process.platform === 'win32' ? 0 : 30_000);

test('retention rejects completion and negative-selection regressions despite another improved row', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store); start(f, store); finish(f, store, initial, { firstFailure: true });
    const next = repair(f, store, initial, 'd');
    for (const row of next.rows) record(f, store, next, row, row.scenario_id === 'S7' ? { observations: { ...episode(row, next).observations, skill_activation: true } } : {});
    store.finishRound(next.id); release(f, store);
    const evidence = [f.file({ fixture_only: true })];
    assert.throws(() => store.decideRound(next.id, { retained: true, reason: 'Comparison gain with writing regressions', evidence }), /no completion or negative-selection regressions/);
    store.decideRound(next.id, { retained: false, reason: 'Preserved S7 regressions', evidence });
    assert.equal(store.report().decisions[next.id].metrics.completion_gains.length, 1);
    assert.equal(store.report().decisions[next.id].metrics.regressions.length, 12);
    assert.equal(store.report().retained_product_round, initial.id);
  } finally { f.cleanup(); }
});

test('two paired action-stage advances can retain a repair while final completions still fail', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store); start(f, store);
    for (const row of initial.rows) record(f, store, initial, row, row.scenario_id === 'S3' ? { outcome: 'failed', reason: 'Inert unresolved comparison', stages: { discovery: false } } : {});
    store.finishRound(initial.id); const next = repair(f, store, initial, 'd');
    for (const row of next.rows) record(f, store, next, row, row.scenario_id === 'S3' ? { outcome: 'failed', reason: 'Inert interpretation still unresolved', stages: { discovery: row.seed !== 47 } } : {});
    store.finishRound(next.id); decide(f, store, next);
    const decision = store.report().decisions[next.id];
    assert.equal(decision.retained, true); assert.equal(decision.metrics.completion_gains.length, 0); assert.equal(decision.metrics.action_stage_advance_in_two_seeds, true);
    assert.throws(() => store.freezeRound({ kind: 'transfer', product: next.product, installation: next.installation, parentRound: next.id }), /milestones/);
    chmodSync(decision.evidence[0].path, 0o600); writeFileSync(decision.evidence[0].path, '{}');
    assert.equal(store.report().retained_product_round, null); assert.equal(store.report().evidence_verification.status, 'invalid');
    assert.throws(() => repair(f, store, next, 'e'), /evidence bytes changed/);
  } finally { f.cleanup(); }
});

test('unknown cleanup blocks continuation; append-only proof permits safety continuation without upgrading grade', () => {
  const f = fixture();
  try {
    const store = f.open(), round = baseline(store); start(f, store); const row = round.rows[0];
    const ref = record(f, store, round, row, { outcome: 'failed', reason: 'Inert cancellation with missing release', owned_cleanup_verified: false });
    assert.throws(() => store.claimEpisode(round.id, round.rows[1].id), /active round/);
    assert.throws(() => release(f, store), /cleanup/);
    const forged = f.file({ owned_cleanup_verified: true, row_id: row.id, episode_sha256: 'f'.repeat(64) });
    assert.throws(() => store.reconcileEpisodeCleanup(row.id, { ...forged, row_id: row.id, owned_cleanup_verified: true }), /actual failed episode/);
    const proof = f.file({ owned_cleanup_verified: true, row_id: row.id, episode_sha256: ref.sha256, fixture_only: true });
    store.reconcileEpisodeCleanup(row.id, { ...proof, row_id: row.id, owned_cleanup_verified: true });
    record(f, store, round, round.rows[1]); const saved = store.report().rounds[0].rows[0];
    assert.equal(saved.outcome, 'failed'); assert.equal(saved.owned_cleanup_verified, false); assert.equal(saved.cleanup_reconciliation.sha256, proof.sha256);
  } finally { f.cleanup(); }
});

test('calibration cannot replenish on reload/resume; locks and backward clocks fail closed', () => {
  const f = fixture();
  try {
    let store = f.open(); baseline(store); start(f, store);
    for (let count = 0; count < 4; count++) store.chargeCalibration('lfm3', `lfm3-${count}`);
    release(f, store); store = f.open(); start(f, store);
    assert.throws(() => store.chargeCalibration('lfm3', 'lfm3-new'), /allowance exhausted/);
    assert.throws(() => store.chargeCalibration('lfm3', 'lfm3-0'), /unique/);
    release(f, store);
    for (const model of ['minicpm', 'bonsai']) { start(f, store, model); for (let count = 0; count < 4; count++) store.chargeCalibration(model, `${model}-${count}`); release(f, store, model); }
    assert.equal(f.open().state.calibration.used, 12);
    f.clock--; assert.throws(() => store.beginAdmission({ modelId: 'lfm3' }), /clock moved backwards/); f.clock++;
    mkdirSync(path.join(f.directory, '.lock')); assert.throws(() => store.beginAdmission({ modelId: 'lfm3' }), /locked/); rmSync(path.join(f.directory, '.lock'), { recursive: true });
    const file = path.join(f.directory, 'journal', '000000.json'); chmodSync(file, 0o600); writeFileSync(file, readFileSync(file, 'utf8').replace('round_frozen', 'round_forged'));
    assert.throws(() => f.open().snapshot(), /journal chain changed/);
  } finally { f.cleanup(); }
});
