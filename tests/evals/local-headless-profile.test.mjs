// SPDX-License-Identifier: MIT
/** Inert scheduling/evidence fixtures only; these are not model execution evidence. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { HARNESSES, buildMatrix } from '../../evals/local/registry.mjs';
import { PROFILE, HEADLESS_POLICY, buildHeadlessRows, buildHeadlessCoverage, headlessReferenceRows, headlessQualification } from '../../evals/local/headless-profile.mjs';
import { buildIterationRows, createIterationSession, openIterationSession, policyForProfile, ITERATION_POLICY } from '../../evals/local/iteration-state.mjs';

const bindings = Object.fromEntries(['evaluator', 'oracle', 'tasks', 'model_configuration'].map(key => [key, 'a'.repeat(64)]));
const identity = byte => ({ sha256: byte.repeat(64) });
function fixture() {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-headless-state-'))), directory = path.join(root, '.artifacts/local-evals/iterations/inert');
  let clock = 1_000_000, serial = 0;
  createIterationSession({ root, directory, identities: bindings, profile: PROFILE, optIn: true, environment: {}, now: clock });
  const open = () => openIterationSession({ root, directory, identities: bindings, optIn: true, environment: {}, now: () => clock });
  const file = value => { const filename = path.join(directory, `inert-${serial++}.json`), bytes = JSON.stringify(value); writeFileSync(filename, bytes, { mode: 0o400 }); return { path: filename, sha256: sha256(bytes) }; };
  return { root, directory, open, file, get clock() { return clock; }, set clock(value) { clock = value; }, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
function release(f, store) {
  if (store.state.active_model) store.releaseModel(store.state.active_model, { ...f.file({ cleanupVerified: true, fixture_only: true }), owned_cleanup_verified: true });
}
function select(f, store, modelId) {
  if (store.state.active_model === modelId) return;
  release(f, store); store.beginAdmission({ modelId }); store.recordAdmission(modelId, f.file({ status: 'admitted', model: { id: modelId }, fixture_only: true }));
}
function episode(row, round, extra = {}) {
  return { ...row, outcome: 'passed', owned_cleanup_verified: true, candidate_installation_sha256: round.installation.sha256,
    final_answer: 'Inert answer, not native evidence.', verification: { status: 'passed' }, fixture_only: true,
    observations: { real_inference: true, native_loop: true, model_attribution: true, independent_verification: true,
      budget_enforced: true, final_answer_verified: true, no_user_hints: true, skill_activation: false },
    metrics: { counters: { inference: 1, tools: row.scenario_id === 'S7' ? 0 : 1, ud_operations: row.scenario_id === 'S7' ? 0 : 1, input: 100, output: 20 }, total_elapsed_ms: 300 }, ...extra };
}
function record(f, store, round, row, extra = {}) {
  select(f, store, row.model_id); store.claimEpisode(round.id, row.id);
  const ref = f.file(episode(row, round, extra)); store.recordEpisode(round.id, row.id, ref); return ref;
}
function finish(f, store, round, overrides = () => ({})) {
  const refs = new Map();
  for (const row of round.rows) refs.set(row.cell_id, record(f, store, round, row, overrides(row)));
  store.finishRound(round.id); release(f, store); return refs;
}
function baseline(store) { return store.freezeRound({ kind: 'baseline', product: identity('b'), installation: identity('c') }); }
function repair(f, store, parent) { return store.freezeRound({ kind: 'repair', parentRound: parent.id, product: identity('d'), installation: identity('e'),
  repairEvidence: { reason: 'Inert shared defect reproduction.', evidence: [f.file({ fixture_only: true })] } }); }
function transfer(store, parent) { return store.freezeRound({ kind: 'transfer', parentRound: parent.id, product: parent.product, installation: parent.installation }); }

test('headless schedule has symmetric paired core, balanced controls, and exact assigned breadth', () => {
  const baseline = buildHeadlessRows(), candidate = buildHeadlessRows({ kind: 'repair' }), breadth = buildHeadlessRows({ kind: 'transfer' }), coverage = buildHeadlessCoverage();
  assert.deepEqual([baseline.length, candidate.length, breadth.length, coverage.length], [72, 63, 54, 117]);
  assert.equal(new Set([...baseline, ...candidate, ...breadth].map(row => row.id)).size, 189);
  assert.deepEqual(baseline.filter(row => row.skills_enabled).map(row => row.cell_id), candidate.map(row => row.cell_id));
  assert.equal(new Set(coverage.map(row => row.cell_id)).size, 117);
  assert.equal(coverage.some(row => !row.skills_enabled), false);
  const headless = new Set(HARNESSES.filter(host => host.execution_location === 'arm64-container').map(host => host.id));
  const assigned = buildMatrix().filter(row => headless.has(row.harness_id));
  assert.equal(assigned.length, 108);
  assert.ok(assigned.every(row => coverage.some(actual => actual.cell_id === row.cell_id)));
  assert.equal(coverage.filter(row => row.harness_id === 'codex-cli' && row.scenario_id === 'S5').length, 9);
  assert.deepEqual([...new Set(breadth.map(row => `${row.harness_id}/${row.scenario_id}`))], ['codex-cli/S2', 'claude-code/S2', 'hermes-agent/S3', 'deepseek-harness/S3', 'grok-build/S4', 'openclaw/S4']);
  const controls = baseline.filter(row => !row.skills_enabled);
  assert.ok(controls.every(row => row.scenario_id === 'S3' && row.harness_id === 'mini-swe-agent'));
  assert.equal(controls.filter(row => baseline.indexOf(row) < baseline.findIndex(other => other.model_id === row.model_id && other.seed === row.seed && other.scenario_id === 'S3' && other.skills_enabled)).length, 5);
  assert.equal(headlessReferenceRows().length, 7);
  assert.deepEqual([...new Set(headlessReferenceRows().map(row => row.model_id))], ['minicpm', 'lfm3', 'bonsai']);
  assert.equal(policyForProfile(), ITERATION_POLICY);
  assert.equal(policyForProfile(PROFILE), HEADLESS_POLICY);
  assert.equal(buildIterationRows().length, 12);
  assert.equal(buildIterationRows({ profile: PROFILE }).length, 72);
  assert.throws(() => buildHeadlessRows({ kind: 'claude-transfer' }));
  assert.throws(() => policyForProfile('arbitrary'));
});

test('v2 freezes coverage before admission and preserves its twelve-hour clock and reservations on resume', () => {
  const f = fixture();
  try {
    let store = f.open(), round = baseline(store);
    assert.equal(store.manifest.schema_version, 2); assert.equal(store.manifest.coverage_rows.length, 117);
    assert.equal(store.report().headless_qualification.missing_cells.length, 117);
    assert.equal(store.clock_started, false);
    select(f, store, round.rows[0].model_id);
    const deadline = f.clock + 720 * 60_000;
    store.chargeCalibration(round.rows[0].model_id, 'inert-calibration');
    record(f, store, round, round.rows[0]); release(f, store);
    f.clock += 60_000; store = f.open();
    assert.equal(store.state.deadline, deadline); assert.equal(store.state.execution_deadline, deadline - 45 * 60_000);
    assert.equal(store.state.reserved.episodes, 1); assert.equal(store.state.calibration.used, 1);
    select(f, store, round.rows[1].model_id);
    f.clock = store.state.execution_deadline - 181_000 + 1;
    assert.throws(() => store.claimEpisode(round.id, round.rows[1].id), /deadline/);
    assert.equal(store.state.reserved.episodes, 1);
  } finally { f.cleanup(); }
});

test('S4 receives extended input counters while ordinary scenarios retain their bounds', () => {
  const f = fixture();
  try {
    const store = f.open(), round = baseline(store);
    for (const row of round.rows.slice(0, 5)) record(f, store, round, row, { metrics: { counters: { inference: 1, tools: 1, ud_operations: 1, input: 110_000, output: 20 } } });
    const rows = store.report().rounds[0].rows.slice(0, 5);
    assert.ok(rows.slice(0, 4).every(row => row.outcome === 'incomplete' && row.budget_violations.includes('input')));
    assert.equal(rows[4].scenario_id, 'S4'); assert.equal(rows[4].outcome, 'passed');
    assert.equal(store.state.reserved.input, 4 * 6 * 16384 + 6 * 32768);
  } finally { f.cleanup(); }
});

test('an open session rechecks journal bytes after its parsed-entry cache is warm', () => {
  const f = fixture();
  try {
    const store = f.open(); baseline(store); store.snapshot();
    const file = path.join(f.directory, 'journal/000000.json');
    chmodSync(file, 0o600); writeFileSync(file, readFileSync(file, 'utf8').replace('round_frozen', 'round_forged'));
    assert.throws(() => store.snapshot(), /journal chain changed/);
  } finally { f.cleanup(); }
});

test('v2 retains resource-blocked model admission and its terminal episode without inventing success', () => {
  const f = fixture();
  try {
    const store = f.open(), round = baseline(store), row = round.rows[0];
    store.beginAdmission({ modelId: row.model_id });
    store.recordAdmission(row.model_id, f.file({ status: 'context_resource_blocked', model: { id: row.model_id }, fixture_only: true }));
    store.claimEpisode(round.id, row.id);
    store.recordEpisode(round.id, row.id, f.file({ ...row, outcome: 'context_resource_blocked', reason: 'Inert memory-pressure admission failure.',
      owned_cleanup_verified: true, candidate_installation_sha256: round.installation.sha256, fixture_only: true }));
    release(f, store);
    const report = store.report();
    assert.equal(report.rounds[0].rows[0].outcome, 'context_resource_blocked');
    assert.equal(report.final_headless_qualification, false);
    assert.equal(report.actual_counters.inference, null);
  } finally { f.cleanup(); }
});

test('v2 rechecks overwritten historical admissions and model-release receipts', () => {
  const f = fixture();
  try {
    const store = f.open(); baseline(store);
    const admissions = [], releases = [];
    for (let index = 0; index < 2; index++) {
      store.beginAdmission({ modelId: 'minicpm' });
      const admission = f.file({ status: 'admitted', model: { id: 'minicpm' }, fixture_only: true }); admissions.push(admission);
      store.recordAdmission('minicpm', admission);
      const proof = f.file({ model_id: 'minicpm', cleanupVerified: true, fixture_only: true }); releases.push(proof);
      store.releaseModel('minicpm', { ...proof, owned_cleanup_verified: true });
    }
    const report = store.report();
    assert.equal(report.lifecycle_evidence.admissions.length, 2); assert.equal(report.lifecycle_evidence.releases.length, 2);
    assert.equal(report.evidence_verification.status, 'verified');
    for (const ref of [admissions[0], releases[0]]) { chmodSync(ref.path, 0o600); writeFileSync(ref.path, '{}'); }
    const invalid = store.report();
    assert.equal(invalid.evidence_verification.status, 'invalid');
    assert.deepEqual(invalid.evidence_verification.errors.map(error => error.evidence_kind), ['admission', 'release']);
    assert.equal(invalid.final_headless_qualification, false);
  } finally { f.cleanup(); }
});

test('failed controls do not authorize a repair and required breadth remains visible before transfer', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store);
    finish(f, store, initial, row => !row.skills_enabled ? { outcome: 'failed', reason: 'Inert disabled-control failure.' } : {});
    assert.throws(() => repair(f, store, initial), /passing core/);
    const breadth = transfer(store, initial);
    assert.equal(breadth.rows.length, 54);
    assert.equal(store.report().headless_qualification.missing_cells.length, 54);
    assert.equal(store.report().final_headless_qualification, false);
    assert.throws(() => store.freezeRound({ kind: 'claude-transfer', parentRound: initial.id, product: initial.product, installation: initial.installation }));
  } finally { f.cleanup(); }
}, 120_000);

test('v2 rejects stage-only retention and permits honest breadth after rejecting its sole repair', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store);
    const fails = row => row.scenario_id === 'S1' && row.model_id === 'minicpm';
    finish(f, store, initial, row => fails(row) ? { outcome: 'failed', reason: 'Inert native failure.', stages: { discovery: false } } : {});
    const candidate = repair(f, store, initial);
    finish(f, store, candidate, row => fails(row) ? { outcome: 'failed', reason: 'Inert later-stage failure.', stages: { discovery: true } } : {});
    const decision = { reason: 'Inert stage advance only.', evidence: [f.file({ fixture_only: true })] };
    assert.throws(() => store.decideRound(candidate.id, { ...decision, retained: true }), /verified completion gain/);
    store.decideRound(candidate.id, { ...decision, retained: false });
    assert.equal(store.decisions[candidate.id].metrics.action_stage_advance_in_two_seeds, true);
    assert.throws(() => repair(f, store, initial), /At most one/);
    assert.equal(transfer(store, initial).parent_round, initial.id);
    assert.equal(store.report().retained_product_round, initial.id);
  } finally { f.cleanup(); }
}, process.platform === 'win32' ? 0 : 120_000);

test('final qualification uses 117 retained-product cells, excludes controls, and rejects corrupted evidence', () => {
  const f = fixture();
  try {
    const store = f.open(), initial = baseline(store);
    finish(f, store, initial, row => row.scenario_id === 'S1' || !row.skills_enabled ? { outcome: 'failed', reason: 'Inert baseline failure.' } : {});
    const candidate = repair(f, store, initial), refs = finish(f, store, candidate);
    store.decideRound(candidate.id, { retained: true, reason: 'Inert completion gain.', evidence: [f.file({ fixture_only: true })] });
    const breadth = transfer(store, candidate); finish(f, store, breadth);
    const report = store.report();
    assert.equal(report.counts.scheduled, 189); assert.equal(report.final_headless_qualification, true);
    assert.equal(report.headless_qualification.rows.length, 117); assert.equal(report.headless_qualification.transfer_paired, false);
    assert.ok(report.headless_qualification.rows.every(row => row.round_id === candidate.id || row.round_id === breadth.id));
    assert.equal(report.full_starter_qualification, false);
    const badTransfer = report.rounds.map(round => round.kind === 'transfer' ? { ...round, installation: identity('f') } : round);
    assert.equal(headlessQualification(store.manifest, badTransfer, candidate.id).status, 'unmet');
    const missingSeed = report.rounds.map(round => round.kind === 'transfer' ? { ...round, rows: round.rows.slice(1) } : round);
    assert.equal(headlessQualification(store.manifest, missingSeed, candidate.id).status, 'unmet');
    const ref = refs.values().next().value; chmodSync(ref.path, 0o600); writeFileSync(ref.path, '{}');
    const invalid = store.report(); assert.equal(invalid.final_headless_qualification, false); assert.equal(invalid.evidence_verification.status, 'invalid');
    assert.equal(readFileSync(path.join(f.directory, 'manifest.json'), 'utf8').includes(PROFILE), true);
  } finally { f.cleanup(); }
}, process.platform === 'win32' ? 0 : 360_000);
