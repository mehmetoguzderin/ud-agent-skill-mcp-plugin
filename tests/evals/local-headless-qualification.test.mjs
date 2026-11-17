// SPDX-License-Identifier: MIT
/** Inert scheduling fixtures never constitute model qualification evidence. */
import { test as vitestTest } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync, lstatSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { PROFILE } from '../../evals/local/headless-profile.mjs';
import { createIterationSession, openIterationSession } from '../../evals/local/iteration-state.mjs';
import { verifyHeadlessEvidence, verifiedProcessAbsence } from '../../evals/local/headless-qualification.mjs';
// Finite journal fixtures retain every replay assertion without a Windows
// wall-clock cutoff for filesystem latency.
const test = (name, run) => vitestTest(name, { timeout: process.platform === 'win32' ? 0 : 90_000 }, run);

test('cleanup claims require ESRCH or a complete successful table proving absence of the same queried process group', () => {
  const observation = { cleanupVerified: true, cleanup_evidence: [{ method: 'signal-zero', pgid: 123, outcome: 'failed', code: 'EPERM' }] };
  assert.equal(verifiedProcessAbsence({ cleanupVerified: true }, 123), false);
  assert.equal(verifiedProcessAbsence(observation, 123), false);
  const table = { method: 'process-table', outcome: 'absent', status: 0, signal: null, same_owner: true, matching: [], rows: [{ pid: 99, pgid: 99, uid: 501 }] };
  observation.cleanup_evidence.push(table);
  assert.equal(verifiedProcessAbsence(observation, 123), true);
  assert.equal(verifiedProcessAbsence(observation, 124), false);
  table.rows.push({ pid: 124, pgid: 123, uid: 501 }); assert.equal(verifiedProcessAbsence(observation, 123), false);
  observation.cleanup_evidence = [{ method: 'signal-zero', pgid: 123, outcome: 'failed', code: 'ESRCH' }];
  assert.equal(verifiedProcessAbsence(observation, 123), true);
  observation.cleanupVerified = false; assert.equal(verifiedProcessAbsence(observation, 123), false);
});

function fixture() {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-headless-final-'))), directory = path.join(root, '.artifacts/local-evals/iterations/inert');
  const identities = Object.fromEntries(['evaluator', 'oracle', 'tasks', 'model_configuration'].map(key => [key, 'a'.repeat(64)]));
  createIterationSession({ root, directory, identities, profile: PROFILE, optIn: true, environment: {}, now: 1_000_000 });
  const store = openIterationSession({ root, directory, optIn: true, environment: {}, now: () => 1_000_000 });
  let serial = 0;
  const file = value => { const file = path.join(directory, `inert-${serial++}.json`), bytes = JSON.stringify(value); writeFileSync(file, bytes, { mode: 0o400 }); return { path: file, sha256: sha256(bytes) }; };
  const admissions = [], releases = [], episodes = [];
  const release = () => {
    if (!store.state.active_model) return;
    const reference = file({ cleanupVerified: true, fixture_only: true }); releases.push(reference);
    store.releaseModel(store.state.active_model, { ...reference, owned_cleanup_verified: true });
  };
  const finish = round => {
    for (const row of round.rows) {
      if (store.state.active_model !== row.model_id) {
        release(); store.beginAdmission({ modelId: row.model_id });
        const reference = file({ status: 'admitted', model: { id: row.model_id }, fixture_only: true }); admissions.push(reference);
        store.recordAdmission(row.model_id, reference);
      }
      store.claimEpisode(round.id, row.id);
      const reference = file({ ...row, outcome: 'passed', owned_cleanup_verified: true, candidate_installation_sha256: round.installation.sha256,
        final_answer: 'Inert answer.', verification: { status: 'passed' }, fixture_only: true,
        observations: { real_inference: true, native_loop: true, model_attribution: true, independent_verification: true, budget_enforced: true, final_answer_verified: true, no_user_hints: true, skill_activation: false },
        metrics: { counters: { inference: 1, tools: row.scenario_id === 'S7' ? 0 : 1, ud_operations: row.scenario_id === 'S7' ? 0 : 1, input: 100, output: 20 }, total_elapsed_ms: 300 } });
      episodes.push(reference); store.recordEpisode(round.id, row.id, reference);
    }
    store.finishRound(round.id); release();
  };
  const initial = store.freezeRound({ kind: 'baseline', product: { sha256: 'b'.repeat(64) }, installation: { sha256: 'c'.repeat(64) } });
  finish(initial);
  finish(store.freezeRound({ kind: 'transfer', parentRound: initial.id, product: initial.product, installation: initial.installation }));
  return { root, directory, store, admissions, releases, episodes, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
function inventory(root) {
  const rows = [];
  const walk = directory => { for (const name of readdirSync(directory).sort()) {
    const file = path.join(directory, name), info = lstatSync(file);
    if (info.isDirectory()) walk(file); else rows.push({ path: path.relative(root, file), mode: info.mode, inode: info.ino, bytes: sha256(readFileSync(file)) });
  } }; walk(root); return rows;
}

test('all117 positive scheduler fixtures remain unqualified after strict read-only replay', async () => {
  const f = fixture();
  try {
    const proposal = f.store.report(); assert.equal(proposal.final_headless_qualification, true);
    const before = inventory(f.root), result = await verifyHeadlessEvidence(f.root, f.directory, proposal);
    assert.equal(result.status, 'unmet');
    assert.equal(result.failures.filter(code => code.startsWith('FIXTURE_ONLY_EPISODE:')).length, 117);
    assert.equal(result.failures.filter(code => code.startsWith('FIXTURE_ONLY_ADMISSION:')).length, 6);
    assert.equal(result.failures.filter(code => code.startsWith('FIXTURE_ONLY_RELEASE:')).length, 6);
    assert.deepEqual(inventory(f.root), before);
  } finally { f.cleanup(); }
});

for (const kind of ['admissions', 'releases']) {
  test(`strict final replay re-reads historical ${kind} bytes instead of trusting the supplied report`, async () => {
    const f = fixture();
    try {
      const proposal = f.store.report(), reference = f[kind][0];
      chmodSync(reference.path, 0o600); writeFileSync(reference.path, readFileSync(reference.path, 'utf8') + ' ');
      const before = inventory(f.root), result = await verifyHeadlessEvidence(f.root, f.directory, proposal);
      assert.equal(result.status, 'unmet');
      assert.ok(result.failures.some(code => code.startsWith(kind === 'admissions' ? 'ADMISSION_REFERENCE_CHANGED:' : 'RELEASE_REFERENCE_CHANGED:')));
      assert.ok(result.failures.includes('PRELIMINARY_COVERAGE_UNVERIFIED'));
      assert.deepEqual(inventory(f.root), before);
    } finally { f.cleanup(); }
  });
}

test('changed episode bytes and claimed final flags cannot manufacture independent qualification', async () => {
  const f = fixture();
  try {
    const proposal = f.store.report(), reference = f.episodes.find(reference => JSON.parse(readFileSync(reference.path)).skills_enabled);
    chmodSync(reference.path, 0o600); writeFileSync(reference.path, readFileSync(reference.path, 'utf8').replace('Inert answer.', 'Tampered answer.'));
    const result = await verifyHeadlessEvidence(f.root, f.directory, proposal);
    assert.equal(result.status, 'unmet'); assert.ok(result.failures.some(code => code.startsWith('EPISODE_REFERENCE_CHANGED:')));
    assert.ok(result.failures.includes('REPORT_DIFFERS_FROM_JOURNAL'));
  } finally { f.cleanup(); }
});

test('journal tampering produces a bounded failure without echoing hostile receipt text', async () => {
  const f = fixture();
  try {
    const proposal = f.store.report(), journal = path.join(f.directory, 'journal/000001.json');
    chmodSync(journal, 0o600); writeFileSync(journal, 'Bearer private-test-capability');
    const result = await verifyHeadlessEvidence(f.root, f.directory, proposal);
    assert.deepEqual(result, { status: 'unmet', failures: ['SESSION_JOURNAL_INVALID'] });
    assert.ok(!JSON.stringify(result).includes('private-test-capability'));
  } finally { f.cleanup(); }
});
