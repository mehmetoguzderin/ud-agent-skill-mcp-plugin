import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sourceReceipt, fileReceipt } from '../../scripts/release/candidate.mjs';
import { buildMatrix } from '../../evals/local/registry.mjs';
import { verifyCampaignEvidence, completedBudgetEvidence, verifyMechanicalRebaseline } from '../../evals/local/qualification.mjs';
import { validateMechanicalRebaseline } from '../../evals/local/campaign.mjs';

test('qualified output usage must be observed, complete and free of abandoned reservations', () => {
  const valid = { counters: { output: 13 }, pending_requests: 0, pending_operations: 0, cleanup: 'verified', stopped: null,
    output_usage_verified: true, abandoned_inference: [], reserved_output: 0, unknown_output_tokens_upper_bound: 0, output_tokens_upper_bound: 13, elapsed_ms: 90 };
  assert.equal(completedBudgetEvidence(valid), true);
  for (const key of Object.keys(valid)) { const incomplete = { ...valid }; delete incomplete[key]; assert.equal(completedBudgetEvidence(incomplete), false, key); }
  for (const change of [
    { output_usage_verified: false }, { abandoned_inference: [{ actual_output_tokens: null, reserved_output_tokens: 512 }] },
    { pending_requests: 1 }, { pending_operations: 1 }, { cleanup: 'pending' }, { cleanup: 'unverified' }, { stopped: 'EPISODE_TIMEOUT' },
    { reserved_output: 512 }, { unknown_output_tokens_upper_bound: 512 }, { output_tokens_upper_bound: 525 }, { elapsed_ms: 95_001 },
  ]) assert.equal(completedBudgetEvidence({ ...valid, ...change }), false, JSON.stringify(change));
});

test('mechanical lineage verifies immutable spending receipts and rejects clock, source and row tampering', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-lineage-')), base = path.join(root, '.artifacts/local-evals/campaigns');
  const priorDirectory = path.join(base, 'prior'), directory = path.join(base, 'baseline');
  for (const folder of [priorDirectory, directory]) mkdirSync(path.join(folder, 'episodes'), { recursive: true });
  const write = (file, value) => writeFileSync(file, JSON.stringify(value));
  try {
    const rows = buildMatrix(), hashes = { evaluator: 'old', oracle: 'fixed', tasks: 'fixed', model_configuration: 'fixed' };
    const prior = { snapshot: 'baseline', rows, started_at: '2026-01-01T00:00:00.000Z', deadline: Date.parse('2026-01-01T12:00:00.000Z'), windows: 3,
      phase_allocations_ms: { baseline: 10 }, preparation: { models: ['exact'] }, hashes, product: { files: [{ path: 'src/mcp.ts', sha256: 'same' }, { path: 'evals/local/budget.mjs', sha256: 'old' }] } };
    const previousRows = rows.slice(0, 8).map(row => ({ ...row, outcome: 'incomplete' }));
    write(path.join(priorDirectory, 'manifest.json'), prior);
    previousRows.forEach((row, index) => write(path.join(priorDirectory, 'episodes', `${index}.json`), row));
    for (const folder of [priorDirectory, directory]) {
      write(path.join(folder, 'phase-baseline.json'), { started: 1, deadline: 2 });
      write(path.join(folder, 'calibration.json'), { used: 12, maximum: 12, per_model: { minicpm: 4, lfm3: 4, bonsai: 4 } });
      for (const id of ['minicpm', 'lfm3', 'bonsai']) write(path.join(folder, `admission-${id}.json`), { id, status: 'admitted' });
    }
    const proof = path.join(root, '.artifacts/local-evals/release-proof.json'); write(proof, { current_owned_compute_absence_verified: true,
      campaign_manifest: fileReceipt(priorDirectory, 'manifest.json'), episodes: previousRows.map((_row, index) => fileReceipt(priorDirectory, `episodes/${index}.json`)) });
    write(path.join(priorDirectory, 'post-stop-release.json'), { cleanupVerified: true, evidence: { path: proof, sha256: fileReceipt(path.dirname(proof), path.basename(proof)).sha256 } });
    const manifest = { ...prior, product: { files: [prior.product.files[0], { ...prior.product.files[1], sha256: 'fixed' }] }, hashes: { ...hashes, evaluator: 'fixed' } };
    manifest.mechanical_rebaseline = { previous_campaign: priorDirectory, previous_manifest_sha256: fileReceipt(priorDirectory, 'manifest.json').sha256,
      ...validateMechanicalRebaseline({ prior, product: manifest.product, hashes: manifest.hashes, preparation: manifest.preparation, episodes: previousRows, now: Date.parse(prior.started_at) }),
      previous_rows: previousRows.map((_row, index) => fileReceipt(priorDirectory, `episodes/${index}.json`)), calibration_receipt: fileReceipt(priorDirectory, 'calibration.json'), phase_receipt: fileReceipt(priorDirectory, 'phase-baseline.json'),
      admissions: ['minicpm', 'lfm3', 'bonsai'].map(id => ({ id, ...fileReceipt(priorDirectory, `admission-${id}.json`) })), release_receipt_sha256: fileReceipt(priorDirectory, 'post-stop-release.json').sha256 };
    write(path.join(priorDirectory, 'mechanical-rebaseline.json'), { campaign: directory });
    assert.deepEqual(verifyMechanicalRebaseline(root, directory, manifest, []), []);
    assert.match(verifyMechanicalRebaseline(root, directory, { ...manifest, deadline: manifest.deadline + 1 }, [])[0], /CLOCK_CHANGED/);
    assert.match(verifyMechanicalRebaseline(root, directory, { ...manifest, hashes: { ...manifest.hashes, oracle: 'changed' } }, [])[0], /oracle/);
    assert.match(verifyMechanicalRebaseline(root, directory, { ...manifest, product: { files: [{ ...manifest.product.files[0], sha256: 'changed' }, manifest.product.files[1]] } }, [])[0], /UD product/);
    for (const [folder, filename, value, expected] of [
      [priorDirectory, 'episodes/0.json', { replaced: true }, /RECEIPT_CHANGED/],
      [priorDirectory, 'mechanical-rebaseline.json', { campaign: path.join(base, 'other') }, /MARKER/],
      [directory, 'phase-baseline.json', { started: 2 }, /PHASE_CHANGED/],
      [directory, 'calibration.json', { used: 0 }, /CALIBRATION_CHANGED/],
      [directory, 'admission-bonsai.json', { id: 'substitute' }, /ADMISSION_CHANGED/],
    ]) {
      const file = path.join(folder, filename), original = readFileSync(file); write(file, value);
      assert.match(verifyMechanicalRebaseline(root, directory, manifest, [])[0], expected); writeFileSync(file, original);
    }
    write(path.join(priorDirectory, 'episodes/extra.json'), {});
    assert.match(verifyMechanicalRebaseline(root, directory, manifest, [])[0], /PRIOR_ROWS_CHANGED/);
    rmSync(path.join(priorDirectory, 'episodes/extra.json'));
    const candidateDirectory = path.join(base, 'candidate'); mkdirSync(path.join(candidateDirectory, 'episodes'), { recursive: true });
    write(path.join(directory, 'manifest.json'), manifest);
    const candidate = { ...manifest, snapshot: 'candidate', baseline: directory };
    assert.match(verifyMechanicalRebaseline(root, candidateDirectory, candidate, Array(353).fill({}))[0], /GLOBAL_EPISODE_LIMIT/);
    assert.deepEqual(verifyMechanicalRebaseline(root, directory, manifest, []), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('a complete matrix of asserted passes cannot replace independent native evidence', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-local-qualification-'));
  const campaign = path.join(root, '.artifacts/local-evals/campaigns/fixture');
  mkdirSync(path.join(campaign, 'episodes'), { recursive: true });
  const write = (file, value) => writeFileSync(file, JSON.stringify(value));
  try {
    write(path.join(root, 'package.json'), { name: 'inert-qualification-fixture' });
    const rows = buildMatrix();
    write(path.join(campaign, 'manifest.json'), { snapshot: 'baseline', rows, product: sourceReceipt(root), installation: { files: [] } });
    write(path.join(campaign, 'calibration.json'), { used: 0, maximum: 12, per_model: {} });
    rows.forEach((row, index) => write(path.join(campaign, 'episodes', `${index}.json`), { ...row, outcome: 'passed', final_answer: 'A claimed successful answer.', observations: {
      real_inference: true, native_loop: true, model_attribution: true, independent_verification: true, budget_enforced: true,
      final_answer_verified: true, no_user_hints: true, skill_activation: row.scenario_id !== 'S7' } }));
    const verified = await verifyCampaignEvidence(root, campaign);
    assert.equal(verified.status, 'unmet');
    assert.ok(verified.failures.includes('INSTALLATION_IDENTITY_MISSING'));
    assert.equal(verified.failures.filter(value => value.startsWith('STATE_EVIDENCE_MISSING:')).length, 171);
    assert.equal(verified.predicates.external_hosting, 'separate');
    write(path.join(campaign, 'calibration.json'), { used: 1, maximum: 12, per_model: { minicpm: 4 } });
    assert.ok((await verifyCampaignEvidence(root, campaign)).failures.includes('CALIBRATION_LIMIT_UNVERIFIED'));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
