/** Same-installation inert admission order and evidence failure cases. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { mkdtempSync, realpathSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { HARNESSES } from '../../evals/local/registry.mjs';
import { writeNew } from '../../evals/local/preparation.mjs';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { prepareCampaignSnapshot, assertCandidatePreparationWindow, verifyCampaignPreflight, verifiedPreflightRelease } from '../../evals/local/campaign-preflight.mjs';
function fixture() {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-preflight-'))), directory = path.join(root, 'campaign'), product = { sha256: 'a'.repeat(64) }, adapter = 'b'.repeat(64), client = 'sha256:' + 'c'.repeat(64), proofDir = path.join(root, 'native-proof');
  mkdirSync(directory); let admitted = false, changed = false, builds = 0; const order = [];
  const reference = name => ({ ...fileReceipt(proofDir, name), path: path.join(proofDir, name) });
  const release = () => { mkdirSync(proofDir, { recursive: true }); writeNew(path.join(proofDir, 'release.json'), { kind: 'inert-native-owned-release', inference: false, product_source_sha256: product.sha256, adapter_sha256: adapter, client_identity: client, owned_cleanup_verified: true, launches: 1, native_sessions: [{ cleanupVerified: true }], steps: ['native-session', 'gateway', 'inert-provider', 'budget-authority'].map(step => ({ step, outcome: 'completed' })) }); return reference('release.json'); };
  const harnesses = () => HARNESSES.map(h => ({ ...h, status: h.id === 'qwen-code' && admitted ? 'mechanically-admitted' : 'interface unsupported', reason: 'Explicit inert unavailable route', ...(h.id === 'qwen-code' ? { container: { image_id: client }, ...(admitted ? { conformance: JSON.parse(readFileSync(path.join(proofDir, 'receipt.json'))) } : {}) } : {}) }));
  const options = { root, directory, product, adapter: () => adapter, source: () => ({ sha256: changed ? 'changed' : product.sha256 }), proofDirectory: () => proofDir,
    install: async (_root, target) => { builds++; order.push('install'); mkdirSync(target); return { sha256: 'installed', files: [] }; },
    inspect: async () => { order.push('inspect'); return harnesses(); },
    verify: async (_root, harness, opts) => { order.push('verify'); assert.equal(harness.id, 'qwen-code'); assert.equal(opts.installation, path.join(directory, 'installation')); assert.equal(opts.optIn, true);
      const proof = { status: 'mechanically-admitted', product_source_sha256: product.sha256, adapter_sha256: adapter, client_identity: client, inference: false, release: release() }; proof.evidence = [proof.release]; writeNew(path.join(proofDir, 'receipt.json'), proof); admitted = true; return proof; } };
  return { root, directory, options, order, proofDir, release, set admitted(v) { admitted = v; }, set changed(v) { changed = v; }, get builds() { return builds; }, cleanup() { rmSync(root, { recursive: true, force: true }); } };
}
test('one installed snapshot supplies inert preflight before clock/admission and retains all18surfaces/11headless', async () => {
  const f = fixture();
  try {
    const result = await prepareCampaignSnapshot(f.options); f.order.push('start-clock');
    assert.deepEqual(f.order, ['install', 'inspect', 'verify', 'inspect', 'start-clock']); assert.equal(f.builds, 1);
    assert.equal(result.harnesses.length, 18); assert.equal(result.harnesses.find(h => h.id === 'codex-desktop').status, 'interface unsupported');
    const receipt = verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter() }); assert.equal(receipt.headless_inventory.length, 11); assert.equal(receipt.calibration_requests, 0); assert.equal(receipt.model_admission_started, false);
    assert.deepEqual(receipt.selected_harness_ids, receipt.headless_inventory.map(row => row.harness_id));
    assert.equal(receipt.installation_root, result.installationRoot); assert.equal(result.harnesses.find(h => h.id === 'qwen-code').status, 'mechanically-admitted');
  } finally { f.cleanup(); }
});
test('selected native routes alone run preflight while both inspections retain all18surfaces', async () => {
  const f = fixture();
  try {
    const result = await prepareCampaignSnapshot({ ...f.options, harnessIds: ['mini-swe-agent', 'qwen-code'] });
    const receipt = verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter(), harnessIds: ['qwen-code', 'mini-swe-agent'] });
    assert.deepEqual(f.order, ['install', 'inspect', 'verify', 'inspect']);
    assert.deepEqual(receipt.selected_harness_ids, ['qwen-code', 'mini-swe-agent']);
    assert.deepEqual(receipt.headless_inventory.map(row => row.harness_id), receipt.selected_harness_ids);
    assert.equal(receipt.headless_inventory.find(row => row.harness_id === 'mini-swe-agent').status, 'blocked');
    assert.equal(receipt.harness_inventory.length, 18); assert.equal(result.harnesses.length, 18);
    assert.equal(receipt.harness_inventory.find(row => row.id === 'claude-code').status, 'interface unsupported');
    assert.throws(() => verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter(), harnessIds: ['qwen-code'] }), /SELECTION_CHANGED/);
  } finally { f.cleanup(); }
});
test('invalid native route selections fail before installation or inspection', async () => {
  for (const harnessIds of [[], ['qwen-code', 'qwen-code'], ['unknown'], ['claude-desktop'], ['__proto__'], 'qwen-code', [42]]) {
    const f = fixture();
    try {
      await assert.rejects(prepareCampaignSnapshot({ ...f.options, harnessIds }), /HARNESS_SELECTION_INVALID/);
      assert.equal(f.builds, 0); assert.deepEqual(f.order, []);
    } finally { f.cleanup(); }
  }
});
test('selected preflight evidence cannot omit, duplicate, substitute or hide required selected rows', async () => {
  const f = fixture();
  try {
    const result = await prepareCampaignSnapshot({ ...f.options, harnessIds: ['qwen-code', 'mini-swe-agent'] });
    const file = result.mechanicalPreflight.path, original = JSON.parse(readFileSync(file));
    const verify = changes => {
      writeFileSync(file, JSON.stringify({ ...original, ...changes }));
      const reference = { ...fileReceipt(path.dirname(file), path.basename(file)), path: file };
      return verifyCampaignPreflight(f.root, reference, f.options.product.sha256, { adapter: f.options.adapter() });
    };
    for (const rows of [original.headless_inventory.slice(1), [original.headless_inventory[0], original.headless_inventory[0]], [original.headless_inventory[0], { harness_id: 'claude-code' }], [null, original.headless_inventory[1]], undefined]) {
      assert.throws(() => verify({ headless_inventory: rows }), /SELECTED_INVENTORY_INCOMPLETE/);
    }
    assert.throws(() => verify({ selected_harness_ids: undefined }), /SELECTED_INVENTORY_INCOMPLETE/);
    for (const ids of [[], ['qwen-code', 'qwen-code'], ['claude-desktop']]) assert.throws(() => verify({ selected_harness_ids: ids }), /HARNESS_SELECTION_INVALID/);
  } finally { f.cleanup(); }
});
test('legacy preflight receipts without a selection still require all11headless routes', async () => {
  const f = fixture();
  try {
    const result = await prepareCampaignSnapshot(f.options), file = result.mechanicalPreflight.path, original = JSON.parse(readFileSync(file));
    delete original.selected_harness_ids; writeFileSync(file, JSON.stringify(original));
    const reference = { ...fileReceipt(path.dirname(file), path.basename(file)), path: file };
    assert.equal(verifyCampaignPreflight(f.root, reference, f.options.product.sha256, { adapter: f.options.adapter() }).headless_inventory.length, 11);
    assert.throws(() => verifyCampaignPreflight(f.root, reference, f.options.product.sha256, { adapter: f.options.adapter(), harnessIds: ['qwen-code'] }), /SELECTION_CHANGED/);
  } finally { f.cleanup(); }
});
test('missing independent proof cannot admit a route even if a verifier returns an optimistic status', async () => {
  const f = fixture();
  try {
    const verify = f.options.verify; f.options.verify = async (...args) => { const result = await verify(...args); f.admitted = false; return result; };
    const result = await prepareCampaignSnapshot(f.options), receipt = verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter() });
    assert.equal(result.harnesses.find(h => h.id === 'qwen-code').status, 'interface unsupported'); assert.equal(receipt.headless_inventory.find(h => h.harness_id === 'qwen-code').status, 'blocked');
    writeFileSync(path.join(f.proofDir, 'release.json'), '{}'); assert.throws(() => verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter() }), /EVIDENCE_CHANGED/);
  } finally { f.cleanup(); }
});
test('a current source/client proof is reused without another private client loop', async () => {
  const f = fixture();
  try {
    await f.options.verify(f.root, { id: 'qwen-code' }, { installation: path.join(f.directory, 'installation'), optIn: true }); f.order.length = 0;
    f.options.verify = async () => { throw new Error('Current proof must be reused'); };
    const result = await prepareCampaignSnapshot(f.options), evidence = verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter() });
    assert.deepEqual(f.order, ['install', 'inspect', 'inspect']); assert.equal(evidence.headless_inventory.find(row => row.harness_id === 'qwen-code').status, 'current-proof-reused');
  } finally { f.cleanup(); }
});
test('a thrown native rejection is an explicit blocker only after source-bound owned release', async () => {
  const f = fixture();
  try {
    f.options.verify = async () => { f.release(); writeNew(path.join(f.proofDir, 'failure.json'), { reason: 'inert protocol rejected', inference: false }); throw new Error('inert protocol rejected'); };
    const result = await prepareCampaignSnapshot(f.options), evidence = verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter() }), row = evidence.headless_inventory.find(row => row.harness_id === 'qwen-code');
    assert.equal(row.status, 'blocked'); assert.equal(row.reason, 'inert protocol rejected'); assert.ok(row.release.sha256);
  } finally { f.cleanup(); }
});
test('source change during mechanical execution aborts before a campaign clock or manifest is created', async () => {
  const f = fixture();
  try { const verify = f.options.verify; f.options.verify = async (...args) => { const result = await verify(...args); f.changed = true; return result; }; await assert.rejects(prepareCampaignSnapshot(f.options), /PRODUCT_CHANGED/); }
  finally { f.cleanup(); }
});
test('prior exact-source failure remains unchanged and blocked after verified release; unknown cleanup stops', async () => {
  const f = fixture();
  try {
    f.release(); const failed = path.join(f.proofDir, 'failure.json'); writeNew(failed, { reason: 'prior inert rejection', inference: false }); const bytes = readFileSync(failed);
    f.options.verify = async () => { throw new Error('Must not overwrite or retry prior attempt'); };
    const result = await prepareCampaignSnapshot(f.options), proof = verifyCampaignPreflight(f.root, result.mechanicalPreflight, f.options.product.sha256, { adapter: f.options.adapter() });
    assert.equal(proof.headless_inventory.find(h => h.harness_id === 'qwen-code').status, 'blocked'); assert.deepEqual(readFileSync(failed), bytes);
  } finally { f.cleanup(); }
  const g = fixture();
  try { mkdirSync(g.proofDir); writeNew(path.join(g.proofDir, 'failure.json'), { reason: 'release unknown' }); await assert.rejects(prepareCampaignSnapshot(g.options), /CLEANUP_UNVERIFIED/); }
  finally { g.cleanup(); }
});
test('candidate repair/replay gates must still fit after mechanical time without resetting the baseline deadline', () => {
  const original = { deadline: 100000, phase_allocations_ms: { diagnosis: 30000, reconciliation: 1000 }, forecast: { replaySeconds: 20 } }, before = structuredClone(original);
  assert.doesNotThrow(() => assertCandidatePreparationWindow(original, 1000, 2000));
  assert.throws(() => assertCandidatePreparationWindow(original, 1000, 31001), /repair allocation expired/);
  assert.throws(() => assertCandidatePreparationWindow(original, 60000, 80000), /replay cannot fit/);
  assert.deepEqual(original, before);
});
test('both inspections require the exact registered18IDs, not a same-sized substituted set', async () => {
  for (const changedInspection of [1, 2]) {
    const f = fixture();
    try {
      let calls = 0; const inspect = f.options.inspect;
      f.options.inspect = async () => { const rows = await inspect(); if (++calls === changedInspection) rows[0].id = 'unregistered-surface'; return rows; };
      await assert.rejects(prepareCampaignSnapshot(f.options), /INVENTORY_INCOMPLETE/);
    } finally { f.cleanup(); }
  }
});
test('release requires all4named observations and current bindings; zero launches support blockers only', () => {
  const f = fixture();
  try {
    const reference = f.release(), file = path.join(f.proofDir, 'release.json'), original = JSON.parse(readFileSync(file));
    const options = { product: f.options.product.sha256, adapter: f.options.adapter(), client: original.client_identity };
    for (const changes of [{ steps: [] }, { steps: original.steps.slice(1) }, { steps: original.steps.map(() => original.steps[0]) }, { adapter_sha256: 'foreign' }, { client_identity: 'foreign' }, { product_source_sha256: 'foreign' }]) {
      writeFileSync(file, JSON.stringify({ ...original, ...changes })); assert.throws(() => verifiedPreflightRelease(f.proofDir, options), /CLEANUP_UNVERIFIED/);
    }
    writeFileSync(file, JSON.stringify({ ...original, launches: 0, native_sessions: [] }));
    assert.throws(() => verifiedPreflightRelease(f.proofDir, options), /CLEANUP_UNVERIFIED/);
    assert.ok(verifiedPreflightRelease(f.proofDir, { ...options, allowZeroLaunches: true }).sha256);
  } finally { f.cleanup(); }
});
