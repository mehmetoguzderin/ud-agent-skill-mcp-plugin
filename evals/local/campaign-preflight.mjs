/** Inert native admission against the campaign's own installed snapshot. MIT. */
import { existsSync, readFileSync, lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { sourceReceipt, fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { inspectHarnesses, nativeConformanceDirectory, nativeAdapterIdentity } from './native.mjs';
import { verifyNativeChatRoute } from './native-conformance.mjs';
import { NATIVE_RECIPES } from './native-recipes.mjs';
import { HARNESSES } from './registry.mjs';
import { writeNew } from './preparation.mjs';
import { failureObservation } from './lifecycle.mjs';

export function assertCandidatePreparationWindow(original, completedAt, now = Date.now()) {
  if (now > completedAt + original.phase_allocations_ms.diagnosis) throw new Error('The persisted diagnosis and repair allocation expired.');
  if (now + original.forecast.replaySeconds * 1000 + original.phase_allocations_ms.reconciliation >= original.deadline) throw new Error('Required complete replay cannot fit before reconciliation.');
}
const RELEASE_STEPS = ['budget-authority', 'gateway', 'inert-provider', 'native-session'];
function assertHarnessInventory(rows) {
  if (!Array.isArray(rows) || rows.length !== HARNESSES.length || JSON.stringify(rows.map(row => row.id).sort()) !== JSON.stringify(HARNESSES.map(row => row.id).sort())) throw new Error('NATIVE_PREFLIGHT_HARNESS_INVENTORY_INCOMPLETE');
}
function selectedHarnessIds(ids) {
  const available = HARNESSES.filter(harness => Object.hasOwn(NATIVE_RECIPES, harness.id)).map(harness => harness.id);
  if (ids === undefined) return available;
  if (!Array.isArray(ids) || ids.length === 0 || new Set(ids).size !== ids.length || ids.some(id => typeof id !== 'string' || !available.includes(id))) throw new Error('NATIVE_PREFLIGHT_HARNESS_SELECTION_INVALID');
  return available.filter(id => ids.includes(id));
}
function assertSelectedInventory(rows, selected) {
  if (!Array.isArray(rows) || rows.length !== selected.length || JSON.stringify(rows.map(row => row?.harness_id).sort()) !== JSON.stringify([...selected].sort())) throw new Error('NATIVE_PREFLIGHT_SELECTED_INVENTORY_INCOMPLETE');
}
export function verifiedPreflightRelease(directory, { product, adapter, client, reference, allowZeroLaunches = false }) {
  const file = path.join(directory, 'release.json');
  if (!existsSync(file) || !lstatSync(file).isFile() || lstatSync(file).isSymbolicLink() || realpathSync(file) !== file) throw new Error('NATIVE_PREFLIGHT_CLEANUP_UNVERIFIED');
  const bytes = readFileSync(file), digest = sha256(bytes), value = JSON.parse(bytes);
  if (reference && (reference.path !== file || reference.sha256 !== digest) || value.kind !== 'inert-native-owned-release' || value.inference !== false || value.product_source_sha256 !== product || value.adapter_sha256 !== adapter || value.client_identity !== client || value.owned_cleanup_verified !== true || !Number.isSafeInteger(value.launches) || value.launches < (allowZeroLaunches ? 0 : 1) || !Array.isArray(value.native_sessions) || value.native_sessions.length !== value.launches || !value.native_sessions.every(item => item.cleanupVerified === true) || !Array.isArray(value.steps) || JSON.stringify(value.steps.map(item => item.step).sort()) !== JSON.stringify(RELEASE_STEPS) || !value.steps.every(item => item.outcome === 'completed')) throw new Error('NATIVE_PREFLIGHT_CLEANUP_UNVERIFIED');
  return { path: file, sha256: digest };
}
export function verifyCampaignPreflight(root, reference, product, { adapter = nativeAdapterIdentity(), harnessIds } = {}) {
  const read = item => {
    if (!item || !path.isAbsolute(item.path) || !item.path.startsWith(realpathSync(root) + path.sep) || !lstatSync(item.path).isFile() || lstatSync(item.path).isSymbolicLink() || realpathSync(item.path) !== item.path) throw new Error('NATIVE_PREFLIGHT_EVIDENCE_INVALID');
    const bytes = readFileSync(item.path); if (sha256(bytes) !== item.sha256) throw new Error('NATIVE_PREFLIGHT_EVIDENCE_CHANGED'); return JSON.parse(bytes);
  };
  const evidence = read(reference);
  if (evidence.inference !== false || evidence.calibration_requests !== 0 || evidence.source_sha256 !== product || evidence.adapter_sha256 !== adapter) throw new Error('NATIVE_PREFLIGHT_BINDING_CHANGED');
  assertHarnessInventory(evidence.harness_inventory);
  // Receipts predating route selection cover every headless recipe. A partial
  // inventory cannot acquire that meaning merely by omitting its selection.
  const selected = selectedHarnessIds(evidence.selected_harness_ids);
  if (harnessIds !== undefined && JSON.stringify(selectedHarnessIds(harnessIds)) !== JSON.stringify(selected)) throw new Error('NATIVE_PREFLIGHT_SELECTION_CHANGED');
  assertSelectedInventory(evidence.headless_inventory, selected);
  for (const row of evidence.headless_inventory) {
    if (row.proof) { const proof = read(row.proof); if (proof.product_source_sha256 !== product || proof.adapter_sha256 !== adapter || proof.client_identity !== row.client_identity) throw new Error('NATIVE_PREFLIGHT_BINDING_CHANGED'); for (const item of proof.evidence ?? []) read(item); }
    if (row.release) { read(row.release); verifiedPreflightRelease(path.dirname(row.release.path), { product, adapter, client: row.client_identity, reference: row.release, allowZeroLaunches: row.status === 'blocked' }); }
  }
  return evidence;
}
/** Installation and fake-provider checks precede the caller's first clock read.
 * A thrown/partially observed cleanup stops preparation, retaining its evidence. */
export async function prepareCampaignSnapshot({ root, directory, product, install, inspect = inspectHarnesses, verify = verifyNativeChatRoute,
  source = sourceReceipt, proofDirectory = nativeConformanceDirectory, exists = existsSync, persist = writeNew, receipt = fileReceipt,
  adapter = nativeAdapterIdentity, beforeRoute = async () => {}, harnessIds, signal, deadline = Date.now() + 30 * 60_000, onProgress = () => {} }) {
  if (typeof install !== 'function') throw new Error('A real installed-snapshot builder is required.');
  const selected = selectedHarnessIds(harnessIds);
  const expected = product.sha256, unchanged = () => { if (source(root).sha256 !== expected) throw new Error('PREFLIGHT_PRODUCT_CHANGED'); };
  const check = () => { signal?.throwIfAborted(); if (Date.now() >= deadline) throw new Error('NATIVE_PREFLIGHT_DEADLINE'); unchanged(); };
  check(); const installationRoot = path.join(directory, 'installation'), installation = await install(root, installationRoot); check();
  const input = await inspect(root), rows = [], preflightDirectory = path.join(directory, 'mechanical-preflight');
  assertHarnessInventory(input);
  for (const harness of input) {
    const recipe = NATIVE_RECIPES[harness.id];
    if (!recipe || !selected.includes(harness.id)) continue; // An associated CLI never admits a desktop/IDE surface.
    check();
    let row = { harness_id: harness.id, inference: false, source_sha256: expected, installation_sha256: installation.sha256 };
    const eligible = harness.execution_location === 'arm64-container' && harness.container?.image_id && harness.image_availability !== 'archived-unavailable' && recipe.canRun;
    if (!eligible) row = { ...row, status: 'blocked', reason: harness.reason ?? 'Verified ARM64 image/native protocol route is unavailable.' };
    else {
      await beforeRoute(); check();
      const identity = harness.container.image_id, adapterIdentity = adapter(), nativeDirectory = proofDirectory(root, harness.id, identity), proofFile = path.join(nativeDirectory, 'receipt.json');
      row.client_identity = identity;
      if (harness.status === 'mechanically-admitted' && harness.conformance) row = { ...row, status: 'current-proof-reused', proof: { ...receipt(nativeDirectory, 'receipt.json'), path: proofFile }, release: verifiedPreflightRelease(nativeDirectory, { product: expected, adapter: adapterIdentity, client: identity, reference: harness.conformance.release }) };
      else if (exists(nativeDirectory)) row = { ...row, status: 'blocked', reason: 'Prior exact-source conformance attempt is retained and cannot be overwritten.', prior_attempt_directory: nativeDirectory, release: verifiedPreflightRelease(nativeDirectory, { product: expected, adapter: adapterIdentity, client: identity, allowZeroLaunches: true }) };
      else {
        try {
          const combined = AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(Math.max(1, deadline - Date.now()))]);
          const proof = await verify(root, harness, { optIn: true, installation: installationRoot, onProgress, signal: combined });
          check();
          row = { ...row, status: proof.status === 'mechanically-admitted' ? 'verified' : 'blocked', proof: { ...receipt(nativeDirectory, 'receipt.json'), path: proofFile }, release: verifiedPreflightRelease(nativeDirectory, { product: expected, adapter: adapterIdentity, client: identity, reference: proof.release, allowZeroLaunches: proof.status !== 'mechanically-admitted' }), ...(proof.status === 'mechanically-admitted' ? {} : { reason: 'Inert native conformance did not satisfy all required observations.' }) };
        } catch (error) {
          let release;
          try { check(); release = verifiedPreflightRelease(nativeDirectory, { product: expected, adapter: adapterIdentity, client: identity, allowZeroLaunches: true }); }
          catch { persist(path.join(preflightDirectory, harness.id + '-failure.json'), { ...row, status: 'failed', failure: failureObservation(error), native_attempt_directory: nativeDirectory }); throw error; }
          row = { ...row, status: 'blocked', reason: error.message, failure: failureObservation(error), native_attempt_directory: nativeDirectory, release };
        }
      }
    }
    persist(path.join(preflightDirectory, harness.id + '.json'), row); rows.push(row); check();
  }
  const harnesses = await inspect(root); check();
  assertHarnessInventory(harnesses);
  const reconciled = rows.map(row => ['verified', 'current-proof-reused'].includes(row.status) && harnesses.find(item => item.id === row.harness_id)?.status !== 'mechanically-admitted'
    ? { ...row, status: 'blocked', initial_observation_status: row.status, reason: 'Current native proof was not independently admitted after preparation.' } : row);
  // Only independently re-inspected current proofs can admit a surface.
  const evidence = { schema_version: 1, kind: 'campaign-inert-native-preflight', inference: false, calibration_requests: 0, model_admission_started: false,
    source_sha256: expected, adapter_sha256: adapter(), installation_sha256: installation.sha256, installation_root: installationRoot,
    selected_harness_ids: selected, headless_inventory: reconciled, harness_inventory: harnesses };
  const file = path.join(preflightDirectory, 'receipt.json'); persist(file, evidence);
  return { installationRoot, installation, harnesses, mechanicalPreflight: { ...receipt(preflightDirectory, 'receipt.json'), path: file } };
}
