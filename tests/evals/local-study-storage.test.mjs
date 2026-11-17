import { posixTest } from '../fixtures/native-scope.mjs';
/** Explicit storage planning, injected accounting only. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { scientificStudyStorage, SCIENTIFIC_STORAGE_PLANS } from '../../evals/local/study-storage.mjs';
test('study admission accounts selected engine bytes and keeps peak fixture caches in the output plan', async () => {
  let bytes=1000, plan, cleanup=false;const checks=[];
  const lease=scientificStudyStorage('/repo','run',{measure:()=>bytes,engine:()=>6000,reserve:value=>{plan=value;return{admission:{limits:{totalBytes:40_000_000_000}},check:value=>{checks.push(value);if(value>3_000_000_000)throw new Error('output exceeds its declared plan');},cleanup:()=>{cleanup=true;}};}});
  assert.equal(plan.externalOwnedBytes,6000);assert.equal(plan.plannedBytes,32_000_000);assert.equal(plan.plannedOutputBytes,3_000_000_000);assert.equal(plan.transientAllowance,10_000_000_000);assert.equal(plan.profile,'release');
  assert.equal(plan.limits,undefined,'No total-storage ceiling override is allowed.');
  bytes+=1_600_000_000;await lease.check();assert.equal(checks.at(-1),1_600_000_000);
  bytes+=1_500_000_000;await assert.rejects(lease.check(),/declared plan/);await lease.cleanup();assert.equal(cleanup,true);
  assert.equal(SCIENTIFIC_STORAGE_PLANS.prepare.output_bytes,800_000_000);assert.equal(SCIENTIFIC_STORAGE_PLANS.prepare.profile,'ordinary');
});
test('failed engine accounting blocks before a storage lease or model clock can start', () => {
  let reserved=false;assert.throws(()=>scientificStudyStorage('/repo','prepare',{measure:()=>0,engine:()=>{throw new Error('engine unavailable');},reserve:()=>{reserved=true;}}),/engine unavailable/);assert.equal(reserved,false);
});

test('fixture preparation release needs observed child and worker-job cleanup, never process-only optimism', async () => {
  const { fixturePreparationRelease } = await import('../../evals/local/runtime-assets.mjs');
  assert.equal(fixturePreparationRelease([], { setupStarted: false }), true);
  assert.equal(fixturePreparationRelease([{ cleanupVerified: false }], { setupStarted: false }), false);
  assert.equal(fixturePreparationRelease([{ cleanupVerified: true }], { setupStarted: true, jobs: { verified: false } }), false);
  assert.equal(fixturePreparationRelease([{ cleanupVerified: true }], { setupStarted: true, jobs: { verified: true } }), true);
});
posixTest('nonzero and cancelled owned fixture children retain actual cleanup evidence on errors', async () => {
  const { runOwned } = await import('../../evals/local/process.mjs');
  await assert.rejects(runOwned(process.execPath, ['-e', 'process.exit(3)'], { timeout: 1000 }), error => error.result?.code === 3 && error.result?.cleanupVerified === true);
  const controller = new AbortController(), pending = runOwned(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeout: 2000, signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, error => error.result?.cleanupVerified === true && error.result?.stop_reason?.includes('AbortError'));
});

test('short rounds reserve one active fixture and bounded installations without raising storage ceilings', async () => {
  for (const phase of ['iterate', 'iterate-transfer']) {
    let plan;
    const lease = scientificStudyStorage('/repo', phase, { measure: () => 100, engine: () => 200,
      reserve: value => { plan = value; return { admission: {}, check() {}, cleanup() {} }; } });
    assert.equal(plan.transientAllowance, 10_000_000_000); assert.equal(plan.limits, undefined);
    assert.equal(plan.externalOwnedBytes, 200);
    assert.ok(plan.plannedOutputBytes >= 1_100_000_000);
    assert.equal(plan.plannedOutputBytes, SCIENTIFIC_STORAGE_PLANS[phase].transient_fixture_output_bytes + SCIENTIFIC_STORAGE_PLANS[phase].persistent_evidence_output_bytes);
    await lease.cleanup();
  }
});

if (process.platform === 'win32') test('unsupported Windows process groups cannot establish fixture cleanup evidence', async () => {
  const { runOwned } = await import('../../evals/local/process.mjs');
  await assert.rejects(runOwned(process.execPath, ['-e', 'process.exit(3)'], { timeout: 1000 }), error => {
    assert.equal(error.message, 'OWNED_PROCESS_GROUP_UNSUPPORTED');
    assert.equal(error.result, undefined);
    return true;
  });
});
