import { test } from 'vitest';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { verifyWorkflowQualification, workflowRuntimeInputOptions, verifyWorkflowRuntimeSubject } from '../../scripts/quality/workflow-host.mjs';
import { verifyAvailableCandidateBindings } from '../../scripts/release/available-candidate.mjs';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { availableOriginalCandidate } from '../fixtures/available-original-candidate.mjs';

function fixture(action) {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-available-workflow-')), sourceRoot = path.join(base, 'source'), candidateRoot = path.join(base, 'candidate');
  mkdirSync(path.join(sourceRoot, 'tests'), { recursive: true }); writeFileSync(path.join(sourceRoot, 'tests/fixture.test.mjs'), '// Synthetic consumer packet; no installed execution claim.\n');
  try {
    const { manifest } = availableOriginalCandidate(sourceRoot, candidateRoot), installation = path.join(candidateRoot, 'native-installation');
    const payload = { source_tree_sha256: manifest.source_tree_sha256, runtime_lock_sha256: manifest.runtime_lock_sha256, inventory_sha256: fileReceipt(installation, 'PACKAGE-INVENTORY.json').sha256 };
    // A synthetic runtime-row projection calibrates the consumer contract. The
    // real CLI first obtains this row through strict verifyRuntimeInputs.
    const selected = { candidate: { qualification: 'available-target-runtime-inputs', source_sha256: manifest.source_tree_sha256, runtime_lock_sha256: manifest.runtime_lock_sha256 }, candidate_receipt: fileReceipt(candidateRoot, 'available-candidate.json'), formats: { native: { inventory_sha256: payload.inventory_sha256 } }, available_bindings: verifyAvailableCandidateBindings(candidateRoot, manifest) };
    action({ base, candidateRoot, installation, manifest, payload, selected });
  } finally { rmSync(base, { recursive: true, force: true }); }
}

test('available workflow qualification cannot promote the subset or reuse diagnostic payloads', () => fixture(({ installation }) => {
  assert.deepEqual(verifyWorkflowQualification(installation, 'available-target'), { qualification: 'available-target-scripted-replay', acceptance_eligible: false, target_execution_eligible: true });
  const filename = path.join(installation, 'BUILD-RECEIPT.json'), original = JSON.parse(readFileSync(filename));
  writeFileSync(filename, JSON.stringify({ ...original, qualification: 'local_candidate' }));
  assert.throws(() => verifyWorkflowQualification(installation, 'available-target'), /payload qualification differs/);
  assert.deepEqual(verifyWorkflowQualification(installation, 'diagnostic'), { qualification: 'diagnostic-scripted-replay-not-final-acceptance', acceptance_eligible: false });
  assert.throws(() => verifyWorkflowQualification(installation, 'accepted'), /qualification/);
}));

test('runtime reader scope is explicit and available execution does not enable diagnostic input admission', () => {
  assert.deepEqual(workflowRuntimeInputOptions('available-target'), { allowDiagnostic: false, allowAvailable: true });
  assert.deepEqual(workflowRuntimeInputOptions('candidate'), { allowDiagnostic: false, allowAvailable: false });
  assert.deepEqual(workflowRuntimeInputOptions('diagnostic'), { allowDiagnostic: true, allowAvailable: false });
  assert.throws(() => workflowRuntimeInputOptions('accepted'), /Unknown workflow runtime input scope/);
});

test('workflow subject preserves exact installation binding and the separate source-replay role', () => fixture(({ selected, payload }) => {
  const result = verifyWorkflowRuntimeSubject(selected, payload, 'available-target');
  assert.equal(result.source_replay_performed, false); assert.equal(result.source_replay_required, true);
  assert.deepEqual(result.source_coverage_receipt, selected.available_bindings.source_coverage_receipt);
  assert.deepEqual(result.offline_inputs, selected.candidate_receipt);
  assert.equal(Object.hasOwn(result, 'complete_available_shipped_component_coverage'), false);
  assert.equal(Object.hasOwn(result, 'acceptance_eligible'), false);
  for (const mutate of [
    value => { value.candidate.qualification = 'preacceptance-runtime-inputs'; },
    value => { value.candidate.source_sha256 = 'a'.repeat(64); },
    value => { value.candidate.runtime_lock_sha256 = 'b'.repeat(64); },
    value => { value.formats.native.inventory_sha256 = 'c'.repeat(64); },
    value => { delete value.available_bindings; },
    value => { value.available_bindings.source_replay_performed = true; },
    value => { value.available_bindings.source_replay_required = false; },
    value => { delete value.available_bindings.source_coverage_receipt; },
  ]) { const changed = structuredClone(selected); mutate(changed); assert.throws(() => verifyWorkflowRuntimeSubject(changed, payload, 'available-target'), /scope|source|runtime|installation|byte bindings/i); }
  assert.throws(() => verifyWorkflowRuntimeSubject(selected, payload, 'candidate'), /explicit evidence scope/);
  assert.throws(() => verifyWorkflowRuntimeSubject(selected, payload, 'diagnostic'), /explicit evidence scope/);
}));

test('actual available archive and material tampering cannot enter the workflow consumer', () => fixture(({ candidateRoot, manifest, payload, selected }) => {
  assert.doesNotThrow(() => verifyWorkflowRuntimeSubject(selected, payload, 'available-target'));
  for (const id of ['npm', 'corresponding-source-0000', 'component-source-coverage']) {
    const filename = path.join(candidateRoot, manifest.artifacts.find(row => row.id === id).path), original = readFileSync(filename); writeFileSync(filename, 'tampered retained input');
    assert.throws(() => verifyAvailableCandidateBindings(candidateRoot, manifest), /receipt mismatch/); writeFileSync(filename, original);
  }
}));

test('real workflow CLI refuses available scope without its explicit inputs before creating profiles or launching a provider', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-workflow-available-cli-')), output = path.join(root, 'report.json');
  try {
    const result = spawnSync(process.execPath, [path.resolve('scripts/quality/run-workflow-evals.mjs'), '--installation', path.join(root, 'not-an-installation'), '--host', 'codex', '--engine', 'docker', '--output', output, '--qualification', 'available-target'], { encoding: 'utf8', timeout: 30000 });
    assert.equal(result.error, undefined); assert.equal(result.status, 1);
    assert.match(result.stderr, /Available-target workflows require explicit runtime inputs, locked Python and a closed QA profile/);
    assert.equal(existsSync(output), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
