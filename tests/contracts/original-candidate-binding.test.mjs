import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { bindOriginalCandidate } from '../../scripts/quality/original-candidate-binding.mjs';
import { runOriginalAcceptance } from '../../scripts/quality/original-acceptance.mjs';
import { fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { availableOriginalCandidate } from '../fixtures/available-original-candidate.mjs';

function fixture(action) {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-original-binding-')), source = path.join(base, 'source'), candidateRoot = path.join(base, 'external-candidate');
  mkdirSync(path.join(source, 'tests'), { recursive: true }); writeFileSync(path.join(source, 'tests/unit.test.mjs'), 'Original immutable test source.');
  // The fixture inherits the native CI compiler selection; bind it to the
  // same source declarations before the candidate source snapshot is frozen.
  mkdirSync(path.join(source, 'quality'), { recursive: true });
  for (const name of ['rust-toolchain.toml', 'quality/toolchain.lock.json']) writeFileSync(path.join(source, name), readFileSync(new URL('../../' + name, import.meta.url)));
  try { const held = availableOriginalCandidate(source, candidateRoot); action({ ...held, base }); }
  finally { rmSync(base, { recursive: true, force: true }); }
}

test('original subjects bind an external available packet without claiming source replay or full-release acceptance', () => fixture(({ sourceRoot, candidateRoot, manifest }) => {
  const result = bindOriginalCandidate(sourceRoot, { candidate: manifest, candidateRoot });
  assert.equal(result.qualification, 'available-target-original-candidate-byte-bindings-only'); assert.equal(result.acceptance_eligible, false); assert.equal(result.production_ready, false);
  assert.equal(result.candidate_bindings.target_execution_eligible, true); assert.equal(result.candidate_bindings.source_replay_performed, false); assert.equal(result.candidate_bindings.source_replay_required, true);
  assert.equal(result.subjects.source_tree_sha256, manifest.source_tree_sha256); assert.equal(result.subjects.runtime_lock_sha256, manifest.runtime_lock_sha256);
  const expected = manifest.artifacts.map(({ id, sha256, size }) => ({ id, sha256, size })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  assert.equal(result.subjects.artifact_set_sha256, sha256(JSON.stringify(expected)));
  assert.equal(result.candidate_manifest.sha256, fileReceipt(candidateRoot, 'available-candidate.json').sha256);
  assert.equal(Object.hasOwn(result.candidate_bindings, 'complete_available_shipped_component_coverage'), false);
  const reordered = Object.fromEntries(Object.entries(manifest).reverse());
  assert.deepEqual(bindOriginalCandidate(sourceRoot, { candidate: reordered, candidateRoot }), result);
}));

test('an artifact root without a candidate rejects before collecting or executing original tests', () => fixture(({ sourceRoot, candidateRoot, base }) => {
  const report = runOriginalAcceptance(sourceRoot, { output: path.join(base, 'rejected'), python: process.execPath, cargo: process.execPath, candidateRoot });
  assert.equal(report.status, 'failed-or-incomplete'); assert.equal(report.executed, 0); assert.match(report.reason, /root requires a candidate manifest/);
  assert.deepEqual(report.commands, []); assert.equal(report.unsigned_evidence, undefined);
}));

test('available original binding requires explicit root, original manifest, final material phase and complete scope', () => fixture(({ sourceRoot, candidateRoot, manifest }) => {
  assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: manifest }), /explicit absolute candidate root/);
  assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: manifest, candidateRoot: '.' }), /explicit absolute candidate root/);
  const changed = structuredClone(manifest); changed.scope.pending_targets = [];
  assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: changed, candidateRoot }), /retained manifest/);
  for (const mutate of [m => { m.material_phase = 'provisional'; }, m => { m.scope.pending_targets = []; }, m => { m.production_ready = true; }]) {
    const bad = structuredClone(manifest); mutate(bad); writeFileSync(path.join(candidateRoot, 'available-candidate.json'), JSON.stringify(bad));
    assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: bad, candidateRoot }), /final source material|pending native scope|actual local source/);
  }
}));

test('original binding rejects stale executing sources and runtime, changed artifact bytes and tampered physical material', () => fixture(({ sourceRoot, candidateRoot, manifest }) => {
  for (const name of ['tests/unit.test.mjs', 'runtime/runtime.lock.json']) {
    const file = path.join(sourceRoot, name), original = readFileSync(file); writeFileSync(file, 'changed');
    assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: manifest, candidateRoot }), /actual local source|runtime lock/); writeFileSync(file, original);
  }
  for (const id of ['npm', 'corresponding-source-0000', 'component-source-coverage']) {
    const file = path.join(candidateRoot, manifest.artifacts.find(row => row.id === id).path), original = readFileSync(file); writeFileSync(file, 'changed candidate bytes');
    assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: manifest, candidateRoot }), /receipt mismatch/); writeFileSync(file, original);
  }
  const file = path.join(candidateRoot, 'native-installation/RELEASE-CANDIDATE.md'); writeFileSync(file, 'changed installed bytes');
  assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: manifest, candidateRoot }), /complete original inventory/);
}));

test('legacy local candidates retain source-root artifact resolution and permit explicit external artifact roots', () => fixture(({ sourceRoot, candidateRoot, manifest }) => {
  const name = 'fixture.bin'; writeFileSync(path.join(sourceRoot, name), 'actual local artifact');
  const local = { schema_version: 1, status: 'local_candidate', production_ready: false, source_tree_sha256: manifest.source_tree_sha256, runtime_lock_sha256: manifest.runtime_lock_sha256, artifacts: [{ id: 'local-fixture', ...fileReceipt(sourceRoot, name) }] };
  const result = bindOriginalCandidate(sourceRoot, { candidate: local }); assert.equal(result.qualification, 'local-original-candidate-byte-bindings-only'); assert.equal(result.acceptance_eligible, false); assert.equal(result.candidate_bindings, undefined);
  writeFileSync(path.join(candidateRoot, name), 'actual local artifact'); assert.deepEqual(bindOriginalCandidate(sourceRoot, { candidate: local, candidateRoot }), result);
  writeFileSync(path.join(candidateRoot, name), 'tampered'); assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: local, candidateRoot }), /receipt mismatch/);
  const duplicate = structuredClone(local); duplicate.artifacts.push(duplicate.artifacts[0]); assert.throws(() => bindOriginalCandidate(sourceRoot, { candidate: duplicate }), /duplicate/);
}));
