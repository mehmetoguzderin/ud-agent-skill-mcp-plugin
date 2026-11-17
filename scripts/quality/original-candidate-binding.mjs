/** Candidate byte subjects shared by original and mutation evidence producers. */
import assert from 'node:assert/strict';
import path from 'node:path';
import { realpathSync } from 'node:fs';
import { fileReceipt, readRecordedBytes, sourceReceipt, verifyRecordedFile } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
import { verifyAvailableCandidateBindings } from '../release/available-candidate.mjs';
import { evidenceSubjects } from '../release/verify-internal.mjs';

/** This verifies bytes, never grants publisher authority or certifies source replay.
 * @param {string} sourceRoot
 * @param {{candidate?: any, candidateRoot?: string}} [options]
 */
export function bindOriginalCandidate(sourceRoot, { candidate, candidateRoot } = {}) {
  sourceRoot = realpathSync(sourceRoot);
  const source = sourceReceipt(sourceRoot);
  assert.ok((candidate?.schema_version === 1 || candidate?.schema_version === 2 && candidate.qualification === 'available-target-preacceptance') && candidate.production_ready === false && candidate.source_tree_sha256 === source.sha256 && Array.isArray(candidate.artifacts) && candidate.artifacts.length > 0, 'Original evidence candidate is not bound to this actual local source.');
  assert.equal(fileReceipt(sourceRoot, 'runtime/runtime.lock.json').sha256, candidate.runtime_lock_sha256, 'Original evidence runtime lock differs from its actual candidate.');
  if (candidate.qualification === 'available-target-preacceptance') {
    assert.ok(typeof candidateRoot === 'string' && path.isAbsolute(candidateRoot), 'Available original evidence requires an explicit absolute candidate root.');
    const root = realpathSync(candidateRoot), manifest = fileReceipt(root, 'available-candidate.json');
    assert.equal(canonicalJson(JSON.parse(readRecordedBytes(root, manifest, 32 * 1024 ** 2).toString('utf8'))), canonicalJson(candidate), 'Original evidence candidate differs from its retained manifest.');
    const bindings = verifyAvailableCandidateBindings(root, candidate);
    return { subjects: evidenceSubjects(source, candidate), qualification: 'available-target-original-candidate-byte-bindings-only', acceptance_eligible: false, production_ready: false, candidate_manifest: manifest, candidate_bindings: bindings };
  }
  assert.equal(candidate.status, 'local_candidate', 'Original evidence requires a local candidate or explicit available-target preacceptance.');
  if (candidateRoot !== undefined) assert.ok(path.isAbsolute(candidateRoot), 'Original evidence candidate root must be absolute.');
  const root = candidateRoot === undefined ? sourceRoot : realpathSync(candidateRoot), ids = new Set();
  for (const artifact of candidate.artifacts) {
    assert.ok(typeof artifact?.id === 'string' && /^[a-z0-9][a-z0-9._-]*$/.test(artifact.id) && !ids.has(artifact.id), 'Original evidence has an invalid or duplicate candidate artifact.');
    ids.add(artifact.id); verifyRecordedFile(root, artifact);
  }
  return { subjects: evidenceSubjects(source, candidate), qualification: 'local-original-candidate-byte-bindings-only', acceptance_eligible: false, production_ready: false };
}
