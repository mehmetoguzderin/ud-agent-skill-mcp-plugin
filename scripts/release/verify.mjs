#!/usr/bin/env node
/** Verify local candidates and source-bound signed release evidence. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readRecordedBytes, sourceReceipt } from './candidate.mjs';
import { candidateSignaturePolicy, verifyProductionCandidateInternal, verifySignatureEnvelope } from './verify-internal.mjs';
export { evidenceSubjects, verifyLocalCandidate, verifySourceMatchesCommit } from './verify-internal.mjs';
import { verifyLocalCandidate } from './verify-internal.mjs';
import { verifyPublisherAuthority } from './publisher-authority.mjs';
import { preflightActualComponentCoverage, verifyActualComponentClosure } from './component-closure.mjs';
import { closeReleaseInterpreter, preflightReleaseInterpreter, verifyReleaseInterpreter } from './verifier-runtime.mjs';

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

// These are read from the same source inventory later compared with the
// protected commit; callers cannot substitute policy, requirements or checks.
export function readSourceBoundReleaseConfiguration(root, inventory) {
  const read = name => {
    const receipt = inventory.files.find(item => item.path === name);
    if (!receipt) throw new Error(`Required source file missing: ${name}`);
    return JSON.parse(readRecordedBytes(root, receipt).toString('utf8'));
  };
  return { policy: read('release/trust/policy.json'), requirements: read('quality/requirements.json') };
}

export function verifyProductionCandidate(root, bytes, signature) {
  bytes = Buffer.from(bytes);
  const inventory = sourceReceipt(root);
  const { policy, requirements } = readSourceBoundReleaseConfiguration(root, inventory);
  // Authenticate before even the bounded presence preflight. The complete
  // internal gate independently rechecks this envelope and protected ancestry
  // before any component subprocess or archive replay can run.
  const candidate = JSON.parse(bytes.toString('utf8'));
  verifySignatureEnvelope(bytes, signature, candidateSignaturePolicy(candidate, policy));
  preflightActualComponentCoverage(candidate, inventory, requirements);
  preflightReleaseInterpreter(root, inventory);
  let runtime;
  try {
    const result = verifyProductionCandidateInternal(root, bytes, signature, policy, requirements, { verifyInterpreter: (trustedRoot, trustedSource) => { runtime = verifyReleaseInterpreter(trustedRoot, trustedSource); return runtime; } }, inventory);
    verifyActualComponentClosure(root, candidate, inventory, runtime);
    verifyPublisherAuthority(root, candidate, inventory, policy);
    return result;
  } finally { closeReleaseInterpreter(runtime); }
}

function main(args) {
  if (args.length !== 2 || !['--local', '--production'].includes(args[0])) throw new Error('Usage: verify.mjs --local|--production <candidate.json>');
  const manifestPath = path.resolve(args[1]);
  const bytes = readFileSync(manifestPath);
  if (args[0] === '--local') return verifyLocalCandidate(defaultRoot, JSON.parse(bytes.toString('utf8')));
  const signature = JSON.parse(readFileSync(manifestPath + '.sig.json', 'utf8'));
  return verifyProductionCandidate(defaultRoot, bytes, signature);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(main(process.argv.slice(2)))); }
  catch (error) { console.error(`Release verification failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; }
}
