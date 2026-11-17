#!/usr/bin/env node
/** Verify local candidates and signed release evidence without publishing. */
import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { readRecordedBytes, sha256, sourceReceipt, verifyRecordedFile } from './candidate.mjs';
import { verifyOciArchive } from './oci.mjs';
import { validateAcceptanceInventory, reconcileSuiteInventory } from './acceptance.mjs';
import { isAcceptanceSource, verifyAcceptanceDiscovery, verifyLocalAcceptanceDiscovery, acceptanceRequirements } from './discover-acceptance.mjs';
import { verifyArtifactContent } from './artifact-content.mjs';
import { verifyCandidateSources } from './source-artifacts.mjs';
import { verifyBetaAcceptance } from './beta-acceptance.mjs';

const HEX = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const ID = /^[a-z0-9][a-z0-9._-]*$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function requireCondition(condition, message) { if (!condition) throw new Error(message); }
export function verifySignatureEnvelope(bytes, signature, policy, purpose = 'release-candidate') {
  requireCondition(policy?.schema_version === 1 && policy.purpose === purpose && Array.isArray(policy.keys), 'Invalid trust policy.');
  requireCondition(signature && typeof signature.key_id === 'string' && typeof signature.signature === 'string' && BASE64.test(signature.signature), 'Invalid signature envelope.');
  const keys = policy.keys.filter(key => key.id === signature.key_id && key.status === 'active' && key.algorithm === 'ed25519');
  requireCondition(keys.length === 1, 'No unique active trusted release key.');
  const key = createPublicKey(keys[0].public_key_pem);
  requireCondition(key.asymmetricKeyType === 'ed25519', 'Unsupported release signing key.');
  const raw = Buffer.from(signature.signature, 'base64');
  requireCondition(raw.length === 64 && verifySignature(null, bytes, key, raw), 'Release signature verification failed.');
  return keys[0].id;
}

export function candidateSignaturePolicy(candidate, policy) {
  if (candidate?.signing_profile === undefined) return policy;
  const beta = policy?.publisher_beta;
  requireCondition(policy?.schema_version === 1 && policy.purpose === 'release-candidate' &&
    candidate.signing_profile === 'publisher-beta' && candidate.status === 'accepted_candidate' &&
    /^\d+\.\d+\.\d+-beta\.\d+$/.test(candidate.product_version ?? '') && beta?.product_version === candidate.product_version,
  'Publisher beta signing is unavailable for this candidate version.');
  requireCondition(Array.isArray(beta.keys) && beta.keys.length === 1, 'Publisher beta signing requires exactly one trusted release key.');
  return { ...policy, keys: beta.keys };
}

/** Canonical subjects signed by an independently trusted evidence producer. */
export function evidenceSubjects(source, candidate) {
  const tests = source.files.filter(item => isAcceptanceSource(item.path)).map(item => ({ path: item.path, sha256: item.sha256, size: item.size })).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  requireCondition(tests.length > 0, 'Test inventory is empty.');
  const artifacts = candidate.artifacts.map(item => ({ id: item.id, sha256: item.sha256, size: item.size })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return { source_tree_sha256: source.sha256, test_inventory_sha256: sha256(Buffer.from(JSON.stringify(tests))), artifact_set_sha256: sha256(Buffer.from(JSON.stringify(artifacts))), runtime_lock_sha256: candidate.runtime_lock_sha256 };
}

export function verifyLocalCandidate(root, candidate) {
  requireCondition(candidate?.schema_version === 1 && candidate.status === 'local_candidate' && candidate.production_ready === false, 'Invalid local candidate status.');
  requireCondition(typeof candidate.product_version === 'string' && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(candidate.product_version), 'Invalid product version.');
  requireCondition(HEX.test(candidate.source_tree_sha256 ?? ''), 'Missing source tree fingerprint.');
  requireCondition(sourceReceipt(root).sha256 === candidate.source_tree_sha256, 'Source tree changed after candidate preparation.');
  requireCondition(Array.isArray(candidate.artifacts) && candidate.artifacts.length > 0, 'Candidate has no artifacts.');
  const ids = new Set();
  for (const artifact of candidate.artifacts) {
    requireCondition(typeof artifact.id === 'string' && ID.test(artifact.id) && !ids.has(artifact.id), 'Invalid or duplicate artifact ID.');
    ids.add(artifact.id);
    verifyRecordedFile(root, artifact);
  }
  return { valid: true, status: 'local_candidate', production_ready: false, artifact_count: ids.size };
}

function gitEnvironment() {
  return { PATH: process.env.PATH ?? '', ...(process.platform === 'win32' && process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}), LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null', GIT_NO_REPLACE_OBJECTS: '1', GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0' };
}

function verifyProtectedCommit(root, commit, protectedRef) {
  if (typeof protectedRef !== 'string' || !/^refs\/remotes\/[A-Za-z0-9._/-]+$/.test(protectedRef) || protectedRef.includes('..')) return false;
  const env = gitEnvironment();
  const run = args => spawnSync('git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', ...args], { cwd: root, encoding: 'utf8', timeout: 15_000, maxBuffer: 16 * 1024 * 1024, env });
  const type = run(['cat-file', '-t', commit]);
  if (type.error || type.status !== 0 || type.stdout.trim() !== 'commit') return false;
  const ancestry = run(['merge-base', '--is-ancestor', commit, protectedRef]);
  return !ancestry.error && ancestry.status === 0;
}

export function verifySourceMatchesCommit(root, commit, inventory, runGit = spawnSync) {
  const options = { cwd: root, timeout: 30_000, maxBuffer: 128 * 1024 * 1024, env: gitEnvironment() };
  const tree = runGit('git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', 'ls-tree', '-r', '--full-tree', '-z', commit], options);
  if (tree.error || tree.status !== 0) return false;
  const entries = new Map();
  for (const item of tree.stdout.toString('utf8').split('\0').filter(Boolean)) {
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t([^\r\n]+)$/.exec(item);
    if (!match || entries.has(match[3])) return false;
    entries.set(match[3], { mode: match[1], oid: match[2] });
  }
  if (entries.size !== inventory.files.length || inventory.files.some(file => !entries.has(file.path) || /[\r\n]/.test(file.path))) return false;
  // A frozen runtime inventory can exceed Git's usual command buffer. Check
  // batches of the actual inventoried sizes without buffering the entire tree.
  const batchBytes = 16 * 1024 * 1024;
  for (let start = 0; start < inventory.files.length;) {
    let end = start, expectedBytes = 0;
    do { expectedBytes += inventory.files[end++].size + 128; }
    while (end < inventory.files.length && expectedBytes + inventory.files[end].size + 128 <= batchBytes);
    const batch = inventory.files.slice(start, end);
    const input = batch.map(file => `${commit}:${file.path}\n`).join('');
    const blobs = runGit('git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', 'cat-file', '--batch'], { ...options, input, maxBuffer: expectedBytes });
    if (blobs.error || blobs.status !== 0) return false;
    let position = 0;
    for (const file of batch) {
      const newline = blobs.stdout.indexOf(10, position); if (newline < 0) return false;
      const header = blobs.stdout.subarray(position, newline).toString('ascii');
      const match = /^([0-9a-f]{40}) blob (\d+)$/.exec(header); if (!match) return false;
      const expected = entries.get(file.path); const size = Number(match[2]);
      if (match[1] !== expected.oid || !Number.isSafeInteger(size) || size !== file.size || (expected.mode === '100755') !== file.executable) return false;
      position = newline + 1; if (position + size >= blobs.stdout.length) return false;
      if (sha256(blobs.stdout.subarray(position, position + size)) !== file.sha256 || blobs.stdout[position + size] !== 10) return false;
      position += size + 1;
    }
    if (position !== blobs.stdout.length) return false;
    start = end;
  }
  return sourceReceipt(root).sha256 === inventory.sha256;
}

export function verifyProductionCandidateInternal(root, bytes, signature, policy, requirements, checks = {}, inventory = null) {
  const candidate = JSON.parse(Buffer.from(bytes).toString('utf8'));
  requireCondition(candidate?.schema_version === 1 && candidate.status === 'accepted_candidate', 'Only an accepted candidate is eligible.');
  const signingPolicy = candidateSignaturePolicy(candidate, policy);
  const publisherBeta = candidate.signing_profile === 'publisher-beta';
  const releaseSigner = verifySignatureEnvelope(Buffer.from(bytes), signature, signingPolicy);
  requireCondition(COMMIT.test(candidate.source_commit ?? '') && COMMIT.test(candidate.publisher_commit ?? ''), 'Genuine source and publisher commits are required.');
  const checkCommit = checks.verifyCommit ?? verifyProtectedCommit;
  requireCondition(checkCommit(root, candidate.source_commit, policy.protected_ref) && checkCommit(root, candidate.publisher_commit, policy.protected_ref), 'Source and publisher commits must exist on the protected source ancestry.');
  const source = inventory ?? sourceReceipt(root);
  requireCondition(HEX.test(candidate.source_tree_sha256 ?? '') && source.sha256 === candidate.source_tree_sha256, 'Source inventory does not match candidate.');
  requireCondition((checks.verifySource ?? verifySourceMatchesCommit)(root, candidate.source_commit, source), 'Source inventory does not match the verified commit.');
  const sourceFile = (name, maximum) => { const item = source.files.find(file => file.path === name); requireCondition(item, `Required source file missing: ${name}`); return readRecordedBytes(root, item, maximum); };
  const candidateSchema = JSON.parse(sourceFile('release/schema/candidate.schema.json').toString('utf8'));
  const ajv = new Ajv2020({ strict: true });
  const validateCandidate = ajv.compile(candidateSchema);
  requireCondition(validateCandidate(candidate), 'Candidate does not match its release schema.');
  const packageInfo = JSON.parse(sourceFile('package.json').toString('utf8'));
  const productText = sourceFile('release/product.yaml').toString('utf8');
  const productVersions = [...productText.matchAll(/^version:\s*([0-9A-Za-z.+-]+)\s*$/gm)];
  requireCondition(typeof candidate.product_version === 'string' && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(candidate.product_version) && packageInfo.version === candidate.product_version && productVersions.length === 1 && productVersions[0][1] === candidate.product_version, 'Product version does not match source identity.');
  requireCondition(HEX.test(candidate.runtime_lock_sha256 ?? ''), 'Missing runtime lock digest.');
  const sourceRuntime = source.files.find(file => file.path === 'runtime/runtime.lock.json');
  requireCondition(candidate.runtime_lock_path === 'runtime/runtime.lock.json' && sourceRuntime && sourceRuntime.sha256 === candidate.runtime_lock_sha256 && sourceRuntime.size === candidate.runtime_lock_size, 'Runtime lock does not match the source inventory.');
  const runtime = { path: candidate.runtime_lock_path, sha256: candidate.runtime_lock_sha256, size: candidate.runtime_lock_size };
  const lock = JSON.parse(readRecordedBytes(root, runtime).toString('utf8'));
  requireCondition(lock.product_version === candidate.product_version && lock.state === 'frozen' && lock.packs && ['core', 'render'].every(pack => /^sha256:[0-9a-f]{64}$/.test(lock.packs[pack]?.index_digest ?? '') && ['linux/amd64', 'linux/arm64'].every(platform => /^sha256:[0-9a-f]{64}$/.test(lock.packs[pack]?.platforms?.[platform] ?? ''))), 'Frozen core/render index and platform digests are required.');
  requireCondition(requirements?.schema_version === 1 && Array.isArray(requirements.required_suites) && requirements.required_suites.length > 0 && Array.isArray(requirements.required_artifacts) && requirements.required_artifacts.length > 0 && [...requirements.required_suites, ...requirements.required_artifacts].every(id => typeof id === 'string' && ID.test(id)), 'Release requirements are invalid.');
  requireCondition(new Set(requirements.required_suites).size === requirements.required_suites.length && new Set(requirements.required_artifacts).size === requirements.required_artifacts.length, 'Release requirements contain duplicates.');
  requireCondition(Array.isArray(candidate.artifacts) && Array.isArray(candidate.evidence), 'Artifacts and evidence are required.');
  const artifactIds = new Set();
  for (const item of candidate.artifacts) {
    requireCondition(typeof item.id === 'string' && ID.test(item.id) && !artifactIds.has(item.id), 'Invalid or duplicate artifact ID.');
    artifactIds.add(item.id);
    verifyRecordedFile(root, item);
    if (!publisherBeta) verifySignatureEnvelope(Buffer.from(`ud-agent-artifact-v1\0${item.sha256}`), item.signature, policy);
  }
  for (const id of requirements.required_artifacts) requireCondition(artifactIds.has(id), `Required artifact missing: ${id}`);
  for (const pack of ['core', 'render']) {
    const artifact = candidate.artifacts.find(item => item.id === `${pack}-oci-index`);
    if (requirements.required_artifacts.includes(`${pack}-oci-index`)) requireCondition(artifact?.oci_digest === lock.packs[pack].index_digest, `OCI index digest differs from runtime lock: ${pack}`);
  }
  // The signed source locks the exact ordered sidecars. Partial corresponding-
  // source collections remain useful locally but cannot authorize promotion.
  verifyCandidateSources(root, candidate, { complete: true });
  const betaAcceptance = requirements.publisher_beta_acceptance;
  const suiteCount = publisherBeta && betaAcceptance?.product_version === candidate.product_version
    ? verifyBetaAcceptance(root, candidate, betaAcceptance)
    : verifyDiscoveredAcceptance({ root, candidate, policy, requirements, signingPolicy, publisherBeta, releaseSigner, source, sourceFile, ajv });
  for (const pack of ['core', 'render']) {
    if (!requirements.required_artifacts.includes(`${pack}-oci-index`)) continue;
    const artifact = candidate.artifacts.find(item => item.id === `${pack}-oci-index`);
    verifyOciArchive(path.join(root, ...artifact.path.split('/')), lock.packs[pack].index_digest, lock.packs[pack].platforms, artifact, lock.packs[pack].images);
  }
  const verifyContent = checks.verifyArtifactContent ?? verifyArtifactContent;
  const verifierRuntime = checks.verifyInterpreter?.(root, source);
  for (const artifact of candidate.artifacts) verifyContent(root, artifact, source, candidate.runtime_lock_sha256, candidate, verifierRuntime);
  requireCondition(sourceReceipt(root).sha256 === source.sha256, 'Source changed during candidate verification.');
  return { valid: true, signer: releaseSigner, ...(publisherBeta ? { signing_profile: candidate.signing_profile } : {}), artifact_count: artifactIds.size, suite_count: suiteCount, runtime_lock_sha256: runtime.sha256 };
}

function verifyDiscoveredAcceptance({ root, candidate, policy, requirements, signingPolicy, publisherBeta, releaseSigner, source, sourceFile, ajv }) {
  const validateEvidence = ajv.compile(JSON.parse(sourceFile('release/schema/evidence.schema.json').toString('utf8')));
  const validateDiscovery = ajv.compile(JSON.parse(sourceFile('release/schema/mutation-discovery.schema.json').toString('utf8')));
  const acceptanceInventory = JSON.parse(sourceFile('quality/acceptance-inventory.json', 256 * 1024 * 1024).toString('utf8'));
  const selectedRequirements = acceptanceRequirements(requirements, acceptanceInventory);
  if (acceptanceInventory.profile === 'bounded' && selectedRequirements.mutation_profiles?.bounded?.signing_profile === 'publisher-beta') {
    requireCondition(publisherBeta, 'This bounded acceptance profile requires publisher-beta authority.');
  }
  const acceptance = validateAcceptanceInventory(acceptanceInventory, selectedRequirements.required_suites);
  if (publisherBeta) requireCondition(acceptanceInventory.profile === 'bounded' && acceptance.has('mutation-bounded'), 'Publisher beta signing requires the complete bounded mutation corpus.');
  // The publisher signs the manifest, which binds the source inventory, and
  // that inventory binds the complete discovery proof and its generation bytes.
  const inventoryAuthority = publisherBeta ? verifyLocalAcceptanceDiscovery(root, acceptanceInventory, requirements) : verifyAcceptanceDiscovery(root, acceptanceInventory, requirements, {
    verifyBackendDiscovery: (discoveryBytes, discoverySignature) => {
      requireCondition(validateDiscovery(JSON.parse(discoveryBytes.toString('utf8'))), 'Mutation discovery does not match its source-bound schema.');
      const signer = verifySignatureEnvelope(discoveryBytes, discoverySignature, { schema_version: 1, purpose: 'mutation-inventory', keys: policy.inventory_keys }, 'mutation-inventory');
      const inventoryKey = policy.inventory_keys.find(key => key.id === signer);
      const inventoryPublic = createPublicKey(inventoryKey.public_key_pem).export({ type: 'spki', format: 'der' });
      const releasePublic = createPublicKey(policy.keys.find(key => key.id === releaseSigner).public_key_pem).export({ type: 'spki', format: 'der' });
      requireCondition(signer !== releaseSigner && !inventoryPublic.equals(releasePublic), 'Mutation inventory authority must be independent of release signing.');
      return signer;
    },
  });
  const subjects = evidenceSubjects(source, candidate);
  const evidencePolicy = { schema_version: 1, purpose: 'test-evidence', keys: policy.evidence_keys };
  requireCondition(publisherBeta || Array.isArray(policy.evidence_keys) && policy.evidence_keys.length > 0, 'Independent evidence trust policy is missing.');
  const releasePublic = createPublicKey(signingPolicy.keys.find(key => key.id === releaseSigner).public_key_pem).export({ type: 'spki', format: 'der' });
  const evidenceIds = new Set();
  for (const item of candidate.evidence) {
    requireCondition(typeof item.suite_id === 'string' && ID.test(item.suite_id) && !evidenceIds.has(item.suite_id), 'Invalid or duplicate evidence ID.');
    evidenceIds.add(item.suite_id);
    const reportBytes = readRecordedBytes(root, item);
    let evidenceSigner, evidencePublic;
    if (!publisherBeta) {
      evidenceSigner = verifySignatureEnvelope(reportBytes, item.signature, evidencePolicy, 'test-evidence');
      const evidenceKey = policy.evidence_keys.find(key => key.id === evidenceSigner);
      evidencePublic = createPublicKey(evidenceKey.public_key_pem).export({ type: 'spki', format: 'der' });
      requireCondition(evidenceSigner !== releaseSigner && !evidencePublic.equals(releasePublic), 'Evidence must use an independent signing key.');
      for (const signer of inventoryAuthority.inventorySigners?.get(item.suite_id) ?? []) {
        const inventoryPublic = createPublicKey(policy.inventory_keys.find(key => key.id === signer).public_key_pem).export({ type: 'spki', format: 'der' });
        requireCondition(signer !== evidenceSigner && !inventoryPublic.equals(evidencePublic), 'Mutation inventory authority must be independent of outcome signing.');
      }
    }
    const report = JSON.parse(reportBytes.toString('utf8'));
    requireCondition(validateEvidence(report), `Evidence does not match its schema: ${item.suite_id}`);
    requireCondition(acceptance.has(item.suite_id), `Evidence suite is not in the frozen inventory: ${item.suite_id}`);
    requireCondition(report.suite_id === item.suite_id && report.verdict === 'passed' && Number.isSafeInteger(report.executed) && report.executed > 0 && report.skipped === 0 && report.errors === 0, `Required suite has no clean execution: ${item.suite_id}`);
    for (const [name, value] of Object.entries(subjects)) requireCondition(report[name] === value, `Evidence subject mismatch: ${item.suite_id}/${name}`);
    const testPaths = new Set(source.files.filter(file => isAcceptanceSource(file.path)).map(file => file.path));
    requireCondition(Array.isArray(report.tests) && report.tests.length === report.executed, `Evidence test inventory mismatch: ${item.suite_id}`);
    const testIds = new Set();
    for (const test of report.tests) {
      requireCondition(test && typeof test.id === 'string' && test.id.length > 0 && test.id.length <= 512 && !testIds.has(test.id) && test.status === 'passed' && testPaths.has(test.source), `Invalid or unbound test evidence: ${item.suite_id}`);
      testIds.add(test.id);
    }
    if (item.suite_id.startsWith('mutation-')) {
      for (const name of ['survivors', 'uncovered', 'timeouts', 'invalid', 'missing']) requireCondition(report[name] === 0, `Unresolved mutation result: ${item.suite_id}/${name}`);
      requireCondition(Number.isSafeInteger(report.killed) && report.killed > 0 && Number.isSafeInteger(report.scheduled) && report.scheduled > 0 && Array.isArray(report.equivalent_exceptions), `Mutation counts are invalid: ${item.suite_id}`);
      requireCondition(!publisherBeta || report.equivalent_exceptions.length === 0, `Publisher beta requires an assertion kill for every scheduled mutant: ${item.suite_id}`);
      requireCondition(Array.isArray(report.mutants) && report.mutants.length === report.scheduled, `Mutation outcome inventory missing: ${item.suite_id}`);
      const sourceHashes = new Map(source.files.filter(file => item.suite_id === 'mutation-bounded' || /^(?:packages|workers|scripts|runtime|quality|contracts|evals|\.github)\//.test(file.path)).map(file => [file.path, file.sha256]));
      const mutants = new Map(); let kills = 0;
      for (const mutant of report.mutants) {
        requireCondition(mutant && typeof mutant.id === 'string' && mutant.id.length > 0 && mutant.id.length <= 1024 && !mutants.has(mutant.id) && sourceHashes.get(mutant.file) === mutant.source_sha256 && HEX.test(mutant.source_sha256 ?? '') && ['killed', 'equivalent'].includes(mutant.status), `Invalid mutation outcome: ${item.suite_id}`);
        if (mutant.status === 'killed') {
          requireCondition(mutant.failure_kind === 'assertion' && Array.isArray(mutant.killed_by) && mutant.killed_by.length > 0 && new Set(mutant.killed_by).size === mutant.killed_by.length && mutant.killed_by.every(id => testIds.has(id)), `Mutation kill lacks clean test evidence: ${item.suite_id}/${mutant.id}`);
          kills++;
        }
        mutants.set(mutant.id, mutant);
      }
      requireCondition(kills === report.killed, `Mutation kill count mismatch: ${item.suite_id}`);
      const reviewed = new Set();
      for (const exception of report.equivalent_exceptions) {
        const mutant = mutants.get(exception?.id);
        requireCondition(mutant?.status === 'equivalent' && !reviewed.has(exception.id) && exception.file === mutant.file && exception.source_sha256 === mutant.source_sha256 && exception.definition_sha256 === mutant.definition_sha256 && HEX.test(exception.definition_sha256 ?? '') && typeof exception.author === 'string' && exception.author.trim().length > 0 && typeof exception.reviewer === 'string' && exception.reviewer.trim().length > 0 && exception.reviewer !== exception.author && typeof exception.reason === 'string' && exception.reason.trim().length >= 40 && exception.evidence && typeof exception.evidence === 'object', `Unreviewed equivalent mutant: ${item.suite_id}`);
        const reviewBytes = readRecordedBytes(root, exception.evidence);
        const reviewSigner = verifySignatureEnvelope(reviewBytes, exception.evidence.signature, { schema_version: 1, purpose: 'mutation-review', keys: policy.review_keys }, 'mutation-review');
        const reviewKey = policy.review_keys.find(key => key.id === reviewSigner);
        const reviewPublic = createPublicKey(reviewKey.public_key_pem).export({ type: 'spki', format: 'der' });
        requireCondition(reviewSigner === exception.reviewer && reviewSigner !== releaseSigner && reviewSigner !== evidenceSigner && !reviewPublic.equals(releasePublic) && !reviewPublic.equals(evidencePublic), `Mutation review signer is not independent: ${item.suite_id}/${exception.id}`);
        const review = JSON.parse(reviewBytes.toString('utf8'));
        requireCondition(review.verdict === 'equivalent' && review.id === exception.id && review.file === exception.file && review.source_sha256 === exception.source_sha256 && review.definition_sha256 === exception.definition_sha256 && review.author === exception.author && review.reviewer === exception.reviewer && review.reason === exception.reason, `Mutation review does not match outcome: ${item.suite_id}/${exception.id}`);
        reviewed.add(exception.id);
      }
      requireCondition(report.scheduled === report.killed + report.equivalent_exceptions.length, `Mutation inventory incomplete: ${item.suite_id}`);
      requireCondition([...mutants.values()].every(mutant => mutant.status !== 'equivalent' || reviewed.has(mutant.id)), `Mutation equivalent review missing: ${item.suite_id}`);
    }
    reconcileSuiteInventory(acceptance.get(item.suite_id), report);
  }
  for (const id of selectedRequirements.required_suites) requireCondition(evidenceIds.has(id), `Required suite missing: ${id}`);
  return evidenceIds.size;
}
