import { test } from 'vitest';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { fileReceipt, safeRelative, sourceReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { compileAcceptanceInventory } from '../../scripts/release/discover-acceptance.mjs';
import { discoveryFixture } from './discovery-fixture.mjs';
import { mutationDiscoveryFixture, prepareMutationDiscoveryFixture } from './mutation-discovery-fixture.mjs';
import { evidenceSubjects, verifyLocalCandidate, verifyProductionCandidate as verifyProductionEntry, verifySourceMatchesCommit, readSourceBoundReleaseConfiguration } from '../../scripts/release/verify.mjs';
// Synthetic fixtures use the internal verifier with fake Git ancestry; the
// public production entry never accepts policy, requirements or check overrides.
import { verifyProductionCandidateInternal as verifyProductionCandidate } from '../../scripts/release/verify-internal.mjs';
import { FixtureRegistry, reconcileFixture, promoteFixture } from '../../scripts/release/reconcile.mjs';
import { createOciFixture, fixtureTar } from './oci-fixture.mjs';

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-release-test-'));
  mkdirSync(path.join(root, 'runtime')); mkdirSync(path.join(root, '.artifacts'));
  mkdirSync(path.join(root, 'tests')); writeFileSync(path.join(root, 'tests/fixture.test.mjs'), 'fixture test\n');
  mkdirSync(path.join(root, 'packages')); writeFileSync(path.join(root, 'packages/fixture.js'), 'export const fixture = true;\n');
  mkdirSync(path.join(root, 'release/schema'), { recursive: true });
  const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  copyFileSync(path.join(projectRoot, 'release/schema/candidate.schema.json'), path.join(root, 'release/schema/candidate.schema.json'));
  copyFileSync(path.join(projectRoot, 'release/schema/evidence.schema.json'), path.join(root, 'release/schema/evidence.schema.json'));
  copyFileSync(path.join(projectRoot, 'release/schema/mutation-discovery.schema.json'), path.join(root, 'release/schema/mutation-discovery.schema.json'));
  writeFileSync(path.join(root, 'release/product.yaml'), 'name: ud-agent-skill-mcp-plugin\nversion: 0.1.0-beta.1\n');
  writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '0.1.0-beta.1' }));
  writeFileSync(path.join(root, 'LICENSE'), 'license\n');
  const runtime = { product_version: '0.1.0-beta.1', state: 'frozen', packs: Object.fromEntries(['core', 'render'].map((name, i) => [name, { index_digest: `sha256:${String(i + 1).repeat(64)}`, platforms: { 'linux/amd64': `sha256:${'a'.repeat(64)}`, 'linux/arm64': `sha256:${'b'.repeat(64)}` } }])) };
  writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify(runtime));
  return { root, runtime, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
function record(root, name, bytes) {
  const relative = `.artifacts/${name}`;
  writeFileSync(path.join(root, relative), bytes);
  return fileReceipt(root, relative);
}
function signedFixture({ sourceComplete = true } = {}) {
  const f = fixture();
  const key = generateKeyPairSync('ed25519');
  const evidenceKey = generateKeyPairSync('ed25519');
  const reviewKey = generateKeyPairSync('ed25519');
  const inventoryKey = generateKeyPairSync('ed25519');
  const policy = { schema_version: 1, purpose: 'release-candidate', protected_ref: 'refs/remotes/origin/main', keys: [{ id: 'fixture', status: 'active', algorithm: 'ed25519', public_key_pem: key.publicKey.export({ type: 'spki', format: 'pem' }) }], evidence_keys: [{ id: 'test-runner', status: 'active', algorithm: 'ed25519', public_key_pem: evidenceKey.publicKey.export({ type: 'spki', format: 'pem' }) }], inventory_keys: [{ id: 'inventory-authority', status: 'active', algorithm: 'ed25519', public_key_pem: inventoryKey.publicKey.export({ type: 'spki', format: 'pem' }) }], review_keys: [{ id: 'reviewer', status: 'active', algorithm: 'ed25519', public_key_pem: reviewKey.publicKey.export({ type: 'spki', format: 'pem' }) }] };
  const envelope = bytes => ({ key_id: 'fixture', signature: sign(null, bytes, key.privateKey).toString('base64') });
  const evidenceEnvelope = bytes => ({ key_id: 'test-runner', signature: sign(null, bytes, evidenceKey.privateKey).toString('base64') });
  const inventoryEnvelope = bytes => ({ key_id: 'inventory-authority', signature: sign(null, bytes, inventoryKey.privateKey).toString('base64') });
  const reviewEnvelope = bytes => ({ key_id: 'reviewer', signature: sign(null, bytes, reviewKey.privateKey).toString('base64') });
  const oci = { core: createOciFixture('core'), render: createOciFixture('render') };
  for (const pack of ['core', 'render']) f.runtime.packs[pack] = { index_digest: oci[pack].index_digest, platforms: oci[pack].platforms };
  writeFileSync(path.join(f.root, 'runtime/runtime.lock.json'), JSON.stringify(f.runtime));
  const artifact = (id, contents, extra = {}) => {
    const rec = record(f.root, `${id}.bin`, contents);
    return { id, ...rec, ...extra, signature: envelope(Buffer.from(`ud-agent-artifact-v1\0${rec.sha256}`)) };
  };
  const artifacts = [artifact('npm', 'npm bytes'), artifact('core-oci-index', oci.core.bytes, { oci_digest: f.runtime.packs.core.index_digest }), artifact('render-oci-index', oci.render.bytes, { oci_digest: f.runtime.packs.render.index_digest })];
  // Synthetic source closure for verifier tests only; no product certification.
  const sourceBytes = Buffer.from('synthetic corresponding source\n'), sourceHash = sha256(sourceBytes), sourceProof = Buffer.from('{"synthetic":true}\n');
  const materials = { schema_version: 1, qualification: 'verified-corresponding-source-subinventories', complete_product_coverage: sourceComplete, files: [{ path: 'blobs/' + sourceHash, sha256: sourceHash, size_bytes: sourceBytes.length }], collections: [{ id: 'synthetic', receipt_path: 'receipts/synthetic.json', receipt_sha256: sha256(sourceProof), receipt_size_bytes: sourceProof.length, members: [{ path: 'blobs/' + sourceHash, sha256: sourceHash, size_bytes: sourceBytes.length }] }] };
  const materialsBytes = Buffer.from(JSON.stringify(materials)), sourceTar = fixtureTar([['MATERIALS.json', materialsBytes], ['receipts/synthetic.json', sourceProof], ['blobs/' + sourceHash, sourceBytes]]), sourcePart = artifact('corresponding-source-0000', sourceTar);
  const sourceIndex = artifact('corresponding-source-index', JSON.stringify({ schema_version: 1, qualification: materials.qualification, complete_product_coverage: sourceComplete, format: 'concatenated-ustar', manifest_sha256: sha256(materialsBytes), stream_sha256: sha256(sourceTar), stream_size_bytes: sourceTar.length, unique_source_files: 1, collections: [{ id: 'synthetic', sha256: sha256(sourceProof) }], parts: [{ id: sourcePart.id, path: path.posix.basename(sourcePart.path), sha256: sourcePart.sha256, size: sourcePart.size }] }));
  artifacts.push(sourcePart, sourceIndex);
  writeFileSync(path.join(f.root, 'runtime/source-materials.lock.json'), JSON.stringify({ schema_version: 1, index: { path: sourceIndex.path, sha256: sourceIndex.sha256, size: sourceIndex.size }, parts: [{ id: sourcePart.id, path: sourcePart.path, sha256: sourcePart.sha256, size: sourcePart.size }] }));
  const mutationSource = fileReceipt(f.root, 'packages/fixture.js');
  const evidenceReport = { suite_id: 'mutation-typescript', verdict: 'passed', executed: 2, errors: 0, skipped: 0, tests: [{ id: 'one', source: 'tests/fixture.test.mjs', status: 'passed' }, { id: 'two', source: 'tests/fixture.test.mjs', status: 'passed' }], survivors: 0, uncovered: 0, timeouts: 0, invalid: 0, missing: 0, killed: 2, scheduled: 2, equivalent_exceptions: [], mutants: [{ id: 'one-mutant', file: mutationSource.path, source_sha256: mutationSource.sha256, status: 'killed', failure_kind: 'assertion', killed_by: ['one'] }, { id: 'two-mutant', file: mutationSource.path, source_sha256: mutationSource.sha256, status: 'killed', failure_kind: 'assertion', killed_by: ['two'] }] };
  for (const [index, mutant] of evidenceReport.mutants.entries()) {
    mutant.definition = { tool: 'synthetic-test-only', version: '1', operator: `fixture-${index}`, original: 'true', replacement: 'false' };
    mutant.definition_sha256 = sha256(canonicalJson(mutant.definition));
  }
  mkdirSync(path.join(f.root, 'quality'));
  const requirements = { schema_version: 1, required_suites: ['mutation-typescript'], required_artifacts: ['npm', 'core-oci-index', 'render-oci-index'] };
  prepareMutationDiscoveryFixture(f.root);
  const catalog = discoveryFixture(f.root);
  const schedule = { schema_version: 1, inventory_only: true, suite_id: evidenceReport.suite_id,
    tests: evidenceReport.tests.map(({ id, source }) => ({ id, source, source_sha256: fileReceipt(f.root, source).sha256, discovered_id: catalog.tests.find(test => test.name === id).id })), mutants: evidenceReport.mutants.map(({ status, failure_kind, killed_by, ...definition }) => definition) };
  schedule.backend_discovery = mutationDiscoveryFixture(f.root, schedule.mutants, inventoryEnvelope);
  const inventory = compileAcceptanceInventory(f.root, catalog, requirements, [schedule]);
  inventory.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: record(f.root, 'discovered-tests.json', JSON.stringify(catalog)), schedules: [record(f.root, 'scheduled-mutants.json', JSON.stringify(schedule))] };
  writeFileSync(path.join(f.root, 'quality/acceptance-inventory.json'), JSON.stringify(inventory));
  const lock = fileReceipt(f.root, 'runtime/runtime.lock.json');
  const candidate = { schema_version: 1, status: 'accepted_candidate', product_version: '0.1.0-beta.1', source_commit: 'a'.repeat(40), publisher_commit: 'b'.repeat(40), source_tree_sha256: sourceReceipt(f.root).sha256, runtime_lock_path: lock.path, runtime_lock_sha256: lock.sha256, runtime_lock_size: lock.size, artifacts, evidence: [] };
  Object.assign(evidenceReport, evidenceSubjects(sourceReceipt(f.root), candidate));
  const reportBytes = Buffer.from(JSON.stringify(evidenceReport));
  candidate.evidence = [{ suite_id: evidenceReport.suite_id, ...record(f.root, 'mutation.json', reportBytes), signature: evidenceEnvelope(reportBytes) }];
  const checks = { verifyCommit: () => true, verifySource: () => true, verifyArtifactContent: () => ({ verified: true, qualifier: 'synthetic-internal-fixture' }) };
  return { ...f, policy, candidate, requirements, checks, envelope, evidenceEnvelope, reviewEnvelope, inventoryEnvelope };
}

test('release candidate and signed-evidence schemas enforce the accepted record shape', () => {
  const f = signedFixture();
  try {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const ajv = new Ajv2020({ strict: true });
    const candidate = ajv.compile(JSON.parse(readFileSync(path.join(root, 'release/schema/candidate.schema.json'), 'utf8')));
    const evidence = ajv.compile(JSON.parse(readFileSync(path.join(root, 'release/schema/evidence.schema.json'), 'utf8')));
    const discovery = ajv.compile(JSON.parse(readFileSync(path.join(root, 'release/schema/mutation-discovery.schema.json'), 'utf8')));
    const authority = JSON.parse(readFileSync(path.join(f.root, '.artifacts/synthetic-backend-discovery.json')));
    assert.equal(discovery(authority), true);
    assert.equal(discovery({ ...authority, scope_complete: false }), false);
    assert.equal(candidate(f.candidate), true);
    const report = JSON.parse(readFileSync(path.join(f.root, '.artifacts/mutation.json'), 'utf8'));
    assert.equal(evidence(report), true);
    assert.equal(evidence({ ...report, tests: [] }), false);
    assert.equal(candidate({ ...f.candidate, evidence: [{ ...f.candidate.evidence[0], signature: undefined }] }), false);
  } finally { f.cleanup(); }
});

test('source inventory is deterministic and rejects traversal paths', () => {
  const f = fixture();
  try {
    assert.deepEqual(sourceReceipt(f.root), sourceReceipt(f.root));
    for (const bad of ['../x', '/x', 'a/../x', 'C:foo', 'a\\b', 'a//b']) assert.throws(() => safeRelative(bad));
  } finally { f.cleanup(); }
});

test('commit comparison requires exact blob bytes and modes with sanitized Git environment', () => {
  const f = fixture(); const oldGitDir = process.env.GIT_DIR; const oldGitConfig = process.env.GIT_CONFIG_COUNT;
  try {
    const inventory = sourceReceipt(f.root);
    const rows = inventory.files.map((file, i) => ({ path: file.path, oid: String(i + 1).padStart(40, '0'), mode: file.executable ? '100755' : '100644', bytes: readFileSync(path.join(f.root, file.path)).toString('base64') }));
    process.env.GIT_DIR = '/untrusted/redirect'; process.env.GIT_CONFIG_COUNT = '1';
    const runner = data => (_command, args, options) => {
      assert.equal(options.env.GIT_DIR, undefined); assert.equal(options.env.GIT_CONFIG_COUNT, undefined); assert.equal(options.env.GIT_NO_REPLACE_OBJECTS, '1');
      if (args.includes('ls-tree')) return { status: 0, stdout: Buffer.from(data.map(row => `${row.mode} blob ${row.oid}\t${row.path}\0`).join('')) };
      assert.ok(args.includes('--batch'));
      return { status: 0, stdout: Buffer.concat(data.flatMap(row => { const bytes = Buffer.from(row.bytes, 'base64'); return [Buffer.from(`${row.oid} blob ${bytes.length}\n`), bytes, Buffer.from('\n')]; })) };
    };
    assert.equal(verifySourceMatchesCommit(f.root, 'a'.repeat(40), inventory, runner(rows)), true);
    const altered = structuredClone(rows); altered[0].bytes = Buffer.from('changed').toString('base64');
    assert.equal(verifySourceMatchesCommit(f.root, 'a'.repeat(40), inventory, runner(altered)), false);
    const changedMode = structuredClone(rows); changedMode[0].mode = changedMode[0].mode === '100644' ? '100755' : '100644';
    assert.equal(verifySourceMatchesCommit(f.root, 'a'.repeat(40), inventory, runner(changedMode)), false);
    assert.equal(verifySourceMatchesCommit(f.root, 'a'.repeat(40), inventory, runner([...rows, { path: 'extra', oid: 'f'.repeat(40), mode: '100644', bytes: '' }])), false);
  } finally {
    if (oldGitDir === undefined) delete process.env.GIT_DIR; else process.env.GIT_DIR = oldGitDir;
    if (oldGitConfig === undefined) delete process.env.GIT_CONFIG_COUNT; else process.env.GIT_CONFIG_COUNT = oldGitConfig;
    f.cleanup();
  }
});

test('local candidate verifies artifact and source bytes without claiming release acceptance', () => {
  const f = fixture();
  try {
    const rec = record(f.root, 'one.tgz', 'candidate bytes');
    const candidate = { schema_version: 1, status: 'local_candidate', production_ready: false, product_version: '0.1.0-beta.1', source_tree_sha256: sourceReceipt(f.root).sha256, artifacts: [{ id: 'npm', ...rec }] };
    assert.equal(verifyLocalCandidate(f.root, candidate).production_ready, false);
    writeFileSync(path.join(f.root, '.artifacts/one.tgz'), 'tampered');
    assert.throws(() => verifyLocalCandidate(f.root, candidate), /mismatch/);
  } finally { f.cleanup(); }
});

test('production requires signed evidence and independently verified OCI bytes', () => {
  const f = signedFixture();
  try {
    let bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.equal(verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks).valid, true);
    assert.throws(() => verifyProductionCandidate(f.root, bytes, { key_id: 'other', signature: f.envelope(bytes).signature }, f.policy, f.requirements, f.checks), /trusted release key/);
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), { ...f.policy, keys: [] }, f.requirements, f.checks), /trusted release key/);
    const badDigest = structuredClone(f.candidate);
    badDigest.artifacts[1].oci_digest = `sha256:${'f'.repeat(64)}`;
    bytes = Buffer.from(JSON.stringify(badDigest));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /OCI index digest/);
  } finally { f.cleanup(); }
});

test('production refuses even signed partial corresponding-source collections', () => {
  const f = signedFixture({ sourceComplete: false });
  try { const bytes = Buffer.from(JSON.stringify(f.candidate)); assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /source product coverage is incomplete/); }
  finally { f.cleanup(); }
});

test('production refuses an incomplete acceptance inventory even with signed evidence', () => {
  const f = signedFixture();
  try {
    writeFileSync(path.join(f.root, 'quality/acceptance-inventory.json'), JSON.stringify({ schema_version: 1, state: 'incomplete', suites: [] }));
    f.candidate.source_tree_sha256 = sourceReceipt(f.root).sha256;
    const bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /frozen suite inventory/);
  } finally { f.cleanup(); }
});

test('production runtime lock must be the exact inventoried source lock', () => {
  const f = signedFixture();
  try {
    const alternate = record(f.root, 'alternate-runtime.lock.json', readFileSync(path.join(f.root, 'runtime/runtime.lock.json')));
    const candidate = { ...f.candidate, runtime_lock_path: alternate.path, runtime_lock_sha256: alternate.sha256, runtime_lock_size: alternate.size };
    const bytes = Buffer.from(JSON.stringify(candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /Runtime lock does not match the source inventory/);
    const wrong = { ...f.candidate, runtime_lock_sha256: '0'.repeat(64) };
    const wrongBytes = Buffer.from(JSON.stringify(wrong));
    assert.throws(() => verifyProductionCandidate(f.root, wrongBytes, f.envelope(wrongBytes), f.policy, f.requirements, f.checks), /Runtime lock does not match the source inventory/);
  } finally { f.cleanup(); }
});

test('public production entry reads policy and requirements from inventoried bytes', () => {
  const f = signedFixture();
  try {
    mkdirSync(path.join(f.root, 'release/trust'), { recursive: true });
    mkdirSync(path.join(f.root, 'quality'), { recursive: true });
    const policyPath = path.join(f.root, 'release/trust/policy.json');
    const requirementsPath = path.join(f.root, 'quality/requirements.json');
    const denyPolicy = { ...f.policy, keys: [] };
    writeFileSync(policyPath, JSON.stringify(denyPolicy));
    writeFileSync(requirementsPath, JSON.stringify(f.requirements));
    const inventory = sourceReceipt(f.root);
    assert.deepEqual(readSourceBoundReleaseConfiguration(f.root, inventory), { policy: denyPolicy, requirements: f.requirements });
    const bytes = Buffer.from(JSON.stringify(f.candidate));
    // Extra arguments are ignored: neither a forged policy nor fake Git
    // checks can override the public entry's source-bound trust policy.
    assert.throws(() => verifyProductionEntry(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /trusted release key/);
    writeFileSync(requirementsPath, JSON.stringify({ ...f.requirements, required_suites: ['substituted'] }));
    assert.throws(() => readSourceBoundReleaseConfiguration(f.root, inventory), /receipt mismatch/);
    writeFileSync(requirementsPath, JSON.stringify(f.requirements));
    writeFileSync(policyPath, JSON.stringify(f.policy));
    assert.throws(() => readSourceBoundReleaseConfiguration(f.root, inventory), /receipt mismatch/);
  } finally { f.cleanup(); }
});

test('release requirements include a distinct MCPB bundle for each native target', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const requirements = JSON.parse(readFileSync(path.join(root, 'quality/requirements.json'), 'utf8'));
  for (const platform of ['linux-amd64', 'linux-arm64', 'macos-arm64', 'windows-amd64', 'windows-arm64']) {
    assert.equal(requirements.required_artifacts.filter(id => id === `mcpb-${platform}`).length, 1);
  }
});

test('mutation survivor and missing evidence block production acceptance', () => {
  const f = signedFixture();
  try {
    const report = JSON.parse(readFileSync(path.join(f.root, '.artifacts/mutation.json')));
    report.survivors = 1;
    const reportBytes = Buffer.from(JSON.stringify(report));
    const evidence = { suite_id: 'mutation-typescript', ...record(f.root, 'mutation.json', reportBytes), signature: f.evidenceEnvelope(reportBytes) };
    f.candidate.evidence = [evidence];
    let bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /Evidence does not match its schema/);
    f.candidate.evidence = [];
    bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /schema|suite missing/);
  } finally { f.cleanup(); }
});

test('signed evidence must bind the actual source, tests, artifacts and independent runner key', () => {
  const f = signedFixture();
  try {
    const report = JSON.parse(readFileSync(path.join(f.root, '.artifacts/mutation.json')));
    report.test_inventory_sha256 = 'f'.repeat(64);
    const altered = Buffer.from(JSON.stringify(report));
    f.candidate.evidence = [{ suite_id: report.suite_id, ...record(f.root, 'mutation.json', altered), signature: f.evidenceEnvelope(altered) }];
    let bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /Evidence subject mismatch/);
    report.test_inventory_sha256 = evidenceSubjects(sourceReceipt(f.root), f.candidate).test_inventory_sha256;
    report.tests[0].source = 'tests/not-present.test.mjs';
    const badTest = Buffer.from(JSON.stringify(report));
    f.candidate.evidence = [{ suite_id: report.suite_id, ...record(f.root, 'mutation.json', badTest), signature: f.evidenceEnvelope(badTest) }];
    bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /unbound test evidence/);
    f.candidate.evidence[0].signature = f.envelope(badTest);
    bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /trusted release key/);
    const sharedKeyPolicy = { ...f.policy, evidence_keys: [{ ...f.policy.keys[0], id: 'same-key' }] };
    f.candidate.evidence[0].signature = { ...f.envelope(badTest), key_id: 'same-key' };
    bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), sharedKeyPolicy, f.requirements, f.checks), /independent signing key/);
  } finally { f.cleanup(); }
});

test('signed artifact metadata cannot substitute for a valid OCI archive', () => {
  const f = signedFixture();
  try {
    const original = f.candidate.artifacts[1];
    const changed = record(f.root, 'core-oci-index.bin', 'not an OCI archive');
    f.candidate.artifacts[1] = { id: original.id, ...changed, oci_digest: original.oci_digest, signature: f.envelope(Buffer.from(`ud-agent-artifact-v1\0${changed.sha256}`)) };
    const report = JSON.parse(readFileSync(path.join(f.root, '.artifacts/mutation.json')));
    Object.assign(report, evidenceSubjects(sourceReceipt(f.root), f.candidate));
    const reportBytes = Buffer.from(JSON.stringify(report));
    f.candidate.evidence = [{ suite_id: report.suite_id, ...record(f.root, 'mutation.json', reportBytes), signature: f.evidenceEnvelope(reportBytes) }];
    const bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /OCI archive/);
  } finally { f.cleanup(); }
});

test('complete mutation inventories require a dedicated signer independent of release and outcomes', () => {
  for (const signer of ['release', 'outcome']) {
    const f = signedFixture();
    try {
      const schedule = JSON.parse(readFileSync(path.join(f.root, '.artifacts/scheduled-mutants.json')));
      const authorityBytes = readFileSync(path.join(f.root, schedule.backend_discovery.path));
      const key = signer === 'release' ? f.policy.keys[0] : f.policy.evidence_keys[0];
      const envelope = signer === 'release' ? f.envelope : f.evidenceEnvelope;
      schedule.backend_discovery.signature = { ...envelope(authorityBytes), key_id: 'inventory-authority' };
      const scheduleRecord = record(f.root, 'scheduled-mutants.json', JSON.stringify(schedule));
      const inventoryPath = path.join(f.root, 'quality/acceptance-inventory.json'), inventory = JSON.parse(readFileSync(inventoryPath));
      inventory.discovery.schedules = [scheduleRecord]; writeFileSync(inventoryPath, JSON.stringify(inventory));
      f.candidate.source_tree_sha256 = sourceReceipt(f.root).sha256;
      const report = JSON.parse(readFileSync(path.join(f.root, '.artifacts/mutation.json')));
      Object.assign(report, evidenceSubjects(sourceReceipt(f.root), f.candidate));
      const reportBytes = Buffer.from(JSON.stringify(report)); f.candidate.evidence = [{ suite_id: report.suite_id, ...record(f.root, 'mutation.json', reportBytes), signature: f.evidenceEnvelope(reportBytes) }];
      const policy = { ...f.policy, inventory_keys: [{ ...key, id: 'inventory-authority' }] };
      const bytes = Buffer.from(JSON.stringify(f.candidate));
      assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), policy, f.requirements, f.checks), new RegExp(`independent of ${signer === 'release' ? 'release' : 'outcome'}`));
    } finally { f.cleanup(); }
  }
});

test('equivalent mutants require unique, source-bound independent signed review', () => {
  const f = signedFixture();
  try {
    const report = JSON.parse(readFileSync(path.join(f.root, '.artifacts/mutation.json')));
    const mutant = report.mutants[0]; mutant.status = 'equivalent'; delete mutant.killed_by; delete mutant.failure_kind;
    report.killed = 1;
    const review = { verdict: 'equivalent', id: mutant.id, file: mutant.file, source_sha256: mutant.source_sha256, definition_sha256: mutant.definition_sha256, author: 'author', reviewer: 'reviewer', reason: 'This mutation changes only a provably unreachable branch under the stated input contract.' };
    const reviewBytes = Buffer.from(JSON.stringify(review));
    const evidence = { ...record(f.root, 'review.json', reviewBytes), signature: f.reviewEnvelope(reviewBytes) };
    const exception = { id: review.id, file: review.file, source_sha256: review.source_sha256, definition_sha256: review.definition_sha256, author: review.author, reviewer: review.reviewer, reason: review.reason, evidence };
    const update = () => {
      const payload = Buffer.from(JSON.stringify(report));
      f.candidate.evidence = [{ suite_id: report.suite_id, ...record(f.root, 'mutation.json', payload), signature: f.evidenceEnvelope(payload) }];
      const candidate = Buffer.from(JSON.stringify(f.candidate));
      return () => verifyProductionCandidate(f.root, candidate, f.envelope(candidate), f.policy, f.requirements, f.checks);
    };
    report.equivalent_exceptions = [exception];
    assert.equal(update()().valid, true);
    report.equivalent_exceptions = [exception, exception];
    assert.throws(update(), /Unreviewed equivalent mutant/);
    report.equivalent_exceptions = [{ ...exception, author: 'reviewer' }];
    assert.throws(update(), /Unreviewed equivalent mutant/);
    report.equivalent_exceptions = [{ ...exception, source_sha256: '0'.repeat(64) }];
    assert.throws(update(), /Unreviewed equivalent mutant/);
    report.equivalent_exceptions = [{ ...exception, definition_sha256: '0'.repeat(64) }];
    assert.throws(update(), /Unreviewed equivalent mutant/);
    report.equivalent_exceptions = [{ ...exception, evidence: { ...evidence, signature: f.evidenceEnvelope(reviewBytes) } }];
    assert.throws(update(), /trusted release key/);
    report.equivalent_exceptions = []; report.mutants[1].id = mutant.id;
    assert.throws(update(), /Invalid mutation outcome/);
  } finally { f.cleanup(); }
});

test('production rejects absent provenance and empty requirements', () => {
  const f = signedFixture();
  try {
    f.candidate.source_commit = '';
    let bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /commits/);
    f.candidate.source_commit = 'a'.repeat(40);
    bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, { ...f.requirements, required_suites: [] }, f.checks), /requirements/);
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, { ...f.checks, verifyCommit: () => false }), /protected source ancestry/);
    f.candidate.product_version = '0.2.0';
    bytes = Buffer.from(JSON.stringify(f.candidate));
    assert.throws(() => verifyProductionCandidate(f.root, bytes, f.envelope(bytes), f.policy, f.requirements, f.checks), /Product version does not match/);
  } finally { f.cleanup(); }
});

function releaseFixture() {
  const f = fixture();
  const a = record(f.root, 'github.bin', 'github bytes');
  const b = record(f.root, 'npm.bin', 'npm bytes');
  const candidate = { manifest_sha256: 'a'.repeat(64), targets: [{ target: 'github', coordinate: 'v1', ...a }, { target: 'npm', coordinate: '@oguz/pkg@1', ...b }] };
  return { ...f, candidate, registry: new FixtureRegistry() };
}

test('fixture reconciliation is idempotent and promotes only fully verified targets', () => {
  const f = releaseFixture();
  try {
    assert.throws(() => promoteFixture(f.candidate, null, f.registry, 'next', 'npm', '@oguz/pkg@1'));
    const first = reconcileFixture(f.root, f.candidate, null, f.registry);
    const second = reconcileFixture(f.root, f.candidate, first, f.registry);
    assert.deepEqual(second, first);
    promoteFixture(f.candidate, second, f.registry, 'next', 'npm', '@oguz/pkg@1');
    assert.deepEqual(f.registry.getChannel('next'), { target: 'npm', coordinate: '@oguz/pkg@1' });
  } finally { f.cleanup(); }
});

test('fixture reconciliation stops on immutable conflicts and retains partial ledger', () => {
  const f = releaseFixture();
  try {
    f.registry.seed('npm', '@oguz/pkg@1', Buffer.from('wrong bytes'));
    assert.throws(() => reconcileFixture(f.root, f.candidate, null, f.registry), error => {
      assert.match(error.message, /conflict/);
      assert.equal(error.ledger.targets['github:v1'].state, 'verified');
      return true;
    });
  } finally { f.cleanup(); }
});

test('lost fixture publication response is recovered by inspecting immutable bytes', () => {
  const f = releaseFixture();
  class LostResponse extends FixtureRegistry {
    lost = false;
    publish(target, coordinate, bytes) {
      super.publish(target, coordinate, bytes);
      if (!this.lost) { this.lost = true; const error = new Error('lost reply'); error.transient = true; throw error; }
    }
  }
  try {
    const registry = new LostResponse();
    const result = reconcileFixture(f.root, f.candidate, null, registry);
    assert.equal(result.targets['github:v1'].state, 'verified');
  } finally { f.cleanup(); }
});
