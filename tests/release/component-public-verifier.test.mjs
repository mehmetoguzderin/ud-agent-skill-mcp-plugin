import { test, expect } from 'vitest';
import { MAX_COMPONENT_SOURCE_REPORT_BYTES } from '../../scripts/release/component-closure.mjs';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { verifyProductionCandidate } from '../../scripts/release/verify.mjs';
const required = JSON.parse(readFileSync('quality/requirements.json')).required_artifacts;
function fixture(root) {
  for (const folder of ['quality', 'release/trust', 'runtime/materials']) mkdirSync(path.join(root, folder), { recursive: true });
  writeFileSync(path.join(root, 'quality/requirements.json'), JSON.stringify({ required_artifacts: required }));
  const key = generateKeyPairSync('ed25519');
  writeFileSync(path.join(root, 'release/trust/policy.json'), JSON.stringify({ schema_version: 1, purpose: 'release-candidate', keys: [{ id: 'original-local-fixture', algorithm: 'ed25519', status: 'active', public_key_pem: key.publicKey.export({ type: 'spki', format: 'pem' }) }] }));
  writeFileSync(path.join(root, 'runtime/materials/component-source-replay.json'), '{"schema_version":1,"families":[]}');
  writeFileSync(path.join(root, 'release/verifier-runtimes.lock.json'), JSON.stringify({ schema_version: 1, purpose: 'release-verifier-python', profiles: [] }));
  return { candidate: { schema_version: 1, status: 'accepted_candidate', artifacts: [...required.map(id => ({ id, path: id, sha256: 'a'.repeat(64), size: 1 })), { id: 'component-source-coverage', path: 'coverage.json', sha256: 'b'.repeat(64), size: 20 }] }, envelope: bytes => ({ key_id: 'original-local-fixture', signature: sign(null, bytes, key.privateKey).toString('base64') }) };
}

test('public release verifier rejects missing native subjects and absent/oversized coverage before any expensive replay', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-public-component-reject-'));
  const previousPython = process.env.UD_RELEASE_PYTHON; delete process.env.UD_RELEASE_PYTHON;
  try {
    const { candidate: original, envelope } = fixture(root);
    for (const modify of [value => value.artifacts.shift(), value => value.artifacts.pop(), value => value.artifacts.push(value.artifacts.at(-1)), value => { value.artifacts.at(-1).size = MAX_COMPONENT_SOURCE_REPORT_BYTES + 1; }]) {
      const candidate = structuredClone(original); modify(candidate);
      const bytes = Buffer.from(JSON.stringify(candidate));
      expect(() => verifyProductionCandidate(root, bytes, envelope(bytes))).toThrow(/component-source/);
    }
    // Complete-shaped metadata is still refused by the actual signature gate;
    // this fixture has no interpreter/replay script and cannot run deep replay.
    const bytes = Buffer.from(JSON.stringify(original));
    expect(() => verifyProductionCandidate(root, bytes, {})).toThrow(/signature envelope/);
    expect(() => verifyProductionCandidate(root, bytes, envelope(bytes))).toThrow(/Genuine source and publisher commits/);
    expect(() => verifyProductionCandidate(root, bytes.toString('utf8'), envelope(bytes))).toThrow(/Genuine source and publisher commits/);
  } finally { if (previousPython === undefined) delete process.env.UD_RELEASE_PYTHON; else process.env.UD_RELEASE_PYTHON = previousPython; rmSync(root, { recursive: true, force: true }); }
});

test('public release verifier rejects a fake Python override without executing it and still authenticates first', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-public-fake-python-')), previousPython = process.env.UD_RELEASE_PYTHON;
  try {
    const { candidate, envelope } = fixture(root), executable = path.join(root, 'fake-python'), marker = path.join(root, 'fake-ran');
    writeFileSync(executable, `#!/bin/sh\nprintf ran > '${marker}'\nprintf '{"verified":true,"complete_product_coverage":true}'\n`); chmodSync(executable, 0o700);
    process.env.UD_RELEASE_PYTHON = executable;
    const bytes = Buffer.from(JSON.stringify(candidate));
    expect(() => verifyProductionCandidate(root, bytes, {})).toThrow(/signature envelope/);
    expect(() => verifyProductionCandidate(root, bytes, envelope(bytes))).toThrow(/No approved release-verifier interpreter/);
    expect(existsSync(marker)).toBe(false);
  } finally { if (previousPython === undefined) delete process.env.UD_RELEASE_PYTHON; else process.env.UD_RELEASE_PYTHON = previousPython; rmSync(root, { recursive: true, force: true }); }
});

test('publisher beta authenticates only its exact version and manifest with the pinned key', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-publisher-beta-'));
  const previousPython = process.env.UD_RELEASE_PYTHON;
  delete process.env.UD_RELEASE_PYTHON;
  try {
    const { candidate } = fixture(root);
    const key = generateKeyPairSync('ed25519');
    const policyPath = path.join(root, 'release/trust/policy.json');
    const policy = JSON.parse(readFileSync(policyPath));
    policy.publisher_beta = {
      product_version: '0.1.0-beta.1',
      keys: [{ id: 'publisher', status: 'active', algorithm: 'ed25519', public_key_pem: key.publicKey.export({ type: 'spki', format: 'pem' }) }],
    };
    writeFileSync(policyPath, JSON.stringify(policy));
    const envelope = bytes => ({ key_id: 'publisher', signature: sign(null, bytes, key.privateKey).toString('base64') });
    const beta = { ...candidate, product_version: '0.1.0-beta.1', signing_profile: 'publisher-beta' };
    const bytes = Buffer.from(JSON.stringify(beta));
    expect(() => verifyProductionCandidate(root, bytes, envelope(bytes))).toThrow(/Genuine source and publisher commits/);
    for (const version of ['0.1.0', '0.1.0-beta.2']) {
      const other = Buffer.from(JSON.stringify({ ...beta, product_version: version }));
      expect(() => verifyProductionCandidate(root, other, envelope(other))).toThrow(/unavailable for this candidate version/);
    }
    const ordinary = Buffer.from(JSON.stringify({ ...beta, signing_profile: undefined }));
    expect(() => verifyProductionCandidate(root, ordinary, envelope(ordinary))).toThrow(/trusted release key/);
    const changed = Buffer.from(JSON.stringify({ ...beta, artifacts: beta.artifacts.slice(1) }));
    expect(() => verifyProductionCandidate(root, changed, envelope(bytes))).toThrow(/signature verification failed/);
  } finally {
    if (previousPython === undefined) delete process.env.UD_RELEASE_PYTHON;
    else process.env.UD_RELEASE_PYTHON = previousPython;
    rmSync(root, { recursive: true, force: true });
  }
});

test('publisher beta schema needs artifact and evidence receipts while permitting one manifest signature', () => {
  const schema = JSON.parse(readFileSync('release/schema/candidate.schema.json'));
  const validate = new Ajv2020({ strict: true }).compile(schema);
  const commit = 'a'.repeat(40), sha256 = 'b'.repeat(64);
  const receipt = { path: '.artifacts/file', sha256, size: 1 };
  const candidate = {
    schema_version: 1, status: 'accepted_candidate', product_version: '0.1.0-beta.1',
    source_commit: commit, publisher_commit: commit, source_tree_sha256: sha256,
    runtime_lock_sha256: sha256, runtime_lock_path: 'runtime/runtime.lock.json', runtime_lock_size: 1,
    artifacts: [{ ...receipt, id: 'npm' }], evidence: [{ ...receipt, suite_id: 'unit' }],
  };
  expect(validate(candidate)).toBe(false);
  const beta = { ...candidate, signing_profile: 'publisher-beta' };
  expect(validate(beta)).toBe(true);
  expect(validate({ ...beta, evidence: [] })).toBe(false);
  expect(validate({ ...beta, artifacts: [{ ...receipt }] })).toBe(false);
});
