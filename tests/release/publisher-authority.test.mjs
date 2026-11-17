import { test, expect } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';
import path from 'node:path';
import os from 'node:os';
import { fileReceipt, sourceReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { publisherAuthoritySubjects, verifyPublisherAuthorityEnvelope, verifySourceDutyReview } from '../../scripts/release/publisher-authority.mjs';

function signed() {
  const components = [{ id: 'fixture-static-runtime', definition_sha256: '1'.repeat(64), binary_sha256: '2'.repeat(64) }];
  const candidate = { runtime_lock_sha256: '3'.repeat(64), artifacts: [{ id: 'native-windows-arm64', sha256: '4'.repeat(64), size: 80 }, { id: 'publisher-authority', sha256: '5'.repeat(64), size: 90 }] };
  const payload = { ...publisherAuthoritySubjects({ sha256: '6'.repeat(64) }, candidate, components), legal_evidence_sha256: '7'.repeat(64) };
  const pairs = ['publisher-owner', 'independent-reviewer'].map(role => ({ role, ...generateKeyPairSync('ed25519') }));
  const policy = { redistribution_keys: pairs.map(({ role, publicKey }) => ({ id: role, role, purpose: 'publisher-redistribution-authority', status: 'active', algorithm: 'ed25519', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }) })) };
  const signatures = pairs.map(({ role, privateKey }) => ({ role, key_id: role, signature: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64') }));
  return { payload, policy, signatures, candidate, components, pairs };
}

test('publisher authority binds independent roles to exact source, binary components and artifacts', () => {
  const { payload, policy, signatures, candidate, components } = signed();
  expect(verifyPublisherAuthorityEnvelope(payload, signatures, policy).verified).toBe(true);
  for (const key of ['source_tree_sha256', 'runtime_lock_sha256', 'artifact_set_sha256', 'legal_evidence_sha256']) expect(() => verifyPublisherAuthorityEnvelope({ ...payload, [key]: 'a'.repeat(64) }, signatures, policy)).toThrow();
  for (const patch of [{ components: [] }, { components: [payload.components[0], payload.components[0]] }, { scope: 'all-future-releases' }, { components: [{ ...payload.components[0], rights: ['all-rights'] }] }]) expect(() => verifyPublisherAuthorityEnvelope({ ...payload, ...patch }, signatures, policy)).toThrow();
  expect(publisherAuthoritySubjects({ sha256: '6'.repeat(64) }, { ...candidate, artifacts: candidate.artifacts.filter(row => row.id !== 'publisher-authority') }, components).artifact_set_sha256).toBe(payload.artifact_set_sha256);
  expect(publisherAuthoritySubjects({ sha256: '6'.repeat(64) }, { ...candidate, artifacts: [...candidate.artifacts, { id: 'npm', sha256: '8'.repeat(64), size: 81 }] }, components).artifact_set_sha256).not.toBe(payload.artifact_set_sha256);
});

test('missing rights, wrong-purpose trust and one key reused under two roles cannot grant authority', () => {
  const { payload, policy, signatures, pairs } = signed();
  for (const value of [[], signatures.slice(0, 1), [signatures[0], signatures[0]]]) expect(() => verifyPublisherAuthorityEnvelope(payload, value, policy)).toThrow();
  for (const patch of [{ status: 'retired' }, { purpose: 'release-signing' }, { role: 'publisher-owner' }]) expect(() => verifyPublisherAuthorityEnvelope(payload, signatures, { redistribution_keys: policy.redistribution_keys.map((key, index) => index ? { ...key, ...patch } : key) })).toThrow();
  const reused = { redistribution_keys: policy.redistribution_keys.map(key => ({ ...key, public_key_pem: pairs[0].publicKey.export({ type: 'spki', format: 'pem' }) })) };
  const duplicatedMaterial = signatures.map(signature => ({ ...signature, signature: sign(null, Buffer.from(canonicalJson(payload)), pairs[0].privateKey).toString('base64') }));
  expect(() => verifyPublisherAuthorityEnvelope(payload, duplicatedMaterial, reused)).toThrow(/key material/);
});

test('publisher beta grant binds package bytes while the outer manifest binds the grant and its checksum list', () => {
  const { candidate, components } = signed();
  const source = { sha256: '6'.repeat(64) };
  const beta = { ...candidate, signing_profile: 'publisher-beta' };
  const withChecksums = { ...beta, artifacts: [...beta.artifacts, { id: 'checksum-manifest', size: 100, sha256: '9'.repeat(64) }] };
  expect(publisherAuthoritySubjects(source, withChecksums, components)).toEqual(publisherAuthoritySubjects(source, beta, components));
  expect(publisherAuthoritySubjects(source, { ...withChecksums, signing_profile: undefined }, components)).not.toEqual(publisherAuthoritySubjects(source, candidate, components));
  withChecksums.artifacts[0] = { ...withChecksums.artifacts[0], sha256: 'b'.repeat(64) };
  expect(publisherAuthoritySubjects(source, withChecksums, components)).not.toEqual(publisherAuthoritySubjects(source, beta, components));
});

test('the independent source-duty review remains exact and does not grant publisher authority', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-source-duty-review-'));
  try {
    mkdirSync(path.join(root, 'quality/reviews'), { recursive: true }); mkdirSync(path.join(root, 'runtime/materials'), { recursive: true });
    for (const name of ['quality/reviews/msvc-source-duty-root-review.json', 'runtime/materials/msvc-static-components.lock.json']) writableFixtureCopy(path.resolve(name), path.join(root, name), root);
    const declaration = JSON.parse(readFileSync(path.join(root, 'runtime/materials/msvc-static-components.lock.json'), 'utf8'));
    const source = sourceReceipt(root), reviewPath = path.join(root, 'quality/reviews/msvc-source-duty-root-review.json'), original = readFileSync(reviewPath, 'utf8');
    expect(verifySourceDutyReview(root, declaration, source).scope).toBe('source-duty-only-no-publisher-authority');
    const review = JSON.parse(original); review.components.pop(); writeFileSync(reviewPath, JSON.stringify(review));
    expect(() => verifySourceDutyReview(root, declaration, sourceReceipt(root))).toThrow(/stale or incomplete/);
    writeFileSync(reviewPath, original); const changed = structuredClone(declaration); changed.components[0].definition_sha256 = 'a'.repeat(64);
    expect(() => verifySourceDutyReview(root, changed, sourceReceipt(root))).toThrow(/omits or changes/);
    expect(sha256(readFileSync(reviewPath))).toBe(fileReceipt(root, 'quality/reviews/msvc-source-duty-root-review.json').sha256);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
