import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SourceTarVerifier } from '../../scripts/release/source-tar.mjs';
import { sourceArtifacts, verifyCandidateSources, verifyRequiredSourceMaterials } from '../../scripts/release/source-artifacts.mjs';
import { fixtureTar } from './oci-fixture.mjs';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function fixture(entries) {
  const bytes = readFileSync('tests/fixtures/source-materials/go-units-v0.5.0.zip'), digest = sha(bytes), proof = Buffer.from('{"original":"source-proof"}\n');
  const material = { schema_version: 1, qualification: 'verified-corresponding-source-subinventories', complete_product_coverage: false, files: [{ path: 'blobs/' + digest, sha256: digest, size_bytes: bytes.length }], collections: [{ id: 'source', receipt_path: 'receipts/source.json', receipt_sha256: sha(proof), receipt_size_bytes: proof.length, members: [{ path: 'blobs/' + digest, sha256: digest, size_bytes: bytes.length }] }] };
  const manifest = Buffer.from(JSON.stringify(material)), normal = [['MATERIALS.json', manifest], ['receipts/source.json', proof], ['blobs/' + digest, bytes]], archive = fixtureTar(entries ? entries(normal) : normal);
  const index = { schema_version: 1, qualification: material.qualification, complete_product_coverage: false, format: 'concatenated-ustar', manifest_sha256: sha(manifest), stream_sha256: sha(archive), stream_size_bytes: archive.length, collections: [{ id: 'source', sha256: sha(proof) }], unique_source_files: 1 };
  return { archive, index, digest };
}
function inspect(archive, index) { const parser = new SourceTarVerifier(index); for (let offset = 0; offset < archive.length; offset += 73) parser.feed(archive.subarray(offset, offset + 73)); return parser.finish(); }

test('streaming USTAR verification binds actual source bytes, closed members and partial qualification', () => {
  const { archive, index } = fixture(); assert.deepEqual(inspect(archive, index), { verified: true, files: 3, complete_product_coverage: false });
  for (const change of [rows => [rows[0], ...rows.slice(1), rows[2]], rows => rows.slice(0, 2), rows => [...rows, ['blobs/' + 'a'.repeat(64), 'undeclared']], rows => [rows[0], rows[1], ['../escape', rows[2][1]]], rows => [rows[0], rows[1], [rows[2][0], Buffer.from('wrong source')]]]) {
    const corrupt = fixture(change); assert.throws(() => inspect(corrupt.archive, corrupt.index), /duplicate|omits|undeclared|unsafe|differ/);
  }
  const link = Buffer.from(archive); link[156] = 50; link.fill(32, 148, 156); const checksum = link.subarray(0, 512).reduce((a, b) => a + b, 0); link.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii'); assert.throws(() => inspect(link, index), /linked/);
  assert.throws(() => inspect(archive.subarray(0, archive.length - 1), index), /truncated/);
});

test('source artifacts reconcile ordered physical shards and cannot certify an incomplete product closure', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-source-assets-')); mkdirSync(path.join(root, 'runtime')); mkdirSync(path.join(root, '.artifacts'));
  try {
    const { archive, index } = fixture(), parts = [];
    for (let offset = 0; offset < archive.length; offset += 4096) { const number = parts.length, bytes = archive.subarray(offset, offset + 4096), filename = `source-${number}.part`, item = { id: `corresponding-source-${String(number).padStart(4, '0')}`, path: '.artifacts/' + filename, sha256: sha(bytes), size: bytes.length }; writeFileSync(path.join(root, item.path), bytes); parts.push(item); }
    index.parts = parts.map(item => ({ ...item, path: path.posix.basename(item.path) })); const indexBytes = Buffer.from(JSON.stringify(index)), indexRecord = { path: '.artifacts/source-index.json', sha256: sha(indexBytes), size: indexBytes.length }; writeFileSync(path.join(root, indexRecord.path), indexBytes);
    writeFileSync(path.join(root, 'runtime/source-materials.lock.json'), JSON.stringify({ schema_version: 1, index: indexRecord, parts }));
    const artifacts = sourceArtifacts(root, { required: true }); assert.equal(artifacts.length, parts.length + 1);
    const original = readFileSync('tests/fixtures/source-materials/go-units-v0.5.0.zip'), wanted = [{ sha256: sha(original), size_bytes: original.length }];
    assert.deepEqual(verifyRequiredSourceMaterials(root, wanted), { verified: true, original_source_materials: 1 });
    assert.throws(() => verifyRequiredSourceMaterials(root, [...wanted, { sha256: 'f'.repeat(64), size_bytes: 4 }]), /omit required|unselected/);
    assert.throws(() => verifyRequiredSourceMaterials(root, [{ sha256: 'f'.repeat(64), size_bytes: 4 }]), /omit required|unselected/);
    assert.throws(() => verifyRequiredSourceMaterials(root, [{ ...wanted[0], size_bytes: original.length + 1 }]), /omit required|unselected/);
    assert.equal(verifyCandidateSources(root, { artifacts }, { complete: false }).verified, true);
    assert.throws(() => verifyCandidateSources(root, { artifacts }), /coverage is incomplete/);
    assert.throws(() => verifyCandidateSources(root, { artifacts: artifacts.slice(1) }, { complete: false }), /omits/);
    writeFileSync(path.join(root, parts[0].path), 'damaged'); assert.throws(() => sourceArtifacts(root), /receipt mismatch/);
    writeFileSync(path.join(root, parts[0].path), archive.subarray(0, parts[0].size));
    mkdirSync(path.join(root, 'release'));
    const relocated = artifacts.map(item => { const output = 'release/' + path.posix.basename(item.path); renameSync(path.join(root, item.path), path.join(root, output)); return { ...item, path: output }; });
    assert.throws(() => sourceArtifacts(root), /ENOENT/);
    assert.equal(verifyCandidateSources(root, { artifacts: relocated }, { complete: false }).verified, true);
    assert.deepEqual(verifyRequiredSourceMaterials(root, wanted, { candidate: { artifacts: relocated } }), { verified: true, original_source_materials: 1 });
    const wrong = structuredClone(relocated); wrong[1].sha256 = 'f'.repeat(64);
    assert.throws(() => verifyCandidateSources(root, { artifacts: wrong }, { complete: false }), /frozen identity/);
    const candidateRoot = path.join(root, 'detached-candidate'); mkdirSync(candidateRoot); renameSync(path.join(root, 'release'), path.join(candidateRoot, 'release'));
    assert.deepEqual(verifyRequiredSourceMaterials(root, wanted, { candidate: { artifacts: relocated }, artifactRoot: candidateRoot }), { verified: true, original_source_materials: 1 });
    assert.throws(() => verifyRequiredSourceMaterials(root, wanted, { candidate: { artifacts: relocated } }), /ENOENT/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
