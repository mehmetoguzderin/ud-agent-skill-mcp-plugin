import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { verifyOciArchive } from '../../scripts/release/oci.mjs';
import { createOciFixture, fixtureTar } from './oci-fixture.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const indexType = 'application/vnd.oci.image.index.v1+json';
const imageType = 'application/vnd.oci.image.manifest.v1+json';
const configType = 'application/vnd.oci.image.config.v1+json';
const layerType = 'application/vnd.oci.image.layer.v1.tar+gzip';
function tar(entries) {
  const out = [];
  for (const [name, value] of entries) {
    const bytes = Buffer.from(value); const header = Buffer.alloc(512);
    header.write(name, 0, 100, 'utf8'); header.write('0000644\0', 100, 'ascii');
    header.write('0000000\0', 108, 'ascii'); header.write('0000000\0', 116, 'ascii');
    header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
    header.write('00000000000\0', 136, 'ascii'); header.fill(32, 148, 156);
    header[156] = 48; header.write('ustar\0', 257, 'ascii'); header.write('00', 263, 'ascii');
    const sum = header.reduce((a, b) => a + b, 0); header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
    out.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...out, Buffer.alloc(1024)]);
}
function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-oci-test-')); const blobs = new Map();
  const blob = (value, mediaType) => { const bytes = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value)); const digest = sha(bytes); blobs.set(digest, bytes); return { mediaType, digest: `sha256:${digest}`, size: bytes.length }; };
  const manifests = ['amd64', 'arm64'].map(architecture => {
    const contents = tar([['fixture.txt', `fixture layer ${architecture}`]]);
    const config = blob({ os: 'linux', architecture, rootfs: { type: 'layers', diff_ids: [`sha256:${sha(contents)}`] } }, configType);
    const layer = blob(gzipSync(contents), layerType);
    return { ...blob({ schemaVersion: 2, mediaType: imageType, config, layers: [layer] }, imageType), platform: { os: 'linux', architecture } };
  });
  const index = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: indexType, manifests }));
  const entries = [['oci-layout', JSON.stringify({ imageLayoutVersion: '1.0.0' })], ['index.json', index], ...[...blobs].map(([digest, bytes]) => [`blobs/sha256/${digest}`, bytes])];
  const filename = path.join(root, 'image.tar'); writeFileSync(filename, tar(entries));
  return { root, filename, entries, expected: `sha256:${sha(index)}`, platforms: Object.fromEntries(manifests.map(item => [`linux/${item.platform.architecture}`, item.digest])), cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test('verifies both image manifests, configs, and layer blobs without extraction', () => {
  const f = fixture(); try { assert.deepEqual(verifyOciArchive(f.filename, f.expected, f.platforms), { index_digest: f.expected, platforms: f.platforms }); } finally { f.cleanup(); }
});

test('reports actual verified uncompressed layer sizes only when requested', () => {
  const f = fixture(); try {
    const result = verifyOciArchive(f.filename, f.expected, f.platforms, undefined, undefined, { includeLayerSizes: true });
    for (const architecture of ['amd64', 'arm64']) {
      const [layer] = result.layer_sizes['linux/' + architecture];
      const contents = tar([['fixture.txt', `fixture layer ${architecture}`]]);
      assert.equal(layer.uncompressed_size_bytes, contents.length);
      assert.equal(layer.size_bytes, gzipSync(contents).length);
      assert.match(layer.digest, /^sha256:[0-9a-f]{64}$/);
    }
  } finally { f.cleanup(); }
});

test('binds local Docker index identities to the selected platform config and rootfs', () => {
  const f = fixture();
  try {
    const index = JSON.parse(f.entries.find(([name]) => name === 'index.json')[1]);
    const entries = [...f.entries];
    const images = {};
    for (const item of index.manifests) {
      const platform = `${item.platform.os}/${item.platform.architecture}`;
      const manifest = JSON.parse(entries.find(([name]) => name === `blobs/sha256/${item.digest.slice(7)}`)[1]);
      const config = JSON.parse(entries.find(([name]) => name === `blobs/sha256/${manifest.config.digest.slice(7)}`)[1]);
      const bytes = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: indexType, manifests: [item] }));
      const wrapper = `sha256:${sha(bytes)}`;
      entries.push([`blobs/sha256/${wrapper.slice(7)}`, bytes]);
      images[platform] = { digest: item.digest, config_digest: manifest.config.digest, diff_ids: config.rootfs.diff_ids, engine_descriptor_digests: [wrapper] };
    }
    writeFileSync(f.filename, tar(entries));
    assert.equal(verifyOciArchive(f.filename, f.expected, f.platforms, undefined, images).index_digest, f.expected);
    const wrong = structuredClone(images);
    wrong['linux/arm64'].engine_descriptor_digests = images['linux/amd64'].engine_descriptor_digests;
    assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms, undefined, wrong), /unverified image/);
    wrong['linux/arm64'] = { ...images['linux/arm64'], config_digest: `sha256:${'0'.repeat(64)}` };
    assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms, undefined, wrong), /config or diff IDs/);
  } finally { f.cleanup(); }
});

test('rejects changed blobs, unexpected platforms, and a false index digest', () => {
  const f = fixture(); try {
    assert.throws(() => verifyOciArchive(f.filename, `sha256:${'a'.repeat(64)}`, f.platforms), /index digest/);
    assert.throws(() => verifyOciArchive(f.filename, f.expected, { ...f.platforms, 'linux/arm64': `sha256:${'b'.repeat(64)}` }), /platform manifest/);
    const changed = f.entries.map(([name, bytes]) => name.startsWith('blobs/') ? [name, Buffer.from('altered')] : [name, bytes]);
    writeFileSync(f.filename, tar(changed)); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /blob digest mismatch/);
  } finally { f.cleanup(); }
});

test('rejects duplicate members, traversal, invalid headers, and truncated archives', () => {
  const f = fixture(); try {
    writeFileSync(f.filename, tar([...f.entries, f.entries[0]])); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /duplicate/);
    writeFileSync(f.filename, tar([...f.entries, ['../escape', 'bad']])); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /unsafe tar path/);
    const damaged = tar(f.entries); damaged[0] ^= 1; writeFileSync(f.filename, damaged); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /checksum/);
    writeFileSync(f.filename, tar(f.entries).subarray(0, 520)); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /truncated|end marker/);
  } finally { f.cleanup(); }
});

test('verifies the archive receipt and rejects tampering before interpreting its content', () => {
  const f = fixture(); try {
    const bytes = tar(f.entries); const receipt = { sha256: sha(bytes), size: bytes.length };
    assert.equal(verifyOciArchive(f.filename, f.expected, f.platforms, receipt).index_digest, f.expected);
    assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms, { ...receipt, size: receipt.size + 1 }), /archive receipt mismatch/);
    assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms, { ...receipt, sha256: 'f'.repeat(64) }), /archive receipt mismatch/);
    assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms, { ...receipt, sha256: 'bad' }), /archive receipt mismatch/);
  } finally { f.cleanup(); }
});

test('accepts an OCI transport index that references the pinned multi-platform index', () => {
  const f = fixture(); try {
    const index = Buffer.from(f.entries.find(([name]) => name === 'index.json')[1]);
    const wrapper = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: indexType, manifests: [{ mediaType: indexType, digest: f.expected, size: index.length }] }));
    const wrapped = f.entries.map(([name, bytes]) => [name, name === 'index.json' ? wrapper : bytes]);
    wrapped.push([`blobs/sha256/${sha(index)}`, index]);
    writeFileSync(f.filename, tar(wrapped));
    assert.equal(verifyOciArchive(f.filename, f.expected, f.platforms).index_digest, f.expected);
    writeFileSync(f.filename, tar(wrapped.filter(([name]) => name !== `blobs/sha256/${sha(index)}`)));
    assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /missing or mismatched descriptor blob/);
  } finally { f.cleanup(); }
});

test('accepts a Docker manifest list as the transport index', () => {
  const f = fixture(); try {
    const index = JSON.parse(f.entries.find(([name]) => name === 'index.json')[1]);
    index.mediaType = 'application/vnd.docker.distribution.manifest.list.v2+json';
    const bytes = Buffer.from(JSON.stringify(index));
    writeFileSync(f.filename, tar(f.entries.map(([name, value]) => [name, name === 'index.json' ? bytes : value])));
    assert.equal(verifyOciArchive(f.filename, `sha256:${sha(bytes)}`, f.platforms).index_digest, `sha256:${sha(bytes)}`);
  } finally { f.cleanup(); }
});

test('accepts Docker image manifests and configurations inside an OCI index', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-oci-docker-')); const filename = path.join(root, 'image.tar');
  try {
    const f = createOciFixture('docker-types', { image: 'application/vnd.docker.distribution.manifest.v2+json', config: 'application/vnd.docker.container.image.v1+json' });
    writeFileSync(filename, f.bytes);
    assert.equal(verifyOciArchive(filename, f.index_digest, f.platforms).index_digest, f.index_digest);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('rejects malformed metadata, missing members, and content after the tar end', () => {
  const f = fixture(); try {
    const changeLayout = value => f.entries.map(([name, bytes]) => [name, name === 'oci-layout' ? value : bytes]);
    writeFileSync(f.filename, tar(changeLayout('{'))); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /invalid JSON/);
    writeFileSync(f.filename, tar(changeLayout(Buffer.from([0xff])))); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /invalid JSON/);
    writeFileSync(f.filename, tar(changeLayout('[]'))); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /expected a JSON object/);
    writeFileSync(f.filename, tar(changeLayout('{"imageLayoutVersion":"2.0"}'))); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /unsupported layout/);
    writeFileSync(f.filename, tar(f.entries.filter(([name]) => name !== 'oci-layout'))); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /missing or oversized oci-layout/);
    writeFileSync(f.filename, Buffer.concat([tar(f.entries), Buffer.from('unexpected')])); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /trailing tar data/);
    writeFileSync(f.filename, tar([...f.entries, ['unrelated', 'payload']])); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /unexpected archive member/);
    const padded = tar(f.entries); padded[512 + Buffer.byteLength(f.entries[0][1])] = 1;
    writeFileSync(f.filename, padded); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /nonzero tar padding/);
    const symbolic = fixtureTar([['some-link', '']]); symbolic[156] = 50; symbolic.fill(32, 148, 156); const sum = symbolic.subarray(0, 512).reduce((a, b) => a + b, 0); symbolic.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
    writeFileSync(f.filename, symbolic); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /links and special/);
  } finally { f.cleanup(); }
});

test('rejects forged platform descriptors even when the transport index is rehashed', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-oci-index-')); const filename = path.join(root, 'image.tar');
  try {
    const f = createOciFixture('descriptor');
    const original = JSON.parse(f.entries.find(([name]) => name === 'index.json')[1]);
    const cases = [
      [{ ...original, schemaVersion: 1 }, /invalid transport index/],
      [{ ...original, manifests: [] }, /invalid platform index/],
      [{ ...original, manifests: [original.manifests[0], original.manifests[0]] }, /unexpected platform manifest/],
      [{ ...original, manifests: [{ ...original.manifests[0], size: -1 }, original.manifests[1]] }, /invalid descriptor identity/],
      [{ ...original, manifests: [{ ...original.manifests[0], size: original.manifests[0].size + 1 }, original.manifests[1]] }, /missing or mismatched descriptor blob/],
      [{ ...original, manifests: [{ ...original.manifests[0], mediaType: 'unknown' }, original.manifests[1]] }, /unexpected platform manifest/],
    ];
    for (const [index, error] of cases) {
      const bytes = Buffer.from(JSON.stringify(index));
      writeFileSync(filename, fixtureTar(f.entries.map(([name, value]) => [name, name === 'index.json' ? bytes : value])));
      assert.throws(() => verifyOciArchive(filename, `sha256:${sha(bytes)}`, f.platforms), error);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('requires both complete, correctly identified platform images', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-oci-manifests-')); const filename = path.join(root, 'image.tar');
  try {
    const cases = [
      [{ changeConfig: config => ({ ...config, os: 'windows' }) }, /configuration platform mismatch/],
      [{ changeConfig: config => ({ ...config, architecture: 'riscv64' }) }, /configuration platform mismatch/],
      [{ config: 'application/example' }, /invalid image config type/],
      [{ changeManifest: manifest => ({ ...manifest, schemaVersion: 1 }) }, /invalid image manifest/],
      [{ changeManifest: manifest => ({ ...manifest, mediaType: 'application/example' }) }, /invalid image manifest/],
      [{ changeManifest: manifest => ({ ...manifest, layers: {} }) }, /invalid image manifest/],
      [{ changeManifest: manifest => ({ ...manifest, layers: [{ ...manifest.layers[0], mediaType: 'application/example' }] }) }, /invalid layer type/],
      [{ changeManifest: manifest => ({ ...manifest, layers: [{ ...manifest.layers[0], digest: `sha256:${'0'.repeat(64)}` }] }) }, /missing or mismatched descriptor blob/],
      [{ changeManifest: manifest => ({ ...manifest, config: { ...manifest.config, size: manifest.config.size + 1 } }) }, /missing or mismatched descriptor blob/],
    ];
    for (const [options, error] of cases) {
      const f = createOciFixture('invalid', options); writeFileSync(filename, f.bytes);
      assert.throws(() => verifyOciArchive(filename, f.index_digest, f.platforms), error);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('rejects malformed expected identities before accessing the archive', () => {
  const f = fixture(); try {
    for (const index of [undefined, '', 'sha256:abc', `sha256:${'A'.repeat(64)}`]) assert.throws(() => verifyOciArchive(f.filename, index, f.platforms), /invalid expected index digest/);
    for (const platforms of [undefined, {}, { 'linux/amd64': f.platforms['linux/amd64'] }, { ...f.platforms, 'linux/s390x': f.expected }, { ...f.platforms, 'linux/arm64': 'bad' }]) assert.throws(() => verifyOciArchive(f.filename, f.expected, platforms), /invalid expected platform set/);
  } finally { f.cleanup(); }
});

test('checks tar directories, numeric fields, end markers and alternate regular-file headers', () => {
  const f = fixture();
  function setHeader(block, mutate) {
    const copy = Buffer.from(block); mutate(copy); copy.fill(32, 148, 156);
    const sum = copy.reduce((a, b) => a + b, 0); copy.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii'); return copy;
  }
  try {
    const directory = setHeader(fixtureTar([['blobs/', '']]).subarray(0, 512), header => { header[156] = 53; });
    const nested = setHeader(fixtureTar([['blobs/sha256/', '']]).subarray(0, 512), header => { header[156] = 53; });
    writeFileSync(f.filename, Buffer.concat([directory, nested, tar(f.entries)]));
    assert.equal(verifyOciArchive(f.filename, f.expected, f.platforms).index_digest, f.expected);
    const invalidDirectory = setHeader(fixtureTar([['other/', '']]).subarray(0, 512), header => { header[156] = 53; });
    writeFileSync(f.filename, Buffer.concat([invalidDirectory, tar(f.entries)])); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /unexpected directory/);
    const invalidNumeric = tar(f.entries); const badHeader = setHeader(invalidNumeric.subarray(0, 512), header => { header.write('00000000008\0', 124, 'ascii'); }); badHeader.copy(invalidNumeric);
    writeFileSync(f.filename, invalidNumeric); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /invalid tar numeric field/);
    const alternate = tar(f.entries); const alternateHeader = setHeader(alternate.subarray(0, 512), header => { header[156] = 0; }); alternateHeader.copy(alternate);
    writeFileSync(f.filename, alternate); assert.equal(verifyOciArchive(f.filename, f.expected, f.platforms).index_digest, f.expected);
    writeFileSync(f.filename, Buffer.concat([Buffer.alloc(512), tar(f.entries)])); assert.throws(() => verifyOciArchive(f.filename, f.expected, f.platforms), /nonzero data after end marker/);
  } finally { f.cleanup(); }
});

test('checks config and layer descriptor shape and supported media types', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-oci-layers-')); const filename = path.join(root, 'image.tar');
  try {
    const accepted = ['application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+zstd', 'application/vnd.docker.image.rootfs.diff.tar.gzip'];
    for (const mediaType of accepted) {
      const f = createOciFixture('valid-layer', { layer: mediaType });
      writeFileSync(filename, f.bytes); assert.equal(verifyOciArchive(filename, f.index_digest, f.platforms).index_digest, f.index_digest);
    }
    const invalid = [
      [manifest => ({ ...manifest, config: { ...manifest.config, digest: 'sha256:bad' } }), /invalid descriptor identity/],
      [manifest => ({ ...manifest, config: { ...manifest.config, size: '1' } }), /invalid descriptor identity/],
      [manifest => ({ ...manifest, layers: [null] }), /invalid layer type/],
      [manifest => ({ ...manifest, layers: [{ ...manifest.layers[0], mediaType: 'application/vnd.oci.image.layer.v1.tar+other' }] }), /invalid layer type/],
      [manifest => ({ ...manifest, layers: [{ ...manifest.layers[0], size: manifest.layers[0].size + 1 }] }), /missing or mismatched descriptor blob/],
    ];
    for (const [changeManifest, expected] of invalid) {
      const f = createOciFixture('bad-layer', { changeManifest }); writeFileSync(filename, f.bytes);
      assert.throws(() => verifyOciArchive(filename, f.index_digest, f.platforms), expected);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('requires correctly ordered rootfs diff IDs and validates compressed layer bytes', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-oci-diff-')); const filename = path.join(root, 'image.tar');
  try {
    const cases = [
      [{ changeConfig: config => ({ ...config, rootfs: undefined }) }, /invalid rootfs diff IDs/],
      [{ changeConfig: config => ({ ...config, rootfs: { type: 'other', diff_ids: config.rootfs.diff_ids } }) }, /invalid rootfs diff IDs/],
      [{ changeConfig: config => ({ ...config, rootfs: { type: 'layers', diff_ids: [] } }) }, /invalid rootfs diff IDs/],
      [{ changeConfig: config => ({ ...config, rootfs: { type: 'layers', diff_ids: ['sha256:bad'] } }) }, /invalid rootfs diff IDs/],
      [{ changeConfig: config => ({ ...config, rootfs: { type: 'layers', diff_ids: [`sha256:${'0'.repeat(64)}`] } }) }, /layer diff ID mismatch/],
      [{ layerPayload: Buffer.from('not a gzip stream') }, /layer decompression failed/],
      [{ layerPayload: Buffer.alloc(0) }, /compressed layer is empty/],
    ];
    for (const [options, expected] of cases) {
      const f = createOciFixture('diff-id', options); writeFileSync(filename, f.bytes);
      assert.throws(() => verifyOciArchive(filename, f.index_digest, f.platforms), expected);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
