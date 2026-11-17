import { createHash } from 'node:crypto';
import { gzipSync, zstdCompressSync } from 'node:zlib';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const indexType = 'application/vnd.oci.image.index.v1+json';
const imageType = 'application/vnd.oci.image.manifest.v1+json';
const configType = 'application/vnd.oci.image.config.v1+json';
const layerType = 'application/vnd.oci.image.layer.v1.tar+gzip';

export function fixtureTar(entries) {
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

export function createOciFixture(seed = '', types = {}) {
  const blobs = new Map();
  const blob = (value, mediaType) => { const bytes = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value)); const digest = sha(bytes); blobs.set(digest, bytes); return { mediaType, digest: `sha256:${digest}`, size: bytes.length }; };
  const manifests = ['amd64', 'arm64'].map(architecture => {
    const contents = fixtureTar([['fixture.txt', `fixture layer ${seed} ${architecture}`]]);
    const mediaType = types.layer ?? layerType;
    const payload = mediaType.endsWith('zstd') ? zstdCompressSync(contents) : mediaType.endsWith('gzip') ? gzipSync(contents) : contents;
    const originalConfig = { os: 'linux', architecture, rootfs: { type: 'layers', diff_ids: [`sha256:${sha(contents)}`] } };
    const configValue = types.changeConfig?.(originalConfig, architecture) ?? originalConfig;
    const config = blob(configValue, types.config ?? configType);
    const layer = blob(types.layerPayload ?? payload, mediaType);
    const original = { schemaVersion: 2, mediaType: types.image ?? imageType, config, layers: [layer] };
    const manifest = types.changeManifest?.(original, architecture) ?? original;
    return { ...blob(manifest, types.image ?? imageType), platform: { os: 'linux', architecture } };
  });
  const index = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: indexType, manifests }));
  const entries = [['oci-layout', JSON.stringify({ imageLayoutVersion: '1.0.0' })], ['index.json', index], ...[...blobs].map(([digest, bytes]) => [`blobs/sha256/${digest}`, bytes])];
  return { entries, bytes: fixtureTar(entries), index_digest: `sha256:${sha(index)}`, platforms: Object.fromEntries(manifests.map(item => [`linux/${item.platform.architecture}`, item.digest])) };
}
