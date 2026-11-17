/** Verify an uncompressed OCI image-layout archive without extracting it. */
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const SHA = /^sha256:([0-9a-f]{64})$/;
const MAX_JSON = 16 * 1024 * 1024;
const MAX_ENTRIES = 50_000;
const MAX_ARCHIVE = 32 * 1024 * 1024 * 1024;
const BLOCK = 512;
const MAX_UNPACKED_LAYER = 8 * 1024 * 1024 * 1024;
const INDEX = new Set(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json']);
const MANIFEST = new Set(['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json']);
const CONFIG = new Set(['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json']);

function insist(condition, message) { if (!condition) throw new Error(`OCI archive: ${message}`); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function octal(bytes) {
  const value = bytes.toString('ascii').replace(/\0.*$/, '').trim();
  insist(value === '' || /^[0-7]+$/.test(value), 'invalid tar numeric field');
  const result = value ? Number.parseInt(value, 8) : 0;
  insist(Number.isSafeInteger(result) && result >= 0, 'tar numeric field is out of range');
  return result;
}
function field(bytes) { return bytes.toString('utf8').replace(/\0.*$/, ''); }
function readExactly(fd, size, position) {
  const bytes = Buffer.alloc(size); let offset = 0;
  while (offset < size) {
    const count = readSync(fd, bytes, offset, size - offset, position + offset);
    insist(count > 0, 'truncated archive'); offset += count;
  }
  return bytes;
}
function json(bytes) {
  try { const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); insist(value && typeof value === 'object' && !Array.isArray(value), 'expected a JSON object'); return value; }
  catch (error) { if (error instanceof Error && error.message.startsWith('OCI archive:')) throw error; throw new Error('OCI archive: invalid JSON'); }
}
function descriptor(value) {
  insist(value && typeof value === 'object' && !Array.isArray(value), 'invalid descriptor');
  const match = SHA.exec(value.digest ?? '');
  insist(match && Number.isSafeInteger(value.size) && value.size >= 0 && typeof value.mediaType === 'string', 'invalid descriptor identity');
  return match[1];
}

// A child hashes decompressed bytes in bounded chunks. It inherits only the
// already-open archive descriptor, preventing a pathname swap between checks.
const DECOMPRESS = String.raw`
const fs = require('node:fs');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const { Writable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const [start, end, limit, kind] = process.argv.slice(1);
const factory = kind === 'gzip' ? zlib.createGunzip : zlib.createZstdDecompress;
if (typeof factory !== 'function') { process.stderr.write('unsupported compression'); process.exit(2); }
let count = 0;
const digest = crypto.createHash('sha256');
const sink = new Writable({write(chunk, _encoding, done) {
  count += chunk.length;
  if (count > Number(limit)) return done(new Error('uncompressed layer exceeds limit'));
  digest.update(chunk); done();
}});
pipeline(fs.createReadStream(null, {fd: 3, autoClose: false, start: Number(start), end: Number(end)}), factory(), sink)
  .then(() => process.stdout.write(JSON.stringify({digest: digest.digest('hex'), size: count})))
  .catch(error => { process.stderr.write(String(error.message)); process.exitCode = 1; });
`;
function layerDiffId(fd, entry, mediaType) {
  if (mediaType.endsWith('.tar')) {
    insist(entry.size <= MAX_UNPACKED_LAYER, 'uncompressed layer exceeds limit');
    return { digest: `sha256:${entry.digest}`, size: entry.size };
  }
  insist(entry.size > 0, 'compressed layer is empty');
  const kind = mediaType.endsWith('zstd') ? 'zstd' : 'gzip';
  const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.NODE_PATH;
  const result = spawnSync(process.execPath, ['-e', DECOMPRESS, String(entry.offset), String(entry.offset + entry.size - 1), String(MAX_UNPACKED_LAYER), kind],
    { stdio: ['ignore', 'pipe', 'pipe', fd], encoding: 'utf8', maxBuffer: 1024, timeout: 300_000, env });
  insist(!result.error && result.status === 0, 'layer decompression failed or is unsupported');
  let value; try { value = JSON.parse(result.stdout); } catch { throw new Error('OCI archive: layer decompression returned invalid evidence'); }
  insist(/^[0-9a-f]{64}$/.test(value.digest ?? '') && Number.isSafeInteger(value.size) && value.size >= 0 && value.size <= MAX_UNPACKED_LAYER, 'layer decompression returned invalid evidence');
  return { digest: `sha256:${value.digest}`, size: value.size };
}

/** Expect a deterministic, uncompressed OCI layout tar; never follow links. */
export function verifyOciArchive(filename, expectedIndex, expectedPlatforms, archiveReceipt, expectedImages, { diagnosticSinglePlatform = false, includeLayerSizes = false } = {}) {
  insist(SHA.test(expectedIndex ?? ''), 'invalid expected index digest');
  const platformNames=Object.keys(expectedPlatforms??{}).sort();
  insist(expectedPlatforms && (platformNames.join(',') === 'linux/amd64,linux/arm64' || (diagnosticSinglePlatform && platformNames.length===1 && ['linux/arm64','linux/amd64'].includes(platformNames[0]))) && Object.values(expectedPlatforms).every(value => SHA.test(value)), 'invalid expected platform set');
  const fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd, { bigint: true });
    insist(before.isFile() && before.size <= BigInt(MAX_ARCHIVE), 'archive is not a bounded regular file');
    const archiveSize = Number(before.size); const entries = new Map(); let offset = 0; let zeros = 0;
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    if (archiveReceipt) {
      insist(/^[0-9a-f]{64}$/.test(archiveReceipt.sha256 ?? '') && archiveReceipt.size === archiveSize, 'archive receipt mismatch');
      const digest = createHash('sha256'); let position = 0;
      while (position < archiveSize) { const count = readSync(fd, chunk, 0, Math.min(chunk.length, archiveSize - position), position); insist(count > 0, 'truncated archive'); digest.update(chunk.subarray(0, count)); position += count; }
      insist(digest.digest('hex') === archiveReceipt.sha256, 'archive receipt mismatch');
    }
    while (offset + BLOCK <= archiveSize) {
      const header = readExactly(fd, BLOCK, offset); offset += BLOCK;
      if (header.every(byte => byte === 0)) { zeros++; if (zeros === 2) break; continue; }
      insist(zeros === 0, 'nonzero data after end marker');
      let checksum = 0; for (let i = 0; i < BLOCK; i++) checksum += i >= 148 && i < 156 ? 32 : header[i];
      insist(checksum === octal(header.subarray(148, 156)), 'tar header checksum mismatch');
      const prefix = field(header.subarray(345, 500)); const leaf = field(header.subarray(0, 100));
      const name = (prefix ? `${prefix}/${leaf}` : leaf).replace(/^\.\//, '');
      const type = header[156]; const size = octal(header.subarray(124, 136));
      insist(name && !name.startsWith('/') && !name.includes('\\') && !name.split('/').some(part => part === '.' || part === '..'), 'unsafe tar path');
      insist(entries.size < MAX_ENTRIES && !entries.has(name), 'duplicate or excessive tar entries');
      insist(type === 0 || type === 48 || type === 53, 'links and special tar entries are unsupported');
      if (type === 53) { insist(size === 0 && ['blobs/', 'blobs/sha256/'].includes(name), 'unexpected directory'); entries.set(name, { size, offset }); continue; }
      insist(name === 'oci-layout' || name === 'index.json' || /^blobs\/sha256\/[0-9a-f]{64}$/.test(name), 'unexpected archive member');
      insist(offset + size <= archiveSize, 'truncated member');
      const digest = createHash('sha256'); let remaining = size; let position = offset;
      while (remaining) { const count = readSync(fd, chunk, 0, Math.min(chunk.length, remaining), position); insist(count > 0, 'truncated member'); digest.update(chunk.subarray(0, count)); remaining -= count; position += count; }
      const actual = digest.digest('hex');
      if (name.startsWith('blobs/')) insist(name.slice('blobs/sha256/'.length) === actual, 'blob digest mismatch');
      entries.set(name, { size, offset, digest: actual });
      const paddedSize = Math.ceil(size / BLOCK) * BLOCK;
      const padding = paddedSize - size;
      if (padding) insist(readExactly(fd, padding, offset + size).every(byte => byte === 0), 'nonzero tar padding');
      offset += paddedSize;
    }
    insist(zeros === 2, 'missing tar end marker');
    while (offset < archiveSize) { const part = readExactly(fd, Math.min(1024 * 1024, archiveSize - offset), offset); insist(part.every(byte => byte === 0), 'trailing tar data'); offset += part.length; }
    const readEntry = name => { const entry = entries.get(name); insist(entry && entry.size <= MAX_JSON, `missing or oversized ${name}`); return readExactly(fd, entry.size, entry.offset); };
    insist(json(readEntry('oci-layout')).imageLayoutVersion === '1.0.0', 'unsupported layout version');
    const transportBytes = readEntry('index.json'); let indexBytes = transportBytes; let index = json(indexBytes);
    insist(index.schemaVersion === 2 && INDEX.has(index.mediaType) && Array.isArray(index.manifests), 'invalid transport index');
    const readDescriptor = item => { const id = descriptor(item); const entry = entries.get(`blobs/sha256/${id}`); insist(entry && entry.size === item.size && entry.digest === id, 'missing or mismatched descriptor blob'); return entry; };
    if (`sha256:${hash(indexBytes)}` !== expectedIndex) {
      insist(Array.isArray(index.manifests) && index.manifests.length === 1 && index.manifests[0].digest === expectedIndex && INDEX.has(index.manifests[0].mediaType), 'index digest mismatch');
      const entry = readDescriptor(index.manifests[0]); insist(entry.size <= MAX_JSON, 'index is too large');
      indexBytes = readExactly(fd, entry.size, entry.offset); index = json(indexBytes);
    }
    insist(index.schemaVersion === 2 && INDEX.has(index.mediaType) && Array.isArray(index.manifests) && index.manifests.length === platformNames.length, 'invalid platform index');
    const seen = new Set(), layerSizes = {};
    for (const item of index.manifests) {
      const platform = `${item.platform?.os}/${item.platform?.architecture}`;
      insist(Object.hasOwn(expectedPlatforms, platform) && !seen.has(platform) && item.digest === expectedPlatforms[platform] && MANIFEST.has(item.mediaType), 'unexpected platform manifest');
      seen.add(platform); const entry = readDescriptor(item); insist(entry.size <= MAX_JSON, 'manifest is too large');
      const manifest = json(readExactly(fd, entry.size, entry.offset));
      insist(manifest.schemaVersion === 2 && MANIFEST.has(manifest.mediaType) && Array.isArray(manifest.layers), 'invalid image manifest');
      insist(CONFIG.has(manifest.config?.mediaType), 'invalid image config type');
      const configEntry = readDescriptor(manifest.config); insist(configEntry.size <= MAX_JSON, 'config is too large');
      const config = json(readExactly(fd, configEntry.size, configEntry.offset));
      insist(`${config.os}/${config.architecture}` === platform, 'image configuration platform mismatch');
      insist(config.rootfs?.type === 'layers' && Array.isArray(config.rootfs.diff_ids) && config.rootfs.diff_ids.length === manifest.layers.length && config.rootfs.diff_ids.every(id => SHA.test(id)), 'invalid rootfs diff IDs');
      if (expectedImages !== undefined) {
        const expected = expectedImages[platform];
        insist(expected && expected.digest === item.digest && expected.config_digest === `sha256:${configEntry.digest}` && JSON.stringify(expected.diff_ids) === JSON.stringify(config.rootfs.diff_ids), 'runtime image config or diff IDs differ from verified OCI graph');
        const wrappers = expected.engine_descriptor_digests ?? [];
        insist(Array.isArray(wrappers) && wrappers.length <= 16 && new Set(wrappers).size === wrappers.length, 'invalid engine descriptor inventory');
        const visitWrapper = (digest, ancestors = new Set()) => {
          insist(SHA.test(digest) && ancestors.size < 8 && !ancestors.has(digest), 'invalid or cyclic engine descriptor');
          if (digest === expectedIndex || digest === item.digest) return;
          const entry = entries.get(`blobs/sha256/${digest.slice(7)}`);
          insist(entry && entry.size <= MAX_JSON, 'engine descriptor blob is missing');
          const wrapper = json(readExactly(fd, entry.size, entry.offset));
          insist(wrapper.schemaVersion === 2 && INDEX.has(wrapper.mediaType) && Array.isArray(wrapper.manifests) && wrapper.manifests.length === 1, 'engine descriptor must contain exactly the selected image');
          const child = wrapper.manifests[0]; readDescriptor(child);
          insist((child.digest === item.digest && MANIFEST.has(child.mediaType)) || INDEX.has(child.mediaType), 'engine descriptor selects an unverified image');
          visitWrapper(child.digest, new Set([...ancestors, digest]));
        };
        for (const digest of wrappers) visitWrapper(digest);
      }
      layerSizes[platform] = [];
      for (const [number, layer] of manifest.layers.entries()) {
        insist(typeof layer?.mediaType === 'string' && /^(?:application\/vnd\.oci\.image\.layer\.v1\.tar(?:\+(?:gzip|zstd))?|application\/vnd\.docker\.image\.rootfs\.diff\.tar(?:\.gzip)?)$/.test(layer.mediaType), 'invalid layer type');
        const layerEntry = readDescriptor(layer);
        const actual = layerDiffId(fd, layerEntry, layer.mediaType);
        insist(actual.digest === config.rootfs.diff_ids[number], 'layer diff ID mismatch');
        if (includeLayerSizes) layerSizes[platform].push({ digest: layer.digest, size_bytes: layerEntry.size, uncompressed_size_bytes: actual.size });
      }
    }
    insist(seen.size === platformNames.length, 'platform manifests missing');
    const after = fstatSync(fd, { bigint: true });
    insist(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs, 'archive changed during verification');
    return { index_digest: expectedIndex, platforms: { ...expectedPlatforms }, ...(includeLayerSizes ? { layer_sizes: layerSizes } : {}) };
  } finally { closeSync(fd); }
}
