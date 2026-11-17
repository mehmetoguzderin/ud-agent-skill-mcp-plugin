/** Bind bounded corresponding-source shards to candidate and SBOM inventories. */
import { closeSync, constants, fstatSync, openSync, readSync, existsSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileReceipt, readRecordedBytes, safeRelative, verifyRecordedFile } from './candidate.mjs';
import { SourceTarVerifier } from './source-tar.mjs';
const SHA = /^[a-f0-9]{64}$/;
function insist(value, message) { if (!value) throw new Error(message); }

/**
 * @overload
 * @param {string} root
 * @param {{required?: boolean, complete?: boolean, includeManifest: true, candidate?: any, artifactRoot?: string}} options
 * @returns {{artifacts: any[], manifest: any}}
 */
/**
 * @overload
 * @param {string} root
 * @param {{required?: boolean, complete?: boolean, includeManifest?: false, candidate?: any, artifactRoot?: string}} [options]
 * @returns {any[]}
 */
/** @param {{required?: boolean, complete?: boolean, includeManifest?: boolean, candidate?: any, artifactRoot?: string}} [options] */
export function sourceArtifacts(root, options = {}) {
  const { required = false, complete = false, includeManifest = false, candidate, artifactRoot = root } = options;
  const name = 'runtime/source-materials.lock.json';
  if (!existsSync(path.join(root, name))) { insist(!required, 'Corresponding-source artifact lock is missing.'); return includeManifest ? { artifacts: [], manifest: undefined } : []; }
  let lock = JSON.parse(readRecordedBytes(root, fileReceipt(root, name)).toString('utf8'));
  insist(lock.schema_version === 1 && lock.index && Array.isArray(lock.parts) && lock.parts.length > 0 && lock.parts.length <= 1000, 'Corresponding-source artifact lock is invalid.');
  if (candidate !== undefined) {
    const released = (row, id) => {
      const found = candidate.artifacts?.filter(item => item.id === id);
      insist(found?.length === 1 && found[0].sha256 === row.sha256 && found[0].size === row.size && path.posix.basename(safeRelative(found[0].path)) === path.posix.basename(safeRelative(row.path)), 'Candidate omits or changes a corresponding-source sidecar frozen identity.');
      return { ...row, path: found[0].path };
    };
    lock = { ...lock, index: released(lock.index, 'corresponding-source-index'), parts: lock.parts.map(row => released(row, row.id)) };
  }
  const index = JSON.parse(readRecordedBytes(artifactRoot, lock.index).toString('utf8'));
  insist(index.schema_version === 1 && index.qualification === 'verified-corresponding-source-subinventories' && index.format === 'concatenated-ustar' && SHA.test(index.stream_sha256 ?? '') && SHA.test(index.manifest_sha256 ?? '') && Number.isSafeInteger(index.stream_size_bytes) && index.stream_size_bytes > 0 && Array.isArray(index.parts) && index.parts.length === lock.parts.length && typeof index.complete_product_coverage === 'boolean', 'Corresponding-source index is invalid.');
  insist(!complete || index.complete_product_coverage === true, 'Corresponding-source product coverage is incomplete.');
  const hash = createHash('sha256'), tar = new SourceTarVerifier(index), chunk = Buffer.alloc(1024 * 1024), seen = new Set(); let total = 0;
  for (const [number, item] of lock.parts.entries()) {
    const expected = index.parts[number]; safeRelative(item.path);
    insist(item.id === `corresponding-source-${String(number).padStart(4, '0')}` && !seen.has(item.path) && path.posix.basename(item.path) === expected.path && item.id === expected.id && item.size === expected.size && item.sha256 === expected.sha256 && item.size > 0 && item.size < 2 * 1024 ** 3, 'Source shard inventory differs from the exact ordered index.');
    seen.add(item.path); verifyRecordedFile(artifactRoot, item);
    const fd = openSync(path.join(artifactRoot, ...item.path.split('/')), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const before = fstatSync(fd, { bigint: true }); let offset = 0;
      insist(before.isFile() && before.size === BigInt(item.size), 'Source shard changed before stream verification.');
      while (offset < item.size) { const count = readSync(fd, chunk, 0, Math.min(chunk.length, item.size - offset), offset); insist(count > 0, 'Source shard is truncated.'); hash.update(chunk.subarray(0, count)); tar.feed(chunk.subarray(0, count)); offset += count; }
      const after = fstatSync(fd, { bigint: true }); insist(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => before[key] === after[key]), 'Source shard changed during stream verification.');
    } finally { closeSync(fd); }
    total += item.size;
  }
  insist(total === index.stream_size_bytes && hash.digest('hex') === index.stream_sha256, 'Reassembled corresponding-source stream differs from its index.');
  tar.finish();
  const artifacts = [{ ...lock.index, id: 'corresponding-source-index', platform: 'all', complete_product_coverage: index.complete_product_coverage }, ...lock.parts.map(item => ({ ...item, platform: 'all' }))];
  return includeManifest ? { artifacts, manifest: tar.manifest } : artifacts;
}

/** Exact physical source scope; flags or unrelated extra blobs cannot satisfy it. */
/** @param {{candidate?: any, artifactRoot?: string}} [options] */
export function verifyRequiredSourceMaterials(root, required, options = {}) {
  const { candidate, artifactRoot = root } = options;
  insist(Array.isArray(required) && required.length > 0 && required.length <= 100000, 'Actual shipped component source requirements are missing.');
  const expected = new Map();
  for (const row of required) { insist(SHA.test(row.sha256 ?? '') && Number.isSafeInteger(row.size_bytes) && row.size_bytes >= 0 && !expected.has(row.sha256), 'Actual source requirements are invalid or duplicated.'); expected.set(row.sha256, row.size_bytes); }
  const { manifest } = sourceArtifacts(root, { required: true, includeManifest: true, candidate, artifactRoot });
  insist(manifest.files.length === expected.size && manifest.files.every(row => expected.get(row.sha256) === row.size_bytes), 'Physical source parts omit required source bytes or contain unselected software/materials.');
  return { verified: true, original_source_materials: expected.size };
}

export function verifyCandidateSources(root, candidate, { complete = true } = {}) {
  const required = sourceArtifacts(root, { required: true, complete, candidate });
  for (const item of required) {
    const found = candidate.artifacts.filter(artifact => artifact.id === item.id);
    insist(found.length === 1 && found[0].sha256 === item.sha256 && found[0].size === item.size, 'Candidate omits or changes a corresponding-source artifact.');
  }
  return { verified: true, complete_product_coverage: required[0].complete_product_coverage, artifacts: required.map(({ id, sha256, size }) => ({ id, sha256, size })) };
}
