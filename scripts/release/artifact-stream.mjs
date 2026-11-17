/** Immutable file-handle admission and bounded streaming for large release assets. */
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import path from 'node:path';
import { safeRelative } from './candidate.mjs';
export const MAX_RELEASE_ASSET = 2 * 1024 ** 3 - 1;
function insist(value, message) { if (!value) throw new Error(message); }
const identity = (left, right) => ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => left[key] === right[key]);
export class PinnedArtifact {
  constructor(root, record) {
    insist(typeof root === 'string' && path.isAbsolute(root) && record && /^[0-9a-f]{64}$/.test(record.sha256 ?? '') && Number.isSafeInteger(record.size) && record.size >= 0 && record.size <= MAX_RELEASE_ASSET, 'Invalid bounded release artifact.');
    safeRelative(record.path); let filename = root;
    for (const part of record.path.split('/')) { filename = path.join(filename, part); insist(!lstatSync(filename).isSymbolicLink(), 'Release artifact traverses a symbolic link.'); }
    this.record = { ...record }; this.fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); this.complete = false; this.error = null;
    try {
      this.stat = fstatSync(this.fd, { bigint: true }); insist(this.stat.isFile() && this.stat.size === BigInt(record.size), 'Release artifact identity differs.');
      const hash = createHash('sha256'); let position = 0; const bytes = Buffer.alloc(1024 * 1024);
      while (position < record.size) { const count = readSync(this.fd, bytes, 0, Math.min(bytes.length, record.size - position), position); insist(count > 0, 'Release artifact is truncated.'); hash.update(bytes.subarray(0, count)); position += count; }
      insist(hash.digest('hex') === record.sha256, 'Release artifact hash differs.'); this.check();
    } catch (error) { this.close(); throw error; }
  }
  check() { insist(this.fd !== null && identity(this.stat, fstatSync(this.fd, { bigint: true })), 'Pinned release artifact changed.'); }
  async *chunks() {
    this.complete = false; this.error = null; const hash = createHash('sha256'); let position = 0;
    try {
      this.check();
      while (position < this.record.size) { const bytes = Buffer.allocUnsafe(Math.min(64 * 1024, this.record.size - position)); const count = readSync(this.fd, bytes, 0, bytes.length, position); insist(count > 0, 'Pinned release artifact is truncated.'); const chunk = bytes.subarray(0, count); hash.update(chunk); position += count; yield chunk; }
      insist(hash.digest('hex') === this.record.sha256, 'Pinned release artifact bytes changed.'); this.check(); this.complete = true;
    } catch (error) { this.error = error; throw error; }
  }
  close() { if (this.fd !== null) { closeSync(this.fd); this.fd = null; } }
}
