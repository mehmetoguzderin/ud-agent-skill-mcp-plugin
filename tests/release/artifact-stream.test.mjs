import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PinnedArtifact, MAX_RELEASE_ASSET } from '../../scripts/release/artifact-stream.mjs';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('pinned artifact streaming preserves exact bytes without reopening a pathname', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-stream-'))), bytes = Buffer.alloc(256 * 1024 + 17, 73); writeFileSync(path.join(root, 'asset'), bytes);
  const subject = new PinnedArtifact(root, { path: 'asset', sha256: sha(bytes), size: bytes.length });
  try {
    const chunks = []; for await (const chunk of subject.chunks()) { assert.ok(chunk.length <= 64 * 1024); chunks.push(chunk); }
    assert.deepEqual(Buffer.concat(chunks), bytes); assert.equal(subject.complete, true); assert.equal(subject.error, null);
    const repeated = []; for await (const chunk of subject.chunks()) repeated.push(chunk); assert.deepEqual(Buffer.concat(repeated), bytes);
  } finally { subject.close(); rmSync(root, { recursive: true, force: true }); }
  assert.throws(() => subject.check(), /changed/);
});

test('pinned streams reject source swaps, corruption, escapes and oversized metadata', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-stream-'))), file = path.join(root, 'asset'); writeFileSync(file, 'original');
  const record = { path: 'asset', sha256: sha(Buffer.from('original')), size: 8 };
  try {
    assert.throws(() => new PinnedArtifact(root, { ...record, sha256: '0'.repeat(64) }), /hash differs/);
    assert.throws(() => new PinnedArtifact(root, { ...record, size: MAX_RELEASE_ASSET + 1 }), /bounded/);
    assert.throws(() => new PinnedArtifact(root, { ...record, path: '../asset' }), /relative|path/i);
    symlinkSync(file, path.join(root, 'linked')); assert.throws(() => new PinnedArtifact(root, { ...record, path: 'linked' }), /symbolic link/);
    const subject = new PinnedArtifact(root, record);
    try {
      writeFileSync(file, 'changed!');
      await assert.rejects(async () => { for await (const _ of subject.chunks()) {} }, /changed/);
      assert.equal(subject.complete, false); assert.match(subject.error.message, /changed/);
    } finally { subject.close(); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
