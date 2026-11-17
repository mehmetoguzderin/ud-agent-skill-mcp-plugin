import { createHash } from 'node:crypto';
import { guardedRead } from './guard.js';
import { verifySnapshotIntegrity } from './snapshot.js';
import type { Snapshot, SnapshotFile } from './snapshot.js';
import { validCandidatePath } from './transactions.js';
import { portablePathKey } from './portable-path.js';

const MAX_FILE = 64 * 1024 * 1024;
const MAX_TOTAL = 512 * 1024 * 1024;
const MAX_FILES = 10_000;
export const TRANSFER_CHUNK_BYTES = 64 * 1024;

type Manifest = { path: string; size: number; sha256: string }[];
export type SnapshotFrame =
  | { type: 'begin'; manifest: Manifest; snapshot_sha256: string }
  | { type: 'chunk'; path: string; offset: number; bytes: Buffer }
  | { type: 'file_end'; path: string }
  | { type: 'end'; snapshot_sha256: string };

/** Sink writes are tentative until commit; abort must discard all partial data. */
export interface SnapshotTransferSink {
  begin(files: readonly SnapshotFile[]): Promise<void>;
  startFile(file: SnapshotFile): Promise<void>;
  writeChunk(bytes: Buffer): Promise<void>;
  finishFile(file: SnapshotFile): Promise<void>;
  commit(): Promise<void>;
  abort(): Promise<void>;
}

function manifestHash(files: readonly SnapshotFile[]): string {
  return createHash('sha256').update(JSON.stringify(files)).digest('hex');
}
function validateManifest(value: unknown, expected: string): Manifest {
  if (!/^[0-9a-f]{64}$/.test(expected) || !Array.isArray(value) || value.length > MAX_FILES) throw new Error('Invalid snapshot manifest.');
  const files: Manifest = []; let total = 0; let previous = '';
  const normalized = new Set<string>();
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Invalid snapshot manifest entry.');
    const file = item as Record<string, unknown>;
    if (Object.keys(file).sort().join(',') !== 'path,sha256,size' || typeof file.path !== 'string' || !validCandidatePath(file.path) || (previous !== '' && previous >= file.path) || !Number.isSafeInteger(file.size) || (file.size as number) < 0 || (file.size as number) > MAX_FILE || typeof file.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(file.sha256)) throw new Error('Invalid snapshot manifest entry.');
    const key = portablePathKey(file.path);
    if (normalized.has(key)) throw new Error('Snapshot manifest paths collide.');
    normalized.add(key); previous = file.path; total += file.size as number;
    if (total > MAX_TOTAL) throw new Error('Snapshot transfer exceeds its byte budget.');
    files.push({ path: file.path, size: file.size as number, sha256: file.sha256 });
  }
  for (const key of normalized) {
    const parts = key.split('/');
    for (let index = 1; index < parts.length; index++) {
      if (normalized.has(parts.slice(0, index).join('/'))) throw new Error('Snapshot manifest has a file and directory path conflict.');
    }
  }
  if (manifestHash(files) !== expected) throw new Error('Snapshot manifest fingerprint does not match.');
  return files;
}
function checkCancelled(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('SNAPSHOT_TRANSFER_CANCELLED'); }

/**
 * Reads each file via its identity-bound guard before yielding its immutable
 * bytes. This provides transport data without passing a mount pathname to an
 * engine. A receiver must treat all frames as tentative until a complete end.
 */
export async function* streamVerifiedSnapshot(guard: string, snapshot: Snapshot, signal?: AbortSignal): AsyncGenerator<SnapshotFrame> {
  const files = validateManifest(snapshot.files, snapshot.sha256);
  const frozen: Snapshot = { ...snapshot, files, snapshot_identity: { ...snapshot.snapshot_identity }, root_identity: { ...snapshot.root_identity } };
  checkCancelled(signal);
  const directory = await verifySnapshotIntegrity(guard, frozen, signal);
  checkCancelled(signal);
  yield { type: 'begin', manifest: files.map(file => ({ ...file })), snapshot_sha256: frozen.sha256 };
  for (const file of files) {
    checkCancelled(signal);
    const bytes = await guardedRead(guard, directory, file.path, MAX_FILE, frozen.snapshot_identity, signal);
    checkCancelled(signal);
    if (bytes.length !== file.size || createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error(`Snapshot transfer input changed: ${file.path}`);
    for (let offset = 0; offset < bytes.length; offset += TRANSFER_CHUNK_BYTES) {
      checkCancelled(signal);
      yield { type: 'chunk', path: file.path, offset, bytes: Buffer.from(bytes.subarray(offset, offset + TRANSFER_CHUNK_BYTES)) };
    }
    checkCancelled(signal);
    yield { type: 'file_end', path: file.path };
  }
  checkCancelled(signal);
  yield { type: 'end', snapshot_sha256: frozen.sha256 };
}

/**
 * Verify framing, byte counts and all per-file hashes before committing. The
 * expected manifest hash must arrive over an authenticated broker channel;
 * this helper alone cannot establish that channel or read-only destination.
 */
export async function receiveVerifiedSnapshot(frames: AsyncIterable<SnapshotFrame>, expected: string, sink: SnapshotTransferSink, signal?: AbortSignal): Promise<void> {
  let files: Manifest | undefined; let index = 0; let offset = 0; let hasher = createHash('sha256'); let started = false; let ended = false;
  try {
    for await (const frame of frames) {
      checkCancelled(signal);
      if (!frame || typeof frame !== 'object' || ended) throw new Error('Unexpected snapshot transfer frame.');
      if (!files) {
        if (frame.type !== 'begin' || frame.snapshot_sha256 !== expected) throw new Error('Snapshot transfer must begin with the expected manifest.');
        files = validateManifest(frame.manifest, expected);
        await sink.begin(files.map(file => ({ ...file })));
        continue;
      }
      if (frame.type === 'end') {
        if (frame.snapshot_sha256 !== expected || index !== files.length || started) throw new Error('Snapshot transfer ended before all files were verified.');
        ended = true; continue;
      }
      const file = files[index];
      if (!file) throw new Error('Snapshot transfer has unexpected file data.');
      if (!started) { await sink.startFile({ ...file }); started = true; }
      if (frame.type === 'chunk') {
        if (frame.path !== file.path || frame.offset !== offset || !Buffer.isBuffer(frame.bytes) || frame.bytes.length === 0 || frame.bytes.length > TRANSFER_CHUNK_BYTES || offset + frame.bytes.length > file.size) throw new Error('Invalid snapshot transfer chunk.');
        // Do not expose a mutable buffer that the producer can modify while writing.
        const bytes = Buffer.from(frame.bytes); hasher.update(bytes); await sink.writeChunk(bytes); offset += bytes.length;
      } else if (frame.type === 'file_end') {
        if (frame.path !== file.path || offset !== file.size || hasher.digest('hex') !== file.sha256) throw new Error('Snapshot transfer file fingerprint does not match.');
        await sink.finishFile({ ...file }); index++; offset = 0; hasher = createHash('sha256'); started = false;
      } else throw new Error('Unexpected snapshot transfer frame.');
    }
    checkCancelled(signal);
    if (!files || !ended) throw new Error('Snapshot transfer was incomplete.');
    await sink.commit();
  } catch (error: unknown) {
    try { await sink.abort(); } catch { throw new Error('SNAPSHOT_TRANSFER_ABORT_UNVERIFIED'); }
    throw error;
  }
}
