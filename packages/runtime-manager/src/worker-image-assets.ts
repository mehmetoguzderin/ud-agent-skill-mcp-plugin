import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';
import path from 'node:path';
import { JournalStore } from '../../workspace/src/journal.js';
import { beginImageImportStaging } from './image-import-staging.js';
import { verifyArchive } from './receipt.js';
import type { ImageTransport } from './receipt.js';
import { withWorkerImageImportLock } from './worker-image-lock.js';
import { recordImageCacheAccess } from './image-cache.js';

type Acquisition = { sourceRoot: string; stateRoot: string; guard: string; transport: ImageTransport; network: 'offline' | 'bootstrap_only'; signal?: AbortSignal; fetcher?: typeof fetch };
const networkCodes = new Set(['ENOTFOUND', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH']);
function cancelled(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('WORKER_CANCELLED'); }
function unavailable(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const value = error as { name?: unknown; code?: unknown; cause?: { code?: unknown } };
  return value.name === 'TimeoutError' || networkCodes.has(String(value.code)) || networkCodes.has(String(value.cause?.code));
}
function validate(input: Acquisition): void {
  const item = input.transport;
  if (![input.sourceRoot, input.stateRoot, input.guard].every(value => typeof value === 'string' && path.isAbsolute(value) && !value.includes('\0')) || !['offline', 'bootstrap_only'].includes(input.network) || !['oci-archive', 'docker-archive'].includes(item.format) || !/^sha256:[0-9a-f]{64}$/.test(item.sha256) || !Number.isSafeInteger(item.sizeBytes) || item.sizeBytes < 1 || item.sizeBytes > 20 * 1024 ** 3 || typeof item.path !== 'string' || item.path.startsWith('/') || item.path.includes('\0') || item.path.includes('\\') || item.path.includes(':') || item.path.split('/').some(part => !part || part === '.' || part === '..') || item.indexDigest !== undefined && (item.format !== 'oci-archive' || !/^sha256:[0-9a-f]{64}$/.test(item.indexDigest))) throw new Error('WORKER_IMAGE_TRANSPORT_INVALID');
}
async function writeVerified(filename: string, chunks: AsyncIterable<Uint8Array>, item: ImageTransport, signal?: AbortSignal): Promise<void> {
  cancelled(signal); const output = await open(filename, 'wx', 0o600); const hash = createHash('sha256'); let size = 0;
  try {
    for await (const chunk of chunks) {
      cancelled(signal); size += chunk.byteLength; if (size > item.sizeBytes) throw new Error('WORKER_IMAGE_TRANSPORT_SIZE_MISMATCH'); hash.update(chunk);
      let offset = 0;
      while (offset < chunk.byteLength) { const result = await output.write(chunk, offset, chunk.byteLength - offset); if (!result.bytesWritten) throw new Error('WORKER_IMAGE_TRANSPORT_WRITE_FAILED'); offset += result.bytesWritten; }
    }
    if (size !== item.sizeBytes || `sha256:${hash.digest('hex')}` !== item.sha256) throw new Error('WORKER_IMAGE_TRANSPORT_INTEGRITY_FAILED');
    cancelled(signal); await output.sync();
  } finally { await output.close(); }
}
async function copyLocal(input: Acquisition, destination: string): Promise<void> {
  let directory = input.sourceRoot;
  for (const part of input.transport.path.split('/').slice(0, -1)) { directory = path.join(directory, part); const info = await lstat(directory); if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('WORKER_IMAGE_TRANSPORT_SOURCE_INVALID'); }
  const file = await open(path.join(input.sourceRoot, ...input.transport.path.split('/')), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true }); if (!before.isFile() || before.size !== BigInt(input.transport.sizeBytes)) throw new Error('WORKER_IMAGE_TRANSPORT_SIZE_MISMATCH');
    async function* contents() { const buffer = Buffer.alloc(1024 * 1024); let offset = 0; for (;;) { cancelled(input.signal); const part = await file.read(buffer, 0, buffer.length, offset); if (!part.bytesRead) break; offset += part.bytesRead; yield buffer.subarray(0, part.bytesRead); } }
    await writeVerified(destination, contents(), input.transport, input.signal); const after = await file.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('WORKER_IMAGE_TRANSPORT_SOURCE_CHANGED');
  } finally { await file.close(); }
}
async function download(input: Acquisition, destination: string): Promise<boolean> {
  let url = new URL(`https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/${encodeURIComponent(path.posix.basename(input.transport.path))}`);
  for (let redirect = 0; redirect < 6; redirect++) {
    cancelled(input.signal);
    let response: Response;
    try { response = await (input.fetcher ?? fetch)(url, { redirect: 'manual', signal: AbortSignal.any([AbortSignal.timeout(120_000), ...(input.signal ? [input.signal] : [])]) }); }
    catch (error) { cancelled(input.signal); if (unavailable(error)) return false; throw error; }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location'); await response.body?.cancel(); if (!location) throw new Error('WORKER_IMAGE_TRANSPORT_REDIRECT_INVALID'); url = new URL(location, url);
      if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hostname !== 'github.com' && !url.hostname.endsWith('.githubusercontent.com')) throw new Error('WORKER_IMAGE_TRANSPORT_REDIRECT_INVALID');
      continue;
    }
    if ([403, 404, 408, 429, 500, 502, 503, 504].includes(response.status)) { await response.body?.cancel(); return false; }
    if (!response.ok || !response.body) { await response.body?.cancel(); throw new Error('WORKER_IMAGE_TRANSPORT_DOWNLOAD_FAILED'); }
    const declared = response.headers.get('content-length'); if (declared !== null && declared !== String(input.transport.sizeBytes)) { await response.body.cancel(); throw new Error('WORKER_IMAGE_TRANSPORT_SIZE_MISMATCH'); }
    try { await writeVerified(destination, response.body, input.transport, input.signal); return true; }
    catch (error) { cancelled(input.signal); if (unavailable(error)) return false; throw error; }
  }
  throw new Error('WORKER_IMAGE_TRANSPORT_REDIRECT_INVALID');
}

/** Setup only. The caller holds its provider lease; all bytes remain hash bound. */
export async function acquireWorkerImageTransport(input: Acquisition): Promise<string | null> {
  validate(input); cancelled(input.signal);
  const root = path.join(input.stateRoot, 'images'); await mkdir(root, { recursive: true, mode: 0o700 }); const store = await JournalStore.open(root, input.guard);
  return withWorkerImageImportLock(store.root, input.guard, async () => {
    cancelled(input.signal); const cached = path.join(root, `${input.transport.sha256.slice(7)}.tar`);
    try {
      const info = await lstat(cached); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== input.transport.sizeBytes || process.platform !== 'win32' && (info.mode & 0o222) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('WORKER_IMAGE_TRANSPORT_CACHE_INVALID');
      await verifyArchive(cached, input.transport.sha256, input.signal); await recordImageCacheAccess(root, input.guard, input.transport); return cached;
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const staged = await beginImageImportStaging(root, input.guard, input.transport);
    try {
      try { await copyLocal(input, staged.filename); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; if (input.network === 'offline' || !await download(input, staged.filename)) return null; }
      await staged.publish(); return cached;
    } finally { await staged.cleanup(); }
  });
}
