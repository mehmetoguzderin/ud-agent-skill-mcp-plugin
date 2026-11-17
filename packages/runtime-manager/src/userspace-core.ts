import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, open, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { createGunzip } from 'node:zlib';
import type { Host } from './profiles.js';
import { acquireCoreArchive } from './userspace-download.js';
import type { UvDownload } from './userspace-download.js';
import { loadNativeGuardReceipt, readBoundedReceiptBytes } from './receipt.js';
import { durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';
import { guardedCreate, guardedIdentity, guardedStateLock } from '../../workspace/src/guard.js';
import { portablePathKey, validPortablePath } from '../../workspace/src/portable-path.js';

type Entry = { path: string; sha256: string; size: number };
const SHA = /^sha256:[0-9a-f]{64}$/;
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('USERSPACE_CORE_RECEIPT_INVALID'); return value as Record<string, unknown>; }
function digest(bytes: Buffer): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function check(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED'); }
export function coreDescriptor(item: Record<string, unknown>, host: Host): UvDownload | undefined {
  if (item.lazy_core === undefined) return undefined;
  const value = object(item.lazy_core);
  if (Object.keys(value).sort().join(',') !== 'sha256,size,url' || value.url !== `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-userspace-${host.platform}-${host.arch}.tar.gz` || typeof value.sha256 !== 'string' || !SHA.test(value.sha256) || !Number.isSafeInteger(value.size) || (value.size as number) < 1 || (value.size as number) > 2 * 1024 ** 3) throw new Error('USERSPACE_CORE_RECEIPT_INVALID');
  return value as UvDownload;
}
export async function readCoreDescriptor(source: string, host: Host): Promise<UvDownload | undefined> {
  const root = object(JSON.parse((await readBoundedReceiptBytes(path.join(source, 'runtime/runtime.lock.json'))).toString('utf8'))); if (root.schema_version !== 1 || root.product_version !== '0.1.0-beta.1' || root.state !== 'frozen') throw new Error('USERSPACE_RECEIPT_NOT_FROZEN');
  const bytes = await readBoundedReceiptBytes(path.join(source, 'runtime/userspace.lock.json'), 32 * 1024 ** 2); if (digest(bytes) !== root.userspace_sha256) throw new Error('USERSPACE_RECEIPT_MISMATCH'); const manifest = object(JSON.parse(bytes.toString('utf8'))); if (manifest.schema_version !== 1 || manifest.product_version !== '0.1.0-beta.1' || manifest.state !== 'frozen') throw new Error('USERSPACE_RECEIPT_NOT_FROZEN'); const item = object(object(manifest.platforms)[`${host.platform}/${host.arch}`]); const descriptor = coreDescriptor(item, host); if (descriptor) coreInventory(item); return descriptor;
}
export function coreInventory(item: Record<string, unknown>, limits: { fileBytes: number; totalBytes: number } = { fileBytes: 128 * 1024 ** 2, totalBytes: 2 * 1024 ** 3 }): { files: Entry[]; directories: Set<string> } {
  if (!Array.isArray(item.files) || item.files.length < 1 || item.files.length > 20000) throw new Error('USERSPACE_CORE_RECEIPT_INVALID');
  const seen = new Set<string>(); const files: Entry[] = []; const directories = new Set<string>(); let total = 0;
  for (const raw of item.files) {
    const value = object(raw);
    if (typeof value.path !== 'string' || !validPortablePath(value.path) || seen.has(portablePathKey(value.path)) || typeof value.sha256 !== 'string' || !SHA.test(value.sha256) || !Number.isSafeInteger(value.size) || (value.size as number) < 0 || (value.size as number) > limits.fileBytes || (total += value.size as number) > limits.totalBytes) throw new Error('USERSPACE_CORE_RECEIPT_INVALID');
    seen.add(portablePathKey(value.path)); files.push(value as Entry);
    for (let parent = path.posix.dirname(value.path); parent !== '.'; parent = path.posix.dirname(parent)) directories.add(parent);
  }
  for (const field of ['worker', 'upstream', 'wheels']) { const selected = item[field]; if (typeof selected !== 'string' || !validPortablePath(selected)) throw new Error('USERSPACE_CORE_RECEIPT_INVALID'); directories.add(selected); for (let parent = path.posix.dirname(selected); parent !== '.'; parent = path.posix.dirname(parent)) directories.add(parent); }
  const keys = new Set<string>(); for (const name of directories) { const key = portablePathKey(name); if (seen.has(key) || keys.has(key)) throw new Error('USERSPACE_CORE_RECEIPT_INVALID'); keys.add(key); }
  return { files, directories };
}
async function privateDirectory(directory: string, guard: string, create = false): Promise<string> {
  if (create) await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory); if (!info.isDirectory() || info.isSymbolicLink() || process.platform !== 'win32' && ((info.mode & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('USERSPACE_CORE_STATE_UNSAFE');
  await openStateAuthority(directory, guard, create); return realpath(directory);
}
/** Read-only: absent lazy assets never trigger a download or directory creation. */
export async function coreAssetRoot(source: string, state: string, item: Record<string, unknown>, host: Host): Promise<string> {
  const receipt = coreDescriptor(item, host); if (!receipt) return source;
  // Native archives may embed their complete selected closure while retaining
  // the same lazy descriptor used by the universal npm package. The installed
  // helper is independent and cannot, by itself, count as an embedded core.
  const payload = coreInventory(item).files.filter(file => file.path !== item.guard);
  if (!payload.length) throw new Error('USERSPACE_CORE_RECEIPT_INVALID');
  let found = 0; let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(16, payload.length) }, async () => {
    for (;;) { const file = payload[cursor++]; if (!file) return; try { await lstat(path.join(source, ...file.path.split('/'))); found++; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } }
  }));
  if (found) { if (found !== payload.length) throw new Error('USERSPACE_CORE_EMBEDDED_INVENTORY_INCOMPLETE'); return source; }
  const guard = await loadNativeGuardReceipt(source, host);
  try { await privateDirectory(state, guard.guard); const parent = await privateDirectory(path.join(state, 'corepacks'), guard.guard); return await privateDirectory(path.join(parent, receipt.sha256.slice(7)), guard.guard); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') { const missing = new Error('USERSPACE_CORE_ASSETS_MISSING') as Error & { code: string }; missing.code = 'ENOENT'; throw missing; } throw error; }
}

/** Streaming USTAR extraction accepts exactly the manifest-bound inventory. */
export async function extractCoreArchive(filename: string, destination: string, item: Record<string, unknown>, expected: UvDownload, signal?: AbortSignal, limits?: { fileBytes: number; totalBytes: number }): Promise<void> {
  const inventory = coreInventory(item, limits); const wanted = new Map(inventory.files.map(file => [file.path, file])); const seen = new Set<string>(); const made = new Set<string>();
  const source = await open(filename, 'r'); const before = await source.stat({ bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(expected.size)) { await source.close(); throw new Error('USERSPACE_CORE_ARCHIVE_CHANGED'); }
  const compressed = createHash('sha256'); const raw = source.createReadStream({ autoClose: false }); raw.on('data', (chunk: Buffer) => compressed.update(chunk));
  const decoded = raw.pipe(createGunzip()); raw.on('error', error => decoded.destroy(error)); const iterator = decoded[Symbol.asyncIterator](); let pending = Buffer.alloc(0); let ended = false; let expanded = 0;
  const maximum = inventory.files.reduce((sum, file) => sum + file.size, 0) + (inventory.files.length + inventory.directories.size + 64) * 1024 + 1024 * 1024;
  const take = async (count: number): Promise<Buffer> => {
    check(signal); const chunks: Buffer[] = []; let remaining = count;
    while (remaining) {
      if (!pending.length) { const part = await iterator.next(); if (part.done) { ended = true; throw new Error('USERSPACE_CORE_ARCHIVE_TRUNCATED'); } pending = Buffer.from(part.value); expanded += pending.length; if (expanded > maximum) throw new Error('USERSPACE_CORE_ARCHIVE_TOO_LARGE'); }
      const length = Math.min(remaining, pending.length); chunks.push(pending.subarray(0, length)); pending = pending.subarray(length); remaining -= length;
    }
    return chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks);
  };
  const text = (bytes: Buffer): string => { const end = bytes.indexOf(0); if (end >= 0 && bytes.subarray(end).some(byte => byte !== 0)) throw new Error('USERSPACE_CORE_TAR_TEXT_INVALID'); return new TextDecoder('utf-8', { fatal: true }).decode(end < 0 ? bytes : bytes.subarray(0, end)); };
  const number = (bytes: Buffer): number => { const encoded = bytes.toString('ascii'); if (!/^[0-7\u0000 ]+$/.test(encoded)) throw new Error('USERSPACE_CORE_TAR_NUMBER_INVALID'); const value = encoded.replaceAll('\0', '').trim(); if (!/^[0-7]+$/.test(value)) throw new Error('USERSPACE_CORE_TAR_NUMBER_INVALID'); const result = Number.parseInt(value, 8); if (!Number.isSafeInteger(result)) throw new Error('USERSPACE_CORE_TAR_NUMBER_INVALID'); return result; };
  const ensure = async (relative: string) => { const parent = path.posix.dirname(relative); if (parent !== '.' && !made.has(parent)) await ensure(parent); if (!made.has(relative)) { await mkdir(path.join(destination, ...relative.split('/')), { mode: 0o700 }); made.add(relative); } };
  try {
    let members = 0;
    for (;;) {
      const header = await take(512);
      if (header.every(byte => byte === 0)) { if (!(await take(512)).every(byte => byte === 0)) throw new Error('USERSPACE_CORE_TAR_END_INVALID'); break; }
      if (++members > inventory.files.length + inventory.directories.size || text(header.subarray(257, 263)) !== 'ustar') throw new Error('USERSPACE_CORE_TAR_FORMAT_INVALID');
      let sum = 0; for (let index = 0; index < 512; index++) sum += index >= 148 && index < 156 ? 32 : header[index]!;
      if (sum !== number(header.subarray(148, 156))) throw new Error('USERSPACE_CORE_TAR_CHECKSUM_INVALID');
      const prefix = text(header.subarray(345, 500)); let name = `${prefix ? `${prefix}/` : ''}${text(header.subarray(0, 100))}`; const kind = header[156]; if (kind === 53 && name.endsWith('/')) name = name.slice(0, -1);
      if (!validPortablePath(name) || seen.has(portablePathKey(name))) throw new Error('USERSPACE_CORE_TAR_PATH_INVALID'); seen.add(portablePathKey(name));
      const size = number(header.subarray(124, 136)); const mode = number(header.subarray(100, 108)); if (mode & 0o7000) throw new Error('USERSPACE_CORE_TAR_MODE_INVALID');
      if (kind === 53) { if (size || !inventory.directories.has(name)) throw new Error('USERSPACE_CORE_TAR_DIRECTORY_INVALID'); await ensure(name); continue; }
      const file = wanted.get(name); if ((kind !== 0 && kind !== 48) || !file || file.size !== size) throw new Error('USERSPACE_CORE_TAR_FILE_INVALID');
      const parent = path.posix.dirname(name); if (parent !== '.') await ensure(parent);
      const target = await open(path.join(destination, ...name.split('/')), 'wx', 0o400 | (mode & 0o111));
      const hash = createHash('sha256'); let position = 0;
      try { while (position < size) { const bytes = await take(Math.min(65536, size - position)); hash.update(bytes); let written = 0; while (written < bytes.length) { const result = await target.write(bytes, written, bytes.length - written); if (!result.bytesWritten) throw new Error('USERSPACE_CORE_WRITE_FAILED'); written += result.bytesWritten; } position += bytes.length; } await target.sync(); } finally { await target.close(); }
      if (`sha256:${hash.digest('hex')}` !== file.sha256) throw new Error('USERSPACE_CORE_FILE_DIGEST_MISMATCH'); wanted.delete(name);
      const padding = (512 - size % 512) % 512; if (padding && (await take(padding)).some(byte => byte !== 0)) throw new Error('USERSPACE_CORE_TAR_PADDING_INVALID');
    }
    if (wanted.size) throw new Error('USERSPACE_CORE_INVENTORY_INCOMPLETE');
    if (pending.some(byte => byte !== 0)) throw new Error('USERSPACE_CORE_TAR_TRAILING_PAYLOAD'); pending = Buffer.alloc(0);
    for (;;) { const part = await iterator.next(); if (part.done) { ended = true; break; } expanded += part.value.length; if (expanded > maximum || Buffer.from(part.value).some(byte => byte !== 0)) throw new Error('USERSPACE_CORE_TAR_TRAILING_PAYLOAD'); }
    const after = await source.stat({ bigint: true });
    if (`sha256:${compressed.digest('hex')}` !== expected.sha256 || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('USERSPACE_CORE_ARCHIVE_CHANGED');
    for (const name of inventory.directories) await ensure(name);
  } finally { if (!ended) { raw.destroy(); decoded.destroy(); } await source.close(); }
}

/** Provider and userspace transports share the exact bounded archive parser. */
export async function extractClosedArchive(filename: string, destination: string, files: Entry[], expected: UvDownload, signal?: AbortSignal): Promise<void> {
  if (!files.length || files.some(file => !file.path.startsWith('runtime/'))) throw new Error('PROVIDER_ASSET_INVENTORY_INVALID');
  await extractCoreArchive(filename, destination, { files, worker: 'runtime', upstream: 'runtime', wheels: 'runtime' }, expected, signal, { fileBytes: 4 * 1024 ** 3, totalBytes: 8 * 1024 ** 3 });
}

/** Acquisition is setup-only, protected by a crash-released native setup lease. */
export async function prepareCoreAssets(sourceRoot: string, stateRoot: string, host: Host, network: 'bootstrap_only' | 'offline', fetcher: typeof fetch, signal?: AbortSignal, verifyMaintenance?: () => Promise<void>): Promise<void> {
  const rootLock = object(JSON.parse((await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime/runtime.lock.json'))).toString('utf8')));
  if (rootLock.schema_version !== 1 || rootLock.product_version !== '0.1.0-beta.1' || rootLock.state !== 'frozen') throw new Error('USERSPACE_RECEIPT_NOT_FROZEN');
  const bytes = await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime/userspace.lock.json'), 32 * 1024 ** 2);
  if (rootLock.state !== 'frozen' || digest(bytes) !== rootLock.userspace_sha256) throw new Error('USERSPACE_RECEIPT_MISMATCH');
  const manifest = object(JSON.parse(bytes.toString('utf8'))); if (manifest.schema_version !== 1 || manifest.product_version !== '0.1.0-beta.1' || manifest.state !== 'frozen') throw new Error('USERSPACE_RECEIPT_NOT_FROZEN'); const item = object(object(manifest.platforms)[`${host.platform}/${host.arch}`]); const receipt = coreDescriptor(item, host); if (!receipt) return;
  coreInventory(item); const guard = await loadNativeGuardReceipt(sourceRoot, host); check(signal);
  try { await coreAssetRoot(sourceRoot, stateRoot, item, host); return; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const state = await privateDirectory(stateRoot, guard.guard, true); const identity = await guardedIdentity(guard.guard, state); const key = digest(bytes).slice(7); const kernel = `.setup-${key}.native`; const marker = `.setup-${key}.lock`;
  let release: (() => Promise<void>) | undefined;
  for (let attempt = 0; !release; attempt++) { check(signal); try { release = await guardedStateLock(guard.guard, state, kernel, identity); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EBUSY' || attempt >= 2400) throw error; await new Promise(done => setTimeout(done, 50)); } }
  try {
    for (const name of ['.maintenance.lock', '.recovery.lock']) { try { await lstat(path.join(state, name)); if (name === '.maintenance.lock' && verifyMaintenance) { await verifyMaintenance(); continue; } throw new Error('USERSPACE_MAINTENANCE_IN_PROGRESS'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } }
    try { const prior = object(JSON.parse((await readBoundedReceiptBytes(path.join(state, marker))).toString('utf8'))); if (prior.schema_version !== 1 || !Number.isSafeInteger(prior.pid) || prior.kernel_lock !== kernel) throw new Error('USERSPACE_OWNER_RECORD_INVALID'); await rm(path.join(state, marker)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    await guardedCreate(guard.guard, state, marker, identity, Buffer.from(`${JSON.stringify({ schema_version: 1, pid: process.pid, kernel_lock: kernel })}\n`));
    try {
      try { await coreAssetRoot(sourceRoot, stateRoot, item, host); return; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      const parent = await privateDirectory(path.join(state, 'corepacks'), guard.guard, true); const journal = path.join(parent, `${receipt.sha256.slice(7)}.install.json`);
      try { const prior = object(JSON.parse((await readBoundedReceiptBytes(journal)).toString('utf8'))); if (prior.schema_version !== 1 || prior.sha256 !== receipt.sha256 || typeof prior.staging !== 'string' || !/^\.install-[a-zA-Z0-9]+$/.test(prior.staging)) throw new Error('USERSPACE_CORE_INSTALL_JOURNAL_INVALID'); const staging = path.join(parent, prior.staging); try { const actual = await guardedIdentity(guard.guard, staging); const expected = object(prior.identity); if (actual.device !== expected.device || actual.inode !== expected.inode) throw new Error('USERSPACE_CORE_INSTALL_IDENTITY_CHANGED'); await rm(staging, { recursive: true }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } await rm(journal); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      await privateDirectory(path.join(state, 'core-cache'), guard.guard, true); const archive = await acquireCoreArchive(receipt, state, host, network, fetcher); if (!archive) throw new Error('USERSPACE_CORE_OFFLINE_CACHE_MISSING'); check(signal);
      const temporary = await mkdtemp(path.join(parent, '.install-')); await privateDirectory(temporary, guard.guard, true); const native = await openStateAuthority(parent, guard.guard);
      await durableWrite(journal, Buffer.from(`${JSON.stringify({ schema_version: 1, sha256: receipt.sha256, staging: path.basename(temporary), identity: await guardedIdentity(guard.guard, temporary) })}\n`), native);
      try { await extractCoreArchive(archive, temporary, item, receipt, signal); check(signal); await rename(temporary, path.join(parent, receipt.sha256.slice(7))); await fsyncDirectory(parent, native); await rm(journal); await fsyncDirectory(parent, native); }
      catch (error) { await rm(temporary, { recursive: true, force: true }); await rm(journal, { force: true }); throw error; }
    } finally { await rm(path.join(state, marker), { force: true }); await fsyncDirectory(state, await openStateAuthority(state, guard.guard)); }
  } finally { await release(); }
}
