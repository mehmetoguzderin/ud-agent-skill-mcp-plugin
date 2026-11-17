import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, readdir, realpath, rename, rm, rmdir, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { guardedCreate, guardedFlushDirectory, guardedIdentity, guardedPrivateDirectory, guardedPrivateRead, guardedStateLock } from './guard.js';
import type { GuardIdentity } from './guard.js';
import { portablePathKey, validPortablePath } from './portable-path.js';

export type NativeState = { guard: string; root: string; identity: GuardIdentity };
export async function openStateAuthority(root: string, guard: string, initialize = false): Promise<NativeState | undefined> {
  if (process.platform !== 'win32') return undefined;
  if (!path.isAbsolute(root) || !path.isAbsolute(guard)) throw new Error('Windows state and native guard must be absolute paths.');
  const authority = { guard, root, identity: await guardedIdentity(guard, root) };
  await guardedPrivateDirectory(guard, root, '.', authority.identity, initialize);
  return authority;
}
function stateRelative(native: NativeState, target: string): string {
  const relative = path.relative(native.root, target);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('Transaction state path escapes its native authority.');
  return relative.split(path.sep).join('/') || '.';
}

export type EntryState = 'pending' | 'writing' | 'applied';
export type JournalEntry = { path: string; before: string | null; after: string | null; state: EntryState; metadata?: Record<string, unknown> };
export type JournalDirectory = { path: string; token: string; state: 'planned' | 'created' | 'released' | 'removed'; identity?: { device: string; inode: string } };
export type Journal = {
  version: 1; id: string; request_hash: string; workspace: string; identity: { device: string; inode: string };
  phase: 'prepared' | 'committing' | 'completed' | 'recovering' | 'rolled_back' | 'conflict';
  entries: JournalEntry[]; directories?: JournalDirectory[]; message?: string;
  read_preconditions?: { path: string; sha256: string | null }[];
};

export function sha256(bytes: Buffer | string): string { return createHash('sha256').update(bytes).digest('hex'); }

const HASH = /^[0-9a-f]{64}$/;
const PHASES = ['prepared', 'committing', 'completed', 'recovering', 'rolled_back', 'conflict'];
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function boundedText(value: unknown, bytes: number): value is string { return typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= bytes && !value.includes('\0') && !Array.from(value).some(character => character.length === 1 && /[\ud800-\udfff]/u.test(character)); }
function identity(value: unknown): boolean { return record(value) && typeof value.device === 'string' && /^\d{1,40}$/.test(value.device) && typeof value.inode === 'string' && /^\d{1,40}$/.test(value.inode); }
function fingerprint(value: unknown): boolean { return value === null || typeof value === 'string' && HASH.test(value); }
function validJournal(value: unknown, id: string): value is Journal {
  if (!record(value) || value.version !== 1 || value.id !== id || typeof value.request_hash !== 'string' || !HASH.test(value.request_hash) || !boundedText(value.workspace, 32768) || !path.isAbsolute(value.workspace) || !identity(value.identity) || !PHASES.includes(value.phase as string) || !Array.isArray(value.entries) || value.entries.length < 1 || value.entries.length > 1000 || value.message !== undefined && !boundedText(value.message, 4 * 1024 * 1024)) return false;
  const files = new Set<string>();
  for (const entry of value.entries) {
    if (!record(entry) || typeof entry.path !== 'string' || !validPortablePath(entry.path) || files.has(portablePathKey(entry.path)) || !fingerprint(entry.before) || !fingerprint(entry.after) || entry.before === null && entry.after === null || !['pending', 'writing', 'applied'].includes(entry.state as string) || entry.metadata !== undefined && (!record(entry.metadata) || Buffer.byteLength(JSON.stringify(entry.metadata), 'utf8') > 2 * 1024 * 1024)) return false;
    files.add(portablePathKey(entry.path));
  }
  if (value.read_preconditions !== undefined) {
    if (!Array.isArray(value.read_preconditions) || value.read_preconditions.length > 10000) return false;
    const names = new Set<string>();
    for (const condition of value.read_preconditions) {
      if (!record(condition) || Object.keys(condition).sort().join(',') !== 'path,sha256' || typeof condition.path !== 'string' || !validPortablePath(condition.path) || names.has(portablePathKey(condition.path)) || !fingerprint(condition.sha256)) return false;
      names.add(portablePathKey(condition.path));
    }
  }
  if (value.directories !== undefined) {
    if (!Array.isArray(value.directories) || value.directories.length > 1000) return false;
    const directories = new Set<string>();
    for (const directory of value.directories) {
      if (!record(directory) || typeof directory.path !== 'string' || !validPortablePath(directory.path) || directories.has(portablePathKey(directory.path)) || typeof directory.token !== 'string' || !HASH.test(directory.token) || !['planned', 'created', 'released', 'removed'].includes(directory.state as string) || directory.identity !== undefined && !identity(directory.identity) || ['created', 'released'].includes(directory.state as string) && directory.identity === undefined) return false;
      directories.add(portablePathKey(directory.path));
    }
  }
  return true;
}

function checkAsset(index: number, role: string): void { if (!Number.isSafeInteger(index) || index < 0 || index >= 1000 || !['before', 'after'].includes(role)) throw new Error('Invalid transaction asset identity.'); }

export async function fsyncDirectory(directory: string, native?: NativeState): Promise<void> {
  if (process.platform === 'win32') {
    if (!native) throw new Error('WINDOWS_STATE_GUARD_REQUIRED');
    return guardedFlushDirectory(native.guard, native.root, stateRelative(native, directory), native.identity);
  }
  const handle = await open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

export async function durableWrite(file: string, bytes: Buffer, native?: NativeState): Promise<void> {
  const temporary = `${file}.${randomUUID()}.tmp`;
  const handle = await open(temporary, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); }
  catch (error: unknown) { await handle.close(); await rm(temporary, { force: true }); throw error; }
  await handle.close();
  try { await rename(temporary, file); await fsyncDirectory(path.dirname(file), native); }
  catch (error: unknown) { await rm(temporary, { force: true }); throw error; }
}

/** Create a journal without ever replacing an existing directory entry. */
async function durableCreate(file: string, bytes: Buffer, native?: NativeState): Promise<void> {
  if (native) return guardedCreate(native.guard, native.root, stateRelative(native, file), native.identity, bytes);
  const temporary = `${file}.${randomUUID()}.tmp`;
  const handle = await open(temporary, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); }
  catch (error: unknown) { await handle.close(); await rm(temporary, { force: true }); throw error; }
  await handle.close();
  try {
    // link is create-exclusive: it cannot replace a journal that appeared after
    // inspection. Until the temp link is removed, readers reject nlink != 1.
    await link(temporary, file);
    await unlink(temporary);
    await fsyncDirectory(path.dirname(file), native);
  } catch (error: unknown) {
    await rm(temporary, { force: true });
    throw error;
  }
}

/** Only a verified, empty, user-private directory is a recoverable orphan. */
async function emptyTransactionDirectory(directory: string, native?: NativeState): Promise<boolean> {
  let info: Awaited<ReturnType<typeof lstat>>;
  try { info = await lstat(directory); }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
  if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && (info.mode & 0o077) !== 0) || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('Transaction directory is not private and user-owned.');
  if (native && process.platform === 'win32') await guardedPrivateDirectory(native.guard, native.root, stateRelative(native, directory), native.identity);
  if ((await readdir(directory)).length !== 0) throw new Error('TRANSACTION_ORPHAN_NOT_EMPTY: unknown state requires explicit reconciliation.');
  const after = await lstat(directory);
  if (!after.isDirectory() || after.isSymbolicLink() || after.dev !== info.dev || after.ino !== info.ino || after.mode !== info.mode || after.uid !== info.uid) throw new Error('Transaction directory changed during inspection.');
  return true;
}

export async function boundedRead(file: string, limit: number, native?: NativeState): Promise<Buffer> {
  if (process.platform === 'win32') {
    if (!native) throw new Error('WINDOWS_STATE_GUARD_REQUIRED');
    return guardedPrivateRead(native.guard, native.root, stateRelative(native, file), limit, native.identity);
  }
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(limit) || (before.mode & 0o077n) !== 0n || (typeof process.getuid === 'function' && before.uid !== BigInt(process.getuid()))) {
      throw new Error('A transaction state file is not a private bounded regular file.');
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead === 0) throw new Error('A transaction state file changed during read.');
      offset += result.bytesRead;
    }
    const extra = Buffer.alloc(1);
    if ((await handle.read(extra, 0, 1, bytes.length)).bytesRead !== 0) throw new Error('A transaction state file changed during read.');
    const after = await handle.stat({ bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) throw new Error('A transaction state file changed during read.');
    return bytes;
  } finally { await handle.close(); }
}

/** User-private state; journal updates and asset writes are durable before mutation. */
export class JournalStore {
  private constructor(readonly root: string, private readonly native?: NativeState) {}

  static async readOnly(root: string, guard: string): Promise<JournalStore> {
    if (!path.isAbsolute(root)) throw new Error('Journal state root must be absolute.');
    for (const name of ['', 'transactions', 'locks']) {
      const target = name ? path.join(root, name) : root, info = await lstat(target);
      if (!info.isDirectory() || info.isSymbolicLink() || process.platform !== 'win32' && (info.mode & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('Journal state is not private and user-owned.');
    }
    return new JournalStore(root, await openStateAuthority(root, guard));
  }

  static async open(root: string, guard?: string): Promise<JournalStore> {
    if (!path.isAbsolute(root)) throw new Error('Journal state root must be absolute.');
    if (process.platform !== 'win32') root = await realpath(root);
    let native: NativeState | undefined;
    if (process.platform === 'win32') {
      if (!guard || !path.isAbsolute(guard)) throw new Error('WINDOWS_STATE_GUARD_REQUIRED: a verified native helper must initialize private transaction state.');
      native = await openStateAuthority(root, guard, true);
    }
    if (process.platform !== 'win32' && guard) native = { guard, root, identity: await guardedIdentity(guard, root) };
    root = await realpath(root);
    if (native && native.root !== root) {
      // Windows realpath expands short names. Keep paths and the native
      // authority in that same spelling, retaining the already admitted ID.
      const canonical = await guardedIdentity(native.guard, root);
      if (canonical.device !== native.identity.device || canonical.inode !== native.identity.inode) throw new Error('Transaction state root changed during canonicalization.');
      native = { ...native, root };
    }
    const info = await lstat(root);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Journal state root must be an existing private directory.');
    if ((process.platform !== 'win32' && (info.mode & 0o077) !== 0) || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('Journal state root is not private and user-owned.');
    for (const name of ['transactions', 'locks']) {
      const target = path.join(root, name);
      await mkdir(target, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
      const targetInfo = await lstat(target);
      if (native && process.platform === 'win32') await guardedPrivateDirectory(native.guard, native.root, stateRelative(native, target), native.identity, true);
      if (!targetInfo.isDirectory() || targetInfo.isSymbolicLink() || (process.platform !== 'win32' && (targetInfo.mode & 0o077) !== 0) || (typeof process.getuid === 'function' && targetInfo.uid !== process.getuid())) throw new Error('Journal subdirectory is not private and user-owned.');
    }
    await fsyncDirectory(root, native);
    return new JournalStore(root, native);
  }

  private transactionDir(id: string): string {
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error('Invalid transaction identifier.');
    return path.join(this.root, 'transactions', id);
  }

  async withWorkspaceLock<T>(workspace: string, action: () => Promise<T>): Promise<T> {
    const name = sha256(workspace);
    const lockDir = path.join(this.root, 'locks', name);
    if (this.native) {
      let release: () => Promise<void>;
      try { release = await guardedStateLock(this.native.guard, this.native.root, `locks/${name}.native`, this.native.identity); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'EBUSY') throw Object.assign(new Error('WORKSPACE_LOCKED_OR_STALE: the native workspace lock is held.'), { code: 'EBUSY' }); throw error; }
      try {
        // Old directory locks may belong to an older live coordinator. Keep
        // their conservative migration boundary instead of stealing them.
        try { await lstat(lockDir); throw new Error('WORKSPACE_LOCKED_OR_STALE: an older directory lock requires explicit recovery.'); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
        return await action();
      } finally { await release(); }
    }
    try { await mkdir(lockDir, { mode: 0o700 }); }
    catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('WORKSPACE_LOCKED_OR_STALE: explicit lock recovery is required.');
      throw error;
    }
    const token = randomUUID();
    const owner = path.join(lockDir, 'owner.json');
    try {
      await writeFile(owner, JSON.stringify({ token, pid: process.pid }), { flag: 'wx', mode: 0o600 });
      const ownerHandle = await open(owner, 'r');
      try { await ownerHandle.sync(); } finally { await ownerHandle.close(); }
      await fsyncDirectory(lockDir, this.native);
      await fsyncDirectory(path.dirname(lockDir), this.native);
      return await action();
    } finally {
      // Only release the exact lock acquired here. Never steal stale locks.
      try {
        const saved = JSON.parse((await boundedRead(owner, 4096, this.native)).toString('utf8')) as { token?: unknown };
        if (saved.token === token) { await unlink(owner); await rmdir(lockDir); await fsyncDirectory(path.dirname(lockDir), this.native); }
      } catch (error: unknown) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
  }

  async create(journal: Journal): Promise<void> {
    if (!validJournal(journal, journal.id)) throw new Error('Transaction journal is invalid.');
    const dir = this.transactionDir(journal.id);
    try {
      await mkdir(dir, { mode: 0o700 });
      await fsyncDirectory(path.dirname(dir), this.native);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      if (!await emptyTransactionDirectory(dir, this.native)) throw new Error('Transaction directory disappeared during recovery.');
    }
    await durableCreate(path.join(dir, 'journal.json'), Buffer.from(`${JSON.stringify(journal)}\n`), this.native);
  }

  async save(journal: Journal): Promise<void> {
    if (!validJournal(journal, journal.id)) throw new Error('Transaction journal is invalid.');
    await durableWrite(path.join(this.transactionDir(journal.id), 'journal.json'), Buffer.from(`${JSON.stringify(journal)}\n`), this.native);
  }

  async load(id: string): Promise<Journal | undefined> {
    let data: Buffer;
    try { data = await boundedRead(path.join(this.transactionDir(id), 'journal.json'), 4 * 1024 * 1024, this.native); }
    catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await emptyTransactionDirectory(this.transactionDir(id), this.native);
      return undefined;
    }
    let value: unknown;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); }
    catch { throw new Error('Transaction journal is invalid.'); }
    if (!validJournal(value, id)) throw new Error('Transaction journal is invalid.');
    return value;
  }

  async saveAsset(id: string, index: number, role: 'before' | 'after', bytes: Buffer): Promise<void> {
    checkAsset(index, role);
    if (!Buffer.isBuffer(bytes) || bytes.length > 64 * 1024 * 1024) throw new Error('Transaction asset exceeds its byte budget.');
    const file = path.join(this.transactionDir(id), `${index}.${role}`);
    const handle = await open(file, 'wx', 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    await fsyncDirectory(path.dirname(file), this.native);
  }

  async loadAsset(id: string, index: number, role: 'before' | 'after', expected: string): Promise<Buffer> {
    checkAsset(index, role);
    if (typeof expected !== 'string' || !HASH.test(expected)) throw new Error('Invalid transaction asset fingerprint.');
    const bytes = await boundedRead(path.join(this.transactionDir(id), `${index}.${role}`), 64 * 1024 * 1024, this.native);
    if (sha256(bytes) !== expected) throw new Error('Transaction recovery asset fingerprint does not match the journal.');
    return bytes;
  }
}
