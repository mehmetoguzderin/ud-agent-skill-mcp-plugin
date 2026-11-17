import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { lstat, mkdir, open, readdir, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { boundedRead, durableWrite, JournalStore, openStateAuthority, sha256 } from '../../workspace/src/journal.js';
import type { NativeState } from '../../workspace/src/journal.js';

type Kind = 'reports' | 'plans' | 'contexts' | 'operations' | 'artifacts';
export type ResourceReference = { uri: string; mime_type: string; size_bytes: number; sha256: string; retention: { expires_at: string } };
type Metadata = ResourceReference & { version: 1; scope: string; kind: Kind; id: string };
type ResourceContent = { uri: string; mimeType: string; text: string; blob?: never } | { uri: string; mimeType: string; blob: string; text?: never };
const MAX_BYTES = 64 * 1024 * 1024;
const PAGE_BYTES = 64 * 1024;
const KINDS = new Set(['reports', 'plans', 'contexts', 'operations', 'artifacts']);
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTENT_ID = /^[0-9a-f]{64}$/;
const writers = new Map<string, Promise<void>>();

/** Serialize this process and wait only for a provably held native lock.
 * Legacy directory locks and unknown state still require explicit recovery. */
async function withResourceWriter<T>(root: string, guard: string | undefined, action: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  const previous = writers.get(root) ?? Promise.resolve();
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const tail = previous.then(() => pending);
  writers.set(root, tail);
  try {
    await previous;
    const lock = await JournalStore.open(root, guard), deadline = Date.now() + 30000;
    for (;;) {
      if (signal?.aborted) throw new Error('WORKER_CANCELLED');
      try { return await lock.withWorkspaceLock('resource-inventory', action); }
      catch (error) {
        if (!(error instanceof Error) || (error as NodeJS.ErrnoException).code !== 'EBUSY' || error.message !== 'WORKSPACE_LOCKED_OR_STALE: the native workspace lock is held.' || Date.now() >= deadline) throw error;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }
  } finally { release(); if (writers.get(root) === tail) writers.delete(root); }
}

async function privateDirectory(root: string): Promise<void> {
  const info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath(root) !== root || (process.platform !== 'win32' && ((info.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && info.uid !== process.getuid())))) throw new Error('RESOURCE_STATE_INVALID');
}

/** An authorized resource URI never resolves an arbitrary filesystem pathname. */
export class ResourceStore {
  private constructor(readonly root: string, private readonly scope: string, private readonly key: Buffer, private readonly native?: NativeState, private readonly guard?: string) {}
  static async open(root: string, grants: readonly string[], guard?: string, signal?: AbortSignal): Promise<ResourceStore> {
    await mkdir(root, { recursive: true, mode: 0o700 });
    await privateDirectory(root);
    await JournalStore.open(root, guard);
    const native = guard ? await openStateAuthority(root, guard) : undefined;
    return withResourceWriter(root, guard, async () => {
    const keyPath = path.join(root, 'cursor.key');
    try {
      const file = await open(keyPath, 'wx', 0o600);
      try { await file.writeFile(randomBytes(32)); await file.sync(); } finally { await file.close(); }
    } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    const key = await boundedRead(keyPath, 32, native);
    if (key.length !== 32) throw new Error('RESOURCE_STATE_INVALID');
    return new ResourceStore(root, sha256(JSON.stringify([...grants].sort())), key, native, guard);
    }, signal);
  }
  /** Upgrade a legacy read handle only after its caller verifies the helper. */
  async withGuard(guard: string): Promise<ResourceStore> {
    if (this.guard !== undefined && this.guard !== guard) throw new Error('RESOURCE_GUARD_CHANGED');
    if (this.guard === guard) return this;
    await privateDirectory(this.root);
    return new ResourceStore(this.root, this.scope, this.key, await openStateAuthority(this.root, guard), guard);
  }
  async put(kind: Kind, bytes: Buffer, mime: string, lifetimeMs = 30 * 24 * 60 * 60 * 1000, signal?: AbortSignal): Promise<ResourceReference> {
    if (!KINDS.has(kind) || bytes.length > MAX_BYTES || !/^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+(?:; charset=(?:utf-8|us-ascii))?$/.test(mime) || !Number.isSafeInteger(lifetimeMs) || lifetimeMs < 1 || lifetimeMs > 30 * 24 * 60 * 60 * 1000) throw new Error('RESOURCE_LIMIT_EXCEEDED');
    return withResourceWriter(this.root, this.guard, async () => {
    const id = kind === 'contexts' ? sha256(`${this.scope}\0${sha256(bytes)}`) : randomUUID(); const folder = path.join(this.root, id);
    if (kind === 'contexts') {
      try {
        await this.read(new URL(`ud://contexts/${id}`));
        const metadata = JSON.parse((await boundedRead(path.join(folder, 'metadata.json'), 8192, this.native)).toString('utf8')) as Metadata;
        if (metadata.sha256 !== sha256(bytes) || metadata.mime_type !== mime) throw new Error('RESOURCE_INTEGRITY_FAILED');
        return { uri: metadata.uri, mime_type: metadata.mime_type, size_bytes: metadata.size_bytes, sha256: metadata.sha256, retention: metadata.retention };
      } catch (error) { if (!(error instanceof Error) || error.message !== 'RESOURCE_NOT_FOUND') throw error; }
    }
    let total = bytes.length, count = 1;
    for (const name of await readdir(this.root)) {
      if (!ID.test(name) && !CONTENT_ID.test(name)) continue;
      const folder = path.join(this.root, name); await privateDirectory(folder);
      let metadata: Metadata;
      try { metadata = JSON.parse((await boundedRead(path.join(folder, 'metadata.json'), 8192, this.native)).toString('utf8')) as Metadata; }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const files = await readdir(folder);
        if (files.some(name => name !== 'data' && !/^metadata\.json\.[0-9a-f-]{36}\.tmp$/.test(name) && !/^data\.[0-9a-f-]{36}\.tmp$/.test(name))) throw new Error('RESOURCE_ORPHAN_INVALID');
        for (const file of files) await boundedRead(path.join(folder, file), MAX_BYTES, this.native);
        await rm(folder, { recursive: true }); continue;
      }
      if (metadata.version !== 1 || metadata.id !== name || !Number.isSafeInteger(metadata.size_bytes) || metadata.size_bytes < 0 || metadata.size_bytes > MAX_BYTES || !Number.isFinite(Date.parse(metadata.retention?.expires_at))) throw new Error('RESOURCE_STATE_INVALID');
      if (Date.parse(metadata.retention.expires_at) <= Date.now()) { await rm(folder, { recursive: true }); continue; }
      total += metadata.size_bytes; count++;
    }
    if (total > 512 * 1024 * 1024 || count > 10_000) throw new Error('RESOURCE_CACHE_LIMIT_EXCEEDED');
    await mkdir(folder, { mode: 0o700 });
    const reference: ResourceReference = { uri: `ud://${kind}/${id}`, mime_type: mime, size_bytes: bytes.length, sha256: sha256(bytes), retention: { expires_at: new Date(Date.now() + lifetimeMs).toISOString() } };
    try {
      await durableWrite(path.join(folder, 'data'), bytes, this.native);
      await durableWrite(path.join(folder, 'metadata.json'), Buffer.from(JSON.stringify({ ...reference, version: 1, kind, id, scope: this.scope })), this.native);
    } catch (error) { await rm(folder, { recursive: true, force: true }); throw error; }
    return reference;
    }, signal);
  }

  /** Full immutable bytes for internal consumers; public reads remain paginated. */
  async bytes(uri: string, expectedKind: Kind): Promise<Buffer> {
    const parsed = new URL(uri);
    if (parsed.hostname !== expectedKind || parsed.search) throw new Error('RESOURCE_URI_INVALID');
    // read applies all scope, expiry, identity and content checks.
    await this.read(parsed);
    const file = path.join(this.root, parsed.pathname.slice(1), 'data');
    const bytes = await boundedRead(file, MAX_BYTES, this.native);
    const metadata = JSON.parse((await boundedRead(path.join(this.root, parsed.pathname.slice(1), 'metadata.json'), 8192, this.native)).toString('utf8')) as Metadata;
    if (sha256(bytes) !== metadata.sha256 || bytes.length !== metadata.size_bytes) throw new Error('RESOURCE_INTEGRITY_FAILED');
    return bytes;
  }
  private cursor(id: string, digest: string, offset: number): string {
    const payload = Buffer.from(JSON.stringify({ id, sha256: digest, offset })).toString('base64url');
    return `${payload}.${createHmac('sha256', this.key).update(payload).digest('base64url')}`;
  }
  async read(uri: URL): Promise<{ contents: ResourceContent[] }> {
    const id = uri.pathname.slice(1), kind = uri.hostname;
    if (uri.protocol !== 'ud:' || !KINDS.has(kind) || (!ID.test(id) && !(kind === 'contexts' && CONTENT_ID.test(id))) || [...uri.searchParams.keys()].some(key => key !== 'cursor') || uri.searchParams.getAll('cursor').length > 1 || uri.hash) throw new Error('RESOURCE_URI_INVALID');
    const folder = path.join(this.root, id);
    let metadata: Metadata;
    try { await privateDirectory(folder); metadata = JSON.parse((await boundedRead(path.join(folder, 'metadata.json'), 8192, this.native)).toString('utf8')) as Metadata; }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Error('RESOURCE_NOT_FOUND'); throw error; }
    if (metadata.version !== 1 || metadata.scope !== this.scope || metadata.id !== id || metadata.kind !== kind || metadata.uri !== `ud://${kind}/${id}` || !/^[0-9a-f]{64}$/.test(metadata.sha256) || !Number.isSafeInteger(metadata.size_bytes) || metadata.size_bytes < 0 || metadata.size_bytes > MAX_BYTES) throw new Error('RESOURCE_ACCESS_DENIED');
    if (!Number.isFinite(Date.parse(metadata.retention?.expires_at)) || Date.parse(metadata.retention.expires_at) <= Date.now()) throw new Error('RESOURCE_EXPIRED');
    const bytes = await boundedRead(path.join(folder, 'data'), MAX_BYTES, this.native);
    if (bytes.length !== metadata.size_bytes || sha256(bytes) !== metadata.sha256) throw new Error('RESOURCE_INTEGRITY_FAILED');
    let offset = 0;
    const cursor = uri.searchParams.get('cursor');
    if (cursor !== null) {
      if (cursor.length > 1024) throw new Error('RESOURCE_CURSOR_INVALID');
      const [payload, signature, extra] = cursor.split('.');
      if (!payload || !signature || extra !== undefined || !/^[A-Za-z0-9_-]+$/.test(signature)) throw new Error('RESOURCE_CURSOR_INVALID');
      const expected = createHmac('sha256', this.key).update(payload).digest(); const provided = Buffer.from(signature, 'base64url');
      if (provided.length !== expected.length || !timingSafeEqual(expected, provided)) throw new Error('RESOURCE_CURSOR_INVALID');
      let value: { id?: unknown; sha256?: unknown; offset?: unknown };
      try { value = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { throw new Error('RESOURCE_CURSOR_INVALID'); }
      if (value.id !== id || value.sha256 !== metadata.sha256 || !Number.isSafeInteger(value.offset) || (value.offset as number) < 0 || (value.offset as number) >= bytes.length || (value.offset as number) % PAGE_BYTES !== 0) throw new Error('RESOURCE_CURSOR_INVALID');
      offset = value.offset as number;
    }
    if (bytes.length <= PAGE_BYTES && cursor === null) {
      if (metadata.mime_type === 'application/json' || metadata.mime_type.startsWith('text/')) return { contents: [{ uri: metadata.uri, mimeType: metadata.mime_type, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) }] };
      return { contents: [{ uri: metadata.uri, mimeType: metadata.mime_type, blob: bytes.toString('base64') }] };
    }
    const end = Math.min(offset + PAGE_BYTES, bytes.length);
    return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ resource: { uri: metadata.uri, mime_type: metadata.mime_type, size_bytes: bytes.length, sha256: metadata.sha256 }, offset, encoding: 'base64', content_base64: bytes.subarray(offset, end).toString('base64'), next_cursor: end < bytes.length ? this.cursor(id, metadata.sha256, end) : null }) }] };
  }
}
