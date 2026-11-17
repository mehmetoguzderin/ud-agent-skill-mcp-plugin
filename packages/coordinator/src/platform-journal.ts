import { lstat, mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import { JournalStore, boundedRead, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';
import type { NativeState } from '../../workspace/src/journal.js';
import { guardedPrivateDirectory } from '../../workspace/src/guard.js';

export type PlatformJob = { schema_version: 1; lifecycle_revision?: 2; pending_create?: 'volume' | 'initializer' | 'loader' | 'worker'; id: string; provider: 'apple-container' | 'lima-nerdctl' | 'wslc'; authority: string; image: string; image_id?: string; image_reference?: string; phase: 'planned' | 'volume' | 'initialized' | 'loader' | 'loaded' | 'worker' | 'ran' | 'cleanup' | 'cleaned'; initializer?: string; loader?: string; worker?: string };
const phases = ['planned', 'volume', 'initialized', 'loader', 'loaded', 'worker', 'ran', 'cleanup', 'cleaned'];
export function validPlatformJob(raw: unknown): raw is PlatformJob {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false; const item = raw as Record<string, unknown>;
  return Object.keys(item).every(key => ['schema_version', 'lifecycle_revision', 'pending_create', 'id', 'provider', 'authority', 'image', 'image_id', 'image_reference', 'phase', 'initializer', 'loader', 'worker'].includes(key)) && item.schema_version === 1 && (item.lifecycle_revision === undefined || item.lifecycle_revision === 2) && (item.pending_create === undefined || item.lifecycle_revision === 2 && ['volume', 'initializer', 'loader', 'worker'].includes(item.pending_create as string)) && typeof item.id === 'string' && /^[0-9a-f-]{36}$/.test(item.id) && ['apple-container', 'lima-nerdctl', 'wslc'].includes(item.provider as string) && typeof item.authority === 'string' && item.authority.length > 0 && item.authority.length <= 4096 && typeof item.image === 'string' && /^sha256:[0-9a-f]{64}$/.test(item.image) && (item.image_id === undefined || typeof item.image_id === 'string' && /^sha256:[0-9a-f]{64}$/.test(item.image_id)) && (item.image_reference === undefined || typeof item.image_reference === 'string' && /^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(item.image_reference) && item.image_reference.endsWith(`@${item.image}`)) && phases.includes(item.phase as string) && ['initializer', 'loader', 'worker'].every(key => item[key] === undefined || typeof item[key] === 'string' && /^[a-z0-9-]{1,80}$/.test(item[key] as string));
}
const valid = validPlatformJob;
export class PlatformJournal {
  private constructor(private readonly store: JournalStore, private readonly native: NativeState | undefined) {}
  static async open(root: string, guard: string): Promise<PlatformJournal> {
    const store = await JournalStore.open(root, guard); const native = await openStateAuthority(store.root, guard);
    const directory = path.join(store.root, 'platform-jobs'); await mkdir(directory, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
    const info = await lstat(directory); if (!info.isDirectory() || info.isSymbolicLink() || process.platform !== 'win32' && (info.mode & 0o077) !== 0) throw new Error('PLATFORM_JOURNAL_UNSAFE');
    if (native) await guardedPrivateDirectory(guard, native.root, 'platform-jobs', native.identity, true);
    await fsyncDirectory(store.root, native); return new PlatformJournal(store, native);
  }
  private file(id: string): string { if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error('PLATFORM_JOB_ID_INVALID'); return path.join(this.store.root, 'platform-jobs', `${id}.json`); }
  async create(job: PlatformJob): Promise<void> { if (!valid(job) || job.phase !== 'planned') throw new Error('PLATFORM_JOB_INVALID'); await this.store.withWorkspaceLock(`platform-job:${job.id}`, async () => { try { await boundedRead(this.file(job.id), 16384, this.native); throw new Error('PLATFORM_JOB_EXISTS'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } await durableWrite(this.file(job.id), Buffer.from(`${JSON.stringify(job)}\n`), this.native); }); }
  async load(id: string): Promise<PlatformJob> { const value: unknown = JSON.parse((await boundedRead(this.file(id), 16384, this.native)).toString('utf8')); if (!valid(value) || value.id !== id) throw new Error('PLATFORM_JOURNAL_INVALID'); return value; }
  async beginCreate(id: string, kind: NonNullable<PlatformJob['pending_create']>): Promise<void> {
    await this.store.withWorkspaceLock(`platform-job:${id}`, async () => {
      const previous = await this.load(id); const before = { volume: 'planned', initializer: 'volume', loader: 'initialized', worker: 'loaded' };
      if (previous.lifecycle_revision !== 2 || previous.pending_create !== undefined || previous.phase !== before[kind] || kind === 'initializer' && previous.provider !== 'apple-container') throw new Error('PLATFORM_JOB_CREATE_INTENT_INVALID');
      await durableWrite(this.file(id), Buffer.from(`${JSON.stringify({ ...previous, pending_create: kind })}\n`), this.native);
    });
  }
  async transition(id: string, phase: PlatformJob['phase'], ids: { initializer?: string; loader?: string; worker?: string } = {}): Promise<void> {
    await this.store.withWorkspaceLock(`platform-job:${id}`, async () => { const previous = await this.load(id); const from = phases.indexOf(previous.phase); const to = phases.indexOf(phase); if (previous.phase === 'cleaned' || !(to === from + 1 || phase === 'cleanup' && from <= phases.indexOf('cleanup') && (from < phases.indexOf('cleanup') || Object.keys(ids).length > 0)) || Object.entries(ids).some(([key, value]) => previous[key as 'initializer' | 'loader' | 'worker'] !== undefined && previous[key as 'initializer' | 'loader' | 'worker'] !== value)) throw new Error('PLATFORM_JOB_TRANSITION_INVALID'); const next = { ...previous, ...ids, phase }; delete next.pending_create; if (!valid(next)) throw new Error('PLATFORM_JOB_INVALID'); await durableWrite(this.file(id), Buffer.from(`${JSON.stringify(next)}\n`), this.native); });
  }
  async pending(): Promise<PlatformJob[]> { const names = await readdir(path.join(this.store.root, 'platform-jobs')); if (names.length > 10000) throw new Error('PLATFORM_JOURNAL_TOO_LARGE'); const result: PlatformJob[] = []; for (const name of names.sort()) { if (!/^[0-9a-f-]{36}\.json$/.test(name)) throw new Error('PLATFORM_JOURNAL_INVALID'); const job = await this.load(name.slice(0, -5)); if (job.phase !== 'cleaned') result.push(job); } return result; }
  async withJobLock<T>(id: string, action: () => Promise<T>): Promise<T> { this.file(id); return this.store.withWorkspaceLock(`platform-execution:${id}`, action); }
}
