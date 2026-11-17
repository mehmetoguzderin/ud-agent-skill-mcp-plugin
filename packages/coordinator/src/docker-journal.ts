import { lstat, mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import type { NativeState } from '../../workspace/src/journal.js';
import { guardedPrivateDirectory } from '../../workspace/src/guard.js';
import { JournalStore, boundedRead, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';

export type DockerPhase = 'planned' | 'volume_pending' | 'volume_ready' | 'loader_pending' | 'loader_created' | 'loaded' | 'worker_pending' | 'worker_created' | 'ran' | 'cleanup_pending' | 'cleaned';
export type DockerJobRecord = {
  version: 1; id: string; engine: string; engine_sha256: string; image_digest: string; image_id: string;
  endpoint: string; daemon_id: string; owner_pid: number; owner_lease?: string;
  phase: DockerPhase; loader_id?: string; worker_id?: string;
  engine_cleanup_reconciliation?: { mode: 'cleanup_only'; original_engine: string; original_engine_sha256: string; current_engine: string; current_engine_sha256: string };
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{64}$/;
const NEXT: Record<DockerPhase, DockerPhase[]> = {
  planned: ['volume_pending', 'cleanup_pending'], volume_pending: ['volume_ready', 'cleanup_pending'],
  volume_ready: ['loader_pending', 'cleanup_pending'], loader_pending: ['loader_created', 'cleanup_pending'],
  loader_created: ['loaded', 'cleanup_pending'], loaded: ['worker_pending', 'cleanup_pending'],
  worker_pending: ['worker_created', 'cleanup_pending'], worker_created: ['ran', 'cleanup_pending'],
  ran: ['cleanup_pending'], cleanup_pending: ['cleaned'], cleaned: [],
};

export function validDockerJobRecord(value: unknown): value is DockerJobRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const job = value as Record<string, unknown>;
  if (Object.keys(job).some(key => !['version', 'id', 'engine', 'engine_sha256', 'image_digest', 'image_id', 'endpoint', 'daemon_id', 'owner_pid', 'owner_lease', 'phase', 'loader_id', 'worker_id', 'engine_cleanup_reconciliation'].includes(key))) return false;
  if (job.version !== 1 || typeof job.id !== 'string' || !UUID.test(job.id) || typeof job.engine !== 'string' || !path.isAbsolute(job.engine) || job.engine.includes('\0') || typeof job.engine_sha256 !== 'string' || !DIGEST.test(job.engine_sha256) || typeof job.image_digest !== 'string' || !DIGEST.test(job.image_digest) || typeof job.image_id !== 'string' || !DIGEST.test(job.image_id) || typeof job.phase !== 'string' || !Object.hasOwn(NEXT, job.phase)) return false;
  if (typeof job.endpoint !== 'string' || !localDockerEndpoint(job.endpoint) || typeof job.daemon_id !== 'string' || !/^[A-Za-z0-9:_.-]{1,256}$/.test(job.daemon_id)) return false;
  if (!Number.isSafeInteger(job.owner_pid) || (job.owner_pid as number) < 1 || (job.owner_pid as number) > 2_147_483_647) return false;
  if (job.owner_lease !== undefined && (typeof job.owner_lease !== 'string' || !/^\.provider-lease-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.native$/.test(job.owner_lease))) return false;
  if (job.engine_cleanup_reconciliation !== undefined) {
    const item = job.engine_cleanup_reconciliation as Record<string, unknown>;
    if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).sort().join(',') !== 'current_engine,current_engine_sha256,mode,original_engine,original_engine_sha256' || item.mode !== 'cleanup_only' || item.current_engine !== job.engine || item.current_engine_sha256 !== job.engine_sha256 || typeof item.original_engine !== 'string' || !path.isAbsolute(item.original_engine) || item.original_engine.includes('\0') || typeof item.original_engine_sha256 !== 'string' || !DIGEST.test(item.original_engine_sha256)) return false;
  }
  if (job.loader_id !== undefined && (typeof job.loader_id !== 'string' || !ID.test(job.loader_id))) return false;
  if (job.worker_id !== undefined && (typeof job.worker_id !== 'string' || !ID.test(job.worker_id))) return false;
  if (['loader_created', 'loaded', 'worker_pending', 'worker_created', 'ran'].includes(job.phase) && !job.loader_id) return false;
  if (['worker_created', 'ran'].includes(job.phase) && !job.worker_id) return false;
  return true;
}
const valid = validDockerJobRecord;

/** Accept only local sockets or Windows named pipes, never a remote daemon. */
export function localDockerEndpoint(value: string): boolean {
  if (value.includes('\0')) return false;
  if (/^npipe:\/\/\/{1,2}\.\/pipe\/[A-Za-z0-9_.-]+$/i.test(value)) return true;
  if (!value.startsWith('unix://')) return false;
  const socket = value.slice('unix://'.length);
  return path.posix.isAbsolute(socket) && !socket.split('/').includes('..');
}

/** A write-ahead journal binds cleanup to exact product-owned Docker objects. */
export class DockerJobJournal {
  private constructor(private readonly store: JournalStore, readonly directory: string, private readonly native?: NativeState) {}

  static async open(stateRoot: string, guard?: string): Promise<DockerJobJournal> {
    const store = await JournalStore.open(stateRoot, guard);
    const native = process.platform === 'win32' && guard ? await openStateAuthority(store.root, guard) : undefined;
    const directory = path.join(store.root, 'docker-jobs');
    await mkdir(directory, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && (info.mode & 0o077) !== 0) || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('Docker job journal is not private and user-owned.');
    if (native) await guardedPrivateDirectory(native.guard, native.root, 'docker-jobs', native.identity, true);
    await fsyncDirectory(store.root, native);
    return new DockerJobJournal(store, directory, native);
  }

  private jobDirectory(id: string): string {
    if (!UUID.test(id)) throw new Error('Invalid Docker job identifier.');
    return path.join(this.directory, id);
  }

  async create(job: DockerJobRecord): Promise<void> {
    if (!valid(job) || job.phase !== 'planned' || job.loader_id !== undefined || job.worker_id !== undefined) throw new Error('Invalid Docker job record.');
    const directory = this.jobDirectory(job.id);
    await mkdir(directory, { mode: 0o700 });
    await fsyncDirectory(this.directory, this.native);
    await durableWrite(path.join(directory, 'job.json'), Buffer.from(`${JSON.stringify(job)}\n`), this.native);
  }

  async load(id: string): Promise<DockerJobRecord> {
    const bytes = await boundedRead(path.join(this.jobDirectory(id), 'job.json'), 64 * 1024, this.native);
    const result: unknown = JSON.parse(bytes.toString('utf8'));
    if (!valid(result) || result.id !== id) throw new Error('Invalid Docker job journal.');
    return result;
  }

  async transition(id: string, phase: DockerPhase, ids: { loader_id?: string; worker_id?: string } = {}): Promise<DockerJobRecord> {
    return this.store.withWorkspaceLock(`docker-job:${id}`, async () => {
      const current = await this.load(id);
      if (!NEXT[current.phase].includes(phase)) throw new Error('Invalid Docker job transition.');
      if ((ids.loader_id !== undefined && (!ID.test(ids.loader_id) || (current.loader_id !== undefined && current.loader_id !== ids.loader_id))) || (ids.worker_id !== undefined && (!ID.test(ids.worker_id) || (current.worker_id !== undefined && current.worker_id !== ids.worker_id)))) throw new Error('Docker container identity changed.');
      const updated = { ...current, ...ids, phase };
      if (!valid(updated)) throw new Error('Invalid Docker job transition data.');
      await durableWrite(path.join(this.jobDirectory(id), 'job.json'), Buffer.from(`${JSON.stringify(updated)}\n`), this.native);
      return updated;
    });
  }

  async pending(): Promise<DockerJobRecord[]> {
    const ids = await readdir(this.directory);
    if (ids.length > 10_000) throw new Error('Docker job journal exceeds its entry limit.');
    const result = [];
    for (const id of ids.sort()) {
      const directory = this.jobDirectory(id); const info = await lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Unsafe Docker job journal entry.');
      const job = await this.load(id);
      if (job.phase !== 'cleaned') result.push(job);
    }
    return result;
  }

  async recordEngineCleanup(id: string, engine: string, engineSha256: string): Promise<void> {
    await this.store.withWorkspaceLock(`docker-job:${id}`, async () => {
      const job = await this.load(id); if (job.phase === 'cleaned') throw new Error('DOCKER_CLEANUP_ALREADY_COMPLETE');
      const updated: DockerJobRecord = { ...job, engine, engine_sha256: engineSha256, engine_cleanup_reconciliation: { mode: 'cleanup_only', original_engine: job.engine_cleanup_reconciliation?.original_engine ?? job.engine, original_engine_sha256: job.engine_cleanup_reconciliation?.original_engine_sha256 ?? job.engine_sha256, current_engine: engine, current_engine_sha256: engineSha256 } };
      if (!valid(updated)) throw new Error('Invalid Docker cleanup handoff.'); await durableWrite(path.join(this.jobDirectory(id), 'job.json'), Buffer.from(`${JSON.stringify(updated)}\n`), this.native);
    });
  }

  async withRecoveryLock<T>(id: string, operation: () => Promise<T>): Promise<T> {
    this.jobDirectory(id);
    return this.store.withWorkspaceLock(`docker-recovery:${id}`, operation);
  }
}
