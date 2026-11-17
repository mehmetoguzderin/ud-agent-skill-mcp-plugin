import { lstat, mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import type { NativeState } from '../../workspace/src/journal.js';
import { guardedPrivateDirectory } from '../../workspace/src/guard.js';
import { JournalStore, boundedRead, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';

export type PodmanPhase = 'planned' | 'volume_pending' | 'volume_ready' | 'loader_pending' | 'loader_created' | 'loaded' | 'worker_pending' | 'worker_created' | 'ran' | 'cleanup_pending' | 'cleaned';
export type PodmanJobRecord = {
  version: 1; id: string; engine: string; engine_sha256: string; image_digest: string; image_id: string;
  graph_root: string; graph_identity: string; owner_pid: number; owner_lease?: string;
  phase: PodmanPhase; vm_identity?: string; policy_sha256?: string; loader_id?: string; worker_id?: string;
  vm_cleanup_reconciliation?: { mode: 'cleanup_only'; original_vm_identity: string; current_vm_identity: string };
  engine_cleanup_reconciliation?: { mode: 'cleanup_only'; original_engine: string; original_engine_sha256: string; current_engine: string; current_engine_sha256: string };
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{64}$/;
const NEXT: Record<PodmanPhase, PodmanPhase[]> = {
  planned: ['volume_pending', 'cleanup_pending'], volume_pending: ['volume_ready', 'cleanup_pending'],
  volume_ready: ['loader_pending', 'cleanup_pending'], loader_pending: ['loader_created', 'cleanup_pending'],
  loader_created: ['loaded', 'cleanup_pending'], loaded: ['worker_pending', 'cleanup_pending'],
  worker_pending: ['worker_created', 'cleanup_pending'], worker_created: ['ran', 'cleanup_pending'],
  ran: ['cleanup_pending'], cleanup_pending: ['cleaned'], cleaned: [],
};

export function validPodmanJobRecord(value: unknown): value is PodmanJobRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const job = value as Record<string, unknown>;
  if (Object.keys(job).some(key => !['version', 'id', 'engine', 'engine_sha256', 'image_digest', 'image_id', 'graph_root', 'graph_identity', 'owner_pid', 'owner_lease', 'phase', 'vm_identity', 'policy_sha256', 'loader_id', 'worker_id', 'vm_cleanup_reconciliation', 'engine_cleanup_reconciliation'].includes(key))) return false;
  if (job.version !== 1 || typeof job.id !== 'string' || !UUID.test(job.id) || typeof job.engine !== 'string' || !path.isAbsolute(job.engine) || job.engine.includes('\0') || typeof job.engine_sha256 !== 'string' || !DIGEST.test(job.engine_sha256) || typeof job.image_digest !== 'string' || !DIGEST.test(job.image_digest) || typeof job.image_id !== 'string' || !DIGEST.test(job.image_id) || typeof job.phase !== 'string' || !Object.hasOwn(NEXT, job.phase)) return false;
  if (typeof job.graph_root !== 'string' || !localPodmanGraphRoot(job.graph_root) || typeof job.graph_identity !== 'string' || !/^\d+:\d+$/.test(job.graph_identity)) return false;
  if (!Number.isSafeInteger(job.owner_pid) || (job.owner_pid as number) < 1 || (job.owner_pid as number) > 2_147_483_647) return false;
  if (job.owner_lease !== undefined && (typeof job.owner_lease !== 'string' || !/^\.provider-lease-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.native$/.test(job.owner_lease))) return false;
  if (job.engine_cleanup_reconciliation !== undefined) {
    const item = job.engine_cleanup_reconciliation as Record<string, unknown>;
    if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).sort().join(',') !== 'current_engine,current_engine_sha256,mode,original_engine,original_engine_sha256' || item.mode !== 'cleanup_only' || item.current_engine !== job.engine || item.current_engine_sha256 !== job.engine_sha256 || typeof item.original_engine !== 'string' || !path.isAbsolute(item.original_engine) || item.original_engine.includes('\0') || typeof item.original_engine_sha256 !== 'string' || !DIGEST.test(item.original_engine_sha256)) return false;
  }
  if (job.policy_sha256 !== undefined && (typeof job.policy_sha256 !== 'string' || !DIGEST.test(job.policy_sha256))) return false;
  if ((job.vm_identity === undefined) !== (job.policy_sha256 === undefined)) return false;
  if (job.vm_identity !== undefined && (typeof job.vm_identity !== 'string' || !/^sha256:[0-9a-f]{64}:[0-9a-f-]{36}$/.test(job.vm_identity))) return false;
  if (job.vm_cleanup_reconciliation !== undefined) {
    const evidence = job.vm_cleanup_reconciliation as Record<string, unknown>;
    if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence) || Object.keys(evidence).sort().join(',') !== 'current_vm_identity,mode,original_vm_identity' || evidence.mode !== 'cleanup_only' || evidence.original_vm_identity !== job.vm_identity || !samePodmanVmForCleanup(evidence.original_vm_identity, evidence.current_vm_identity)) return false;
  }
  if (job.loader_id !== undefined && (typeof job.loader_id !== 'string' || !ID.test(job.loader_id))) return false;
  if (job.worker_id !== undefined && (typeof job.worker_id !== 'string' || !ID.test(job.worker_id))) return false;
  if (['loader_created', 'loaded', 'worker_pending', 'worker_created', 'ran'].includes(job.phase) && !job.loader_id) return false;
  if (['worker_created', 'ran'].includes(job.phase) && !job.worker_id) return false;
  return true;
}
const valid = validPodmanJobRecord;

/** A fresh boot may clean the same persistent machine; it never inherits execution admission. */
export function samePodmanVmForCleanup(original: unknown, current: unknown): boolean {
  const valid = /^sha256:[0-9a-f]{64}:[0-9a-f-]{36}$/;
  return typeof original === 'string' && typeof current === 'string' && valid.test(original) && valid.test(current) && original.slice(0, 71) === current.slice(0, 71);
}

/** Bind only an absolute native Linux storage directory. */
export function localPodmanGraphRoot(value: string): boolean {
  return value.startsWith('/') && !value.includes('\0') && !value.includes('\\') && value.split('/').every(part => part !== '..' && part !== '.');
}

/** A write-ahead journal binds cleanup to exact product-owned Podman objects. */
export class PodmanJobJournal {
  private constructor(private readonly store: JournalStore, readonly directory: string, private readonly native?: NativeState) {}

  static async open(stateRoot: string, guard?: string): Promise<PodmanJobJournal> {
    const store = await JournalStore.open(stateRoot, guard);
    const native = process.platform === 'win32' && guard ? await openStateAuthority(store.root, guard) : undefined;
    const directory = path.join(store.root, 'podman-jobs');
    await mkdir(directory, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && (info.mode & 0o077) !== 0) || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('Podman job journal is not private and user-owned.');
    if (native) await guardedPrivateDirectory(native.guard, native.root, 'podman-jobs', native.identity, true);
    await fsyncDirectory(store.root, native);
    return new PodmanJobJournal(store, directory, native);
  }

  private jobDirectory(id: string): string {
    if (!UUID.test(id)) throw new Error('Invalid Podman job identifier.');
    return path.join(this.directory, id);
  }

  async create(job: PodmanJobRecord): Promise<void> {
    if (!valid(job) || job.phase !== 'planned' || job.loader_id !== undefined || job.worker_id !== undefined) throw new Error('Invalid Podman job record.');
    const directory = this.jobDirectory(job.id);
    await mkdir(directory, { mode: 0o700 });
    await fsyncDirectory(this.directory, this.native);
    await durableWrite(path.join(directory, 'job.json'), Buffer.from(`${JSON.stringify(job)}\n`), this.native);
  }

  async load(id: string): Promise<PodmanJobRecord> {
    const bytes = await boundedRead(path.join(this.jobDirectory(id), 'job.json'), 64 * 1024, this.native);
    const result: unknown = JSON.parse(bytes.toString('utf8'));
    if (!valid(result) || result.id !== id) throw new Error('Invalid Podman job journal.');
    return result;
  }

  async transition(id: string, phase: PodmanPhase, ids: { loader_id?: string; worker_id?: string } = {}): Promise<PodmanJobRecord> {
    return this.store.withWorkspaceLock(`podman-job:${id}`, async () => {
      const current = await this.load(id);
      if (!NEXT[current.phase].includes(phase)) throw new Error('Invalid Podman job transition.');
      if ((ids.loader_id !== undefined && (!ID.test(ids.loader_id) || (current.loader_id !== undefined && current.loader_id !== ids.loader_id))) || (ids.worker_id !== undefined && (!ID.test(ids.worker_id) || (current.worker_id !== undefined && current.worker_id !== ids.worker_id)))) throw new Error('Podman container identity changed.');
      const updated = { ...current, ...ids, phase };
      if (!valid(updated)) throw new Error('Invalid Podman job transition data.');
      await durableWrite(path.join(this.jobDirectory(id), 'job.json'), Buffer.from(`${JSON.stringify(updated)}\n`), this.native);
      return updated;
    });
  }

  async recordVmCleanup(id: string, current: string): Promise<void> {
    await this.store.withWorkspaceLock(`podman-job:${id}`, async () => {
      const job = await this.load(id);
      if (!samePodmanVmForCleanup(job.vm_identity, current) || !job.vm_identity) throw new Error('PODMAN_VM_RECOVERY_CONTEXT_CHANGED');
      const updated = { ...job, vm_cleanup_reconciliation: { mode: 'cleanup_only' as const, original_vm_identity: job.vm_identity, current_vm_identity: current } };
      if (!valid(updated)) throw new Error('Invalid Podman VM cleanup evidence.');
      await durableWrite(path.join(this.jobDirectory(id), 'job.json'), Buffer.from(`${JSON.stringify(updated)}\n`), this.native);
    });
  }

  async pending(): Promise<PodmanJobRecord[]> {
    const ids = await readdir(this.directory);
    if (ids.length > 10_000) throw new Error('Podman job journal exceeds its entry limit.');
    const result = [];
    for (const id of ids.sort()) {
      const directory = this.jobDirectory(id); const info = await lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Unsafe Podman job journal entry.');
      const job = await this.load(id);
      if (job.phase !== 'cleaned') result.push(job);
    }
    return result;
  }

  async recordEngineCleanup(id: string, engine: string, engineSha256: string): Promise<void> {
    await this.store.withWorkspaceLock(`podman-job:${id}`, async () => {
      const job = await this.load(id); if (job.phase === 'cleaned') throw new Error('PODMAN_CLEANUP_ALREADY_COMPLETE');
      const updated: PodmanJobRecord = { ...job, engine, engine_sha256: engineSha256, engine_cleanup_reconciliation: { mode: 'cleanup_only', original_engine: job.engine_cleanup_reconciliation?.original_engine ?? job.engine, original_engine_sha256: job.engine_cleanup_reconciliation?.original_engine_sha256 ?? job.engine_sha256, current_engine: engine, current_engine_sha256: engineSha256 } };
      if (!valid(updated)) throw new Error('Invalid Podman cleanup handoff.'); await durableWrite(path.join(this.jobDirectory(id), 'job.json'), Buffer.from(`${JSON.stringify(updated)}\n`), this.native);
    });
  }

  async withRecoveryLock<T>(id: string, operation: () => Promise<T>): Promise<T> {
    this.jobDirectory(id);
    return this.store.withWorkspaceLock(`podman-recovery:${id}`, operation);
  }
}
