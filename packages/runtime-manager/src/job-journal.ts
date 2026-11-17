import { lstat, mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import { JournalStore, boundedRead, durableWrite, fsyncDirectory } from '../../workspace/src/journal.js';

export type JobPhase = 'planned' | 'created' | 'running' | 'cleanup_pending' | 'cleaned';
export type JobRecord = { version: 1; name: string; engine: 'podman'; engine_sha256: string; image_digest: string; phase: JobPhase; container_id?: string; engine_mode?: 'rootless' | 'rootful' };
const transitions: Record<JobPhase, JobPhase[]> = {
  planned: ['created', 'cleanup_pending'], created: ['running', 'cleanup_pending'], running: ['cleanup_pending'], cleanup_pending: ['cleaned'], cleaned: [],
};

function validRecord(value: unknown): value is JobRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const job = value as Record<string, unknown>;
  return job.version === 1 && typeof job.name === 'string' && /^ud-agent-[0-9a-f-]{36}$/.test(job.name) && job.engine === 'podman'
    && typeof job.engine_sha256 === 'string' && /^sha256:[0-9a-f]{64}$/.test(job.engine_sha256)
    && typeof job.image_digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(job.image_digest)
    && typeof job.phase === 'string' && Object.hasOwn(transitions, job.phase)
    && (job.engine_mode === undefined || job.engine_mode === 'rootless' || job.engine_mode === 'rootful')
    && (job.container_id === undefined || (typeof job.container_id === 'string' && /^[0-9a-f]{64}$/.test(job.container_id)));
}

/** Records ownership before create; incomplete cleanup records are never deleted. */
export class JobJournal {
  private constructor(private readonly store: JournalStore, readonly directory: string) {}
  static async open(stateRoot: string): Promise<JobJournal> {
    const store = await JournalStore.open(stateRoot);
    const directory = path.join(store.root, 'jobs');
    await mkdir(directory, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('Job journal is not private and user-owned.');
    await fsyncDirectory(store.root);
    return new JobJournal(store, directory);
  }
  private jobDirectory(name: string): string {
    if (!/^ud-agent-[0-9a-f-]{36}$/.test(name)) throw new Error('Invalid job identifier.');
    return path.join(this.directory, name);
  }
  async create(job: JobRecord): Promise<void> {
    if (!validRecord(job) || job.phase !== 'planned' || job.container_id !== undefined) throw new Error('Invalid initial job record.');
    const directory = this.jobDirectory(job.name);
    await mkdir(directory, { mode: 0o700 });
    await fsyncDirectory(this.directory);
    await durableWrite(path.join(directory, 'job.json'), Buffer.from(`${JSON.stringify(job)}\n`));
  }
  async load(name: string): Promise<JobRecord> {
    const bytes = await boundedRead(path.join(this.jobDirectory(name), 'job.json'), 64 * 1024);
    const job: unknown = JSON.parse(bytes.toString('utf8'));
    if (!validRecord(job) || job.name !== name) throw new Error('Invalid job journal.');
    return job;
  }
  async transition(name: string, next: JobPhase, containerId?: string): Promise<JobRecord> {
    return this.store.withWorkspaceLock(`job:${name}`, async () => {
      const current = await this.load(name);
      if (!transitions[current.phase].includes(next)) throw new Error('Invalid job journal transition.');
      if (containerId !== undefined && !/^[0-9a-f]{64}$/.test(containerId)) throw new Error('Invalid owned container ID.');
      if (current.container_id !== undefined && containerId !== undefined && current.container_id !== containerId) throw new Error('Owned container ID changed.');
      const resolvedId = containerId ?? current.container_id;
      if ((next === 'created' || next === 'running') && !resolvedId) throw new Error('Container ID must be recorded first.');
      const updated: JobRecord = { ...current, phase: next, ...(resolvedId === undefined ? {} : { container_id: resolvedId }) };
      await durableWrite(path.join(this.jobDirectory(name), 'job.json'), Buffer.from(`${JSON.stringify(updated)}\n`));
      return updated;
    });
  }
  async pending(): Promise<JobRecord[]> {
    const names = await readdir(this.directory);
    if (names.length > 10_000) throw new Error('Job journal exceeds its entry limit.');
    const jobs: JobRecord[] = [];
    for (const name of names.sort()) {
      if (!/^ud-agent-[0-9a-f-]{36}$/.test(name)) throw new Error('Unexpected job journal entry.');
      const info = await lstat(this.jobDirectory(name));
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Unsafe job journal entry.');
      const job = await this.load(name);
      if (job.phase !== 'cleaned') jobs.push(job);
    }
    return jobs;
  }
}
