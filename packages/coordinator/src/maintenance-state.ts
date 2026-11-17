import { lstat, readdir, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { boundedRead, fsyncDirectory, openStateAuthority, sha256 } from '../../workspace/src/journal.js';
import { guardedIdentity, guardedPrivateDirectory } from '../../workspace/src/guard.js';
import { validDockerJobRecord } from './docker-journal.js';
import type { DockerJobRecord } from './docker-journal.js';
import { validPodmanJobRecord } from './podman-journal.js';
import type { PodmanJobRecord } from './podman-journal.js';
import { validPlatformJob } from './platform-journal.js';
import type { PlatformJob } from './platform-journal.js';

type Job = DockerJobRecord | PodmanJobRecord | PlatformJob;
export type SavedJob<T extends Job = Job> = { value: T; file: string; sha256: string; directory?: string };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Read-only inventory never initializes a journal or rewrites state ACLs. */
export async function readMaintenanceJobs<T extends Job>(root: string, guard: string, kind: 'docker' | 'podman' | 'platform'): Promise<SavedJob<T>[]> {
  const directory = path.join(root, `${kind}-jobs`); let names: string[];
  try { names = await readdir(directory); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
  if (names.length > 10000) throw new Error('PROVIDER_JOB_INVENTORY_TOO_LARGE'); const identity = await guardedIdentity(guard, root); await guardedPrivateDirectory(guard, root, `${kind}-jobs`, identity);
  const native = await openStateAuthority(root, guard); const rows: SavedJob<T>[] = [];
  for (const name of names.sort()) {
    const id = kind === 'platform' && name.endsWith('.json') ? name.slice(0, -5) : name;
    if (!UUID.test(id) || kind === 'platform' && name !== `${id}.json`) throw new Error('PROVIDER_JOB_INVENTORY_INVALID');
    if (kind !== 'platform') await guardedPrivateDirectory(guard, root, `${kind}-jobs/${id}`, identity);
    const file = kind === 'platform' ? path.join(directory, name) : path.join(directory, id, 'job.json'); const bytes = await boundedRead(file, 65536, native);
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); const valid = kind === 'docker' ? validDockerJobRecord : kind === 'podman' ? validPodmanJobRecord : validPlatformJob;
    if (!valid(value) || value.id !== id) throw new Error('PROVIDER_JOB_INVENTORY_INVALID'); rows.push({ value: value as T, file, sha256: sha256(bytes), ...(kind === 'platform' ? {} : { directory: path.dirname(file) }) });
  }
  return rows;
}
/** Remove only verified terminal records; retain unknown adjacent contents. */
export async function removeCleanedJob(root: string, guard: string, row: SavedJob, dryRun: boolean): Promise<boolean> {
  if (row.value.phase !== 'cleaned') throw new Error('PROVIDER_JOB_NOT_CLEANED');
  if (row.directory) { const names = await readdir(row.directory); if (names.length !== 1 || names[0] !== 'job.json') return false; }
  const native = await openStateAuthority(root, guard); if (sha256(await boundedRead(row.file, 65536, native)) !== row.sha256) throw new Error('PROVIDER_JOB_RECORD_CHANGED');
  const info = await lstat(row.file); if (!info.isFile() || info.isSymbolicLink()) throw new Error('PROVIDER_JOB_RECORD_CHANGED');
  if (!dryRun) { await rm(row.file); if (row.directory) await rmdir(row.directory); await fsyncDirectory(path.dirname(row.directory ?? row.file), native); } return true;
}
