import { createHash } from 'node:crypto';
import { chmod, chown, lstat, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { guardedRead } from '../../workspace/src/guard.js';
import type { Snapshot } from '../../workspace/src/snapshot.js';
import type { JobJournal } from './job-journal.js';

/** Staging is always beneath the exact owned journal, never a caller-chosen path. */
function stagePath(journal: JobJournal, name: string): string {
  if (!/^ud-agent-[0-9a-f-]{36}$/.test(name)) throw new Error('Invalid rootful staging identity.');
  return path.join(journal.directory, name, 'input');
}

/**
 * Copy a previously verified snapshot into a private job directory and make it
 * readable by container UID/GID 10001. Only an already-root local coordinator
 * may do this; this function never invokes sudo or changes the original tree.
 */
export async function stageRootfulSnapshot(journal: JobJournal, name: string, guard: string, snapshot: Snapshot, verifiedRoot: string): Promise<string> {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) throw new Error('ROOTFUL_STAGING_REQUIRES_AUTHORIZED_ROOT_CONTEXT');
  const job = await journal.load(name);
  if (job.phase !== 'planned' || job.engine_mode !== 'rootful') throw new Error('Rootful staging requires its planned owned job.');
  const root = stagePath(journal, name); await mkdir(root, { mode: 0o700 });
  const directories = new Set<string>([root]);
  for (const file of snapshot.files) {
    const parts = file.path.split('/');
    if (parts.some(part => !part || part === '.' || part === '..' || part.includes('\\') || part.includes('\0'))) throw new Error('Invalid rootful snapshot path.');
    const target = path.join(root, ...parts); const parent = path.dirname(target);
    const relativeParent = path.relative(root, parent);
    if (relativeParent.startsWith('..' + path.sep) || path.isAbsolute(relativeParent)) throw new Error('Rootful snapshot path escaped staging.');
    let current = root;
    for (const part of parts.slice(0, -1)) {
      current = path.join(current, part);
      if (!directories.has(current)) { await mkdir(current, { mode: 0o700 }); directories.add(current); }
    }
    const bytes = await guardedRead(guard, verifiedRoot, file.path, 64 * 1024 * 1024, snapshot.snapshot_identity);
    if (bytes.length !== file.size || createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error('ROOTFUL_SNAPSHOT_CHANGED');
    await writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
    await chown(target, 10001, 10001); await chmod(target, 0o400);
  }
  for (const directory of [...directories].sort((a, b) => b.length - a.length)) { await chown(directory, 10001, 10001); await chmod(directory, 0o500); }
  return root;
}

/** Cleanup only the staging directory bound to this rootful owned job. */
export async function cleanupRootfulSnapshot(journal: JobJournal, name: string): Promise<void> {
  const job = await journal.load(name);
  if (job.engine_mode !== 'rootful' || job.phase !== 'cleanup_pending') throw new Error('Rootful staging cleanup requires its pending owned job.');
  const root = stagePath(journal, name);
  try {
    const info = await lstat(root);
    if (!info.isDirectory() || info.isSymbolicLink() || ![0, 10001].includes(info.uid)) throw new Error('ROOTFUL_STAGING_OWNERSHIP_UNVERIFIED');
    await rm(root, { recursive: true, force: true });
  } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
}
