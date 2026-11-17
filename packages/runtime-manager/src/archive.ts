import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { JournalStore } from '../../workspace/src/journal.js';
import { guardedIdentity, guardedStateLock } from '../../workspace/src/guard.js';
import { beginImageImportStaging } from './image-import-staging.js';

export type ArchiveStagingOwner = { stateRoot: string; guard: string; signal?: AbortSignal };

/** Stage the exact accepted archive into product-owned private scratch. */
export async function stageVerifiedArchive(filename: string, expected: string, expectedBytes: number, owner?: ArchiveStagingOwner): Promise<{ filename: string; cleanup: () => Promise<void> }> {
  if (!path.isAbsolute(filename) || !/^sha256:[0-9a-f]{64}$/.test(expected) || !Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > 20 * 1024 * 1024 * 1024) throw new Error('Invalid offline archive receipt.');
  if (owner?.signal?.aborted) throw new Error('WORKER_CANCELLED');
  if (owner) { if (!path.isAbsolute(owner.stateRoot) || !path.isAbsolute(owner.guard)) throw new Error('Invalid archive staging authority.'); await mkdir(owner.stateRoot, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; }); const info = await lstat(owner.stateRoot); if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Invalid archive staging authority.'); }
  const store = owner ? await JournalStore.open(owner.stateRoot, owner.guard) : undefined;
  const release = owner && store ? await guardedStateLock(owner.guard, store.root, '.archive-stage.native', await guardedIdentity(owner.guard, store.root)) : undefined;
  let staged: Awaited<ReturnType<typeof beginImageImportStaging>> | undefined; let directory: string | undefined; let cleaned = false;
  const cleanup = async () => { if (cleaned) return; cleaned = true; try { if (staged) await staged.cleanup(); if (directory) await rm(directory, { recursive: true, force: true }); } finally { await release?.(); } };
  try {
    if (owner && store) staged = await beginImageImportStaging(store.root, owner.guard, { format: 'oci-archive', path: 'worker.tar', sha256: expected, sizeBytes: expectedBytes });
    else directory = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-image-'));
    const source = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const targetPath = staged?.filename ?? path.join(directory!, 'worker.tar');
    try {
      const before = await source.stat({ bigint: true });
      if (!before.isFile() || before.size !== BigInt(expectedBytes)) throw new Error('Offline archive size differs from its receipt.');
      const target = await open(targetPath, 'wx', 0o600);
      try {
        const hash = createHash('sha256'); const buffer = Buffer.alloc(1024 * 1024);
        let position = 0;
        while (true) {
          if (owner?.signal?.aborted) throw new Error('WORKER_CANCELLED');
          const { bytesRead } = await source.read(buffer, 0, buffer.length, position);
          if (bytesRead === 0) break;
          position += bytesRead;
          if (BigInt(position) > before.size) throw new Error('Offline archive changed during staging.');
          hash.update(buffer.subarray(0, bytesRead));
          let written = 0;
          while (written < bytesRead) {
            const result = await target.write(buffer, written, bytesRead - written);
            if (result.bytesWritten === 0) throw new Error('Offline archive staging stopped unexpectedly.');
            written += result.bytesWritten;
          }
        }
        const after = await source.stat({ bigint: true });
        if (BigInt(position) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('Offline archive changed during staging.');
        if (`sha256:${hash.digest('hex')}` !== expected) throw new Error('Offline archive digest does not match the receipt.');
        await target.sync();
      } finally { await target.close(); }
    } finally { await source.close(); }
    return { filename: targetPath, cleanup };
  } catch (error: unknown) { await cleanup(); throw error; }
}
