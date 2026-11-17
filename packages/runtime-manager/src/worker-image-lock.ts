import { AsyncLocalStorage } from 'node:async_hooks';
import { realpath } from 'node:fs/promises';
import { JournalStore } from '../../workspace/src/journal.js';
import { guardedIdentity } from '../../workspace/src/guard.js';
import type { GuardIdentity } from '../../workspace/src/guard.js';
const held = new AsyncLocalStorage<{ root: string; guard: string; identity: GuardIdentity }>();
/** Reentrancy is authority-bound, never an operation argument or global flag. */
export async function withWorkerImageImportLock<T>(root: string, guard: string, action: () => Promise<T>): Promise<T> {
  const canonical = await realpath(root); const identity = await guardedIdentity(guard, canonical); const active = held.getStore();
  if (active?.root === canonical) { if (active.guard !== guard || active.identity.device !== identity.device || active.identity.inode !== identity.inode) throw new Error('WORKER_IMAGE_IMPORT_AUTHORITY_CHANGED'); return action(); }
  const journal = await JournalStore.open(canonical, guard); return journal.withWorkspaceLock('worker-image-import', () => held.run({ root: canonical, guard, identity }, action));
}
