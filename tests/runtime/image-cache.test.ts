import { createHash } from 'node:crypto';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { recordImageCacheAccess, reclaimImageCache } from '../../packages/runtime-manager/src/image-cache.js';
import { withWorkerImageImportLock } from '../../packages/runtime-manager/src/worker-image-lock.js';
import { JournalStore } from '../../packages/workspace/src/journal.js';
import { requireProviderMaintenance, withProviderMaintenance } from '../../packages/coordinator/src/provider-leases.js';
import { guardedIdentity, guardedStateLock } from '../../packages/workspace/src/guard.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const sha = (bytes: Buffer | string) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
async function fixture(action: (root: string) => Promise<void>) { const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-image-index-'))); try { await JournalStore.open(root, guard); await action(root); } finally { await rm(root, { recursive: true, force: true }); } }
async function add(root: string, contents: string, old = false) { const bytes = Buffer.from(contents); const transport = { format: 'oci-archive' as const, path: `${old ? 'old-version' : 'runtime/images'}/${contents}.tar`, sha256: sha(bytes), sizeBytes: bytes.length }; const file = path.join(root, `${transport.sha256.slice(7)}.tar`); await writeFile(file, bytes, { mode: 0o400 }); await chmod(file, 0o400); await recordImageCacheAccess(root, guard, transport); return transport; }
describe('persisted immutable worker transport ownership', () => {
  it('reclaims retired version identities without treating arbitrary hash filenames as ownership', async () => fixture(async root => {
    const retired = await add(root, 'retired', true); const current = await add(root, 'current'); const unknown = path.join(root, `${'a'.repeat(64)}.tar`); await writeFile(unknown, 'retain'); const indexFile = path.join(root, '.image-cache.json'), before = await readFile(indexFile); const dry = await reclaimImageCache(root, guard, { dryRun: true, all: true }); expect(dry.removed).toEqual([`${retired.sha256.slice(7)}.tar`, `${current.sha256.slice(7)}.tar`]); expect(await readFile(indexFile)).toEqual(before); const done = await reclaimImageCache(root, guard, { dryRun: false, all: true }); expect(done.removed).toEqual(dry.removed); expect(await readFile(unknown, 'utf8')).toBe('retain'); expect(JSON.parse(await readFile(indexFile, 'utf8')).entries).toEqual([]);
  }));
  it('bounds owned retention by byte size and access order while honoring selected identities', async () => fixture(async root => {
    const first = await add(root, 'first'), second = await add(root, 'second'), third = await add(root, 'third'); await recordImageCacheAccess(root, guard, first);
    const result = await reclaimImageCache(root, guard, { dryRun: false, maxBytes: 10, maxEntries: 2, keep: new Set([first.sha256]) }); expect(result.removed).toEqual([`${second.sha256.slice(7)}.tar`]); expect(result.bytes).toBe(10); expect(result.retained).toEqual([`${third.sha256.slice(7)}.tar`, `${first.sha256.slice(7)}.tar`]);
  }));
  it('blocks replaced files, changed bytes and forged root/source contracts before deleting any other entry', async () => fixture(async root => {
    const first = await add(root, 'first'), second = await add(root, 'second'); const selected = path.join(root, `${second.sha256.slice(7)}.tar`); await rename(selected, `${selected}.original`); await writeFile(selected, 'second', { mode: 0o400 }); await chmod(selected, 0o400); await expect(reclaimImageCache(root, guard, { dryRun: false, all: true })).rejects.toThrow('OWNED_FILE_CHANGED'); expect(await readFile(path.join(root, `${first.sha256.slice(7)}.tar`), 'utf8')).toBe('first'); await rm(selected); await rename(`${selected}.original`, selected); await chmod(selected, 0o600); await writeFile(selected, 'mutate'); await chmod(selected, 0o400); await expect(reclaimImageCache(root, guard, { dryRun: false, all: true })).rejects.toThrow('digest'); await chmod(selected, 0o600); await writeFile(selected, 'second'); await chmod(selected, 0o400);
    const indexFile = path.join(root, '.image-cache.json'); const original = JSON.parse(await readFile(indexFile, 'utf8'));
    for (const altered of [{ ...original, root_identity: { device: '0', inode: '0' } }, { ...original, entries: [{ ...original.entries[0], source_contract_sha256: sha('forged') }, original.entries[1]] }, { ...original, entries: [original.entries[0], original.entries[0]] }]) { await writeFile(indexFile, JSON.stringify(altered)); await expect(reclaimImageCache(root, guard, { dryRun: false, all: true })).rejects.toThrow('OWNERSHIP_INDEX_INVALID'); expect((await lstat(selected)).isFile()).toBe(true); }
  }));
  it('binds reentrant imports and mutation maintenance to exact independent async authorities', async () => fixture(async root => {
    await expect(requireProviderMaintenance(guard, root)).rejects.toThrow('AUTHORITY_REQUIRED'); const other = path.join(root, 'other'); await mkdir(other, { mode: 0o700 }); await JournalStore.open(other, guard);
    await withProviderMaintenance(guard, root, async () => { await requireProviderMaintenance(guard, root); await expect(requireProviderMaintenance(guard, other)).rejects.toThrow('AUTHORITY_REQUIRED'); let calls = 0; await withWorkerImageImportLock(root, guard, () => withWorkerImageImportLock(root, guard, async () => { calls++; })); expect(calls).toBe(1);
      const alternate = path.join(root, process.platform === 'win32' ? 'alternate.exe' : 'alternate'); await copyFile(guard, alternate); await chmod(alternate, 0o700); await expect(withWorkerImageImportLock(root, guard, () => withWorkerImageImportLock(root, alternate, async () => undefined))).rejects.toThrow('IMPORT_AUTHORITY_CHANGED');
      const lockName = `locks/${createHash('sha256').update('worker-image-import').digest('hex')}.native`; const release = await guardedStateLock(guard, other, lockName, await guardedIdentity(guard, other)); try { await expect(withWorkerImageImportLock(root, guard, () => withWorkerImageImportLock(other, guard, async () => undefined))).rejects.toThrow('WORKSPACE_LOCKED'); } finally { await release(); }
      let ready!: () => void; let finish!: () => void; const started = new Promise<void>(done => { ready = done; }); const pending = new Promise<void>(done => { finish = done; }); const active = withWorkerImageImportLock(root, guard, async () => { ready(); await pending; }); await started; try { await expect(withWorkerImageImportLock(root, guard, async () => undefined)).rejects.toThrow('WORKSPACE_LOCKED'); } finally { finish(); await active; }
    });
    await withProviderMaintenance(guard, root, async () => { await expect(requireProviderMaintenance(guard, root)).rejects.toThrow('AUTHORITY_REQUIRED'); }, { dryRun: true });
  }), 30_000);
});
