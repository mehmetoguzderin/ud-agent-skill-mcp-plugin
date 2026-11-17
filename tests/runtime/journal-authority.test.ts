import { test, expect, vi } from 'vitest';
import { mkdir, mkdtemp, readdir, realpath, rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const native = vi.hoisted(() => ({ identity: vi.fn(), directory: vi.fn(), flush: vi.fn() }));
vi.mock('../../packages/workspace/src/guard.js', async original => ({
  ...await original<typeof import('../../packages/workspace/src/guard.js')>(),
  guardedIdentity: native.identity, guardedPrivateDirectory: native.directory, guardedFlushDirectory: native.flush,
}));
import { JournalStore } from '../../packages/workspace/src/journal.js';

// A portable alias models two spellings already admitted by the native helper.
// This is an orchestration regression, not Windows ACL or short-name evidence.
async function fixture(action: (alias: string, canonical: string, guard: string) => Promise<void>) {
  const base = await mkdtemp(path.join(os.tmpdir(), 'ud-journal-alias-'));
  const canonical = path.join(await realpath(base), 'state'), alias = path.join(base, 'alias');
  await mkdir(canonical, { mode: 0o700 }); await symlink(canonical, alias, 'dir');
  const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
  native.identity.mockReset(); native.directory.mockReset(); native.flush.mockReset();
  native.identity.mockResolvedValue({ device: '1', inode: '2' });
  Object.defineProperty(process, 'platform', { value: 'win32' });
  try { await action(alias, canonical, path.join(base, 'guard.exe')); }
  finally { Object.defineProperty(process, 'platform', platform); await rm(base, { recursive: true, force: true }); }
}

test('journal aliases retain the admitted identity while using one canonical native root', async () => fixture(async (alias, canonical, guard) => {
  const store = await JournalStore.open(alias, guard);
  expect(store.root).toBe(canonical);
  expect(native.identity.mock.calls).toEqual([[guard, alias], [guard, canonical]]);
  expect(native.directory.mock.calls.slice(1)).toEqual(['transactions', 'locks'].map(name => [guard, canonical, name, { device: '1', inode: '2' }, true]));
  expect(native.flush).toHaveBeenCalledWith(guard, canonical, '.', { device: '1', inode: '2' });
  expect((await readdir(canonical)).sort()).toEqual(['locks', 'transactions']);
}));

test('a changed directory identity cannot acquire canonical journal children', async () => fixture(async (alias, canonical, guard) => {
  native.identity.mockImplementation(async (_guard: string, root: string) => ({ device: '1', inode: root === alias ? '2' : '3' }));
  await expect(JournalStore.open(alias, guard)).rejects.toThrow('changed during canonicalization');
  expect(await readdir(canonical)).toEqual([]);
  expect(native.directory).toHaveBeenCalledTimes(1); expect(native.flush).not.toHaveBeenCalled();
}));

test('native admission failure is never bypassed by resolving an alias', async () => fixture(async (alias, canonical, guard) => {
  native.identity.mockRejectedValue(new Error('native root refused'));
  await expect(JournalStore.open(alias, guard)).rejects.toThrow('native root refused');
  expect(native.identity).toHaveBeenCalledTimes(1); expect(native.directory).not.toHaveBeenCalled();
  expect(await readdir(canonical)).toEqual([]);
}));
