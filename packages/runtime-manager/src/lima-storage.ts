import { createHash } from 'node:crypto';
import { lstat, mkdir, readdir, realpath, rm, rmdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { boundedRead, durableWrite, fsyncDirectory, JournalStore, openStateAuthority } from '../../workspace/src/journal.js';
import { guardedIdentity, guardedStateLock } from '../../workspace/src/guard.js';

type Identity = { device: string; inode: string };
type Binding = { schema_version: 1; state: string; state_identity: Identity; home: string; home_identity: Identity };
type Removal = { schema_version: 1; binding: Binding; legacy: boolean; phase: 'planned' | 'marker_removed' | 'home_removed' | 'completed' };
const markerName = '_ud-agent-owner.json';
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('LIMA_HOME_BINDING_INVALID'); return value as Record<string, unknown>; }
function identity(value: unknown): Identity { const data = object(value); if (typeof data.device !== 'string' || !/^\d{1,40}$/.test(data.device) || typeof data.inode !== 'string' || !/^\d{1,40}$/.test(data.inode)) throw new Error('LIMA_HOME_BINDING_INVALID'); return { device: data.device, inode: data.inode }; }
function same(a: Identity, b: Identity): boolean { return a.device === b.device && a.inode === b.inode; }
async function privateDirectory(home: string): Promise<void> { const info = await lstat(home); if (!info.isDirectory() || info.isSymbolicLink() || process.platform !== 'win32' && (info.mode & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('LIMA_OWNED_HOME_UNSAFE'); }
export function limaSocketPathFits(home: string): boolean { return Buffer.byteLength(path.join(home, 'ud-agent', 'ssh.sock.1234567890123456')) < 104; }
async function readBinding(state: string, guard: string): Promise<Binding | undefined> {
  let data: Record<string, unknown>;
  try { data = object(JSON.parse((await boundedRead(path.join(state, 'lima-home.json'), 8192, await openStateAuthority(state, guard))).toString('utf8'))); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
  if (Object.keys(data).sort().join(',') !== 'home,home_identity,schema_version,state,state_identity' || data.schema_version !== 1 || data.state !== state || typeof data.home !== 'string' || !path.isAbsolute(data.home)) throw new Error('LIMA_HOME_BINDING_INVALID');
  return { schema_version: 1, state, state_identity: identity(data.state_identity), home: data.home, home_identity: identity(data.home_identity) };
}
async function readRemoval(state: string, guard: string): Promise<Removal | undefined> {
  let value: Record<string, unknown>; try { value = object(JSON.parse((await boundedRead(path.join(state, 'lima-home-delete.json'), 16384, await openStateAuthority(state, guard))).toString('utf8'))); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
  const data = object(value.binding);
  if (Object.keys(value).sort().join(',') !== 'binding,legacy,phase,schema_version' || value.schema_version !== 1 || typeof value.legacy !== 'boolean' || !['planned', 'marker_removed', 'home_removed', 'completed'].includes(value.phase as string) || Object.keys(data).sort().join(',') !== 'home,home_identity,schema_version,state,state_identity' || data.schema_version !== 1 || data.state !== state || typeof data.home !== 'string' || !path.isAbsolute(data.home)) throw new Error('LIMA_HOME_REMOVAL_JOURNAL_INVALID');
  const binding: Binding = { schema_version: 1, state, state_identity: identity(data.state_identity), home: data.home, home_identity: identity(data.home_identity) }; if (!same(binding.state_identity, await guardedIdentity(guard, state))) throw new Error('LIMA_HOME_BINDING_CHANGED');
  return { schema_version: 1, binding, legacy: value.legacy, phase: value.phase as Removal['phase'] };
}
/** Observational metadata for resuming a final deletion without invoking Lima. */
export async function ownedLimaHomeRemoval(stateRoot: string, guard: string): Promise<Removal | undefined> {
  const state = await realpath(stateRoot); const value = await readRemoval(state, guard); if (!value) return undefined; const current = await readBinding(state, guard); if (current && JSON.stringify(current) !== JSON.stringify(value.binding)) { if (value.phase === 'completed') return undefined; throw new Error('LIMA_HOME_BINDING_CHANGED'); } return value;
}

/** Read-only binding lookup, including the previous state/lima-home layout. */
export async function resolveOwnedLimaHome(stateRoot: string, guard: string): Promise<string | undefined> {
  const state = await realpath(stateRoot), binding = await readBinding(state, guard);
  const removal = await ownedLimaHomeRemoval(state, guard);
  if (removal) { if (removal.phase !== 'completed') throw new Error('LIMA_HOME_REMOVAL_REQUIRES_RECOVERY'); if (!binding) return undefined; }
  if (!binding) {
    let legacy: Record<string, unknown>;
    try { legacy = object(JSON.parse((await boundedRead(path.join(state, 'lima-instance.json'), 16384, await openStateAuthority(state, guard))).toString('utf8'))); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
    const home = path.join(state, 'lima-home');
    if (legacy.schema_version !== 1 || legacy.home !== home) throw new Error('LIMA_HOME_BINDING_INVALID');
    await privateDirectory(home); if (await realpath(home) !== home) throw new Error('LIMA_OWNED_HOME_UNSAFE'); return home;
  }
  if (!same(binding.state_identity, await guardedIdentity(guard, state))) throw new Error('LIMA_HOME_BINDING_CHANGED');
  await privateDirectory(binding.home);
  if (await realpath(binding.home) !== binding.home || !same(binding.home_identity, await guardedIdentity(guard, binding.home))) throw new Error('LIMA_HOME_BINDING_CHANGED');
  const marker = object(JSON.parse((await boundedRead(path.join(binding.home, markerName), 8192, await openStateAuthority(binding.home, guard))).toString('utf8')));
  if (JSON.stringify(marker) !== JSON.stringify(binding)) throw new Error('LIMA_HOME_BINDING_CHANGED');
  return binding.home;
}

/** Keep physical VM storage short; Lima canonicalizes symlinks before use. */
export async function prepareOwnedLimaHome(stateRoot: string, guard: string, testCacheRoot?: string, testFallbackRoot?: string): Promise<string> {
  const store = await JournalStore.open(stateRoot, guard), state = store.root;
  const pending = await ownedLimaHomeRemoval(state, guard); if (pending && pending.phase !== 'completed' && !await removeEmptyOwnedLimaHome(state, guard)) throw new Error('LIMA_HOME_REMOVAL_REQUIRES_RECOVERY');
  const release = await guardedStateLock(guard, state, '.lima-home.native', await guardedIdentity(guard, state));
  try {
    const present = await resolveOwnedLimaHome(state, guard);
    if (present) { if (process.platform === 'darwin' && !limaSocketPathFits(present)) throw new Error('LIMA_OWNED_HOME_PATH_TOO_LONG'); return present; }
    const key = createHash('sha256').update(state).digest('hex');
    let parent = testCacheRoot ?? path.join(os.homedir(), 'Library', 'Caches', 'ud-agent', 'l');
    if (!path.isAbsolute(parent)) throw new Error('LIMA_OWNED_HOME_UNSAFE');
    await mkdir(parent, { recursive: true, mode: 0o700 }); await privateDirectory(parent); parent = await realpath(parent);
    let home = path.join(parent, key.slice(0, 16));
    if (process.platform === 'darwin' && !limaSocketPathFits(home)) {
      if (testFallbackRoot !== undefined) {
        if (!path.isAbsolute(testFallbackRoot)) throw new Error('LIMA_OWNED_HOME_UNSAFE');
        await privateDirectory(testFallbackRoot); const fallback = await realpath(testFallbackRoot);
        home = path.join(fallback, `l-${key.slice(0, 16)}`);
      } else home = path.join('/private/tmp', `ud-agent-lima-${key.slice(0, 24)}`);
    }
    try { await mkdir(home, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    await privateDirectory(home); if (await realpath(home) !== home || process.platform === 'darwin' && !limaSocketPathFits(home)) throw new Error('LIMA_OWNED_HOME_PATH_TOO_LONG');
    const binding: Binding = { schema_version: 1, state, state_identity: await guardedIdentity(guard, state), home, home_identity: await guardedIdentity(guard, home) };
    const names = await readdir(home), marker = path.join(home, markerName);
    if (names.some(name => name !== markerName)) throw new Error('LIMA_UNOWNED_CACHE_DIRECTORY');
    if (names.length) {
      if (JSON.stringify(JSON.parse((await boundedRead(marker, 8192, await openStateAuthority(home, guard))).toString('utf8'))) !== JSON.stringify(binding)) throw new Error('LIMA_HOME_BINDING_CHANGED');
    } else await durableWrite(marker, Buffer.from(JSON.stringify(binding)), await openStateAuthority(home, guard, true));
    await durableWrite(path.join(state, 'lima-home.json'), Buffer.from(JSON.stringify(binding)), await openStateAuthority(state, guard));
    if (await readRemoval(state, guard)) await rm(path.join(state, 'lima-home-delete.json'));
    return home;
  } finally { await release(); }
}

/** Drop an empty owned cache only; callers reconcile VM/config/assets first. */
export async function removeEmptyOwnedLimaHome(stateRoot: string, guard: string): Promise<boolean> {
  const state = await realpath(stateRoot); const release = await guardedStateLock(guard, state, '.lima-home.native', await guardedIdentity(guard, state));
  try {
    const native = await openStateAuthority(state, guard); let binding = await readBinding(state, guard); let removal = await ownedLimaHomeRemoval(state, guard);
    if (removal?.phase === 'completed') return true;
    if (!removal) {
      let legacy = false;
      if (!binding) { const home = await resolveOwnedLimaHome(state, guard); if (!home) return false; legacy = true; binding = { schema_version: 1, state, state_identity: await guardedIdentity(guard, state), home, home_identity: await guardedIdentity(guard, home) }; }
      const home = await resolveOwnedLimaHome(state, guard); if (!home || (await readdir(home)).some(name => legacy || name !== markerName)) return false;
      removal = { schema_version: 1, binding, legacy, phase: 'planned' }; await durableWrite(path.join(state, 'lima-home-delete.json'), Buffer.from(JSON.stringify(removal)), native);
    }
    binding = removal.binding;
    try {
      await privateDirectory(binding.home); if (await realpath(binding.home) !== binding.home || !same(binding.home_identity, await guardedIdentity(guard, binding.home))) throw new Error('LIMA_HOME_BINDING_CHANGED');
      const names = await readdir(binding.home); if (names.some(name => removal!.legacy || name !== markerName)) return false;
      if (names.includes(markerName)) { const marker = JSON.parse((await boundedRead(path.join(binding.home, markerName), 8192, await openStateAuthority(binding.home, guard))).toString('utf8')); if (JSON.stringify(marker) !== JSON.stringify(binding)) throw new Error('LIMA_HOME_BINDING_CHANGED'); await rm(path.join(binding.home, markerName)); await fsyncDirectory(binding.home, await openStateAuthority(binding.home, guard)); }
      removal.phase = 'marker_removed'; await durableWrite(path.join(state, 'lima-home-delete.json'), Buffer.from(JSON.stringify(removal)), native);
      await rmdir(binding.home); await fsyncDirectory(path.dirname(binding.home), await openStateAuthority(path.dirname(binding.home), guard));
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    removal.phase = 'home_removed'; await durableWrite(path.join(state, 'lima-home-delete.json'), Buffer.from(JSON.stringify(removal)), native);
    const current = await readBinding(state, guard); if (current) { if (JSON.stringify(current) !== JSON.stringify(binding)) throw new Error('LIMA_HOME_BINDING_CHANGED'); await rm(path.join(state, 'lima-home.json')); await fsyncDirectory(state, native); }
    removal.phase = 'completed'; await durableWrite(path.join(state, 'lima-home-delete.json'), Buffer.from(JSON.stringify(removal)), native); return true;
  } finally { await release(); }
}
