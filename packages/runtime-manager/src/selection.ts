import { lstat, mkdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { boundedRead, durableWrite, openStateAuthority } from '../../workspace/src/journal.js';
import { ENGINES, isEngineSupported } from './profiles.js';
import type { ConcreteEngine, Host } from './profiles.js';
import { userspaceStateRoot } from './userspace.js';

export function selectionRoot(host: Host, stateRoot?: string): string {
  return `${stateRoot ?? userspaceStateRoot(host)}-selection`;
}

async function privateRoot(root: string): Promise<void> {
  if (!path.isAbsolute(root)) throw new Error('SELECTION_STATE_UNVERIFIED');
  const info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath(root) !== root || (process.platform !== 'win32' && ((info.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && info.uid !== process.getuid())))) throw new Error('SELECTION_STATE_UNVERIFIED');
}

/** Observational only: no state directories or repairs are created by checks. */
export async function loadSavedSelection(root: string, host: Host, guard?: string): Promise<ConcreteEngine | undefined> {
  try {
    await privateRoot(root);
    if (process.platform === 'win32' && !guard) throw new Error('WINDOWS_STATE_GUARD_REQUIRED');
    const native = guard ? await openStateAuthority(root, guard) : undefined;
    const value = JSON.parse((await boundedRead(path.join(root, 'selected.json'), 4096, native)).toString('utf8')) as Record<string, unknown>;
    if (value.schema_version !== 1 || value.product_version !== '0.1.0-beta.1' || typeof value.engine !== 'string' || value.engine === 'auto' || !ENGINES.includes(value.engine as ConcreteEngine)) throw new Error('SELECTION_STATE_INVALID');
    if (value.platform !== host.platform || value.arch !== host.arch) return undefined;
    const engine = value.engine as ConcreteEngine;
    return isEngineSupported(engine, host) ? engine : undefined;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

/** Called only after a selected profile has successfully established readiness. */
export async function saveSelection(root: string, host: Host, engine: ConcreteEngine, guard?: string): Promise<void> {
  if (!ENGINES.includes(engine) || engine === ('auto' as string) || !isEngineSupported(engine, host)) throw new Error('SELECTION_STATE_INVALID');
  await mkdir(root, { recursive: true, mode: 0o700 });
  await privateRoot(root);
  if (process.platform === 'win32' && !guard) throw new Error('WINDOWS_STATE_GUARD_REQUIRED');
  const native = guard ? await openStateAuthority(root, guard, true) : undefined;
  await durableWrite(path.join(root, 'selected.json'), Buffer.from(`${JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', platform: host.platform, arch: host.arch, engine })}\n`), native);
}
