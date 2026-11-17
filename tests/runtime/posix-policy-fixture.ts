/** Model POSIX mode bits only for explicitly created fixture paths on Windows.
 * Real handles, bytes, owners, identities and all unrelated paths stay native.
 * This tests Mac-only policies; it is not Windows ACL acceptance evidence.
 */
import path from 'node:path';
type Fs = typeof import('node:fs/promises');
type Journal = typeof import('../../packages/workspace/src/journal.js');

/** Byte storage for mocked Mac coordinator policies, never native durability
 * or Windows ACL evidence. Only named receipts inside the active fixture may
 * use this adapter; production journal/guard implementations are unchanged. */
export function posixJournalPolicyFixture(actual: Journal, fs: Fs, fixtureRoot: () => string, names: readonly string[], platform: string = process.platform): Journal {
  if (platform !== 'win32') return actual;
  async function selected(file: string) {
    const root = fixtureRoot(), relative = path.relative(root, file);
    if (!root || !path.isAbsolute(root) || !path.isAbsolute(file) || !relative || path.isAbsolute(relative) || relative.split(path.sep).includes('..') || !names.includes(path.basename(file))
      || await fs.realpath(root) !== root || await fs.realpath(path.dirname(file)) !== path.dirname(file)) throw new Error('POSIX journal model escaped its named fixture receipts.');
    const info = await fs.lstat(file).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
    if (info && (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1)) throw new Error('POSIX journal model requires ordinary unaliased fixture bytes.');
    return info;
  }
  return { ...actual,
    durableWrite: async (file: string, bytes: Buffer) => {
      await selected(file);
      if (!Buffer.isBuffer(bytes) || bytes.length > 1024 * 1024) throw new Error('POSIX journal model exceeds its fixture byte bound.');
      await fs.writeFile(file, bytes, { mode: 0o600 });
    },
    boundedRead: async (file: string, limit: number) => {
      const before = await selected(file);
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024 * 1024 || before && before.size > limit) throw new Error('POSIX journal model exceeds its fixture read bound.');
      const bytes = await fs.readFile(file), after = await selected(file);
      if (!before || !after || bytes.length > limit || before.size !== bytes.length || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw new Error('POSIX journal model fixture bytes changed during read.');
      return bytes;
    },
  } as Journal;
}

export function posixPolicyFixture(actual: Fs, platform: string = process.platform): Fs {
  if (platform !== 'win32') return actual;
  const modes = new Map<string, number>();
  const key = (filename: unknown) => typeof filename === 'string' ? path.resolve(filename) : undefined;
  function remember(filename: unknown, mode: unknown): void { const selected = key(filename); if (selected && typeof mode === 'number') modes.set(selected, mode & 0o7777); }
  function projected<T extends { mode: number | bigint }>(stat: T, filename: unknown): T {
    const selected = key(filename), mode = selected === undefined ? undefined : modes.get(selected);
    if (mode === undefined) return stat;
    return new Proxy(stat, { get(target, property) { if (property === 'mode') return typeof target.mode === 'bigint' ? (target.mode & 0o170000n) | BigInt(mode) : (target.mode & 0o170000) | mode; const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value; } });
  }
  return { ...actual,
    mkdir: async (...args: Parameters<Fs['mkdir']>) => { const result = await actual.mkdir(...args); remember(args[0], typeof args[1] === 'object' ? args[1]?.mode : args[1]); return result; },
    writeFile: async (...args: Parameters<Fs['writeFile']>) => { await actual.writeFile(...args); remember(args[0], typeof args[2] === 'object' ? args[2]?.mode : undefined); },
    chmod: async (...args: Parameters<Fs['chmod']>) => { await actual.chmod(...args); remember(args[0], args[1]); },
    rename: async (...args: Parameters<Fs['rename']>) => { await actual.rename(...args); const source = key(args[0]), target = key(args[1]); if (source && target && modes.has(source)) { modes.set(target, modes.get(source)!); modes.delete(source); } },
    lstat: async (...args: Parameters<Fs['lstat']>) => projected(await actual.lstat(...args), args[0]),
    stat: async (...args: Parameters<Fs['stat']>) => projected(await actual.stat(...args), args[0]),
    open: async (...args: Parameters<Fs['open']>) => {
      const handle = await actual.open(...args); remember(args[0], args[2]);
      return new Proxy(handle, { get(target, property) { if (property === 'stat') return async (...options: Parameters<typeof target.stat>) => projected(await target.stat(...options), args[0]); const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value; } });
    },
  } as Fs;
}

/** Foreign coordinator policies still discover their inert fixture files with
 * the physical host's path syntax and suffix. This does not execute a binary
 * or claim native availability of the modeled Mac/Linux runtime. */
export function physicalExecutablePolicyFixture(actual: typeof import('../../packages/runtime-manager/src/profiles.js')): typeof actual {
  if (process.platform !== 'win32') return actual;
  return { ...actual, findExecutable: (engine, host, searchPath) => actual.findExecutable(engine, { ...host, platform: 'win32' }, searchPath) };
}
