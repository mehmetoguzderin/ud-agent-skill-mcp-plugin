import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, expect, test, vi } from 'vitest';
import { readBoundedReceiptBytes, verifyArchive } from '../../packages/runtime-manager/src/receipt.js';

const race = vi.hoisted(() => ({ filename: '', observation: 0, transition: undefined as undefined | ((observation: number) => Promise<void>), closes: [] as Array<ReturnType<typeof vi.fn>> }));
// Exercise the fallback with real files/handles on every host. The ordinary
// command-receipt suite separately retains the host's native O_NOFOLLOW value.
vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, constants: { ...actual.constants, O_NOFOLLOW: 0 } };
});
vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    lstat: async (...args: Parameters<typeof actual.lstat>) => {
      const observation = args[0] === race.filename ? ++race.observation : undefined;
      if (observation !== undefined) await race.transition?.(observation);
      const result = await Reflect.apply(actual.lstat, actual, args);
      if (observation === 1) await race.transition?.(0);
      return result;
    },
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      if (args[0] === race.filename) race.closes.push(vi.spyOn(handle, 'close'));
      return handle;
    },
  };
});
afterEach(() => { race.filename = ''; race.observation = 0; race.transition = undefined; race.closes = []; });

const bytes = Buffer.from('{"receipt":"exact frozen bytes"}\n');
const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const readers = [
  { name: 'offline archive', read: (file: string) => verifyArchive(file, digest), changed: 'Offline archive changed during verification.' },
  { name: 'bounded receipt', read: (file: string) => readBoundedReceiptBytes(file), changed: 'Runtime receipt changed during reading.' },
];

for (const reader of readers) {
  test(`${reader.name} refuses an existing symlink before opening its target`, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-receipt-link-'));
    try {
      const target = path.join(root, 'target'), link = path.join(root, 'link');
      await writeFile(target, bytes); await symlink(target, link, 'file');
      race.filename = link;
      await expect(reader.read(link)).rejects.toThrow('bounded regular file');
      expect(race.closes).toHaveLength(0);
      expect(await readFile(target)).toEqual(bytes);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  for (const observation of [0, 2, 3]) for (const replacement of ['ordinary file', 'symlink'] as const) {
    test(`${reader.name} refuses ${replacement} replacement ${observation === 0 ? 'before opening' : observation === 2 ? 'after opening' : 'after reading'} and closes any held file`, async () => {
      const root = await mkdtemp(path.join(os.tmpdir(), 'ud-receipt-race-'));
      try {
        const file = path.join(root, 'input'), held = path.join(root, 'held');
        await writeFile(file, bytes); race.filename = file;
        race.transition = async count => {
          if (count !== observation) return;
          // Retain the admitted inode so replacement cannot depend on inode reuse.
          await rename(file, held);
          if (replacement === 'symlink') await symlink(held, file, 'file');
          else await writeFile(file, bytes);
        };
        await expect(reader.read(file)).rejects.toThrow(reader.changed);
        expect(race.closes).toHaveLength(1);
        for (const close of race.closes) expect(close).toHaveBeenCalledTimes(1);
        expect(await readFile(held)).toEqual(bytes);
        expect(await readFile(file)).toEqual(bytes);
      } finally { await rm(root, { recursive: true, force: true }); }
    });
  }
}

test('bounded receipt preserves exact bytes and refuses its byte limit before opening', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ud-receipt-bound-'));
  try {
    const file = path.join(root, 'input'); await writeFile(file, bytes); race.filename = file;
    expect(await readBoundedReceiptBytes(file, bytes.length)).toEqual(bytes);
    expect(race.closes).toHaveLength(1); expect(race.closes[0]).toHaveBeenCalledTimes(1);
    race.closes = [];
    await expect(readBoundedReceiptBytes(file, bytes.length - 1)).rejects.toThrow('bounded regular file');
    expect(race.closes).toHaveLength(0);
  } finally { await rm(root, { recursive: true, force: true }); }
});
