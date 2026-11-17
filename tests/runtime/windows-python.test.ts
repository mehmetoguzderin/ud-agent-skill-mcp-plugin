import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, test, vi } from 'vitest';
const hooks = vi.hoisted(() => ({ afterOpen: undefined as undefined | ((file: string) => Promise<void>) }));
vi.mock('node:fs/promises', async original => {
  const actual = await original<typeof import('node:fs/promises')>();
  return { ...actual, open: async (...args: Parameters<typeof actual.open>) => {
    const handle = await actual.open(...args);
    try { if (typeof args[0] === 'string') await hooks.afterOpen?.(args[0]); }
    catch (error) { await handle.close(); throw error; }
    return handle;
  } };
});
import { resolveWindowsPython } from '../../packages/coordinator/src/windows-python.js';

const hash = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
async function fixture(run: (value: { root: string; python: string; base: string; config: string; home: string }) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-windows-python-')));
  try {
    const home = path.join(root, 'verified-base'), python = path.join(root, 'venv/Scripts/python.exe'), base = path.join(home, 'python.exe'), config = path.join(root, 'venv/pyvenv.cfg');
    await mkdir(home); await mkdir(path.dirname(python), { recursive: true });
    await writeFile(python, 'verified venv redirector'); await writeFile(base, 'verified base interpreter');
    await writeFile(config, `home = ${home}\r\ninclude-system-site-packages = false\r\nversion = 3.15.2\r\n`);
    await run({ root, python, base, config, home });
  } finally { hooks.afterOpen = undefined; await rm(root, { recursive: true, force: true }); }
}

test('direct base selection binds all three complete byte identities without executing an interpreter', async () => fixture(async ({ python, base, config }) => {
  const original = await Promise.all([python, base, config].map(file => readFile(file)));
  expect(await resolveWindowsPython(python)).toEqual({ executable: base, executableSha256: hash(original[1]!),
    venv: { executable: python, executableSha256: hash(original[0]!), config, configSha256: hash(original[2]!) } });
  expect(await Promise.all([python, base, config].map(file => readFile(file)))).toEqual(original);
  expect(await resolveWindowsPython(base)).toEqual({ executable: base, executableSha256: hash(original[1]!) });
}));

test.each(['\n', '\r\n'])('preserves ordinary whitespace and the complete config identity with %j line endings', async newline => fixture(async ({ python, base, config, home }) => {
  const bytes = Buffer.from(`\tHOME\t=\t${home}\t${newline}include-system-site-packages = false${newline}`);
  await writeFile(config, bytes);
  const resolved = await resolveWindowsPython(python);
  expect(resolved.executable).toBe(base);
  expect(resolved.venv?.configSha256).toBe(hash(bytes));
  expect(await readFile(config)).toEqual(bytes);
}));

test.each([32767, 32768])('matches CPython startup admission at the %i-byte config boundary', async size => fixture(async ({ python, base, config, home }) => {
  const prefix = Buffer.from(`home = ${home}\n# `), bytes = Buffer.concat([prefix, Buffer.alloc(size - prefix.length, 0x78)]);
  await writeFile(config, bytes);
  if (size === 32767) {
    const resolved = await resolveWindowsPython(python);
    expect(resolved.executable).toBe(base);
    expect(resolved.venv?.configSha256).toBe(hash(bytes));
  } else await expect(resolveWindowsPython(python)).rejects.toThrow('WORKER_PYTHON_ENVIRONMENT_INVALID');
  expect(await readFile(config)).toEqual(bytes);
}));

test.each(['\0', '\u001c', '\u0085', '\ufeff'])('refuses hidden home keys introduced by control or BOM %j', async hidden => fixture(async ({ python, config, home }) => {
  // Python treats these differently from JS decoding/trimming: NUL ends its
  // native scan; U+001C/U+0085 strip as whitespace; BOM remains part of a key.
  const bytes = Buffer.from(`${hidden}home = ${home}\nhome = ${home}\n`);
  await writeFile(config, bytes);
  await expect(resolveWindowsPython(python)).rejects.toThrow('WORKER_PYTHON_ENVIRONMENT_INVALID');
  expect(await readFile(config)).toEqual(bytes);
}));

test('refuses a UTF-8 BOM instead of silently turning it into a home key', async () => fixture(async ({ python, config, home }) => {
  await writeFile(config, Buffer.from(`\ufeffhome = ${home}\n`));
  await expect(resolveWindowsPython(python)).rejects.toThrow('WORKER_PYTHON_ENVIRONMENT_INVALID');
}));

test.each(['missing', 'duplicate-home', 'mixed-case-home', 'relative-home', 'missing-home', 'oversized', 'invalid-utf8', 'ambiguous'])('refuses %s virtual environment configuration', async kind => fixture(async ({ python, config, home }) => {
  if (kind === 'missing') await rm(config);
  else if (kind === 'duplicate-home') await writeFile(config, `home = ${home}\nhome = ${home}\n`);
  else if (kind === 'mixed-case-home') await writeFile(config, `HOME = ${home}\nhome = ${home}\n`);
  else if (kind === 'relative-home') await writeFile(config, 'home = ../ambient\n');
  else if (kind === 'missing-home') await writeFile(config, 'version = 3.15.2\n');
  else if (kind === 'oversized') await writeFile(config, 'x'.repeat(65537));
  else if (kind === 'invalid-utf8') await writeFile(config, Buffer.from([0xff]));
  else await writeFile(path.join(path.dirname(python), 'pyvenv.cfg'), `home = ${home}\n`);
  await expect(resolveWindowsPython(python)).rejects.toThrow('WORKER_PYTHON_ENVIRONMENT_INVALID');
}));

test.each(['launcher', 'config', 'base'])('rejects an aliased %s without changing its target', async kind => fixture(async ({ python, config, base }) => {
  const file = kind === 'launcher' ? python : kind === 'config' ? config : base, target = file + '.retained';
  const bytes = await readFile(file); await rename(file, target); await symlink(target, file);
  await expect(resolveWindowsPython(python)).rejects.toThrow('WORKER_PYTHON_ENVIRONMENT_INVALID');
  expect(await readFile(target)).toEqual(bytes);
}));

test('a configuration replaced after opening cannot select a base from stale bytes', async () => fixture(async ({ python, config }) => {
  const original = await readFile(config), retained = config + '.retained'; let swapped = false;
  hooks.afterOpen = async file => { if (file === config && !swapped) { swapped = true; await rename(config, retained); await writeFile(config, original); } };
  await expect(resolveWindowsPython(python)).rejects.toThrow('WORKER_RUNTIME_IDENTITY_CHANGED');
  expect(swapped).toBe(true); expect(await readFile(retained)).toEqual(original); expect(await readFile(config)).toEqual(original);
}));
