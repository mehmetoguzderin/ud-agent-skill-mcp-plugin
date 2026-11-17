import * as actual from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { posixPolicyFixture, posixJournalPolicyFixture } from './posix-policy-fixture.js';
import * as journal from '../../packages/workspace/src/journal.js';
describe('explicit POSIX policy metadata fixtures', () => {
  it('leaves native POSIX filesystems and every unregistered path unchanged', async () => {
    expect(posixPolicyFixture(actual, 'darwin')).toBe(actual); expect(posixPolicyFixture(actual, 'linux')).toBe(actual);
    const root = await actual.mkdtemp(path.join(os.tmpdir(), 'ud-mode-fixture-'));
    try {
      const fs = posixPolicyFixture(actual, 'win32'), filename = path.join(root, 'unregistered'); await actual.writeFile(filename, 'native bytes');
      expect(await fs.lstat(filename)).toEqual(await actual.lstat(filename)); expect(await fs.readFile(filename, 'utf8')).toBe('native bytes');
    } finally { await actual.rm(root, { recursive: true, force: true }); }
  });
  it('projects declared mode bits while retaining real identities, file kinds, bytes and handle behavior', async () => {
    const root = await actual.mkdtemp(path.join(os.tmpdir(), 'ud-mode-fixture-'));
    try {
      const fs = posixPolicyFixture(actual, 'win32'), directory = path.join(root, 'private'); await fs.mkdir(directory, { mode: 0o700 });
      const filename = path.join(directory, 'owned'); await fs.writeFile(filename, 'trusted bytes', { mode: 0o700 }); await actual.chmod(filename, 0o644);
      const modeled = await fs.lstat(filename, { bigint: true }), real = await actual.lstat(filename, { bigint: true });
      expect(modeled.mode & 0o777n).toBe(0o700n); expect(modeled.ino).toBe(real.ino); expect(modeled.dev).toBe(real.dev); expect(modeled.uid).toBe(real.uid); expect(modeled.isFile()).toBe(true); expect(await fs.readFile(filename, 'utf8')).toBe('trusted bytes');
      await fs.chmod(filename, 0o777); expect((await fs.lstat(filename)).mode & 0o777).toBe(0o777);
      const created = path.join(directory, 'created'), handle = await fs.open(created, 'wx', 0o600);
      try { await handle.writeFile('handle bytes'); await actual.chmod(created, 0o644); expect((await handle.stat()).mode & 0o777).toBe(0o600); expect((await handle.stat({ bigint: true })).mode & 0o777n).toBe(0o600n); }
      finally { await handle.close(); }
      const renamed = path.join(directory, 'renamed'); await fs.rename(created, renamed); expect((await fs.lstat(renamed)).mode & 0o777).toBe(0o600); expect(await actual.readFile(renamed, 'utf8')).toBe('handle bytes');
      expect((await fs.lstat(directory)).mode & 0o777).toBe(0o700);
    } finally { await actual.rm(root, { recursive: true, force: true }); }
  });
  it('models only named journal receipt bytes and preserves every native POSIX journal function', async () => {
    expect(posixJournalPolicyFixture(journal, actual, () => '', [], 'darwin')).toBe(journal);
    expect(posixJournalPolicyFixture(journal, actual, () => '', [], 'linux')).toBe(journal);
    const root = await actual.realpath(await actual.mkdtemp(path.join(os.tmpdir(), 'ud-journal-policy-')));
    try {
      const fs = posixPolicyFixture(actual, 'win32'), model = posixJournalPolicyFixture(journal, fs, () => root, ['receipt.json'], 'win32');
      const file = path.join(root, 'receipt.json'), bytes = Buffer.from('{"receipt":"exact"}');
      await model.durableWrite(file, bytes); expect(await model.boundedRead(file, 1024)).toEqual(bytes);
      expect(await actual.readFile(file)).toEqual(bytes); expect((await fs.lstat(file)).mode & 0o777).toBe(0o600);
      await expect(model.boundedRead(file, bytes.length - 1)).rejects.toThrow('read bound');
      await expect(model.durableWrite(path.join(root, 'unknown.json'), bytes)).rejects.toThrow('named fixture');
      await expect(model.durableWrite(path.join(root, '..', 'receipt.json'), bytes)).rejects.toThrow('named fixture');
      expect(await actual.readdir(root)).toEqual(['receipt.json']);
    } finally { await actual.rm(root, { recursive: true, force: true }); }
  });
  it('refuses aliased journal fixture files and parents without changing their targets', async () => {
    const root = await actual.realpath(await actual.mkdtemp(path.join(os.tmpdir(), 'ud-journal-alias-')));
    try {
      const model = posixJournalPolicyFixture(journal, actual, () => root, ['receipt.json'], 'win32'), target = path.join(root, 'target');
      await actual.writeFile(target, 'preserved'); await actual.symlink(target, path.join(root, 'receipt.json'));
      await expect(model.boundedRead(path.join(root, 'receipt.json'), 1024)).rejects.toThrow('unaliased');
      await expect(model.durableWrite(path.join(root, 'receipt.json'), Buffer.from('changed'))).rejects.toThrow('unaliased');
      await actual.mkdir(path.join(root, 'directory')); await actual.symlink(path.join(root, 'directory'), path.join(root, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
      await expect(model.durableWrite(path.join(root, 'alias/receipt.json'), Buffer.from('changed'))).rejects.toThrow('named fixture');
      expect(await actual.readFile(target, 'utf8')).toBe('preserved'); expect(await actual.readdir(path.join(root, 'directory'))).toEqual([]);
    } finally { await actual.rm(root, { recursive: true, force: true }); }
  });
});
