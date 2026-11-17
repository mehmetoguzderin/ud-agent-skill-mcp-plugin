import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { beginImageImportStaging, recoverImageImportStaging } from '../../packages/runtime-manager/src/image-import-staging.js';
import { JournalStore } from '../../packages/workspace/src/journal.js';
import { stageVerifiedArchive } from '../../packages/runtime-manager/src/archive.js';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { once } from 'node:events';
import { guardedIdentity, guardedStateLock } from '../../packages/workspace/src/guard.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const bytes = Buffer.from('independent accepted archive bytes'); const sha = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const transport = { format: 'oci-archive' as const, path: 'runtime/images/core.tar', sha256: sha, sizeBytes: bytes.length };
const receipts = new Map([[`${sha.slice(7)}.tar`, { sha256: sha, size: bytes.length }]]);
async function fixture(test: (root: string) => Promise<void>) { const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-image-stage-'))); try { await JournalStore.open(root, guard); await test(root); } finally { await rm(root, { recursive: true, force: true }); } }
async function record(root: string) { const name = (await readdir(root)).find(name => name.endsWith('.json'))!; return { name, file: path.join(root, name), value: JSON.parse(await readFile(path.join(root, name), 'utf8')) }; }
describe('native-owned image import staging recovery', () => {
  it('recovers a real coordinator crash and releases its native scratch lock', async () => fixture(async root => {
    const archive = path.join(root, 'source.tar'); const scratch = path.join(root, 'scratch'); await writeFile(archive, bytes); const module = pathToFileURL(path.resolve('packages/runtime-manager/src/archive.ts')).href;
    const script = `const {stageVerifiedArchive}=await import(${JSON.stringify(module)});const stage=await stageVerifiedArchive(${JSON.stringify(archive)},${JSON.stringify(sha)},${bytes.length},{stateRoot:${JSON.stringify(scratch)},guard:${JSON.stringify(guard)}});console.log(JSON.stringify({filename:stage.filename}));`;
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
    try {
      const filename = await new Promise<string>((resolve, reject) => { let output = ''; const timer = setTimeout(() => reject(new Error('staging child did not become ready')), 10000); child.once('error', error => { clearTimeout(timer); reject(error); }); child.stdout.on('data', chunk => { output += chunk; if (output.includes('\n')) { clearTimeout(timer); try { resolve(JSON.parse(output.split('\n')[0]!).filename); } catch (error) { reject(error); } } }); child.once('exit', code => { clearTimeout(timer); if (!output.includes('\n')) reject(new Error(`staging child exited ${code}`)); }); });
      expect(await readFile(filename)).toEqual(bytes); const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
      let unlock: (() => Promise<void>) | undefined;
      for (let attempt = 0; !unlock && attempt < 100; attempt++) { try { unlock = await guardedStateLock(guard, scratch, '.archive-stage.native', await guardedIdentity(guard, scratch), true); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EBUSY') throw error; await new Promise(done => setTimeout(done, 10)); } }
      expect(unlock).toBeDefined(); try { expect((await recoverImageImportStaging(scratch, guard, receipts, false)).paths).toHaveLength(2); } finally { await unlock?.(); }
      await expect(readFile(filename)).rejects.toMatchObject({ code: 'ENOENT' }); const next = await stageVerifiedArchive(archive, sha, bytes.length, { stateRoot: scratch, guard }); expect(await readFile(next.filename)).toEqual(bytes); await next.cleanup(); await next.cleanup();
    } finally { if (child.exitCode === null && child.signalCode === null) { const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited; } }
  }));
  it('publishes only verified immutable bytes and removes its journal and private directory', async () => fixture(async root => {
    const staged = await beginImageImportStaging(root, guard, transport); await writeFile(staged.filename, bytes); const before = await lstat(staged.filename, { bigint: true }); await staged.publish(); await staged.cleanup(); const cached = path.join(root, `${sha.slice(7)}.tar`); expect(await readFile(cached)).toEqual(bytes); const after = await lstat(cached, { bigint: true }); expect([after.dev, after.ino]).toEqual([before.dev, before.ino]); if (process.platform !== 'win32') expect(Number(after.mode) & 0o222).toBe(0); expect((await readdir(root)).filter(name => name.startsWith('.image-import-'))).toEqual([]);
  }));
  it('previews without writes, cancels incomplete bytes, and preserves unrelated staging names', async () => fixture(async root => {
    const staged = await beginImageImportStaging(root, guard, transport); await writeFile(staged.filename, bytes.subarray(0, 7)); await writeFile(path.join(root, 'unrelated.tmp'), 'retain'); const before = await readdir(root); const dry = await recoverImageImportStaging(root, guard, receipts, true); expect(dry.paths).toHaveLength(2); expect(await readdir(root)).toEqual(before); expect(await readFile(staged.filename)).toEqual(bytes.subarray(0, 7)); await recoverImageImportStaging(root, guard, receipts, false); await expect(readFile(staged.filename)).rejects.toMatchObject({ code: 'ENOENT' }); expect(await readFile(path.join(root, 'unrelated.tmp'), 'utf8')).toBe('retain'); await expect(readFile(path.join(root, `${sha.slice(7)}.tar`))).rejects.toMatchObject({ code: 'ENOENT' });
  }));
  it('recovers planned directory creation and response loss after publication', async () => {
    for (const phase of ['planned', 'ready', 'published'] as const) await fixture(async root => {
      const staged = await beginImageImportStaging(root, guard, transport); const saved = await record(root); saved.value.phase = phase; if (phase === 'planned') saved.value.directory_identity = null;
      await writeFile(staged.filename, bytes); if (phase !== 'planned') { await chmod(staged.filename, 0o400); await rename(staged.filename, path.join(root, `${sha.slice(7)}.tar`)); } await writeFile(saved.file, JSON.stringify(saved.value), { mode: 0o600 });
      await recoverImageImportStaging(root, guard, receipts, false); expect((await readdir(root)).filter(name => name.startsWith('.image-import-'))).toEqual([]); if (phase !== 'planned') expect(await readFile(path.join(root, `${sha.slice(7)}.tar`))).toEqual(bytes);
    });
  });
  it('blocks changed ownership, unknown payloads, and forged paths before removing either candidate', async () => fixture(async root => {
    const staged = await beginImageImportStaging(root, guard, transport); await writeFile(staged.filename, bytes); const saved = await record(root); const directory = path.dirname(staged.filename);
    await writeFile(path.join(directory, 'foreign'), 'retain'); await expect(recoverImageImportStaging(root, guard, receipts, false)).rejects.toThrow('HAS_UNOWNED_FILES'); expect(await readFile(staged.filename)).toEqual(bytes); await rm(path.join(directory, 'foreign'));
    await writeFile(path.join(directory, '.ud-agent-directory-owner'), 'a'.repeat(64)); await expect(recoverImageImportStaging(root, guard, receipts, false)).rejects.toThrow('OWNER_CHANGED'); await writeFile(path.join(directory, '.ud-agent-directory-owner'), saved.value.token);
    await writeFile(saved.file, JSON.stringify({ ...saved.value, directory: '../escape' })); await expect(recoverImageImportStaging(root, guard, receipts, false)).rejects.toThrow('JOURNAL_INVALID'); await writeFile(saved.file, JSON.stringify(saved.value));
    await rename(directory, `${directory}.original`); await mkdir(directory, { mode: 0o700 }); await expect(recoverImageImportStaging(root, guard, receipts, false)).rejects.toThrow('IDENTITY_CHANGED'); expect(await readFile(path.join(`${directory}.original`, 'worker.tar'))).toEqual(bytes);
  }));
  it('preserves obsolete receipts and rejects invalid completed publications', async () => fixture(async root => {
    const staged = await beginImageImportStaging(root, guard, transport); await writeFile(staged.filename, bytes); const dry = await recoverImageImportStaging(root, guard, new Map(), false); expect(dry.paths).toEqual([]); expect(dry.protected).toHaveLength(2); expect(await readFile(staged.filename)).toEqual(bytes);
    const saved = await record(root); saved.value.phase = 'ready'; await writeFile(saved.file, JSON.stringify(saved.value)); await writeFile(staged.filename, Buffer.alloc(bytes.length)); await expect(recoverImageImportStaging(root, guard, receipts, false)).rejects.toThrow('digest'); expect(await readFile(saved.file)).toBeDefined();
  }));
});
