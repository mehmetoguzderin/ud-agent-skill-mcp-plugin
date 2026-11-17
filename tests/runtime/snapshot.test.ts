import { describe, expect, it } from 'vitest';
import { mkdtemp, readFile, realpath, rm, symlink, writeFile, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { captureValidationSnapshot, verifySnapshotIntegrity } from '../../packages/workspace/src/snapshot.js';
import { writeNativeEngine } from './native-engine-fixture.js';

const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));

describe('guarded snapshots', () => {
  it('captures dirty bytes exactly, excludes Git, and cleans only its own snapshot', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-treebank-'));
    try {
      await mkdir(path.join(root, '.git'));
      await writeFile(path.join(root, '.git', 'secret'), 'private');
      await writeFile(path.join(root, 'README.md'), 'documentation');
      const bytes = Buffer.from('# sent_id = 1\r\n1\tÄ\t_\tX\t_\t_\t0\troot\t_\t_');
      await writeFile(path.join(root, 'dirty.conllu'), bytes);
      await expect(captureValidationSnapshot(guard, await realpath(root), [])).rejects.toThrow('authorized roots');
      const snapshot = await captureValidationSnapshot(guard, await realpath(root), [await realpath(root)]);
      try {
        expect(snapshot.files.map(file => file.path)).toEqual(['README.md', 'dirty.conllu']);
        expect(await readFile(path.join(snapshot.directory, 'dirty.conllu'))).toEqual(bytes);
        expect(snapshot.consistency).toBe('verified-per-file');
        expect(snapshot.sha256).toMatch(/^[0-9a-f]{64}$/);
      } finally { await snapshot.cleanup(); }
      expect(await readFile(path.join(root, 'dirty.conllu'))).toEqual(bytes);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('rejects symlinks instead of reading targets outside the grant', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-treebank-'));
    try {
      await symlink('/etc/passwd', path.join(root, 'out.conllu'));
      await expect(captureValidationSnapshot(guard, await realpath(root), [await realpath(root)])).rejects.toThrow('unsupported link');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('rejects a workspace root replaced between enumeration and read', async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-root-swap-'));
    try {
      const root = path.join(await realpath(base), 'root');
      const oldRoot = path.join(await realpath(base), 'old-root');
      const marker = path.join(await realpath(base), 'swapped');
      await mkdir(root);
      await writeFile(path.join(root, 'data.conllu'), 'original');
      const script = `#!${process.execPath}\n` +
        `const fs = require('node:fs'); const cp = require('node:child_process');\n` +
        `const result = cp.spawnSync(${JSON.stringify(guard)}, process.argv.slice(2));\n` +
        `if (result.status === 0 && process.argv[2] === 'list' && !fs.existsSync(${JSON.stringify(marker)})) {\n` +
        `fs.renameSync(${JSON.stringify(root)}, ${JSON.stringify(oldRoot)}); fs.mkdirSync(${JSON.stringify(root)});\n` +
        `fs.writeFileSync(${JSON.stringify(path.join(root, 'data.conllu'))}, 'replaced'); fs.writeFileSync(${JSON.stringify(marker)}, '1'); }\n` +
        `process.stdout.write(result.stdout); process.stderr.write(result.stderr); process.exit(result.status ?? 1);\n`;
      const wrapper = await writeNativeEngine({ root: await realpath(base), name: 'guard-wrapper', program: script });
      await expect(captureValidationSnapshot(wrapper, root, [root])).rejects.toThrow('WORKSPACE_ROOT_CHANGED');
      expect(await readFile(marker, 'utf8')).toBe('1');
      expect(await readFile(path.join(root, 'data.conllu'), 'utf8')).toBe('replaced');
      expect(await readFile(path.join(oldRoot, 'data.conllu'), 'utf8')).toBe('original');
    } finally { await rm(base, { recursive: true, force: true }); }
  }, 20000);

  it('cannot follow a workspace swapped to a symlink just before grant binding', async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-bind-race-'));
    try {
      const canonical = await realpath(base);
      const grant = path.join(canonical, 'grant'); const outside = path.join(canonical, 'outside');
      const workspace = path.join(grant, 'bank'); const old = path.join(grant, 'old');
      const marker = path.join(canonical, 'swapped-and-guarded.json');
      await mkdir(grant); await mkdir(outside); await mkdir(workspace);
      await writeFile(path.join(workspace, 'file.conllu'), 'inside');
      await writeFile(path.join(outside, 'file.conllu'), 'outside secret');
      const script = `#!${process.execPath}\n` +
        `const fs = require('node:fs'); const cp = require('node:child_process');\n` +
        `if (process.argv[2] === 'bind') { fs.renameSync(${JSON.stringify(workspace)}, ${JSON.stringify(old)}); fs.symlinkSync(${JSON.stringify(outside)}, ${JSON.stringify(workspace)}, ${JSON.stringify(process.platform === 'win32' ? 'junction' : 'dir')}); }\n` +
        `const result = cp.spawnSync(${JSON.stringify(guard)}, process.argv.slice(2)); if(process.argv[2]==='bind')fs.writeFileSync(${JSON.stringify(marker)},JSON.stringify({status:result.status,error:result.error?.code??null,stderr:result.stderr?.toString()})); process.stdout.write(result.stdout); process.stderr.write(result.stderr); process.exit(result.status ?? 1);\n`;
      const wrapper = await writeNativeEngine({ root: canonical, name: 'guard-wrapper', program: script });
      await expect(captureValidationSnapshot(wrapper, workspace, [grant])).rejects.toThrow('Filesystem guard rejected');
      const observed = JSON.parse(await readFile(marker, 'utf8'));
      expect(observed.error).toBeNull(); expect(observed.status).toBeGreaterThan(0); expect(observed.stderr).toContain('ud-agent-guard:');
      expect(await readFile(path.join(old, 'file.conllu'), 'utf8')).toBe('inside');
      expect(await readFile(path.join(outside, 'file.conllu'), 'utf8')).toBe('outside secret');
    } finally { await rm(base, { recursive: true, force: true }); }
  }, 20000);

  it('detects replacement of a workspace below a still-identical grant after binding', async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-bind-swap-'));
    try {
      const grant = path.join(await realpath(base), 'grant');
      const workspace = path.join(grant, 'bank'); const old = path.join(grant, 'old');
      const marker = path.join(await realpath(base), 'swapped');
      await mkdir(grant); await mkdir(workspace); await writeFile(path.join(workspace, 'file.conllu'), 'inside');
      const script = `#!${process.execPath}\n` +
        `const fs = require('node:fs'); const cp = require('node:child_process');\n` +
        `const result = cp.spawnSync(${JSON.stringify(guard)}, process.argv.slice(2));\n` +
        `if (result.status === 0 && process.argv[2] === 'bind' && !fs.existsSync(${JSON.stringify(marker)})) { fs.renameSync(${JSON.stringify(workspace)}, ${JSON.stringify(old)}); fs.mkdirSync(${JSON.stringify(workspace)}); fs.writeFileSync(${JSON.stringify(path.join(workspace, 'file.conllu'))}, 'replacement'); fs.writeFileSync(${JSON.stringify(marker)}, '1'); }\n` +
        `process.stdout.write(result.stdout); process.stderr.write(result.stderr); process.exit(result.status ?? 1);\n`;
      const wrapper = await writeNativeEngine({ root: await realpath(base), name: 'guard-wrapper', program: script });
      await expect(captureValidationSnapshot(wrapper, workspace, [grant])).rejects.toThrow('WORKSPACE_ROOT_CHANGED');
      expect(await readFile(marker, 'utf8')).toBe('1');
      expect(await readFile(path.join(workspace, 'file.conllu'), 'utf8')).toBe('replacement');
      expect(await readFile(path.join(old, 'file.conllu'), 'utf8')).toBe('inside');
    } finally { await rm(base, { recursive: true, force: true }); }
  }, 20000);

  it('rejects changed staged bytes and extra staged files before execution', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-treebank-'));
    try {
      await writeFile(path.join(root, 'data.conllu'), 'original');
      const snapshot = await captureValidationSnapshot(guard, await realpath(root), [await realpath(root)]);
      try {
        expect(await verifySnapshotIntegrity(guard, snapshot)).toBe(await realpath(snapshot.directory));
        await writeFile(path.join(snapshot.directory, 'data.conllu'), 'modified');
        await expect(verifySnapshotIntegrity(guard, snapshot)).rejects.toThrow('Snapshot bytes changed');
        await writeFile(path.join(snapshot.directory, 'data.conllu'), 'original');
        await writeFile(path.join(snapshot.directory, 'extra'), 'injected');
        await expect(verifySnapshotIntegrity(guard, snapshot)).rejects.toThrow('Unexpected');
      } finally { await snapshot.cleanup(); }
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('cancels an in-flight guard call and removes its snapshot', async () => {
    if (process.platform === 'win32') {
      const cancelled = new AbortController(); cancelled.abort();
      await expect(captureValidationSnapshot(guard, path.resolve('.'), [path.resolve('.')], cancelled.signal)).rejects.toThrow('WORKER_CANCELLED');
      return;
    }
    const base = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-snapshot-cancel-'));
    try {
      const root = await realpath(base); const wrapper = path.join(root, 'guard-wrapper');
      await writeFile(path.join(root, 'data.conllu'), 'original');
      const script = `#!${process.execPath}\n` +
        `const cp=require('node:child_process'); if(process.argv[2]==='list') setTimeout(()=>process.exit(0),10000); else {const r=cp.spawnSync(${JSON.stringify(guard)},process.argv.slice(2));process.stdout.write(r.stdout);process.stderr.write(r.stderr);process.exit(r.status??1);}\n`;
      await writeFile(wrapper, script, { mode: 0o700 });
      const controller = new AbortController(); const started = Date.now();
      const timer = setTimeout(() => controller.abort(), 200);
      try { await expect(captureValidationSnapshot(wrapper, root, [root], controller.signal)).rejects.toThrow('WORKER_CANCELLED'); }
      finally { clearTimeout(timer); }
      expect(Date.now() - started).toBeLessThan(3000);
      expect(await readFile(path.join(root, 'data.conllu'), 'utf8')).toBe('original');
    } finally { await rm(base, { recursive: true, force: true }); }
  });
});
