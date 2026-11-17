import { test, expect, vi } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
const cleanup = vi.hoisted(() => ({ observe: undefined, refuse: false, retained: '' }));
vi.mock('node:fs/promises', async original => {
  const actual = await original();
  return { ...actual, rm: async (target, options) => {
    if (path.basename(target).startsWith('ud-bundle-verified-tools-')) {
      cleanup.observe?.(target);
      if (cleanup.refuse) { cleanup.retained = target; throw Object.assign(new Error('persistent private compiler handle refusal'), { code: 'EPERM' }); }
    }
    return actual.rm(target, options);
  } };
});
import { coordinatorToolInputs, replayCoordinator, verifyCoordinatorToolInputs } from '../../scripts/release/replay-coordinator-bundle.mjs';

test('bundle replay refuses absent or changed tool authority before importing a candidate compiler module', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-source-tools-'));
  try {
    const main = path.join(root, 'node_modules/esbuild/lib/main.js'), marker = path.join(root, 'untrusted-import-ran');
    const binary = path.join(root, `node_modules/@esbuild/${process.platform}-${process.arch}/${process.platform === 'win32' ? 'esbuild.exe' : 'bin/esbuild'}`);
    mkdirSync(path.dirname(main), { recursive: true }); mkdirSync(path.dirname(binary), { recursive: true });
    writeFileSync(main, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed');`);
    writeFileSync(path.join(root, 'node_modules/esbuild/package.json'), '{"version":"fixture"}');
    writeFileSync(binary, 'unverified compiler bytes');
    const observed = coordinatorToolInputs(root);
    expect(verifyCoordinatorToolInputs(root, observed)).toEqual(observed);
    await expect(replayCoordinator(root, root)).rejects.toThrow(/original locked npm/);
    expect(existsSync(marker)).toBe(false);
    writeFileSync(main, 'changed candidate compiler');
    await expect(replayCoordinator(root, root, observed)).rejects.toThrow(/original locked npm/);
    expect(existsSync(marker)).toBe(false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

function delayedCompiler(root) {
  const source = path.join(root, 'source'), assets = path.join(root, 'assets'), marker = path.join(root, 'compiler-stopped');
  mkdirSync(path.join(source, 'packages/coordinator/src'), { recursive: true });
  writeFileSync(path.join(source, 'packages/coordinator/src/entry.ts'), 'export const original = true;');
  const main = path.join(assets, 'node_modules/esbuild/lib/main.js');
  mkdirSync(path.dirname(main), { recursive: true });
  writeFileSync(path.join(assets, 'node_modules/esbuild/package.json'), '{"version":"fixture"}');
  writeFileSync(main, `exports.version='fixture';exports.build=async()=>({outputFiles:[{contents:Buffer.from('original output')}],metafile:{inputs:{}}});exports.stop=()=>new Promise(resolve=>setTimeout(()=>{require('node:fs').writeFileSync(${JSON.stringify(marker)},'stopped');resolve()},20));`);
  const binary = path.join(assets, `node_modules/@esbuild/${process.platform}-${process.arch}/${process.platform === 'win32' ? 'esbuild.exe' : 'bin/esbuild'}`);
  mkdirSync(path.dirname(binary), { recursive: true });writeFileSync(binary, 'unexecuted fixture compiler');
  return { source, assets, marker, expected: coordinatorToolInputs(assets) };
}

test('bundle replay waits for its compiler shutdown before deleting the private executable tree', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-source-tools-stop-'));let removed;
  try {
    const fixture = delayedCompiler(root);
    cleanup.observe = target => { expect(readFileSync(fixture.marker, 'utf8')).toBe('stopped'); removed = target; };
    const result = await replayCoordinator(fixture.source, fixture.assets, fixture.expected);
    expect(result.tool_version).toBe('fixture');expect(removed).toBeTypeOf('string');expect(existsSync(removed)).toBe(false);
  } finally { cleanup.observe = undefined;rmSync(root, { recursive: true, force: true }); }
});

test('persistent private compiler cleanup refusal remains a replay failure and preserves its bytes', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-source-tools-refusal-')), prior = process.env.ESBUILD_BINARY_PATH;
  try {
    const fixture = delayedCompiler(root);cleanup.refuse = true;
    await expect(replayCoordinator(fixture.source, fixture.assets, fixture.expected)).rejects.toThrow('persistent private compiler handle refusal');
    expect(readFileSync(fixture.marker, 'utf8')).toBe('stopped');
    expect(existsSync(path.join(cleanup.retained, fixture.expected[2].path))).toBe(true);
    expect(process.env.ESBUILD_BINARY_PATH).toBe(prior);
  } finally {
    cleanup.refuse = false;if (cleanup.retained) rmSync(cleanup.retained, { recursive: true, force: true });cleanup.retained = '';
    rmSync(root, { recursive: true, force: true });
  }
});
