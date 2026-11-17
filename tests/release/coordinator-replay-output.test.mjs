import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { coordinatorToolInputs, replayCoordinator } from '../../scripts/release/replay-coordinator-bundle.mjs';
import { sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';

const repository = path.resolve(import.meta.dirname, '../..');
test('compiler receipts bind the exact Windows or Unix package executable layout', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-bundle-platform-')), platform = Object.getOwnPropertyDescriptor(process, 'platform');
  try {
    for (const host of ['win32', 'linux']) {
      const binary = `node_modules/@esbuild/${host}-${process.arch}/${host === 'win32' ? 'esbuild.exe' : 'bin/esbuild'}`;
      for (const name of ['node_modules/esbuild/lib/main.js', 'node_modules/esbuild/package.json', binary]) {
        const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, name);
      }
      Object.defineProperty(process, 'platform', { configurable: true, value: host });
      const inputs = coordinatorToolInputs(root);
      assert.equal(inputs.length, 3); assert.equal(inputs[2].path, binary); assert.equal(inputs[2].sha256, sha256(binary));
      rmSync(path.join(root, binary));
      assert.throws(() => coordinatorToolInputs(root), /ENOENT/);
    }
  } finally { Object.defineProperty(process, 'platform', platform); rmSync(root, { recursive: true, force: true }); }
});

function sources(root) { mkdirSync(path.join(root, 'packages/coordinator/src'), { recursive: true }); writeFileSync(path.join(root, 'packages/coordinator/src/entry.ts'), 'import {parse} from "yaml"; console.log(parse("answer: 42").answer);\n'); writeFileSync(path.join(root, 'README.md'), 'Exact original fixture input.\n'); }
function sdk(root) {
  for (const row of coordinatorToolInputs(repository)) { const target = path.join(root, row.path); mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(path.join(repository, row.path), target); chmodSync(target, row.executable ? 0o755 : 0o644); }
  cpSync(path.join(repository, 'node_modules/yaml'), path.join(root, 'node_modules/yaml'), { recursive: true, dereference: false });
  return coordinatorToolInputs(root);
}

test('producer output and independent proof have identical bytes across different source and dependency roots', async () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-bundle-layout-')), originalEnv = process.env.ESBUILD_BINARY_PATH;
  try {
    const rows = [];
    for (const name of ['first', 'unrelated/deeper/second']) {
      const root = path.join(base, name), source = path.join(root, 'source'), tools = path.join(root, 'tools'), output = path.join(root, 'bundle.mjs'); sources(source); const expected = sdk(tools);
      process.env.ESBUILD_BINARY_PATH = '/must/not/select/ambient/compiler';
      const produced = await replayCoordinator(source, tools, expected, { output }), proof = await replayCoordinator(source, tools, expected);
      assert.deepEqual(proof.bundle, produced.bundle); assert.equal(sha256(readFileSync(output)), produced.bundle.sha256); assert.equal(readFileSync(output).length, produced.bundle.size_bytes);
      assert.equal(produced.source_inventory_sha256, sourceReceipt(source).sha256); assert.equal(process.env.ESBUILD_BINARY_PATH, '/must/not/select/ambient/compiler');
      assert.ok(produced.inputs.some(row => row.path === 'node_modules/yaml/package.json'));
      const executed = spawnSync(process.execPath, [output], { encoding: 'utf8', timeout: 30000 }); assert.equal(executed.status, 0, executed.stderr); assert.equal(executed.stdout.trim(), '42');
      rows.push({ bytes: readFileSync(output), proof });
    }
    assert.deepEqual(rows[0].bytes, rows[1].bytes); assert.deepEqual(rows[0].proof.inputs, rows[1].proof.inputs);
  } finally { if (originalEnv === undefined) delete process.env.ESBUILD_BINARY_PATH; else process.env.ESBUILD_BINARY_PATH = originalEnv; rmSync(base, { recursive: true, force: true }); }
}, 60000);

test('changed original source, compiler bytes or an existing output refuses to publish a bundle', async () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-bundle-tamper-'));
  try {
    const source = path.join(base, 'source'), tools = path.join(base, 'tools'), output = path.join(base, 'bundle.mjs'); sources(source); const expected = sdk(tools);
    const pending = replayCoordinator(source, tools, expected, { output });
    writeFileSync(path.join(source, 'README.md'), 'Changed after immutable source capture.\n');
    await assert.rejects(pending, /source changed during bundle replay/); assert.equal(existsSync(output), false);
    writeFileSync(path.join(tools, expected[0].path), 'changed compiler implementation');
    await assert.rejects(replayCoordinator(source, tools, expected, { output }), /not verified against original locked npm archives/); assert.equal(existsSync(output), false);
    writeFileSync(output, 'retained prior output');
    await assert.rejects(replayCoordinator(source, tools, expected, { output }), /new absolute file/); assert.equal(readFileSync(output, 'utf8'), 'retained prior output');
  } finally { rmSync(base, { recursive: true, force: true }); }
}, 60000);
