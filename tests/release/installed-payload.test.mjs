import { test, expect } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { installedMcpLaunch, verifyInstalledPayload } from '../../scripts/quality/installed-payload.mjs';

function fixture(run) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-installed-payload-'));
  const files = ['runtime/runtime.lock.json', 'runtime/node/bin/node', 'runtime/node/bin/node.exe', 'lib/coordinator.mjs', 'bin/ud-agent', 'bin/ud-agent.exe', 'cli.cjs', 'mcpb-entry.cjs'];
  for (const file of files) { const target = path.join(root, file); mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, file); chmodSync(target, 0o755); }
  writeFileSync(path.join(root, 'BUILD-RECEIPT.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', kind: 'native', platform: 'darwin-arm64', source_tree_sha256: 'a'.repeat(64), runtime_lock_sha256: fileReceipt(root, files[0]).sha256 }));
  files.push('BUILD-RECEIPT.json');
  const inventory = { schema_version: 1, files: files.map(file => fileReceipt(root, file)) };
  writeFileSync(path.join(root, 'PACKAGE-INVENTORY.json'), JSON.stringify(inventory));
  try { return run(root, inventory); } finally { rmSync(root, { recursive: true, force: true }); }
}

test('installed payload verifies complete immutable inventory and exact build subjects', () => fixture(root => {
  const before = verifyInstalledPayload(root);
  expect(before).toEqual(expect.objectContaining({ files: 9, source_tree_sha256: 'a'.repeat(64), kind: 'native' }));
  for (const format of ['coordinator', 'native', 'npm', 'mcpb']) installedMcpLaunch(root, '/workspace', { format, node: process.execPath });
  expect(verifyInstalledPayload(root)).toEqual(before);
}));

test('installed payload rejects missing, altered, duplicate and unlisted files', () => fixture((root, inventory) => {
  const name = path.join(root, 'PACKAGE-INVENTORY.json'), original = readFileSync(name);
  writeFileSync(name, JSON.stringify({ ...inventory, files: inventory.files.slice(1) })); expect(() => verifyInstalledPayload(root)).toThrow(/omits/);
  writeFileSync(name, JSON.stringify({ ...inventory, files: [...inventory.files, inventory.files[0]] })); expect(() => verifyInstalledPayload(root)).toThrow(/inventory/);
  writeFileSync(name, original); writeFileSync(path.join(root, 'lib/coordinator.mjs'), 'rebundled source'); expect(() => verifyInstalledPayload(root)).toThrow(/inventory/);
}));

test('installed payload rejects forged runtime subjects even with a rewritten inventory', () => fixture((root, inventory) => {
  const file = 'BUILD-RECEIPT.json', build = JSON.parse(readFileSync(path.join(root, file)));
  writeFileSync(path.join(root, file), JSON.stringify({ ...build, runtime_lock_sha256: 'f'.repeat(64) }));
  inventory.files = inventory.files.map(row => row.path === file ? fileReceipt(root, file) : row);
  writeFileSync(path.join(root, 'PACKAGE-INVENTORY.json'), JSON.stringify(inventory));
  expect(() => verifyInstalledPayload(root)).toThrow(/subjects/);
}));

test('Windows extraction ignores only POSIX executable bits while retaining exact bytes', () => fixture((root, inventory) => {
  inventory.files = inventory.files.map(row => ({ ...row, executable: !row.executable }));
  writeFileSync(path.join(root, 'PACKAGE-INVENTORY.json'), JSON.stringify(inventory));
  expect(verifyInstalledPayload(root, { platform: 'win32' }).files).toBe(9);
  expect(() => verifyInstalledPayload(root, { platform: 'darwin' })).toThrow(/inventory/);
  writeFileSync(path.join(root, 'cli.cjs'), 'changed');
  expect(() => verifyInstalledPayload(root, { platform: 'win32' })).toThrow(/inventory/);
}));

test('installed payload rejects links instead of following files outside its package', () => fixture(root => {
  const target = path.join(root, 'lib/coordinator.mjs'); rmSync(target); symlinkSync(path.join(root, 'cli.cjs'), target);
  expect(() => verifyInstalledPayload(root)).toThrow(/link/);
  expect(() => installedMcpLaunch(root, '/workspace')).toThrow(/link/);
}));

test('installed launch profiles execute actual npm, native and MCPB entry points', () => fixture(root => {
  expect(installedMcpLaunch(root, '/workspace', { format: 'native' })).toEqual({ command: path.join(root, 'bin/ud-agent' + (process.platform === 'win32' ? '.exe' : '')), args: ['mcp', '--allow-root', '/workspace'], node: path.join(root, 'runtime/node/bin/node' + (process.platform === 'win32' ? '.exe' : '')), coordinator: path.join(root, 'lib/coordinator.mjs'), env: {} });
  expect(installedMcpLaunch(root, '/workspace', { format: 'npm' }).args).toEqual([path.join(root, 'cli.cjs'), 'mcp', '--allow-root', '/workspace']);
  expect(installedMcpLaunch(root, '/workspace', { format: 'mcpb' }).args).toEqual([path.join(root, 'mcpb-entry.cjs'), '/workspace']);
  expect(installedMcpLaunch(root, '/workspace', { format: 'native', platform: 'win32' }).command).toBe(path.join(root, 'bin/ud-agent.exe'));
  for (const options of [{ format: 'unknown' }, { bundleName: '../coordinator.mjs' }, { format: 'npm', bundleName: 'coordinator-node24.mjs' }, { node: 'node' }]) expect(() => installedMcpLaunch(root, '/workspace', options)).toThrow();
}));

test('Windows vendor Node launches the native coordinator in both archive formats', () => fixture(root => {
  const sha256 = 'a'.repeat(64), workspace = path.join(root, 'tree with spaces');
  writeFileSync(path.join(root, 'runtime/windows-node.json'), JSON.stringify({ sha256: 'sha256:' + sha256 }));
  rmSync(path.join(root, 'runtime/node/bin/node.exe'));
  const options = { platform: 'win32', localAppData: root };
  const native = installedMcpLaunch(root, workspace, { ...options, format: 'native' });
  const mcpb = installedMcpLaunch(root, workspace, { ...options, format: 'mcpb' });
  expect(native.command).toBe(path.join(root, 'bin/ud-agent.exe'));
  expect(native.node).toBe(path.join(root, 'ud-agent/data/node-cache', `node-${sha256}.exe`));
  expect(native.args).toEqual(['mcp', '--allow-root', workspace]);
  expect(mcpb).toEqual({ ...native, args: ['--mcpb-workspace', workspace] });
}));
