import { test, expect } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { resolveCrossBuildInputs, retainCrossBuildInputs } from '../../scripts/release/cross-build-inputs.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';

posixTest('retained recipes and all binary subjects survive a subsequent build without rewriting origin paths', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-retain-cross-'));
  try {
    const cross = { schema_version: 1, source_sha256: 'a'.repeat(64), platforms: {} };
    for (const platform of ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64']) {
      cross.platforms[platform] = {};
      for (const name of ['ud-agent', 'ud-agent-guard']) { const relative = `target/${platform}/${name}`; mkdirSync(path.dirname(path.join(root, relative)), { recursive: true }); writeFileSync(path.join(root, relative), `${platform}/${name}`); chmodSync(path.join(root, relative), 0o755); cross.platforms[platform][name] = fileReceipt(root, relative); }
    }
    const original = Buffer.from(JSON.stringify(cross)); writeFileSync(path.join(root, 'cross.json'), original);
    const output = path.join(root, 'retained'); retainCrossBuildInputs(root, 'cross.json', output);
    writeFileSync(path.join(root, 'cross.json'), '{}'); writeFileSync(path.join(root, cross.platforms['darwin-arm64']['ud-agent'].path), 'next build');
    const saved = JSON.parse(readFileSync(path.join(output, 'INPUTS.json')));
    expect(readFileSync(path.join(output, 'cross-build-receipt.json'))).toEqual(original);
    expect(saved.binaries).toHaveLength(12);
    for (const row of saved.binaries) expect(fileReceipt(output, row.path).sha256).toBe(row.sha256);
    expect(() => retainCrossBuildInputs(root, 'cross.json', path.join(root, 'invalid'))).toThrow(/complete original/);
    writeFileSync(path.join(root, 'cross.json'), original);
    expect(() => retainCrossBuildInputs(root, 'cross.json', path.join(root, 'stale'))).toThrow(/differs from its original/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

posixTest('missing build outputs reuse only the exact verified retained recipe and reject corruption', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-retained-cross-'));
  try {
    const cross = { schema_version: 1, source_sha256: 'a'.repeat(64), platforms: {} };
    for (const platform of ['darwin-arm64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64']) {
      cross.platforms[platform] = {};
      for (const name of ['ud-agent', 'ud-agent-guard']) {
        const relative = `target/${platform}/${name}`;
        mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
        writeFileSync(path.join(root, relative), `${platform}/${name}`); chmodSync(path.join(root, relative), 0o755);
        cross.platforms[platform][name] = fileReceipt(root, relative);
      }
    }
    writeFileSync(path.join(root, 'cross.json'), JSON.stringify(cross));
    const retainedRoot = path.join(root, 'retained'); retainCrossBuildInputs(root, 'cross.json', retainedRoot);
    const missing = cross.platforms['darwin-arm64']['ud-agent'].path;
    unlinkSync(path.join(root, missing));
    const resolved = resolveCrossBuildInputs(root, 'cross.json', { retainedRoot });
    expect(readFileSync(resolved.binaries.find(row => row.platform === 'darwin-arm64' && row.name === 'ud-agent').path, 'utf8')).toBe('darwin-arm64/ud-agent');
    const copied = path.join(root, 'copied'); retainCrossBuildInputs(root, 'cross.json', copied, { retainedRoot });
    expect(JSON.parse(readFileSync(path.join(copied, 'INPUTS.json'))).binaries).toHaveLength(10);

    writeFileSync(path.join(root, 'cross.json'), JSON.stringify({ ...cross, source_sha256: 'b'.repeat(64) }));
    expect(() => resolveCrossBuildInputs(root, 'cross.json', { retainedRoot })).toThrow(/recipe differs/);
    writeFileSync(path.join(root, 'cross.json'), JSON.stringify(cross));

    writeFileSync(path.join(root, missing), 'bad output'); chmodSync(path.join(root, missing), 0o755);
    expect(() => resolveCrossBuildInputs(root, 'cross.json', { retainedRoot })).toThrow(/differs from its original/);
    const guards = resolveCrossBuildInputs(root, 'cross.json', { retainedRoot, names: ['ud-agent-guard'] });
    expect(guards.binaries).toHaveLength(5);
    expect(guards.binaries.every(row => row.name === 'ud-agent-guard')).toBe(true);
    expect(() => resolveCrossBuildInputs(root, 'cross.json', { names: ['unknown'] })).toThrow(/binary selection/);
    unlinkSync(path.join(root, missing));
    const retained = JSON.parse(readFileSync(path.join(retainedRoot, 'INPUTS.json')));
    const entry = retained.binaries.find(row => row.platform === 'darwin-arm64' && row.name === 'ud-agent');
    chmodSync(path.join(retainedRoot, entry.path), 0o755); writeFileSync(path.join(retainedRoot, entry.path), 'bad retained output');
    expect(() => resolveCrossBuildInputs(root, 'cross.json', { retainedRoot })).toThrow(/differs/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('non-executable original subjects cannot produce a successful retained cross-build receipt', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-nonexecutable-cross-'));
  try {
    const cross = { schema_version: 1, source_sha256: 'a'.repeat(64), platforms: {} };
    for (const platform of ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64']) {
      cross.platforms[platform] = {};
      for (const name of ['ud-agent', 'ud-agent-guard']) {
        const relative = `target/${platform}/${name}`, file = path.join(root, relative);
        mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, `${platform}/${name}`, { mode: 0o600 });
        cross.platforms[platform][name] = fileReceipt(root, relative);
        expect(cross.platforms[platform][name].executable).toBe(false);
      }
    }
    const recipe = JSON.stringify(cross), output = path.join(root, 'retained'); writeFileSync(path.join(root, 'cross.json'), recipe);
    expect(() => retainCrossBuildInputs(root, 'cross.json', output)).toThrow('Cross-build subject differs from its original recipe.');
    expect(existsSync(output)).toBe(false); expect(readFileSync(path.join(root, 'cross.json'), 'utf8')).toBe(recipe);
    for (const binaries of Object.values(cross.platforms)) for (const row of Object.values(binaries)) expect(fileReceipt(root, row.path)).toEqual(row);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
