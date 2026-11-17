import { mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { loadSavedSelection, saveSelection } from '../../packages/runtime-manager/src/selection.js';

it('persists only supported verified selections and never creates state during a read', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-selection-')));
  try {
    const guard = process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined;
    const state = path.join(root, 'state'), host = { platform: 'darwin' as const, arch: 'arm64' };
    expect(await loadSavedSelection(state, host, guard)).toBeUndefined();
    await saveSelection(state, host, 'docker', guard);
    expect(await loadSavedSelection(state, host, guard)).toBe('docker');
    expect(await loadSavedSelection(state, { platform: 'win32', arch: 'arm64' }, guard)).toBeUndefined();
    await expect(saveSelection(state, host, 'wslc', guard)).rejects.toThrow('SELECTION_STATE_INVALID');
    await writeFile(path.join(state, 'selected.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', platform: host.platform, arch: host.arch, engine: 'invented' }));
    await expect(loadSavedSelection(state, host, guard)).rejects.toThrow('SELECTION_STATE_INVALID');
  } finally { await rm(root, { recursive: true, force: true }); }
});
