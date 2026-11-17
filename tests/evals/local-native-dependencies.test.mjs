// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { CLIENT_LOCK, CLIENT_LOCK_SHA256, nativeClientDependencyRecipe, assertNativeClientDependencyRecipe, nativeClientRequirements, nativeClientDependencyCheck } from '../../evals/local/native-clients.mjs';
import { prepareLinuxClientLock } from '../../evals/local/container.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

test('Hermes optional MCP recipe is independently pinned and rejects stale receipts without invalidating other clients', () => {
  const selected = nativeClientDependencyRecipe('hermes-agent');
  assert.equal(selected.packages[0].version, '1.26.0');
  assert.match(nativeClientRequirements('hermes-agent'), /mcp @ https:\/\/files\.pythonhosted\.org\/.+#sha256=[a-f0-9]{64}\n/);
  assert.match(nativeClientDependencyCheck('hermes-agent'), /from mcp import ClientSession, StdioServerParameters/);
  assert.throws(() => assertNativeClientDependencyRecipe('hermes-agent', {}), /DEPENDENCY_RECIPE_CHANGED/);
  assert.throws(() => assertNativeClientDependencyRecipe('hermes-agent', { dependency_recipe_sha256: 'old' }), /DEPENDENCY_RECIPE_CHANGED/);
  assert.doesNotThrow(() => assertNativeClientDependencyRecipe('hermes-agent', { dependency_recipe_sha256: selected.sha256 }));
  for (const client of CLIENT_LOCK.clients.filter(client => client.id !== 'hermes-agent')) {
    assert.equal(nativeClientDependencyRecipe(client.id), undefined);
    assert.doesNotThrow(() => assertNativeClientDependencyRecipe(client.id, { client_lock_sha256: CLIENT_LOCK_SHA256 }));
  }
});

test('Linux Hermes dependency resolution includes and verifies the exact SDK artifact independently of host resolution', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-hermes-dependencies-')), prepared = { directory: path.join(root, 'host') };
  try {
    for (const missing of [false, true]) {
      const directory = path.join(root, String(missing)); mkdirSync(directory);
      const run = prepareLinuxClientLock(root, 'hermes-agent', directory, prepared, { runner: async (binary, args) => {
        assert.equal(binary, 'uv'); assert.equal(args[args.indexOf('--python-platform') + 1], 'aarch64-manylinux_2_36');
        const input = readFileSync(args.at(-1), 'utf8');
        assert.equal(input, nativeClientRequirements('hermes-agent'));
        writeFileSync(args[args.indexOf('--output-file') + 1], missing ? input.split('\n')[0] : input);
        return { stdout: '' };
      } });
      if (missing) await assert.rejects(run, /LINUX_DEPENDENCY_IDENTITY_CHANGED/);
      else { const result = await run; assert.equal(result.sha256, sha256(nativeClientRequirements('hermes-agent'))); }
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
