// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { test } from 'vitest';
import { parse } from 'yaml';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { canonicalSkillFiles, connectedSkillFiles, skillInventory } from '../../scripts/generate/skill-files.mjs';
import { loadDistributionIdentity } from '../../scripts/release/host-adapters.mjs';

const root = process.cwd();
const json = async (name: string) => JSON.parse(await readFile(path.join(root, name), 'utf8'));

// Qwen's native ToolSearchTool discovery metadata exposes the first 160
// characters of each first line (157 + ellipsis when truncated). The pinned
// Qwen0.27.2 chunk-AAMQ5CMG.js source binds this client boundary.
// Every advertised purpose must survive it.
// This ceiling checks a real client boundary, not a preferred prose length.
const NATIVE_DISCOVERY_DESCRIPTION_LIMIT = 160;

test.each(['modern', 'legacy'] as const)('MCP %s discovery preserves all contracts and complete short purposes', async era => {
  const profile = await mkdtemp(path.join(os.tmpdir(), 'ud-discovery-profile-'));
  const client = new Client({ name: 'ud-discovery-contract-test', version: '1' }, {
    versionNegotiation: era === 'modern' ? { mode: { pin: '2026-07-28' } } : { mode: 'legacy' },
  });
  const transport = new StdioClientTransport({
    command: process.execPath, args: ['--import', 'tsx', path.join(root, 'packages/coordinator/src/entry.ts')], stderr: 'pipe',
    env: { PATH: process.env.PATH ?? '', HOME: profile, USERPROFILE: profile, LOCALAPPDATA: profile,
      XDG_DATA_HOME: profile, TMPDIR: profile, TMP: profile, TEMP: profile,
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) },
  });
  try {
    await client.connect(transport);
    const contracts = [...await json('contracts/ud-interfaces.json'), ...await json('contracts/environment.json')];
    const { tools } = await client.listTools();
    assert.equal(tools.length, 104);
    assert.deepEqual(tools.map(tool => tool.name).sort(), contracts.map(contract => contract.name).sort());
    for (const contract of contracts) {
      const tool = tools.find(candidate => candidate.name === contract.name)!;
      assert.equal(typeof tool.description, 'string', contract.name);
      assert.ok(tool.description!.trim().length > 0, contract.name);
      assert.equal(tool.description!.trim(), tool.description!.split('\n')[0].trim(),
        `${contract.name}: native discovery exposes only the first line`);
      assert.ok(tool.description!.length <= NATIVE_DISCOVERY_DESCRIPTION_LIMIT,
        `${contract.name}: its purpose is truncated by native discovery (${tool.description!.length} characters)`);
      assert.deepEqual(tool.inputSchema, await json(`contracts/schema/operations/${contract.name}.input.schema.json`), `${contract.name}: input contract`);
      assert.deepEqual(tool.outputSchema, await json(`contracts/schema/results/${contract.name}.schema.json`), `${contract.name}: result contract`);
      assert.deepEqual(tool.annotations, contract.id.startsWith('ENV-')
        ? { readOnlyHint: contract.name === 'check_ud_environment', idempotentHint: true, destructiveHint: false, openWorldHint: contract.name === 'setup_ud_environment' }
        : { readOnlyHint: !contract.access?.writes_workspace && !contract.access?.writes_outputs, idempotentHint: !contract.access?.writes_workspace, destructiveHint: contract.access?.writes_workspace === true, openWorldHint: false },
      `${contract.name}: access annotations`);
    }
    const catalog = await client.readResource({ uri: 'ud://catalog/v1' });
    const content = catalog.contents.find(item => 'text' in item && item.mimeType === 'application/json');
    assert.ok(content && 'text' in content, 'authoritative contract catalog remains available');
    assert.deepEqual(JSON.parse(content.text), contracts, 'operation IDs, signatures and runtime bindings remain authoritative');
  } finally { await client.close(); await rm(profile, { recursive: true, force: true }); }
}, 30_000);

test('canonical skill discovery identifies readable guidance and an actual installed CLI', async () => {
  const packageMetadata = await json('packages/npm-distribution/package.json.in');
  const executables = new Set(Object.keys(packageMetadata.bin));
  const canonical = canonicalSkillFiles(root);
  const connected = connectedSkillFiles(root, loadDistributionIdentity(root));
  for (const { name } of skillInventory(root)) {
    assert.ok(!executables.has(name), `${name} is a workflow label, not an exported binary`);
    const source = canonical.get(`${name}/SKILL.md`)!;
    const published = connected.get(`${name}/SKILL.md`)!;
    assert.deepEqual(published, source, `${name}: canonical and distributed discovery metadata agree`);
    const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(published.toString('utf8'));
    assert.ok(match, name);
    const metadata = parse(match[1]);
    assert.equal(metadata.name, name);
    assert.match(metadata.description, /\b(?:workflow|instructions?)\b/i, `${name}: label guidance as guidance`);
    assert.match(metadata.description, /\b(?:read|load|activate)\b/i, `${name}: expose how guidance is used`);
    assert.ok([...executables].some(command => metadata.description.includes(command)), `${name}: identify a real package executable`);
    assert.match(metadata.description, /\bPATH\b/, `${name}: resolve the installed executable rather than guess its location`);
    assert.match(metadata.description, /\b(?:registered|connected)\b.*\b(?:tools|MCP)\b/i,
      `${name}: preserve the existing native tool route`);
  }
});
