import { readFileSync } from 'node:fs';
import { cp, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { expect, it } from 'vitest';
import { loadContracts } from '../../packages/coordinator/src/catalog.js';
import { domainMetadata } from '../../packages/coordinator/src/generated-contracts.js';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

const fixture = JSON.parse(readFileSync(new URL('../fixtures/compatibility/104-tools-v1.json', import.meta.url), 'utf8'));
it('retains all 104 frozen identities, signatures, provenance and generated dispatch bindings', () => {
  let current: ReturnType<typeof loadContracts> | undefined;
  expect(() => { current = loadContracts(path.resolve('.')); }).not.toThrow();
  expect([...(current?.domain ?? []), ...(current?.environment ?? [])]).toEqual(fixture.tools);
  expect(domainMetadata).toEqual(fixture.tools.slice(0, 102).map((tool: Record<string, unknown>) => Object.fromEntries(['id', 'name', 'runtime_pack', 'handler', 'output_schema', 'access'].map(key => [key, tool[key]]))));
});

it('rejects an installed catalog whose handler, runtime, access or result contract differs from its generated binding', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-catalog-binding-')));
  try {
    writableFixtureCopy('contracts', path.join(root, 'contracts'), root);
    const file = path.join(root, 'contracts/ud-interfaces.json'), original = JSON.parse(await readFile(file, 'utf8'));
    for (const patch of [{ handler: 'ud_agent.domain.workspace:unrelated' }, { runtime_pack: 'render' }, { access: { writes_workspace: false, writes_outputs: false, executes_project_code: false } }, { output_schema: 'contracts/schema/results/unrelated.schema.json' }]) {
      await writeFile(file, JSON.stringify([{ ...original[0], ...patch }, ...original.slice(1)]));
      expect(() => loadContracts(root)).toThrow('differs from its generated dispatch binding');
    }
    await writeFile(file, JSON.stringify(original)); expect(() => loadContracts(root)).not.toThrow();
  } finally { await rm(root, { recursive: true, force: true }); }
});
