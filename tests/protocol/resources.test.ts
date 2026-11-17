import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it, vi } from 'vitest';
const state = vi.hoisted(() => ({ root: '' }));
vi.mock('../../packages/runtime-manager/src/userspace.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/userspace.js')>(), userspaceStateRoot: () => state.root }));
vi.mock('../../packages/runtime-manager/src/receipt.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/receipt.js')>(), loadNativeGuardReceipt: async () => ({ guard: path.resolve('target/debug/ud-agent-guard.exe') }) }));
import { createServer } from '../../packages/coordinator/src/server.js';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';

it('reads initial and paginated authorized resources through the actual in-memory legacy MCP resource routes', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-protocol-resources-')));
  state.root = path.join(root, 'state');
  const server = createServer(path.resolve('.'), undefined, [root]);
  const client = new Client({ name: 'resource-fixture', version: '1' }, { versionNegotiation: { mode: 'legacy' } });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    const resources = await ResourceStore.open(`${state.root}-resources`, [root], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
    const small = await resources.put('reports', Buffer.from('{"passed":true}'), 'application/json');
    const bytes = Buffer.from('日本語'.repeat(30000)), large = await resources.put('artifacts', bytes, 'text/plain');
    const foreign = await (await ResourceStore.open(`${state.root}-resources`, ['/another-workspace'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined)).put('reports', Buffer.from('{}'), 'application/json');
    await server.connect(serverTransport); await client.connect(clientTransport);
    expect(await client.readResource({ uri: small.uri })).toMatchObject({ contents: [{ text: '{"passed":true}', mimeType: 'application/json' }] });
    const chunks: Buffer[] = []; let uri: string | undefined = large.uri;
    while (uri) {
      const result = await client.readResource({ uri });
      const page = JSON.parse((result.contents[0] as { text: string }).text);
      expect(page.offset).toBe(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
      chunks.push(Buffer.from(page.content_base64, 'base64'));
      uri = page.next_cursor ? `${large.uri}?cursor=${encodeURIComponent(page.next_cursor)}` : undefined;
    }
    expect(Buffer.concat(chunks)).toEqual(bytes);
    await expect(client.readResource({ uri: foreign.uri })).rejects.toThrow('RESOURCE_ACCESS_DENIED');
    await expect(client.readResource({ uri: `${large.uri}?cursor=forged` })).rejects.toThrow('RESOURCE_CURSOR_INVALID');
  } finally { await client.close(); await server.close(); await rm(root, { recursive: true, force: true }); }
}, 30000);
