import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { installedCoordinator } from '../fixtures/installed-coordinator.js';

let entry: string;
let privateProfile: string;
beforeAll(async()=>{privateProfile=await mkdtemp(path.join(os.tmpdir(),'ud-stdio-profile-'));entry=await installedCoordinator(path.join(privateProfile,'installed'));});
afterAll(async()=>{if(privateProfile)await rm(privateProfile,{recursive:true,force:true});});
const transport = () => new StdioClientTransport({ command: process.execPath, args: [entry], stderr: 'pipe', env: {
  PATH:process.env.PATH??'',HOME:privateProfile,USERPROFILE:privateProfile,LOCALAPPDATA:privateProfile,XDG_DATA_HOME:privateProfile,
  TMPDIR:privateProfile,TMP:privateProfile,TEMP:privateProfile,
  ...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{}),...(process.env.UD_AGENT_PYTHON?{UD_AGENT_PYTHON:process.env.UD_AGENT_PYTHON}:{})
} });

describe('MCP stdio protocol', () => {
  it.each(['modern', 'legacy'] as const)('discovers the full catalog through the %s protocol', async era => {
    const client = new Client({ name: 'ud-agent-test', version: '1.0.0' }, {
      versionNegotiation: era === 'modern' ? { mode: { pin: '2026-07-28' } } : { mode: 'legacy' },
    });
    try {
      await client.connect(transport());
      expect(client.getProtocolEra()).toBe(era);
      expect(client.getNegotiatedProtocolVersion()).toBe(era === 'modern' ? '2026-07-28' : '2025-11-25');
      const result = await client.listTools();
      expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThan(4 * 1024 * 1024);
      const names = result.tools.map(tool => tool.name);
      expect(names).toHaveLength(104);
      expect(new Set(names).size).toBe(104);
      expect(names).toContain('check_ud_environment');
      expect(names).toContain('setup_ud_environment');
      expect(names).toContain('trees_merge');
      const check = await client.callTool({ name: 'check_ud_environment', arguments: { engine: 'userspace' } });
      expect(check.isError).not.toBe(true);
      expect(check.structuredContent).toMatchObject({ operation: 'check_ud_environment', operation_id: 'ENV-001', result: { ready: false, runtime: { engine: 'userspace' } } });
    } finally { await client.close(); }
  }, 30_000);
});
