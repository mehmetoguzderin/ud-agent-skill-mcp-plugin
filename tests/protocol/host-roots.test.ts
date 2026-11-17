import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { build } from 'esbuild';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

it.each(['modern', 'legacy'] as const)('uses the %s host workspace grant without requiring environment variables', async era => {
  const workspace = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-host-roots-')));
  const client = new Client({ name: 'host-roots-fixture', version: '1' }, { capabilities: { roots: { listChanged: true } }, versionNegotiation: era === 'modern' ? { mode: { pin: '2026-07-28' } } : { mode: 'legacy' } });
  let requested = 0, revoked = false;
  client.setRequestHandler('roots/list', () => { requested++; return { roots: revoked ? [] : [{ uri: pathToFileURL(workspace).href }] }; });
  const installed = path.join(workspace, 'installed'), profile = path.join(workspace, 'profile');
  const env = { ...process.env, UD_AGENT_ALLOWED_ROOTS: '', HOME: profile, USERPROFILE: profile, LOCALAPPDATA: profile, XDG_DATA_HOME: profile } as Record<string, string>;
  try {
    await writeFile(path.join(workspace, 'a.conllu'), '');
    await mkdir(installed);await mkdir(profile);
    writableFixtureCopy(path.resolve('contracts'), path.join(installed, 'contracts'), installed);
    writableFixtureCopy(path.resolve('release'), path.join(installed, 'release'), installed);
    const relativeGuard = `runtime/helpers/guard${process.platform === 'win32' ? '.exe' : ''}`, guard = path.join(installed, relativeGuard);
    await mkdir(path.dirname(guard), { recursive: true });
    await copyFile(path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), guard);await chmod(guard, 0o700);
    const bytes = await readFile(guard);
    await writeFile(path.join(installed, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: {}, native_helpers: { [`${process.platform}/${process.arch}`]: { guard: { path: relativeGuard, sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, size_bytes: bytes.length } } } }));
    const entry = path.join(installed, 'coordinator.mjs');
    await build({ entryPoints: [path.resolve('packages/coordinator/src/entry.ts')], outfile: entry, bundle: true, platform: 'node', format: 'esm', target: 'node24', mainFields: ['module', 'main'], banner: { js: 'import { createRequire as __udCreateRequire } from "node:module";const require=__udCreateRequire(import.meta.url);' } });
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry], stderr: 'pipe', env }));
    const result = await client.callTool({ name: 'check_ud_environment', arguments: { engine: 'userspace', working_tree_path: workspace } });
    expect(result.isError, JSON.stringify(result)).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ operation: 'check_ud_environment', execution: { status: 'completed' }, result: { runtime: { engine: 'userspace' } } });
    expect(requested).toBe(1);
    await client.callTool({ name: 'check_ud_environment', arguments: { engine: 'userspace', working_tree_path: workspace } });
    expect(requested).toBe(era === 'modern' ? 2 : 1);
    revoked = true;
    if (era === 'legacy') await client.notification({ method: 'notifications/roots/list_changed' });
    const rejected = await client.callTool({ name: 'check_ud_environment', arguments: { engine: 'userspace', working_tree_path: workspace } });
    expect(rejected.isError).toBe(true);
    expect(rejected.structuredContent).toMatchObject({ result: { code: 'WORKSPACE_NOT_AUTHORIZED' } });
    expect(requested).toBe(era === 'modern' ? 3 : 2);
  } finally { await client.close(); await rm(workspace, { recursive: true, force: true }); }
}, 30000);
