/** Actual bundled stdio processes; private profiles and an empty executable PATH. */
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { buildSync } from 'esbuild';
import { afterAll, beforeAll, expect, test } from 'vitest';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

let root: string, entry: string;
beforeAll(() => {
  root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-progress-stdio-')));
  writableFixtureCopy(path.resolve('contracts'), path.join(root, 'contracts'), root);
  const relative = 'runtime/helpers/guard' + (process.platform === 'win32' ? '.exe' : ''), helper = path.join(root, relative);
  mkdirSync(path.dirname(helper), { recursive: true }); copyFileSync(path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), helper); chmodSync(helper, 0o700);
  const bytes = readFileSync(helper);
  writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: {}, native_helpers: { [`${process.platform}/${process.arch}`]: { guard: { path: relative, sha256: 'sha256:' + createHash('sha256').update(bytes).digest('hex'), size_bytes: bytes.length } } } }));
  entry = path.join(root, 'coordinator.mjs');
  buildSync({ entryPoints: [path.resolve('packages/coordinator/src/entry.ts')], outfile: entry, bundle: true, platform: 'node', format: 'esm', target: 'node24', mainFields: ['module', 'main'], banner: { js: 'import { createRequire as __udCreateRequire } from "node:module";const require=__udCreateRequire(import.meta.url);' } });
});
afterAll(() => { if (root) rmSync(root, { recursive: true, force: true }); });

test.each(['modern', 'legacy'] as const)('actual %s stdio readiness progress returns a complete unready inquiry and leaves its profile untouched', async era => {
  const profile = path.join(root, 'profile-' + era); mkdirSync(profile, { mode: 0o700 });
  const env = { PATH: '', HOME: profile, USERPROFILE: profile, LOCALAPPDATA: profile, XDG_DATA_HOME: profile, TMPDIR: profile, TMP: profile, TEMP: profile, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
  const client = new Client({ name: 'actual-progress-' + era, version: '1' }, { versionNegotiation: era === 'modern' ? { mode: { pin: '2026-07-28' } } : { mode: 'legacy' } });
  const progress: { progress: number; total?: number; message?: string }[] = [];
  try {
    const transport = new StdioClientTransport({ command: process.execPath, args: [entry, 'mcp'], env, stderr: 'pipe' });
    await client.connect(transport);
    // The client SDK dispatches notification handlers on a later microtask but
    // settles responses synchronously, so a final notification read in the same
    // chunk as the result can reach onprogress after the handler is removed.
    // Record the server's wire order directly.
    const wire: { progress: number; total?: number; message?: string }[] = [], forward = transport.onmessage!;
    transport.onmessage = (message, ...rest) => { if ('method' in message && message.method === 'notifications/progress') { const { progressToken: _token, ...value } = message.params as { progressToken: unknown; progress: number; total?: number; message?: string }; wire.push(value); } forward(message, ...rest); };
    const result = await client.callTool({ name: 'check_ud_environment', arguments: { offline: true } }, { onprogress: value => progress.push(value) });
    expect(client.getProtocolEra()).toBe(era);
    expect(result).toMatchObject({ structuredContent: { operation: 'check_ud_environment', execution: { status: 'completed' }, result: { ready: false, working_tree_changes: [] } } });
    expect(result.isError).not.toBe(true);
    expect(wire).toEqual([{ progress: 0, total: 4, message: 'Checking local runtime readiness' }, { progress: 4, total: 4, message: 'Readiness inquiry completed' }]);
    expect(wire.slice(0, progress.length)).toEqual(progress);
    expect(await readdir(profile)).toEqual([]);
  } finally { await client.close(); }
}, 30000);
