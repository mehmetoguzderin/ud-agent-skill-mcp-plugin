/** Actual CLI reads of inert resources; no worker, provider or inference. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { buildSync } from 'esbuild';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';
import { userspaceStateRoot } from '../../packages/runtime-manager/src/userspace.js';

test('CLI resource reads preserve bytes, duplicate-equivalent grants, identities and cursor denials', async () => {
  const folder = await realpath(mkdtempSync(path.join(os.tmpdir(), 'ud-resource-cli-'))), source = process.cwd();
  try {
    const profile = path.join(folder, 'profile'), workspace = path.join(folder, 'workspace'), foreign = path.join(folder, 'foreign');
    for (const item of [profile, workspace, foreign]) mkdirSync(item, { mode: 0o700 });
    cpSync(path.join(source, 'contracts'), path.join(folder, 'contracts'), { recursive: true });
    let guard: string | undefined;
    if (process.platform === 'win32') {
      guard = path.join(source, 'target/debug/ud-agent-guard.exe');
      const bytes = readFileSync(guard); mkdirSync(path.join(folder, 'native')); mkdirSync(path.join(folder, 'runtime'));
      cpSync(guard, path.join(folder, 'native/guard.exe'));
      writeFileSync(path.join(folder, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'unbuilt', native_helpers: { [`win32/${process.arch}`]: { guard: { path: 'native/guard.exe', sha256: 'sha256:' + createHash('sha256').update(bytes).digest('hex'), size_bytes: bytes.length } } } }));
    }
    const entry = path.join(folder, 'coordinator.mjs');
    buildSync({ entryPoints: [path.join(source, 'packages/coordinator/src/entry.ts')], outfile: entry, bundle: true, platform: 'node', format: 'esm', target: 'node24', mainFields: ['module', 'main'], banner: { js: 'import { createRequire as __udCreateRequire } from "node:module";const require=__udCreateRequire(import.meta.url);' } });
    const env = { HOME: profile, USERPROFILE: profile, LOCALAPPDATA: profile, XDG_DATA_HOME: profile, PATH: path.join(folder, 'no-executables'), LANG: 'C.UTF-8', ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
    const stateRoot = `${userspaceStateRoot({ platform: process.platform, arch: process.arch }, env)}-resources`;
    const store = await ResourceStore.open(stateRoot, [workspace], guard), duplicated = await ResourceStore.open(stateRoot, [workspace, workspace], guard);
    const data = Buffer.from('{"inert_resource":"exact bytes","count":9}\n');
    const normal = await store.put('reports', data, 'application/json'), oldCli = await duplicated.put('reports', data, 'application/json');
    const context = await store.put('contexts', data, 'application/json');
    const foreignStore = await ResourceStore.open(stateRoot, [foreign], guard), foreignContext = await foreignStore.put('contexts', data, 'application/json');
    assert.notEqual(context.uri, foreignContext.uri, 'Context identities retain their exact grant scope.');
    const run = (uri: string, roots: string[], inherited: string[] = []) => spawnSync(process.execPath, [entry, 'read-resource', uri, '--json', ...roots.flatMap(root => ['--allow-root', root])], { env: { ...env, UD_AGENT_ALLOWED_ROOTS: JSON.stringify(inherited) }, cwd: workspace, encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
    for (const reference of [normal, oldCli, context]) {
      const result = run(reference.uri, [workspace], [workspace]); assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).contents[0].text, data.toString());
    }
    for (const roots of [[], [foreign], [folder], [workspace, foreign]]) {
      const denied = run(normal.uri, roots); assert.equal(denied.status, 1); assert.match(denied.stderr, /RESOURCE_ACCESS_DENIED/);
    }
    const wrongContext = run(foreignContext.uri, [workspace]); assert.equal(wrongContext.status, 1); assert.match(wrongContext.stderr, /RESOURCE_ACCESS_DENIED/);
    const large = Buffer.from('日本語'.repeat(10000)), paged = await store.put('reports', large, 'text/plain');
    const first = run(paged.uri, [workspace], [workspace]); assert.equal(first.status, 0, first.stderr);
    const page = JSON.parse(JSON.parse(first.stdout).contents[0].text); assert.equal(page.offset, 0); assert.ok(page.next_cursor);
    const next = run(`${paged.uri}?cursor=${encodeURIComponent(page.next_cursor)}`, [workspace], [workspace]); assert.equal(next.status, 0, next.stderr);
    const tail = JSON.parse(JSON.parse(next.stdout).contents[0].text);
    assert.deepEqual(Buffer.concat([Buffer.from(page.content_base64, 'base64'), Buffer.from(tail.content_base64, 'base64')]), large);
    const other = await store.put('reports', large, 'text/plain');
    for (const uri of [`${paged.uri}?cursor=forged`, `${other.uri}?cursor=${encodeURIComponent(page.next_cursor)}`]) {
      const denied = run(uri, [workspace], [workspace]); assert.equal(denied.status, 1); assert.match(denied.stderr, /RESOURCE_CURSOR_INVALID/);
    }
    const unsupported = run('file:///not-a-product-resource', [workspace]); assert.equal(unsupported.status, 1); assert.match(unsupported.stderr, /RESOURCE_URI_INVALID/);
    const tamper = await store.put('reports', Buffer.from('original'), 'text/plain');
    writeFileSync(path.join(stateRoot, new URL(tamper.uri).pathname.slice(1), 'data'), 'tampered');
    const invalid = run(tamper.uri, [workspace], [workspace]); assert.equal(invalid.status, 1); assert.match(invalid.stderr, /RESOURCE_INTEGRITY_FAILED/);
  } finally { rmSync(folder, { recursive: true, force: true }); }
}, 60_000);
