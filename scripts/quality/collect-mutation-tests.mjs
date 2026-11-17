#!/usr/bin/env node
/** Complete original test discovery inside a fresh read-only source job. */
import assert from 'node:assert/strict';
import { lstatSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

/** The fixed CLI supplies SDK paths; original unit fixtures may supply their own tools. */
/** @param {string} root @param {{python?: string, cache?: string, cargo?: string, vendor?: string}} [options] */
export async function collectMutationTests(root, { python, cache, cargo = '/opt/mutation/rust/bin/cargo', vendor = '/opt/mutation/rust/vendor' } = {}) {
  assert.notEqual(process.platform, 'win32', 'This fixed protected collector requires the POSIX mutation job');
  root = realpathSync(root); cache = realpathSync(cache);
  assert.ok(path.isAbsolute(python) && path.isAbsolute(cargo) && path.isAbsolute(vendor), 'Original collection requires absolute interpreter/compiler/vendor paths');
  assert.equal(cache, path.join(path.dirname(root), 'cache'), 'Collection cache must be the exact sibling private job cache');
  const info = lstatSync(cache); assert.ok(info.isDirectory() && !info.isSymbolicLink() && (info.mode & 0o777) === 0o700 && info.uid === process.getuid(), 'Collection cache must be private and owned');
  const { sourceReceipt, readRecordedBytes } = await import(pathToFileURL(path.join(root, 'scripts/release/candidate.mjs')).href);
  const before = sourceReceipt(root), privateRoot = path.join(cache, 'acceptance'), tree = path.join(privateRoot, 'tree'), privateCache = path.join(privateRoot, 'cache'), home = path.join(cache, 'cargo-home'), target = path.join(tree, 'target');
  mkdirSync(privateRoot, { mode: 0o700 }); mkdirSync(tree, { mode: 0o700 }); mkdirSync(privateCache, { mode: 0o700 });
  for (const row of before.files) { const file = path.join(tree, row.path); mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 }); writeFileSync(file, readRecordedBytes(root, row, 512 * 1024 ** 2), { flag: 'wx', mode: row.executable ? 0o700 : 0o600 }); }
  symlinkSync(realpathSync(path.join(root, 'node_modules')), path.join(tree, 'node_modules'), 'dir');
  assert.equal(sourceReceipt(tree).sha256, before.sha256, 'Private collection copy differs from original source');
  mkdirSync(home, { mode: 0o700 }); mkdirSync(target, { mode: 0o700 });
  writeFileSync(path.join(home, 'config.toml'), '[net]\noffline = true\n[source.crates-io]\nreplace-with = "verified-vendor"\n[source.verified-vendor]\ndirectory = ' + JSON.stringify(vendor) + '\n[build]\njobs = 2\nincremental = false\ntarget-dir = ' + JSON.stringify(target) + '\nrustc = ' + JSON.stringify(path.join(path.dirname(cargo), process.platform === 'win32' ? 'rustc.exe' : 'rustc')) + '\n', { flag: 'wx', mode: 0o600 });
  const updates = { CARGO_HOME: home, CARGO_TARGET_DIR: target, CARGO_NET_OFFLINE: 'true', UD_AGENT_PYTHON: python, UD_RELEASE_PYTHON: python, PYTHONDONTWRITEBYTECODE: '1' }, previous = new Map([...Object.keys(updates), 'RUSTUP_TOOLCHAIN'].map(key => [key, process.env[key]]));
  try {
    Object.assign(process.env, updates); delete process.env.RUSTUP_TOOLCHAIN;
    const { discoverAcceptance } = await import(pathToFileURL(path.join(root, 'scripts/release/discover-acceptance.mjs')).href);
    const catalog = discoverAcceptance(tree, { python, cargo, protectedCache: privateCache, protectedSource: { root, sha256: before.sha256 } });
    assert.equal(sourceReceipt(root).sha256, before.sha256, 'Original source changed during protected catalog collection');
    assert.equal(sourceReceipt(tree).sha256, before.sha256, 'Private source changed during protected catalog collection');
    assert.equal(catalog.qualification, 'inventory-only-no-outcomes');
    assert.ok(['vitest', 'python', 'rust'].every(runner => catalog.tests.some(test => test.runner === runner)), 'All three original runner families are required');
    assert.ok(Buffer.byteLength(JSON.stringify(catalog)) <= 32 * 1024 ** 2, 'Complete catalog exceeds the bounded result contract');
    return catalog;
  } finally {
    for (const [key, value] of previous) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
}

/** Preserve the existing secondary Vitest inventory identity, from full collection. */
export function secondaryVitestTests(catalog) {
  assert.equal(catalog.qualification, 'inventory-only-no-outcomes');
  const rows = catalog.tests.filter(row => row.runner === 'vitest');
  assert.ok(rows.length > 0, 'Complete collection returned no Vitest cases');
  return rows.map(row => {
    assert.ok(row.id.startsWith('vitest:' + row.source + '#'), 'Vitest inventory identity differs');
    return { id: row.id.slice('vitest:'.length), source: row.source, source_sha256: row.source_sha256, name: row.name, occurrence: row.occurrence, runner: row.runner };
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    assert.equal(process.platform, 'linux'); assert.ok(process.getuid() >= 100001 && process.getuid() === process.geteuid());
    const args = process.argv.slice(2); assert.ok(args.length === 4 || args.length === 6); assert.equal(args[0], '--python'); assert.equal(args[2], '--result');
    if (args.length === 6) { assert.equal(args[4], '--result-format'); assert.equal(args[5], 'vitest-tests'); }
    const catalog = await collectMutationTests(process.cwd(), { python: args[1], cache: process.env.TMPDIR });
    const { writeChildResult } = await import(new URL('./stryker-child.mjs', import.meta.url).href); writeChildResult(args[3], args.length === 6 ? secondaryVitestTests(catalog) : catalog);
  } catch (error) { console.error('Protected original catalog collection failed: ' + (error.stack ?? error.message)); process.exitCode = 1; }
}
