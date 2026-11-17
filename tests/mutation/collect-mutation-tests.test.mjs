import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { collectMutationTests } from '../../scripts/quality/collect-mutation-tests.mjs';
import { compileAcceptanceInventory } from '../../scripts/release/discover-acceptance.mjs';
import { sourceReceipt } from '../../scripts/release/candidate.mjs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

const repository = path.resolve(import.meta.dirname, '../..');
function executable(name) { for (const directory of (process.env.PATH ?? '').split(path.delimiter)) { const file = path.join(directory, name); if (path.isAbsolute(file) && existsSync(file)) return file; } throw Error('Original compiler prerequisite is missing'); }
const python = process.env.UD_AGENT_PYTHON ?? process.env.UD_RELEASE_PYTHON ?? path.join(repository, '.venv/bin/python'), cargo = executable(process.platform === 'win32' ? 'cargo.exe' : 'cargo');
function readonly(directory, writable) {
  for (const name of readdirSync(directory)) { const file = path.join(directory, name), info = lstatSync(file); if (info.isSymbolicLink()) continue; if (info.isDirectory()) { if (writable) chmodSync(file, 0o700); readonly(file, writable); if (!writable) chmodSync(file, 0o500); } else chmodSync(file, writable ? 0o600 : 0o400); }
  chmodSync(directory, writable ? 0o700 : 0o500);
}
function fixture() {
  const parent = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-original-catalog-'))), root = path.join(parent, 'tree'), cache = path.join(parent, 'cache'), vendor = path.join(parent, 'vendor'); mkdirSync(root); mkdirSync(cache, { mode: 0o700 }); mkdirSync(vendor);
  const put = (name, body) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, body); };
  writableFixtureCopy(path.join(repository, 'scripts/release'), path.join(root, 'scripts/release'), parent);
  // The copied release discovery modules import these quality helpers.
  for (const name of ['docker-owned-storage', 'fault-assess', 'mutation-scope', 'native-test-scopes', 'node-dependencies', 'original-storage', 'storage-lifecycle', 'windows-storage']) put(`scripts/quality/${name}.mjs`, readFileSync(path.join(repository, `scripts/quality/${name}.mjs`)));
  put('scripts/quality/windows-storage-acl.py', readFileSync(path.join(repository, 'scripts/quality/windows-storage-acl.py')));
  put('packages/workspace/src/portable-path.ts', readFileSync(path.join(repository, 'packages/workspace/src/portable-path.ts')));
  put('workers/ud/src/ud_agent/unicode_casefold.json', readFileSync(path.join(repository, 'workers/ud/src/ud_agent/unicode_casefold.json')));
  put('Cargo.toml', '[workspace]\nmembers=["packages/launcher"]\nresolver="2"\n'); put('Cargo.lock', 'version=4\n\n[[package]]\nname="ud-agent-launcher"\nversion="0.1.0-beta.1"\n');
  put('packages/launcher/Cargo.toml', '[package]\nname="ud-agent-launcher"\nversion="0.1.0-beta.1"\nedition="2021"\n[[bin]]\nname="ud-agent"\npath="src/main.rs"\n[[bin]]\nname="ud-agent-guard"\npath="src/fs_guard.rs"\n');
  put('packages/launcher/src/main.rs', 'fn main(){}\n');
  put('packages/launcher/src/fs_guard.rs', 'fn main(){println!("original compiled fixture guard");}\n#[cfg(test)]mod tests{#[test]fn original_case(){panic!("test body must never execute during collection");}#[cfg(target_os="linux")]#[test]fn native_linux_case(){panic!("native Linux body must never execute");}}\n');
  put('vitest.config.mjs', 'export default {test:{include:["tests/*.test.mjs"],pool:"forks",fileParallelism:false}};\n');
  put('tests/tiny.test.mjs', 'import {test}from"vitest";import fs from"node:fs";import assert from"node:assert/strict";import {spawnSync}from"node:child_process";import path from"node:path";const exe=path.resolve("target/debug/ud-agent-guard");const run=spawnSync(exe,[],{encoding:"utf8"});assert.equal(run.status,0,run.stderr);assert.equal(run.stdout.trim(),"original compiled fixture guard");assert.equal(process.env.UD_AGENT_PYTHON,' + JSON.stringify(python) + ');assert.equal(process.env.UD_RELEASE_PYTHON,' + JSON.stringify(python) + ');test("original JS body is not run",()=>{fs.writeFileSync(' + JSON.stringify(path.join(cache, 'js-body-ran')) + ',"bad");throw Error("must not run");});\n');
  put('tests/test_tiny.py', 'import pathlib,unittest\nclass Tiny(unittest.TestCase):\n def test_original_python_body_is_not_run(self):\n  pathlib.Path(' + JSON.stringify(path.join(cache, 'python-body-ran')) + ').write_text("bad")\n  raise RuntimeError("must not run")\n');
  symlinkSync(path.join(repository, 'node_modules'), path.join(root, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
  return { parent, root, cache, vendor };
}

test('complete original catalog executes all three real collection families against read-only source without running test bodies', async () => {
  const { parent, root, cache, vendor } = fixture();
  try {
    if (process.platform === 'win32') { await assert.rejects(collectMutationTests(root, { python, cargo, cache, vendor }), /POSIX mutation job/); return; }
    const originalCargoHome = process.env.CARGO_HOME;
    readonly(root, false); const before = sourceReceipt(root), catalog = await collectMutationTests(root, { python, cargo, cache, vendor });
    assert.equal(catalog.qualification, 'inventory-only-no-outcomes'); assert.equal(sourceReceipt(root).sha256, before.sha256);
    assert.deepEqual(new Set(catalog.tests.map(row => row.runner)), new Set(['vitest', 'python', 'rust']));
    assert.ok(catalog.tests.some(row => row.name === 'original JS body is not run'));
    assert.ok(catalog.tests.some(row => row.name === 'test_tiny.Tiny.test_original_python_body_is_not_run'));
    assert.ok(catalog.tests.some(row => row.name === 'tests::original_case'));
    assert.equal(catalog.tests.some(row => row.name === 'tests::native_linux_case'), process.platform === 'linux');
    assert.equal(existsSync(path.join(cache, 'js-body-ran')), false); assert.equal(existsSync(path.join(cache, 'python-body-ran')), false); assert.equal(existsSync(path.join(root, 'target')), false);
    assert.equal(catalog.collection_profile.kind, 'protected-private-original-collection');
    assert.equal(catalog.collection_profile.original_source.input_sha256, catalog.input_sha256);
    assert.equal(catalog.collection_python.path, python);
    assert.deepEqual(catalog.prerequisite_build_transcripts[0].args, ['build','--locked','--bins','-p','ud-agent-launcher','--message-format=json']);
    assert.equal(existsSync(path.join(catalog.collection_root, 'target/debug/ud-agent-guard')), true);
    assert.ok(catalog.transcripts.find(row => row.runner === 'vitest').args.includes('--configLoader=runner'));
    const inventory = compileAcceptanceInventory(root, catalog, { schema_version: 1, required_suites: ['unit'] }); assert.equal(inventory.suites[0].tests.length, catalog.tests.length);
    for (const change of [
      copy => { copy.collection_profile.wrapper.source += '\n// changed recipe\n'; },
      copy => { copy.collection_profile.original_config.sha256 = 'f'.repeat(64); },
      copy => { copy.transcripts.find(row => row.runner === 'vitest').args.push('--testNamePattern=one'); },
      copy => { copy.collection_profile.cache += '/elsewhere'; },
      copy => { copy.collection_python.sha256 = 'f'.repeat(64); },
      copy => { copy.prerequisite_build_transcripts = []; },
      copy => { copy.collection_profile.original_source.input_sha256 = 'e'.repeat(64); },
    ]) { const changed = structuredClone(catalog); change(changed); assert.throws(() => compileAcceptanceInventory(root, changed, { schema_version: 1, required_suites: ['unit'] }), /collection|configuration|wrapper|preparation|source copy binding/); }
    chmodSync(root, 0o700); mkdirSync(path.join(root, 'quality')); writeFileSync(path.join(root, 'quality/acceptance-inventory.json'), '{"state":"frozen"}\n'); chmodSync(root, 0o500);
    assert.equal(compileAcceptanceInventory(root, catalog, { schema_version: 1, required_suites: ['unit'] }).suites[0].tests.length, catalog.tests.length);
    assert.equal(process.env.CARGO_HOME, originalCargoHome);
  } finally { readonly(root, true); rmSync(parent, { recursive: true, force: true }); }
}, 90000);

test('catalog collection rejects a cache outside the exact private job without changing source', async () => {
  const { parent, root, cache, vendor } = fixture();
  try { const before = sourceReceipt(root); await assert.rejects(collectMutationTests(root, { python, cargo, cache: vendor, vendor }), /exact sibling private job cache|POSIX mutation job/); assert.equal(sourceReceipt(root).sha256, before.sha256); assert.deepEqual(readdirSync(cache), []); }
  finally { rmSync(parent, { recursive: true, force: true }); }
});
