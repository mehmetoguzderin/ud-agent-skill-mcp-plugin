import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, realpathSync, rmSync } from 'node:fs';
import { spawnSync, spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { recoverStorage } from '../../scripts/quality/storage-lifecycle.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';

const runner = path.resolve('scripts/quality/installed-operation-matrix.mjs');
function fixture(mode) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-installed-storage-test-')));
  const installation = path.join(root, 'installation'), scratch = path.join(root, 'scratch'), report = path.join(root, 'evidence/report.json'), ready = path.join(root, 'ready');
  mkdirSync(scratch); mkdirSync(path.join(installation, 'runtime'), { recursive: true }); mkdirSync(path.join(installation, 'contracts/schema/operations'), { recursive: true }); mkdirSync(path.join(installation, 'contracts/schema/results'), { recursive: true });
  for (const name of ['runtime.lock.json', 'userspace.lock.json']) writeFileSync(path.join(installation, 'runtime', name), '{}');
  // This fixture exercises storage lifecycle through an inert coordinator,
  // never domain correctness. Preserve its minimal schemas, while supplying
  // the complete authoritative catalogs now bound by the 104-operation runner.
  const catalogs = Object.fromEntries(['ud-interfaces.json', 'environment.json'].map(name => {
    const bytes = readFileSync(path.resolve('contracts', name));
    writeFileSync(path.join(installation, 'contracts', name), bytes);
    return [name, JSON.parse(bytes)];
  }));
  const domain = catalogs['ud-interfaces.json'], environment = catalogs['environment.json'];
  assert.equal(domain.length, 102); assert.equal(environment.length, 2);
  const registry = [...domain, ...environment], names = domain.map(contract => contract.name);
  assert.equal(new Set(registry.map(contract => contract.name)).size, 104);
  for (const { name } of registry) for (const schema of [`operations/${name}.input.schema.json`, `results/${name}.schema.json`]) {
    writeFileSync(path.join(installation, 'contracts/schema', schema), JSON.stringify({ type: 'object' }));
  }
  writeFileSync(path.join(installation, 'coordinator.mjs'), mode === 'wait' ? `import{writeFileSync}from'node:fs';export async function executeOperation(){writeFileSync(${JSON.stringify(ready)},'ready');await new Promise(resolve=>setInterval(resolve,100000));}` : `export async function executeOperation(){${mode === 'fail' ? "throw Error('demonstrated fixture failure');" : "return {structuredContent:{result:{passed:true},execution:{status:'completed'},provenance:{fixture:true}}};"}}`);
  const inventory = path.join(root, 'fixtures.json');
  writeFileSync(inventory, JSON.stringify({ schema_version: 1, scheduled_operations: 102, cases: names.map(operation => ({ operation, files: [], prerequisites: [], arguments: {}, expected_fields: { passed: true } })) }));
  return { root, scratch, report, ready, args: [runner, '--installation', installation, '--fixtures', inventory, '--state-root', path.join(root, 'state'), '--operations', 'validation_report', '--report', report], env: { ...process.env, TMPDIR: scratch, UD_AGENT_STORAGE_ROOT: root, UD_STORAGE_LEASE: '' } };
}
for (const mode of ['pass', 'fail']) test(`installed ${mode} keeps evidence and removes the owned profile`, () => {
  const value = fixture(mode);
  try {
    const result = spawnSync(process.execPath, value.args, { env: value.env, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, mode === 'pass' ? 0 : 1, result.stderr);
    const report = JSON.parse(readFileSync(value.report));
    assert.equal(report.rows[0].status, mode === 'pass' ? 'passed' : 'failed');
    assert.equal(existsSync(report.profile), false);
    assert.equal(existsSync(path.join(value.root, '.artifacts/.storage-reservation')), false);
    assert.deepEqual(readdirSync(value.scratch), []);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

posixTest('installed cancellation preserves its incomplete report and cleans owned scratch', async () => {
  const value = fixture('wait'); let child;
  try {
    child = spawn(process.execPath, value.args, { env: value.env, stdio: 'ignore' });
    const exited = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
    for (let attempt = 0; attempt < 100 && !existsSync(value.ready); attempt++) await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(existsSync(value.ready), 'coordinator entered its operation after saving the report');
    assert.ok(existsSync(value.report), 'coordinator entered the installed workflow');
    child.kill('SIGTERM');
    assert.deepEqual(await exited, { code: 143, signal: null });
    const report = JSON.parse(readFileSync(value.report));
    assert.equal(report.status, 'failed-or-incomplete');
    assert.equal(existsSync(report.profile), false);
    assert.deepEqual(readdirSync(value.scratch), []);
  } finally { child?.kill('SIGKILL'); rmSync(value.root, { recursive: true, force: true }); }
});

test('forced installed termination preserves incomplete evidence and recovers only stopped owned scratch', async () => {
  const value = fixture('wait'); let child, exited;
  try {
    child = spawn(process.execPath, value.args, { env: value.env, stdio: 'ignore' });
    exited = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
    for (let attempt = 0; attempt < 200 && !existsSync(value.ready); attempt++) await new Promise(resolve => setTimeout(resolve, 20));
    assert.ok(existsSync(value.ready), 'coordinator entered its operation after saving the report');
    assert.ok(existsSync(value.report), 'coordinator entered the installed workflow');
    const original = readFileSync(value.report), report = JSON.parse(original);
    assert.equal(report.status, 'failed-or-incomplete'); assert.equal(existsSync(report.profile), true);
    assert.throws(() => recoverStorage(value.root), /active or ambiguous/);
    const signal = process.platform === 'win32' ? 'SIGTERM' : 'SIGKILL';
    assert.equal(child.kill(signal), true); assert.deepEqual(await exited, { code: null, signal });
    assert.deepEqual(readFileSync(value.report), original); assert.equal(existsSync(report.profile), true);
    assert.equal(recoverStorage(value.root), true); assert.equal(existsSync(report.profile), false);
    assert.deepEqual(readFileSync(value.report), original);
    assert.equal(existsSync(path.join(value.root, '.artifacts/.storage-reservation')), false); assert.deepEqual(readdirSync(value.scratch), []);
  } finally {
    child?.kill('SIGKILL'); if (exited) await exited;
    if (existsSync(path.join(value.root, '.artifacts/.storage-reservation'))) recoverStorage(value.root);
    rmSync(value.root, { recursive: true, force: true });
  }
}, 15_000);
