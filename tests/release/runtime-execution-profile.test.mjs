import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { sourceReceipt } from '../../scripts/release/candidate.mjs';
import { prepareRuntimeExecutionProfile, verifyRuntimeExecutionProfile } from '../../scripts/quality/runtime-execution-profile.mjs';
import { providerQaExecution } from '../../scripts/quality/native-provider-acceptance.mjs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

const repository = path.resolve(import.meta.dirname, '../..');
function writable(directory) {
  chmodSync(directory, 0o700);
  for (const name of readdirSync(directory)) { const file = path.join(directory, name), info = lstatSync(file); if (info.isSymbolicLink()) continue; if (info.isDirectory()) writable(file); else chmodSync(file, 0o600); }
}
test('detached real provider driver imports only its explicit frozen QA installation and rejects source or dependency substitution', () => {
  const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-detached-QA-'))), source = path.join(base, 'original-source'), profile = path.join(base, 'execution'); mkdirSync(source);
  try {
    writableFixtureCopy(path.join(repository, 'scripts'), path.join(source, 'scripts'), base);
    for (const name of ['package.json', 'package-lock.json', 'packages/workspace/src/portable-path.ts', 'workers/ud/src/ud_agent/unicode_casefold.json']) { const target = path.join(source, name); mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(path.join(repository, name), target); }
    assert.equal(existsSync(path.join(source, 'node_modules')), false);
    const before = sourceReceipt(source), prepared = prepareRuntimeExecutionProfile(source, repository, profile);
    assert.equal(prepared.source_sha256, before.sha256); assert.equal(prepared.qualification, 'actual-selected-QA-installation'); assert.equal(prepared.original_vendor_byte_or_reproduced_build_claim, false);
    assert.equal(realpathSync(path.join(prepared.source_root, 'node_modules')), path.join(profile, 'qa/node_modules'));
    const detached = path.join(base, 'empty-working-directory'); mkdirSync(detached);
    const result = spawnSync(process.execPath, [path.join(prepared.source_root, 'scripts/quality/native-provider-acceptance.mjs'), '--qa-preflight', profile], { cwd: detached, env: { PATH: path.dirname(process.execPath), HOME: detached, USERPROFILE: detached, TMPDIR: detached, TMP: detached, TEMP: detached, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) }, encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 ** 2 });
    assert.equal(result.error, undefined); assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout); assert.equal(report.qualification, 'detached-QA-driver-import-preflight-not-installed-execution');
    assert.deepEqual(report.qa_execution.module_resolution.map(row => row.specifier), ['@modelcontextprotocol/client', '@modelcontextprotocol/client/stdio', 'ajv/dist/2020.js']);
    assert.deepEqual(report.qa_execution.module_resolution.map(row => row.path), ['@modelcontextprotocol/client/dist/index.mjs', '@modelcontextprotocol/client/dist/stdio.mjs', 'ajv/dist/2020.js']);
    assert.equal(report.qa_execution.profile_root, profile); assert.equal(report.qa_execution.source_root, prepared.source_root);
    assert.throws(() => providerQaExecution(profile), /actual executing source copy/);
    assert.deepEqual(verifyRuntimeExecutionProfile(profile, { sourceRoot: prepared.source_root }), prepared);
    const driver = path.join(prepared.source_root, 'scripts/quality/native-provider-acceptance.mjs'), original = readFileSync(driver); chmodSync(driver, 0o600); writeFileSync(driver, Buffer.concat([original, Buffer.from('\n// changed private execution source\n')]));
    assert.throws(() => verifyRuntimeExecutionProfile(profile), /QA execution source copy changed/); writeFileSync(driver, original); chmodSync(driver, 0o444);
    const dependency = report.qa_execution.module_resolution[0].path, privateDependency = path.join(prepared.qa_node_modules, dependency), originalDependency = readFileSync(path.join(repository, 'node_modules', dependency));
    chmodSync(privateDependency, 0o600); writeFileSync(privateDependency, 'changed private dependency');
    assert.throws(() => verifyRuntimeExecutionProfile(profile), /Closed QA dependency bytes changed/);
    assert.deepEqual(readFileSync(path.join(repository, 'node_modules', dependency)), originalDependency); assert.deepEqual(sourceReceipt(source), before);
    assert.throws(() => prepareRuntimeExecutionProfile(source, repository, profile), /new detached profile/);
  } finally { writable(base); rmSync(base, { recursive: true, force: true }); }
}, process.platform === 'win32' ? 0 : 90000);

test('QA execution rejects a mismatched package lock before adopting dependencies or creating output', () => {
  const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-QA-lock-'))), source = path.join(base, 'source'), output = path.join(base, 'output'); mkdirSync(source);
  try { writeFileSync(path.join(source, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}'); assert.throws(() => prepareRuntimeExecutionProfile(source, repository, output), /package lock differs/); assert.equal(existsSync(output), false); }
  finally { rmSync(base, { recursive: true, force: true }); }
});
