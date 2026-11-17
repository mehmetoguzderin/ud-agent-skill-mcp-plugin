import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, constants, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { retainSourceSnapshot } from '../../scripts/release/prepare.mjs';
import { nodeDependencyInventory, validateNodeTargetPackages } from '../../scripts/quality/node-dependencies.mjs';
import { availableOriginalCandidate } from '../fixtures/available-original-candidate.mjs';

const repository = path.resolve(import.meta.dirname, '../..');
function tool(name) {
  const filename = (process.env.PATH ?? '').split(path.delimiter).filter(path.isAbsolute).map(directory => path.join(directory, name)).find(existsSync);
  assert.ok(filename, 'Original test prerequisite is unavailable: ' + name); return filename;
}
const python = process.env.UD_AGENT_PYTHON ?? path.join(repository, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const cargo = tool(process.platform === 'win32' ? 'cargo.exe' : 'cargo');
function modes(directory, writable) {
  chmodSync(directory, writable ? 0o700 : 0o555);
  for (const name of readdirSync(directory)) { const file = path.join(directory, name), info = lstatSync(file); if (info.isSymbolicLink()) continue; if (info.isDirectory()) modes(file, writable); else chmodSync(file, writable ? 0o600 | (info.mode & 0o111) : info.mode & ~0o222); }
}

function fixture(mode, action) {
  const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-original-writable-'))), input = path.join(base, 'immutable-source'), working = path.join(base, 'working'), candidateRoot = path.join(base, 'candidate'), output = path.join(base, 'outcomes');
  const put = (name, value) => { const filename = path.join(input, name); mkdirSync(path.dirname(filename), { recursive: true }); writeFileSync(filename, value); };
  try {
    for (const folder of ['scripts/release', 'scripts/quality']) for (const name of readdirSync(path.join(repository, folder)).filter(name => name.endsWith('.mjs'))) put(folder + '/' + name, readFileSync(path.join(repository, folder, name)));
    for (const name of ['scripts/quality/original-python.py', 'scripts/quality/windows-storage-acl.py', 'scripts/quality/windows-original-token.py', 'scripts/generate/skill-files.mjs', 'packages/workspace/src/portable-path.ts', 'workers/ud/src/ud_agent/unicode_casefold.json', 'package-lock.json', 'rust-toolchain.toml', 'quality/toolchain.lock.json']) put(name, readFileSync(path.join(repository, name)));
    put('package.json', '{"type":"module"}\n');
    put('Cargo.toml', '[workspace]\nmembers=["packages/launcher"]\nresolver="2"\n');
    put('Cargo.lock', 'version = 4\n\n[[package]]\nname = "ud-agent-launcher"\nversion = "0.1.0-beta.1"\n');
    put('packages/launcher/Cargo.toml', '[package]\nname="ud-agent-launcher"\nversion="0.1.0-beta.1"\nedition="2021"\n[[bin]]\nname="ud-agent-guard"\npath="src/guard.rs"\n');
    put('packages/launcher/src/main.rs', 'fn main(){}\n#[cfg(test)]mod tests{#[test]fn original_behavior(){assert_eq!(2+2,4);}}\n');
    put('packages/launcher/src/guard.rs', 'fn main(){}\n#[cfg(test)]mod tests{#[test]fn original_guard_behavior(){assert!(true);}}\n');
    put('vitest.config.mjs', 'export default {test:{include:["tests/*.test.mjs"],pool:"forks",fileParallelism:false}};\n');
    put('tests/tiny.test.mjs', 'import{test,expect}from"vitest";test("real original JS",()=>expect(2+2).toBe(4));\n');
    put('tests/test_tiny.py', 'import unittest\nclass Tiny(unittest.TestCase):\n def test_original_python(self):self.assertEqual(2+2,4)\n');
    put('README.md', 'Immutable genuine original-runner fixture.\n');
    put('scripts/quality/check.mjs', mode === 'tamper-artifact'
      ? 'import fs from"node:fs";fs.writeFileSync(' + JSON.stringify(path.join(candidateRoot, 'artifacts/npm.bin')) + ',"changed after initial binding");\n'
      : 'import assert from"node:assert/strict";assert.equal(2+2,4);\n');
    const { manifest } = availableOriginalCandidate(input, candidateRoot), original = sourceReceipt(input);
    modes(input, false);
    // Reuse the existing ordinary writable source copier, not the installed
    // driver's frozen profile. All caches/targets belong to this private copy.
    retainSourceSnapshot(input, original, working);
    const selectedModules = path.join(repository, 'node_modules'), before = nodeDependencyInventory(selectedModules), lock = JSON.parse(readFileSync(path.join(input, 'package-lock.json')));
    const target = { os: process.platform, cpu: process.arch, libc: process.platform === 'linux' ? process.report.getReport().header.glibcVersionRuntime ? 'glibc' : 'musl' : undefined };
    validateNodeTargetPackages(selectedModules, lock, target);
    cpSync(selectedModules, path.join(working, 'node_modules'), { recursive: true, dereference: false, verbatimSymlinks: true, errorOnExist: true, force: false, mode: constants.COPYFILE_FICLONE });
    function writableDependencies(directory) { chmodSync(directory, lstatSync(directory).mode & 0o777 | 0o700); for (const name of readdirSync(directory)) { const file = path.join(directory, name), info = lstatSync(file); if (info.isSymbolicLink()) continue; if (info.isDirectory()) writableDependencies(file); else chmodSync(file, info.mode & 0o777 | 0o200); } }
    writableDependencies(path.join(working, 'node_modules'));
    assert.deepEqual(nodeDependencyInventory(path.join(working, 'node_modules')), before, 'Private QA snapshot differs before execution');
    assert.deepEqual(sourceReceipt(working), original);
    const result = spawnSync(process.execPath, [path.join(working, 'scripts/quality/original-acceptance.mjs'), '--output', output, '--python', python, '--cargo', cargo, '--candidate', path.join(candidateRoot, 'available-candidate.json'), '--candidate-root', candidateRoot], { cwd: base, encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 ** 2, env: { ...process.env, ...(process.env.UD_SUPERVISOR_STORAGE_LEASE ? { UD_STORAGE_LEASE: process.env.UD_SUPERVISOR_STORAGE_LEASE } : {}), UD_AGENT_PYTHON: python, UD_RELEASE_PYTHON: python } });
    assert.equal(result.error, undefined, result.stderr);
    assert.ok(existsSync(path.join(output, 'report.json')), result.stderr || result.stdout || 'Original acceptance did not retain its report');
    const report = JSON.parse(readFileSync(path.join(output, 'report.json')));
    action({ input, working, candidateRoot, manifest, output, report, result, original });
    assert.deepEqual(sourceReceipt(input), original); assert.deepEqual(sourceReceipt(working), original);
    assert.deepEqual(nodeDependencyInventory(selectedModules), before, 'Selected shared QA dependencies changed');
    assert.equal(existsSync(path.join(input, 'target')), false); assert.equal(existsSync(path.join(input, '.artifacts')), false);
  } finally { modes(base, true); rmSync(base, { recursive: true, force: true }); }
}

test('detached writable original CLI runs all runner families and binds the exact external available candidate', () => fixture('pass', ({ input, working, manifest, output, report, result }) => {
  assert.equal(result.status, 0, report.reason ?? result.stderr); assert.equal(report.status, 'passed-locally');
  assert.equal(report.scheduled, 4); assert.equal(report.executed, 4); assert.equal(report.skipped, 0); assert.equal(report.source_unchanged, true);
  assert.deepEqual(report.tests.map(row => row.runner).sort(), ['python', 'rust', 'rust', 'vitest']);
  assert.equal(existsSync(path.join(working, 'target/debug', process.platform === 'win32' ? 'ud-agent-guard.exe' : 'ud-agent-guard')), true);
  assert.notEqual(lstatSync(path.join(input, 'README.md')).ino, lstatSync(path.join(working, 'README.md')).ino);
  assert.equal(lstatSync(path.join(input, 'README.md')).mode & 0o222, 0); assert.notEqual(lstatSync(path.join(working, 'README.md')).mode & 0o200, 0);
  const evidence = JSON.parse(readFileSync(path.join(output, report.unsigned_evidence.path)));
  assert.equal(evidence.source_tree_sha256, manifest.source_tree_sha256); assert.equal(evidence.runtime_lock_sha256, manifest.runtime_lock_sha256);
  assert.equal(evidence.candidate_binding.acceptance_eligible, false); assert.equal(evidence.candidate_binding.production_ready, false);
  assert.equal(evidence.candidate_binding.candidate_bindings.source_replay_performed, false); assert.equal(evidence.candidate_binding.candidate_bindings.source_replay_required, true);
  assert.equal(evidence.tests.every(row => row.status === 'passed'), true); assert.deepEqual(evidence.tests, report.tests);
  assert.equal(report.commands.some(row => row.args.includes('--reporter=json')), true);
}), process.platform === 'win32' ? 0 : 180000);

test('candidate bytes changed after original binding prevent unsigned evidence despite passing genuine test cases', () => fixture('tamper-artifact', ({ output, report, result }) => {
  assert.equal(result.status, 1); assert.equal(report.status, 'failed-or-incomplete'); assert.match(report.reason, /receipt mismatch/);
  assert.equal(report.executed, 4); assert.equal(report.source_unchanged, true); assert.equal(report.unsigned_evidence, undefined); assert.equal(existsSync(path.join(output, 'unit-evidence.unsigned.json')), false);
}), process.platform === 'win32' ? 0 : 180000);
