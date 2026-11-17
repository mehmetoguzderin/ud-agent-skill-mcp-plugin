import { test } from 'vitest';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { runOriginalAcceptance } from '../../scripts/quality/original-acceptance.mjs';
import { runDefaultTests } from '../../scripts/quality/test.mjs';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';

const repository = path.resolve(import.meta.dirname, '../..');
function executable(names) {
  for (const name of names) {
    if (path.isAbsolute(name) && existsSync(name)) return name;
    for (const directory of (process.env.PATH ?? '').split(path.delimiter)) {
      const filename = path.join(directory, name);
      if (directory && existsSync(filename)) return path.resolve(filename);
    }
  }
  throw new Error('The required original-test interpreter/compiler is unavailable.');
}
const python = executable([...(process.env.UD_AGENT_PYTHON ? [process.env.UD_AGENT_PYTHON] : []), path.join(repository, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python'), ...(process.platform === 'win32' ? ['python.exe'] : ['python3'])]);
const cargo = executable([process.platform === 'win32' ? 'cargo.exe' : 'cargo']);
function linkDependency(source, target) {
  // The Windows scanner can briefly hold newly created junction metadata.
  for (let attempt = 0; ; attempt++) {
    try { symlinkSync(source, target, process.platform === 'win32' ? 'junction' : 'dir'); return; }
    catch (error) {
      if (process.platform !== 'win32' || !['EBUSY', 'EPERM', 'EACCES'].includes(error.code) || attempt === 10) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    }
  }
}

function fixture(mode, action) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-original-orchestration-')));
  const put = (name, bytes) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, bytes); };
  try {
    put('Cargo.toml', '[workspace]\nmembers = ["packages/launcher"]\nresolver = "2"\n');
    put('Cargo.lock', 'version = 4\n\n[[package]]\nname = "ud-agent-launcher"\nversion = "0.1.0-beta.1"\n');
    copyFileSync(path.join(repository, 'rust-toolchain.toml'), path.join(root, 'rust-toolchain.toml'));
    put('quality/toolchain.lock.json', readFileSync(path.join(repository, 'quality/toolchain.lock.json')));
    put('packages/launcher/Cargo.toml', '[package]\nname = "ud-agent-launcher"\nversion = "0.1.0-beta.1"\nedition = "2021"\nlicense = "MIT"\n[[bin]]\nname = "ud-agent-guard"\npath = "src/guard.rs"\n');
    put('packages/launcher/src/main.rs', `fn main() {}\n#[cfg(test)] mod tests { #[test] fn main_behavior() { assert_eq!(2 + 2, ${mode === 'rust-failure' ? 5 : 4}); } }\n`);
    put('packages/launcher/src/guard.rs', 'fn main() {}\n#[cfg(test)] mod tests { #[test] fn guard_behavior() { assert!(true); } }\n');
    put('vitest.config.mjs', 'export default {cacheDir:".artifacts/vite-cache",test:{include:["tests/*.test.mjs"],pool:"forks",fileParallelism:false}};\n');
    put('tests/tiny.test.mjs', `import {test,expect} from 'vitest';\n${mode === 'vitest-skip' ? 'test.skip' : 'test'}('original JS behavior',()=>expect(2+2).toBe(${mode === 'vitest-failure' ? 5 : 4}));\n${mode === 'vitest-skip' ? "test('present neighbor cannot hide a skipped required case',()=>expect(1).toBe(1));\n" : ''}`);
    if (mode === 'vitest-unhandled') put('tests/tiny.test.mjs', `import {test,expect,afterAll} from 'vitest';\ntest('original JS behavior',()=>{expect(2+2).toBe(4);Promise.reject(new Error('original runner unhandled fixture'));});\nafterAll(()=>new Promise(resolve=>setTimeout(resolve,25)));\n`);
    if (mode === 'bound-native-scopes') {
      put('tests/fixtures/native-scope.mjs', readFileSync(path.join(repository, 'tests/fixtures/native-scope.mjs')));
      put('quality/native-test-scopes.json', JSON.stringify({ schema_version: 1, scopes: [{ source: 'tests/tiny.test.mjs', supported_os: ['darwin', 'linux'], purpose: 'Original runner fixture retains native declaration obligations independently of local outcomes.' }] }));
      put('tests/tiny.test.mjs', readFileSync(path.join(root, 'tests/tiny.test.mjs'), 'utf8') + `import {posixTest} from './fixtures/native-scope.mjs';\nposixTest('original POSIX native fixture',()=>expect(process.platform === 'darwin' || process.platform === 'linux').toBe(true));\n`);
    }
    put('tests/test_tiny.py', `import os,sys,unittest\nclass Tiny(unittest.TestCase):\n def test_original_python_behavior(self):\n  self.assertEqual(os.environ['UD_AGENT_PYTHON'],${JSON.stringify(python)})\n  self.assertEqual(os.environ['UD_RELEASE_PYTHON'],${JSON.stringify(python)})\n  self.assertEqual(2+2,${mode === 'python-failure' ? 5 : 4})\n${mode === 'omitted-case' ? " if not sys.argv[0].endswith('original-python.py'):\n  def test_discovered_required_case(self): self.assertTrue(True)\n" : ''}`);
    put('README.md', 'Tiny genuine original-runner fixture.\n');
    put('scripts/quality/check.mjs', mode === 'stale-source'
      ? 'import fs from "node:fs";fs.appendFileSync("README.md","changed during execution\\n");\n'
      : mode === 'replaced-test-binary'
        ? 'import fs from "node:fs";import path from "node:path";for(const name of fs.readdirSync("target/debug/deps")){const file=path.join("target/debug/deps",name);if(/^ud_agent_(launcher|guard)-[a-f0-9]+(?:\\.exe)?$/.test(name))fs.appendFileSync(file,"changed binary identity");}\n'
        : `import assert from "node:assert/strict";assert.equal(2+2,4);assert.equal(process.env.UD_AGENT_PYTHON,${JSON.stringify(python)});assert.equal(process.env.UD_RELEASE_PYTHON,${JSON.stringify(python)});\n`);
    copyFileSync(path.join(repository, 'scripts/quality/original-python.py'), path.join(root, 'scripts/quality/original-python.py'));
    // Vite puts its config bundle beside node_modules. Keep that directory
    // private/writable while every actual dependency remains in the sealed SDK.
    const modules=path.join(root,'node_modules');mkdirSync(modules,{mode:0o700});
    for(const name of readdirSync(path.join(repository,'node_modules'))){if(name.startsWith('.'))continue;const source=path.join(repository,'node_modules',name);if(lstatSync(source).isDirectory()||lstatSync(source).isSymbolicLink())linkDependency(source,path.join(modules,name));}
    mkdirSync(path.join(root, '.artifacts'));
    let candidate;
    if (mode.startsWith('bound-')) {
      put('runtime/runtime.lock.json', '{"schema_version":1,"state":"frozen","product_version":"0.1.0-beta.1"}\n');
      put('.artifacts/candidate.bin', 'Actual local candidate bytes, never published.\n');
      candidate={schema_version:1,status:'local_candidate',production_ready:false,source_tree_sha256:sourceReceipt(root).sha256,runtime_lock_sha256:fileReceipt(root,'runtime/runtime.lock.json').sha256,artifacts:[{id:'local-fixture',...fileReceipt(root,'.artifacts/candidate.bin')}]};
      if(mode==='bound-bad-source')candidate.source_tree_sha256='f'.repeat(64);
      if(mode==='bound-bad-runtime')candidate.runtime_lock_sha256='f'.repeat(64);
      if(mode==='bound-bad-artifact')candidate.artifacts[0].sha256='f'.repeat(64);
    }
    const before = sourceReceipt(root), output = path.join(root, '.artifacts/result');
    const report = mode === 'default-entry' ? runDefaultTests(root, { output, python, cargo }).report : runOriginalAcceptance(root, { output, python, cargo, ...(candidate?{candidate}:{}) });
    action({ root, output, report, before, candidate });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test('default npm test entry discovers and executes the root Python case alongside actual Node and Rust cases',()=>fixture('default-entry',({report})=>{
 assert.equal(report.status,'passed-locally',report.reason);
 assert.equal(report.scheduled,4);assert.equal(report.executed,4);assert.equal(report.skipped,0);
 assert.ok(report.tests.some(row=>row.source==='tests/test_tiny.py'&&row.status==='passed'));
 assert.deepEqual(report.tests.map(row=>row.runner).sort(),['python','rust','rust','vitest']);
}),90000);

test('optional unit evidence binds real candidate bytes and runtime lock without signing or claiming installed acceptance',()=>fixture('bound-pass',({root,output,report,before,candidate})=>{
 assert.equal(report.status,'passed-locally',report.reason);
 const evidence=JSON.parse(readFileSync(path.join(output,report.unsigned_evidence.path)));
 const validate=new Ajv2020({strict:true}).compile(JSON.parse(readFileSync(path.join(repository,'release/schema/evidence.schema.json'))));
 assert.equal(validate(evidence),true,JSON.stringify(validate.errors));
 assert.equal(evidence.suite_id,'unit');assert.equal(evidence.verdict,'passed');assert.equal(evidence.executed,4);
 assert.equal(evidence.qualification,'unsigned-local-original-tests-not-installed-or-mutation-certification');
 assert.equal(evidence.source_tree_sha256,before.sha256);assert.equal(evidence.runtime_lock_sha256,fileReceipt(root,'runtime/runtime.lock.json').sha256);
 assert.equal(evidence.artifact_set_sha256,sha256(JSON.stringify(candidate.artifacts.map(({id,sha256,size})=>({id,sha256,size})))));
 const sources=['packages/launcher/src/guard.rs','packages/launcher/src/main.rs','scripts/quality/check.mjs','scripts/quality/original-python.py','tests/test_tiny.py','tests/tiny.test.mjs'];
 assert.equal(evidence.test_inventory_sha256,sha256(JSON.stringify(sources.map(name=>{const{path,sha256,size}=fileReceipt(root,name);return{path,sha256,size};}))));
 assert.deepEqual(evidence.tests,report.tests);assert.deepEqual(evidence.raw_execution.discovery,report.discovery);assert.equal(evidence.raw_execution.commands.length,6);
 assert.equal('signature' in evidence,false);assert.equal('production_ready' in evidence,false);
}),90000);

test('original reports and unsigned evidence preserve native obligations without adding foreign outcomes', () => fixture('bound-native-scopes', ({ root, output, report }) => {
  assert.equal(report.status, 'passed-locally', report.reason);
  const receipt = report.native_applicability, foreign = process.platform === 'win32';
  assert.equal(receipt.environment_os, process.platform);
  assert.deepEqual(receipt.manifest, fileReceipt(root, 'quality/native-test-scopes.json'));
  assert.deepEqual(receipt.declaration_helper, fileReceipt(root, 'tests/fixtures/native-scope.mjs'));
  assert.equal(receipt.scopes[0].status, foreign ? 'pending-native' : 'applicable-native');
  assert.deepEqual(report.pending_native_scopes, foreign ? receipt.scopes : []);
  assert.equal(report.executed, foreign ? 4 : 5); assert.equal(report.scheduled, report.executed); assert.equal(report.skipped, 0);
  assert.equal(report.tests.some(row => row.name === 'original POSIX native fixture'), !foreign);
  assert.equal(report.tests.every(row => row.status === 'passed'), true);
  const evidence = JSON.parse(readFileSync(path.join(output, report.unsigned_evidence.path)));
  assert.deepEqual(evidence.native_applicability, receipt); assert.deepEqual(evidence.pending_native_scopes, report.pending_native_scopes);
  assert.equal(evidence.executed, report.executed); assert.deepEqual(evidence.tests, report.tests);
}), 90000);

for(const mode of['bound-bad-source','bound-bad-runtime','bound-bad-artifact'])test(`unsigned evidence rejects ${mode} without inventing candidate acceptance`,()=>fixture(mode,({output,report})=>{
 assert.equal(report.status,'failed-or-incomplete');assert.equal(report.executed,0);assert.equal(report.unsigned_evidence,undefined);assert.equal(existsSync(path.join(output,'unit-evidence.unsigned.json')),false);
}),90000);

test('original acceptance executes discovery, static checks and all three real runners in a tiny checkout', () => fixture('pass', ({ root, output, report, before }) => {
  assert.equal(report.status, 'passed-locally', report.reason);
  assert.equal(report.qualification, 'actual-local-original-tests-not-installed-or-mutation-certification');
  assert.equal(report.suite_id, 'unit');
  assert.deepEqual(report.environment.python,{path:python,canonical_path:realpathSync(python),sha256:sha256(readFileSync(realpathSync(python)))});
  assert.equal(report.source_tree_sha256, before.sha256); assert.equal(sourceReceipt(root).sha256, before.sha256);
  assert.equal(report.source_unchanged, true); assert.equal(report.scheduled, 4); assert.equal(report.executed, 4); assert.equal(report.skipped, 0);
  assert.deepEqual(report.tests.map(row => row.runner).sort(), ['python', 'rust', 'rust', 'vitest']);
  assert.deepEqual(new Set(report.tests.map(row => row.source)), new Set(['tests/tiny.test.mjs', 'tests/test_tiny.py', 'packages/launcher/src/main.rs', 'packages/launcher/src/guard.rs']));
  for (const row of report.tests) { assert.equal(row.status, 'passed'); assert.equal(row.source_sha256, fileReceipt(root, row.source).sha256); }
  assert.equal(report.commands.length, 6);
  for (const command of report.commands) {
    assert.equal(command.exit_code, 0); assert.equal(command.signal, null); assert.equal(command.error, null);
    for (const stream of ['stdout', 'stderr']) assert.deepEqual(fileReceipt(output, command[stream].path), command[stream]);
  }
  const catalog = JSON.parse(readFileSync(path.join(output, 'discovery.json')));
  assert.equal(catalog.tests.length, report.tests.length);
  assert.deepEqual(report.tests.map(row => row.id), catalog.tests.map(row => row.id).sort((a,b)=>a.localeCompare(b,'en')));
  assert.deepEqual(JSON.parse(readFileSync(path.join(output, 'report.json'))), report);
}), 90_000);

for (const mode of ['vitest-failure', 'vitest-skip', 'vitest-unhandled', 'python-failure', 'rust-failure', 'omitted-case', 'stale-source', 'replaced-test-binary']) {
  test(`original acceptance rejects actual ${mode} instead of borrowing a command-level pass`, () => fixture(mode, ({ output, report }) => {
    assert.equal(report.status, 'failed-or-incomplete');
    assert.equal(report.executed, mode === 'stale-source' ? 4 : 0);
    assert.equal(report.tests.length, report.executed);
    assert.equal(typeof report.reason, 'string'); assert.ok(report.reason.length > 20);
    assert.equal(report.source_unchanged, mode !== 'stale-source');
    if (mode === 'omitted-case') assert.match(report.reason, /missing outcomes/);
    else if (mode === 'stale-source') assert.match(report.reason, /sources changed/);
    else if (mode === 'replaced-test-binary') assert.match(report.reason, /executable changed after discovery/);
    else assert.match(report.reason, /command failed|failed, pending, skipped/);
    if (mode.startsWith('vitest-') || mode === 'python-failure') {
      assert.deepEqual(report.commands.map(row => row.stdout.path), ['guard-build.stdout', 'static.stdout', 'vitest.stdout', 'python-0.stdout', 'rust-0.stdout', 'rust-1.stdout']);
      assert.equal(report.runner_errors.some(row => row.runner === (mode === 'python-failure' ? 'python-0' : 'vitest')), true);
      assert.deepEqual(report.vitest, fileReceipt(output, 'vitest.json'));
      assert.deepEqual(report.python, [fileReceipt(output, 'python-0.json')]);
      const laterPython = JSON.parse(readFileSync(path.join(output, 'python-0.json')));
      assert.equal(laterPython.successful, mode !== 'python-failure');
      assert.equal(laterPython.tests_run, 1);
      for (const name of ['rust-0.stdout', 'rust-1.stdout']) assert.match(readFileSync(path.join(output, name), 'utf8'), /test result: ok\. 1 passed/);
      for (const row of report.commands) for (const stream of ['stdout', 'stderr']) assert.deepEqual(fileReceipt(output, row[stream].path), row[stream]);
      assert.equal(report.executed, 0); assert.deepEqual(report.tests, []);
      assert.equal(report.unsigned_evidence, undefined); assert.equal(existsSync(path.join(output, 'unit-evidence.unsigned.json')), false);
    }
    if (mode === 'vitest-unhandled') {
      const cases = JSON.parse(readFileSync(path.join(output, 'vitest.json')));
      assert.equal(cases.numPassedTests, 1); assert.equal(cases.numFailedTests, 0);
      assert.match(readFileSync(path.join(output, 'vitest.stdout'), 'utf8') + readFileSync(path.join(output, 'vitest.stderr'), 'utf8'), /original runner unhandled fixture/);
    }
    assert.equal(JSON.parse(readFileSync(path.join(output, 'report.json'))).status, 'failed-or-incomplete');
  }), 90_000);
}
