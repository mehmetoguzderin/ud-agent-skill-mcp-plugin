import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { installNpmPayload, npmInstallationToolchain } from '../../scripts/quality/installed-npm.mjs';
import { installedMcpLaunch } from '../../scripts/quality/installed-payload.mjs';
import { providerAcceptanceSearchPath, providerEvidenceScope, providerMatrixFormats, runInstalledCli, installNpmPayloadBounded, withAcceptanceStorage } from '../../scripts/quality/native-provider-acceptance.mjs';
import { operationMatrixSummary } from '../../scripts/quality/userspace-acceptance.mjs';
import { fixtureTar } from './oci-fixture.mjs';

// Explicit original-test prerequisite; the adapter itself never selects npm from PATH.
const npmCandidates = [path.resolve(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'), path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'), ...(process.env.PATH ?? '').split(path.delimiter).map(directory => path.join(directory, process.platform === 'win32' ? 'node_modules/npm/bin/npm-cli.js' : 'npm'))];
const npmCli = process.env.UD_RELEASE_NPM_CLI ?? npmCandidates.filter(file => existsSync(file)).map(file => realpathSync(file)).find(file => file.endsWith(path.join('npm', 'bin', 'npm-cli.js')));

function fixture(base, extra = {}) {
  const root = path.join(base, 'original'); mkdirSync(root);
  const files = {
    'runtime/runtime.lock.json': '{}', 'lib/coordinator.mjs': '// immutable original fixture\n',
    'cli.cjs': '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({arguments:process.argv.slice(2),home:process.env.HOME,ambient:process.env.UD_NPM_TEST_AMBIENT??null}));\n',
    'package.json': JSON.stringify({ name: '@mehmetoguzderin/ud-agent-skill-mcp-plugin', version: '0.1.0-beta.1', bin: { 'ud-agent': 'cli.cjs' }, engines: { node: '>=24 <27' }, publishConfig: { access: 'public' }, scripts: { install: 'node -e "throw Error(\'lifecycle must never run\')"' }, ...extra }),
  };
  files['BUILD-RECEIPT.json'] = JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', kind: 'npm', platform: 'all', source_tree_sha256: 'a'.repeat(64), runtime_lock_sha256: sha256(Buffer.from(files['runtime/runtime.lock.json'])) });
  for (const [name, bytes] of Object.entries(files)) { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, bytes); if (name === 'cli.cjs') chmodSync(file, 0o755); }
  const records = Object.keys(files).map(name => fileReceipt(root, name)); files['PACKAGE-INVENTORY.json'] = JSON.stringify({ schema_version: 1, files: records }); writeFileSync(path.join(root, 'PACKAGE-INVENTORY.json'), files['PACKAGE-INVENTORY.json']);
  const tar = fixtureTar(Object.entries(files).map(([name, bytes]) => ['package/' + name, bytes]));
  let offset = 0;
  for (const [name, bytes] of Object.entries(files)) {
    if (name === 'cli.cjs') { tar.write('0000755\0', offset + 100, 'ascii'); tar.fill(32, offset + 148, offset + 156); const sum = tar.subarray(offset, offset + 512).reduce((a, b) => a + b, 0); tar.write(`${sum.toString(8).padStart(6, '0')}\0 `, offset + 148, 'ascii'); }
    offset += 512 + Math.ceil(Buffer.byteLength(bytes) / 512) * 512;
  }
  writeFileSync(path.join(base, 'original.tgz'), gzipSync(tar));
  return { root: 'original', artifact: fileReceipt(base, 'original.tgz') };
}

test('actual offline npm installs original bytes and invokes its installed public CLI without lifecycle or ambient configuration', async () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-npm-installed-'));
  try {
    assert.ok(npmCli, 'Original npm CLI prerequisite is required');
    const item = fixture(base), original = readFileSync(path.join(base, 'original.tgz')), prefix = path.join(base, 'private'), marker = path.join(base, 'ambient-startup-ran'), startup = path.join(base, 'ambient-startup.cjs');
    writeFileSync(startup, 'require("node:fs").writeFileSync(' + JSON.stringify(marker) + ',"unexpected ambient startup");\n');
    const previous = process.env.NODE_OPTIONS; let result;
    try { process.env.NODE_OPTIONS = '--require=' + JSON.stringify(startup); result = installNpmPayload(base, item, prefix, { npmCli }); }
    finally { if (previous === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = previous; }
    assert.equal(existsSync(marker), false, 'npm preparation executed ambient Node startup code');
    assert.equal(result.receipt.status, 0); assert.equal(result.receipt.network, 'offline'); assert.equal(result.receipt.lifecycle_scripts, false);
    assert.equal(result.receipt.npm.files > 0, true); assert.match(result.receipt.npm.inventory_sha256, /^[a-f0-9]{64}$/);
    assert.ok(result.root.startsWith(path.join(prefix, 'node_modules') + path.sep));
    const launch = installedMcpLaunch(result.root, '/workspace', { format: 'npm', node: result.node });
    const invoked = spawnSync(launch.command, launch.args, { env: { PATH: path.dirname(result.node), HOME: path.join(prefix, 'home') }, encoding: 'utf8', timeout: 10000 });
    assert.equal(invoked.error, undefined); assert.equal(invoked.status, 0, invoked.stderr);
    assert.deepEqual(JSON.parse(invoked.stdout), { arguments: ['mcp', '--allow-root', '/workspace'], home: path.join(prefix, 'home'), ambient: null });
    const cleanup = await runInstalledCli(launch, ['uninstall', '--owned-runtime', '--engine', 'userspace'], { PATH: path.dirname(result.node), HOME: path.join(prefix, 'home') });
    assert.deepEqual(cleanup, { arguments: ['uninstall', '--owned-runtime', '--engine', 'userspace'], home: path.join(prefix, 'home'), ambient: null });
    assert.deepEqual(readFileSync(path.join(base, 'original.tgz')), original);
    assert.deepEqual(readFileSync(path.join(result.root, 'cli.cjs')), readFileSync(path.join(base, 'original/cli.cjs')));
    assert.equal(result.receipt.environment.PATH, path.dirname(result.node));
    assert.equal(result.receipt.environment.npm_config_userconfig, path.join(prefix, 'user.npmrc'));
    assert.equal(result.receipt.environment.NODE_OPTIONS, undefined);
    assert.throws(() => installNpmPayload(base, item, prefix, { npmCli }), /new absolute private prefix/);
  } finally { rmSync(base, { recursive: true, force: true }); }
}, process.platform === 'win32' ? 0 : 30000);

test('npm admission rejects changed archives, extra dependencies, unsafe tool selection and unbound installed bytes', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-npm-inputs-'));
  try {
    const item = fixture(base, { dependencies: { 'foreign-package': 'https://example.invalid/not-fetched.tgz' } });
    assert.throws(() => installNpmPayload(base, item, path.join(base, 'dependency')), /must not install dependency/);
    writeFileSync(path.join(base, 'original.tgz'), 'changed bytes');
    assert.throws(() => installNpmPayload(base, item, path.join(base, 'corrupt')), /Artifact receipt mismatch/);
    assert.throws(() => npmInstallationToolchain({ npmCli: 'npm' }), /absolute tool paths/);
    assert.throws(() => npmInstallationToolchain({ npmCli: path.join(base, 'original/cli.cjs') }), /npm package CLI/);
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test('offline npm install verifies archive-backed identities with no expanded candidate root', () => {
  const base=mkdtempSync(path.join(os.tmpdir(),'ud-npm-archive-v2-'));
  try{
    assert.ok(npmCli);const item=fixture(base),original=path.join(base,item.root),build=JSON.parse(readFileSync(path.join(original,'BUILD-RECEIPT.json'),'utf8'));
    Object.assign(item,{inventory_sha256:fileReceipt(original,'PACKAGE-INVENTORY.json').sha256,build_receipt_sha256:fileReceipt(original,'BUILD-RECEIPT.json').sha256,source_sha256:build.source_tree_sha256,runtime_lock_sha256:build.runtime_lock_sha256});delete item.root;rmSync(original,{recursive:true});
    const installed=installNpmPayload(base,item,path.join(base,'private'),{npmCli});assert.equal(installed.receipt.payload.inventory_sha256,item.inventory_sha256);assert.equal(installed.receipt.payload.kind,'npm');
    assert.throws(()=>installNpmPayload(base,{...item,inventory_sha256:'f'.repeat(64)},path.join(base,'forged'),{npmCli}),/archive inventory/);
  }finally{rmSync(base,{recursive:true,force:true});}
},process.platform === 'win32' ? 0 : 30000);

test('bounded actual npm installation removes its private profile and ignores ambient Node startup',async()=>{
  const base=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-npm-bounded-'))),reportPath=path.join(base,'report.json');
  try{
    assert.ok(npmCli);const item=fixture(base),marker=path.join(base,'ambient-ran'),startup=path.join(base,'ambient.cjs');writeFileSync(startup,'require("node:fs").writeFileSync('+JSON.stringify(marker)+',"bad")');
    const previous=process.env.NODE_OPTIONS;let installation;
    try{process.env.NODE_OPTIONS='--require='+JSON.stringify(startup);await withAcceptanceStorage({root:base,reportPath,label:'npm-fixture'},async storage=>{
      const installed=await installNpmPayloadBounded(base,item,path.join(storage.profile,'npm'),npmCli,storage);installation=installed.root;assert.equal(installed.receipt.network,'offline');assert.equal(existsSync(marker),false);assert.ok(existsSync(installation));writeFileSync(reportPath,JSON.stringify({status:'passed'}));
    });}finally{if(previous===undefined)delete process.env.NODE_OPTIONS;else process.env.NODE_OPTIONS=previous;}
    assert.equal(existsSync(marker),false);assert.equal(existsSync(installation),false);assert.equal(JSON.parse(readFileSync(reportPath)).scratch_cleanup,'verified');
  }finally{rmSync(base,{recursive:true,force:true});}
},process.platform === 'win32' ? 0 : 30000);

test('npm matrix coverage is an exact third entrypoint union and available targets cannot claim complete release acceptance', () => {
  const legacy = { formats: { native: {}, mcpb: {} } }, current = { formats: { native: {}, mcpb: {}, npm: {} } };
  assert.deepEqual(providerMatrixFormats(legacy), ['native', 'mcpb']); assert.deepEqual(providerMatrixFormats(current), ['native', 'mcpb', 'npm']);
  assert.deepEqual(providerMatrixFormats(current, 'npm'), ['npm']); assert.throws(() => providerMatrixFormats(legacy, 'npm'), /absent/);
  assert.throws(() => providerMatrixFormats({ formats: { npm: {} } }), /incomplete/);
  const operations = ['validation_report', 'project_consistency_report'], rows = ['native', 'mcpb', 'npm'].flatMap(format => operations.map(operation => ({ format, operation, status: operation === 'project_consistency_report' ? 'capability-rejection-verified' : 'passed' })));
  assert.deepEqual(operationMatrixSummary(rows, operations, providerMatrixFormats(current), 'userspace'), { complete: true, completed_operations: 3, capability_rejections: 3, scheduled: 6 });
  assert.equal(operationMatrixSummary([...rows.slice(0, -1), rows[0]], operations, providerMatrixFormats(current), 'userspace').complete, false);
  assert.deepEqual(providerEvidenceScope({ qualification: 'available-target-runtime-inputs' }, 'available-target'), { qualification: 'available-target-provider-preacceptance-execution', acceptance_eligible: false, target_execution_eligible: true });
  assert.throws(() => providerEvidenceScope({ qualification: 'available-target-runtime-inputs' }));
  assert.throws(() => providerEvidenceScope({ qualification: 'preacceptance-runtime-inputs' }, 'available-target'));
});

test('provider child search paths retain only the explicit engine, Node and fixed OS utilities', async () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-npm-provider-path-'));
  try {
    const engine = path.join(base, 'engine'), foreign = path.join(base, 'unrelated'); mkdirSync(engine); mkdirSync(foreign);
    const name = process.platform === 'win32' ? 'docker.exe' : 'docker', bytes = Buffer.from('read-only executable identity fixture; never run'); writeFileSync(path.join(engine, name), bytes); chmodSync(path.join(engine, name), 0o755);
    const selected = await providerAcceptanceSearchPath({ engine: 'docker' }, { searchPath: [foreign, engine].join(path.delimiter) });
    assert.equal(selected.engine.sha256, sha256(bytes)); assert.equal(selected.engine.selected_path, path.join(engine, name));
    assert.ok(selected.path.split(path.delimiter).includes(engine)); assert.ok(selected.path.split(path.delimiter).includes(path.dirname(process.execPath))); assert.equal(selected.path.split(path.delimiter).includes(foreign), false);
    await assert.rejects(providerAcceptanceSearchPath({ engine: 'podman' }, { searchPath: engine }), /prerequisite is absent/);
    assert.deepEqual(await providerAcceptanceSearchPath({ engine: 'userspace', searchPath: engine }), { path: engine });
  } finally { rmSync(base, { recursive: true, force: true }); }
});
