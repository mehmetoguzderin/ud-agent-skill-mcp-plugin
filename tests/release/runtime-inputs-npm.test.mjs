import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, realpathSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { fileReceipt, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { packageInventory, retainSourceSnapshot } from '../../scripts/release/prepare.mjs';
import { writeSkillSupport } from '../../scripts/release/skill-support.mjs';
import { prepareRuntimeInputs, verifyRuntimeInputs } from '../../scripts/release/runtime-inputs.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';
import { availableScope } from '../../scripts/release/available-candidate.mjs';
import { fixtureTar } from './oci-fixture.mjs';

const root = path.resolve(import.meta.dirname, '../..'), python = process.env.UD_AGENT_PYTHON ?? process.env.UD_RELEASE_PYTHON ?? path.join(root, '.venv/bin/python');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const targets = ['darwin-arm64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'];
function binary(target) {
  const bytes = Buffer.alloc(128);
  if (target.startsWith('linux-')) { bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]); bytes.writeUInt16LE(target.endsWith('arm64') ? 183 : 62, 18); }
  else if (target.startsWith('darwin-')) { bytes.set([0xcf, 0xfa, 0xed, 0xfe]); bytes.writeUInt32LE(target.endsWith('arm64') ? 0x100000c : 0x1000007, 4); }
  else { bytes.write('MZ'); bytes.writeUInt32LE(64, 60); bytes.write('PE\0\0', 64); bytes.writeUInt16LE(target.endsWith('arm64') ? 0xaa64 : 0x8664, 68); }
  return bytes;
}
function put(base, relative, bytes, executable = false) { const file = path.join(base, relative); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, bytes); if (executable) chmodSync(file, 0o755); }
function archive(source, destination, format) { const result = spawnSync(python, [path.join(root, 'scripts/release/archive-dev.py'), source, destination, '--format', format], { encoding: 'utf8', timeout: 30000 }); assert.equal(result.error, undefined); assert.equal(result.status, 0, result.stderr); }
function fixture(base) {
  const native = path.join(base, 'native'); mkdirSync(native); writableFixtureCopy(path.join(root, 'skills'), path.join(native, 'skills'), base); writeSkillSupport(root, native);
  const payloads = { core: Buffer.from('explicit unexecuted core transport fixture'), render: Buffer.from('explicit unexecuted render transport fixture') };
  const runtime = Buffer.from(JSON.stringify({ schema_version: 1, state: 'frozen', packs: Object.fromEntries(Object.entries(payloads).map(([pack, bytes]) => [pack, { images: { 'linux/arm64': { transports: [{ format: 'oci-archive', path: 'images/' + pack + '.tar', sha256: 'sha256:' + sha(bytes), size_bytes: bytes.length }] } } }])) }));
  for (const [file, bytes] of Object.entries({ 'runtime/runtime.lock.json': runtime, 'lib/coordinator.mjs': '// exact nonexecuted fixture bytes\n', 'RELEASE-CANDIDATE.md': 'Assembled fixture candidate.\n', 'manifest.json': '{"version":"0.1.0-beta.1"}', 'contracts/ud-interfaces.json': readFileSync(path.join(root, 'contracts/ud-interfaces.json')) })) put(native, file, bytes);
  for (const file of ['bin/ud-agent', 'bin/ud-agent-guard', 'runtime/node/bin/node']) put(native, file, binary('linux-arm64'), true);
  const source = 'a'.repeat(64), runtimeHash = sha(runtime); packageInventory(native, 'native', 'linux-arm64', source, runtimeHash, 'preacceptance_candidate');
  archive(native, path.join(base, 'native.tar.gz'), 'tar.gz'); archive(native, path.join(base, 'native.mcpb'), 'zip');
  const npm = path.join(base, 'npm'); cpSync(native, npm, { recursive: true });
  put(npm, 'cli.cjs', '#!/usr/bin/env node\nthrow Error("archive fixture is never executed");\n', true);
  put(npm, 'package.json', JSON.stringify({ name: '@mehmetoguzderin/ud-agent-skill-mcp-plugin', version: '0.1.0-beta.1', bin: { 'ud-agent': 'cli.cjs' }, engines: { node: '>=24 <27' }, publishConfig: { access: 'public' } }));
  put(npm, 'platforms.json', readFileSync(path.join(root, 'packages/npm-distribution/platforms.json')));
  for (const target of targets) for (const name of ['ud-agent', 'ud-agent-guard']) put(npm, `platforms/${target}/${name}${target.startsWith('win32-') ? '.exe' : ''}`, binary(target), true);
  rmSync(path.join(npm, 'PACKAGE-INVENTORY.json'));
  packageInventory(npm, 'npm', 'all', source, runtimeHash, 'preacceptance_candidate');
  const wrapper = path.join(base, 'npm-archive'); mkdirSync(wrapper); cpSync(npm, path.join(wrapper, 'package'), { recursive: true }); archive(wrapper, path.join(base, 'original.tgz'), 'tar.gz');
  const history = JSON.parse(readFileSync(path.join(root, 'tests/fixtures/release-existing-history.json'), 'utf8')), git = path.join(base, 'history'), names = ['HEAD', 'config'];
  mkdirSync(path.join(git, 'refs'), { recursive: true }); put(git, 'HEAD', Buffer.from(history.head_base64, 'base64')); put(git, 'config', '[core]\nrepositoryformatversion = 0\nbare = true\n');
  for (const item of history.objects) { const content = Buffer.from(item.content_base64, 'base64'), object = Buffer.concat([Buffer.from(`${item.type} ${content.length}\0`), content]); assert.equal(createHash('sha1').update(object).digest('hex'), item.oid); const name = `objects/${item.oid.slice(0, 2)}/${item.oid.slice(2)}`; put(git, name, deflateSync(object)); names.push(name); }
  const files = names.sort().map(file => fileReceipt(git, file)); put(base, 'history.json', JSON.stringify({ schema_version: 1, kind: 'read-only-existing-git-history', commit: history.commit, tree_oid: history.tree_oid, files, inventory_sha256: sha(Buffer.from(canonicalJson(files))) }));
  const catalog = JSON.parse(readFileSync(path.join(native, 'contracts/ud-interfaces.json'))); put(base, 'fixtures.json', JSON.stringify({ schema_version: 1, scheduled_operations: 102, cases: catalog.map(item => ({ operation: item.name })) }));
  for (const [pack, bytes] of Object.entries(payloads)) put(base, `images/${pack}.tar`, bytes);
  return { schema_version: 1, source_sha256: source, runtime_lock_sha256: runtimeHash, rows: [{ platform: 'linux-arm64', formats: { native: { root: 'native', artifact: fileReceipt(base, 'native.tar.gz') }, mcpb: { root: 'native', artifact: fileReceipt(base, 'native.mcpb') }, npm: { root: 'npm', artifact: fileReceipt(base, 'original.tgz') } } }], offline_assets: Object.keys(payloads).map(pack => { const row = fileReceipt(base, `images/${pack}.tar`); return { path: row.path, sha256: row.sha256, size_bytes: row.size }; }), fixtures: fileReceipt(base, 'fixtures.json'), git_history: { path: 'history', receipt: fileReceipt(base, 'history.json') } };
}

test('runtime inputs admit the exact all-platform npm archive beside unchanged native/MCPB subjects', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-npm-'));
  try {
    const recipe = fixture(base), output = path.join(base, 'inputs'), result = prepareRuntimeInputs(base, recipe, output, { python });
    assert.deepEqual(Object.keys(result.rows[0].formats).sort(), ['mcpb', 'native', 'npm']);
    const selected = verifyRuntimeInputs(output, 'linux-arm64', { python }); assert.equal(selected.formats.npm.artifact.sha256, recipe.rows[0].formats.npm.artifact.sha256);
    assert.equal(JSON.parse(readFileSync(path.join(output, selected.formats.npm.root, 'BUILD-RECEIPT.json'))).platform, 'all');
    assert.deepEqual(readFileSync(path.join(output, selected.formats.npm.root, 'lib/coordinator.mjs')), readFileSync(path.join(base, 'npm/lib/coordinator.mjs')));
    put(output, selected.formats.npm.root + '/cli.cjs', 'changed installed original');
    assert.throws(() => verifyRuntimeInputs(output, 'linux-arm64', { python }), /inventory/);
  } finally { rmSync(base, { recursive: true, force: true }); }
}, 30000);

test('native archives cannot masquerade as npm and an unbound available subset cannot be admitted', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-npm-kind-'));
  try {
    const recipe = fixture(base); copyFileSync(path.join(base, 'native.tar.gz'), path.join(base, 'wrong.tgz')); recipe.rows[0].formats.npm.artifact = fileReceipt(base, 'wrong.tgz');
    assert.throws(() => prepareRuntimeInputs(base, recipe, path.join(base, 'wrong-inputs'), { python }), /Original package archive rejected/);
    // Available admission must fail before attempting to inspect unbound bytes.
    const available = path.join(base, 'unbound-available'); mkdirSync(available); put(available, 'candidate-inputs.json', JSON.stringify({ schema_version: 1, qualification: 'available-target-runtime-inputs', source_sha256: recipe.source_sha256, runtime_lock_sha256: recipe.runtime_lock_sha256, rows: recipe.rows }));
    assert.throws(() => verifyRuntimeInputs(available, 'linux-arm64', { python }), /authority was not explicitly selected/);
    assert.throws(() => verifyRuntimeInputs(available, 'linux-arm64', { python, allowAvailable: true }), /receipt|path|artifact/i);
  } finally { rmSync(base, { recursive: true, force: true }); }
}, 30000);

test('unbound available inputs fail before creating a copy or output', () => {
  const parent = mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-available-')), base = path.join(parent, 'available'); mkdirSync(base);
  try {
    const recipe = fixture(base); put(base, 'available-candidate.json', JSON.stringify({ schema_version: 1 })); recipe.available_candidate = fileReceipt(base, 'available-candidate.json');
    const output = path.join(parent, 'inputs'), before = readFileSync(path.join(base, 'original.tgz'));
    assert.throws(() => prepareRuntimeInputs(base, recipe, output, { python, available: true }), /preacceptance authority/);
    assert.equal(existsSync(output), false); assert.deepEqual(readFileSync(path.join(base, 'original.tgz')), before);
    assert.throws(() => prepareRuntimeInputs(base, recipe, path.join(base, 'recursive-output'), { python, available: true }), /separate output directory/);
  } finally { rmSync(parent, { recursive: true, force: true }); }
}, 30000);

function availableFixture(base) {
  const recipe = fixture(base), authorities = path.join(base, 'authorities'); mkdirSync(authorities);
  const original = Buffer.from('required original fixture source'), hash = sha(original), notice = Buffer.from('original notice');
  const sourceManifest = { schema_version: 1, qualification: 'verified-corresponding-source-subinventories', complete_product_coverage: false, files: [{ path: 'blobs/' + hash, sha256: hash, size_bytes: original.length }], collections: [{ id: 'original', receipt_path: 'receipts/original.json', receipt_sha256: sha(notice), receipt_size_bytes: notice.length, members: [{ path: 'blobs/' + hash, sha256: hash, size_bytes: original.length }] }] };
  const manifestBytes = Buffer.from(JSON.stringify(sourceManifest)), part = fixtureTar([['MATERIALS.json', manifestBytes], ['receipts/original.json', notice], ['blobs/' + hash, original]]);
  put(base, 'artifacts/source.part', part); const partRow = { id: 'corresponding-source-0000', ...fileReceipt(base, 'artifacts/source.part') };
  const sourceIndex = { schema_version: 1, qualification: sourceManifest.qualification, complete_product_coverage: false, format: 'concatenated-ustar', manifest_sha256: sha(manifestBytes), stream_sha256: sha(part), stream_size_bytes: part.length, parts: [{ ...partRow, path: 'source.part' }], collections: [{ id: 'original', sha256: sha(notice) }], unique_source_files: 1 };
  put(base, 'artifacts/source-index.json', JSON.stringify(sourceIndex)); const indexRow = fileReceipt(base, 'artifacts/source-index.json');
  put(authorities, 'LICENSE', 'fixture MIT original'); put(authorities, 'quality/requirements.json', readFileSync(path.join(root, 'quality/requirements.json')));
  const runtimeBytes = readFileSync(path.join(base, 'native/runtime/runtime.lock.json')), userspace = JSON.stringify({ platforms: { 'linux/arm64': {} } });
  put(authorities, 'runtime/runtime.lock.json', runtimeBytes); put(authorities, 'runtime/userspace.lock.json', userspace); put(authorities, 'runtime/source-materials.lock.json', JSON.stringify({ schema_version: 1, index: indexRow, parts: [partRow] }));
  const source = sourceReceipt(authorities); recipe.source_sha256 = source.sha256;
  retainSourceSnapshot(authorities, source, path.join(base, 'source-snapshot'));
  for (const name of ['runtime.lock.json', 'userspace.lock.json']) put(base, 'runtime-inputs/runtime/' + name, readFileSync(path.join(authorities, 'runtime', name)));
  put(base, 'RUNTIME-INVENTORY.json', JSON.stringify({ schema_version: 1, files: ['runtime/runtime.lock.json', 'runtime/userspace.lock.json'].map(name => fileReceipt(path.join(base, 'runtime-inputs'), name)) }));
  for (const [directory, kind] of [['native', 'native'], ['npm', 'npm']]) { rmSync(path.join(base, directory, 'PACKAGE-INVENTORY.json')); packageInventory(path.join(base, directory), kind, kind === 'npm' ? 'all' : 'linux-arm64', source.sha256, recipe.runtime_lock_sha256, 'preacceptance_candidate'); }
  archive(path.join(base, 'native'), path.join(base, 'artifacts/native.tar.gz'), 'tar.gz'); archive(path.join(base, 'native'), path.join(base, 'artifacts/native.mcpb'), 'zip');
  rmSync(path.join(base, 'npm-archive/package'), { recursive: true }); cpSync(path.join(base, 'npm'), path.join(base, 'npm-archive/package'), { recursive: true }); archive(path.join(base, 'npm-archive'), path.join(base, 'artifacts/original.tgz'), 'tar.gz');
  const kinds = { native: ['native-linux-arm64', 'native.tar.gz'], mcpb: ['mcpb-linux-arm64', 'native.mcpb'], npm: ['npm', 'original.tgz'] };
  const artifacts = Object.entries(kinds).map(([kind, [id, name]]) => { const row = fileReceipt(base, 'artifacts/' + name); recipe.rows[0].formats[kind].artifact = row; return { id, platform: kind === 'npm' ? 'all' : 'linux-arm64', ...row }; });
  artifacts.push({ id: 'corresponding-source-index', platform: 'all', ...indexRow }, { platform: 'all', ...partRow });
  const candidate = { schema_version: 1, qualification: 'available-target-preacceptance', status: 'preacceptance_candidate', production_ready: false, material_phase: 'final', source_tree_sha256: source.sha256, runtime_lock_sha256: recipe.runtime_lock_sha256, scope: availableScope(authorities, ['linux-arm64'], artifacts), artifacts, installations: [{ platform: 'linux-arm64', formats: Object.fromEntries(Object.entries(kinds).map(([kind, [id]]) => [kind, { root: recipe.rows[0].formats[kind].root, artifact_id: id }])) }], source_snapshot: { root: 'source-snapshot', receipt: fileReceipt(base, 'source-snapshot/SOURCE-RECEIPT.json') }, runtime_root: 'runtime-inputs', runtime_inventory: fileReceipt(base, 'RUNTIME-INVENTORY.json') };
  const coverage = { schema_version: 1, qualification: 'replayed-actual-shipped-component-source-license-closure', source_inventory_sha256: source.sha256, runtime_lock_sha256: recipe.runtime_lock_sha256, complete_available_shipped_component_coverage: true, complete_product_coverage: false, unresolved_shipped_members: [], missing_distribution_subjects: candidate.scope.pending_artifacts.map(row => ({ code: 'REQUIRED_DISTRIBUTION_MISSING', artifact: row.id })).sort((a, b) => a.artifact.localeCompare(b.artifact)), subjects: artifacts.map(row => ({ id: row.id, artifact_sha256: row.sha256 })), inspection_inputs: { qualification: 'observed-component-replay-inputs-no-unretained-input-waiver', unretained_inputs: [] }, required_materials: [{ sha256: hash, size_bytes: original.length }] };
  put(base, 'artifacts/coverage.json', JSON.stringify(coverage)); artifacts.push({ id: 'component-source-coverage', platform: 'all', ...fileReceipt(base, 'artifacts/coverage.json') }); put(base, 'available-candidate.json', JSON.stringify(candidate)); recipe.available_candidate = fileReceipt(base, 'available-candidate.json');
  return recipe;
}

test('available input preparation references immutable candidate once, deduplicates payloads and accepts explicit supplemental inputs', () => {
  const parent = mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-reference-')), base = path.join(parent, 'available'), support = path.join(parent, 'support'); mkdirSync(base); mkdirSync(support);
  try {
    const recipe = availableFixture(base); cpSync(path.join(base, 'history'), path.join(support, 'history'), { recursive: true }); copyFileSync(path.join(base, 'history.json'), path.join(support, 'history.json')); copyFileSync(path.join(base, 'fixtures.json'), path.join(support, 'fixtures.json'));
    recipe.git_history.input_root = 'support'; recipe.fixtures.input_root = 'support';
    const output = path.join(parent, 'inputs');
    assert.throws(() => prepareRuntimeInputs(base, recipe, output, { python, available: true }), /explicit support root/);
    assert.equal(existsSync(output), false);
    const result = prepareRuntimeInputs(base, recipe, output, { python, available: true, supportRoot: support });
    assert.equal(result.available_candidate_root, realpathSync(base));
    assert.equal(result.package_paths, 'available-candidate');
    assert.equal(result.rows[0].formats.native.root, result.rows[0].formats.mcpb.root);
    assert.equal(existsSync(path.join(output, 'installations')), false);
    assert.equal(existsSync(path.join(output, 'artifacts')), false);
    assert.equal(existsSync(path.join(output, 'available-candidate/source-snapshot')), false);
    assert.equal(existsSync(path.join(output, 'available-candidate/artifacts')), false);
    assert.deepEqual(readFileSync(path.join(output, result.fixtures.path)), readFileSync(path.join(support, 'fixtures.json')));
    const selected = verifyRuntimeInputs(output, 'linux-arm64', { python, allowAvailable: true });
    assert.equal(selected.platform, 'linux-arm64'); assert.equal(selected.package_root, realpathSync(base));
    assert.deepEqual(readFileSync(path.join(selected.package_root, selected.formats.native.root, 'lib/coordinator.mjs')), readFileSync(path.join(base, 'native/lib/coordinator.mjs')));
    const inputFile=path.join(output,'candidate-inputs.json'), retainedInput=readFileSync(inputFile), forged=JSON.parse(retainedInput);forged.rows[0].formats.native.root='npm';put(output,'candidate-inputs.json',JSON.stringify(forged));
    assert.throws(()=>verifyRuntimeInputs(output,'linux-arm64',{python,allowAvailable:true}),/package paths/);writeFileSync(inputFile,retainedInput);
    const license = path.join(base, 'source-snapshot/LICENSE'), held = readFileSync(license); writeFileSync(license, 'altered source');
    assert.throws(() => verifyRuntimeInputs(output, 'linux-arm64', { python, allowAvailable: true }), /retained source/); writeFileSync(license, held);
    const original = path.join(base, recipe.rows[0].formats.native.artifact.path), bytes = readFileSync(original); writeFileSync(original, 'altered archive');
    assert.throws(() => verifyRuntimeInputs(output, 'linux-arm64', { python, allowAvailable: true }), /mismatch/); writeFileSync(original, bytes);
    // Earlier copied and self-contained available manifests remain readable.
    const legacyOutput=path.join(parent,'legacy-inputs');prepareRuntimeInputs(base,recipe,legacyOutput,{python,available:true,supportRoot:support,referencePackages:false});
    rmSync(path.join(legacyOutput, 'available-candidate'), { recursive: true }); cpSync(base, path.join(legacyOutput, 'available-candidate'), { recursive: true });
    const legacy = JSON.parse(readFileSync(path.join(legacyOutput, 'candidate-inputs.json'))); delete legacy.available_candidate_root; put(legacyOutput, 'candidate-inputs.json', JSON.stringify(legacy));
    assert.equal(verifyRuntimeInputs(legacyOutput, 'linux-arm64', { python, allowAvailable: true }).platform, 'linux-arm64');
  } finally { rmSync(parent, { recursive: true, force: true }); }
}, 30000);

test('archive-backed available packages verify and drive runtime inputs without expanded installation trees', () => {
  const parent=mkdtempSync(path.join(os.tmpdir(),'ud-runtime-archive-v2-')),base=path.join(parent,'available');mkdirSync(base);
  try {
    const recipe=availableFixture(base),candidate=JSON.parse(readFileSync(path.join(base,'available-candidate.json'),'utf8'));
    candidate.schema_version=2;
    for(const [format,item] of Object.entries(candidate.installations[0].formats)){
      const original=path.join(base,item.root);item.inventory_sha256=fileReceipt(original,'PACKAGE-INVENTORY.json').sha256;item.build_receipt_sha256=fileReceipt(original,'BUILD-RECEIPT.json').sha256;delete item.root;delete recipe.rows[0].formats[format].root;
    }
    put(base,'available-candidate.json',JSON.stringify(candidate));recipe.available_candidate=fileReceipt(base,'available-candidate.json');
    rmSync(path.join(base,'native'),{recursive:true});rmSync(path.join(base,'npm'),{recursive:true});
    const output=path.join(parent,'inputs'),prepared=prepareRuntimeInputs(base,recipe,output,{python,available:true});
    assert.equal(prepared.rows[0].formats.native.root,undefined);assert.equal(existsSync(path.join(output,'installations')),false);
    const selected=verifyRuntimeInputs(output,'linux-arm64',{python,allowAvailable:true});assert.equal(selected.operation_names.length,102);assert.equal(selected.formats.npm.root,undefined);
    const file=path.join(output,'candidate-inputs.json'),held=readFileSync(file),forged=JSON.parse(held);forged.rows[0].formats.native.inventory_sha256='f'.repeat(64);put(output,'candidate-inputs.json',JSON.stringify(forged));
    assert.throws(()=>verifyRuntimeInputs(output,'linux-arm64',{python,allowAvailable:true}),/contract differs/);writeFileSync(file,held);
    const artifact=path.join(base,recipe.rows[0].formats.native.artifact.path),bytes=readFileSync(artifact);writeFileSync(artifact,'changed');
    assert.throws(()=>verifyRuntimeInputs(output,'linux-arm64',{python,allowAvailable:true}),/mismatch/);writeFileSync(artifact,bytes);
  } finally {rmSync(parent,{recursive:true,force:true});}
},30000);
