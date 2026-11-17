import { test, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { packageInventory } from '../../scripts/release/prepare.mjs';
import { writeSkillSupport } from '../../scripts/release/skill-support.mjs';
import { prepareRuntimeInputs, verifyRuntimeInputs } from '../../scripts/release/runtime-inputs.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

const root = path.resolve(import.meta.dirname, '../..'), python = process.env.UD_AGENT_PYTHON ?? process.env.UD_RELEASE_PYTHON ?? path.join(root, '.venv/bin/python');
function sha(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function fixture(base) {
  const installation = path.join(base, 'payload'), files = {};
  mkdirSync(installation); writableFixtureCopy(path.join(root, 'skills'), path.join(installation, 'skills'), base); writeSkillSupport(root, installation);
  const workers = Object.fromEntries(['core', 'render'].map(pack => [pack, Buffer.from(`explicit non-executed ${pack} archive fixture`)])), runtime = { schema_version: 1, state: 'frozen', packs: Object.fromEntries(['core', 'render'].map(pack => [pack, { images: { 'linux/arm64': { transports: [{ format: 'oci-archive', path: `runtime/images/${pack}-arm64.tar`, sha256: 'sha256:' + sha(workers[pack]), size_bytes: workers[pack].length }] } } }])) };
  files['runtime/runtime.lock.json'] = Buffer.from(JSON.stringify(runtime)); files['lib/coordinator.mjs'] = Buffer.from('// original fixture bytes; no execution\n'); files['RELEASE-CANDIDATE.md'] = Buffer.from('Fixture candidate assembled before tests.\n'); files['manifest.json'] = Buffer.from('{"version":"0.1.0-beta.1"}'); files['contracts/ud-interfaces.json'] = readFileSync(path.join(root, 'contracts/ud-interfaces.json'));
  const binary = Buffer.alloc(64); binary.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]); binary.writeUInt16LE(183, 18);
  for (const name of ['bin/ud-agent', 'bin/ud-agent-guard', 'runtime/node/bin/node']) files[name] = binary;
  for (const [name, bytes] of Object.entries(files)) { const target = path.join(installation, name); mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, bytes); if (name.includes('/bin/') || name.startsWith('bin/')) chmodSync(target, 0o755); }
  const source = 'a'.repeat(64), runtimeHash = sha(files['runtime/runtime.lock.json']); packageInventory(installation, 'native', 'linux-arm64', source, runtimeHash, 'preacceptance_candidate');
  for (const [name, format] of [['native.tar.gz', 'tar.gz'], ['native.mcpb', 'zip']]) { const result = spawnSync(python, [path.join(root, 'scripts/release/archive-dev.py'), installation, path.join(base, name), '--format', format], { encoding: 'utf8' }); expect(result.status, result.stderr).toBe(0); }
  const history = JSON.parse(readFileSync(path.join(root, 'tests/fixtures/release-existing-history.json'), 'utf8')), git = path.join(base, 'history'); mkdirSync(path.join(git, 'objects'), { recursive: true }); mkdirSync(path.join(git, 'refs')); writeFileSync(path.join(git, 'HEAD'), Buffer.from(history.head_base64, 'base64')); writeFileSync(path.join(git, 'config'), '[core]\nrepositoryformatversion = 0\nbare = true\n');
  const gitFiles = ['HEAD', 'config'];
  for (const item of history.objects) { const body = Buffer.from(item.content_base64, 'base64'), object = Buffer.concat([Buffer.from(`${item.type} ${body.length}\0`), body]); expect(createHash('sha1').update(object).digest('hex')).toBe(item.oid); const name = `objects/${item.oid.slice(0, 2)}/${item.oid.slice(2)}`; mkdirSync(path.dirname(path.join(git, name)), { recursive: true }); writeFileSync(path.join(git, name), deflateSync(object)); gitFiles.push(name); }
  const records = gitFiles.sort().map(name => fileReceipt(git, name)), proof = { schema_version: 1, kind: 'read-only-existing-git-history', commit: history.commit, tree_oid: history.tree_oid, files: records, inventory_sha256: sha(Buffer.from(canonicalJson(records))) }; writeFileSync(path.join(base, 'history.json'), JSON.stringify(proof));
  const catalog = JSON.parse(files['contracts/ud-interfaces.json']); writeFileSync(path.join(base, 'fixtures.json'), JSON.stringify({ schema_version: 1, scheduled_operations: 102, cases: catalog.map(item => ({ operation: item.name })) }));
  for (const pack of ['core', 'render']) { mkdirSync(path.join(base, 'runtime/images'), { recursive: true }); writeFileSync(path.join(base, `runtime/images/${pack}-arm64.tar`), workers[pack]); }
  return { schema_version: 1, source_sha256: source, runtime_lock_sha256: runtimeHash, rows: [{ platform: 'linux-arm64', formats: { native: { root: 'payload', artifact: fileReceipt(base, 'native.tar.gz') }, mcpb: { root: 'payload', artifact: fileReceipt(base, 'native.mcpb') } } }], offline_assets: ['core', 'render'].map(pack => { const row = fileReceipt(base, `runtime/images/${pack}-arm64.tar`); return { path: row.path, sha256: row.sha256, size_bytes: row.size }; }), fixtures: fileReceipt(base, 'fixtures.json'), git_history: { path: 'history', receipt: fileReceipt(base, 'history.json') } };
}

test('runtime input producer binds original archives, installed roots, complete fixtures, history and offline assets', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-inputs-'));
  try {
    const recipe = fixture(base), output = path.join(base, 'candidate'); const manifest = prepareRuntimeInputs(base, recipe, output, { python }); expect(manifest.rows.length).toBe(1); const selectedPackage=verifyRuntimeInputs(output, 'linux-arm64', { python });expect(selectedPackage.platform).toBe('linux-arm64');expect(selectedPackage.archive_expanded_sizes.native).toBeGreaterThan(0);expect(selectedPackage.archive_expanded_sizes.mcpb).toBe(selectedPackage.archive_expanded_sizes.native);
    expect(() => verifyRuntimeInputs(output, 'win32-arm64', { python })).toThrow('Pending native build');
    const selected = path.join(output, 'installations/linux-arm64/native/lib/coordinator.mjs'); writeFileSync(selected, '// changed'); expect(() => verifyRuntimeInputs(output, 'linux-arm64', { python })).toThrow('inventory');
  } finally { rmSync(base, { recursive: true, force: true }); }
}, 30_000);

test('runtime input producer refuses missing offline bytes', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-inputs-'));
  try { const recipe = fixture(base); recipe.offline_assets.pop(); expect(() => prepareRuntimeInputs(base, recipe, path.join(base, 'candidate'), { python })).toThrow('Offline acquisition asset'); } finally { rmSync(base, { recursive: true, force: true }); }
});

test('runtime input producer cannot test a payload relabeled after archiving', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-inputs-'));
  try {
    const recipe = fixture(base), file = path.join(base, 'payload/BUILD-RECEIPT.json'), build = JSON.parse(readFileSync(file, 'utf8')); build.qualification = 'local_candidate'; writeFileSync(file, JSON.stringify(build));
    packageInventory(path.join(base, 'payload'), 'native', 'linux-arm64', recipe.source_sha256, recipe.runtime_lock_sha256, 'local_candidate');
    expect(() => prepareRuntimeInputs(base, recipe, path.join(base, 'candidate'), { python })).toThrow('inventory');
  } finally { rmSync(base, { recursive: true, force: true }); }
});
