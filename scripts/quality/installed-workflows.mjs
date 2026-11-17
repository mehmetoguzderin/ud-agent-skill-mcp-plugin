#!/usr/bin/env node
/** Real coordinator/worker checks against a supplied installed runtime pack. */
import assert from 'node:assert/strict';
import { reserveStorage, STORAGE_LIMITS } from './storage-lifecycle.mjs';
import { createHash } from 'node:crypto';
import { copyFile, cp, lstat, mkdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const flags = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => index % 2 ? pairs : [...pairs, [value, all[index + 1]]], []));
if (!flags['--runtime-pack'] || !['uv', 'venv'].includes(flags['--installer'])) throw new Error('--runtime-pack PATH --installer uv|venv are required.');
const source = await realpath('.');
const storageRoot = path.resolve(process.env.UD_AGENT_STORAGE_ROOT ?? process.cwd());
const storage = reserveStorage({ root: storageRoot, plannedBytes: STORAGE_LIMITS.ordinaryBytes, label: 'ud-installed-workflows' });
const profile = storage.directory;
const reportPath = path.resolve(flags['--report'] ?? path.join(storageRoot, '.artifacts/installed-reports', path.basename(profile) + '.json'));
assert.ok(reportPath !== profile && !reportPath.startsWith(profile + path.sep), 'Installed evidence must be outside disposable scratch.');
await mkdir(path.dirname(reportPath), { recursive: true, mode: 0o700 });
try {

const installation = path.join(profile, 'installation');
await cp(await realpath(flags['--runtime-pack']), installation, { recursive: true, dereference: false });
await cp(path.join(source, 'contracts'), path.join(installation, 'contracts'), { recursive: true });
await build({ entryPoints: ['packages/coordinator/src/operations.ts'], bundle: true, platform: 'node', mainFields: ['module', 'main'], format: 'esm', banner: { js: "import { createRequire as __udCreateRequire } from 'node:module'; const require = __udCreateRequire(import.meta.url);" }, outfile: path.join(installation, 'coordinator.mjs') });
const { executeOperation } = await import(pathToFileURL(path.join(installation, 'coordinator.mjs')).href);
const domain = JSON.parse(await readFile(path.join(installation, 'contracts/ud-interfaces.json'), 'utf8'));
const environment = JSON.parse(await readFile(path.join(installation, 'contracts/environment.json'), 'utf8'));
const bin = path.join(profile, 'bin'); await mkdir(bin);
const found = spawnSync(process.env.UD_AGENT_PYTHON ?? 'python3', ['-I', '-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' });
assert.equal(found.status, 0, found.stderr);
await symlink(await realpath(found.stdout.trim()), path.join(bin, process.platform === 'win32' ? 'python3.exe' : 'python3'));
if (flags['--installer'] === 'uv') {
  const windows = process.platform === 'win32';
  const executable = spawnSync(windows ? 'where.exe' : 'which', [windows ? 'uv.exe' : 'uv'], { encoding: 'utf8', timeout: 10_000, maxBuffer: 65_536 });
  assert.equal(executable.status, 0, executable.error?.message ?? executable.stderr);
  await symlink(await realpath(executable.stdout.trim().split(/\r?\n/)[0]), path.join(bin, process.platform === 'win32' ? 'uv.exe' : 'uv'));
}
const workspace = path.join(profile, 'workspace'); await mkdir(workspace);
const output = path.join(profile, 'exports'); await mkdir(output);
const original = Buffer.from('# sent_id = one\r\n# text = Hi\r\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\r\n\r\n');
await writeFile(path.join(workspace, 'a.conllu'), original);
const options = { sourceRoot: installation, searchPath: bin, userspaceStateRoot: path.join(profile, 'state'), allowedRoots: [workspace, output] };
if (flags['--core-archive']) {
  const receipt = JSON.parse(await readFile(path.join(installation, 'runtime/userspace.lock.json'), 'utf8')).platforms[`${process.platform}/${process.arch}`].lazy_core;
  assert.ok(receipt);
  const archive = await realpath(flags['--core-archive']), bytes = await readFile(archive);
  assert.equal(bytes.length, receipt.size);
  assert.equal('sha256:' + createHash('sha256').update(bytes).digest('hex'), receipt.sha256);
  const cache = path.join(profile, 'state', 'core-cache');
  await mkdir(cache, { recursive: true, mode: 0o700 });
  await copyFile(archive, path.join(cache, `${receipt.sha256.slice(7)}.tar.gz`));
  // Universal npm packages intentionally omit selected-host core bytes; this
  // profile exercises their actual offline acquisition/extraction route.
  await rm(path.join(installation, 'runtime/pack'), { recursive: true });
}
const rows = [];
async function call(name, args, expected) {
  storage.check();
  const contract = [...domain, ...environment].find(item => item.name === name); assert.ok(contract);
  const start = performance.now();
  const response = await executeOperation(contract, args, domain, options);
  assert.equal(response.isError, undefined, JSON.stringify(response));
  expected(response.structuredContent.result);
  storage.check();
  rows.push({ operation: name, elapsed_ms: performance.now() - start, execution: response.structuredContent.execution, inputs: response.structuredContent.inputs, provenance: response.structuredContent.provenance });
  return response.structuredContent.result;
}
await call('setup_ud_environment', { engine: 'userspace', required_tools: ['validation_report'], network: 'offline' }, result => { assert.equal(result.ready, true); assert.equal(result.installer, flags['--installer']); assert.equal(result.reused, false); });
await call('setup_ud_environment', { engine: 'userspace', required_tools: ['validation_report'], network: 'offline' }, result => { assert.equal(result.ready, true); assert.equal(result.reused, true); });
await call('sentence_render', { working_tree_path: workspace, sentence_conllu: original.toString(), output_format: 'svg', output_path: path.join(output, 'static.svg'), ud_context_path: '' }, result => { assert.equal(result.export_transaction.status, 'completed'); });
assert.ok((await readFile(path.join(output, 'static.svg'), 'utf8')).includes('<svg'));
for (const name of ['renders', 'render-cache', 'render-vendor-cache']) await assert.rejects(lstat(path.join(profile, 'state', name)), { code: 'ENOENT' });
if (flags['--render-archive']) {
  const receipt = JSON.parse(await readFile(path.join(installation, 'runtime/userspace.lock.json'), 'utf8')).platforms[`${process.platform}/${process.arch}`].lazy_render;
  assert.ok(receipt);
  const cache = path.join(profile, 'state', 'render-cache'); await mkdir(cache, { mode: 0o700 });
  const renderArchive = await realpath(flags['--render-archive']);
  const renderBytes = await readFile(renderArchive);
  assert.equal(renderBytes.length, receipt.size);
  assert.equal('sha256:' + createHash('sha256').update(renderBytes).digest('hex'), receipt.sha256);
  await copyFile(renderArchive, path.join(cache, `${receipt.sha256.slice(7)}.tar.gz`));
  if (flags['--vendor-archive']) {
    const recipeReader = String.raw`import hashlib,json,sys,tarfile
with tarfile.open(sys.argv[1], 'r:gz') as source:
 def read(name):
  item=source.getmember(name)
  if not item.isfile() or item.size>4*1024*1024:raise ValueError('invalid bounded browser metadata')
  with source.extractfile(item) as content:return content.read(item.size+1)
 manifest=json.loads(read('manifest.json'));deferred=manifest['deferred_browser']
 if deferred['provider'] not in ('google-chrome-for-testing','microsoft-edge'):raise ValueError('unsupported browser provider')
 raw=read(deferred['recipe']);expected=next(item for item in manifest['files'] if item['path']==deferred['recipe'])
 if len(raw)!=expected['size_bytes'] or hashlib.sha256(raw).hexdigest()!=expected['sha256']:raise ValueError('browser recipe is not bound to the installed base')
 recipe=json.loads(raw)
 if recipe['provider']!=deferred['provider']:raise ValueError('browser provider differs from locked recipe')
 print(json.dumps({'provider':recipe['provider'],'archive':recipe['archive']}))`;
    const decoded = spawnSync(found.stdout.trim(), ['-I', '-c', recipeReader, renderArchive], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
    assert.equal(decoded.status, 0, decoded.stderr);
    const recipe = JSON.parse(decoded.stdout);
    const vendorBytes = await readFile(await realpath(flags['--vendor-archive']));
    assert.equal(vendorBytes.length, recipe.archive.size_bytes);
    assert.equal(createHash('sha256').update(vendorBytes).digest('hex'), recipe.archive.sha256);
    const vendorCache = path.join(profile, 'state', 'render-vendor-cache');
    await mkdir(vendorCache, { mode: 0o700 });
    await copyFile(await realpath(flags['--vendor-archive']), path.join(vendorCache, `${recipe.archive.sha256}.${recipe.provider === 'microsoft-edge' ? 'msi' : 'zip'}`));
  }
  await call('setup_ud_environment', { engine: 'userspace', required_tools: ['sentence_render'], network: 'offline' }, result => { assert.equal(result.ready, true, JSON.stringify(result)); });
}
const base = { working_tree_path: workspace, ud_context_path: '' };
await call('validation_report', { ...base, file_paths: ['a.conllu'], options: { language_code: 'en', level: 2 } }, result => { assert.equal(result.passed, false); assert.ok(result.incidents.some(item => item.testid === 'non-unix-newline')); });
assert.deepEqual(await readFile(path.join(workspace, 'a.conllu')), original);
const valid = Buffer.from(original.toString().replaceAll('\r\n', '\n'));
await writeFile(path.join(workspace, 'a.conllu'), valid);
await call('validation_report', { ...base, file_paths: ['a.conllu'], options: { language_code: 'en', level: 2 } }, result => { assert.equal(result.passed, true, JSON.stringify(result)); });
await call('validation_report', { ...base, file_paths: ['a.conllu'], options: { language_code: 'en', level: 2, check_families: ['content', 'repository', 'documentation'], repository_name: 'UD_English-Example' } }, result => {
  assert.equal(result.passed, false, 'The intentionally incomplete repository must have incidents.');
  assert.equal(result.coverage.content, 'completed'); assert.equal(result.coverage.repository, 'completed'); assert.equal(result.coverage.documentation, 'completed');
  assert.ok(result.incidents.length > 0);
});
await call('token_lemma_set', { ...base, token_ref: { tree_ref: { file_path: 'a.conllu', sent_id: 'one' }, token_id: '1' }, lemma: 'hello', edit_options: { mode: 'preview', validation_options: { language_code: 'en', level: 2 } } }, result => { assert.equal(result.transaction.status, 'preview'); assert.equal(result.transaction.candidate_validation.passed, true); });
assert.deepEqual(await readFile(path.join(workspace, 'a.conllu')), valid);
await call('token_lemma_set', { ...base, token_ref: { tree_ref: { file_path: 'a.conllu', sent_id: 'one' }, token_id: '1' }, lemma: 'hello', edit_options: { mode: 'apply', idempotency_key: 'installed-lemma', validation_options: { language_code: 'en', level: 2 } } }, result => { assert.equal(result.transaction.status, 'completed'); });
assert.deepEqual(await readFile(path.join(workspace, 'a.conllu')), Buffer.from(valid.toString().replace('\thi\t', '\thello\t')));
const appliedBytes = await readFile(path.join(workspace, 'a.conllu'));
await call('token_lemma_set', { ...base, token_ref: { tree_ref: { file_path: 'a.conllu', sent_id: 'one' }, token_id: '1' }, lemma: 'hello', edit_options: { mode: 'apply', idempotency_key: 'installed-lemma', validation_options: { language_code: 'en', level: 2 } } }, result => { assert.equal(result.transaction.replayed, true); });
assert.deepEqual(await readFile(path.join(workspace, 'a.conllu')), appliedBytes);
await call('treebank_snapshot', { ...base, output_dir_path: output }, result => { assert.equal(result.status, 'complete'); assert.equal(result.export_transaction.status, 'completed'); });
const expected = await readFile(path.join(workspace, 'a.conllu'));
assert.deepEqual(await readFile(path.join(output, 'a.conllu')), expected);
if (flags['--render-archive']) for (const format of ['png', 'pdf']) {
  await call('sentence_render', { ...base, sentence_conllu: valid.toString(), output_format: format, output_path: path.join(output, `sentence.${format}`) }, result => { assert.equal(result.export_transaction.status, 'completed'); });
  const data = await readFile(path.join(output, `sentence.${format}`));
  assert.ok(format === 'png' ? data.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')) : data.subarray(0, 5).equals(Buffer.from('%PDF-')));
}
const report = { schema_version: 1, kind: 'diagnostic-installed-workflows', source: createHash('sha256').update(await readFile(path.join(installation, 'coordinator.mjs'))).digest('hex'), platform: process.platform, architecture: process.arch, provider: 'native-userspace', installer: flags['--installer'], profile, rows, status: 'passed', limitations: ['This diagnostic build is not final candidate certification.'] };
await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
process.stdout.write(JSON.stringify({ status: 'passed', report: reportPath, operations: rows.map(row => row.operation) }) + '\n');

} finally {
  let cleanupError;
  try { storage.cleanup(); } catch (error) { cleanupError = error; }
  const retained = await readFile(reportPath).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  if (retained !== null) {
    const report = JSON.parse(retained); report.scratch_cleanup = cleanupError ? 'failed' : 'verified';
    if (cleanupError) { report.status = 'failed-or-incomplete'; report.cleanup_error = cleanupError.message; }
    await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
  }
  if (cleanupError) throw cleanupError;
}
