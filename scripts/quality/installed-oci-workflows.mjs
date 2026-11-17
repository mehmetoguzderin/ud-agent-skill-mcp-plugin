#!/usr/bin/env node
/** Diagnostic installed execution; final packages must repeat these checks. */
import assert from 'node:assert/strict';
import { reserveStorage, STORAGE_LIMITS } from './storage-lifecycle.mjs';
import { createHash } from 'node:crypto';
import { copyFile, cp, link, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const source = await realpath('.'), hash = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const flags = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => index % 2 ? pairs : [...pairs, [value, all[index + 1]]], []));
if (!flags['--worker-receipt'] || !flags['--context']) throw new Error('--worker-receipt PATH --context PATH are required.');
const storageRoot = path.resolve(process.env.UD_AGENT_STORAGE_ROOT ?? process.cwd());
const storage = reserveStorage({ root: storageRoot, plannedBytes: STORAGE_LIMITS.ordinaryBytes, label: 'ud-installed-oci' });
const profile = storage.directory;
const reportPath = path.resolve(flags['--report'] ?? path.join(storageRoot, '.artifacts/installed-reports', path.basename(profile) + '.json'));
assert.ok(reportPath !== profile && !reportPath.startsWith(profile + path.sep), 'Installed evidence must be outside disposable scratch.');
await mkdir(path.dirname(reportPath), { recursive: true, mode: 0o700 });
try {
const installation = path.join(profile, 'installation');
await mkdir(path.join(installation, 'runtime/images'), { recursive: true });
await cp(path.join(source, 'contracts'), path.join(installation, 'contracts'), { recursive: true });
const receipt = JSON.parse(await readFile(flags['--worker-receipt'], 'utf8'));
const context = JSON.parse(await readFile(flags['--context'], 'utf8'));
const lock = { schema_version: 1, format_revision: receipt.deferred_platforms?.length ? 1 : 2, product_version: '0.1.0-beta.1', state: 'frozen', native_helpers: {}, packs: receipt.packs };
for (const pack of Object.values(lock.packs)) {
  pack.context_sha256 = `sha256:${context.context_sha256}`;
  for (const transport of [...Object.values(pack.images).flatMap(image => image.transports), pack.index_transport]) {
    const original = path.resolve(source, transport.path), destination = `runtime/images/${path.basename(original)}`;
    try { await link(original, path.join(installation, destination)); } catch (error) { if (error.code === 'EXDEV') await copyFile(original, path.join(installation, destination)); else throw error; }
    transport.path = destination;
  }
}
const guardRelative = `runtime/helpers/${process.platform}/${process.arch}/ud-agent-guard${process.platform === 'win32' ? '.exe' : ''}`;
await mkdir(path.dirname(path.join(installation, guardRelative)), { recursive: true });
let guard = path.join(source, 'target/debug', process.platform === 'win32' ? 'ud-agent-guard.exe' : 'ud-agent-guard');
let guardReceiptSha;
let helperBuild = { profile: 'debug', qualification: 'diagnostic helper; not production performance evidence' };
if (flags['--native-receipt']) {
  const native = JSON.parse(await readFile(flags['--native-receipt'], 'utf8'));
  async function inputs(directory) {
    const files = [];
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory()) files.push(...await inputs(filename));
      else { assert.ok(entry.isFile(), 'Native source contains an unbound alias.'); files.push(filename); }
    }
    return files;
  }
  const sources = [path.join(source, 'Cargo.toml'), path.join(source, 'Cargo.lock'), ...await inputs(path.join(source, 'packages/launcher'))].sort();
  const identity = createHash('sha256');
  for (const filename of sources) identity.update(path.relative(source, filename)).update('\0').update(await readFile(filename)).update('\0');
  assert.equal(native.schema_version, 1); assert.equal(native.source_sha256, identity.digest('hex'), 'Native build receipt is stale.');
  const helper = native.platforms?.[`${process.platform}-${process.arch}`]?.['ud-agent-guard'];
  assert.match(helper?.sha256 ?? '', /^[0-9a-f]{64}$/); assert.ok(typeof helper.path === 'string' && !path.isAbsolute(helper.path) && !helper.path.split(/[\\/]/).some(part => ['', '.', '..'].includes(part)));
  guard = path.join(source, helper.path); assert.equal(await realpath(guard), guard);
  guardReceiptSha = `sha256:${helper.sha256}`; assert.equal(hash(await readFile(guard)), guardReceiptSha);
  helperBuild = { profile: 'optimized', qualification: 'source-bound cross-build; runtime acceptance recorded by this diagnostic separately', source_sha256: native.source_sha256, receipt_sha256: hash(await readFile(flags['--native-receipt'])) };
}
await copyFile(guard, path.join(installation, guardRelative));
const bytes = await readFile(path.join(installation, guardRelative)); if (guardReceiptSha) assert.equal(hash(bytes), guardReceiptSha, 'Native helper changed during installation.'); lock.native_helpers[`${process.platform}/${process.arch}`] = { guard: { path: guardRelative, sha256: hash(bytes), size_bytes: bytes.length } };
const policy = await readFile(path.join(source, 'runtime/policies/render-seccomp.json'));
await mkdir(path.join(installation, 'runtime/policies')); await writeFile(path.join(installation, 'runtime/policies/render-seccomp.json'), policy);
lock.packs.render.seccomp_profile = { path: 'runtime/policies/render-seccomp.json', sha256: hash(policy), size_bytes: policy.length };
await writeFile(path.join(installation, 'runtime/runtime.lock.json'), JSON.stringify(lock) + '\n');
await build({ entryPoints: ['packages/coordinator/src/operations.ts'], bundle: true, platform: 'node', mainFields: ['module', 'main'], format: 'esm', banner: { js: "import { createRequire as __udCreateRequire } from 'node:module'; const require = __udCreateRequire(import.meta.url);" }, outfile: path.join(installation, 'coordinator.mjs') });
const { executeOperation } = await import(pathToFileURL(path.join(installation, 'coordinator.mjs')).href);
const domain = JSON.parse(await readFile(path.join(installation, 'contracts/ud-interfaces.json'), 'utf8'));
const environment = JSON.parse(await readFile(path.join(installation, 'contracts/environment.json'), 'utf8'));
const workspace = path.join(profile, 'workspace'), output = path.join(profile, 'exports'); await mkdir(workspace); await mkdir(output);
const sample = '# sent_id = one\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n';
await writeFile(path.join(workspace, 'a.conllu'), sample);
const options = { sourceRoot: installation, userspaceStateRoot: path.join(profile, 'state'), allowedRoots: [workspace, output], autoSetup: true, setupNetwork: 'offline' };
const rows = [], base = { working_tree_path: workspace, ud_context_path: '' };
async function call(name, args, expected) {
  storage.check();
  const contract = [...domain, ...environment].find(item => item.name === name); assert.ok(contract);
  const start = performance.now(), response = await executeOperation(contract, args, domain, options);
  assert.equal(response.isError, undefined, JSON.stringify(response)); expected(response.structuredContent.result);
  storage.check();
  rows.push({ operation: name, elapsed_ms: performance.now() - start, execution: response.structuredContent.execution, provenance: response.structuredContent.provenance }); return response.structuredContent.result;
}
await call('validation_report', { ...base, file_paths: ['a.conllu'], options: { language_code: 'en', level: 2 } }, result => assert.equal(result.passed, true));
assert.equal(await readFile(path.join(workspace, 'a.conllu'), 'utf8'), sample);
await call('token_lemma_set', { ...base, token_ref: { tree_ref: { file_path: 'a.conllu', sent_id: 'one' }, token_id: '1' }, lemma: 'hello', edit_options: { mode: 'apply', idempotency_key: 'oci-lemma', validation_options: { language_code: 'en', level: 2 } } }, result => assert.equal(result.transaction.status, 'completed'));
assert.equal(await readFile(path.join(workspace, 'a.conllu'), 'utf8'), sample.replace('\thi\t', '\thello\t'));
await call('token_lemma_set', { ...base, token_ref: { tree_ref: { file_path: 'a.conllu', sent_id: 'one' }, token_id: '1' }, lemma: 'hello', edit_options: { mode: 'apply', idempotency_key: 'oci-lemma', validation_options: { language_code: 'en', level: 2 } } }, result => { assert.equal(result.replayed, true); assert.equal(result.transaction.status, 'completed'); });
const edited = sample.replace('\thi\t', '\thello\t'), planned = edited.replace('\thello\t', '\thowdy\t');
await writeFile(path.join(workspace, 'plan.json'), JSON.stringify({ schema_version: 'ud-plan-v1', actions: [{ id: 'lemma', type: 'replace_file', file_path: 'a.conllu', before_sha256: hash(edited).slice(7), after_sha256: hash(planned).slice(7), content: planned, depends_on: [] }] }));
await call('plan_apply', { working_tree_path: workspace, plan_path: 'plan.json', selected_action_ids: ['lemma'], options: { mode: 'apply', idempotency_key: 'oci-plan', validation_options: { language_code: 'en', level: 2 } } }, result => { assert.equal(result.transaction.status, 'completed'); assert.equal(result.validation.passed, true); });
assert.equal(await readFile(path.join(workspace, 'a.conllu'), 'utf8'), planned);
await writeFile(path.join(workspace, 'b.conllu'), planned);
const projectCode = `from udtools import Validator\nfrom udtools.state import State\nimport os\nclass Project(Validator):\n def validate_files(self, files):\n  if os.geteuid() == 0:\n   raise RuntimeError('Unexpected root identity')\n  try:\n   with open(files[0], 'ab') as handle:\n    handle.write(b'unsafe')\n  except OSError:\n   pass\n  else:\n   raise RuntimeError('Input was writable')\n  if os.path.exists('/var/run/docker.sock'):\n   raise RuntimeError('Engine socket was exposed')\n  return State()\n`;
await writeFile(path.join(workspace, 'project.py'), projectCode);
await call('project_consistency_report', { ...base, validator_module_path: 'project.py', validator_class_name: 'Project', options: { language_code: 'en', level: 2 } }, result => {
  assert.equal(result.status, 'complete'); assert.equal(result.passed, false); assert.equal(result.official.passed, false); assert.equal(result.project.passed, true);
  assert.ok(result.official.incidents.some(item => item.testid === 'non-unique-sent-id'));
  assert.equal(result.provenance.project_code.sha256, hash(projectCode).slice(7));
});
assert.equal(await readFile(path.join(workspace, 'a.conllu'), 'utf8'), planned); assert.equal(await readFile(path.join(workspace, 'b.conllu'), 'utf8'), planned);
await rm(path.join(workspace, 'b.conllu'));
await call('treebank_snapshot', { ...base, output_dir_path: output }, result => assert.equal(result.export_transaction.status, 'completed'));
assert.equal(await readFile(path.join(output, 'a.conllu'), 'utf8'), planned);
if (flags['--render'] === 'yes') for (const format of ['png', 'pdf']) {
  await call('sentence_render', { ...base, sentence_conllu: sample, output_format: format, output_path: path.join(output, `sentence.${format}`) }, result => assert.equal(result.export_transaction.status, 'completed'));
  const bytes = await readFile(path.join(output, `sentence.${format}`)); assert.ok(format === 'png' ? bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')) : bytes.subarray(0, 5).equals(Buffer.from('%PDF-')));
}
await writeFile(reportPath, JSON.stringify({ schema_version: 1, kind: 'diagnostic-installed-oci-workflows', status: 'passed', host: { os: process.platform, process_arch: process.arch }, profile, native_helper: { ...helperBuild, sha256: hash(bytes) }, runtime_lock_sha256: hash(await readFile(path.join(installation, 'runtime/runtime.lock.json'))), coordinator_sha256: hash(await readFile(path.join(installation, 'coordinator.mjs'))), rows, limitations: ['Diagnostic installed source; final candidate certification remains separate.'] }, null, 2) + '\n');
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
