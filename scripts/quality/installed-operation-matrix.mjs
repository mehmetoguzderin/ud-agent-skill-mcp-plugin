#!/usr/bin/env node
/** Execute independently authored fixtures through an installed coordinator. */
import assert from 'node:assert/strict';
import { reserveStorage, storageTreeBytes } from './storage-lifecycle.mjs';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import Ajv from 'ajv/dist/2020.js';
import { completeInstalledCases, installedCliContext, executeInstalledCli, installedCoverage } from './installed-cli-operations.mjs';
import { originalDockerBytes } from './original-storage.mjs';

const flags = Object.fromEntries(process.argv.slice(2).reduce((pairs, item, index, all) => index % 2 ? pairs : [...pairs, [item, all[index + 1]]], []));
if (!flags['--installation'] || !flags['--fixtures'] || !flags['--state-root']) throw new Error('--installation PATH --fixtures PATH --state-root PATH are required.');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const installation = await realpath(flags['--installation']), fixtureBytes = await readFile(flags['--fixtures']);
const runtime = flags['--runtime'] ?? 'oci';
const transport = flags['--transport'] ?? 'direct'; assert.ok(['direct', 'cli'].includes(transport), '--transport must be direct or cli.');
assert.ok(['oci', 'userspace'].includes(runtime), '--runtime must be oci or userspace.');
if (runtime === 'userspace') assert.ok(flags['--search-path'], 'Userspace acceptance requires an explicit isolated --search-path.');
const entry = transport === 'cli' ? path.resolve(flags['--entry'] ?? '') : path.join(installation, 'coordinator.mjs');
if (transport === 'cli') assert.ok(flags['--entry'] && flags['--profile-home'], 'CLI execution requires explicit --entry and --profile-home.');
const entryRelative = path.relative(installation, entry); assert.ok(entryRelative && !entryRelative.startsWith('..') && !path.isAbsolute(entryRelative));
const bindings = Object.fromEntries(await Promise.all(['runtime/runtime.lock.json', 'runtime/userspace.lock.json', entryRelative].map(async name => [name, digest(await readFile(path.join(installation, name)).catch(error => { if (name === 'runtime/userspace.lock.json' && runtime === 'oci' && error.code === 'ENOENT') return Buffer.alloc(0); throw error; }))])));
const runnerSha256 = digest(await readFile(new URL(import.meta.url)));
const inventory = JSON.parse(fixtureBytes), domain = JSON.parse(await readFile(path.join(installation, 'contracts/ud-interfaces.json')));
assert.equal(inventory.schema_version, 1); assert.equal(inventory.scheduled_operations, 102); assert.equal(inventory.cases.length, 102);
assert.deepEqual(inventory.cases.map(row => row.operation).sort(), domain.map(row => row.name).sort());
const executeOperation = transport === 'direct' ? (await import(pathToFileURL(entry).href)).executeOperation : undefined;
const storageRoot = path.resolve(process.env.UD_AGENT_STORAGE_ROOT ?? process.cwd());
const environment = JSON.parse(await readFile(path.join(installation, 'contracts/environment.json'))), registry = [...domain, ...environment];
const contractBindings = Object.fromEntries(await Promise.all(['contracts/ud-interfaces.json', 'contracts/environment.json', ...registry.flatMap(row => [`contracts/schema/operations/${row.name}.input.schema.json`, `contracts/schema/results/${row.name}.schema.json`])].map(async name => [name, digest(await readFile(path.join(installation, name)))])));
const helperSha256 = digest(await readFile(new URL('./installed-cli-operations.mjs', import.meta.url)));
const engine = runtime === 'userspace' ? 'userspace' : flags['--engine'] ?? 'docker';
const cases = transport === 'cli' ? completeInstalledCases(inventory, domain, environment, { engine }) : inventory.cases;
const selected = flags['--operations']?.split(',');
if (selected) for (const name of selected) assert.ok((transport === 'cli' ? registry : domain).some(row => row.name === name), `Unknown operation ${name}`);
const scheduled = cases.filter(row => !selected || selected.includes(row.operation));
let workspacePeak = 0;
for (const fixture of scheduled) {
  let size = fixture.files.reduce((sum, file) => { assert.ok(Number.isSafeInteger(file.size_bytes) && file.size_bytes >= 0); return sum + file.size_bytes; }, 0);
  size += (fixture.expected_artifacts ?? []).reduce((sum, artifact) => sum + artifact.size_bytes, 0);
  for (const prerequisite of fixture.prerequisites) {
    assert.equal(prerequisite.type, 'existing_git_repository');
    const original = await realpath(flags['--git-source'] ?? prerequisite.repository_path);
    const metadata = execFileSync('git', ['-C', original, 'rev-parse', '--absolute-git-dir'], { encoding: 'utf8' }).trim();
    size += storageTreeBytes(metadata);
  }
  workspacePeak = Math.max(workspacePeak, size);
}
// Workers already bound resource bytes. Only one fixture workspace survives
// at a time; reserve its inputs/history/expected exports plus transfer headroom.
const home = transport === 'cli' ? path.resolve(flags['--profile-home']) : undefined;
if (home) { assert.ok(home.startsWith(storageRoot + path.sep), 'CLI home must be repository-owned.'); await mkdir(home, { recursive: true, mode: 0o700 }); }
const cli = home ? installedCliContext({ root: storageRoot, installation, entry, home, stateRoot: flags['--state-root'], engine, ...(flags['--search-path'] ? { searchPath: flags['--search-path'] } : {}) }) : undefined;
const storage = reserveStorage({ root: storageRoot, plannedBytes: 256 * 1024 ** 2 + workspacePeak, ...(cli ? { plannedOutputBytes: 1_000_000_000, outputParent: home, outputPath: home, externalOwnedBytes: engine === 'docker' ? originalDockerBytes(storageRoot) : 0 } : {}), label: 'installed-operation-matrix' });
const profile = storage.directory, rows = [];
const reportPath = path.resolve(flags['--report'] ?? path.join(storageRoot, '.artifacts/installed-reports', path.basename(profile) + '-matrix.json'));
assert.ok(reportPath !== profile && !reportPath.startsWith(profile + path.sep), 'Installed evidence must be outside disposable scratch.');
await mkdir(path.dirname(reportPath), { recursive: true, mode: 0o700 });
const ajv = new Ajv({ strict: true, allErrors: true, allowUnionTypes: true });
function substitute(value, workspace, output) {
  if (typeof value === 'string') return value.replaceAll('${WORKSPACE}', workspace).replaceAll('${OUTPUT}', output);
  if (Array.isArray(value)) return value.map(item => substitute(item, workspace, output));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, substitute(item, workspace, output)]));
  return value;
}
function field(value, name) { return name.split('.').reduce((item, key) => item?.[key], value); }
async function save() {
  for (const name of ['runtime/runtime.lock.json', entryRelative]) assert.equal(digest(await readFile(path.join(installation, name))), bindings[name], `Installed bytes changed during execution: ${name}`);
  for (const [name, expected] of Object.entries(contractBindings)) assert.equal(digest(await readFile(path.join(installation, name))), expected, `Installed contracts changed during execution: ${name}`);
  await writeFile(reportPath, JSON.stringify({ schema_version: 1, kind: 'diagnostic-installed-operation-matrix', status: rows.length === scheduled.length && rows.every(row => ['passed', 'capability-rejection-verified'].includes(row.status)) ? 'passed' : 'failed-or-incomplete', runtime, transport, installation, profile, ...(cli ? { private_home: home, cli_entry: entry, operation_coverage: installedCoverage(registry, rows) } : {}), fixture_sha256: digest(fixtureBytes), immutable_bindings: { ...bindings, ...contractBindings }, runner_sha256: runnerSha256, helper_sha256: helperSha256, host: { os: process.platform, process_architecture: process.arch }, full_inventory: cases.map(row => row.operation), scheduled: scheduled.map(row => row.operation), rows, limitations: ['Diagnostic installed execution; final frozen candidate certification is separate.', ...(runtime === 'userspace' ? ['Project-authored validator execution is unsupported in userspace; its explicit rejection is tested separately from successful domain execution.'] : [])] }, null, 2) + '\n');
}
try {
await save();
for (const fixture of scheduled) {
  storage.check(cli ? storageTreeBytes(home) : 0);
  const workspace = path.join(profile, fixture.operation, 'workspace'), output = path.join(profile, fixture.operation, 'output');
  await mkdir(workspace, { recursive: true }); await mkdir(output);
  const started = performance.now(); let response;
  try {
    for (const file of fixture.files) {
      assert.ok(file.path && !file.path.includes('\\') && !path.isAbsolute(file.path) && file.path.split('/').every(part => part && !['.', '..', '.git'].includes(part)));
      const bytes = Buffer.from(file.content_base64, 'base64'); assert.equal(bytes.toString('base64'), file.content_base64); assert.equal(bytes.length, file.size_bytes); assert.equal(digest(bytes), file.sha256);
      const destination = path.join(workspace, ...file.path.split('/')); await mkdir(path.dirname(destination), { recursive: true }); await writeFile(destination, bytes, { flag: 'wx' });
    }
    const args = substitute(fixture.arguments, workspace, output), expected = { ...fixture.expected_fields };
    let history;
    for (const prerequisite of fixture.prerequisites) {
      assert.equal(prerequisite.type, 'existing_git_repository');
      const source = await realpath(flags['--git-source'] ?? prerequisite.repository_path);
      const commit = execFileSync('git', ['-C', source, 'rev-parse', '--verify', '--end-of-options', `${prerequisite.requested_revision}^{commit}`], { encoding: 'utf8' }).trim();
      const tree = execFileSync('git', ['-C', source, 'rev-parse', '--verify', `${commit}^{tree}`], { encoding: 'utf8' }).trim();
      assert.equal(commit, prerequisite.requested_revision); assert.equal(tree, prerequisite.tree_oid);
      const corpus = execFileSync('git', ['-C', source, 'ls-tree', '-r', '-z', '--name-only', commit], { encoding: 'utf8' }).split('\0').filter(name => name.endsWith('.conllu'));
      assert.equal(corpus.length, prerequisite.conllu_files); assert.ok(!corpus.includes('main.conllu'));
      const originalMetadata = execFileSync('git', ['-C', source, 'rev-parse', '--absolute-git-dir'], { encoding: 'utf8' }).trim();
      const metadata = path.join(workspace, '.git'); await cp(originalMetadata, metadata, { recursive: true, dereference: false });
      // Reuse the copied historical HEAD/refs unchanged. Only the fixture's
      // local core configuration changes from a cache to a worktree.
      await writeFile(path.join(metadata, 'config'), '[core]\nrepositoryformatversion = 0\nbare = false\n');
      args.base_revision = commit;
      history = { kind: 'copied-existing-public-history', commit, tree_oid: tree, newly_created_commits: 0, newly_authored_refs: 0, expected_base_corpus_files: corpus.length };
    }
    const inputSchema = ajv.compile(JSON.parse(await readFile(path.join(installation, 'contracts/schema/operations', `${fixture.operation}.input.schema.json`))));
    assert.ok(inputSchema(args), JSON.stringify(inputSchema.errors));
    if (cli) {
      const input = path.join(profile, fixture.operation, 'input.json'); await writeFile(input, JSON.stringify(args) + '\n', { flag: 'wx', mode: 0o600 });
      response = await executeInstalledCli(cli, { operation: fixture.operation, input, grants: [workspace, output], cwd: workspace });
    } else response = await executeOperation(domain.find(row => row.name === fixture.operation), args, domain, { sourceRoot: installation, userspaceStateRoot: path.resolve(flags['--state-root']), allowedRoots: [workspace, output], autoSetup: true, setupNetwork: 'offline', ...(runtime === 'userspace' ? { savedEngine: 'userspace', searchPath: flags['--search-path'] } : {}) });
    await writeFile(path.join(profile, fixture.operation, 'response.json'), JSON.stringify(response, null, 2) + '\n');
    if (runtime === 'userspace' && fixture.operation === 'project_consistency_report') {
      assert.equal(response.isError, true); assert.equal(response.structuredContent.execution.status, 'incomplete');
      assert.equal(response.structuredContent.result.code, 'ENVIRONMENT_NOT_READY');
      assert.equal(response.structuredContent.result.environment.status, 'blocked_by_policy');
      assert.deepEqual(response.structuredContent.result.environment.unsupported_operations, ['project_consistency_report']);
      assert.equal(response.structuredContent.result.environment.runtime.project_code_allowed, false);
      assert.equal(response.structuredContent.provenance.worker, undefined);
      rows.push({ operation: fixture.operation, status: 'capability-rejection-verified', elapsed_ms: performance.now() - started, execution: response.structuredContent.execution, reason: response.structuredContent.result, ...(response.cli_execution ? { cli_execution: response.cli_execution } : {}) });
      await rm(path.join(profile, fixture.operation), { recursive: true });
      await save(); continue;
    }
    assert.equal(response.isError, undefined, JSON.stringify(response));
    const outputSchema = ajv.compile(JSON.parse(await readFile(path.join(installation, 'contracts/schema/results', `${fixture.operation}.schema.json`))));
    assert.ok(outputSchema(response.structuredContent), JSON.stringify(outputSchema.errors));
    const result = response.structuredContent.result;
    if (args.edit_options?.mode === 'preview' || args.options?.mode === 'preview') for (const file of fixture.files) assert.equal(digest(await readFile(path.join(workspace, file.path))), file.sha256, 'Preview changed an input file.');
    for (const [name, value] of Object.entries(expected)) assert.deepEqual(field(result, name), value, `${fixture.operation}: ${name}`);
    for (const artifact of fixture.expected_artifacts ?? []) {
      const reference = result.artifacts?.[artifact.index];
      assert.ok(reference?.uri?.startsWith('ud://artifacts/'));
      const data = await readFile(path.join(`${cli?.resourceStateRoot ?? path.resolve(flags['--state-root'])}-resources`, new URL(reference.uri).pathname.slice(1), 'data'));
      assert.equal(data.length, artifact.size_bytes); assert.equal(digest(data), artifact.sha256); assert.equal(data.toString('base64'), artifact.content_base64);
      const exported = result.exports?.find(item => item.sha256 === artifact.sha256);
      if (exported) assert.deepEqual(await readFile(exported.path), data);
    }
    rows.push({ operation: fixture.operation, status: 'passed', elapsed_ms: performance.now() - started, execution: response.structuredContent.execution, provenance: response.structuredContent.provenance, ...(response.cli_execution ? { cli_execution: response.cli_execution } : {}), ...(history ? { history } : {}) });
    process.stdout.write(`${fixture.operation}: passed\n`);
  } catch (error) {
    rows.push({ operation: fixture.operation, status: 'failed', elapsed_ms: performance.now() - started, reason: error.message, ...(response ? { execution: response.structuredContent?.execution, provenance: response.structuredContent?.provenance, ...(response.cli_execution ? { cli_execution: response.cli_execution } : {}) } : {}), ...(error.execution ? { cli_execution: error.execution } : {}) });
    process.stdout.write(`${fixture.operation}: failed: ${error.message.slice(0, 1000)}\n`);
  }
  await rm(path.join(profile, fixture.operation), { recursive: true });
  storage.check(cli ? storageTreeBytes(home) : 0);
  await save();
}
process.stdout.write(JSON.stringify({ report: reportPath, passed: rows.filter(row => row.status === 'passed').length, capability_rejections_verified: rows.filter(row => row.status === 'capability-rejection-verified').length, failed: rows.filter(row => !['passed', 'capability-rejection-verified'].includes(row.status)).length, scheduled: scheduled.length }) + '\n');
if (rows.some(row => !['passed', 'capability-rejection-verified'].includes(row.status))) process.exitCode = 1;

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
