#!/usr/bin/env node
/** Scripted actual installed MCP replay. Never invokes or grades a model. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { captureWorkspace, gradeWorkflow } from './workflow-grader.mjs';
import { loadWorkflowCorpus, substituteWorkflow } from './workflow-corpus.mjs';
import { loadWorkflowHost, workflowHostEntry, workflowProfile, verifyWorkflowCleanup, verifyWorkflowQualification, workflowRuntimeInputOptions, verifyWorkflowRuntimeSubject } from './workflow-host.mjs';
import { verifiedWorkflowResource } from './workflow-resources.mjs';
import { installedMcpLaunch, verifyInstalledPayload } from './installed-payload.mjs';
import { fileReceipt, sha256, sourceReceipt } from '../release/candidate.mjs';
import { closeReleaseInterpreter, verifyReleaseInterpreter, releaseVerifierReceipt } from '../release/verifier-runtime.mjs';
import { localDockerAuthority } from './mutation-scope.mjs';
import { verifyRuntimeInputs } from '../release/runtime-inputs.mjs';
import { seedOfflineProviderAssets, seedOfflineUserspaceAssets, providerQaExecution, withAcceptanceStorage, runAcceptanceCommand } from './native-provider-acceptance.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const argv = process.argv.slice(2), flags = {};
for (let i = 0; i < argv.length; i += 2) {
  const key = argv[i], value = argv[i + 1];
  if (!['--installation', '--host', '--output', '--engine', '--format', '--node', '--installer', '--search-path', '--offline-assets', '--python', '--qualification', '--qa-profile'].includes(key) || !value || value.startsWith('--') || Object.hasOwn(flags, key)) throw new Error('Usage: run-workflow-evals.mjs --installation PATH --host codex|claude|gemini --output NEW_REPORT --engine ENGINE [--format native|npm|coordinator] [--node ABSOLUTE_NODE] [--installer uv|venv --search-path ISOLATED_PATH] [--offline-assets CANDIDATE_ROOT --python EXACT_PYTHON] [--qualification candidate|diagnostic|available-target --qa-profile CLOSED_QA_PROFILE]');
  flags[key] = value;
}
if (!flags['--installation'] || !flags['--host'] || !flags['--output'] || !flags['--engine']) throw new Error('Workflow installation, host, output and explicit engine are required.');
if (!['docker', 'docker-rootless', 'podman', 'apple-container', 'wslc', 'lima-nerdctl', 'userspace'].includes(flags['--engine'])) throw new Error('Unsupported explicit workflow engine.');
if (flags['--installer'] && (flags['--engine'] !== 'userspace' || !['uv', 'venv'].includes(flags['--installer']) || !flags['--search-path'])) throw new Error('A forced userspace installer requires its isolated search path.');
if (flags['--search-path'] && flags['--search-path'].split(path.delimiter).some(value => !path.isAbsolute(value))) throw new Error('Workflow search path entries must be absolute.');
const requestedScope = flags['--qualification'] ?? 'candidate', inputOptions = workflowRuntimeInputOptions(requestedScope);
if (requestedScope === 'available-target' && (!flags['--offline-assets'] || !flags['--python'] || !flags['--qa-profile'])) throw new Error('Available-target workflows require explicit runtime inputs, locked Python and a closed QA profile.');
const qa = flags['--qa-profile'] ? providerQaExecution(path.resolve(flags['--qa-profile'])) : undefined;
const installation = await realpath(flags['--installation']), corpus = loadWorkflowCorpus(root), adapter = loadWorkflowHost(root, flags['--host']);
const payload = verifyInstalledPayload(installation);
const qualification = verifyWorkflowQualification(installation, requestedScope);
const verifierSource = sourceReceipt(root);
if (qualification.acceptance_eligible || qualification.target_execution_eligible) assert.equal(verifierSource.sha256, payload.source_tree_sha256, 'Acceptance driver source must match the frozen candidate source');
await withAcceptanceStorage({root,reportPath:flags['--output'],label:'workflow-evaluation'},async storage=>{
const profile = storage.profile;
const home = path.join(profile, 'home'); await mkdir(home);
const node = await realpath(flags['--node'] ?? process.execPath);
const privateProfile = workflowProfile(home);
const env = { ...privateProfile.env, PATH: flags['--search-path'] ?? process.env.PATH ?? '', TMPDIR: profile, TMP: profile, TEMP: profile, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}), ...(process.env.DOCKER_HOST ? { DOCKER_HOST: process.env.DOCKER_HOST } : {}), ...(process.env.DOCKER_CONTEXT ? { DOCKER_CONTEXT: process.env.DOCKER_CONTEXT } : {}) };
// Existing local engine configuration is read through an explicit path; credentials
// are never copied into the worker or into any fixture workspace.
if (process.env.DOCKER_CONFIG) env.DOCKER_CONFIG = process.env.DOCKER_CONFIG;
if (['docker', 'docker-rootless'].includes(flags['--engine'])) {
  const authority = localDockerAuthority(process.env, context => {
    const result = spawnSync('docker', ['context', 'inspect', ...(context ? [context] : []), '--format', '{{.Endpoints.docker.Host}}'], { encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024 });
    if (result.status !== 0) throw new Error('Cannot inspect the selected local Docker endpoint.');
    return result.stdout.trim();
  });
  env.DOCKER_HOST = authority.endpoint; delete env.DOCKER_CONTEXT;
}
const report = { schema_version: 1, kind: 'installed-scripted-workflow-replay', ...qualification, status: 'incomplete', host: adapter.host, engine: flags['--engine'], profile, payload, inputs: ['evals/cases/workflows.json', `evals/adapters/${adapter.host}.json`, 'scripts/quality/run-workflow-evals.mjs', 'scripts/quality/workflow-grader.mjs', 'scripts/quality/workflow-resources.mjs', 'scripts/quality/workflow-corpus.mjs', 'scripts/quality/workflow-host.mjs'].map(name => fileReceipt(root, name)), scheduled: corpus.replay_cases.map(item => item.id), rows: [], routing: { status: 'pending-external', scheduled: corpus.routing_cases.map(item => item.id), attempts: 0 }, observation_scope: ['actual MCP tool calls/results', 'workspace bytes and modes', 'advertised resource bytes'], limitations: ['No model was invoked; scripted replay does not establish skill routing.', 'OS-level network/process events require separate provider acceptance.'], cleanup: { status: 'pending' } };
report.verifier_source_sha256 = verifierSource.sha256;
if (qa) report.qa_execution = qa;
if (requestedScope === 'available-target') report.limitations.push('Only available candidate/material byte bindings are verified here; full independent source replay, pending platforms, signing and publication remain separate gates.');
const output = path.resolve(flags['--output']);
await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
let cleanupLaunch, offlineRoot, offlineSubject;
function readOfflineInputs(candidateRoot) {
  const python = flags['--python'] ? path.resolve(flags['--python']) : undefined, verifierRuntime = verifyReleaseInterpreter(root, sourceReceipt(root), { python });
  try { report.verifier_runtime = releaseVerifierReceipt(verifierRuntime); return verifyRuntimeInputs(candidateRoot, `${process.platform}-${process.arch}`, { python: python ?? process.env.UD_RELEASE_PYTHON, verifierRuntime, ...inputOptions }); }
  finally { closeReleaseInterpreter(verifierRuntime); }
}
try {
  if (flags['--offline-assets']) {
    if (process.platform === 'win32') env.UD_AGENT_OFFLINE = '1';
    const candidateRoot = await realpath(flags['--offline-assets']), selected = readOfflineInputs(candidateRoot);
    offlineRoot = candidateRoot; offlineSubject = verifyWorkflowRuntimeSubject(selected, payload, requestedScope); Object.assign(report, offlineSubject);
    report.seeding = flags['--engine'] === 'userspace' ? await seedOfflineUserspaceAssets(candidateRoot, selected.candidate, installation, privateProfile.state, { installer: flags['--installer'] ?? 'uv', storage }) : await seedOfflineProviderAssets(candidateRoot, selected.candidate, installation, privateProfile.state, { engine: flags['--engine'], target: `${process.platform}-${process.arch}`, worker: `linux/${process.arch === 'arm64' ? 'arm64' : 'amd64'}` }, storage);
  }
  for (const item of corpus.replay_cases) {
    storage.check();
    const workspace = path.join(profile, item.id); await mkdir(workspace);
    for (const [name, content] of Object.entries(item.files)) {
      const filename = path.join(workspace, name); await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, content, { flag: 'wx' });
    }
    const launch = installedMcpLaunch(installation, workspace, { node, format: flags['--format'] ?? 'native', localAppData: env.LOCALAPPDATA });
    const split = launch.args.indexOf('mcp');
    if (split < 0) throw new Error('Selected entry cannot provide the installed connector.');
    const prefix = launch.args.slice(0, split); cleanupLaunch = { command: launch.command, prefix };
    const connected = await runAcceptanceCommand(launch.command, [...prefix, 'connect', adapter.connect_host, '--working-tree', workspace], { cwd: workspace, env, timeout: 120000, maxBuffer: 4 * 1024 * 1024, storage });
    assert.equal(connected.status, 0, connected.stderr);
    const entry = workflowHostEntry(adapter, workspace, installation, node);
    const before = captureWorkspace(workspace), client = new Client({ name: `ud-eval-${adapter.host}`, version: '1' });storage.setClient(client);
    const transport = new StdioClientTransport({ ...entry, cwd: workspace, env, stderr: 'pipe' });
    const row = { id: item.id, status: 'incomplete', steps: [] }; report.rows.push(row);
    try {
      await client.connect(transport);
      if (transport.stderr) transport.stderr.on('data', chunk => { row.stderr = ((row.stderr ?? '') + chunk.toString()).slice(-1024 * 1024); });
      const listed = await client.listTools(); assert.equal(listed.tools.length, 104);
      const setupStarted = performance.now();
      const setup = await client.callTool({ name: 'setup_ud_environment', arguments: { working_tree_path: workspace, engine: flags['--engine'], required_tools: [...new Set(item.steps.map(step => step.operation))], network: 'offline' } }, { timeout: 300000 });
      assert.equal(setup.structuredContent?.result?.ready, true, JSON.stringify(setup));
      assert.equal(setup.structuredContent.result.runtime.engine, flags['--engine']);
      if (flags['--installer']) assert.equal(setup.structuredContent.result.installer, flags['--installer'], 'Forced installer branch was not executed.');
      row.setup = { elapsed_ms: performance.now() - setupStarted, result: setup.structuredContent.result };
      for (const step of item.steps) {
        storage.check();
        const response = await client.callTool({ name: step.operation, arguments: substituteWorkflow(step.arguments, workspace) }, { timeout: 300000 });
        const observed = { operation: step.operation, response }; row.steps.push(observed);
        const outcome = response.structuredContent; assert.ok(outcome, 'Structured result missing');
        const references = outcome.artifacts ?? [], resources = [];
        for (const reference of references) { const bytes = await verifiedWorkflowResource(client, reference); resources.push({ uri: reference.uri, sha256: sha256(bytes), size_bytes: bytes.length }); }
        const expected = { ...step.expected, artifacts: [], required_tools: [step.operation], allowed_tools: [step.operation], allowed_writes: item.allowed_writes, allow_network: true, allowed_processes: [] };
        const grade = gradeWorkflow({ workspaceRoot: workspace, artifactRoot: workspace, before, observation: { source: 'mcp-client', complete: true, events: [{ type: 'tool_call', name: step.operation }] }, outcome: { ...outcome, artifacts: [] }, expected });
        Object.assign(observed, { grade, resources, execution: outcome.execution, provenance: outcome.provenance });
        assert.equal(grade.passed, true, JSON.stringify(grade.diagnostics));
      }
      for (const [name, content] of Object.entries(item.expected_files)) assert.deepEqual(await readFile(path.join(workspace, name)), Buffer.from(content), `Independent output differs: ${name}`);
      row.status = 'passed';
    } catch (error) { row.status = 'failed'; row.reason = String(error); }
    finally { try { await client.close(); } finally { storage.setClient(undefined); await rm(workspace,{recursive:true,force:true}); } }
    storage.check();
    await writeFile(output, JSON.stringify(report, null, 2) + '\n');
  }
} catch (error) { report.error = String(error); }
finally {
  storage.beginCleanup();
  if (cleanupLaunch) {
    try { const removed = await runAcceptanceCommand(cleanupLaunch.command, [...cleanupLaunch.prefix, 'uninstall', '--owned-runtime', '--engine', flags['--engine']], { env, timeout: 300000, maxBuffer: 4 * 1024 * 1024, storage });
      report.cleanup = { status: 'failed', exit_code: removed.status, stdout: removed.stdout, stderr: removed.stderr };
      assert.equal(removed.status, 0, removed.stderr); verifyWorkflowCleanup(JSON.parse(removed.stdout), flags['--engine']); report.cleanup.status = 'owned-runtime-uninstalled'; }
    catch (error) { report.cleanup.status = 'failed'; report.cleanup.reason = String(error); }
  }
  try { assert.deepEqual(verifyInstalledPayload(installation), payload); report.candidate_unchanged = true; }
  catch (error) { report.error = String(error); report.candidate_unchanged = false; }
  if (offlineRoot && offlineSubject) try { assert.deepEqual(verifyWorkflowRuntimeSubject(readOfflineInputs(offlineRoot), payload, requestedScope), offlineSubject); report.offline_inputs_unchanged = true; }
  catch (error) { report.error = String(error); report.offline_inputs_unchanged = false; }
  if (qa) try { assert.deepEqual(providerQaExecution(qa.profile_root), qa); report.qa_execution_unchanged = true; }
  catch (error) { report.error = String(error); report.qa_execution_unchanged = false; }
  report.verifier_source_unchanged = sourceReceipt(root).sha256 === verifierSource.sha256;
  if ((qualification.acceptance_eligible || qualification.target_execution_eligible) && !report.verifier_source_unchanged) report.error = 'Verifier source changed during acceptance';
  report.status = !report.error && report.candidate_unchanged && report.cleanup.status === 'owned-runtime-uninstalled' && report.rows.length === report.scheduled.length && report.rows.every(item => item.status === 'passed') ? (requestedScope === 'available-target' ? 'passed-available-target-scripted-replay' : qualification.acceptance_eligible ? 'passed-scripted-replay' : 'passed-diagnostic-scripted-replay') : 'failed-or-incomplete';
  await writeFile(output, JSON.stringify(report, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ status: report.status, report: output, profile }) + '\n');
if (!['passed-scripted-replay', 'passed-diagnostic-scripted-replay', 'passed-available-target-scripted-replay'].includes(report.status)) process.exitCode = 1;
});
