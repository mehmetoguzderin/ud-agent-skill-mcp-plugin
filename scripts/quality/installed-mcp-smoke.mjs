#!/usr/bin/env node
/** Actual installed stdio workflows, with local workers and a private host profile. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { installedMcpLaunch, verifyInstalledPayload } from './installed-payload.mjs';
import { localDockerAuthority } from './mutation-scope.mjs';
import { resolveOriginalExecutable } from './test.mjs';
import { workflowProfile } from './workflow-host.mjs';

const flags = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => index % 2 ? pairs : [...pairs, [value, all[index + 1]]], []));
if (!flags['--installation']) throw new Error('--installation PATH is required.');
const installation = await realpath(flags['--installation']);
const payload = verifyInstalledPayload(installation);
const profile = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-installed-mcp-'))), workspace = path.join(profile, 'workspace'), homeDirectory = path.join(profile, 'profile');
await mkdir(workspace); await mkdir(homeDirectory);
const sample = '# sent_id = one\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n';
await writeFile(path.join(workspace, 'a.conllu'), sample);
const windows = process.platform === 'win32';
const executable = await realpath(flags['--node'] ?? process.execPath);
const docker = await realpath(resolveOriginalExecutable(windows ? 'docker.exe' : 'docker'));
const { endpoint } = localDockerAuthority(process.env, context => execFileSync(docker, ['context', 'inspect', ...(context ? [context] : []), '--format', '{{.Endpoints.docker.Host}}'], { encoding: 'utf8' }).trim());
const privateEnvironment = workflowProfile(homeDirectory).env;
if (windows) await mkdir(privateEnvironment.LOCALAPPDATA);
const systemRoot = windows ? process.env.SystemRoot ?? 'C:\\Windows' : undefined;
const systemPaths = systemRoot ? [path.join(systemRoot, 'System32')] : ['/usr/bin', '/bin'];
const environment = { ...privateEnvironment, PATH: [path.dirname(docker), ...systemPaths].join(path.delimiter), LANG: 'C.UTF-8', TMPDIR: profile, TMP: profile, TEMP: profile, ...(systemRoot ? { SystemRoot: systemRoot } : {}) };
const dockerConfiguration = path.join(homeDirectory, '.docker');
execFileSync(docker, ['--config', dockerConfiguration, 'context', 'create', 'ud-local-fixture', '--docker', `host=${endpoint}`], { stdio: 'pipe', env: environment });
execFileSync(docker, ['--config', dockerConfiguration, 'context', 'use', 'ud-local-fixture'], { stdio: 'pipe', env: environment });
const bundleName = flags['--bundle-name'] ?? 'coordinator.mjs';
const launch = installedMcpLaunch(installation, workspace, { format: flags['--format'] ?? 'coordinator', node: executable, bundleName, localAppData: privateEnvironment.LOCALAPPDATA });
const entry = launch.coordinator;
const rows = [];
for (const era of ['modern', 'legacy']) {
  const client = new Client({ name: 'ud-installed-protocol-fixture', version: '1' }, { versionNegotiation: era === 'modern' ? { mode: { pin: '2026-07-28' } } : { mode: 'legacy' } });
  let stderr = '';
  const transport = new StdioClientTransport({ command: launch.command, args: launch.args, env: { ...environment, ...launch.env }, cwd: workspace, stderr: 'pipe' });
  const start = performance.now();
  try {
    if (transport.stderr) transport.stderr.on('data', chunk => { stderr += chunk; });
    await client.connect(transport); assert.equal(client.getProtocolEra(), era);
    const listed = await client.listTools(); assert.equal(listed.tools.length, 104); assert.equal(new Set(listed.tools.map(tool => tool.name)).size, 104);
    const result = await client.callTool({ name: 'validation_report', arguments: { working_tree_path: workspace, file_paths: ['a.conllu'], ud_context_path: '', options: { language_code: 'en', level: 2 } } }, { timeout: 300000 });
    assert.equal(result.isError, undefined, JSON.stringify(result)); assert.equal(result.structuredContent.result.passed, true); assert.equal(result.structuredContent.provenance.runtime, 'docker');
    assert.equal(await readFile(path.join(workspace, 'a.conllu'), 'utf8'), sample);
    const reference = result.structuredContent.result.report_resource, resource = await client.readResource({ uri: reference.uri });
    assert.equal(resource.contents.length, 1); const text = resource.contents[0].text;
    assert.equal(createHash('sha256').update(text).digest('hex'), reference.sha256);
    assert.equal(JSON.parse(text).result.passed, true);
    rows.push({ era, protocol: client.getNegotiatedProtocolVersion(), status: 'passed', elapsed_ms: performance.now() - start, node: execFileSync(launch.node, ['--version'], { encoding: 'utf8' }).trim(), provenance: result.structuredContent.provenance, tools: 104 });
  } catch (error) {
    rows.push({ era, status: 'failed', reason: error.message, stderr });
  } finally { await client.close(); }
}
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.deepEqual(verifyInstalledPayload(installation), payload, 'Installed candidate changed during protocol testing.');
const report = path.join(profile, 'report.json');
await writeFile(report, JSON.stringify({ schema_version: 1, kind: 'diagnostic-installed-mcp-smoke', status: rows.every(row => row.status === 'passed') ? 'passed' : 'failed', profile, payload, format: flags['--format'] ?? 'coordinator', entry: launch.command, coordinator_sha256: sha(await readFile(entry)), runtime_lock_sha256: sha(await readFile(path.join(installation, 'runtime/runtime.lock.json'))), node_sha256: sha(await readFile(launch.node)), rows, limitations: ['Diagnostic installed execution of the unchanged packaged payload; final frozen candidate certification is separate.'] }, null, 2) + '\n');
process.stdout.write(JSON.stringify({ report, rows }) + '\n');
if (rows.some(row => row.status !== 'passed')) process.exitCode = 1;
