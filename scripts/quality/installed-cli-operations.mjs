/** Actual installed CLI execution using the independent domain fixtures. MIT. */
import assert from 'node:assert/strict';
import { realpathSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { startOwned } from '../../evals/local/process.mjs';
import { privateEnvironment } from '../../evals/local/preparation.mjs';
import { selectedDockerEnvironment } from '../../evals/local/container.mjs';
import { cleanupObservation } from '../../evals/local/lifecycle.mjs';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

export function completeInstalledCases(inventory, domain, environment, { engine = 'docker' } = {}) {
  assert.equal(inventory.schema_version, 1); assert.equal(inventory.cases.length, 102);
  assert.equal(domain.length, 102); assert.equal(environment.length, 2);
  assert.deepEqual(inventory.cases.map(row => row.operation).sort(), domain.map(row => row.name).sort());
  assert.deepEqual(environment.map(row => row.name).sort(), ['check_ud_environment', 'setup_ud_environment']);
  const common = { files: [], prerequisites: [], expected_artifacts: [] };
  return [
    { ...common, operation: 'setup_ud_environment', arguments: { working_tree_path: '${WORKSPACE}', engine, required_tools: ['validation_report', 'sentence_render'], network: 'offline' }, expected_fields: { ready: true, 'runtime.engine': engine } },
    { ...common, operation: 'check_ud_environment', arguments: { working_tree_path: '${WORKSPACE}', engine, required_tools: ['validation_report', 'sentence_render'], offline: true }, expected_fields: { ready: true, 'runtime.engine': engine } },
    ...inventory.cases,
  ];
}
export function installedCliContext({ root, installation, entry, home, stateRoot, engine = 'docker', searchPath = process.env.PATH ?? '', dockerEnvironment = selectedDockerEnvironment }) {
  assert.ok(path.isAbsolute(entry), '--entry must select the actual installed CLI explicitly.');
  const executable = realpathSync(entry); assert.ok(executable.startsWith(realpathSync(installation) + path.sep), 'CLI entry escapes the installed candidate.');
  const expected = process.platform === 'darwin' ? path.join(home, 'Library/Application Support/ud-agent/userspace') : process.platform === 'win32' ? path.join(home, 'ud-agent/data/userspace') : path.join(home, 'ud-agent/userspace');
  assert.equal(path.resolve(stateRoot), path.resolve(expected), '--state-root must equal the private CLI profile state, without global configuration.');
  const environment = { ...privateEnvironment(root, home), USERPROFILE: home, LOCALAPPDATA: home, PATH: searchPath, XDG_DATA_HOME: home, ...(engine === 'docker' ? dockerEnvironment() : {}) };
  return { command: process.execPath, entry: executable, entry_sha256: digest(readFileSync(executable)), environment,
    resourceStateRoot: expected };
}
export async function executeInstalledCli(context, { operation, input, grants, cwd, timeout = 180_000, start = startOwned }) {
  assert.ok(Number.isSafeInteger(timeout) && timeout > 0 && timeout <= 180_000);
  assert.equal(digest(readFileSync(context.entry)), context.entry_sha256, 'Installed CLI bytes changed before invocation.');
  const args = [context.entry, 'call', operation, '--input', input, ...grants.flatMap(root => ['--allow-root', root])];
  const owned = start(context.command, args, { env: context.environment, cwd, timeout, maximumBytes: 16 * 1024 ** 2 }); owned.child.stdin.end();
  const result = await owned.done;
  assert.equal(digest(readFileSync(context.entry)), context.entry_sha256, 'Installed CLI bytes changed during invocation.');
  const execution = { command: context.command, entry: context.entry, entry_sha256: context.entry_sha256, arguments: args.slice(1), cleanup: cleanupObservation(result),
    stdout_sha256: digest(result.stdout), stderr_sha256: digest(result.stderr), exit_code: result.code };
  assert.equal(result.cleanupVerified, true, JSON.stringify(execution));
  let structuredContent;
  try { structuredContent = JSON.parse(result.stdout); }
  catch (error) { throw Object.assign(new Error('Installed CLI did not return a complete structured result.'), { cause: error, execution }); }
  assert.ok(structuredContent && typeof structuredContent === 'object' && !Array.isArray(structuredContent), 'CLI result must be a structured object.');
  assert.ok([0, 1].includes(result.code) && !result.signal && !result.stop_reason, JSON.stringify(execution));
  return { structuredContent, ...(result.code === 1 ? { isError: true } : {}), cli_execution: execution };
}
export function installedCoverage(registry, rows) {
  const names = registry.map(row => row.name), seen = new Set(rows.map(row => row.operation));
  return { expected: names.length, executed: names.filter(name => seen.has(name)).length, missing: names.filter(name => !seen.has(name)),
    complete: names.length === 104 && names.every(name => seen.has(name)) && rows.length === 104 && rows.every(row => row.status === 'passed'),
    extra: [...seen].filter(name => !names.includes(name)) };
}
