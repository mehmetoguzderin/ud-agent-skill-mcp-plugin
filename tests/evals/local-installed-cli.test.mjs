/** Installed public CLI inventory/execution mechanics; inert process only. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { existsSync, mkdtempSync, writeFileSync, rmSync, readFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { completeInstalledCases, executeInstalledCli, installedCoverage, installedCliContext } from '../../scripts/quality/installed-cli-operations.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';
test('installed CLI schedule retains102 independent fixtures and explicitly executes both environment operations', () => {
  const domain = Array.from({ length: 102 }, (_, i) => ({ name: 'operation_' + i })), environment = [{ name: 'check_ud_environment' }, { name: 'setup_ud_environment' }];
  const fixtures = { schema_version: 1, cases: domain.map(row => ({ operation: row.name, arguments: { original: true } })) };
  const cases = completeInstalledCases(fixtures, domain, environment); assert.equal(cases.length, 104); assert.deepEqual(cases.slice(2), fixtures.cases);
  assert.equal(cases[0].operation, 'setup_ud_environment'); assert.equal(cases[0].arguments.network, 'offline'); assert.equal(cases[1].operation, 'check_ud_environment'); assert.equal(cases[1].arguments.offline, true);
  const registry = [...domain, ...environment], rows = cases.map(row => ({ operation: row.operation, status: 'passed' }));
  assert.equal(installedCoverage(registry, rows).complete, true); assert.equal(installedCoverage(registry, rows.slice(1)).complete, false);
  assert.equal(installedCoverage(registry, [...rows.slice(1), rows[1]]).complete, false);
  assert.throws(() => completeInstalledCases({ ...fixtures, cases: fixtures.cases.slice(1) }, domain, environment));
});
posixTest('actual separate inert CLI process receives public call/input/grants and records byte-bound release', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-installed-cli-'))), entry = path.join(root, 'cli.mjs'), input = path.join(root, 'input.json');
  writeFileSync(input, '{}'); writeFileSync(entry, "process.stdout.write(JSON.stringify({execution:{status:'completed'},result:{arguments:process.argv.slice(2),private_home:process.env.HOME,ambient:process.env.UD_TEST_SECRET??null}}));");
  try {
    const sha = createHash('sha256').update(readFileSync(entry)).digest('hex');
    const result = await executeInstalledCli({ command: process.execPath, entry, entry_sha256: sha, environment: { HOME: root, PATH: process.env.PATH } }, { operation: 'check_ud_environment', input, grants: [root], cwd: root });
    assert.deepEqual(result.structuredContent.result.arguments, ['call', 'check_ud_environment', '--input', input, '--allow-root', root]); assert.equal(result.structuredContent.result.private_home, root);
    assert.equal(result.cli_execution.cleanup.cleanupVerified, true); assert.equal(result.cli_execution.entry_sha256, sha); assert.equal(result.cli_execution.exit_code, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
if (process.platform === 'win32') test('Windows refuses the POSIX installed-CLI supervisor before dispatch or changing fixture bytes', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-installed-cli-refusal-'))), entry = path.join(root, 'cli.mjs'), input = path.join(root, 'input.json'), started = path.join(root, 'started');
  const bytes = Buffer.from(`import{writeFileSync}from'node:fs';writeFileSync(${JSON.stringify(started)},'dispatched');`);
  writeFileSync(input, '{}'); writeFileSync(entry, bytes);
  try {
    const sha = createHash('sha256').update(bytes).digest('hex');
    await assert.rejects(executeInstalledCli({ command: process.execPath, entry, entry_sha256: sha, environment: { HOME: root } }, { operation: 'check_ud_environment', input, grants: [root], cwd: root }), /OWNED_PROCESS_GROUP_UNSUPPORTED/);
    assert.equal(existsSync(started), false); assert.deepEqual(readFileSync(entry), bytes); assert.equal(readFileSync(input, 'utf8'), '{}');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test('CLI resources use the common grant-scoped state across engines, separate from engine worker state', () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-cli-resource-state-'))), entry = path.join(root, 'cli.mjs'); writeFileSync(entry, '// inert installed entry');
  try {
    const expected = process.platform === 'darwin' ? path.join(root, 'Library/Application Support/ud-agent/userspace') : process.platform === 'win32' ? path.join(root, 'ud-agent/data/userspace') : path.join(root, 'ud-agent/userspace');
    const options = { root, installation: root, entry, home: root, stateRoot: expected, dockerEnvironment: () => ({ DOCKER_HOST: 'unix:///private/inert.sock' }) };
    for (const engine of ['docker', 'userspace']) assert.equal(installedCliContext({ ...options, engine }).resourceStateRoot, expected);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
