/** Native private-profile catalog/payload fixture; no model or network access. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, sha256, sourceReceipt } from '../release/candidate.mjs';

const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--codex' || args[2] !== '--output') throw new Error('Usage: codex-native-smoke.mjs --codex PINNED_BINARY --output NEW_REPORT');
const root = process.cwd(), binary = path.resolve(args[1]), output = path.resolve(args[3]);
if (existsSync(output)) throw new Error('Host fixture evidence requires a new output path.');
const lock = JSON.parse(readFileSync('quality/host-harnesses.lock.json', 'utf8')).codex;
const platform = lock.platforms[`${process.platform}/${process.arch}`];
assert.ok(platform, 'This native host has no frozen Codex executable receipt.');
assert.equal(process.platform, 'darwin', 'This fixture requires the actual macOS deny-network sandbox.');
const info = lstatSync(binary), binaryBytes = readFileSync(binary);
assert.ok(info.isFile() && !info.isSymbolicLink());
assert.equal(info.size, platform.size_bytes); assert.equal(sha256(binaryBytes), platform.executable_sha256);
const snapshot = sourceReceipt(root), catalog = JSON.parse(readFileSync('packaging/codex/marketplace.json', 'utf8'));
const plugin = JSON.parse(readFileSync('plugin.json', 'utf8')), npmSource = catalog.plugins[0].source;
assert.equal(catalog.name, 'ud-agent-skill-mcp-plugin'); assert.equal(plugin.name, catalog.plugins[0].name);
assert.deepEqual(npmSource, { source: 'npm', package: '@mehmetoguzderin/ud-agent-skill-mcp-plugin', version: '0.1.0-beta.1' });
const skillNames = ['ud-compare', 'ud-edit', 'ud-investigate', 'ud-release', 'ud-rules-docs', 'ud-validate'];
const inputs = ['packaging/codex/marketplace.json', 'plugin.json', '.mcp.json', ...skillNames.map(name => `skills/${name}/SKILL.md`)].map(name => fileReceipt(root, name));
mkdirSync(path.dirname(output), { recursive: true });
const temporary = mkdtempSync(path.join(path.dirname(output), 'codex-native-')), identity = lstatSync(temporary);
const home = path.join(temporary, 'home'), codexHome = path.join(home, 'codex'), published = path.join(temporary, 'published-catalog'), local = path.join(temporary, 'local-catalog');
for (const directory of [home, codexHome, path.join(published, '.claude-plugin'), path.join(local, '.claude-plugin')]) mkdirSync(directory, { recursive: true, mode: 0o700 });
writeFileSync(path.join(published, '.claude-plugin/marketplace.json'), JSON.stringify(catalog));
const localCatalog = structuredClone(catalog); localCatalog.plugins[0].source = { source: 'local', path: './plugin' };
writeFileSync(path.join(local, '.claude-plugin/marketplace.json'), JSON.stringify(localCatalog));
const payload = path.join(local, 'plugin'); mkdirSync(payload);
for (const filename of ['plugin.json', '.mcp.json']) cpSync(path.join(root, filename), path.join(payload, filename));
cpSync(path.join(root, 'skills'), path.join(payload, 'skills'), { recursive: true });
const policy = '(version 1) (allow default) (deny network*)', sandbox = '/usr/bin/sandbox-exec';
const report = { schema_version: 1, qualification: 'native-host-local-install-fixture-not-published-npm-fetch', status: 'failed', source_tree_sha256: snapshot.sha256, inputs,
  host: { os: process.platform, architecture: process.arch }, harness: { name: 'codex', version: lock.version, sha256: platform.executable_sha256 },
  containment: { provider: 'macOS sandbox-exec', executable_sha256: sha256(readFileSync(sandbox)), network_policy: policy, network_policy_sha256: sha256(policy) },
  model_requests: false, remote_publication: false, actual_published_npm_fetch: false, profile: temporary, commands: [] };
const env = { PATH: '/usr/bin:/bin', HOME: home, CODEX_HOME: codexHome, LANG: 'en_US.UTF-8' };
function run(arguments_) {
  const result = spawnSync(sandbox, ['-p', policy, binary, ...arguments_], { cwd: home, env, encoding: 'utf8', timeout: 45_000, maxBuffer: 4 * 1024 * 1024 });
  report.commands.push({ arguments: arguments_, status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr, error: result.error?.message ?? null });
  assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}
try {
  assert.equal(run(['--version']).trim(), 'codex-cli ' + lock.version);
  const id = plugin.name + '@' + catalog.name;
  assert.equal(JSON.parse(run(['plugin', 'marketplace', 'add', published, '--json'])).marketplaceName, catalog.name);
  const available = JSON.parse(run(['plugin', 'list', '--marketplace', catalog.name, '--available', '--json']));
  assert.deepEqual(available.installed, []); assert.equal(available.available.length, 1); assert.deepEqual(available.available[0].source, npmSource);
  run(['plugin', 'marketplace', 'remove', catalog.name, '--json']);
  run(['plugin', 'marketplace', 'add', local, '--json']);
  const installed = JSON.parse(run(['plugin', 'add', id, '--json']));
  assert.equal(installed.pluginId, id); assert.equal(installed.version, plugin.version);
  const installedPath = path.join(codexHome, 'plugins/cache', catalog.name, plugin.name, plugin.version);
  assert.equal(installed.installedPath, installedPath); assert.equal(lstatSync(installedPath).isSymbolicLink(), false);
  for (const filename of ['plugin.json', '.mcp.json']) assert.deepEqual(readFileSync(path.join(installedPath, filename)), readFileSync(path.join(payload, filename)));
  assert.deepEqual(readdirSync(path.join(installedPath, 'skills')).sort(), skillNames);
  for (const name of skillNames) assert.deepEqual(readFileSync(path.join(installedPath, 'skills', name, 'SKILL.md')), readFileSync(path.join(payload, 'skills', name, 'SKILL.md')));
  const listed = JSON.parse(run(['plugin', 'list', '--marketplace', catalog.name, '--json']));
  assert.equal(listed.installed.length, 1); assert.equal(listed.installed[0].pluginId, id); assert.equal(listed.installed[0].enabled, true);
  assert.equal(JSON.parse(run(['plugin', 'add', id, '--json'])).installedPath, installedPath);
  assert.equal(JSON.parse(run(['plugin', 'remove', id, '--json'])).pluginId, id); assert.equal(existsSync(installedPath), false);
  assert.deepEqual(JSON.parse(run(['plugin', 'list', '--marketplace', catalog.name, '--json'])).installed, []);
  run(['plugin', 'marketplace', 'remove', catalog.name, '--json']);
  for (const input of inputs) assert.deepEqual(fileReceipt(root, input.path), input, 'Selected fixture inputs changed during host acceptance.');
  assert.equal(sha256(readFileSync(binary)), platform.executable_sha256);
  report.status = 'passed'; report.installed_payload = { skills: 6, mcp_servers: 1, enabled: true, reused_install: true, uninstall_cache_removed: true };
} catch (error) { report.error = String(error); process.exitCode = 1; }
finally {
  const current = lstatSync(temporary);
  assert.ok(current.isDirectory() && !current.isSymbolicLink() && current.dev === identity.dev && current.ino === identity.ino, 'Fixture profile root changed; cleanup requires recovery.');
  rmSync(temporary, { recursive: true }); report.cleanup = { status: 'removed-owned-profile', device: String(identity.dev), inode: String(identity.ino) };
}
writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ status: report.status, qualification: report.qualification, evidence: output }));
