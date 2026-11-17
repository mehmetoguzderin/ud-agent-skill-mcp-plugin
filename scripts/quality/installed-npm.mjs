/** Install one already verified local npm artifact; never rebuild or fetch it. */
import assert from 'node:assert/strict';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileReceipt, readRecordedBytes, sha256 } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
import { npmManifestFromTarball } from '../release/npm-package.mjs';
import { verifyInstalledPayload } from './installed-payload.mjs';

const PACKAGE = '@mehmetoguzderin/ud-agent-skill-mcp-plugin';
function ordinaryTree(root) {
  const files = [], links = []; let size = 0;
  function walk(directory, prefix = '') {
    for (const name of readdirSync(directory).sort()) {
      const relative = prefix + name, file = path.join(directory, name), info = lstatSync(file);
      if (info.isSymbolicLink()) { const target = readlinkSync(file), resolved = realpathSync(file); assert.ok(!path.isAbsolute(target) && !target.includes('\\') && resolved.startsWith(root + path.sep), 'npm tool link escapes its exact closure'); links.push({ path: relative, target }); }
      else if (info.isDirectory()) walk(file, relative + '/');
      else { assert.ok(info.isFile() && files.length < 50000, 'npm tool closure is not ordinary or bounded'); size += info.size; assert.ok(size <= 256 * 1024 ** 2, 'npm tool closure exceeds its bound'); files.push(fileReceipt(root, relative)); }
    }
  }
  walk(root); assert.ok(files.length + links.length <= 50000, 'npm tool closure exceeds its file bound'); return { files, links };
}

/** @param {{node?: string, npmCli?: string}} [options] */
export function npmInstallationToolchain({ node = process.execPath, npmCli } = {}) {
  assert.ok(path.isAbsolute(node) && (npmCli === undefined || path.isAbsolute(npmCli)), 'npm installation requires absolute tool paths');
  node = realpathSync(node);
  if (npmCli === undefined) {
    const candidates = [path.resolve(path.dirname(node), '../lib/node_modules/npm/bin/npm-cli.js'), path.join(path.dirname(node), 'node_modules/npm/bin/npm-cli.js')];
    npmCli = candidates.find(file => existsSync(file));
    assert.ok(npmCli, 'Explicit npm CLI is required when the selected Node distribution has no npm');
  }
  npmCli = realpathSync(npmCli);
  const root = path.dirname(path.dirname(npmCli));
  assert.equal(path.relative(root, npmCli), path.join('bin', 'npm-cli.js'), 'Only the npm package CLI is supported');
  const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.name, 'npm'); assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  const executable = fileReceipt(path.dirname(node), path.basename(node));
  assert.ok(process.platform === 'win32' || executable.executable, 'Selected npm Node is not executable');
  const inventory = ordinaryTree(root);
  return { node, npmCli, root, node_receipt: executable, npm_version: manifest.version, files: inventory.files, links: inventory.links, inventory_sha256: sha256(Buffer.from(canonicalJson(inventory))) };
}

/** The consumer performs an actual offline npm install into its new private profile. */
export function installNpmPayload(candidateRoot, item, privateRoot, options = {}) {
  const bytes = readRecordedBytes(candidateRoot, item.artifact, 128 * 1024 ** 2), manifest = npmManifestFromTarball(bytes);
  assert.equal(manifest.name, PACKAGE); assert.equal(manifest.version, '0.1.0-beta.1');
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies']) assert.ok(manifest[key] === undefined || typeof manifest[key] === 'object' && manifest[key] !== null && Object.keys(manifest[key]).length === 0, 'The bundled npm product must not install dependency packages');
  const tool = npmInstallationToolchain(options);
  assert.ok(path.isAbsolute(privateRoot) && !existsSync(privateRoot), 'npm installation requires a new absolute private prefix');
  mkdirSync(privateRoot, { mode: 0o700 });
  const artifact = path.join(privateRoot, 'verified-package.tgz');
  writeFileSync(artifact, bytes, { flag: 'wx', mode: 0o400 });
  for (const name of ['home', 'cache']) mkdirSync(path.join(privateRoot, name), { mode: 0o700 });
  for (const name of ['user.npmrc', 'global.npmrc']) writeFileSync(path.join(privateRoot, name), '', { flag: 'wx', mode: 0o600 });
  const env = { PATH: path.dirname(tool.node), HOME: path.join(privateRoot, 'home'), USERPROFILE: path.join(privateRoot, 'home'), TMPDIR: privateRoot, TMP: privateRoot, TEMP: privateRoot, LANG: 'C', LC_ALL: 'C', CI: 'true', npm_config_cache: path.join(privateRoot, 'cache'), npm_config_userconfig: path.join(privateRoot, 'user.npmrc'), npm_config_globalconfig: path.join(privateRoot, 'global.npmrc'), npm_config_update_notifier: 'false', ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
  const invoke = args => spawnSync(tool.node, [tool.npmCli, ...args], { cwd: privateRoot, env, encoding: 'utf8', timeout: 300000, maxBuffer: 4 * 1024 ** 2 });
  const nodeVersion = spawnSync(tool.node, ['--version'], { cwd: privateRoot, env, encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  assert.equal(nodeVersion.error, undefined); assert.equal(nodeVersion.signal, null); assert.equal(nodeVersion.status, 0, nodeVersion.stderr); assert.match(nodeVersion.stdout.trim(), /^v(?:24|25|26)\.\d+\.\d+$/);
  const version = invoke(['--version']); assert.equal(version.error, undefined); assert.equal(version.signal, null); assert.equal(version.status, 0, version.stderr); assert.equal(version.stdout.trim(), tool.npm_version);
  const args = ['install', '--prefix', privateRoot, '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--no-progress', '--package-lock=false', '--save=false', '--bin-links=false', artifact];
  const result = invoke(args);
  writeFileSync(path.join(privateRoot, 'install.log'), JSON.stringify({ status: result.status, signal: result.signal, error: result.error?.message, stdout: result.stdout, stderr: result.stderr }, null, 2) + '\n', { flag: 'wx' });
  assert.equal(result.error, undefined, result.stderr); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
  const root = path.join(privateRoot, 'node_modules', ...PACKAGE.split('/')), installed = verifyInstalledPayload(root);
  assert.equal(installed.kind, 'npm'); assert.equal(installed.platform, 'all');
  if (item.root !== undefined) assert.deepEqual(installed, verifyInstalledPayload(path.join(candidateRoot, item.root)), 'Actual npm installation differs from the verified candidate package');
  else {
    assert.equal(installed.inventory_sha256,item.inventory_sha256,'Actual npm installation differs from the verified archive inventory');
    assert.equal(fileReceipt(root,'BUILD-RECEIPT.json').sha256,item.build_receipt_sha256,'Actual npm installation differs from the verified archive build receipt');
    assert.equal(installed.source_tree_sha256,item.source_sha256); assert.equal(installed.runtime_lock_sha256,item.runtime_lock_sha256);
  }
  const after = npmInstallationToolchain({ node: tool.node, npmCli: tool.npmCli });
  assert.equal(after.inventory_sha256, tool.inventory_sha256, 'npm tool closure changed during installation'); assert.deepEqual(after.node_receipt, tool.node_receipt, 'npm Node changed during installation');
  assert.deepEqual(readRecordedBytes(candidateRoot, item.artifact, bytes.length), bytes, 'Original npm archive changed during installation');
  const receipt = { schema_version: 1, qualification: 'actual-offline-local-npm-installation-not-published-registry-fetch', package: { name: manifest.name, version: manifest.version }, artifact: item.artifact, command: [tool.node, tool.npmCli, ...args], environment: env, node: { ...tool.node_receipt, path: tool.node, version: nodeVersion.stdout.trim() }, npm: { cli: tool.npmCli, version: tool.npm_version, inventory_sha256: tool.inventory_sha256, files: tool.files.length, links: tool.links.length }, status: 0, network: 'offline', lifecycle_scripts: false, installed_root: root, payload: installed, install_log_sha256: sha256(readFileSync(path.join(privateRoot, 'install.log'))) };
  writeFileSync(path.join(privateRoot, 'installation-receipt.json'), JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
  return { root, node: tool.node, receipt };
}
