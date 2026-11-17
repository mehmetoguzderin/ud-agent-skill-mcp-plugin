/** MIT. Private native-client acquisition; no global package manager mutation. */
import { existsSync, mkdirSync, readFileSync, readdirSync, lstatSync, readlinkSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertOptIn, privateEnvironment, executable, writeNew } from './preparation.mjs';
import { runOwned } from './process.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

export const CLIENT_LOCK = Object.freeze(JSON.parse(readFileSync(new URL('./native-clients.lock.json', import.meta.url))));
export const CLIENT_LOCK_SHA256 = sha256(JSON.stringify(CLIENT_LOCK));
const DEPENDENCIES = JSON.parse(readFileSync(new URL('./native-client-dependencies.lock.json', import.meta.url)));
/** Separate per-client optional dependencies avoid invalidating unrelated pins. */
export function nativeClientDependencyRecipe(id) {
  const recipe = DEPENDENCIES.clients?.[id];
  if (!recipe) return undefined;
  const pin = CLIENT_LOCK.clients.find(client => client.id === id);
  if (DEPENDENCIES.schema_version !== 1 || pin?.manager !== 'uv' || recipe.client_version !== pin.version || !Array.isArray(recipe.packages)
    || recipe.packages.some(value => !/^[a-z0-9-]+$/.test(value.package) || !/^[0-9]+(?:\.[0-9]+)+$/.test(value.version)
      || !/^https:\/\/files\.pythonhosted\.org\/packages\/.+\.whl$/.test(value.url) || !/^[a-f0-9]{64}$/.test(value.sha256))) throw new Error('NATIVE_CLIENT_DEPENDENCY_RECIPE_INVALID');
  return { ...recipe, sha256: sha256(JSON.stringify(recipe)) };
}
export function assertNativeClientDependencyRecipe(id, receipt) {
  const recipe = nativeClientDependencyRecipe(id);
  if (recipe && receipt?.dependency_recipe_sha256 !== recipe.sha256) throw new Error('NATIVE_CLIENT_DEPENDENCY_RECIPE_CHANGED');
}
export function nativeClientRequirements(id) {
  const pin = CLIENT_LOCK.clients.find(client => client.id === id && client.manager === 'uv');
  if (!pin) throw new Error('NATIVE_CLIENT_PYTHON_RECIPE_REQUIRED');
  return [pin, ...(nativeClientDependencyRecipe(id)?.packages ?? [])].map(value => `${value.package} @ ${value.url}#sha256=${value.sha256}\n`).join('');
}
export function nativeClientDependencyCheck(id) {
  const recipe = nativeClientDependencyRecipe(id);
  if (!recipe) return undefined;
  if (id !== 'hermes-agent') throw new Error('NATIVE_CLIENT_DEPENDENCY_CHECK_UNAVAILABLE');
  return 'import importlib.metadata; from mcp import ClientSession, StdioServerParameters; from mcp.client.stdio import stdio_client; '
    + `assert importlib.metadata.version("mcp") == ${JSON.stringify(recipe.packages[0].version)}; print("native MCP transport imports verified")`;
}
export const clientDirectory = (root, id) => path.join(root, '.artifacts/local-evals/clients', id);

function inventory(directory) {
  const files = [];
  function visit(relative) {
    for (const name of readdirSync(path.join(directory, relative)).sort()) {
      if (name === '__pycache__' || name.endsWith('.pyc')) continue;
      const selected = path.posix.join(relative, name), file = path.join(directory, selected), stat = lstatSync(file);
      if (stat.isSymbolicLink()) files.push({ path: selected, link: readlinkSync(file) });
      else if (stat.isDirectory()) visit(selected);
      else if (stat.isFile()) files.push({ path: selected, size: stat.size, sha256: sha256(readFileSync(file)) });
      else throw new Error('NATIVE_CLIENT_SPECIAL_FILE');
    }
  }
  visit(''); return files;
}
export function readPreparedClient(root, id) {
  const base = clientDirectory(root, id), file = path.join(base, 'receipt.json');
  if (!existsSync(file)) return undefined;
  const receipt = JSON.parse(readFileSync(file));
  const pin = CLIENT_LOCK.clients.find(client => client.id === id);
  if (!pin || receipt.schema_version !== 1 || receipt.client_lock_sha256 !== CLIENT_LOCK_SHA256 || receipt.id !== id || receipt.platform !== process.platform || receipt.arch !== process.arch || receipt.version !== pin.version) throw new Error('NATIVE_CLIENT_RECEIPT_MISMATCH');
  assertNativeClientDependencyRecipe(id, receipt);
  const directory = path.join(base, 'installation');
  if (receipt.directory !== directory || !path.isAbsolute(receipt.executable) || !receipt.executable.startsWith(directory + path.sep)) throw new Error('NATIVE_CLIENT_PATH_MISMATCH');
  if (sha256(JSON.stringify(inventory(directory))) !== receipt.inventory_sha256 || sha256(readFileSync(realpathSync(receipt.executable))) !== receipt.executable_sha256) throw new Error('NATIVE_CLIENT_BYTES_CHANGED');
  return receipt;
}

/** Finish identity checks after a bounded acquisition, including a prior attempt
 * that installed successfully but failed its non-generating CLI probe. */
export async function verifyNativeClientInstallation(root, id, { optIn, runner = runOwned } = {}) {
  assertOptIn({ optIn });
  const pin = CLIENT_LOCK.clients.find(client => client.id === id);
  if (!pin) throw new Error('NATIVE_CLIENT_SELECTION_INVALID');
  const base = clientDirectory(root, id), directory = path.join(base, 'installation'), home = path.join(base, 'home');
  const old = readPreparedClient(root, id); if (old) return old;
  const env = privateEnvironment(root, home);
  const binary = path.join(directory, pin.manager === 'npm' ? 'node_modules/.bin' : 'venv/bin', pin.command);
  let version;
  if (pin.manager === 'npm') {
    const lock = JSON.parse(readFileSync(path.join(directory, 'package-lock.json')));
    const selected = lock.packages?.[`node_modules/${pin.package}`];
    const installed = JSON.parse(readFileSync(path.join(directory, 'node_modules', pin.package, 'package.json')));
    if (selected?.version !== pin.version || selected.integrity !== pin.integrity || installed.version !== pin.version || installed.name !== pin.package) throw new Error('NATIVE_CLIENT_REGISTRY_IDENTITY_CHANGED');
    version = await runner(binary, ['--version'], { cwd: directory, env, timeout: 30_000 });
  } else {
    const requirements = readFileSync(path.join(directory, 'requirements.lock'), 'utf8');
    if (!requirements.includes(pin.url) || !requirements.includes(pin.sha256)) throw new Error('NATIVE_CLIENT_REGISTRY_IDENTITY_CHANGED');
    version = await runner(path.join(directory, 'venv/bin/python'), ['-I', '-B', '-c', 'import importlib.metadata,sys; print(importlib.metadata.version(sys.argv[1]))', pin.package], { cwd: directory, env, timeout: 30_000 });
    if (version.stdout.trim() !== pin.version) throw new Error('NATIVE_CLIENT_VERSION_CHANGED');
  }
  const help = await runner(binary, ['--help'], { cwd: directory, env, timeout: 30_000 });
  const dependencyRecipe = nativeClientDependencyRecipe(id), dependencyCheck = nativeClientDependencyCheck(id);
  if (dependencyCheck) {
    const requirements = readFileSync(path.join(directory, 'requirements.lock'), 'utf8');
    if (dependencyRecipe.packages.some(value => !requirements.includes(value.url) || !requirements.includes(value.sha256))) throw new Error('NATIVE_CLIENT_DEPENDENCY_LOCK_CHANGED');
    await runner(path.join(directory, 'venv/bin/python'), ['-I', '-B', '-c', dependencyCheck], { cwd: directory, env, timeout: 30_000 });
  }
  if (!existsSync(path.join(base, 'help.txt'))) writeFileSync(path.join(base, 'help.txt'), help.stdout || help.stderr, { flag: 'wx', mode: 0o600 });
  const receipt = { schema_version: 1, id, version: pin.version, reported_version: (version.stdout || version.stderr).trim(), platform: process.platform, arch: process.arch,
    directory, executable: binary, executable_sha256: sha256(readFileSync(realpathSync(binary))), client_lock_sha256: CLIENT_LOCK_SHA256,
    ...(dependencyRecipe ? { dependency_recipe_sha256: dependencyRecipe.sha256 } : {}),
    inventory_sha256: sha256(JSON.stringify(inventory(directory))), qualification: 'installed-only-no-agent-loop-evidence', inference: false };
  writeNew(path.join(base, 'receipt.json'), receipt); return receipt;
}

/** Dependency resolution occurs once, before campaign freeze, and is retained in
 * the private installation inventory. A failed preparation is never admitted. */
export async function prepareNativeClients(root, { optIn, ids = CLIENT_LOCK.clients.map(client => client.id), runner = runOwned, onProgress = () => {} } = {}) {
  assertOptIn({ optIn });
  if (!Array.isArray(ids) || new Set(ids).size !== ids.length || ids.some(id => !CLIENT_LOCK.clients.some(client => client.id === id))) throw new Error('NATIVE_CLIENT_SELECTION_INVALID');
  const results = [];
  for (const id of ids) {
    const pin = CLIENT_LOCK.clients.find(client => client.id === id), base = clientDirectory(root, id);
    try {
      const old = readPreparedClient(root, id);
      if (old) { results.push(old); continue; }
      if (existsSync(base)) throw new Error('NATIVE_CLIENT_PREVIOUS_ATTEMPT_REQUIRES_RECONCILIATION');
      const directory = path.join(base, 'installation'), home = path.join(base, 'home');
      mkdirSync(directory, { recursive: true, mode: 0o700 }); mkdirSync(home, { mode: 0o700 });
      const env = { ...privateEnvironment(root, home), npm_config_cache: path.join(root, '.artifacts/local-evals/npm-cache'), npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false' };
      onProgress({ client: id, stage: 'private-installation' });
      let binary;
      if (pin.manager === 'npm') {
        const npm = executable('npm'); if (!npm) throw new Error('NPM_UNAVAILABLE');
        writeNew(path.join(directory, 'package.json'), { name: `ud-local-${id}`, private: true, version: '0.0.0', dependencies: { [pin.package]: pin.version } });
        await runner(npm, ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: directory, env, timeout: 300_000 });
        const lock = JSON.parse(readFileSync(path.join(directory, 'package-lock.json')));
        const selected = lock.packages?.[`node_modules/${pin.package}`];
        if (selected?.version !== pin.version || selected.integrity !== pin.integrity) throw new Error('NATIVE_CLIENT_REGISTRY_IDENTITY_CHANGED');
        await runner(npm, ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: directory, env, timeout: 600_000 });
        if (id === 'claude-code') await runner(process.execPath, [path.join(directory, 'node_modules/@anthropic-ai/claude-code/install.cjs')], { cwd: directory, env, timeout: 30_000 });
        binary = path.join(directory, 'node_modules/.bin', pin.command);
      } else {
        const uv = executable('uv'); if (!uv) throw new Error('UV_UNAVAILABLE');
        const venv = path.join(directory, 'venv'), python = path.join(venv, 'bin/python');
        await runner(uv, ['venv', '--python', '3.12', venv], { cwd: directory, env, timeout: 180_000 });
        writeFileSync(path.join(directory, 'requirements.in'), nativeClientRequirements(id), { flag: 'wx', mode: 0o600 });
        await runner(uv, ['pip', 'compile', '--python', python, '--generate-hashes', 'requirements.in', '--output-file', 'requirements.lock'], { cwd: directory, env, timeout: 300_000 });
        await runner(uv, ['pip', 'sync', '--python', python, '--require-hashes', 'requirements.lock'], { cwd: directory, env, timeout: 600_000 });
        binary = path.join(venv, 'bin', pin.command);
      }
      void binary;
      results.push(await verifyNativeClientInstallation(root, id, { optIn, runner }));
    } catch (error) {
      const failure = { id, status: 'blocked', reason: error.message, inference: false };
      if (existsSync(base) && !existsSync(path.join(base, 'failure.json'))) writeNew(path.join(base, 'failure.json'), failure);
      results.push(failure);
    }
  }
  return results;
}
