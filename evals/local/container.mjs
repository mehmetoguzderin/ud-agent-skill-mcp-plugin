/** MIT. Owned ARM64 native-harness containers. No engine socket enters a task. */
import path from 'node:path';
import { existsSync, mkdirSync, readFileSync, writeFileSync, realpathSync, copyFileSync, readdirSync, lstatSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { startOwned, runOwned } from './process.mjs';
import { assertOptIn, privateEnvironment, executable, writeNew } from './preparation.mjs';
import { localDockerAuthority } from '../../scripts/quality/mutation-scope.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { CLIENT_LOCK, CLIENT_LOCK_SHA256, readPreparedClient, nativeClientDependencyRecipe, assertNativeClientDependencyRecipe, nativeClientRequirements, nativeClientDependencyCheck } from './native-clients.mjs';
import { withStorage } from '../../scripts/quality/storage-lifecycle.mjs';
import { originalDockerBytes } from '../../scripts/quality/original-storage.mjs';
import { cleanupObservation, failureObservation } from './lifecycle.mjs';

const LABEL = 'io.github.mehmetoguzderin.ud-agent.local-eval';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
/** Retry only a verified-empty, identity-bound bridge: Docker may briefly retain
 * an endpoint after its container has already been removed. No forced removal. */
export async function removeOwnedNetwork({ docker, runner, env, networkId, network, owner, deadline, now = () => Date.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const steps = [];
  const run = async (args, step) => {
    const remaining = deadline - now(); if (remaining <= 25) throw new Error('CONTAINER_CLEANUP_DEADLINE');
    try { const result = await runner(docker, args, { env, timeout: Math.min(500, remaining - 25), cancellationMs: Math.min(100, remaining - 1) }); steps.push({ step, outcome: 'completed' }); return result; }
    catch (error) { steps.push({ step, outcome: 'failed', failure: failureObservation(error) }); throw error; }
  };
  try {
    for (let attempt = 0; attempt < 3; attempt++) {
      const info = JSON.parse((await run(['network', 'inspect', networkId], 'network-inspect')).stdout)[0];
      if (info?.Id !== networkId || info.Labels?.[LABEL] !== owner || info.Name !== network || Object.keys(info.Containers ?? {}).length) throw new Error('CONTAINER_NETWORK_OWNERSHIP_CHANGED');
      try { await run(['network', 'rm', networkId], 'network-remove'); return { cleanupVerified: true, steps }; }
      catch (error) { if (attempt === 2 || deadline - now() <= 50) throw error; await sleep(Math.min(25, deadline - now())); }
    }
  } catch (error) { return { cleanupVerified: false, steps, failure: failureObservation(error) }; }
}
function inspectImageDependencies(root, environment) {
  const base = path.join(root, '.artifacts/local-evals/client-images'), selected = new Map();
  if (!existsSync(base)) return [];
  for (const name of readdirSync(base)) {
    const file = path.join(base, name, 'receipt.json'); if (!existsSync(file)) continue;
    // A prior complete chain is reverified by originalDockerBytes, including
    // exact daemon absence for removed intermediate records. Never rewrite it.
    if (existsSync(path.join(base, name, 'ancestry.json'))) continue;
    const receipt = JSON.parse(readFileSync(file)); let id = receipt.image_id; const chain = [];
    for (let depth = 0; id; depth++) {
      if (depth > 32 || !DIGEST.test(id) || chain.some(row => row.image_id === id)) throw new Error('CLIENT_IMAGE_ANCESTRY_INVALID');
      const result = spawnSync('docker', ['image', 'inspect', id], { env: environment, encoding: 'utf8', timeout: 10_000, maxBuffer: 65536 });
      if (result.status !== 0 || result.error) throw new Error('CLIENT_IMAGE_ANCESTRY_UNAVAILABLE');
      const image = JSON.parse(result.stdout)[0];
      if (image?.Id !== id || image.Architecture !== 'arm64' || image.Os !== 'linux' || !Number.isSafeInteger(image.Size) || depth === 0 && image.Config?.Labels?.[LABEL] !== receipt.created_by) throw new Error('CLIENT_IMAGE_ANCESTRY_CHANGED');
      const row = { image_id: id, size_bytes: image.Size, parent: image.Parent ?? '' }; chain.push(row); selected.set(id, row); id = row.parent;
    }
    const evidence = { schema_version: 1, image_id: receipt.image_id, relationship: 'immutable-dependencies-of-owned-client-image-not-deletion-authority', images: chain };
    const record = path.join(base, name, 'ancestry.json');
    if (existsSync(record)) { if (JSON.stringify(JSON.parse(readFileSync(record))) !== JSON.stringify(evidence)) throw new Error('CLIENT_IMAGE_ANCESTRY_CHANGED'); }
    else writeNew(record, evidence);
  }
  return [...selected.values()];
}
export function privateBridgeNetwork(value, owner) {
  const privateSubnet = subnet => {
    if (typeof subnet !== 'string' || !/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(subnet)) return false;
    const [address, prefix] = subnet.split('/'), octets = address.split('.').map(Number);
    if (octets.some(byte => byte < 0 || byte > 255) || Number(prefix) > 30) return false;
    return octets[0] === 10 && Number(prefix) >= 8 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 && Number(prefix) >= 12 || octets[0] === 192 && octets[1] === 168 && Number(prefix) >= 16;
  };
  return value?.Driver === 'bridge' && value.Labels?.[LABEL] === owner && value.Options?.['com.docker.network.bridge.enable_icc'] === 'false'
    && Array.isArray(value.IPAM?.Config) && value.IPAM.Config.length > 0 && value.IPAM.Config.every(row => privateSubnet(row.Subnet)) && Object.keys(value.Containers ?? {}).length === 0;
}

export function selectedDockerEnvironment(environment = process.env, inspect = args => spawnSync('docker', args, { env: environment, encoding: 'utf8', timeout: 10_000, maxBuffer: 65536 })) {
  const authority = localDockerAuthority(environment, context => {
    const result = inspect(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', ...(context ? [context] : [])]);
    if (result.status !== 0 || result.error) throw new Error('LOCAL_DOCKER_AUTHORITY_UNAVAILABLE');
    return result.stdout.trim();
  });
  return { DOCKER_HOST: authority.endpoint };
}

/** Discover installed CLI code without importing the account's Docker config or
 * credentials. Both build and imagetools need Buildx under the private HOME. */
export function privateDockerBuildEnvironment(root, docker, { engineEnvironment = selectedDockerEnvironment(), pluginDirectories } = {}) {
  const installedDocker = realpathSync(docker);
  const candidates = pluginDirectories ?? [path.resolve(path.dirname(installedDocker), '../cli-plugins'),
    '/usr/local/lib/docker/cli-plugins', '/usr/local/libexec/docker/cli-plugins', '/usr/lib/docker/cli-plugins', '/usr/libexec/docker/cli-plugins'];
  let plugins;
  for (const candidate of candidates) {
    if (!path.isAbsolute(candidate) || !existsSync(candidate)) continue;
    const directory = realpathSync(candidate), binary = path.join(directory, 'docker-buildx');
    if (!lstatSync(directory).isDirectory() || !existsSync(binary)) continue;
    const info = lstatSync(binary);
    if (info.isFile() && !info.isSymbolicLink() && (info.mode & 0o111)) { plugins = directory; break; }
  }
  if (!plugins) throw new Error('CLIENT_BUILDX_INSTALLATION_UNAVAILABLE');
  const home = path.join(root, '.artifacts/local-evals/build-home'), configDirectory = path.join(home, '.docker');
  let selected = root;
  for (const component of ['.artifacts', 'local-evals', 'build-home', '.docker']) {
    selected = path.join(selected, component);
    const info = lstatSync(selected, { throwIfNoEntry: false });
    if (info && (!info.isDirectory() || info.isSymbolicLink())) throw new Error('CLIENT_DOCKER_CONFIG_PATH_INVALID');
    if (!info) mkdirSync(selected, { mode: 0o700 });
  }
  const file = path.join(configDirectory, 'config.json'), expected = JSON.stringify({ cliPluginsExtraDirs: [plugins] }, null, 2) + '\n';
  const info = lstatSync(file, { throwIfNoEntry: false });
  if (info) {
    if (!info.isFile() || info.isSymbolicLink() || readFileSync(file, 'utf8') !== expected) throw new Error('CLIENT_DOCKER_CONFIG_CHANGED');
  } else writeFileSync(file, expected, { flag: 'wx', mode: 0o600 });
  return { ...privateEnvironment(root, home), ...engineEnvironment, DOCKER_CONFIG: configDirectory };
}

export function containerArguments({ name, owner, image, network, taskRoot, profile, command, args = [], env = {}, mounts = [] }) {
  if (!/^ud-agent-local-eval-[a-f0-9-]{36}$/.test(name) || !/^[a-f0-9-]{36}$/.test(owner) || !DIGEST.test(image) || !/^ud-agent-local-eval-[a-f0-9-]{36}$/.test(network)) throw new Error('CONTAINER_IDENTITY_INVALID');
  if (![taskRoot, profile, command].every(path.isAbsolute) || taskRoot === profile || !Array.isArray(args)) throw new Error('CONTAINER_PATH_INVALID');
  const mount = (source, target, readonly) => {
    if (![source, target].every(path.isAbsolute) || [source, target].some(value => /[,\n\0]/.test(value)) || /(?:docker|podman)\.sock$/.test(source)) throw new Error('CONTAINER_MOUNT_FORBIDDEN');
    return ['--mount', `type=bind,src=${source},dst=${target}${readonly ? ',readonly' : ''}`];
  };
  const argv = ['run', '--rm', '--init', '--platform', 'linux/arm64', '--name', name, '--label', `${LABEL}=${owner}`, '--network', network,
    '--add-host', 'host.docker.internal:host-gateway', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
    '--memory', '2g', '--cpus', '2', '--user', `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`, '--workdir', taskRoot,
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=134217728,mode=1777', ...mount(taskRoot, taskRoot, false), ...mount(profile, profile, false)];
  for (const item of mounts) argv.push(...mount(item.source, item.target, true));
  for (const [key, value] of Object.entries(env)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof value !== 'string' || value.includes('\0') || ['DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT'].includes(key)) throw new Error('CONTAINER_ENVIRONMENT_FORBIDDEN');
    argv.push('--env', `${key}=${value}`);
  }
  return [...argv, '--entrypoint', command, image, ...args];
}

/** Resolve Python dependencies for the Linux container, not the macOS process
 * doing preparation. Source builds cannot acquire unrecorded build dependencies. */
export async function prepareLinuxClientLock(root, id, directory, prepared, { runner = runOwned, env } = {}) {
  const pin = CLIENT_LOCK.clients.find(client => client.id === id && client.manager === 'uv');
  if (!pin || !path.isAbsolute(directory) || !path.isAbsolute(prepared?.directory ?? '')) throw new Error('CLIENT_LINUX_LOCK_INPUT_INVALID');
  const input = path.join(directory, 'requirements.in'), lock = path.join(directory, 'requirements.lock');
  writeFileSync(input, nativeClientRequirements(id), { flag: 'wx', mode: 0o600 });
  await runner('uv', ['pip', 'compile', '--python', path.join(prepared.directory, 'venv/bin/python'),
    '--python-version', '3.12', '--python-platform', 'aarch64-manylinux_2_36', '--only-binary', ':all:',
    '--generate-hashes', '--output-file', lock, input], { cwd: root, env, timeout: 300_000 });
  const contents = readFileSync(lock, 'utf8');
  if (!contents.includes(pin.url) || !contents.includes(pin.sha256)) throw new Error('CLIENT_LINUX_LOCK_IDENTITY_CHANGED');
  if ((nativeClientDependencyRecipe(id)?.packages ?? []).some(value => !contents.includes(value.url) || !contents.includes(value.sha256))) throw new Error('CLIENT_LINUX_DEPENDENCY_IDENTITY_CHANGED');
  return { platform: 'linux/arm64', python_version: '3.12', wheel_platform: 'aarch64-manylinux_2_36', resolution: 'target-platform-wheels-only',
    input_sha256: sha256(readFileSync(input)), sha256: sha256(contents) };
}

/** Read the OCI manifest bytes without the legacy manifest command's conversion
 * to Docker schema 2, which changes the digest. The exact bytes bind the config;
 * the completed image is independently inspected for Linux ARM64 below. */
export async function verifyContainerBaseManifest(docker, reference, expected, { runner = runOwned, env } = {}) {
  if (!/^(?:node|python):[\w.-]+@sha256:[a-f0-9]{64}$/.test(reference) || !DIGEST.test(expected)) throw new Error('CLIENT_BASE_CONFIG_INVALID');
  const raw = (await runner(docker, ['buildx', 'imagetools', 'inspect', '--raw', reference], { env, timeout: 30_000, maximumBytes: 1024 ** 2 })).stdout;
  const digest = reference.slice(reference.indexOf('@') + 1);
  if (typeof raw !== 'string' || `sha256:${sha256(raw)}` !== digest) throw new Error('CLIENT_BASE_MANIFEST_DIGEST_CHANGED');
  const manifest = JSON.parse(raw);
  if (manifest?.schemaVersion !== 2 || !['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'].includes(manifest.mediaType) ||
      manifest.config?.digest !== expected || !Array.isArray(manifest.layers) || !manifest.layers.length ||
      manifest.layers.some(layer => !DIGEST.test(layer?.digest ?? '') || !Number.isSafeInteger(layer.size) || layer.size < 0)) throw new Error('CLIENT_BASE_CONFIG_CHANGED');
  return { reference, manifest_digest: digest, config_digest: expected };
}

export const OPENCLAW_LIFECYCLE_RECIPE = 'openclaw-2026.11.3-native-lifecycle-v1';
/** Execute only the pinned package's own pre/postinstall in a networkless build
 * layer. Runtime containers remain read-only and cannot repair their package. */
export function nativePackageLifecycleDockerfile(id) {
  if (id !== 'openclaw') return '';
  const pin = CLIENT_LOCK.clients.find(client => client.id === id);
  if (pin?.version !== '2026.11.3') throw new Error('CLIENT_OPENCLAW_LIFECYCLE_VERSION_CHANGED');
  const script = 'import{readFileSync,existsSync}from"node:fs";'
    + 'import{configureFsSafeNative}from"@openclaw/fs-safe/config";import{readCloneFileMetadata}from"@openclaw/fs-safe/copy";'
    + 'import{completePendingPackageLifecycle}from"./node_modules/openclaw/dist/infra/package-lifecycle.js";'
    + 'const root="/opt/client/node_modules/openclaw",manifest=JSON.parse(readFileSync(root+"/package.json"));'
    + 'if(manifest.name!=="openclaw"||manifest.version!=="2026.11.3")throw Error("OPENCLAW_PACKAGE_IDENTITY_CHANGED");'
    + 'configureFsSafeNative({mode:"require"});await readCloneFileMetadata([]);'
    + 'await completePendingPackageLifecycle({packageRoot:root,timeoutMs:60000});'
    + 'for(const marker of[".openclaw-lifecycle-pending",".openclaw-lifecycle-lock","dist/openclaw-install-guard"])if(existsSync(root+"/"+marker))throw Error("OPENCLAW_LIFECYCLE_INCOMPLETE");';
  return `RUN --network=none timeout --signal=KILL 150s node --input-type=module -e '${script}'\n`;
}

export async function buildNativeClientImage(root, id, options = {}) {
  assertOptIn(options);
  if (!CLIENT_LOCK.clients.some(client => client.id === id)) throw new Error('CLIENT_CONTAINER_RECIPE_UNAVAILABLE');
  if (typeof options.baseImage !== 'string' || !/^(?:node|python):[\w.-]+@sha256:[a-f0-9]{64}$/.test(options.baseImage)) throw new Error('CLIENT_BASE_IMAGE_MUST_BE_PINNED');
  if (existsSync(path.join(root, '.artifacts/local-evals/client-images', id, 'receipt.json'))) return buildClientImage(root, id, options);
  const engineEnvironment = { ...process.env, ...selectedDockerEnvironment() };
  inspectImageDependencies(root, engineEnvironment);
  const ownedEngineBytes = originalDockerBytes(root, engineEnvironment);
  return withStorage({ root, label: `local-eval-client-${id}`, profile: 'ordinary', plannedBytes: 2_000_000_000, plannedOutputBytes: 2_000_000_000,
    externalOwnedBytes: ownedEngineBytes }, async lease => {
    const receipt = await buildClientImage(root, id, options); lease.check(receipt.image_size); inspectImageDependencies(root, engineEnvironment); return receipt;
  });
}

async function buildClientImage(root, id, { optIn, baseImage, nodeImage, baseConfigDigest, nodeConfigDigest, runner = runOwned, onProgress = () => {} } = {}) {
  assertOptIn({ optIn });
  const pin = CLIENT_LOCK.clients.find(client => client.id === id);
  if (!pin) throw new Error('CLIENT_CONTAINER_RECIPE_UNAVAILABLE');
  const npm = pin.manager === 'npm';
  if (typeof baseImage !== 'string' || !(npm ? /^node:[a-zA-Z0-9_.-]+@sha256:[a-f0-9]{64}$/ : /^python:3\.12[\w.-]*@sha256:[a-f0-9]{64}$/).test(baseImage)) throw new Error('CLIENT_BASE_IMAGE_MUST_BE_PINNED');
  if (!npm && !/^node:[a-zA-Z0-9_.-]+@sha256:[a-f0-9]{64}$/.test(nodeImage ?? '')) throw new Error('CLIENT_NODE_BRIDGE_IMAGE_MUST_BE_PINNED');
  if (baseConfigDigest !== undefined && !DIGEST.test(baseConfigDigest) || nodeConfigDigest !== undefined && !DIGEST.test(nodeConfigDigest)) throw new Error('CLIENT_BASE_CONFIG_INVALID');
  const prepared = readPreparedClient(root, id); if (!prepared) throw new Error('CLIENT_PRIVATE_LOCK_REQUIRED');
  const directory = path.join(root, '.artifacts/local-evals/client-images', id);
  const docker = executable('docker'); if (!docker) throw new Error('DOCKER_UNAVAILABLE');
  const env = privateDockerBuildEnvironment(root, docker);
  const receiptFile = path.join(directory, 'receipt.json');
  if (existsSync(receiptFile)) {
    const old = JSON.parse(readFileSync(receiptFile));
    assertNativeClientDependencyRecipe(id, old);
    if (id === 'openclaw' && old.package_lifecycle_recipe !== OPENCLAW_LIFECYCLE_RECIPE) throw new Error('CLIENT_IMAGE_RECIPE_CHANGED: preserve the prior OpenClaw image receipt and prepare a fresh owned build context.');
    if (old.client_lock_sha256 !== CLIENT_LOCK_SHA256 || old.base_image !== baseImage || old.node_image !== nodeImage ||
        old.base_config_digest !== baseConfigDigest || old.node_config_digest !== nodeConfigDigest ||
        !npm && (old.dependency_resolution?.platform !== 'linux/arm64' || old.dependency_resolution?.resolution !== 'target-platform-wheels-only')) throw new Error('CLIENT_IMAGE_RECIPE_CHANGED');
    const lock = path.join(directory, npm ? 'package-lock.json' : 'requirements.lock');
    if (sha256(readFileSync(lock)) !== old.dependency_lock_sha256 || sha256(readFileSync(path.join(directory, 'Dockerfile'))) !== old.dockerfile_sha256 ||
        !npm && old.dependency_resolution.sha256 !== old.dependency_lock_sha256) throw new Error('CLIENT_IMAGE_INPUT_BYTES_CHANGED');
    const inspection = JSON.parse((await runner(docker, ['image', 'inspect', old.image_id], { env, timeout: 20_000 })).stdout)[0];
    if (inspection?.Id !== old.image_id || inspection.Architecture !== 'arm64' || inspection.Os !== 'linux') throw new Error('CLIENT_IMAGE_IDENTITY_CHANGED');
    return old;
  }
  if (existsSync(directory)) throw new Error('CLIENT_IMAGE_PREVIOUS_ATTEMPT_REQUIRES_RECONCILIATION');
  for (const [reference, expected] of [[baseImage, baseConfigDigest], [nodeImage, nodeConfigDigest]]) if (expected) {
    await verifyContainerBaseManifest(docker, reference, expected, { runner, env });
  }
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  let dependencyResolution;
  if (npm) for (const name of ['package.json', 'package-lock.json']) copyFileSync(path.join(prepared.directory, name), path.join(directory, name));
  else dependencyResolution = await prepareLinuxClientLock(root, id, directory, prepared, { runner, env });
  // Claude's pinned wrapper postinstall only verifies/copies its optional native
  // binary; all other lifecycle scripts remain disabled. Python resolves only
  // artifacts allowed by the prepared hash lock, with no unpinned bootstrap.
  const dockerfile = npm
    ? `FROM ${baseImage}\nWORKDIR /opt/client\nCOPY package.json package-lock.json ./\nRUN npm ci --ignore-scripts --no-audit --no-fund${id === 'claude-code' ? ' && node node_modules/@anthropic-ai/claude-code/install.cjs' : ''} && npm cache clean --force\n${nativePackageLifecycleDockerfile(id)}ENV PATH="/opt/client/node_modules/.bin:/usr/local/bin:/usr/bin:/bin"\n`
    : `FROM ${nodeImage} AS node\nFROM ${baseImage}\nCOPY --from=node /usr/local/bin/node /usr/local/bin/node\nCOPY --from=node /usr/lib/aarch64-linux-gnu/libstdc++.so.6* /usr/lib/aarch64-linux-gnu/libatomic.so.1* /usr/lib/aarch64-linux-gnu/\nWORKDIR /opt/client\nCOPY requirements.lock ./\nRUN node --version && python -m venv /opt/client/venv && /opt/client/venv/bin/python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock && /opt/client/venv/bin/python -m pip check\nENV PATH="/opt/client/venv/bin:/usr/local/bin:/usr/bin:/bin"\n`;
  const dependencyCheck = nativeClientDependencyCheck(id), dependencyRecipe = nativeClientDependencyRecipe(id);
  const checkedDockerfile = dockerfile + (dependencyCheck ? `RUN --network=none timeout --signal=KILL 30s /opt/client/venv/bin/python -I -B -c '${dependencyCheck}'\n` : '');
  writeFileSync(path.join(directory, 'Dockerfile'), checkedDockerfile, { flag: 'wx', mode: 0o600 });
  const tag = `localhost/ud-agent-local-client-${id}:${pin.version}`, owner = randomUUID();
  onProgress({ client: id, stage: 'arm64-image-build' });
  await runner(docker, ['build', '--platform', 'linux/arm64', '--label', `${LABEL}=${owner}`, '--tag', tag, directory], { env, cwd: directory, timeout: 600_000, maximumBytes: 16 * 1024 ** 2 });
  const image = JSON.parse((await runner(docker, ['image', 'inspect', tag], { env, timeout: 20_000 })).stdout)[0];
  if (!DIGEST.test(image?.Id ?? '') || image.Architecture !== 'arm64' || image.Os !== 'linux') throw new Error('CLIENT_IMAGE_ARCHITECTURE_INVALID');
  const receipt = { schema_version: 1, id, version: pin.version, image_id: image.Id, image_size: image.Size, platform: 'linux/arm64', base_image: baseImage, ...(nodeImage ? { node_image: nodeImage } : {}),
    ...(id === 'openclaw' ? { package_lifecycle_recipe: OPENCLAW_LIFECYCLE_RECIPE } : {}),
    ...(baseConfigDigest ? { base_config_digest: baseConfigDigest } : {}), ...(nodeConfigDigest ? { node_config_digest: nodeConfigDigest } : {}),
    ...(dependencyRecipe ? { dependency_recipe_sha256: dependencyRecipe.sha256 } : {}),
    client_lock_sha256: CLIENT_LOCK_SHA256, dependency_lock_sha256: sha256(readFileSync(path.join(directory, npm ? 'package-lock.json' : 'requirements.lock'))), dockerfile_sha256: sha256(checkedDockerfile),
    ...(dependencyResolution ? { dependency_resolution: dependencyResolution } : {}),
    qualification: 'built-only-native-loop-unverified', command: npm ? `/opt/client/node_modules/.bin/${pin.command}` : `/opt/client/venv/bin/${pin.command}`, created_by: owner, inference: false };
  writeNew(receiptFile, receipt); return receipt;
}

/** Calls only immutable image IDs. A private network is independently inspected
 * and removed after its only owned container has stopped. */
export async function startContainer({ root, image, taskRoot, profile, command, args, env, mounts = [], signal, log, probeUrls = [], runner = runOwned, start = startOwned, beforeLaunch }) {
  const docker = executable('docker'); if (!docker) throw new Error('DOCKER_UNAVAILABLE');
  const owner = randomUUID(), name = `ud-agent-local-eval-${owner}`, network = name;
  const engineEnvironment = { ...privateEnvironment(root, path.join(profile, 'engine')), ...selectedDockerEnvironment() };
  if ([taskRoot, profile].some(directory => realpathSync(directory) !== directory)) throw new Error('CONTAINER_SYMLINK_ROOT');
  const selected = JSON.parse((await runner(docker, ['image', 'inspect', image], { env: engineEnvironment, timeout: 10_000 })).stdout)[0];
  if (selected?.Id !== image || selected.Architecture !== 'arm64' || selected.Os !== 'linux') throw new Error('CONTAINER_IMAGE_NOT_NATIVE_ARM64');
  const created = await runner(docker, ['network', 'create', '--driver', 'bridge', '--opt', 'com.docker.network.bridge.enable_icc=false', '--label', `${LABEL}=${owner}`, network], { env: engineEnvironment, timeout: 10_000 });
  const networkId = created.stdout.trim();
  if (!/^[a-f0-9]{64}$/.test(networkId)) throw new Error('CONTAINER_NETWORK_IDENTITY_INVALID');
  let processHandle, cleanupPromise;
  async function inspectOwned(deadline = Date.now() + 5000) {
    const options = { env: engineEnvironment, timeout: Math.max(1, Math.min(500, deadline - Date.now() - 25)), cancellationMs: 100 };
    if (Date.now() >= deadline - 25) throw new Error('CONTAINER_CLEANUP_DEADLINE');
    const result = await runner(docker, ['ps', '--all', '--no-trunc', '--filter', `label=${LABEL}=${owner}`, '--format', '{{json .}}'], options);
    const rows = result.stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    if (rows.length > 1 || rows.some(row => row.Names !== name || !/^[a-f0-9]{64}$/.test(row.ID))) throw new Error('CONTAINER_OWNERSHIP_AMBIGUOUS');
    if (!rows.length) return undefined;
    const item = JSON.parse((await runner(docker, ['inspect', rows[0].ID], options)).stdout)[0];
    if (item.Id !== rows[0].ID || item.Image !== image || item.Config?.Labels?.[LABEL] !== owner || item.Name !== '/' + name) throw new Error('CONTAINER_OWNERSHIP_CHANGED');
    return item;
  }
  async function cleanup(reason = 'container-finished') {
    if (!cleanupPromise) cleanupPromise = (async () => {
      const evidence = [], deadline = Date.now() + 5000; let verified = false;
      const processRelease = processHandle ? processHandle.stop(reason) : Promise.resolve({ cleanupVerified: true, no_owned_process: true });
      const step = async (name, action) => { try { const value = await action(); evidence.push({ step: name, outcome: 'completed' }); return value; } catch (error) { evidence.push({ step: name, outcome: 'failed', failure: failureObservation(error) }); throw error; } };
      try {
        const owned = await step('container-inspect-initial', () => inspectOwned(deadline));
        if (owned?.State.Running) {
          try { await step('container-kill', () => runner(docker, ['kill', '--signal', 'KILL', owned.Id], { env: engineEnvironment, timeout: Math.max(1, Math.min(500, deadline - Date.now() - 25)), cancellationMs: 100 })); }
          catch (error) {
            // Releasing the attached host process can stop/remove the container
            // between inspect and kill. Keep that failed command as evidence;
            // only a fresh identity-bound observation can resolve the race.
            const observed = await step('container-inspect-after-kill-failure', () => inspectOwned(deadline));
            if (observed && observed.State?.Running !== false || error.result?.cleanupVerified !== true) throw error;
          }
        }
        const remaining = await step('container-inspect-stopped', () => inspectOwned(deadline));
        if (remaining && remaining.State?.Running !== false) throw new Error('CONTAINER_STILL_RUNNING');
        if (remaining) await step('container-remove', () => runner(docker, ['rm', remaining.Id], { env: engineEnvironment, timeout: Math.max(1, Math.min(500, deadline - Date.now() - 25)), cancellationMs: 100 }));
        const networkRelease = await removeOwnedNetwork({ docker, runner, env: engineEnvironment, networkId, network, owner, deadline }); evidence.push(...networkRelease.steps);
        if (!networkRelease.cleanupVerified) throw Object.assign(new Error('CONTAINER_NETWORK_RELEASE_UNVERIFIED'), { cause: networkRelease.failure });
        verified = (await step('container-absence-final', () => inspectOwned(deadline))) === undefined;
      } catch (error) { evidence.push({ outcome: 'failed', failure: failureObservation(error) }); }
      const result = await processRelease;
      evidence.push({ step: 'host-process-release', ...cleanupObservation(result) });
      return { ...result, cleanupVerified: verified && result.cleanupVerified === true && Date.now() <= deadline, container_cleanup: evidence, container_id: name, image_id: image, network_id: networkId, deadline, finished_at: Date.now() };
    })();
    return cleanupPromise;
  }
  try {
    const networkInfo = JSON.parse((await runner(docker, ['network', 'inspect', networkId], { env: engineEnvironment, timeout: 10_000 })).stdout)[0];
    if (!privateBridgeNetwork(networkInfo, owner)) throw new Error('CONTAINER_NETWORK_NOT_PRIVATE');
    const bridgeObservations = [];
    for (const probe of probeUrls) {
      const url = new URL(probe.url); if (url.protocol !== 'http:' || url.hostname !== 'host.docker.internal') throw new Error('CONTAINER_BRIDGE_ENDPOINT_INVALID');
      const script = 'import{lookup}from"node:dns/promises";const p=JSON.parse(process.argv[1]),host=await lookup(new URL(p.url).hostname);const b=host.address.split(".").map(Number);if(!(b.length===4&&(b[0]===10||b[0]===172&&b[1]>=16&&b[1]<=31||b[0]===192&&b[1]===168)))throw new Error("host bridge is not private IPv4");const r=await fetch(p.url,{headers:p.headers??{},signal:AbortSignal.timeout(5000)});if(!r.ok)throw new Error("private bridge unreachable "+r.status);console.log(JSON.stringify({address:host.address,status:r.status,body:await r.text()}));';
      const checked = await runner(docker, containerArguments({ name, owner, image, network, taskRoot, profile, command: '/usr/local/bin/node', args: ['--input-type=module', '-e', script, JSON.stringify(probe)], env: {} }), { env: engineEnvironment, timeout: 10_000 });
      bridgeObservations.push({ url: probe.url, ...JSON.parse(checked.stdout) });
    }
    await beforeLaunch?.();
    processHandle = start(docker, containerArguments({ name, owner, image, network, taskRoot, profile, command, args, env, mounts }), { env: engineEnvironment, signal, timeout: 90_000, log });
    processHandle.child.stdin.end();
    const done = processHandle.done.then(async result => ({ ...result, ...await cleanup(), stdout: result.stdout, stderr: result.stderr }));
    return { child: processHandle.child, done, stop: cleanup, resourceContainer: { executable: docker, ids: [name], env: engineEnvironment }, identity: { execution_location: 'arm64-container', container_id: name, image_id: image, network_id: networkId, private_bridge: { subnets: networkInfo.IPAM.Config, inter_container_communication: false, probes: bridgeObservations }, runtime_location: 'native-macos' } };
  } catch (error) { const result = await cleanup(); error.cleanupVerified = result.cleanupVerified; error.container_cleanup = cleanupObservation(result); throw error; }
}
