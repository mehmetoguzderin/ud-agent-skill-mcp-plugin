#!/usr/bin/env node
/** Execute a Linux Actions job locally with an owned canonical tool-cache volume. */
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { sourceReceipt } from '../release/candidate.mjs';
import {captureDiagnosticSnapshot} from './diagnostic-snapshot.mjs';
import { reserveStorage, storageTreeBytes, STORAGE_LIMITS } from './storage-lifecycle.mjs';
import { localDockerAuthority } from './mutation-scope.mjs';
import { inspectOwnedDockerStorage, lockedDockerImages } from './docker-owned-storage.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OWNER_LABEL = 'io.github.mehmetoguzderin.ud-agent.act-owner';
// A local Actions run retains the SDK transfer, tool cache and job layers
// together. This allowance is confined to that workflow's owned resources.
export const LOCAL_ACTIONS_STORAGE_PLAN = Object.freeze({ plannedBytes: 12_000_000_000, profile: 'release', transientAllowance: 12_000_000_000 });
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024, ...options });
  if (result.error || result.status !== 0) throw new Error(`${program} failed: ${result.error?.message ?? result.stderr ?? result.status}`);
  return result.stdout;
}

export function resolveActJob({ job, architecture }) {
  if (!['amd64', 'arm64'].includes(architecture) || !['native', 'node24', 'mutation'].includes(job)) throw new Error('Unsupported local Actions job.');
  const workflowJob = job === 'native' && architecture === 'arm64' ? 'native-arm' : job;
  return { workflowJob, dependencyJobs: workflowJob === 'native-arm' ? ['mutation-sdk'] : [] };
}

export function buildActArgs({ overlay, job, architecture, image, cacheRoot, serviceRoot, dockerSocket, owner }) {
  const { workflowJob } = resolveActJob({ job, architecture });
  const args = ['workflow_dispatch', '--workflows', overlay, '--job', workflowJob, '--platform', `ubuntu-26.04=${image}`, '--platform', `ubuntu-26.04-arm=${image}`,
    '--container-architecture', `linux/${architecture}`, '--container-daemon-socket', dockerSocket ?? '/var/run/docker.sock', '--pull=false', '--action-offline-mode', '--use-gitignore=false',
    '--action-cache-path', cacheRoot, '--env-file', '/dev/null', '--secret-file', '/dev/null', '--var-file', '/dev/null',
    '--env', 'RUNNER_TOOL_CACHE=/opt/hostedtoolcache', '--env', 'AGENT_TOOLSDIRECTORY=/opt/hostedtoolcache'];
  const inputs = {
    native_targets: JSON.stringify(workflowJob === 'native' ? ['linux-x64'] : []),
    linux_arm64: String(workflowJob === 'native-arm'),
    node24: String(workflowJob === 'node24'),
    // The frozen local source already includes the exact verified SDK. Skip
    // hosted artifact transport while retaining the native image verification.
    sdk_run_id: workflowJob === 'native-arm' ? 'local-verified' : '', sdk_run_attempt: '1',
  };
  for (const [name, value] of Object.entries(inputs)) args.push('--input', `${name}=${value}`);
  if (owner !== undefined) { if (!/^[a-f0-9]{32}$/.test(owner)) throw new Error('Invalid local Actions owner.'); args.push('--env', 'UD_AGENT_LOCAL_ACTIONS_OWNER=' + owner); }
  if (serviceRoot) args.push('--cache-server-path', path.join(serviceRoot, 'cache'), '--artifact-server-path', path.join(serviceRoot, 'artifacts'), '--artifact-server-port', '34567');
  if (architecture === 'amd64') args.push('--env','QEMU_CPU=max');
  if (job === 'native') args.push('--matrix', `target:linux-${architecture === 'amd64' ? 'x64' : 'arm64'}`);
  return args;
}

export function isOwnedActMutationResource(resource, owner, kind) {
  const labels = kind === 'container' ? resource.Config?.Labels : resource.Labels;
  const mutation = labels?.['io.github.mehmetoguzderin.ud-agent.mutation'];
  if (!/^[a-f0-9]{32}$/.test(owner) || labels?.[OWNER_LABEL] !== owner || !/^[a-f0-9-]{36}$/.test(mutation ?? '')) return false;
  const name = (resource.Name ?? '').replace(/^\//, '');
  return (kind === 'container' ? [`ud-mutation-input-${mutation}`, `ud-mutation-job-${mutation}`, `ud-mutation-job-${mutation}-usage`, `ud-mutation-job-${mutation}-input-usage`, `ud-mutation-job-${mutation}-evidence`] : [`ud-mutation-input-${mutation}`, `ud-mutation-state-${mutation}`]).includes(name);
}

function ownedActContainer(container, owner, volume, image) {
  return container.Config?.Labels?.[OWNER_LABEL] === owner && (
    container.Mounts?.some(mount => mount.Name === volume && mount.Destination === '/opt/hostedtoolcache') ||
    container.Name === '/ud-agent-act-init-' + owner && container.Config.Image === image && container.Mounts?.some(mount => mount.Name === volume && mount.Destination === '/cache') ||
    container.Name === '/ud-agent-act-probe-' + owner && container.Config.Image === image && container.Mounts?.some(mount => mount.Destination === '/engine.sock') ||
    new RegExp('^/ud-agent-act-meter-' + owner + '-[0-9]+$').test(container.Name ?? '') && container.Config.Image === image && container.Mounts?.some(mount => mount.Destination === '/cache' && mount.RW === false) ||
    isOwnedActMutationResource(container, owner, 'container'));
}

/** Actual owned Docker writable layers and mounted volume allocations. The
 * injected docker function only inspects existing objects and mounts volumes
 * read-only in a short-lived probe; it never prunes or edits shared volumes. */
export function measureActDockerUsage(docker, owner, cacheVolume, image) {
  if (!/^[a-f0-9]{32}$/.test(owner) || cacheVolume !== `ud-agent-act-${owner}-arm64` && cacheVolume !== `ud-agent-act-${owner}-amd64`) throw new Error('Local Actions storage identity is invalid.');
  const lines = value => value.trim() ? value.trim().split(/\s+/) : [];
  const volumes = lines(docker(['volume', 'ls', '-q', '--filter', `label=${OWNER_LABEL}=${owner}`]));
  if (!volumes.includes(cacheVolume) || new Set(volumes).size !== volumes.length) throw new Error('Local Actions owned volume inventory is incomplete.');
  for (const name of volumes) {
    const [volume] = JSON.parse(docker(['volume', 'inspect', name]));
    if (!volume || volume.Name !== name || volume.Labels?.[OWNER_LABEL] !== owner || name !== cacheVolume && !isOwnedActMutationResource(volume, owner, 'volume')) throw new Error('Local Actions volume ownership differs.');
  }
  const containers = lines(docker(['ps', '-aq', '--filter', `label=${OWNER_LABEL}=${owner}`]));
  if (new Set(containers).size !== containers.length) throw new Error('Local Actions container inventory is duplicated.');
  let writableBytes = 0;
  for (const id of containers) {
    if (!/^[a-f0-9]{12,64}$/.test(id)) throw new Error('Local Actions container identity is invalid.');
    const [container] = JSON.parse(docker(['inspect', '--size', id]));
    if (!container || !container.Id?.startsWith(id) || !ownedActContainer(container, owner, cacheVolume, image) || !Number.isSafeInteger(container.SizeRw) || container.SizeRw < 0) throw new Error('Local Actions container ownership or writable size differs.');
    writableBytes += container.SizeRw;
    for (const mount of container.Mounts ?? []) if (mount.Type === 'volume' && mount.RW && !volumes.includes(mount.Name)) {
      // The trusted, owned job also mounts act-managed workspace/environment
      // volumes and the shared cache. Account for all of them read-only;
      // observing a mount does not grant cleanup authority over its volume.
      const [resource] = JSON.parse(docker(['volume', 'inspect', mount.Name]));
      if (!resource || resource.Name !== mount.Name) throw new Error('Local Actions mounted volume identity differs.');
      volumes.push(mount.Name);
    }
  }
  let volumeBytes = 0, freeBytes;
  for (let index = 0; index < volumes.length; index++) {
    const name = volumes[index];
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) throw new Error('Local Actions volume name is invalid.');
    const result = docker(['run', '--rm', '--name', `ud-agent-act-meter-${owner}-${index}`, '--label', `${OWNER_LABEL}=${owner}`, '--pull=never', '--network', 'none', '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'DAC_OVERRIDE', '--security-opt', 'no-new-privileges', '--memory', '64m', '--pids-limit', '32', '--mount', `type=volume,src=${name},dst=/cache,readonly`, '--entrypoint', '/bin/sh', image, '-c', 'LC_ALL=C du -s -B1 /cache && LC_ALL=C df -P -B1 /cache']);
    const rows = result.trim().split(/\r?\n/), usage = /^(\d+)\s+\/cache$/.exec(rows[0] ?? ''), free = /^\S+\s+\d+\s+\d+\s+(\d+)\s+\d+%\s+\/cache$/.exec(rows.at(-1) ?? '');
    const size = Number(usage?.[1]), available = Number(free?.[1]);
    if (!usage || !free || !Number.isSafeInteger(size) || size < 0 || !Number.isSafeInteger(available) || available < 0) throw new Error('Local Actions volume or engine free-space observation is unavailable.');
    volumeBytes += size; freeBytes = Math.min(freeBytes ?? available, available);
  }
  if (!Number.isSafeInteger(volumeBytes + writableBytes) || !Number.isSafeInteger(freeBytes)) throw new Error('Local Actions Docker storage size is unavailable.');
  return { volume_bytes: volumeBytes, writable_bytes: writableBytes, size_bytes: volumeBytes + writableBytes, engine_free_bytes: freeBytes };
}

export function checkActDockerStorage(storage, usage, reports) {
  if (!Number.isSafeInteger(reports) || reports < 0 || !Number.isSafeInteger(usage?.size_bytes) || usage.size_bytes < 0 || !Number.isSafeInteger(usage.engine_free_bytes) || usage.engine_free_bytes < 0) throw new Error('Local Actions storage observations are incomplete.');
  const observed = storage.check(usage.size_bytes + reports);
  const remaining = Math.max(0, storage.plannedBytes - observed.usedBytes - usage.size_bytes - reports);
  if (usage.engine_free_bytes - remaining < STORAGE_LIMITS.freeReserveBytes) throw new Error('Local Actions engine cannot preserve the 10 GB free reserve.');
  return observed;
}

export async function runLocalActions({ architecture, job = 'native', dockerHost, emulationProvider }) {
  const { workflowJob, dependencyJobs } = resolveActJob({ job, architecture });
  const needsSdk = dependencyJobs.includes('mutation-sdk');
  const lock = JSON.parse(readFileSync(path.join(root, 'quality/act.lock.json'), 'utf8'));
  const assetRoot = path.resolve(process.env.UD_AGENT_QA_ASSET_ROOT ?? root);
  const storageRoot = path.resolve(process.env.UD_AGENT_STORAGE_ROOT ?? root);
  const executable = path.join(assetRoot, '.artifacts/act/act');
  if (process.platform !== 'darwin' || process.arch !== 'arm64' || digest(readFileSync(executable)) !== lock.darwin_arm64.binary_sha256) throw new Error('Pinned local act executable is unavailable or changed.');
  if (dockerHost !== undefined && (!dockerHost.startsWith('unix://') || !path.resolve(dockerHost.slice(7)).startsWith(path.join(root,'.artifacts')+path.sep))) throw new Error('Local Actions alternate Docker endpoint must be a product-owned Unix socket.');
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key])=>!/(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)/i.test(key)));
  if (dockerHost !== undefined) environment.DOCKER_HOST = dockerHost;
  const docker = args => run('docker',args,{env:environment});
  const authority = localDockerAuthority(environment, context => docker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', ...(context ? [context] : [])]).trim());
  if (authority.transport !== 'unix') throw new Error('Local Actions requires a verified local Unix Docker endpoint.');
  const retainedImages = new Map();
  for (const name of [lock.linux_runner.nonroot_image, ...(needsSdk ? [JSON.parse(readFileSync(path.join(path.resolve(process.env.UD_AGENT_CI_SDK_ROOT ?? path.join(assetRoot, '.artifacts/mutation-ci-sdk')), 'ci-sdk.json'), 'utf8')).image_id] : [])]) {
    const [image] = JSON.parse(docker(['image', 'inspect', name]));
    if (!/^sha256:[a-f0-9]{64}$/.test(image.Id ?? '') || !Number.isSafeInteger(image.Size) || image.Size < 0) throw new Error('Local Actions image size or identity is invalid.');
    retainedImages.set(image.Id, image.Size);
  }
  const imageInventory = inspectOwnedDockerStorage(docker, { selectedImages: [...retainedImages].map(([image_id, size_bytes]) => ({ image_id, size_bytes })), knownImageIds: lockedDockerImages(JSON.parse(readFileSync(path.join(root, 'runtime/runtime.lock.json'), 'utf8'))) });
  let activeChild, stopActive, finishExecution;
  const executionFinished = new Promise(resolve => { finishExecution = resolve; });
  const storage = reserveStorage({ onCancel: async () => { if (activeChild) { stopActive(); await executionFinished; } }, root: storageRoot, ownedRoots: [assetRoot], externalOwnedBytes: imageInventory.image_bytes, ...LOCAL_ACTIONS_STORAGE_PLAN, inputRoots: [root], label: 'local-actions' });
  try {
  const owner = randomUUID().replaceAll('-', '');
  const directory = path.join(storageRoot, '.artifacts/act/runs', owner);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const captured=captureDiagnosticSnapshot(root,path.join(storage.directory,'source'));
  const executionRoot=captured.copy;
  const image = lock.linux_runner.nonroot_image;
  const overlay = path.join(directory, 'workflow.yml');
  const python = process.env.UD_AGENT_PYTHON ?? path.join(root, '.venv/bin/python');
  const socketGid = Number(docker(['run', '--rm', '--name', 'ud-agent-act-probe-' + owner, '--label', `${OWNER_LABEL}=${owner}`, '--pull=never', '--platform', `linux/${architecture}`, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--mount', 'type=bind,source=/var/run/docker.sock,target=/engine.sock,readonly', '--entrypoint', '/usr/bin/stat', image, '-c', '%g', '/engine.sock']).trim());
  if (!Number.isSafeInteger(socketGid) || socketGid < 0) throw new Error('Docker socket group is invalid.');
  const dependencyArgs = dependencyJobs.flatMap(name => ['--dependency-job', name]);
  const receipt = JSON.parse(run(python, [path.join(executionRoot,'scripts/quality/act_overlay.py'), '--workflow', path.join(executionRoot,'.github/workflows/ci.yml'), '--output', overlay, '--job', workflowJob, '--architecture', architecture, '--owner', owner, '--image', image, '--socket-gid', String(socketGid), ...dependencyArgs, ...(needsSdk ? ['--local-sdk'] : [])]));
  const volume = receipt.toolcache_volume;
  const initial = captured.source_tree_sha256;
  if (needsSdk) {
    const sdkRoot = path.resolve(process.env.UD_AGENT_CI_SDK_ROOT ?? path.join(assetRoot, '.artifacts/mutation-ci-sdk'));
    const sdk = JSON.parse(readFileSync(path.join(sdkRoot, 'ci-sdk.json'), 'utf8'));
    const key = run(python, [path.join(executionRoot, 'scripts/quality/prepare-mutation-runtime.py'), '--ci-cache-key'], { cwd: executionRoot }).trim();
    if (sdk.schema_version !== 1 || sdk.cache_key !== key || sdk.archive?.path !== 'sdk-image.tar' || !Number.isSafeInteger(sdk.archive.size_bytes) || !/^[a-f0-9]{64}$/.test(sdk.archive.sha256 ?? '')) throw new Error('Prepared CI SDK does not match the candidate inputs.');
    storage.copy(path.join(sdkRoot, 'sdk-image.tar'), path.relative(storage.directory, path.join(executionRoot, '.artifacts/mutation-ci-sdk/sdk-image.tar')).split(path.sep).join('/'), { size: sdk.archive.size_bytes, sha256: sdk.archive.sha256 });
    for (const name of ['ci-sdk.json', 'input-receipt.json']) storage.copy(path.join(sdkRoot, name), path.relative(storage.directory, path.join(executionRoot, '.artifacts/mutation-ci-sdk', name)).split(path.sep).join('/'));
  }
  storage.check();
  const outcome = { ...receipt, source_tree_sha256: initial, execution_root: executionRoot, host:{os:process.platform,architecture:process.arch}, worker:{os:'linux',architecture,emulated:architecture!=='arm64',...(architecture==='amd64'?{qemu_cpu:'max',emulation_provider:emulationProvider??'docker-qemu'}:{})}, ...(dockerHost?{docker_endpoint:dockerHost}:{}), docker_storage_checks: 'preflight', started_at: new Date().toISOString(), status: 'failed', cleanup: 'pending' };
  const save = () => writeFileSync(path.join(directory, 'run.json'), JSON.stringify(outcome, null, 2) + '\n');
  save();
  let created = false;
  try {
    docker(['volume', 'create', '--label', `${OWNER_LABEL}=${owner}`, volume]); created = true;
    const dockerUsage = measureActDockerUsage(docker, owner, volume, image);
    checkActDockerStorage(storage, dockerUsage, storageTreeBytes(directory));
    outcome.preflight_docker_bytes = dockerUsage.size_bytes;
    outcome.preflight_engine_free_bytes = dockerUsage.engine_free_bytes;
    // Only the newly created, owned cache is writable. Product workers and the
    // Trusted workflow driver receives the verified engine route; ordinary
    // mutation workers retain their separate socket-free containment.
    docker(['run', '--rm', '--name', 'ud-agent-act-init-' + owner, '--label', `${OWNER_LABEL}=${owner}`, '--pull=never', '--platform', `linux/${architecture}`, '--network', 'none', '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges', '--mount', `type=volume,source=${volume},target=/cache`, '--entrypoint', '/bin/chown', image, '1001:1001', '/cache']);
    const args = buildActArgs({ overlay, job, architecture, image, cacheRoot: path.join(assetRoot, '.artifacts/act/cache/act'), serviceRoot: path.join(storage.directory, 'services'), dockerSocket: authority.endpoint, owner });
    const log = path.join(directory, 'workflow.log');
    const { openSync, closeSync } = await import('node:fs');
    const output = openSync(log, 'wx', 0o600);
    try {
      const child = activeChild = spawn(executable, args, { cwd: executionRoot, env: { ...environment, XDG_CACHE_HOME: path.join(assetRoot, '.artifacts/act/cache') }, stdio: ['ignore', 'pipe', 'pipe'] });
      let forceStop;
      stopActive = () => { child.kill('SIGTERM'); forceStop ??= setTimeout(() => child.kill('SIGKILL'), 5000); forceStop.unref(); };
      const capture = chunk => { writeSync(output, chunk); };
      child.stdout.on('data', capture); child.stderr.on('data', capture);
      const timeout = setTimeout(() => { outcome.error ??= 'Local Actions exceeded its 45-minute execution limit.'; stopActive(); }, 45 * 60 * 1000);
      let result;
      try { result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); }); }
      finally { clearTimeout(timeout); clearTimeout(forceStop); }
      if (outcome.error) throw new Error(outcome.error);
      outcome.exit_code = result.code; outcome.signal = result.signal;
      outcome.source_unchanged = sourceReceipt(executionRoot).sha256 === initial;
      outcome.original_source_unchanged = sourceReceipt(root).sha256 === initial;
      outcome.status = result.code === 0 && !result.signal && outcome.source_unchanged ? 'passed' : 'failed';
      outcome.log = log;
    } finally { closeSync(output); }
  } catch (error) { outcome.error = error.message; }
  finally {
    if (created) {
      try {
        const [found] = JSON.parse(docker(['volume', 'inspect', volume]));
        if (found.Name !== volume || found.Labels?.[OWNER_LABEL] !== owner) throw new Error('Local Actions cache ownership changed.');
        const consumers = docker(['ps', '-aq', '--filter', `label=${OWNER_LABEL}=${owner}`]).trim().split(/\s+/).filter(Boolean);
        for (const id of consumers) {
          const [container] = JSON.parse(docker(['inspect', id]));
          if (container.Id !== id && !container.Id.startsWith(id)) throw new Error('Local Actions container identity changed.');
          if (!ownedActContainer(container, owner, volume, image)) throw new Error('Local Actions consumer ownership changed.');
          docker(['rm', '--force', container.Id]);
        }
        const nested = docker(['volume', 'ls', '-q', '--filter', `label=${OWNER_LABEL}=${owner}`]).trim().split(/\s+/).filter(Boolean);
        for (const name of nested.filter(name => name !== volume)) {
          const [resource] = JSON.parse(docker(['volume', 'inspect', name]));
          if (!isOwnedActMutationResource(resource, owner, 'volume')) throw new Error('Local Actions nested volume ownership changed.');
          docker(['volume', 'rm', name]);
        }
        docker(['volume', 'rm', volume]);
        outcome.cleanup = 'verified';
      } catch (error) { outcome.cleanup = 'failed'; outcome.cleanup_error = error.message; outcome.status = 'failed'; }
    } else outcome.cleanup = 'not_created';
    try { storage.cleanup(); outcome.scratch_cleanup = 'verified'; } catch (error) { outcome.scratch_cleanup = 'failed'; outcome.cleanup_error ??= error.message; outcome.status = 'failed'; }
    outcome.finished_at = new Date().toISOString(); save();
  }
  return { ...outcome, receipt: path.join(directory, 'run.json') };
  } finally { try { storage.cleanup(); } finally { finishExecution(); } }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [architecture, job = 'native'] = process.argv.slice(2);
  if (!['amd64', 'arm64'].includes(architecture) || process.argv.length > 4) throw new Error('Usage: run-act.mjs amd64|arm64 [native|node24|mutation]');
  const result = await runLocalActions({ architecture, job });
  console.log(JSON.stringify(result)); process.exitCode = result.status === 'passed' ? 0 : 1;
}
