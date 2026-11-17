import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { chmod, mkdir, rm, writeFile } from 'node:fs/promises';
import type { Host } from '../../runtime-manager/src/profiles.js';
import type { ImageReceipt } from '../../runtime-manager/src/receipt.js';
import { readBoundedReceiptBytes, verifyArchive } from '../../runtime-manager/src/receipt.js';
import { createHash } from 'node:crypto';
import { inspectLocalDocker } from '../../runtime-manager/src/docker-inspection.js';
import { runEngineCommand as runCommand, withEngineSupervisor, withoutEngineCancellation, engineSupervisor, workerStreamError } from './engine-command.js';
import { supervisedCommand } from '../../runtime-manager/src/supervised-command.js';
import type { CommandSupervisor } from '../../runtime-manager/src/supervised-command.js';
import { captureValidationSnapshot, operationInputPaths, verifySnapshotIntegrity } from '../../workspace/src/snapshot.js';
import { captureOperationSnapshot } from '../../workspace/src/input-broker.js';
import type { ContextBundle } from '../../workspace/src/input-broker.js';
import { streamVerifiedSnapshot } from '../../workspace/src/snapshot-transfer.js';
import { encodeSnapshotFrames } from '../../workspace/src/snapshot-wire.js';
import { DockerJobJournal, localDockerEndpoint } from './docker-journal.js';
import { inspectDockerJob, inspectDockerVolume } from './docker-policy.js';
import type { DockerJobPolicy } from './docker-policy.js';
import { currentProviderLease, providerLeaseActive, withProviderLease } from './provider-leases.js';
import { JournalStore } from '../../workspace/src/journal.js';
import { verifyDockerCleanupAuthority } from './docker-authority.js';
import type { DockerCleanupAuthority } from './docker-authority.js';

type DockerValidationInput = {
  engine: string; engineSha256: string; guard: string; guardSha256: string; image: ImageReceipt;
  host: Host; stateRoot: string; workingTree: string; allowedRoots: readonly string[];
  filePaths: string[]; options: Record<string, unknown>; signal?: AbortSignal;
  expectedIdentity?: Readonly<{ endpoint: string; daemonId: string; imageId: string; rootless: boolean | null; daemonArchitecture?: string; workerArchitecture?: string; emulation?: boolean }>;
  selectAllFiles?: boolean;
  operation?: string; arguments?: Record<string, unknown>; contextBundle?: ContextBundle;
};
type Result = { result: Record<string, unknown>; snapshot: { root_identity?: { device: string; inode: string }; sha256: string; files: { path: string; size: number; sha256: string }[]; source_map?: { snapshot_path: string; original_path: string }[] }; runtime: 'docker' };
const ENTRYPOINT = ['/usr/local/bin/python'];
const PREFIX = `import sys;sys.path[:0]=['/opt/ud-agent/worker','/opt/ud-agent/upstream/udtools/src'];`;
const LOADER = `${PREFIX}from ud_agent.oci_loader import main;raise SystemExit(main())`;
const WORKER = `${PREFIX}from ud_agent.oci_worker import main;raise SystemExit(main())`;
const LIMITS = { timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024 };

function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function json(bytes: Buffer): unknown { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; } catch { throw new Error('DOCKER_RESPONSE_INVALID'); } }
function commandArgs(name: string, id: string, imageId: string, volume: string, readOnly: boolean, command: string[], seccompPath?: string): string[] {
  return ['create', '--name', name, '--label', `io.ud-agent.job=${id}`, '--pull=never', '--interactive',
    '--user', '10001:10001', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--memory', String(2 * 1024 * 1024 * 1024), '--cpus', '2', '--pids-limit', '128',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=67108864', '--mount', `type=volume,src=${volume},dst=/input${readOnly ? ',readonly' : ''}`,
    ...(seccompPath ? ['--security-opt', `seccomp=${seccompPath}`] : []), '--entrypoint', ENTRYPOINT[0]!, imageId, ...command];
}
function dockerEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/usr/bin:/bin', LANG: 'C' };
  for (const key of ['HOME', 'USERPROFILE', 'SystemRoot', 'TMPDIR', 'TMP', 'TEMP', 'USER', 'LOGNAME'] as const) if (process.env[key] !== undefined) env[key] = process.env[key];
  return env;
}

/** Start one recorded container with bounded streaming input and output. */
async function attach(engine: string, endpoint: string, id: string, input: AsyncIterable<Buffer>, authority: CommandSupervisor, signal?: AbortSignal): Promise<Buffer> {
  if (signal?.aborted) throw new Error('WORKER_CANCELLED');
  try {
    const result = await supervisedCommand(engine, ['--host', endpoint, 'start', '--attach', '--interactive', id], input, authority,
      { timeoutMs: 300000, maxStdoutBytes: 32 * 1024 * 1024, maxStderrBytes: 1024 * 1024, maxInputBytes: 20 * 1024 * 1024 * 1024 }, dockerEnvironment(), signal);
    if (result.code !== 0) throw new Error('DOCKER_WORKER_FAILED');
    return result.stdout;
  } catch (problem) { return workerStreamError(problem); }
}

async function* one(data: Buffer): AsyncGenerator<Buffer> { yield data; }

function parseLine(data: Buffer): Record<string, unknown> {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(data);
  if (!text.endsWith('\n') || text.slice(0, -1).includes('\n')) throw new Error('DOCKER_WORKER_RESPONSE_INVALID');
  const parsed = object(json(Buffer.from(text.slice(0, -1))));
  if (!parsed) throw new Error('DOCKER_WORKER_RESPONSE_INVALID');
  return parsed;
}

async function dockerCommand(engine: string, endpoint: string, args: string[]) { return runCommand(engine, ['--host', endpoint, ...args], LIMITS); }

async function inspectContainer(engine: string, endpoint: string, id: string): Promise<unknown | undefined> {
  const result = await dockerCommand(engine, endpoint, ['container', 'inspect', id]);
  if (result.code === 0) return json(result.stdout);
  const listing = await dockerCommand(engine, endpoint, ['container', 'ls', '--all', '--no-trunc', '--filter', `id=${id}`, '--format', '{{.ID}}']);
  if (listing.code !== 0 || listing.stdout.toString('utf8').trim() !== '') throw new Error('DOCKER_CLEANUP_UNVERIFIED');
  return undefined;
}

async function removeContainer(engine: string, endpoint: string, id: string, name: string, jobId: string, imageId: string): Promise<void> {
  const inspected = await inspectContainer(engine, endpoint, id);
  if (inspected === undefined) return;
  const item = Array.isArray(inspected) && inspected.length === 1 ? object(inspected[0]) : undefined;
  const labels = object(object(item?.Config)?.Labels);
  if (!item || item.Id !== id || item.Name !== `/${name}` || item.Image !== imageId || labels?.['io.ud-agent.job'] !== jobId) throw new Error('DOCKER_CLEANUP_OWNERSHIP_MISMATCH');
  const removed = await dockerCommand(engine, endpoint, ['container', 'rm', '--force', id]);
  if (removed.code !== 0 || await inspectContainer(engine, endpoint, id) !== undefined) throw new Error('DOCKER_CLEANUP_UNVERIFIED');
}

async function removeVolume(engine: string, endpoint: string, volume: string, jobId: string): Promise<void> {
  const inspected = await dockerCommand(engine, endpoint, ['volume', 'inspect', volume]);
  if (inspected.code !== 0) {
    const list = await dockerCommand(engine, endpoint, ['volume', 'ls', '--filter', `label=io.ud-agent.job=${jobId}`, '--format', '{{.Name}}']);
    if (list.code !== 0 || list.stdout.toString('utf8').split(/\r?\n/).includes(volume)) throw new Error('DOCKER_CLEANUP_UNVERIFIED');
    return;
  }
  if (!inspectDockerVolume(json(inspected.stdout), volume, jobId)) throw new Error('DOCKER_CLEANUP_OWNERSHIP_MISMATCH');
  const removed = await dockerCommand(engine, endpoint, ['volume', 'rm', volume]);
  if (removed.code !== 0) throw new Error('DOCKER_CLEANUP_UNVERIFIED');
  const after = await dockerCommand(engine, endpoint, ['volume', 'ls', '--filter', `label=io.ud-agent.job=${jobId}`, '--format', '{{.Name}}']);
  if (after.code !== 0 || after.stdout.toString('utf8').split(/\r?\n/).includes(volume)) throw new Error('DOCKER_CLEANUP_UNVERIFIED');
}

async function daemonInfo(engine: string, endpoint: string): Promise<Record<string, unknown>> {
  const result = await dockerCommand(engine, endpoint, ['info', '--format', '{{json .}}']);
  const info = result.code === 0 ? object(json(result.stdout)) : undefined;
  if (!info || typeof info.ID !== 'string' || !/^[A-Za-z0-9:_.-]{1,256}$/.test(info.ID) || typeof info.Architecture !== 'string') throw new Error('DOCKER_DAEMON_IDENTITY_UNVERIFIED');
  return info;
}

/** Bind the local daemon independently of any image or acquisition step. */
export async function inspectDockerDaemonIdentity(engine: string, host: Host): Promise<{ endpoint: string; daemonId: string; architecture: string; rootless: boolean | null }> {
  // Discovery retains its read-only availability result. An admitted native
  // scope must propagate guardian/integrity failures instead of hiding them as
  // an unavailable engine and accidentally selecting a fallback.
  const supervised = engineSupervisor(engine);
  const docker = supervised ? undefined : await inspectLocalDocker(engine, host);
  if (docker && docker.status !== 'available') throw new Error('DOCKER_ENGINE_UNAVAILABLE');
  const context = await runCommand(engine, ['context', 'inspect'], LIMITS);
  const contexts = context.code === 0 ? json(context.stdout) : undefined;
  const endpoint = Array.isArray(contexts) && contexts.length === 1 ? object(object(object(contexts[0])?.Endpoints)?.docker)?.Host : undefined;
  if (typeof endpoint !== 'string' || !localDockerEndpoint(endpoint)) throw new Error('DOCKER_ENDPOINT_UNVERIFIED');
  const daemon = await daemonInfo(engine, endpoint);
  if (supervised && (typeof daemon.ServerVersion !== 'string' || !daemon.ServerVersion || !Array.isArray(daemon.SecurityOptions) || daemon.SecurityOptions.some(value => typeof value !== 'string'))) throw new Error('DOCKER_DAEMON_IDENTITY_UNVERIFIED');
  const rootless = supervised ? (daemon.SecurityOptions as string[]).some(value => value === 'name=rootless' || value.startsWith('name=rootless,')) : docker!.rootless;
  const architecture = daemon.Architecture === 'x86_64' ? 'amd64' : daemon.Architecture === 'aarch64' ? 'arm64' : daemon.Architecture;
  if (!['amd64', 'arm64'].includes(architecture as string)) throw new Error('DOCKER_DAEMON_ARCHITECTURE_MISMATCH');
  return { endpoint, daemonId: daemon.ID as string, architecture: architecture as string, rootless };
}

/** Read-only identity check. This does not create containers or attest confinement. */
export async function inspectDockerImageIdentity(engine: string, host: Host, image: ImageReceipt): Promise<{ endpoint: string; daemonId: string; imageId: string; rootless: boolean | null; daemonArchitecture?: string; workerArchitecture?: string; emulation?: boolean }> {
  const daemon = await inspectDockerDaemonIdentity(engine, host);
  const { endpoint } = daemon;
  let imageResult;
  for (const identity of image.configDigest ? [image.configDigest, ...(image.engineDescriptorDigests ?? [])] : [image.reference]) {
    imageResult = await dockerCommand(engine, endpoint, ['image', 'inspect', '--platform', `linux/${host.arch === 'x64' ? 'amd64' : host.arch}`, identity]); if (imageResult.code === 0) break;
  }
  if (!imageResult || imageResult.code !== 0) throw new Error('DOCKER_IMAGE_NOT_PRESENT');
  const imageData = imageResult.code === 0 ? json(imageResult.stdout) : undefined;
  const found = Array.isArray(imageData) && imageData.length === 1 ? object(imageData[0]) : undefined;
  const imageId = found?.Id;
  const expectedArch = host.arch === 'x64' ? 'amd64' : host.arch;
  if (!['amd64', 'arm64'].includes(daemon.architecture) || typeof imageId !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(imageId) || found?.Os !== 'linux' || found?.Architecture !== expectedArch) throw new Error('DOCKER_IMAGE_NOT_VERIFIED');
  if (image.configDigest !== undefined) {
    const rootfs = object(found.RootFS);
    const descriptor = object(found.Descriptor);
    const configIdentity = imageId === image.configDigest;
    const indexIdentity = image.engineDescriptorDigests?.includes(imageId) === true && descriptor?.digest === imageId && ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'].includes(descriptor.mediaType as string);
    if ((!configIdentity && !indexIdentity) || !image.diffIds?.length || rootfs?.Type !== 'layers' || !Array.isArray(rootfs.Layers) || rootfs.Layers.length !== image.diffIds.length || rootfs.Layers.some((layer, index) => layer !== image.diffIds?.[index])) throw new Error('DOCKER_IMAGE_NOT_VERIFIED');
  } else if (!Array.isArray(found?.RepoDigests) || !found.RepoDigests.includes(image.reference)) throw new Error('DOCKER_IMAGE_NOT_VERIFIED');
  return { endpoint, daemonId: daemon.daemonId, imageId, rootless: daemon.rootless, daemonArchitecture: daemon.architecture, workerArchitecture: expectedArch, emulation: daemon.architecture !== expectedArch };
}

/** Reconcile only journaled resources after a settled create/attach sequence. */
export async function recoverDockerValidation(stateRoot: string, id: string, guard?: string, authority?: DockerCleanupAuthority): Promise<void> {
  if (authority && !engineSupervisor(authority.engine)) {
    const verified = await verifyDockerCleanupAuthority(authority);
    if (!verified.guardSha256) throw new Error('DOCKER_CLEANUP_GUARD_IDENTITY_REQUIRED');
    return withEngineSupervisor({ engine: verified.engine, guard: verified.guard, guardSha256: verified.guardSha256, executableSha256: verified.engineSha256 }, () => recoverDockerValidation(stateRoot, id, guard, verified));
  }
  const journal = await DockerJobJournal.open(stateRoot, guard);
  await journal.withRecoveryLock(id, async () => {
    let job = await journal.load(id);
    if (job.phase === 'cleaned') return;
    if (job.owner_lease) { if (!guard) throw new Error('DOCKER_RECOVERY_GUARD_REQUIRED'); if (await providerLeaseActive(guard, stateRoot, job.owner_lease)) throw new Error('DOCKER_JOB_OWNER_ACTIVE'); }
    else try { process.kill(job.owner_pid, 0); throw new Error('DOCKER_JOB_OWNER_ACTIVE'); }
    catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
    }
    if (authority) {
      const fresh = await verifyDockerCleanupAuthority(authority);
      if (fresh.identity.endpoint !== job.endpoint || fresh.identity.daemonId !== job.daemon_id) throw new Error('DOCKER_DAEMON_CHANGED');
      if (job.engine !== fresh.engine || job.engine_sha256 !== fresh.engineSha256) { await journal.recordEngineCleanup(id, fresh.engine, fresh.engineSha256); job = await journal.load(id); }
    }
    await verifyArchive(job.engine, job.engine_sha256);
    if ((await daemonInfo(job.engine, job.endpoint)).ID !== job.daemon_id) throw new Error('DOCKER_DAEMON_CHANGED');
    const loaderName = `ud-agent-${id}-loader`; const workerName = `ud-agent-${id}-worker`; const volume = `ud-agent-${id}-input`;
    if (job.phase === 'volume_pending') {
      const found = await dockerCommand(job.engine, job.endpoint, ['volume', 'inspect', volume]);
      if (found.code !== 0) throw new Error('DOCKER_CREATE_OUTCOME_UNKNOWN: the unsettled create has not produced an observable resource.');
      if (!inspectDockerVolume(json(found.stdout), volume, id)) throw new Error('DOCKER_CLEANUP_OWNERSHIP_MISMATCH');
      job = await journal.transition(id, 'volume_ready');
    } else if (job.phase === 'loader_pending' || job.phase === 'worker_pending') {
      const name = job.phase === 'loader_pending' ? loaderName : workerName;
      const raw = await inspectContainer(job.engine, job.endpoint, name);
      const found = Array.isArray(raw) && raw.length === 1 ? object(raw[0]) : undefined;
      if (!found) throw new Error('DOCKER_CREATE_OUTCOME_UNKNOWN: the unsettled create has not produced an observable resource.');
      const labels = object(object(found.Config)?.Labels);
      if (typeof found.Id !== 'string' || !/^[a-f0-9]{64}$/.test(found.Id) || found.Name !== `/${name}` || found.Image !== job.image_id || labels?.['io.ud-agent.job'] !== id) throw new Error('DOCKER_CLEANUP_OWNERSHIP_MISMATCH');
      job = job.phase === 'loader_pending' ? await journal.transition(id, 'loader_created', { loader_id: found.Id }) : await journal.transition(id, 'worker_created', { worker_id: found.Id });
    }
    const current = job.phase === 'cleanup_pending' ? job : await journal.transition(id, 'cleanup_pending');
    if (current.worker_id) await removeContainer(current.engine, current.endpoint, current.worker_id, workerName, id, current.image_id);
    if (current.loader_id) await removeContainer(current.engine, current.endpoint, current.loader_id, loaderName, id, current.image_id);
    // `planned` precedes volume creation; all later settled phases may own it.
    if (job.phase !== 'planned') await removeVolume(current.engine, current.endpoint, volume, id);
    await journal.transition(id, 'cleaned');
  });
}

/**
 * Execute one validation using only a locally present immutable image. Callers
 * must supply identities from a verified product receipt. A failed or timed-out
 * create remains journaled for reconciliation; it is never called clean.
 */
export async function runDockerValidation(input: DockerValidationInput): Promise<Result> {
  if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
  if (!path.isAbsolute(input.engine) || !path.isAbsolute(input.guard) || !path.isAbsolute(input.workingTree) || !path.isAbsolute(input.stateRoot)) throw new Error('Invalid Docker runtime paths.');
  await verifyArchive(input.guard, input.guardSha256);
  await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
  await JournalStore.open(input.stateRoot, input.guard);
  return withEngineSupervisor({ engine: input.engine, guard: input.guard, guardSha256: input.guardSha256, executableSha256: input.engineSha256, ...(input.signal ? { signal: input.signal } : {}) },
    () => withProviderLease(input.guard, input.stateRoot, () => runDockerJob(input), input.signal ? { signal: input.signal } : {}));
}

async function runDockerJob(input: DockerValidationInput): Promise<Result> {
  if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
  if (!path.isAbsolute(input.engine) || !path.isAbsolute(input.guard) || !path.isAbsolute(input.workingTree) || !path.isAbsolute(input.stateRoot)) throw new Error('Invalid Docker runtime paths.');
  if (!/^sha256:[0-9a-f]{64}$/.test(input.image.digest) || !/^sha256:[0-9a-f]{64}$/.test(input.image.contextSha256) || !/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(input.image.reference) || !input.image.reference.endsWith(`@${input.image.digest}`)) throw new Error('DOCKER_IMAGE_RECEIPT_INVALID');
  await verifyArchive(input.engine, input.engineSha256); await verifyArchive(input.guard, input.guardSha256);
  const { endpoint, daemonId, imageId, rootless, daemonArchitecture, workerArchitecture, emulation } = await inspectDockerImageIdentity(input.engine, input.host, input.image);
  if (input.expectedIdentity && (endpoint !== input.expectedIdentity.endpoint || daemonId !== input.expectedIdentity.daemonId || imageId !== input.expectedIdentity.imageId || rootless !== input.expectedIdentity.rootless || input.expectedIdentity.daemonArchitecture !== undefined && daemonArchitecture !== input.expectedIdentity.daemonArchitecture || input.expectedIdentity.workerArchitecture !== undefined && workerArchitecture !== input.expectedIdentity.workerArchitecture || input.expectedIdentity.emulation !== undefined && emulation !== input.expectedIdentity.emulation)) throw new Error('DOCKER_IDENTITY_CHANGED');
  const assertDaemon = async () => { if ((await daemonInfo(input.engine, endpoint)).ID !== daemonId) throw new Error('DOCKER_DAEMON_CHANGED'); };
  const operation = input.operation ?? 'validation_report';
  if (!/^(?:[a-z][a-z0-9_]*|_project_rules)$/.test(operation)) throw new Error('Invalid worker operation.');
  const operationArguments = input.arguments ?? { file_paths: input.filePaths, options: input.options };
  const captured = await captureOperationSnapshot(input.guard, { ...operationArguments, working_tree_path: input.workingTree }, input.allowedRoots, input.signal, undefined, operation, input.contextBundle);
  const snapshot = captured.snapshot;
  let seccompPath: string | undefined, seccomp: Record<string, unknown> | undefined;
  try {
    if (input.image.seccompProfile) {
      const bytes = await readBoundedReceiptBytes(input.image.seccompProfile.path);
      if (bytes.length !== input.image.seccompProfile.sizeBytes || `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== input.image.seccompProfile.sha256) throw new Error('DOCKER_SECCOMP_CHANGED');
      const parsed = object(json(bytes)); if (!parsed || parsed.defaultAction !== 'SCMP_ACT_ERRNO') throw new Error('DOCKER_SECCOMP_POLICY_INVALID');
      seccomp = parsed;
      await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
      seccompPath = path.join(input.stateRoot, `seccomp-${randomUUID()}.json`);
      await writeFile(seccompPath, bytes, { flag: 'wx', mode: 0o400 }); await chmod(seccompPath, 0o400);
    }
    await verifySnapshotIntegrity(input.guard, snapshot, input.signal);
    const filePaths = input.selectAllFiles ? snapshot.files.filter(file => file.path.endsWith('.conllu') && !file.path.startsWith('.ud-agent-inputs/')).map(file => file.path) : (captured.arguments.file_paths ?? input.filePaths) as string[];
    const available = new Set(snapshot.files.map(file => file.path));
    if (operation === 'validation_report' && (!Array.isArray(filePaths) || filePaths.length === 0 || filePaths.length > 10_000 || filePaths.some(file => typeof file !== 'string' || !available.has(file)) || new Set(filePaths).size !== filePaths.length)) throw new Error('Selected files must identify distinct snapshot files.');
    const id = randomUUID(); const volume = `ud-agent-${id}-input`; const loaderName = `ud-agent-${id}-loader`; const workerName = `ud-agent-${id}-worker`;
    const loaderCommand = ['-I', '-B', '-c', LOADER, snapshot.sha256]; const workerCommand = ['-I', '-B', '-c', WORKER];
    const journal = await DockerJobJournal.open(input.stateRoot, input.guard);
    const ownerLease = await currentProviderLease(input.stateRoot); if (!ownerLease) throw new Error('DOCKER_PROVIDER_LEASE_REQUIRED');
    await journal.create({ version: 1, id, engine: input.engine, engine_sha256: input.engineSha256, image_digest: input.image.digest, image_id: imageId, endpoint, daemon_id: daemonId, owner_pid: process.pid, owner_lease: ownerLease, phase: 'planned' });
    let loaderId: string | undefined; let workerId: string | undefined; let volumeCreated = false; let uncertain = false; let response: Record<string, unknown> | undefined; let failure: unknown;
    try {
      await assertDaemon(); await journal.transition(id, 'volume_pending'); uncertain = true;
      const createdVolume = await dockerCommand(input.engine, endpoint, ['volume', 'create', '--label', `io.ud-agent.job=${id}`, volume]);
      if (createdVolume.code !== 0 || createdVolume.stdout.toString('utf8').trim() !== volume) throw new Error('DOCKER_VOLUME_CREATE_FAILED');
      uncertain = false;
      volumeCreated = true; await journal.transition(id, 'volume_ready');
      const volumeInfo = await dockerCommand(input.engine, endpoint, ['volume', 'inspect', volume]);
      if (volumeInfo.code !== 0 || !inspectDockerVolume(json(volumeInfo.stdout), volume, id)) throw new Error('DOCKER_VOLUME_UNVERIFIED');
      const create = async (name: string, command: string[], readOnlyInput: boolean): Promise<string> => {
        await assertDaemon();
        uncertain = true;
        const result = await dockerCommand(input.engine, endpoint, commandArgs(name, id, imageId, volume, readOnlyInput, command, seccompPath));
        const container = result.stdout.toString('utf8').trim();
        if (result.code !== 0 || !/^[0-9a-f]{64}$/.test(container)) throw new Error('DOCKER_CONTAINER_CREATE_FAILED');
        uncertain = false;
        return container;
      };
      const inspect = async (container: string, name: string, command: string[], readOnlyInput: boolean) => {
        const raw = await inspectContainer(input.engine, endpoint, container);
        const policy: DockerJobPolicy = { name, jobId: id, imageId, containerId: container, volume, readOnlyInput, entrypoint: ENTRYPOINT, command, ...(seccomp ? { seccomp } : {}) };
        const violations = inspectDockerJob(raw, policy);
        if (violations.length) throw new Error(`DOCKER_CONTAINER_POLICY_FAILED: ${violations.join(', ')}`);
      };
      await journal.transition(id, 'loader_pending');
      loaderId = await create(loaderName, loaderCommand, false);
      await journal.transition(id, 'loader_created', { loader_id: loaderId });
      await inspect(loaderId, loaderName, loaderCommand, false);
      await assertDaemon();
      const supervisor = { guard: input.guard, guardSha256: input.guardSha256, executableSha256: input.engineSha256 };
      const loaded = parseLine(await attach(input.engine, endpoint, loaderId, encodeSnapshotFrames(streamVerifiedSnapshot(input.guard, snapshot, input.signal)), supervisor, input.signal));
      if (loaded.status !== 'loaded' || loaded.snapshot_sha256 !== snapshot.sha256) throw new Error('DOCKER_SNAPSHOT_LOAD_FAILED');
      await journal.transition(id, 'loaded'); await journal.transition(id, 'worker_pending');
      workerId = await create(workerName, workerCommand, true);
      await journal.transition(id, 'worker_created', { worker_id: workerId });
      await inspect(workerId, workerName, workerCommand, true);
      await assertDaemon();
      const args = { ...captured.arguments, ...(operation === 'validation_report' ? { file_paths: filePaths } : {}) };
      const request = Buffer.from(`${JSON.stringify({ operation, arguments: args, snapshot_sha256: snapshot.sha256, files: snapshot.files, ...(captured.brokerEvidence ? { broker_evidence: captured.brokerEvidence } : {}) })}\n`);
      if (request.length > 16 * 1024 * 1024) throw new Error('WORKER_REQUEST_TOO_LARGE');
      response = parseLine(await attach(input.engine, endpoint, workerId, one(request), supervisor, input.signal));
      await journal.transition(id, 'ran');
    } catch (error: unknown) { failure = error; }
    if (uncertain) throw new Error('DOCKER_CREATE_OUTCOME_UNKNOWN: owned job requires reconciliation.');
    try {
      await withoutEngineCancellation(async () => {
        await journal.transition(id, 'cleanup_pending');
        await verifyArchive(input.engine, input.engineSha256);
        await assertDaemon();
        if (workerId) await removeContainer(input.engine, endpoint, workerId, workerName, id, imageId);
        if (loaderId) await removeContainer(input.engine, endpoint, loaderId, loaderName, id, imageId);
        if (volumeCreated) await removeVolume(input.engine, endpoint, volume, id);
        await journal.transition(id, 'cleaned');
      });
    } catch { throw new Error('DOCKER_CLEANUP_UNVERIFIED: owned job requires reconciliation.'); }
    if (failure) throw failure;
    if (!response || response.ok !== true || !response.result || typeof response.result !== 'object' || Array.isArray(response.result)) {
      const error = object(response?.error);
      if (error && typeof error.code === 'string' && typeof error.message === 'string') { const value = new Error(error.message) as Error & { code: string }; value.code = error.code; throw value; }
      throw new Error('DOCKER_WORKER_RESPONSE_INVALID');
    }
    return { result: response.result as Record<string, unknown>, snapshot: { root_identity: snapshot.root_identity, sha256: snapshot.sha256, files: snapshot.files, source_map: captured.sourceMap }, runtime: 'docker' };
  } finally { await snapshot.cleanup(); if (seccompPath) await rm(seccompPath, { force: true }); }
}
