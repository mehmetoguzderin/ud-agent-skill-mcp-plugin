import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Host } from '../../runtime-manager/src/profiles.js';
import type { ImageReceipt } from '../../runtime-manager/src/receipt.js';
import { readBoundedReceiptBytes, verifyArchive } from '../../runtime-manager/src/receipt.js';
import { runEngineCommand as runCommand, withEngineSupervisor, withoutEngineCancellation, engineSupervisor, workerStreamError } from './engine-command.js';
import { supervisedCommand } from '../../runtime-manager/src/supervised-command.js';
import type { CommandSupervisor } from '../../runtime-manager/src/supervised-command.js';
import { verifySnapshotIntegrity } from '../../workspace/src/snapshot.js';
import { captureOperationSnapshot } from '../../workspace/src/input-broker.js';
import type { ContextBundle } from '../../workspace/src/input-broker.js';
import { streamVerifiedSnapshot } from '../../workspace/src/snapshot-transfer.js';
import { encodeSnapshotFrames } from '../../workspace/src/snapshot-wire.js';
import { guardedIdentity, guardedRead } from '../../workspace/src/guard.js';
import { PodmanJobJournal, samePodmanVmForCleanup } from './podman-journal.js';
import { inspectPodmanInputVolume, inspectPodmanWorker, inspectPodmanWorkerSpec } from './podman-policy.js';
import { currentProviderLease, providerLeaseActive, withProviderLease } from './provider-leases.js';
import { JournalStore } from '../../workspace/src/journal.js';
import { verifyPodmanCleanupAuthority } from './podman-authority.js';
import type { PodmanCleanupAuthority } from './podman-authority.js';
import type { PodmanWorkerPolicy } from './podman-policy.js';
import { podmanVmContext, podmanVmForIdentity, withPodmanVm, podmanVmCommand, podmanVmStream, podmanVmDirectoryIdentity, podmanVmPrivateDirectory, podmanVmRead, podmanVmPolicy } from './podman-vm.js';

export type PodmanIdentity = Readonly<{ graphRoot: string; graphIdentity: string; architecture: string; imageId: string; rootless: true; environment: readonly string[]; runRoot: string; runIdentity: string; kernelRelease: string; virtualMachine?: string }>;
export type PodmanWorkerInput = { engine: string; engineSha256: string; guard: string; guardSha256: string; image: ImageReceipt; host: Host; stateRoot: string; workingTree: string; allowedRoots: readonly string[]; filePaths: string[]; options: Record<string, unknown>; signal?: AbortSignal; expectedIdentity?: PodmanIdentity; selectAllFiles?: boolean; operation?: string; arguments?: Record<string, unknown>; contextBundle?: ContextBundle };
type Result = { result: Record<string, unknown>; snapshot: { sha256: string; files: { path: string; size: number; sha256: string }[]; source_map?: { snapshot_path: string; original_path: string }[]; root_identity?: { device: string; inode: string } }; runtime: 'podman' };
const PREFIX = "import sys;sys.path[:0]=['/opt/ud-agent/worker','/opt/ud-agent/upstream/udtools/src'];";
const LOADER = `${PREFIX}from ud_agent.oci_loader import main;raise SystemExit(main())`;
const WORKER = `${PREFIX}from ud_agent.oci_worker import main;raise SystemExit(main())`;
const ENTRYPOINT = ['/usr/local/bin/python'];
const LIMITS = { timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024 };
const CONF = '[containers]\nmounts = []\n[engine]\nhooks_dir = []\n';
function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function json(bytes: Buffer): unknown { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('PODMAN_RESPONSE_INVALID'); } }
function prefixed(value: unknown): string | undefined { return typeof value === 'string' && /^(?:sha256:)?[0-9a-f]{64}$/.test(value) ? value.startsWith('sha256:') ? value : `sha256:${value}` : undefined; }
async function cmd(engine: string, args: readonly string[], config?: string) { const vm = podmanVmContext(); return vm ? podmanVmCommand(vm, args, config) : runCommand(engine, ['--remote=false', ...args], { ...LIMITS, ...(config ? { containersConf: config } : {}) }); }
async function directoryIdentity(guard: string, root: string) { const vm = podmanVmContext(); return vm ? podmanVmDirectoryIdentity(vm, root) : guardedIdentity(guard, root); }

/** Native local rootless storage identity; no VM, daemon, pull or service setup. */
export async function inspectPodmanStorageIdentity(engine: string, host: Host): Promise<Omit<PodmanIdentity, 'imageId' | 'environment'>> {
  const vm = podmanVmContext();
  if (vm) {
    const result = await cmd(engine, ['info', '--format', 'json']);
    if (result.code !== 0) throw new Error('PODMAN_ENGINE_UNAVAILABLE');
    const info = object(json(result.stdout)), machine = object(info?.host), store = object(info?.store);
    if (machine?.os !== 'linux' || machine.arch !== vm.architecture || object(machine.security)?.rootless !== true || machine.cgroupVersion !== 'v2' || typeof machine.kernel !== 'string' || typeof store?.graphRoot !== 'string' || typeof store.runRoot !== 'string') throw new Error('PODMAN_VM_ROOTLESS_GUEST_REQUIRED');
    const graph = await podmanVmDirectoryIdentity(vm, store.graphRoot), run = await podmanVmDirectoryIdentity(vm, store.runRoot);
    await podmanVmPrivateDirectory(vm, store.graphRoot, graph); await podmanVmPrivateDirectory(vm, store.runRoot, run);
    return { graphRoot: store.graphRoot, graphIdentity: `${graph.device}:${graph.inode}`, runRoot: store.runRoot, runIdentity: `${run.device}:${run.inode}`, architecture: vm.architecture, kernelRelease: machine.kernel, rootless: true, virtualMachine: `${vm.fingerprint}:${vm.bootId}` };
  }
  if (host.platform !== 'linux' || !['arm64', 'x64'].includes(host.arch) || typeof process.getuid !== 'function' || process.getuid() === 0) throw new Error('PODMAN_ROOTLESS_REQUIRED');
  const result = await cmd(engine, ['info', '--format', 'json']);
  if (result.code !== 0) throw new Error('PODMAN_ENGINE_UNAVAILABLE');
  const info = object(json(result.stdout)), machine = object(info?.host), security = object(machine?.security), store = object(info?.store);
  const architecture = host.arch === 'x64' ? 'amd64' : host.arch;
  if (typeof machine?.kernel !== 'string' || !/^\d+\.\d+/.test(machine.kernel)) throw new Error('PODMAN_STORAGE_UNVERIFIED');
  if (machine?.os !== 'linux' || machine.arch !== architecture || security?.rootless !== true || machine.cgroupVersion !== 'v2') throw new Error('PODMAN_ROOTLESS_REQUIRED');
  if (typeof store?.graphRoot !== 'string' || !path.isAbsolute(store.graphRoot)) throw new Error('PODMAN_STORAGE_UNVERIFIED');
  const graphRoot = await realpath(store.graphRoot), infoStat = await lstat(graphRoot, { bigint: true });
  if (graphRoot !== store.graphRoot || !infoStat.isDirectory() || infoStat.isSymbolicLink() || infoStat.uid !== BigInt(process.getuid()) || (infoStat.mode & 0o022n) !== 0n) throw new Error('PODMAN_STORAGE_UNVERIFIED');
  if (typeof store.runRoot !== 'string' || !path.isAbsolute(store.runRoot)) throw new Error('PODMAN_STORAGE_UNVERIFIED');
  const runRoot = await realpath(store.runRoot), runStat = await lstat(runRoot, { bigint: true });
  if (runRoot !== store.runRoot || !runStat.isDirectory() || runStat.isSymbolicLink() || runStat.uid !== BigInt(process.getuid()) || (runStat.mode & 0o022n) !== 0n) throw new Error('PODMAN_STORAGE_UNVERIFIED');
  return { graphRoot, graphIdentity: `${infoStat.dev}:${infoStat.ino}`, runRoot, runIdentity: `${runStat.dev}:${runStat.ino}`, architecture, kernelRelease: machine.kernel, rootless: true };
}

/** Admit local OCI configuration and diff IDs without inventing a RepoDigest. */
export async function inspectPodmanImageIdentity(engine: string, host: Host, image: ImageReceipt): Promise<PodmanIdentity> {
  const storage = await inspectPodmanStorageIdentity(engine, host);
  const result = await cmd(engine, ['image', 'inspect', image.configDigest ?? image.reference]);
  if (result.code !== 0) throw new Error('PODMAN_IMAGE_NOT_PRESENT');
  const data = json(result.stdout), item = Array.isArray(data) && data.length === 1 ? object(data[0]) : undefined;
  const imageId = prefixed(item?.Id);
  if (!imageId || item?.Os !== 'linux' || item.Architecture !== storage.architecture) throw new Error('PODMAN_IMAGE_NOT_VERIFIED');
  if (image.configDigest) {
    const rootfs = object(item.RootFS);
    if (imageId !== image.configDigest || !image.diffIds?.length || rootfs?.Type !== 'layers' || !Array.isArray(rootfs.Layers) || rootfs.Layers.length !== image.diffIds.length || rootfs.Layers.some((value, index) => value !== image.diffIds?.[index])) throw new Error('PODMAN_IMAGE_NOT_VERIFIED');
  } else if (item.Digest !== image.digest || !Array.isArray(item.RepoDigests) || !item.RepoDigests.includes(image.reference)) throw new Error('PODMAN_IMAGE_NOT_VERIFIED');
  const config = object(item.Config), environment = config?.Env ?? [];
  if (!Array.isArray(environment) || environment.length > 64 || environment.some(value => typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*=/.test(value) || /[\0\r\n]/.test(value) || value.length > 16 * 1024) || new Set(environment.map(value => (value as string).split('=', 1)[0])).size !== environment.length || environment.reduce((total, value) => total + (value as string).length, 0) > 64 * 1024) throw new Error('PODMAN_IMAGE_ENVIRONMENT_INVALID');
  const fixed = new Map((environment as string[]).map(value => { const split = value.indexOf('='); return [value.slice(0, split), value.slice(split + 1)] as const; }));
  fixed.set('HOME', '/tmp'); fixed.set('HOSTNAME', 'ud-agent');
  return { ...storage, imageId, environment: Object.freeze([...fixed].map(([name, value]) => `${name}=${value}`)) };
}

/** Create and verify only product-owned immutable configuration, not user config. */
async function policyFiles(root: string): Promise<{ config: string; hooks: string; mounts: string }> {
  const directory = path.join(root, 'policy');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const hooks = path.join(directory, 'hooks'), config = path.join(directory, 'containers.conf'), mounts = path.join(directory, 'mounts.conf');
  await mkdir(hooks, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
  for (const name of [root, directory, hooks]) { const info = await lstat(name); if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) throw new Error('PODMAN_POLICY_DIRECTORY_UNVERIFIED'); }
  if ((await readdir(hooks)).length) throw new Error('PODMAN_HOOKS_INJECTED');
  for (const [name, content] of [[config, CONF], [mounts, '']] as const) {
    await writeFile(name, content, { flag: 'wx', mode: 0o400 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
    const info = await lstat(name);
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o277) !== 0 || (await readBoundedReceiptBytes(name)).toString('utf8') !== content) throw new Error('PODMAN_POLICY_FILE_UNVERIFIED');
  }
  return { config, hooks, mounts };
}
function createArgs(policy: PodmanWorkerPolicy, files: { hooks: string; mounts: string }, seccomp: string): string[] {
  return [`--hooks-dir=${files.hooks}`, `--default-mounts-file=${files.mounts}`, 'create', '--name', policy.name, '--label', `io.ud-agent.job=${policy.jobId}`, '--pull=never', '--interactive', '--user=10001:10001', '--userns=keep-id:uid=10001,gid=10001', '--network=none', '--pid=private', '--ipc=private', '--cgroupns=private', '--uts=private', '--read-only', '--read-only-tmpfs=false', '--cap-drop=ALL', '--security-opt=no-new-privileges', `--security-opt=seccomp=${seccomp}`, '--memory=2147483648', '--cpus=2', '--pids-limit=128', '--ulimit=nofile=1024:1024', '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=67108864', '--volume', `${policy.volume}:/input:${policy.readOnlyInput ? 'ro' : 'rw'},nocopy,z`, '--image-volume=ignore', '--no-hosts', '--no-hostname', '--hostname=ud-agent', '--no-healthcheck', '--systemd=false', '--init=false', '--http-proxy=false', '--unsetenv-all', ...policy.environment.flatMap(value => ['--env', value]), '--workdir=/tmp', '--restart=no', '--timeout=300', '--entrypoint', ENTRYPOINT[0]!, policy.imageId, ...policy.command];
}
function environment(config: string): NodeJS.ProcessEnv { const env: NodeJS.ProcessEnv = { PATH: '/usr/bin:/bin', LANG: 'C', CONTAINERS_CONF: config }; for (const key of ['HOME', 'TMPDIR', 'TMP', 'TEMP', 'USER', 'LOGNAME'] as const) if (process.env[key] !== undefined) env[key] = process.env[key]; return env; }
async function attach(engine: string, config: string, id: string, input: AsyncIterable<Buffer>, authority: CommandSupervisor, signal?: AbortSignal): Promise<Buffer> {
  if (signal?.aborted) throw new Error('WORKER_CANCELLED');
  const vm = podmanVmContext(); if (vm) return podmanVmStream(vm, ['start', '--attach', '--interactive', id], input, config, signal);
  try {
    const result = await supervisedCommand(engine, ['--remote=false', 'start', '--attach', '--interactive', id], input, authority,
      { timeoutMs: 300000, maxStdoutBytes: 32 * 1024 * 1024, maxStderrBytes: 1024 * 1024, maxInputBytes: 20 * 1024 * 1024 * 1024 }, environment(config), signal);
    if (result.code !== 0) throw new Error(`PODMAN_WORKER_FAILED: ${result.stderr.toString('utf8').slice(0, 4096)}`);
    return result.stdout;
  } catch (problem) { return workerStreamError(problem); }
}
function parseLine(bytes: Buffer): Record<string, unknown> { const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); if (!text.endsWith('\n') || text.slice(0, -1).includes('\n')) throw new Error('PODMAN_WORKER_RESPONSE_INVALID'); const parsed = object(json(Buffer.from(text))); if (!parsed) throw new Error('PODMAN_WORKER_RESPONSE_INVALID'); return parsed; }
async function* one(bytes: Buffer): AsyncGenerator<Buffer> { yield bytes; }
async function inspectContainer(engine: string, id: string, config?: string): Promise<unknown | undefined> {
  const inspect = await cmd(engine, ['container', 'inspect', id], config);
  if (inspect.code === 0) return json(inspect.stdout);
  const exists = await cmd(engine, ['container', 'exists', id], config);
  if (exists.code !== 1) throw new Error('PODMAN_CLEANUP_UNVERIFIED');
  return undefined;
}
async function removeContainer(engine: string, id: string, name: string, jobId: string, imageId: string, config?: string): Promise<void> {
  const raw = await inspectContainer(engine, id, config); if (raw === undefined) return;
  const item = Array.isArray(raw) && raw.length === 1 ? object(raw[0]) : undefined, labels = object(object(item?.Config)?.Labels);
  if (!item || item.Id !== id || item.Name !== name || prefixed(item.Image) !== imageId || labels?.['io.ud-agent.job'] !== jobId) throw new Error('PODMAN_CLEANUP_OWNERSHIP_MISMATCH');
  const removed = await cmd(engine, ['container', 'rm', '--force', id], config);
  if (removed.code !== 0 || await inspectContainer(engine, id, config) !== undefined) throw new Error('PODMAN_CLEANUP_UNVERIFIED');
}
async function removeVolume(engine: string, volume: string, jobId: string, graphRoot: string, config?: string): Promise<void> {
  const inspect = await cmd(engine, ['volume', 'inspect', volume], config);
  if (inspect.code !== 0) { const exists = await cmd(engine, ['volume', 'exists', volume], config); if (exists.code !== 1) throw new Error('PODMAN_CLEANUP_UNVERIFIED'); return; }
  if (!inspectPodmanInputVolume(json(inspect.stdout), volume, jobId, graphRoot)) throw new Error('PODMAN_CLEANUP_OWNERSHIP_MISMATCH');
  const result = await cmd(engine, ['volume', 'rm', volume], config), exists = await cmd(engine, ['volume', 'exists', volume], config);
  if (result.code !== 0 || exists.code !== 1) throw new Error('PODMAN_CLEANUP_UNVERIFIED');
}

/** Recover settled creates by exact owned labels; ambiguous absence remains pending. */
export async function recoverPodmanWorker(stateRoot: string, id: string, guard?: string, authority?: PodmanCleanupAuthority): Promise<void> {
  if (authority && !engineSupervisor(authority.engine)) {
    const verified = await verifyPodmanCleanupAuthority(authority);
    if (!verified.guardSha256) throw new Error('PODMAN_CLEANUP_GUARD_IDENTITY_REQUIRED');
    return withEngineSupervisor({ engine: verified.engine, guard: verified.guard, guardSha256: verified.guardSha256, executableSha256: verified.engineSha256 }, () => recoverPodmanWorker(stateRoot, id, guard, verified));
  }
  if (authority?.vm && !podmanVmContext()) return withPodmanVm(authority.vm, () => recoverPodmanWorker(stateRoot, id, guard, authority));
  const journal = await PodmanJobJournal.open(stateRoot, guard);
  await journal.withRecoveryLock(id, async () => {
    let job = await journal.load(id); if (job.phase === 'cleaned') return;
    if (job.owner_lease) { if (!guard) throw new Error('PODMAN_RECOVERY_GUARD_REQUIRED'); if (await providerLeaseActive(guard, stateRoot, job.owner_lease)) throw new Error('PODMAN_JOB_OWNER_ACTIVE'); }
    else try { process.kill(job.owner_pid, 0); throw new Error('PODMAN_JOB_OWNER_ACTIVE'); } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
    if (authority) {
      const fresh = await verifyPodmanCleanupAuthority(authority);
      if (fresh.identity.graphRoot !== job.graph_root || fresh.identity.graphIdentity !== job.graph_identity || (fresh.identity.virtualMachine ?? undefined) !== job.vm_identity && !samePodmanVmForCleanup(job.vm_identity, fresh.identity.virtualMachine)) throw new Error('PODMAN_STORAGE_CHANGED');
      if (fresh.engine !== job.engine || fresh.engineSha256 !== job.engine_sha256) { await journal.recordEngineCleanup(id, fresh.engine, fresh.engineSha256); job = await journal.load(id); }
    }
    await verifyArchive(job.engine, job.engine_sha256);
    const host: Host = { platform: 'linux', arch: process.arch };
    const storage = await inspectPodmanStorageIdentity(job.engine, host);
    if ((storage.virtualMachine ?? undefined) !== job.vm_identity && !samePodmanVmForCleanup(job.vm_identity, storage.virtualMachine)) throw new Error('PODMAN_VM_RECOVERY_CONTEXT_CHANGED');
    if (storage.graphRoot !== job.graph_root || storage.graphIdentity !== job.graph_identity) throw new Error('PODMAN_STORAGE_CHANGED');
    if (storage.virtualMachine && storage.virtualMachine !== job.vm_identity) await journal.recordVmCleanup(id, storage.virtualMachine);
    const recoveryVm = podmanVmContext();
    let files: { config: string; hooks: string; mounts: string };
    if (recoveryVm) {
      if (!job.policy_sha256) throw new Error('PODMAN_VM_RECOVERY_POLICY_REQUIRED');
      const root = path.posix.join(recoveryVm.guestHome, '.local/share/ud-agent-skill-mcp-plugin/podman-policy', job.policy_sha256.slice(7));
      const directory = await podmanVmDirectoryIdentity(recoveryVm, root);
      const policy = await podmanVmRead(recoveryVm, root, 'seccomp.json', directory, 1024 * 1024);
      if (`sha256:${createHash('sha256').update(policy).digest('hex')}` !== job.policy_sha256) throw new Error('PODMAN_VM_POLICY_INTEGRITY_FAILED');
      files = await podmanVmPolicy(recoveryVm, policy);
    } else files = await policyFiles(stateRoot);
    const volume = `ud-agent-${id}-input`;
    const discover = async (name: string, recorded?: string) => {
      const raw = await inspectContainer(job.engine, recorded ?? name, files.config);
      if (raw === undefined) return undefined;
      const item = Array.isArray(raw) && raw.length === 1 ? object(raw[0]) : undefined;
      if (typeof item?.Id !== 'string' || !/^[0-9a-f]{64}$/.test(item.Id)) throw new Error('PODMAN_CLEANUP_UNVERIFIED');
      await removeContainer(job.engine, item.Id, name, id, job.image_id, files.config); return item.Id;
    };
    if (job.phase === 'volume_pending') {
      const found = await cmd(job.engine, ['volume', 'inspect', volume], files.config);
      if (found.code !== 0) throw new Error('PODMAN_CREATE_OUTCOME_UNKNOWN');
      if (!inspectPodmanInputVolume(json(found.stdout), volume, id, storage.graphRoot)) throw new Error('PODMAN_CLEANUP_OWNERSHIP_MISMATCH');
    }
    const worker = await discover(`ud-agent-${id}-worker`, job.worker_id);
    const loader = await discover(`ud-agent-${id}-loader`, job.loader_id);
    if (job.phase === 'loader_pending' && !loader || job.phase === 'worker_pending' && !worker) throw new Error('PODMAN_CREATE_OUTCOME_UNKNOWN');
    if (job.phase !== 'cleanup_pending') await journal.transition(id, 'cleanup_pending');
    if (job.phase !== 'planned') await removeVolume(job.engine, volume, id, storage.graphRoot, files.config);
    await journal.transition(id, 'cleaned');
  });
}

/** Reconcile only dead owners; concurrent live jobs retain their resources. */
export async function recoverPendingPodmanJobs(stateRoot: string, guard?: string, authority?: PodmanCleanupAuthority | (() => Promise<PodmanCleanupAuthority>)): Promise<void> {
  const journal = await PodmanJobJournal.open(stateRoot, guard);
  let cleanup = typeof authority === 'function' ? undefined : authority;
  for (const job of await journal.pending()) {
    let alive = true;
    if (job.owner_lease) { if (!guard) throw new Error('PODMAN_RECOVERY_GUARD_REQUIRED'); alive = await providerLeaseActive(guard, stateRoot, job.owner_lease); }
    else try { process.kill(job.owner_pid, 0); }
    catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') alive = false; else throw error; }
    if (!alive) {
      if (!cleanup && typeof authority === 'function') cleanup = await authority();
      await recoverPodmanWorker(stateRoot, job.id, guard, cleanup);
    }
  }
}

/** Generic contract operation execution through a verified read-only OCI handoff. */
export async function runPodmanWorker(input: PodmanWorkerInput): Promise<Result> {
  const boundVm = podmanVmForIdentity(input.expectedIdentity);
  if (boundVm && !podmanVmContext()) return withPodmanVm(boundVm, () => runPodmanWorker(input));
  if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
  if (!path.isAbsolute(input.stateRoot)) throw new Error('PODMAN_RUNTIME_PATH_INVALID');
  await verifyArchive(input.guard, input.guardSha256); await mkdir(input.stateRoot, { recursive: true, mode: 0o700 }); await JournalStore.open(input.stateRoot, input.guard);
  return withEngineSupervisor({ engine: input.engine, guard: input.guard, guardSha256: input.guardSha256, executableSha256: input.engineSha256, ...(input.signal ? { signal: input.signal } : {}) },
    () => withProviderLease(input.guard, input.stateRoot, () => runLeasedPodmanWorker(input), input.signal ? { signal: input.signal } : {}));
}
async function runLeasedPodmanWorker(input: PodmanWorkerInput): Promise<Result> {
  if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
  for (const name of [input.engine, input.guard, input.workingTree, input.stateRoot]) if (!path.isAbsolute(name) || /[\0\r\n]/.test(name)) throw new Error('PODMAN_RUNTIME_PATH_INVALID');
  await verifyArchive(input.engine, input.engineSha256); await verifyArchive(input.guard, input.guardSha256);
  const identity = await inspectPodmanImageIdentity(input.engine, input.host, input.image);
  if (input.expectedIdentity && JSON.stringify(identity) !== JSON.stringify(input.expectedIdentity)) throw new Error('PODMAN_IDENTITY_CHANGED');
  const assertStorage = async () => { const now = await inspectPodmanStorageIdentity(input.engine, input.host); if (now.graphRoot !== identity.graphRoot || now.graphIdentity !== identity.graphIdentity || now.runRoot !== identity.runRoot || now.runIdentity !== identity.runIdentity) throw new Error('PODMAN_STORAGE_CHANGED'); };
  if (!input.image.seccompProfile) throw new Error('PODMAN_SECCOMP_POLICY_REQUIRED');
  const seccompBytes = await readBoundedReceiptBytes(input.image.seccompProfile.path);
  if (seccompBytes.length !== input.image.seccompProfile.sizeBytes || `sha256:${createHash('sha256').update(seccompBytes).digest('hex')}` !== input.image.seccompProfile.sha256) throw new Error('PODMAN_SECCOMP_CHANGED');
  const seccomp = object(json(seccompBytes)); if (!seccomp || seccomp.defaultAction !== 'SCMP_ACT_ERRNO') throw new Error('PODMAN_SECCOMP_POLICY_INVALID');
  const operation = input.operation ?? 'validation_report'; if (!/^(?:[a-z][a-z0-9_]*|_project_rules)$/.test(operation)) throw new Error('PODMAN_OPERATION_INVALID');
  const captured = await captureOperationSnapshot(input.guard, { ...(input.arguments ?? { file_paths: input.filePaths, options: input.options }), working_tree_path: input.workingTree }, input.allowedRoots, input.signal, undefined, operation, input.contextBundle);
  const snapshot = captured.snapshot;
  const seccompPath = path.join(input.stateRoot, `seccomp-${randomUUID()}.json`);
  let seccompCreated = false;
  try {
    await mkdir(input.stateRoot, { recursive: true, mode: 0o700 });
    const vm = podmanVmContext();
    const files = vm ? await podmanVmPolicy(vm, seccompBytes) : await policyFiles(input.stateRoot);
    await writeFile(seccompPath, seccompBytes, { flag: 'wx', mode: 0o400 }); seccompCreated = true; await chmod(seccompPath, 0o400);
    await verifySnapshotIntegrity(input.guard, snapshot, input.signal);
    const filePaths = input.selectAllFiles ? snapshot.files.filter(file => file.path.endsWith('.conllu') && !file.path.startsWith('.ud-agent-inputs/')).map(file => file.path) : input.filePaths;
    const available = new Set(snapshot.files.map(file => file.path));
    if (operation === 'validation_report' && (filePaths.length === 0 || filePaths.length > 10_000 || new Set(filePaths).size !== filePaths.length || filePaths.some(name => !available.has(name)))) throw new Error('PODMAN_SELECTED_FILES_INVALID');
    const id = randomUUID(), volume = `ud-agent-${id}-input`, loaderName = `ud-agent-${id}-loader`, workerName = `ud-agent-${id}-worker`;
    const journal = await PodmanJobJournal.open(input.stateRoot, input.guard);
    const ownerLease = await currentProviderLease(input.stateRoot); if (!ownerLease) throw new Error('PODMAN_PROVIDER_LEASE_REQUIRED');
    await journal.create({ version: 1, id, engine: input.engine, engine_sha256: input.engineSha256, image_digest: input.image.digest, image_id: identity.imageId, graph_root: identity.graphRoot, graph_identity: identity.graphIdentity, owner_pid: process.pid, owner_lease: ownerLease, phase: 'planned', ...(identity.virtualMachine ? { vm_identity: identity.virtualMachine, policy_sha256: input.image.seccompProfile.sha256 } : {}) });
    let loaderId: string | undefined, workerId: string | undefined, volumeCreated = false, uncertain = false, failure: unknown, response: Record<string, unknown> | undefined;
    try {
      await assertStorage(); await journal.transition(id, 'volume_pending'); uncertain = true;
      const created = await cmd(input.engine, ['volume', 'create', '--label', `io.ud-agent.job=${id}`, '--uid=0', '--gid=0', volume], files.config);
      if (created.code !== 0 || created.stdout.toString('utf8').trim() !== volume) {
        const partial = await cmd(input.engine, ['volume', 'inspect', volume], files.config);
        if (partial.code === 0 && inspectPodmanInputVolume(json(partial.stdout), volume, id, identity.graphRoot)) { volumeCreated = true; uncertain = false; }
        else if (partial.code !== 0 && created.code !== 0 && (await cmd(input.engine, ['volume', 'exists', volume], files.config)).code === 1) uncertain = false;
        throw new Error(`PODMAN_VOLUME_CREATE_FAILED: ${created.stderr.toString('utf8').slice(0, 2048)}`);
      }
      uncertain = false; volumeCreated = true; await journal.transition(id, 'volume_ready');
      const inspected = await cmd(input.engine, ['volume', 'inspect', volume], files.config);
      const volumePath = inspected.code === 0 ? inspectPodmanInputVolume(json(inspected.stdout), volume, id, identity.graphRoot) : undefined;
      if (!volumePath) throw new Error('PODMAN_VOLUME_UNVERIFIED');
      const volumeIdentity = await directoryIdentity(input.guard, volumePath);
      if (vm) await podmanVmPrivateDirectory(vm, volumePath, volumeIdentity, true);
      else {
      const volumeDirectory = await open(volumePath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      try {
        const before = await volumeDirectory.stat({ bigint: true });
        if (!before.isDirectory() || before.uid !== BigInt(process.getuid!()) || before.dev.toString() !== volumeIdentity.device || before.ino.toString() !== volumeIdentity.inode) throw new Error('PODMAN_VOLUME_OWNERSHIP_CHANGED');
        await volumeDirectory.chmod(0o700);
        const after = await volumeDirectory.stat({ bigint: true });
        if ((after.mode & 0o077n) !== 0n || after.dev !== before.dev || after.ino !== before.ino) throw new Error('PODMAN_VOLUME_PRIVACY_UNVERIFIED');
      } finally { await volumeDirectory.close(); }
      }
      const verifyVolume = async () => {
        const check = await cmd(input.engine, ['volume', 'inspect', volume], files.config);
        if (check.code !== 0 || inspectPodmanInputVolume(json(check.stdout), volume, id, identity.graphRoot) !== volumePath) throw new Error('PODMAN_VOLUME_OWNERSHIP_CHANGED');
        const now = await directoryIdentity(input.guard, volumePath);
        if (now.device !== volumeIdentity.device || now.inode !== volumeIdentity.inode) throw new Error('PODMAN_VOLUME_IDENTITY_CHANGED');
      };
      const create = async (name: string, command: string[], readOnlyInput: boolean): Promise<string> => {
        await assertStorage(); await verifyVolume();
        const policy: PodmanWorkerPolicy = { name, jobId: id, imageId: identity.imageId, containerId: '', volume, volumePath, graphRoot: identity.graphRoot, runRoot: identity.runRoot, architecture: identity.architecture, kernelRelease: identity.kernelRelease, readOnlyInput, entrypoint: ENTRYPOINT, command, environment: [...identity.environment], seccomp };
        uncertain = true;
        const result = await cmd(input.engine, createArgs(policy, files, 'seccomp' in files && typeof files.seccomp === 'string' ? files.seccomp : seccompPath), files.config);
        const containerId = result.stdout.toString('utf8').trim();
        if (result.code !== 0 || !/^[0-9a-f]{64}$/.test(containerId)) {
          const partial = await inspectContainer(input.engine, name, files.config);
          const item = Array.isArray(partial) && partial.length === 1 ? object(partial[0]) : undefined;
          const labels = object(object(item?.Config)?.Labels);
          if (item && typeof item.Id === 'string' && /^[0-9a-f]{64}$/.test(item.Id) && item.Name === name && prefixed(item.Image) === identity.imageId && labels?.['io.ud-agent.job'] === id) {
            if (readOnlyInput) workerId = item.Id; else loaderId = item.Id;
            uncertain = false;
            await journal.transition(id, readOnlyInput ? 'worker_created' : 'loader_created', readOnlyInput ? { worker_id: item.Id } : { loader_id: item.Id });
          } else if (partial === undefined && result.code !== 0) uncertain = false;
          throw new Error(`PODMAN_CONTAINER_CREATE_FAILED: ${result.stderr.toString('utf8').slice(0, 2048)}`);
        }
        uncertain = false;
        // Save the identity before inspection can fail, permitting exact cleanup.
        if (readOnlyInput) workerId = containerId; else loaderId = containerId;
        await journal.transition(id, readOnlyInput ? 'worker_created' : 'loader_created', readOnlyInput ? { worker_id: containerId } : { loader_id: containerId });
        await verifyVolume();
        const preliminary = inspectPodmanWorker(await inspectContainer(input.engine, containerId, files.config), { ...policy, containerId });
        const preliminaryViolations = preliminary.violations.filter(name => !['capabilities', 'oci_config_path'].includes(name));
        if (preliminaryViolations.length) throw new Error(`PODMAN_CONTAINER_POLICY_FAILED: ${preliminaryViolations.join(', ')}`);
        // Podman writes the effective OCI spec during init. The image command
        // remains stopped until policy inspection succeeds and start is called.
        const initialized = await cmd(input.engine, ['container', 'init', containerId], files.config);
        if (initialized.code !== 0) throw new Error(`PODMAN_CONTAINMENT_INIT_FAILED: ${initialized.stderr.toString('utf8').slice(0, 2048)}`);
        await verifyVolume();
        const inspection = inspectPodmanWorker(await inspectContainer(input.engine, containerId, files.config), { ...policy, containerId });
        if (inspection.violations.length || !inspection.configPath) throw new Error(`PODMAN_CONTAINER_POLICY_FAILED: ${inspection.violations.join(', ')}`);
        const graph = await directoryIdentity(input.guard, identity.graphRoot);
        if (`${graph.device}:${graph.inode}` !== identity.graphIdentity) throw new Error('PODMAN_STORAGE_CHANGED');
        const relativeSpec = path.posix.relative(identity.graphRoot, inspection.configPath);
        const specification = json(vm ? await podmanVmRead(vm, identity.graphRoot, relativeSpec, graph, 1024 * 1024, input.signal) : await guardedRead(input.guard, identity.graphRoot, relativeSpec, 1024 * 1024, graph, input.signal));
        const violations = inspectPodmanWorkerSpec(specification, { ...policy, containerId });
        if (violations.length) throw Object.assign(new Error(`PODMAN_OCI_POLICY_FAILED: ${violations.join(', ')}`), { details: specification });
        return containerId;
      };
      await journal.transition(id, 'loader_pending');
      loaderId = await create(loaderName, ['-I', '-B', '-c', LOADER, snapshot.sha256], false);
      const supervisor = { guard: input.guard, guardSha256: input.guardSha256, executableSha256: input.engineSha256 };
      const loaded = parseLine(await attach(input.engine, files.config, loaderId, encodeSnapshotFrames(streamVerifiedSnapshot(input.guard, snapshot, input.signal)), supervisor, input.signal));
      if (loaded.status !== 'loaded' || loaded.snapshot_sha256 !== snapshot.sha256) throw new Error('PODMAN_SNAPSHOT_LOAD_FAILED');
      await journal.transition(id, 'loaded'); await journal.transition(id, 'worker_pending');
      workerId = await create(workerName, ['-I', '-B', '-c', WORKER], true);
      const request = Buffer.from(`${JSON.stringify({ operation, arguments: { ...captured.arguments, ...(operation === 'validation_report' ? { file_paths: filePaths } : {}) }, snapshot_sha256: snapshot.sha256, files: snapshot.files, ...(captured.brokerEvidence ? { broker_evidence: captured.brokerEvidence } : {}) })}\n`);
      if (request.length > 16 * 1024 * 1024) throw new Error('WORKER_REQUEST_TOO_LARGE');
      response = parseLine(await attach(input.engine, files.config, workerId, one(request), supervisor, input.signal));
      await journal.transition(id, 'ran');
    } catch (error: unknown) { failure = error; }
    if (uncertain) throw new Error(`PODMAN_CREATE_OUTCOME_UNKNOWN: owned job requires reconciliation. ${failure instanceof Error ? failure.message : ''}`);
    try {
      await withoutEngineCancellation(async () => {
        await journal.transition(id, 'cleanup_pending'); await verifyArchive(input.engine, input.engineSha256); await assertStorage();
        if (workerId) await removeContainer(input.engine, workerId, workerName, id, identity.imageId, files.config);
        if (loaderId) await removeContainer(input.engine, loaderId, loaderName, id, identity.imageId, files.config);
        if (volumeCreated) await removeVolume(input.engine, volume, id, identity.graphRoot, files.config);
        await journal.transition(id, 'cleaned');
      });
    } catch { throw new Error('PODMAN_CLEANUP_UNVERIFIED: owned job requires reconciliation.'); }
    if (failure) throw failure;
    if (!response || response.ok !== true || !object(response.result)) { const error = object(response?.error); if (typeof error?.code === 'string' && typeof error.message === 'string') throw Object.assign(new Error(error.message), { code: error.code }); throw new Error('PODMAN_WORKER_RESPONSE_INVALID'); }
    return { result: response.result as Record<string, unknown>, snapshot: { sha256: snapshot.sha256, files: snapshot.files, source_map: captured.sourceMap, root_identity: snapshot.root_identity }, runtime: 'podman' };
  } finally { await snapshot.cleanup(); if (seccompCreated) await rm(seccompPath, { force: true }); }
}
