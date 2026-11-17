import { createHash, randomUUID } from 'node:crypto';
import { runCommand } from '../../runtime-manager/src/command.js';
import type { CommandOptions, CommandResult } from '../../runtime-manager/src/command.js';
import { streamCommand } from '../../runtime-manager/src/stream-command.js';
import { appleCreateArguments, inspectAppleJob, withAppleRuntime } from '../../runtime-manager/src/apple-runtime.js';
import type { AppleRuntime } from '../../runtime-manager/src/apple-runtime.js';
import { limaImageIdentity, limaVolumeIdentity, limaJobStateDirectory, limaGuestCommand, limaShellArguments, inspectLimaJob, limaCommand, limaCreateArguments } from '../../runtime-manager/src/lima-nerdctl.js';
import type { LimaRuntime } from '../../runtime-manager/src/lima-nerdctl.js';
import { inspectWslcJob, wslcArguments, wslcCommand, wslcCreateArguments } from '../../runtime-manager/src/wslc-runtime.js';
import type { WslcRuntime } from '../../runtime-manager/src/wslc-runtime.js';
import type { ImageReceipt } from '../../runtime-manager/src/receipt.js';
import { readBoundedReceiptBytes } from '../../runtime-manager/src/receipt.js';
import { compileLimaSeccomp } from '../../runtime-manager/src/lima-seccomp.js';
import { captureOperationSnapshot } from '../../workspace/src/input-broker.js';
import { verifySnapshotIntegrity } from '../../workspace/src/snapshot.js';
import { streamVerifiedSnapshot } from '../../workspace/src/snapshot-transfer.js';
import { encodeSnapshotFrames } from '../../workspace/src/snapshot-wire.js';
import type { ProviderRequest, ProviderResult } from './provider-runtime.js';
import { withProviderLease } from './provider-leases.js';
import { PlatformJournal } from './platform-journal.js';
import type { PlatformJob } from './platform-journal.js';

export type PlatformRuntime = AppleRuntime | LimaRuntime | WslcRuntime;
type Runner = typeof runCommand;
type Transfer = typeof streamCommand;
type GuestCommand = (args: readonly string[], options?: CommandOptions) => Promise<CommandResult>;
const OPTIONS = { timeoutMs: 30_000, maxOutputBytes: 16 * 1024 * 1024 };
const PREFIX = "import sys;sys.path[:0]=['/opt/ud-agent/worker','/opt/ud-agent/upstream/udtools/src'];";
const INITIALIZE = 'import os;os.chmod("/input",0o700);os.chown("/input",10001,10001);print("initialized")';
function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function json(bytes: Buffer): unknown { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('PLATFORM_RESPONSE_INVALID'); } }
function line(bytes: Buffer): Record<string, unknown> { const raw = bytes.toString('utf8'); if (!raw.endsWith('\n') || raw.slice(0, -1).includes('\n')) throw new Error('PLATFORM_RESPONSE_FRAMING_INVALID'); const result = object(json(bytes)); if (!result) throw new Error('PLATFORM_RESPONSE_INVALID'); return result; }
function containerPrefix(runtime: PlatformRuntime): string[] { return runtime.engine === 'wslc' ? ['container'] : []; }
function inspectArgs(runtime: PlatformRuntime, name: string): string[] { return runtime.engine === 'lima-nerdctl' ? ['container', 'inspect', '--mode=native', name] : [...containerPrefix(runtime), 'inspect', name]; }
function canonicalId(runtime: PlatformRuntime, raw: unknown): string | undefined { const item = Array.isArray(raw) && raw.length === 1 ? object(raw[0]) : undefined; const id = runtime.engine === 'apple-container' ? object(item?.configuration)?.id : runtime.engine === 'lima-nerdctl' ? item?.ID : item?.Id; return typeof id === 'string' && /^[a-z0-9-]{1,80}$/.test(id) ? id : undefined; }
function inventoryIdentities(bytes: Buffer): Set<string> {
  const raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim(); if (!raw) return new Set();
  const parsed: unknown[] = raw.startsWith('[') ? json(Buffer.from(raw)) as unknown[] : raw.split(/\r?\n/).map(line => json(Buffer.from(line)));
  if (!Array.isArray(parsed) || parsed.length > 10000) throw new Error('PLATFORM_INVENTORY_INVALID'); const names = new Set<string>();
  for (const raw of parsed) { const item = object(raw); const config = object(item?.configuration); const values = [item?.ID, item?.Id, item?.id, item?.Name, item?.Names, item?.name, config?.id, config?.name].flatMap(value => Array.isArray(value) ? value : [value]).filter((value): value is string => typeof value === 'string' && value.length > 0); if (!item || !values.length || values.some(value => value.length > 512 || value.includes('\0') || value.includes('\n'))) throw new Error('PLATFORM_INVENTORY_INVALID'); for (const value of values) names.add(value.startsWith('/') ? value.slice(1) : value); }
  return names;
}
async function confirmContainerAbsent(runtime: PlatformRuntime, command: (args: readonly string[]) => Promise<CommandResult>, name: string, id: string): Promise<void> {
  const inventory = await command(runtime.engine === 'apple-container' ? ['list', '--all', '--format', 'json'] : [...(runtime.engine === 'lima-nerdctl' ? ['container'] : containerPrefix(runtime)), 'ls', '--all', '--no-trunc', '--format', '{{json .}}']);
  if (inventory.code !== 0) throw new Error('PLATFORM_CLEANUP_UNVERIFIED'); const names = inventoryIdentities(inventory.stdout); if (names.has(name) || names.has(id)) throw new Error('PLATFORM_CLEANUP_UNVERIFIED');
}
async function confirmVolumeAbsent(runtime: PlatformRuntime, command: (args: readonly string[]) => Promise<CommandResult>, volume: string): Promise<void> {
  const result = await command(['volume', runtime.engine === 'apple-container' ? 'list' : 'ls', '--format', 'json']); if (result.code !== 0 || inventoryIdentities(result.stdout).has(volume)) throw new Error('PLATFORM_CLEANUP_UNVERIFIED');
}

export function platformAuthorityIdentity(runtime: PlatformRuntime): string {
  return runtime.engine === 'lima-nerdctl' ? runtime.identity : runtime.engine === 'wslc' ? `${runtime.receipt.binarySha256}:${runtime.receipt.sdkSha256}:${runtime.receipt.storage}:${runtime.session}:${runtime.sessionIdentity.id}:${runtime.sessionIdentity.creatorPid}` : `${runtime.receipt.engine.binarySha256}:${runtime.receipt.kernel.sha256}:${runtime.receipt.initImage.digest}`;
}

/** One common broker, with provider-specific command and inspection adapters. */
export async function runPlatformWorker(runtime: PlatformRuntime, image: ImageReceipt, guard: string, stateRoot: string, input: ProviderRequest, runner: Runner = runCommand, transfer: Transfer = streamCommand): Promise<ProviderResult> {
  return withProviderLease(guard, stateRoot, () => runLeasedPlatformWorker(runtime, image, guard, stateRoot, input, runner, transfer), input.signal ? { signal: input.signal } : {});
}
async function runLeasedPlatformWorker(runtime: PlatformRuntime, image: ImageReceipt, guard: string, stateRoot: string, input: ProviderRequest, runner: Runner, transfer: Transfer): Promise<ProviderResult> {
  if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
  if (runtime.engine === 'apple-container') return withAppleRuntime(runtime, command => execute(runtime, image, guard, stateRoot, input, command, transfer), runner);
  const command = (args: readonly string[], options: CommandOptions = OPTIONS) => runtime.engine === 'lima-nerdctl' ? limaCommand(runtime, args, options, runner) : wslcCommand(runtime, args, options, runner);
  return execute(runtime, image, guard, stateRoot, input, command, transfer, runtime.engine === 'lima-nerdctl' ? (args, options = OPTIONS) => limaGuestCommand(runtime, args, options, runner) : undefined);
}

async function execute(runtime: PlatformRuntime, image: ImageReceipt, guard: string, stateRoot: string, input: ProviderRequest, rawCommand: (args: readonly string[], options?: CommandOptions) => Promise<CommandResult>, transfer: Transfer, guestCommand?: GuestCommand): Promise<ProviderResult> {
  const command = (args: readonly string[], options: CommandOptions = OPTIONS) => rawCommand(args, { ...options, ...(input.signal ? { signal: input.signal } : {}) });
  let seccomp: Record<string, unknown> | undefined, seccompInput: Buffer | undefined;
  if (runtime.engine === 'lima-nerdctl' && image.seccompProfile) {
    const policy = image.seccompProfile, bytes = await readBoundedReceiptBytes(policy.path);
    if (bytes.length !== policy.sizeBytes || `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== policy.sha256) throw new Error('LIMA_SECCOMP_PROFILE_CHANGED');
    seccomp = compileLimaSeccomp(json(bytes), runtime.receipt.architecture);
    seccompInput = Buffer.from(JSON.stringify(seccomp));
  }
  let engineImageId = image.configDigest;
  if (runtime.engine === 'lima-nerdctl') { const inspected = await command(['image', 'inspect', '--mode=native', image.reference]); if (inspected.code !== 0 || !limaImageIdentity(json(inspected.stdout), image, runtime.receipt.architecture)) throw new Error('LIMA_IMAGE_IDENTITY_INVALID'); }
  if (runtime.engine === 'wslc') {
    const inspected = await command(['image', 'inspect', image.reference]); const raw = inspected.code === 0 ? json(inspected.stdout) : undefined; const item = Array.isArray(raw) && raw.length === 1 ? object(raw[0]) : undefined;
    const descriptor = object(item?.Descriptor); const descriptorIdentity = typeof item?.Id === 'string' && image.engineDescriptorDigests?.includes(item.Id) === true && descriptor?.digest === item.Id && ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'].includes(descriptor.mediaType as string);
    if (!image.configDigest || (item?.Id !== image.configDigest && !descriptorIdentity) || item?.Os !== 'linux' || item.Architecture !== runtime.receipt.architecture || JSON.stringify(object(item.RootFS)?.Layers) !== JSON.stringify(image.diffIds) || !Array.isArray(item.RepoDigests) || !item.RepoDigests.includes(image.reference)) throw new Error('WSLC_IMAGE_IDENTITY_INVALID');
    engineImageId = item.Id as string;
  }
  const captured = await captureOperationSnapshot(guard, { ...input.arguments, working_tree_path: input.workingTree }, input.allowedRoots, input.signal, undefined, input.operation, input.contextBundle);
  const { snapshot } = captured;
  try {
    await verifySnapshotIntegrity(guard, snapshot, input.signal);
    const journal = await PlatformJournal.open(stateRoot, guard); const id = randomUUID(); const volume = `ud-agent-${id}-input`; const loader = `ud-agent-${id}-loader`; const worker = `ud-agent-${id}-worker`;
    const job: PlatformJob = { schema_version: 1, lifecycle_revision: 2, id, provider: runtime.engine, authority: platformAuthorityIdentity(runtime), image: image.digest, image_reference: image.reference, ...(engineImageId ? { image_id: engineImageId } : {}), phase: 'planned' };
    return await journal.withJobLock(id, async () => {
    await journal.create(job); let failure: unknown; let response: Record<string, unknown> | undefined; let uncertain = false; let inputSource: string | undefined;
    const loaderCommand = ['-I', '-B', '-c', `${PREFIX}from ud_agent.oci_loader import main;raise SystemExit(main())`, snapshot.sha256];
    const workerCommand = ['-I', '-B', '-c', `${PREFIX}from ud_agent.oci_worker import main;raise SystemExit(main(${runtime.engine === 'lima-nerdctl' ? '' : `provider='${runtime.engine}'`}))`];
    const createArgs = (name: string, args: readonly string[], readonly: boolean) => runtime.engine === 'apple-container' ? appleCreateArguments(runtime, { name, jobId: id, volume, command: args, readOnlyInput: readonly }) : runtime.engine === 'lima-nerdctl' ? limaCreateArguments({ name, jobId: id, volume, image: image.reference, command: args, readOnlyInput: readonly, ...(seccompInput ? { seccompFromStdin: true } : {}) }) : wslcCreateArguments({ name, jobId: id, volume, image: image.reference, command: args, readOnlyInput: readonly });
    const stateDirectories = new Map<string, string>();
    const attach = async (container: string, frames: AsyncIterable<Buffer>) => {
      const args = [...containerPrefix(runtime), 'start', '--attach', '--interactive', container];
      const executable = runtime.engine === 'apple-container' ? runtime.receipt.engine.executable : runtime.receipt.executable;
      if (runtime.engine === 'lima-nerdctl') {
        const guestUid = runtime.receipt.guestUid;
        const directory = stateDirectories.get(container) ?? '';
        if (!directory || !runtime.receipt.ctr || !runtime.receipt.ctrSha256 || !guestCommand) throw new Error('LIMA_TASK_TRANSPORT_REQUIRED');
        const pidFile = `${directory}/ud-agent-stdin.pid`;
        const guest = (args: readonly string[]) => guestCommand(args, { ...OPTIONS, ...(input.signal ? { signal: input.signal } : {}) });
        const parent = await guest(['/usr/bin/stat', '--printf=%F|%u|%a|%i', '--', directory]);
        const parentFields = parent.stdout.toString('utf8').split('|');
        if (parent.code !== 0 || parentFields.length !== 4 || parentFields[0] !== 'directory' || parentFields[1] !== String(guestUid) || parentFields[2] !== '700' || !/^[1-9][0-9]*$/.test(parentFields[3]!)) throw new Error('LIMA_TASK_STDIN_HANDOFF_FAILED: container state directory is not private');
        if ((await guest(['/usr/bin/test', '!', '-e', pidFile, '-a', '!', '-L', pidFile])).code !== 0) throw new Error('LIMA_TASK_STDIN_HANDOFF_FAILED');
        // ctr creates its IO copier before registering the task and assigning
        // its stdin closer. Its atomic pid-file write occurs after that
        // assignment. Wait before sending input: a one-line worker can exit
        // before a running-task poll observes it. The marker is confined to
        // the inspected, unique container state directory and was absent
        // immediately before this exact pinned ctr invocation.
        async function* gated() {
          const deadline = Date.now() + 30_000;
          let ready = false;
          while (Date.now() < deadline) {
            if (input.signal?.aborted) throw new Error('WORKER_CANCELLED');
            const status = await guest(['/usr/bin/stat', '--printf=%F|%u|%a|%s|%i|%h', '--', pidFile]);
            if (status.code === 0) {
              const fields = status.stdout.toString('utf8').split('|');
              // ctr's atomic writer explicitly chmods 0666. The exact owner-
              // only parent, rather than the marker's permissions, prevents
              // other users and nonzero-UID workers from accessing this file.
              if (fields.length !== 6 || fields[0] !== 'regular file' || fields[1] !== String(guestUid) || !['600', '644', '666'].includes(fields[2]!) || !/^(?:[1-9]|10)$/.test(fields[3]!) || !/^[1-9][0-9]*$/.test(fields[4]!) || fields[5] !== '1') throw new Error(`LIMA_TASK_STDIN_HANDOFF_FAILED: invalid marker metadata ${JSON.stringify(fields).slice(0, 512)}`);
              const value = await guest(['/usr/bin/cat', '--', pidFile]);
              const confirmed = await guest(['/usr/bin/stat', '--printf=%F|%u|%a|%s|%i|%h', '--', pidFile]);
              const parentConfirmed = await guest(['/usr/bin/stat', '--printf=%F|%u|%a|%i', '--', directory]);
              if (value.code !== 0 || !/^[1-9][0-9]{0,9}$/.test(value.stdout.toString('utf8')) || confirmed.code !== 0 || !confirmed.stdout.equals(status.stdout) || parentConfirmed.code !== 0 || !parentConfirmed.stdout.equals(parent.stdout)) throw new Error('LIMA_TASK_STDIN_HANDOFF_FAILED: malformed or changed marker');
              ready = true; break;
            }
            if (status.code !== 1) throw new Error('LIMA_TASK_STDIN_HANDOFF_FAILED');
            await new Promise(resolve => setTimeout(resolve, 20));
          }
          if (!ready) throw new Error('LIMA_TASK_STDIN_HANDOFF_FAILED: task did not initialize its input within 30 seconds');
          for await (const chunk of frames) yield chunk;
        }
        return transfer(executable, limaShellArguments(runtime.receipt, [runtime.receipt.ctr, '--address', runtime.receipt.address, '--namespace', 'ud-agent', 'tasks', 'start', '--fifo-dir', directory, '--pid-file', pidFile, container]), gated(), input.signal, { ...(runtime.receipt.home ? { limaHome: runtime.receipt.home } : {}), ...(runtime.supervisor ? { supervisor: { ...runtime.supervisor, executableSha256: runtime.receipt.binarySha256 } } : {}) });
      }
      const receipt = runtime.receipt;
      const engineSha = runtime.engine === 'apple-container' ? runtime.receipt.engine.binarySha256 : runtime.receipt.binarySha256;
      return transfer(executable, runtime.engine === 'wslc' ? wslcArguments(runtime, args) : args, frames, input.signal, receipt.guardSha256 ? { supervisor: { guard: receipt.guard, guardSha256: receipt.guardSha256, executableSha256: engineSha } } : undefined);
    };
    const create = async (name: string, args: readonly string[], readonly: boolean): Promise<string> => {
      uncertain = true; const created = await command(createArgs(name, args, readonly), { ...OPTIONS, ...(seccompInput ? { input: seccompInput } : {}) }); if (created.code !== 0) throw new Error('PLATFORM_CREATE_FAILED');
      const raw = await command(inspectArgs(runtime, name)); const decoded = raw.code === 0 ? json(raw.stdout) : undefined; const containerId = canonicalId(runtime, decoded);
      if (!containerId) throw new Error('PLATFORM_CREATED_IDENTITY_INVALID');
      if (runtime.engine === 'lima-nerdctl') { const directory = limaJobStateDirectory(decoded, runtime, containerId, id); if (!directory) throw new Error('LIMA_JOB_STATE_DIRECTORY_INVALID'); stateDirectories.set(containerId, directory); }
      const violations = runtime.engine === 'apple-container' ? inspectAppleJob(decoded, { name, jobId: id, image: image.reference, command: args, readOnlyInput: readonly, volume }) : runtime.engine === 'lima-nerdctl' ? inspectLimaJob(decoded, { id: containerId, jobId: id, image: image.reference, command: args, readOnlyInput: readonly, runtime, ...(seccomp ? { seccomp } : {}), ...(inputSource ? { inputSource } : {}) }) : inspectWslcJob(decoded, { id: containerId, name, jobId: id, imageId: engineImageId!, volume, command: args, readOnlyInput: readonly });
      if (violations.length) throw new Error(`PLATFORM_CONTAINMENT_FAILED: ${violations.join(',')}`); uncertain = false; return containerId;
    };
    try {
      await journal.beginCreate(id, 'volume'); uncertain = true;
      const created = await command(['volume', 'create', '--label', `io.ud-agent.job=${id}`, ...(runtime.engine === 'apple-container' ? ['-s', '4G'] : []), volume]);
      if (created.code !== 0) throw new Error('PLATFORM_VOLUME_CREATE_FAILED');
      inputSource = await verifyVolume(runtime, command, volume, id); uncertain = false;
      await journal.transition(id, 'volume');
      // Apple volumes do not copy the image mountpoint's ownership. The only
      // uid-zero process is this fixed, network-disabled volume preparer; all
      // transfer and domain work executes with uid/gid 10001.
      if (runtime.engine === 'apple-container') {
        const initName = `ud-agent-${id}-loader`; const args = createArgs(initName, ['-I', '-B', '-c', INITIALIZE], false);
        args[args.indexOf('--uid') + 1] = '0'; args[args.indexOf('--gid') + 1] = '0'; args.splice(args.indexOf('--cap-drop'), 0, '--cap-add', 'CHOWN');
        await journal.beginCreate(id, 'initializer'); uncertain = true; if ((await command(args)).code !== 0) throw new Error('PLATFORM_VOLUME_PREPARE_FAILED');
        const raw = await command(inspectArgs(runtime, initName)); const inspected = raw.code === 0 ? json(raw.stdout) : undefined; const initializedId = canonicalId(runtime, inspected);
        const item = Array.isArray(inspected) && inspected.length === 1 ? object(inspected[0]) : undefined; const config = object(item?.configuration); const processConfig = object(config?.initProcess); const user = object(object(processConfig?.user)?.id); const resources = object(config?.resources); const mounts = Array.isArray(config?.mounts) ? config.mounts.map(object) : [];
        if (!initializedId || config?.id !== initName || object(config.labels)?.['io.ud-agent.job'] !== id || object(config.image)?.reference !== image.reference || config.readOnly !== true || config.ssh !== false || config.virtualization !== false || JSON.stringify(config.networks) !== '[]' || JSON.stringify(config.publishedSockets) !== '[]' || JSON.stringify(config.publishedPorts) !== '[]' || JSON.stringify(config.capAdd) !== '["CAP_CHOWN"]' || JSON.stringify(config.capDrop) !== '["ALL"]' || user?.uid !== 0 || user.gid !== 0 || processConfig?.executable !== '/usr/local/bin/python' || JSON.stringify(processConfig.arguments) !== JSON.stringify(['-I', '-B', '-c', INITIALIZE]) || resources?.cpus !== 2 || resources.memoryInBytes !== 2147483648 || mounts.some(value => value?.destination !== '/tmp' && value?.destination !== '/input') || !mounts.some(value => value?.destination === '/input' && object(object(value.type)?.volume)?.name === volume && Array.isArray(value.options) && (value.options.length === 0 || value.options.length === 1 && value.options[0] === 'rw'))) throw new Error('PLATFORM_VOLUME_PREPARER_UNVERIFIED');
        await journal.transition(id, 'initialized', { initializer: initializedId }); uncertain = false;
        async function* empty() { /* Fixed initializer accepts no input. */ }
        if ((await attach(initializedId, empty())).toString('utf8') !== 'initialized\n') throw new Error('PLATFORM_VOLUME_PREPARE_FAILED');
        await removeOwned(runtime, command, initializedId, initName, id, image.reference);
      } else await journal.transition(id, 'initialized');
      await journal.beginCreate(id, 'loader'); const loaderId = await create(loader, loaderCommand, false); await journal.transition(id, 'loader', { loader: loaderId });
      const loaded = line(await attach(loaderId, encodeSnapshotFrames(streamVerifiedSnapshot(guard, snapshot, input.signal))));
      if (loaded.status !== 'loaded' || loaded.snapshot_sha256 !== snapshot.sha256) throw new Error('PLATFORM_SNAPSHOT_LOAD_FAILED'); await journal.transition(id, 'loaded');
      await journal.beginCreate(id, 'worker'); const workerId = await create(worker, workerCommand, true); await journal.transition(id, 'worker', { worker: workerId });
      const args = { ...captured.arguments, ...(input.operation === 'validation_report' && input.selectAllFiles ? { file_paths: snapshot.files.filter(file => file.path.endsWith('.conllu') && !file.path.startsWith('.ud-agent-inputs/')).map(file => file.path) } : {}) };
      const request = Buffer.from(`${JSON.stringify({ operation: input.operation, arguments: args, snapshot_sha256: snapshot.sha256, files: snapshot.files, ...(captured.brokerEvidence ? { broker_evidence: captured.brokerEvidence } : {}) })}\n`);
      if (request.length > 16 * 1024 * 1024) throw new Error('WORKER_REQUEST_TOO_LARGE'); async function* one() { yield request; }
      response = line(await attach(workerId, one())); await journal.transition(id, 'ran');
    } catch (error) { failure = error; }
    if (uncertain) throw new Error(`PLATFORM_CREATE_OUTCOME_UNKNOWN: durable ownership journal retained for recovery.${failure instanceof Error ? ` ${failure.message}` : ''}`, { cause: failure });
    // Cancellation revokes work, never the separate duty to remove resources
    // whose ownership is already durably known.
    await cleanupPlatformJob(runtime, image, journal, id, rawCommand, guestCommand);
    if (failure) throw failure;
    if (response?.ok !== true || !object(response.result)) { const error = object(response?.error); const failure = new Error(typeof error?.message === 'string' ? error.message : 'PLATFORM_WORKER_RESPONSE_INVALID') as Error & { code?: string }; if (typeof error?.code === 'string') failure.code = error.code; throw failure; }
    return { result: response.result as Record<string, unknown>, snapshot: { root_identity: { device: snapshot.root_identity.device, inode: snapshot.root_identity.inode }, sha256: snapshot.sha256, files: snapshot.files, source_map: captured.sourceMap } };
    });
  } finally { await snapshot.cleanup(); }
}

async function verifyVolume(runtime: PlatformRuntime, command: (args: readonly string[]) => Promise<CommandResult>, name: string, id: string): Promise<string> {
  const result = await command(['volume', 'inspect', name]); const decoded = result.code === 0 ? json(result.stdout) : undefined; const item = Array.isArray(decoded) && decoded.length === 1 ? object(decoded[0]) : undefined;
  if (runtime.engine === 'lima-nerdctl') {
    const listing = await command(['volume', 'ls', '--format', '{{json .}}']);
    if (listing.code !== 0) throw new Error('PLATFORM_VOLUME_OWNERSHIP_INVALID');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(listing.stdout).trim();
    const rows = !text ? [] : text.startsWith('[') ? json(Buffer.from(text)) : text.split(/\r?\n/).map(value => json(Buffer.from(value)));
    const source = limaVolumeIdentity(decoded, rows, { name, jobId: id });
    if (!source) throw new Error('PLATFORM_VOLUME_OWNERSHIP_INVALID');
    return source;
  }
  const config = runtime.engine === 'apple-container' ? object(item?.configuration) ?? item : item;
  if (!config || (config.Name ?? config.name) !== name || (config.Driver ?? config.driver) !== 'local' || object(config.Labels ?? config.labels)?.['io.ud-agent.job'] !== id) throw new Error('PLATFORM_VOLUME_OWNERSHIP_INVALID');
  const source = config.Mountpoint ?? config.source; if (typeof source !== 'string' || !source.startsWith('/') || source.includes('\0')) throw new Error('PLATFORM_VOLUME_SOURCE_INVALID'); return source;
}

async function removeOwned(runtime: PlatformRuntime, command: (args: readonly string[]) => Promise<CommandResult>, container: string, name: string, id: string, image: string, guestCommand?: GuestCommand): Promise<void> {
  const inspected = await command(inspectArgs(runtime, name));
  if (inspected.code !== 0) { await confirmContainerAbsent(runtime, command, name, container); return; }
  const decoded = json(inspected.stdout); const item = Array.isArray(decoded) && decoded.length === 1 ? object(decoded[0]) : undefined; const config = runtime.engine === 'apple-container' ? object(item?.configuration) : runtime.engine === 'lima-nerdctl' ? item : object(item?.Config);
  if (canonicalId(runtime, decoded) !== container || object(config?.labels ?? config?.Labels)?.['io.ud-agent.job'] !== id || runtime.engine === 'apple-container' && object(config?.image)?.reference !== image || runtime.engine === 'lima-nerdctl' && item?.Image !== image) throw new Error('PLATFORM_CLEANUP_OWNERSHIP_MISMATCH');
  const directory = runtime.engine === 'lima-nerdctl' ? limaJobStateDirectory(decoded, runtime, container, id) : undefined;
  if (runtime.engine === 'lima-nerdctl' && !directory) throw new Error('PLATFORM_CLEANUP_OWNERSHIP_MISMATCH');
  await command([...containerPrefix(runtime), 'stop', '--time', '2', container]);
  const removed = await command([...containerPrefix(runtime), runtime.engine === 'apple-container' ? 'delete' : 'rm', '--force', container]); if (removed.code !== 0) throw new Error('PLATFORM_CLEANUP_UNVERIFIED');
  const after = await command(inspectArgs(runtime, container)); if (after.code === 0) throw new Error('PLATFORM_CLEANUP_UNVERIFIED'); await confirmContainerAbsent(runtime, command, name, container);
  if (runtime.engine === 'lima-nerdctl') { const absent = await (guestCommand ?? (args => limaGuestCommand(runtime, args)))(['/usr/bin/test', '!', '-e', directory!, '-a', '!', '-L', directory!]); if (absent.code !== 0) throw new Error('PLATFORM_CLEANUP_UNVERIFIED'); }
}

export async function cleanupPlatformJob(runtime: PlatformRuntime, image: ImageReceipt, journal: PlatformJournal, id: string, command: (args: readonly string[]) => Promise<CommandResult>, guestCommand?: GuestCommand): Promise<void> {
  const saved = await journal.load(id); if (saved.provider !== runtime.engine || saved.authority !== platformAuthorityIdentity(runtime) || saved.image !== image.digest) throw new Error('PLATFORM_RECOVERY_AUTHORITY_CHANGED'); if (saved.phase === 'cleaned') return;
  if (saved.phase !== 'cleanup') await journal.transition(id, 'cleanup');
  for (const kind of ['worker', 'loader'] as const) if (saved[kind]) await removeOwned(runtime, command, saved[kind], `ud-agent-${id}-${kind}`, id, image.reference, guestCommand);
  if (saved.initializer && !saved.loader) await removeOwned(runtime, command, saved.initializer, `ud-agent-${id}-loader`, id, image.reference);
  const volume = `ud-agent-${id}-input`; const inspection = await command(['volume', 'inspect', volume]);
  if (inspection.code === 0) { await verifyVolume(runtime, command, volume, id); const removed = await command(['volume', runtime.engine === 'apple-container' ? 'delete' : 'rm', volume]); if (removed.code !== 0) throw new Error('PLATFORM_CLEANUP_UNVERIFIED'); }
  await confirmVolumeAbsent(runtime, command, volume);
  await journal.transition(id, 'cleaned');
}

/** Reconcile observed owned creates while preserving all ambiguous absence. */
export async function recoverPlatformJobs(runtime: PlatformRuntime, image: ImageReceipt, guard: string, stateRoot: string, runner: Runner = runCommand): Promise<{ recovered: string[]; active: string[] }> {
  const perform = async (command: (args: readonly string[], options?: CommandOptions) => Promise<CommandResult>) => {
    const journal = await PlatformJournal.open(stateRoot, guard); const recovered: string[] = []; const active: string[] = [];
    for (const initial of await journal.pending()) {
      if (initial.provider !== runtime.engine || initial.image !== image.digest) continue;
      if (initial.authority !== platformAuthorityIdentity(runtime)) throw new Error('PLATFORM_RECOVERY_AUTHORITY_CHANGED');
      try {
        await journal.withJobLock(initial.id, async () => {
          const job = await journal.load(initial.id); if (job.phase === 'cleaned') return;
          if (job.phase === 'planned' && !job.pending_create) { await journal.transition(job.id, 'cleanup'); await journal.transition(job.id, 'cleaned'); recovered.push(job.id); return; }
          if (job.pending_create === 'volume' || job.lifecycle_revision !== 2 && job.phase === 'volume') { try { await verifyVolume(runtime, command, `ud-agent-${job.id}-input`, job.id); } catch (error) { if (error instanceof Error && error.message === 'PLATFORM_VOLUME_OWNERSHIP_INVALID') throw new Error('PLATFORM_CREATE_OUTCOME_UNKNOWN: unsettled volume create has no verified owned resource yet.'); throw error; } }
          const ids: { initializer?: string; loader?: string; worker?: string } = {};
          for (const kind of ['loader', 'worker'] as const) {
            const name = `ud-agent-${job.id}-${kind}`; const raw = await command(inspectArgs(runtime, name)); if (raw.code !== 0) continue;
            const decoded = json(raw.stdout); const id = canonicalId(runtime, decoded); const item = Array.isArray(decoded) && decoded.length === 1 ? object(decoded[0]) : undefined; const config = runtime.engine === 'apple-container' ? object(item?.configuration) : runtime.engine === 'lima-nerdctl' ? item : object(item?.Config);
            const ownedKind = kind === 'loader' && job.pending_create === 'initializer' ? 'initializer' : kind;
            if (!id || object(config?.labels ?? config?.Labels)?.['io.ud-agent.job'] !== job.id || runtime.engine === 'apple-container' && object(config?.image)?.reference !== image.reference || runtime.engine === 'lima-nerdctl' && item?.Image !== image.reference || job[ownedKind] !== undefined && job[ownedKind] !== id) throw new Error('PLATFORM_RECOVERY_OWNERSHIP_MISMATCH'); ids[ownedKind] = id;
          }
          if (job.pending_create && job.pending_create !== 'volume' && !job[job.pending_create] && !ids[job.pending_create] || job.lifecycle_revision !== 2 && (job.phase === 'initialized' && !job.loader && !ids.loader || job.phase === 'loaded' && !job.worker && !ids.worker || runtime.engine === 'apple-container' && job.phase === 'volume' && !job.initializer && !ids.loader)) throw new Error('PLATFORM_CREATE_OUTCOME_UNKNOWN: unsettled create has no verified resource yet.');
          if (job.phase !== 'cleanup' || Object.keys(ids).length) await journal.transition(job.id, 'cleanup', ids);
          await cleanupPlatformJob(runtime, image, journal, job.id, command, runtime.engine === 'lima-nerdctl' ? args => limaGuestCommand(runtime, args, OPTIONS, runner) : undefined); recovered.push(job.id);
        });
      } catch (error) { if (error instanceof Error && error.message.startsWith('WORKSPACE_LOCKED_OR_STALE:')) { active.push(initial.id); continue; } throw error; }
    }
    return { recovered, active };
  };
  if (runtime.engine === 'apple-container') return withAppleRuntime(runtime, perform, runner);
  return perform((args, options = OPTIONS) => runtime.engine === 'lima-nerdctl' ? limaCommand(runtime, args, options, runner) : wslcCommand(runtime, args, options, runner));
}
