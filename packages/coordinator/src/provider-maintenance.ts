import { cleanOwnedLimaFiles } from '../../runtime-manager/src/lima-cleanup.js';
import { recoverLimaGeneratedConfig } from './lima-config-recovery.js';
import { recoverImageImportStaging } from '../../runtime-manager/src/image-import-staging.js';
import { reclaimImageCache } from '../../runtime-manager/src/image-cache.js';
import { cleanImageRepairArtifacts } from './image-repair.js';
import { cleanProviderAssets, providerAssetRoot } from '../../runtime-manager/src/provider-assets.js';
import { lstat, readdir, realpath, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { parseDocument } from 'yaml';
import path from 'node:path';
import type { RuntimeOptions, OciEngine } from '../../runtime-manager/src/environment.js';
import type { Host } from '../../runtime-manager/src/profiles.js';
import { readBoundedReceipt, verifyArchive } from '../../runtime-manager/src/receipt.js';
import { boundedRead, durableWrite, fsyncDirectory, JournalStore, openStateAuthority, sha256 } from '../../workspace/src/journal.js';
import { guardedIdentity, guardedPrivateDirectory, guardedRead, guardedStateLock } from '../../workspace/src/guard.js';
import { resolveDockerCleanupAuthority, resolveProductGuard } from './docker-authority.js';
import { resolvePodmanCleanupAuthority } from './podman-authority.js';
import { dockerStateRoot } from './docker-readiness.js';
import { podmanStateRoot } from './podman-readiness.js';
import { platformStateRoot, resolvePlatformMaintenance } from './platform-readiness.js';
import { recoverDockerValidation } from './docker-worker.js';
import { recoverPodmanWorker } from './podman-worker.js';
import type { DockerJobRecord } from './docker-journal.js';
import type { PodmanJobRecord } from './podman-journal.js';
import { readMaintenanceJobs, removeCleanedJob } from './maintenance-state.js';
import { withProviderMaintenance } from './provider-leases.js';
import { recoverPlatformJobs } from './platform-worker.js';
import { PlatformJournal } from './platform-journal.js';
import type { PlatformJob } from './platform-journal.js';
import { validateProviderReceipt } from '../../runtime-manager/src/provider-receipt.js';
import { runCommand } from '../../runtime-manager/src/command.js';
import { inspectLima } from '../../runtime-manager/src/lima.js';
import { ownedLimaHomeRemoval, removeEmptyOwnedLimaHome, resolveOwnedLimaHome } from '../../runtime-manager/src/lima-storage.js';
import { validateOwnedLimaTemplate } from '../../runtime-manager/src/lima-provision.js';
import { admitLimaRuntime, limaCommand, limaGuestCommand, limaImageIdentity } from '../../runtime-manager/src/lima-nerdctl.js';
import { readImageTransports } from '../../runtime-manager/src/receipt.js';
import type { ImageReceipt } from '../../runtime-manager/src/receipt.js';
import type { LimaRuntimeReceipt } from '../../runtime-manager/src/lima-nerdctl.js';
import { selectLimaCli } from '../../runtime-manager/src/lima-cli-admission.js';
import { readWslcSessions, saveWslcSession } from '../../runtime-manager/src/wslc-state.js';
import { wslcArguments, wslcSessionIdentity, wslcText } from '../../runtime-manager/src/wslc-runtime.js';
import type { WslcRuntimeReceipt } from '../../runtime-manager/src/wslc-runtime.js';

export type ProviderMaintenanceRequest = { action: 'cache' | 'owned-runtime'; dryRun: boolean; signal?: AbortSignal };
export type ProviderMaintenanceResult = { engine: OciEngine; status: 'absent' | 'dry_run' | 'complete'; action: 'cache' | 'owned-runtime'; dry_run: boolean; paths: string[]; resources: string[]; recovered_jobs: string[]; protected_paths: string[]; limitations: string[] };
const SHA = /^sha256:[0-9a-f]{64}$/;
function object(raw: unknown): Record<string, unknown> | undefined { return raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw as Record<string, unknown> : undefined; }
function check(signal?: AbortSignal) { if (signal?.aborted) throw new Error('PROVIDER_MAINTENANCE_CANCELLED'); }
function canonical(value: unknown): string { if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`; if (value !== null && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`; return JSON.stringify(value); }
function jsonRows(bytes: Buffer): Record<string, unknown>[] { const text = wslcText(bytes).trim(); if (!text) return []; const value: unknown = text.startsWith('[') ? JSON.parse(text) : text.split(/\r?\n/).map(line => JSON.parse(line) as unknown); if (!Array.isArray(value) || value.length > 10000 || value.some(item => !object(item))) throw new Error('PROVIDER_RESOURCE_INVENTORY_INVALID'); return value as Record<string, unknown>[]; }

/** A running owned VM may still contain work added by its administrator. */
function maintenanceLimaReceipt(record: Record<string, unknown>, executable: string, home: string): LimaRuntimeReceipt {
  return { schema_version: 1, executable, binarySha256: record.executable_sha256 as string, home, instance: record.instance as string, nerdctl: record.nerdctl as string, nerdctlSha256: record.nerdctl_sha256 as string, containerd: record.containerd as string, containerdSha256: record.containerd_sha256 as string, ...(typeof record.ctr === 'string' && typeof record.ctr_sha256 === 'string' ? { ctr: record.ctr, ctrSha256: record.ctr_sha256 } : {}), ...(typeof record.nsenter === 'string' && typeof record.nsenter_sha256 === 'string' ? { nsenter: record.nsenter, nsenterSha256: record.nsenter_sha256 } : {}), address: record.address as string, guestUid: record.guest_uid as number, guestHome: record.guest_home as string, architecture: record.architecture as 'amd64' | 'arm64' };
}
async function verifyLimaHasOnlyOwnedCache(record: Record<string, unknown>, lock: Record<string, unknown>, executable: string, home: string, guard: string, guardSha256: string, signal?: AbortSignal): Promise<void> {
  const receipt = maintenanceLimaReceipt(record, executable, home);
  const runtime = await admitLimaRuntime(receipt, runCommand, { guard, guardSha256 });
  const options = { timeoutMs: 30000, maxOutputBytes: 16 * 1024 * 1024, limaHome: home, ...(signal ? { signal } : {}) };
  const namespaces = await limaCommand(runtime, ['namespace', 'ls', '--quiet'], options);
  if (namespaces.code !== 0) throw new Error('LIMA_OWNED_RESOURCE_INVENTORY_FAILED');
  const names = namespaces.stdout.toString('utf8').trim().split(/\r?\n/).filter(Boolean);
  if (names.length > 1000 || new Set(names).size !== names.length || names.some(name => !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(name))) throw new Error('LIMA_OWNED_RESOURCE_INVENTORY_FAILED');
  const allowedImages = new Map<string, ImageReceipt[]>();
  for (const raw of Object.values(object(lock.packs) ?? {})) {
    const pack = object(raw), image = object(object(pack?.images)?.[`linux/${receipt.architecture}`]); if (!image) continue;
    if (typeof image.digest !== 'string' || !SHA.test(image.digest) || typeof image.reference !== 'string' || !/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(image.reference) || !image.reference.endsWith(`@${image.digest}`) || typeof pack?.context_sha256 !== 'string' || !SHA.test(pack.context_sha256) || typeof image.config_digest !== 'string' || !SHA.test(image.config_digest) || !Array.isArray(image.diff_ids) || !image.diff_ids.length || image.diff_ids.some(value => typeof value !== 'string' || !SHA.test(value))) throw new Error('LIMA_OWNED_IMAGE_SOURCE_INVALID');
    const transports = readImageTransports(image.transports); const selected: ImageReceipt = { digest: image.digest, reference: image.reference, contextSha256: pack.context_sha256, configDigest: image.config_digest, diffIds: image.diff_ids as string[], ...(transports ? { transports } : {}), ...(Array.isArray(image.engine_descriptor_digests) ? { engineDescriptorDigests: image.engine_descriptor_digests as string[] } : {}) };
    for (const alias of new Set([selected.reference, `import@${selected.digest}`, ...(transports ?? []).flatMap(item => item.format === 'oci-archive' && item.indexDigest ? [`import@${item.indexDigest}`] : [])])) allowedImages.set(alias, [...(allowedImages.get(alias) ?? []), selected]);
  }
  for (const namespace of names) {
    const run = async (args: string[]) => {
      check(signal); await limaCommand(runtime, ['info', '--mode=native', '--format', '{{json .}}'], options);
      const value = await limaGuestCommand(runtime, [receipt.nerdctl, '--address', receipt.address, '--namespace', namespace, '--snapshotter', 'overlayfs', '--cgroup-manager', 'systemd', ...args], options);
      await limaCommand(runtime, ['info', '--mode=native', '--format', '{{json .}}'], options);
      if (value.code !== 0) throw new Error('LIMA_OWNED_RESOURCE_INVENTORY_FAILED'); return jsonRows(value.stdout);
    };
    if ((await run(['container', 'ls', '--all', '--no-trunc', '--format', '{{json .}}'])).length || (await run(['volume', 'ls', '--format', '{{json .}}'])).length) throw new Error('LIMA_OWNED_VM_HAS_UNOWNED_RESOURCES');
    for (const image of await run(['image', 'ls', '--digests', '--no-trunc', '--format', '{{json .}}'])) {
      const name = typeof image.Name === 'string' ? image.Name : typeof image.Repository === 'string' && typeof image.Digest === 'string' && SHA.test(image.Digest) ? `${image.Repository}@${image.Digest}` : undefined;
      const candidates = name ? allowedImages.get(name) : undefined; if (!name || !candidates?.length || namespace !== 'ud-agent') throw new Error('LIMA_OWNED_VM_HAS_UNOWNED_RESOURCES');
      const inspected = await run(['image', 'inspect', '--mode=native', name]); if (!candidates.some(candidate => limaImageIdentity(inspected, { ...candidate, reference: name }, receipt.architecture))) throw new Error('LIMA_OWNED_VM_HAS_UNOWNED_RESOURCES');
    }
  }
}

async function maintainPlatformState(options: RuntimeOptions, engine: 'apple-container' | 'lima-nerdctl' | 'wslc', executable: string, host: Host, root: string, guard: string, guardSha256: string, request: ProviderMaintenanceRequest, result: ProviderMaintenanceResult): Promise<void> {
  const lock = await readBoundedReceipt(path.join(options.sourceRoot, 'runtime/runtime.lock.json')); const originalRecord = object(lock.provider_receipts)?.[`${engine}/${host.platform}/${host.arch}`];
  if (originalRecord === undefined) throw new Error('PROVIDER_MAINTENANCE_RECEIPT_REQUIRED'); validateProviderReceipt(engine, host, originalRecord); let record = originalRecord;
  let jobs = await readMaintenanceJobs<PlatformJob>(root, guard, 'platform'); const native = await openStateAuthority(root, guard);
  try { await verifyArchive(executable, originalRecord.executable_sha256 as string, request.signal); }
  catch (error) {
    if (engine !== 'lima-nerdctl') throw error;
    const selection = await selectLimaCli({ executable, officialSha256: originalRecord.executable_sha256 as string, sourceRoot: options.sourceRoot, stateRoot: root, prepare: true, repair: true, ...(request.signal ? { signal: request.signal } : {}) });
    if (!selection?.identity) throw new Error('LIMA_CLEANUP_CLI_ADMISSION_REQUIRED');
    record = { ...originalRecord, executable_sha256: selection.binarySha256 };
    // This handoff authorizes cleanup only; ordinary execution still requires
    // explicit repair and a successful new containment probe before commit.
    if (!request.dryRun) await durableWrite(path.join(root, 'lima-cli-cleanup.json'), Buffer.from(`${JSON.stringify({ schema_version: 1, mode: 'cleanup_only', source_receipt_sha256: sha256(Buffer.from(canonical(originalRecord))), identity: selection.identity, ...(selection.previousReceiptSha256 ? { previous_receipt_sha256: selection.previousReceiptSha256 } : {}) })}\n`), native);
    result.limitations.push('The currently verified Lima CLI is authorized for cleanup only; ordinary runtime admission is unchanged.');
  }
  const engineRunner: typeof runCommand = (file, args, commandOptions) => runCommand(file, args, { ...commandOptions, supervisor: { guard, guardSha256, executableSha256: record.executable_sha256 as string } });
  if (jobs.some(row => row.value.provider !== engine)) throw new Error('PROVIDER_JOB_NAMESPACE_CHANGED');
  let ownedLima: { instance: string; home: string; template: string; stopped: boolean; removed?: boolean } | undefined;
  if (engine === 'lima-nerdctl' && record.provisioning) {
    let owner: Record<string, unknown> | undefined; const removal = request.action === 'owned-runtime' ? await ownedLimaHomeRemoval(root, guard) : undefined;
    if (removal && !request.dryRun && removal.phase !== 'completed') { if (!await removeEmptyOwnedLimaHome(root, guard)) throw new Error('LIMA_HOME_REMOVAL_REQUIRES_RECOVERY'); removal.phase = 'completed'; }
    const home = removal?.binding.home ?? await resolveOwnedLimaHome(root, guard) ?? path.join(root, 'lima-home');
    try { owner = object(JSON.parse((await boundedRead(path.join(root, 'lima-instance.json'), 16384, native)).toString('utf8'))); if (!owner) throw new Error('LIMA_MAINTENANCE_OWNERSHIP_CHANGED'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (owner && (owner.schema_version !== 1 || owner.instance !== record.instance || owner.home !== home || typeof owner.template_sha256 !== 'string' || !SHA.test(owner.template_sha256) || !['creating', 'created', 'running'].includes(owner.phase as string))) throw new Error('LIMA_MAINTENANCE_OWNERSHIP_CHANGED');
    const state = removal ? {} as { selected?: { status: string } } : await inspectLima({ executable, binarySha256: record.executable_sha256 as string, home }, record.instance as string, engineRunner);
    if (!owner && !state.selected && request.action === 'owned-runtime') { try { const prior = object(JSON.parse((await boundedRead(path.join(root, 'lima-uninstall.json'), 16384, native)).toString('utf8'))); if (prior?.schema_version === 1 && prior.instance === record.instance && prior.home === home && typeof prior.template_sha256 === 'string' && SHA.test(prior.template_sha256) && ['planned', 'stopped', 'completed'].includes(prior.phase as string)) owner = { ...prior, phase: 'created' }; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } }
    if (state.selected && !owner) { result.protected_paths.push(`lima-home/${record.instance as string}`); }
    if (state.selected && owner) {
      const config = parseDocument((await guardedRead(guard, home, `${record.instance as string}/lima.yaml`, 1024 * 1024, await guardedIdentity(guard, home))).toString('utf8'), { uniqueKeys: true }); if (config.errors.length || config.warnings.length) throw new Error('LIMA_OWNED_CONFIG_CHANGED'); const value = config.toJS({ maxAliasCount: 0 }) as Record<string, unknown>; validateOwnedLimaTemplate(value, record.architecture as 'amd64' | 'arm64');
      if (`sha256:${createHash('sha256').update(canonical(value)).digest('hex')}` !== owner.template_sha256) throw new Error('LIMA_OWNED_CONFIG_CHANGED');
    }
    if (owner) ownedLima = { instance: record.instance as string, home, template: owner.template_sha256 as string, stopped: !state.selected || state.selected.status === 'stopped', ...(removal ? { removed: removal.phase === 'completed' } : {}) };
    if (state.selected && state.selected.status === 'other') throw new Error('LIMA_VM_STATE_UNVERIFIED');
  }
  if (!request.dryRun && jobs.some(row => row.value.phase !== 'cleaned') && !(request.action === 'owned-runtime' && (ownedLima?.stopped || engine === 'wslc'))) {
    for (const pack of ['core', 'render'] as const) {
      if (!jobs.some(row => row.value.phase !== 'cleaned')) break;
      const authority = await resolvePlatformMaintenance(options, engine, executable, host, pack); if (!authority) continue;
      const recovered = await recoverPlatformJobs(authority.runtime, authority.image, guard, root); if (recovered.active.length) throw new Error('PROVIDER_RUNTIME_IN_USE'); result.recovered_jobs.push(...recovered.recovered); jobs = await readMaintenanceJobs(root, guard, 'platform');
    }
    if (jobs.some(row => row.value.phase !== 'cleaned')) throw new Error('PROVIDER_JOB_RECOVERY_AUTHORITY_REQUIRED');
  }
  if (request.action === 'owned-runtime' && ownedLima) {
    result.resources.push(`lima:${ownedLima.instance}`);
    if (!ownedLima.stopped) await verifyLimaHasOnlyOwnedCache(record, lock, executable, ownedLima.home, guard, guardSha256, request.signal);
    if (!request.dryRun) {
      const journalPath = path.join(root, 'lima-uninstall.json'); const stamp = { schema_version: 1, instance: ownedLima.instance, home: ownedLima.home, template_sha256: ownedLima.template };
      try { const prior = object(JSON.parse((await boundedRead(journalPath, 16384, native)).toString('utf8'))); if (!prior || Object.keys(prior).some(key => ![...Object.keys(stamp), 'phase'].includes(key)) || Object.entries(stamp).some(([key, value]) => prior[key] !== value) || !['planned', 'stopped', 'completed'].includes(prior.phase as string)) throw new Error('LIMA_UNINSTALL_JOURNAL_INVALID'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      await durableWrite(journalPath, Buffer.from(`${JSON.stringify({ ...stamp, phase: 'planned' })}\n`), native);
      let homeRemoved = ownedLima.removed === true;
      if (!homeRemoved) {
      const generated = object(object(record.provisioning)?.generated_config);
      if (generated && typeof generated.networks_sha256 === 'string') {
        const recovered = await recoverLimaGeneratedConfig(root, guard, guardSha256, maintenanceLimaReceipt(record, executable, ownedLima.home), { generatedConfig: { networksSha256: generated.networks_sha256 } }, (file, args, commandOptions) => runCommand(file, args, { ...commandOptions, ...(request.signal ? { signal: request.signal } : {}) }));
        if (recovered.status === 'protected') result.limitations.push(recovered.reason ?? 'Generated Lima configuration is protected without durable create authority.');
      }
      const runnerOptions = { timeoutMs: 120000, maxOutputBytes: 4 * 1024 * 1024, limaHome: ownedLima.home, ...(request.signal ? { signal: request.signal } : {}) };
      const before = await inspectLima({ executable, binarySha256: record.executable_sha256 as string, home: ownedLima.home }, ownedLima.instance, engineRunner);
      if (before.selected?.status === 'running') { check(request.signal); const stop = await engineRunner(executable, ['stop', '--tty=false', ownedLima.instance], runnerOptions); if (stop.code !== 0) throw new Error('LIMA_OWNED_STOP_UNVERIFIED'); }
      const stopped = await inspectLima({ executable, binarySha256: record.executable_sha256 as string, home: ownedLima.home }, ownedLima.instance, engineRunner); if (stopped.selected && stopped.selected.status !== 'stopped') throw new Error('LIMA_OWNED_STOP_UNVERIFIED');
      await durableWrite(journalPath, Buffer.from(`${JSON.stringify({ ...stamp, phase: 'stopped' })}\n`), native);
      if (stopped.selected) { check(request.signal); const deleted = await engineRunner(executable, ['delete', '--tty=false', ownedLima.instance], runnerOptions); if (deleted.code !== 0) throw new Error('LIMA_OWNED_DELETE_UNVERIFIED'); }
      if ((await inspectLima({ executable, binarySha256: record.executable_sha256 as string, home: ownedLima.home }, ownedLima.instance, engineRunner)).selected) throw new Error('LIMA_OWNED_DELETE_UNVERIFIED');
      const files = await cleanOwnedLimaFiles(root, ownedLima.home, guard, record.provisioning as Record<string, unknown>, false); result.paths.push(...files.paths.map(name => path.join(ownedLima!.home, name))); result.protected_paths.push(...files.protected.map(name => path.join(ownedLima!.home, name)));
      homeRemoved = await removeEmptyOwnedLimaHome(root, guard); if (!homeRemoved) result.protected_paths.push(ownedLima.home);
      }
      if (homeRemoved) for (const name of ['lima-generated-config.json', 'lima-aux-cleanup.json', 'lima-create-origin.json', 'lima-generated-config-recovery.json']) { try { const metadata = object(JSON.parse((await boundedRead(path.join(root, name), 65536, native)).toString('utf8'))); if (metadata?.schema_version !== 1 || metadata.home !== ownedLima.home) throw new Error('LIMA_CLEANUP_METADATA_CHANGED'); await rm(path.join(root, name)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } }
      await durableWrite(journalPath, Buffer.from(`${JSON.stringify({ ...stamp, phase: 'completed' })}\n`), native);
      const journal = await PlatformJournal.open(root, guard); for (const row of jobs.filter(row => row.value.phase !== 'cleaned')) { await journal.transition(row.value.id, 'cleanup'); await journal.transition(row.value.id, 'cleaned'); result.recovered_jobs.push(row.value.id); }
      await rm(path.join(root, 'lima-instance.json'), { force: true }); jobs = await readMaintenanceJobs(root, guard, 'platform');
    }
    result.limitations.push('Other Lima instances and shared Lima services are retained.');
  }
  if (engine === 'wslc' && request.action === 'owned-runtime') {
    const sdk = record.sdk as string; const receipt: WslcRuntimeReceipt = { schema_version: 1, executable, binarySha256: record.executable_sha256 as string, sdk: path.isAbsolute(sdk) ? sdk : path.join(options.sourceRoot, ...sdk.split('/')), sdkSha256: record.sdk_sha256 as string, guard, storage: path.join(root, 'session-storage'), architecture: host.arch === 'x64' ? 'amd64' : 'arm64' };
    const owned = await readWslcSessions(receipt);
    if (owned.length) { const assets = await providerAssetRoot(options.sourceRoot, root, guard, record, engine, host); if (!path.isAbsolute(sdk)) receipt.sdk = path.join(assets, ...sdk.split('/')); await verifyArchive(receipt.sdk, receipt.sdkSha256, request.signal); }
    if (!owned.length) { try { await lstat(receipt.storage); result.protected_paths.push('session-storage'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } }
    const sessionAuthority = (session: typeof owned[number]) => session.identity ? `${session.engine_sha256}:${session.sdk_sha256}:${receipt.storage}:${session.session}:${session.identity.id}:${session.identity.creatorPid}` : undefined;
    if (jobs.some(row => row.value.phase !== 'cleaned' && !owned.some(session => sessionAuthority(session) === row.value.authority))) throw new Error('WSLC_JOB_SESSION_AUTHORITY_REQUIRED');
    const runSession = (session: string, args: string[]) => engineRunner(executable, wslcArguments({ session }, args), { timeoutMs: 30000, maxOutputBytes: 16 * 1024 * 1024 });
    for (const session of owned) {
      result.resources.push(`wslc:${session.session}`); if (request.dryRun) continue;
      const system = await engineRunner(executable, ['system', 'info', '--format', 'json'], { timeoutMs: 30000, maxOutputBytes: 16 * 1024 * 1024 }); if (system.code !== 0) throw new Error('WSLC_SESSION_INSPECTION_INVALID');
      const actual = wslcSessionIdentity(JSON.parse(wslcText(system.stdout)), session.session);
      if (actual && session.identity && (actual.id !== session.identity.id || actual.creatorPid !== session.identity.creatorPid)) throw new Error('WSLC_SESSION_IDENTITY_CHANGED');
      if (actual) {
        const containers = await runSession(session.session, ['container', 'ls', '--all', '--no-trunc', '--format', 'json']); if (containers.code !== 0) throw new Error('WSLC_SESSION_RESOURCE_INSPECTION_FAILED');
        for (const item of jsonRows(containers.stdout)) {
          const id = item.ID ?? item.Id; if (typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id)) throw new Error('WSLC_SESSION_RESOURCE_INSPECTION_FAILED');
          const inspected = await runSession(session.session, ['container', 'inspect', id]); const values = inspected.code === 0 ? jsonRows(inspected.stdout) : []; const container = values.length === 1 ? values[0] : undefined; const config = object(container?.Config); const jobId = object(config?.Labels)?.['io.ud-agent.job']; const job = jobs.find(row => row.value.id === jobId)?.value;
          const expectedName = typeof container?.Name === 'string' ? container.Name.replace(/^\//, '') : '';
          if (!container || container.Id !== id || !job || job.authority !== sessionAuthority(session) || ![`ud-agent-${job.id}-loader`, `ud-agent-${job.id}-worker`].includes(expectedName) || (job.image_id !== undefined && container.Image !== job.image_id) || (job.image_reference !== undefined ? config?.Image !== job.image_reference : typeof config?.Image !== 'string' || !/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(config.Image) || !config.Image.endsWith(`@${job.image}`))) throw new Error('WSLC_SESSION_HAS_UNOWNED_RESOURCES');
        }
        const volumes = await runSession(session.session, ['volume', 'ls', '--format', 'json']); if (volumes.code !== 0) throw new Error('WSLC_SESSION_RESOURCE_INSPECTION_FAILED');
        for (const item of jsonRows(volumes.stdout)) {
          const name = item.Name; if (typeof name !== 'string') throw new Error('WSLC_SESSION_RESOURCE_INSPECTION_FAILED');
          const inspected = await runSession(session.session, ['volume', 'inspect', name]); const values = inspected.code === 0 ? jsonRows(inspected.stdout) : []; const volume = values.length === 1 ? values[0] : undefined; const job = jobs.find(row => row.value.id === object(volume?.Labels)?.['io.ud-agent.job'])?.value;
          if (!volume || volume.Name !== name || !job || job.authority !== sessionAuthority(session) || name !== `ud-agent-${job.id}-input`) throw new Error('WSLC_SESSION_HAS_UNOWNED_RESOURCES');
        }
        check(request.signal); const terminated = await engineRunner(executable, wslcArguments({ session: session.session }, ['system', 'session', 'terminate']), { timeoutMs: 35000, maxOutputBytes: 1024 * 1024 }); if (terminated.code !== 0) throw new Error('WSLC_SESSION_CLEANUP_UNVERIFIED');
      }
      const deadline = Date.now() + 35000;
      for (;;) { const inspected = await engineRunner(executable, ['system', 'info', '--format', 'json'], { timeoutMs: 30000, maxOutputBytes: 16 * 1024 * 1024 }); if (inspected.code !== 0) throw new Error('WSLC_SESSION_CLEANUP_UNVERIFIED'); if (!wslcSessionIdentity(JSON.parse(wslcText(inspected.stdout)), session.session)) break; if (Date.now() >= deadline) throw new Error('WSLC_SESSION_CLEANUP_UNVERIFIED'); await new Promise(done => setTimeout(done, 20)); }
      const storageIdentity = await guardedIdentity(guard, receipt.storage); let released = false;
      while (!released) { try { const unlock = await guardedStateLock(guard, receipt.storage, `.session-${session.session}.native`, storageIdentity, true); await unlock(); released = true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') released = true; else if ((error as NodeJS.ErrnoException).code !== 'EBUSY' || Date.now() >= deadline) throw new Error('WSLC_SESSION_OWNER_STILL_ACTIVE'); else await new Promise(done => setTimeout(done, 20)); } }
      session.phase = 'terminated'; await saveWslcSession(receipt, session);
    }
    if (!request.dryRun && owned.length) {
      const journal = await PlatformJournal.open(root, guard); for (const row of jobs.filter(row => row.value.phase !== 'cleaned')) { await journal.transition(row.value.id, 'cleanup'); await journal.transition(row.value.id, 'cleaned'); result.recovered_jobs.push(row.value.id); }
      await rm(receipt.storage, { recursive: true }); await fsyncDirectory(root, native); result.paths.push('session-storage'); jobs = await readMaintenanceJobs(root, guard, 'platform');
    }
  }
  for (const row of jobs) if (row.value.phase === 'cleaned') { if (await removeCleanedJob(root, guard, row, request.dryRun)) result.paths.push(path.relative(root, row.file)); else result.protected_paths.push(path.relative(root, row.file)); }
  const assetsCleaned = await cleanProviderAssets(root, guard, record, engine, host, request.action, request.dryRun, request.signal); result.paths.push(...assetsCleaned.paths); result.protected_paths.push(...assetsCleaned.protected);
  if (request.dryRun) result.resources.push(...jobs.filter(row => row.value.phase !== 'cleaned').map(row => `pending-job:${row.value.id}`));
}

/** Source-bound transports are private cache files, never daemon images. */
async function cleanCaches(options: RuntimeOptions, root: string, guard: string, host: Host, request: ProviderMaintenanceRequest, result: ProviderMaintenanceResult): Promise<void> {
  const lock = await readBoundedReceipt(path.join(options.sourceRoot, 'runtime/runtime.lock.json')); const wanted = new Map<string, { sha256: string; size: number }>();
  const addReceipt = (sha256: unknown, size: unknown) => { if (typeof sha256 !== 'string' || !SHA.test(sha256) || !Number.isSafeInteger(size) || (size as number) < 1 || (size as number) > 20 * 1024 ** 3) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID'); const name = `${sha256.slice(7)}.tar`; const previous = wanted.get(name); if (previous && previous.size !== size) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID'); wanted.set(name, { sha256, size: size as number }); };
  for (const pack of Object.values(object(lock.packs) ?? {})) for (const image of Object.values(object(object(pack)?.images) ?? {})) {
    const item = object(image); if (!item) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID');
    const transports = item.transports ?? []; if (!Array.isArray(transports)) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID');
    for (const raw of transports) { const value = object(raw); if (!value || typeof value.sha256 !== 'string' || !SHA.test(value.sha256) || !Number.isSafeInteger(value.size_bytes) || (value.size_bytes as number) < 1 || (value.size_bytes as number) > 20 * 1024 ** 3) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID'); const name = `${value.sha256.slice(7)}.tar`; const previous = wanted.get(name); if (previous && previous.size !== value.size_bytes) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID'); wanted.set(name, { sha256: value.sha256, size: value.size_bytes as number }); }
  }
  for (const raw of Object.values(object(lock.packs) ?? {})) { const index = object(object(raw)?.index_transport); if (index) addReceipt(index.sha256, index.size_bytes); }
  const provider = object(object(lock.provider_receipts)?.[`${result.engine}/${host.platform}/${host.arch}`]);
  if (provider) { const init = object(provider.init_image); if (init?.transport_sha256 !== undefined) addReceipt(init.transport_sha256, init.transport_size_bytes); const assets = object(provider.provisioning)?.assets; if (assets !== undefined) { if (!Array.isArray(assets)) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID'); for (const raw of assets) { const asset = object(raw); if (!asset) throw new Error('PROVIDER_CACHE_SOURCE_RECEIPT_INVALID'); addReceipt(asset.sha256, asset.size_bytes); } } }
  const identity = await guardedIdentity(guard, root); const native = await openStateAuthority(root, guard);
  const scratch = path.join(root, 'archive-staging');
  let scratchPresent = true; try { await lstat(scratch); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; scratchPresent = false; }
  if (scratchPresent) {
    const info = await lstat(scratch); if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('IMAGE_IMPORT_STAGING_ROOT_CHANGED'); await guardedPrivateDirectory(guard, root, 'archive-staging', identity); const scratchIdentity = await guardedIdentity(guard, scratch);
    let release: (() => Promise<void>) | undefined;
    try { release = await guardedStateLock(guard, scratch, '.archive-stage.native', scratchIdentity, request.dryRun); } catch (error) { if (!(request.dryRun && (error as NodeJS.ErrnoException).code === 'ENOENT')) throw error; }
    try {
      const staged = await recoverImageImportStaging(scratch, guard, wanted, request.dryRun); result.paths.push(...staged.paths.map(name => `archive-staging/${name}`)); result.protected_paths.push(...staged.protected.map(name => `archive-staging/${name}`));
      const known = new Set([...staged.paths, ...staged.protected, '.archive-stage.native', 'locks', 'transactions']); for (const name of await readdir(scratch)) if (!known.has(name)) result.protected_paths.push(`archive-staging/${name}`);
    } finally { await release?.(); }
  }
  for (const name of ['probe-core.json', 'probe-render.json']) {
    const file = path.join(root, name); let bytes: Buffer;
    try { bytes = await boundedRead(file, 65536, native); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
    const value = object(JSON.parse(bytes.toString('utf8')));
    if (!value || (value.schema_version !== 1 && ![1, 2].includes(value.version as number))) { result.protected_paths.push(name); continue; }
    result.paths.push(name); if (!request.dryRun) await rm(file);
  }
  const images = path.join(root, 'images'); let names: string[];
  try { names = await readdir(images); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
  if (names.length > 10000) throw new Error('PROVIDER_CACHE_INVENTORY_TOO_LARGE'); await guardedPrivateDirectory(guard, root, 'images', identity);
  // Offline seeding can populate a verified cache before the first import.
  // Only real maintenance initializes its private journal/lock directories.
  if (!request.dryRun) await JournalStore.open(images, guard);
  const imageIdentity = await guardedIdentity(guard, images); const importName = result.engine === 'podman' ? 'podman-image-import' : result.engine === 'docker' || result.engine === 'docker-rootless' ? 'docker-image-import' : 'worker-image-import';
  let release: (() => Promise<void>) | undefined;
  try { release = await guardedStateLock(guard, images, `locks/${sha256(importName)}.native`, imageIdentity, request.dryRun); }
  catch (error) { if (!(request.dryRun && (error as NodeJS.ErrnoException).code === 'ENOENT')) throw error; }
  try {
    try { await lstat(path.join(images, 'locks', sha256(importName))); throw new Error('PROVIDER_LEGACY_IMPORT_LOCK_REQUIRES_RECOVERY'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const staged = await recoverImageImportStaging(images, guard, wanted, request.dryRun); result.paths.push(...staged.paths.map(name => `images/${name}`)); result.protected_paths.push(...staged.protected.map(name => `images/${name}`));
    const repairArtifacts = request.action === 'owned-runtime' ? await cleanImageRepairArtifacts(root, images, guard, request.dryRun) : []; result.paths.push(...repairArtifacts.map(name => `images/${name}`));
    const reclaimed = await reclaimImageCache(images, guard, { dryRun: request.dryRun, all: true }); result.paths.push(...reclaimed.removed.map(name => `images/${name}`));
    for (const name of names.sort()) {
      if (['locks', 'transactions', '.image-cache.json'].includes(name)) continue;
      if (staged.paths.includes(name) || reclaimed.removed.includes(name) || repairArtifacts.includes(name)) continue;
      const receipt = wanted.get(name); if (!receipt) { result.protected_paths.push(`images/${name}`); continue; }
      check(request.signal); const file = path.join(images, name); const info = await lstat(file);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== receipt.size || process.platform !== 'win32' && (info.mode & 0o222) !== 0) throw new Error('PROVIDER_CACHE_IDENTITY_INVALID');
      await verifyArchive(file, receipt.sha256, request.signal); result.paths.push(`images/${name}`); if (!request.dryRun) await rm(file);
    }
    if (!request.dryRun) await fsyncDirectory(images, await openStateAuthority(images, guard));
  } finally { await release?.(); }
}

/** Only owned jobs/cache are removed; shared engines, images and VMs remain. */
export async function maintainProviderRuntime(options: RuntimeOptions, engine: OciEngine, executable: string, host: Host, request: ProviderMaintenanceRequest): Promise<ProviderMaintenanceResult> {
  if (!['cache', 'owned-runtime'].includes(request.action) || typeof request.dryRun !== 'boolean') throw new Error('PROVIDER_MAINTENANCE_REQUEST_INVALID'); check(request.signal);
  if (request.signal) options = { ...options, signal: request.signal };
  const selected = engine === 'docker' || engine === 'docker-rootless' ? dockerStateRoot(options, host) : engine === 'podman' ? podmanStateRoot(options, host) : platformStateRoot(options, engine, host);
  const result: ProviderMaintenanceResult = { engine, status: request.dryRun ? 'dry_run' : 'complete', action: request.action, dry_run: request.dryRun, paths: [], resources: [], recovered_jobs: [], protected_paths: [], limitations: ['Shared engines and cached OCI images are retained.'] };
  let root: string; try { root = await realpath(selected); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { ...result, status: 'absent' }; throw error; }
  const guard = await resolveProductGuard(options.sourceRoot, host);
  return withProviderMaintenance(guard.guard, root, async inventory => {
    result.protected_paths.push(...inventory.protected_leases);
    if (engine === 'docker' || engine === 'docker-rootless') {
      let jobs = await readMaintenanceJobs<DockerJobRecord>(root, guard.guard, 'docker');
      if (request.dryRun) result.resources.push(...jobs.filter(row => row.value.phase !== 'cleaned').map(row => `pending-job:${row.value.id}`));
      else if (jobs.some(row => row.value.phase !== 'cleaned')) { const authority = await resolveDockerCleanupAuthority(options.sourceRoot, executable, host); for (const row of jobs.filter(row => row.value.phase !== 'cleaned')) { check(request.signal); await recoverDockerValidation(root, row.value.id, guard.guard, authority); result.recovered_jobs.push(row.value.id); } jobs = await readMaintenanceJobs(root, guard.guard, 'docker'); }
      for (const row of jobs) if (row.value.phase === 'cleaned') { if (await removeCleanedJob(root, guard.guard, row, request.dryRun)) result.paths.push(path.relative(root, row.directory ?? row.file)); else result.protected_paths.push(path.relative(root, row.directory ?? row.file)); }
    } else if (engine === 'podman') {
      let jobs = await readMaintenanceJobs<PodmanJobRecord>(root, guard.guard, 'podman');
      if (request.dryRun) result.resources.push(...jobs.filter(row => row.value.phase !== 'cleaned').map(row => `pending-job:${row.value.id}`));
      else if (jobs.some(row => row.value.phase !== 'cleaned')) { const authority = await resolvePodmanCleanupAuthority(options.sourceRoot, executable, host); for (const row of jobs.filter(row => row.value.phase !== 'cleaned')) { check(request.signal); await recoverPodmanWorker(root, row.value.id, guard.guard, authority); result.recovered_jobs.push(row.value.id); } jobs = await readMaintenanceJobs(root, guard.guard, 'podman'); }
      for (const row of jobs) if (row.value.phase === 'cleaned') { if (await removeCleanedJob(root, guard.guard, row, request.dryRun)) result.paths.push(path.relative(root, row.directory ?? row.file)); else result.protected_paths.push(path.relative(root, row.directory ?? row.file)); }
      result.limitations.push('An existing Podman machine is shared provider infrastructure and is retained.');
    } else {
      await maintainPlatformState(options, engine, executable, host, root, guard.guard, guard.guardSha256, request, result);
    }
    await cleanCaches(options, root, guard.guard, host, request, result); return result;
  }, { dryRun: request.dryRun, ...(request.signal ? { signal: request.signal } : {}) });
}
