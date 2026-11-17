import { prepareOwnedLimaHome, resolveOwnedLimaHome } from '../../runtime-manager/src/lima-storage.js';
import { providerAssetDescriptor, providerAssetRoot, prepareProviderAssets, verifyProviderAssetTree } from '../../runtime-manager/src/provider-assets.js';
import { repairOwnedAssetPack } from '../../runtime-manager/src/asset-repair.js';
import { runtimeCatalog } from '../../runtime-manager/src/runtime-demand.js';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { RuntimeOptions, OciReadiness } from '../../runtime-manager/src/environment.js';
import type { Host } from '../../runtime-manager/src/profiles.js';
import { userspaceStateRoot } from '../../runtime-manager/src/userspace.js';
import { readBoundedReceipt, readBoundedReceiptBytes, readImageTransports, loadImageReceipt, verifyArchive } from '../../runtime-manager/src/receipt.js';
import type { ImageReceipt, WorkerPack } from '../../runtime-manager/src/receipt.js';
import { admitAppleRuntime, withAppleRuntime } from '../../runtime-manager/src/apple-runtime.js';
import { importAppleOfflineImage } from '../../runtime-manager/src/apple.js';
import { loadAppleEngineReceipt, verifyAppleEngine } from '../../runtime-manager/src/apple-engine.js';
import { admitLimaRuntime, bindLimaOfflineImage, limaCommand, limaNerdctlArguments } from '../../runtime-manager/src/lima-nerdctl.js';
import type { LimaRuntimeReceipt } from '../../runtime-manager/src/lima-nerdctl.js';
import { ensureOwnedLimaInstance } from '../../runtime-manager/src/lima-provision.js';
import type { LimaProvisioning } from '../../runtime-manager/src/lima-provision.js';
import { admitWslcRuntime, adoptWslcRuntime, isWslcRuntimeAlive, wslcCommand } from '../../runtime-manager/src/wslc-runtime.js';
import type { WslcRuntimeReceipt } from '../../runtime-manager/src/wslc-runtime.js';
import { stageVerifiedArchive } from '../../runtime-manager/src/archive.js';
import { limaProvisionRunner } from '../../runtime-manager/src/lima-system-helper.js';
import { acquireWorkerImageTransport } from '../../runtime-manager/src/worker-image-assets.js';
import { withWorkerImageImportLock } from '../../runtime-manager/src/worker-image-lock.js';
import { reclaimImageCache } from '../../runtime-manager/src/image-cache.js';
import { repairWorkerImageTransport } from './image-repair.js';
import { verifyOciClosure } from '../../runtime-manager/src/oci-closure.js';
import { streamCommand } from '../../runtime-manager/src/stream-command.js';
import { resolveProductGuard } from './docker-authority.js';
import { loadContracts } from './catalog.js';
import { recoverPlatformJobs, runPlatformWorker } from './platform-worker.js';
import type { PlatformRuntime } from './platform-worker.js';
import { boundedRead, durableWrite, JournalStore, openStateAuthority } from '../../workspace/src/journal.js';
import type { AdmittedProvider } from './provider-runtime.js';
import { runCommand } from '../../runtime-manager/src/command.js';
import { validateProviderReceipt } from '../../runtime-manager/src/provider-receipt.js';
import { commitLimaCli, selectLimaCli } from '../../runtime-manager/src/lima-cli-admission.js';
import type { LimaCliSelection } from '../../runtime-manager/src/lima-cli-admission.js';
import { withProviderLease, withProviderMaintenance } from './provider-leases.js';
import { RENDER_PROBE_REVISION, RENDER_PROBE_SENTENCE, verifyRenderProbe } from './render-probe.js';

export type PlatformEngine = 'apple-container' | 'lima-nerdctl' | 'wslc';
type Authority = { runtime: PlatformRuntime; image: ImageReceipt; guard: string; stateRoot: string; fingerprint: string; cli?: LimaCliSelection };
const cached = new Map<string, Authority>();
const SAMPLE = '# sent_id = duplicate\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n';
function checkCancelled(options: RuntimeOptions): void { if (options.signal?.aborted) throw new Error('PLATFORM_SETUP_CANCELLED'); }
function setupRunner(options: RuntimeOptions, runner = runCommand): typeof runCommand { return (executable, args, commandOptions) => { checkCancelled(options); return runner(executable, args, { ...commandOptions, ...(options.signal ? { signal: options.signal } : {}) }); }; }
function object(raw: unknown): Record<string, unknown> | undefined { return raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw as Record<string, unknown> : undefined; }
function sha(bytes: Buffer | string): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
export function platformStateRoot(options: RuntimeOptions, engine: PlatformEngine, host: Host): string { return `${options.userspaceStateRoot ?? userspaceStateRoot(host)}-${engine}`; }
function key(options: RuntimeOptions, engine: PlatformEngine, executable: string, pack: WorkerPack): string { return `${options.sourceRoot}\0${options.userspaceStateRoot ?? ''}\0${engine}\0${executable}\0${pack}`; }
function tools(options: RuntimeOptions) { return runtimeCatalog(loadContracts(options.sourceRoot).domain, options.operationDemand); }
function packFor(options: RuntimeOptions, requested: readonly string[]): WorkerPack | undefined { const rows = tools(options); if (requested.length === 0 || requested.some(name => !rows.some(item => item.name === name))) return undefined; const packs = [...new Set(rows.filter(item => requested.includes(item.name)).map(item => item.runtime_pack))]; return packs.length === 1 && (packs[0] === 'core' || packs[0] === 'render') ? packs[0] : undefined; }
function imageFrom(raw: unknown): ImageReceipt { const item = object(raw); if (!item || typeof item.digest !== 'string' || typeof item.reference !== 'string' || typeof item.context_sha256 !== 'string' || typeof item.config_digest !== 'string' || !Array.isArray(item.diff_ids) || item.diff_ids.some(value => typeof value !== 'string')) throw new Error('PROVIDER_INIT_RECEIPT_INVALID'); const transports = readImageTransports(item.transports); return { digest: item.digest, reference: item.reference, contextSha256: item.context_sha256, configDigest: item.config_digest, diffIds: item.diff_ids as string[], ...(transports ? { transports } : {}), ...(typeof item.transport_sha256 === 'string' && typeof item.transport_size_bytes === 'number' ? { transportSha256: item.transport_sha256, transportSizeBytes: item.transport_size_bytes } : {}) }; }

async function limaCli(options: RuntimeOptions, executable: string, host: Host, record: Record<string, unknown>, prepare: boolean): Promise<LimaCliSelection | null> {
  return selectLimaCli({ executable, officialSha256: record.executable_sha256 as string, sourceRoot: options.sourceRoot, stateRoot: platformStateRoot(options, 'lima-nerdctl', host), prepare, repair: options.setupMode === 'repair', ...(options.signal ? { signal: options.signal } : {}) }, setupRunner(options));
}
async function admittedLimaCli(options: RuntimeOptions, executable: string, host: Host): Promise<LimaCliSelection | null> {
  const lock = await readBoundedReceipt(path.join(options.sourceRoot, 'runtime/runtime.lock.json')); if (lock.state !== 'frozen') return null;
  const records = object(lock.provider_receipts); if (lock.provider_receipts !== undefined && !records) throw new Error('PROVIDER_RECEIPT_INVALID');
  const record = records?.[`lima-nerdctl/${host.platform}/${host.arch}`]; if (record === undefined) return null;
  validateProviderReceipt('lima-nerdctl', host, record);
  if (options.setupMode === 'repair') {
    const descriptor = providerAssetDescriptor(record, 'lima-nerdctl', host);
    if (descriptor) {
      const guard = await resolveProductGuard(options.sourceRoot, host);
      try { const assets = await providerAssetRoot(options.sourceRoot, platformStateRoot(options, 'lima-nerdctl', host), guard.guard, record, 'lima-nerdctl', host); await verifyProviderAssetTree(assets, descriptor, options.signal); }
      catch (error) { if ((error as Error).message !== 'PROVIDER_ASSETS_MISSING') throw error; }
    }
  }
  return limaCli(options, executable, host, record, false);
}

async function resolve(options: RuntimeOptions, engine: PlatformEngine, executable: string, host: Host, pack: WorkerPack, setup: boolean, cleanupOnly = false): Promise<Authority | null> {
  checkCancelled(options); const runner = setupRunner(options);
  const rootBytes = await readBoundedReceiptBytes(path.join(options.sourceRoot, 'runtime/runtime.lock.json')); const lock = object(JSON.parse(rootBytes.toString('utf8')));
  if (lock?.state !== 'frozen') return null;
  const records = object(lock.provider_receipts); if (lock.provider_receipts !== undefined && !records) throw new Error('PROVIDER_RECEIPT_INVALID');
  const record = records?.[`${engine}/${host.platform}/${host.arch}`]; if (record === undefined) return null;
  validateProviderReceipt(engine, host, record);
  if (record.schema_version !== 1 || typeof record.executable_sha256 !== 'string') throw new Error('PROVIDER_RECEIPT_INVALID');
  const cli = engine === 'lima-nerdctl' ? await limaCli(cleanupOnly ? { ...options, setupMode: 'repair' } : options, executable, host, record, setup || cleanupOnly) : undefined;
  if (cli === null) return null;
  if (engine !== 'lima-nerdctl') await verifyArchive(executable, record.executable_sha256);
  const nativeGuard = await resolveProductGuard(options.sourceRoot, host); let stateRoot = platformStateRoot(options, engine, host);
  if (setup) { await mkdir(stateRoot, { recursive: true, mode: 0o700 }); await JournalStore.open(stateRoot, nativeGuard.guard); }
  const stateInfo = await lstat(stateRoot); if (!stateInfo.isDirectory() || stateInfo.isSymbolicLink() || process.platform !== 'win32' && (stateInfo.mode & 0o077) !== 0) throw new Error('PROVIDER_STATE_UNSAFE');
  stateRoot = await realpath(stateRoot);
  const native = await openStateAuthority(stateRoot, nativeGuard.guard); const image = await loadImageReceipt(options.sourceRoot, pack, host.arch === 'x64' ? 'amd64' : 'arm64');
  const assets = setup ? await prepareProviderAssets(options.sourceRoot, stateRoot, nativeGuard.guard, record, engine, host, options.setupNetwork ?? 'offline', options.signal) : await providerAssetRoot(options.sourceRoot, stateRoot, nativeGuard.guard, record, engine, host);
  // Metadata-only installations acquire a bounded publisher transport before
  // provisioning a VM or importing anything. Cache/integrity failures remain
  // distinct from genuine archive unavailability.
  const workerTransport = image.transports?.find(value => value.format === 'oci-archive');
  const workerArchive = setup && workerTransport ? await acquireWorkerImageTransport({ sourceRoot: options.sourceRoot, stateRoot, guard: nativeGuard.guard, transport: workerTransport, network: options.setupNetwork ?? 'offline', ...(options.signal ? { signal: options.signal } : {}) }) : undefined;
  if (workerArchive === null) return null;
  // Keep the legacy official-binary fingerprint stable. External admission
  // additionally binds the verified installed CLI hash and stable version.
  const fingerprint = sha(JSON.stringify({ version: 1, root: sha(rootBytes), provider: record, image, guard: nativeGuard.guardSha256, ...(pack === 'render' ? { render_probe_revision: RENDER_PROBE_REVISION } : {}), ...(cli?.source === 'external' ? { cli: { sha256: cli.binarySha256, version: cli.version } } : {}) }));
  const previous = cached.get(key(options, engine, executable, pack));
  if (!setup && previous?.fingerprint === fingerprint) {
    if (previous.runtime.engine === 'apple-container') await withAppleRuntime(previous.runtime, async () => undefined, setupRunner(options, options.appleRunner));
    else if (previous.runtime.engine === 'lima-nerdctl') {
      const checked = await limaCommand(previous.runtime, ['info', '--mode=native', '--format', '{{json .}}'], undefined, runner);
      const info = checked.code === 0 ? object(JSON.parse(checked.stdout.toString('utf8'))) : undefined;
      if (info?.Rootless !== true || info.Namespace !== 'ud-agent' || info.Snapshotter !== 'overlayfs' || info.CgroupManager !== 'systemd') throw new Error('LIMA_ROOTLESS_CONTAINERD_REQUIRED');
    } else { const checked = await wslcCommand(previous.runtime, ['system', 'info', '--format', 'json'], undefined, runner); if (checked.code !== 0) throw new Error('WSLC_OWNED_SESSION_NOT_RUNNING'); }
    return previous;
  }
  let runtime: PlatformRuntime;
  if (engine === 'apple-container') {
    if (host.platform !== 'darwin' || host.arch !== 'arm64') throw new Error('APPLE_HOST_UNSUPPORTED');
    const invokeApple = setupRunner(options, options.appleRunner);
    const appleRunner: typeof runCommand = (executable, args, commandOptions) => invokeApple(executable, args, { ...commandOptions, supervisor: { guard: nativeGuard.guard, guardSha256: nativeGuard.guardSha256, executableSha256: record.executable_sha256 as string } });
    // Signature verification invokes the OS's fixed codesign executable.
    const provider = await verifyAppleEngine(executable, await loadAppleEngineReceipt(options.sourceRoot), invokeApple);
    if (provider.binarySha256 !== record.executable_sha256) throw new Error('APPLE_PROVIDER_RECEIPTS_DISAGREE');
    const initImage = imageFrom(record.init_image); const kernel = object(record.kernel);
    if (!kernel || typeof kernel.path !== 'string' || typeof kernel.sha256 !== 'string') throw new Error('APPLE_KERNEL_RECEIPT_INVALID');
    const kernelPath = path.isAbsolute(kernel.path) ? kernel.path : path.join(assets, ...kernel.path.split('/'));
    if (setup) {
      for (const [selected, name] of [[image, pack], [initImage, 'init']] as const) {
        const transport = selected.transports?.find(value => value.format === 'oci-archive');
        const archive = name === pack && workerArchive ? workerArchive : transport ? path.join(name === 'init' ? assets : options.sourceRoot, transport.path) : path.join(name === 'init' ? assets : options.sourceRoot, 'runtime/images', `${name}-linux-arm64.tar`);
        checkCancelled(options); await importAppleOfflineImage(provider, transport ? { ...selected, transportSha256: transport.sha256, transportSizeBytes: transport.sizeBytes, ...(transport.indexDigest ? { transportIndexDigest: transport.indexDigest } : {}) } : selected, archive, appleRunner, name === 'init' ? 'init' : 'worker', { stateRoot: path.join(stateRoot, 'archive-staging'), guard: nativeGuard.guard, ...(options.signal ? { signal: options.signal } : {}) });
      }
    }
    runtime = await admitAppleRuntime({ schema_version: 1, engine: provider, initImage, kernel: { path: kernelPath, sha256: kernel.sha256 }, guard: nativeGuard.guard, guardSha256: nativeGuard.guardSha256, stateRoot }, image, appleRunner, !setup);
  } else if (engine === 'lima-nerdctl') {
    for (const field of ['instance', 'nerdctl', 'nerdctl_sha256', 'containerd', 'containerd_sha256', 'address', 'guest_home', 'architecture']) if (typeof record[field] !== 'string') throw new Error('LIMA_RUNTIME_RECEIPT_INVALID');
    const provisioning = object(record.provisioning);
    const ownedHome = provisioning ? setup ? await prepareOwnedLimaHome(stateRoot, nativeGuard.guard) : await resolveOwnedLimaHome(stateRoot, nativeGuard.guard) : undefined;
    if (provisioning && !ownedHome) return null;
    const receipt: LimaRuntimeReceipt & { cliVersion?: string } = { schema_version: 1, executable, binarySha256: cli!.binarySha256, ...(cli!.version ? { cliVersion: cli!.version } : {}), instance: record.instance as string, nerdctl: record.nerdctl as string, nerdctlSha256: record.nerdctl_sha256 as string, containerd: record.containerd as string, containerdSha256: record.containerd_sha256 as string, ...(typeof record.ctr === 'string' && typeof record.ctr_sha256 === 'string' ? { ctr: record.ctr, ctrSha256: record.ctr_sha256 } : {}), ...(typeof record.nsenter === 'string' && typeof record.nsenter_sha256 === 'string' ? { nsenter: record.nsenter, nsenterSha256: record.nsenter_sha256 } : {}), address: record.address as string, guestUid: record.guest_uid as number, guestHome: record.guest_home as string, architecture: record.architecture as 'amd64' | 'arm64', ...(provisioning ? { home: ownedHome! } : typeof record.home === 'string' ? { home: record.home } : {}) };
    if (setup && provisioning) {
      const productPath = (raw: unknown): string => { if (typeof raw !== 'string' || raw.startsWith('/') || raw.includes('\\') || raw.includes(':') || raw.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('LIMA_PROVISION_RECEIPT_INVALID'); return path.join(assets, ...raw.split('/')); };
      if (typeof provisioning.template_sha256 !== 'string' || typeof provisioning.offline_ready !== 'boolean' || !Array.isArray(provisioning.assets)) throw new Error('LIMA_PROVISION_RECEIPT_INVALID');
      const provision: LimaProvisioning = { ...(provisioning.generated_config ? { generatedConfig: { networksSha256: object(provisioning.generated_config)!.networks_sha256 as string } } : {}), template: productPath(provisioning.template_path), templateSha256: provisioning.template_sha256, offlineReady: provisioning.offline_ready, assets: provisioning.assets.map(raw => { const asset = object(raw); if (!asset || typeof asset.key !== 'string' || typeof asset.sha256 !== 'string' || typeof asset.size_bytes !== 'number') throw new Error('LIMA_PROVISION_RECEIPT_INVALID'); return { key: asset.key, path: productPath(asset.path), sha256: asset.sha256, sizeBytes: asset.size_bytes }; }) };
      const supervisedRunner = limaProvisionRunner(receipt, nativeGuard.guard, nativeGuard.guardSha256, runner);
      await ensureOwnedLimaInstance(receipt, provision, nativeGuard.guard, stateRoot, options.setupNetwork ?? 'offline', supervisedRunner, options.signal);
    }
    runtime = await admitLimaRuntime(receipt, runner, { guard: nativeGuard.guard, guardSha256: nativeGuard.guardSha256 });
    if (setup) await importOffline(runtime, options.sourceRoot, image, nativeGuard.guard, stateRoot, options.signal, workerArchive, nativeGuard.guardSha256);
  } else {
    if (host.platform !== 'win32' || typeof record.sdk !== 'string' || typeof record.sdk_sha256 !== 'string') throw new Error('WSLC_RUNTIME_RECEIPT_INVALID');
    const storage = path.join(stateRoot, 'session-storage'); if (setup) { await mkdir(storage, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; }); await openStateAuthority(storage, nativeGuard.guard, true); }
    const receipt: WslcRuntimeReceipt = { schema_version: 1, executable, binarySha256: record.executable_sha256, sdk: path.isAbsolute(record.sdk) ? record.sdk : path.join(assets, ...record.sdk.split('/')), sdkSha256: record.sdk_sha256, guard: nativeGuard.guard, guardSha256: nativeGuard.guardSha256, storage, architecture: host.arch === 'x64' ? 'amd64' : 'arm64' };
    const sameRuntime = [...cached.values()].find(value => value.runtime.engine === 'wslc' && isWslcRuntimeAlive(value.runtime) && value.stateRoot === stateRoot)?.runtime;
    if (sameRuntime?.engine === 'wslc') runtime = sameRuntime;
    else if (setup) runtime = await admitWslcRuntime(receipt, runner, undefined, options.signal);
    else {
      const saved = object(JSON.parse((await boundedRead(path.join(stateRoot, `probe-${pack}.json`), 16384, native)).toString('utf8')));
      if (saved?.fingerprint !== fingerprint || typeof saved.session !== 'string') return null;
      const identity = object(saved.session_identity);
      if (saved.session_identity !== undefined && (!identity || typeof identity.id !== 'string' || !/^[1-9][0-9]{0,19}$/.test(identity.id) || !Number.isSafeInteger(identity.creatorPid))) throw new Error('WSLC_SAVED_SESSION_INVALID');
      runtime = await adoptWslcRuntime(receipt, saved.session, runner, identity ? { id: identity.id as string, creatorPid: identity.creatorPid as number } : undefined);
    }
    if (setup) await importOffline(runtime, options.sourceRoot, image, nativeGuard.guard, stateRoot, options.signal, workerArchive, nativeGuard.guardSha256);
  }
  const authority = { runtime, image, guard: nativeGuard.guard, stateRoot, fingerprint, ...(cli ? { cli } : {}) }; cached.set(key(options, engine, executable, pack), authority); return authority;
}

async function importOffline(runtime: Exclude<PlatformRuntime, { engine: 'apple-container' }>, sourceRoot: string, image: ImageReceipt, guard: string, stateRoot: string, signal?: AbortSignal, acquiredArchive?: string, guardSha256?: string): Promise<void> {
  if (signal?.aborted) throw new Error('PLATFORM_SETUP_CANCELLED');
  const transport = image.transports?.find(item => item.format === 'oci-archive'); if (!transport) throw new Error('PROVIDER_OFFLINE_OCI_TRANSPORT_REQUIRED');
  const staged = await stageVerifiedArchive(acquiredArchive ?? path.join(sourceRoot, ...transport.path.split('/')), transport.sha256, transport.sizeBytes, { stateRoot: path.join(stateRoot, 'archive-staging'), guard, ...(signal ? { signal } : {}) });
  try {
    await verifyOciClosure(staged.filename, { manifestDigest: image.digest, architecture: runtime.receipt.architecture, ...(transport.indexDigest ? { indexDigest: transport.indexDigest } : {}), ...(image.configDigest ? { configDigest: image.configDigest } : {}), ...(image.diffIds ? { diffIds: image.diffIds } : {}) });
    if (runtime.engine === 'lima-nerdctl') {
      await streamCommand(runtime.receipt.executable, limaNerdctlArguments(runtime.receipt, ['load', '--input', '/dev/stdin']), createReadStream(staged.filename) as AsyncIterable<Buffer>, signal, { ...(runtime.receipt.home ? { limaHome: runtime.receipt.home } : {}), ...(guardSha256 ? { supervisor: { guard, guardSha256, executableSha256: runtime.receipt.binarySha256 } } : {}) });
      await bindLimaOfflineImage(runtime, image, (executable, args, options) => runCommand(executable, args, { ...options, ...(signal ? { signal } : {}) }));
    } else {
      const result = await wslcCommand(runtime, ['image', 'load', '--input', staged.filename], { timeoutMs: 600_000, maxOutputBytes: 4 * 1024 * 1024, ...(signal ? { signal } : {}) }); if (result.code !== 0) throw new Error('WSLC_OFFLINE_IMPORT_FAILED');
    }
  } finally { await staged.cleanup(); }
}

export function platformIsolation(runtime: PlatformRuntime): Pick<OciReadiness, 'rootless' | 'guest_rootless' | 'isolation_model' | 'virtual_machine'> {
  if (runtime.engine === 'lima-nerdctl') return { rootless: null, guest_rootless: true, isolation_model: 'rootless_oci_in_vm', virtual_machine: { name: runtime.receipt.instance, fingerprint: runtime.identity, boot_id: runtime.bootId } };
  return { rootless: null, isolation_model: runtime.isolation_model };
}
function readiness(options: RuntimeOptions, engine: PlatformEngine, executable: string, pack: WorkerPack, authority: Authority): OciReadiness { return { engine, executable, ...platformIsolation(authority.runtime), image_digest: authority.image.digest, context_sha256: authority.image.contextSha256, verification: 'verified', available_operations: tools(options).filter(item => item.runtime_pack === pack).map(item => item.name) }; }

async function platformPackReadiness(options: RuntimeOptions, engine: PlatformEngine, executable: string, host: Host, requested: readonly string[]): Promise<OciReadiness | null> {
  const pack = packFor(options, requested); if (!pack) return null;
  // An existing admission remains an integrity boundary even if its probe was
  // lost. A newly discovered external binary has no readiness claim yet.
  if (engine === 'lima-nerdctl' && !await admittedLimaCli(options, executable, host)) return null;
  try { const root = platformStateRoot(options, engine, host); const guard = await resolveProductGuard(options.sourceRoot, host); const native = await openStateAuthority(root, guard.guard); const record = object(JSON.parse((await boundedRead(path.join(root, `probe-${pack}.json`), 16384, native)).toString('utf8'))); const authority = await resolve(options, engine, executable, host, pack, false); if (!authority) return null; return record?.fingerprint === authority.fingerprint ? readiness(options, engine, executable, pack, authority) : null; }
  catch (error) {
    const missing = error as NodeJS.ErrnoException; const state = platformStateRoot(options, engine, host);
    if (missing.code === 'ENOENT' && typeof missing.path === 'string' && (missing.path === executable || missing.path === state || missing.path.startsWith(`${state}${path.sep}`)) || error instanceof Error && /(?:NOT_RUNNING|RUNNING_INSTANCE_REQUIRED|LOCAL_IMAGE_CLOSURE_MISSING|LIMA_GUEST_BOOT_CHANGED|WSLC_AUTHORITY_REQUIRED|PROVIDER_ASSETS_MISSING)$/.test(error.message)) return null;
    throw error;
  }
}

async function setupPlatformPack(options: RuntimeOptions, engine: PlatformEngine, executable: string, host: Host, requested: readonly string[]): Promise<OciReadiness | null> {
  checkCancelled(options);
  const pack = packFor(options, requested); if (!pack) return null;
  if (options.setupMode === 'repair') {
    const lock = await readBoundedReceipt(path.join(options.sourceRoot, 'runtime/runtime.lock.json')); const record = object(lock.provider_receipts)?.[`${engine}/${host.platform}/${host.arch}`];
    if (record !== undefined) {
      validateProviderReceipt(engine, host, record); const descriptor = providerAssetDescriptor(record, engine, host);
      if (descriptor) {
        if (engine === 'lima-nerdctl') { if (!await limaCli(options, executable, host, record, true)) return null; } else await verifyArchive(executable, record.executable_sha256 as string); const guard = await resolveProductGuard(options.sourceRoot, host); const state = platformStateRoot(options, engine, host); await mkdir(state, { recursive: true, mode: 0o700 }); await JournalStore.open(state, guard.guard);
        await withProviderMaintenance(guard.guard, state, () => repairOwnedAssetPack(state, guard.guard, 'provider', descriptor, async () => { const assets = await providerAssetRoot(options.sourceRoot, state, guard.guard, record, engine, host); await verifyProviderAssetTree(assets, descriptor, options.signal); }, async () => { await prepareProviderAssets(options.sourceRoot, state, guard.guard, record, engine, host, options.setupNetwork ?? 'offline', options.signal); }, options.signal), options.signal ? { signal: options.signal } : {});
      }
    }
  }
  const existing = await platformPackReadiness(options, engine, executable, host, requested);
  // Admission/import and owned VM creation share the same process-death-safe
  // lock as probes; an unprobed concurrent setup cannot leak a second session.
  const lock = await readBoundedReceipt(path.join(options.sourceRoot, 'runtime/runtime.lock.json')); if (lock.state !== 'frozen') return null;
  const records = object(lock.provider_receipts); if (lock.provider_receipts !== undefined && !records) throw new Error('PROVIDER_RECEIPT_INVALID');
  const record = records?.[`${engine}/${host.platform}/${host.arch}`]; if (record === undefined) return null; validateProviderReceipt(engine, host, record);
  if (engine === 'lima-nerdctl') { if (!await limaCli(options, executable, host, record, true)) return null; } else await verifyArchive(executable, record.executable_sha256 as string); await loadImageReceipt(options.sourceRoot, pack, host.arch === 'x64' ? 'amd64' : 'arm64');
  const guard = await resolveProductGuard(options.sourceRoot, host); const state = platformStateRoot(options, engine, host); checkCancelled(options); await mkdir(state, { recursive: true, mode: 0o700 });
  const journal = await JournalStore.open(state, guard.guard);
  // Quiescent maintenance precedes registration of this setup's job lease.
  // A busy ordinary setup skips pruning; explicit repair cannot race readers.
  try { await withProviderMaintenance(guard.guard, state, async () => {
    const image = await loadImageReceipt(options.sourceRoot, pack, host.arch === 'x64' ? 'amd64' : 'arm64');
    if (options.setupMode === 'repair') {
      const assets = await providerAssetRoot(options.sourceRoot, state, guard.guard, record, engine, host); const descriptor = providerAssetDescriptor(record, engine, host);
      if (descriptor) await verifyProviderAssetTree(assets, descriptor, options.signal);
      else {
        const verify = async (raw: unknown, sha: unknown) => { if (typeof raw !== 'string' || typeof sha !== 'string') throw new Error('PROVIDER_REPAIR_SOURCE_INVALID'); const file = path.isAbsolute(raw) ? raw : path.join(assets, ...raw.split('/')); await verifyArchive(file, sha, options.signal); };
        if (engine === 'apple-container') { const kernel = object(record.kernel); await verify(kernel?.path, kernel?.sha256); const init = object(record.init_image); if (init?.transport_sha256) await verify('runtime/images/init-linux-arm64.tar', init.transport_sha256); }
        else if (engine === 'wslc') await verify(record.sdk, record.sdk_sha256);
        else { const provisioning = object(record.provisioning); if (provisioning) { await verify(provisioning.template_path, provisioning.template_sha256); for (const raw of provisioning.assets as unknown[]) { const asset = object(raw); await verify(asset?.path, asset?.sha256); } } }
      }
      const transport = image.transports?.find(item => item.format === 'oci-archive');
      if (transport) await repairWorkerImageTransport({ sourceRoot: options.sourceRoot, stateRoot: state, guard: guard.guard, transport, network: options.setupNetwork ?? 'offline', acquire: () => acquireWorkerImageTransport({ sourceRoot: options.sourceRoot, stateRoot: state, guard: guard.guard, transport, network: options.setupNetwork ?? 'offline', ...(options.signal ? { signal: options.signal } : {}) }), ...(options.signal ? { signal: options.signal } : {}) });
    }
    const images = path.join(state, 'images'); let present = true; try { await lstat(images); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; present = false; }
    if (present) { const keep = new Set<string>(); for (const value of Object.values(object(lock.packs) ?? {})) { const selected = object(object(object(value)?.images)?.[`linux/${host.arch === 'x64' ? 'amd64' : 'arm64'}`]); if (selected?.transports !== undefined) for (const transport of readImageTransports(selected.transports) ?? []) keep.add(transport.sha256); } await withWorkerImageImportLock(images, guard.guard, () => reclaimImageCache(images, guard.guard, { dryRun: false, keep })); }
  }, options.signal ? { signal: options.signal } : {}); }
  catch (error) { if (!(options.setupMode !== 'repair' && error instanceof Error && error.message === 'PROVIDER_RUNTIME_IN_USE')) throw error; }
  if (existing) return existing;
  return withProviderLease(guard.guard, state, () => journal.withWorkspaceLock(`${engine}-setup`, async () => {
    checkCancelled(options);
    const warm = await platformPackReadiness(options, engine, executable, host, requested); if (warm) return warm;
    const authority = await resolve(options, engine, executable, host, pack, true); if (!authority) return null;
    await recoverPlatformJobs(authority.runtime, authority.image, authority.guard, authority.stateRoot); checkCancelled(options);
    const probe = await mkdtemp(path.join(authority.stateRoot, 'probe-'));
    try {
      for (const name of ['a.conllu', 'b.conllu']) await writeFile(path.join(probe, name), SAMPLE, { mode: 0o600 });
      checkCancelled(options);
      const result = await runPlatformWorker(authority.runtime, authority.image, authority.guard, authority.stateRoot, { operation: 'validation_report', arguments: { working_tree_path: probe, file_paths: ['a.conllu', 'b.conllu'], options: { language_code: 'en', level: 2 } }, workingTree: probe, allowedRoots: [probe], filePaths: ['a.conllu', 'b.conllu'], options: { language_code: 'en', level: 2 }, ...(options.signal ? { signal: options.signal } : {}) });
      if (result.result.passed !== false || !Array.isArray(result.result.incidents) || !result.result.incidents.some(raw => object(raw)?.testid === 'non-unique-sent-id')) throw new Error('PLATFORM_VALIDATION_PROBE_FAILED');
      for (const name of ['a.conllu', 'b.conllu']) if (await readFile(path.join(probe, name), 'utf8') !== SAMPLE) throw new Error('PLATFORM_PROBE_INPUT_CHANGED');
      if (pack === 'render') for (const format of ['png', 'pdf'] as const) {
        checkCancelled(options);
        const rendered = await runPlatformWorker(authority.runtime, authority.image, authority.guard, authority.stateRoot, { operation: 'sentence_render', arguments: { working_tree_path: probe, sentence_conllu: RENDER_PROBE_SENTENCE, output_format: format, output_path: `/out/probe.${format}`, ud_context_path: '' }, workingTree: probe, allowedRoots: [probe], filePaths: [], options: {}, ...(options.signal ? { signal: options.signal } : {}) });
        verifyRenderProbe(rendered.result, format);
      }
      checkCancelled(options); if (authority.cli) await commitLimaCli(authority.cli, authority.stateRoot, options.signal);
      await durableWrite(path.join(authority.stateRoot, `probe-${pack}.json`), Buffer.from(`${JSON.stringify({ schema_version: 1, fingerprint: authority.fingerprint, ...(authority.runtime.engine === 'wslc' ? { session: authority.runtime.session, session_identity: authority.runtime.sessionIdentity } : {}) })}\n`), await openStateAuthority(authority.stateRoot, authority.guard));
      return readiness(options, engine, executable, pack, authority);
    } finally { await rm(probe, { recursive: true, force: true }); }
  }), options.signal ? { signal: options.signal } : {});
}

function requestGroups(options: RuntimeOptions, requested: readonly string[]): string[][] {
  const rows = tools(options); if (requested.length === 0 || requested.some(name => !rows.some(item => item.name === name))) return [];
  return (['core', 'render'] as const).map(pack => rows.filter(item => item.runtime_pack === pack && requested.includes(item.name)).map(item => item.name)).filter(group => group.length > 0);
}
export async function platformReadiness(options: RuntimeOptions, engine: PlatformEngine, executable: string, host: Host, requested: readonly string[]): Promise<OciReadiness | null> {
  const groups = requestGroups(options, requested); if (!groups.length) return null; const records: OciReadiness[] = [];
  for (const group of groups) { const record = await platformPackReadiness(options, engine, executable, host, group); if (!record) return null; records.push(record); }
  return { ...records[0]!, available_operations: [...new Set(records.flatMap(record => [...record.available_operations]))] };
}
export async function setupPlatform(options: RuntimeOptions, engine: PlatformEngine, executable: string, host: Host, requested: readonly string[]): Promise<OciReadiness | null> {
  const groups = requestGroups(options, requested); if (!groups.length) return null; const records: OciReadiness[] = [];
  for (const group of groups) { const record = await setupPlatformPack(options, engine, executable, host, group); if (!record) return null; records.push(record); }
  return { ...records[0]!, available_operations: [...new Set(records.flatMap(record => [...record.available_operations]))] };
}

export async function resolveAdmittedPlatform(options: RuntimeOptions, engine: PlatformEngine, executable: string, host: Host, requested: readonly string[]): Promise<AdmittedProvider | null> {
  if (!await platformReadiness(options, engine, executable, host, requested)) return null; const pack = packFor(options, requested)!; const authority = await resolve(options, engine, executable, host, pack, false); if (!authority) return null;
  return { guard: authority.guard, image: authority.image, stateRoot: authority.stateRoot, platform: { host_os: host.platform, host_architecture: host.arch, worker_architecture: host.arch === 'x64' ? 'amd64' : 'arm64', provider: engine, emulated: false, ...platformIsolation(authority.runtime), ...(authority.runtime.engine === 'apple-container' ? { atomic_no_pull: false, cache_mutation_boundary: authority.runtime.cache_mutation_boundary } : {}) }, run: input => runPlatformWorker(authority.runtime, authority.image, authority.guard, authority.stateRoot, input) };
}

/** Cleanup authority is observational and does not create or import anything. */
export function resolvePlatformMaintenance(options: RuntimeOptions, engine: PlatformEngine, executable: string, host: Host, pack: WorkerPack): Promise<Authority | null> { return resolve(options, engine, executable, host, pack, false, true); }
