import { runtimeCatalog } from '../../runtime-manager/src/runtime-demand.js';
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { OciReadiness, RuntimeOptions } from '../../runtime-manager/src/environment.js';
import type { Host } from '../../runtime-manager/src/profiles.js';
import { inspectPodmanStorageIdentity } from './podman-worker.js';
import { userspaceStateRoot } from '../../runtime-manager/src/userspace.js';
import { loadImageReceipt, readBoundedReceipt } from '../../runtime-manager/src/receipt.js';
import { boundedRead, durableWrite, JournalStore, openStateAuthority } from '../../workspace/src/journal.js';
import { resolvePodmanAuthority, resolvePodmanCleanupAuthority, verifyPodmanAuthority } from './podman-authority.js';
import { resolveProductGuard } from './docker-authority.js';
import type { PodmanAuthority } from './podman-authority.js';
import { recoverPendingPodmanJobs, runPodmanWorker } from './podman-worker.js';
import { loadContracts } from './catalog.js';
import type { WorkerPack } from '../../runtime-manager/src/receipt.js';
import { ensurePodmanImage } from './podman-import.js';
import { withEngineSupervisor } from './engine-command.js';
import { podmanVmContext, resolvePodmanVm, withPodmanVm } from './podman-vm.js';
import { RENDER_PROBE_REVISION, RENDER_PROBE_SENTENCE, verifyRenderProbe } from './render-probe.js';
import { withProviderLease } from './provider-leases.js';

type Engine = 'podman';
const PROBE_REVISION = 2;
const SAMPLE = '# sent_id = duplicate\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n';

function stateRoot(options: RuntimeOptions, host: Host): string { return `${options.userspaceStateRoot ?? userspaceStateRoot(host)}-podman`; }
function marker(authority: PodmanAuthority, pack: WorkerPack): string {
  return JSON.stringify({ version: PROBE_REVISION, ...(pack === 'render' ? { render_probe_revision: RENDER_PROBE_REVISION } : {}), engine: authority.engine, engine_sha256: authority.engineSha256,
    guard: authority.guard, guard_sha256: authority.guardSha256, product_lock_sha256: authority.productLockSha256,
    manifest_sha256: authority.manifestSha256, image: authority.image, identity: authority.identity });
}
async function privateState(root: string, guard: string): Promise<void> {
  const info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && (info.mode & 0o077) !== 0) || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('PODMAN_STATE_UNVERIFIED');
  if (process.platform === 'win32') await openStateAuthority(root, guard);
}
function inventory(options: RuntimeOptions): { name: string; runtime_pack: string }[] {
  try { return runtimeCatalog(loadContracts(options.sourceRoot).domain, options.operationDemand); }
  catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [{ name: 'validation_report', runtime_pack: 'core' }];
    throw error;
  }
}
function packsFor(options: RuntimeOptions, requested: readonly string[]): WorkerPack[] {
  const tools = inventory(options);
  if (requested.length === 0 || requested.some(name => !tools.some(item => item.name === name))) return [];
  return [...new Set(tools.filter(item => requested.includes(item.name)).map(item => item.runtime_pack))].filter((pack): pack is WorkerPack => pack === 'core' || pack === 'render');
}
function probePath(root: string, pack: WorkerPack): string { return path.join(root, pack === 'core' ? 'probe.json' : 'probe-render.json'); }
async function record(options: RuntimeOptions, engine: Engine, executable: string, host: Host, authority: PodmanAuthority, pack: WorkerPack): Promise<OciReadiness | null> {
  const inspection = authority.vm ? await withPodmanVm(authority.vm, () => inspectPodmanStorageIdentity(executable, host)) : await inspectPodmanStorageIdentity(executable, host);
  if (inspection.graphRoot !== authority.identity.graphRoot || inspection.graphIdentity !== authority.identity.graphIdentity) return null;
  return { engine, executable, rootless: authority.vm ? null : true, ...(authority.vm ? { isolation_model: 'rootless_oci_in_vm', guest_rootless: true, virtual_machine: { name: authority.vm.machine, fingerprint: authority.vm.fingerprint, boot_id: authority.vm.bootId } } : {}), image_digest: authority.image.digest, context_sha256: authority.image.contextSha256, verification: 'verified', available_operations: inventory(options).filter(item => item.runtime_pack === pack).map(item => item.name) };
}
async function resolve(options: RuntimeOptions, executable: string, host: Host, pack: WorkerPack, prepareVm = false): Promise<PodmanAuthority | null> {
  try { return await resolvePodmanAuthority(options.sourceRoot, executable, host, pack, prepareVm); }
  catch (error: unknown) {
    const value = error as { code?: unknown; message?: unknown };
    if (value.code === 'ENOENT') {
      // Missing assets beneath a frozen receipt are integrity failures. Only a
      // missing top-level receipt denotes a genuinely unprepared installation.
      let root: Record<string, unknown>;
      try { root = await readBoundedReceipt(path.join(options.sourceRoot, 'runtime', 'runtime.lock.json')); }
      catch (rootError: unknown) { if ((rootError as NodeJS.ErrnoException).code === 'ENOENT') return null; throw rootError; }
      if (root.state === 'frozen') throw error;
      return null;
    }
    if (value.message === 'RUNTIME_RECEIPT_NOT_FROZEN' || value.message === 'USERSPACE_RECEIPT_NOT_FROZEN' || value.message === 'PODMAN_IMAGE_NOT_PRESENT' || value.message === 'PODMAN_ENGINE_UNAVAILABLE' || value.message === 'PODMAN_VM_GUEST_HELPER_REQUIRED' || value.message === 'PODMAN_VM_RUNNING_ROOTLESS_MACHINE_REQUIRED') return null;
    throw error;
  }
}

/** Read-only readiness bound to the successful product-owned probe receipt. */
export async function podmanReadiness(options: RuntimeOptions, engine: Engine, executable: string, host: Host, requested: readonly string[]): Promise<OciReadiness | null> {
  const packs = packsFor(options, requested); if (packs.length === 0) return null;
  const records: OciReadiness[] = [];
  for (const pack of packs) {
    const admitted = await admittedForPack(options, engine, executable, host, pack);
    if (!admitted) return null;
    records.push(admitted.readiness);
  }
  return { ...records[0]!, available_operations: records.flatMap(item => [...item.available_operations]) };
}

/** Return the capability whose exact identity matches the successful probe. */
export async function resolveAdmittedPodmanAuthority(options: RuntimeOptions, engine: Engine, executable: string, host: Host, requested: readonly string[]): Promise<{ authority: PodmanAuthority; readiness: OciReadiness } | null> {
  const packs = packsFor(options, requested);
  return packs.length === 1 ? admittedForPack(options, engine, executable, host, packs[0]!) : null;
}

async function admittedForPack(options: RuntimeOptions, engine: Engine, executable: string, host: Host, pack: WorkerPack): Promise<{ authority: PodmanAuthority; readiness: OciReadiness } | null> {
  const authority = await resolve(options, executable, host, pack);
  if (!authority) return null;
  const root = stateRoot(options, host);
  try {
    await privateState(root, authority.guard);
    const native = await openStateAuthority(root, authority.guard);
    const saved = await boundedRead(probePath(root, pack), 128 * 1024, native);
    if (saved.toString('utf8') !== `${marker(authority, pack)}\n`) return null;
    await verifyPodmanAuthority(authority);
    const readiness = await record(options, engine, executable, host, authority, pack);
    return readiness ? { authority, readiness } : null;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

/** Run a real cross-file validation probe and save evidence only after cleanup. */
export async function setupPodman(options: RuntimeOptions, engine: Engine, executable: string, host: Host, requested: readonly string[]): Promise<OciReadiness | null> {
  const packs = packsFor(options, requested); if (packs.length === 0) return null;
  const product = await resolveProductGuard(options.sourceRoot, host); const root = stateRoot(options, host);
  await mkdir(root, { recursive: true, mode: 0o700 }); await JournalStore.open(root, product.guard);
  return withProviderLease(product.guard, root, () => setupLeasedPodman(options, engine, executable, host, packs), options.signal ? { signal: options.signal } : {});
}
async function setupLeasedPodman(options: RuntimeOptions, engine: Engine, executable: string, host: Host, packs: WorkerPack[]): Promise<OciReadiness | null> {
  const records: OciReadiness[] = [];
  for (const pack of packs) { const ready = await setupPack(options, engine, executable, host, pack); if (!ready) return null; records.push(ready); }
  return { ...records[0]!, available_operations: records.flatMap(item => [...item.available_operations]) };
}

async function setupPack(options: RuntimeOptions, engine: Engine, executable: string, host: Host, pack: WorkerPack): Promise<OciReadiness | null> {
  if (host.platform !== 'linux' && !podmanVmContext()) {
    try { const vm = await resolvePodmanVm(options.sourceRoot, executable, host, true); return withPodmanVm(vm, () => setupPack(options, engine, executable, host, pack)); }
    catch (error) { if (error instanceof Error && error.message === 'PODMAN_VM_RUNNING_ROOTLESS_MACHINE_REQUIRED') return null; throw error; }
  }
  let authority = await resolve(options, executable, host, pack, true);
  if (!authority) {
    try {
      const image = await loadImageReceipt(options.sourceRoot, pack, podmanVmContext()?.architecture ?? (host.arch === 'x64' ? 'amd64' : 'arm64'));
      const product = await resolveProductGuard(options.sourceRoot, host);
      const admission = await resolvePodmanCleanupAuthority(options.sourceRoot, executable, host);
      if (!admission.guardSha256) throw new Error('PODMAN_CLEANUP_GUARD_IDENTITY_REQUIRED');
      const imported = await withEngineSupervisor({ engine: executable, guard: admission.guard, guardSha256: admission.guardSha256, executableSha256: admission.engineSha256, ...(options.signal ? { signal: options.signal } : {}) }, () => ensurePodmanImage({ sourceRoot: options.sourceRoot, stateRoot: path.join(stateRoot(options, host), 'images'), engine: executable, host, image, guard: product.guard, network: options.setupNetwork ?? 'bootstrap_only', ...(options.signal ? { signal: options.signal } : {}) }));
      if (imported) authority = await resolve(options, executable, host, pack, true);
    } catch (error: unknown) {
      if (!(error instanceof Error) || !['RUNTIME_RECEIPT_NOT_FROZEN', 'PODMAN_ENGINE_UNAVAILABLE'].includes(error.message)) throw error;
    }
  }
  if (!authority || !(await record(options, engine, executable, host, authority, pack))) return null;
  if (authority.vm && !podmanVmContext()) return withPodmanVm(authority.vm, () => setupPack(options, engine, executable, host, pack));
  const root = stateRoot(options, host);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const journal = await JournalStore.open(root, authority.guard);
  await privateState(root, authority.guard);
  const native = await openStateAuthority(root, authority.guard);
  return journal.withWorkspaceLock('podman-setup', async () => {
    await recoverPendingPodmanJobs(root, authority.guard, () => resolvePodmanCleanupAuthority(options.sourceRoot, executable, host));
    const existing = await admittedForPack(options, engine, executable, host, pack);
    if (existing) return existing.readiness;
    const probe = await mkdtemp(path.join(root, 'probe-'));
    try {
      await writeFile(path.join(probe, 'a.conllu'), SAMPLE, { mode: 0o600 });
      await writeFile(path.join(probe, 'b.conllu'), SAMPLE, { mode: 0o600 });
      await verifyPodmanAuthority(authority);
      const result = await runPodmanWorker({ engine: authority.engine, engineSha256: authority.engineSha256, guard: authority.guard, guardSha256: authority.guardSha256, image: authority.image, expectedIdentity: authority.identity, host, stateRoot: root, workingTree: probe, allowedRoots: [probe], filePaths: ['a.conllu', 'b.conllu'], options: { language_code: 'en', level: 2 }, ...(options.signal ? { signal: options.signal } : {}) });
      if (result.result.passed !== false || !Array.isArray(result.result.incidents) || !result.result.incidents.some(item => item && typeof item === 'object' && (item as { testid?: unknown }).testid === 'non-unique-sent-id')) throw new Error('PODMAN_VALIDATION_PROBE_FAILED');
      if (await readFile(path.join(probe, 'a.conllu'), 'utf8') !== SAMPLE || await readFile(path.join(probe, 'b.conllu'), 'utf8') !== SAMPLE) throw new Error('PODMAN_PROBE_INPUT_CHANGED');
      if (pack === 'render') for (const format of ['png', 'pdf'] as const) {
        const rendered = await runPodmanWorker({ engine: authority.engine, engineSha256: authority.engineSha256, guard: authority.guard, guardSha256: authority.guardSha256, image: authority.image, expectedIdentity: authority.identity, host, stateRoot: root, workingTree: probe, allowedRoots: [probe], filePaths: [], options: {}, operation: 'sentence_render', arguments: { sentence_conllu: RENDER_PROBE_SENTENCE, output_format: format, output_path: `/out/probe.${format}`, ud_context_path: '' }, ...(options.signal ? { signal: options.signal } : {}) });
        verifyRenderProbe(rendered.result, format);
      }
      await verifyPodmanAuthority(authority);
      await durableWrite(probePath(root, pack), Buffer.from(`${marker(authority, pack)}\n`), native);
      return await record(options, engine, executable, host, authority, pack);
    } finally { await rm(probe, { recursive: true, force: true }); }
  });
}

export function podmanStateRoot(options: RuntimeOptions, host: Host): string { return stateRoot(options, host); }
