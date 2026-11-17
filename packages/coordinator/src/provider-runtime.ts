import type { OciEngine, OciInspection, RuntimeOptions } from '../../runtime-manager/src/environment.js';
import type { Host } from '../../runtime-manager/src/profiles.js';
import type { ImageReceipt } from '../../runtime-manager/src/receipt.js';
import type { ContextBundle } from '../../workspace/src/input-broker.js';
import { dockerReadiness, dockerStateRoot, resolveAdmittedDockerAuthority, setupDocker } from './docker-readiness.js';
import { runDockerValidation } from './docker-worker.js';
import { verifyDockerAuthority } from './docker-authority.js';
import { podmanReadiness, podmanStateRoot, resolveAdmittedPodmanAuthority, setupPodman } from './podman-readiness.js';
import { inspectPodmanStorageIdentity, runPodmanWorker } from './podman-worker.js';
import { verifyPodmanAuthority } from './podman-authority.js';
import { inspectPodmanVm } from './podman-vm.js';
import { platformReadiness, platformStateRoot, resolveAdmittedPlatform, setupPlatform } from './platform-readiness.js';
import { runCommand } from '../../runtime-manager/src/command.js';
import { parseLimaInstances, LIMA_INSTANCE_FORMAT } from '../../runtime-manager/src/lima.js';
import { meetsWslcMinimum, parseWslcClientVersion } from '../../runtime-manager/src/wslc-inspection.js';
import { resolveOwnedLimaHome } from '../../runtime-manager/src/lima-storage.js';
import { readBoundedReceipt } from '../../runtime-manager/src/receipt.js';
import { validateProviderReceipt } from '../../runtime-manager/src/provider-receipt.js';
import { resolveProductGuard } from './docker-authority.js';
import { lstat } from 'node:fs/promises';
import path from 'node:path';

export type ProviderRequest = { operation: string; arguments: Record<string, unknown>; workingTree: string; allowedRoots: readonly string[]; filePaths: string[]; options: Record<string, unknown>; selectAllFiles?: boolean; signal?: AbortSignal; contextBundle?: ContextBundle };
export type ProviderResult = { result: Record<string, unknown>; snapshot: { root_identity?: { device: string; inode: string }; sha256: string; files: { path: string; sha256: string; size: number }[]; source_map?: { snapshot_path: string; original_path: string }[] } };
export type AdmittedProvider = { guard: string; image: ImageReceipt; stateRoot: string; platform?: Record<string, unknown>; run(input: ProviderRequest): Promise<ProviderResult> };

/** Read-only provider availability is separate from admitted worker readiness. */
export async function providerInspection(engine: OciEngine, executable: string, host: Host, options?: RuntimeOptions): Promise<OciInspection> {
  if (engine === 'apple-container') {
    if (host.platform !== 'darwin' || host.arch !== 'arm64') return { availability: 'unavailable', rootless: null, reason: 'Apple Container requires an Apple silicon Mac.' };
    const status = await runCommand(executable, ['system', 'status'], { timeoutMs: 10000, maxOutputBytes: 65536 });
    return { availability: status.code === 0 ? 'available' : 'unavailable', rootless: null, reason: status.code === 0 ? 'Apple Container service responds; worker/init/kernel closure and VM containment require separate admission.' : 'Apple Container service is stopped or unavailable.' };
  }
  if (engine === 'lima-nerdctl') {
    let home: string | undefined, instance: string | undefined;
    if (options) {
      if (options.signal?.aborted) throw new Error('WORKER_CANCELLED');
      const lock = await readBoundedReceipt(path.join(options.sourceRoot, 'runtime/runtime.lock.json'));
      const records = lock.provider_receipts;
      if (records !== undefined && (!records || typeof records !== 'object' || Array.isArray(records))) throw new Error('PROVIDER_RECEIPT_INVALID');
      const record = (records as Record<string, unknown> | undefined)?.[`lima-nerdctl/${host.platform}/${host.arch}`];
      if (lock.state !== 'frozen' || record === undefined) return { availability: 'unavailable', rootless: null, reason: 'The installed release has no admitted Lima profile.' };
      validateProviderReceipt('lima-nerdctl', host, record); instance = record.instance as string;
      if (record.provisioning) {
        const state = platformStateRoot(options, 'lima-nerdctl', host), guard = await resolveProductGuard(options.sourceRoot, host);
        try { home = await resolveOwnedLimaHome(state, guard.guard); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
        if (!home) {
          for (const name of ['lima-instance.json', 'probe-core.json', 'probe-render.json']) {
            try { await lstat(path.join(state, name)); throw new Error('LIMA_HOME_BINDING_MISSING'); }
            catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
          }
          return { availability: 'unavailable', rootless: null, reason: 'The product-owned Lima instance has not been prepared.' };
        }
      } else if (typeof record.home === 'string') home = record.home;
    }
    const listing = await runCommand(executable, ['list', '--format', LIMA_INSTANCE_FORMAT], { timeoutMs: 10000, maxOutputBytes: 4 * 1024 * 1024, ...(home ? { limaHome: home } : {}), ...(options?.signal ? { signal: options.signal } : {}) });
    const running = listing.code === 0 && parseLimaInstances(listing.stdout).some(item => item.status === 'running' && (instance === undefined || item.name === instance));
    return { availability: running ? 'available' : 'unavailable', rootless: null, reason: running ? options ? 'The receipt-selected Lima VM is running in its verified home; rootless containerd admission is separate.' : 'A running Lima VM is present; receipt-bound rootless containerd admission is separate.' : options ? 'No running selected Lima instance is available.' : 'No running Lima instance is available.' };
  }
  if (engine === 'wslc') {
    if (host.platform !== 'win32') return { availability: 'unavailable', rootless: null, reason: 'WSL Containers requires Windows.' };
    const result = await runCommand(executable, ['version'], { timeoutMs: 10000, maxOutputBytes: 4096 }); const version = result.code === 0 ? parseWslcClientVersion(result.stdout) : undefined;
    return { availability: version && meetsWslcMinimum(version) ? 'available' : 'unavailable', rootless: null, reason: version && meetsWslcMinimum(version) ? 'The supported WSL Containers client is present; administrator prerequisites and owned-session admission are separate.' : 'A supported WSL Containers client is unavailable.' };
  }
  if (engine === 'podman') {
    try {
      if (host.platform !== 'linux') {
        const vm = await inspectPodmanVm(executable, host);
        return { availability: 'available', rootless: null, reason: `The existing ${vm.machine} Podman VM responds with a verified rootless Linux guest; worker admission is separate.` };
      }
      await inspectPodmanStorageIdentity(executable, host); return { availability: 'available', rootless: true, reason: 'The supported local rootless Podman storage identity is verified.' };
    }
    catch (error) {
      if (error instanceof Error && /(?:ENGINE_UNAVAILABLE|AUTHORITY_UNAVAILABLE|ROOTLESS_REQUIRED|ARCHITECTURE|VM_RUNNING_ROOTLESS_MACHINE_REQUIRED|VM_ROOTLESS_GUEST_REQUIRED|VM_HOST_UNSUPPORTED)/.test(error.message)) return { availability: 'unavailable', rootless: null, reason: error.message };
      throw error;
    }
  }
  return { availability: 'unavailable', rootless: null, reason: 'The selected provider has not supplied verified local availability.' };
}

export function providerReadiness(options: RuntimeOptions, engine: OciEngine, executable: string, host: Host, requested: readonly string[]) {
  if (engine === 'docker' || engine === 'docker-rootless') return dockerReadiness(options, engine, executable, host, requested);
  if (engine === 'podman') return podmanReadiness(options, engine, executable, host, requested);
  if (engine === 'apple-container' || engine === 'lima-nerdctl' || engine === 'wslc') return platformReadiness(options, engine, executable, host, requested);
  return Promise.resolve(null);
}
export function setupProvider(options: RuntimeOptions, engine: OciEngine, executable: string, host: Host, requested: readonly string[]) {
  if (engine === 'docker' || engine === 'docker-rootless') return setupDocker(options, engine, executable, host, requested);
  if (engine === 'podman') return setupPodman(options, engine, executable, host, requested);
  if (engine === 'apple-container' || engine === 'lima-nerdctl' || engine === 'wslc') return setupPlatform(options, engine, executable, host, requested);
  return Promise.resolve(null);
}

/** Keep engine authority inside this process and verify it again for every job. */
export async function resolveAdmittedProvider(options: RuntimeOptions, engine: OciEngine, executable: string, host: Host, requested: readonly string[]): Promise<AdmittedProvider | null> {
  if (engine === 'apple-container' || engine === 'lima-nerdctl' || engine === 'wslc') return resolveAdmittedPlatform(options, engine, executable, host, requested);
  if (engine === 'docker' || engine === 'docker-rootless') {
    const admitted = await resolveAdmittedDockerAuthority(options, engine, executable, host, requested);
    if (!admitted) return null;
    const authority = await verifyDockerAuthority(admitted.authority);
    return { guard: authority.guard, image: authority.image, stateRoot: dockerStateRoot(options, host), platform: { host_os: host.platform, process_arch: host.arch, daemon_arch: authority.identity.daemonArchitecture, worker_arch: authority.identity.workerArchitecture, emulation: authority.identity.emulation }, run: async input => {
      await verifyDockerAuthority(admitted.authority);
      return runDockerValidation({ ...input, engine: authority.engine, engineSha256: authority.engineSha256, guard: authority.guard, guardSha256: authority.guardSha256, image: authority.image, expectedIdentity: authority.identity, host, stateRoot: dockerStateRoot(options, host) });
    } };
  }
  if (engine === 'podman') {
    const admitted = await resolveAdmittedPodmanAuthority(options, engine, executable, host, requested);
    if (!admitted) return null;
    const authority = await verifyPodmanAuthority(admitted.authority);
    return { guard: authority.guard, image: authority.image, stateRoot: podmanStateRoot(options, host), platform: { host_os: host.platform, process_arch: host.arch, worker_arch: authority.identity.architecture, provider: 'podman', ...(authority.vm ? { isolation_model: 'rootless_oci_in_vm', guest_rootless: true, virtual_machine: { name: authority.vm.machine, fingerprint: authority.vm.fingerprint, boot_id: authority.vm.bootId } } : { isolation_model: 'rootless_oci', rootless: true }) }, run: async input => {
      await verifyPodmanAuthority(admitted.authority);
      return runPodmanWorker({ ...input, engine: authority.engine, engineSha256: authority.engineSha256, guard: authority.guard, guardSha256: authority.guardSha256, image: authority.image, expectedIdentity: authority.identity, host, stateRoot: podmanStateRoot(options, host) });
    } };
  }
  return null;
}
