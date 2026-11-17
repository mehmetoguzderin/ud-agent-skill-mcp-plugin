import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import type { Host } from '../../runtime-manager/src/profiles.js';
import { loadImageReceipt, loadNativeGuardReceipt, readBoundedReceiptBytes } from '../../runtime-manager/src/receipt.js';
import type { ImageReceipt, WorkerPack } from '../../runtime-manager/src/receipt.js';
import { resolveProductGuard } from './docker-authority.js';
import { inspectPodmanImageIdentity, inspectPodmanStorageIdentity } from './podman-worker.js';
import { bindPodmanVmIdentity, resolvePodmanVm, withPodmanVm } from './podman-vm.js';
import type { PodmanVm } from './podman-vm.js';
import { withEngineSupervisor } from './engine-command.js';

type Identity = import('./podman-worker.js').PodmanIdentity;
export type PodmanAuthority = Readonly<{ engine: string; engineSha256: string; guard: string; guardSha256: string; productLockSha256: string; manifestSha256: string; image: Readonly<ImageReceipt>; identity: Identity; vm?: PodmanVm }>;
type Binding = { sourceRoot: string; host: Host; rootLock: string; manifest: string; authority: PodmanAuthority; pack: WorkerPack };
const issued = new WeakMap<object, Binding>();
export type PodmanCleanupAuthority = Readonly<{ engine: string; engineSha256: string; guard: string; guardSha256?: string; identity: Awaited<ReturnType<typeof inspectPodmanStorageIdentity>>; vm?: PodmanVm }>;
const cleanupIssued = new WeakMap<object, { sourceRoot: string; host: Host; rootLock: string; guardSha256: string }>();

function digest(data: Buffer): string { return `sha256:${createHash('sha256').update(data).digest('hex')}`; }

/** Hash the selected local executable and reject replacement while reading it. */
async function hashEngine(filename: string): Promise<string> {
  if (!path.isAbsolute(filename)) throw new Error('PODMAN_EXECUTABLE_UNVERIFIED');
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size > 512n * 1024n * 1024n || (before.mode & 0o022n) !== 0n || (before.mode & 0o111n) === 0n || (typeof process.getuid === 'function' && before.uid !== 0n && before.uid !== BigInt(process.getuid()))) throw new Error('PODMAN_EXECUTABLE_UNVERIFIED');
    const hash = createHash('sha256'); const bytes = Buffer.alloc(1024 * 1024); let position = 0;
    for (;;) { const part = await file.read(bytes, 0, bytes.length, position); if (!part.bytesRead) break; position += part.bytesRead; if (BigInt(position) > before.size) throw new Error('PODMAN_EXECUTABLE_CHANGED'); hash.update(bytes.subarray(0, part.bytesRead)); }
    const after = await file.stat({ bigint: true });
    if (BigInt(position) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('PODMAN_EXECUTABLE_CHANGED');
    return `sha256:${hash.digest('hex')}`;
  } finally { await file.close(); }
}

export async function resolvePodmanCleanupAuthority(sourceRoot: string, engine: string, host: Host): Promise<PodmanCleanupAuthority> {
  const rootLock = digest(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime/runtime.lock.json'))); const guard = await resolveProductGuard(sourceRoot, host);
  const vm = host.platform === 'linux' ? undefined : await resolvePodmanVm(sourceRoot, engine, host, true);
  const engineSha256 = await hashEngine(engine);
  const identity = await withEngineSupervisor({ engine, guard: guard.guard, guardSha256: guard.guardSha256, executableSha256: engineSha256 }, () => vm ? withPodmanVm(vm, () => inspectPodmanStorageIdentity(engine, host)) : inspectPodmanStorageIdentity(engine, host));
  const authority = Object.freeze({ engine, engineSha256, guard: guard.guard, guardSha256: guard.guardSha256, identity: Object.freeze(identity), ...(vm ? { vm } : {}) });
  cleanupIssued.set(authority, { sourceRoot, host, rootLock, guardSha256: guard.guardSha256 }); return verifyPodmanCleanupAuthority(authority);
}
export async function verifyPodmanCleanupAuthority(authority: PodmanCleanupAuthority): Promise<PodmanCleanupAuthority> {
  const binding = cleanupIssued.get(authority); if (!binding) throw new Error('PODMAN_CLEANUP_AUTHORITY_REQUIRED');
  if (digest(await readBoundedReceiptBytes(path.join(binding.sourceRoot, 'runtime/runtime.lock.json'))) !== binding.rootLock || await hashEngine(authority.engine) !== authority.engineSha256) throw new Error('PODMAN_CLEANUP_AUTHORITY_CHANGED');
  const guard = await resolveProductGuard(binding.sourceRoot, binding.host); if (guard.guard !== authority.guard || guard.guardSha256 !== binding.guardSha256) throw new Error('PODMAN_CLEANUP_AUTHORITY_CHANGED');
  if (authority.guardSha256 !== undefined && authority.guardSha256 !== binding.guardSha256) throw new Error('PODMAN_CLEANUP_AUTHORITY_CHANGED');
  const current = await withEngineSupervisor({ engine: authority.engine, guard: authority.guard, guardSha256: binding.guardSha256, executableSha256: authority.engineSha256 }, () => authority.vm ? withPodmanVm(authority.vm, () => inspectPodmanStorageIdentity(authority.engine, binding.host)) : inspectPodmanStorageIdentity(authority.engine, binding.host));
  if (current.graphRoot !== authority.identity.graphRoot || current.graphIdentity !== authority.identity.graphIdentity || current.virtualMachine !== authority.identity.virtualMachine) throw new Error('PODMAN_STORAGE_CHANGED'); return authority;
}

/**
 * Bind the installed product receipt, guard, selected executable, local daemon,
 * and locally present publisher digest. This is not a containment probe and
 * must not by itself make an environment ready. No import or pull is performed.
 */
export async function resolvePodmanAuthority(sourceRoot: string, engine: string, host: Host = { platform: process.platform, arch: process.arch }, workerPack: WorkerPack = 'core', prepareVm = false): Promise<PodmanAuthority> {
  if (!path.isAbsolute(sourceRoot) || !['linux', 'darwin', 'win32'].includes(host.platform) || !['arm64', 'x64'].includes(host.arch)) throw new Error('PODMAN_AUTHORITY_UNAVAILABLE');
  const rootLock = digest(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime', 'runtime.lock.json')));
  const vm = host.platform === 'linux' ? undefined : await resolvePodmanVm(sourceRoot, engine, host, prepareVm);
  const image = await loadImageReceipt(sourceRoot, workerPack, vm?.architecture ?? (host.arch === 'x64' ? 'amd64' : 'arm64'));
  const pack = await resolveProductGuard(sourceRoot, host);
  const engineSha256 = await hashEngine(engine);
  const identity = await withEngineSupervisor({ engine, guard: pack.guard, guardSha256: pack.guardSha256, executableSha256: engineSha256 }, () => vm ? withPodmanVm(vm, () => inspectPodmanImageIdentity(engine, host, image)) : inspectPodmanImageIdentity(engine, host, image));
  if (digest(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime', 'runtime.lock.json'))) !== rootLock) throw new Error('PODMAN_RECEIPT_CHANGED');
  const authority: PodmanAuthority = Object.freeze({ engine, engineSha256, guard: pack.guard, guardSha256: pack.guardSha256, productLockSha256: rootLock, manifestSha256: pack.manifestSha256, image: Object.freeze({ ...image }), identity: Object.freeze(identity), ...(vm ? { vm } : {}) });
  if (vm) bindPodmanVmIdentity(authority.identity, vm);
  issued.set(authority, { sourceRoot, host: { ...host }, rootLock, manifest: pack.manifestSha256, authority, pack: workerPack });
  return authority;
}

/** A copied, serialized, stale or fabricated capability is never authority. */
export async function verifyPodmanAuthority(authority: unknown): Promise<PodmanAuthority> {
  if (!authority || typeof authority !== 'object') throw new Error('PODMAN_PRODUCT_AUTHORITY_REQUIRED');
  const binding = issued.get(authority);
  if (!binding) throw new Error('PODMAN_PRODUCT_AUTHORITY_REQUIRED');
  const current = binding.authority;
  if (digest(await readBoundedReceiptBytes(path.join(binding.sourceRoot, 'runtime', 'runtime.lock.json'))) !== binding.rootLock) throw new Error('PODMAN_RECEIPT_CHANGED');
  const pack = await resolveProductGuard(binding.sourceRoot, binding.host);
  if (pack.manifestSha256 !== binding.manifest || pack.guard !== current.guard || pack.guardSha256 !== current.guardSha256) throw new Error('PODMAN_RECEIPT_CHANGED');
  if (await hashEngine(current.engine) !== current.engineSha256) throw new Error('PODMAN_EXECUTABLE_CHANGED');
  const identity = await withEngineSupervisor({ engine: current.engine, guard: current.guard, guardSha256: current.guardSha256, executableSha256: current.engineSha256 }, () => current.vm ? withPodmanVm(current.vm, () => inspectPodmanImageIdentity(current.engine, binding.host, current.image)) : inspectPodmanImageIdentity(current.engine, binding.host, current.image));
  if (JSON.stringify(identity) !== JSON.stringify(current.identity)) throw new Error('PODMAN_IDENTITY_CHANGED');
  return current;
}
