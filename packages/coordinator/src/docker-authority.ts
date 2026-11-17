import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import type { Host } from '../../runtime-manager/src/profiles.js';
import { loadImageReceipt, loadNativeGuardReceipt, readBoundedReceiptBytes } from '../../runtime-manager/src/receipt.js';
import type { ImageReceipt, WorkerPack } from '../../runtime-manager/src/receipt.js';
import { verifyUserspacePack } from '../../runtime-manager/src/userspace.js';
import { inspectDockerDaemonIdentity, inspectDockerImageIdentity } from './docker-worker.js';
import { withEngineSupervisor } from './engine-command.js';

type Identity = Readonly<{ endpoint: string; daemonId: string; imageId: string; rootless: boolean | null; daemonArchitecture?: string; workerArchitecture?: string; emulation?: boolean }>;
export type DockerAuthority = Readonly<{ engine: string; engineSha256: string; guard: string; guardSha256: string; productLockSha256: string; manifestSha256: string; image: Readonly<ImageReceipt>; identity: Identity }>;
type Binding = { sourceRoot: string; host: Host; rootLock: string; manifest: string; authority: DockerAuthority; pack: WorkerPack };
const issued = new WeakMap<object, Binding>();
export type DockerCleanupAuthority = Readonly<{ engine: string; engineSha256: string; guard: string; guardSha256?: string; identity: { endpoint: string; daemonId: string } }>;
const cleanupIssued = new WeakMap<object, { sourceRoot: string; host: Host; rootLock: string; guardSha256: string }>();

function digest(data: Buffer): string { return `sha256:${createHash('sha256').update(data).digest('hex')}`; }

/** Hash the selected local executable and reject replacement while reading it. */
async function hashEngine(filename: string): Promise<string> {
  if (!path.isAbsolute(filename)) throw new Error('DOCKER_EXECUTABLE_UNVERIFIED');
  const named = await lstat(filename, { bigint: true });
  if (!named.isFile() || named.isSymbolicLink()) throw new Error('DOCKER_EXECUTABLE_UNVERIFIED');
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    const identity = (other: typeof before) => other.isFile() && !other.isSymbolicLink() && ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode', 'uid'].every(key => before[key as keyof typeof before] === other[key as keyof typeof before]);
    // Windows has no POSIX executable/mode bits. The native engine supervisor
    // still pins these exact bytes and owns process creation on every platform.
    if (!identity(named) || !before.isFile() || before.size < 1n || before.size > 512n * 1024n * 1024n || (process.platform !== 'win32' && ((before.mode & 0o022n) !== 0n || (before.mode & 0o111n) === 0n)) || (typeof process.getuid === 'function' && before.uid !== 0n && before.uid !== BigInt(process.getuid()))) throw new Error('DOCKER_EXECUTABLE_UNVERIFIED');
    const hash = createHash('sha256'); const bytes = Buffer.alloc(1024 * 1024); let position = 0;
    for (;;) { const part = await file.read(bytes, 0, bytes.length, position); if (!part.bytesRead) break; position += part.bytesRead; if (BigInt(position) > before.size) throw new Error('DOCKER_EXECUTABLE_CHANGED'); hash.update(bytes.subarray(0, part.bytesRead)); }
    const after = await file.stat({ bigint: true });
    if (BigInt(position) !== before.size || !identity(after) || !identity(await lstat(filename, { bigint: true }))) throw new Error('DOCKER_EXECUTABLE_CHANGED');
    return `sha256:${hash.digest('hex')}`;
  } finally { await file.close(); }
}

export async function resolveProductGuard(sourceRoot: string, host: Host) {
  try { return await loadNativeGuardReceipt(sourceRoot, host); }
  catch (error: unknown) {
    // Existing releases may carry the guard in their verified userspace pack.
    // This reader does not prepare an environment or discover ambient Python.
    if (!(error instanceof Error) || error.message !== 'NATIVE_HELPER_RECEIPT_MISSING') throw error;
    return verifyUserspacePack(sourceRoot, host);
  }
}

/**
 * Bind the installed product receipt, guard, selected executable, local daemon,
 * and locally present publisher digest. This is not a containment probe and
 * must not by itself make an environment ready. No import or pull is performed.
 */
export async function resolveDockerAuthority(sourceRoot: string, engine: string, host: Host = { platform: process.platform, arch: process.arch }, workerPack: WorkerPack = 'core'): Promise<DockerAuthority> {
  if (!path.isAbsolute(sourceRoot) || !['darwin', 'linux', 'win32'].includes(host.platform) || !['arm64', 'x64'].includes(host.arch)) throw new Error('DOCKER_AUTHORITY_UNAVAILABLE');
  const rootLock = digest(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime', 'runtime.lock.json')));
  const image = await loadImageReceipt(sourceRoot, workerPack, host.arch === 'x64' ? 'amd64' : 'arm64');
  const pack = await resolveProductGuard(sourceRoot, host);
  const engineSha256 = await hashEngine(engine);
  const identity = await withEngineSupervisor({ engine, guard: pack.guard, guardSha256: pack.guardSha256, executableSha256: engineSha256 }, () => inspectDockerImageIdentity(engine, host, image));
  if (digest(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime', 'runtime.lock.json'))) !== rootLock) throw new Error('DOCKER_RECEIPT_CHANGED');
  const authority: DockerAuthority = Object.freeze({ engine, engineSha256, guard: pack.guard, guardSha256: pack.guardSha256, productLockSha256: rootLock, manifestSha256: pack.manifestSha256, image: Object.freeze({ ...image }), identity: Object.freeze(identity) });
  issued.set(authority, { sourceRoot, host: { ...host }, rootLock, manifest: pack.manifestSha256, authority, pack: workerPack });
  return authority;
}

/** A copied, serialized, stale or fabricated capability is never authority. */
export async function verifyDockerAuthority(authority: unknown): Promise<DockerAuthority> {
  if (!authority || typeof authority !== 'object') throw new Error('DOCKER_PRODUCT_AUTHORITY_REQUIRED');
  const binding = issued.get(authority);
  if (!binding) throw new Error('DOCKER_PRODUCT_AUTHORITY_REQUIRED');
  const current = binding.authority;
  if (digest(await readBoundedReceiptBytes(path.join(binding.sourceRoot, 'runtime', 'runtime.lock.json'))) !== binding.rootLock) throw new Error('DOCKER_RECEIPT_CHANGED');
  const pack = await resolveProductGuard(binding.sourceRoot, binding.host);
  if (pack.manifestSha256 !== binding.manifest || pack.guard !== current.guard || pack.guardSha256 !== current.guardSha256) throw new Error('DOCKER_RECEIPT_CHANGED');
  if (await hashEngine(current.engine) !== current.engineSha256) throw new Error('DOCKER_EXECUTABLE_CHANGED');
  const identity = await withEngineSupervisor({ engine: current.engine, guard: current.guard, guardSha256: current.guardSha256, executableSha256: current.engineSha256 }, () => inspectDockerImageIdentity(current.engine, binding.host, current.image));
  if (identity.endpoint !== current.identity.endpoint || identity.daemonId !== current.identity.daemonId || identity.imageId !== current.identity.imageId || identity.rootless !== current.identity.rootless || identity.daemonArchitecture !== current.identity.daemonArchitecture || identity.workerArchitecture !== current.identity.workerArchitecture || identity.emulation !== current.identity.emulation) throw new Error('DOCKER_IDENTITY_CHANGED');
  return current;
}

/** Cleanup needs the same local daemon, independently of image availability. */
export async function resolveDockerCleanupAuthority(sourceRoot: string, engine: string, host: Host): Promise<DockerCleanupAuthority> {
  const rootLock = digest(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime/runtime.lock.json'))); const guard = await resolveProductGuard(sourceRoot, host);
  const engineSha256 = await hashEngine(engine);
  const identity = await withEngineSupervisor({ engine, guard: guard.guard, guardSha256: guard.guardSha256, executableSha256: engineSha256 }, () => inspectDockerDaemonIdentity(engine, host));
  const authority = Object.freeze({ engine, engineSha256, guard: guard.guard, guardSha256: guard.guardSha256, identity: Object.freeze(identity) });
  cleanupIssued.set(authority, { sourceRoot, host, rootLock, guardSha256: guard.guardSha256 }); return verifyDockerCleanupAuthority(authority);
}
export async function verifyDockerCleanupAuthority(authority: DockerCleanupAuthority): Promise<DockerCleanupAuthority> {
  const binding = cleanupIssued.get(authority); if (!binding) throw new Error('DOCKER_CLEANUP_AUTHORITY_REQUIRED');
  if (digest(await readBoundedReceiptBytes(path.join(binding.sourceRoot, 'runtime/runtime.lock.json'))) !== binding.rootLock || await hashEngine(authority.engine) !== authority.engineSha256) throw new Error('DOCKER_CLEANUP_AUTHORITY_CHANGED');
  const guard = await resolveProductGuard(binding.sourceRoot, binding.host); if (guard.guard !== authority.guard || guard.guardSha256 !== binding.guardSha256) throw new Error('DOCKER_CLEANUP_AUTHORITY_CHANGED');
  if (authority.guardSha256 !== undefined && authority.guardSha256 !== binding.guardSha256) throw new Error('DOCKER_CLEANUP_AUTHORITY_CHANGED');
  const current = await withEngineSupervisor({ engine: authority.engine, guard: authority.guard, guardSha256: binding.guardSha256, executableSha256: authority.engineSha256 }, () => inspectDockerDaemonIdentity(authority.engine, binding.host)); if (current.endpoint !== authority.identity.endpoint || current.daemonId !== authority.identity.daemonId) throw new Error('DOCKER_DAEMON_CHANGED');
  return authority;
}
