import { createHash } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { loadImageReceipt, readBoundedReceiptBytes, verifyArchive } from './receipt.js';
import type { ImageReceipt, LinuxArch } from './receipt.js';
import { verifyEmptyPodmanMounts, verifyIsolatedPodmanConfig } from './podman-config.js';

const PRODUCT = '0.1.0-beta.1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const issued = new WeakMap<object, ProductBinding>();
export type PodmanAssetPaths = { engine: string; tracer: string; guard: string; seccomp: string; containersConf: string; defaultMounts: string };
export type PodmanAuthority = Readonly<{
  architecture: LinuxArch;
  image: Readonly<ImageReceipt>;
  engineSha256: string; tracerSha256: string; guardSha256: string;
  seccompSha256: string; containersConfSha256: string;
}>;
export type PodmanAuthorityUse = { architecture: LinuxArch; paths: PodmanAssetPaths; image: ImageReceipt };
type ProductBinding = { sourceRoot: string; paths: Readonly<PodmanAssetPaths>; productLockHash: string; imageLockHash: string; authority: PodmanAuthority };

function sha256(bytes: Buffer): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function object(raw: unknown): Record<string, unknown> | undefined { return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw as Record<string, unknown> : undefined; }
function parseObject(bytes: Buffer): Record<string, unknown> {
  try { const value = object(JSON.parse(bytes.toString('utf8'))); if (value) return value; }
  catch { /* A malformed receipt is never a source of authority. */ }
  throw new Error('PODMAN_POLICY_RECEIPT_INVALID');
}
function digest(record: Record<string, unknown>, name: string): string {
  const value = record[name];
  if (typeof value !== 'string' || !DIGEST.test(value)) throw new Error(`PODMAN_POLICY_RECEIPT_INVALID: ${name}`);
  return value;
}
async function executable(filename: string, expected: string): Promise<void> {
  const info = await lstat(filename);
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o022) !== 0 || (typeof process.getuid === 'function' && info.uid !== 0 && info.uid !== process.getuid()) || (info.mode & 0o111) === 0) throw new Error('Podman runtime executable is not a trusted regular file.');
  await verifyArchive(filename, expected);
}
async function verifyBindings(binding: ProductBinding): Promise<void> {
  const { paths, authority, sourceRoot } = binding;
  if (sha256(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime', 'podman-policy.lock.json'))) !== binding.productLockHash || sha256(await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime', 'runtime.lock.json'))) !== binding.imageLockHash) throw new Error('PODMAN_RECEIPT_CHANGED');
  await executable(paths.engine, authority.engineSha256);
  await executable(paths.tracer, authority.tracerSha256);
  await executable(paths.guard, authority.guardSha256);
  await verifyArchive(paths.seccomp, authority.seccompSha256);
  await verifyIsolatedPodmanConfig(paths.containersConf, authority.containersConfSha256);
  await verifyEmptyPodmanMounts(paths.defaultMounts);
}

/**
 * Load only from the coordinator's trusted installation root, never request
 * arguments. This capability binds verified assets and an immutable image to
 * this process; it is not live confinement evidence or release certification.
 * The installation's authenticity must be verified by the release mechanism.
 */
export async function loadPodmanAuthority(sourceRoot: string, architecture: LinuxArch, paths: PodmanAssetPaths): Promise<PodmanAuthority> {
  if (!path.isAbsolute(sourceRoot) || (architecture !== 'amd64' && architecture !== 'arm64') || Object.values(paths).some(value => typeof value !== 'string' || !path.isAbsolute(value))) throw new Error('Invalid Podman authority inputs.');
  const policyPath = path.join(sourceRoot, 'runtime', 'podman-policy.lock.json');
  const imagePath = path.join(sourceRoot, 'runtime', 'runtime.lock.json');
  let policyBytes: Buffer;
  try { policyBytes = await readBoundedReceiptBytes(policyPath); }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Error('PODMAN_POLICY_RECEIPT_NOT_FROZEN'); throw error; }
  const lock = parseObject(policyBytes);
  if (lock.schema_version !== 1 || lock.product_version !== PRODUCT || lock.state !== 'frozen') throw new Error('PODMAN_POLICY_RECEIPT_NOT_FROZEN');
  const host = object(object(lock.platforms)?.[`linux/${architecture}`]);
  if (!host) throw new Error('Podman platform policy receipt is missing.');
  const imageBytes = await readBoundedReceiptBytes(imagePath);
  const image = await loadImageReceipt(sourceRoot, 'core', architecture);
  if (sha256(imageBytes) !== sha256(await readBoundedReceiptBytes(imagePath))) throw new Error('PODMAN_RECEIPT_CHANGED');
  const authority: PodmanAuthority = Object.freeze({
    architecture, image: Object.freeze({ ...image }), engineSha256: digest(host, 'engine_sha256'), tracerSha256: digest(host, 'tracer_sha256'),
    guardSha256: digest(host, 'guard_sha256'), seccompSha256: digest(host, 'seccomp_sha256'), containersConfSha256: digest(host, 'containers_conf_sha256'),
  });
  const binding: ProductBinding = { sourceRoot, paths: Object.freeze({ ...paths }), productLockHash: sha256(policyBytes), imageLockHash: sha256(imageBytes), authority };
  await verifyBindings(binding);
  issued.set(authority, binding);
  return authority;
}

/** Reject copied, serialized, fabricated or stale product capabilities. */
export async function verifyPodmanAuthority(authority: unknown, use: PodmanAuthorityUse): Promise<void> {
  if (!authority || typeof authority !== 'object') throw new Error('PODMAN_PRODUCT_AUTHORITY_REQUIRED');
  const binding = issued.get(authority);
  if (!binding) throw new Error('PODMAN_PRODUCT_AUTHORITY_REQUIRED');
  if (!use || use.architecture !== binding.authority.architecture || !use.paths || (['engine', 'tracer', 'guard', 'seccomp', 'containersConf', 'defaultMounts'] as const).some(key => use.paths[key] !== binding.paths[key]) || !use.image || use.image.digest !== binding.authority.image.digest || use.image.reference !== binding.authority.image.reference || use.image.contextSha256 !== binding.authority.image.contextSha256 || use.image.transportSha256 !== binding.authority.image.transportSha256 || use.image.transportSizeBytes !== binding.authority.image.transportSizeBytes) throw new Error('PODMAN_PRODUCT_AUTHORITY_MISMATCH');
  await verifyBindings(binding);
}

