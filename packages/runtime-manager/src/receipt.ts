import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import type { BigIntStats } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

export type WorkerPack = 'core' | 'render';
export type LinuxArch = 'amd64' | 'arm64';
export type ImageTransport = { path: string; sha256: string; sizeBytes: number } & ({ format: 'oci-archive'; indexDigest?: string } | { format: 'docker-archive'; indexDigest?: never });
export type ImageReceipt = { digest: string; reference: string; contextSha256: string; configDigest?: string; engineDescriptorDigests?: readonly string[]; diffIds?: readonly string[]; transports?: readonly ImageTransport[]; seccompProfile?: { path: string; sha256: string; sizeBytes: number }; transportSha256?: string; transportSizeBytes?: number; transportIndexDigest?: string };
const DIGEST = /^sha256:[0-9a-f]{64}$/;

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs && left.mode === right.mode && left.nlink === right.nlink;
}

/** Bind the ordinary named file to the held descriptor even where O_NOFOLLOW is unavailable. */
async function openBoundedRegularFile(filename: string, maximum: bigint, invalid: string, changed: string): Promise<{ handle: FileHandle; before: BigIntStats }> {
  const named = await lstat(filename, { bigint: true });
  if (!named.isFile() || named.isSymbolicLink() || named.size > maximum) throw new Error(invalid);
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat({ bigint: true });
    const afterOpen = await lstat(filename, { bigint: true });
    if (!before.isFile() || !afterOpen.isFile() || afterOpen.isSymbolicLink() || !sameFile(named, before) || !sameFile(before, afterOpen)) throw new Error(changed);
    return { handle, before };
  } catch (error) { await handle.close(); throw error; }
}

async function verifyFileUnchanged(filename: string, handle: FileHandle, before: BigIntStats, changed: string): Promise<void> {
  const held = await handle.stat({ bigint: true });
  const named = await lstat(filename, { bigint: true });
  if (!named.isFile() || named.isSymbolicLink() || !sameFile(before, held) || !sameFile(before, named)) throw new Error(changed);
}

/** Shared by ordinary worker and provider init-image receipt readers. */
export function readImageTransports(value: unknown): readonly ImageTransport[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0 || value.length > 8) throw new Error('Worker transports are invalid.');
  const paths = new Set<string>();
  return Object.freeze(value.map((raw: unknown) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Worker transport is invalid.');
    const item = raw as Record<string, unknown>;
    if (!['oci-archive', 'docker-archive'].includes(item.format as string) || typeof item.path !== 'string' || !safeProductPath(item.path) || paths.has(item.path) || typeof item.sha256 !== 'string' || !DIGEST.test(item.sha256) || !Number.isSafeInteger(item.size_bytes) || (item.size_bytes as number) < 1 || (item.size_bytes as number) > 20 * 1024 * 1024 * 1024) throw new Error('Worker transport is invalid.');
    if (item.index_digest !== undefined && (item.format !== 'oci-archive' || typeof item.index_digest !== 'string' || !DIGEST.test(item.index_digest))) throw new Error('Worker transport index identity is invalid.');
    paths.add(item.path);
    const transport = { path: item.path, sha256: item.sha256, sizeBytes: item.size_bytes as number };
    return item.format === 'oci-archive' ? { ...transport, format: 'oci-archive' as const, ...(item.index_digest === undefined ? {} : { indexDigest: item.index_digest as string }) } : { ...transport, format: 'docker-archive' as const };
  }));
}

export async function readBoundedReceiptBytes(file: string, maximum = 1024 * 1024): Promise<Buffer> {
  if (!path.isAbsolute(file)) throw new Error('Release receipt path must be absolute.');
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 32 * 1024 * 1024) throw new Error('Invalid runtime receipt byte limit.');
  const { handle: info, before: stat } = await openBoundedRegularFile(file, BigInt(maximum), 'Runtime receipt must be a bounded regular file.', 'Runtime receipt changed during reading.');
  let raw: Buffer;
  try {
    raw = Buffer.alloc(Number(stat.size));
    let position = 0;
    while (position < raw.length) {
      const chunk = await info.read(raw, position, raw.length - position, position);
      if (chunk.bytesRead === 0) throw new Error('Runtime receipt changed during reading.');
      position += chunk.bytesRead;
    }
    const extra = Buffer.alloc(1);
    if ((await info.read(extra, 0, 1, position)).bytesRead !== 0) throw new Error('Runtime receipt changed during reading.');
    await verifyFileUnchanged(file, info, stat, 'Runtime receipt changed during reading.');
  } finally { await info.close(); }
  return raw;
}

export async function readBoundedReceipt(file: string): Promise<Record<string, unknown>> {
  const parsed: unknown = JSON.parse((await readBoundedReceiptBytes(file)).toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid runtime receipt.');
  return parsed as Record<string, unknown>;
}

/** Only a frozen product receipt supplies executable image identities. */
export async function loadImageReceipt(sourceRoot: string, pack: WorkerPack, arch: LinuxArch): Promise<ImageReceipt> {
  if (!path.isAbsolute(sourceRoot)) throw new Error('Release source root must be absolute.');
  const lock = await readBoundedReceipt(path.join(sourceRoot, 'runtime', 'runtime.lock.json'));
  if (lock.schema_version !== 1 || lock.product_version !== '0.1.0-beta.1' || lock.state !== 'frozen' || !lock.packs || typeof lock.packs !== 'object') throw new Error('RUNTIME_RECEIPT_NOT_FROZEN');
  const packs = lock.packs as Record<string, unknown>;
  const selected = packs[pack];
  if (!selected || typeof selected !== 'object' || Array.isArray(selected)) throw new Error('Required worker pack is missing from the receipt.');
  const packReceipt = selected as Record<string, unknown>;
  if (typeof packReceipt.context_sha256 !== 'string' || !DIGEST.test(packReceipt.context_sha256) || !packReceipt.images || typeof packReceipt.images !== 'object') throw new Error('Worker context receipt is invalid.');
  const images = packReceipt.images as Record<string, unknown>;
  const image = images[`linux/${arch}`];
  if (!image || typeof image !== 'object' || Array.isArray(image)) throw new Error('Worker image platform is absent from the receipt.');
  const record = image as Record<string, unknown>;
  if (typeof record.digest !== 'string' || !DIGEST.test(record.digest) || typeof record.reference !== 'string' || !/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(record.reference) || !record.reference.endsWith(`@${record.digest}`)) throw new Error('Worker image identity is not an immutable publisher-bound digest.');
  if (record.transport_sha256 !== undefined && (typeof record.transport_sha256 !== 'string' || !DIGEST.test(record.transport_sha256))) throw new Error('Worker image transport digest is invalid.');
  if ((record.transport_sha256 === undefined) !== (record.transport_size_bytes === undefined) || (record.transport_size_bytes !== undefined && (!Number.isSafeInteger(record.transport_size_bytes) || (record.transport_size_bytes as number) < 1 || (record.transport_size_bytes as number) > 20 * 1024 * 1024 * 1024))) throw new Error('Worker image transport size is invalid.');
  if (packReceipt.index_digest !== undefined && (typeof packReceipt.index_digest !== 'string' || !DIGEST.test(packReceipt.index_digest))) throw new Error('Worker index identity is invalid.');
  if (packReceipt.platforms !== undefined) {
    const platforms = packReceipt.platforms as Record<string, unknown>;
    if (!platforms || typeof platforms !== 'object' || Array.isArray(platforms) || platforms[`linux/${arch}`] !== record.digest) throw new Error('Worker platform identities disagree.');
  }
  if ((record.config_digest === undefined) !== (record.diff_ids === undefined) || (record.config_digest !== undefined && (typeof record.config_digest !== 'string' || !DIGEST.test(record.config_digest) || !Array.isArray(record.diff_ids) || record.diff_ids.length === 0 || record.diff_ids.some(value => typeof value !== 'string' || !DIGEST.test(value))))) throw new Error('Worker rootfs identity is invalid.');
  if (record.engine_descriptor_digests !== undefined && (!record.config_digest || !Array.isArray(record.engine_descriptor_digests) || record.engine_descriptor_digests.length < 1 || record.engine_descriptor_digests.length > 8 || new Set(record.engine_descriptor_digests).size !== record.engine_descriptor_digests.length || record.engine_descriptor_digests.some(value => typeof value !== 'string' || !DIGEST.test(value)))) throw new Error('Worker engine descriptors are invalid.');
  const transports = readImageTransports(record.transports);
  let seccompProfile: ImageReceipt['seccompProfile'];
  if (packReceipt.seccomp_profile !== undefined) {
    const profile = packReceipt.seccomp_profile as Record<string, unknown>;
    if (!profile || typeof profile !== 'object' || Array.isArray(profile) || typeof profile.path !== 'string' || !safeProductPath(profile.path) || typeof profile.sha256 !== 'string' || !DIGEST.test(profile.sha256) || !Number.isSafeInteger(profile.size_bytes) || (profile.size_bytes as number) < 1 || (profile.size_bytes as number) > 1024 * 1024) throw new Error('Worker seccomp receipt is invalid.');
    const filename = path.join(sourceRoot, ...profile.path.split('/'));
    const bytes = await readBoundedReceiptBytes(filename);
    if (bytes.length !== profile.size_bytes || `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== profile.sha256) throw new Error('Worker seccomp policy differs from its receipt.');
    seccompProfile = { path: filename, sha256: profile.sha256, sizeBytes: bytes.length };
  }
  return { ...(record.engine_descriptor_digests === undefined ? {} : { engineDescriptorDigests: Object.freeze([...(record.engine_descriptor_digests as string[])]) }), digest: record.digest, reference: record.reference, contextSha256: packReceipt.context_sha256, ...(record.config_digest === undefined ? {} : { configDigest: record.config_digest as string, diffIds: Object.freeze([...(record.diff_ids as string[])]) }), ...(transports === undefined ? {} : { transports: Object.freeze(transports) }), ...(seccompProfile === undefined ? {} : { seccompProfile }), ...(record.transport_sha256 === undefined ? {} : { transportSha256: record.transport_sha256 as string, transportSizeBytes: record.transport_size_bytes as number }) };
}

function safeProductPath(value: string): boolean {
  return value.length > 0 && !value.includes('\\') && !value.includes(':') && !value.includes('\0') && !value.startsWith('/') && value.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}

/** Native helper admission is independent of Python, Perl and userspace setup. */
export async function loadNativeGuardReceipt(sourceRoot: string, host: { platform: string; arch: string }): Promise<{ guard: string; guardSha256: string; manifestSha256: string }> {
  if (!path.isAbsolute(sourceRoot)) throw new Error('Release source root must be absolute.');
  const bytes = await readBoundedReceiptBytes(path.join(sourceRoot, 'runtime/runtime.lock.json'));
  const lock = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
  if (lock.schema_version !== 1 || lock.product_version !== '0.1.0-beta.1' || !['frozen', 'unbuilt'].includes(lock.state as string)) throw new Error('NATIVE_HELPER_RECEIPT_INVALID');
  const helpers = lock.native_helpers as Record<string, { guard?: unknown }> | undefined;
  const item = helpers?.[`${host.platform}/${host.arch}`]?.guard as Record<string, unknown> | undefined;
  if (!item) throw new Error('NATIVE_HELPER_RECEIPT_MISSING');
  if (typeof item.path !== 'string' || !safeProductPath(item.path) || typeof item.sha256 !== 'string' || !DIGEST.test(item.sha256) || !Number.isSafeInteger(item.size_bytes) || (item.size_bytes as number) < 1 || (item.size_bytes as number) > 512 * 1024 * 1024) throw new Error('NATIVE_HELPER_RECEIPT_INVALID');
  let guard = sourceRoot;
  for (const part of item.path.split('/')) { guard = path.join(guard, part); if ((await lstat(guard)).isSymbolicLink()) throw new Error('NATIVE_HELPER_RECEIPT_INVALID'); }
  const info = await lstat(guard);
  if (!info.isFile() || info.size !== item.size_bytes || (process.platform !== 'win32' && ((info.mode & 0o022) !== 0 || (info.mode & 0o111) === 0 || (typeof process.getuid === 'function' && info.uid !== 0 && info.uid !== process.getuid())))) throw new Error('NATIVE_HELPER_RECEIPT_INVALID');
  await verifyArchive(guard, item.sha256);
  return { guard, guardSha256: item.sha256, manifestSha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}` };
}

/** An archive is trusted for import only when the exact frozen bytes match. */
export async function verifyArchive(filename: string, expectedDigest: string, signal?: AbortSignal): Promise<void> {
  if (!path.isAbsolute(filename) || !DIGEST.test(expectedDigest)) throw new Error('Invalid offline archive receipt.');
  const { handle, before } = await openBoundedRegularFile(filename, 20n * 1024n * 1024n * 1024n, 'Offline archive is not a bounded regular file.', 'Offline archive changed during verification.');
  try {
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    let position = 0;
    while (true) {
      if (signal?.aborted) throw new Error('WORKER_CANCELLED');
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      position += bytesRead;
      if (BigInt(position) > before.size) throw new Error('Offline archive changed during verification.');
      hash.update(buffer.subarray(0, bytesRead));
    }
    if (BigInt(position) !== before.size) throw new Error('Offline archive changed during verification.');
    await verifyFileUnchanged(filename, handle, before, 'Offline archive changed during verification.');
    if (`sha256:${hash.digest('hex')}` !== expectedDigest) throw new Error('Offline archive digest does not match the receipt.');
  } finally { await handle.close(); }
}
