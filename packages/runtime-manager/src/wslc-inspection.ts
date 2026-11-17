import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { runCommand } from './command.js';
import { verifyArchive } from './receipt.js';
import type { Host } from './profiles.js';

/** Microsoft's documented minimum for the WSL Containers preview. */
const MINIMUM_VERSION = [2, 9, 3, 0] as const;
const VERSION_ARGS = ['version'] as const;

type Runner = typeof runCommand;
export type WslcInspectionInput = {
  executable: string;
  /** Exact hash from a separately authenticated product/provider receipt. */
  expectedSha256: string;
  host?: Host;
  runner?: Runner;
};
export type WslcInspection = {
  engine: 'wslc';
  status: 'client_present_unverified' | 'host_prerequisite' | 'inspection_incomplete';
  client_version: string | null;
  client_hash_verified: boolean;
  minimum_version_met: boolean | null;
  isolation_model: 'managed-wsl-vm';
  rootless_verified: null;
  session_state: 'not_inspected';
  worker_uid_verified: false;
  networking_disabled_verified: false;
  resource_bounds_verified: false;
  image_identity_verified: false;
  cleanup_verified: false;
  production_ready: false;
  reason: string;
};

/** Parse the actual plain `wslc version` form, independent of a UI locale. */
export function parseWslcClientVersion(bytes: Buffer): string | undefined {
  if (bytes.length > 4096) return undefined;
  let text: string;
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) text = bytes.subarray(2).toString('utf16le');
  else if (bytes.length >= 2 && bytes[1] === 0 && bytes.length % 2 === 0) text = bytes.toString('utf16le');
  else text = bytes.toString('utf8').replace(/^\uFEFF/, '');
  const match = /^wslc(?:\.exe)?\s+([0-9]{1,5}(?:\.[0-9]{1,5}){2,3})\s*$/i.exec(text);
  if (!match?.[1]) return undefined;
  const parts = match[1].split('.');
  if (parts.some(part => part.length > 1 && part.startsWith('0'))) return undefined;
  return parts.join('.');
}

export function meetsWslcMinimum(version: string): boolean {
  if (!/^[0-9]{1,5}(?:\.[0-9]{1,5}){2,3}$/.test(version)) return false;
  const parts = version.split('.').map(Number);
  for (let index = 0; index < MINIMUM_VERSION.length; index++) {
    const part = parts[index] ?? 0;
    const minimum = MINIMUM_VERSION[index] ?? 0;
    if (part !== minimum) return part > minimum;
  }
  return true;
}

/**
 * Client-only inspection. Image or container inspect can establish a WSL
 * session, so it is deliberately omitted from this read-only operation.
 * Product policy must authenticate the expected hash before invoking this API.
 * A matching hash is integrity evidence, not an Authenticode or isolation proof.
 * No production dispatcher consumes this preliminary result.
 *
 * Upstream: https://learn.microsoft.com/en-us/windows/wsl/wsl-container
 * https://github.com/microsoft/WSL/blob/master/src/windows/wslc/commands/VersionCommand.cpp
 */
export async function inspectWslcClient(input: WslcInspectionInput): Promise<WslcInspection> {
  const base = {
    engine: 'wslc' as const, isolation_model: 'managed-wsl-vm' as const,
    rootless_verified: null, session_state: 'not_inspected' as const,
    worker_uid_verified: false as const, networking_disabled_verified: false as const,
    resource_bounds_verified: false as const, image_identity_verified: false as const,
    cleanup_verified: false as const, production_ready: false as const,
  };
  const host = input.host ?? { platform: process.platform, arch: process.arch };
  if (host.platform !== 'win32' || !['arm64', 'x64'].includes(host.arch)) {
    return { ...base, status: 'host_prerequisite', client_version: null, client_hash_verified: false, minimum_version_met: null, reason: 'WSL Containers is supported only on the selected Windows architectures.' };
  }
  if (!path.isAbsolute(input.executable) || !/^sha256:[0-9a-f]{64}$/.test(input.expectedSha256)) throw new Error('A full executable path and frozen SHA-256 are required.');
  await verifyArchive(input.executable, input.expectedSha256);
  const before = await lstat(input.executable, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error('WSLc executable must be a regular file.');
  const runner = input.runner ?? runCommand;
  let versionResult: Awaited<ReturnType<Runner>> | undefined;
  try { versionResult = await runner(input.executable, VERSION_ARGS, { timeoutMs: 10_000, maxOutputBytes: 4096 }); }
  catch { /* Still recheck the executable after an interrupted query. */ }
  const after = await lstat(input.executable, { bigint: true });
  if (!after.isFile() || after.isSymbolicLink() || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('WSLc executable changed during inspection.');
  await verifyArchive(input.executable, input.expectedSha256);
  if (!versionResult) return { ...base, status: 'inspection_incomplete', client_version: null, client_hash_verified: true, minimum_version_met: null, reason: 'The bounded WSLc client version query did not complete.' };
  const version = versionResult.code === 0 ? parseWslcClientVersion(versionResult.stdout) : undefined;
  if (!version) return { ...base, status: 'inspection_incomplete', client_version: null, client_hash_verified: true, minimum_version_met: null, reason: 'WSLc did not return a recognized client version.' };
  if (!meetsWslcMinimum(version)) return { ...base, status: 'host_prerequisite', client_version: version, client_hash_verified: true, minimum_version_met: false, reason: 'WSL Containers requires WSL 2.9.3 or later; administrator-managed updates may be required.' };
  return { ...base, status: 'client_present_unverified', client_version: version, client_hash_verified: true, minimum_version_met: true, reason: 'The client version is present; its signer, session, worker isolation, image identity, and cleanup remain unverified.' };
}
