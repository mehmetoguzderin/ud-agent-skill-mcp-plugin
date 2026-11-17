import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { guardedIdentity, guardedStateLock } from '../../workspace/src/guard.js';
import { runCommand } from './command.js';
import type { CommandOptions, CommandResult } from './command.js';
import { verifyArchive } from './receipt.js';
import type { ImageReceipt } from './receipt.js';
import { verifyOciClosure } from './oci-closure.js';
import type { TrustedAppleEngine } from './apple.js';

type Runner = typeof runCommand;
export type AppleRuntimeReceipt = { schema_version: 1; engine: TrustedAppleEngine; initImage: ImageReceipt; kernel: { path: string; sha256: string }; guard: string; guardSha256?: string; stateRoot: string };
export type AppleRuntime = Readonly<{ engine: 'apple-container'; receipt: AppleRuntimeReceipt; image: ImageReceipt; isolation_model: 'per-container-vm'; rootless: null; no_pull_atomic: false; cache_mutation_boundary: 'external-engine-administrator' }>;
const issued = new WeakSet<object>();
const SHA = /^sha256:[0-9a-f]{64}$/;
const OPTIONS = { timeoutMs: 30_000, maxOutputBytes: 16 * 1024 * 1024 };
export function isAppleRuntimeAdmitted(value: unknown): value is AppleRuntime { return value !== null && typeof value === 'object' && issued.has(value); }
function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function json(bytes: Buffer): unknown { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('APPLE_RESPONSE_INVALID'); } }
function supervisedRunner(receipt: AppleRuntimeReceipt, runner: Runner): Runner { if (receipt.guardSha256 === undefined) return runner; if (!SHA.test(receipt.guardSha256)) throw new Error('APPLE_SUPERVISOR_RECEIPT_INVALID'); return (executable, args, options) => runner(executable, args, { ...options, supervisor: { guard: receipt.guard, guardSha256: receipt.guardSha256!, executableSha256: receipt.engine.binarySha256 } }); }

/** Current Apple output nests image descriptions under configuration. */
export function appleLocalImageIdentity(value: unknown, image: ImageReceipt): boolean {
  if (!Array.isArray(value)) return false;
  return value.some(raw => {
    const item = object(raw); const config = object(item?.configuration); const descriptor = object(config?.descriptor);
    if (config?.name !== image.reference || typeof descriptor?.digest !== 'string' || !SHA.test(descriptor.digest)) return false;
    if (!image.configDigest || !image.diffIds?.length) return descriptor.digest === image.digest;
    return Array.isArray(item?.variants) && item.variants.some(raw => {
      const variant = object(raw); const platform = object(variant?.platform); const config = object(variant?.config); const rootfs = object(config?.rootfs);
      return variant?.digest === image.digest && platform?.architecture === 'arm64' && platform.os === 'linux' && config?.architecture === 'arm64' && config.os === 'linux' && rootfs?.type === 'layers' && JSON.stringify(rootfs.diff_ids) === JSON.stringify(image.diffIds);
    });
  });
}

function validImage(image: ImageReceipt): void {
  if (!SHA.test(image.digest) || !image.reference.endsWith(`@${image.digest}`) || !/^[-a-z0-9.]+(?::[0-9]+)?\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(image.reference) || !image.configDigest || !SHA.test(image.configDigest) || !image.diffIds?.length || image.diffIds.some(value => !SHA.test(value))) throw new Error('APPLE_IMAGE_CLOSURE_RECEIPT_REQUIRED');
}

async function checkIdentities(receipt: AppleRuntimeReceipt, images: readonly ImageReceipt[], runner: Runner): Promise<void> {
  await verifyArchive(receipt.engine.executable, receipt.engine.binarySha256);
  await verifyArchive(receipt.kernel.path, receipt.kernel.sha256);
  const result = await runner(receipt.engine.executable, ['image', 'list', '--format', 'json'], OPTIONS);
  const listed = result.code === 0 ? json(result.stdout) : undefined;
  for (const image of images) if (!appleLocalImageIdentity(listed, image)) throw new Error('APPLE_LOCAL_IMAGE_CLOSURE_MISSING');
  // Inspect is get-only upstream: it must never be replaced by run/create/pull.
  // It traverses each present platform config. The init reference may be
  // filtered from printable results by the provider; save below verifies it.
  for (const image of images) {
    const result = await runner(receipt.engine.executable, ['image', 'inspect', image.reference], OPTIONS);
    if (result.code !== 0 || !appleLocalImageIdentity(json(result.stdout), image)) throw new Error('APPLE_LOCAL_IMAGE_CONFIG_MISSING');
  }
}

/** Admit the full local worker/init/kernel closure; never acquire from a registry. */
export async function admitAppleRuntime(receipt: AppleRuntimeReceipt, image: ImageReceipt, runner: Runner = runCommand, existingLockOnly = false): Promise<AppleRuntime> {
  if (receipt.schema_version !== 1 || ![receipt.engine.executable, receipt.kernel.path, receipt.guard, receipt.stateRoot].every(value => path.isAbsolute(value)) || !SHA.test(receipt.engine.binarySha256) || !SHA.test(receipt.kernel.sha256)) throw new Error('APPLE_RUNTIME_RECEIPT_INVALID');
  validImage(image); validImage(receipt.initImage);
  runner = supervisedRunner(receipt, runner);
  const release = await guardedStateLock(receipt.guard, receipt.stateRoot, '.apple-provider.native', await guardedIdentity(receipt.guard, receipt.stateRoot), existingLockOnly);
  try {
    await checkIdentities(receipt, [image, receipt.initImage], runner);
    const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-apple-closure-'));
    try {
      for (const [index, selected] of [image, receipt.initImage].entries()) {
        const filename = path.join(directory, `${index}.oci.tar`);
        const saved = await runner(receipt.engine.executable, ['image', 'save', '--platform', 'linux/arm64', '--output', filename, selected.reference], { timeoutMs: 600_000, maxOutputBytes: 1024 * 1024 });
        if (saved.code !== 0) throw new Error('APPLE_LOCAL_IMAGE_BLOBS_MISSING');
        await verifyOciClosure(filename, { manifestDigest: selected.digest, architecture: 'arm64', configDigest: selected.configDigest!, diffIds: selected.diffIds!, timestampPax: true });
      }
    } finally { await rm(directory, { recursive: true, force: true }); }
    await checkIdentities(receipt, [image, receipt.initImage], runner);
    const runtime: AppleRuntime = Object.freeze({ engine: 'apple-container', receipt: Object.freeze({ ...receipt, engine: Object.freeze({ ...receipt.engine }), kernel: Object.freeze({ ...receipt.kernel }), initImage: Object.freeze({ ...receipt.initImage, diffIds: Object.freeze([...receipt.initImage.diffIds!]) }) }), image: Object.freeze({ ...image, diffIds: Object.freeze([...image.diffIds!]) }), isolation_model: 'per-container-vm', rootless: null, no_pull_atomic: false, cache_mutation_boundary: 'external-engine-administrator' });
    issued.add(runtime); return runtime;
  } finally { await release(); }
}

/**
 * Serialize product jobs and verify immutable cache identities before/after.
 * Apple is local-first, not atomically no-pull. A separate engine administrator
 * deleting a cache object during create remains an explicit trust boundary.
 */
export async function withAppleRuntime<T>(runtime: AppleRuntime, action: (command: (args: readonly string[], options?: CommandOptions) => Promise<CommandResult>) => Promise<T>, runner: Runner = runCommand): Promise<T> {
  if (!issued.has(runtime)) throw new Error('APPLE_RUNTIME_AUTHORITY_REQUIRED');
  const { receipt } = runtime;
  runner = supervisedRunner(receipt, runner);
  const release = await guardedStateLock(receipt.guard, receipt.stateRoot, '.apple-provider.native', await guardedIdentity(receipt.guard, receipt.stateRoot), true);
  try {
    await checkIdentities(receipt, [runtime.image, receipt.initImage], runner);
    const result = await action(async (args, options = OPTIONS) => {
      if (args[0] === 'run' || args.includes('pull') || args.includes('--force') && args[0] === 'image') throw new Error('APPLE_UNAUTHORIZED_ENGINE_ACTION');
      await verifyArchive(receipt.engine.executable, receipt.engine.binarySha256);
      return runner(receipt.engine.executable, args, options);
    });
    await checkIdentities(receipt, [runtime.image, receipt.initImage], runner);
    return result;
  } finally { await release(); }
}

export function appleCreateArguments(runtime: AppleRuntime, job: { name: string; jobId: string; volume: string; readOnlyInput: boolean; command: readonly string[] }): string[] {
  if (!issued.has(runtime)) throw new Error('APPLE_RUNTIME_AUTHORITY_REQUIRED');
  if (!/^ud-agent-[0-9a-f-]{36}-(?:loader|worker)$/.test(job.name) || !/^[0-9a-f-]{36}$/.test(job.jobId) || !/^ud-agent-[0-9a-f-]{36}-input$/.test(job.volume) || job.command.length === 0) throw new Error('APPLE_JOB_INVALID');
  return ['create', '--name', job.name, '--label', `io.ud-agent.job=${job.jobId}`, '--interactive', '--uid', '10001', '--gid', '10001', '--workdir', '/work',
    '--platform', 'linux/arm64',
    '--cpus', '2', '--memory', '2048M', '--network', 'none', '--no-dns', '--read-only', '--cap-drop', 'ALL', '--ulimit', 'nproc=128:128', '--ulimit', 'nofile=1024:1024',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=67108864', '--mount', `type=volume,source=${job.volume},target=/input${job.readOnlyInput ? ',readonly' : ''}`,
    '--kernel', runtime.receipt.kernel.path, '--init-image', runtime.receipt.initImage.reference, '--entrypoint', '/usr/local/bin/python', runtime.image.reference, ...job.command];
}

/** Provider inspection uses its actual VM schema, not Docker's HostConfig. */
export function inspectAppleJob(value: unknown, expected: { name: string; jobId: string; image: string; command: readonly string[]; readOnlyInput: boolean; volume?: string }): string[] {
  const item = Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined; const config = object(item?.configuration); const processConfig = object(config?.initProcess); const resources = object(config?.resources);
  const failures: string[] = [];
  if (!config || config.id !== expected.name || object(config.labels)?.['io.ud-agent.job'] !== expected.jobId || object(config.image)?.reference !== expected.image) failures.push('identity');
  const user = object(object(processConfig?.user)?.id);
  if (processConfig?.executable !== '/usr/local/bin/python' || processConfig.terminal !== false || processConfig.workingDirectory !== '/work' || user?.uid !== 10001 || user.gid !== 10001 || JSON.stringify(processConfig.arguments) !== JSON.stringify(expected.command)) failures.push('process');
  if (config?.readOnly !== true || config.ssh !== false || config.virtualization !== false || !Array.isArray(config.networks) || config.networks.length !== 0 || !Array.isArray(config.publishedPorts) || config.publishedPorts.length !== 0 || !Array.isArray(config.publishedSockets) || config.publishedSockets.length !== 0 || !Array.isArray(config.capDrop) || !config.capDrop.includes('ALL') || !Array.isArray(config.capAdd) || config.capAdd.length !== 0) failures.push('isolation');
  if (resources?.cpus !== 2 || resources.memoryInBytes !== 2147483648) failures.push('vm_limits');
  const limits = Array.isArray(processConfig?.rlimits) ? processConfig.rlimits.map(object) : [];
  if (!limits.some(value => value?.limit === 'RLIMIT_NPROC' && value.hard === 128 && value.soft === 128)) failures.push('process_limit');
  const mounts = Array.isArray(config?.mounts) ? config.mounts.map(object) : []; const input = mounts.filter(value => value?.destination === '/input');
  const inputOptions = input[0]?.options;
  const inputMode = Array.isArray(inputOptions) && (expected.readOnlyInput ? inputOptions.length === 1 && inputOptions[0] === 'ro' : inputOptions.length === 0 || inputOptions.length === 1 && inputOptions[0] === 'rw');
  if (input.length !== 1 || !expected.volume || object(object(input[0]?.type)?.volume)?.name !== expected.volume || !inputMode) failures.push('input');
  if (mounts.some(value => value?.destination !== '/input' && value?.destination !== '/tmp' || value?.destination === '/tmp' && !object(object(value.type)?.tmpfs))) failures.push('extra_mounts');
  return failures;
}
