import path from 'node:path';
import { createHash } from 'node:crypto';
import { runCommand } from './command.js';
import type { CommandOptions, CommandResult } from './command.js';
import { inspectLima } from './lima.js';
import { verifyArchive } from './receipt.js';
import type { ImageReceipt } from './receipt.js';
import type { CommandSupervisor } from './supervised-command.js';
import { equalLimaSeccomp } from './lima-seccomp.js';

export type LimaRuntimeReceipt = {
  schema_version: 1;
  executable: string; binarySha256: string; instance: string;
  nerdctl: string; nerdctlSha256: string; containerd: string; containerdSha256: string;
  ctr?: string; ctrSha256?: string;
  nsenter?: string; nsenterSha256?: string;
  address: string; guestUid: number; guestHome: string; architecture: 'amd64' | 'arm64';
  home?: string;
};
export type LimaRuntime = Readonly<{ engine: 'lima-nerdctl'; receipt: Readonly<LimaRuntimeReceipt>; identity: string; bootId: string; rootless: true; supervisor?: Readonly<Omit<CommandSupervisor, 'executableSha256'>> }>;
type Runner = typeof runCommand;
const issued = new WeakSet<object>();
const SHA = /^sha256:[0-9a-f]{64}$/;
const NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DEFAULT = { timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024 };

function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function json(bytes: Buffer): unknown { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('LIMA_RESPONSE_INVALID'); } }
function absoluteGuest(value: string): boolean { return path.posix.isAbsolute(value) && !value.includes('\0') && !value.includes('\n') && !value.split('/').includes('..'); }
function nativeName(content: Record<string, unknown> | undefined): unknown { return content?.Name !== undefined ? content.name === undefined ? content.Name : undefined : content?.name; }
function namedNativeImage(value: unknown, reference: string): Record<string, unknown> | undefined {
  if (!Array.isArray(value) || value.length < 1 || value.length > 10_000) return undefined;
  // Native inspect enumerates every local alias of the selected target digest.
  const matching = value.map(object).filter(item => nativeName(object(item?.Image)) === reference);
  return matching.length === 1 ? matching[0] : undefined;
}
function rootfsIdentity(value: unknown, diffIds: readonly string[]): boolean {
  if (!Array.isArray(value)) return false;
  if (JSON.stringify(value) === JSON.stringify(diffIds)) return true;
  // nerdctl v2.4.2's native inspector calls identity.ChainIDs in place on
  // ImageConfig.RootFS.DiffIDs. Preserve the frozen diff IDs; accept only their
  // exact ordered OCI chain projection, never arbitrary snapshot identifiers.
  const chains: string[] = [];
  for (const diff of diffIds) chains.push(chains.length === 0 ? diff : `sha256:${createHash('sha256').update(`${chains.at(-1)} ${diff}`).digest('hex')}`);
  return JSON.stringify(value) === JSON.stringify(chains);
}
function validReceipt(value: LimaRuntimeReceipt): void {
  if (value.schema_version !== 1 || !path.isAbsolute(value.executable) || !SHA.test(value.binarySha256) || !NAME.test(value.instance)
      || !absoluteGuest(value.nerdctl) || !SHA.test(value.nerdctlSha256) || !absoluteGuest(value.containerd) || !SHA.test(value.containerdSha256)
      || !absoluteGuest(value.address) || !absoluteGuest(value.guestHome) || !Number.isSafeInteger(value.guestUid) || value.guestUid < 1 || value.guestUid > 0xffff_ffff
      || !['amd64', 'arm64'].includes(value.architecture)) throw new Error('LIMA_RUNTIME_RECEIPT_INVALID');
  if (value.home !== undefined && (!path.isAbsolute(value.home) || value.home.includes('\0'))) throw new Error('LIMA_RUNTIME_RECEIPT_INVALID');
  if ((value.ctr === undefined) !== (value.ctrSha256 === undefined) || value.ctr !== undefined && (!absoluteGuest(value.ctr) || !SHA.test(value.ctrSha256!))) throw new Error('LIMA_RUNTIME_RECEIPT_INVALID');
  if ((value.nsenter === undefined) !== (value.nsenterSha256 === undefined) || value.nsenter !== undefined && (!absoluteGuest(value.nsenter) || !SHA.test(value.nsenterSha256!))) throw new Error('LIMA_RUNTIME_RECEIPT_INVALID');
}

/** Lima has its own shell grammar. Never pass Docker's host flags through it. */
export function limaShellArguments(receipt: LimaRuntimeReceipt, command: readonly string[]): string[] {
  validReceipt(receipt);
  if (command.length === 0 || command.length > 220 || command.some(value => value.includes('\0'))) throw new Error('LIMA_COMMAND_INVALID');
  return ['shell', '--start=false', '--tty=false', '--preserve-env=false', '--reconnect=false', '--workdir=/', '--shell=/bin/sh', receipt.instance, '/usr/bin/env', '-i',
    'PATH=/usr/local/bin:/usr/bin:/bin', `HOME=${receipt.guestHome}`, `XDG_RUNTIME_DIR=/run/user/${receipt.guestUid}`,
    'LANG=C', 'NERDCTL_TOML=/dev/null', ...command];
}

export function limaNerdctlArguments(receipt: LimaRuntimeReceipt, args: readonly string[]): string[] {
  return limaShellArguments(receipt, [receipt.nerdctl, '--address', receipt.address, '--namespace', 'ud-agent', '--snapshotter', 'overlayfs', '--cgroup-manager', 'systemd', ...args]);
}

async function guestIdentity(receipt: LimaRuntimeReceipt, runner: Runner, expectedBoot?: string): Promise<string> {
  const options = { ...DEFAULT, ...(receipt.home ? { limaHome: receipt.home } : {}) };
  const uid = await runner(receipt.executable, limaShellArguments(receipt, ['/usr/bin/id', '-u']), options);
  if (uid.code !== 0 || uid.stdout.toString('utf8').trim() !== String(receipt.guestUid)) throw new Error('LIMA_GUEST_USER_CHANGED');
  const checks = await runner(receipt.executable, limaShellArguments(receipt, ['/usr/bin/sha256sum', '--', receipt.nerdctl, receipt.containerd, ...(receipt.ctr ? [receipt.ctr] : []), ...(receipt.nsenter ? [receipt.nsenter] : [])]), options);
  const expected = [`${receipt.nerdctlSha256.slice(7)}  ${receipt.nerdctl}`, `${receipt.containerdSha256.slice(7)}  ${receipt.containerd}`, ...(receipt.ctr ? [`${receipt.ctrSha256!.slice(7)}  ${receipt.ctr}`] : []), ...(receipt.nsenter ? [`${receipt.nsenterSha256!.slice(7)}  ${receipt.nsenter}`] : [])];
  if (checks.code !== 0 || checks.stdout.toString('utf8').trimEnd().split('\n').some((line, index) => line !== expected[index]) || checks.stdout.toString('utf8').trimEnd().split('\n').length !== expected.length) throw new Error('LIMA_GUEST_EXECUTABLE_CHANGED');
  const boot = await runner(receipt.executable, limaShellArguments(receipt, ['/usr/bin/cat', '--', '/proc/sys/kernel/random/boot_id']), options);
  const bootId = boot.stdout.toString('utf8').trim(); if (boot.code !== 0 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(bootId) || expectedBoot !== undefined && bootId !== expectedBoot) throw new Error('LIMA_GUEST_BOOT_CHANGED');
  return bootId;
}

/** Observational admission: no VM starts, downloads, or service changes. */
export async function admitLimaRuntime(receipt: LimaRuntimeReceipt, runner: Runner = runCommand, supervisor?: Omit<CommandSupervisor, 'executableSha256'>): Promise<LimaRuntime> {
  validReceipt(receipt);
  if (supervisor) {
    if (!path.isAbsolute(supervisor.guard) || !SHA.test(supervisor.guardSha256)) throw new Error('LIMA_SUPERVISOR_RECEIPT_INVALID');
    const execute = runner; runner = (executable, args, options) => execute(executable, args, { ...options, supervisor: { ...supervisor, executableSha256: receipt.binarySha256 } });
  }
  const inventory = await inspectLima(receipt, receipt.instance, runner);
  if (!inventory.selected || inventory.selected.status !== 'running' || inventory.selected.arch !== receipt.architecture) throw new Error('LIMA_RUNNING_INSTANCE_REQUIRED');
  const bootId = await guestIdentity(receipt, runner);
  const result = await runner(receipt.executable, limaNerdctlArguments(receipt, ['info', '--mode=native', '--format', '{{json .}}']), { ...DEFAULT, ...(receipt.home ? { limaHome: receipt.home } : {}) });
  const info = object(json(result.stdout));
  if (result.code !== 0 || info?.Rootless !== true || info.Namespace !== 'ud-agent' || info.Snapshotter !== 'overlayfs' || info.CgroupManager !== 'systemd' || !object(info.Daemon)) throw new Error('LIMA_ROOTLESS_CONTAINERD_REQUIRED');
  await verifyArchive(receipt.executable, receipt.binarySha256);
  const frozenReceipt = Object.freeze({ ...receipt });
  const runtime: LimaRuntime = Object.freeze({ engine: 'lima-nerdctl', receipt: frozenReceipt, identity: `${receipt.instance}:${receipt.address}:${receipt.nerdctlSha256}:${receipt.containerdSha256}${receipt.ctrSha256 ? `:${receipt.ctrSha256}` : ''}${receipt.nsenterSha256 ? `:${receipt.nsenterSha256}` : ''}:${bootId}`, bootId, rootless: true, ...(supervisor ? { supervisor: Object.freeze({ ...supervisor }) } : {}) });
  issued.add(runtime);
  return runtime;
}

/** Reverify both host and guest authorities for every command and recovery. */
export async function limaCommand(runtime: LimaRuntime, args: readonly string[], options: CommandOptions = DEFAULT, runner: Runner = runCommand): Promise<CommandResult> {
  if (!issued.has(runtime)) throw new Error('LIMA_AUTHORITY_REQUIRED');
  return limaGuestCommand(runtime, [runtime.receipt.nerdctl, '--address', runtime.receipt.address, '--namespace', 'ud-agent', '--snapshotter', 'overlayfs', '--cgroup-manager', 'systemd', ...args], options, runner);
}

/** Internal fixed guest commands share the exact host/guest authority checks. */
export async function limaGuestCommand(runtime: LimaRuntime, args: readonly string[], options: CommandOptions = DEFAULT, runner: Runner = runCommand): Promise<CommandResult> {
  if (!issued.has(runtime)) throw new Error('LIMA_AUTHORITY_REQUIRED');
  if (runtime.supervisor) { const execute = runner; runner = (executable, args, options) => execute(executable, args, { ...options, supervisor: { ...runtime.supervisor!, executableSha256: runtime.receipt.binarySha256 } }); }
  if (options.signal) { const execute = runner; runner = (executable, args, commandOptions) => execute(executable, args, { ...commandOptions, signal: options.signal! }); }
  await verifyArchive(runtime.receipt.executable, runtime.receipt.binarySha256);
  await guestIdentity(runtime.receipt, runner, runtime.bootId);
  const result = await runner(runtime.receipt.executable, limaShellArguments(runtime.receipt, args), { ...options, ...(runtime.receipt.home ? { limaHome: runtime.receipt.home } : {}) });
  await verifyArchive(runtime.receipt.executable, runtime.receipt.binarySha256);
  return result;
}

/** The directory belongs to this exact native container, not a host workspace. */
export function limaJobStateDirectory(value: unknown, runtime: LimaRuntime, id: string, jobId: string): string | undefined {
  if (!issued.has(runtime) || !/^[a-f0-9]{64}$/.test(id)) return undefined;
  const item = Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined; const labels = object(item?.Labels);
  const source = labels?.['nerdctl/state-dir'], prefix = `${runtime.receipt.guestHome}/.local/share/nerdctl/`;
  if (item?.ID !== id || labels?.['io.ud-agent.job'] !== jobId || labels?.['nerdctl/namespace'] !== 'ud-agent' || !['loader', 'worker'].some(kind => labels?.['nerdctl/name'] === `ud-agent-${jobId}-${kind}`) || typeof source !== 'string' || !source.startsWith(prefix) || !absoluteGuest(source) || !/^[a-f0-9]{8}$/.test(source.slice(prefix.length).split('/')[0] ?? '') || source.slice(prefix.length + 9) !== `containers/ud-agent/${id}`) return undefined;
  return source;
}

/** Native nerdctl inspection is deliberately distinct from Docker inspection. */
export function limaImageIdentity(value: unknown, receipt: ImageReceipt, architecture: 'amd64' | 'arm64'): string | undefined {
  const item = namedNativeImage(value, receipt.reference);
  const manifest = object(item?.ManifestDesc); const config = object(item?.ImageConfigDesc); const imageConfig = object(item?.ImageConfig);
  const rootfs = object(imageConfig?.rootfs); const content = object(item?.Image);
  const name = nativeName(content);
  const target = object(content?.Target !== undefined ? content.target === undefined ? content.Target : undefined : content?.target);
  if (!receipt.configDigest || !receipt.diffIds?.length || manifest?.digest !== receipt.digest || config?.digest !== receipt.configDigest
      || imageConfig?.architecture !== architecture || imageConfig.os !== 'linux' || rootfs?.type !== 'layers'
      || !rootfsIdentity(rootfs.diff_ids, receipt.diffIds)
      || name !== receipt.reference || (target?.digest !== receipt.digest && (typeof target?.digest !== 'string' || !SHA.test(target.digest) || object(item?.IndexDesc)?.digest !== target.digest))) return undefined;
  const manifestBody = object(item?.Manifest);
  if (manifestBody && (manifestBody.schemaVersion !== 2 || object(manifestBody.config)?.digest !== receipt.configDigest || !Array.isArray(manifestBody.layers) || manifestBody.layers.length !== receipt.diffIds.length || manifestBody.layers.some(raw => { const layer = object(raw); return typeof layer?.digest !== 'string' || !SHA.test(layer.digest); }))) return undefined;
  const indexBody = object(item?.Index);
  if (target?.digest !== receipt.digest && indexBody && (indexBody.schemaVersion !== 2 || !Array.isArray(indexBody.manifests) || !indexBody.manifests.some(raw => object(raw)?.digest === receipt.digest))) return undefined;
  if (typeof name === 'string' && name.startsWith('import@') && target?.digest !== name.slice(7)) return undefined;
  const indexes = receipt.transports?.filter(item => item.format === 'oci-archive' && item.indexDigest).map(item => item.indexDigest) ?? [];
  if (target?.digest !== receipt.digest && indexes.length > 0 && !indexes.includes(target?.digest as string)) return undefined;
  return receipt.reference;
}

/** Setup only: ctr's local ImageService creates a name without registry fetches. */
export async function bindLimaOfflineImage(runtime: LimaRuntime, image: ImageReceipt, runner: Runner = runCommand): Promise<{ bound: boolean; reference: string }> {
  if (!issued.has(runtime)) throw new Error('LIMA_AUTHORITY_REQUIRED');
  if (!/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(image.reference) || !image.reference.endsWith(`@${image.digest}`)) throw new Error('LIMA_IMAGE_RECEIPT_INVALID');
  const current = await limaCommand(runtime, ['image', 'inspect', '--mode=native', image.reference], undefined, runner);
  const currentValue = current.code === 0 ? json(current.stdout) : undefined;
  if (limaImageIdentity(currentValue, image, runtime.receipt.architecture)) return { bound: false, reference: image.reference };
  if (namedNativeImage(currentValue, image.reference)) throw new Error('LIMA_IMAGE_IDENTITY_INVALID');
  if (!runtime.receipt.ctr || !runtime.receipt.ctrSha256) throw new Error('LIMA_LOCAL_TAG_HELPER_REQUIRED');
  const source = `import@${image.digest}`;
  const imported = await limaCommand(runtime, ['image', 'inspect', '--mode=native', source], undefined, runner);
  if (imported.code !== 0 || !limaImageIdentity(json(imported.stdout), { ...image, reference: source }, runtime.receipt.architecture)) throw new Error('LIMA_IMPORTED_IMAGE_IDENTITY_INVALID');
  const tagged = await limaGuestCommand(runtime, [runtime.receipt.ctr, '--address', runtime.receipt.address, '--namespace', 'ud-agent', 'images', 'tag', source, image.reference], DEFAULT, runner);
  // No force flag is used: unrelated destination names are never overwritten.
  if (tagged.code !== 0) throw new Error('LIMA_LOCAL_TAG_FAILED');
  await inspectLimaImage(runtime, image, runner);
  return { bound: true, reference: image.reference };
}

export async function inspectLimaImage(runtime: LimaRuntime, image: ImageReceipt, runner: Runner = runCommand): Promise<string> {
  const result = await limaCommand(runtime, ['image', 'inspect', '--mode=native', image.reference], DEFAULT, runner);
  const identity = result.code === 0 ? limaImageIdentity(json(result.stdout), image, runtime.receipt.architecture) : undefined;
  if (!identity) throw new Error('LIMA_IMAGE_IDENTITY_INVALID');
  return identity;
}

/** nerdctl's native volume inspect omits Driver; require its separate native
 * inventory to attest the local driver under the same admitted guest. */
export function limaVolumeIdentity(value: unknown, inventory: unknown, expected: { name: string; jobId: string }): string | undefined {
  const item = Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined;
  const source = item?.Mountpoint;
  if (item?.Name !== expected.name || object(item.Labels)?.['io.ud-agent.job'] !== expected.jobId || typeof source !== 'string' || !absoluteGuest(source) || item.Driver !== undefined && item.Driver !== 'local' || !Array.isArray(inventory) || inventory.length > 10_000) return undefined;
  const matching = inventory.map(object).filter(row => row?.Name === expected.name);
  if (matching.length !== 1 || matching[0]?.Driver !== 'local' || matching[0].Mountpoint !== source) return undefined;
  return source;
}

/** The command itself forbids pulls; an inspection/create race fails locally. */
export function limaCreateArguments(job: { name: string; jobId: string; image: string; volume: string; command: readonly string[]; readOnlyInput: boolean; seccompFromStdin?: boolean }): string[] {
  if (!/^ud-agent-[0-9a-f-]{36}-(?:loader|worker)$/.test(job.name) || !/^[0-9a-f-]{36}$/.test(job.jobId)
      || !/^ud-agent-[0-9a-f-]{36}-input$/.test(job.volume) || !/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(job.image)
      || job.command.length < 1 || job.command.some(value => value.includes('\0'))) throw new Error('LIMA_JOB_INVALID');
  return ['create', '--name', job.name, '--label', `io.ud-agent.job=${job.jobId}`, '--pull=never', '--interactive',
    '--user', '10001:10001', '--workdir', '/work', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    ...(job.seccompFromStdin ? ['--security-opt', 'seccomp=/dev/stdin'] : []),
    '--memory', '2147483648', '--cpus', '2', '--pids-limit', '128', '--ulimit', 'nofile=1024:1024',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=67108864', '--mount', `type=volume,src=${job.volume},dst=/input${job.readOnlyInput ? ',readonly' : ''}`,
    '--entrypoint', '/usr/local/bin/python', job.image, ...job.command];
}

/** Inspect exact OCI configuration rather than relying on accepted CLI flags. */
function trustedHooks(value: unknown, runtime: LimaRuntime): boolean {
  if (!issued.has(runtime)) return false;
  const hooks = object(value), receipt = runtime.receipt;
  if (!hooks || Object.keys(hooks).some(key => !['createRuntime', 'poststop'].includes(key))) return false;
  const prefix = [`--H=${receipt.address}`, `--a=${receipt.address}`, `--address=${receipt.address}`, '--cgroup-manager=systemd', `--host=${receipt.address}`, '--n=ud-agent', '--namespace=ud-agent', '--snapshotter=overlayfs', 'internal', 'oci-hook'];
  const fixedEnv = [`HOME=${receipt.guestHome}`, `XDG_RUNTIME_DIR=/run/user/${receipt.guestUid}`, 'LANG=C', 'NERDCTL_TOML=/dev/null', 'PWD=/', `ROOTLESSKIT_STATE_DIR=/run/user/${receipt.guestUid}/containerd-rootless`, `ROOTLESSKIT_PARENT_EUID=${receipt.guestUid}`, `ROOTLESSKIT_PARENT_EGID=${receipt.guestUid}`, 'PATH=/usr/local/bin:/usr/bin:/bin', 'PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'];
  for (const [kind, action] of [['createRuntime', 'createRuntime'], ['poststop', 'postStop']]) {
    const values = hooks[kind!]; if (!Array.isArray(values) || values.length !== 1) return false;
    const hook = object(values[0]); if (!hook || Object.keys(hook).some(key => !['path', 'args', 'env'].includes(key))) return false;
    const wrapper = hook.path === receipt.nerdctl ? [receipt.nerdctl] : receipt.nsenter && receipt.nsenterSha256 && hook.path === receipt.nsenter ? [receipt.nsenter, `-n/run/user/${receipt.guestUid}/containerd-rootless/netns`, '-F', '--', receipt.nerdctl] : undefined;
    if (!wrapper || JSON.stringify(hook.args) !== JSON.stringify([...wrapper, ...prefix, action]) || !Array.isArray(hook.env) || hook.env.some(value => typeof value !== 'string')) return false;
    const environment = hook.env as string[];
    if (fixedEnv.some(value => environment.filter(item => item === value).length !== 1)) return false;
    const remaining = environment.filter(value => !fixedEnv.includes(value));
    if (remaining.length > 1 || remaining.some(value => !/^NERDCTL_HOST_GATEWAY_IP=(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.slice(value.indexOf('=') + 1).split('.').some(octet => Number(octet) > 255))) return false;
  }
  return true;
}

export function inspectLimaJob(value: unknown, expected: { id: string; jobId: string; image: string; command: readonly string[]; readOnlyInput: boolean; inputSource?: string; runtime?: LimaRuntime; seccomp?: Record<string, unknown> }): string[] {
  const item = Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined;
  const failures: string[] = []; const spec = object(item?.Spec); const processConfig = object(spec?.process); const user = object(processConfig?.user);
  const linux = object(spec?.linux); const resources = object(linux?.resources); const caps = object(processConfig?.capabilities);
  if (!item || item.ID !== expected.id || item.Image !== expected.image || object(item.Labels)?.['io.ud-agent.job'] !== expected.jobId) failures.push('identity');
  if (object(spec?.root)?.readonly !== true || user?.uid !== 10001 || user.gid !== 10001 || processConfig?.noNewPrivileges !== true || processConfig.terminal !== undefined && processConfig.terminal !== false || processConfig.cwd !== '/work'
      || JSON.stringify(processConfig.args) !== JSON.stringify(['/usr/local/bin/python', ...expected.command])) failures.push('process');
  if (!caps || Object.keys(caps).some(key => !['bounding', 'effective', 'inheritable', 'permitted', 'ambient'].includes(key)) || ['bounding', 'effective', 'inheritable', 'permitted', 'ambient'].some(key => caps[key] !== undefined && (!Array.isArray(caps[key]) || (caps[key] as unknown[]).length !== 0))) failures.push('capabilities');
  if (user?.additionalGids !== undefined && (!Array.isArray(user.additionalGids) || user.additionalGids.some(gid => gid !== 10001))) failures.push('supplementary_groups');
  const namespaces = Array.isArray(linux?.namespaces) ? linux.namespaces.map(object) : [];
  for (const kind of ['pid', 'ipc', 'network', 'user', 'cgroup']) {
    const inheritedUser = kind === 'user' && expected.runtime && issued.has(expected.runtime) && namespaces.every(value => value?.type !== 'user') && linux?.uidMappings == null && linux?.gidMappings == null;
    if (!inheritedUser && namespaces.filter(value => value?.type === kind && value.path === undefined).length !== 1) failures.push(`namespace_${kind}`);
  }
  if (expected.seccomp ? !equalLimaSeccomp(linux?.seccomp, expected.seccomp) : !object(linux?.seccomp) || object(linux?.seccomp)?.defaultAction !== 'SCMP_ACT_ERRNO') failures.push('seccomp');
  const cpu = object(resources?.cpu);
  if (object(resources?.memory)?.limit !== 2147483648 || object(resources?.pids)?.limit !== 128 || !Number.isSafeInteger(cpu?.quota) || !Number.isSafeInteger(cpu?.period) || (cpu?.period as number) <= 0 || (cpu?.quota as number) <= 0 || (cpu?.quota as number) > (cpu?.period as number) * 2) failures.push('limits');
  const mounts = Array.isArray(spec?.mounts) ? spec.mounts.map(object) : [];
  const input = mounts.filter(value => value?.destination === '/input'); const tmp = mounts.filter(value => value?.destination === '/tmp');
  const inputOptions = input[0]?.options;
  const writableNativeBind = !expected.readOnlyInput && input[0]?.type === 'none' && Array.isArray(inputOptions) && inputOptions.length === 1 && inputOptions[0] === 'rbind';
  const recursiveReadonlyBind = expected.readOnlyInput && input[0]?.type === 'none' && Array.isArray(inputOptions) && inputOptions.length === 2 && inputOptions.includes('rbind') && inputOptions.includes('rro');
  const oppositeMode = Array.isArray(inputOptions) && (expected.readOnlyInput ? inputOptions.includes('rw') : inputOptions.includes('ro') || inputOptions.includes('rro'));
  if (input.length !== 1 || !expected.inputSource || input[0]?.source !== expected.inputSource || !Array.isArray(inputOptions) || oppositeMode || !(inputOptions as unknown[]).includes(expected.readOnlyInput ? 'ro' : 'rw') && !writableNativeBind && !recursiveReadonlyBind) failures.push('input');
  if (tmp.length !== 1 || tmp[0]?.type !== 'tmpfs' || !Array.isArray(tmp[0]?.options) || !['nosuid', 'nodev', 'noexec'].every(flag => (tmp[0]?.options as unknown[]).includes(flag))) failures.push('scratch');
  if (spec?.hooks !== undefined && Object.values(object(spec.hooks) ?? { invalid: true }).some(value => !Array.isArray(value) || value.length !== 0) && (!expected.runtime || !trustedHooks(spec.hooks, expected.runtime))) failures.push('hooks');
  return failures;
}
