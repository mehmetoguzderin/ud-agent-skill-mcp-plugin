import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { runEngineCommand as runCommand, withEngineSupervisor, engineSupervisor } from './engine-command.js';
import type { CommandOptions, CommandResult } from '../../runtime-manager/src/command.js';
import { streamCommand } from '../../runtime-manager/src/stream-command.js';
import { loadNativeGuardReceipt, verifyArchive } from '../../runtime-manager/src/receipt.js';
import type { Host } from '../../runtime-manager/src/profiles.js';
import { guardedIdentity, guardedPrivateRead } from '../../workspace/src/guard.js';
import type { GuardIdentity } from '../../workspace/src/guard.js';

export type PodmanVm = Readonly<{ engine: string; engineSha256: string; hostGuard: string; hostGuardSha256: string; machine: string; fingerprint: string; guestUid: number; guestHome: string; guestPodman: string; guestPodmanSha256: string; guestGuard: string; guestGuardSha256: string; bootId: string; architecture: 'arm64' | 'amd64' }>;
const sessions = new WeakSet<object>();
const identities = new WeakMap<object, PodmanVm>();
export function bindPodmanVmIdentity(identity: object, vm: PodmanVm): void { if (!sessions.has(vm)) throw new Error('PODMAN_VM_AUTHORITY_REQUIRED'); identities.set(identity, vm); }
export function podmanVmForIdentity(identity: object | undefined): PodmanVm | undefined { return identity ? identities.get(identity) : undefined; }
const context = new AsyncLocalStorage<PodmanVm>();
const LIMITS: CommandOptions = { timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024 };
const SHA = /^sha256:[0-9a-f]{64}$/;
function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function json(bytes: Buffer): unknown { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error('PODMAN_VM_RESPONSE_INVALID'); } }
function digest(bytes: Buffer): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
export function quotePodmanGuest(value: string): string { if (typeof value !== 'string' || /[\0\r\n]/.test(value)) throw new Error('PODMAN_VM_ARGUMENT_INVALID'); return `'${value.replaceAll("'", "'\\''")}'`; }
function guestPath(value: unknown): value is string { return typeof value === 'string' && path.posix.isAbsolute(value) && path.posix.normalize(value) === value && !/[\0\r\n]/.test(value) && value.split('/').every(part => part !== '..' && part !== '.'); }
function sshArgs(machine: string, args: readonly string[]): string[] { if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(machine) || args.length === 0 || args.length > 220) throw new Error('PODMAN_VM_ARGUMENT_INVALID'); return ['machine', 'ssh', machine, args.map(quotePodmanGuest).join(' ')]; }
async function guest(engine: string, machine: string, args: readonly string[], options: CommandOptions = LIMITS): Promise<CommandResult> { return runCommand(engine, sshArgs(machine, args), options); }

function ownedDirectories(home: string, root: string, uid: number): string {
  if (!guestPath(home) || !guestPath(root) || !root.startsWith(home + '/')) throw new Error('PODMAN_VM_GUEST_PATH_INVALID');
  const values = [home]; let current = home;
  for (const part of root.slice(home.length + 1).split('/')) { current += '/' + part; values.push(current); }
  return 'set -eu; umask 077; ' + values.map((value, index) => `test ! -L ${quotePodmanGuest(value)}; ${index ? `if test ! -e ${quotePodmanGuest(value)}; then mkdir -- ${quotePodmanGuest(value)}; fi; ` : ''}test -d ${quotePodmanGuest(value)}; test "$(/usr/bin/stat -c %u -- ${quotePodmanGuest(value)})" = ${uid}; mode=$(/usr/bin/stat -c %a -- ${quotePodmanGuest(value)}); test "$((0$mode & 022))" = 0`).join('; ') + '; ';
}

async function machineIdentity(engine: string, expected?: string, hostGuard?: string): Promise<{ machine: string; fingerprint: string; username: string }> {
  const result = await runCommand(engine, ['machine', 'inspect', ...(expected ? [expected] : [])], LIMITS);
  const raw = result.code === 0 ? json(result.stdout) : undefined;
  const item = Array.isArray(raw) && raw.length === 1 ? object(raw[0]) : undefined, ssh = object(item?.SSHConfig);
  if (!item || typeof item.Name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(item.Name) || expected && item.Name !== expected || String(item.State).toLowerCase() !== 'running' || item.Rootful !== false || typeof ssh?.RemoteUsername !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(ssh.RemoteUsername) || !Number.isSafeInteger(ssh.Port) || (ssh.Port as number) < 1 || (ssh.Port as number) > 65535 || typeof ssh.IdentityPath !== 'string' && typeof ssh.Identity !== 'string') throw new Error('PODMAN_VM_RUNNING_ROOTLESS_MACHINE_REQUIRED');
  const identity = String(ssh.IdentityPath ?? ssh.Identity);
  if (!path.isAbsolute(identity)) throw new Error('PODMAN_VM_SSH_IDENTITY_UNVERIFIED');
  const stat = await lstat(identity);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024 || process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.())) throw new Error('PODMAN_VM_SSH_IDENTITY_UNVERIFIED');
  // Only a digest is retained; private SSH key bytes never enter workers/results.
  const key = hostGuard ? await guardedPrivateRead(hostGuard, path.dirname(identity), path.basename(identity), 1024 * 1024, await guardedIdentity(hostGuard, path.dirname(identity))) : await readFile(identity);
  const fingerprint = digest(Buffer.from(JSON.stringify({ name: item.Name, created: item.Created, config: item.ConfigDir, port: ssh.Port, user: ssh.RemoteUsername, identity, key_sha256: digest(key) })));
  return { machine: item.Name, fingerprint, username: ssh.RemoteUsername };
}
function environment(home: string, uid: number, config?: string): string[] { return ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', `HOME=${home}`, `XDG_RUNTIME_DIR=/run/user/${uid}`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus`, 'LANG=C', ...(config ? [`CONTAINERS_CONF=${config}`] : [])]; }
async function verifiedGuest(runtime: PodmanVm): Promise<void> {
  if (!sessions.has(runtime)) throw new Error('PODMAN_VM_AUTHORITY_REQUIRED');
  await verifyArchive(runtime.engine, runtime.engineSha256);
  await verifyArchive(runtime.hostGuard, runtime.hostGuardSha256);
  const current = await machineIdentity(runtime.engine, runtime.machine, runtime.hostGuard); if (current.fingerprint !== runtime.fingerprint) throw new Error('PODMAN_VM_IDENTITY_CHANGED');
  const boot = await guest(runtime.engine, runtime.machine, ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']);
  if (boot.code !== 0 || boot.stdout.toString('ascii').trim() !== runtime.bootId) throw new Error('PODMAN_VM_BOOT_CHANGED');
  const hashes = await guest(runtime.engine, runtime.machine, [...environment(runtime.guestHome, runtime.guestUid), '/usr/bin/sha256sum', '--', runtime.guestPodman, runtime.guestGuard]);
  const expected = [`${runtime.guestPodmanSha256.slice(7)}  ${runtime.guestPodman}`, `${runtime.guestGuardSha256.slice(7)}  ${runtime.guestGuard}`];
  if (hashes.code !== 0 || JSON.stringify(hashes.stdout.toString('utf8').trimEnd().split('\n')) !== JSON.stringify(expected)) throw new Error('PODMAN_VM_EXECUTABLE_CHANGED');
}

/** Read-only VM availability; no guest files or services are changed. */
export async function inspectPodmanVm(engine: string, host: Host): Promise<{ machine: string; fingerprint: string; guestUid: number; guestHome: string; guestPodmanSha256: string; bootId: string; architecture: 'arm64' | 'amd64' }> {
  if (!['darwin', 'win32'].includes(host.platform) || !['arm64', 'x64'].includes(host.arch)) throw new Error('PODMAN_VM_HOST_UNSUPPORTED');
  const selected = await machineIdentity(engine);
  const uid = await guest(engine, selected.machine, ['/usr/bin/id', '-u']);
  const guestUid = Number(uid.stdout.toString('ascii').trim());
  if (uid.code !== 0 || !Number.isSafeInteger(guestUid) || guestUid < 1 || guestUid > 0xffff_ffff) throw new Error('PODMAN_VM_GUEST_USER_UNVERIFIED');
  const passwd = await guest(engine, selected.machine, ['/usr/bin/getent', 'passwd', selected.username]);
  const fields = passwd.stdout.toString('utf8').trimEnd().split(':'); const guestHome = fields[5];
  if (passwd.code !== 0 || fields.length !== 7 || Number(fields[2]) !== guestUid || !guestPath(guestHome)) throw new Error('PODMAN_VM_GUEST_HOME_UNVERIFIED');
  const info = await guest(engine, selected.machine, [...environment(guestHome, guestUid), '/usr/bin/podman', '--remote=false', 'info', '--format', 'json']);
  const data = info.code === 0 ? object(json(info.stdout)) : undefined, machine = object(data?.host);
  const architecture = machine?.arch; if (architecture !== 'amd64' && architecture !== 'arm64') throw new Error('PODMAN_VM_GUEST_ARCHITECTURE_UNSUPPORTED');
  if (machine?.os !== 'linux' || machine.arch !== architecture || object(machine.security)?.rootless !== true || machine.cgroupVersion !== 'v2') throw new Error('PODMAN_VM_ROOTLESS_GUEST_REQUIRED');
  const hash = await guest(engine, selected.machine, [...environment(guestHome, guestUid), '/usr/bin/sha256sum', '--', '/usr/bin/podman']);
  const match = /^([0-9a-f]{64})  \/usr\/bin\/podman\n?$/.exec(hash.stdout.toString('ascii'));
  const boot = await guest(engine, selected.machine, ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']);
  const bootId = boot.stdout.toString('ascii').trim();
  if (hash.code !== 0 || !match || boot.code !== 0 || !/^[0-9a-f-]{36}$/.test(bootId)) throw new Error('PODMAN_VM_GUEST_IDENTITY_UNVERIFIED');
  return { machine: selected.machine, fingerprint: selected.fingerprint, guestUid, guestHome, guestPodmanSha256: `sha256:${match[1]}`, bootId, architecture };
}

/** Stage only the pinned Linux guard in product-owned storage, never global installation. */
export async function resolvePodmanVm(sourceRoot: string, engine: string, host: Host, prepare = false): Promise<PodmanVm> {
  const observed = await inspectPodmanVm(engine, host);
  const hostHelper = await loadNativeGuardReceipt(sourceRoot, host);
  const engineInfo = await lstat(engine); if (!engineInfo.isFile() || engineInfo.isSymbolicLink() || engineInfo.size > 512 * 1024 * 1024) throw new Error('PODMAN_VM_HOST_EXECUTABLE_UNVERIFIED');
  const engineSha256 = digest(await readFile(engine));
  return withEngineSupervisor({ engine, guard: hostHelper.guard, guardSha256: hostHelper.guardSha256, executableSha256: engineSha256 }, () => resolvePodmanVmWithEngine(sourceRoot, engine, observed, hostHelper, engineSha256, prepare));
}
async function resolvePodmanVmWithEngine(sourceRoot: string, engine: string, observed: Awaited<ReturnType<typeof inspectPodmanVm>>, hostHelper: Awaited<ReturnType<typeof loadNativeGuardReceipt>>, engineSha256: string, prepare: boolean): Promise<PodmanVm> {
  const privateIdentity = await machineIdentity(engine, observed.machine, hostHelper.guard);
  if (privateIdentity.fingerprint !== observed.fingerprint) throw new Error('PODMAN_VM_IDENTITY_CHANGED');
  const helper = await loadNativeGuardReceipt(sourceRoot, { platform: 'linux', arch: observed.architecture === 'amd64' ? 'x64' : 'arm64' });
  const directory = path.posix.join(observed.guestHome, '.local/share/ud-agent-skill-mcp-plugin/guest', helper.guardSha256.slice(7));
  const guard = path.posix.join(directory, 'ud-agent-guard');
  let checked = await guest(engine, observed.machine, [...environment(observed.guestHome, observed.guestUid), '/usr/bin/sha256sum', '--', guard]);
  if (checked.code !== 0 && prepare) {
    const bytes = await readFile(helper.guard);
    if (bytes.length > 64 * 1024 * 1024 || digest(bytes) !== helper.guardSha256) throw new Error('PODMAN_VM_GUEST_HELPER_INTEGRITY_FAILED');
    const temporary = path.posix.join(directory, `.guard-${randomUUID()}`);
    const script = ownedDirectories(observed.guestHome, directory, observed.guestUid) + `test "$(/usr/bin/stat -c %a -- ${quotePodmanGuest(directory)})" = 700; created=0; cleanup() { if test "$created" = 1; then rm -f -- ${quotePodmanGuest(temporary)}; fi; }; trap cleanup EXIT; set -C; exec 3> ${quotePodmanGuest(temporary)}; set +C; created=1; /usr/bin/cat >&3; exec 3>&-; test "$(/usr/bin/sha256sum -- ${quotePodmanGuest(temporary)} | /usr/bin/cut -d ' ' -f1)" = ${helper.guardSha256.slice(7)}; chmod 500 -- ${quotePodmanGuest(temporary)}; if ! ln -T -- ${quotePodmanGuest(temporary)} ${quotePodmanGuest(guard)}; then test ! -L ${quotePodmanGuest(guard)}; test "$(/usr/bin/sha256sum -- ${quotePodmanGuest(guard)} | /usr/bin/cut -d ' ' -f1)" = ${helper.guardSha256.slice(7)}; fi; rm -- ${quotePodmanGuest(temporary)}; created=0`;
    const installed = await guest(engine, observed.machine, [...environment(observed.guestHome, observed.guestUid), '/bin/sh', '-c', script], { ...LIMITS, input: bytes });
    if (installed.code !== 0) throw new Error('PODMAN_VM_GUEST_HELPER_SETUP_FAILED');
    checked = await guest(engine, observed.machine, [...environment(observed.guestHome, observed.guestUid), '/usr/bin/sha256sum', '--', guard]);
  }
  if (checked.code !== 0) throw new Error('PODMAN_VM_GUEST_HELPER_REQUIRED');
  if (checked.stdout.toString('utf8').trimEnd() !== `${helper.guardSha256.slice(7)}  ${guard}`) throw new Error('PODMAN_VM_GUEST_HELPER_INTEGRITY_FAILED');
  const runtime: PodmanVm = Object.freeze({ engine, engineSha256, hostGuard: hostHelper.guard, hostGuardSha256: hostHelper.guardSha256, machine: observed.machine, fingerprint: observed.fingerprint, guestUid: observed.guestUid, guestHome: observed.guestHome, guestPodman: '/usr/bin/podman', guestPodmanSha256: observed.guestPodmanSha256, guestGuard: guard, guestGuardSha256: helper.guardSha256, bootId: observed.bootId, architecture: observed.architecture });
  sessions.add(runtime); await verifiedGuest(runtime);
  return runtime;
}
export function podmanVmContext(): PodmanVm | undefined { return context.getStore(); }
async function withVmSupervisor<T>(runtime: PodmanVm, operation: () => Promise<T>): Promise<T> {
  if (!sessions.has(runtime)) throw new Error('PODMAN_VM_AUTHORITY_REQUIRED');
  const current = engineSupervisor(runtime.engine);
  if (current) {
    if (current.guard !== runtime.hostGuard || current.guardSha256 !== runtime.hostGuardSha256 || current.executableSha256 !== runtime.engineSha256) throw new Error('PODMAN_VM_HOST_AUTHORITY_CHANGED');
    return operation();
  }
  return withEngineSupervisor({ engine: runtime.engine, guard: runtime.hostGuard, guardSha256: runtime.hostGuardSha256, executableSha256: runtime.engineSha256 }, operation);
}
export async function withPodmanVm<T>(runtime: PodmanVm, operation: () => Promise<T>): Promise<T> { return withVmSupervisor(runtime, async () => { await verifiedGuest(runtime); return context.run(runtime, operation); }); }
export async function podmanVmCommand(runtime: PodmanVm, args: readonly string[], config?: string, options: CommandOptions = LIMITS): Promise<CommandResult> { return withVmSupervisor(runtime, async () => { await verifiedGuest(runtime); return guest(runtime.engine, runtime.machine, [...environment(runtime.guestHome, runtime.guestUid, config), runtime.guestPodman, '--remote=false', ...args], options); }); }
export async function podmanVmStream(runtime: PodmanVm, args: readonly string[], frames: AsyncIterable<Buffer>, config?: string, signal?: AbortSignal): Promise<Buffer> { return withVmSupervisor(runtime, async () => { await verifiedGuest(runtime); return streamCommand(runtime.engine, sshArgs(runtime.machine, [...environment(runtime.guestHome, runtime.guestUid, config), runtime.guestPodman, '--remote=false', ...args]), frames, signal, { supervisor: { guard: runtime.hostGuard, guardSha256: runtime.hostGuardSha256, executableSha256: runtime.engineSha256 } }); }); }
export async function podmanVmGuard(runtime: PodmanVm, args: readonly string[], input?: Buffer, signal?: AbortSignal): Promise<Buffer> { return withVmSupervisor(runtime, async () => { await verifiedGuest(runtime); const result = await guest(runtime.engine, runtime.machine, [...environment(runtime.guestHome, runtime.guestUid), runtime.guestGuard, ...args], { ...LIMITS, maxOutputBytes: 4 * 1024 * 1024, ...(input ? { input } : {}), ...(signal ? { signal } : {}) }); if (result.code !== 0) throw new Error(`PODMAN_VM_GUARD_REJECTED: ${result.stderr.toString('utf8').slice(0, 1024)}`); return result.stdout; }); }
export async function podmanVmDirectoryIdentity(runtime: PodmanVm, root: string): Promise<GuardIdentity> { if (!guestPath(root)) throw new Error('PODMAN_VM_GUEST_PATH_INVALID'); const value = object(json(await podmanVmGuard(runtime, ['identity', '--root', root]))); if (typeof value?.device !== 'string' || !/^\d+$/.test(value.device) || typeof value.inode !== 'string' || !/^\d+$/.test(value.inode)) throw new Error('PODMAN_VM_GUARD_RESPONSE_INVALID'); return { device: value.device, inode: value.inode }; }
export async function podmanVmPrivateDirectory(runtime: PodmanVm, root: string, identity: GuardIdentity, initialize = false): Promise<void> { await podmanVmGuard(runtime, [initialize ? 'state-private-init' : 'state-private-check', '--root', root, '--root-device', identity.device, '--root-inode', identity.inode]); }
export async function podmanVmRead(runtime: PodmanVm, root: string, relative: string, identity: GuardIdentity, maximum: number, signal?: AbortSignal): Promise<Buffer> { if (!guestPath(root) || !relative || relative.startsWith('/') || relative.split('/').some(value => ['.', '..', ''].includes(value)) || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4 * 1024 * 1024) throw new Error('PODMAN_VM_GUEST_PATH_INVALID'); return podmanVmGuard(runtime, ['read', '--root', root, '--path', relative, '--root-device', identity.device, '--root-inode', identity.inode, '--max-bytes', String(maximum)], undefined, signal); }

/** Immutable product policy files; unrelated guest runtimes are never reconfigured. */
export async function podmanVmPolicy(runtime: PodmanVm, seccomp: Buffer): Promise<{ config: string; hooks: string; mounts: string; seccomp: string }> {
  return withVmSupervisor(runtime, () => preparePodmanVmPolicy(runtime, seccomp));
}
async function preparePodmanVmPolicy(runtime: PodmanVm, seccomp: Buffer): Promise<{ config: string; hooks: string; mounts: string; seccomp: string }> {
  await verifiedGuest(runtime);
  const hash = digest(seccomp).slice(7), root = path.posix.join(runtime.guestHome, '.local/share/ud-agent-skill-mcp-plugin/podman-policy', hash);
  const created = await guest(runtime.engine, runtime.machine, [...environment(runtime.guestHome, runtime.guestUid), '/bin/sh', '-c', ownedDirectories(runtime.guestHome, root + '/hooks', runtime.guestUid)]);
  if (created.code !== 0) throw new Error('PODMAN_VM_POLICY_DIRECTORY_FAILED');
  const identity = await podmanVmDirectoryIdentity(runtime, root); await podmanVmPrivateDirectory(runtime, root, identity);
  const files = { 'containers.conf': Buffer.from('[containers]\nmounts = []\n[engine]\nhooks_dir = []\n'), 'mounts.conf': Buffer.alloc(0), 'seccomp.json': seccomp };
  for (const [name, bytes] of Object.entries(files)) {
    const existing = await podmanVmGuard(runtime, ['list', '--root', root, '--path', '.', '--root-device', identity.device, '--root-inode', identity.inode]);
    const names = json(existing); if (!Array.isArray(names)) throw new Error('PODMAN_VM_POLICY_INVENTORY_INVALID');
    if (!names.some(item => object(item)?.name === name)) {
      try { await podmanVmGuard(runtime, ['create', '--root', root, '--path', name, '--root-device', identity.device, '--root-inode', identity.inode, '--max-bytes', '1048576'], bytes); }
      catch (error) { if (!(error instanceof Error) || !error.message.includes('AlreadyExists')) throw error; }
    }
    const actual = await podmanVmRead(runtime, root, name, identity, Math.max(1, bytes.length + 1));
    if (!actual.equals(bytes)) throw new Error('PODMAN_VM_POLICY_INTEGRITY_FAILED');
  }
  const hooks = await podmanVmDirectoryIdentity(runtime, root + '/hooks'); await podmanVmPrivateDirectory(runtime, root + '/hooks', hooks);
  const content = json(await podmanVmGuard(runtime, ['list', '--root', root + '/hooks', '--path', '.', '--root-device', hooks.device, '--root-inode', hooks.inode]));
  if (!Array.isArray(content) || content.length) throw new Error('PODMAN_VM_HOOKS_INJECTED');
  return { config: root + '/containers.conf', mounts: root + '/mounts.conf', hooks: root + '/hooks', seccomp: root + '/seccomp.json' };
}
