import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { verifyArchive } from './receipt.js';
import type { ImageReceipt } from './receipt.js';
import { inspectWslcClient } from './wslc-inspection.js';
import { runCommand } from './command.js';
import type { CommandOptions, CommandResult } from './command.js';
import { saveWslcSession, writeWslcSessionIntent } from './wslc-state.js';

type Runner = typeof runCommand;
export type WslcRuntimeReceipt = { schema_version: 1; executable: string; binarySha256: string; sdk: string; sdkSha256: string; guard: string; guardSha256?: string; storage: string; architecture: 'amd64' | 'arm64' };
export type WslcSessionIdentity = { id: string; creatorPid: number };
export type WslcRuntime = Readonly<{ engine: 'wslc'; receipt: Readonly<WslcRuntimeReceipt>; session: string; sessionIdentity: Readonly<WslcSessionIdentity>; rootless: null; isolation_model: 'managed-wsl-vm' }>;
type SessionControl = { close: () => Promise<void>; alive: () => boolean; creatorPid?: number };
const issued = new WeakMap<object, SessionControl>();
const SHA = /^sha256:[0-9a-f]{64}$/;
const OPTIONS = { timeoutMs: 30_000, maxOutputBytes: 16 * 1024 * 1024 };
export function isWslcRuntimeAlive(runtime: WslcRuntime): boolean { return issued.get(runtime)?.alive() === true; }
function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function supervisedRunner(receipt: WslcRuntimeReceipt, runner: Runner): Runner { if (receipt.guardSha256 === undefined) return runner; if (!SHA.test(receipt.guardSha256)) throw new Error('WSLC_SUPERVISOR_RECEIPT_INVALID'); return (executable, args, options) => runner(executable, args, { ...options, supervisor: { guard: receipt.guard, guardSha256: receipt.guardSha256!, executableSha256: receipt.binarySha256 } }); }
export function wslcText(bytes: Buffer): string { return new TextDecoder(bytes.length >= 2 && (bytes[0] === 0xff && bytes[1] === 0xfe || bytes[1] === 0) ? 'utf-16le' : 'utf-8', { fatal: true }).decode(bytes); }
export function wslcSessionIdentity(value: unknown, name: string): WslcSessionIdentity | undefined {
  const sessions = object(object(value)?.Server)?.Sessions;
  if (!Array.isArray(sessions) || sessions.length > 10000) throw new Error('WSLC_SESSION_INSPECTION_INVALID');
  const ids = new Set<string>(); let selected: WslcSessionIdentity | undefined;
  for (const raw of sessions) {
    const item = object(raw); const id = typeof item?.ID === 'string' && /^[1-9][0-9]{0,19}$/.test(item.ID) ? item.ID : Number.isSafeInteger(item?.ID) && (item!.ID as number) > 0 ? String(item!.ID) : undefined;
    if (!item || !id || ids.has(id) || typeof item.Name !== 'string' || item.Name.length > 512 || !Number.isSafeInteger(item.CreatorPid) || (item.CreatorPid as number) < 1 || (item.CreatorPid as number) > 0xffffffff) throw new Error('WSLC_SESSION_INSPECTION_INVALID');
    ids.add(id); if (item.Name === name) { if (selected) throw new Error('WSLC_SESSION_INSPECTION_INVALID'); selected = { id, creatorPid: item.CreatorPid as number }; }
  }
  return selected;
}
async function inspectSession(receipt: WslcRuntimeReceipt, name: string, runner: Runner, options = OPTIONS): Promise<WslcSessionIdentity> {
  const inspected = await runner(receipt.executable, wslcArguments({ session: name }, ['system', 'info', '--format', 'json']), options);
  if (inspected.code !== 0) throw new Error('WSLC_OWNED_SESSION_NOT_RUNNING');
  const identity = wslcSessionIdentity(JSON.parse(wslcText(inspected.stdout)), name);
  if (!identity) throw new Error('WSLC_OWNED_SESSION_NOT_RUNNING'); return identity;
}

/** Only the owned session is selected. Never let wslc implicitly make a default. */
export function wslcArguments(runtime: Pick<WslcRuntime, 'session'>, args: readonly string[]): string[] {
  if (!/^ud-agent-[0-9a-f-]{36}$/.test(runtime.session) || args.length === 0 || args.some(value => value.includes('\0'))) throw new Error('WSLC_COMMAND_INVALID');
  return ['--session', runtime.session, ...args];
}

async function startSession(receipt: WslcRuntimeReceipt, session: string, signal?: AbortSignal): Promise<SessionControl> {
  if (signal?.aborted) throw new Error('WSLC_SETUP_CANCELLED');
  if (process.platform !== 'win32') throw new Error('WSLC_WINDOWS_NATIVE_REQUIRED');
  return new Promise((resolve, reject) => {
    const child = spawn(receipt.guard, ['wsl-session', '--sdk', receipt.sdk, '--sdk-sha256', receipt.sdkSha256.slice(7), '--storage', receipt.storage, '--name', session], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows', PATH: `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32`, LANG: 'C' } });
    let output = ''; let stderr = ''; let ready = false; let closed = false; let cancelled = false; let end: ((error?: Error) => void) | undefined;
    // EOF asks the native SDK owner to terminate and verify its session. Keep
    // the owner alive until that cleanup finishes, including a create in flight.
    const abort = () => { cancelled = true; child.stdin.end(); }; signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
    const timeout = setTimeout(() => { child.kill(); reject(new Error('WSLC_SESSION_TIMEOUT')); }, 300_000);
    child.stdout.on('data', (chunk: Buffer) => {
      output += chunk.toString('utf8'); if (output.length > 4096) { child.kill(); return; }
      if (!ready && output.endsWith('\n')) {
        let value: Record<string, unknown> | undefined; try { value = object(JSON.parse(output)); } catch { /* Rejected below. */ }
        if (value?.schema_version !== 1 || value.ready !== true || value.session !== session || value.cpu_count !== 2 || value.memory_mb !== 2048 || value.rootless !== null) { child.kill(); reject(new Error('WSLC_SESSION_RESPONSE_INVALID')); return; }
        if (cancelled) { child.stdin.end(); return; }
        ready = true; clearTimeout(timeout); signal?.removeEventListener('abort', abort); let closure: Promise<void> | undefined;
        resolve({ ...(child.pid ? { creatorPid: child.pid } : {}), alive: () => !closed, close: () => closure ??= new Promise<void>((done, fail) => {
          if (closed) { fail(new Error('WSLC_SESSION_ENDED_UNEXPECTEDLY')); return; }
          const timer = setTimeout(() => { child.kill(); fail(new Error('WSLC_SESSION_CLEANUP_UNVERIFIED')); }, 35_000);
          end = error => { clearTimeout(timer); if (error) fail(error); else done(); }; child.stdin.end();
        }) });
      }
    });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); if (stderr.length > 65536) child.kill(); });
    child.stdin.on('error', () => { /* Native exit is authoritative. */ });
    child.once('error', error => { clearTimeout(timeout); signal?.removeEventListener('abort', abort); if (ready) end?.(error); else reject(error); });
    child.once('close', code => { closed = true; clearTimeout(timeout); signal?.removeEventListener('abort', abort); const error = code === 0 ? undefined : new Error(`WSLC_SESSION_FAILED: ${stderr.trim()}`); if (ready) end?.(error); else reject(error ?? new Error(cancelled ? 'WSLC_SETUP_CANCELLED' : 'WSLC_SESSION_ENDED_BEFORE_READY')); });
  });
}

/** Setup owns the session and storage; administrator prerequisites are never installed here. */
export async function admitWslcRuntime(receipt: WslcRuntimeReceipt, runner: Runner = runCommand, sessionStarter = startSession, signal?: AbortSignal): Promise<WslcRuntime> {
  if (signal?.aborted) throw new Error('WSLC_SETUP_CANCELLED');
  if (receipt.schema_version !== 1 || ![receipt.executable, receipt.sdk, receipt.guard, receipt.storage].every(value => path.isAbsolute(value)) || !SHA.test(receipt.binarySha256) || !SHA.test(receipt.sdkSha256) || !['amd64', 'arm64'].includes(receipt.architecture)) throw new Error('WSLC_RUNTIME_RECEIPT_INVALID');
  runner = supervisedRunner(receipt, runner);
  const client = await inspectWslcClient({ executable: receipt.executable, expectedSha256: receipt.binarySha256, host: { platform: 'win32', arch: receipt.architecture === 'amd64' ? 'x64' : 'arm64' }, runner });
  if (client.status !== 'client_present_unverified') throw new Error(`WSLC_CLIENT_PREREQUISITE: ${client.reason}`);
  await verifyArchive(receipt.sdk, receipt.sdkSha256);
  if (signal?.aborted) throw new Error('WSLC_SETUP_CANCELLED');
  const session = `ud-agent-${randomUUID()}`; const ownership = await writeWslcSessionIntent(receipt, session); const control = await sessionStarter(receipt, session, signal);
  if (signal?.aborted) { await control.close(); throw new Error('WSLC_SETUP_CANCELLED'); }
  let sessionIdentity: WslcSessionIdentity;
  try { sessionIdentity = await inspectSession(receipt, session, runner); if (control.creatorPid !== undefined && sessionIdentity.creatorPid !== control.creatorPid) throw new Error('WSLC_SESSION_CREATOR_CHANGED'); }
  catch (error) { await control.close(); throw error; }
  const runtime: WslcRuntime = Object.freeze({ engine: 'wslc', receipt: Object.freeze({ ...receipt }), session, sessionIdentity: Object.freeze(sessionIdentity), rootless: null, isolation_model: 'managed-wsl-vm' });
  ownership.phase = 'active'; ownership.identity = sessionIdentity;
  try { await saveWslcSession(receipt, ownership); } catch (error) { await control.close(); throw error; }
  issued.set(runtime, { ...control, close: async () => { await control.close(); ownership.phase = 'terminated'; await saveWslcSession(receipt, ownership); } }); return runtime;
}

export async function closeWslcRuntime(runtime: WslcRuntime): Promise<void> { const control = issued.get(runtime); if (!control) throw new Error('WSLC_AUTHORITY_REQUIRED'); await control.close(); issued.delete(runtime); }
/** Reuse a previously probed, private-state-bound session without creating one. */
export async function adoptWslcRuntime(receipt: WslcRuntimeReceipt, session: string, runner: Runner = runCommand, expected?: WslcSessionIdentity): Promise<WslcRuntime> {
  if (!/^ud-agent-[0-9a-f-]{36}$/.test(session)) throw new Error('WSLC_SESSION_IDENTITY_INVALID');
  runner = supervisedRunner(receipt, runner);
  await verifyArchive(receipt.executable, receipt.binarySha256); await verifyArchive(receipt.sdk, receipt.sdkSha256);
  const sessionIdentity = await inspectSession(receipt, session, runner);
  if (expected && (sessionIdentity.id !== expected.id || sessionIdentity.creatorPid !== expected.creatorPid)) throw new Error('WSLC_SESSION_IDENTITY_CHANGED');
  const runtime: WslcRuntime = Object.freeze({ engine: 'wslc', receipt: Object.freeze({ ...receipt }), session, sessionIdentity: Object.freeze(sessionIdentity), rootless: null, isolation_model: 'managed-wsl-vm' });
  issued.set(runtime, { alive: () => true, close: async () => { throw new Error('WSLC_SESSION_NOT_CREATED_BY_THIS_COORDINATOR'); } });
  return runtime;
}
export async function wslcCommand(runtime: WslcRuntime, args: readonly string[], options: CommandOptions = OPTIONS, runner: Runner = runCommand): Promise<CommandResult> {
  const control = issued.get(runtime); if (!control || !control.alive()) throw new Error('WSLC_AUTHORITY_REQUIRED');
  runner = supervisedRunner(runtime.receipt, runner);
  await verifyArchive(runtime.receipt.executable, runtime.receipt.binarySha256); await verifyArchive(runtime.receipt.sdk, runtime.receipt.sdkSha256);
  const actual = await inspectSession(runtime.receipt, runtime.session, runner, options);
  if (actual.id !== runtime.sessionIdentity.id || actual.creatorPid !== runtime.sessionIdentity.creatorPid) throw new Error('WSLC_SESSION_IDENTITY_CHANGED');
  const result = await runner(runtime.receipt.executable, wslcArguments(runtime, args), options);
  if (!control.alive()) throw new Error('WSLC_SESSION_ENDED_UNEXPECTEDLY');
  await verifyArchive(runtime.receipt.executable, runtime.receipt.binarySha256); return { ...result, stdout: Buffer.from(wslcText(result.stdout)), stderr: Buffer.from(wslcText(result.stderr)) };
}

export function wslcCreateArguments(job: { name: string; jobId: string; image: string; volume: string; readOnlyInput: boolean; command: readonly string[] }): string[] {
  if (!/^ud-agent-[0-9a-f-]{36}-(?:loader|worker)$/.test(job.name) || !/^[0-9a-f-]{36}$/.test(job.jobId) || !/^ud-agent-[0-9a-f-]{36}-input$/.test(job.volume) || !/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(job.image) || job.command.length === 0) throw new Error('WSLC_JOB_INVALID');
  // WSLc does not implement --read-only or --security-opt. Its fixed worker
  // entrypoint installs and verifies its own Landlock/seccomp protections.
  return ['container', 'create', '--name', job.name, '--label', `io.ud-agent.job=${job.jobId}`, '--pull', 'never', '--interactive', '--user', '10001:10001', '--workdir', '/work',
    '--network', 'none', '--cap-drop', 'ALL', '--memory', '2147483648', '--cpus', '2', '--ulimit', 'nproc=128:128', '--ulimit', 'nofile=1024:1024', '--no-healthcheck',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=67108864', '--mount', `type=volume,source=${job.volume},target=/input${job.readOnlyInput ? ',readonly' : ''}`,
    '--entrypoint', '/usr/local/bin/python', job.image, ...job.command];
}

/** WSL emits the Docker inspect data model, but lacks Docker-only controls. */
export function inspectWslcJob(value: unknown, expected: { id: string; name: string; jobId: string; imageId: string; volume: string; command: readonly string[]; readOnlyInput: boolean }): string[] {
  const item = Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined; const config = object(item?.Config); const host = object(item?.HostConfig); const failures: string[] = [];
  if (!item || item.Id !== expected.id || item.Name !== `/${expected.name}` || item.Image !== expected.imageId || object(config?.Labels)?.['io.ud-agent.job'] !== expected.jobId) failures.push('identity');
  if (config?.User !== '10001:10001' || config.Tty !== false || config.OpenStdin !== true || JSON.stringify(config.Entrypoint) !== JSON.stringify(['/usr/local/bin/python']) || JSON.stringify(config.Cmd) !== JSON.stringify(expected.command)) failures.push('process');
  if (host?.Privileged !== false || host.NetworkMode !== 'none' || !Array.isArray(host.CapDrop) || !host.CapDrop.includes('ALL') || Array.isArray(host.CapAdd) && host.CapAdd.length !== 0 || Array.isArray(host.Devices) && host.Devices.length !== 0) failures.push('isolation');
  if (host?.Memory !== 2147483648 || host.NanoCpus !== 2_000_000_000) failures.push('limits');
  const mounts = Array.isArray(item?.Mounts) ? item.Mounts.map(object).filter(value => value?.Type !== 'tmpfs') : [];
  if (mounts.length !== 1 || mounts[0]?.Type !== 'volume' || mounts[0].Name !== expected.volume || mounts[0].Destination !== '/input' || mounts[0].RW !== !expected.readOnlyInput) failures.push('input');
  return failures;
}
