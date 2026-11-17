import { spawn } from 'node:child_process';
import path from 'node:path';
import type { Writable } from 'node:stream';
import { verifyArchive } from './receipt.js';
import type { CommandResult } from './command.js';

export type CommandSupervisor = { guard: string; guardSha256: string; executableSha256: string };
type Limits = { timeoutMs: number; maxStdoutBytes: number; maxStderrBytes: number; maxInputBytes: number };
const SHA = /^sha256:[0-9a-f]{64}$/;
const MAX_FRAME = 1024 * 1024;
function error(code: string): Error { return Object.assign(new Error(code), { code }); }
export function supervisorFrame(kind: 1 | 2 | 3, data: Buffer = Buffer.alloc(0)): Buffer {
  if (![1, 2, 3].includes(kind) || !Buffer.isBuffer(data) || data.length > MAX_FRAME || kind === 1 && data.length === 0 || kind !== 1 && data.length !== 0) throw error('SUPERVISOR_INPUT_INVALID');
  const header = Buffer.alloc(5); header[0] = kind; header.writeUInt32BE(data.length, 1); return Buffer.concat([header, data]);
}

/** Native guardian retains the child's birth identity through group/job cleanup.
 * Input EOF means cancellation; END_INPUT closes only the actual child's stdin. */
export async function supervisedCommand(executable: string, args: readonly string[], input: AsyncIterable<Buffer>, authority: CommandSupervisor, limits: Limits, environment: NodeJS.ProcessEnv, signal?: AbortSignal): Promise<CommandResult> {
  if (!path.isAbsolute(executable) || !path.isAbsolute(authority.guard) || !SHA.test(authority.guardSha256) || !SHA.test(authority.executableSha256) || args.length > 256 || args.some(value => typeof value !== 'string' || value.includes('\0'))
      || !Number.isSafeInteger(limits.timeoutMs) || limits.timeoutMs < 1 || limits.timeoutMs > 600000 || [limits.maxStdoutBytes, limits.maxStderrBytes].some(value => !Number.isSafeInteger(value) || value < 1 || value > 64 * 1024 * 1024) || !Number.isSafeInteger(limits.maxInputBytes) || limits.maxInputBytes < 0 || limits.maxInputBytes > 20 * 1024 * 1024 * 1024) throw error('SUPERVISOR_AUTHORITY_INVALID');
  if (signal?.aborted) throw error('SUPERVISED_COMMAND_CANCELLED');
  if (!input || typeof input[Symbol.asyncIterator] !== 'function') throw error('SUPERVISOR_INPUT_INVALID');
  const iterator = input[Symbol.asyncIterator]();
  await verifyArchive(authority.guard, authority.guardSha256, signal); await verifyArchive(executable, authority.executableSha256, signal);
  return new Promise((resolve, reject) => {
    const child = spawn(authority.guard, ['stream-supervise', '--executable', executable, '--executable-sha256', authority.executableSha256.slice(7), '--arguments-json', JSON.stringify(args), '--timeout-ms', String(limits.timeoutMs), '--max-input-bytes', String(limits.maxInputBytes), '--max-stdout-bytes', String(limits.maxStdoutBytes), '--max-stderr-bytes', String(limits.maxStderrBytes), '--control-fd', '3'], { shell: false, windowsHide: true, env: environment, stdio: ['pipe', 'pipe', 'pipe', 'pipe'] });
    const control = child.stdio[3] as Writable;
    const stdout: Buffer[] = [], stderr: Buffer[] = []; let stdoutSize = 0, stderrSize = 0, pending = Buffer.alloc(0), nativeErrorSize = 0, nativeDiagnostic = Buffer.alloc(0);
    let result: Record<string, unknown> | undefined, failure: Error | undefined, settled = false, cancelled = false, closed = false, producerComplete = false, deliveryFailed = false;
    let nativeExitCode: number | null | undefined, producerTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (value?: CommandResult, problem?: Error) => {
      if (settled) return; settled = true; clearTimeout(watchdog); clearTimeout(producerTimer); signal?.removeEventListener('abort', abort);
      child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
      control.destroy();
      if (iterator.return) void iterator.return().catch(() => undefined);
      if (problem) {
        if (nativeDiagnostic.length && problem.cause === undefined) problem.cause = new Error(`Native guardian stderr (${nativeErrorSize} bytes; final ${nativeDiagnostic.length} retained; exit ${nativeExitCode ?? 'unavailable'}): ${nativeDiagnostic.toString('utf8')}`);
        reject(problem);
      } else resolve(value!);
    };
    const cancel = () => {
      if (!control.destroyed && !control.writableEnded) control.end();
      if (closed || child.stdin.destroyed || child.stdin.writableEnded) return;
      child.stdin.end(supervisorFrame(3));
    };
    const abort = () => { cancelled = true; cancel(); };
    const watchdog = setTimeout(() => { cancel(); finish(undefined, error('SUPERVISOR_CLEANUP_UNVERIFIED')); }, limits.timeoutMs + 5000);
    signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
    child.stdin.on('error', () => { /* Guardian may close after a verified terminal result. */ });
    control.on('error', () => { /* Terminal native outcome remains authoritative. */ });
    child.once('error', () => { failure = error('SUPERVISOR_START_FAILED'); });
    child.stderr.on('data', (bytes: Buffer) => { nativeErrorSize += bytes.length; nativeDiagnostic = Buffer.from(Buffer.concat([nativeDiagnostic, bytes]).subarray(-8192)); if (nativeErrorSize > 1024 * 1024) { failure = error('SUPERVISOR_RESPONSE_INVALID'); cancel(); } });
    child.stdout.on('data', (chunk: Buffer) => {
      if (settled) return;
      try {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 5) {
          if (result) throw error('SUPERVISOR_RESPONSE_INVALID');
          const kind = pending[0], length = pending.readUInt32BE(1);
          if (![1, 2, 3].includes(kind!) || length > MAX_FRAME || kind === 3 && length > 4096) throw error('SUPERVISOR_RESPONSE_INVALID');
          if (pending.length < 5 + length) break;
          const bytes = pending.subarray(5, 5 + length); pending = pending.subarray(5 + length);
          if (kind === 1) { stdoutSize += length; if (stdoutSize > limits.maxStdoutBytes) throw error('SUPERVISOR_RESPONSE_INVALID'); stdout.push(Buffer.from(bytes)); }
          else if (kind === 2) { stderrSize += length; if (stderrSize > limits.maxStderrBytes) throw error('SUPERVISOR_RESPONSE_INVALID'); stderr.push(Buffer.from(bytes)); }
          else {
            const decoded: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
            if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) throw error('SUPERVISOR_RESPONSE_INVALID');
            result = decoded as Record<string, unknown>;
            if (result.schema_version !== 1 || result.cleanup_verified !== true || result.executable_sha256 !== authority.executableSha256.slice(7) || typeof result.timed_out !== 'boolean' || typeof result.cancelled !== 'boolean' || result.exit_code !== null && (!Number.isSafeInteger(result.exit_code) || (result.exit_code as number) < 0 || (result.exit_code as number) > 0xffffffff) || result.signal !== undefined && (result.exit_code !== null || !Number.isSafeInteger(result.signal) || (result.signal as number) < 1 || (result.signal as number) > 128) || result.error !== undefined && !['output_limit', 'input_limit', 'input_protocol'].includes(result.error as string)) throw error('SUPERVISOR_RESPONSE_INVALID');
          }
        }
      } catch (problem) {
        const code = (problem as NodeJS.ErrnoException)?.code;
        failure = problem instanceof SyntaxError || code === 'ERR_ENCODING_INVALID_ENCODED_DATA' || code === 'SUPERVISOR_RESPONSE_INVALID' ? error('SUPERVISOR_RESPONSE_INVALID') : problem instanceof Error ? problem : error('SUPERVISOR_RESPONSE_INVALID');
        cancel();
      }
    });
    const complete = () => {
      if (!closed || settled) return;
      if (failure) { finish(undefined, failure); return; }
      if (nativeExitCode !== 0 || !result || pending.length !== 0) { finish(undefined, error('SUPERVISOR_CLEANUP_UNVERIFIED')); return; }
      if (cancelled || result.cancelled) { finish(undefined, error('SUPERVISED_COMMAND_CANCELLED')); return; }
      if (result.timed_out) { finish(undefined, error('SUPERVISED_COMMAND_TIMEOUT')); return; }
      if (result.error === 'output_limit') { finish(undefined, error('SUPERVISED_COMMAND_OUTPUT_LIMIT')); return; }
      if (result.error !== undefined) { finish(undefined, error('SUPERVISED_COMMAND_INPUT_INVALID')); return; }
      if (result.exit_code === null) { finish(undefined, error('SUPERVISED_COMMAND_TERMINATED')); return; }
      if (result.exit_code === 0 && !producerComplete) { producerTimer ??= setTimeout(() => finish(undefined, error('SUPERVISED_COMMAND_INPUT_INCOMPLETE')), 1000); return; }
      if (result.exit_code === 0 && deliveryFailed) { finish(undefined, error('SUPERVISED_COMMAND_INPUT_INCOMPLETE')); return; }
      finish({ code: result.exit_code as number, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    };
    child.once('close', code => { closed = true; nativeExitCode = code; complete(); });
    const write = (bytes: Buffer) => new Promise<void>((done, fail) => { child.stdin.write(bytes, problem => problem ? fail(problem) : done()); });
    void (async () => {
      let total = 0;
      for (;;) {
        if (settled || cancelled) return;
        const next = await iterator.next(); if (next.done) { producerComplete = true; complete(); break; }
        if (!Buffer.isBuffer(next.value)) throw error('SUPERVISOR_INPUT_INVALID');
        total += next.value.length; if (total > limits.maxInputBytes) throw error('SUPERVISOR_INPUT_INVALID');
        for (let offset = 0; offset < next.value.length; offset += MAX_FRAME) {
          if (settled || cancelled) return;
          if (closed || deliveryFailed) { deliveryFailed = true; break; }
          try { await write(supervisorFrame(1, next.value.subarray(offset, offset + MAX_FRAME))); }
          catch (problem) { if (!['EPIPE', 'ERR_STREAM_DESTROYED', 'ERR_STREAM_WRITE_AFTER_END'].includes((problem as NodeJS.ErrnoException)?.code ?? '')) throw problem; deliveryFailed = true; break; }
        }
      }
      if (!settled && !cancelled && !closed) await write(supervisorFrame(2));
      // The open guardian input is the lifetime/control lease.
    })().catch(problem => { if (settled || cancelled || ['EPIPE', 'ERR_STREAM_DESTROYED', 'ERR_STREAM_WRITE_AFTER_END'].includes((problem as NodeJS.ErrnoException)?.code ?? '')) return; failure = problem instanceof Error ? problem : error('SUPERVISOR_INPUT_INVALID'); cancel(); complete(); });
  });
}
