import { spawn } from 'node:child_process';
import path from 'node:path';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { supervisedCommand } from './supervised-command.js';
import type { CommandSupervisor } from './supervised-command.js';

/** Bounded streaming transport; input bytes never pass through shell or argv. */
export async function streamCommand(executable: string, args: readonly string[], input: AsyncIterable<Buffer>, signal?: AbortSignal, environment?: { limaHome?: string; supervisor?: CommandSupervisor }): Promise<Buffer> {
  if (!path.isAbsolute(executable) || args.length > 256 || args.some(value => value.includes('\0'))) throw new Error('STREAM_COMMAND_INVALID');
  if (signal?.aborted) throw new Error('WORKER_CANCELLED');
  const env: NodeJS.ProcessEnv = { PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/usr/bin:/bin', LANG: 'C' };
  for (const name of ['HOME', 'USERPROFILE', 'SystemRoot', 'TMPDIR', 'TMP', 'TEMP', 'USER', 'LOGNAME'] as const) if (process.env[name] !== undefined) env[name] = process.env[name];
  if (environment?.limaHome !== undefined) { if (!path.isAbsolute(environment.limaHome) || environment.limaHome.includes('\0')) throw new Error('STREAM_COMMAND_ENVIRONMENT_INVALID'); env.LIMA_HOME = environment.limaHome; }
  if (environment?.supervisor) {
    let result;
    try { result = await supervisedCommand(executable, args, input, environment.supervisor, { timeoutMs: 300000, maxStdoutBytes: 32 * 1024 * 1024, maxStderrBytes: 1024 * 1024, maxInputBytes: 20 * 1024 * 1024 * 1024 }, env, signal); }
    catch (error) { const value = (error as Error).message; const mapped = value === 'SUPERVISED_COMMAND_CANCELLED' ? 'WORKER_CANCELLED' : value === 'SUPERVISED_COMMAND_TIMEOUT' ? 'WORKER_TIMEOUT' : value === 'SUPERVISED_COMMAND_OUTPUT_LIMIT' ? 'WORKER_OUTPUT_TOO_LARGE' : undefined; if (mapped) throw new Error(mapped, { cause: error }); throw error; }
    if (result.code !== 0) throw new Error('PLATFORM_WORKER_FAILED', { cause: { exit_code: result.code, stderr: result.stderr.toString('utf8').slice(0, 16384) } });
    return result.stdout;
  }
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [...args], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env });
    let failure: Error | undefined; let outputBytes = 0; let stderrBytes = 0; const output: Buffer[] = []; const errors: Buffer[] = []; let code: number | null | undefined; let transferred = false;
    const stop = (error: Error) => { failure ??= error; child.kill('SIGKILL'); child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy(); transferred = true; finish(); };
    const abort = () => stop(new Error('WORKER_CANCELLED')); const timer = setTimeout(() => stop(new Error('WORKER_TIMEOUT')), 300_000);
    signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
    child.stdout.on('data', (bytes: Buffer) => { outputBytes += bytes.length; if (outputBytes > 32 * 1024 * 1024) stop(new Error('WORKER_OUTPUT_TOO_LARGE')); else output.push(bytes); });
    child.stderr.on('data', (bytes: Buffer) => { stderrBytes += bytes.length; if (stderrBytes > 1024 * 1024) stop(new Error('WORKER_OUTPUT_TOO_LARGE')); else errors.push(bytes); });
    child.once('error', error => { failure ??= error; });
    const finish = () => { if (code === undefined || !transferred) return; clearTimeout(timer); signal?.removeEventListener('abort', abort); if (failure) reject(failure); else if (code !== 0) reject(new Error('PLATFORM_WORKER_FAILED', { cause: { exit_code: code, stderr: Buffer.concat(errors).toString('utf8').slice(0, 16384) } })); else resolve(Buffer.concat(output)); };
    async function* bounded() { let count = 0; for await (const chunk of input) { if (!Buffer.isBuffer(chunk)) throw new Error('WORKER_TRANSFER_INVALID'); count += chunk.length; if (count > 20 * 1024 * 1024 * 1024) throw new Error('WORKER_TRANSFER_TOO_LARGE'); yield chunk; } }
    void pipeline(Readable.from(bounded()), child.stdin as Writable).then(() => { transferred = true; finish(); }, error => { transferred = true; stop(error instanceof Error ? error : new Error('WORKER_TRANSFER_FAILED')); finish(); });
    child.once('close', result => { code = result; finish(); });
  });
}
