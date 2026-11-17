import { spawn } from 'node:child_process';
import path from 'node:path';
import { supervisedCommand } from './supervised-command.js';
import type { CommandSupervisor } from './supervised-command.js';

export type CommandResult = { code: number; stdout: Buffer; stderr: Buffer };
export type CommandOptions = { timeoutMs: number; maxOutputBytes: number; input?: Buffer; signal?: AbortSignal; containersConf?: string; limaHome?: string; supervisor?: CommandSupervisor };

/** Internal engine/guard commands only. Arguments are never interpreted by a shell. */
export async function runCommand(executable: string, args: readonly string[], options: CommandOptions): Promise<CommandResult> {
  if (!path.isAbsolute(executable) || executable.includes('\0')) throw new Error('Executable must be an absolute trusted path.');
  if (args.length > 256 || args.some(arg => typeof arg !== 'string' || arg.includes('\0'))) throw new Error('Invalid command arguments.');
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 600_000) throw new Error('Invalid command timeout.');
  if (!Number.isSafeInteger(options.maxOutputBytes) || options.maxOutputBytes < 1 || options.maxOutputBytes > 64 * 1024 * 1024) throw new Error('Invalid command output limit.');
  if (options.input && options.input.length > 64 * 1024 * 1024) throw new Error('Command input exceeds its byte budget.');
  if (options.containersConf !== undefined && (!path.isAbsolute(options.containersConf) || options.containersConf.includes('\0'))) throw new Error('Container configuration must be an absolute trusted path.');
  if (options.limaHome !== undefined && (!path.isAbsolute(options.limaHome) || options.limaHome.includes('\0'))) throw new Error('Lima storage must be an absolute trusted path.');
  if (options.signal?.aborted) throw new Error('COMMAND_CANCELLED');
  const safeEnv: NodeJS.ProcessEnv = { PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/usr/bin:/bin', LANG: 'C' };
  for (const key of ['HOME', 'USERPROFILE', 'SystemRoot', 'TMPDIR', 'TMP', 'TEMP', 'USER', 'LOGNAME'] as const) {
    if (process.env[key] !== undefined) safeEnv[key] = process.env[key];
  }
  if (options.containersConf !== undefined) safeEnv.CONTAINERS_CONF = options.containersConf;
  if (options.limaHome !== undefined) safeEnv.LIMA_HOME = options.limaHome;
  if (options.supervisor) {
    async function* input() { if (options.input) yield options.input; }
    try { return await supervisedCommand(executable, args, input(), options.supervisor, { timeoutMs: options.timeoutMs, maxStdoutBytes: options.maxOutputBytes, maxStderrBytes: options.maxOutputBytes, maxInputBytes: 64 * 1024 * 1024 }, safeEnv, options.signal); }
    catch (error) { const value = (error as Error).message; const mapped = value === 'SUPERVISED_COMMAND_CANCELLED' ? 'COMMAND_CANCELLED' : value === 'SUPERVISED_COMMAND_TIMEOUT' ? 'COMMAND_TIMEOUT' : value === 'SUPERVISED_COMMAND_OUTPUT_LIMIT' ? 'COMMAND_OUTPUT_LIMIT' : undefined; if (mapped) throw new Error(mapped, { cause: error }); throw error; }
  }
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [...args], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: safeEnv });
    const stdout: Buffer[] = []; const stderr: Buffer[] = [];
    let outputBytes = 0; let failure: Error | undefined;
    const stop = (error: Error) => { failure ??= error; child.kill('SIGKILL'); child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy(); };
    const timer = setTimeout(() => stop(new Error('COMMAND_TIMEOUT')), options.timeoutMs);
    const onAbort = () => stop(new Error('COMMAND_CANCELLED'));
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    const capture = (destination: Buffer[]) => (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > options.maxOutputBytes) { stop(new Error('COMMAND_OUTPUT_LIMIT')); return; }
      destination.push(chunk);
    };
    child.stdout.on('data', capture(stdout));
    child.stderr.on('data', capture(stderr));
    child.stdin.on('error', error => { if ((error as NodeJS.ErrnoException).code !== 'EPIPE') failure ??= error; });
    child.once('error', error => { failure ??= error; });
    child.stdin.end(options.input);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
      if (failure) return reject(failure);
      if (signal || code === null) return reject(new Error(`COMMAND_TERMINATED: ${signal ?? 'unknown'}`));
      resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
  });
}
