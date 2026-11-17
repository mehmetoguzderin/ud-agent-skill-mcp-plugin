import path from 'node:path';
import { lstat } from 'node:fs/promises';
import { runCommand } from './command.js';
import type { Host } from './profiles.js';

export type DockerInspection = {
  status: 'available' | 'unavailable';
  rootless: boolean | null;
  reason: string;
};

function localEndpoint(value: unknown, host: Host): boolean {
  if (typeof value !== 'string' || value.includes('\0')) return false;
  if (host.platform === 'win32') return /^npipe:\/\/\/{1,2}\.\/pipe\/[A-Za-z0-9_.-]+$/i.test(value);
  if (!value.startsWith('unix://')) return false;
  const location = value.slice('unix://'.length);
  return path.posix.isAbsolute(location) && !location.split('/').includes('..');
}

/** Inspect an already-running local Docker daemon without creating resources. */
export async function inspectLocalDocker(executable: string, host: Host, runner: typeof runCommand = runCommand): Promise<DockerInspection> {
  const unavailable = (reason: string): DockerInspection => ({ status: 'unavailable', rootless: null, reason });
  if (!path.isAbsolute(executable)) return unavailable('Docker executable must have an absolute path.');
  try {
    const info = await lstat(executable);
    if (!info.isFile() || info.isSymbolicLink() || (host.platform !== 'win32' && ((info.mode & 0o022) !== 0 || (typeof process.getuid === 'function' && info.uid !== 0 && info.uid !== process.getuid())))) return unavailable('Docker executable is not a trusted regular file.');
    const limits = { timeoutMs: 5_000, maxOutputBytes: 1024 * 1024 };
    const context = await runner(executable, ['context', 'inspect'], limits);
    if (context.code !== 0) return unavailable('Docker context inspection failed.');
    const contexts: unknown = JSON.parse(context.stdout.toString('utf8'));
    if (!Array.isArray(contexts) || contexts.length !== 1 || !contexts[0] || typeof contexts[0] !== 'object') return unavailable('Docker context inspection returned invalid data.');
    const endpoints = (contexts[0] as { Endpoints?: { docker?: { Host?: unknown } } }).Endpoints;
    if (!localEndpoint(endpoints?.docker?.Host, host)) return unavailable('Docker context is not a local Unix socket or Windows named pipe.');
    const result = await runner(executable, ['info', '--format', '{{json .}}'], limits);
    if (result.code !== 0) return unavailable('The local Docker daemon is unavailable.');
    const data: unknown = JSON.parse(result.stdout.toString('utf8'));
    if (!data || typeof data !== 'object' || Array.isArray(data)) return unavailable('Docker returned invalid server information.');
    const server = data as Record<string, unknown>;
    if (typeof server.ServerVersion !== 'string' || server.ServerVersion.length === 0 || !Array.isArray(server.SecurityOptions) || server.SecurityOptions.some(item => typeof item !== 'string')) return unavailable('Docker server information is incomplete.');
    return { status: 'available', rootless: server.SecurityOptions.some(item => item === 'name=rootless' || item.startsWith('name=rootless,')), reason: 'A local Docker daemon answered the read-only inspection.' };
  } catch {
    return unavailable('The bounded local Docker inspection did not complete.');
  }
}
