import { afterAll, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { supervisedCommand } from '../../packages/runtime-manager/src/supervised-command.js';

const guardRoot = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-supervised-native-')));
const guard = path.join(guardRoot, process.platform === 'win32' ? 'guard.exe' : 'guard');
await writeFile(guard, await readFile(path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'))); await chmod(guard, 0o500);
afterAll(async () => { await rm(guardRoot, { recursive: true, force: true }); });
// Hosted tool caches can expose Node as mode 0777. The native guardian must
// keep rejecting those shared inodes; execute an exact private fixture copy.
// Keep already-safe installations in place: some use prefix-relative libraries.
const original = await realpath(process.execPath);
const privateCopy = process.platform !== 'win32' && ((await stat(original)).mode & 0o022) !== 0;
const executable = privateCopy ? path.join(guardRoot, 'node') : original;
if (privateCopy) { await copyFile(original, executable); await chmod(executable, 0o500); }
const digest = async (file: string) => `sha256:${createHash('sha256').update(await readFile(file)).digest('hex')}`;
const authority = { guard, guardSha256: await digest(guard), executableSha256: await digest(original) };
const environment = { PATH: process.platform === 'win32' ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/usr/bin:/bin', ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot } : {}), LANG: 'C' };
const limits = { timeoutMs: 5000, maxStdoutBytes: 1024 * 1024, maxStderrBytes: 1024, maxInputBytes: 8 * 1024 * 1024 };

it('real native guardian closes child stdin at END while retaining its separate lifetime lease', async () => {
  const bytes = Buffer.from([0, 1, 255, 10, 13]);
  async function* input() { yield bytes; }
  const result = await supervisedCommand(executable, ['-e', 'const chunks=[];process.stdin.on("data",b=>chunks.push(b));process.stdin.on("end",()=>{process.stdout.write(Buffer.concat(chunks));process.stderr.write("independent native stderr")});'], input(), authority, limits, environment);
  expect(result.code).toBe(0); expect(result.stdout).toEqual(bytes); expect(result.stderr.toString()).toBe('independent native stderr');
}, 20000);

it('real native guardian cancels promptly when multi-MiB input is blocked by a child that never reads', async () => {
  // Arm the abort when the guardian first pulls input (after spawn), so a slow
  // pre-spawn executable verification cannot turn this into a pre-launch cancel.
  let timer: ReturnType<typeof setTimeout> | undefined;
  async function* input() { timer = setTimeout(() => controller.abort(), 200); yield Buffer.alloc(4 * 1024 * 1024, 65); }
  const controller = new AbortController();
  let abortedAt: number | undefined;
  controller.signal.addEventListener('abort', () => { abortedAt = performance.now(); }, { once: true });
  try { await expect(supervisedCommand(executable, ['-e', 'setInterval(()=>{},1000)'], input(), authority, limits, environment, controller.signal)).rejects.toThrow('SUPERVISED_COMMAND_CANCELLED'); }
  finally { clearTimeout(timer); }
  // Cancellation latency starts at the actual abort; hashing the guardian and
  // executable is setup and must not consume the cleanup latency assertion.
  expect(abortedAt).toBeDefined();
  expect(performance.now() - abortedAt!).toBeLessThan(3000);
}, 20000);

it('a successful engine exit cannot suppress a producer tail type failure', async () => {
  async function* failedInput() { await new Promise(resolve => setTimeout(resolve, 150)); throw new TypeError('independent producer tail failure'); yield Buffer.alloc(0); }
  await expect(supervisedCommand(executable, ['-e', 'process.exit(0)'], failedInput(), authority, limits, environment)).rejects.toBeInstanceOf(TypeError);
}, 20000);

it('a successful engine exit rejects an unfinished source with its specific bounded completion error', async () => {
  async function* heldInput() { await new Promise(() => {}); yield Buffer.alloc(0); }
  // Executable/guardian byte verification precedes the native execution
  // budget. Its duration under concurrent CI I/O is not the completion grace.
  // The exact incomplete-input error distinguishes that grace from the native
  // timeout or the cleanup watchdog; either wrong outcome fails this assertion.
  await expect(supervisedCommand(executable, ['-e', 'process.exit(0)'], heldInput(), authority, limits, environment)).rejects.toThrow('SUPERVISED_COMMAND_INPUT_INCOMPLETE');
}, 20000);
