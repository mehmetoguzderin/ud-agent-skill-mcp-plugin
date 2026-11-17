/** Original worker lifecycle fault fixtures; no child program is executed. */
import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({ spawn: vi.fn(), capture: vi.fn(), transfer: vi.fn(), cleanup: vi.fn() }));
vi.mock('node:child_process', () => ({ spawn: mocked.spawn }));
vi.mock('../../packages/workspace/src/input-broker.js', () => ({ captureOperationSnapshot: mocked.capture }));
vi.mock('../../packages/workspace/src/snapshot-transfer.js', () => ({ streamVerifiedSnapshot: mocked.transfer }));
vi.mock('../../packages/workspace/src/snapshot-wire.js', () => ({ encodeSnapshotFrames: async function* () { yield Buffer.from('original fixture snapshot'); } }));

import { runUserspaceValidation } from '../../packages/coordinator/src/userspace-worker.js';

it('Windows worker dispatch pins the base and venv files while ignoring ambient Python overrides', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-worker-venv-dispatch-'))), platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
  const prior = Object.fromEntries(['__PYVENV_LAUNCHER__', 'PYTHONHOME', 'PYTHONPATH'].map(key => [key, process.env[key]]));
  const streams = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() };
  try {
    const base = path.join(root, 'base/python.exe'), launcher = path.join(root, 'venv/Scripts/python.exe'), config = path.join(root, 'venv/pyvenv.cfg');
    await mkdir(path.dirname(base)); await mkdir(path.dirname(launcher), { recursive: true });
    await writeFile(base, 'base'); await writeFile(launcher, 'redirector'); const configBytes = `home = ${path.dirname(base)}\n`; await writeFile(config, configBytes);
    Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
    for (const key of Object.keys(prior)) process.env[key] = 'untrusted ambient value';
    const child = Object.assign(new EventEmitter(), streams, { stdio: [streams.stdin, streams.stdout, streams.stderr], exitCode: null as number | null, signalCode: null, kill: vi.fn() });
    mocked.cleanup.mockReset().mockResolvedValue(undefined);
    mocked.capture.mockReset().mockImplementation(async (_guard, args) => ({ arguments: args, sourceMap: [], snapshot: { sha256: 'a'.repeat(64), files: [{ path: 'a.conllu', size: 1, sha256: 'b'.repeat(64) }], cleanup: mocked.cleanup } }));
    mocked.transfer.mockReset().mockImplementation(() => (async function* () {})());
    mocked.spawn.mockReset().mockImplementation(() => {
      setImmediate(() => { streams.stdout.end('{"ok":true,"result":{"passed":true}}\n'); streams.stderr.end(); child.exitCode = 0; child.emit('exit', 0, null); child.emit('close', 0, null); });
      return child;
    });
    const original = path.resolve('package.json'), runtime = { python: launcher, bootstrap: original, guard: original, workerPath: root, upstreamPath: root, contextPath: original };
    expect((await runUserspaceValidation(runtime, { operation: 'validation_report', arguments: { working_tree_path: root, file_paths: ['a.conllu'] }, allowedRoots: [root] })).result).toEqual({ passed: true });
    const [executable, argv, options] = mocked.spawn.mock.calls[0]!;
    expect(executable).toBe(runtime.guard);
    const values = Object.fromEntries(Array.from({ length: (argv.length - 1) / 2 }, (_, index) => [argv[index * 2 + 1], argv[index * 2 + 2]]));
    const hash = (value: string) => createHash('sha256').update(value).digest('hex');
    expect(values).toMatchObject({ '--executable': base, '--executable-sha256': hash('base'), '--venv-executable': launcher, '--venv-executable-sha256': hash('redirector'), '--venv-config': config, '--venv-config-sha256': hash(configBytes) });
    expect(options.env.__PYVENV_LAUNCHER__).toBe(launcher); expect(options.env.PYTHONHOME).toBeUndefined(); expect(options.env.PYTHONPATH).toBeUndefined();
    expect(mocked.cleanup).toHaveBeenCalledTimes(1);
  } finally {
    Object.defineProperty(process, 'platform', platform);
    for (const [key, value] of Object.entries(prior)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    for (const stream of Object.values(streams)) stream.destroy(); await rm(root, { recursive: true, force: true });
  }
});

it.each(['stdout', 'stderr', 'transfer'] as const)('owns %s resets before and after worker exit and preserves bounded refusal evidence', async streamName => {
  const streams = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), transfer: new PassThrough() };
  if (process.platform === 'win32') { streams.transfer.destroy(); streams.transfer = streams.stdin; }
  const child = Object.assign(new EventEmitter(), streams, { stdio: [streams.stdin, streams.stdout, streams.stderr, streams.transfer], exitCode: null as number | null, signalCode: null, kill: vi.fn() });
  const reset = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
  mocked.cleanup.mockReset().mockResolvedValue(undefined);
  mocked.capture.mockReset().mockImplementation(async (_guard, args) => ({ arguments: args, sourceMap: [], snapshot: { sha256: 'a'.repeat(64), files: [{ path: 'a.conllu', size: 1, sha256: 'b'.repeat(64) }], cleanup: mocked.cleanup } }));
  mocked.transfer.mockReset().mockImplementation(() => (async function* () {})());
  mocked.spawn.mockReset().mockImplementation(() => {
    setImmediate(() => {
      streams.stderr.write('discarded-prefix' + '.'.repeat(10_000) + 'worker fixture refusal\n');
      streams[streamName].emit('error', reset);
      child.exitCode = 1; child.emit('exit', 1, null);
      streams.stdout.end(); streams.stderr.end(); child.emit('close', 1, null);
    });
    return child;
  });
  // Hash ordinary original bytes where the real supervisor would pin binaries.
  const original = path.resolve('package.json');
  const runtime = { python: original, bootstrap: original, guard: original, workerPath: path.resolve('workers/ud/src'), upstreamPath: path.resolve('workers'), contextPath: original };
  const failure = await runUserspaceValidation(runtime, { operation: 'validation_report', arguments: { working_tree_path: path.resolve('tests'), file_paths: ['a.conllu'] }, allowedRoots: [path.resolve('tests')] }).then(() => undefined, error => error);
  expect(failure?.message).toBe('WORKER_EXECUTION_FAILED');
  expect(failure?.cause?.message).toContain('final 8192 retained; exit 1');
  expect(failure?.cause?.message).toContain('worker fixture refusal');
  expect(failure?.cause?.message).not.toContain('discarded-prefix');
  expect(failure?.cause?.cause).toBe(reset);
  expect(mocked.cleanup).toHaveBeenCalledTimes(1);
  expect(mocked.transfer.mock.calls[0]![2].aborted).toBe(true);
  const kills = child.kill.mock.calls.length;
  expect(() => streams[streamName].emit('error', reset)).not.toThrow();
  expect(child.kill).toHaveBeenCalledTimes(kills);
  for (const stream of Object.values(streams)) stream.destroy();
});

it('ignores late pipe resets after a successful worker has settled without repeating cancellation or cleanup', async () => {
  const streams = { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), transfer: new PassThrough() };
  if (process.platform === 'win32') { streams.transfer.destroy(); streams.transfer = streams.stdin; }
  const child = Object.assign(new EventEmitter(), streams, { stdio: [streams.stdin, streams.stdout, streams.stderr, streams.transfer], exitCode: null as number | null, signalCode: null, kill: vi.fn() });
  let cancellations = 0;
  mocked.cleanup.mockReset().mockResolvedValue(undefined);
  mocked.capture.mockReset().mockImplementation(async (_guard, args, _roots, signal) => {
    signal.addEventListener('abort', () => cancellations++);
    return { arguments: args, sourceMap: [], snapshot: { sha256: 'a'.repeat(64), files: [{ path: 'a.conllu', size: 1, sha256: 'b'.repeat(64) }], cleanup: mocked.cleanup } };
  });
  mocked.transfer.mockReset().mockImplementation(() => (async function* () {})());
  mocked.spawn.mockReset().mockImplementation(() => {
    setImmediate(() => {
      streams.stdout.end('{"ok":true,"result":{"passed":true}}\n'); streams.stderr.end();
      child.exitCode = 0; child.emit('exit', 0, null); child.emit('close', 0, null);
    });
    return child;
  });
  const original = path.resolve('package.json');
  const runtime = { python: original, bootstrap: original, guard: original, workerPath: path.resolve('workers/ud/src'), upstreamPath: path.resolve('workers'), contextPath: original };
  const outcome = await runUserspaceValidation(runtime, { operation: 'validation_report', arguments: { working_tree_path: path.resolve('tests'), file_paths: ['a.conllu'] }, allowedRoots: [path.resolve('tests')] });
  expect(outcome.result).toEqual({ passed: true });
  for (const stream of [streams.stdout, streams.stderr, streams.transfer]) expect(() => stream.emit('error', Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }))).not.toThrow();
  expect(child.kill).not.toHaveBeenCalled(); expect(cancellations).toBe(1); expect(mocked.cleanup).toHaveBeenCalledTimes(1);
  for (const stream of Object.values(streams)) stream.destroy();
});
