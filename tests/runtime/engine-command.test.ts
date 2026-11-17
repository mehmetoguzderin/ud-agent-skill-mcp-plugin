import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ command: vi.fn(async () => ({ code: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) })) }));
vi.mock('../../packages/runtime-manager/src/command.js', () => ({ runCommand: mocks.command }));
import { engineSupervisor, runEngineCommand, withEngineSupervisor, withoutEngineCancellation, workerStreamError } from '../../packages/coordinator/src/engine-command.js';

const authority = (name: string) => ({ engine: path.resolve(name), guard: path.resolve('guard'), guardSha256: `sha256:${'a'.repeat(64)}`, executableSha256: `sha256:${'b'.repeat(64)}` });
const options = { timeoutMs: 1000, maxOutputBytes: 1024 };

describe('issued engine command scopes', () => {
  it('isolates concurrent async workflows and restores the outer discovery context', async () => {
    const first = authority('first'), second = authority('second');
    let release!: () => void;
    const barrier = new Promise<void>(resolve => { release = resolve; });
    await Promise.all([
      withEngineSupervisor(first, async () => { await barrier; expect(engineSupervisor(first.engine)?.executableSha256).toBe(first.executableSha256); await runEngineCommand(first.engine, ['info'], options); }),
      withEngineSupervisor(second, async () => { release(); await Promise.resolve(); expect(() => engineSupervisor(first.engine)).toThrow('ENGINE_SUPERVISOR_SCOPE_MISMATCH'); await runEngineCommand(second.engine, ['info'], options); }),
    ]);
    expect(engineSupervisor(first.engine)).toBeUndefined();
    for (const expected of [first, second]) expect(mocks.command.mock.calls).toContainEqual([expected.engine, ['info'], { ...options, supervisor: { guard: expected.guard, guardSha256: expected.guardSha256, executableSha256: expected.executableSha256 } }]);
    await runEngineCommand(first.engine, ['context', 'inspect'], options);
    expect(mocks.command).toHaveBeenLastCalledWith(first.engine, ['context', 'inspect'], options);
  });

  it('keeps exact supervision during mandatory cleanup after cancellation', async () => {
    const current = authority('engine'), controller = new AbortController(); controller.abort();
    await withEngineSupervisor({ ...current, signal: controller.signal }, async () => {
      await runEngineCommand(current.engine, ['start'], options);
      expect(mocks.command).toHaveBeenLastCalledWith(current.engine, ['start'], expect.objectContaining({ signal: controller.signal, supervisor: engineSupervisor(current.engine) }));
      await withoutEngineCancellation(() => runEngineCommand(current.engine, ['container', 'rm'], options));
      expect(mocks.command).toHaveBeenLastCalledWith(current.engine, ['container', 'rm'], { ...options, supervisor: engineSupervisor(current.engine) });
      await runEngineCommand(current.engine, ['inspect'], options);
      expect(mocks.command).toHaveBeenLastCalledWith(current.engine, ['inspect'], expect.objectContaining({ signal: controller.signal }));
    });
    expect(await withoutEngineCancellation(async () => 'unscoped')).toBe('unscoped');
  });

  it('freezes a copy and rejects invalid paths, hashes and conflicting authorities before dispatch', async () => {
    const current = authority('engine');
    await withEngineSupervisor(current, async () => {
      current.guardSha256 = `sha256:${'c'.repeat(64)}`;
      expect(engineSupervisor(current.engine)?.guardSha256).toBe(`sha256:${'a'.repeat(64)}`);
      await expect(runEngineCommand(current.engine, [], { ...options, supervisor: { guard: current.guard, guardSha256: current.guardSha256, executableSha256: current.executableSha256 } })).rejects.toThrow('ENGINE_SUPERVISOR_SCOPE_MISMATCH');
      await expect(runEngineCommand(path.resolve('foreign'), [], options)).rejects.toThrow('ENGINE_SUPERVISOR_SCOPE_MISMATCH');
    });
    for (const invalid of [{ engine: 'relative' }, { guard: 'relative' }, { guard: current.guard + '\0' }, { executableSha256: 'b'.repeat(64) }, { guardSha256: `sha256:${'A'.repeat(64)}` }]) expect(() => withEngineSupervisor({ ...current, ...invalid }, async () => true)).toThrow('ENGINE_SUPERVISOR_AUTHORITY_INVALID');
  });

  it('preserves worker error compatibility without hiding integrity or producer failures', () => {
    for (const [code, expected] of [['SUPERVISED_COMMAND_CANCELLED', 'WORKER_CANCELLED'], ['SUPERVISED_COMMAND_TIMEOUT', 'WORKER_TIMEOUT'], ['SUPERVISED_COMMAND_OUTPUT_LIMIT', 'WORKER_OUTPUT_TOO_LARGE']]) expect(() => workerStreamError(Object.assign(new Error(code), { code }))).toThrow(expected);
    for (const error of [Object.assign(new Error('guard changed'), { code: 'SUPERVISOR_CLEANUP_UNVERIFIED' }), new TypeError('producer failed'), 'unexpected']) {
      try { workerStreamError(error); expect.fail('unexpected failure suppressed'); } catch (actual) { expect(actual).toBe(error); }
    }
  });
});
