/** Original callback/state fixtures, not worker execution evidence. */
import { expect, test } from 'vitest';
import { Continuations } from '../../packages/coordinator/src/continuations.js';
import type { ContinuationProgress, ToolResponse } from '../../packages/coordinator/src/continuations.js';
import type { Contract } from '../../packages/coordinator/src/catalog.js';
const contract: Contract = { id: '048', name: 'validation_report', original_signature: '', upstream_provenance: 'C', runtime_pack: 'core', parameters: [] };
const complete: ToolResponse = { content: [{ type: 'text', text: 'Completed original fixture' }], structuredContent: { result: { passed: true } } };
test('continuation progress is bounded to active listeners while all concurrent resumptions retain the actual result', async () => {
  const manager = new Continuations('scope'), events: number[] = [];
  let publish!: ContinuationProgress, finish!: (value: ToolResponse) => void;
  const pending = await manager.run(contract, {}, { budget_ms: 1 }, async (_signal, progress) => { publish = progress; return new Promise<ToolResponse>(resolve => { finish = resolve; }); });
  const token = (pending.structuredContent.result as { continuation_token: string }).continuation_token;
  const requests = Array.from({ length: 65 }, (_, index) => manager.run(contract, {}, { token, budget_ms: 5000 }, async () => { throw new Error('A resumed request must not execute again'); }, undefined, async () => { events.push(index); }));
  try { await publish(2, 4, 'Original fixture phase'); expect(events).toEqual(Array.from({ length: 64 }, (_, index) => index)); }
  finally { finish(complete); }
  for (const value of await Promise.all(requests)) expect(value).toEqual(complete);
  await publish(3, 4, 'No active requests'); expect(events).toHaveLength(64); manager.close();
});
test('failed or stalled progress does not block other listeners and an already-aborted resume cancels owned work', async () => {
  const manager = new Continuations('scope'), events: number[] = [];
  let publish!: ContinuationProgress, finish!: (value: ToolResponse) => void, ownedSignal!: AbortSignal;
  const pending = await manager.run(contract, {}, { budget_ms: 1 }, async (signal, progress) => { ownedSignal = signal; publish = progress; return new Promise<ToolResponse>(resolve => { finish = resolve; }); });
  const token = (pending.structuredContent.result as { continuation_token: string }).continuation_token;
  const bad = manager.run(contract, {}, { token, budget_ms: 5000 }, async () => complete, undefined, async () => { throw new Error('Advisory only'); });
  const stalled = manager.run(contract, {}, { token, budget_ms: 5000 }, async () => complete, undefined, async () => new Promise<void>(() => {}));
  const healthy = manager.run(contract, {}, { token, budget_ms: 5000 }, async () => complete, undefined, async phase => { events.push(phase); });
  await publish(2, 4, 'Active'); expect(events).toEqual([2]);
  const controller = new AbortController(); controller.abort();
  const cancelled = manager.run(contract, {}, { token, budget_ms: 5000 }, async () => complete, controller.signal);
  expect(ownedSignal.aborted).toBe(true); finish(complete);
  for (const value of await Promise.all([bad, stalled, healthy, cancelled])) expect(value).toEqual(complete);
  manager.close();
});
test('an already-issued notification can settle late with its original identity but a returned RPC receives no new deliveries', async () => {
  const manager = new Continuations('scope'), calls: string[] = [], deliveries: string[] = [];
  let publish!: ContinuationProgress, finish!: (value: ToolResponse) => void, releaseSend!: () => void;
  const transportGate = new Promise<void>(resolve => { releaseSend = resolve; });
  const initial = await manager.run(contract, {}, { budget_ms: 1 }, async (_signal, progress) => { publish = progress; await progress(0, 4, 'Original phase'); return new Promise<ToolResponse>(resolve => { finish = resolve; }); }, undefined, async phase => { calls.push('initial:' + phase); await transportGate; deliveries.push('initial:' + phase); });
  const token = (initial.structuredContent.result as { continuation_token: string }).continuation_token;
  expect(calls).toEqual(['initial:0']); expect(deliveries).toEqual([]);
  const resumed = manager.run(contract, {}, { token, budget_ms: 5000 }, async () => complete, undefined, async phase => { calls.push('resumed:' + phase); deliveries.push('resumed:' + phase); });
  try {
    await publish(2, 4, 'Current phase'); expect(calls).toEqual(['initial:0', 'resumed:0', 'resumed:2']);
    releaseSend(); await transportGate; await Promise.resolve();
    expect(deliveries).toEqual(['resumed:0', 'resumed:2', 'initial:0']);
  } finally { releaseSend(); finish(complete); }
  expect(await resumed).toEqual(complete); await publish(3, 4, 'No active RPC');
  expect(calls).toEqual(['initial:0', 'resumed:0', 'resumed:2']); manager.close();
});
