import { expect, it, vi } from 'vitest';
import { Continuations } from '../../packages/coordinator/src/continuations.js';
import type { ToolResponse } from '../../packages/coordinator/src/continuations.js';
import type { Contract } from '../../packages/coordinator/src/catalog.js';

const contract: Contract = { id: '048', name: 'validation_report', original_signature: '', upstream_provenance: 'C', runtime_pack: 'core', parameters: [] };
const complete: ToolResponse = { content: [{ type: 'text', text: 'Executed.' }], structuredContent: { result: { passed: true } } };
it('continues the same exact request once and rejects cross-tool, changed-argument and cross-session tokens', async () => {
  const manager = new Continuations('scope-and-policy');
  let release!: (value: ToolResponse) => void;
  const execute = vi.fn(() => new Promise<ToolResponse>(resolve => { release = resolve; }));
  const args = { working_tree_path: '/granted', options: { language_code: 'en' } };
  const pending = await manager.run(contract, args, { budget_ms: 1 }, execute);
  const details = pending.structuredContent.result as { continuation_token: string; operation_resource: string };
  expect(details.continuation_token).toMatch(/^cont-v1:/);
  expect(manager.read(new URL(details.operation_resource))).toMatchObject({ contents: [{ text: expect.stringContaining('working') }] });
  await expect(manager.run(contract, { ...args, working_tree_path: '/other' }, { token: details.continuation_token }, execute)).rejects.toThrow('CONTINUATION_IDENTITY_MISMATCH');
  await expect(new Continuations('scope-and-policy').run(contract, args, { token: details.continuation_token }, execute)).rejects.toThrow('CONTINUATION_IDENTITY_MISMATCH');
  release(complete);
  expect(await manager.run(contract, args, { token: details.continuation_token }, execute)).toEqual(complete);
  expect(execute).toHaveBeenCalledTimes(1);
  manager.close();
});
it('cancels explicit and session-owned work, retaining execution failure rather than reporting completion', async () => {
  const manager = new Continuations('policy');
  let observed: AbortSignal | undefined;
  const execute = (signal: AbortSignal) => new Promise<ToolResponse>((_resolve, reject) => { observed = signal; signal.addEventListener('abort', () => reject(new Error('WORKER_CANCELLED'))); });
  const first = await manager.run(contract, {}, { budget_ms: 1 }, execute);
  const token = (first.structuredContent.result as { continuation_token: string }).continuation_token;
  const cancelled = await manager.run(contract, {}, { token, cancel: true }, execute);
  expect(observed?.aborted).toBe(true); expect(cancelled.isError).toBe(true);
  await manager.run(contract, { another: true }, { budget_ms: 1 }, execute);
  manager.close(); expect(observed?.aborted).toBe(true);
});
