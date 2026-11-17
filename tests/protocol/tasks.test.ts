import { expect, it, vi } from 'vitest';
import { TaskTransport } from '../../packages/coordinator/src/task-transport.js';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';

type Message = Parameters<NonNullable<StdioServerTransport['onmessage']>>[0];
function fixture() {
  const output: Record<string, unknown>[] = [], input: Message[] = [];
  const inner: Pick<StdioServerTransport, 'start' | 'close' | 'send' | 'onmessage' | 'onclose' | 'onerror'> = { start: async () => {}, close: async () => { inner.onclose?.(); }, send: async message => { output.push(message as Record<string, unknown>); } };
  const transport = new TaskTransport(inner); transport.onmessage = message => input.push(message);
  const receive = async (message: unknown) => { inner.onmessage?.(message as Message); await vi.waitFor(() => expect(output.length + input.length).toBeGreaterThan(0)); await new Promise(resolve => setImmediate(resolve)); };
  return { transport, output, input, receive };
}

it('negotiates legacy Tasks, preserves validated dispatch, waits for cleanup and isolates task identity', async () => {
  const f = fixture(); await f.transport.start();
  await f.receive({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25' } });
  await f.transport.send({ jsonrpc: '2.0', id: 1, result: { capabilities: {} } } as Message);
  expect(f.output[0]).toMatchObject({ result: { capabilities: { tasks: { list: {}, cancel: {}, requests: { tools: { call: {} } } } } } });
  await f.receive({ jsonrpc: '2.0', method: 'notifications/initialized' });
  await f.receive({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'token_lemma_set', arguments: { lemma: 'hello' }, task: { ttl: 30000 } } });
  const task = (f.output.at(-1)!.result as { task: { taskId: string } }).task;
  const request = f.input.at(-1)! as { id: string; params: Record<string, unknown> };
  expect(request.params).toEqual({ name: 'token_lemma_set', arguments: { lemma: 'hello' } });
  expect(f.transport.signalForRequest(request.id)?.aborted).toBe(false);
  await f.receive({ jsonrpc: '2.0', id: 3, method: 'tasks/cancel', params: { taskId: task.taskId } });
  expect(f.transport.signalForRequest(request.id)?.aborted).toBe(true);
  expect(f.output.at(-1)).toMatchObject({ result: { status: 'working', statusMessage: expect.stringContaining('cleanup') } });
  const before = f.output.length;
  await f.receive({ jsonrpc: '2.0', id: 4, method: 'tasks/result', params: { taskId: task.taskId } });
  expect(f.output.length).toBe(before);
  const result = { content: [{ type: 'text', text: 'Cancelled and owned cleanup verified.' }], isError: true };
  await f.transport.send({ jsonrpc: '2.0', id: request.id, result } as Message);
  expect(f.output).toContainEqual({ jsonrpc: '2.0', id: 4, result });
  expect(f.output.at(-1)).toMatchObject({ method: 'notifications/tasks/status', params: { status: 'cancelled' } });
  await f.receive({ jsonrpc: '2.0', id: 5, method: 'tasks/get', params: { taskId: 'another-session' } });
  expect(f.output.at(-1)).toMatchObject({ error: { code: -32602 } });
  await f.transport.close();
});

it('does not advertise or intercept removed Tasks vocabulary on modern MCP', async () => {
  const f = fixture(); await f.transport.start();
  await f.receive({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2026-07-28' } });
  await f.transport.send({ jsonrpc: '2.0', id: 1, result: { capabilities: {} } } as Message);
  expect(f.output[0]).toEqual({ jsonrpc: '2.0', id: 1, result: { capabilities: {} } });
  await f.receive({ jsonrpc: '2.0', method: 'notifications/initialized' });
  const request = { jsonrpc: '2.0', id: 2, method: 'tasks/list', params: {} } as Message;
  await f.receive(request); expect(f.input.at(-1)).toEqual(request);
  await f.transport.close();
});
