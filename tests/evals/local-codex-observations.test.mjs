import { posixTest } from '../fixtures/native-scope.mjs';
// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { nativeCodexMcpResults, nativeLogResults, resolveNativeResults } from '../../evals/local/native-observations.mjs';
import { createGateway } from '../../evals/local/gateway.mjs';
import { createBudgetAuthority } from '../../evals/local/budget.mjs';

const arguments_ = { working_tree_path: '/task', required_tools: ['validation_report'], offline: true };
const pendingCall = (id = 'provider-call') => ({ id, namespace: 'mcp__ud', name: 'check_ud_environment', arguments: arguments_ });
const started = (id = 'item_3') => ({ type: 'item.started', item: { id, type: 'mcp_tool_call', server: 'ud', tool: 'check_ud_environment', arguments: arguments_, status: 'in_progress', result: null, error: null } });
const completed = (status = 'completed', id = 'item_3') => ({ type: 'item.completed', item: { ...started(id).item, status, result: { content: [{ type: 'text', text: 'Domain findings are not transport status.' }], structured_content: { result: { ready: false }, execution: { status: 'completed' } } } } });
const parse = (...events) => nativeLogResults(events.map(event => typeof event === 'string' ? event : JSON.stringify(event)).join('\n'));
const history = call => ({ input: [
  { type: 'function_call', call_id: call.id, namespace: call.namespace, name: call.name, arguments: JSON.stringify(call.arguments) },
  { type: 'function_call_output', call_id: call.id, output: 'Wall time: 0.1 seconds\nOutput:\n{"ready":false}' },
] });
const resolve = (calls, events, body = history(calls[0]), consumed = new Set()) => resolveNativeResults('responses', body, new Map(calls.map(call => [call.id, call])), events, consumed);

test('Codex MCP terminal status requires matching start, exact identity and an actual result or error', () => {
  const events = parse(started(), completed());
  assert.equal(events.length, 1);
  assert.equal(events[0].failed, false);
  assert.equal(events[0].namespace, 'mcp__ud');
  assert.deepEqual(events[0].arguments, arguments_);
  assert.deepEqual(events[0].native_evidence, { started: started().item, completed: completed().item });
  assert.equal(parse(started(), completed('failed'))[0].failed, true, 'explicit failed status overrides success-looking result text');
  const error = { ...completed('failed'), item: { ...completed('failed').item, result: null, error: { message: 'MCP connection lost' } } };
  assert.equal(parse(started(), error)[0].failed, true);
  assert.deepEqual(nativeCodexMcpResults(JSON.stringify(completed())), [], 'completion without native start remains unverified');
});

test('Codex observer rejects missing, contradictory, duplicate and changed lifecycle evidence', () => {
  const changed = (event, changes) => ({ ...event, item: { ...event.item, ...changes } });
  for (const events of [
    [started()], [completed()], [completed(), started()], [started(), started(), completed()], [started(), completed(), completed()],
    [started(), completed(), completed('failed')],
    [started(), changed(completed(), { server: 'other' })],
    [started(), changed(completed(), { tool: 'other' })],
    [started(), changed(completed(), { arguments: { ...arguments_, offline: false } })],
    [started(), changed(completed(), { result: null })],
    [started(), changed(completed(), { result: {} })],
    [started(), changed(completed(), { error: { message: 'contradictory' } })],
    [started(), changed(completed(), { status: 'in_progress' })],
    [started(), changed(completed('failed'), { result: null, error: null })],
    [changed(started(), { status: 'completed' }), completed()],
    [changed(started(), { result: { content: [] } }), completed()],
    [changed(started(), { error: undefined }), completed()],
    [changed(started(), { arguments: 'string' }), completed()],
    [{ type: 'item.updated', item: started().item }, completed()],
    [started(), { type: 'tool_result', id: 'item_3', text: 'success' }],
  ]) assert.deepEqual(parse(...events), [], JSON.stringify(events));
});

test('unique MCP correlation preserves both IDs, namespace, arguments and explicit status', () => {
  const call = pendingCall(), events = parse(started(), completed());
  const result = resolve([call], events);
  assert.equal(result.length, 1);
  assert.equal(result[0].id, call.id); assert.equal(result[0].native_id, 'item_3');
  assert.equal(result[0].name, call.name); assert.equal(result[0].namespace, call.namespace);
  assert.deepEqual(result[0].arguments, call.arguments); assert.equal(result[0].failed, false);
  assert.equal(result[0].source, 'native-codex-unique-mcp-call-and-result-status');
  assert.deepEqual(resolve([call], events, history(call), new Set(['item_3'])), [], 'a consumed native event cannot resolve another provider call');
  assert.deepEqual(resolveNativeResults(undefined, undefined, new Map([[call.id, call]]), events), result, 'final reconciliation uses actual completed native evidence');
  assert.deepEqual(resolveNativeResults('chat', undefined, new Map([['item_3', pendingCall('item_3')]]), events), [], 'a coincidentally equal spelling cannot bypass Codex correlation');
});

test('same-name parallel calls, duplicate native matches and mismatched provider history stay unverified', () => {
  const call = pendingCall(), events = parse(started(), completed());
  const ambiguous = [call, pendingCall('second-provider-call')];
  assert.deepEqual(resolve(ambiguous, events, { input: [...history(call).input, ...history(ambiguous[1]).input] }), []);
  assert.deepEqual(resolve([call], parse(started(), completed(), started('item_4'), completed('completed', 'item_4'))), []);
  assert.deepEqual(resolve([call], [...events, ...events]), [], 'duplicate observations cannot invent unique correspondence');
  for (const field of ['namespace', 'name', 'arguments']) {
    const body = history(call); body.input[0][field] = field === 'arguments' ? '{}' : 'other';
    assert.deepEqual(resolve([call], events, body), [], field);
  }
  for (const body of [{ input: [] }, { input: [history(call).input[0]] }, { input: [history(call).input[1]] }, { input: [...history(call).input, history(call).input[0]] }, { input: [...history(call).input, history(call).input[1]] }]) {
    assert.deepEqual(resolve([call], events, body), []);
  }
  const wrong = { ...call, namespace: 'mcp__other', id: 'item_3' };
  assert.deepEqual(resolve([wrong], events, history(wrong)), [], 'native-ID spelling cannot override namespace mismatch');
  const reordered = { ...call, arguments: { offline: true, required_tools: ['validation_report'], working_tree_path: '/task' } };
  assert.equal(resolve([reordered], events, history(reordered)).length, 1, 'canonical object key order is representational');
});

test('explicit provider error and contradictory Codex native success fail as conflicting evidence', () => {
  const call = pendingCall(), body = history(call); body.input[1].is_error = true;
  assert.throws(() => resolve([call], parse(started(), completed()), body), /NATIVE_RESULT_CONFLICT/);
});

posixTest('gateway continues after a completed Codex MCP result using native evidence while preserving provider bytes', async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-codex-observe-')));
  const records = [], requests = []; let nativeEvents = [];
  const call = pendingCall();
  const upstream = http.createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    requests.push(JSON.parse(Buffer.concat(chunks)));
    const output = requests.length === 1 ? [{ type: 'function_call', call_id: call.id, namespace: call.namespace, name: call.name, arguments: JSON.stringify(call.arguments) }]
      : [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'complete' }] }];
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ status: 'completed', output, usage: { input_tokens: 1, output_tokens: 1 } }));
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const budget = await createBudgetAuthority({ directory });
  const gateway = await createGateway({ upstream: `http://127.0.0.1:${upstream.address().port}`, model: 'fixture', budget, record: event => records.push(event), nativeResults: () => nativeEvents, tokenize: async () => ({ trusted: true, inputTokens: 1 }) });
  const tools = [{ type: 'namespace', name: 'mcp__ud', tools: [{ type: 'function', name: call.name, parameters: { type: 'object' } }] }];
  const send = body => fetch(gateway.url + '/v1/responses', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'fixture', tools, ...body }) });
  try {
    const first = await send({ input: 'Read.' }); assert.equal(first.status, 200); await first.arrayBuffer();
    nativeEvents = parse(started(), completed());
    const secondBody = history(call), second = await send(secondBody); assert.equal(second.status, 200); await second.arrayBuffer();
    assert.equal(requests.length, 2); assert.deepEqual(requests[1].input, secondBody.input);
    const observed = records.find(event => event.type === 'native_result_observed');
    assert.equal(observed.id, call.id); assert.equal(observed.native_id, 'item_3');
    assert.equal(observed.namespace, 'mcp__ud'); assert.equal(observed.failed, false);
    assert.equal(budget.snapshot().native_recovery.verified, true);
    assert.equal(records.some(event => event.type === 'gateway_rejection'), false);
  } finally {
    await gateway.close(); await budget.close(); upstream.closeAllConnections();
    await new Promise(resolve => upstream.close(resolve)); await rm(directory, { recursive: true, force: true });
  }
});
