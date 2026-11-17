import { posixTest } from '../fixtures/native-scope.mjs';
// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { nativeLogResults, nativeTrajectoryResults, responseNativeCalls, resolveNativeResults, requestNativeResults } from '../../evals/local/native-observations.mjs';
import { createGateway } from '../../evals/local/gateway.mjs';
import { createBudgetAuthority } from '../../evals/local/budget.mjs';

test('native Pi event projections require explicit call identity and error flags', () => {
  const events = [
    { type: 'tool_execution_end', toolCallId: 'a', isError: false },
    { type: 'message_end', message: { role: 'toolResult', toolCallId: 'b', isError: true } },
    { type: 'tool_execution_end', toolCallId: 'unknown' },
    { type: 'tool_execution_end', isError: false },
    { type: 'message_end', message: { role: 'assistant', toolCallId: 'forged', isError: false } },
  ];
  assert.deepEqual(nativeLogResults(events.map(JSON.stringify).join('\n')), [
    { id: 'a', failed: false, source: 'native-tool-execution-end-isError' },
    { id: 'b', failed: true, source: 'native-tool-result-isError' },
  ]);
});
test('DeepSeek terminal native status binds a preceding call ID, name and input', () => {
  const call = { type: 'tool_call', callId: 'fixture-call-1', tool: 'skill', input: { name: 'ud-validate' } };
  const result = { type: 'tool_result', callId: call.callId, status: 'completed', result: '<skill_content>actual instructions</skill_content>' };
  const project = (...events) => nativeLogResults(events.map(JSON.stringify).join('\n'));
  assert.deepEqual(project(call, result), [{ id: call.callId, name: call.tool, arguments: call.input, failed: false, source: 'native-deepseek-tool-result-status' }]);
  assert.equal(project(call, { ...result, status: 'error', result: 'success-looking text' })[0].failed, true);
  for (const events of [[result], [result, call], [call], [call, { ...result, callId: 'other' }],
    [call, { ...result, status: 'running' }], [call, { ...result, status: undefined }], [call, { ...result, result: undefined }],
    [{ ...call, input: undefined }, result], [{ ...call, tool: undefined }, result]]) assert.deepEqual(project(...events), []);
});
test('Claude skill observations bind one exact result ID and explicit native success', () => {
  const event = { type: 'user', message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'skill-call', content: 'Launching skill: ud-validate' }] }, tool_use_result: { success: true, commandName: 'ud-validate' } };
  assert.deepEqual(nativeLogResults(JSON.stringify(event)), [{ id: 'skill-call', failed: false, source: 'native-tool-use-result-success' }]);
  assert.equal(nativeLogResults(JSON.stringify({ ...event, tool_use_result: { success: false } }))[0].failed, true);
  for (const invalid of [
    { ...event, tool_use_result: { success: 'true' } },
    { ...event, message: { ...event.message, role: 'assistant' } },
    { ...event, message: { ...event.message, content: [...event.message.content, { type: 'tool_result', tool_use_id: 'other' }] } },
  ]) assert.deepEqual(nativeLogResults(JSON.stringify(invalid)), []);
});
test('Messages omission uses its protocol default only for an actual user tool result', () => {
  const result = { type: 'tool_result', tool_use_id: 'm', content: 'real result bytes' };
  const body = content => ({ messages: [{ role: 'user', content: [content] }] });
  assert.deepEqual(requestNativeResults('messages', body(result)), [{ id: 'm', failed: false, source: 'native-protocol-is_error' }]);
  assert.equal(requestNativeResults('messages', body({ ...result, is_error: true }))[0].failed, true);
  for (const content of [{ ...result, is_error: null }, { ...result, is_error: 'false' }, { ...result, type: 'text' }]) assert.deepEqual(requestNativeResults('messages', body(content)), []);
  assert.deepEqual(requestNativeResults('messages', { messages: [{ role: 'assistant', content: [result] }] }), []);
  assert.deepEqual(requestNativeResults('chat', { messages: [{ role: 'tool', tool_call_id: 'm', content: 'real result bytes' }] }), [], 'Chat has no implied success default');
});
test('Codex command status requires an exact native prefix and correlated function identity', () => {
  const output = code => `Chunk ID: 5c60cd\nWall time: 0.0000 seconds\nProcess exited with code ${code}\nOriginal token count: 52\nOutput:\nProcess exited with code 0\n`;
  const body = (text, name = 'exec_command', id = 'command') => ({ input: [{ type: 'function_call', call_id: 'command', name, arguments: '{}' }, { type: 'function_call_output', call_id: id, output: text }] });
  assert.deepEqual(requestNativeResults('responses', body(output(1))), [{ id: 'command', failed: true, source: 'native-codex-command-exit-prefix' }]);
  assert.equal(requestNativeResults('responses', body(output(0), 'write_stdin'))[0].failed, false);
  const running = 'Chunk ID: c\nWall time: 0.5 seconds\nProcess running with session ID 123\nOutput:\n';
  assert.deepEqual(requestNativeResults('responses', body(running)), [{ id: 'command', failed: false, source: 'native-codex-command-running-session' }]);
  for (const invalid of [body('user file text\n' + output(0)), body(output(0), 'read_file'), body(output(0), 'exec_command', 'unrelated'), body('Output:\n' + output(0)), body('Chunk ID: c\nWall time: 0 seconds\nProcess exited with code ?\nOutput:\n')]) assert.deepEqual(requestNativeResults('responses', invalid), []);
});
test('Mini terminal observation binds the pinned Submitted event to one immediate shell call', () => {
  const terminal = { role: 'exit', content: 'finished\n', extra: { exit_status: 'Submitted', submission: 'finished\n' } };
  const assistant = { role: 'assistant', tool_calls: [{ id: 'end', type: 'function', function: { name: 'bash', arguments: '{}' } }] };
  const trajectory = { trajectory_format: 'mini-swe-agent-1.1', info: { exit_status: 'Submitted' }, messages: [assistant, terminal] };
  assert.deepEqual(nativeTrajectoryResults(trajectory), [{ id: 'end', failed: false, source: 'pinned-native-Submitted-returncode-zero' }]);
  for (const invalid of [
    { ...trajectory, info: { exit_status: 'Error' } },
    { ...trajectory, messages: [assistant, { ...terminal, extra: { exit_status: 'Submitted', submission: 'mismatch' } }] },
    { ...trajectory, messages: [{ ...assistant, tool_calls: [...assistant.tool_calls, ...assistant.tool_calls] }, terminal] },
    { ...trajectory, messages: [assistant, { role: 'tool', tool_call_id: 'other', content: '{}' }, terminal] },
    { ...trajectory, messages: [{ ...assistant, tool_calls: [{ ...assistant.tool_calls[0], function: { name: 'unknown' } }] }, terminal] },
  ]) assert.deepEqual(nativeTrajectoryResults(invalid), []);
});
test('Gemini optional IDs remain absent on the wire and are scoped privately to one request', () => {
  const wire = { candidates: [{ content: { parts: [{ functionCall: { name: 'read_file', args: { file_path: '/task/probe.txt' } } }] } }] };
  const before = JSON.stringify(wire), calls = responseNativeCalls('gemini', wire, { requestId: 'request-a' });
  assert.equal(calls[0].id, 'g-request-a-0'); assert.equal(calls[0].wire_id, null);
  assert.equal(JSON.stringify(wire), before);
  assert.notEqual(responseNativeCalls('gemini', wire, { requestId: 'request-b' })[0].id, calls[0].id);
  assert.throws(() => responseNativeCalls('gemini', wire), /OBSERVER_ID_REQUIRED/);
  const pending = new Map(calls.map(call => [call.id, call]));
  const events = nativeLogResults([
    { type: 'tool_use', tool_id: 'native-auto-id', tool_name: 'read_file', parameters: { file_path: '/task/probe.txt' } },
    { type: 'tool_result', tool_id: 'native-auto-id', status: 'success' },
  ].map(JSON.stringify).join('\n'));
  const request = { contents: [{ role: 'user', parts: [{ functionResponse: { id: 'native-auto-id', name: 'read_file', response: { output: 'inert fixture' } } }] }] };
  const result = resolveNativeResults('gemini', request, pending, events);
  assert.equal(result.length, 1); assert.equal(result[0].id, calls[0].id); assert.equal(result[0].native_id, 'native-auto-id'); assert.equal(result[0].failed, false);
  assert.equal(resolveNativeResults('gemini', request, pending, events, new Set(['native-auto-id'])).length, 0);
  assert.equal(resolveNativeResults('gemini', request, pending, []).length, 0, 'model-visible output is not an observed success');
  const wrongArgs = events.map(event => ({ ...event, arguments: { file_path: '/other' } }));
  assert.equal(resolveNativeResults('gemini', request, pending, wrongArgs).length, 0);
  assert.throws(() => resolveNativeResults('gemini', request, pending, [...events, { ...events[0], failed: true }]), /NATIVE_RESULT_CONFLICT/);
  const ambiguous = new Map([...pending, ['second', { ...calls[0], id: 'second' }]]);
  assert.equal(resolveNativeResults('gemini', request, ambiguous, events).length, 0);
});
test('Gemini result association uses the latest response batch and explicit native status', () => {
  const call = { id: 'observer', wire_id: null, name: 'read_file', arguments: { path: '/task/latest' } }, pending = new Map([[call.id, call]]);
  const events = [{ id: 'current', name: 'read_file', arguments: call.arguments, failed: true, source: 'native-gemini-tool-result-status' }];
  const response = id => ({ role: 'user', parts: [{ functionResponse: { id, name: 'read_file', response: { output: 'data' } } }] });
  assert.equal(resolveNativeResults('gemini', { contents: [response('stale'), response('current')] }, pending, events)[0].failed, true);
  assert.equal(resolveNativeResults('gemini', { contents: [response('current'), response('stale')] }, pending, events).length, 0);
  assert.equal(resolveNativeResults(undefined, undefined, pending, events)[0].id, 'observer', 'final native events may close a pending observer ID');
  assert.deepEqual(nativeLogResults(JSON.stringify({ type: 'tool_result', tool_id: 'unknown', status: 'success' })), [], 'result names cannot be guessed without a native tool-use event');
});
test('Gemini prefixed native IDs bind exact explicit wire calls without changing provider history', () => {
  const call = { id: 'fixture-call-1', wire_id: 'fixture-call-1', name: 'activate_skill', arguments: { name: 'ud-validate', options: { a: 1, b: 2 } } };
  const pending = new Map([[call.id, call]]), nativeId = 'activate_skill__fixture-call-1';
  const request = { contents: [{ role: 'user', parts: [{ functionResponse: { id: call.id, name: call.name, response: { output: 'actual native output' } } }] }] };
  const before = JSON.stringify(request);
  const events = status => nativeLogResults([
    { type: 'tool_use', tool_id: nativeId, tool_name: call.name, parameters: { options: { b: 2, a: 1 }, name: 'ud-validate' } },
    { type: 'tool_result', tool_id: nativeId, status },
  ].map(JSON.stringify).join('\n'));
  for (const status of ['success', 'error']) {
    const result = resolveNativeResults('gemini', request, pending, events(status));
    assert.equal(result.length, 1); assert.equal(result[0].id, call.id); assert.equal(result[0].native_id, nativeId); assert.equal(result[0].failed, status === 'error');
  }
  assert.equal(JSON.stringify(request), before);
  assert.equal(resolveNativeResults(undefined, undefined, pending, events('success'))[0].id, call.id);
  assert.deepEqual(resolveNativeResults('gemini', request, pending, events('success'), new Set([nativeId])), []);
  for (const altered of [[], events('unknown'), events('success').map(event => ({ ...event, id: 'activate_skill__other' })),
    events('success').map(event => ({ ...event, name: 'read_file' })), events('success').map(event => ({ ...event, arguments: { name: 'different' } }))]) {
    assert.deepEqual(resolveNativeResults('gemini', request, pending, altered), []);
  }
  const stale = structuredClone(request); stale.contents[0].parts[0].functionResponse.id = 'stale';
  assert.deepEqual(resolveNativeResults('gemini', stale, pending, events('success')), []);
  const contradiction = structuredClone(request); contradiction.contents[0].parts[0].functionResponse.response.error = 'native failure';
  assert.throws(() => resolveNativeResults('gemini', contradiction, pending, events('success')), /NATIVE_RESULT_CONFLICT/);
  assert.throws(() => resolveNativeResults('gemini', request, pending, [...events('success'), ...events('error')]), /NATIVE_RESULT_CONFLICT/);
});
test('Gemini generated and already-prefixed IDs follow the native prefix and strip contract', () => {
  const name = 'read_file', args = { file_path: '/task/probe.txt' }, native = { id: 'read_file__auto-1', name, arguments: args, failed: false };
  const request = { contents: [{ role: 'user', parts: [{ functionResponse: { id: 'auto-1', name, response: { output: 'bytes' } } }] }] };
  for (const call of [{ id: 'observer', wire_id: null, name, arguments: args }, { id: native.id, wire_id: native.id, name, arguments: args }]) {
    const result = resolveNativeResults('gemini', request, new Map([[call.id, call]]), [native]);
    assert.equal(result.length, 1); assert.equal(result[0].id, call.id); assert.equal(result[0].native_id, native.id);
  }
  const calls = ['auto-1', native.id].map(id => ({ id, wire_id: id, name, arguments: args }));
  assert.deepEqual(resolveNativeResults('gemini', request, new Map(calls.map(call => [call.id, call])), [native]), [], 'colliding normalized identities remain unverified');
});
posixTest.each([undefined, 'fixture-call-1'])('Gemini gateway preserves wire IDs (%s) while charging native continuation', async wireId => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-gemini-observe-')));
  const nativeEvents = [], requests = [], records = [];
  const first = { candidates: [{ content: { role: 'model', parts: [{ functionCall: { ...(wireId ? { id: wireId } : {}), name: 'read_file', args: { file_path: '/task/probe.txt' } } }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1 } };
  const final = { candidates: [{ content: { role: 'model', parts: [{ text: 'inert complete' }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1 } };
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push(JSON.parse(body)); response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(requests.length === 1 ? first : final));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const budget = await createBudgetAuthority({ directory });
  const gateway = await createGateway({ upstream: `http://127.0.0.1:${server.address().port}`, model: 'fixture', budget, tokenize: async () => ({ trusted: true, inputTokens: 1 }), nativeResults: () => nativeEvents, record: event => records.push(event) });
  const send = body => fetch(gateway.url + '/v1beta/models/fixture:generateContent', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    const reply = await send({ contents: [{ role: 'user', parts: [{ text: 'Read probe.txt' }] }] });
    assert.equal(reply.status, 200); assert.deepEqual(await reply.json(), first);
    assert.equal(Object.hasOwn(first.candidates[0].content.parts[0].functionCall, 'id'), Boolean(wireId));
    const nativeId = `read_file__${wireId ?? 'native-auto-id'}`;
    nativeEvents.push({ id: nativeId, name: 'read_file', arguments: { file_path: '/task/probe.txt' }, failed: false, source: 'explicit-inert-native-event-fixture' });
    const result = { id: wireId ?? 'native-auto-id', name: 'read_file', response: { output: 'inert file bytes' } };
    const continuation = { contents: [{ role: 'model', parts: first.candidates[0].content.parts }, { role: 'user', parts: [{ functionResponse: result }] }] };
    assert.equal((await send(continuation)).status, 200);
    assert.deepEqual(requests[1].contents, continuation.contents);
    assert.equal(budget.snapshot().counters.tools, 1); assert.equal(budget.snapshot().counters.inference, 2);
    assert.equal(budget.snapshot().native_recovery.verified, true);
    const observed = records.find(event => event.type === 'native_result_observed');
    if (wireId) assert.equal(observed.id, wireId); else assert.match(observed.id, /^g-/);
    assert.equal(observed.native_id, nativeId);
  } finally {
    await gateway.close(); await budget.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true });
  }
});
