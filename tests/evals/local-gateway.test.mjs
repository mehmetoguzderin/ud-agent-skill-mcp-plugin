import { posixTest } from '../fixtures/native-scope.mjs';
// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { createBudgetAuthority } from '../../evals/local/budget.mjs';
import { createGateway } from '../../evals/local/gateway.mjs';

const model = 'fixture/model';
const textResponse = { choices: [{ message: { content: 'Done' }, finish_reason: 'stop' }], usage: { prompt_tokens: 100, completion_tokens: 5, completion_tokens_details: { reasoning_tokens: 3 } } };
async function fixture(action, { reply = textResponse, limits = {}, tokenize = async () => ({ trusted: true, inputTokens: 100 }), sampling = {}, seed, wireModel = model, supportedSampling = {}, customResponses = false } = {}) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-gateway-'))), requests = [], records = [];
  const upstream = http.createServer(async (request, response) => {
    let text = ''; for await (const part of request) text += part;
    requests.push({ path: request.url, body: JSON.parse(text), headers: request.headers });
    if (typeof reply === 'function') return reply(response);
    response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(reply));
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const budget = await createBudgetAuthority({ directory, limits });
  const gateway = await createGateway({ upstream: `http://127.0.0.1:${upstream.address().port}`, model, wireModel, budget, tokenize, sampling, seed, supportedSampling, customResponses, record: row => records.push(row) });
  const send = (body, route = '/v1/chat/completions') => fetch(gateway.url + route, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer private-value', 'x-api-key': 'private-key' }, body: JSON.stringify({ model, ...body }) });
  try { await action({ send, requests, records, budget, gateway }); }
  finally { await gateway.close(); await budget.close(); upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve)); await rm(directory, { recursive: true, force: true }); }
}
posixTest('records actual next request and bounded transport settings without leaking credentials', () => fixture(async ({ send, requests, records, budget }) => {
  assert.equal((await send({ messages: [{ role: 'user', content: 'Check data' }], max_tokens: 900 })).status, 200);
  const next = { messages: [{ role: 'user', content: 'Check data' }, { role: 'tool', tool_call_id: 'x', content: 'Actual returned evidence' }] };
  assert.equal((await send(next)).status, 200);
  assert.equal(requests[0].body.max_tokens, 512); assert.equal(requests[0].headers.authorization, undefined);
  assert.deepEqual(records.filter(row => row.type === 'provider_request')[1].body.messages, next.messages);
  assert.equal(records[0].headers.authorization, '[REDACTED]'); assert.equal(records[0].headers['x-api-key'], '[REDACTED]');
  assert.equal(budget.snapshot().counters.output, 10); // completion usage already includes reasoning
}));
posixTest('untrusted token counting and a different model never reach inference', async () => {
  await fixture(async ({ send, requests }) => { assert.equal((await send({})).status, 422); assert.equal(requests.length, 0); }, { tokenize: async () => ({ inputTokens: 100 }) });
  await fixture(async ({ send, requests }) => { assert.equal((await send({ model: 'other' })).status, 422); assert.equal(requests.length, 0); });
});
posixTest('private container event transport authenticates before charging and exposes only the active model', () => fixture(async ({ gateway, budget, requests }) => {
  const models = await (await fetch(gateway.url + '/v1/models')).json();
  assert.deepEqual(models.data.map(row => row.id), [model]);
  const event = { type: 'operation_start', operation_id: 'fixture-operation', name: 'validation_report', arguments: {} };
  const post = (token, value) => fetch(gateway.url + '/__eval_budget', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ event: value }) });
  assert.equal((await post('incorrect', event)).status, 403);
  assert.equal(budget.snapshot().counters.ud_operations, 0); assert.equal(budget.snapshot().stopped, null);
  assert.equal((await post(budget.token, event)).status, 200);
  assert.equal(budget.snapshot().counters.ud_operations, 1);
  assert.equal((await post(budget.token, { type: 'operation_result', operation_id: event.operation_id, response: { structuredContent: { execution: { status: 'completed' } } } })).status, 200);
  assert.equal(budget.snapshot().pending_operations, 0); assert.equal(requests.length, 0);
  const metadata = await fetch(gateway.url + '/api/show', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model }) });
  assert.equal(metadata.status, 404); assert.equal(budget.snapshot().stopped, null);
}));
posixTest('missing output usage cannot produce a qualifying or tool-dispatchable response', () => fixture(async ({ send, budget }) => {
  const response = await send({}); assert.equal(response.status, 422); assert.match(await response.text(), /OUTPUT_USAGE_UNVERIFIED/); assert.equal(budget.snapshot().stopped, 'OUTPUT_USAGE_UNVERIFIED');
}, { reply: { choices: textResponse.choices } }));
posixTest('backend input usage must match the exact count before exposing any result', async () => {
  await fixture(async ({ send, records, budget }) => {
    const response = await send({ messages: [{ role: 'user', content: 'Inspect data.' }] });
    assert.equal(response.status, 422); assert.match(await response.text(), /SERVER_TOKEN_ACCOUNTING_MISMATCH/);
    assert.equal(records.some(row => row.type === 'model_visible_response'), false);
    assert.equal(budget.snapshot().stopped, 'SERVER_TOKEN_ACCOUNTING_MISMATCH');
  }, { reply: { ...textResponse, usage: { prompt_tokens: 101, completion_tokens: 5 } } });
  await fixture(async ({ send, records }) => {
    assert.equal((await send({})).status, 200);
    assert.equal(records.find(row => row.type === 'provider_request').tokens.trusted, true);
    assert.equal(records.find(row => row.type === 'provider_request').tokens.inputTokens, 100);
  });
});
posixTest('streamed complete tool calls are buffered and rejected before native dispatch when over budget', () => fixture(async ({ send, budget, records }) => {
  const response = await send({ stream: true }); assert.equal(response.status, 422);
  const body = await response.text(); assert.match(body, /BUDGET_EXCEEDED_TOOLS/); assert.doesNotMatch(body, /erase_data/);
  assert.equal(budget.snapshot().counters.tools, 0); assert.equal(records.some(row => row.type === 'model_visible_response'), false);
}, { limits: { tools: 0 }, reply: response => {
  response.setHeader('content-type', 'text/event-stream');
  for (const row of [
    { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'call-1', type: 'function', function: { name: 'erase_data', arguments: '{' } }] } }] },
    { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '"path":"a"}' } }] }, finish_reason: 'tool_calls' }] },
    { choices: [], usage: { prompt_tokens: 100, completion_tokens: 20 } },
  ]) response.write(`data: ${JSON.stringify(row)}\n\n`);
  response.end('data: [DONE]\n\n');
} }));
posixTest('Responses completion and Anthropic streamed tool blocks retain native wire payloads', async () => {
  await fixture(async ({ send, budget }) => { assert.equal((await send({}, '/v1/responses')).status, 200); assert.equal(budget.snapshot().counters.tools, 1); }, { reply: { status: 'completed', output: [{ type: 'function_call', call_id: 'c1', name: 'inspect', arguments: '{}' }], usage: { input_tokens: 100, output_tokens: 10 } } });
  await fixture(async ({ send, budget }) => { const reply = await send({ stream: true }, '/v1/messages'); assert.equal(reply.status, 200); assert.match(await reply.text(), /message_stop/); assert.equal(budget.snapshot().counters.tools, 1); }, { reply: response => {
    response.setHeader('content-type', 'text/event-stream');
    for (const row of [
      { type: 'message_start', message: { usage: { input_tokens: 100, output_tokens: 0 } } },
      { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'c1', name: 'inspect', input: {} } },
      { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{}' } },
      { type: 'content_block_stop', index: 0 },
      { type: 'message_delta', delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 10 } },
      { type: 'message_stop' },
    ]) response.write(`data: ${JSON.stringify(row)}\n\n`);
    response.end();
  } });
});
posixTest('Gemini accounts for thought tokens and preserves the selected model path', () => fixture(async ({ send, budget, requests }) => {
  assert.equal((await send({ contents: [] }, '/v1beta/models/fixture%2Fmodel:generateContent')).status, 200);
  assert.equal(budget.snapshot().counters.output, 12); assert.equal(requests[0].body.generationConfig.maxOutputTokens, 512);
}, { reply: { candidates: [{ content: { parts: [{ text: 'Done' }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 5, thoughtsTokenCount: 7 } } }));
posixTest('verified custom Responses transport preserves exact input and counts it before dispatch', () => fixture(async ({ send, budget }) => {
  const response = await send({ tools: [{ type: 'custom', name: 'patch', format: { type: 'text' } }], stream: true }, '/v1/responses');
  assert.equal(response.status, 200); assert.match(await response.text(), /literal\\ninput/);
  assert.equal(budget.snapshot().counters.tools, 1);
}, { customResponses: true, reply: response => {
  const item = { type: 'custom_tool_call', call_id: 'c1', id: 'ct1', name: 'patch', input: 'literal\ninput' };
  response.setHeader('content-type', 'text/event-stream');
  for (const event of [{ type: 'response.output_item.added', output_index: 0, item: { ...item, input: '' } },
    { type: 'response.custom_tool_call_input.delta', output_index: 0, delta: item.input },
    { type: 'response.custom_tool_call_input.done', output_index: 0, input: item.input },
    { type: 'response.output_item.done', output_index: 0, item },
    { type: 'response.completed', response: { status: 'completed', output: [item], usage: { input_tokens: 100, output_tokens: 8 } } }]) response.write(`data: ${JSON.stringify(event)}\n\n`);
  response.end();
} }));
posixTest('frozen sampling and seeds override native defaults and unsupported protocol mappings block', async () => {
  let ordinal = 17;
  await fixture(async ({ send, requests, records }) => {
    await send({ temperature: 2, seed: 999, enable_thinking: true, chat_template_kwargs: { enable_thinking: true } });
    await send({});
    assert.equal(requests[0].body.temperature, 0.1); assert.equal(requests[0].body.seed, 17); assert.equal(requests[1].body.seed, 18);
    assert.equal(requests[0].body.chat_template_kwargs.enable_thinking, false);
    assert.equal(requests[0].body.enable_thinking, false);
    assert.equal(requests[0].body.top_n_sigma, null); assert.equal(requests[0].body.repetition_context_size, 20);
    assert.equal(records.find(row => row.type === 'upstream_request').effective_sampling.top_k, 50);
    const rejected = await send({}, '/v1/messages'); assert.equal(rejected.status, 422); assert.match(await rejected.text(), /SAMPLING_UNSUPPORTED_MESSAGES/);
    assert.equal(requests.length, 2);
  }, { sampling: { temperature: 0.1, top_k: 50, top_n_sigma: null, repetition_context_size: 20, enable_thinking: false }, seed: () => ordinal++ });
});
posixTest('Responses streaming cannot hide an additional dispatchable tool behind its final response', () => fixture(async ({ send, budget }) => {
  const response = await send({ stream: true }, '/v1/responses');
  assert.equal(response.status, 422); assert.match(await response.text(), /STREAM_TOOL_IDENTITY_MISMATCH/);
  assert.equal(budget.snapshot().counters.tools, 0);
}, { reply: response => {
  response.setHeader('content-type', 'text/event-stream');
  response.write(`data: ${JSON.stringify({ type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', call_id: 'hidden', name: 'hidden_tool', arguments: '' } })}\n\n`);
  response.end(`data: ${JSON.stringify({ type: 'response.completed', response: { status: 'completed', output: [], usage: { output_tokens: 10 } } })}\n\n`);
} }));
posixTest('public model identity maps only to its frozen local backend artifact', () => fixture(async ({ send, requests, records }) => {
  const response = await send({}); assert.equal(response.status, 200);
  assert.equal(requests[0].body.model, '/private/evaluation/exact-model');
  assert.equal(records.find(event => event.type === 'provider_request').body.model, model);
  assert.equal(records.find(event => event.type === 'upstream_request').body.model, '/private/evaluation/exact-model');
}, { wireModel: '/private/evaluation/exact-model' }));
posixTest('verified Responses sampler extensions preserve the frozen profile and seed without changing input', async () => {
  const reply = { status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: 'done' }] }], usage: { input_tokens: 100, output_tokens: 5 } };
  await fixture(async ({ send, requests }) => {
    const input = [{ role: 'user', content: 'Check this dataset' }];
    const response = await send({ input, top_k: 999, seed: 999, enable_thinking: true }, '/v1/responses');
    assert.equal(response.status, 200); assert.deepEqual(requests[0].body.input, input);
    assert.equal(requests[0].body.top_k, 50); assert.equal(requests[0].body.repetition_penalty, 1.1); assert.equal(requests[0].body.seed, 23); assert.equal(requests[0].body.enable_thinking, false); assert.equal(requests[0].body.p_less, false);
  }, { reply, sampling: { top_k: 50, repetition_penalty: 1.1, enable_thinking: false, p_less: false }, seed: 23, supportedSampling: { responses: ['top_k', 'repetition_penalty', 'enable_thinking', 'p_less', 'seed'] } });
  await fixture(async ({ send, requests }) => { const response = await send({}, '/v1/responses'); assert.equal(response.status, 422); assert.match(await response.text(), /SAMPLING_UNSUPPORTED_RESPONSES_TOP_K/); assert.equal(requests.length, 0); }, { reply, sampling: { top_k: 50 } });
});
posixTest('server-side compaction and tools the route would silently drop are explicit pre-inference blockers', async () => {
  for (const input of [{ context_management: [{ type: 'compaction', compact_threshold: 1000 }] }, { tools: [{ type: 'custom', name: 'apply_patch' }] }]) {
    await fixture(async ({ send, requests, records, budget }) => {
      const response = await send(input, '/v1/responses'); assert.equal(response.status, 422);
      assert.match(await response.text(), /SERVER_(COMPACTION|TOOL_TYPE)_UNSUPPORTED/);
      assert.equal(requests.length, 0); assert.equal(budget.snapshot().counters.inference, 0);
      assert.deepEqual(records.find(row => row.type === 'provider_received').body, { model, ...input });
      assert.equal(records.find(row => row.type === 'gateway_rejection').outcome, 'interface_unsupported');
    });
  }
});
posixTest('verified Chat disables implicit server compaction and clamps every output alias before generation', async () => {
  await fixture(async ({ send, requests }) => {
    const response = await send({ max_tokens: 8000, max_completion_tokens: 9000, max_output_tokens: 7000 });
    assert.equal(response.status, 200); assert.deepEqual(requests[0].body.context_management, []);
    for (const key of ['max_tokens', 'max_completion_tokens', 'max_output_tokens']) assert.equal(requests[0].body[key], 512);
  }, { supportedSampling: { chat: ['context_management'] } });
  await fixture(async ({ send, requests }) => {
    const response = await send({ context_management: [{ type: 'compaction', compact_threshold: 500 }] });
    assert.equal(response.status, 422); assert.equal(requests.length, 0);
  }, { supportedSampling: { chat: ['context_management'] } });
});
posixTest('Responses max_tokens precedence cannot bypass a smaller reserved output limit', () => fixture(async ({ send, requests }) => {
  const response = await send({ max_tokens: 5000, max_completion_tokens: 6000, max_output_tokens: 12 }, '/v1/responses');
  assert.equal(response.status, 200);
  for (const key of ['max_tokens', 'max_completion_tokens', 'max_output_tokens']) assert.equal(requests[0].body[key], 12);
}, { reply: { status: 'completed', output: [], usage: { input_tokens: 100, output_tokens: 5 } } }));

test('gateway admission rejects remote upstreams and an absent budget before exposing a listener', async () => {
  for (const upstream of ['https://127.0.0.1:19999', 'http://example.com:19999', 'http://secret@localhost:19999', 'http://localhost:19999?token=secret']) {
    await assert.rejects(createGateway({ upstream, model, tokenize: async () => ({ trusted: true, inputTokens: 1 }) }), /LOCAL_UPSTREAM_REQUIRED/);
  }
  await assert.rejects(createGateway({ upstream: 'http://127.0.0.1:19999', model, tokenize: async () => ({ trusted: true, inputTokens: 1 }) }), /GATEWAY_CONFIGURATION_INVALID/);
});
if (process.platform === 'win32') test('Windows gateway setup cannot obtain a POSIX budget capability', async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-gateway-refusal-')));
  try { await assert.rejects(createBudgetAuthority({ directory }), /BUDGET_PLATFORM_UNSUPPORTED/); }
  finally { await rm(directory, { recursive: true, force: true }); }
});
