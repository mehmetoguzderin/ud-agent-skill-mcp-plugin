import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { measureEpisodeContext } from '../../evals/local/measurements.mjs';

const count = body => JSON.stringify(body).length; // Inert tokenizer fixture only.
function eventsFor(id, body, protocol = 'chat', generated = 23) {
  return [{ type: 'provider_request', id, path: '/v1/chat/completions', body, tokens: { trusted: true, inputTokens: count(body), contextTokens: count(body) } },
    { type: 'upstream_request', id, protocol, body },
    { type: 'provider_response', id, protocol, status: 200, streaming: false, body: { usage: { prompt_tokens: count(body), completion_tokens: generated } } },
    { type: 'model_visible_response', id, outputTokens: generated }];
}
async function installed(run) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-measurements-'));
  const body = '# Validate data\n' + 'Use the canonical validation operation and inspect the returned evidence. '.repeat(3);
  try {
    for (const name of ['ud-validate', 'ud-edit', 'ud-compare', 'ud-investigate', 'ud-rules-docs', 'ud-release']) {
      const skill = path.join(directory, 'skills', name); mkdirSync(skill, { recursive: true });
      writeFileSync(path.join(skill, 'SKILL.md'), `---\nname: ${name}\n---\n\n${name === 'ud-validate' ? body : '# Unused ' + name + '\n' + 'Independent guidance. '.repeat(8)}\n`);
    }
    await run(directory, body.trim());
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('observed totals retain all requests while one largest request receives at most six count-only ablations', () => installed(async (installation, skill) => {
  const first = { model: 'wire', messages: [{ role: 'user', content: 'Validate the treebank.' }] };
  const body = { model: 'wire', messages: [{ role: 'system', content: 'Native harness instructions.' },
    { role: 'user', content: [{ type: 'text', text: 'Validate the treebank.' }, { type: 'image_url', image_url: { url: 'data:image/png;base64,AA==' } }] },
    { role: 'assistant', content: null, tool_calls: [{ type: 'function', id: 'read-1', function: { name: 'shell', arguments: '{}' } }] },
    { role: 'tool', tool_call_id: 'read-1', content: skill + '\nActual report: invalid line 2.' }],
    tools: [{ type: 'function', function: { name: 'mcp__ud__validate', description: 'UD metadata', parameters: {} } }, { type: 'function', function: { name: 'shell', description: 'Native shell', parameters: {} } }] };
  const events = [...eventsFor('startup', first, 'chat', 11), ...eventsFor('largest', body, 'chat', 23)], before = structuredClone(events), calls = [];
  const result = await measureEpisodeContext({ events, installation, operations: [{ operation: 'validate' }], tokenize: async request => {
    calls.push(structuredClone(request.body)); assert.equal(request.countOnly, true); assert.ok(request.signal instanceof AbortSignal);
    return { trusted: true, inputTokens: count(request.body), contextTokens: count(request.body) };
  } });
  assert.deepEqual(events, before);
  assert.equal(result.inference_requests, 0);
  assert.equal(result.observed.submitted_input.observed_tokens, count(first) + count(body));
  assert.equal(result.observed.generated_output.observed_tokens, 34);
  assert.equal(result.startup.request_id, 'startup');
  assert.equal(result.decomposition.request_id, 'largest');
  assert.equal(result.decomposition.count_calls, 6);
  assert.equal(result.decomposition.status, 'complete');
  assert.equal(calls[0].tools.length, 2); assert.equal(calls[1].tools.length, 1);
  assert.equal(calls[2].messages.at(-1).content.includes(skill), false);
  assert.equal(calls[3].messages[1].content.length, 1);
  assert.equal(calls[4].messages.at(-1).content, '');
  assert.equal(calls[5].messages.some(message => message.role === 'system'), false);
  assert.equal(calls[5].tools.length, 0);
  const deltas = Object.values(result.decomposition.components).reduce((sum, component) => sum + component.marginal_input_tokens, 0);
  assert.equal(deltas + result.decomposition.residual_input_tokens, count(body));
}));

test('missing output evidence and unavailable counters remain explicit rather than zero-cost conclusions', async () => {
  const body = { messages: [{ role: 'user', content: 'hello' }] }, events = eventsFor('one', body).slice(0, 2);
  const result = await measureEpisodeContext({ events });
  assert.equal(result.observed.generated_output.status, 'partial');
  assert.equal(result.observed.generated_output.observed_requests, 0);
  assert.equal(result.decomposition.status, 'unavailable');
  assert.ok(Object.values(result.decomposition.components).every(component => component.status === 'unavailable' && component.marginal_input_tokens === undefined));
});

test('count drift fails the marginal reconciliation without replacing exact observed totals', async () => {
  const body = { messages: [{ role: 'user', content: 'hello' }] };
  const result = await measureEpisodeContext({ events: eventsFor('one', body), operations: ['validate'], tokenize: async () => ({ trusted: true, inputTokens: count(body) + 1 }) });
  assert.equal(result.decomposition.count_calls, 1);
  assert.equal(result.decomposition.status, 'unavailable');
  assert.ok(Object.values(result.decomposition.components).every(component => component.reason === 'MEASUREMENT_BASELINE_COUNT_MISMATCH'));
  assert.equal(result.observed.submitted_input.observed_tokens, count(body));
});

test('mixed UD discovery text prevents a pure native-overhead claim and no missing skill source is inferred absent', async () => {
  const body = { messages: [{ role: 'system', content: 'Native instructions. Available skill: ud-validate.' }, { role: 'user', content: 'hello' }], tools: [{ type: 'function', function: { name: 'shell', parameters: {} } }] };
  const result = await measureEpisodeContext({ events: eventsFor('one', body), operations: ['validate'], tokenize: async request => ({ trusted: true, inputTokens: count(request.body) }) });
  assert.equal(result.decomposition.components.activated_skill_bodies.status, 'unavailable');
  assert.equal(result.decomposition.components.native_harness_overhead.status, 'partial');
  assert.match(result.decomposition.components.native_harness_overhead.reason, /mixed/);
  assert.ok(result.decomposition.count_calls <= 6);
});

test('count-only deadline aborts a stalled counter and preserves missing components', async () => {
  vi.useFakeTimers();
  try {
    let signal;
    const body = { messages: [{ role: 'user', content: 'hello' }] };
    const pending = measureEpisodeContext({ events: eventsFor('one', body), tokenize: async request => { signal = request.signal; return new Promise(() => {}); } });
    await vi.advanceTimersByTimeAsync(10_000);
    const result = await pending;
    assert.equal(signal.aborted, true);
    assert.equal(result.decomposition.count_calls, 1);
    assert.equal(result.decomposition.status, 'unavailable');
    assert.equal(result.decomposition.elapsed_ms, 10_000);
  } finally { vi.useRealTimers(); }
});

test('streaming observed token accounting distinguishes Responses, Messages and Gemini reasoning tokens', async () => {
  const rows = [];
  const fixtures = [
    ['responses', [{ type: 'response.completed', response: { usage: { input_tokens: 10, output_tokens: 12 } } }]],
    ['messages', [{ type: 'message_start', message: { usage: { input_tokens: 10, output_tokens: 0 } } }, { type: 'message_delta', usage: { output_tokens: 13 } }, { type: 'message_stop' }]],
    ['gemini', [{ usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 14, thoughtsTokenCount: 2 } }]],
  ];
  for (const [protocol, body] of fixtures) rows.push({ type: 'provider_request', id: protocol, tokens: { trusted: true, inputTokens: 10 }, body: {} }, { type: 'upstream_request', id: protocol, protocol, body: {} }, { type: 'provider_response', id: protocol, protocol, status: 200, streaming: true, body });
  const result = await measureEpisodeContext({ events: rows });
  assert.equal(result.observed.generated_output.observed_tokens, 41);
  assert.equal(result.observed.generated_output.status, 'complete');
  assert.equal(result.observed.model_visible_output.status, 'partial');
});
