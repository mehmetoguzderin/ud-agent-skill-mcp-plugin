// SPDX-License-Identifier: MIT
/** Local transport observer and budget gate; never selects tools or repairs arguments. */
import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { randomUUID } from 'node:crypto';
import { responseNativeCalls, resolveNativeResults } from './native-observations.mjs';
import { validateResponsesNamespaces, validateResponsesOutput } from './responses-namespace.mjs';

const fail = message => Object.assign(new Error(message), { code: message });
const integer = value => Number.isSafeInteger(value) && value >= 0;
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const SECRET = /^(?:authorization|proxy-authorization|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|password|secret)$/i;
const CHAT_SAMPLERS = ['temperature', 'top_p', 'top_k', 'repetition_penalty', 'presence_penalty', 'frequency_penalty', 'min_p', 'top_n_sigma', 'p_less', 'typical_p', 'repetition_context_size', 'presence_context_size', 'frequency_context_size'];
const RESPONSE_CALL_TYPES = new Set(['function_call', 'shell_call', 'apply_patch_call', 'custom_tool_call']);
export function gatewayOutcome(reason) {
  if (/CONTEXT|TOKEN_COUNT|OUTPUT_USAGE|INPUT_USAGE|TOKEN_ACCOUNTING/.test(reason)) return 'context_resource_blocked';
  if (/BUDGET_EXCEEDED_(INPUT|OUTPUT)/.test(reason)) return 'token_budget_exceeded';
  if (/TIMEOUT/.test(reason)) return 'timed_out';
  if (/UNSUPPORTED|MODEL_NOT_ADMITTED/.test(reason)) return 'interface_unsupported';
  return 'failed';
}
export function redactTraffic(value) {
  if (Array.isArray(value)) return value.map(redactTraffic);
  if (object(value)) return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, SECRET.test(key) ? '[REDACTED]' : redactTraffic(child)]));
  return typeof value === 'string' ? value.replace(/Bearer\s+[A-Za-z0-9._~+\/-]+/gi, 'Bearer [REDACTED]') : value;
}
function functionCall(value) {
  if (!object(value) || typeof value.name !== 'string' || !value.name) throw fail('TOOL_CALL_UNSUPPORTED');
  if (typeof value.arguments === 'string') {
    try { if (!object(JSON.parse(value.arguments))) throw fail('TOOL_ARGUMENTS_INCOMPLETE'); } catch { throw fail('TOOL_ARGUMENTS_INCOMPLETE'); }
  } else if (!object(value.arguments)) throw fail('TOOL_ARGUMENTS_INCOMPLETE');
}
function toolCount(protocol, response) {
  if (protocol === 'chat') {
    if (!Array.isArray(response.choices) || response.choices.length !== 1 || !object(response.choices[0].message)) throw fail('PROVIDER_RESPONSE_UNSUPPORTED');
    const choice = response.choices[0], message = choice.message, calls = message.tool_calls ?? [];
    if (!Array.isArray(calls) || message.function_call) throw fail('TOOL_CALL_UNSUPPORTED');
    for (const call of calls) { if (call.type !== 'function' || typeof call.id !== 'string' || !call.id) throw fail('TOOL_CALL_UNSUPPORTED'); functionCall(call.function); }
    if (calls.length && choice.finish_reason !== 'tool_calls') throw fail('TOOL_ARGUMENTS_INCOMPLETE');
    return calls.length;
  }
  if (protocol === 'responses') {
    if (!Array.isArray(response.output) || response.status !== 'completed') throw fail('PROVIDER_RESPONSE_INCOMPLETE');
    let count = 0;
    for (const item of response.output) {
      if (item.type === 'function_call') { functionCall(item); if (typeof item.call_id !== 'string' || !item.call_id) throw fail('TOOL_CALL_UNSUPPORTED'); count++; }
      else if (item.type === 'custom_tool_call') { if (typeof item.call_id !== 'string' || !item.call_id || typeof item.name !== 'string' || !item.name || typeof item.input !== 'string') throw fail('TOOL_CALL_UNSUPPORTED'); count++; }
      else if (item.type === 'shell_call') { if (typeof item.call_id !== 'string' || !item.call_id || !object(item.action) || item.action.type !== 'exec' || typeof item.action.command !== 'string' && (!Array.isArray(item.action.command) || item.action.command.some(command => typeof command !== 'string'))) throw fail('TOOL_CALL_UNSUPPORTED'); count++; }
      else if (item.type === 'apply_patch_call') { if (typeof item.call_id !== 'string' || !item.call_id || typeof item.patch !== 'string' && !object(item.operation)) throw fail('TOOL_CALL_UNSUPPORTED'); count++; }
      else if (!['message', 'reasoning'].includes(item.type)) throw fail('TOOL_CALL_UNSUPPORTED');
    }
    return count;
  }
  if (protocol === 'messages') {
    if (!Array.isArray(response.content)) throw fail('PROVIDER_RESPONSE_UNSUPPORTED');
    let count = 0;
    for (const item of response.content) {
      if (item.type === 'tool_use') { if (typeof item.id !== 'string' || !item.id) throw fail('TOOL_CALL_UNSUPPORTED'); functionCall({ name: item.name, arguments: item.input }); count++; }
      else if (!['text', 'thinking', 'redacted_thinking'].includes(item.type)) throw fail('TOOL_CALL_UNSUPPORTED');
    }
    if (count && response.stop_reason !== 'tool_use') throw fail('TOOL_ARGUMENTS_INCOMPLETE');
    return count;
  }
  if (!Array.isArray(response.candidates) || response.candidates.length !== 1) throw fail('PROVIDER_RESPONSE_UNSUPPORTED');
  const candidate = response.candidates[0];
  if (!Array.isArray(candidate.content?.parts)) throw fail('PROVIDER_RESPONSE_UNSUPPORTED');
  let count = 0;
  for (const item of candidate.content.parts) {
    if (item.functionCall) { functionCall({ name: item.functionCall.name, arguments: item.functionCall.args }); count++; }
    else if (typeof item.text !== 'string' && !item.thoughtSignature) throw fail('PROVIDER_RESPONSE_UNSUPPORTED');
  }
  if (count && candidate.finishReason !== 'STOP') throw fail('TOOL_ARGUMENTS_INCOMPLETE');
  return count;
}
function outputUsage(protocol, response) {
  const usage = protocol === 'gemini' ? response.usageMetadata : response.usage;
  if (!object(usage)) throw fail('OUTPUT_USAGE_UNVERIFIED');
  let count;
  if (protocol === 'chat') {
    count = usage.completion_tokens;
    if (usage.completion_tokens_details?.reasoning_tokens !== undefined && (!integer(usage.completion_tokens_details.reasoning_tokens) || usage.completion_tokens_details.reasoning_tokens > count)) throw fail('OUTPUT_USAGE_UNVERIFIED');
  } else if (protocol === 'gemini') {
    if (!integer(usage.candidatesTokenCount) || (usage.thoughtsTokenCount !== undefined && !integer(usage.thoughtsTokenCount))) throw fail('OUTPUT_USAGE_UNVERIFIED');
    count = usage.candidatesTokenCount + (usage.thoughtsTokenCount ?? 0);
  } else {
    count = usage.output_tokens;
    if (usage.output_tokens_details?.reasoning_tokens !== undefined && (!integer(usage.output_tokens_details.reasoning_tokens) || usage.output_tokens_details.reasoning_tokens > count)) throw fail('OUTPUT_USAGE_UNVERIFIED');
  }
  if (!integer(count)) throw fail('OUTPUT_USAGE_UNVERIFIED');
  return count;
}
function inputUsage(protocol, response) {
  const usage = protocol === 'gemini' ? response.usageMetadata : response.usage;
  if (!object(usage)) throw fail('INPUT_USAGE_UNVERIFIED');
  const value = protocol === 'chat' ? usage.prompt_tokens : protocol === 'gemini' ? usage.promptTokenCount : usage.input_tokens;
  if (!integer(value)) throw fail('INPUT_USAGE_UNVERIFIED');
  if (protocol === 'messages') {
    const cached = [usage.cache_read_input_tokens ?? 0, usage.cache_creation_input_tokens ?? 0];
    if (!cached.every(integer)) throw fail('INPUT_USAGE_UNVERIFIED');
    return value + cached[0] + cached[1];
  }
  return value;
}
function events(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes).replaceAll('\r\n', '\n');
  const output = [];
  for (const block of text.split('\n\n')) {
    const data = block.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
    if (data && data !== '[DONE]') { try { output.push(JSON.parse(data)); } catch { throw fail('STREAM_PROTOCOL_UNSUPPORTED'); } }
  }
  if (!output.length) throw fail('STREAM_PROTOCOL_UNSUPPORTED');
  return output;
}
function streamedResponse(protocol, rows) {
  if (protocol === 'responses') {
    const complete = rows.filter(row => row.type === 'response.completed');
    if (complete.length !== 1 || rows.some(row => ['error', 'response.failed', 'response.incomplete'].includes(row.type))) throw fail('PROVIDER_RESPONSE_INCOMPLETE');
    const final = complete[0].response, calls = new Map((final?.output ?? []).filter(item => RESPONSE_CALL_TYPES.has(item.type)).map(item => [item.call_id, item]));
    const indexes = new Map();
    const allowed = new Set(['response.created', 'response.in_progress', 'response.output_item.added', 'response.output_item.done', 'response.content_part.added', 'response.content_part.done', 'response.output_text.delta', 'response.output_text.done', 'response.refusal.delta', 'response.refusal.done', 'response.function_call_arguments.delta', 'response.function_call_arguments.done', 'response.custom_tool_call_input.delta', 'response.custom_tool_call_input.done', 'response.reasoning_summary_part.added', 'response.reasoning_summary_part.done', 'response.reasoning_summary_text.delta', 'response.reasoning_summary_text.done', 'response.reasoning_text.delta', 'response.reasoning_text.done', 'response.completed']);
    for (const row of rows) {
      if (!allowed.has(row.type)) throw fail('STREAM_PROTOCOL_UNSUPPORTED');
      if (row.type === 'response.output_item.added' || row.type === 'response.output_item.done') {
        const item = row.item;
        if (!item || !['message', 'reasoning', ...RESPONSE_CALL_TYPES].includes(item.type)) throw fail('TOOL_CALL_UNSUPPORTED');
        if (RESPONSE_CALL_TYPES.has(item.type)) {
          const expected = calls.get(item.call_id);
          if (!expected || item.type !== expected.type || item.id !== expected.id || item.name !== expected.name || item.namespace !== expected.namespace || row.type === 'response.output_item.done' && item.type === 'function_call' && item.arguments !== expected.arguments) throw fail('STREAM_TOOL_IDENTITY_MISMATCH');
          if (row.type === 'response.output_item.done' && item.type === 'custom_tool_call' && item.input !== expected.input) throw fail('STREAM_TOOL_IDENTITY_MISMATCH');
          const existing = indexes.get(row.output_index);
          if (existing && existing !== item.call_id) throw fail('STREAM_TOOL_IDENTITY_MISMATCH');
          indexes.set(row.output_index, item.call_id);
        }
      }
      if (row.type === 'response.function_call_arguments.delta' || row.type === 'response.function_call_arguments.done') {
        const expected = calls.get(indexes.get(row.output_index));
        if (!expected || row.type === 'response.function_call_arguments.done' && expected.type === 'function_call' && row.arguments !== expected.arguments) throw fail('STREAM_TOOL_IDENTITY_MISMATCH');
      }
      if (row.type === 'response.custom_tool_call_input.delta' || row.type === 'response.custom_tool_call_input.done') {
        const expected = calls.get(indexes.get(row.output_index));
        if (!expected || expected.type !== 'custom_tool_call' || row.type.endsWith('.done') && row.input !== expected.input) throw fail('STREAM_TOOL_IDENTITY_MISMATCH');
      }
    }
    return final;
  }
  if (protocol === 'chat') {
    const calls = new Map(); let usage, finish;
    for (const row of rows) {
      if (row.error || !Array.isArray(row.choices) || row.choices.length > 1) throw fail('STREAM_PROTOCOL_UNSUPPORTED');
      if (row.usage) usage = row.usage;
      for (const choice of row.choices) {
        if (choice.index !== 0 || choice.delta?.function_call) throw fail('STREAM_PROTOCOL_UNSUPPORTED');
        if (choice.finish_reason) finish = choice.finish_reason;
        for (const call of choice.delta?.tool_calls ?? []) {
          if (!integer(call.index)) throw fail('STREAM_PROTOCOL_UNSUPPORTED');
          const current = calls.get(call.index) ?? { id: '', type: 'function', function: { name: '', arguments: '' } };
          if (call.type && call.type !== 'function') throw fail('TOOL_CALL_UNSUPPORTED');
          current.id += call.id ?? ''; current.function.name += call.function?.name ?? ''; current.function.arguments += call.function?.arguments ?? ''; calls.set(call.index, current);
        }
      }
    }
    if (!finish) throw fail('PROVIDER_RESPONSE_INCOMPLETE');
    return { usage, choices: [{ finish_reason: finish, message: { tool_calls: [...calls.values()] } }] };
  }
  if (protocol === 'messages') {
    const blocks = new Map(); let usage, stop, ended = false;
    for (const row of rows) {
      if (row.type === 'error') throw fail('PROVIDER_RESPONSE_INCOMPLETE');
      if (row.type === 'message_start') usage = row.message?.usage;
      if (row.type === 'content_block_start') { if (!integer(row.index) || blocks.has(row.index)) throw fail('STREAM_PROTOCOL_UNSUPPORTED'); blocks.set(row.index, { ...row.content_block }); }
      if (row.type === 'content_block_delta' && row.delta?.type === 'input_json_delta') {
        const block = blocks.get(row.index); if (!block || block.type !== 'tool_use') throw fail('STREAM_PROTOCOL_UNSUPPORTED');
        block.partial = (block.partial ?? '') + row.delta.partial_json;
      }
      if (row.type === 'message_delta') { usage = { ...usage, ...row.usage }; stop = row.delta?.stop_reason ?? stop; }
      if (row.type === 'message_stop') ended = true;
    }
    if (!ended || !stop) throw fail('PROVIDER_RESPONSE_INCOMPLETE');
    const content = [...blocks.values()].map(block => {
      if (block.partial !== undefined) { try { block.input = JSON.parse(block.partial); delete block.partial; } catch { throw fail('TOOL_ARGUMENTS_INCOMPLETE'); } }
      return block;
    });
    return { usage, content, stop_reason: stop };
  }
  const parts = []; let usageMetadata, finishReason;
  for (const row of rows) {
    if (row.error || !Array.isArray(row.candidates) || row.candidates.length !== 1) throw fail('STREAM_PROTOCOL_UNSUPPORTED');
    if (row.usageMetadata) usageMetadata = row.usageMetadata;
    parts.push(...(row.candidates[0].content?.parts ?? [])); finishReason = row.candidates[0].finishReason ?? finishReason;
  }
  if (!finishReason) throw fail('PROVIDER_RESPONSE_INCOMPLETE');
  return { usageMetadata, candidates: [{ content: { parts }, finishReason }] };
}
async function boundedBytes(stream, maximum) {
  const chunks = []; let size = 0;
  for await (const bytes of stream) { size += bytes.length; if (size > maximum) throw fail('TRAFFIC_SIZE_EXCEEDED'); chunks.push(Buffer.from(bytes)); }
  return Buffer.concat(chunks);
}
function route(url, body, model, customResponses = false) {
  let protocol;
  if (url.pathname === '/v1/chat/completions') protocol = 'chat';
  else if (url.pathname === '/v1/responses') protocol = 'responses';
  else if (url.pathname === '/v1/messages') protocol = 'messages';
  else {
    const match = /^\/v1(?:beta)?\/models\/(.+):(generateContent|streamGenerateContent)$/.exec(url.pathname);
    if (!match) throw fail('PROVIDER_ROUTE_UNSUPPORTED');
    if (decodeURIComponent(match[1]) !== model) throw fail('MODEL_NOT_ADMITTED');
    protocol = 'gemini';
  }
  if (protocol !== 'gemini' && body.model !== model) throw fail('MODEL_NOT_ADMITTED');
  if (body.n !== undefined && body.n !== 1 || body.generationConfig?.candidateCount !== undefined && body.generationConfig.candidateCount !== 1 || body.background === true) throw fail('PROVIDER_REQUEST_UNSUPPORTED');
  if (['chat', 'responses'].includes(protocol) && (body.context_management !== undefined && (!Array.isArray(body.context_management) || body.context_management.length !== 0) || body.compaction !== undefined)) throw fail('SERVER_COMPACTION_UNSUPPORTED');
  if (protocol === 'responses') validateResponsesNamespaces(body, { customResponses, nativeTools: true });
  return protocol;
}
function frozenSampling(protocol, body, sampling, seed, supportedSampling) {
  const extensions = new Set(supportedSampling[protocol] ?? []);
  const map = protocol === 'gemini' ? { temperature: 'temperature', top_p: 'topP', top_k: 'topK', presence_penalty: 'presencePenalty' }
    : protocol === 'responses' ? { temperature: 'temperature', top_p: 'top_p' }
      : protocol === 'messages' ? { temperature: 'temperature', top_p: 'top_p', top_k: 'top_k' }
        : Object.fromEntries(CHAT_SAMPLERS.map(key => [key, key]));
  const target = protocol === 'gemini' ? body.generationConfig ??= {} : body;
  for (const [key, value] of Object.entries(sampling)) {
    if (key === 'enable_thinking' && protocol === 'chat') { body.enable_thinking = value; body.chat_template_kwargs = { ...body.chat_template_kwargs, enable_thinking: value }; continue; }
    if (extensions.has(key)) { target[key] = value; continue; }
    if (!Object.hasOwn(map, key)) throw fail(`SAMPLING_UNSUPPORTED_${protocol.toUpperCase()}_${key.toUpperCase()}`);
    target[map[key]] = value;
  }
  if (seed !== undefined) {
    if (!integer(seed) || seed > 0xffffffff) throw fail('SAMPLING_SEED_INVALID');
    if (!['chat', 'gemini'].includes(protocol) && !extensions.has('seed')) throw fail(`SAMPLING_UNSUPPORTED_${protocol.toUpperCase()}_SEED`);
    target.seed = seed;
  }
  return { ...sampling, ...(seed === undefined ? {} : { seed }) };
}

/** All upstream protocols must be supported by the selected server/gateway itself. */
export async function createGateway({ upstream, model, wireModel = model, budget, tokenize, record = async () => {}, sampling = {}, seed, supportedSampling = {}, customResponses = false, nativeResults = () => [] }) {
  const base = new URL(upstream);
  if (base.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost', 'host.docker.internal'].includes(base.hostname) || base.username || base.password || base.search || base.hash) throw fail('LOCAL_UPSTREAM_REQUIRED');
  if (typeof model !== 'string' || !model || typeof wireModel !== 'string' || !wireModel || typeof tokenize !== 'function' || !budget?.reserveInference || !budget?.finishInference || !budget?.stop) throw fail('GATEWAY_CONFIGURATION_INVALID');
  if (!object(sampling) || Object.entries(sampling).some(([key, value]) => ['enable_thinking', 'p_less'].includes(key) ? typeof value !== 'boolean' : !CHAT_SAMPLERS.includes(key) || value !== null && !Number.isFinite(value))) throw fail('SAMPLING_CONFIGURATION_INVALID');
  if (!object(supportedSampling) || Object.entries(supportedSampling).some(([protocol, fields]) => !['chat', 'responses', 'messages', 'gemini'].includes(protocol) || !Array.isArray(fields) || fields.some(field => typeof field !== 'string'))) throw fail('SAMPLING_CAPABILITIES_INVALID');
  const lifetime = new AbortController(), active = new Set();
  const log = async event => record(redactTraffic(event));
  const pendingNative = new Map(), consumedNativeIds = new Set();
  async function reconcileNativeResults(protocol, body, final = false) {
    if (!budget.nativeResult || !pendingNative.size) return;
    for (let attempt = 0; attempt < 6; attempt++) {
      const observed = resolveNativeResults(protocol, body, pendingNative, await nativeResults(), consumedNativeIds);
      for (const result of observed) if (pendingNative.has(result.id)) {
        await budget.nativeResult({ id: result.id, failed: result.failed });
        consumedNativeIds.add(result.native_id ?? result.id);
        pendingNative.delete(result.id);
        await log({ type: 'native_result_observed', ...result });
      }
      if (!pendingNative.size) return;
      // Native stdout and the provider socket use separate pipes. Allow their
      // bounded delivery skew, never infer success from model-visible prose.
      if (attempt < 5) await new Promise(resolve => setTimeout(resolve, 20));
    }
    const id = pendingNative.keys().next().value;
    await log({ type: 'native_result_missing', id, final });
    try { await budget.nativeResult({ id, failed: null }); }
    finally { pendingNative.delete(id); }
  }
  const server = http.createServer(async (request, response) => {
    const id = randomUUID(), controller = new AbortController(); active.add(controller);
    let reserved;
    const abort = () => { if (!response.writableEnded) { controller.abort(); if (reserved) void budget.stop('CLIENT_CANCELLED'); } };
    response.on('close', abort);
    try {
      const requestUrl = new URL(request.url, 'http://127.0.0.1');
      if (request.method === 'GET' && requestUrl.pathname === '/v1/models') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ object: 'list', data: [{ id: model, object: 'model', owned_by: 'local-evaluation' }] })); return;
      }
      // Grok probes the root; Hermes tries these server metadata endpoints.
      // They are absent, rather than inference failures: preserve that negative
      // observation without pretending this gateway is LM Studio or Ollama.
      if (request.method === 'GET' && (['/', '/api/v1/models', '/api/tags', '/v1/props', '/props', '/version'].includes(requestUrl.pathname)
        || requestUrl.pathname === `/v1/models/${model}` || requestUrl.pathname === `/v1/models/${encodeURIComponent(model)}`)) {
        await log({ type: 'provider_metadata_probe', id, path: requestUrl.pathname, status: 404, inference: false });
        response.writeHead(404, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: 'Server-specific metadata is not provided by this local OpenAI-compatible endpoint.' })); return;
      }
      if (request.method === 'POST' && requestUrl.pathname === '/api/show') {
        const body = JSON.parse(await boundedBytes(request, 65536));
        await log({ type: 'provider_metadata_probe', id, path: requestUrl.pathname, body, status: 404, inference: false });
        response.writeHead(404, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: 'Ollama metadata is not provided by this local OpenAI-compatible endpoint.' })); return;
      }
      if (request.method === 'POST' && requestUrl.pathname === '/__eval_budget') {
        const supplied = Buffer.from(String(request.headers.authorization ?? ''));
        const expected = Buffer.from(`Bearer ${budget.token}`);
        if (!budget.token || supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
          response.writeHead(403); response.end(JSON.stringify({ ok: false, error: 'BUDGET_UNAUTHORIZED' })); return;
        }
        const payload = JSON.parse(await boundedBytes(request, 2 * 1024 * 1024));
        if (!object(payload) || Object.keys(payload).length !== 1 || !object(payload.event)) throw fail('BUDGET_EVENT_INVALID');
        const value = await budget.event(payload.event);
        response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ ok: true, value })); return;
      }
      if (request.method !== 'POST') throw fail('PROVIDER_ROUTE_UNSUPPORTED');
      const url = new URL(request.url, 'http://127.0.0.1'), bytes = await boundedBytes(request, 16 * 1024 * 1024);
      let body; try { body = JSON.parse(bytes); } catch { throw fail('PROVIDER_REQUEST_INVALID'); }
      if (!object(body)) throw fail('PROVIDER_REQUEST_INVALID');
      await log({ type: 'provider_received', id, path: url.pathname, headers: request.headers, body });
      const counting = url.pathname === '/v1/messages/count_tokens';
      const protocol = route(counting ? new URL('/v1/messages', url) : url, body, model, customResponses);
      if (!counting) await reconcileNativeResults(protocol, body);
      const field = protocol === 'responses' ? 'max_output_tokens' : 'max_tokens';
      const aliases = ['max_tokens', 'max_completion_tokens', 'max_output_tokens'];
      const supplied = aliases.filter(key => body[key] !== undefined).map(key => body[key]);
      if (protocol === 'gemini' && body.generationConfig?.maxOutputTokens !== undefined) supplied.push(body.generationConfig.maxOutputTokens);
      if (supplied.some(value => !integer(value) || value < 1)) throw fail('PROVIDER_REQUEST_INVALID');
      const requested = supplied.length ? Math.min(...supplied) : undefined;
      const forwarded = structuredClone(body);
      if (protocol !== 'gemini') forwarded.model = wireModel;
      // The pinned MLX server otherwise enables automatic Chat compaction even
      // when omitted. Only set this control for an inspected backend field.
      if (['chat', 'responses'].includes(protocol) && supportedSampling[protocol]?.includes('context_management')) forwarded.context_management = [];
      const effectiveSampling = frozenSampling(protocol, forwarded, sampling, counting ? undefined : typeof seed === 'function' ? seed() : seed, supportedSampling);
      const count = await tokenize({ protocol, path: url.pathname, body: forwarded });
      if (!object(count) || count.trusted !== true || !integer(count.inputTokens) || !integer(count.contextTokens ?? count.inputTokens)) throw fail('TOKEN_COUNT_UNVERIFIED');
      await log({ type: 'token_accounting', id, tokens: count });
      if (counting) {
        await log({ type: 'provider_token_count', id, input_tokens: count.inputTokens });
        response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ input_tokens: count.inputTokens })); return;
      }
      await log({ type: 'provider_request', id, path: url.pathname, headers: request.headers, body, tokens: count, selected_model: model });
      reserved = await budget.reserveInference({ inputTokens: count.inputTokens, contextTokens: count.contextTokens ?? count.inputTokens, ...(requested === undefined ? {} : { maxOutputTokens: requested }) });
      if (protocol === 'gemini') forwarded.generationConfig = { ...forwarded.generationConfig, maxOutputTokens: reserved.maxOutputTokens };
      else forwarded[field] = reserved.maxOutputTokens;
      // Backend extensions may prefer an alias over the protocol's canonical
      // field. Every supplied alias must carry the same reserved allowance.
      for (const alias of aliases) if (forwarded[alias] !== undefined) forwarded[alias] = reserved.maxOutputTokens;
      if (protocol === 'chat' && forwarded.stream === true) forwarded.stream_options = { ...forwarded.stream_options, include_usage: true };
      const target = new URL(base.href); target.pathname = `${base.pathname.replace(/\/$/, '')}${url.pathname}`;
      if (protocol === 'gemini' && wireModel !== model) target.pathname = target.pathname.replace(/(\/models\/).+(:(?:streamGenerateContent|generateContent))$/, (_match, prefix, suffix) => prefix + encodeURIComponent(wireModel) + suffix);
      for (const [key, value] of url.searchParams) {
        if (!(protocol === 'gemini' && key === 'alt' && value === 'sse') && !(protocol === 'messages' && key === 'beta' && value === 'true')) throw fail('PROVIDER_QUERY_UNSUPPORTED');
        target.searchParams.set(key, value);
      }
      await log({ type: 'upstream_request', id, protocol, body: forwarded, effective_sampling: effectiveSampling });
      const signal = AbortSignal.any([lifetime.signal, controller.signal, ...(budget.signal ? [budget.signal] : [])]);
      const reply = await fetch(target, { method: 'POST', headers: { 'content-type': 'application/json', 'x-ud-eval-request-id': id, ...(request.headers['anthropic-version'] ? { 'anthropic-version': request.headers['anthropic-version'] } : {}) }, body: JSON.stringify(forwarded), signal, redirect: 'error' });
      const output = await boundedBytes(reply.body, 32 * 1024 * 1024);
      const streaming = reply.headers.get('content-type')?.includes('text/event-stream') === true;
      let parsed; try { parsed = streaming ? events(output) : JSON.parse(output); } catch { throw fail('PROVIDER_RESPONSE_INVALID'); }
      await log({ type: 'provider_response', id, protocol, status: reply.status, streaming, body: parsed });
      if (!reply.ok) throw fail(`UPSTREAM_HTTP_${reply.status}`);
      const complete = streaming ? streamedResponse(protocol, parsed) : parsed;
      const outputTokens = outputUsage(protocol, complete), toolCalls = toolCount(protocol, complete);
      if (protocol === 'responses') validateResponsesOutput(body, complete);
      if (inputUsage(protocol, complete) !== count.inputTokens) throw fail('SERVER_TOKEN_ACCOUNTING_MISMATCH');
      await budget.finishInference({ id: reserved.id, outputTokens, toolCalls }); reserved = undefined;
      if (budget.admitNativeCalls) {
        const calls = responseNativeCalls(protocol, complete, { requestId: id });
        await budget.admitNativeCalls({ calls });
        for (const call of calls) pendingNative.set(call.id, call);
        if (calls.length) await log({ type: 'native_calls_admitted', calls });
      }
      await log({ type: 'model_visible_response', id, outputTokens, toolCalls, streaming, body: parsed });
      response.writeHead(reply.status, { 'content-type': streaming ? 'text/event-stream' : 'application/json', 'content-length': output.length }); response.end(output);
    } catch (error) {
      const reason = error.code ?? error.message;
      let pathname = '[INVALID]';
      try { pathname = new URL(request.url, 'http://127.0.0.1').pathname.slice(0, 2048); } catch { /* Malformed targets remain failures. */ }
      const method = /^[A-Z]{1,16}$/.test(request.method ?? '') ? request.method : '[INVALID]';
      await log({ type: 'gateway_rejection', id, method, pathname, reason, outcome: gatewayOutcome(reason) }).catch(() => {});
      await budget.stop(reason ?? 'PROVIDER_REQUEST_FAILED');
      if (!response.destroyed) { response.writeHead(422, { 'content-type': 'application/json' }); response.end(JSON.stringify({ error: { type: 'local_evaluation_blocked', message: error.code ?? error.message } })); }
    } finally { active.delete(controller); response.off('close', abort); }
  });
  server.requestTimeout = 90000; server.headersTimeout = 10000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { url: `http://127.0.0.1:${server.address().port}`, reconcileNativeResults: () => reconcileNativeResults(undefined, undefined, true), async close() { lifetime.abort(); for (const controller of active) controller.abort(); if (active.size) await budget.stop('GATEWAY_CLOSED'); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}
