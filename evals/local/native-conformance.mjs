/** MIT. Deterministic native-client protocol probes. No model is loaded or called.
 * Canned tool calls prove transport mechanics only, never model competence. */
import http from 'node:http';
import path from 'node:path';
import { mkdirSync, readFileSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { startNative, nativeAdapterIdentity, nativeConformance, nativeConformanceDirectory } from './native.mjs';
import { createBudgetAuthority } from './budget.mjs';
import { assertOptIn, writeNew } from './preparation.mjs';
import { sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { NATIVE_RECIPES } from './native-recipes.mjs';
import { createGateway } from './gateway.mjs';
import { cleanupObservation, failureObservation } from './lifecycle.mjs';
import { responsesDeclarations } from './responses-namespace.mjs';

/** Transport evidence only: exact attached bytes, never pixel understanding. */
export function nativeImageDelivery(body, expected) {
  if (!Buffer.isBuffer(expected) || !expected.length || expected.length > 8 * 1024 ** 2) throw new Error('CONFORMANCE_IMAGE_FIXTURE_INVALID');
  const images = [];
  for (const message of Array.isArray(body?.input) ? body.input : []) {
    if (message.role !== 'user' || !Array.isArray(message.content)) continue;
    for (const part of message.content) {
      if (part?.type !== 'input_image') continue;
      const url = part.image_url;
      const match = typeof url === 'string' && /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(url);
      if (!match || match[2].length > 12 * 1024 ** 2) { images.push({ verified: false, reason: 'bounded-inline-image-not-observed' }); continue; }
      const bytes = Buffer.from(match[2], 'base64');
      images.push({ verified: bytes.equals(expected) && bytes.toString('base64') === match[2], mime_type: `image/${match[1]}`, sha256: sha256(bytes), size_bytes: bytes.length });
    }
  }
  return { kind: 'native-image-byte-delivery', inference: false, source_sha256: sha256(expected), source_size_bytes: expected.length,
    images, verified: images.length === 1 && images[0].verified === true, semantic_verification: 'requires-scored-image-scenario' };
}

function chatResponse(response, request, message) {
  const tool = message.tool_calls?.length > 0, finish = tool ? 'tool_calls' : 'stop';
  if (request.stream) {
    response.writeHead(200, { 'content-type': 'text/event-stream' });
    const delta = { ...message, ...(tool ? { tool_calls: message.tool_calls.map((call, index) => ({ index, ...call })) } : {}) };
    for (const chunk of [{ choices: [{ index: 0, delta, finish_reason: null }] }, { choices: [{ index: 0, delta: {}, finish_reason: finish }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }]) response.write('data: ' + JSON.stringify({ id: randomUUID(), object: 'chat.completion.chunk', created: 1, model: request.model, ...chunk }) + '\n\n');
    response.end('data: [DONE]\n\n');
  } else {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ id: randomUUID(), object: 'chat.completion', created: 1, model: request.model, choices: [{ index: 0, message, finish_reason: finish }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
  }
}

/** Exact inert protocol frames. Never used by a scored model-backed episode. */
export function nativeFixtureFrames(protocol, model, call = null, text = 'fixture-complete') {
  const id = 'fixture-response-' + randomUUID();
  if (protocol === 'chat') {
    const message = call ? { role: 'assistant', content: null, tool_calls: [{ id: call.id, type: 'function', function: { name: call.name, arguments: JSON.stringify(call.arguments) } }] } : { role: 'assistant', content: text };
    const finish = call ? 'tool_calls' : 'stop';
    return { body: { id, object: 'chat.completion', created: 1, model, choices: [{ index: 0, message, finish_reason: finish }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } },
      frames: [{ choices: [{ index: 0, delta: { ...message, ...(call ? { tool_calls: message.tool_calls.map((value, index) => ({ index, ...value })) } : {}) }, finish_reason: null }] }, { choices: [{ index: 0, delta: {}, finish_reason: finish }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }].map(row => ({ data: { id, object: 'chat.completion.chunk', created: 1, model, ...row } })), done: true };
  }
  if (protocol === 'messages') {
    const content = call ? { type: 'tool_use', id: call.id, name: call.name, input: call.arguments } : { type: 'text', text };
    const body = { id, type: 'message', role: 'assistant', model, content: [content], stop_reason: call ? 'tool_use' : 'end_turn', stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
    const rows = [{ type: 'message_start', message: { ...body, content: [], stop_reason: null } },
      { type: 'content_block_start', index: 0, content_block: call ? { ...content, input: {} } : { type: 'text', text: '' } },
      { type: 'content_block_delta', index: 0, delta: call ? { type: 'input_json_delta', partial_json: JSON.stringify(call.arguments) } : { type: 'text_delta', text } },
      { type: 'content_block_stop', index: 0 }, { type: 'message_delta', delta: { stop_reason: body.stop_reason, stop_sequence: null }, usage: { output_tokens: 1 } }, { type: 'message_stop' }];
    return { body, frames: rows.map(data => ({ event: data.type, data })) };
  }
  if (protocol === 'responses') {
    const item = call ? call.type === 'custom' ? { id: 'tool-' + call.id, type: 'custom_tool_call', call_id: call.id, name: call.name, input: call.input, status: 'completed' }
      : { id: 'tool-' + call.id, type: 'function_call', call_id: call.id, name: call.name, arguments: JSON.stringify(call.arguments), status: 'completed' }
      : { id: 'msg-' + id, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text, annotations: [] }] };
    if (call?.namespace !== undefined) item.namespace = call.namespace;
    const body = { id, object: 'response', status: 'completed', model, output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } };
    const rows = [{ type: 'response.created', response: { ...body, status: 'in_progress', output: [] } },
      { type: 'response.output_item.added', output_index: 0, item: { ...item, status: 'in_progress', ...(call ? call.type === 'custom' ? { input: '' } : { arguments: '' } : { content: [] }) } }];
    if (call) rows.push(call.type === 'custom' ? { type: 'response.custom_tool_call_input.delta', output_index: 0, item_id: item.id, delta: call.input } : { type: 'response.function_call_arguments.delta', output_index: 0, item_id: item.id, delta: item.arguments });
    else rows.push({ type: 'response.content_part.added', output_index: 0, item_id: item.id, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } }, { type: 'response.output_text.delta', output_index: 0, item_id: item.id, content_index: 0, delta: text });
    rows.push({ type: 'response.output_item.done', output_index: 0, item }, { type: 'response.completed', response: body });
    return { body, frames: rows.map(data => ({ event: data.type, data })) };
  }
  if (protocol === 'gemini') {
    const body = { candidates: [{ content: { role: 'model', parts: [call ? { functionCall: { id: call.id, name: call.name, args: call.arguments } } : { text }] }, finishReason: 'STOP', index: 0 }], usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 }, modelVersion: model };
    return { body, frames: [{ data: body }] };
  }
  throw new Error('CONFORMANCE_PROTOCOL_UNAVAILABLE');
}

function fixtureResponse(response, request, protocol, call) {
  const fixture = nativeFixtureFrames(protocol, request.model ?? 'local-eval-fixture', call);
  const stream = request.stream || protocol === 'gemini' && request.__stream;
  if (!stream) { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(fixture.body)); return; }
  response.writeHead(200, { 'content-type': 'text/event-stream' });
  for (const frame of fixture.frames) response.write((frame.event ? `event: ${frame.event}\n` : '') + 'data: ' + JSON.stringify(frame.data) + '\n\n');
  if (fixture.done) response.write('data: [DONE]\n\n');
  response.end();
}

/** Native result continuation differs across endpoint families. */
export function nativeFixtureResults(protocol, body) {
  if (protocol === 'chat') return (body.messages ?? []).filter(message => message.role === 'tool').map(message => ({ id: message.tool_call_id, content: message.content }));
  if (protocol === 'responses') return (Array.isArray(body.input) ? body.input : []).filter(item => ['function_call_output', 'custom_tool_call_output'].includes(item.type)).map(item => ({ id: item.call_id, content: item.output }));
  if (protocol === 'messages') return (body.messages ?? []).flatMap(message => Array.isArray(message.content) ? message.content.filter(item => item.type === 'tool_result').map(item => ({ id: item.tool_use_id, content: item.content, is_error: item.is_error })) : []);
  if (protocol === 'gemini') return (body.contents ?? []).flatMap(message => (message.parts ?? []).filter(item => item.functionResponse).map(item => ({ id: item.functionResponse.id, name: item.functionResponse.name, content: item.functionResponse.response })));
  throw new Error('CONFORMANCE_PROTOCOL_UNAVAILABLE');
}

const canonicalFixtureArguments = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);

/** OpenClaw's pinned custom-provider strict replay policy removes punctuation
 * from these short fixture IDs (tool-call-id.ts). Observe that projection only
 * when the exact native call name and arguments remain in provider history. */
export function nativeFixtureCallResults(harnessId, protocol, body, call) {
  if (!call) return [];
  const results = nativeFixtureResults(protocol, body);
  if (harnessId !== 'openclaw' || protocol !== 'chat') return results.filter(result => result.id === call.id || protocol === 'gemini' && !result.id && result.name === call.name);
  if (!/^fixture-call-[1-9][0-9]*$/.test(call.id)) return [];
  const ids = new Set([call.id, call.id.replace(/[^a-zA-Z0-9]/g, '').slice(0, 40)]);
  const history = (body.messages ?? []).filter(message => message.role === 'assistant').flatMap(message => message.tool_calls ?? []).filter(item => ids.has(item.id));
  if (history.length !== 1 || history[0].function?.name !== call.name) return [];
  let arguments_; try { arguments_ = JSON.parse(history[0].function.arguments); } catch { return []; }
  if (canonicalFixtureArguments(arguments_) !== canonicalFixtureArguments(call.arguments)) return [];
  const matches = results.filter(result => result.id === history[0].id);
  return matches.length === 1 ? matches : [];
}

/** Follow only the actual latest native Tool Search result, including its exact
 * returned MCP id. The external-content wrapper is data; no text instructions
 * or guessed prefix can select the inert environment operation. */
function openClawFixtureDiscoveryTarget(request) {
  const messages = request.messages ?? [], result = messages.findLast(message => message.role === 'tool');
  if (typeof result?.content !== 'string') throw new Error('CONFORMANCE_DISCOVERY_RESULT_UNAVAILABLE');
  const calls = messages.filter(message => message.role === 'assistant').flatMap(message => message.tool_calls ?? []).filter(call => call.id === result.tool_call_id);
  if (calls.length !== 1 || calls[0].function?.name !== 'tool_search') throw new Error('CONFORMANCE_DISCOVERY_RESULT_UNAVAILABLE');
  let query; try { query = JSON.parse(calls[0].function.arguments); } catch { throw new Error('CONFORMANCE_DISCOVERY_RESULT_UNAVAILABLE'); }
  if (query.query !== 'check_ud_environment') throw new Error('CONFORMANCE_DISCOVERY_RESULT_UNAVAILABLE');
  const wrapped = /<<<EXTERNAL_UNTRUSTED_CONTENT id="([a-f0-9]+)">>>\nSource: API\n---\n([\s\S]*)\n<<<END_EXTERNAL_UNTRUSTED_CONTENT id="\1">>>\s*$/.exec(result.content);
  let entries; try { entries = JSON.parse(wrapped ? wrapped[2] : result.content); } catch { throw new Error('CONFORMANCE_DISCOVERY_RESULT_UNAVAILABLE'); }
  const matches = Array.isArray(entries) ? entries.filter(entry => entry?.source === 'mcp' && entry.sourceName === 'ud' && entry.mcp?.serverName === 'ud' &&
    entry.mcp.toolName === 'check_ud_environment' && entry.mcp.operation === 'tool' && typeof entry.id === 'string' && entry.id.length > 0) : [];
  if (matches.length !== 1) throw new Error('CONFORMANCE_DISCOVERY_RESULT_UNAVAILABLE');
  return matches[0].id;
}

export function nativeFixtureRoute(protocol, url) {
  const pathname = new URL(url, 'http://127.0.0.1').pathname;
  return protocol === 'chat' ? pathname === '/v1/chat/completions' : protocol === 'responses' ? pathname === '/v1/responses' : protocol === 'messages' ? pathname === '/v1/messages' : protocol === 'gemini' && /^\/v1(?:beta)?\/models\/local-eval-fixture:(?:streamGenerateContent|generateContent)$/.test(pathname);
}

export function nativeFixtureRecipe(harnessId, { taskRoot, profile, oracle }) {
  if (!NATIVE_RECIPES[harnessId]) throw new Error('CONFORMANCE_RECIPE_UNAVAILABLE');
  const shellQuote = value => "'" + String(value).replaceAll("'", "'\\''") + "'";
  const read = (file, names = ['read_file', 'read', 'Read']) => ({ kind: 'read', names, file });
  const skill = (names, args) => ({ kind: 'skill', names, arguments: args });
  const operation = { kind: 'operation', names: ['mcp__ud__check_ud_environment'], arguments: { working_tree_path: taskRoot, required_tools: ['validation_report'], offline: true } };
  const folders = { 'codex-cli': '.agents/skills', 'claude-code': '.claude/skills', 'gemini-cli': '.gemini/skills', 'grok-build': '.grok/skills', pi: '.agents/skills', 'kimi-code': '.agents/skills' };
  const skillPath = path.join(['hermes-agent', 'deepseek-harness', 'openclaw'].includes(harnessId) ? profile : taskRoot,
    harnessId === 'hermes-agent' ? '.hermes/skills' : harnessId === 'deepseek-harness' ? '.dsh/skills' : harnessId === 'openclaw' ? '.openclaw/skills' : folders[harnessId] ?? '.agents/skills', 'ud-validate/SKILL.md');
  const activate = harnessId === 'qwen-code' ? skill(['skill'], { skill: 'ud-validate' })
    : harnessId === 'claude-code' || harnessId === 'kimi-code' ? skill(['Skill', 'skill'], { skill: 'ud-validate' })
      : harnessId === 'gemini-cli' ? skill(['activate_skill'], { name: 'ud-validate' })
        : harnessId === 'hermes-agent' ? skill(['skill_view'], { name: 'ud-validate' })
          : harnessId === 'deepseek-harness' ? skill(['skill'], { name: 'ud-validate' }) : read(skillPath);
  if (harnessId === 'mini-swe-agent') return [
    { kind: 'shell', names: ['bash'], arguments: { command: 'cat ' + shellQuote(skillPath) } },
    { kind: 'shell', names: ['bash'], arguments: { command: 'cat ' + shellQuote(oracle) } },
    { kind: 'shell', names: ['bash'], arguments: { command: `ud-agent call check_ud_environment --input ${shellQuote(path.join(taskRoot, 'environment-request.json'))} --allow-root ${shellQuote(taskRoot)}` } },
    { kind: 'submit', names: ['bash'], arguments: { command: "printf 'COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\\nfixture-complete\\n'" } },
  ];
  return [{ ...activate, fallbackFile: skillPath }, read(oracle), ...(harnessId === 'qwen-code' ? [{ kind: 'discovery', names: ['tool_search'], arguments: { query: 'select:mcp__ud__check_ud_environment' } }] : []), operation];
}

function declarations(protocol, request) {
  if (protocol === 'responses') return responsesDeclarations(request, { customResponses: true, nativeTools: true });
  const tools = protocol === 'gemini' ? (request.tools ?? []).flatMap(tool => tool.functionDeclarations ?? []) : request.tools ?? [];
  return tools.map(tool => tool.function ? { ...tool.function, type: tool.type } : tool);
}

export function nativeFixtureDiscovery(tool) {
  const schema = tool.parameters ?? tool.input_schema ?? tool.parametersJsonSchema ?? {}, arguments_ = { query: 'check_ud_environment' };
  // Pinned Claude ToolSearch requires an explicit value despite publishing this
  // mechanical default. Unknown required fields remain a blocked fixture.
  if ((schema.required ?? []).includes('max_results')) {
    const value = schema.properties?.max_results?.default;
    if (!Number.isInteger(value) || value < 1 || value > 10) throw new Error('CONFORMANCE_DISCOVERY_DEFAULT_UNVERIFIED');
    arguments_.max_results = value;
  }
  return { kind: 'discovery', names: [tool.name], arguments: arguments_ };
}

/** Select only an actually declared native function. Unknown client schemas block. */
export function declaredFixtureCall(protocol, request, action, id) {
  const tools = declarations(protocol, request);
  let tool = tools.find(tool => action.names.includes(tool.name));
  if (!tool && action.kind === 'skill' && action.fallbackFile) return declaredFixtureCall(protocol, request, { kind: 'read', names: ['read_file', 'read', 'Read'], file: action.fallbackFile }, id);
  if (action.kind === 'operation') tool ??= tools.find(tool => /(?:^|_)check_ud_environment$/.test(tool.name));
  if (!tool && action.kind === 'operation' && tools.some(tool => tool.name === 'tool_call')) return { id, name: 'tool_call', arguments: { name: 'mcp__ud__check_ud_environment', arguments: action.arguments } };
  let args = action.arguments;
  if (!tool && action.kind === 'operation' && protocol === 'chat') {
    const dispatcher = tools.find(tool => tool.name === 'dispatch_action');
    if (dispatcher) {
      const schema = dispatcher.parameters ?? dispatcher.input_schema ?? {};
      if (schema.properties?.id?.type !== 'string' || schema.properties?.args?.type !== 'object') throw new Error('CONFORMANCE_DISPATCH_SCHEMA_UNAVAILABLE');
      tool = dispatcher; args = { id: openClawFixtureDiscoveryTarget(request), args: action.arguments };
    }
  }
  if (action.kind === 'read') {
    if (tool) {
      const properties = (tool.parameters ?? tool.input_schema ?? tool.parametersJsonSchema)?.properties ?? {};
      const field = ['file_path', 'path', 'filename', 'filePath'].find(name => Object.hasOwn(properties, name));
      if (!field) throw new Error('CONFORMANCE_READ_SCHEMA_UNAVAILABLE');
      args = { [field]: action.file };
    } else {
      tool = tools.find(tool => ['exec_command', 'run_shell_command', 'shell', 'terminal', 'bash'].includes(tool.name));
      if (tool) {
        const properties = (tool.parameters ?? tool.input_schema ?? tool.parametersJsonSchema)?.properties ?? {}, field = ['cmd', 'command'].find(name => Object.hasOwn(properties, name));
        if (!field) throw new Error('CONFORMANCE_SHELL_SCHEMA_UNAVAILABLE');
        args = { [field]: 'cat ' + "'" + action.file.replaceAll("'", "'\\''") + "'" };
      }
    }
  }
  if (!tool) throw new Error('CONFORMANCE_DECLARED_TOOL_UNAVAILABLE:' + action.kind);
  if (tool.type === 'custom') throw new Error('CONFORMANCE_CUSTOM_INPUT_UNVERIFIED');
  const required = (tool.parameters ?? tool.input_schema ?? tool.parametersJsonSchema)?.required ?? [];
  if (required.some(name => !Object.hasOwn(args, name))) throw new Error('CONFORMANCE_REQUIRED_ARGUMENT_UNAVAILABLE');
  return { id, name: tool.name, ...(tool.namespace === undefined ? {} : { namespace: tool.namespace }), arguments: args };
}

/** A startup probe records actual requests and process errors. It cannot admit a
 * route: tool, skill, cancellation and isolation conformance are separate. */
export async function captureNativeStartup(root, harness, { optIn, installation } = {}) {
  assertOptIn({ optIn });
  const directory = path.join(root, '.artifacts/local-evals/native-preflight', harness.id + '-' + randomUUID());
  const taskRoot = path.join(directory, 'task'), profile = path.join(directory, 'profile');
  mkdirSync(taskRoot, { recursive: true, mode: 0o700 }); writeFileSync(path.join(taskRoot, 'probe.txt'), 'inert native fixture\n');
  const requests = []; let native, server, error, result, finalAnswer = '', events = [];
  try {
    server = http.createServer(async (req, res) => {
      if (req.method === 'GET') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ object: 'list', data: [{ id: 'local-eval-fixture', object: 'model', created: 1, owned_by: 'local' }] })); return;
      }
      let bytes = ''; for await (const chunk of req) bytes += chunk;
      const body = JSON.parse(bytes); requests.push({ url: req.url, body });
      if (requests.length > 10) { res.writeHead(429); res.end(); void native?.stop('inert-request-bound'); return; }
      if (NATIVE_RECIPES[harness.id].protocol === 'messages') {
        const message = { id: 'msg-fixture', type: 'message', role: 'assistant', model: body.model, content: [{ type: 'text', text: 'fixture-complete' }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
        if (!body.stream) { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(message)); return; }
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        const chunks = [{ type: 'message_start', message: { ...message, content: [], stop_reason: null } }, { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }, { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'fixture-complete' } }, { type: 'content_block_stop', index: 0 }, { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 1 } }, { type: 'message_stop' }];
        for (const chunk of chunks) res.write(`event: ${chunk.type}\ndata: ${JSON.stringify(chunk)}\n\n`); res.end(); return;
      }
      if (NATIVE_RECIPES[harness.id].protocol === 'gemini') {
        const message = { candidates: [{ content: { role: 'model', parts: [{ text: 'fixture-complete' }] }, finishReason: 'STOP', index: 0 }], usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 }, modelVersion: 'local-eval-fixture' };
        res.setHeader('content-type', req.url.includes('streamGenerateContent') ? 'text/event-stream' : 'application/json');
        res.end(req.url.includes('streamGenerateContent') ? `data: ${JSON.stringify(message)}\n\n` : JSON.stringify(message)); return;
      }
      if (NATIVE_RECIPES[harness.id].protocol === 'responses') {
        const item = { id: 'msg-fixture', type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'fixture-complete', annotations: [] }] };
        const response = { id: 'resp-fixture', object: 'response', status: 'completed', model: body.model, output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } };
        if (!body.stream) { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(response)); return; }
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        for (const chunk of [{ type: 'response.created', response: { ...response, status: 'in_progress', output: [] } }, { type: 'response.output_item.added', output_index: 0, item: { ...item, status: 'in_progress', content: [] } }, { type: 'response.content_part.added', item_id: item.id, output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } }, { type: 'response.output_text.delta', item_id: item.id, output_index: 0, content_index: 0, delta: 'fixture-complete' }, { type: 'response.output_item.done', output_index: 0, item }, { type: 'response.completed', response }]) res.write(`event: ${chunk.type}\ndata: ${JSON.stringify(chunk)}\n\n`);
        res.end(); return;
      }
      chatResponse(res, body, { role: 'assistant', content: 'fixture-complete' });
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    native = await startNative({ root, harness, installation, taskRoot, profile, endpoint: `http://127.0.0.1:${server.address().port}`, model: 'local-eval-fixture', modelContextCapacity: 65536, prompt: 'Read probe.txt and report its contents.', skillsEnabled: true, allowUnverified: true });
    result = await native.done; finalAnswer = native.finalAnswer(result); events = native.events(result);
  } catch (caught) { error = caught.message; }
  finally { await native?.stop('startup-probe-finished'); if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } }
  const evidence = { kind: 'native-startup-probe', inference: false, harness_id: harness.id, adapter_sha256: nativeAdapterIdentity(), directory, requests, result, finalAnswer, events, error, qualification: 'startup-only-not-admission' };
  writeNew(path.join(directory, 'evidence.json'), evidence); return evidence;
}

export async function verifyQwenNativeRoute(root, harness, options = {}) { return verifyNativeChatRoute(root, harness, options); }

export function observedSkillBody(harnessId, requests, body) {
  if (harnessId === 'mini-swe-agent') return requests.slice(1).some(request => request.body.messages?.some(message => {
    if (message.role !== 'tool' || typeof message.content !== 'string') return false;
    try { const result = JSON.parse(message.content); return result.returncode === 0 && typeof result.output === 'string' && result.output.includes(body); }
    catch { return false; }
  }));
  const strings = (value, depth = 0) => {
    if (depth > 12) return [];
    if (typeof value === 'string') {
      let decoded;
      try { if (/^\s*[\[{]/.test(value)) decoded = JSON.parse(value); } catch { /* Native prose is not JSON. */ }
      return [value, ...(decoded ? strings(decoded, depth + 1) : [])];
    }
    if (Array.isArray(value)) return value.flatMap(item => strings(item, depth + 1));
    return value && typeof value === 'object' ? Object.values(value).flatMap(item => strings(item, depth + 1)) : [];
  };
  return requests.slice(1).some(request => strings(request.body).some(value => value.includes(body) || value.replace(/^\s*\d+[|:] ?/gm, '').includes(body)));
}

export async function verifyNativeChatRoute(root, harness, { optIn, installation, onProgress = () => {}, signal } = {}) {
  assertOptIn({ optIn });
  if (!NATIVE_RECIPES[harness.id]?.canRun) throw new Error('CONFORMANCE_RECIPE_UNAVAILABLE');
  const protocol = NATIVE_RECIPES[harness.id].protocol;
  const adapterIdentity = nativeAdapterIdentity();
  const productIdentity = sourceReceipt(root).sha256;
  const identity = harness.container?.image_id ?? harness.executable_sha256 ?? sha256(readFileSync(harness.executable));
  const old = nativeConformance(root, harness.id, identity); if (old) return old;
  const directory = nativeConformanceDirectory(root, harness.id, identity);
  if (existsSync(directory)) throw new Error('CONFORMANCE_PRIOR_ATTEMPT_REQUIRES_RECONCILIATION');
  const taskRoot = path.join(directory, 'task'), profile = path.join(directory, 'profile');
  mkdirSync(taskRoot, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(taskRoot, 'probe.txt'), 'inert native transport fixture\n', { mode: 0o600 });
  const image = harness.id === 'codex-cli' ? path.join(taskRoot, 'diagram.png') : undefined;
  if (image) copyFileSync(path.join(root, 'evals/local/fixtures/diagram.png'), image);
  const secret = 'oracle-isolation-' + randomUUID(), oracle = path.join(directory, 'private-oracle.txt');
  writeFileSync(oracle, secret, { flag: 'wx', mode: 0o600 });
  writeFileSync(path.join(taskRoot, 'environment-request.json'), JSON.stringify({ working_tree_path: taskRoot, required_tools: ['validation_report'], offline: true }), { mode: 0o600 });
  const requests = [], cancellationRequests = [], formatRequests = [], events = [], calls = [], tools = nativeFixtureRecipe(harness.id, { taskRoot, profile, oracle });
  let expectedRequests = tools.length + (harness.id === 'mini-swe-agent' ? 0 : 1);
  let native, cancelling, formatRecovery = false, server, authority, gateway, startupSettingsBefore, startupSettingsAfter;
  const malformedFixture = 'inert malformed tool output <tool_call>{invalid}</tool_call>';
  let launches = 0, receipt, authorityAttempted = false, failedBudgetRelease;
  const nativeSessions = [];
  async function releaseNative(reason) {
    if (!native) return;
    const released = await native.stop(reason);
    nativeSessions.push({ reason, ...cleanupObservation(released) }); native = undefined;
    if (released.cleanupVerified !== true) throw new Error('CONFORMANCE_NATIVE_RELEASE_UNVERIFIED');
    return released;
  }
  const pending = new Set();
  try {
    authorityAttempted = true;
    authority = await createBudgetAuthority({ directory: path.join(directory, 'authority'), onEvent: event => events.push(event), onStop: () => native?.stop('conformance-timeout') });
    server = http.createServer(async (req, res) => {
      if (req.url === '/v1/models') { res.setHeader('content-type', 'application/json'); res.end('{"object":"list","data":[{"id":"local-eval-fixture","object":"model"}]}'); return; }
      let bytes = '';
      for await (const chunk of req) { bytes += chunk; if (bytes.length > 2 * 1024 ** 2) { res.writeHead(413); res.end(); return; } }
      try {
        const body = JSON.parse(bytes);
        if (cancelling) { cancellationRequests.push({ url: req.url, body }); pending.add(res); res.on('close', () => pending.delete(res)); cancelling(); return; }
        if (formatRecovery) {
          formatRequests.push({ url: req.url, body });
          if (formatRequests.length > 2 || !nativeFixtureRoute('chat', req.url)) throw new Error('CONFORMANCE_FORMAT_RECOVERY_EXCEEDED');
          const message = formatRequests.length === 1 ? { role: 'assistant', content: malformedFixture }
            : { role: 'assistant', content: null, tool_calls: [{ id: 'format-recovery-submit', type: 'function', function: {
              name: 'bash', arguments: JSON.stringify({ command: "printf 'COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\\nfixture-complete\\n'" }),
            } }] };
          chatResponse(res, body, message); return;
        }
        requests.push({ url: req.url, body });
        const route = nativeFixtureRoute(protocol, req.url);
        if (!route || protocol !== 'gemini' && body.model !== 'local-eval-fixture' || requests.length > expectedRequests) throw new Error('Unexpected native request');
        let selected = tools[requests.length - 1];
        if (selected?.kind === 'operation') {
          const declared = declarations(protocol, body);
          if (!declared.some(tool => /(?:^|_)check_ud_environment$/.test(tool.name) || tool.name === 'tool_call')) {
            const search = declared.find(tool => ['tool_search', 'ToolSearch', 'search_tools'].includes(tool.name));
            if (search && tools[requests.length - 2]?.kind !== 'discovery') {
              selected = nativeFixtureDiscovery(search);
              tools.splice(requests.length - 1, 0, selected); expectedRequests++;
            }
          }
        }
        const call = selected ? declaredFixtureCall(protocol, body, selected, `fixture-call-${requests.length}`) : null;
        if (call) calls.push(call);
        fixtureResponse(res, { ...body, __stream: req.url.includes('streamGenerateContent') }, protocol, call);
      } catch (error) { res.writeHead(400, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: { message: error.message } })); }
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    gateway = await createGateway({ upstream: `http://127.0.0.1:${server.address().port}`, model: 'local-eval-fixture', budget: authority,
      nativeResults: () => native?.observedResults?.() ?? [],
      tokenize: async () => ({ trusted: true, inputTokens: 1, contextTokens: 1, source: 'explicit-inert-protocol-fixture-not-a-model-tokenizer' }), record: async event => { events.push(event); } });
    const endpoint = gateway.url, environment = { UD_AGENT_EVAL_BUDGET: JSON.stringify({ socketPath: authority.socketPath, token: authority.token }) };
    onProgress({ harness: harness.id, stage: 'inert-native-tool-roundtrip' });
    launches++;
    native = await startNative({ root, harness, model: 'local-eval-fixture', modelContextCapacity: 65536, endpoint, taskRoot, profile, prompt: 'Read probe.txt and report its contents.', ...(image ? { image } : {}),
      signal, skillsEnabled: true, installation, budgetEnvironment: environment, hostBudgetEnvironment: environment, allowUnverified: true, record: event => events.push(event),
      beforeStart: harness.id === 'qwen-code' ? () => { startupSettingsBefore = sha256(readFileSync(path.join(taskRoot, '.qwen/settings.json'))); } : undefined });
    const result = await native.done, finalAnswer = native.finalAnswer(result);
    await gateway.reconcileNativeResults();
    if (harness.id === 'qwen-code') startupSettingsAfter = sha256(readFileSync(path.join(taskRoot, '.qwen/settings.json')));
    events.push(...native.events(result));
    const body = readFileSync(path.join(installation, 'skills/ud-validate/SKILL.md'), 'utf8').replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').trim();
    const serialized = JSON.stringify(requests);
    const imageDelivery = image ? nativeImageDelivery(requests[0]?.body, readFileSync(image)) : undefined;
    const continued = (call, index) => nativeFixtureCallResults(harness.id, protocol, requests[index + 1]?.body ?? {}, call).length > 0;
    const checks = {
      provider_roundtrip: requests.length === expectedRequests && requests.every(request => protocol === 'gemini' ? request.url.includes('/models/local-eval-fixture:') : request.body.model === 'local-eval-fixture'),
      tool_roundtrip: calls.slice(0, harness.id === 'mini-swe-agent' ? -1 : undefined).every(continued) && events.some(event => event.type === 'operation_result' && event.name === 'check_ud_environment'),
      skill_discovery: JSON.stringify(requests[0]?.body ?? {}).includes('ud-validate') && observedSkillBody(harness.id, requests, body),
      final_output: result.code === 0 && result.cleanupVerified === true && finalAnswer.trim() === 'fixture-complete',
      oracle_isolation: !serialized.includes(secret) && nativeFixtureCallResults(harness.id, protocol, requests[2]?.body ?? {}, calls[1]).some(message => /denied|not permitted|not allowed|outside|ENOENT|not found|no such file|does not exist/i.test(JSON.stringify(message))),
      cancellation: false,
      budget_enforced: authority.snapshot().counters.inference === expectedRequests && authority.snapshot().counters.tools === calls.length && authority.snapshot().counters.ud_operations >= 1,
      native_recovery_observed: authority.snapshot().native_recovery?.verified === true,
      ...(imageDelivery ? { image_delivery: imageDelivery.verified } : {}),
      ...(harness.id === 'qwen-code' ? { startup_metadata_stable: typeof startupSettingsBefore === 'string' && startupSettingsBefore === startupSettingsAfter } : {}),
    };
    writeNew(path.join(directory, 'roundtrip.json'), { kind: 'inert-native-client-conformance', inference: false, protocol, requests, calls, events, result, finalAnswer, checks, budget: authority.snapshot(), ...(imageDelivery ? { image_delivery: imageDelivery } : {}),
      ...(harness.id === 'qwen-code' ? { startup_settings: { path: path.join(taskRoot, '.qwen/settings.json'), before_sha256: startupSettingsBefore, after_sha256: startupSettingsAfter } } : {}) });
    await releaseNative('roundtrip-finished');
    if (signal?.aborted) throw new Error('CONFORMANCE_CANCELLED');
    if (harness.id === 'mini-swe-agent') {
      const formatTask = path.join(directory, 'format-task'), formatProfile = path.join(directory, 'format-profile');
      mkdirSync(formatTask, { mode: 0o700 }); writeFileSync(path.join(formatTask, 'probe.txt'), 'format recovery fixture\n');
      const before = authority.snapshot(), firstFormatEvent = events.length; formatRecovery = true;
      launches++;
      native = await startNative({ root, harness, model: 'local-eval-fixture', modelContextCapacity: 65536, endpoint, taskRoot: formatTask, profile: formatProfile,
        prompt: 'Read probe.txt and report its contents.', signal, skillsEnabled: true, installation,
        budgetEnvironment: environment, hostBudgetEnvironment: environment, allowUnverified: true });
      const result = await native.done;
      await gateway.reconcileNativeResults();
      const after = authority.snapshot(), formatEvents = events.slice(firstFormatEvent);
      const history = formatRequests[1]?.body.messages ?? [];
      const capturedMalformed = formatEvents.some(event => event.type === 'model_visible_response' && event.toolCalls === 0
        && event.body?.choices?.[0]?.message?.content === malformedFixture);
      const nativeFeedback = history.some(message => message.role === 'user' && /tool call error|no tool calls found/i.test(String(message.content)));
      checks.native_format_recovery = formatRequests.length === 2 && result.code === 0 && result.cleanupVerified === true
        && native.finalAnswer(result).trim() === 'fixture-complete'
        && capturedMalformed && nativeFeedback
        && after.counters.inference - before.counters.inference === 2 && after.counters.tools - before.counters.tools === 1;
      writeNew(path.join(directory, 'format-recovery.json'), { kind: 'inert-native-format-recovery', inference: false, raw_assistant_content: malformedFixture,
        requests: formatRequests, events: formatEvents, result, finalAnswer: native.finalAnswer(result), before, after,
        retention: { private_raw_response_captured: capturedMalformed, native_format_feedback_observed: nativeFeedback,
          native_failed_assistant_retained: history.some(message => message.role === 'assistant' && message.content === malformedFixture),
          policy: 'Pinned mini-swe discards failed assistant generations and supplies native format feedback; private gateway evidence retains exact bytes.' }, verified: checks.native_format_recovery });
      await releaseNative('format-recovery-finished'); formatRecovery = false;
      if (signal?.aborted) throw new Error('CONFORMANCE_CANCELLED');
    }
    // Fresh cancellation session, with no model response. Its first real HTTP
    // request proves startup reached the provider before owned cancellation.
    const cancelTask = path.join(directory, 'cancel-task'), cancelProfile = path.join(directory, 'cancel-profile');
    mkdirSync(cancelTask, { mode: 0o700 }); writeFileSync(path.join(cancelTask, 'probe.txt'), 'cancel fixture\n');
    let reached; const providerReached = new Promise(resolve => { reached = resolve; });
    cancelling = reached;
    launches++;
    native = await startNative({ root, harness, model: 'local-eval-fixture', modelContextCapacity: 65536, endpoint, taskRoot: cancelTask, profile: cancelProfile, prompt: 'Read probe.txt.',
      signal, skillsEnabled: true, installation, budgetEnvironment: environment, hostBudgetEnvironment: environment, allowUnverified: true });
    let timer;
    const arrived = await Promise.race([providerReached.then(() => true), native.done.then(() => false), new Promise(resolve => { timer = setTimeout(() => resolve(false), 20_000); })]);
    clearTimeout(timer);
    const started = Date.now(), stopped = await native.stop('inert-cancellation-probe');
    checks.cancellation = arrived && stopped.cleanupVerified === true && Date.now() - started <= 5000;
    checks.fresh_conversation = cancellationRequests.length === 1 && !/fixture-call-\d/.test(JSON.stringify(cancellationRequests)) && !JSON.stringify(cancellationRequests).includes(secret);
    writeNew(path.join(directory, 'cancellation.json'), { kind: 'inert-owned-cancellation', inference: false, provider_reached: arrived, requests: cancellationRequests, elapsed_ms: Date.now() - started, result: stopped });
    const evidence = ['roundtrip.json', 'cancellation.json', ...(harness.id === 'mini-swe-agent' ? ['format-recovery.json'] : [])].map(name => ({ path: path.join(directory, name), sha256: sha256(readFileSync(path.join(directory, name))) }));
    if (nativeAdapterIdentity() !== adapterIdentity) throw new Error('CONFORMANCE_ADAPTER_CHANGED');
    if (sourceReceipt(root).sha256 !== productIdentity) throw new Error('CONFORMANCE_PRODUCT_CHANGED');
    receipt = { schema_version: 1, harness_id: harness.id, adapter_sha256: adapterIdentity, client_identity: identity, product_source_sha256: productIdentity, inference: false,
      checks, evidence, status: Object.values(checks).every(Boolean) ? 'mechanically-admitted' : 'blocked', source: 'native-client-with-inert-provider', execution_location: harness.container ? 'arm64-container' : 'native-macos' };
    return receipt;
  } catch (error) {
    if (error.budget_cleanup) failedBudgetRelease = error.budget_cleanup;
    if (!native && error.native_cleanup) nativeSessions.push({ reason: 'native-start-failed', ...cleanupObservation(error.native_cleanup) });
    writeNew(path.join(directory, 'failure.json'), { inference: false, reason: error.message, failure: failureObservation(error), requests, events }); throw error;
  } finally {
    const steps = [];
    async function close(name, action) {
      try { await action(); steps.push({ step: name, outcome: 'completed' }); }
      catch (error) { steps.push({ step: name, outcome: 'failed', failure: failureObservation(error) }); }
    }
    await close('native-session', () => releaseNative('conformance-finished'));
    for (const response of pending) response.destroy();
    await close('gateway', async () => { await gateway?.close(); });
    await close('inert-provider', async () => {
      if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); if (server.listening) throw new Error('CONFORMANCE_PROVIDER_STILL_LISTENING'); }
    });
    await close('budget-authority', async () => {
      if (authority) { await authority.close(); if (existsSync(authority.socketPath)) throw new Error('CONFORMANCE_BUDGET_SOCKET_REMAINS'); }
      else if (authorityAttempted && failedBudgetRelease?.cleanupVerified !== true) throw new Error('CONFORMANCE_BUDGET_SETUP_RELEASE_UNVERIFIED');
    });
    const release = { schema_version: 1, kind: 'inert-native-owned-release', inference: false, product_source_sha256: productIdentity,
      adapter_sha256: adapterIdentity, client_identity: identity, launches, native_sessions: nativeSessions, steps, ...(failedBudgetRelease ? { failed_budget_cleanup: failedBudgetRelease } : {}),
      owned_cleanup_verified: nativeSessions.length === launches && nativeSessions.every(item => item.cleanupVerified === true) && steps.every(item => item.outcome === 'completed') };
    const releasePath = path.join(directory, 'release.json'); writeNew(releasePath, release);
    if (receipt) {
      receipt.release = { path: releasePath, sha256: sha256(readFileSync(releasePath)) }; receipt.evidence.push(receipt.release);
      receipt.checks.owned_release = release.owned_cleanup_verified;
      receipt.status = Object.values(receipt.checks).every(Boolean) ? 'mechanically-admitted' : 'blocked';
      writeNew(path.join(directory, 'receipt.json'), receipt);
    }
    if (!release.owned_cleanup_verified) throw new Error('CONFORMANCE_OWNED_RELEASE_UNVERIFIED');
  }
}
