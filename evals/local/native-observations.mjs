/** Exact native call/result projection for pre-dispatch recovery gating. MIT. */
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const object = value => value && typeof value === 'object' && !Array.isArray(value);
const args = value => typeof value === 'string' ? JSON.parse(value) : value;

/** Kimi 2.5.3's persistent tool.result records retain the status omitted by its
 * stream-json writer. normalizeToolResult and toolTelemetryOutcome define absent
 * isError as success on an actual result; missing results remain unknown. */
export function nativeKimiWireResults(text) {
  const calls = new Map(), ids = new Map(), invalid = new Set(), completed = new Set(), results = [];
  for (const line of text.split('\n')) {
    let row; try { row = JSON.parse(line); } catch { continue; }
    if (row?.type !== 'context.append_loop_event' || row.agentId !== 'main' || !object(row.event)) continue;
    const event = row.event, id = event.toolCallId;
    if (typeof id !== 'string' || !id) continue;
    if (event.type === 'tool.call' && typeof event.uuid === 'string' && event.uuid && typeof event.name === 'string' && event.name && object(event.args)) {
      if (calls.has(event.uuid) || ids.has(id)) { invalid.add(id); if (calls.has(event.uuid)) invalid.add(calls.get(event.uuid).toolCallId); continue; }
      calls.set(event.uuid, event); ids.set(id, event.uuid);
    }
    if (event.type !== 'tool.result') continue;
    const call = calls.get(event.parentUuid), result = event.result;
    if (!call || call.toolCallId !== id || !object(result) || !Object.hasOwn(result, 'output') ||
        !(typeof result.output === 'string' || Array.isArray(result.output)) ||
        Object.hasOwn(result, 'isError') && typeof result.isError !== 'boolean') continue;
    if (completed.has(id)) { invalid.add(id); continue; }
    completed.add(id);
    results.push({ id, name: call.name, arguments: call.args, failed: result.isError === true, source: 'native-kimi-persistent-tool-result',
      native_evidence: { call_uuid: call.uuid, parent_uuid: event.parentUuid, result } });
  }
  return results.filter(result => !invalid.has(result.id));
}

/** A newly created private profile must have only one main-agent journal. Never
 * follow a task-created symlink or combine other sessions/subagents as evidence. */
export function nativeKimiProfileResults(profile) {
  const descend = (parent, name) => {
    const file = path.join(parent, name), info = lstatSync(file, { throwIfNoEntry: false });
    if (!info) return undefined;
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('KIMI_NATIVE_EVIDENCE_PATH_INVALID');
    return file;
  };
  let base = descend(profile, '.kimi-code'); if (!base) return [];
  base = descend(base, 'sessions'); if (!base) return [];
  const files = [];
  for (const workspace of readdirSync(base).filter(name => /^wd_[A-Za-z0-9_-]+$/.test(name))) {
    const directory = descend(base, workspace);
    for (const session of readdirSync(directory).filter(name => /^session_[a-f0-9-]{36}$/.test(name))) {
      let selected = descend(directory, session); selected = descend(selected, 'agents'); if (!selected) continue;
      selected = descend(selected, 'main'); if (!selected) continue;
      const file = path.join(selected, 'wire.jsonl'), info = lstatSync(file, { throwIfNoEntry: false });
      if (!info) continue;
      if (!info.isFile() || info.isSymbolicLink() || info.size > 32 * 1024 ** 2) throw new Error('KIMI_NATIVE_EVIDENCE_PATH_INVALID');
      files.push(file);
    }
  }
  if (files.length > 1) throw new Error('KIMI_NATIVE_EVIDENCE_SESSION_AMBIGUOUS');
  return files.length ? nativeKimiWireResults(readFileSync(files[0], 'utf8')) : [];
}
export function responseNativeCalls(protocol, response, { requestId } = {}) {
  if (protocol === 'chat') return (response.choices?.[0]?.message?.tool_calls ?? []).map(call => ({ id: call.id, name: call.function.name, arguments: args(call.function.arguments) }));
  if (protocol === 'messages') return response.content.filter(item => item.type === 'tool_use').map(item => ({ id: item.id, name: item.name, arguments: item.input }));
  if (protocol === 'responses') return response.output.filter(item => ['function_call', 'custom_tool_call', 'shell_call', 'apply_patch_call'].includes(item.type)).map(item => ({
    id: item.call_id, name: item.name ?? item.type, ...(item.namespace === undefined ? {} : { namespace: item.namespace }), arguments: item.type === 'function_call' ? args(item.arguments) : item.type === 'custom_tool_call' ? { input: item.input } : item.type === 'shell_call' ? item.action : { patch: item.patch ?? item.operation },
  }));
  return (response.candidates?.[0]?.content?.parts ?? []).filter(item => item.functionCall).map((item, ordinal) => {
    const call = item.functionCall;
    if (call.id !== undefined && call.id !== null && (typeof call.id !== 'string' || !call.id)) throw new Error('GEMINI_CALL_ID_INVALID');
    if (!call.id && (typeof requestId !== 'string' || !requestId || requestId.length > 80)) throw new Error('GEMINI_OBSERVER_ID_REQUIRED');
    return { id: call.id ?? `g-${requestId}-${ordinal}`, wire_id: call.id ?? null, name: call.name, arguments: call.args };
  });
}
/** Codex 0.167.1 maps raw MCP IDs to item_N in its JSONL writer. It retains
 * server, tool, arguments and explicit terminal status. Require the matching
 * start and completion, never derive status from a tool's prose or UD findings.
 * Source: codex-rs/exec/src/event_processor_with_jsonl_output.rs at rust-v0.167.1. */
export function nativeCodexMcpResults(text) {
  const started = new Map(), completed = new Set(), invalid = new Set(), results = [];
  for (const line of text.split('\n')) {
    let event; try { event = JSON.parse(line); } catch { continue; }
    if (!['item.started', 'item.completed'].includes(event?.type) || event.item?.type !== 'mcp_tool_call') continue;
    const item = event.item, id = item.id;
    if (typeof id !== 'string' || !/^item_\d+$/.test(id)) continue;
    if (typeof item.server !== 'string' || !/^[A-Za-z0-9_-]{1,59}$/.test(item.server) ||
        typeof item.tool !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(item.tool) || !object(item.arguments)) { invalid.add(id); continue; }
    if (event.type === 'item.started') {
      if (started.has(id) || completed.has(id) || item.status !== 'in_progress' || item.result !== null || item.error !== null) { invalid.add(id); continue; }
      started.set(id, item); continue;
    }
    if (completed.has(id)) { invalid.add(id); continue; }
    completed.add(id);
    const call = started.get(id), result = object(item.result) && Array.isArray(item.result.content), error = object(item.error) && typeof item.error.message === 'string';
    if (!call || item.server !== call.server || item.tool !== call.tool || canonical(item.arguments) !== canonical(call.arguments) ||
        !['completed', 'failed'].includes(item.status) ||
        item.status === 'completed' && (!result || item.error !== null) ||
        item.status === 'failed' && !(result && item.error === null || error && item.result === null)) { invalid.add(id); continue; }
    results.push({ id, name: item.tool, namespace: `mcp__${item.server}`, arguments: item.arguments,
      failed: item.status === 'failed', source: 'native-codex-mcp-terminal-status',
      native_evidence: { started: call, completed: item } });
  }
  return results.filter(result => !invalid.has(result.id));
}

export function nativeLogResults(text) {
  const results = nativeCodexMcpResults(text), geminiCalls = new Map(), deepseekCalls = new Map();
  for (const line of text.split('\n')) {
    let event; try { event = JSON.parse(line); } catch { continue; }
    if (event.type === 'tool_use' && typeof event.tool_id === 'string' && typeof event.tool_name === 'string' && object(event.parameters)) geminiCalls.set(event.tool_id, { name: event.tool_name, arguments: event.parameters });
    if (event.type === 'tool_result' && typeof event.tool_id === 'string' && ['success', 'error'].includes(event.status) && geminiCalls.has(event.tool_id))
      results.push({ id: event.tool_id, ...geminiCalls.get(event.tool_id), failed: event.status === 'error', source: 'native-gemini-tool-result-status' });
    // The pinned dsh-headless JSON stream maps message.isError directly to
    // error/completed, and emits a result only for appended tool/result events.
    if (event.type === 'tool_call' && typeof event.callId === 'string' && event.callId && typeof event.tool === 'string' && event.tool && object(event.input))
      deepseekCalls.set(event.callId, { name: event.tool, arguments: event.input });
    if (event.type === 'tool_result' && typeof event.callId === 'string' && ['completed', 'error'].includes(event.status) && typeof event.result === 'string' && deepseekCalls.has(event.callId))
      results.push({ id: event.callId, ...deepseekCalls.get(event.callId), failed: event.status === 'error', source: 'native-deepseek-tool-result-status' });
    for (const part of event.message?.content ?? []) if (part.type === 'tool_result' && typeof part.tool_use_id === 'string') {
      if (typeof part.is_error === 'boolean') results.push({ id: part.tool_use_id, failed: part.is_error, source: 'native-event-is_error' });
      else if (event.message.role === 'user' && typeof event.tool_use_result?.success === 'boolean' && event.message.content.filter(value => value.type === 'tool_result').length === 1)
        results.push({ id: part.tool_use_id, failed: !event.tool_use_result.success, source: 'native-tool-use-result-success' });
    }
    if (event.type === 'tool_execution_end' && typeof event.toolCallId === 'string' && typeof event.isError === 'boolean')
      results.push({ id: event.toolCallId, failed: event.isError, source: 'native-tool-execution-end-isError' });
    if (event.type === 'message_end' && event.message?.role === 'toolResult' && typeof event.message.toolCallId === 'string' && typeof event.message.isError === 'boolean')
      results.push({ id: event.message.toolCallId, failed: event.message.isError, source: 'native-tool-result-isError' });
  }
  return results;
}

const canonical = value => JSON.stringify(value, (_key, item) => object(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);

/** Bind only a unique exact native MCP identity to a unique provider call.
 * Different item_N/provider IDs remain separately recorded. Identical parallel
 * calls are ambiguous because Codex omits the original ID, so stay unverified. */
function resolveCodexMcpResults(body, pending, observed) {
  const native = observed.filter(event => event.source === 'native-codex-mcp-terminal-status'), bound = [];
  const equal = (left, right) => left.name === right.name && left.namespace === right.namespace && canonical(left.arguments) === canonical(right.arguments);
  for (const call of pending) {
    if (!call.namespace?.startsWith('mcp__') || pending.filter(candidate => equal(candidate, call)).length !== 1) continue;
    const matches = native.filter(event => equal(event, call));
    if (matches.length !== 1) continue;
    if (body !== undefined && body !== null) {
      const input = Array.isArray(body.input) ? body.input : [];
      const history = input.filter(item => item.type === 'function_call' && item.call_id === call.id);
      const replies = input.filter(item => item.type === 'function_call_output' && item.call_id === call.id);
      if (history.length !== 1 || replies.length !== 1) continue;
      let arguments_; try { arguments_ = args(history[0].arguments); } catch { continue; }
      if (!equal({ name: history[0].name, namespace: history[0].namespace, arguments: arguments_ }, call)) continue;
    }
    const result = matches[0];
    bound.push({ ...result, id: call.id, native_id: result.id, source: 'native-codex-unique-mcp-call-and-result-status' });
  }
  return bound;
}

/** Bind Gemini wire IDs only in private observation state. The pinned CLI adds
 * `${name}__` to native IDs and removes that prefix from provider history
 * (Turn.handlePendingFunctionCall and stripToolCallIdPrefixes in 0.68.0).
 * Exact call arguments and explicit native status remain required. */
export function resolveNativeResults(protocol, body, pendingCalls, nativeEvents = [], consumedNativeIds = new Set()) {
  const pending = [...pendingCalls.values()], observed = nativeEvents.filter(event => {
    if (typeof event.failed !== 'boolean' || consumedNativeIds.has(event.id)) return false;
    if (event.source !== 'native-openclaw-persistent-tool-result') return true;
    const call = pendingCalls.get(event.id);
    return (!protocol || protocol === 'chat') && call?.name === event.name && canonical(call.arguments) === canonical(event.arguments);
  });
  const protocolResults = body ? requestNativeResults(protocol, body) : [];
  // Codex's substituted IDs must never accidentally match a provider ID through
  // the generic direct-ID path, even when both happen to be spelled item_N.
  const direct = [...protocolResults, ...observed.filter(event => event.source !== 'native-codex-mcp-terminal-status'),
    ...(!protocol || protocol === 'responses' ? resolveCodexMcpResults(body, pending, observed) : [])];
  const statuses = new Map();
  for (const result of direct) {
    if (statuses.has(result.id) && statuses.get(result.id) !== result.failed) throw new Error('NATIVE_RESULT_CONFLICT');
    statuses.set(result.id, result.failed);
  }
  const geminiCalls = pending.filter(call => call.wire_id === null || typeof call.wire_id === 'string');
  if (protocol !== 'gemini' && !geminiCalls.length) return direct;
  const resolved = direct.filter(result => pendingCalls.has(result.id) && (!geminiCalls.some(call => call.id === result.id) || protocolResults.includes(result)));
  const messages = body?.contents ?? [];
  const latest = messages.findLast(message => (message.parts ?? []).some(part => part.functionResponse));
  const responses = (latest?.parts ?? []).filter(part => part.functionResponse).map(part => part.functionResponse);
  const nativeId = call => typeof call.wire_id === 'string' ? call.wire_id.startsWith(`${call.name}__`) ? call.wire_id : `${call.name}__${call.wire_id}` : null;
  for (const call of geminiCalls) {
    const expectedNativeId = nativeId(call), prefix = `${call.name}__`;
    if (expectedNativeId ? geminiCalls.filter(value => nativeId(value) === expectedNativeId).length !== 1 : pending.filter(value => value.name === call.name).length !== 1) continue;
    const replies = responses.filter(reply => reply.name === call.name && (!expectedNativeId || reply.id === call.wire_id || reply.id === expectedNativeId.slice(prefix.length)));
    if (body && replies.length !== 1) continue;
    const reply = replies[0];
    const matching = observed.filter(event => event.name === call.name && canonical(event.arguments) === canonical(call.arguments)
      && (!expectedNativeId || event.id === expectedNativeId || event.id === call.wire_id)
      && (!reply?.id || event.id === reply.id || event.id === prefix + reply.id));
    // Native logs may expose the same explicit result in more than one event.
    const unique = new Map(matching.map(event => [event.id, event]));
    if (unique.size !== 1) continue;
    const result = unique.values().next().value;
    if (statuses.has(call.id) && statuses.get(call.id) !== result.failed) throw new Error('NATIVE_RESULT_CONFLICT');
    const bound = { ...result, id: call.id, native_id: result.id, source: 'native-gemini-unique-call-and-result-status' };
    const existing = resolved.findIndex(value => value.id === call.id);
    if (existing === -1) resolved.push(bound); else resolved[existing] = bound;
  }
  return resolved;
}
export function requestNativeResults(protocol, body) {
  const results = [];
  const add = (id, content, explicit) => {
    if (typeof id !== 'string') return;
    if (typeof explicit === 'boolean') { results.push({ id, failed: explicit, source: 'native-protocol-is_error' }); return; }
    let decoded = content;
    if (typeof decoded === 'string') { try { decoded = JSON.parse(decoded); } catch { return; } }
    // mini-swe serializes the native shell observation with its actual returncode.
    if (object(decoded) && Number.isInteger(decoded.returncode)) results.push({ id, failed: decoded.returncode !== 0, source: 'native-shell-returncode' });
  };
  if (protocol === 'chat') for (const message of body.messages ?? []) if (message.role === 'tool') add(message.tool_call_id, message.content, message.is_error);
  // Messages defines omitted is_error as a successful result block. This is an
  // observed protocol result, not an assumed success when the block is absent.
  // https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls
  if (protocol === 'messages') for (const message of body.messages ?? []) for (const part of Array.isArray(message.content) ? message.content : []) if (message.role === 'user' && part.type === 'tool_result') add(part.tool_use_id, part.content, part.is_error === undefined ? false : part.is_error);
  if (protocol === 'responses') {
    const items = Array.isArray(body.input) ? body.input : [], names = new Map(items.filter(item => item.type === 'function_call').map(item => [item.call_id, item.name]));
    for (const item of items) if (item.type === 'function_call_output') {
      if (['exec_command', 'write_stdin'].includes(names.get(item.call_id)) && typeof item.output === 'string') {
        const match = /^Chunk ID: [A-Za-z0-9_-]+\nWall time: \d+(?:\.\d+)? seconds\nProcess exited with code (-?\d+)\n(?:Original token count: \d+\n)?(?:Final output|Output):\n/.exec(item.output);
        if (match) { results.push({ id: item.call_id, failed: Number(match[1]) !== 0, source: 'native-codex-command-exit-prefix' }); continue; }
        const running = /^Chunk ID: [A-Za-z0-9_-]+\nWall time: \d+(?:\.\d+)? seconds\nProcess running with session ID \d+\n(?:Original token count: \d+\n)?(?:Final output|Output):\n/.test(item.output);
        if (running) { results.push({ id: item.call_id, failed: false, source: 'native-codex-command-running-session' }); continue; }
      }
      add(item.call_id, item.output, item.is_error);
    }
  }
  if (protocol === 'gemini') for (const message of body.contents ?? []) for (const part of message.parts ?? []) if (part.functionResponse) add(part.functionResponse.id, part.functionResponse.response, part.functionResponse.response?.error ? true : undefined);
  return results;
}
export function nativeTrajectoryResults(trajectory) {
  if (trajectory?.trajectory_format !== 'mini-swe-agent-1.1' || !Array.isArray(trajectory.messages)) return [];
  const results = requestNativeResults('chat', { messages: trajectory.messages });
  const terminal = trajectory.messages.at(-1), preceding = trajectory.messages.at(-2), calls = preceding?.tool_calls;
  // The pinned local environment raises Submitted only after executing a shell
  // command with returncode 0 and the native completion sentinel. It omits that
  // ordinary tool message, so bind this source-defined terminal result narrowly.
  if (trajectory.info?.exit_status === 'Submitted' && terminal?.role === 'exit' && terminal.extra?.exit_status === 'Submitted' &&
      typeof terminal.content === 'string' && terminal.extra.submission === terminal.content && preceding?.role === 'assistant' &&
      Array.isArray(calls) && calls.length === 1 && calls[0].type === 'function' && calls[0].function?.name === 'bash' && typeof calls[0].id === 'string' &&
      !results.some(result => result.id === calls[0].id)) results.push({ id: calls[0].id, failed: false, source: 'pinned-native-Submitted-returncode-zero' });
  return results;
}
