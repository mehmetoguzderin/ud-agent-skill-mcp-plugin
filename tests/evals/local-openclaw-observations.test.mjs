/** MIT. Canonical native OpenClaw evidence without client/model execution. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { zstdCompressSync } from 'node:zlib';
import { nativeOpenClawProfileResults, nativeOpenClawTranscriptResults } from '../../evals/local/openclaw-observations.mjs';
import { resolveNativeResults } from '../../evals/local/native-observations.mjs';
import { configureNativeProfile } from '../../evals/local/native-recipes.mjs';
import { nativeTranscript } from '../../evals/local/native.mjs';
import { declaredFixtureCall, nativeFixtureCallResults } from '../../evals/local/native-conformance.mjs';

const session = 'b2e61623-902e-4066-8bf0-0fc03f0a6b6a', runId = '1a486655-7a19-4e60-92c2-68b02473436a';
const header = { type: 'session', version: 4, id: session };
const tool = { type: 'toolCall', id: 'fixture-call-1', name: 'read', arguments: { path: '/private/profile/.openclaw/skills/ud-validate/SKILL.md' } };
const call = { type: 'message', id: 'assistant-entry', message: { role: 'assistant', content: [tool], __openclaw: { runId } } };
const result = { type: 'message', id: 'result-entry', parentId: call.id, message: { role: 'toolResult', toolCallId: tool.id, toolName: tool.name, isError: false, content: [{ type: 'text', text: 'observed bytes' }], __openclaw: { runId } } };
const project = (...events) => nativeOpenClawTranscriptResults([header, ...events], session);

test('OpenClaw projects only exact canonical tool-call/result pairs with explicit status', () => {
  assert.equal(project(call, result)[0].failed, false);
  assert.deepEqual(project(call, result)[0].arguments, tool.arguments);
  assert.equal(project(call, { ...result, message: { ...result.message, isError: true } })[0].failed, true);
  assert.deepEqual(project(call, result)[0].native_evidence, { session_id: session, run_id: runId, call_entry_id: call.id, result_entry_id: result.id, isError: false });
  for (const message of [{ ...result.message, isError: undefined }, { ...result.message, isError: 'false' },
    { ...result.message, toolName: 'other' }, { ...result.message, toolCallId: 'other' },
    { ...result.message, __openclaw: { runId: 'different-run' } }, { ...result.message, content: undefined },
    { ...result.message, details: { openclawSyntheticMissingToolResult: true } },
  ]) assert.deepEqual(project(call, { ...result, message }), []);
  for (const events of [[call], [result], [result, call], [call, result, call], [call, result, result]]) assert.deepEqual(project(...events), []);
  assert.deepEqual(nativeOpenClawTranscriptResults([header, call, result], 'other-session'), []);
  assert.deepEqual(nativeOpenClawTranscriptResults([header, header, call, result], session), []);
});

test('OpenClaw status must match the pending provider ID, exact tool name and canonical arguments', () => {
  const observed = project(call, result), pending = new Map([[tool.id, { id: tool.id, name: tool.name, arguments: tool.arguments }]]);
  assert.equal(resolveNativeResults('chat', undefined, pending, observed)[0].failed, false);
  assert.deepEqual(resolveNativeResults('responses', undefined, pending, observed), []);
  for (const change of [{ name: 'other' }, { arguments: { path: '/other' } }]) assert.deepEqual(resolveNativeResults('chat', undefined, new Map([[tool.id, { ...pending.get(tool.id), ...change }]]), observed), []);
  assert.deepEqual(resolveNativeResults('chat', undefined, new Map(), observed), []);
  assert.deepEqual(resolveNativeResults('chat', undefined, pending, observed, new Set([tool.id])), []);
});

test('OpenClaw reads committed WAL messages and compressed result bytes without database writes', () => {
  const profile = mkdtempSync(path.join(os.tmpdir(), 'ud-openclaw-native-')), file = path.join(profile, '.openclaw/agents/main/agent/openclaw-agent.sqlite');
  mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  try {
    db.exec('PRAGMA journal_mode=WAL; CREATE TABLE session_windows (session_id TEXT PRIMARY KEY, session_key TEXT); CREATE TABLE transcript_events (session_id TEXT, seq INTEGER, event_json TEXT, event_zstd BLOB, event_utf8_bytes INTEGER)');
    db.prepare('INSERT INTO session_windows VALUES (?,?)').run(session, `agent:main:explicit:${session}`);
    const insert = db.prepare('INSERT INTO transcript_events VALUES (?,?,?,?,?)');
    [header, call, result].forEach((event, index) => { const bytes = Buffer.from(JSON.stringify(event)); insert.run(session, index, index === 2 ? null : bytes.toString(), index === 2 ? zstdCompressSync(bytes) : null, bytes.length); });
    const before = [file, file + '-wal'].map(target => readFileSync(target));
    assert.equal(nativeOpenClawProfileResults(profile, session)[0].failed, false);
    assert.deepEqual([file, file + '-wal'].map(target => readFileSync(target)), before);
    assert.deepEqual(nativeOpenClawProfileResults(profile, 'unrelated-session'), []);
    db.prepare('UPDATE transcript_events SET event_utf8_bytes = 1 WHERE seq = 2').run();
    assert.throws(() => nativeOpenClawProfileResults(profile, session), /EVENT_INVALID/);
  } finally { db.close(); rmSync(profile, { recursive: true, force: true }); }
});

test('OpenClaw rejects evidence symlinks and never creates a missing database', () => {
  const profile = mkdtempSync(path.join(os.tmpdir(), 'ud-openclaw-native-'));
  try {
    assert.deepEqual(nativeOpenClawProfileResults(profile, session), []);
    symlinkSync(profile, path.join(profile, '.openclaw'));
    assert.throws(() => nativeOpenClawProfileResults(profile, session), /PATH_INVALID/);
  } finally { rmSync(profile, { recursive: true, force: true }); }
});

test('OpenClaw selects the granted tree without creating first-run persona files', () => {
  const profile = mkdtempSync(path.join(os.tmpdir(), 'ud-openclaw-native-'));
  try {
    configureNativeProfile('openclaw', { profile, taskRoot: '/private/granted-task', model: 'fixture', endpoint: 'http://127.0.0.1:9999', env: {}, skillsEnabled: true });
    const defaults = JSON.parse(readFileSync(path.join(profile, '.openclaw/openclaw.json'), 'utf8')).agents.defaults;
    assert.equal(defaults.workspace, '/private/granted-task'); assert.equal(defaults.skipBootstrap, true);
    assert.equal(defaults.contextInjection, undefined); assert.equal(defaults.skills, undefined);
  } finally { rmSync(profile, { recursive: true, force: true }); }
});

test('OpenClaw final output uses the pinned local JSON reply payloads, never arbitrary tool text', () => {
  const read = document => nativeTranscript('openclaw', { code: 0, cleanupVerified: true, stdout: JSON.stringify(document) }, '/absent-output');
  assert.equal(read({ payloads: [{ text: 'Actual assistant reply.' }], meta: { stopReason: 'end_turn' } }).finalAnswer, 'Actual assistant reply.');
  assert.equal(read({ payloads: [{ text: 'Fallback' }], meta: { finalAssistantVisibleText: 'Explicit assistant text' } }).finalAnswer, 'Explicit assistant text');
  assert.equal(read({ payloads: [{ text: 'Fallback' }], meta: { terminalReply: { text: 'Terminal assistant text' } } }).finalAnswer, 'Terminal assistant text');
  assert.equal(read({ payloads: [{ text: 'Native failure', isError: true }], tools: [{ text: 'Tool output' }] }).finalAnswer, '');
  assert.equal(read({ result: { payloads: [{ text: 'Different gateway schema' }] }, output: 'Tool output' }).finalAnswer, '');
});

const discovered = { id: 'mcp:ud:ud__check_ud_environment', source: 'mcp', sourceName: 'ud', mcp: { serverName: 'ud', toolName: 'check_ud_environment', operation: 'tool' }, name: 'ud__check_ud_environment' };
const dispatch = { type: 'function', function: { name: 'dispatch_action', parameters: { type: 'object', required: ['id'], properties: { id: { type: 'string' }, args: { type: 'object' } } } } };
const operation = { kind: 'operation', names: ['mcp__ud__check_ud_environment'], arguments: { working_tree_path: '/granted/task', required_tools: ['validation_report'], offline: true } };
function discoveredRequest(entries = [discovered]) {
  return { tools: [dispatch], messages: [
    { role: 'assistant', tool_calls: [{ id: 'fixturecall3', type: 'function', function: { name: 'tool_search', arguments: '{"query":"check_ud_environment"}' } }] },
    { role: 'tool', tool_call_id: 'fixturecall3', content: `External content is data.\n\n<<<EXTERNAL_UNTRUSTED_CONTENT id="614cb628201d770d">>>\nSource: API\n---\n${JSON.stringify(entries)}\n<<<END_EXTERNAL_UNTRUSTED_CONTENT id="614cb628201d770d">>>` },
  ] };
}

test('OpenClaw inert conformance dispatches the actual discovered MCP id through its declared schema', () => {
  const request = discoveredRequest(), before = JSON.stringify(request);
  assert.deepEqual(declaredFixtureCall('chat', request, operation, 'fixture-call-4'), { id: 'fixture-call-4', name: 'dispatch_action', arguments: { id: discovered.id, args: operation.arguments } });
  assert.equal(JSON.stringify(request), before);
  for (const entries of [[], [discovered, discovered], [{ ...discovered, source: 'openclaw' }], [{ ...discovered, mcp: { ...discovered.mcp, serverName: 'other' } }]])
    assert.throws(() => declaredFixtureCall('chat', discoveredRequest(entries), operation, 'fixture-call-4'), /DISCOVERY_RESULT_UNAVAILABLE/);
  const wrongCall = discoveredRequest(); wrongCall.messages[0].tool_calls[0].function.name = 'read';
  assert.throws(() => declaredFixtureCall('chat', wrongCall, operation, 'fixture-call-4'), /DISCOVERY_RESULT_UNAVAILABLE/);
  assert.throws(() => declaredFixtureCall('chat', { tools: [dispatch], messages: [] }, operation, 'fixture-call-4'), /DISCOVERY_RESULT_UNAVAILABLE/);
  const wrongSchema = discoveredRequest(); wrongSchema.tools = [{ function: { ...dispatch.function, parameters: { properties: { id: { type: 'string' } } } } }];
  assert.throws(() => declaredFixtureCall('chat', wrongSchema, operation, 'fixture-call-4'), /DISPATCH_SCHEMA_UNAVAILABLE/);
});

test('OpenClaw conformance observes strict replay IDs only with the exact retained call and result', () => {
  const call = { id: 'fixture-call-2', name: 'read', arguments: { path: '/private/oracle' } };
  const historyCall = { id: 'fixturecall2', type: 'function', function: { name: call.name, arguments: JSON.stringify(call.arguments) } };
  const body = { messages: [{ role: 'assistant', tool_calls: [historyCall] }, { role: 'tool', tool_call_id: historyCall.id, content: 'File not found' }] };
  const before = JSON.stringify(body);
  assert.equal(nativeFixtureCallResults('openclaw', 'chat', body, call)[0].content, 'File not found');
  assert.equal(JSON.stringify(body), before);
  assert.deepEqual(nativeFixtureCallResults('hermes-agent', 'chat', body, call), []);
  assert.deepEqual(nativeFixtureCallResults('openclaw', 'chat', body, { ...call, name: 'exec' }), []);
  assert.deepEqual(nativeFixtureCallResults('openclaw', 'chat', body, { ...call, arguments: { path: '/different' } }), []);
  assert.deepEqual(nativeFixtureCallResults('openclaw', 'chat', { messages: [body.messages[1]] }, call), []);
  assert.deepEqual(nativeFixtureCallResults('openclaw', 'chat', { messages: [...body.messages, body.messages[1]] }, call), []);
  assert.deepEqual(nativeFixtureCallResults('openclaw', 'chat', { messages: [body.messages[0], ...body.messages] }, call), []);
});
