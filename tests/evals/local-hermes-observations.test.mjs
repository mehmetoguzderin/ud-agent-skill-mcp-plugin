import { posixTest } from '../fixtures/native-scope.mjs';
// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parse } from 'yaml';
import { configureNativeProfile } from '../../evals/local/native-recipes.mjs';
import { nativeHermesResults, nativeHermesProfileResults, nativeHermesFinalOutput, nativeHermesProfileFinalOutput } from '../../evals/local/hermes-observations.mjs';
import { resolveNativeResults } from '../../evals/local/native-observations.mjs';
import { nativeTranscript } from '../../evals/local/native.mjs';

const event = { type: 'hermes.post_tool_call', schema_version: 1, tool_call_id: 'call-1', tool_name: 'read_file', args: { path: 'data.txt' },
  status: 'ok', result: 'Actual native text', session_id: 'session-1', turn_id: 'turn-1', api_request_id: 'request-1' };
const finalEvent = { type: 'hermes.post_llm_call', schema_version: 1, session_id: 'session-1', turn_id: 'turn-1', task_id: 'task-1',
  assistant_response: 'First line\n\n  Indented second line\nLast line\n', model: 'fixture', platform: 'cli' };

test('Hermes observer records native status verbatim without classifying returned prose', () => {
  for (const status of ['ok', 'error', 'blocked', 'cancelled', 'timeout']) {
    const observed = nativeHermesResults(JSON.stringify({ ...event, status, result: status === 'ok' ? 'error appears in a quoted document' : { success: true } }));
    assert.equal(observed.length, 1); assert.equal(observed[0].failed, status !== 'ok');
    assert.equal(observed[0].id, event.tool_call_id); assert.deepEqual(observed[0].arguments, event.args);
    const pending = new Map([[event.tool_call_id, { id: event.tool_call_id, name: event.tool_name, arguments: event.args }]]);
    assert.equal(resolveNativeResults('chat', { messages: [] }, pending, observed)[0].failed, status !== 'ok');
  }
  assert.deepEqual(nativeHermesResults(JSON.stringify({ ...event, status: 'unknown' })), []);
  assert.deepEqual(nativeHermesResults(JSON.stringify({ ...event, tool_call_id: null })), []);
  assert.deepEqual(nativeHermesResults(JSON.stringify({ ...event, result: undefined })), []);
  assert.equal(nativeHermesResults(JSON.stringify(event) + '\n{"incomplete":').length, 1);
  assert.throws(() => nativeHermesResults([event, event].map(JSON.stringify).join('\n')), /RESULT_AMBIGUOUS/);
  assert.throws(() => nativeHermesResults([event, { ...event, tool_call_id: 'call-2', session_id: 'other-session' }].map(JSON.stringify).join('\n')), /SESSION_AMBIGUOUS/);
});

test('Hermes final output is the unique native post-LLM observation, preserving multiline answers and excluding startup stdout', () => {
  const profile = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-hermes-final-')));
  try {
    const output = path.join(profile, 'final-answer.txt');
    const result = { code: 0, cleanupVerified: true, stdout: '  ⚠ tirith security scanner enabled but not available — command scanning will use pattern matching only\r\n' + finalEvent.assistant_response + '\n' };
    writeFileSync(output, 'unverified output file');
    assert.equal(nativeTranscript('hermes-agent', result, output).finalAnswer, '', 'Neither arbitrary stdout nor output files establish a Hermes final answer');
    assert.equal(nativeTranscript('hermes-agent', result, output).events.some(item => item.type === 'native.adapter.completed'), false);
    writeFileSync(path.join(profile, 'native-hermes.jsonl'), [event, finalEvent].map(JSON.stringify).join('\n') + '\n');
    const observed = nativeTranscript('hermes-agent', result, output);
    assert.equal(observed.finalAnswer, finalEvent.assistant_response);
    assert.deepEqual(observed.events.find(item => item.type === 'hermes.post_llm_call'), finalEvent);
    assert.equal(observed.events.some(item => item.type === 'native.adapter.completed'), true);
    assert.equal(nativeHermesProfileResults(profile).length, 1, 'Final events do not manufacture tool results');
    assert.deepEqual(nativeHermesProfileFinalOutput(profile), { finalAnswer: finalEvent.assistant_response, event: finalEvent });
    assert.equal(nativeTranscript('hermes-agent', { ...result, code: 1 }, output).events.some(item => item.type === 'native.adapter.completed'), false);
  } finally { rmSync(profile, { recursive: true, force: true }); }
  assert.equal(nativeHermesFinalOutput(JSON.stringify(event)), undefined);
  assert.throws(() => nativeHermesFinalOutput([finalEvent, finalEvent].map(JSON.stringify).join('\n')), /FINAL_AMBIGUOUS/);
  assert.throws(() => nativeHermesFinalOutput(JSON.stringify({ ...finalEvent, assistant_response: null })), /FINAL_UNVERIFIED/);
  assert.throws(() => nativeHermesFinalOutput([event, { ...finalEvent, session_id: 'another-session' }].map(JSON.stringify).join('\n')), /SESSION_AMBIGUOUS/);
  assert.throws(() => nativeHermesFinalOutput([event, { ...finalEvent, turn_id: 'another-turn' }].map(JSON.stringify).join('\n')), /TURN_AMBIGUOUS/);
});

posixTest('configured Hermes plugin registers only passive native hooks and preserves callback inputs', () => {
  const profile = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-hermes-observer-')));
  try {
    const configured = configureNativeProfile('hermes-agent', { profile, model: 'fixture', endpoint: 'http://127.0.0.1:19999', env: {}, modelContextCapacity: 65536 });
    const config = parse(readFileSync(path.join(profile, '.hermes/config.yaml'), 'utf8'));
    assert.deepEqual(config.plugins.enabled, ['ud-local-observer']);
    const plugin = path.join(profile, '.hermes/plugins/ud-local-observer');
    assert.deepEqual(parse(readFileSync(path.join(plugin, 'plugin.yaml'), 'utf8')).hooks, ['post_tool_call', 'post_llm_call']);
    const script = `import concurrent.futures, copy, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location('observer', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class Context:
    def __init__(self): self.hooks = []
    def register_hook(self, name, callback): self.hooks.append((name, callback))
ctx = Context()
assert module.register(ctx) is None
assert [name for name, _ in ctx.hooks] == ['post_tool_call', 'post_llm_call']
assert not os.path.exists(os.environ['UD_LOCAL_HERMES_OBSERVATIONS'])
callback = ctx.hooks[0][1]
def invoke(index):
    event = {'tool_call_id': 'call-' + str(index), 'tool_name': 'read_file', 'args': {'path': 'data.txt'}, 'status': 'ok', 'result': {'text': 'native result'}, 'session_id': 'one-session'}
    before = copy.deepcopy(event)
    assert callback(**event) is None
    assert event == before
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(invoke, range(8)))
final = {'session_id': 'one-session', 'task_id': 'task-1', 'turn_id': 'turn-1', 'assistant_response': 'First line\\n\\n  Second line\\n', 'model': 'fixture', 'platform': 'cli', 'user_message': 'private user content', 'conversation_history': [{'role': 'user', 'content': 'private history'}]}
before = copy.deepcopy(final)
assert ctx.hooks[1][1](**final) is None
assert final == before
print('passive native hook preserved all inputs')
`;
    const result = spawnSync('/usr/bin/python3', ['-c', script, path.join(plugin, '__init__.py')], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', UD_LOCAL_HERMES_OBSERVATIONS: configured.env.UD_LOCAL_HERMES_OBSERVATIONS }, timeout: 10_000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(nativeHermesProfileResults(profile).length, 8, 'Concurrent callbacks must produce complete distinct records');
    assert.equal(nativeHermesProfileFinalOutput(profile).finalAnswer, 'First line\n\n  Second line\n');
    const original = readFileSync(configured.env.UD_LOCAL_HERMES_OBSERVATIONS, 'utf8');
    assert.equal(original.includes('private user content'), false);
    assert.equal(original.includes('private history'), false);
    const target = path.join(profile, 'target'); writeFileSync(target, original);
    rmSync(configured.env.UD_LOCAL_HERMES_OBSERVATIONS); symlinkSync(target, configured.env.UD_LOCAL_HERMES_OBSERVATIONS);
    assert.throws(() => nativeHermesProfileResults(profile), /PATH_INVALID/);
    assert.throws(() => nativeHermesProfileFinalOutput(profile), /PATH_INVALID/);
  } finally { rmSync(profile, { recursive: true, force: true }); }
}, 15_000);
