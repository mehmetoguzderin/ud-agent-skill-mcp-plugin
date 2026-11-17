/** MIT. Pinned Kimi durable observations; no native client or model runs. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { nativeKimiWireResults, nativeKimiProfileResults, nativeLogResults } from '../../evals/local/native-observations.mjs';

const call = { type: 'tool.call', uuid: 'a7766054-64ca-447f-af77-bac9ccd24003', toolCallId: 'fixture-call-1', name: 'Skill', args: { skill: 'ud-validate' } };
const result = { type: 'tool.result', parentUuid: call.uuid, toolCallId: call.toolCallId, result: { output: 'Skill "ud-validate" loaded inline. Follow its instructions.', durationMs: 1 } };
const line = (event, agentId = 'main') => JSON.stringify({ type: 'context.append_loop_event', agentId, event });
const journal = (...events) => events.map(event => line(event)).join('\n') + '\n';

test('Kimi projects a terminal native journal result rather than guessing from stream-json prose', () => {
  const observed = nativeKimiWireResults(journal(call, result));
  assert.equal(observed.length, 1); assert.equal(observed[0].id, call.toolCallId); assert.equal(observed[0].failed, false);
  assert.equal(observed[0].source, 'native-kimi-persistent-tool-result');
  assert.deepEqual(observed[0].arguments, call.args); assert.deepEqual(observed[0].native_evidence.result, result.result);
  for (const isError of [true, false]) {
    assert.equal(nativeKimiWireResults(journal(call, { ...result, result: { ...result.result, isError } }))[0].failed, isError);
  }
  assert.equal(nativeKimiWireResults(journal(call, { ...result, result: { output: 'success-looking text', isError: true } }))[0].failed, true);
  assert.deepEqual(nativeLogResults(JSON.stringify({ role: 'tool', tool_call_id: call.toolCallId, content: result.result.output })), []);
});

test('Kimi missing, malformed, unrelated, duplicate, or subagent results stay unverified', () => {
  for (const text of [journal(call), journal(result), journal(call, { ...result, parentUuid: 'other' }),
    journal(call, { ...result, toolCallId: 'other' }), journal(call, { ...result, result: {} }),
    journal(call, { ...result, result: { output: 'bytes', isError: null } }),
    journal(call, { ...result, result: { output: 'bytes', isError: 'false' } }),
    journal(call, result, result), journal(call, result, { ...call, uuid: 'second' }),
    [line(call, 'subagent'), line(result, 'subagent')].join('\n'),
    journal(call) + '{"type":"context.append_loop_event","agentId":"main","event":{"type":"tool.result"',
  ]) assert.deepEqual(nativeKimiWireResults(text), []);
});

test('Kimi reads only the single main-agent journal under its fresh private profile', () => {
  const profile = mkdtempSync(path.join(os.tmpdir(), 'ud-kimi-native-'));
  const sessions = path.join(profile, '.kimi-code/sessions/wd_task_abc');
  const file = id => path.join(sessions, `session_${id}`, 'agents/main/wire.jsonl');
  try {
    assert.deepEqual(nativeKimiProfileResults(profile), []);
    const selected = file('630db659-83f9-49e9-aec2-66eaaf17c2b4'); mkdirSync(path.dirname(selected), { recursive: true }); writeFileSync(selected, journal(call, result));
    assert.equal(nativeKimiProfileResults(profile)[0].failed, false);
    const second = file('730db659-83f9-49e9-aec2-66eaaf17c2b4'); mkdirSync(path.dirname(second), { recursive: true }); writeFileSync(second, journal(call, result));
    assert.throws(() => nativeKimiProfileResults(profile), /SESSION_AMBIGUOUS/);
    rmSync(second); symlinkSync(selected, second);
    assert.throws(() => nativeKimiProfileResults(profile), /EVIDENCE_PATH_INVALID/);
  } finally { rmSync(profile, { recursive: true, force: true }); }
});
