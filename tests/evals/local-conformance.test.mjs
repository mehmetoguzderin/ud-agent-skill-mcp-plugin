// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { nativeFixtureFrames, nativeFixtureResults, nativeFixtureRecipe, declaredFixtureCall, observedSkillBody, nativeFixtureRoute, nativeFixtureDiscovery, nativeImageDelivery } from '../../evals/local/native-conformance.mjs';
import { NATIVE_RECIPES } from '../../evals/local/native-recipes.mjs';

const call = { id: 'call-inert', name: 'read', arguments: { path: '/task/probe.txt', optional: null } };

test('native image delivery requires exact inline user image bytes, not filenames or text claims', () => {
  const bytes = Buffer.from('independent-inert-pixel-fixture');
  const part = { type: 'input_image', image_url: 'data:image/png;base64,' + bytes.toString('base64') };
  const request = content => ({ input: [{ role: 'user', content }] });
  const observed = nativeImageDelivery(request([part]), bytes);
  assert.equal(observed.verified, true); assert.equal(observed.inference, false);
  assert.equal(observed.semantic_verification, 'requires-scored-image-scenario');
  assert.equal(nativeImageDelivery(request([{ type: 'input_text', text: 'diagram.png' }]), bytes).verified, false);
  assert.equal(nativeImageDelivery(request([{ ...part, image_url: 'file:///task/diagram.png' }]), bytes).verified, false);
  assert.equal(nativeImageDelivery(request([part]), Buffer.from('different image')).verified, false);
  assert.equal(nativeImageDelivery({ input: [{ role: 'assistant', content: [part] }] }, bytes).verified, false);
  assert.equal(nativeImageDelivery(request([part, part]), bytes).verified, false);
});

test('native fixture paths preserve supported native protocol queries', () => {
  assert.equal(nativeFixtureRoute('messages', '/v1/messages?beta=true'), true);
  assert.equal(nativeFixtureRoute('gemini', '/v1beta/models/local-eval-fixture:streamGenerateContent?alt=sse'), true);
  assert.equal(nativeFixtureRoute('responses', '/v1/responses'), true);
  assert.equal(nativeFixtureRoute('messages', '/v1/chat/completions?beta=true'), false);
  assert.equal(nativeFixtureRoute('gemini', '/v1beta/models/other:generateContent'), false);
});
test('deferred discovery supplies only a published bounded mechanical default', () => {
  const tool = { name: 'ToolSearch', input_schema: { required: ['query', 'max_results'], properties: { query: { type: 'string' }, max_results: { type: 'number', default: 5 } } } };
  const action = nativeFixtureDiscovery(tool);
  assert.deepEqual(action, { kind: 'discovery', names: ['ToolSearch'], arguments: { query: 'check_ud_environment', max_results: 5 } });
  assert.equal(declaredFixtureCall('messages', { tools: [tool] }, action, 'search').arguments.max_results, 5);
  assert.throws(() => nativeFixtureDiscovery({ ...tool, input_schema: { ...tool.input_schema, properties: { max_results: {} } } }), /DEFAULT_UNVERIFIED/);
  assert.throws(() => declaredFixtureCall('messages', { tools: [{ ...tool, input_schema: { ...tool.input_schema, required: ['query', 'unknown'] } }] }, action, 'search'), /REQUIRED_ARGUMENT_UNAVAILABLE/);
});

test('inert tool fixtures preserve complete semantic calls and accounting in all endpoint families', () => {
  for (const protocol of ['chat', 'responses', 'messages', 'gemini']) {
    const fixture = nativeFixtureFrames(protocol, 'local-eval-fixture', call);
    assert.ok(fixture.frames.length > 0);
    const serialized = JSON.stringify(fixture.body);
    assert.match(serialized, /call-inert/); assert.match(serialized, /local-eval-fixture/);
    if (protocol === 'chat') { assert.equal(fixture.body.choices[0].finish_reason, 'tool_calls'); assert.deepEqual(JSON.parse(fixture.body.choices[0].message.tool_calls[0].function.arguments), call.arguments); }
    if (protocol === 'responses') { assert.equal(fixture.body.status, 'completed'); assert.deepEqual(JSON.parse(fixture.body.output[0].arguments), call.arguments); }
    if (protocol === 'messages') { assert.equal(fixture.body.stop_reason, 'tool_use'); assert.deepEqual(fixture.body.content[0].input, call.arguments); }
    if (protocol === 'gemini') { assert.equal(fixture.body.candidates[0].finishReason, 'STOP'); assert.deepEqual(fixture.body.candidates[0].content.parts[0].functionCall.args, call.arguments); }
    const final = nativeFixtureFrames(protocol, 'local-eval-fixture');
    assert.match(JSON.stringify(final.body), /fixture-complete/);
  }
});
test('Responses custom calls preserve exact input through stream and terminal item', () => {
  const fixture = nativeFixtureFrames('responses', 'local-eval-fixture', { id: 'custom', type: 'custom', name: 'shell', input: 'cat /task/probe.txt\n' });
  assert.equal(fixture.body.output[0].type, 'custom_tool_call');
  assert.equal(fixture.body.output[0].input, 'cat /task/probe.txt\n');
  assert.equal(fixture.frames.find(row => row.data.type === 'response.custom_tool_call_input.delta').data.delta, 'cat /task/probe.txt\n');
  assert.throws(() => nativeFixtureFrames('unknown', 'fixture'), /PROTOCOL_UNAVAILABLE/);
});
test('subsequent requests retain exact native tool-result identity across protocols', () => {
  const cases = {
    chat: { messages: [{ role: 'tool', tool_call_id: 'c', content: 'returned fixture' }] },
    responses: { input: [{ type: 'function_call_output', call_id: 'c', output: 'returned fixture' }, { type: 'custom_tool_call_output', call_id: 'custom', output: 'custom fixture' }] },
    messages: { messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c', content: 'returned fixture', is_error: false }] }] },
    gemini: { contents: [{ role: 'user', parts: [{ functionResponse: { id: 'c', name: 'read', response: { result: 'returned fixture' } } }] }] },
  };
  for (const [protocol, body] of Object.entries(cases)) {
    const result = nativeFixtureResults(protocol, body)[0];
    assert.equal(result.id, 'c'); assert.match(JSON.stringify(result.content), /returned fixture/);
    assert.deepEqual(nativeFixtureResults(protocol, {}), []);
  }
  assert.equal(nativeFixtureResults('responses', cases.responses)[1].id, 'custom');
});
test('all eleven pinned headless surfaces have skill, isolation and coordinator probes', () => {
  const ids = Object.keys(NATIVE_RECIPES);
  assert.equal(ids.length, 11);
  for (const id of ids) {
    const recipe = nativeFixtureRecipe(id, { taskRoot: '/task', profile: '/profile', oracle: '/private/oracle' });
    assert.ok(recipe.length >= 3, id);
    assert.match(JSON.stringify(recipe[0]), /ud-validate/, id);
    assert.match(JSON.stringify(recipe[1]), /private\/oracle/, id);
    assert.match(JSON.stringify(recipe), /check_ud_environment/, id);
  }
  assert.throws(() => nativeFixtureRecipe('desktop', {}), /RECIPE_UNAVAILABLE/);
});
test('probe selection uses only declared function schemas and never fills unknown required arguments', () => {
  const read = { kind: 'read', names: ['read_file', 'read'], file: '/task/probe.txt' };
  const chat = { tools: [{ type: 'function', function: { name: 'read_file', parameters: { required: ['path'], properties: { path: { type: 'string' } } } } }] };
  assert.deepEqual(declaredFixtureCall('chat', chat, read, 'c'), { id: 'c', name: 'read_file', arguments: { path: '/task/probe.txt' } });
  const messages = { tools: [{ name: 'Read', input_schema: { required: ['file_path'], properties: { file_path: { type: 'string' } } } }] };
  assert.equal(declaredFixtureCall('messages', messages, { ...read, names: ['Read'] }, 'c').arguments.file_path, '/task/probe.txt');
  const gemini = { tools: [{ functionDeclarations: [{ name: 'read_file', parametersJsonSchema: { required: ['file_path'], properties: { file_path: { type: 'string' } } } }] }] };
  assert.equal(declaredFixtureCall('gemini', gemini, read, 'c').arguments.file_path, '/task/probe.txt');
  const skillFallback = { kind: 'skill', names: ['activate_skill'], arguments: { name: 'ud-validate' }, fallbackFile: '/task/.gemini/skills/ud-validate/SKILL.md' };
  assert.equal(declaredFixtureCall('gemini', gemini, skillFallback, 'c').arguments.file_path, skillFallback.fallbackFile);
  const shell = { tools: [{ type: 'function', name: 'exec_command', parameters: { required: ['cmd'], properties: { cmd: { type: 'string' } } } }] };
  assert.equal(declaredFixtureCall('responses', shell, read, 'c').arguments.cmd, "cat '/task/probe.txt'");
  const custom = { tools: [{ type: 'custom', name: 'read_file' }] };
  assert.throws(() => declaredFixtureCall('responses', custom, { kind: 'read', names: ['read_file'], file: '/x' }, 'c'), /READ_SCHEMA_UNAVAILABLE/);
  const unknown = { tools: [{ type: 'function', name: 'exec_command', parameters: { required: ['cmd', 'unknown'], properties: { cmd: {} } } }] };
  assert.throws(() => declaredFixtureCall('responses', unknown, read, 'c'), /REQUIRED_ARGUMENT_UNAVAILABLE/);
  assert.throws(() => declaredFixtureCall('chat', {}, read, 'c'), /DECLARED_TOOL_UNAVAILABLE/);
});
test('skill-body proof follows the next request and tolerates native read line numbers only', () => {
  const body = '# Validate\nUse authoritative results.';
  assert.equal(observedSkillBody('claude-code', [{ body: {} }, { body: { messages: [{ role: 'user', content: [{ type: 'tool_result', content: body }] }] } }], body), true);
  assert.equal(observedSkillBody('hermes-agent', [{ body: {} }, { body: { messages: [{ role: 'tool', content: JSON.stringify({ output: '1|# Validate\n2|Use authoritative results.' }) }] } }], body), true);
  assert.equal(observedSkillBody('codex-cli', [{ body: { input: body } }], body), false, 'startup metadata cannot establish activation');
  assert.equal(observedSkillBody('gemini-cli', [{ body: {} }, { body: { contents: [{ parts: [{ functionResponse: { response: { output: body.replace('authoritative', 'guessed') } } }] }] } }], body), false);
});
