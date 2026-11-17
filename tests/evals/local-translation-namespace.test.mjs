import { posixTest } from '../fixtures/native-scope.mjs';
// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { createBudgetAuthority } from '../../evals/local/budget.mjs';
import { createGateway } from '../../evals/local/gateway.mjs';
import { needsResponsesTranslation, responsesDeclarations, validateResponsesNamespaces, validateResponsesOutput } from '../../evals/local/responses-namespace.mjs';
import { declaredFixtureCall, nativeFixtureFrames } from '../../evals/local/native-conformance.mjs';
import { responseNativeCalls } from '../../evals/local/native-observations.mjs';

const unsupported = [
  { type: 'namespace', name: 'outer', tools: [{ type: 'namespace', name: 'inner', tools: [{ type: 'function', name: 'spawn_agent', parameters: { type: 'object' } }] }] },
  { type: 'web_search' },
];

test('nested Responses namespaces and hosted search are rejected before a translation library can drop them', () => {
  const code = `import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('translation',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
errors=[]
for tool in json.loads(sys.argv[2]):
 try: module.encode_namespace_responses({'input':'Read the report.','tools':[tool]}); errors.append('accepted')
 except ValueError as error: errors.append(str(error))
print(json.dumps({'errors':errors,'libraries_loaded':[name for name in ('litellm','mlx','torch','transformers') if name in sys.modules]}))`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, path.resolve('evals/local/translation.py'), JSON.stringify(unsupported)], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { errors: ['SERVER_TOOL_TYPE_UNSUPPORTED', 'SERVER_TOOL_TYPE_UNSUPPORTED'], libraries_loaded: [] });
});

function python(code, value) {
  const result = spawnSync('python3', ['-I', '-B', '-c', `import importlib.util,json,sys,copy,types\nspec=importlib.util.spec_from_file_location('translation',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\nvalue=json.loads(sys.argv[2])\n${code}`, path.resolve('evals/local/translation.py'), JSON.stringify(value)], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
const fn = (name, extra = {}) => ({ type: 'function', name, description: 'Exact é description.', parameters: { anyOf: [{ type: 'object', properties: { x: { type: 'string' } }, required: ['x'] }, { type: 'object', properties: { y: { type: 'integer' } } }], 'x-private-schema': { example: '東京' } }, strict: false, ...extra });
const ns = (name, members, extra = {}) => ({ type: 'namespace', name, description: 'Namespace instructions.', tools: members, ...extra });

test('literal qualified aliases are reversible across same-name members, flat names, call IDs and exact argument bytes', () => {
  const args = '{ "x" : "é\\n東京" }';
  const body = { model: 'local', input: [
    { type: 'function_call', id: 'native-item-a', call_id: 'call-a', namespace: 'first', name: 'read', arguments: args },
    { type: 'function_call_output', call_id: 'call-a', output: 'verbatim result\n' },
  ], tools: [fn('read'), ns('first', [fn('read')]), ns('second', [fn('read')])], tool_choice: { type: 'function', namespace: 'second', name: 'read' } };
  assert.equal(needsResponsesTranslation(body), true);
  const declarations = validateResponsesNamespaces(body);
  assert.deepEqual(declarations.map(tool => [tool.namespace ?? null, tool.name]), [[null, 'read'], ['first', 'read'], ['second', 'read']]);
  const result = python(`
original=copy.deepcopy(value);encoded,ledger=m.encode_namespace_responses(value);m.validate_responses(encoded)
raw=value['input'][0]['arguments']
response={'status':'completed','output':[{'type':'function_call','id':'fc-'+str(i),'call_id':'backend-'+str(i),'name':alias,'arguments':raw} for i,alias in enumerate(ledger)]}
decoded=m.decode_namespace_calls(response,ledger)
print(json.dumps({'unchanged':original==value,'encoded':encoded,'decoded':decoded,'events':m.stream_events('responses',decoded),'selected':m.needs_responses_translation(value)}))`, body);
  assert.equal(result.unchanged, true); assert.equal(result.selected, true);
  assert.deepEqual(result.encoded.tools.map(tool => tool.name), ['read', 'first__read', 'second__read']);
  for (const tool of result.encoded.tools) assert.deepEqual(tool.parameters, body.tools[0].parameters);
  assert.equal(result.encoded.tools[1].description, 'Namespace instructions.\n\nExact é description.');
  const { namespace: _namespace, ...originalCall } = body.input[0];
  assert.deepEqual(result.encoded.input[0], { ...originalCall, name: 'first__read' });
  assert.deepEqual(result.encoded.input[1], body.input[1]);
  assert.deepEqual(result.encoded.tool_choice, { type: 'function', name: 'second__read' });
  assert.deepEqual(result.decoded.output.map(item => [item.call_id, item.namespace ?? null, item.name, item.arguments]), [
    ['backend-0', null, 'read', args], ['backend-1', 'first', 'read', args], ['backend-2', 'second', 'read', args],
  ]);
  validateResponsesOutput(body, result.decoded);
  assert.deepEqual(result.events.filter(row => row.type === 'response.output_item.done').map(row => row.item), result.decoded.output);
});

test('JS and Python reject alias collisions, unknown fields, nested/hosted members and unbound namespace history', () => {
  const invalid = [
    { tools: [fn('first__read'), ns('first', [fn('read')])] },
    { tools: [ns('a__b', [fn('c')]), ns('a', [fn('b__c')])] },
    { tools: [ns('a', [fn('read'), fn('read')])] },
    { tools: [ns('a', [fn('read')]), ns('a', [fn('other')])] },
    { tools: [ns('a', [fn('read')], { permission: 'unknown' })] },
    { tools: [ns('a', [fn('read', { unknown_schema_control: true })])] },
    { tools: [ns('a', [{ type: 'web_search' }])] },
    { tools: [ns('a', [ns('b', [fn('read')])])] },
    { tools: [ns('a'.repeat(64), [fn('read')])] },
    { tools: [ns('a', [fn('read')])], input: [{ type: 'function_call', call_id: 'x', name: 'read', namespace: 'b', arguments: '{}' }] },
    { tools: [ns('a', [fn('read')])], input: [{ type: 'function_call', call_id: 'x', name: 'read', arguments: '{}' }] },
    { tools: [ns('a', [fn('read')])], tool_choice: { type: 'function', namespace: 'b', name: 'read' } },
  ];
  const errors = invalid.map(body => { try { validateResponsesNamespaces(body); return 'accepted'; } catch (error) { return error.code; } });
  assert.ok(errors.every(code => code !== 'accepted'));
  assert.deepEqual(python(`
errors=[]
for body in value:
 try:m.encode_namespace_responses(body);errors.append('accepted')
 except ValueError as error:errors.append(str(error))
print(json.dumps(errors))`, invalid), errors);
});

test('namespaced custom grammar codec keeps raw input and rejects undeclared backend aliases without bare-name guessing', () => {
  const body = { input: [{ type: 'custom_tool_call', id: 'custom-item', call_id: 'custom-call', namespace: 'editor', name: 'patch', input: 'é\n*** End\n' }, { type: 'custom_tool_call_output', call_id: 'custom-call', output: 'done' }], tools: [ns('editor', [{ type: 'custom', name: 'patch', format: { type: 'grammar', syntax: 'lark', definition: 'start: "é"' } }])] };
  const result = python(`
m.grammar_matcher=lambda specification:None
encoded,ledger=m.encode_namespace_responses(value);encoded,custom=m.encode_custom_responses(encoded);m.validate_responses(encoded)
native={'output':[{'type':'function_call','id':'fc-custom','call_id':'custom-call','name':'editor__patch','arguments':encoded['input'][0]['arguments']}]}
decoded=m.decode_namespace_calls(m.decode_custom_calls(native,custom),ledger)
errors=[]
for name in ('patch','other__patch','editor__unknown'):
 try:m.decode_namespace_calls({'output':[{'type':'custom_tool_call','call_id':'x','name':name,'input':'raw'}]},ledger);errors.append('accepted')
 except ValueError as error:errors.append(str(error))
print(json.dumps({'encoded':encoded,'decoded':decoded,'errors':errors}))`, body);
  assert.equal(result.encoded.tools[0].name, 'editor__patch');
  assert.ok(result.encoded.tools[0].parameters.properties.input.description.includes('start: "é"'));
  assert.equal(result.decoded.output[0].input, body.input[0].input);
  assert.equal(result.decoded.output[0].namespace, 'editor'); assert.equal(result.decoded.output[0].name, 'patch');
  assert.equal(result.decoded.output[0].call_id, 'custom-call');
  validateResponsesOutput(body, result.decoded);
  validateResponsesOutput({ tools: [...body.tools, { type: 'custom', name: 'flat' }] }, { output: [{ type: 'custom_tool_call', name: 'flat', call_id: 'flat-call', input: 'unchanged' }] });
  assert.ok(result.errors.every(reason => reason === 'RESPONSES_NAMESPACE_IDENTITY_INVALID'));
});

test('namespace fixture and native observations retain declared namespace and original call identity', () => {
  const request = { tools: [fn('read'), ns('mcp__ud', [fn('check_ud_environment', { parameters: { type: 'object', properties: {} } })])] };
  const call = declaredFixtureCall('responses', request, { kind: 'operation', names: ['check_ud_environment'], arguments: {} }, 'exact-call');
  assert.deepEqual(call, { id: 'exact-call', name: 'check_ud_environment', namespace: 'mcp__ud', arguments: {} });
  const fixture = nativeFixtureFrames('responses', 'model', call);
  assert.equal(fixture.body.output[0].namespace, 'mcp__ud');
  assert.ok(fixture.frames.filter(frame => frame.data.item).every(frame => frame.data.item.namespace === 'mcp__ud'));
  assert.deepEqual(responseNativeCalls('responses', fixture.body), [call]);
  assert.throws(() => validateResponsesOutput(request, { output: [{ type: 'function_call', name: 'check_ud_environment', arguments: '{}', call_id: 'wrong' }] }), /RESPONSES_NAMESPACE_IDENTITY_INVALID/);
  assert.equal(responsesDeclarations(request)[1].namespace, 'mcp__ud');
});

test('exact schema and call bytes survive request conversion; publisher call mutations fail instead of being repaired', () => {
  const body = { tools: [ns('a', [fn('read')])], input: [{ type: 'function_call', call_id: 'id', namespace: 'a', name: 'read', arguments: '{ "x" : "é" }' }, { type: 'function_call_output', call_id: 'id', output: 'ok' }] };
  const result = python(`
encoded,_=m.encode_namespace_responses(value)
expected=encoded['input'][0]
chat={'tools':[{'type':'function','function':{'name':'a__read','parameters':{'type':'object'}}}],'messages':[{'role':'assistant','tool_calls':[{'id':'id','type':'function','function':{'name':'a__read','arguments':expected['arguments']}}]}]}
m.preserve_responses_payload(chat,encoded)
errors=[]
for field in ('id','name','arguments'):
 bad=copy.deepcopy(chat);call=bad['messages'][0]['tool_calls'][0]
 if field=='id':call[field]='changed'
 else:call['function'][field]='changed'
 try:m.preserve_responses_payload(bad,encoded);errors.append('accepted')
 except ValueError as error:errors.append(str(error))
print(json.dumps({'chat':chat,'errors':errors}))`, body);
  assert.deepEqual(result.chat.tools[0].function.parameters, body.tools[0].tools[0].parameters);
  assert.equal(result.chat.messages[0].tool_calls[0].function.arguments, body.input[0].arguments);
  assert.ok(result.errors.every(code => code === 'RESPONSES_LIBRARY_TOOL_HISTORY_CHANGED'));
});

posixTest.each(['valid', 'missing', 'stream-mismatch'])('gateway preserves raw namespace request and admits only the original declared output identity (%s)', async variant => {
  const valid = variant === 'valid';
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-namespace-gateway-')));
  const body = { model: 'inert-local-model', input: 'Inspect the environment.', tools: [ns('mcp__ud', [fn('check_ud_environment')])] };
  const records = []; let received, counted;
  const reply = { status: 'completed', output: [{ type: 'function_call', call_id: 'exact-call', name: 'check_ud_environment', ...(variant !== 'missing' ? { namespace: 'mcp__ud' } : {}), arguments: '{ "x": "é" }' }], usage: { input_tokens: 1, output_tokens: 1 } };
  const frames = [{ type: 'response.output_item.added', output_index: 0, item: { ...reply.output[0], namespace: 'wrong', arguments: '' } }, { type: 'response.completed', response: reply }];
  const upstream = http.createServer(async (request, response) => {
    const chunks = []; for await (const part of request) chunks.push(part);
    received = JSON.parse(Buffer.concat(chunks));
    response.setHeader('content-type', variant === 'stream-mismatch' ? 'text/event-stream' : 'application/json');
    response.end(variant === 'stream-mismatch' ? frames.map(frame => 'data: ' + JSON.stringify(frame) + '\n\n').join('') : JSON.stringify(reply));
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const budget = await createBudgetAuthority({ directory });
  const gateway = await createGateway({ upstream: `http://127.0.0.1:${upstream.address().port}`, model: body.model, budget, record: event => records.push(event), tokenize: async value => { counted = value.body; return { trusted: true, inputTokens: 1 }; } });
  try {
    const response = await fetch(gateway.url + '/v1/responses', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal(response.status, valid ? 200 : 422);
    assert.deepEqual(received.tools, body.tools); assert.deepEqual(counted.tools, body.tools);
    assert.deepEqual(records.find(row => row.type === 'provider_received').body, body);
    assert.deepEqual(records.find(row => row.type === 'provider_response').body, variant === 'stream-mismatch' ? frames : reply);
    if (valid) {
      assert.deepEqual(await response.json(), reply);
      assert.deepEqual(records.find(row => row.type === 'native_calls_admitted').calls, [{ id: 'exact-call', name: 'check_ud_environment', namespace: 'mcp__ud', arguments: { x: 'é' } }]);
    } else {
      assert.match(await response.text(), variant === 'stream-mismatch' ? /STREAM_TOOL_IDENTITY_MISMATCH/ : /RESPONSES_NAMESPACE_IDENTITY_INVALID/);
      assert.equal(records.some(row => row.type === 'model_visible_response'), false);
    }
  } finally {
    await gateway.close(); await budget.close(); upstream.closeAllConnections();
    await new Promise(resolve => upstream.close(resolve)); await rm(directory, { recursive: true, force: true });
  }
});

test('token-count and generation conversion share a deterministic encoded request; output mutation remains a failure', () => {
  const body = { model: 'model', input: 'Read.', tools: [ns('one', [fn('read')])], enable_thinking: false, seed: 23 };
  const result = python(`
class Responses:
 @staticmethod
 def transform_responses_api_request_to_chat_completion_request(**kwargs):
  return {'tools':[{'type':'function','function':{'name':tool['name']}} for tool in kwargs['responses_api_request']['tools']],'messages':[{'role':'user','content':kwargs['input']}]}
 @staticmethod
 def transform_chat_completion_response_to_responses_api_response(**kwargs):
  call=kwargs['chat_completion_response']['choices'][0]['message']['tool_calls'][0]
  return types.SimpleNamespace(model_dump=lambda **unused:{'status':'completed','output':[{'type':'function_call','call_id':call['id'],'name':call['function']['name'],'arguments':call['function']['arguments']}]})
adapters=(Responses,None,None)
counted=m.to_chat('responses',value,'wire',adapters);generated=m.to_chat('responses',value,'wire',adapters)
backend={'model':'wire','choices':[{'message':{'tool_calls':[{'id':'original-call','type':'function','function':{'name':'one__read','arguments':'{ "x": "é" }'}}]}}],'usage':{'prompt_tokens':1,'completion_tokens':1}}
native=m.from_chat('responses',value,backend,'wire',adapters)
class Mutating(Responses):
 @staticmethod
 def transform_chat_completion_response_to_responses_api_response(**kwargs):
  return types.SimpleNamespace(model_dump=lambda **unused:{'output':[{'type':'function_call','call_id':'changed','name':'one__read','arguments':'{}'}]})
try:m.from_chat('responses',value,backend,'wire',(Mutating,None,None));error='accepted'
except ValueError as failure:error=str(failure)
print(json.dumps({'same':counted==generated,'counted':counted,'native':native,'error':error}))`, body);
  assert.equal(result.same, true); assert.equal(result.counted.tools[0].function.name, 'one__read');
  assert.deepEqual(result.counted.tools[0].function.parameters, body.tools[0].tools[0].parameters);
  assert.equal(result.counted.seed, 23); assert.equal(result.counted.enable_thinking, false);
  assert.deepEqual(result.native.output[0], { type: 'function_call', call_id: 'original-call', name: 'read', namespace: 'one', arguments: '{ "x": "é" }' });
  assert.equal(result.error, 'RESPONSES_LIBRARY_TOOL_OUTPUT_CHANGED');
});

posixTest.each(unsupported)('native Responses never receives silently omitted $type declarations, even with custom translation enabled', async tool => {
  // Pinned MLX-VLM 0.7.11's _response_tool_registry skips these tool types.
  // An otherwise valid successful reply must never turn that omission into a pass.
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-unsupported-responses-')));
  let received = 0, tokenized = 0;
  const upstream = http.createServer(async (request, response) => {
    for await (const _part of request) { /* Consume the request if the guard fails. */ }
    received++;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'Complete.' }] }], usage: { input_tokens: 1, output_tokens: 1 } }));
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const budget = await createBudgetAuthority({ directory });
  const gateway = await createGateway({ upstream: `http://127.0.0.1:${upstream.address().port}`, model: 'inert-local-model', budget,
    customResponses: true, tokenize: async () => { tokenized++; return { trusted: true, inputTokens: 1 }; } });
  try {
    const response = await fetch(gateway.url + '/v1/responses', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'inert-local-model', input: 'Read the report.', tools: [tool] }) });
    assert.equal(response.status, 422);
    assert.match(await response.text(), /SERVER_TOOL_TYPE_UNSUPPORTED/);
    assert.equal(tokenized, 0);
    assert.equal(received, 0);
    assert.equal(budget.snapshot().counters.inference, 0);
  } finally {
    await gateway.close(); await budget.close();
    upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
