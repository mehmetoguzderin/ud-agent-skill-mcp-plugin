import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

function python(body) {
  const code = `import importlib.util,json,sys,types,copy\nspec=importlib.util.spec_from_file_location('translation',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, path.resolve('evals/local/translation.py')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('translation import loads no model, provider library or serving process', () => {
  assert.deepEqual(python(`print(json.dumps([name for name in ('litellm','mlx','torch','transformers') if name in sys.modules]))`), []);
});

test('translation rejects orphan results, non-object arguments, compaction and unsupported tools before the library can repair or drop them', () => {
  const result = python(`
items=[{'input':[{'type':'function_call_output','call_id':'missing','output':'ready'}]}, {'input':[{'type':'function_call','call_id':'a','name':'echo','arguments':'[]'}]}, {'input':'hello','tools':[{'type':'custom','name':'exec'}]}, {'input':'hello','previous_response_id':'saved'}, {'input':'hello','context_management':[{'type':'compaction'}]}, {'input':[{'role':'user','content':[{'type':'input_image','image_url':'https://example.invalid/image.png'}]}]}]
errors=[]
for body in items:
 try: m.validate_responses(body); errors.append('accepted')
 except ValueError as error: errors.append(str(error))
print(json.dumps(errors))`);
  assert.deepEqual(result, ['ORPHAN_TOOL_RESULT_UNSUPPORTED', 'TOOL_ARGUMENTS_INVALID', 'RESPONSES_TOOL_TYPE_UNSUPPORTED', 'STATEFUL_OR_COMPACTED_RESPONSES_UNSUPPORTED', 'STATEFUL_OR_COMPACTED_RESPONSES_UNSUPPORTED', 'INLINE_IMAGE_REQUIRED']);
});

test('Gemini rejects ambiguous parallel identity and foreign media instead of silently losing content', () => {
  const result = python(`
call={'functionCall':{'name':'echo','args':{'value':'ready'}}}
bodies=[{'contents':[{'role':'model','parts':[call,call]}]}, {'contents':[{'role':'user','parts':[{'functionResponse':{'name':'echo','response':{'value':'ready'}}}]}]}, {'contents':[{'role':'user','parts':[{'fileData':{'fileUri':'https://example.invalid/image.png'}}]}]}]
errors=[]
for body in bodies:
 try: m.validate_gemini(body); errors.append('accepted')
 except ValueError as error: errors.append(str(error))
print(json.dumps(errors))`);
  assert.deepEqual(result, ['GEMINI_AMBIGUOUS_PARALLEL_CALL_UNSUPPORTED', 'ORPHAN_TOOL_RESULT_UNSUPPORTED', 'GEMINI_PART_UNSUPPORTED']);
});

test('frozen sampler extensions survive the publisher adapter without another generation or input mutation', () => {
  const result = python(`
seen=[]
class Responses:
 @staticmethod
 def transform_responses_api_request_to_chat_completion_request(**kwargs):
  seen.append(kwargs); return {'model':kwargs['model'],'messages':[{'role':'user','content':'hello'}],'custom_llm_provider':'openai','max_tokens':kwargs['responses_api_request']['max_output_tokens']}
class Gemini:
 def translate_generate_content_to_completion(self,**kwargs):
  seen.append(kwargs); return {'model':kwargs['model'],'messages':[{'role':'user','content':'hello'}],'max_tokens':kwargs['config']['maxOutputTokens']}
adapters=(Responses,Gemini,None)
r={'model':'local','input':'hello','max_output_tokens':128,'seed':47,'top_k':50,'presence_penalty':1.5,'enable_thinking':False}
g={'contents':[{'role':'user','parts':[{'text':'hello'}]}],'generationConfig':{'maxOutputTokens':128,'seed':47,'topK':50,'presence_penalty':1.5,'enable_thinking':False}}
before=copy.deepcopy([r,g]); output=[m.to_chat('responses',r,'wire',adapters),m.to_chat('gemini',g,'wire',adapters)]
print(json.dumps({'unchanged':before==[r,g],'output':output,'calls':len(seen)}))`);
  assert.equal(result.unchanged, true);
  assert.equal(result.calls, 2);
  for (const row of result.output) {
    assert.equal(row.model, 'wire'); assert.equal(row.seed, 47); assert.equal(row.top_k, 50);
    assert.equal(row.presence_penalty, 1.5); assert.equal(row.enable_thinking, false);
    assert.equal(row.max_tokens, 128); assert.equal(row.stream, false); assert.deepEqual(row.context_management, []);
  }
});

test('buffered Responses streaming retains each full tool identity and usage before completion', () => {
  const result = python(`
response={'id':'response-1','status':'completed','model':'wire','output':[{'type':'function_call','id':'fc-1','call_id':'call-1','name':'first','arguments':'{\\"a\\":1}'},{'type':'function_call','id':'fc-2','call_id':'call-2','name':'second','arguments':'{\\"b\\":2}'}],'usage':{'input_tokens':127,'output_tokens':33}}
print(json.dumps(m.stream_events('responses',response)))`);
  assert.deepEqual(result.filter(row => row.type === 'response.output_item.done').map(row => row.item.call_id), ['call-1', 'call-2']);
  assert.deepEqual(result.filter(row => row.type === 'response.function_call_arguments.done').map(row => row.arguments), ['{"a":1}', '{"b":2}']);
  assert.equal(result.at(-1).type, 'response.completed');
  assert.deepEqual(result.at(-1).response.usage, { input_tokens: 127, output_tokens: 33 });
  assert.deepEqual(result.map(row => row.sequence_number), result.map((_, index) => index));
});

test('Messages refuses tool renaming and orphan results while complete streams preserve tool and token evidence', () => {
  const result = python(`
errors=[]
for body in ({'messages':[{'role':'user','content':[{'type':'tool_result','tool_use_id':'missing','content':'ready'}]}]}, {'messages':[{'role':'user','content':'hello'}],'tools':[{'name':'x'*65,'input_schema':{}}]}, {'messages':[{'role':'user','content':'hello'}],'thinking':{'type':'enabled','budget_tokens':1000}}):
 try: m.validate_messages(body); errors.append('accepted')
 except ValueError as error: errors.append(str(error))
response={'id':'message-1','type':'message','role':'assistant','model':'wire','content':[{'type':'tool_use','id':'call-1','name':'echo','input':{'value':'ready'}}],'stop_reason':'tool_use','usage':{'input_tokens':127,'output_tokens':33}}
print(json.dumps({'errors':errors,'events':m.stream_events('messages',response)}))`);
  assert.deepEqual(result.errors, ['ORPHAN_TOOL_RESULT_UNSUPPORTED', 'MESSAGES_TOOL_TYPE_UNSUPPORTED', 'THINKING_OR_COMPACTION_UNSUPPORTED']);
  assert.equal(result.events[0].message.usage.input_tokens, 127);
  assert.equal(result.events[1].content_block.id, 'call-1');
  assert.equal(result.events[2].delta.partial_json, '{"value":"ready"}');
  assert.equal(result.events.at(-2).usage.output_tokens, 33);
  assert.equal(result.events.at(-1).type, 'message_stop');
});

test('translation traffic redacts nested credentials and bearer strings without changing model text otherwise', () => {
  assert.deepEqual(python(`print(json.dumps(m.redact({'api_key':'private','metadata':{'authorization':'Bearer private'},'text':'hello Bearer hidden-token','tool':'ud_validate'})))`), { api_key: '[REDACTED]', metadata: { authorization: '[REDACTED]' }, text: 'hello Bearer [REDACTED]', tool: 'ud_validate' });
});

test('custom tools use a reversible same-name input-string envelope and preserve native grammar and history bytes', () => {
  const result = python(`
grammar='start: "*** Begin Patch\\\\n*** End Patch"'
m.grammar_matcher=lambda specification:None
raw='*** Begin Patch\\n+é\\n*** End Patch\\n'
body={'tools':[{'type':'custom','name':'apply_patch','description':'Native description verbatim.','format':{'type':'grammar','syntax':'lark','definition':grammar}}],'input':[{'type':'custom_tool_call','id':'ctc_a','call_id':'a','name':'apply_patch','input':raw},{'type':'custom_tool_call_output','call_id':'a','output':'committed'}],'tool_choice':{'type':'custom','name':'apply_patch'}}
original=copy.deepcopy(body); encoded,specifications=m.encode_custom_responses(body)
m.validate_responses(encoded)
response={'output':[{'type':'function_call','id':'fc_a','call_id':'a','name':'apply_patch','arguments':json.dumps({'input':raw})}],'status':'completed'}
decoded=m.decode_custom_calls(response,specifications)
events=m.stream_events('responses',decoded)
print(json.dumps({'unchanged':body==original,'encoded':encoded,'decoded':decoded,'events':events,'grammar':grammar,'raw':raw,'custom':m.has_custom_responses(body)}))`);
  assert.equal(result.unchanged, true); assert.equal(result.custom, true);
  const tool = result.encoded.tools[0];
  assert.equal(tool.name, 'apply_patch'); assert.equal(tool.description, 'Native description verbatim.');
  assert.deepEqual(tool.parameters.required, ['input']); assert.equal(tool.parameters.additionalProperties, false);
  assert.ok(tool.parameters.properties.input.description.includes(result.grammar));
  assert.deepEqual(JSON.parse(result.encoded.input[0].arguments), { input: result.raw });
  assert.equal(result.encoded.input[1].type, 'function_call_output'); assert.equal(result.encoded.input[1].call_id, 'a');
  assert.equal(result.decoded.output[0].type, 'custom_tool_call'); assert.equal(result.decoded.output[0].input, result.raw);
  assert.equal(result.events.find(event => event.type === 'response.custom_tool_call_input.done').input, result.raw);
});

test('custom wrappers reject malformed JSON, duplicate fields, extra arguments and non-string input before dispatch', () => {
  const result = python(`
errors=[]
for arguments in ('bad','{}','[]','{"input":3}','{"input":"a","extra":"b"}','{"input":"a","input":"b"}'):
 try: m.decode_custom_calls({'output':[{'type':'function_call','call_id':'a','name':'custom','arguments':arguments}]},{'custom':{'type':'text'}}); errors.append('accepted')
 except ValueError as error: errors.append(str(error))
try: m.encode_custom_responses({'tools':[{'type':'custom','name':'custom','format':{'type':'unknown'}}]}); unknown='accepted'
except ValueError as error: unknown=str(error)
print(json.dumps({'errors':errors,'unknown':unknown}))`);
  assert.ok(result.errors.every(reason => reason === 'CUSTOM_TOOL_ARGUMENTS_INVALID'));
  assert.equal(result.unknown, 'CUSTOM_TOOL_FORMAT_UNSUPPORTED');
});

test('custom grammar validation consumes unchanged UTF-8 bytes and rejects a non-accepting result', () => {
  const result = python(`
consumed=[]
class Matcher:
 def deep_copy(self): return self
 def consume_tokens(self,tokens): consumed.append(tokens); return True
 def is_accepting(self): return False
m.grammar_matcher=lambda specification:Matcher()
try: m.decode_custom_calls({'output':[{'type':'function_call','call_id':'a','name':'custom','arguments':json.dumps({'input':'é\\n'})}]},{'custom':{'type':'grammar','syntax':'lark','definition':'start: "x"'}}); outcome='accepted'
except ValueError as error: outcome=str(error)
print(json.dumps({'outcome':outcome,'consumed':consumed}))`);
  assert.equal(result.outcome, 'CUSTOM_TOOL_GRAMMAR_REJECTED');
  assert.deepEqual(result.consumed, [[195, 169, 10]]);
});

test('Gemini parallel same-name calls preserve distinct IDs through results and complete SSE without repairing payloads', () => {
  const result = python(`
calls=[{'id':'read-a','type':'function','function':{'name':'read_file','arguments':'{"path":"a"}'}},{'id':'read-b','type':'function','function':{'name':'read_file','arguments':'{"path":"b"}'}}]
backend={'model':'wire','choices':[{'message':{'role':'assistant','tool_calls':calls}}],'usage':{'prompt_tokens':10,'completion_tokens':12}}
native={'candidates':[{'content':{'role':'model','parts':[{'functionCall':{'name':'read_file','args':{'path':'a'}}},{'functionCall':{'name':'read_file','args':{'path':'b'}}}]}}]}
m.restore_gemini_response_ids(native,backend)
body={'contents':[native['candidates'][0]['content'],{'role':'user','parts':[{'functionResponse':{'id':'read-b','name':'read_file','response':{'contents':'B'}}},{'functionResponse':{'id':'read-a','name':'read_file','response':{'contents':'A'}}}]}]}
ledger=m.validate_gemini(body)
translated={'messages':[{'role':'assistant','tool_calls':[{**call,'id':'call_read_file'} for call in calls]},{'role':'tool','tool_call_id':'call_read_file','content':'{"contents":"B"}'},{'role':'tool','tool_call_id':'call_read_file','content':'{"contents":"A"}'}]}
m.restore_gemini_request_ids(translated,ledger)
errors=[]
for transform in ('arguments','result'):
 bad=copy.deepcopy(translated)
 if transform=='arguments': bad['messages'][0]['tool_calls'][1]['function']['arguments']='{"path":"WRONG"}'
 else: bad['messages'][2]['content']='{"contents":"WRONG"}'
 try: m.restore_gemini_request_ids(bad,ledger);errors.append('accepted')
 except ValueError as e: errors.append(str(e))
print(json.dumps({'native':native,'messages':translated['messages'],'stream':m.stream_events('gemini',native),'errors':errors}))`);
  assert.deepEqual(result.native.candidates[0].content.parts.map(p => p.functionCall.id), ['read-a','read-b']);
  assert.deepEqual(result.messages[0].tool_calls.map(c => c.id), ['read-a','read-b']);
  assert.deepEqual(result.messages.slice(1).map(c => c.tool_call_id), ['read-b','read-a']);
  assert.deepEqual(result.stream, [result.native]);
  assert.deepEqual(result.errors, ['GEMINI_LIBRARY_TOOL_PAYLOAD_CHANGED','GEMINI_LIBRARY_TOOL_PAYLOAD_CHANGED']);
});

test('Gemini IDs cannot collide or hide ambiguous, duplicate, mismatched or orphan results', () => {
  const result = python(`
a={'functionCall':{'id':'a','name':'read','args':{'path':'a'}}};b={'functionCall':{'id':'b','name':'read','args':{'path':'b'}}}
bodies=[{'contents':[{'role':'model','parts':[a,a]}]},{'contents':[{'role':'model','parts':[a,b]},{'role':'user','parts':[{'functionResponse':{'name':'read','response':{}}}]}]},{'contents':[{'role':'model','parts':[a,b]},{'role':'user','parts':[{'functionResponse':{'id':'b','name':'other','response':{}}}]}]},{'contents':[{'role':'model','parts':[a]},{'role':'user','parts':[{'functionResponse':{'id':'a','name':'read','response':{}}},{'functionResponse':{'id':'a','name':'read','response':{}}}]}]}]
errors=[]
for body in bodies:
 try: m.validate_gemini(body);errors.append('accepted')
 except ValueError as e: errors.append(str(e))
print(json.dumps(errors))`);
  assert.deepEqual(result,['GEMINI_DUPLICATE_CALL_ID','GEMINI_AMBIGUOUS_PARALLEL_CALL_UNSUPPORTED','ORPHAN_TOOL_RESULT_UNSUPPORTED','ORPHAN_TOOL_RESULT_UNSUPPORTED']);
});
