import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

function python(body) {
  const code = `import importlib.util,json,sys,copy,types\ndef load(name,file):\n spec=importlib.util.spec_from_file_location(name,file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module\nm=load('messages_protocol',sys.argv[1])\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, path.resolve('evals/local/messages_protocol.py'), path.resolve('evals/local/translation.py'), path.resolve('evals/local/mlx_server.py')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('only exact keep-all no-op edits pass and preserve every message without loading provider libraries', () => {
  const result = python(`
body={'messages':[{'role':'user','content':'original é\\n'}],'context_management':{'edits':[{'type':'clear_thinking_20251015','keep':'all'}]}}
original=copy.deepcopy(body);projected,proof=m.normalize_messages_request(body)
errors=[]
for edit in ({'edits':[{'type':'clear_thinking_20251015'}]},{'edits':[{'type':'clear_thinking_20251015','keep':{'type':'thinking_turns','value':1}}]},{'edits':[{'type':'clear_tool_uses_20250919','keep':'all'}]},{'edits':[{'type':'clear_thinking_20251015','keep':'all','trigger':1}]}):
 try:m.normalize_messages_request({**body,'context_management':edit});errors.append('accepted')
 except ValueError as error:errors.append(str(error))
print(json.dumps({'unchanged':body==original,'projected':projected,'proof':proof,'errors':errors,'heavy':[name for name in ('mlx','mlx_vlm','torch','litellm','transformers') if name in sys.modules]}))`);
  assert.equal(result.unchanged, true);
  assert.equal(result.projected.messages[0].content, 'original é\n');
  assert.equal(result.projected.context_management, undefined);
  assert.equal(result.proof.context_edit, 'keep-all-noop');
  assert.ok(result.errors.every(row => row === 'MESSAGES_CONTEXT_EDIT_UNSUPPORTED'));
  assert.deepEqual(result.heavy, []);
});

test('deferred tools stay hidden until a real result reference activates their exact declared schema', () => {
  const result = python(`
tools=[{'name':'ToolSearch','input_schema':{'type':'object','properties':{'query':{'type':'string'}}}},{'name':'read','input_schema':{'type':'object','properties':{'path':{'type':'string'}},'required':['path']},'defer_loading':True},{'name':'write','input_schema':{'type':'object'},'defer_loading':True}]
first={'messages':[{'role':'user','content':'Inspect the file.'}],'tools':tools}
initial,initial_proof=m.normalize_messages_request(first)
raw='  result é\\n'
body={**first,'messages':first['messages']+[{'role':'assistant','content':[{'type':'tool_use','id':'search-1','name':'ToolSearch','input':{'query':'read'}}]},{'role':'user','content':[{'type':'tool_result','tool_use_id':'search-1','content':[{'type':'text','text':raw},{'type':'tool_reference','tool_name':'read'}]}]}]}
original=copy.deepcopy(body);projected,proof=m.normalize_messages_request(body)
translation=load('translation',sys.argv[2]);validated=translation.validate_messages(body)
print(json.dumps({'initial':initial,'initial_proof':initial_proof,'projected':projected,'proof':proof,'unchanged':body==original,'parity':validated==projected,'raw':raw,'schema':tools[1]['input_schema']}))`);
  assert.deepEqual(result.initial.tools.map(tool => tool.name), ['ToolSearch']);
  assert.deepEqual(result.projected.tools.map(tool => tool.name), ['ToolSearch', 'read']);
  assert.deepEqual(result.projected.tools[1].input_schema, result.schema);
  assert.equal(result.projected.tools[1].defer_loading, undefined);
  assert.equal(result.projected.messages.at(-1).content[0].content, result.raw + '\n{"type":"tool_reference","tool_name":"read"}');
  assert.deepEqual(result.proof.activated_references, [{ tool_use_id: 'search-1', tool_name: 'read' }]);
  assert.deepEqual(result.proof.deferred_tool_names, ['write']);
  assert.equal(result.proof.search_or_tool_selection, false);
  assert.equal(result.proof.argument_repair, false);
  assert.equal(result.unchanged, true);
  assert.equal(result.parity, true);
});

test('references, callers, forced choices and malformed histories fail closed without synthetic discovery', () => {
  const result = python(`
tool={'name':'read','input_schema':{'type':'object'},'defer_loading':True}
call={'role':'assistant','content':[{'type':'tool_use','id':'search-1','name':'ToolSearch','input':{}}]}
reference={'role':'user','content':[{'type':'tool_result','tool_use_id':'search-1','content':[{'type':'tool_reference','tool_name':'missing'}]}]}
cases=[{'messages':[call,reference],'tools':[tool]}, {'messages':[reference],'tools':[tool]}, {'messages':[{'role':'user','content':[{'type':'tool_reference','tool_name':'read'}]}],'tools':[tool]}, {'messages':[],'tools':[{**tool,'defer_loading':'true'}]}, {'messages':[],'tools':[tool,tool]}, {'messages':[],'tools':[tool],'tool_choice':{'type':'tool','name':'read'}}, {'messages':[],'tools':[{**tool,'allowed_callers':['code_execution_20260120']}]}, {'messages':[{'role':'assistant','content':[{'type':'tool_use','id':'a','name':'read','input':{}}]}],'tools':[tool]}, {'messages':[{'role':'assistant','content':[{'type':'tool_use','id':'a','name':'ToolSearch','input':[]}]}],'tools':[]}, {'messages':[],'tools':{}}]
errors=[]
for body in cases:
 try:m.normalize_messages_request(body);errors.append('accepted')
 except ValueError as error:errors.append(str(error))
print(json.dumps(errors))`);
  assert.deepEqual(result, ['MESSAGES_TOOL_REFERENCE_UNDECLARED', 'ORPHAN_TOOL_RESULT_UNSUPPORTED', 'MESSAGES_TOOL_REFERENCE_OUTSIDE_RESULT', 'MESSAGES_DEFER_LOADING_INVALID', 'MESSAGES_TOOL_NAME_DUPLICATE', 'MESSAGES_TOOL_CHOICE_UNLOADED', 'MESSAGES_TOOL_CALLER_UNSUPPORTED', 'MESSAGES_TOOL_HISTORY_UNLOADED', 'TOOL_HISTORY_INVALID', 'MESSAGES_TOOL_TYPE_UNSUPPORTED']);
});

test('native MLX and LiteLLM entrypoints apply the same projection to token counting and generation inputs', () => {
  const result = python(`
import tempfile,pathlib,hashlib
mlx=load('mlx_adapter',sys.argv[3])
errors=[]
for version in ('0.7.12','0.7.11'):
 try:mlx.patch_messages_module(mlx,version)
 except RuntimeError as error:errors.append(str(error))
source='''def _anthropic_messages_to_internal(request):
 return request.model_dump(mode="python",exclude_none=True)
'''
class Request:
 def __init__(self,body):self.body=body
 def model_dump(self,**kwargs):return copy.deepcopy(self.body)
 @classmethod
 def model_validate(cls,body):return cls(body)
with tempfile.TemporaryDirectory() as temporary:
 file=pathlib.Path(temporary)/'native.py';file.write_text(source);native=load('fake_native_messages',file)
 mlx.EXPECTED_MESSAGES=hashlib.sha256(file.read_bytes()).hexdigest();proof=mlx.patch_messages_module(native,'0.7.11')
 body={'messages':[{'role':'user','content':'hello'}],'tools':[{'name':'hidden','input_schema':{},'defer_loading':True}],'context_management':{'edits':[{'type':'clear_thinking_20251015','keep':'all'}]}}
 native_input=native._anthropic_messages_to_internal(Request(body));translation=load('translation',sys.argv[2]);translated_input=translation.validate_messages(body)
 print(json.dumps({'native':native_input,'translated':translated_input,'proof':proof,'errors':errors,'source_unchanged':hashlib.sha256(file.read_bytes()).hexdigest()==mlx.EXPECTED_MESSAGES}))`);
  assert.deepEqual(result.native, result.translated);
  assert.deepEqual(result.native.tools, []);
  assert.equal(result.proof.installed_files_changed, false);
  assert.equal(result.proof.semantic_argument_repairs, false);
  assert.equal(result.source_unchanged, true);
  assert.deepEqual(result.errors, ['MLX_MESSAGES_PATCH_VERSION_UNVERIFIED', 'MLX_MESSAGES_PATCH_SOURCE_UNVERIFIED']);
});

test('harness system turns and disabled-thinking metadata follow native MLX semantics through translation', () => {
  const result = python(`
translation=load('translation',sys.argv[2])
seen=[]
class Adapter:
 def translate_completion_input_params_with_tool_mapping(self,body,**kwargs):
  seen.append(copy.deepcopy(body));return {'messages':body['messages'],'tools':[],'max_tokens':512,'user':'transport-user','prompt_cache_key':'transport-key','reasoning_effort':'none'},{}
body={'messages':[{'role':'system','content':'leading'},{'role':'user','content':'intent'},{'role':'system','content':[{'type':'text','text':'environment'}]}],'system':'existing','thinking':{'type':'adaptive','display':'updates'},'enable_thinking':False,'context_management':{'edits':[{'type':'clear_thinking_20251015','keep':'all'}]},'metadata':{'user_id':'transport-user'}}
original=copy.deepcopy(body);out=translation.to_chat('messages',body,'/exact',(None,None,None,Adapter))
class Unsupported(Adapter):
 def translate_completion_input_params_with_tool_mapping(self,body,**kwargs):return {'messages':body['messages'],'reasoning_effort':'high'},{}
try:translation.to_chat('messages',body,'/exact',(None,None,None,Unsupported));bad='accepted'
except ValueError as error:bad=str(error)
print(json.dumps({'seen':seen[0],'out':out,'unchanged':body==original,'bad':bad}))`);
  assert.equal(result.seen.system, 'existing\nleading');
  assert.deepEqual(result.seen.messages.map(row => row.role), ['user', 'user']);
  assert.equal(result.seen.messages[1].content[0].text, 'environment');
  assert.deepEqual(result.seen.thinking, { type: 'disabled' });
  assert.equal(result.out.reasoning_effort, undefined);
  assert.equal(result.out.user, undefined);
  assert.equal(result.out.prompt_cache_key, undefined);
  assert.equal(result.out.max_tokens, 512);
  assert.equal(result.out.stream, false);
  assert.equal(result.unchanged, true);
  assert.equal(result.bad, 'THINKING_DISABLED');
});
