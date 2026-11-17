import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const source = path.resolve('evals/local/runtime.py');
function python(body) {
  const code = `import importlib.util,json,sys,types,copy\nspec=importlib.util.spec_from_file_location("eval_runtime",sys.argv[1])\nm=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('token-accounting module imports without runtime dependencies or model work', () => {
  assert.deepEqual(python('print(json.dumps([name for name in ("mlx","mlx_vlm","torch","transformers") if name in sys.modules]))'), []);
});

test('text accounting fails closed before native malformed-argument repair or multimodal assumptions', () => {
  const results = python(`
valid={"messages":[{"role":"user","content":"please edit"},{"role":"assistant","content":None,"tool_calls":[{"type":"function","function":{"name":"edit","arguments":"{\\"file\\":\\"tree.conllu\\"}"}}]}]}
unchanged=copy.deepcopy(valid); m.validate_text_chat(valid)
invalids=[{"input":[]},{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/image.png"}}]}]},{**valid,"enable_thinking":True},{**valid,"context_management":[{}]}]
for arguments in ('{broken','[]','null'):
 candidate=copy.deepcopy(valid); candidate['messages'][1]['tool_calls'][0]['function']['arguments']=arguments; invalids.append(candidate)
errors=[]
for candidate in invalids:
 try: m.validate_text_chat(candidate); errors.append('accepted')
 except RuntimeError as error: errors.append(str(error))
print(json.dumps({"unchanged":valid==unchanged,"errors":errors}))`);
  assert.equal(results.unchanged, true);
  assert.deepEqual(results.errors, ['PROTOCOL_TOKEN_ACCOUNTING_UNSUPPORTED', 'INLINE_IMAGE_REQUIRED', 'TOKEN_ACCOUNTING_POLICY_UNSUPPORTED', 'TOKEN_ACCOUNTING_POLICY_UNSUPPORTED', 'TOOL_ARGUMENT_TOKEN_ACCOUNTING_UNSUPPORTED', 'TOOL_ARGUMENT_TOKEN_ACCOUNTING_UNSUPPORTED', 'TOOL_ARGUMENT_TOKEN_ACCOUNTING_UNSUPPORTED']);
});

test('image accounting accepts only bounded inline native image inputs and leaves their bytes intact', () => {
  const result = python(`
body={'messages':[{'role':'user','content':[{'type':'text','text':'inspect'},{'type':'image_url','image_url':{'url':'data:image/png;base64,AA=='}}]}]}
original=copy.deepcopy(body); m.validate_text_chat(body)
errors=[]
for content in ([{'type':'input_audio','input_audio':{}}],[{'type':'image_url','image_url':{'url':'data:image/png;base64,%%%%'}}],[{'type':'image_url','image_url':{'url':'file:///private/image.png'}}]):
 try: m.validate_text_chat({'messages':[{'role':'user','content':content}]}); errors.append('accepted')
 except RuntimeError as error: errors.append(str(error))
print(json.dumps({'unchanged':body==original,'errors':errors}))`);
  assert.equal(result.unchanged, true);
  assert.deepEqual(result.errors, ['PROCESSOR_TOKEN_ACCOUNTING_UNSUPPORTED', 'INLINE_IMAGE_INVALID', 'INLINE_IMAGE_REQUIRED']);
});

test('accounting delegates to native normalization, formatter and CPU preprocessing without offsets or model construction', () => {
  const results = python(`
calls=[]
def module(name,**attributes):
 selected=types.ModuleType(name)
 for key,value in attributes.items(): setattr(selected,key,value)
 sys.modules[name]=selected
 return selected
module('mlx'); core=module('mlx.core',cpu='cpu',set_default_device=lambda value:calls.append(['device',value])); sys.modules['mlx'].core=core
for name in ('mlx_vlm','mlx_vlm.tools','mlx_vlm.server'): module(name)
def forbidden(*args,**kwargs): raise AssertionError('Model weights or generation must never be invoked')
class Config:
 @classmethod
 def from_dict(cls,config): calls.append(['configuration_only']); return types.SimpleNamespace(**config)
architecture=types.SimpleNamespace(ModelConfig=Config,Model=forbidden)
processor=types.SimpleNamespace()
def register(config,**kwargs): calls.append(['register']); return architecture,config['model_type']
def load_processor(*args,**kwargs): calls.append(['processor',kwargs]); return processor
module('mlx_vlm.utils',load_config=lambda path:{'model_type':'prism_hadamard_qwen35'},get_model_and_args=register,load_processor=load_processor,update_module_configs=lambda config,*args:config,apply_generation_config_defaults=lambda config,*args:config,load=forbidden,load_model=forbidden)
class Message:
 def __init__(self,value): self.value=value
 def model_dump(self,**kwargs): return copy.deepcopy(self.value)
class Request:
 @classmethod
 def model_validate(cls,body):
  calls.append(['request',body['enable_thinking'],body['context_management']])
  return types.SimpleNamespace(**{**body,'messages':[Message(value) for value in body['messages']],'tools':body.get('tools'),'tool_choice':body.get('tool_choice')})
module('mlx_vlm.server.schemas',ChatRequest=Request)
def transient(messages,request): return messages+[{'role':'user','content':'native transient suffix'}]
module('mlx_vlm.server.compaction',with_transient_context=transient)
def normalize(message):
 for call in message.get('tool_calls',[]):
  if isinstance(call['function'].get('arguments'),str): call['function']['arguments']=json.loads(call['function']['arguments'])
 return message
def instructions(messages): calls.append(['instruction_normalization'])
module('mlx_vlm.server.request_normalization',_chat_message_to_prompt=normalize,_normalize_instruction_messages=instructions,_build_gen_args=lambda request,processor:types.SimpleNamespace(to_template_kwargs=lambda:{'enable_thinking':False},preprocessing_kwargs=lambda:{}))
module('mlx_vlm.tools.policy',_prepare_chat_tool_choice=lambda messages,tools,choice:(messages,tools,choice))
def formatter(processor,config,messages,**kwargs):
 calls.append(['formatter',messages,kwargs]); return 'the actual native rendered prompt'
module('mlx_vlm.prompt_utils',apply_chat_template=formatter)
class Generator:
 def __init__(self,*args,**kwargs): forbidden()
 def _cpu_preprocess(self,prompt,**kwargs):
  calls.append(['preprocess',prompt,self.model.config.model_type]); return {'input_ids':types.SimpleNamespace(size=native_count)}
module('mlx_vlm.server.generation',ResponseGenerator=Generator,_count_prompt_tokens=lambda inputs:inputs['input_ids'].size)
m.importlib.metadata.version=lambda name:'0.7.11'
body={'messages':[{'role':'user','content':'please edit'},{'role':'assistant','content':None,'tool_calls':[{'function':{'name':'edit','arguments':'{\\"file\\":\\"tree.conllu\\"}'}}]}],'tool_choice':'auto'}
original=copy.deepcopy(body); outputs=[]
for native_count in (731,9002): outputs.append(m.tokenize_chat(body,'.'))
print(json.dumps({'outputs':outputs,'calls':calls,'unchanged':body==original}))`);
  assert.deepEqual(results.outputs.map(row => row.inputTokens), [731, 9002]);
  assert.equal(results.unchanged, true);
  assert.equal(results.outputs.every(row => row.trusted && row.provenance.device === 'cpu' && row.provenance.model_weights_loaded === false), true);
  assert.equal(results.calls[0][0], 'device');
  assert.ok(results.calls.findIndex(row => row[0] === 'register') < results.calls.findIndex(row => row[0] === 'processor'));
  const rendered = results.calls.find(row => row[0] === 'formatter');
  assert.equal(rendered[1].at(-1).content, 'native transient suffix');
  assert.deepEqual(rendered[1][1].tool_calls[0].function.arguments, { file: 'tree.conllu' });
  assert.equal(rendered[2].enable_thinking, false);
  assert.equal(rendered[2].tool_choice, 'auto');
});

test('unknown native-runtime versions cannot certify token counts', () => {
  assert.equal(python(`
m.importlib.metadata.version=lambda name:'0.8.0'
try: m.tokenize_chat({'messages':[{'role':'user','content':'hello'}]},'.'); outcome='accepted'
except RuntimeError as error: outcome=str(error)
print(json.dumps(outcome))`), 'TOKEN_ACCOUNTING_RUNTIME_UNVERIFIED');
});
