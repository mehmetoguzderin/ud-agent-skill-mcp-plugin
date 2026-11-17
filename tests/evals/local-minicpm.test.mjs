import { posixTest } from '../fixtures/native-scope.mjs';
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

// These tests use only Python's standard library and fake model/processor objects.
// They cannot download or load weights, import Torch, or generate model output.
const source = path.resolve('evals/local/minicpm_server.py');
function python(body) {
  const code = `import importlib.util,json,sys,types\nspec=importlib.util.spec_from_file_location("minicpm_server",sys.argv[1])\nm=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('MiniCPM module imports inertly and advertises only implemented native Chat routes', () => {
  const result = python('print(json.dumps({"heavy_imports":[name for name in ("torch","transformers","numpy","PIL") if name in sys.modules],"schema":m.openapi()}))');
  assert.deepEqual(result.heavy_imports, []);
  assert.deepEqual(Object.keys(result.schema.paths).sort(), ['/chat/input_tokens', '/v1/chat/completions']);
  const fields = result.schema.paths['/v1/chat/completions'].post.requestBody.content['application/json'].schema.properties;
  assert.equal(fields.enable_thinking.default, false);
  assert.equal(fields.presence_penalty.default, 0);
  assert.equal(fields.repetition_context_size.default, null);
});

test('MiniCPM rejects output aliases, thinking and sampler settings outside its implementation', () => {
  const result = python(`
base={"model":m.ARTIFACT,"messages":[{"role":"user","content":"hello"}],"seed":23,"max_tokens":512}
def check(extra):
 try:
  m.validate_request({**base,**extra},"/exact"); return "accepted"
 except ValueError as error: return str(error)
print(json.dumps([check(extra) for extra in [{},{"max_tokens":513},{"max_completion_tokens":511},{"enable_thinking":True},{"presence_penalty":1.5},{"context_management":[{}]},{"n":2},{"max_new_tokens":10000},{"top_k":0.5},{"seed":True}]]))`);
  assert.deepEqual(result, ['accepted', 'OUTPUT_LIMIT_INVALID', 'OUTPUT_LIMIT_INVALID', 'THINKING_DISABLED', 'SAMPLER_UNSUPPORTED:presence_penalty', 'REQUEST_MULTIGENERATION_UNSUPPORTED', 'REQUEST_MULTIGENERATION_UNSUPPORTED', 'REQUEST_FIELD_UNSUPPORTED:max_new_tokens', 'SAMPLER_INVALID', 'SEED_INVALID']);
});

test('publisher XML tool parser preserves text and decodes only declared argument types', () => {
  const result = python(`
tool={"type":"function","function":{"name":"edit","parameters":{"type":"object","properties":{"text":{"type":"string"},"count":{"type":"integer"},"flags":{"type":"object"}},"required":["text","count","flags"]}}}
text='Before.\\n<tool_call>\\n<function=edit>\\n<parameter=text>\\n  Birds é \\nnext line\\n</parameter>\\n<parameter=count>\\n2\\n</parameter>\\n<parameter=flags>\\n{"validate":true}\\n</parameter>\\n</function>\\n</tool_call>'
parsed=m.parse_output(text,[tool]); parsed["tool_calls"][0].pop("id")
print(json.dumps(parsed))`);
  assert.equal(result.content, 'Before.\n');
  assert.deepEqual(JSON.parse(result.tool_calls[0].function.arguments), { text: '  Birds é \nnext line', count: 2, flags: { validate: true } });
});

test('publisher XML parser never repairs missing, duplicate, truncated or undeclared arguments', () => {
  const result = python(`
tools=[{"type":"function","function":{"name":"echo","parameters":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"]}}}]
valid='<tool_call>\\n<function=echo>\\n<parameter=value>\\nready\\n</parameter>\\n</function>\\n</tool_call>'
cases=[valid[:-3],valid+' suffix',valid.replace('function=echo','function=other'),valid.replace('<parameter=value>\\nready\\n</parameter>',''),valid.replace('<parameter=value>','<parameter=unknown>'),valid.replace('</parameter>','</parameter>\\n<parameter=value>duplicate</parameter>'),'<tool_call']
results=[]
for text in cases:
 try: m.parse_output(text,tools); results.append('accepted')
 except ValueError as error: results.append(str(error))
stray=m.parse_output(valid.replace('</parameter>','</parameter>\\n</parameter>'),tools)['tool_calls'][0]['function']['arguments']
results.append(stray)
print(json.dumps(results))`);
  assert.deepEqual(result, ['TOOL_ARGUMENTS_INCOMPLETE', 'TOOL_ARGUMENTS_INCOMPLETE', 'TOOL_NAME_UNDECLARED', 'TOOL_ARGUMENTS_MISSING', 'TOOL_ARGUMENTS_INVALID', 'TOOL_ARGUMENTS_INVALID', 'TOOL_ARGUMENTS_INCOMPLETE', '{"value":"ready"}']);
});

test('lenient XML parsing passes names and parameters through like vLLM but never repairs syntax', () => {
  const result = python(`
tools=[{"type":"function","function":{"name":"echo","parameters":{"type":"object","properties":{"value":{"type":"string"},"count":{"type":"integer"}},"required":["value"]}}}]
valid='<tool_call>\\n<function=echo>\\n<parameter=value>\\nready\\n</parameter>\\n</function>\\n</tool_call>'
cases=[valid[:-3],valid+' suffix',valid.replace('function=echo','function=other'),valid.replace('<parameter=value>\\nready\\n</parameter>',''),valid.replace('<parameter=value>','<parameter=unknown>'),valid.replace('</parameter>','</parameter>\\n<parameter=value>duplicate</parameter>'),valid.replace('</parameter>','</parameter>\\n<parameter=count>two</parameter>'),'<tool_call']
results=[]
for text in cases:
 try:
  call=m.parse_output(text,tools,lenient=True)['tool_calls'][0]['function']; results.append(call['name']+' '+call['arguments'])
 except ValueError as error: results.append(str(error))
print(json.dumps(results))`);
  assert.deepEqual(result, ['TOOL_ARGUMENTS_INCOMPLETE', 'TOOL_ARGUMENTS_INCOMPLETE', 'other {"value":"ready"}', 'echo {}', 'echo {"unknown":"ready"}', 'TOOL_ARGUMENTS_INVALID', 'echo {"value":"ready","count":"two"}', 'TOOL_ARGUMENTS_INCOMPLETE']);
});

test('AVX512 NF4 repack is kept only for shapes bitsandbytes can reshape (vision fc2 in_features 4304 is not)', () => {
  const result = python(`
from types import SimpleNamespace as N
def layer(i,o,b=64): return N(in_features=i,out_features=o,weight=N(quant_state=N(blocksize=b)))
print(json.dumps([m.avx512_repack_supported(x) for x in (layer(1024,2048),layer(4304,1152),layer(1024,1000),layer(4304,1152,16),N(in_features=128,out_features=64))]))`);
  assert.deepEqual(result, [true, false, false, true, true]);
});

test('tool-history normalization parses JSON arguments without mutating the recorded request', () => {
  const result = python(`
original=[{"role":"assistant","content":None,"tool_calls":[{"type":"function","id":"c","function":{"name":"echo","arguments":"{\\"value\\":\\"ready\\"}"}}]}]
normalized=m.normalize_messages(original)
try: m.normalize_messages([{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.test/image.png"}}]}]); remote='accepted'
except ValueError as error: remote=str(error)
print(json.dumps({"original":original,"normalized":normalized,"remote":remote}))`);
  assert.equal(typeof result.original[0].tool_calls[0].function.arguments, 'string');
  assert.deepEqual(result.normalized[0].tool_calls[0].function.arguments, { value: 'ready' });
  assert.equal(result.remote, 'INLINE_IMAGE_REQUIRED');
});

test('native token count uses full processor tensor shape and rejects context overflow', () => {
  const result = python(`
class Processor:
 def apply_chat_template(self,messages,**kwargs):
  self.observed=kwargs
  return {"input_ids":types.SimpleNamespace(shape=(1,self.count))}
processor=Processor(); processor.count=32000
backend=m.Backend.__new__(m.Backend); backend.directory='/exact'; backend.processor=processor
body={"model":"/exact","messages":[{"role":"user","content":"x"}],"max_tokens":512}
prepared=backend.prepare(body)
processor.count=32500
try: backend.prepare(body); overflow='accepted'
except ValueError as error: overflow=str(error)
print(json.dumps({"tokens":prepared[1],"settings":processor.observed,"overflow":overflow,"count_only":backend.prepare(body,count_only=True)[1]}))`);
  assert.equal(result.tokens, 32000);
  assert.equal(result.settings.tokenize, true);
  assert.equal(result.settings.enable_thinking, false);
  assert.equal(result.settings.return_dict, true);
  assert.equal(result.settings.downsample_mode, '16x');
  assert.equal(result.overflow, 'CONTEXT_ENVELOPE_EXCEEDED');
  assert.equal(result.count_only, 32500);
});

test('count-only requests accept a client output ceiling that the generation gateway will clamp', () => {
  const result = python(`
body={'model':'/exact','messages':[{'role':'user','content':'hello'}],'max_tokens':4096}
counted=m.validate_request(body,'/exact',count_only=True)[2]
try: m.validate_request(body,'/exact'); generation='accepted'
except ValueError as error: generation=str(error)
print(json.dumps({'counted_limit':counted,'generation':generation}))`);
  assert.equal(result.counted_limit, 4096);
  assert.equal(result.generation, 'OUTPUT_LIMIT_INVALID');
});

test('streamed tool completion includes exact usage and exposes parsed calls without raw XML', () => {
  const result = python(`
import io,queue,threading
class Streamer:
 def __init__(self,*args,**kwargs): self.items=queue.Queue()
 def __next__(self):
  item=self.items.get(timeout=0.25)
  if item is None: raise StopIteration
  return item
 def end(self): self.items.put(None)
fake_transformers=types.ModuleType('transformers'); fake_transformers.TextIteratorStreamer=Streamer; sys.modules['transformers']=fake_transformers
tools=[{"type":"function","function":{"name":"echo","parameters":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"]}}}]
class Backend:
 directory='/exact'; processor=types.SimpleNamespace(tokenizer=None)
 def generate(self,body,prepared,cancelled,streamer):
  text='<tool_call>\\n<function=echo>\\n<parameter=value>\\nready\\n</parameter>\\n</function>\\n</tool_call>'
  streamer.items.put(text[:5]); streamer.items.put(text[5:]); streamer.end()
  return {"choices":[{"message":m.parse_output(text,tools),"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":100,"completion_tokens":22,"total_tokens":122}}
backend=Backend(); handler=m.handler_for(backend).__new__(m.handler_for(backend)); handler.wfile=io.BytesIO()
handler.send_response=lambda status:None; handler.send_header=lambda key,value:None; handler.end_headers=lambda:None
handler.stream({"tools":tools},None,threading.Event())
events=[json.loads(line[6:]) for line in handler.wfile.getvalue().decode().splitlines() if line.startswith('data: {')]
print(json.dumps(events))`);
  assert.deepEqual(result.at(-1).usage, { prompt_tokens: 100, completion_tokens: 22, total_tokens: 122 });
  const calls = result.flatMap(event => event.choices.flatMap(choice => choice.delta.tool_calls ?? []));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].function.name, 'echo');
  assert.deepEqual(JSON.parse(calls[0].function.arguments), { value: 'ready' });
  assert.equal(result.some(event => event.choices.some(choice => choice.delta.content?.includes('<tool_call>'))), false);
});

test('generation counts produced token IDs, fixes sampling, and forwards cancellation criteria', () => {
  const result = python(`
import contextlib,threading
fake_transformers=types.ModuleType('transformers'); fake_transformers.StoppingCriteria=object; fake_transformers.StoppingCriteriaList=list
sys.modules['transformers']=fake_transformers
sys.modules['numpy']=types.SimpleNamespace(random=types.SimpleNamespace(seed=lambda value:None))
class Tokens:
 shape=(3,)
 def tolist(self): return [1,2,99]
 def __getitem__(self,key): return 99
class Generated:
 def __getitem__(self,key): return Tokens()
class Model:
 device='mps'; generation_config=types.SimpleNamespace(eos_token_id=[99])
 def generate(self,**kwargs): self.kwargs=kwargs; return Generated()
class Inputs(dict):
 def to(self,device): return self
model=Model(); backend=m.Backend.__new__(m.Backend); backend.model=model; backend.directory='/exact'
backend.torch=types.SimpleNamespace(manual_seed=lambda value:None,mps=types.SimpleNamespace(manual_seed=lambda value:None),inference_mode=contextlib.nullcontext)
backend.processor=types.SimpleNamespace(tokenizer=types.SimpleNamespace(decode=lambda ids,**kwargs:'ready'))
cancelled=threading.Event(); body={"tools":[]}
response=backend.generate(body,(Inputs(input_ids='processor-derived'),123,512,m.SAMPLING,47),cancelled)
criteria=model.kwargs.pop('stopping_criteria'); before=criteria[0](None,None); cancelled.set(); after=criteria[0](None,None)
print(json.dumps({"response":response,"generation":model.kwargs,"cancel_before":before,"cancel_after":after}))`);
  assert.deepEqual(result.response.usage, { prompt_tokens: 123, completion_tokens: 3, total_tokens: 126 });
  assert.equal(result.response.choices[0].finish_reason, 'stop');
  assert.equal(result.generation.max_new_tokens, 512);
  assert.equal(result.generation.input_ids, 'processor-derived');
  assert.equal(result.generation.presence_penalty, undefined);
  assert.equal(result.generation.temperature, 0.7);
  assert.equal(result.cancel_before, false);
  assert.equal(result.cancel_after, true);
});

test('XML decoding supports legal nullable/composed/local-reference schemas without coercion', () => {
  const result = python(`
root={'$defs':{'count':{'anyOf':[{'type':'integer'},{'type':'null'}]}}}
cases=[('1',{'type':['integer','null']}),('null',{'type':['integer','null']}),('true',{'type':['integer','null']}),('"1"',{'type':['integer','null']}),('1',{'$ref':'#/$defs/count'}),('false',{'oneOf':[{'type':'boolean'},{'type':'null'}]}),('  x  ',{'type':['string','null']}),('null',{'type':'string'}),('NaN',{'type':'number'}),('1e999',{'type':'number'}),('{}',{'$ref':'https://invalid.test/schema'}),('1',{'$ref':'#/$defs/missing'})]
results=[]
for raw,schema in cases:
 try: results.append({'value':m.parameter_value(raw,schema,root)})
 except ValueError as error: results.append({'error':str(error)})
tool={'type':'function','function':{'name':'count','parameters':{**root,'type':'object','properties':{'value':{'$ref':'#/$defs/count'}},'required':['value']}}}
call=m.parse_output('<tool_call><function=count><parameter=value>1</parameter></function></tool_call>',[tool])
print(json.dumps({'cases':results,'arguments':json.loads(call['tool_calls'][0]['function']['arguments'])}))`);
  assert.deepEqual(result.cases, [
    { value: 1 }, { value: null }, { error: 'TOOL_PARAMETER_TYPE_MISMATCH' },
    { error: 'TOOL_PARAMETER_TYPE_MISMATCH' }, { value: 1 }, { value: false },
    { value: '  x  ' }, { value: 'null' }, { error: 'TOOL_PARAMETER_TYPE_MISMATCH' },
    { error: 'TOOL_PARAMETER_TYPE_MISMATCH' }, { error: 'TOOL_PARAMETER_SCHEMA_UNSUPPORTED' },
    { error: 'TOOL_PARAMETER_SCHEMA_UNSUPPORTED' }
  ]);
  assert.deepEqual(result.arguments, { value: 1 });
});

test('all 104 installed operation contracts have decodable top-level parameter schemas', () => {
  const result = python(`
from pathlib import Path
files=sorted((Path(m.__file__).resolve().parents[2]/'contracts/schema/operations').glob('*.input.schema.json'))
failures=[]; count=0
for file in files:
 schema=json.loads(file.read_text())
 for name,parameter in schema.get('properties',{}).items():
  count+=1
  try: m.schema_types(parameter,schema)
  except ValueError as error: failures.append({'operation':file.name,'parameter':name,'error':str(error)})
schema=json.loads(next(file for file in files if file.name=='token_form_set.input.schema.json').read_text())
value=m.parameter_value('{"file_path":"example.conllu","sent_id":"example","token_id":"1"}',schema['properties']['token_ref'],schema)
print(json.dumps({'operations':len(files),'parameters':count,'failures':failures,'reference':value,'enum':m.parameter_value('svg',{'enum':['svg','png']})}))`);
  assert.equal(result.operations, 104); assert.ok(result.parameters >= 500);
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.reference, { file_path: 'example.conllu', sent_id: 'example', token_id: '1' });
  assert.equal(result.enum, 'svg');
});

posixTest('private generation evidence distinguishes cap-censored XML from EOS grammar failure', () => {
  const result = python(`
import contextlib,threading,tempfile,pathlib,stat
fake_transformers=types.ModuleType('transformers'); fake_transformers.StoppingCriteria=object; fake_transformers.StoppingCriteriaList=list
sys.modules['transformers']=fake_transformers
sys.modules['numpy']=types.SimpleNamespace(random=types.SimpleNamespace(seed=lambda value:None))
class Tokens:
 shape=(3,)
 def __init__(self,values): self.values=values
 def tolist(self): return self.values
class Generated:
 def __init__(self,values): self.values=values
 def __getitem__(self,key): return Tokens(self.values)
class Model:
 device='mps'; generation_config=types.SimpleNamespace(eos_token_id=[99]); values=[1,2,3]
 def generate(self,**kwargs): return Generated(self.values)
class Inputs(dict):
 def to(self,device): return self
with tempfile.TemporaryDirectory() as directory:
 evidence=m.GenerationEvidence(directory)
 backend=m.Backend.__new__(m.Backend); backend.model=Model(); backend.directory='/exact'; backend.evidence=evidence
 backend.torch=types.SimpleNamespace(manual_seed=lambda value:None,mps=types.SimpleNamespace(manual_seed=lambda value:None),inference_mode=contextlib.nullcontext)
 backend.processor=types.SimpleNamespace(tokenizer=types.SimpleNamespace(decode=lambda ids,**kwargs:'<tool_call><function=echo>'))
 errors=[]; responses=[]
 for values in ([1,2,3],[1,2,99]):
  backend.model.values=values
  try: responses.append(backend.generate({'tools':[]},(Inputs(),123,3,m.SAMPLING,47),threading.Event()))
  except ValueError as error: errors.append(str(error))
 files=sorted(pathlib.Path(directory).glob('*.json'))
 records=[json.loads(file.read_text()) for file in files]
 print(json.dumps({'errors':errors,'responses':responses,'records':records,'permissions':[stat.S_IMODE(file.stat().st_mode) for file in files]}))`);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.responses.map(row => row.choices[0].finish_reason), ['length', 'stop']);
  assert.ok(result.responses.every(row => row.choices[0].message.content === '<tool_call><function=echo>' && !row.choices[0].message.tool_calls && row.usage.completion_tokens === 3));
  assert.deepEqual(result.records.map(row => row.termination).sort(), ['eos', 'length']);
  assert.ok(result.records.every(row => row.completion_tokens === 3 && row.prompt_tokens === 123 && row.maximum_tokens === 3 && row.token_ids.length === 3 && row.text === '<tool_call><function=echo>' && row.parser_status === 'rejected'));
  assert.deepEqual(result.permissions, [0o600, 0o600]);
});

posixTest('malformed complete tool generations preserve raw stream content and trusted usage with zero dispatch', () => {
  const result = python(`
import contextlib,threading,tempfile,pathlib,io,queue
class Streamer:
 def __init__(self,*args,**kwargs): self.items=queue.Queue()
 def __next__(self):
  item=self.items.get(timeout=0.25)
  if item is None: raise StopIteration
  return item
 def end(self):self.items.put(None)
fake=types.ModuleType('transformers');fake.StoppingCriteria=object;fake.StoppingCriteriaList=list;fake.TextIteratorStreamer=Streamer;sys.modules['transformers']=fake
sys.modules['numpy']=types.SimpleNamespace(random=types.SimpleNamespace(seed=lambda value:None))
raw='Préface. <tool_call> tool_call{"name":"echo","arguments":{}} </tool_call>'
class Tokens:
 shape=(3,)
 def tolist(self):return [1,2,99]
class Generated:
 def __getitem__(self,key):return Tokens()
class Model:
 device='mps';generation_config=types.SimpleNamespace(eos_token_id=[99])
 def generate(self,**kwargs):
  streamer=kwargs.get('streamer')
  if streamer:streamer.items.put(raw[:12]);streamer.items.put(raw[12:]);streamer.end()
  return Generated()
class Inputs(dict):
 def to(self,device):return self
with tempfile.TemporaryDirectory() as directory:
 backend=m.Backend.__new__(m.Backend);backend.directory='/exact';backend.evidence=m.GenerationEvidence(directory);backend.model=Model()
 backend.torch=types.SimpleNamespace(manual_seed=lambda value:None,mps=types.SimpleNamespace(manual_seed=lambda value:None),inference_mode=contextlib.nullcontext)
 backend.processor=types.SimpleNamespace(tokenizer=types.SimpleNamespace(decode=lambda ids,**kwargs:raw))
 body={'tools':[]};prepared=(Inputs(),123,512,m.SAMPLING,47)
 response=backend.generate(body,prepared,threading.Event())
 handler=m.handler_for(backend).__new__(m.handler_for(backend));handler.wfile=io.BytesIO();handler.send_response=lambda status:None;handler.send_header=lambda key,value:None;handler.end_headers=lambda:None
 handler.stream(body,prepared,threading.Event())
 wire=handler.wfile.getvalue().decode();events=[json.loads(line[6:]) for line in wire.splitlines() if line.startswith('data: {')]
 records=[json.loads(file.read_text()) for file in pathlib.Path(directory).glob('*.json')]
 backend.evidence=None
 try:backend.generate(body,prepared,threading.Event());without_receipt='accepted'
 except ValueError as error:without_receipt=str(error)
 print(json.dumps({'raw':raw,'response':response,'events':events,'done':wire.endswith('data: [DONE]\\n\\n'),'records':records,'without_receipt':without_receipt}))`);
  assert.equal(result.response.choices[0].message.content, result.raw);
  assert.equal(result.response.choices[0].message.tool_calls, undefined);
  assert.deepEqual(result.response.usage, { prompt_tokens: 123, completion_tokens: 3, total_tokens: 126 });
  assert.equal(result.events.flatMap(row => row.choices).map(row => row.delta.content ?? '').join(''), result.raw);
  assert.ok(result.events.every(row => row.choices.every(choice => !choice.delta.tool_calls)));
  assert.equal(result.events.at(-2).choices[0].finish_reason, 'stop');
  assert.equal(result.events.at(-1).usage.completion_tokens, 3);
  assert.equal(result.done, true);
  assert.ok(result.records.every(row => row.parser_status === 'rejected' && row.dispatch_eligible === false && row.text === result.raw && row.termination === 'eos'));
  assert.equal(result.without_receipt, 'TOOL_ARGUMENTS_INCOMPLETE');
});

if (process.platform === 'win32') test('MiniCPM refuses POSIX generation evidence on Windows before creating files', () => {
  const result = python(`import tempfile,pathlib
with tempfile.TemporaryDirectory() as root:
 directory=pathlib.Path(root)/'not-created'
 try: m.GenerationEvidence(str(directory))
 except ValueError as error: reason=str(error)
 else: raise AssertionError('Windows must not establish POSIX evidence authority')
 print(json.dumps({'reason':reason,'created':directory.exists()}))`);
  assert.deepEqual(result, { reason: 'PRIVATE_GENERATION_PLATFORM_UNSUPPORTED', created: false });
});
