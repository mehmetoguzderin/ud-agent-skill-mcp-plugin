import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const source = path.resolve('evals/local/mlx_server.py');
function python(body) {
  const code = `import importlib.util,json,sys\nspec=importlib.util.spec_from_file_location('ud_mlx_adapter',sys.argv[1])\nm=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('MLX adapter imports inertly and refuses unknown version or source', () => {
  const result = python(`
errors=[]
for version in ('0.7.12','0.7.11'):
 try: m.patch_modules(m,m,version)
 except RuntimeError as error: errors.append(str(error))
print(json.dumps({'heavy':[name for name in ('mlx','mlx_vlm','torch','transformers') if name in sys.modules], 'errors':errors}))`);
  assert.deepEqual(result.heavy, []);
  assert.deepEqual(result.errors, ['MLX_XML_PATCH_VERSION_UNVERIFIED', 'MLX_XML_PATCH_SOURCE_UNVERIFIED']);
});

test('loaded-object observer binds native loader source and records only successfully returned objects', () => {
  const result = python(String.raw`
import tempfile,pathlib,hashlib
with tempfile.TemporaryDirectory() as temporary:
 file=pathlib.Path(temporary)/'generation.py'
 file.write_text('def load_model_resources(path, adapter):\n return ("native-model", "native-processor", "native-config")\n')
 spec=importlib.util.spec_from_file_location('inert_generation',file);generation=importlib.util.module_from_spec(spec);spec.loader.exec_module(generation)
 try:m.observe_model_load(generation,'0.7.11',lambda *args:{})
 except RuntimeError as error:before=str(error)
 m.EXPECTED_GENERATION=hashlib.sha256(file.read_bytes()).hexdigest()
 calls=[]
 def identity(path,model,processor,loader):
  calls.append([path,model,processor,loader.__name__]);return {'model':path,'model_loaded':True}
 observation=m.observe_model_load(generation,'0.7.11',identity)
 empty=dict(observation);value=generation.load_model_resources('/exact',None);loaded=dict(observation)
 try:generation.load_model_resources('/exact','foreign-adapter')
 except RuntimeError as error:blocked=str(error)
 print(json.dumps({'before':before,'empty':empty,'calls':calls,'value':value,'loaded':loaded,'blocked':blocked,'after':observation}))`);
  assert.equal(result.before, 'MLX_LOAD_OBSERVER_SOURCE_UNVERIFIED'); assert.deepEqual(result.empty, {});
  assert.deepEqual(result.calls, [['/exact', 'native-model', 'native-processor', 'load_model_resources']]);
  assert.deepEqual(result.value, ['native-model', 'native-processor', 'native-config']);
  assert.deepEqual(result.loaded, { model: '/exact', model_loaded: true });
  assert.equal(result.blocked, 'EXACT_MODEL_ADAPTER_UNSUPPORTED'); assert.deepEqual(result.after, {});
});

test('source-bound patch keeps partial unions gated and strictly decodes completed nullable arguments', () => {
  const result = python(String.raw`
import tempfile,pathlib,hashlib
stream_source='''import json
def _xml_call(text, tools, module):
    properties = module._get_arguments_config('echo', tools)
    key='value'
    if text.endswith('!'):
        return module._convert_param_value(text[:-1],key,properties)
    if properties.get(key, {}).get(
                "type"
            ) in module._string_types:
        return 'partial-string'
    return 'gated'
'''
parser_source='''_string_types={'string'}
def _get_arguments_config(name, tools):
 return tools[0]['function']['parameters']['properties']
def _convert_param_value(value,name,properties):
 return value
'''
def load(file,name):
 spec=importlib.util.spec_from_file_location(name,file); result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
with tempfile.TemporaryDirectory() as temporary:
 directory=pathlib.Path(temporary); stream_file=directory/'streaming.py';parser_file=directory/'parser.py'
 stream_file.write_text(stream_source);parser_file.write_text(parser_source)
 streaming=load(stream_file,'fake_streaming');parser=load(parser_file,'fake_parser')
 m.EXPECTED={'streaming':hashlib.sha256(stream_file.read_bytes()).hexdigest(),'parser':hashlib.sha256(parser_file.read_bytes()).hexdigest()}
 receipt=m.patch_modules(streaming,parser,'0.7.11')
 def tools(schema,defs={}):return [{'function':{'name':'echo','parameters':{'properties':{'value':schema},'$defs':defs}}}]
 nullable=tools({'type':['integer','null']})
 values=[streaming._xml_call('1',nullable,parser),streaming._xml_call('1!',nullable,parser),streaming._xml_call('null!',nullable,parser)]
 try: streaming._xml_call('true!',nullable,parser)
 except ValueError as error: invalid=str(error)
 referenced=tools({'$ref':'#/$defs/value'},{'value':{'anyOf':[{'type':'integer'},{'type':'null'}]}})
 values.append(streaming._xml_call('2!',referenced,parser))
 print(json.dumps({'values':values,'invalid':invalid,'receipt':receipt,'unchanged':m.EXPECTED=={'streaming':hashlib.sha256(stream_file.read_bytes()).hexdigest(),'parser':hashlib.sha256(parser_file.read_bytes()).hexdigest()}}))`);
  assert.deepEqual(result.values, ['gated', 1, null, 2]);
  assert.equal(result.invalid, 'TOOL_PARAMETER_TYPE_MISMATCH');
  assert.equal(result.receipt.installed_files_changed, false);
  assert.equal(result.receipt.semantic_argument_repairs, false);
  assert.equal(result.unchanged, true);
});
