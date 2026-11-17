import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const source = path.resolve('evals/local/study_forward.py');
function python(body) {
  const code = `import importlib.util,json,sys\nspec=importlib.util.spec_from_file_location('ud_forward',sys.argv[1])\nm=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('forward executor imports without weights and validates bounded text-only interventions', () => {
  const result = python(`
base={'request':{'messages':[{'role':'user','content':'hello'}]},'spans':[{'name':'intent','start':0,'end':2}]}
cases=[base,{**base,'request':{'messages':[{'role':'user','content':[{'type':'image_url','image_url':{'url':'data:image/png;base64,AAAA'}}]}]}},{**base,'candidate_token_ids':[-1]},{**base,'intervention':{'kind':'zero_operator_last_position','layer':0}},{**base,'instrument':True,'intervention':{'kind':'zero_operator_last_position','layer':0}}]
results=[]
for value in cases:
 try: m.validate_probe(value); results.append('accepted')
 except ValueError as error: results.append(str(error))
print(json.dumps({'heavy':[name for name in ('mlx','torch','transformers','numpy') if name in sys.modules],'results':results}))`);
  assert.deepEqual(result.heavy, []);
  assert.deepEqual(result.results, ['accepted', 'FORWARD_TEXT_ONLY', 'FORWARD_CANDIDATES_INVALID', 'FORWARD_INTERVENTION_INVALID', 'accepted']);
});

test('attention summaries preserve head masses and distinguish length-normalized span density', () => {
  const result = python(`
summary=m.attention_summary([[0.1,0.2,0.3,0.4],[0.4,0.3,0.2,0.1]],[{'name':'skill','start':0,'end':2},{'name':'intent','start':3,'end':4}])
errors=[]
for rows,spans in [([[0.1]],[]),([[float('nan')]],[]),([[1.0]],[{'name':'outside','start':0,'end':2}])]:
 try: m.attention_summary(rows,spans)
 except ValueError as error: errors.append(str(error))
print(json.dumps({'summary':summary,'errors':errors}))`);
  assert.equal(result.summary.query_rows, 1);
  assert.equal(result.summary.key_tokens, 4);
  assert.equal(result.summary.heads, 2);
  assert.ok(Math.abs(result.summary.spans[0].mean_mass - 0.5) < 1e-10);
  assert.ok(Math.abs(result.summary.spans[0].mean_mass_per_token - 0.25) < 1e-10);
  assert.ok(Math.abs(result.summary.spans[1].mean_mass - 0.25) < 1e-10);
  assert.deepEqual(result.errors, ['ATTENTION_ROW_INVALID', 'ATTENTION_ROW_INVALID', 'FORWARD_SPAN_OUTSIDE_CONTEXT']);
});

test('semantic spans require an exact unique match in the actual native token sequence', () => {
  const result = python(`
class Tokenizer:
 def encode(self,text,**kwargs): return {'skill':[2,3],'missing':[8],'duplicate':[1]}[text]
spans,observations=m.resolve_spans(Tokenizer(),[1,2,3,1],{'span_texts':[{'name':'skill','text':'skill'},{'name':'missing','text':'missing'},{'name':'duplicate','text':'duplicate'}]})
print(json.dumps({'spans':spans,'observations':observations}))`);
  assert.deepEqual(result.spans, [{ name: 'skill', start: 1, end: 3 }]);
  assert.deepEqual(result.observations.map(row => row.status), ['resolved', 'unmatched', 'ambiguous']);
  assert.equal(result.observations[1].start, undefined);
  assert.equal(result.observations[2].start, undefined);
});

test('teacher forcing scores token t+1 from position t without appending the final target', () => {
  const result = python(`print(json.dumps([m.scoring_metadata(4,suffix) for suffix in ([],[7],[7,8,9])]))`);
  assert.deepEqual(result[0].prediction_positions, []);
  assert.deepEqual(result[1].prediction_positions, [3]);
  assert.deepEqual(result[1].input_appended_token_ids, []);
  assert.deepEqual(result[2].prediction_positions, [3, 4, 5]);
  assert.deepEqual(result[2].input_appended_token_ids, [7, 8]);
  assert.deepEqual(result[2].continuation_token_ids, [7, 8, 9]);
  assert.equal(result[2].next_logits_position, 3);
  assert.equal(result[2].attention_query_position, 3);
  assert.equal(result[2].operator_observation_position, 3);
  assert.match(result[2].distribution, /before sampler/);
});

test('ordinary study forwards reject oversized captured prefixes before model execution, including appended marker input', () => {
  const result = python(`
rows=[]
for prompt,continuation in ((16384,0),(16383,2),(16384,2),(20000,0),(32768,0)):
 try: rows.append(m.bounded_forward_tokens(prompt,continuation))
 except ValueError as error: rows.append(str(error))
print(json.dumps(rows))`);
  assert.deepEqual(result, [16384, 16384, 'FORWARD_CONTEXT_LIMIT', 'FORWARD_CONTEXT_LIMIT', 'FORWARD_CONTEXT_LIMIT']);
});

test('prefix query positions and rotating key identities exclude teacher-forced future tokens', () => {
  const result = python(`
RotatingKVCache=type('RotatingKVCache',(),{})
def layout(index,queries,keep=0):
 cache=RotatingKVCache();cache.offset=10;cache._idx=index;cache.keep=keep
 return m.attention_key_layout(10,4,queries,cache)
full=m.attention_key_layout(5,5,2)
print(json.dumps({'torch_position':m.prefix_position(4,0,5),'mlx_tail_position':m.prefix_position(4,3,2),
 'full':full,'causal_prefix_mask':[position<=3 for position in full['physical_positions']],
 'concat':layout(4,2),'ring':layout(2,1),'ambiguous':layout(2,2),'retained':layout(4,2,1),
 'mask_queries':[m.attention_mask_query((2,5),0,2),m.attention_mask_query((1,1,5,5),3,5)]}))`);
  assert.equal(result.torch_position, 3); assert.equal(result.mlx_tail_position, 0);
  assert.deepEqual(result.causal_prefix_mask, [true, true, true, true, false]);
  assert.deepEqual(result.concat.temporal_order, [0, 1, 2, 3]);
  assert.deepEqual(result.ring.temporal_order, [2, 3, 0, 1]);
  assert.deepEqual(result.ring.physical_positions, [8, 9, 6, 7]);
  assert.equal(result.ambiguous, null); assert.equal(result.retained, null);
  assert.deepEqual(result.mask_queries, [0, 3]);
});

test('actual Torch execution returns the prefix-end vector and candidate scores while retaining both marker likelihoods', () => {
  const result = python(`
import contextlib,math,types
class Tensor:
 def __init__(self,value): self.value=value;self.dtype='integer'
 @property
 def shape(self):
  value=self.value;shape=[]
  while isinstance(value,list):
   shape.append(len(value));value=value[0] if value else None
  return tuple(shape)
 def __getitem__(self,key):
  value=self.value
  if not isinstance(key,tuple): return Tensor(value[key])
  if len(key)==2 and isinstance(key[0],slice): return Tensor([row[key[1]] for row in value[key[0]]])
  for part in key: value=value[part]
  return Tensor(value)
 def tolist(self): return self.value
 def float(self): return self
 def cpu(self): return self
 def item(self): return self.value
class Inputs(dict):
 def to(self,device): return self
def log_softmax(tensor,dim):
 return Tensor([[v-math.log(sum(math.exp(x) for x in row)) for v in row] for row in tensor.value])
torch=types.SimpleNamespace(cat=lambda values,dim:Tensor([sum([item.value[0] for item in values],[])]),tensor=lambda value,**kwargs:Tensor(value),
 inference_mode=contextlib.nullcontext,log_softmax=log_softmax,is_tensor=lambda item:False)
tokenizer=types.SimpleNamespace(encode=lambda text,**kwargs:[2,3])
worker=m.TorchForward.__new__(m.TorchForward);worker.torch=torch;worker.layers=[];worker.tokenizer=tokenizer
worker.backend=types.SimpleNamespace(prepare=lambda request:(Inputs(input_ids=Tensor([[1,2,3,4]])),4,512,{},23))
worker.model=types.SimpleNamespace()
class Model:
 device='inert'
 def __call__(self,**kwargs):
  assert kwargs['input_ids'].tolist()==[[1,2,3,4,2]]
  assert kwargs['logits_to_keep']==2
  return types.SimpleNamespace(logits=Tensor([[[9,1,0,0],[0,0,3,8]]]),past_key_values=types.SimpleNamespace(layers=[]))
worker.model=Model()
result=worker.run({'request':{},'continuation':'tool_search','candidate_token_ids':[0]})
print(json.dumps(result))`);
  assert.deepEqual(result.next_logits, [9, 1, 0, 0]);
  assert.equal(result.next_logits_position, 3); assert.equal(result.attention_query_position, 3);
  assert.equal(result.cache_states_position, 4); assert.equal(result.intervention_position, null);
  assert.equal(result.continuation_log_probabilities.length, 2);
  assert.ok(result.candidate_log_probabilities[0].log_probability > -0.01);
  assert.ok(result.continuation_log_probabilities[0] < -8);
  assert.ok(result.continuation_log_probabilities[1] > -0.01);
});

test('sliding-key windows explicitly distinguish inaccessible spans from missing observations', () => {
  const result = python(`print(json.dumps(m.attention_summary([[0.25,0.75]],[{'name':'old-skill','start':0,'end':2},{'name':'intent','start':3,'end':4}],2)))`);
  assert.equal(result.key_offset, 2);
  assert.equal(result.spans[0].key_window_status, 'outside');
  assert.equal(result.spans[0].covered_key_tokens, 0);
  assert.equal(result.spans[0].mean_mass, 0);
  assert.equal(result.spans[1].key_window_status, 'complete');
  assert.equal(result.spans[1].mean_mass, 0.75);
});

test('direct forward execution requires opt-in before any model runtime import', () => {
  const result = spawnSync('python3', ['-I', '-B', source, '--model', '/unavailable/model', '--artifact', 'openbmb/MiniCPM-V-4.7-1B-int4'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Explicit --opt-in outside CI is required/);
  assert.doesNotMatch(result.stderr, /ModuleNotFoundError/);
});
