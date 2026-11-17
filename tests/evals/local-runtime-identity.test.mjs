/** Loaded-object fixtures only; no heavyweight package imports or model loads. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

function python(body) {
  const code = `import importlib.util,json,sys,types,tempfile,pathlib\nspec=importlib.util.spec_from_file_location('ud_identity',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, path.resolve('evals/local/runtime_identity.py')], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr); return JSON.parse(result.stdout);
}

test('MiniCPM identity observes loaded NF4 modules, actual parameter placement and processor class', () => {
  const result = python(String.raw`
m.source_identity=lambda value:{'module':value.__module__,'name':value.__name__,'sha256':'a'*64}
m.importlib.metadata.version=lambda name:'inert-version'
Linear=type('Linear4bit',(),{'__module__':'bitsandbytes.nn.modules'})
layer=Linear();layer.weight=types.SimpleNamespace(quant_type='nf4')
parameter=types.SimpleNamespace(device='mps:0',dtype='torch.uint8')
model=types.SimpleNamespace(parameters=lambda:[parameter],modules=lambda:[layer])
processor=types.SimpleNamespace(image_processor=types.SimpleNamespace())
with tempfile.TemporaryDirectory() as directory:
 pathlib.Path(directory,'config.json').write_text('{}')
 observed=m.minicpm_identity(directory,model,processor,'mps')
 parameter.device='cpu'
 try:m.minicpm_identity(directory,model,processor,'mps')
 except RuntimeError as error:placement=str(error)
 parameter.device='mps:0';layer.weight.quant_type='fp4'
 try:m.minicpm_identity(directory,model,processor,'mps')
 except RuntimeError as error:quantization=str(error)
 print(json.dumps({'observed':observed,'placement':placement,'quantization':quantization,'heavy':[name for name in ('torch','mlx','transformers') if name in sys.modules]}))`);
  assert.deepEqual(result.heavy, []); assert.equal(result.observed.device, 'mps');
  assert.deepEqual(result.observed.parameter_devices, ['mps:0']); assert.equal(result.observed.quantization.format, 'bitsandbytes-nf4');
  assert.equal(result.placement, 'MINICPM_EFFECTIVE_DEVICE_UNVERIFIED'); assert.equal(result.quantization, 'MINICPM_EFFECTIVE_NF4_UNVERIFIED');
});

test('Bonsai identity checks every configured loaded Hadamard replacement rather than generic two-bit metadata', () => {
  const result = python(String.raw`
m.source_identity=lambda value:{'module':value.__module__,'name':value.__name__,'sha256':'a'*64}
m.importlib.metadata.version=lambda name:'inert-version'
Linear=type('HadamardQuantizedLinear',(),{'__module__':'mlx_vlm.models.prism_hadamard_qwen35'})
layer=Linear();layer.bits=2;layer.group_size=128;layer.block=512;layer.signs=object()
Model=type('Model',(),{'__module__':'mlx_vlm.models.prism_hadamard_qwen35'})
model=Model();model.named_modules=lambda:[('language_model.layer',layer)];model.parameters=lambda:{'weight':'inert'}
parameter=types.SimpleNamespace(dtype='uint32',nbytes=256)
mx=types.SimpleNamespace(default_device=lambda:'Device(gpu, 0)')
with tempfile.TemporaryDirectory() as directory:
 pathlib.Path(directory,'config.json').write_text(json.dumps({'model_type':'prism_hadamard_qwen35','modules':[{'path':'layer','embedding':False,'block':512}]}))
 observed=m.mlx_identity(directory,model,object(),mx,lambda values:[('weight',parameter)],m.mlx_identity)
 layer.block=0
 try:m.mlx_identity(directory,model,object(),mx,lambda values:[('weight',parameter)],m.mlx_identity)
 except RuntimeError as error:wrong=str(error)
 print(json.dumps({'observed':observed,'wrong':wrong}))`);
  assert.equal(result.observed.quantization.hadamard.verified_modules, 1); assert.equal(result.observed.quantization.hadamard.rotated_modules, 1);
  assert.equal(result.observed.parameter_storage_bytes, 256); assert.equal(result.wrong, 'BONSAI_EFFECTIVE_HADAMARD_UNVERIFIED');
});
