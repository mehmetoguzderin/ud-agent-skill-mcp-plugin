import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const source = path.resolve('evals/local/loop_mlx_server.py');
function python(body) {
  const code = `import importlib.util,json,sys,types\nspec=importlib.util.spec_from_file_location("loop_mlx_server",sys.argv[1])\nm=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(m)\n${body}`;
  const result = spawnSync('python3', ['-I', '-B', '-c', code, source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim().split('\n').at(-1));
}

test('MLX loop server imports without MLX or model weights and keeps registry sampling', () => {
  const result = python('print(json.dumps({"heavy":[n for n in ("mlx","mlx_vlm","torch","transformers") if n in sys.modules],"artifacts":m.ARTIFACTS,"lfm3":m.SAMPLING["lfm3_vl"]}))');
  assert.deepEqual(result.heavy, []);
  assert.deepEqual(Object.values(result.artifacts).sort(), ['LiquidAI/LFM3-VL-2B-MLX-5bit', 'prism-ml/Ternary-Bonsai-2-2B-mlx-2bit']);
  assert.deepEqual(result.lfm3, { temperature: 0.1, top_p: 1, top_k: 50, repetition_penalty: 1.1 });
});

test('CPU throughput routing keeps decode on the native kernel and dequantizes each weight once for prefill', () => {
  const result = python(`
calls=[]
class A:
    def __init__(self,shape,tag="x"): self.shape=shape; self.tag=tag; self.T=self; self.dtype="bf16"
    def astype(self,d): return A(self.shape,self.tag+":"+d)
mx=types.SimpleNamespace(float32="f32",bfloat16="bf16")
mx.quantized_matmul=lambda *a,**k: calls.append("native") or "native"
mx.dequantize=lambda w,s,b,group_size,bits: calls.append("dequantize") or A((8,8),"dense")
mx.eval=lambda *a: None
mx.matmul=lambda x,w: calls.append("matmul:"+w.tag) or A(x.shape)
stats=m.install_prefill_dequantization(mx)
w=A((8,8),"w")
mx.quantized_matmul(A((1,1,8)),w,"s","b",transpose=True,group_size=64,bits=5)
mx.quantized_matmul(A((1,32,8)),w,"s","b",transpose=True,group_size=64,bits=5)
mx.quantized_matmul(A((1,32,8)),w,"s","b",transpose=True,group_size=64,bits=5)
mx.quantized_matmul(A((1,32,8)),w,"s",None,transpose=True,group_size=64,bits=5)
print(json.dumps({"calls":calls,"stats":stats}))`);
  assert.deepEqual(result.calls, ['native', 'dequantize', 'matmul:dense:bf16:f32', 'matmul:dense:bf16:f32', 'native']);
  assert.deepEqual(result.stats, { dequantized_weights: 1, dequantized_calls: 2, native_calls: 2 });
});

test('MLX loop server rejects requests for another model or unsupported fields before rendering', () => {
  const result = python(`
b=m.Backend.__new__(m.Backend)
b.directory="/models/lfm3"; b.artifact="LiquidAI/LFM3-VL-2B-MLX-5bit"; b.sampling=m.SAMPLING["lfm3_vl"]
out=[]
for body in ({"model":"other","messages":[]},{"model":"/models/lfm3","messages":[],"logprobs":True},{"model":"/models/lfm3","messages":[],"stream":True}):
    try: b._prepare(body); out.append("accepted")
    except ValueError as e: out.append(str(e))
print(json.dumps(out))`);
  assert.deepEqual(result, ['MODEL_NOT_ADMITTED', 'REQUEST_FIELD_UNSUPPORTED:logprobs', 'REQUEST_MODE_UNSUPPORTED']);
});
