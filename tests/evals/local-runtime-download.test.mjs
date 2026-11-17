/** Exercise downloader control flow with a fake publisher; no network or model load. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

test('download publishes immutable file hashes and runtime packages without entering a model-loader branch', () => {
  const source = path.resolve('evals/local/runtime.py');
  const result = spawnSync('python3', ['-I', '-B', '-c', String.raw`
import importlib.util,json,sys,types,tempfile,pathlib
spec=importlib.util.spec_from_file_location('ud_runtime_probe',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
 def download(artifact,revision,local_dir):
  assert artifact=='publisher/exact' and revision=='a'*40 and local_dir==directory
  pathlib.Path(directory,'config.json').write_text('{"model_type":"inert"}')
  cache=pathlib.Path(directory,'.cache');cache.mkdir();(cache/'receipt').write_text('excluded acquisition cache')
 def model_info(artifact,revision=None):
  assert artifact=='publisher/exact' and revision=='a'*40
  return types.SimpleNamespace(sha='a'*40)
 api=types.SimpleNamespace(model_info=model_info)
 sys.modules['huggingface_hub']=types.SimpleNamespace(HfApi=lambda:api,snapshot_download=download)
 m.importlib.metadata.distributions=lambda:[types.SimpleNamespace(metadata={'Name':'inert-package'},version='1.2.3')]
 sys.argv=['runtime.py','download','--artifact','publisher/exact','--directory',directory,'--revision','a'*40]
 m.main()
 assert not any(name in sys.modules for name in ('torch','transformers','mlx'))
`, source], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.artifact, 'publisher/exact'); assert.equal(receipt.revision, 'a'.repeat(40));
  assert.deepEqual(receipt.packages, { 'inert-package': '1.2.3' });
  assert.equal(receipt.files.length, 1); assert.equal(receipt.files[0].path, 'config.json');
  assert.match(receipt.files[0].sha256, /^[a-f0-9]{64}$/); assert.ok(receipt.files[0].size > 0);
});
