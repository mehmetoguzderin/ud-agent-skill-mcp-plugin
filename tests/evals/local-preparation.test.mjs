import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync, realpathSync, statSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { prepare, readPreparation, captureRuntimeClosure, RUNTIME_REQUIREMENTS, RUNTIME_RECIPE_SHA256, localPaths } from '../../evals/local/preparation.mjs';
import { MODELS } from '../../evals/local/registry.mjs';
import { fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';

const versions = {
  mlx: { 'mlx-vlm': '0.7.11', transformers: '5.22.2', 'huggingface-hub': '1.33.0', litellm: '1.109.0', llguidance: '1.9.1' },
  minicpm: { transformers: '5.22.2', torch: '2.15.0', torchvision: '0.29.2', bitsandbytes: '0.50.2', accelerate: '1.15.0' }
};
const modelFile = directory => { const { path, sha256, size } = fileReceipt(directory, 'config.json'); return { path, sha256, size }; };

async function fixture(run, { existing = true } = {}) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-runtime-repair-'))), paths = localPaths(root);
  mkdirSync(path.join(root, 'evals/local'), { recursive: true }); writeFileSync(path.join(root, 'evals/local/runtime.py'), '# inert download helper\n');
  const prefix = path.join(root, 'readonly-python'), interpreter = path.join(prefix, 'bin/python3.12');
  mkdirSync(path.dirname(interpreter), { recursive: true }); writeFileSync(interpreter, 'inert interpreter');
  const state = { calls: [], fail: null, time: 100_000, expire: false };
  const makeVenv = directory => {
    mkdirSync(path.join(directory, 'bin'), { recursive: true }); mkdirSync(path.join(directory, 'lib/site-packages'), { recursive: true });
    symlinkSync(interpreter, path.join(directory, 'bin/python'));
    writeFileSync(path.join(directory, 'pyvenv.cfg'), 'include-system-site-packages = false\n');
    writeFileSync(path.join(directory, 'lib/site-packages/inert.py'), 'inert dependency bytes');
  };
  const runner = async (command, args, options = {}) => {
    state.calls.push({ command, args, options });
    if (command === 'uv' && args[0] === 'venv') { makeVenv(args.at(-1)); return { stdout: '' }; }
    if (command === 'uv' && args[1] === 'compile') {
      writeFileSync(args[args.indexOf('--output-file') + 1], 'inert-dependency==1.0 --hash=sha256:inert\n'); return { stdout: '' };
    }
    if (command === 'uv' && args[1] === 'sync') {
      if (state.fail === 'sync') throw new Error('inert dependency installation failure');
      if (state.expire) state.time += 20 * 60_000;
      return { stdout: '' };
    }
    if (command === 'uv' && args[1] === 'check') {
      if (state.fail === 'check') throw new Error('inert inconsistent dependencies');
      return { stdout: '' };
    }
    const script = args[args.indexOf('-c') + 1];
    if (script?.includes('importlib.metadata.distributions')) return { stdout: JSON.stringify(versions[command.split(path.sep).includes('minicpm') ? 'minicpm' : 'mlx']) };
    if (script?.includes('AutoProcessor')) {
      if (state.fail === 'processor') throw new Error('inert missing exact processor dependency');
      assert.equal(options.env.HF_HUB_OFFLINE, '1'); assert.equal(options.env.TRANSFORMERS_OFFLINE, '1');
      assert.ok(!script.includes('AutoModel.from_pretrained') && !script.includes('.generate('));
      const selected = JSON.parse(args.at(-2));
      return { stdout: JSON.stringify({ inference: false, model_weights_loaded: false, translation: args.at(-1) === 'mlx' && state.fail !== 'translation' ? { litellm: '1.109.0', llguidance: '1.9.1' } : null,
        processors: selected.map(({ id }) => ({ id, processor: 'InertProcessor', tokenizer: 'InertTokenizer', input_tokens: 14 })) }) };
    }
    if (script?.includes('sys.flags.isolated')) {
      const directory = path.dirname(path.dirname(command));
      return { stdout: JSON.stringify({ prefix: directory, base_prefix: prefix, executable: interpreter, isolated: 1, sys_path: [path.join(directory, 'lib/site-packages')] }) };
    }
    if (args.includes('download')) {
      const directory = args[args.indexOf('--directory') + 1]; mkdirSync(directory, { recursive: true }); writeFileSync(path.join(directory, 'config.json'), '{}\n');
      const cache = path.join(directory, '.cache/huggingface/download'); mkdirSync(cache, { recursive: true });
      writeFileSync(path.join(cache, 'config.json.metadata'), `${'a'.repeat(40)}\n${sha256(readFileSync(path.join(directory, 'config.json')))}\n100\n`);
      if (state.fail === 'download-metadata') throw new Error('inert metadata publication failure after successful download');
      return { stdout: JSON.stringify({ artifact: args[args.indexOf('--artifact') + 1], revision: 'a'.repeat(40), files: [modelFile(directory)] }) };
    }
    throw new Error(`Unexpected inert command ${command} ${args.join(' ')}`);
  };
  let original;
  if (existing) {
    mkdirSync(paths.base, { recursive: true });
    original = { schema_version: 2, created_at: '2026-11-11T00:00:00Z', runtimes: [], models: [] };
    for (const id of ['mlx', 'minicpm']) {
      const directory = path.join(paths.runtime, id, 'venv'), lock = path.join(paths.runtime, id, 'requirements.lock'); makeVenv(directory); writeFileSync(lock, 'old dependencies\n');
      const packages = { ...versions[id] }; if (id === 'minicpm') delete packages.torchvision;
      const runtime = { id, status: 'prepared', directory, python: path.join(directory, 'bin/python'), lock, lock_sha256: sha256(readFileSync(lock)), packages,
        ...(id === 'mlx' ? { preflight: { inference: false, model_weights_loaded: false, translation: { litellm: '1.109.0', llguidance: '1.9.1' } } } : {}) };
      runtime.closure = await captureRuntimeClosure(root, runtime, { runner }); original.runtimes.push(runtime);
    }
    for (const model of MODELS) {
      const directory = path.join(paths.models, model.id); mkdirSync(directory, { recursive: true }); writeFileSync(path.join(directory, 'config.json'), '{}\n');
      original.models.push({ id: model.id, artifact: model.artifact, status: 'prepared', runtime_id: model.id === 'minicpm' ? 'minicpm' : 'mlx', directory, revision: 'a'.repeat(40), files: [modelFile(directory)] });
    }
    writeFileSync(path.join(paths.base, 'preparation.sealed.json'), JSON.stringify(original, null, 2) + '\n');
  }
  state.calls.length = 0;
  // Only this fully inert runner exercises the transaction in CI. Live-entry
  // rejection is covered separately; no command can fall through to a process.
  const ciKeys = ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILD_BUILDID', 'JENKINS_URL'];
  const ciValues = new Map(ciKeys.map(key => [key, process.env[key]]));
  for (const key of ciKeys) delete process.env[key];
  try { await run({ root, paths, original, state, runner, now: () => state.time }); }
  finally {
    for (const [key, value] of ciValues) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(root, { recursive: true, force: true });
  }
}

test('explicit MiniCPM repair preserves old receipts, models and MLX while publishing one verified immutable selection', () => fixture(async ({ root, paths, original, state, runner, now }) => {
  const oldFile = path.join(paths.base, 'preparation.sealed.json'), oldBytes = readFileSync(oldFile), oldInode = statSync(oldFile).ino;
  const oldModule = path.join(original.runtimes[1].directory, 'lib/site-packages/inert.py'), oldModuleInode = statSync(oldModule).ino;
  const repaired = await prepare(root, { optIn: true, repairRuntime: true, runner, now });
  assert.equal(repaired.schema_version, 3); assert.equal(repaired.dependency_recipe_sha256, RUNTIME_RECIPE_SHA256);
  assert.deepEqual(repaired.models, original.models);
  assert.deepEqual(repaired.runtimes.find(runtime => runtime.id === 'mlx'), original.runtimes[0]);
  const mini = repaired.runtimes.find(runtime => runtime.id === 'minicpm');
  assert.notEqual(mini.directory, original.runtimes[1].directory); assert.equal(mini.packages.torchvision, '0.29.2');
  assert.equal(mini.preflight.model_weights_loaded, false); assert.equal(mini.preflight.inference, false);
  assert.ok(readFileSync(oldFile).equals(oldBytes)); assert.equal(statSync(oldFile).ino, oldInode); assert.equal(statSync(oldModule).ino, oldModuleInode);
  assert.equal(state.calls.filter(call => call.args[0] === 'venv').length, 1);
  assert.ok(state.calls.every(call => !call.args.includes('download') && call.options.timeout <= 20 * 60_000));
  const compile = state.calls.find(call => call.args[1] === 'compile');
  assert.match(readFileSync(compile.args[compile.args.indexOf('--constraint') + 1], 'utf8'), /accelerate==1\.15\.0/);
  const pointer = JSON.parse(readFileSync(path.join(paths.base, 'preparation.current.json')));
  assert.match(pointer.receipt, /^preparations\/[a-f0-9]{64}\.json$/);
  assert.equal(sha256(readFileSync(path.join(paths.base, pointer.receipt))), pointer.sha256);
  assert.deepEqual(readPreparation(root), repaired);
  const calls = state.calls.length;
  assert.deepEqual(await prepare(root, { optIn: true, repairRuntime: true, runner, now }), repaired);
  assert.deepEqual(await prepare(root, { optIn: true, runner }), repaired);
  assert.equal(state.calls.length, calls);
}));

test('failed processor or dependency checks preserve the selection and cannot trigger another installation attempt', async () => {
  for (const failure of ['processor', 'check', 'sync']) await fixture(async ({ root, paths, original, state, runner, now }) => {
    const bytes = readFileSync(path.join(paths.base, 'preparation.sealed.json')), hash = sha256(bytes);
    mkdirSync(path.join(paths.base, 'preparations'));
    writeFileSync(path.join(paths.base, 'preparations', `${hash}.json`), bytes);
    const pointer = path.join(paths.base, 'preparation.current.json');
    writeFileSync(pointer, JSON.stringify({ schema_version: 1, receipt: `preparations/${hash}.json`, sha256: hash }));
    const pointerBytes = readFileSync(pointer), pointerInode = statSync(pointer).ino;
    state.fail = failure;
    await assert.rejects(prepare(root, { optIn: true, repairRuntime: true, runner, now }), /inert/);
    assert.deepEqual(readPreparation(root), original); assert.ok(readFileSync(pointer).equals(pointerBytes)); assert.equal(statSync(pointer).ino, pointerInode);
    const calls = state.calls.length;
    await assert.rejects(prepare(root, { optIn: true, repairRuntime: true, runner, now }), /one runtime repair attempt/);
    assert.equal(state.calls.length, calls);
    const attempts = readdirSync(path.join(paths.base, 'preparation-repairs'));
    assert.equal(attempts.length, 1);
    const result = JSON.parse(readFileSync(path.join(paths.base, 'preparation-repairs', attempts[0], 'result.json')));
    assert.equal(result.status, 'failed'); assert.equal(result.inference, false);
  });
});

test('the shared twenty-minute repair deadline prevents processor probes and activation after installation overruns', () => fixture(async ({ root, paths, original, state, runner, now }) => {
  state.expire = true;
  await assert.rejects(prepare(root, { optIn: true, repairRuntime: true, runner, now }), /20-minute runtime repair deadline/);
  assert.ok(state.calls.every(call => !call.args.some(arg => String(arg).includes('AutoProcessor'))));
  assert.deepEqual(readPreparation(root), original); assert.equal(existsSync(path.join(paths.base, 'preparation.current.json')), false);
}));

test('another repair transaction retains its lock and prevents concurrent installation', () => fixture(async ({ root, paths, state, runner, now }) => {
  const mutex = path.join(paths.base, 'preparation-repair.lock'); mkdirSync(mutex);
  await assert.rejects(prepare(root, { optIn: true, repairRuntime: true, runner, now }), /owns the private transaction lock/);
  assert.equal(state.calls.length, 0); assert.ok(existsSync(mutex));
}));

test('selection rejects path escapes, symlinks and changed immutable receipt bytes', () => fixture(async ({ root, paths, runner, now }) => {
  await prepare(root, { optIn: true, repairRuntime: true, runner, now });
  const pointerFile = path.join(paths.base, 'preparation.current.json'), pointerBytes = readFileSync(pointerFile), pointer = JSON.parse(pointerBytes);
  writeFileSync(pointerFile, JSON.stringify({ ...pointer, receipt: '../outside.json' }));
  assert.throws(() => readPreparation(root), /identity or path/);
  writeFileSync(pointerFile, pointerBytes);
  const target = path.join(paths.base, pointer.receipt), bytes = readFileSync(target);
  rmSync(target); writeFileSync(target, Buffer.concat([bytes, Buffer.from(' ')]));
  assert.throws(() => readPreparation(root), /receipt bytes changed/);
  rmSync(target); symlinkSync(path.join(paths.base, 'preparation.sealed.json'), target);
  assert.throws(() => readPreparation(root), /regular private file/);
  rmSync(target); writeFileSync(target, bytes);
  rmSync(pointerFile); symlinkSync(target, pointerFile);
  assert.throws(() => readPreparation(root), /regular private file/);
}));

test('repair requires explicit opt-in and leaves an existing unmodified environment alone during ordinary preparation', () => fixture(async ({ root, original, state, runner, now }) => {
  await assert.rejects(prepare(root, { repairRuntime: true, runner, now }), /--opt-in/);
  assert.deepEqual(await prepare(root, { optIn: true, runner }), original); assert.equal(state.calls.length, 0);
}));

test('fresh preparation includes MiniCPM vision dependencies and verifies registered native MLX processors without weights', () => fixture(async ({ root, state, runner }) => {
  assert.match(RUNTIME_REQUIREMENTS.minicpm, /torchvision==0\.29\.2/);
  assert.doesNotMatch(RUNTIME_REQUIREMENTS.mlx, /torch/);
  assert.match(RUNTIME_REQUIREMENTS.mlx, /litellm\[proxy\]==1\.109\.0\nllguidance==1\.9\.1/);
  const prepared = await prepare(root, { optIn: true, runner });
  assert.ok(prepared.runtimes.every(runtime => runtime.status === 'prepared' && runtime.preflight?.model_weights_loaded === false));
  assert.equal(prepared.models.length, 3);
  const probes = state.calls.filter(call => call.args.some(arg => String(arg).includes('AutoProcessor')));
  assert.equal(probes.length, 2);
  const mlx = probes.find(call => call.args.at(-1) === 'mlx');
  assert.match(mlx.args[3], /get_model_and_args\(config,model_path=directory\)/);
  assert.match(mlx.args[3], /from llguidance import LLMatcher,LLTokenizer,TokenizerWrapper/);
  assert.deepEqual(prepared.runtimes.find(runtime => runtime.id === 'mlx').preflight.translation, { litellm: '1.109.0', llguidance: '1.9.1' });
  assert.deepEqual(readPreparation(root), prepared);
}, { existing: false }));

test('fresh preparation blocks an unverified translator before model admission', () => fixture(async ({ root, state, runner }) => {
  state.fail = 'translation';
  const prepared = await prepare(root, { optIn: true, runner });
  const mlx = prepared.runtimes.find(runtime => runtime.id === 'mlx');
  assert.equal(mlx.status, 'blocked');
  assert.match(mlx.reason, /translation dependency preflight/);
}, { existing: false }));

test('runtime repair replaces stale translator dependencies without changing exact model bytes', () => fixture(async ({ root, paths, original, state, runner, now }) => {
  const stale = structuredClone(original);
  delete stale.runtimes.find(runtime => runtime.id === 'mlx').packages.llguidance;
  delete stale.runtimes.find(runtime => runtime.id === 'mlx').preflight;
  const originalFile = path.join(paths.base, 'preparation.sealed.json');
  writeFileSync(originalFile, JSON.stringify(stale));
  const before = readFileSync(originalFile);
  const repaired = await prepare(root, { optIn: true, repairRuntime: true, runner, now });
  assert.deepEqual(repaired.repair.replaced_runtimes, ['mlx', 'minicpm']);
  assert.deepEqual(repaired.repair.preserved_runtimes, []);
  assert.deepEqual(repaired.models, stale.models);
  assert.ok(readFileSync(originalFile).equals(before));
  assert.equal(state.calls.filter(call => call.args[0] === 'venv').length, 2);
  assert.equal(repaired.runtimes.find(runtime => runtime.id === 'mlx').preflight.translation.llguidance, '1.9.1');
  const calls = state.calls.length;
  assert.deepEqual(await prepare(root, { optIn: true, repairRuntime: true, runner, now }), repaired);
  assert.equal(state.calls.length, calls);
}));

test('acquisition retry verifies cached publisher bytes and explicit commits before publishing fresh processor and runtime evidence', () => fixture(async ({ root, paths, state, runner, now }) => {
  state.fail = 'download-metadata';
  const failed = await prepare(root, { optIn: true, runner });
  assert.ok(failed.models.every(model => model.status === 'blocked'));
  const pointerFile = path.join(paths.base, 'preparation.current.json'), priorPointer = readFileSync(pointerFile);
  const selected = JSON.parse(priorPointer), priorFile = path.join(paths.base, selected.receipt), priorBytes = readFileSync(priorFile), priorInode = statSync(priorFile).ino;
  state.fail = null; state.calls.length = 0;
  const recovered = await prepare(root, { optIn: true, retryAcquisition: true, runner, now });
  assert.ok(recovered.models.every(model => model.status === 'prepared' && model.revision === 'a'.repeat(40)));
  assert.ok(recovered.runtimes.every(runtime => runtime.status === 'prepared' && runtime.preflight.inference === false && runtime.closure.sha256));
  assert.equal(recovered.acquisition_retry.previous_receipt_sha256, selected.sha256);
  assert.equal(recovered.acquisition_retry.cache_verification.length, 3);
  assert.equal(recovered.acquisition_retry.dependency_installations, 0);
  assert.ok(readFileSync(priorFile).equals(priorBytes)); assert.equal(statSync(priorFile).ino, priorInode);
  assert.ok(!readFileSync(pointerFile).equals(priorPointer));
  assert.deepEqual(readPreparation(root), recovered);
  assert.equal(state.calls.filter(call => call.args.includes('download')).length, 3);
  assert.ok(state.calls.filter(call => call.args.includes('download')).every(call => call.args[call.args.indexOf('--revision') + 1] === 'a'.repeat(40)));
  assert.ok(state.calls.every(call => !call.args.includes('venv') && !call.args.includes('sync') && !call.args.includes('compile') && call.options.timeout <= 20 * 60_000));
  const count = state.calls.length;
  assert.deepEqual(await prepare(root, { optIn: true, retryAcquisition: true, runner, now }), recovered);
  assert.equal(state.calls.length, count);
}, { existing: false }));

test('acquisition retry rejects changed cache bytes, ambiguous commits and failed processor proof without replacing old failure evidence', async () => {
  for (const failure of ['bytes', 'revisions', 'processor']) await fixture(async ({ root, paths, state, runner, now }) => {
    state.fail = 'download-metadata'; await prepare(root, { optIn: true, runner });
    const pointerFile = path.join(paths.base, 'preparation.current.json'), priorPointer = readFileSync(pointerFile);
    const first = path.join(paths.models, MODELS[0].id);
    if (failure === 'bytes') writeFileSync(path.join(first, 'config.json'), 'tampered bytes');
    if (failure === 'revisions') writeFileSync(path.join(first, '.cache/huggingface/download/extra.metadata'), `${'b'.repeat(40)}\n${'b'.repeat(64)}\n100\n`);
    state.calls.length = 0; state.fail = failure === 'processor' ? 'processor' : null;
    await assert.rejects(prepare(root, { optIn: true, retryAcquisition: true, runner, now }), failure === 'bytes' ? /publisher digest/ : failure === 'revisions' ? /one exact immutable/ : /processor/);
    assert.ok(readFileSync(pointerFile).equals(priorPointer));
    assert.ok(readPreparation(root).models.every(model => model.status === 'blocked'));
    if (failure !== 'processor') assert.equal(state.calls.filter(call => call.args.includes('download')).length, 0);
    const calls = state.calls.length;
    await assert.rejects(prepare(root, { optIn: true, retryAcquisition: true, runner, now }), /one acquisition retry attempt/);
    assert.equal(state.calls.length, calls);
    const attempts = readdirSync(path.join(paths.base, 'acquisition-retries'));
    const result = JSON.parse(readFileSync(path.join(paths.base, 'acquisition-retries', attempts[0], 'result.json')));
    assert.equal(result.status, 'failed'); assert.equal(result.inference, false);
  }, { existing: false });
});

test('acquisition retry and dependency repair cannot be combined', () => fixture(async ({ root, state, runner }) => {
  await assert.rejects(prepare(root, { optIn: true, retryAcquisition: true, repairRuntime: true, runner }), /separate bounded transactions/);
  assert.equal(state.calls.length, 0);
}));
