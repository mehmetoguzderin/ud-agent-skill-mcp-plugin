/** Explicit, private dependency/model acquisition and immutable preparation receipts. MIT. */
import { existsSync, mkdirSync, readFileSync, readdirSync, lstatSync, statSync, writeFileSync, realpathSync, readlinkSync, renameSync, rmSync, openSync, closeSync, fsyncSync, createReadStream } from 'node:fs';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { MODELS } from './registry.mjs';
import { runOwned } from './process.mjs';
import { sha256, fileReceipt } from '../../scripts/release/candidate.mjs';

// MiniCPM's processor requires torchvision. MLX registers its own Bonsai
// processor and does not need a second tensor framework for that model.
export const RUNTIME_REQUIREMENTS = Object.freeze({
  mlx: 'mlx-vlm==0.7.11\ntransformers==5.22.2\nhuggingface-hub\nlitellm[proxy]==1.109.0\nllguidance==1.9.1\n',
  minicpm: 'transformers==5.22.2\ntorch==2.15.0\ntorchvision==0.29.2\naccelerate\nbitsandbytes==0.50.2\npillow\nhuggingface-hub\n'
});
export const RUNTIME_RECIPE_SHA256 = sha256(JSON.stringify(RUNTIME_REQUIREMENTS));
const REPAIR_LIMIT_MS = 20 * 60_000;
const PACKAGE_PROBE = 'import importlib.metadata,json;print(json.dumps({d.metadata["Name"]:d.version for d in importlib.metadata.distributions()}))';
const PROCESSOR_PROBE = `import json,sys,os,importlib.metadata
from collections.abc import Mapping
from pathlib import Path
from transformers import AutoProcessor,AutoTokenizer
results=[]
translation=None
if sys.argv[2]=='mlx':
    os.environ['LITELLM_LOCAL_MODEL_COST_MAP']='True'
    from litellm.responses.litellm_completion_transformation.transformation import LiteLLMCompletionResponsesConfig
    from litellm.google_genai.adapters.transformation import GoogleGenAIAdapter
    from litellm.llms.anthropic.messages.adapters.transformation import AnthropicAdapter
    from litellm.types.utils import ModelResponse
    from llguidance import LLMatcher,LLTokenizer,TokenizerWrapper
    translation={name:importlib.metadata.version(name) for name in ['litellm','llguidance']}
for item in json.loads(sys.argv[1]):
    if sys.argv[2]=='mlx':
        import mlx.core as mx
        mx.set_default_device(mx.cpu)
        from mlx_vlm.utils import load_config,get_model_and_args,load_processor
        directory=Path(item['directory'])
        config=load_config(directory)
        get_model_and_args(config,model_path=directory)
        processor=load_processor(directory,add_detokenizer=False,local_files_only=True)
    else:
        import torch,torchvision
        from torchvision.transforms import InterpolationMode
        processor=AutoProcessor.from_pretrained(item['directory'],trust_remote_code=True,local_files_only=True)
    tokenizer=getattr(processor,'tokenizer',None) or AutoTokenizer.from_pretrained(item['directory'],trust_remote_code=True,local_files_only=True)
    tokens=tokenizer.apply_chat_template([{'role':'user','content':'Dependency preflight.'}],tokenize=True,add_generation_prompt=True,enable_thinking=False)
    ids=tokens['input_ids'] if isinstance(tokens,Mapping) else tokens
    if not isinstance(ids,list) or not ids or any(type(value) is not int for value in ids):
        raise RuntimeError('PROCESSOR_TOKEN_SHAPE_UNVERIFIED')
    results.append({'id':item['id'],'processor':type(processor).__name__,'tokenizer':type(tokenizer).__name__,'input_tokens':len(ids)})
print(json.dumps({'inference':False,'model_weights_loaded':False,'processors':results,'translation':translation}))`;
const EXPECTED_PACKAGES = Object.freeze({
  mlx: Object.freeze({ transformers: '5.22.2', 'mlx-vlm': '0.7.11', litellm: '1.109.0', llguidance: '1.9.1' }),
  minicpm: Object.freeze({ transformers: '5.22.2', torch: '2.15.0', torchvision: '0.29.2', bitsandbytes: '0.50.2' })
});

export function assertOptIn(options, environment = process.env) {
  if (options.optIn !== true) throw new Error('Explicit --opt-in is required for model preparation or execution.');
  if (['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILD_BUILDID', 'JENKINS_URL'].some(key => environment[key] && !['false', '0'].includes(environment[key]))) throw new Error('Live local evaluation is disabled in CI.');
}
export function localPaths(root) {
  const base = path.join(root, '.artifacts/local-evals');
  return { base, runtime: path.join(base, 'runtime'), models: path.join(base, 'models'), campaigns: path.join(base, 'campaigns') };
}
export function privateEnvironment(root, profile) {
  const { base } = localPaths(root);
  return { PATH: process.env.PATH, LANG: 'en_US.UTF-8', HOME: profile, XDG_CONFIG_HOME: path.join(profile, 'config'), XDG_CACHE_HOME: path.join(profile, 'cache'), XDG_DATA_HOME: path.join(profile, 'data'),
    UV_CACHE_DIR: path.join(base, 'uv-cache'), UV_PYTHON_INSTALL_DIR: path.join(base, 'python'), HF_HOME: path.join(base, 'hf-cache'), HF_HUB_DISABLE_TELEMETRY: '1', DO_NOT_TRACK: '1', LITELLM_TELEMETRY: 'False', TOKENIZERS_PARALLELISM: 'false', PYTHONNOUSERSITE: '1', PYTHONDONTWRITEBYTECODE: '1' };
}
export function pythonPath(directory) { return path.join(directory, 'bin/python'); }
export function writeNew(file, value) {
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
function within(root, file) { return file === root || file.startsWith(root + path.sep); }
function treeInventory(directory, { allowedRoots = [directory], model = false, excludedPaths = [] } = {}) {
  if (!path.isAbsolute(directory) || !lstatSync(directory).isDirectory() || lstatSync(directory).isSymbolicLink()) throw new Error('Preparation inventory requires an actual absolute directory.');
  const records = [];
  const walk = relative => {
    const selected = relative ? path.join(directory, relative) : directory;
    for (const name of readdirSync(selected).sort()) {
      if (name === '__pycache__' || name.endsWith('.pyc') || model && name === '.cache') continue;
      const item = relative ? `${relative}/${name}` : name, file = path.join(directory, item), info = lstatSync(file);
      if (excludedPaths.includes(file)) continue;
      if (info.isSymbolicLink()) {
        if (model) throw new Error('Prepared model contains a symbolic link.');
        const target = realpathSync(file);
        if (!allowedRoots.some(root => within(root, target))) throw new Error(`Runtime symlink escapes its recorded closure: ${item}`);
        records.push({ path: item, symlink: readlinkSync(file), target });
      } else if (info.isDirectory()) walk(item);
      else if (info.isFile()) records.push(fileReceipt(directory, item));
      else throw new Error('Special file in preparation inventory.');
    }
  };
  walk('');
  if (!records.length) throw new Error('Preparation inventory is empty.');
  return records.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
}

/** Capture installed packages and the actual interpreter prefix, without changing either. */
export async function captureRuntimeClosure(root, runtime, { runner = runOwned } = {}) {
  const paths = localPaths(root), directory = realpathSync(runtime.directory), python = realpathSync(runtime.python);
  if (!within(realpathSync(paths.runtime), directory) || !within(directory, path.join(realpathSync(path.dirname(runtime.python)), path.basename(runtime.python)))) throw new Error('Runtime environment is outside the owned preparation directory.');
  const env = privateEnvironment(root, path.join(paths.base, 'prepare-home'));
  const inspected = await runner(runtime.python, ['-I', '-B', '-c', 'import sys,os,json;print(json.dumps({"prefix":os.path.realpath(sys.prefix),"base_prefix":os.path.realpath(sys.base_prefix),"executable":os.path.realpath(sys.executable),"isolated":sys.flags.isolated,"sys_path":[os.path.realpath(p) for p in sys.path]}))'], { cwd: root, env, timeout: 30_000 });
  const interpreter = JSON.parse(inspected.stdout.trim());
  if (interpreter.prefix !== directory || interpreter.executable !== python || !path.isAbsolute(interpreter.base_prefix) || !within(interpreter.base_prefix, python) || interpreter.isolated !== 1 || !Array.isArray(interpreter.sys_path) || interpreter.sys_path.some(item => !path.isAbsolute(item))) throw new Error('Interpreter prefix does not bind the selected executable.');
  const pyvenv = readFileSync(path.join(directory, 'pyvenv.cfg'), 'utf8');
  if (!/^include-system-site-packages\s*=\s*false\s*$/mi.test(pyvenv)) throw new Error('Private runtime must disable system site packages.');
  const exclusions = [];
  const library = path.join(interpreter.base_prefix, 'lib');
  if (existsSync(library)) for (const version of readdirSync(library).filter(name => /^python\d+\.\d+$/.test(name))) {
    const unused = path.join(library, version, 'site-packages');
    if (!existsSync(unused)) continue;
    const target = realpathSync(unused);
    if (interpreter.sys_path.some(item => within(unused, item) || within(target, item))) throw new Error('Global site packages are present on the private interpreter search path.');
    exclusions.push({ path: unused, target, ...(lstatSync(unused).isSymbolicLink() ? { symlink: readlinkSync(unused) } : {}), reason: 'System site packages disabled in pyvenv.cfg and absent from the isolated interpreter sys.path.' });
  }
  const allowedRoots = [directory, interpreter.base_prefix];
  const trees = [...new Set(allowedRoots)].map(directory => ({ directory, files: treeInventory(directory, { allowedRoots, excludedPaths: exclusions.map(item => item.path) }) }));
  return { schema_version: 1, scope: 'installed-environment-and-interpreter-prefix', excludes: ['generated Python bytecode', 'OS shared libraries outside the interpreter prefix'],
    interpreter: { ...interpreter, acquisition: within(paths.base, interpreter.base_prefix) ? 'owned-private-interpreter' : 'existing-readonly-interpreter' }, exclusions,
    trees, sha256: sha256(JSON.stringify(trees)) };
}

/** Preserve an older receipt and establish the first content baseline without inference. */
export async function sealPreparation(root, receipt, { runner = runOwned } = {}) {
  const paths = localPaths(root), sealedFile = path.join(paths.base, 'preparation.sealed.json');
  if (existsSync(sealedFile)) return verifyPreparation(root, JSON.parse(readFileSync(sealedFile, 'utf8')));
  if (![1, 2].includes(receipt?.schema_version) || !Array.isArray(receipt.runtimes) || !Array.isArray(receipt.models)) throw new Error('Invalid preparation receipt.');
  const originalFile = path.join(paths.base, 'preparation.json');
  const bytes = existsSync(originalFile) ? readFileSync(originalFile) : Buffer.from(JSON.stringify(receipt, null, 2) + '\n');
  if (JSON.stringify(JSON.parse(bytes)) !== JSON.stringify(receipt)) throw new Error('Preparation receipt differs from the original acquisition record.');
  const previousHash = sha256(bytes), backup = path.join(paths.base, `preparation-original-${previousHash}.json`);
  if (existsSync(backup)) { if (sha256(readFileSync(backup)) !== previousHash) throw new Error('Original preparation evidence changed.'); }
  else writeFileSync(backup, bytes, { flag: 'wx', mode: 0o400 });
  const sealed = { ...receipt, schema_version: 2, runtimes: [], seal: { kind: 'post-preparation-content-baseline', inference: false,
    original_receipt: backup, original_sha256: previousHash,
    qualification: 'Current installed bytes are recorded; this seal does not retroactively verify unrecorded original installation events.' } };
  for (const runtime of receipt.runtimes) {
    if (runtime.status !== 'prepared') { sealed.runtimes.push(runtime); continue; }
    if (sha256(readFileSync(runtime.lock)) !== runtime.lock_sha256) throw new Error('Runtime lock changed before content sealing.');
    sealed.runtimes.push({ ...runtime, closure: await captureRuntimeClosure(root, runtime, { runner }) });
  }
  verifyPreparation(root, sealed);
  writeNew(sealedFile, sealed);
  return sealed;
}

export function readPreparation(root) {
  return verifyPreparation(root, selectedPreparation(root).receipt);
}

function selectedPreparation(root) {
  const base = localPaths(root).base, pointer = path.join(base, 'preparation.current.json');
  let file, expectedHash;
  if (existsSync(pointer) || (() => { try { return lstatSync(pointer).isSymbolicLink(); } catch { return false; } })()) {
    if (!lstatSync(pointer).isFile() || lstatSync(pointer).isSymbolicLink()) throw new Error('Preparation selection must be a regular private file.');
    const selected = JSON.parse(readFileSync(pointer, 'utf8'));
    if (selected.schema_version !== 1 || !/^[a-f0-9]{64}$/.test(selected.sha256 ?? '') || selected.receipt !== `preparations/${selected.sha256}.json`) throw new Error('Preparation selection identity or path is invalid.');
    file = path.join(base, selected.receipt); expectedHash = selected.sha256;
    const directory = path.join(base, 'preparations');
    if (lstatSync(directory).isSymbolicLink() || realpathSync(directory) !== path.join(realpathSync(base), 'preparations')) throw new Error('Preparation receipt directory escapes its private root.');
  } else {
    const sealed = path.join(base, 'preparation.sealed.json');
    file = existsSync(sealed) ? sealed : path.join(base, 'preparation.json');
  }
  if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink()) throw new Error('Preparation receipt must be a regular private file.');
  const bytes = readFileSync(file), hash = sha256(bytes);
  if (expectedHash && expectedHash !== hash) throw new Error('Selected preparation receipt bytes changed.');
  return { file, bytes, sha256: hash, receipt: JSON.parse(bytes) };
}

/** Only the small selection pointer is replaceable; every referenced receipt is new. */
function publishPreparation(root, receipt, { beforeSelect } = {}) {
  const base = localPaths(root).base, directory = path.join(base, 'preparations');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (lstatSync(directory).isSymbolicLink() || realpathSync(directory) !== path.join(realpathSync(base), 'preparations')) throw new Error('Preparation receipt directory escapes its private root.');
  const bytes = Buffer.from(JSON.stringify(receipt, null, 2) + '\n'), hash = sha256(bytes), file = path.join(directory, `${hash}.json`);
  if (existsSync(file)) {
    if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink() || !readFileSync(file).equals(bytes)) throw new Error('Immutable preparation receipt collision.');
  } else writeFileSync(file, bytes, { flag: 'wx', mode: 0o400 });
  beforeSelect?.({ file, sha256: hash });
  const temporary = path.join(base, `.preparation-current-${randomUUID()}.json`), pointer = path.join(base, 'preparation.current.json');
  try {
    const descriptor = openSync(temporary, 'wx', 0o600);
    try { writeFileSync(descriptor, JSON.stringify({ schema_version: 1, receipt: `preparations/${hash}.json`, sha256: hash }) + '\n'); fsyncSync(descriptor); }
    finally { closeSync(descriptor); }
    renameSync(temporary, pointer);
  } finally { if (existsSync(temporary)) rmSync(temporary); }
  return { file, sha256: hash };
}

export function verifyPreparation(root, receipt) {
  if (![1, 2, 3].includes(receipt.schema_version) || !Array.isArray(receipt.models) || !Array.isArray(receipt.runtimes)) throw new Error('Invalid preparation receipt.');
  if (new Set(receipt.models.map(model => model.id)).size !== receipt.models.length || new Set(receipt.runtimes.map(runtime => runtime.id)).size !== receipt.runtimes.length) throw new Error('Duplicate preparation identity.');
  for (const model of receipt.models) {
    if (model.status !== 'prepared') continue;
    const expected = MODELS.find(item => item.id === model.id);
    if (!expected || expected.artifact !== model.artifact || !/^[a-f0-9]{40}$/.test(model.revision ?? '')) throw new Error('Unbound model identity.');
    if (!Array.isArray(model.files) || !model.files.length || path.resolve(model.directory) !== path.join(localPaths(root).models, model.id)) throw new Error('Model inventory is absent or outside its owned directory.');
    const actual = treeInventory(model.directory, { model: true }).map(({ path, sha256, size }) => ({ path, sha256, size }));
    if (JSON.stringify(actual) !== JSON.stringify(model.files)) throw new Error('Prepared model inventory or bytes changed.');
  }
  for (const runtime of receipt.runtimes ?? []) {
    if (runtime.status !== 'prepared') continue;
    if (sha256(readFileSync(runtime.lock)) !== runtime.lock_sha256) throw new Error('Runtime lock changed.');
    const closure = runtime.closure;
    if (closure?.schema_version !== 1 || !Array.isArray(closure.trees) || !closure.trees.length || closure.sha256 !== sha256(JSON.stringify(closure.trees))) throw new Error('Runtime content closure is missing; run explicit preparation to seal its current bytes.');
    const canonical = realpathSync(runtime.directory), allowedRoots = [canonical, closure.interpreter.base_prefix];
    if (!within(realpathSync(localPaths(root).runtime), canonical) || realpathSync(runtime.python) !== closure.interpreter.executable || closure.interpreter.prefix !== canonical || JSON.stringify(closure.trees.map(tree => tree.directory)) !== JSON.stringify([...new Set(allowedRoots)])) throw new Error('Runtime closure identity differs.');
    if (!/^include-system-site-packages\s*=\s*false\s*$/mi.test(readFileSync(path.join(canonical, 'pyvenv.cfg'), 'utf8')) || closure.interpreter.isolated !== 1 || !Array.isArray(closure.interpreter.sys_path)) throw new Error('Private interpreter isolation evidence changed.');
    const exclusions = closure.exclusions ?? [];
    for (const item of exclusions) {
      const relative = path.relative(closure.interpreter.base_prefix, item.path).split(path.sep).join('/');
      if (!/^lib\/python\d+\.\d+\/site-packages$/.test(relative) || realpathSync(item.path) !== item.target || (lstatSync(item.path).isSymbolicLink() ? readlinkSync(item.path) : undefined) !== item.symlink || closure.interpreter.sys_path.some(entry => within(item.path, entry) || within(item.target, entry))) throw new Error('Unused system site-packages exclusion is unverified.');
    }
    for (const tree of closure.trees) if (JSON.stringify(treeInventory(tree.directory, { allowedRoots, excludedPaths: exclusions.map(item => item.path) })) !== JSON.stringify(tree.files)) throw new Error('Prepared runtime package or interpreter bytes changed.');
  }
  return receipt;
}

function normalizedPackages(packages) {
  if (!packages || typeof packages !== 'object' || Array.isArray(packages)) throw new Error('Installed package metadata is missing.');
  const values = {};
  for (const [name, version] of Object.entries(packages)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || typeof version !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9.!+_-]*$/.test(version)) throw new Error('Installed package metadata contains an invalid name or version.');
    const key = name.toLowerCase().replaceAll(/[_.]+/g, '-');
    if (Object.hasOwn(values, key)) throw new Error('Installed package metadata contains a duplicate normalized name.');
    values[key] = version;
  }
  return values;
}

async function checkRuntime(root, runtime, models, { runner, env }) {
  const packages = normalizedPackages(runtime.packages);
  const expected = EXPECTED_PACKAGES[runtime.id];
  if (!expected) throw new Error('Unknown model runtime dependency recipe.');
  if (Object.entries(expected).some(([name, version]) => packages[name] !== version)) throw new Error('Installed model runtime does not match the complete pinned dependency recipe.');
  await runner('uv', ['pip', 'check', '--python', runtime.python], { cwd: root, env, timeout: 30_000 });
  const selected = models.filter(model => model.runtime_id === runtime.id);
  const required = MODELS.filter(model => (model.id === 'minicpm' ? 'minicpm' : 'mlx') === runtime.id);
  if (selected.length !== required.length || required.some(expected => !selected.some(model => model.id === expected.id && model.artifact === expected.artifact && model.status === 'prepared'))) throw new Error('Exact processor assets are unavailable for the runtime dependency check.');
  const probed = await runner(runtime.python, ['-I', '-B', '-c', PROCESSOR_PROBE, JSON.stringify(selected.map(({ id, directory }) => ({ id, directory }))), runtime.id], {
    cwd: root, env: { ...env, HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1' }, timeout: 120_000
  });
  const preflight = JSON.parse(probed.stdout.trim().split('\n').at(-1));
  if (preflight.inference !== false || preflight.model_weights_loaded !== false || !Array.isArray(preflight.processors) ||
      preflight.processors.length !== selected.length || selected.some(model => !preflight.processors.some(item => item.id === model.id && typeof item.processor === 'string' && typeof item.tokenizer === 'string' && Number.isSafeInteger(item.input_tokens) && item.input_tokens > 0))) throw new Error('Exact processor dependency preflight was not verified.');
  if (runtime.id === 'mlx' && (preflight.translation?.litellm !== expected.litellm || preflight.translation?.llguidance !== expected.llguidance)) throw new Error('Exact translation dependency preflight was not verified.');
  return preflight;
}

/** One bounded dependency repair; old environments, model bytes and receipts stay intact. */
export async function repairPreparation(root, { optIn, onProgress = () => {}, runner = runOwned, now = Date.now } = {}) {
  assertOptIn({ optIn });
  const deadline = now() + REPAIR_LIMIT_MS, paths = localPaths(root), selected = selectedPreparation(root);
  const previous = verifyPreparation(root, selected.receipt);
  const matchesRecipe = id => {
    const runtime = previous.runtimes.find(item => item.id === id);
    return runtime?.status === 'prepared' && runtime.preflight?.inference === false &&
      (id !== 'mlx' || runtime.preflight?.translation?.litellm === EXPECTED_PACKAGES.mlx.litellm && runtime.preflight?.translation?.llguidance === EXPECTED_PACKAGES.mlx.llguidance) &&
      Object.entries(EXPECTED_PACKAGES[id]).every(([name, version]) => normalizedPackages(runtime.packages)[name] === version);
  };
  if (previous.dependency_recipe_sha256 === RUNTIME_RECIPE_SHA256 && Object.keys(EXPECTED_PACKAGES).every(matchesRecipe) && previous.runtimes.every(runtime => runtime.preflight?.inference === false)) return previous;
  const replaced = Object.keys(EXPECTED_PACKAGES).filter(id => !matchesRecipe(id));
  // A legacy recipe may have the right versions but lack the processor proof.
  if (!replaced.length) replaced.push('minicpm');
  if (MODELS.some(expected => !previous.models.some(model => model.id === expected.id && model.artifact === expected.artifact && model.status === 'prepared'))) throw new Error('Runtime repair requires the existing exact prepared model inventories; it does not download or replace weights.');
  const id = sha256(JSON.stringify({ previous_receipt: selected.sha256, recipe: RUNTIME_RECIPE_SHA256 }));
  const repairs = path.join(paths.base, 'preparation-repairs'), directory = path.join(repairs, id), mutex = path.join(paths.base, 'preparation-repair.lock');
  mkdirSync(repairs, { recursive: true, mode: 0o700 });
  try { mkdirSync(mutex, { mode: 0o700 }); } catch (error) { if (error.code === 'EEXIST') throw new Error('Another preparation repair owns the private transaction lock.'); throw error; }
  const attemptFile = path.join(directory, 'attempt.json'), resultFile = path.join(directory, 'result.json');
  const checkDeadline = () => { if (now() >= deadline) throw new Error('The 20-minute runtime repair deadline was reached.'); };
  const env = privateEnvironment(root, path.join(paths.base, 'prepare-home'));
  mkdirSync(env.HOME, { recursive: true, mode: 0o700 });
  const boundedRunner = async (command, args, options = {}) => {
    checkDeadline();
    const result = await runner(command, args, { ...options, timeout: Math.min(options.timeout ?? 90_000, deadline - now()), log: path.join(directory, 'preparation.log') });
    checkDeadline(); return result;
  };
  try {
    if (existsSync(attemptFile)) {
      // A completed, verified preparation can finish an interrupted pointer
      // publication without installing again. Failed/incomplete attempts cannot.
      const result = existsSync(resultFile) ? JSON.parse(readFileSync(resultFile, 'utf8')) : null;
      if (result?.status !== 'prepared' || result.previous_receipt_sha256 !== selected.sha256 || result.recipe_sha256 !== RUNTIME_RECIPE_SHA256 || !/^[a-f0-9]{64}$/.test(result.receipt_sha256 ?? '')) throw new Error(`This receipt and recipe already used their one runtime repair attempt: ${result?.reason ?? 'incomplete attempt; no automatic retry'}`);
      const file = path.join(paths.base, 'preparations', `${result.receipt_sha256}.json`), bytes = readFileSync(file);
      if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink() || sha256(bytes) !== result.receipt_sha256) throw new Error('Prepared repair receipt changed before selection.');
      const recovered = verifyPreparation(root, JSON.parse(bytes));
      if (recovered.repair?.previous_receipt_sha256 !== selected.sha256 || recovered.dependency_recipe_sha256 !== RUNTIME_RECIPE_SHA256) throw new Error('Prepared repair lineage differs.');
      checkDeadline(); publishPreparation(root, recovered); return recovered;
    }
    mkdirSync(directory, { mode: 0o700 });
    writeNew(attemptFile, { schema_version: 1, id, started_at: new Date(now()).toISOString(), deadline, maximum_attempts: 1, inference: false,
      previous_receipt: selected.file, previous_receipt_sha256: selected.sha256, recipe_sha256: RUNTIME_RECIPE_SHA256 });
    const receipt = { ...previous, schema_version: 3, created_at: new Date(now()).toISOString(), dependency_recipe_sha256: RUNTIME_RECIPE_SHA256, runtimes: previous.runtimes.filter(runtime => !replaced.includes(runtime.id)),
      repair: { id, inference: false, model_weights_reused: true, replaced_runtimes: replaced, preserved_runtimes: previous.runtimes.filter(runtime => !replaced.includes(runtime.id)).map(runtime => runtime.id), previous_receipt: selected.file, previous_receipt_sha256: selected.sha256, recipe_sha256: RUNTIME_RECIPE_SHA256, attempt_directory: directory } };
    // The old seal describes the previous installation. Its immutable receipt
    // remains the lineage source; it must not label a newly installed runtime.
    delete receipt.seal;
    for (const runtimeId of replaced) {
      const requirements = RUNTIME_REQUIREMENTS[runtimeId];
      checkDeadline();
      const runtimeDirectory = path.join(paths.runtime, 'repairs', id, runtimeId), venv = path.join(runtimeDirectory, 'venv');
      mkdirSync(runtimeDirectory, { recursive: true, mode: 0o700 });
      const input = path.join(runtimeDirectory, 'requirements.in'), lock = path.join(runtimeDirectory, 'requirements.lock'), constraints = path.join(runtimeDirectory, 'previous-packages.txt');
      const prior = previous.runtimes.find(runtime => runtime.id === runtimeId);
      const pinned = prior?.packages ? normalizedPackages(prior.packages) : {};
      const text = Object.entries(pinned).filter(([name]) => !Object.hasOwn(EXPECTED_PACKAGES[runtimeId], name)).sort(([left], [right]) => left.localeCompare(right)).map(([name, version]) => `${name}==${version}`).join('\n');
      writeFileSync(input, requirements, { flag: 'wx', mode: 0o600 }); writeFileSync(constraints, text + '\n', { flag: 'wx', mode: 0o600 });
      onProgress(`Preparing replacement private ${runtimeId} runtime; prior environment preserved`);
      await boundedRunner('uv', ['venv', '--python', '3.12', venv], { cwd: root, env, timeout: 180_000 });
      await boundedRunner('uv', ['pip', 'compile', '--python', pythonPath(venv), '--generate-hashes', '--constraint', constraints, '--output-file', lock, input], { cwd: root, env, timeout: 240_000 });
      await boundedRunner('uv', ['pip', 'sync', '--python', pythonPath(venv), '--require-hashes', lock], { cwd: root, env, timeout: 600_000 });
      const installed = await boundedRunner(pythonPath(venv), ['-I', '-B', '-c', PACKAGE_PROBE], { cwd: root, env, timeout: 30_000 });
      const runtime = { id: runtimeId, status: 'prepared', directory: venv, python: pythonPath(venv), lock, lock_sha256: sha256(readFileSync(lock)), packages: JSON.parse(installed.stdout.trim()) };
      runtime.preflight = await checkRuntime(root, runtime, previous.models, { runner: boundedRunner, env });
      runtime.closure = await captureRuntimeClosure(root, runtime, { runner: boundedRunner });
      receipt.runtimes.push(runtime);
    }
    checkDeadline(); verifyPreparation(root, receipt); checkDeadline();
    if (selectedPreparation(root).sha256 !== selected.sha256) throw new Error('Preparation selection changed during the repair.');
    publishPreparation(root, receipt, { beforeSelect: published => {
      checkDeadline();
      writeNew(resultFile, { schema_version: 1, status: 'prepared', inference: false, previous_receipt_sha256: selected.sha256,
        recipe_sha256: RUNTIME_RECIPE_SHA256, receipt_sha256: published.sha256, completed_at: new Date(now()).toISOString() });
    } });
    return receipt;
  } catch (error) {
    if (existsSync(attemptFile) && !existsSync(resultFile)) writeNew(resultFile, { schema_version: 1, status: 'failed', inference: false, previous_receipt_sha256: selected.sha256,
      recipe_sha256: RUNTIME_RECIPE_SHA256, reason: error.message, completed_at: new Date(now()).toISOString() });
    throw error;
  } finally { rmSync(mutex, { recursive: true }); }
}

/** Recover only complete, publisher-bound cached files; never infer a revision from main. */
async function cachedAcquisition(root, model, checkDeadline) {
  const directory = path.join(localPaths(root).models, model.id);
  const cache = path.join(directory, '.cache/huggingface/download'), metadata = [];
  const owned = (file, type) => {
    const info = lstatSync(file);
    if (info.isSymbolicLink() || !info[type]() || realpathSync(file) !== path.join(realpathSync(localPaths(root).base), path.relative(localPaths(root).base, file))) throw new Error('Cached acquisition path is not an actual owned file or directory.');
    return info;
  };
  owned(directory, 'isDirectory'); owned(cache, 'isDirectory');
  const walk = relative => {
    for (const name of readdirSync(path.join(cache, relative)).sort()) {
      checkDeadline();
      const item = path.join(relative, name), file = path.join(cache, item), info = lstatSync(file);
      if (info.isSymbolicLink()) throw new Error('Cached acquisition metadata contains a symbolic link.');
      if (info.isDirectory()) { owned(file, 'isDirectory'); walk(item); }
      else if (info.isFile() && name.endsWith('.metadata')) {
        if (info.size > 4096 || metadata.length >= 1000) throw new Error('Cached acquisition metadata exceeds its bounded inventory.');
        const lines = readFileSync(file, 'utf8').trim().split('\n');
        if (!/^[a-f0-9]{40}$/.test(lines[0] ?? '') || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(lines[1] ?? '')) throw new Error('Cached acquisition revision or publisher digest is invalid.');
        metadata.push({ path: item.slice(0, -'.metadata'.length).split(path.sep).join('/'), revision: lines[0], etag: lines[1], metadata_sha256: sha256(readFileSync(file)) });
      } else if (!info.isFile()) throw new Error('Special file in cached acquisition metadata.');
    }
  };
  walk('');
  const revisions = [...new Set(metadata.map(item => item.revision))];
  if (revisions.length !== 1 || !metadata.length) throw new Error('Cached acquisition does not bind one exact immutable model revision.');
  const files = [];
  for (const item of metadata) {
    checkDeadline();
    const file = path.join(directory, item.path), info = owned(file, 'isFile');
    const digest = createHash('sha256'), publisher = item.etag.length === 40 ? createHash('sha1').update(`blob ${info.size}\0`) : null;
    for await (const bytes of createReadStream(file)) { checkDeadline(); digest.update(bytes); publisher?.update(bytes); }
    const hash = digest.digest('hex');
    if ((publisher ? publisher.digest('hex') : hash) !== item.etag) throw new Error('Cached model bytes differ from the recorded publisher digest.');
    files.push({ path: item.path, sha256: hash, size: info.size });
  }
  files.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  return { revision: revisions[0], directory, files, metadata };
}

/** One bounded retry per failed receipt/helper/recipe; no dependency reinstall or inference. */
export async function retryAcquisition(root, { optIn, onProgress = () => {}, runner = runOwned, now = Date.now } = {}) {
  assertOptIn({ optIn });
  const paths = localPaths(root), selected = selectedPreparation(root), previous = verifyPreparation(root, selected.receipt);
  if (MODELS.every(model => previous.models.some(item => item.id === model.id && item.status === 'prepared')) && Object.keys(EXPECTED_PACKAGES).every(id => previous.runtimes.some(item => item.id === id && item.status === 'prepared' && item.preflight?.inference === false))) return previous;
  const helper = path.join(root, 'evals/local/runtime.py'), helperHash = sha256(readFileSync(helper));
  if (!lstatSync(helper).isFile() || lstatSync(helper).isSymbolicLink()) throw new Error('Acquisition helper must be an actual source file.');
  const id = sha256(JSON.stringify({ previous_receipt: selected.sha256, helper_sha256: helperHash, recipe_sha256: RUNTIME_RECIPE_SHA256 }));
  const retries = path.join(paths.base, 'acquisition-retries'), directory = path.join(retries, id), mutex = path.join(paths.base, 'preparation-repair.lock');
  mkdirSync(retries, { recursive: true, mode: 0o700 });
  if (realpathSync(retries) !== path.join(realpathSync(paths.base), 'acquisition-retries')) throw new Error('Acquisition retry directory escapes its private root.');
  try { mkdirSync(mutex, { mode: 0o700 }); } catch (error) { if (error.code === 'EEXIST') throw new Error('Another preparation repair owns the private transaction lock.'); throw error; }
  const deadline = now() + REPAIR_LIMIT_MS, attemptFile = path.join(directory, 'attempt.json'), resultFile = path.join(directory, 'result.json');
  const checkDeadline = () => { if (now() >= deadline) throw new Error('The 20-minute acquisition retry deadline was reached.'); };
  const env = privateEnvironment(root, path.join(paths.base, 'prepare-home'));
  const boundedRunner = async (command, args, options = {}) => {
    checkDeadline();
    if (sha256(readFileSync(helper)) !== helperHash) throw new Error('Acquisition helper changed during its bounded retry.');
    const result = await runner(command, args, { ...options, timeout: Math.min(options.timeout ?? 90_000, deadline - now()), log: path.join(directory, 'preparation.log') });
    checkDeadline(); return result;
  };
  const lineage = { previous_receipt_sha256: selected.sha256, helper_sha256: helperHash, recipe_sha256: RUNTIME_RECIPE_SHA256 };
  try {
    if (existsSync(attemptFile)) {
      const result = existsSync(resultFile) ? JSON.parse(readFileSync(resultFile, 'utf8')) : null;
      if (result?.status !== 'prepared' || Object.entries(lineage).some(([key, value]) => result[key] !== value) || !/^[a-f0-9]{64}$/.test(result.receipt_sha256 ?? '')) throw new Error('This receipt, helper and recipe already used their one acquisition retry attempt.');
      const file = path.join(paths.base, 'preparations', `${result.receipt_sha256}.json`), bytes = readFileSync(file);
      if (!lstatSync(file).isFile() || lstatSync(file).isSymbolicLink() || sha256(bytes) !== result.receipt_sha256) throw new Error('Recovered acquisition retry receipt changed.');
      const recovered = verifyPreparation(root, JSON.parse(bytes));
      if (Object.entries(lineage).some(([key, value]) => recovered.acquisition_retry?.[key] !== value)) throw new Error('Recovered acquisition retry lineage differs.');
      checkDeadline(); publishPreparation(root, recovered); return recovered;
    }
    mkdirSync(directory, { mode: 0o700 });
    writeNew(attemptFile, { schema_version: 1, id, started_at: new Date(now()).toISOString(), deadline, maximum_attempts: 1, inference: false, previous_receipt: selected.file, ...lineage });
    const receipt = { ...previous, schema_version: 3, created_at: new Date(now()).toISOString(), dependency_recipe_sha256: RUNTIME_RECIPE_SHA256, models: [], runtimes: [],
      acquisition_retry: { id, inference: false, dependency_installations: 0, previous_receipt: selected.file, ...lineage, attempt_directory: directory, cache_verification: [] } };
    delete receipt.seal;
    for (const runtimeId of Object.keys(EXPECTED_PACKAGES)) {
      const prior = previous.runtimes.find(runtime => runtime.id === runtimeId);
      if (!prior?.directory || !prior.python || !prior.lock || !prior.packages || sha256(readFileSync(prior.lock)) !== prior.lock_sha256) throw new Error('Acquisition retry requires the preserved private runtime and unchanged dependency lock.');
      if (!within(realpathSync(paths.runtime), realpathSync(prior.directory)) || path.resolve(prior.python) !== path.join(path.resolve(prior.directory), 'bin/python')) throw new Error('Acquisition retry runtime escapes its owned environment.');
      const installed = await boundedRunner(prior.python, ['-I', '-B', '-c', PACKAGE_PROBE], { cwd: root, env, timeout: 30_000 });
      const packages = JSON.parse(installed.stdout.trim()), actual = normalizedPackages(packages), recorded = normalizedPackages(prior.packages);
      if (Object.keys(actual).length !== Object.keys(recorded).length || Object.entries(recorded).some(([name, version]) => actual[name] !== version) || Object.entries(EXPECTED_PACKAGES[runtimeId]).some(([name, version]) => actual[name] !== version)) throw new Error('Acquisition retry installed package identity differs from its preserved pinned runtime.');
      const runtime = { ...prior, status: 'prepared', packages }; delete runtime.reason; delete runtime.preflight;
      runtime.closure = await captureRuntimeClosure(root, runtime, { runner: boundedRunner });
      receipt.runtimes.push(runtime);
    }
    for (const model of MODELS) {
      const prior = previous.models.find(item => item.id === model.id);
      if (prior?.status === 'prepared') { receipt.models.push(prior); continue; }
      onProgress(`Verifying cached ${model.artifact} at its recorded immutable revision`);
      const cached = await cachedAcquisition(root, model, checkDeadline), runtime = receipt.runtimes.find(item => item.id === (model.id === 'minicpm' ? 'minicpm' : 'mlx'));
      receipt.acquisition_retry.cache_verification.push({ id: model.id, revision: cached.revision, files: cached.files, metadata: cached.metadata });
      const fetched = await boundedRunner(runtime.python, [helper, 'download', '--artifact', model.artifact, '--directory', cached.directory, '--revision', cached.revision], { cwd: root, env, timeout: 600_000 });
      const value = JSON.parse(fetched.stdout.trim().split('\n').at(-1));
      if (value.artifact !== model.artifact || value.revision !== cached.revision || JSON.stringify(value.files) !== JSON.stringify(cached.files)) throw new Error('Retried model acquisition differs from its verified cached immutable artifact.');
      receipt.models.push({ ...value, id: model.id, status: 'prepared', directory: cached.directory, runtime_id: runtime.id });
    }
    for (const runtime of receipt.runtimes) {
      runtime.preflight = await checkRuntime(root, runtime, receipt.models, { runner: boundedRunner, env });
      runtime.closure = await captureRuntimeClosure(root, runtime, { runner: boundedRunner });
    }
    checkDeadline(); verifyPreparation(root, receipt); checkDeadline();
    if (sha256(readFileSync(helper)) !== helperHash || selectedPreparation(root).sha256 !== selected.sha256) throw new Error('Preparation selection or acquisition helper changed during retry.');
    publishPreparation(root, receipt, { beforeSelect: published => {
      checkDeadline(); writeNew(resultFile, { schema_version: 1, status: 'prepared', inference: false, ...lineage, receipt_sha256: published.sha256, completed_at: new Date(now()).toISOString() });
    } });
    return receipt;
  } catch (error) {
    if (existsSync(attemptFile) && !existsSync(resultFile)) writeNew(resultFile, { schema_version: 1, status: 'failed', inference: false, ...lineage, reason: error.message, completed_at: new Date(now()).toISOString() });
    throw error;
  } finally { rmSync(mutex, { recursive: true }); }
}

export async function prepare(root, { optIn, repairRuntime = false, retryAcquisition: retry = false, onProgress = () => {}, runner = runOwned, now = Date.now } = {}) {
  assertOptIn({ optIn });
  const paths = localPaths(root); mkdirSync(paths.base, { recursive: true, mode: 0o700 });
  if (repairRuntime && retry) throw new Error('Runtime repair and acquisition retry are separate bounded transactions.');
  if (retry) return retryAcquisition(root, { optIn, onProgress, runner, now });
  if (repairRuntime) return repairPreparation(root, { optIn, onProgress, runner, now });
  const receiptPath = path.join(paths.base, 'preparation.json');
  if (existsSync(path.join(paths.base, 'preparation.current.json'))) return readPreparation(root);
  if (existsSync(path.join(paths.base, 'preparation.sealed.json'))) return readPreparation(root);
  if (existsSync(receiptPath)) return sealPreparation(root, JSON.parse(readFileSync(receiptPath)), { runner });
  const env = privateEnvironment(root, path.join(paths.base, 'prepare-home'));
  mkdirSync(env.HOME, { recursive: true, mode: 0o700 });
  const receipt = { schema_version: 1, created_at: new Date().toISOString(), dependency_recipe_sha256: RUNTIME_RECIPE_SHA256, host: { platform: process.platform, architecture: process.arch }, runtimes: [], models: [] };
  for (const [id, text] of Object.entries(RUNTIME_REQUIREMENTS)) {
    const directory = path.join(paths.runtime, id), venv = path.join(directory, 'venv');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const input = path.join(directory, 'requirements.in'), lock = path.join(directory, 'requirements.lock');
    writeFileSync(input, text, { mode: 0o600 });
    onProgress(`Preparing private ${id} runtime`);
    try {
      await runner('uv', ['venv', '--python', '3.12', venv], { cwd: root, env, timeout: 180_000 });
      await runner('uv', ['pip', 'compile', '--python', pythonPath(venv), '--generate-hashes', '--output-file', lock, input], { cwd: root, env, timeout: 240_000 });
      await runner('uv', ['pip', 'sync', '--python', pythonPath(venv), '--require-hashes', lock], { cwd: root, env, timeout: 600_000 });
      const versions = await runner(pythonPath(venv), ['-I', '-B', '-c', PACKAGE_PROBE], { cwd: root, env });
      receipt.runtimes.push({ id, status: 'prepared', directory: venv, python: pythonPath(venv), lock, lock_sha256: sha256(readFileSync(lock)), packages: JSON.parse(versions.stdout) });
    } catch (error) { receipt.runtimes.push({ id, status: 'blocked', reason: error.message }); }
  }
  for (const model of MODELS) {
    const runtime = receipt.runtimes.find(item => item.id === (model.id === 'minicpm' ? 'minicpm' : 'mlx'));
    const directory = path.join(paths.models, model.id);
    if (runtime.status !== 'prepared') { receipt.models.push({ id: model.id, artifact: model.artifact, status: 'blocked', reason: runtime.reason }); continue; }
    onProgress(`Fetching exact ${model.artifact} artifact`);
    try {
      const result = await runner(runtime.python, [path.join(root, 'evals/local/runtime.py'), 'download', '--artifact', model.artifact, '--directory', directory], { cwd: root, env, timeout: 600_000 });
      const fetched = JSON.parse(result.stdout.trim().split('\n').at(-1));
      receipt.models.push({ id: model.id, status: 'prepared', directory, runtime_id: runtime.id, ...fetched });
    } catch (error) { receipt.models.push({ id: model.id, artifact: model.artifact, status: 'blocked', reason: error.message }); }
  }
  for (const runtime of receipt.runtimes) {
    if (runtime.status !== 'prepared') continue;
    try { runtime.preflight = await checkRuntime(root, runtime, receipt.models, { runner, env }); }
    catch (error) { runtime.status = 'blocked'; runtime.reason = error.message; }
  }
  writeNew(receiptPath, receipt);
  const sealed = await sealPreparation(root, receipt, { runner });
  publishPreparation(root, sealed);
  return sealed;
}

export function executable(name, searchPath = process.env.PATH ?? '') {
  if (path.isAbsolute(name)) return existsSync(name) && lstatSync(name).isFile() ? name : null;
  for (const directory of searchPath.split(path.delimiter).filter(path.isAbsolute)) {
    const file = path.join(directory, name);
    if (existsSync(file) && statSync(file).isFile() && (statSync(file).mode & 0o111)) return file;
  }
  return null;
}
