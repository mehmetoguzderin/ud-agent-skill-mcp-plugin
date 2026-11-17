import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, symlinkSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const fake = vi.hoisted(() => ({ starts: [], requests: [], stopReasons: [], model: '', mini: false, image: false, mismatch: false, extendedFails: false, loadFails: false, semanticsFail: false, messages: false }));
vi.mock('node:net', () => ({ default: { createServer() {
  const server = { once() { return server; }, listen(_port, _host, ready) { ready(); }, address() { return { port: 18743 }; }, close(done) { done(); } };
  return server;
} } }));
vi.mock('../../evals/local/process.mjs', () => ({
  startOwned(command, args, options) {
    fake.starts.push({ command, args, options });
    let resolve;
    const done = new Promise(value => { resolve = value; });
    const server = args[0] === '-m' || (args[0].endsWith('minicpm_server.py') || args[0].endsWith('mlx_server.py')) || args[0].endsWith('translation.py');
    const owned = { child: { pid: 2147483000, stdin: { end(input) {
      if (server) { if (fake.loadFails) resolve({ code: 1, cleanupVerified: true, stderr: 'exact NF4 backend unavailable' }); return; }
      if (fake.hangHelper && (fake.hangHelper === 'schemas' && args[0] === '-I' || fake.hangHelper === 'tokenize' && args.includes('tokenize'))) { fake.onHelper?.(); return; }
      if (args[0] === '-I') { resolve({ code: 0, cleanupVerified: true, stdout: JSON.stringify({ origin: 'installed-pydantic-model', version: '0.7.11', chat: schema().components.schemas.Chat, responses: { properties: { ...schema().components.schemas.Chat.properties, input: {} } }, responses_seed_forwarded: true, messages: schema().components.schemas.Chat, messages_extra_forwarded: ['seed'], sources: [], cache_config: { apc_enabled: true, apc_disk_enabled: false, apc_memory_max_gb: 1, apc_memory_reserve_gb: 2, apc_block_size: 16, apc_num_blocks: 2048, apc_checkpoint_entries: 2, apc_checkpoint_interval_tokens: 2048, apc_checkpoint_guard_tokens: 1, hash: fake.cacheConfigMismatch ? 'fast' : 'sha256' }, cache_sources: [0, 1, 2].map(i => ({ path: '/inert/pinned-source-' + i, sha256: 'a'.repeat(64) })) }) }); return; }
      if (args.includes('load-minicpm')) { resolve(fake.loadFails ? { code: 1, cleanupVerified: true, stderr: 'exact NF4 backend unavailable' } : { code: 0, cleanupVerified: true, stdout: '{"loaded":true}' }); return; }
      const body = JSON.parse(input);
      if (!fake.image && body.messages.some(message => Array.isArray(message.content))) { resolve({ code: 1, cleanupVerified: true, stderr: 'PROCESSOR_TOKEN_ACCOUNTING_UNSUPPORTED' }); return; }
      const count = Math.ceil(JSON.stringify(body.messages).length / 4) + Math.ceil(JSON.stringify(body.tools ?? []).length / 4);
      resolve({ code: 0, cleanupVerified: true, stdout: JSON.stringify({ exact: true, inputTokens: count, contextTokens: count }) });
    } } }, done, async stop(reason) { fake.stopReasons.push(reason); resolve({ code: null, signal: 'SIGTERM', cleanupVerified: true }); return done; } };
    options.signal?.addEventListener('abort', () => { void owned.stop('cancelled'); }, { once: true });
    return owned;
  },
}));

import { admitModel, servingProfile, resetMlxConversationCache, managementErrorObservation, MLX_CACHE_POLICY, verifyLoadedRuntimeIdentity } from '../../evals/local/serving.mjs';
import { MODELS } from '../../evals/local/registry.mjs';
import { captureRuntimeClosure, sealPreparation, verifyPreparation, localPaths, readPreparation } from '../../evals/local/preparation.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

function schema() {
  const properties = Object.fromEntries(['model', 'messages', 'tools', 'seed', 'enable_thinking', 'temperature', 'top_p', 'top_k', 'repetition_penalty', 'presence_penalty', 'min_p', 'top_n_sigma', 'p_less', 'typical_p', 'frequency_penalty', 'repetition_context_size', 'presence_context_size', 'frequency_context_size'].map(name => [name, { default: null }]));
  Object.assign(properties, { min_p: { default: 0 }, top_n_sigma: { default: 0 }, p_less: { default: false }, typical_p: { default: 1 } });
  return { paths: { '/v1/cache/reset': { post: {} }, '/v1/cache/stats': { get: {} }, '/metrics': { get: {} }, '/v1/chat/completions': { post: { requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Chat' } } } } } } }, components: { schemas: { Chat: { properties } } } };
}
function loadedIdentity() {
  const source = { module: 'inert.module', name: 'LoadedClass', sha256: 'a'.repeat(64) };
  const common = { schema_version: 1, model_loaded: true, model: fake.model, files: { 'config.json': sha256(readFileSync(path.join(fake.model, 'config.json'))) },
    model_class: { ...source, module: 'mlx_vlm.models.lfm3_vl.model' }, processor_class: source, parameter_dtypes: ['float16'] };
  return fake.mini ? { ...common, runtime: 'transformers-bitsandbytes', packages: { torch: '2.15.0', transformers: '5.22.2', bitsandbytes: '0.50.2' },
    loader: 'transformers.AutoModelForImageTextToText.from_pretrained', device: 'mps', parameter_devices: ['mps:0'],
    quantization: { format: 'bitsandbytes-nf4', linear_modules: 20 }, quantized_class: source, image_processor_class: source }
    : { ...common, runtime: 'mlx-vlm', packages: { mlx: '0.31.2', 'mlx-vlm': '0.7.11' },
      loader: { ...source, sha256: '7d19bafb1fcd8d0427572920d545130deabd024c3483f240bdcb0cf7b2ddcd1a' },
      device: 'gpu', model_type: 'lfm3_vl', parameter_storage_bytes: 1024, quantization: { format: 'mlx-5bit', quantized_modules: 10, module_bits: [5] } };
}
function installFetch() {
  vi.stubGlobal('fetch', vi.fn(async (url, options) => {
    if (url.endsWith('/local-eval/runtime-identity')) return Response.json({ ...loadedIdentity(), ...(fake.identityOverride ?? {}) });
    if (url.endsWith('/health')) return Response.json({ status: 'ok', litellm: '1.109.0', llguidance: '1.9.1', model: fake.model });
    if (url.endsWith('/v1/models')) return Response.json({ data: [{ id: fake.model }] });
    if (url.endsWith('/v1/metrics')) return Response.json({ summary: { in_flight: 0, requests_started: fake.requests.length, requests_completed: fake.requests.length, requests_failed: 0 }, server: { loaded_model: fake.model, request_queue_depth: 0, audio_queue_depth: 0, apc: { enabled: true } } });
    if (url.endsWith('/v1/cache/reset')) return Response.json({ enabled: true, status: 'cleared' });
    if (url.endsWith('/v1/cache/stats')) return Response.json({ enabled: true, resident_bytes: fake.cacheResidue ? 1 : 0, exact_resident_bytes: 0, pool_used: 0, memory_max_bytes: 1024 ** 3, block_size: 16, num_blocks: 2048, disk_writes: 0 });
    if (url.endsWith('/openapi.json')) { const document = schema(); if (fake.mini) document.paths['/chat/input_tokens'] = { post: {} }; if (fake.messages) { document.paths['/messages'] = { post: {} }; document.paths['/messages/count_tokens'] = { post: {} }; } return Response.json(document); }
    const body = JSON.parse(options.body);
    if (url.endsWith('/chat/input_tokens')) return Response.json({ trusted: true, input_tokens: Math.ceil(JSON.stringify(body.messages).length / 4) + Math.ceil(JSON.stringify(body.tools ?? []).length / 4) });
    if (url.endsWith('/messages/count_tokens')) return Response.json({ input_tokens: 231 });
    if (url.endsWith('/local-eval/transform')) return Response.json({ body: { model: fake.model, messages: [{ role: 'user', content: 'translated native request' }], max_tokens: 128, seed: body.body.seed } });
    fake.requests.push(body);
    if (body.stream) return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('data: {"choices":[{"delta":{"content":"1"}}]}\n\n')); } }), { headers: { 'content-type': 'text/event-stream' } });
    const tokens = Math.ceil(JSON.stringify(body.messages).length / 4) + Math.ceil(JSON.stringify(body.tools ?? []).length / 4);
    if (fake.extendedFails && tokens > 20_000) return Response.json({ error: 'context limit' }, { status: 400 });
    const image = body.messages.some(message => Array.isArray(message.content));
    const continued = body.messages.some(message => message.role === 'tool');
    const message = fake.semanticsFail ? { role: 'assistant', content: 'I cannot perform that task.' } : image ? { role: 'assistant', content: 'obj' } : continued ? { role: 'assistant', content: 'CALIBRATION_OK' } : { role: 'assistant', content: null, tool_calls: [{ id: 'call-calibration', type: 'function', function: { name: 'calibration_echo', arguments: '{"value":"ready"}' } }] };
    return Response.json({ model: fake.model, choices: [{ message, finish_reason: message.tool_calls ? 'tool_calls' : 'stop' }], usage: { prompt_tokens: tokens + (fake.mismatch ? 1 : 0), completion_tokens: 20 } });
  }));
}
async function temporary(run) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-serving-'));
  Object.assign(fake, { starts: [], requests: [], stopReasons: [], model: path.join(root, 'models/lfm3'), mini: false, image: false, mismatch: false, extendedFails: false, loadFails: false, semanticsFail: false, messages: false, cacheConfigMismatch: false, cacheResidue: false, hangHelper: null, onHelper: null, identityOverride: null });
  mkdirSync(path.join(root, 'evals/local/fixtures'), { recursive: true }); writeFileSync(path.join(root, 'evals/local/fixtures/diagram.png'), 'inert-image');
  mkdirSync(fake.model, { recursive: true }); writeFileSync(path.join(fake.model, 'config.json'), JSON.stringify({ text_config: { max_position_embeddings: 262144 } }));
  const prepared = { id: 'lfm3', artifact: MODELS[1].artifact, status: 'prepared', directory: fake.model, revision: 'a'.repeat(40) };
  const runtime = { status: 'prepared', python: path.join(root, 'private/bin/python'), packages: { 'mlx-vlm': '0.7.11' }, lock_sha256: 'b'.repeat(64) };
  const options = { deadline: Date.now() + 120_000, calibration: { used: 0, maximum: 12 } };
  const originalKill = process.kill.bind(process);
  const kill = vi.spyOn(process, 'kill').mockImplementation((pid, signal) => {
    if (Math.abs(pid) === 2147483000) throw Object.assign(new Error('Inert owned process has exited.'), { code: 'ESRCH' });
    return originalKill(pid, signal);
  });
  installFetch();
  try { await run({ root, prepared, runtime, options }); } finally { kill.mockRestore(); vi.unstubAllGlobals(); rmSync(root, { recursive: true, force: true }); }
}

test('server profile freezes published samplers and refuses unknown seed/default semantics', () => {
  const document = schema(), profile = servingProfile(document, MODELS[1]);
  assert.equal(profile.sampling.temperature, 0.1);
  assert.equal(profile.sampling.min_p, 0);
  assert.equal(profile.sampling.enable_thinking, false);
  assert.equal(profile.sampling.presence_penalty, null);
  delete document.components.schemas.Chat.properties.seed;
  assert.throws(() => servingProfile(document, MODELS[1]), /SERVER_FIELD_UNVERIFIED:seed/);
  const missingDefault = schema(); delete missingDefault.components.schemas.Chat.properties.min_p;
  assert.throws(() => servingProfile(missingDefault, MODELS[1]), /SERVER_DEFAULT_UNVERIFIED:min_p/);
});

test('inert MLX admission verifies real wire counts, one-model loopback binding, contexts and owned cancellation', () => temporary(async ({ root, prepared, runtime, options }) => {
  const result = await admitModel(root, prepared, runtime, options);
  assert.equal(result.status, 'admitted', result.reason);
  assert.deepEqual(result.capabilities, { text: true, tools: true, images: false, ordinary_context: true, extended_context: true, cancellation: true, protocols: ['chat'] });
  assert.equal(options.calibration.used, 3);
  assert.equal(result.wire_model, prepared.directory);
  assert.equal(result.messages_protocol.source, 'evals/local/messages_protocol.py');
  assert.equal(result.messages_protocol.sha256, sha256(readFileSync(new URL('../../evals/local/messages_protocol.py', import.meta.url))));
  assert.equal(result.messages_protocol.search_or_tool_selection, false);
  assert.ok(result.calibration_observations.context.ordinary_context_tokens <= 16384 - 512);
  assert.ok(result.calibration_observations.context.ordinary_context_tokens >= 16384 - 512 - 16);
  assert.ok(result.calibration_observations.context.extended_context_tokens <= 32768 - 512);
  assert.equal(result.calibration_observations.context.inference, false);
  const launches = fake.starts.filter(start => start.args[0].endsWith('mlx_server.py'));
  assert.equal(launches.length, 2);
  assert.ok(launches.every(start => start.args.includes('127.0.0.1') && start.args.includes(prepared.directory) && start.options.env.HF_HUB_OFFLINE === '1'));
  assert.ok(fake.requests.every(request => request.enable_thinking === false && request.max_tokens <= 512));
  assert.deepEqual(fake.requests.map(request => request.seed), [17, 17, 23]);
  const count = await result.tokenize({ protocol: 'chat', body: { messages: [{ role: 'user', content: 'hello' }] } });
  assert.equal(count.trusted, true);
  await assert.rejects(result.tokenize({ protocol: 'responses', body: {} }), /PROTOCOL_TOKEN_ACCOUNTING_UNVERIFIED/);
  const evidence = readFileSync(path.join(result.evidence_directory, 'admission.jsonl'), 'utf8');
  assert.match(evidence, /image_capability_blocked/);
  assert.match(evidence, /"requested_envelope":32768/);
  await result.stop();
  assert.ok(fake.stopReasons.includes('calibration-cancellation'));
}));

test('image admission uses processor accounting and all four requests remain globally charged', () => temporary(async ({ root, prepared, runtime, options }) => {
  fake.image = true;
  const result = await admitModel(root, prepared, runtime, options);
  assert.equal(result.status, 'admitted', result.reason);
  assert.equal(result.capabilities.images, true);
  assert.equal(options.calibration.used, 4);
  await result.stop();
}));

test('loaded object/device identity is required before calibration and admission reuse', () => temporary(async ({ root, prepared, runtime, options }) => {
  fake.identityOverride = { device: 'cpu' };
  const blocked = await admitModel(root, prepared, runtime, options);
  assert.equal(blocked.reason, 'MODEL_LOADED_MLX_IDENTITY_UNVERIFIED');
  assert.equal(options.calibration.used, 0); assert.equal(blocked.cleanup.cleanupVerified, true);
  fake.identityOverride = null;
  const admitted = await admitModel(root, prepared, runtime, options);
  assert.equal(admitted.status, 'admitted', admitted.reason);
  assert.equal(admitted.runtime_identity.device, 'gpu'); assert.match(admitted.runtime_identity.sha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(admitted.ownedProcesses(), [{ role: 'model-server', pid: 2147483000 }]);
  await admitted.stop(); assert.deepEqual(admitted.ownedProcesses(), []);
  const used = options.calibration.used;
  const changed = { ...admitted, runtime_identity: { ...admitted.runtime_identity, sha256: '0'.repeat(64) } };
  const reused = await admitModel(root, prepared, runtime, { ...options, reuseAdmission: changed });
  assert.equal(reused.reason, 'REUSED_ADMISSION_IDENTITY_MISMATCH'); assert.equal(options.calibration.used, used);
}));

test('prelaunch blocking records zero launches and resource rejection releases actual owned startup', () => temporary(async ({ root, prepared, runtime, options }) => {
  const absent = await admitModel(root, { ...prepared, status: 'failed', reason: 'artifact acquisition failed' }, runtime, options);
  assert.deepEqual(absent.cleanup, { stopped: true, cleanupVerified: true, launches: 0, no_owned_processes_launched: true, evidence_kind: 'prelaunch-control-flow' });
  assert.equal(fake.starts.length, 0);
  const seen = [];
  const blocked = await admitModel(root, prepared, runtime, { ...options, observeResources: async observation => {
    seen.push({ stage: observation.stage, processes: observation.processes });
    if (observation.processes.length) throw new Error('RESOURCE_MEMORY_BLOCKED:reserve-exhausted');
  } });
  assert.deepEqual(seen.map(row => row.stage), ['before-launch', 'server-ready']);
  assert.equal(blocked.reason, 'RESOURCE_MEMORY_BLOCKED:reserve-exhausted'); assert.equal(blocked.cleanup.cleanupVerified, true);
  assert.equal(options.calibration.used, 0); assert.ok(fake.stopReasons.includes('admission-failed'));
}));

test('resource monitoring interrupts an unresolved startup before calibration', () => temporary(async ({ root, prepared, runtime, options }) => {
  const previous = globalThis.fetch, stages = [];
  vi.stubGlobal('fetch', vi.fn(async (url, request) => {
    if (!url.endsWith('/health')) return previous(url, request);
    return new Promise((_resolve, reject) => request.signal.addEventListener('abort', () => reject(request.signal.reason), { once: true }));
  }));
  const blocked = await admitModel(root, prepared, runtime, { ...options, observeResources: async ({ stage, processes }) => {
    stages.push(stage);
    if (stage === 'admission-running') { assert.equal(processes[0].role, 'model-server'); throw new Error('RESOURCE_MEMORY_BLOCKED:critical-pressure'); }
  } });
  assert.deepEqual(stages, ['before-launch', 'admission-running']); assert.equal(blocked.reason, 'RESOURCE_MEMORY_BLOCKED:critical-pressure');
  assert.equal(blocked.cleanup.cleanupVerified, true); assert.equal(options.calibration.used, 0);
}));

test('Bonsai admission requires observed specialized Hadamard modules and pinned transform implementation', () => temporary(async ({ prepared, runtime }) => {
  const exact = { ...prepared, id: 'bonsai', artifact: MODELS[2].artifact }, basic = loadedIdentity();
  const identity = { ...basic, model_type: 'prism_hadamard_qwen35', model_class: { ...basic.model_class, module: 'mlx_vlm.models.prism_hadamard_qwen35.model' },
    quantization: { format: 'mlx-2bit', quantized_modules: 10, module_bits: [2] } };
  assert.throws(() => verifyLoadedRuntimeIdentity(identity, MODELS[2], exact, runtime), /MODEL_LOADED_BONSAI_TRANSFORM_UNVERIFIED/);
  identity.quantization.hadamard = { verified_modules: 10, rotated_modules: 8, modules_sha256: 'a'.repeat(64),
    implementation: { module: 'mlx_vlm.models.prism_hadamard_qwen35.model', name: 'HadamardQuantizedLinear', sha256: '4336633e333f9e744b526463a8eff1a3d99f1843da29031fb058f5d52ec4a681' } };
  assert.equal(verifyLoadedRuntimeIdentity(identity, MODELS[2], exact, runtime).device, 'gpu');
  identity.quantization.hadamard.implementation.sha256 = '0'.repeat(64);
  assert.throws(() => verifyLoadedRuntimeIdentity(identity, MODELS[2], exact, runtime), /MODEL_LOADED_BONSAI_TRANSFORM_UNVERIFIED/);
}));

test('semantic calibration failures remain observations and cannot block mechanically valid native workflows', () => temporary(async ({ root, prepared, runtime, options }) => {
  fake.image = true; fake.semanticsFail = true;
  const result = await admitModel(root, prepared, runtime, options);
  assert.equal(result.status, 'admitted', result.reason);
  assert.equal(result.admission_kind, 'mechanical');
  assert.equal(result.capabilities.tools, false);
  assert.equal(result.calibration_observations.tool_call.observed, false);
  assert.equal(result.capabilities.images, true);
  assert.equal(result.calibration_observations.image.semantic_verification, 'deferred-to-independent-S5-oracle');
  assert.equal(options.calibration.used, 4);
  assert.ok(JSON.stringify(fake.requests[0]).length < 2048, 'initial admission must not be a padded long-context benchmark');
  assert.ok(fake.requests[1].messages.some(message => message.role === 'tool' && message.tool_call_id === 'calibration-fixture'));
  assert.match(readFileSync(path.join(result.evidence_directory, 'admission.jsonl'), 'utf8'), /independent-inert-protocol-fixture/);
  await result.stop();
  const reused = await admitModel(root, prepared, runtime, { ...options, reuseAdmission: result });
  assert.equal(reused.status, 'admitted', reused.reason);
  assert.equal(reused.capabilities.tools, false);
  assert.equal(options.calibration.used, 4);
  await reused.stop();
}));

test('verified native Messages routes expose exact full-request counting without another generation', () => temporary(async ({ root, prepared, runtime, options }) => {
  fake.messages = true;
  const result = await admitModel(root, prepared, runtime, options);
  assert.equal(result.status, 'admitted', result.reason);
  assert.ok(result.capabilities.protocols.includes('messages'));
  const used = options.calibration.used;
  assert.deepEqual(await result.tokenize({ protocol: 'messages', body: { messages: [{ role: 'user', content: 'hello' }], tools: [] } }), { trusted: true, inputTokens: 231, contextTokens: 231 });
  assert.equal(options.calibration.used, used);
  await result.stop();
}));

test('a pinned owned translation sidecar adds protocols and counts the exact transformed Chat request', () => temporary(async ({ root, prepared, runtime, options }) => {
  const translationRuntime = { ...runtime, packages: { ...runtime.packages, litellm: '1.109.0' } };
  const result = await admitModel(root, prepared, runtime, { ...options, translationRuntime });
  assert.equal(result.status, 'admitted', result.reason);
  assert.deepEqual(result.native_protocol_fields, { chat: result.protocol_fields.chat });
  assert.deepEqual(result.translation_evidence.translated_protocols, ['gemini', 'responses', 'messages']);
  assert.ok(result.protocol_fields.gemini.includes('seed'));
  const used = options.calibration.used;
  const transformed = await result.tokenize({ protocol: 'responses', body: { model: prepared.directory, input: 'hello', seed: 17 } });
  assert.equal(transformed.trusted, true);
  assert.equal(options.calibration.used, used);
  const launches = fake.starts.filter(start => start.args[0].endsWith('translation.py'));
  assert.equal(launches.length, 1);
  const configuration = JSON.parse(readFileSync(launches[0].args[2], 'utf8'));
  assert.equal(configuration.model, prepared.directory);
  assert.deepEqual(configuration.native_protocols, ['chat']);
  assert.equal(configuration.traffic, result.translation_evidence.traffic);
  await result.stop();
  const reused = await admitModel(root, prepared, runtime, { ...options, translationRuntime, reuseAdmission: result });
  assert.equal(reused.status, 'admitted', reused.reason);
  assert.equal(options.calibration.used, used);
  await reused.stop();
  const changed = await admitModel(root, prepared, runtime, { ...options, translationRuntime: { ...translationRuntime, lock_sha256: 'c'.repeat(64) }, reuseAdmission: result });
  assert.equal(changed.reason, 'REUSED_ADMISSION_IDENTITY_MISMATCH');
}));

test('an unsupported 32K tokenizer capacity retains16K without padded generation or a false extended claim', () => temporary(async ({ root, prepared, runtime, options }) => {
  writeFileSync(path.join(prepared.directory, 'config.json'), JSON.stringify({ text_config: { max_position_embeddings: 16384 } }));
  const result = await admitModel(root, prepared, runtime, options);
  assert.equal(result.status, 'admitted', result.reason);
  assert.equal(result.extended_context_envelope, null);
  assert.equal(result.context_envelope, 16384);
  assert.equal(result.capabilities.extended_context, false);
  assert.equal(options.calibration.used, 3);
  assert.ok(fake.requests.every(request => JSON.stringify(request).length < 4096));
  assert.equal(result.calibration_observations.context.inference, false);
  assert.equal(result.calibration_observations.context.enforced_extended_envelope, null);
  await result.stop();
}));

test('accounting mismatch and exhausted calibration allowance fail admission and stop owned work', () => temporary(async ({ root, prepared, runtime, options }) => {
  fake.mismatch = true;
  const mismatch = await admitModel(root, prepared, runtime, options);
  assert.equal(mismatch.status, 'context_resource_blocked');
  assert.match(mismatch.reason, /TOKEN_ACCOUNTING_MISMATCH/);
  assert.equal(mismatch.cleanup.stopped, true);
  fake.mismatch = false; options.calibration.used = 12;
  const exhausted = await admitModel(root, prepared, runtime, options);
  assert.equal(exhausted.status, 'model_blocked');
  assert.equal(exhausted.reason, 'CALIBRATION_BUDGET_EXCEEDED');
  assert.equal(options.calibration.used, 12);
  assert.equal(exhausted.cleanup.stopped, true);
}));

test('MiniCPM uses its exact native server and processor accounting without a conversion', () => temporary(async ({ root, prepared, runtime, options }) => {
  const exact = { ...prepared, id: 'minicpm', artifact: MODELS[0].artifact };
  fake.mini = true;
  const loaded = await admitModel(root, exact, runtime, options);
  assert.equal(loaded.status, 'admitted', loaded.reason);
  assert.equal(fake.requests.length, 4);
  assert.equal(options.calibration.used, 4);
  assert.ok(fake.starts[0].args[0].endsWith('minicpm_server.py'));
  assert.ok(fake.starts[0].args.includes('--evidence-directory'));
  assert.ok(fake.starts.every(start => !start.args.includes('load-minicpm')));
  await loaded.stop();
  fake.loadFails = true;
  const failed = await admitModel(root, exact, runtime, options);
  assert.equal(failed.status, 'model_blocked');
  assert.equal(failed.reason, 'MODEL_SERVER_EXITED');
}));

test('admission reuse restarts the exact server without granting another calibration allowance', () => temporary(async ({ root, prepared, runtime, options }) => {
  const charges = [];
  options.calibration.onCharge = async value => { charges.push(value.used); assert.equal(fake.requests.length, value.used - 1); };
  const original = await admitModel(root, prepared, runtime, options);
  assert.equal(original.status, 'admitted', original.reason);
  assert.deepEqual(charges, [1, 2, 3]);
  await original.stop();
  const used = options.calibration.used, requests = fake.requests.length;
  const reused = await admitModel(root, prepared, runtime, { ...options, reuseAdmission: original });
  assert.equal(reused.status, 'admitted', reused.reason);
  assert.equal(options.calibration.used, used);
  assert.equal(fake.requests.length, requests);
  assert.equal(reused.artifact, prepared.artifact);
  assert.equal(reused.revision, prepared.revision);
  assert.equal(reused.runtime_lock_sha256, runtime.lock_sha256);
  await reused.stop();
  const changed = await admitModel(root, prepared, runtime, { ...options, reuseAdmission: { ...original, runtime_lock_sha256: 'f'.repeat(64) } });
  assert.equal(changed.status, 'model_blocked');
  assert.equal(changed.reason, 'REUSED_ADMISSION_IDENTITY_MISMATCH');
  assert.equal(fake.requests.length, requests);
}));

test('a cancelled admission cannot spawn or spend calibration allowance', () => temporary(async ({ root, prepared, runtime, options }) => {
  const controller = new AbortController(); controller.abort('operator-cancelled');
  const result = await admitModel(root, prepared, runtime, { ...options, signal: controller.signal });
  assert.equal(result.reason, 'ADMISSION_CANCELLED'); assert.equal(result.cleanup.cleanupVerified, true);
  assert.equal(fake.starts.length, 0); assert.equal(options.calibration.used, 0);
}));

test('admission cancellation interrupts owned startup health traffic and verifies release', () => temporary(async ({ root, prepared, runtime, options }) => {
  const controller = new AbortController();
  vi.stubGlobal('fetch', vi.fn(async (_url, request) => new Promise((_resolve, reject) => {
    request.signal.addEventListener('abort', () => reject(request.signal.reason), { once: true });
    queueMicrotask(() => controller.abort('operator-cancelled'));
  })));
  const result = await admitModel(root, prepared, runtime, { ...options, signal: controller.signal });
  assert.equal(result.reason, 'ADMISSION_CANCELLED'); assert.equal(result.cleanup.cleanupVerified, true);
  assert.equal(fake.starts.length, 1); assert.equal(fake.starts[0].options.signal, controller.signal);
  assert.equal(options.calibration.used, 0); assert.equal(fake.requests.length, 0);
}));

test('admission cancellation reaches schema and tokenizer subprocesses without granting retries', async () => {
  for (const phase of ['schemas', 'tokenize']) await temporary(async ({ root, prepared, runtime, options }) => {
    const controller = new AbortController(); fake.hangHelper = phase;
    fake.onHelper = () => queueMicrotask(() => controller.abort('operator-cancelled'));
    const result = await admitModel(root, prepared, runtime, { ...options, signal: controller.signal });
    assert.equal(result.reason, 'ADMISSION_CANCELLED'); assert.equal(result.cleanup.cleanupVerified, true);
    assert.ok(fake.starts.every(start => start.options.signal === controller.signal));
    assert.equal(options.calibration.used, 0); assert.equal(fake.requests.length, 0);
    assert.equal(fake.starts.filter(start => start.args[0].endsWith('mlx_server.py')).length, 1);
  });
});

test('a cancellation during calibration charging preserves the charge and prevents generation', () => temporary(async ({ root, prepared, runtime, options }) => {
  const controller = new AbortController();
  options.calibration.onCharge = async () => { controller.abort('operator-cancelled'); };
  const result = await admitModel(root, prepared, runtime, { ...options, signal: controller.signal });
  assert.equal(result.reason, 'ADMISSION_CANCELLED'); assert.equal(result.cleanup.cleanupVerified, true);
  assert.equal(options.calibration.used, 1); assert.equal(fake.requests.length, 0);
}));

test('reused admission cancellation stops the translation sidecar and exact backend together', () => temporary(async ({ root, prepared, runtime, options }) => {
  const translationRuntime = { ...runtime, packages: { ...runtime.packages, litellm: '1.109.0' } };
  const prior = await admitModel(root, prepared, runtime, { ...options, translationRuntime });
  assert.equal(prior.status, 'admitted'); await prior.stop();
  const controller = new AbortController(), previousFetch = globalThis.fetch, startOffset = fake.starts.length;
  vi.stubGlobal('fetch', vi.fn(async (url, request) => {
    if (url.endsWith('/health') && fake.starts.slice(startOffset).some(start => start.args[0].endsWith('translation.py'))) return new Promise((_resolve, reject) => {
      request.signal.addEventListener('abort', () => reject(request.signal.reason), { once: true });
      queueMicrotask(() => controller.abort('operator-cancelled'));
    });
    return previousFetch(url, request);
  }));
  const used = options.calibration.used;
  const result = await admitModel(root, prepared, runtime, { ...options, translationRuntime, reuseAdmission: prior, signal: controller.signal });
  assert.equal(result.reason, 'ADMISSION_CANCELLED'); assert.equal(result.cleanup.cleanupVerified, true);
  assert.equal(options.calibration.used, used);
  assert.ok(fake.starts.slice(startOffset).every(start => start.options.signal === controller.signal));
  assert.equal(fake.starts.slice(startOffset).filter(start => start.args[0].endsWith('translation.py')).length, 1);
}));

test('Responses capability requires native schema and native full-request token accounting', () => {
  const document = schema(), chat = document.components.schemas.Chat;
  document.components.schemas.Responses = { properties: { ...chat.properties, input: {} } };
  delete document.components.schemas.Responses.properties.seed;
  document.paths['/responses'] = { post: { requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Responses' } } } } } };
  document.paths['/responses/input_tokens'] = { post: {} };
  const native = { origin: 'installed-pydantic-model', version: '0.7.11', responses_seed_forwarded: true, responses: document.components.schemas.Responses };
  const profile = servingProfile(document, MODELS[1], native);
  assert.ok(profile.protocol_fields.responses.includes('seed'));
  assert.equal(profile.responses_token_endpoint, '/responses/input_tokens');
  delete document.paths['/responses/input_tokens'];
  assert.equal(servingProfile(document, MODELS[1]).protocol_fields.responses, undefined);
});

test('raw Request Responses endpoints use installed Pydantic evidence without blocking valid Chat', () => {
  const document = schema();
  document.paths['/responses'] = { post: { responses: { 200: {} } } };
  document.paths['/responses/input_tokens'] = { post: { responses: { 200: {} } } };
  assert.equal(servingProfile(document, MODELS[1]).protocol_fields.responses, undefined);
  const properties = { ...document.components.schemas.Chat.properties, input: {} }; delete properties.seed;
  const native = { origin: 'installed-pydantic-model', version: '0.7.11', responses_seed_forwarded: true, responses: { properties } };
  assert.ok(servingProfile(document, MODELS[1], native).protocol_fields.responses.includes('seed'));
  assert.equal(servingProfile(document, MODELS[1], { ...native, responses_seed_forwarded: false }).protocol_fields.responses, undefined);
  const reference = document.paths['/v1/chat/completions'].post.requestBody.content['application/json'].schema;
  document.paths['/v1/chat/completions'].post.requestBody.content['application/json'].schema = { anyOf: [{ type: 'null' }, { allOf: [reference] }] };
  assert.ok(servingProfile(document, MODELS[1], native).protocol_fields.chat.includes('seed'));
});

test('Messages extensions require source-proven forwarding and the native count endpoint', () => {
  const document = schema(); document.paths['/messages'] = { post: {} }; document.paths['/messages/count_tokens'] = { post: {} };
  const properties = { ...document.components.schemas.Chat.properties }; delete properties.seed; delete properties.min_p;
  const native = { origin: 'installed-pydantic-model', version: '0.7.11', messages: { properties }, messages_extra_forwarded: ['seed', 'min_p'] };
  const profile = servingProfile(document, MODELS[1], native);
  assert.equal(profile.messages_token_endpoint, '/messages/count_tokens');
  assert.ok(profile.protocol_fields.messages.includes('min_p'));
  assert.ok(profile.protocol_fields.messages.includes('seed'));
  assert.equal(servingProfile(document, MODELS[1], { ...native, messages_extra_forwarded: ['seed'] }).protocol_fields.messages, undefined);
  assert.equal(servingProfile(document, MODELS[1], { ...native, version: 'unknown' }).protocol_fields.messages, undefined);
  delete document.paths['/messages/count_tokens'];
  assert.equal(servingProfile(document, MODELS[1], native).protocol_fields.messages, undefined);
});

test('post-preparation sealing preserves old evidence and detects changed package/interpreter closure', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-preparation-')));
  try {
    const paths = localPaths(root), directory = path.join(paths.runtime, 'mlx/venv'), prefix = path.join(root, 'existing-python');
    mkdirSync(path.join(directory, 'bin'), { recursive: true }); mkdirSync(path.join(directory, 'lib/site-packages'), { recursive: true }); mkdirSync(path.join(prefix, 'bin'), { recursive: true });
    const interpreter = path.join(prefix, 'bin/python3.12'), python = path.join(directory, 'bin/python');
    writeFileSync(interpreter, 'inert interpreter'); symlinkSync(interpreter, python);
    writeFileSync(path.join(directory, 'pyvenv.cfg'), 'include-system-site-packages = false\n');
    const unused = path.join(root, 'global-site-packages'); mkdirSync(unused);
    writeFileSync(path.join(unused, 'ambient.py'), 'unrelated global package');
    mkdirSync(path.join(prefix, 'lib/python3.12'), { recursive: true });
    symlinkSync(unused, path.join(prefix, 'lib/python3.12/site-packages'));
    const module = path.join(directory, 'lib/site-packages/example.py'); writeFileSync(module, 'original package');
    const lock = path.join(paths.runtime, 'mlx/requirements.lock'); writeFileSync(lock, 'example==1.0 --hash=sha256:inert\n');
    const runtime = { id: 'mlx', status: 'prepared', directory, python, lock, lock_sha256: sha256(readFileSync(lock)) };
    const runner = async () => ({ stdout: JSON.stringify({ prefix: directory, base_prefix: prefix, executable: interpreter, isolated: 1, sys_path: [path.join(directory, 'lib/site-packages')] }) });
    const captured = await captureRuntimeClosure(root, runtime, { runner });
    assert.equal(captured.interpreter.acquisition, 'existing-readonly-interpreter');
    assert.equal(captured.exclusions.length, 1);
    const original = { schema_version: 1, runtimes: [runtime], models: [] }, originalBytes = JSON.stringify(original, null, 2) + '\n';
    writeFileSync(path.join(paths.base, 'preparation.json'), originalBytes);
    assert.throws(() => verifyPreparation(root, original), /closure is missing/);
    const sealed = await sealPreparation(root, original, { runner });
    assert.equal(sealed.schema_version, 2);
    assert.equal(readFileSync(path.join(paths.base, 'preparation.json'), 'utf8'), originalBytes);
    assert.equal(readFileSync(sealed.seal.original_receipt, 'utf8'), originalBytes);
    assert.equal(readPreparation(root).schema_version, 2);
    writeFileSync(path.join(unused, 'ambient.py'), 'unrelated update');
    assert.doesNotThrow(() => verifyPreparation(root, sealed));
    writeFileSync(module, 'changed package');
    assert.throws(() => verifyPreparation(root, sealed), /bytes changed/);
    writeFileSync(module, 'original package'); writeFileSync(path.join(directory, 'lib/site-packages/unrecorded.py'), 'added');
    assert.throws(() => verifyPreparation(root, sealed), /bytes changed/);
    rmSync(path.join(directory, 'lib/site-packages/unrecorded.py')); writeFileSync(interpreter, 'changed interpreter');
    assert.throws(() => verifyPreparation(root, sealed), /bytes changed/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

function cacheFixture({ busy = false, residue = false, concurrent = false, disk = false, wrongModel = false, missing = false } = {}) {
  const calls = []; let metrics = 0;
  const fetchImpl = async (url, options) => {
    const route = new URL(url).pathname; calls.push({ route, method: options.method });
    if (route === '/v1/metrics') {
      metrics++;const count = concurrent && metrics === 2 ? 4 : 3;
      return Response.json({ summary: { in_flight: busy ? 1 : 0, requests_started: count, requests_completed: count, requests_failed: 0 },
        server: { loaded_model: wrongModel ? '/foreign/model' : '/private/model', request_queue_depth: 0, audio_queue_depth: 0, apc: { enabled: true } } });
    }
    if (route === '/v1/cache/reset') return Response.json({ enabled: true, status: 'cleared' });
    return Response.json({ enabled: true, resident_bytes: residue ? 1 : 0, ...(missing ? {} : { exact_resident_bytes: 0 }), pool_used: 0, memory_max_bytes: 1024 ** 3, block_size: 16, num_blocks: 2048, disk_writes: 0, ...(disk ? { disk_bytes: 0 } : {}) });
  };
  return { calls, fetchImpl };
}

test('frozen APC enables bounded memory only and source-bound settings reject a mismatched runtime', () => temporary(async ({ root, prepared, runtime, options }) => {
  const model = await admitModel(root, prepared, runtime, options);
  assert.equal(model.status, 'admitted', model.reason);
  assert.deepEqual(model.cache_policy, MLX_CACHE_POLICY);
  assert.equal(model.cache_policy_evidence.sources.length, 3);
  const env = fake.starts[0].options.env;
  assert.equal(env.APC_ENABLED, '1'); assert.equal(env.APC_DISK_ENABLED, '0'); assert.equal(env.APC_MEMORY_MAX_GB, '1'); assert.equal(env.APC_MEMORY_RESERVE_GB, '2');
  assert.equal(env.APC_HASH, 'sha256'); assert.equal(env.APC_BLOCK_SIZE, '16'); assert.equal(env.APC_NUM_BLOCKS, '2048'); assert.equal(env.APC_CHECKPOINT_ENTRIES, '2');
  await model.stop(); fake.cacheConfigMismatch = true;
  const rejected = await admitModel(root, prepared, runtime, options);
  assert.equal(rejected.reason, 'CACHE_POLICY_SOURCE_UNVERIFIED'); assert.equal(rejected.cleanup.cleanupVerified, true);
}));

test('cache reset is a count-free native management sequence with verified idle and zero residency', async () => {
  const fixture = cacheFixture();
  const proof = await resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model', idle: true, fetchImpl: fixture.fetchImpl });
  assert.equal(proof.inference, false); assert.equal(proof.verified, true); assert.equal(proof.cache.resident_bytes, 0);
  assert.deepEqual(fixture.calls, [{ route: '/v1/metrics', method: 'GET' }, { route: '/v1/cache/reset', method: 'POST' }, { route: '/v1/cache/stats', method: 'GET' }, { route: '/v1/metrics', method: 'GET' }]);
});

test('one lost management response repeats the entire idempotent sequence and retains private transport attribution', async () => {
  const fixture = cacheFixture(), observations = []; let lost = false;
  const proof = await resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model', idle: true, onObservation: event => observations.push(event), fetchImpl: async (url, options) => {
    const result = await fixture.fetchImpl(url, options);
    assert.equal(options.headers.connection, 'close');
    if (url.endsWith('/v1/cache/reset') && !lost) { lost = true; throw new TypeError('fetch failed', { cause: Object.assign(new Error('other side closed'), { code: 'UND_ERR_SOCKET' }) }); }
    return result;
  } });
  assert.equal(proof.verified, true); assert.equal(proof.inference, false); assert.equal(proof.transport.attempts, 2);
  assert.deepEqual(fixture.calls.map(row => row.route), ['/v1/metrics', '/v1/cache/reset', '/v1/metrics', '/v1/cache/reset', '/v1/cache/stats', '/v1/metrics']);
  assert.equal(observations[0].error.cause.code, 'UND_ERR_SOCKET'); assert.equal(observations[0].route, '/v1/cache/reset');
  assert.equal(observations[1].type, 'cache_management_recovery');
});

test('management transport recovery cannot hide cancellation, concurrency, invalid responses or a second connection failure', async () => {
  const fixture = cacheFixture(); let calls = 0;
  await assert.rejects(resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model', idle: true, fetchImpl: async () => {
    calls++; throw new TypeError('fetch failed', { cause: Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED', address: '127.0.0.1', port: 1234 }) });
  } }), error => error.code === 'CACHE_RESET_TRANSPORT_FAILED' && error.management_observations.length === 2 && error.cause.cause.code === 'ECONNREFUSED');
  assert.equal(calls, 2);
  let metrics = 0, lost = false;
  await assert.rejects(resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model', idle: true, fetchImpl: async (url, options) => {
    if (url.endsWith('/v1/metrics')) { metrics++; const response = await fixture.fetchImpl(url, options); const value = await response.json(); value.summary.requests_started = value.summary.requests_completed = metrics === 1 ? 3 : 4; return Response.json(value); }
    if (!lost) { lost = true; throw new TypeError('fetch failed', { cause: Object.assign(new Error('reset'), { code: 'ECONNRESET' }) }); }
    return fixture.fetchImpl(url, options);
  } }), /CACHE_RESET_CONCURRENT_REQUEST/);
  const controller = new AbortController(); controller.abort(); calls = 0;
  await assert.rejects(resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model', idle: true, signal: controller.signal, fetchImpl: async () => {
    calls++; throw new TypeError('fetch failed', { cause: Object.assign(new Error('reset'), { code: 'ECONNRESET' }) });
  } }), /CACHE_RESET_TRANSPORT_FAILED/); assert.equal(calls, 1);
  calls = 0;
  await assert.rejects(resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model', idle: true, fetchImpl: async () => { calls++; return new Response('not JSON'); } }), /MODEL_RESPONSE_INVALID/);
  assert.equal(calls, 1);
  assert.equal(managementErrorObservation(new Error('Bearer private-token')).message, 'Bearer [REDACTED]');
});

test('active, concurrent, foreign-model, persistent-disk and unobserved cache states cannot pass reset', async () => {
  for (const [state, error] of [[{ busy: true }, 'CACHE_RESET_SERVER_NOT_IDLE_OR_UNVERIFIED'], [{ wrongModel: true }, 'CACHE_RESET_SERVER_NOT_IDLE_OR_UNVERIFIED'], [{ residue: true }, 'CACHE_RESET_RESIDENCY_OR_POLICY_UNVERIFIED'], [{ missing: true }, 'CACHE_RESET_RESIDENCY_OR_POLICY_UNVERIFIED'], [{ disk: true }, 'CACHE_RESET_RESIDENCY_OR_POLICY_UNVERIFIED'], [{ concurrent: true }, 'CACHE_RESET_CONCURRENT_REQUEST']]) {
    const fixture = cacheFixture(state);
    await assert.rejects(resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model', idle: true, fetchImpl: fixture.fetchImpl }), new RegExp(error));
    if (state.busy || state.wrongModel) assert.equal(fixture.calls.length, 1, 'No reset may occur while active or unattributed');
  }
  await assert.rejects(resetMlxConversationCache({ upstream: 'http://127.0.0.1:1234', model: '/private/model' }), /CACHE_RESET_REQUIRES_IDLE_CALLER/);
  await assert.rejects(resetMlxConversationCache({ upstream: 'https://example.org', model: '/private/model', idle: true }), /CACHE_RESET_PRIVATE_ENDPOINT_REQUIRED/);
});

test('MiniCPM retains per-request native cache and reset makes no provider or generation requests', () => temporary(async ({ root, prepared, runtime, options }) => {
  fake.mini = true;
  const exact = { ...prepared, id: 'minicpm', artifact: MODELS[0].artifact };
  const model = await admitModel(root, exact, runtime, options); const used = options.calibration.used, requests = fake.requests.length;
  const proof = await model.resetConversationCache({ idle: true });
  assert.equal(proof.persistent_cache, false); assert.equal(proof.inference, false); assert.equal(proof.verified, true);
  assert.equal(options.calibration.used, used); assert.equal(fake.requests.length, requests); assert.equal(fake.starts[0].options.env.APC_ENABLED, undefined);
  await model.stop(); await assert.rejects(model.resetConversationCache({ idle: true }), /MODEL_SERVER_NOT_RUNNING/);
}));

test('native cache management is proven before calibration and a failed reset spends no inference requests', () => temporary(async ({ root, prepared, runtime, options }) => {
  fake.cacheResidue = true;
  const result = await admitModel(root, prepared, runtime, options);
  assert.equal(result.status, 'model_blocked'); assert.equal(result.reason, 'CACHE_RESET_RESIDENCY_OR_POLICY_UNVERIFIED');
  assert.equal(options.calibration.used, 0); assert.equal(fake.requests.length, 0); assert.equal(result.cleanup.cleanupVerified, true);
}));
