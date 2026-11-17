/** Exact local model admission. No model is loaded merely by importing this module. MIT. */
import net from 'node:net';
import { mkdirSync, readFileSync, appendFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { startOwned } from './process.mjs';
import { localPaths, privateEnvironment } from './preparation.mjs';
import { MODELS } from './registry.mjs';
import { needsResponsesTranslation } from './responses-namespace.mjs';

const fail = code => Object.assign(new Error(code), { code });
const integer = value => Number.isSafeInteger(value) && value >= 0;
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
export function messagesProtocolIdentity() {
  return { version: 'ud-local-messages-v1', source: 'evals/local/messages_protocol.py',
    sha256: createHash('sha256').update(readFileSync(new URL('./messages_protocol.py', import.meta.url))).digest('hex'),
    context_edit: 'only-exact-keep-all-noop', deferred_tools: 'native-result-reference-only',
    definition_placement: 'local-chat-template-tool-section', search_or_tool_selection: false, argument_repair: false };
}
export const MLX_CACHE_POLICY = Object.freeze({ kind: 'mlx-automatic-prefix-cache', runtime_version: '0.7.11', enabled: true, disk_enabled: false,
  memory_max_bytes: 1024 ** 3, memory_reserve_bytes: 2 * 1024 ** 3, hash: 'sha256', block_size: 16, num_blocks: 2048, checkpoint_entries: 2,
  checkpoint_interval_tokens: 2048, checkpoint_guard_tokens: 1, conversation_reset: 'idle-native-reset-and-zero-residency-verification' });
const MLX_CACHE_ENV = Object.freeze({ APC_ENABLED: '1', APC_DISK_ENABLED: '0', APC_MEMORY_MAX_GB: '1', APC_MEMORY_RESERVE_GB: '2', APC_HASH: 'sha256',
  APC_BLOCK_SIZE: '16', APC_NUM_BLOCKS: '2048', APC_CHECKPOINT_ENTRIES: '2', APC_CHECKPOINT_INTERVAL_TOKENS: '2048', APC_CHECKPOINT_GUARD_TOKENS: '1' });
const MINICPM_CACHE_POLICY = Object.freeze({ kind: 'native-per-request-generation-cache', persistent_prefix_cache: false });
const PROBE_TOOL = { type: 'function', function: { name: 'calibration_echo', description: 'Return the supplied diagnostic string.', parameters: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'], additionalProperties: false } } };
/** Admission binds observations of loaded objects, never a requested device or config alone. */
export function verifyLoadedRuntimeIdentity(identity, model, prepared, runtime) {
  const source = value => typeof value?.module === 'string' && value.module.length > 0 && typeof value?.name === 'string' && value.name.length > 0 && /^[a-f0-9]{64}$/.test(value.sha256 ?? '');
  const configHash = createHash('sha256').update(readFileSync(path.join(prepared.directory, 'config.json'))).digest('hex');
  if (identity?.schema_version !== 1 || identity.model_loaded !== true || identity.model !== prepared.directory ||
      identity.files?.['config.json'] !== configHash || !source(identity.model_class) || !source(identity.processor_class) ||
      !Array.isArray(identity.parameter_dtypes) || !identity.parameter_dtypes.length || identity.parameter_dtypes.some(value => typeof value !== 'string' || !value) ||
      identity.quantization?.format !== model.quantization || !identity.packages || Object.entries(identity.packages).some(([name, version]) => typeof version !== 'string' || runtime.packages?.[name] !== undefined && runtime.packages[name] !== version)) throw fail('MODEL_LOADED_IDENTITY_UNVERIFIED');
  if (model.id === 'minicpm') {
    if (identity.runtime !== 'transformers-bitsandbytes' || identity.loader !== 'transformers.AutoModelForImageTextToText.from_pretrained' ||
        !['mps', 'cuda', 'cpu'].includes(identity.device) || !Array.isArray(identity.parameter_devices) || !identity.parameter_devices.length ||
        identity.parameter_devices.some(value => typeof value !== 'string' || value.split(':')[0] !== identity.device) ||
        !integer(identity.quantization.linear_modules) || identity.quantization.linear_modules < 1 || !source(identity.quantized_class) || !source(identity.image_processor_class) ||
        !['torch', 'transformers', 'bitsandbytes'].every(name => typeof identity.packages[name] === 'string')) throw fail('MODEL_LOADED_MINICPM_IDENTITY_UNVERIFIED');
  } else {
    const type = model.id === 'bonsai' ? 'prism_hadamard_qwen35' : 'lfm3_vl', bits = model.id === 'bonsai' ? 2 : 5;
    if (identity.runtime !== 'mlx-vlm' || identity.packages['mlx-vlm'] !== '0.7.11' || typeof identity.packages.mlx !== 'string' ||
        identity.device !== 'gpu' || identity.model_type !== type || !identity.model_class.module.includes(type) ||
        !source(identity.loader) || identity.loader.sha256 !== '7d19bafb1fcd8d0427572920d545130deabd024c3483f240bdcb0cf7b2ddcd1a' ||
        !integer(identity.parameter_storage_bytes) || identity.parameter_storage_bytes < 1 ||
        !integer(identity.quantization.quantized_modules) || identity.quantization.quantized_modules < 1 || !identity.quantization.module_bits?.includes(bits)) throw fail('MODEL_LOADED_MLX_IDENTITY_UNVERIFIED');
    if (model.id === 'bonsai') {
      const transform = identity.quantization.hadamard;
      if (!integer(transform?.verified_modules) || transform.verified_modules < 1 || !integer(transform.rotated_modules) || transform.rotated_modules < 1 ||
          transform.rotated_modules > transform.verified_modules || !/^[a-f0-9]{64}$/.test(transform.modules_sha256 ?? '') || !source(transform.implementation) ||
          transform.implementation.sha256 !== '4336633e333f9e744b526463a8eff1a3d99f1843da29031fb058f5d52ec4a681') throw fail('MODEL_LOADED_BONSAI_TRANSFORM_UNVERIFIED');
    }
  }
  return { ...identity, sha256: createHash('sha256').update(JSON.stringify(identity)).digest('hex') };
}
const NATIVE_SCHEMAS = `import ast,hashlib,importlib.metadata,inspect,json
from mlx_vlm.server.schemas import ChatRequest,OpenAIRequest,AnthropicRequest
from mlx_vlm.server import request_normalization
from mlx_vlm.server.runtime_config import RuntimeConfig
from mlx_vlm import apc
from importlib.util import find_spec
tree=ast.parse(inspect.getsource(request_normalization._build_gen_args))
forwarded=sorted({n.arg for n in ast.walk(tree) if isinstance(n,ast.keyword) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='getattr' and len(n.value.args)>=2 and isinstance(n.value.args[0],ast.Name) and n.value.args[0].id=='request' and isinstance(n.value.args[1],ast.Constant) and n.value.args[1].value==n.arg})
files=sorted(set(inspect.getsourcefile(x) for x in [ChatRequest,OpenAIRequest,AnthropicRequest,request_normalization._build_gen_args]))
cfg=RuntimeConfig.from_env()
cache_config={name:getattr(cfg,name) for name in ['apc_enabled','apc_disk_enabled','apc_memory_max_gb','apc_memory_reserve_gb','apc_block_size','apc_num_blocks','apc_checkpoint_entries','apc_checkpoint_interval_tokens','apc_checkpoint_guard_tokens']}
cache_config['hash']='sha256' if apc._hash_use_sha256() else 'fast'
cache_files=sorted(set([inspect.getsourcefile(RuntimeConfig),inspect.getsourcefile(apc.APCManager),find_spec('mlx_vlm.server.app').origin]))
print(json.dumps({'origin':'installed-pydantic-model','version':importlib.metadata.version('mlx-vlm'),'chat':ChatRequest.model_json_schema(),'responses':OpenAIRequest.model_json_schema(),'responses_seed_forwarded':'seed' in forwarded and OpenAIRequest.model_config.get('extra')=='allow','messages':AnthropicRequest.model_json_schema(),'messages_extra_forwarded':forwarded if AnthropicRequest.model_config.get('extra')=='allow' else [],'sources':[{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()} for p in files],'cache_config':cache_config,'cache_sources':[{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()} for p in cache_files]}))`;

async function unusedPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function remaining(deadline, ceiling) {
  const duration = Math.min(ceiling, deadline - Date.now());
  if (duration <= 0) throw fail('ADMISSION_DEADLINE_EXCEEDED');
  return duration;
}
async function jsonResponse(response) {
  if (!response.ok) throw fail(`MODEL_HTTP_${response.status}:${(await response.text()).slice(0, 1000)}`);
  const text = await response.text();
  if (Buffer.byteLength(text) > 4 * 1024 ** 2) throw fail('MODEL_RESPONSE_TOO_LARGE');
  try { return JSON.parse(text); } catch { throw fail('MODEL_RESPONSE_INVALID'); }
}
/** Management requests never generate, consume inference allowance, or pass
 * through an agent. The caller must already have stopped its episode workers. */
export function managementErrorObservation(error, depth = 0) {
  if (!error || depth > 3) return null;
  const clean = value => String(value).slice(0, 1000).replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
  return { name: clean(error.name ?? 'Error'), message: clean(error.message ?? error),
    ...Object.fromEntries(['code', 'errno', 'syscall', 'address', 'port'].filter(key => ['string', 'number'].includes(typeof error[key])).map(key => [key, typeof error[key] === 'string' ? clean(error[key]) : error[key]])),
    ...(error.cause ? { cause: managementErrorObservation(error.cause, depth + 1) } : {}),
    ...(Array.isArray(error.errors) ? { errors: error.errors.slice(0, 4).map(value => managementErrorObservation(value, depth + 1)) } : {}) };
}

/** One wall-clock allowance covers draining the observer and releasing every
 * owned group. Stops begin immediately; a slow sample cannot postpone them.
 * Late observations remain evidence, never retroactive deadline compliance. */
export async function stopAdmissionProcesses({ owned, resourcePending, reason, record, startedAt = Date.now(), cancellationMs = 5000 }) {
  if (!Array.isArray(owned) || owned.some(process => typeof process?.stop !== 'function') || !integer(startedAt) ||
      !Number.isSafeInteger(cancellationMs) || cancellationMs < 1 || cancellationMs > 5000 || typeof record !== 'function') throw fail('ADMISSION_RELEASE_CONFIGURATION_INVALID');
  const deadline = startedAt + cancellationMs;
  let timedOut = false, timer;
  let drainage = { status: resourcePending ? 'pending' : 'not-running' };
  const outcomes = owned.map(() => ({ cleanupVerified: false, observation: 'pending' }));
  const settling = owned.map((selected, index) => Promise.resolve().then(() => selected.stop(reason)).then(outcome => {
    outcomes[index] = outcome;
    if (timedOut) record({ type: 'owned_server_stop_late_outcome', pid: selected.child?.pid, reason, deadline, outcome, within_cancellation_allowance: false });
  }, error => {
    outcomes[index] = { cleanupVerified: false, observation: 'rejected', error: managementErrorObservation(error) };
    if (timedOut) record({ type: 'owned_server_stop_late_outcome', pid: selected.child?.pid, reason, deadline, outcome: outcomes[index], within_cancellation_allowance: false });
  }));
  if (resourcePending) settling.push(Promise.resolve(resourcePending).then(() => {
    drainage = { status: 'fulfilled' };
    if (timedOut) record({ type: 'owned_server_stop_late_resource_drain', reason, deadline, drainage, within_cancellation_allowance: false });
  }, error => {
    drainage = { status: 'rejected', error: managementErrorObservation(error) };
    if (timedOut) record({ type: 'owned_server_stop_late_resource_drain', reason, deadline, drainage, within_cancellation_allowance: false });
  }));
  try {
    await Promise.race([Promise.all(settling), new Promise(resolve => {
      timer = setTimeout(() => { timedOut = true; resolve(); }, Math.max(0, deadline - Date.now()));
    })]);
  } finally { clearTimeout(timer); }
  const elapsed = Date.now() - startedAt;
  const cleanupVerified = !timedOut && elapsed <= cancellationMs && drainage.status !== 'pending' && outcomes.every(outcome => outcome?.cleanupVerified === true);
  const evidence = structuredClone({ type: 'owned_server_stopped', reason, pids: owned.map(selected => selected.child?.pid ?? null),
    started_at: startedAt, deadline, cancellation_ms: cancellationMs, elapsed_ms: elapsed, cleanupVerified, resource_drain: drainage, outcomes });
  record(evidence);
  if (!cleanupVerified) throw Object.assign(fail('CANCELLATION_UNVERIFIED'), { cleanup: evidence });
  return { stopped: true, cleanupVerified, elapsed_ms: elapsed };
}

export async function resetMlxConversationCache({ upstream, model, idle, signal, deadline = Date.now() + 5000, fetchImpl = fetch, onObservation = () => {} }) {
  const url = new URL(upstream);
  if (idle !== true) throw fail('CACHE_RESET_REQUIRES_IDLE_CALLER');
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw fail('CACHE_RESET_PRIVATE_ENDPOINT_REQUIRED');
  const bound = AbortSignal.timeout(remaining(deadline, 5000)), selectedSignal = signal ? AbortSignal.any([signal, bound]) : bound;
  const failures = [];
  let attempt = 0, initialSummary;
  const request = async (route, method = 'GET') => {
    try {
      // Management calls are infrequent and must not inherit an idle pooled
      // socket after synchronous source/storage verification. No inference is
      // performed here, and every request closes its connection after use.
      return await jsonResponse(await fetchImpl(upstream + route, { method, headers: { connection: 'close' }, signal: selectedSignal, redirect: 'error' }));
    } catch (error) {
      const observation = { type: 'cache_management_failure', inference: false, route, method, attempt, error: managementErrorObservation(error) };
      failures.push(observation); onObservation(observation); throw error;
    }
  };
  const assertIdle = value => {
    const summary = value?.summary, server = value?.server;
    if (summary?.in_flight !== 0 || server?.request_queue_depth !== 0 || server?.audio_queue_depth !== 0 || server?.loaded_model !== model || server?.apc?.enabled !== true ||
        !['requests_started', 'requests_completed', 'requests_failed'].every(key => integer(summary?.[key])) || summary.requests_started !== summary.requests_completed + summary.requests_failed) throw fail('CACHE_RESET_SERVER_NOT_IDLE_OR_UNVERIFIED');
    return { summary, server: { loaded_model: server.loaded_model, request_queue_depth: server.request_queue_depth, audio_queue_depth: server.audio_queue_depth } };
  };
  for (attempt = 1; attempt <= 2; attempt++) {
    try {
      const before = assertIdle(await request('/v1/metrics'));
      if (initialSummary && ['requests_started', 'requests_completed', 'requests_failed'].some(key => initialSummary[key] !== before.summary[key])) throw fail('CACHE_RESET_CONCURRENT_REQUEST');
      initialSummary ??= before.summary;
      const reset = await request('/v1/cache/reset', 'POST');
      if (reset.enabled !== true || reset.status !== 'cleared') throw fail('CACHE_RESET_NOT_CONFIRMED');
      const cache = await request('/v1/cache/stats');
      if (cache.enabled !== true || cache.resident_bytes !== 0 || cache.exact_resident_bytes !== 0 || cache.pool_used !== 0 ||
          cache.memory_max_bytes !== MLX_CACHE_POLICY.memory_max_bytes || cache.block_size !== MLX_CACHE_POLICY.block_size || cache.num_blocks !== MLX_CACHE_POLICY.num_blocks ||
          ['disk_bytes', 'disk_pending_bytes', 'disk_max_bytes'].some(key => Object.hasOwn(cache, key)) || cache.disk_writes !== 0) throw fail('CACHE_RESET_RESIDENCY_OR_POLICY_UNVERIFIED');
      const after = assertIdle(await request('/v1/metrics'));
      if (['requests_started', 'requests_completed', 'requests_failed'].some(key => before.summary[key] !== after.summary[key])) throw fail('CACHE_RESET_CONCURRENT_REQUEST');
      return { kind: 'conversation-cache-reset', inference: false, verified: true, policy: MLX_CACHE_POLICY, before, reset, cache, after,
        transport: { attempts: attempt, failures } };
    } catch (error) {
      const recoverable = ['UND_ERR_SOCKET', 'UND_ERR_RES_CONTENT_LENGTH_MISMATCH', 'ECONNRESET', 'EPIPE', 'ECONNREFUSED'];
      const networkFailure = error instanceof TypeError &&
        (recoverable.includes(error.cause?.code) || error.cause instanceof AggregateError && error.cause.errors.length > 0 && error.cause.errors.every(value => recoverable.includes(value.code)));
      // The entire idle/reset/zero-residency sequence is idempotent. A lost POST
      // response is not assumed to mean the clear failed: re-observe idle first.
      // Never retry a domain/policy rejection, timeout or cancelled caller.
      if (attempt === 1 && networkFailure && !selectedSignal.aborted && deadline - Date.now() > 25) {
        onObservation({ type: 'cache_management_recovery', inference: false, attempt, next_attempt: 2, action: 'repeat-verified-idle-reset-sequence' });
        await delay(20); continue;
      }
      if (networkFailure) throw Object.assign(fail('CACHE_RESET_TRANSPORT_FAILED'), { cause: error, management_observations: failures });
      throw error;
    }
  }
}

function verifyMlxCacheConfiguration(document, nativeSchemas) {
  const expected = { apc_enabled: true, apc_disk_enabled: false, apc_memory_max_gb: 1, apc_memory_reserve_gb: 2, apc_block_size: 16,
    apc_num_blocks: 2048, apc_checkpoint_entries: 2, apc_checkpoint_interval_tokens: 2048, apc_checkpoint_guard_tokens: 1, hash: 'sha256' };
  if (Object.entries(expected).some(([key, value]) => nativeSchemas?.cache_config?.[key] !== value) ||
      !Array.isArray(nativeSchemas?.cache_sources) || nativeSchemas.cache_sources.length !== 3 || nativeSchemas.cache_sources.some(source => !path.isAbsolute(source.path ?? '') || !/^[a-f0-9]{64}$/.test(source.sha256 ?? '')) ||
      !document.paths?.['/v1/cache/reset']?.post || !document.paths?.['/v1/cache/stats']?.get || !(document.paths?.['/v1/metrics']?.get || document.paths?.['/metrics']?.get)) throw fail('CACHE_POLICY_SOURCE_UNVERIFIED');
  return { config: nativeSchemas.cache_config, sources: nativeSchemas.cache_sources };
}
function schemaObject(document, schema, depth = 0) {
  if (depth > 16 || !schema || typeof schema !== 'object') throw fail('SERVER_SCHEMA_UNVERIFIED');
  if (schema.$ref) {
    if (!schema.$ref.startsWith('#/')) throw fail('SERVER_SCHEMA_UNVERIFIED');
    const resolved = schema.$ref.slice(2).split('/').reduce((value, key) => value?.[key.replaceAll('~1', '/').replaceAll('~0', '~')], document);
    return schemaObject(document, resolved, depth + 1);
  }
  if (Array.isArray(schema.allOf)) {
    const parts = schema.allOf.map(part => schemaObject(document, part, depth + 1));
    return { ...schema, properties: Object.assign({}, ...parts.map(part => part.properties ?? {}), schema.properties ?? {}) };
  }
  if (Array.isArray(schema.anyOf) || Array.isArray(schema.oneOf)) {
    const alternatives = (schema.anyOf ?? schema.oneOf).filter(part => part.type !== 'null');
    if (alternatives.length !== 1) throw fail('SERVER_SCHEMA_AMBIGUOUS');
    return schemaObject(document, alternatives[0], depth + 1);
  }
  return schema;
}

/** Freeze defaults from the selected server's schema, not from assumed API compatibility. */
export function servingProfile(document, model, nativeSchemas) {
  const endpoint = (document.paths?.['/chat/completions'] ?? document.paths?.['/v1/chat/completions'])?.post;
  const schema = schemaObject(document, endpoint?.requestBody?.content?.['application/json']?.schema);
  const fields = schema.properties ?? {};
  for (const name of ['model', 'messages', 'tools', 'seed', 'enable_thinking', ...Object.keys(model.sampling)]) if (!fields[name]) throw fail(`SERVER_FIELD_UNVERIFIED:${name}`);
  const sampling = { ...model.sampling };
  for (const name of ['presence_penalty', 'min_p', 'top_n_sigma', 'p_less', 'typical_p', 'frequency_penalty', 'repetition_context_size', 'presence_context_size', 'frequency_context_size']) {
    if (Object.hasOwn(sampling, name)) continue;
    if (!fields[name]) throw fail(`SERVER_DEFAULT_UNVERIFIED:${name}`);
    sampling[name] = Object.hasOwn(fields[name], 'default') ? fields[name].default : null;
  }
  sampling.enable_thinking = false;
  const protocolFields = { chat: Object.keys(fields).sort() };
  const responses = (document.paths?.['/responses'] ?? document.paths?.['/v1/responses'])?.post;
  const countRoute = document.paths?.['/responses/input_tokens']?.post ? '/responses/input_tokens' : document.paths?.['/v1/responses/input_tokens']?.post ? '/v1/responses/input_tokens' : null;
  const chatCountRoute = document.paths?.['/chat/input_tokens']?.post ? '/chat/input_tokens' : null;
  const messages = (document.paths?.['/messages'] ?? document.paths?.['/v1/messages'])?.post;
  const messagesCountRoute = document.paths?.['/messages/count_tokens']?.post ? '/messages/count_tokens' : document.paths?.['/v1/messages/count_tokens']?.post ? '/v1/messages/count_tokens' : null;
  if (responses && countRoute) {
    const advertised = responses.requestBody?.content?.['application/json']?.schema;
    const installed = nativeSchemas?.origin === 'installed-pydantic-model' && nativeSchemas.version === '0.7.11' && nativeSchemas.responses_seed_forwarded === true ? nativeSchemas.responses : undefined;
    const properties = advertised ? schemaObject(document, advertised).properties ?? {} : installed ? schemaObject(installed, installed).properties ?? {} : {};
    if (['model', 'input', 'tools', ...Object.keys(sampling)].every(key => Object.hasOwn(properties, key))) {
      // In the pinned 0.7.11 runtime OpenAIRequest permits extra fields, and
      // request_normalization._build_gen_args forwards getattr(request,'seed').
      if (Object.hasOwn(properties, 'seed') || installed) protocolFields.responses = [...new Set([...Object.keys(properties), 'seed'])].sort();
    }
  }
  if (messages && messagesCountRoute && nativeSchemas?.origin === 'installed-pydantic-model' && nativeSchemas.version === '0.7.11' && nativeSchemas.messages) {
    const properties = schemaObject(nativeSchemas.messages, nativeSchemas.messages).properties ?? {};
    // Extensions are admitted only when the selected Pydantic model preserves
    // them and the pinned normalizer forwards each named field unchanged.
    const forwarded = nativeSchemas.messages_extra_forwarded ?? [];
    const names = new Set([...Object.keys(properties), ...forwarded]);
    if (['model', 'messages', 'tools', 'seed', ...Object.keys(sampling)].every(key => names.has(key))) protocolFields.messages = [...names].sort();
  }
  return { protocol: 'chat', endpoint: '/v1/chat/completions', sampling, seed_behavior: 'explicit-request-seed', schema_fields: Object.keys(fields).sort(),
    protocol_fields: protocolFields, responses_token_endpoint: protocolFields.responses ? countRoute : null, chat_token_endpoint: chatCountRoute,
    messages_token_endpoint: protocolFields.messages ? messagesCountRoute : null,
    seed_extension_evidence: protocolFields.responses ? 'mlx-vlm-0.7.11:OpenAIRequest.extra=allow;request_normalization._build_gen_args:seed=getattr(request,seed,None)' : null };
}

/**
 * Admit only observed capabilities. Text admission never certifies pixel input or
 * a native provider protocol whose exact tokenizer path has not been verified.
 */
export async function admitModel(root, preparedModel, runtime, { deadline, calibration, onProgress = () => {}, reuseAdmission, translationRuntime, signal: suppliedSignal, observeResources } = {}) {
  const prelaunchBlocked = reason => ({ status: 'model_blocked', reason, cleanup: { stopped: true, cleanupVerified: true, launches: 0, no_owned_processes_launched: true, evidence_kind: 'prelaunch-control-flow' } });
  const model = MODELS.find(item => item.id === preparedModel?.id);
  if (!model || preparedModel.artifact !== model.artifact || preparedModel.status !== 'prepared' || runtime?.status !== 'prepared') return prelaunchBlocked(preparedModel?.reason ?? runtime?.reason ?? 'Exact prepared model and runtime are required.');
  if (!path.isAbsolute(preparedModel.directory ?? '') || !path.isAbsolute(runtime.python ?? '') || !/^[a-f0-9]{40}$/.test(preparedModel.revision ?? '')) return prelaunchBlocked('Prepared model identity or private runtime path is unbound.');
  if (!Number.isSafeInteger(deadline) || deadline <= Date.now() || !calibration || !integer(calibration.used) || !integer(calibration.maximum) || calibration.maximum > 12 || calibration.used > calibration.maximum) throw fail('ADMISSION_BUDGET_REQUIRED');
  if (observeResources !== undefined && typeof observeResources !== 'function') throw fail('RESOURCE_OBSERVER_INVALID');
  const resourceController = new AbortController();
  const admissionSignal = observeResources ? suppliedSignal ? AbortSignal.any([suppliedSignal, resourceController.signal]) : resourceController.signal : suppliedSignal;
  const directory = path.join(localPaths(root).base, 'admission', `${model.id}-${randomUUID()}`);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const cachePolicy = model.id === 'minicpm' ? MINICPM_CACHE_POLICY : MLX_CACHE_POLICY;
  const messagesProtocol = messagesProtocolIdentity();
  const env = { ...privateEnvironment(root, path.join(directory, 'home')), HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1', MLX_VLM_ENABLE_THINKING: 'false', MLX_VLM_MAX_NUM_SEQS: '1', MLX_VLM_MAX_TOKENS: '512', MAX_KV_SIZE: '32768', ...(model.id === 'minicpm' ? {} : MLX_CACHE_ENV) };
  mkdirSync(env.HOME, { recursive: true, mode: 0o700 });
  const eventsFile = path.join(directory, 'admission.jsonl');
  const record = value => appendFileSync(eventsFile, JSON.stringify({ at: new Date().toISOString(), ...value }) + '\n', { mode: 0o600 });
  const capability = { text: false, tools: false, images: false, ordinary_context: false, extended_context: false, cancellation: false, protocols: [] };
  let calibrationObservations = {};
  let server, serverExited = false, upstream, backendUpstream, profile, nativeProtocolFields, translationEvidence, cacheEvidence, runtimeIdentity, requests = 0;
  const helpers = new Set();
  const persistentHelpers = new Set();
  const helper = path.join(root, 'evals/local/runtime.py');
  let resourceTimer, resourcePending, resourceFailure, resourceSuspended = false;
  const ownedProcesses = () => [...(server && !serverExited ? [{ role: 'model-server', pid: server.child.pid }] : []), ...[...persistentHelpers].map(helper => ({ role: 'translation-server', pid: helper.child.pid }))];
  const checkCancelled = () => { if (resourceFailure) throw resourceFailure; if (admissionSignal?.aborted) throw fail('ADMISSION_CANCELLED'); };
  function sampleResources(stage) {
    if (!observeResources || resourceSuspended) return Promise.resolve();
    if (resourcePending) return resourcePending;
    resourcePending = Promise.resolve().then(() => observeResources({ processes: ownedProcesses(), stage, signal: admissionSignal })).catch(error => {
      resourceFailure ??= error;
      record({ type: 'admission_resource_failure', stage, error: managementErrorObservation(error) });
      resourceController.abort(error); throw error;
    }).finally(() => { resourcePending = undefined; });
    return resourcePending;
  }
  async function finishResourceMonitoring() {
    clearInterval(resourceTimer); resourceTimer = undefined;
    await resourcePending; checkCancelled();
  }
  const selectedSignal = (signal, ceiling, until = deadline) => {
    const signals = [admissionSignal, signal, ...(ceiling === undefined ? [] : [AbortSignal.timeout(remaining(until, ceiling))])].filter(Boolean);
    return signals.length > 1 ? AbortSignal.any(signals) : signals[0];
  };

  async function subprocess(args, input, timeout = 30_000, signal) {
    checkCancelled();
    const owned = startOwned(runtime.python, args, { cwd: root, env, signal: selectedSignal(signal), timeout: remaining(deadline, timeout), log: path.join(directory, 'helpers.log') });
    helpers.add(owned);
    owned.child.stdin.end(input === undefined ? undefined : JSON.stringify(input));
    let result;
    try { result = await owned.done; } finally { if (result?.cleanupVerified === true) helpers.delete(owned); }
    checkCancelled();
    if (result.code !== 0 || result.cleanupVerified !== true) throw fail(`RUNTIME_PROBE_FAILED:${result.cleanup_error ?? result.error ?? result.stderr?.slice(-2000) ?? result.stop_reason ?? result.code}`);
    try { return JSON.parse(result.stdout.trim().split('\n').at(-1)); } catch { throw fail('RUNTIME_PROBE_RESPONSE_INVALID'); }
  }
  const countSignal = signal => selectedSignal(signal, 30_000);
  async function tokenizeRaw(body, signal) {
    if (profile?.chat_token_endpoint) {
      const counted = await jsonResponse(await fetch(`${backendUpstream}${profile.chat_token_endpoint}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, model: preparedModel.directory, ...profile.sampling, context_management: [] }), signal: countSignal(signal), redirect: 'error' }));
      if (counted.trusted !== true || !integer(counted.input_tokens)) throw fail('TOKENIZER_ACCOUNTING_UNVERIFIED');
      return { trusted: true, inputTokens: counted.input_tokens, contextTokens: counted.input_tokens };
    }
    const counted = await subprocess([helper, 'tokenize', '--artifact', model.artifact, '--directory', preparedModel.directory], body, 30_000, signal);
    if (counted.exact !== true && counted.trusted !== true || !integer(counted.inputTokens) || !integer(counted.contextTokens) || counted.contextTokens < counted.inputTokens) throw fail('TOKENIZER_ACCOUNTING_UNVERIFIED');
    return { trusted: true, inputTokens: counted.inputTokens, contextTokens: counted.contextTokens };
  }
  async function stop(reason = 'model-block-finished') {
    const startedAt = Date.now();
    resourceSuspended = true;
    if (!server && !helpers.size && !resourcePending) return { stopped: true, cleanupVerified: true, elapsed_ms: Date.now() - startedAt };
    const released = await stopAdmissionProcesses({ owned: [...helpers, ...(server ? [server] : [])], resourcePending, reason, record, startedAt });
    server = undefined; helpers.clear(); persistentHelpers.clear();
    return released;
  }
  async function launch() {
    checkCancelled();
    const port = await unusedPort(); upstream = `http://127.0.0.1:${port}`; backendUpstream = upstream; serverExited = false;
    checkCancelled();
    const command = [path.join(root, model.id === 'minicpm' ? 'evals/local/minicpm_server.py' : 'evals/local/mlx_server.py')];
    const capture = model.id === 'minicpm' ? ['--evidence-directory', path.join(directory, 'private-generations')] : [];
    record({ type: 'runtime_adapter', file: command[0], private_generation_directory: model.id === 'minicpm' ? path.join(directory, 'private-generations') : null });
    server = startOwned(runtime.python, [...command, '--model', preparedModel.directory, '--host', '127.0.0.1', '--port', String(port), ...capture], { cwd: root, env, signal: admissionSignal, timeout: remaining(deadline, deadline - Date.now()), log: path.join(directory, 'server.log') });
    resourceSuspended = false;
    server.child.stdin.end();
    const selected = server;
    selected.done.then(outcome => { if (server === selected) serverExited = true; record({ type: 'server_exit', outcome }); });
    const until = Math.min(deadline, Date.now() + 120_000);
    while (Date.now() < until) {
      checkCancelled();
      if (serverExited) throw fail('MODEL_SERVER_EXITED');
      try {
        const response = await fetch(`${upstream}/health`, { signal: selectedSignal(undefined, 1000, until), redirect: 'error' });
        if (response.ok) {
          const models = await jsonResponse(await fetch(`${upstream}/v1/models`, { signal: selectedSignal(undefined, 5000, until), redirect: 'error' }));
          if (!Array.isArray(models.data) || models.data.length !== 1 || ![preparedModel.directory, model.artifact].includes(models.data[0]?.id)) throw fail('SINGLE_MODEL_INVENTORY_UNVERIFIED');
          const identity = await jsonResponse(await fetch(`${upstream}/local-eval/runtime-identity`, { signal: selectedSignal(undefined, 5000, until), redirect: 'error' }));
          const observed = verifyLoadedRuntimeIdentity(identity, model, preparedModel, runtime);
          if (runtimeIdentity && runtimeIdentity.sha256 !== observed.sha256) throw fail('MODEL_LOADED_IDENTITY_CHANGED');
          runtimeIdentity = observed;
          if (serverExited) throw fail('MODEL_SERVER_EXITED');
          record({ type: 'server_ready', upstream, models, runtime_identity: runtimeIdentity });
          await sampleResources('server-ready'); return;
        }
      } catch (error) { checkCancelled(); if (['SINGLE_MODEL_INVENTORY_UNVERIFIED', 'MODEL_SERVER_EXITED'].includes(error.code) || typeof error.code === 'string' && error.code.startsWith('MODEL_LOADED_')) throw error; }
      await delay(Math.min(250, Math.max(0, until - Date.now())));
    }
    throw fail('MODEL_SERVER_HEALTH_TIMEOUT');
  }
  async function activateTranslation() {
    checkCancelled();
    nativeProtocolFields = structuredClone(profile.protocol_fields);
    if (!translationRuntime) return;
    if (translationRuntime.status !== 'prepared' || translationRuntime.packages?.litellm !== '1.109.0' || !path.isAbsolute(translationRuntime.python ?? '') || !/^[a-f0-9]{64}$/.test(translationRuntime.lock_sha256 ?? '')) throw fail('TRANSLATION_RUNTIME_UNVERIFIED');
    const port = await unusedPort(), address = `http://127.0.0.1:${port}`;
    checkCancelled();
    const traffic = path.join(directory, 'translation.jsonl'), configuration = path.join(directory, 'translation.json');
    writeFileSync(configuration, JSON.stringify({ upstream: backendUpstream, model: preparedModel.directory, artifact: model.artifact, native_protocols: Object.keys(nativeProtocolFields), traffic }), { mode: 0o600 });
    writeFileSync(traffic, '', { mode: 0o600 });
    const owned = startOwned(translationRuntime.python, [path.join(root, 'evals/local/translation.py'), '--config', configuration, '--port', String(port)], { cwd: root, env, signal: admissionSignal, timeout: remaining(deadline, deadline - Date.now()), log: path.join(directory, 'translation-server.log') });
    helpers.add(owned); persistentHelpers.add(owned); owned.child.stdin.end();
    let exited = false;
    owned.done.then(outcome => { exited = true; record({ type: 'translation_exit', outcome }); });
    const until = Math.min(deadline, Date.now() + 30_000);
    let ready = false;
    while (Date.now() < until) {
      checkCancelled();
      if (exited) throw fail('TRANSLATION_SERVER_EXITED');
      try {
        const response = await jsonResponse(await fetch(`${address}/health`, { signal: selectedSignal(undefined, 1000, until), redirect: 'error' }));
        if (response.status === 'ok' && response.litellm === '1.109.0' && response.llguidance === '1.9.1' && response.model === preparedModel.directory) { ready = true; break; }
      } catch { checkCancelled(); /* Bounded owned startup; no generation or provider retry. */ }
      await delay(Math.min(250, Math.max(0, until - Date.now())));
    }
    if (!ready || exited) throw fail('TRANSLATION_SERVER_HEALTH_TIMEOUT');
    const translated = ['gemini', ...(nativeProtocolFields.responses ? [] : ['responses']), ...(nativeProtocolFields.messages ? [] : ['messages'])];
    const fields = [...new Set([...Object.keys(profile.sampling), 'seed'])].sort();
    for (const protocol of translated) profile.protocol_fields[protocol] = [...fields, ...(protocol === 'responses' ? ['context_management'] : [])].sort();
    capability.protocols = Object.keys(profile.protocol_fields);
    upstream = address;
    translationEvidence = { runtime: 'litellm', version: '1.109.0', runtime_lock_sha256: translationRuntime.lock_sha256, traffic, translated_protocols: translated, backend_upstream: backendUpstream, semantic_repairs: false,
      custom_responses: { encoding: 'function-with-exact-input-string', grammar_validation: 'llguidance-1.9.1-post-generation', constrained_decoding: false },
      namespace_responses: { encoding: 'literal-namespace__name', collision_policy: 'reject', schema_preservation: 'exact', output_identity: 'declared-qualified-name-only' } };
    record({ type: 'translation_ready', ...translationEvidence, upstream });
  }
  async function charge(label) {
    checkCancelled();
    await sampleResources(`before-calibration:${label}`);
    checkCancelled();
    if (requests >= 4 || calibration.used >= calibration.maximum) throw fail('CALIBRATION_BUDGET_EXCEEDED');
    remaining(deadline, 1); requests++; calibration.used++;
    await calibration.onCharge?.({ used: calibration.used, maximum: calibration.maximum });
    record({ type: 'calibration_charged', label, model_requests: requests, campaign_requests: calibration.used });
    checkCancelled();
  }
  async function completion(body, label) {
    const count = await tokenizeRaw(body);
    if (count.contextTokens + body.max_tokens > 32768) throw fail('CONTEXT_ENVELOPE_EXCEEDED');
    await charge(label);
    const request = { ...body, model: preparedModel.directory, ...profile.sampling, seed: 17, stream: false, context_management: [] };
    record({ type: 'calibration_request', label, request, token_count: count });
    const started = Date.now();
    const response = await jsonResponse(await fetch(`${upstream}${profile.endpoint}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request), signal: selectedSignal(undefined, 90_000), redirect: 'error' }));
    record({ type: 'calibration_response', label, response, elapsed_ms: Date.now() - started });
    if (response.model !== preparedModel.directory && response.model !== model.artifact) throw fail('MODEL_ATTRIBUTION_UNVERIFIED');
    if (response.usage?.prompt_tokens !== count.inputTokens || !integer(response.usage?.completion_tokens) || response.usage.completion_tokens > body.max_tokens) throw fail('SERVER_TOKEN_ACCOUNTING_MISMATCH');
    if (!Array.isArray(response.choices) || response.choices.length !== 1 || !response.choices[0]?.message) throw fail('CHAT_PROTOCOL_UNVERIFIED');
    return { response, count };
  }
  async function contextBody(messages, envelope) {
    // Binary search uses the actual tokenizer and never performs inference.
    const target = envelope - 512, prefix = messages[0].content;
    let low = 0, high = envelope, best;
    for (let round = 0; round < 18 && low <= high; round++) {
      const amount = Math.floor((low + high) / 2), body = { messages: [{ ...messages[0], content: prefix + '\n' + 'neutral calibration padding '.repeat(amount) }, ...messages.slice(1)], tools: [PROBE_TOOL], max_tokens: 512 };
      const count = await tokenizeRaw(body);
      if (count.contextTokens <= target) { best = { body, count }; low = amount + 1; } else high = amount - 1;
    }
    if (!best || best.count.contextTokens < target - 16) throw fail('CONTEXT_ENVELOPE_UNVERIFIED');
    record({ type: 'context_input', evidence_kind: 'tokenizer-only-capacity-check', inference: false, requested_envelope: envelope, input_tokens: best.count.inputTokens, output_reserve: 512 });
    return best;
  }
  function admittedResult() {
    checkCancelled();
    return { status: 'admitted', admission_kind: 'mechanical', calibration_observations: calibrationObservations, upstream, wire_model: preparedModel.directory, evidence_directory: directory, capabilities: capability,
      artifact: model.artifact, revision: preparedModel.revision, runtime_lock_sha256: runtime.lock_sha256,
      runtime_identity: runtimeIdentity,
      cache_policy: cachePolicy, messages_protocol: messagesProtocol, ...(cacheEvidence ? { cache_policy_evidence: cacheEvidence } : {}),
      context_envelope: 16384, extended_context_envelope: capability.extended_context ? 32768 : null, sampling: profile.sampling, seed_behavior: profile.seed_behavior,
      protocol_fields: profile.protocol_fields, native_protocol_fields: nativeProtocolFields ?? profile.protocol_fields, ...(translationEvidence ? { translation_evidence: translationEvidence } : {}), protocol_evidence: { chat: 'calibrated-transport-and-token-accounting;semantic-outcomes-recorded-separately', ...(profile.protocol_fields.responses ? { responses: 'pinned-schema-and-exact-backend-token-accounting;native-agent-execution-pending' } : {}), ...(profile.protocol_fields.messages ? { messages: 'pinned-schema-and-native-token-endpoint;native-agent-execution-pending' } : {}) },
      model: { id: model.id, artifact: model.artifact, revision: preparedModel.revision }, stop,
      ownedProcesses,
      async resetConversationCache({ idle = false, signal } = {}) {
        checkCancelled();
        if (!server || serverExited) throw fail('MODEL_SERVER_NOT_RUNNING');
        if (idle !== true) throw fail('CACHE_RESET_REQUIRES_IDLE_CALLER');
        const proof = model.id === 'minicpm' ? { kind: 'conversation-cache-reset', inference: false, verified: true, persistent_cache: false, policy: cachePolicy,
          verification: 'source-bound-native-per-request-cache;no-persistent-reset-applicable' }
          : await resetMlxConversationCache({ upstream: backendUpstream, model: preparedModel.directory, idle, signal: selectedSignal(signal), deadline: Math.min(deadline, Date.now() + 5000), onObservation: record });
        record(proof); return proof;
      },
      async tokenize({ protocol, body, signal }) {
        checkCancelled();
        if (!capability.protocols.includes(protocol)) throw fail('PROTOCOL_TOKEN_ACCOUNTING_UNVERIFIED');
        if (!server || serverExited) throw fail('MODEL_SERVER_NOT_RUNNING');
        if (translationEvidence && (translationEvidence.translated_protocols.includes(protocol) || protocol === 'responses' && needsResponsesTranslation(body))) {
          const transformed = await jsonResponse(await fetch(`${upstream}/local-eval/transform`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ protocol, body }), signal: countSignal(signal), redirect: 'error' }));
          if (!transformed.body || transformed.body.model !== preparedModel.directory) throw fail('TRANSLATION_MODEL_ATTRIBUTION_UNVERIFIED');
          const counted = await tokenizeRaw(transformed.body, signal);
          record({ type: 'translated_token_count', protocol, backend_request: transformed.body, tokens: counted });
          return counted;
        }
        if (protocol === 'responses' || protocol === 'messages') {
          const endpoint = protocol === 'responses' ? profile.responses_token_endpoint : profile.messages_token_endpoint;
          const response = await jsonResponse(await fetch(`${backendUpstream}${endpoint}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, model: preparedModel.directory }), signal: countSignal(signal), redirect: 'error' }));
          if (!integer(response.input_tokens)) throw fail(`${protocol.toUpperCase()}_TOKEN_ACCOUNTING_UNVERIFIED`);
          record({ type: `native_${protocol}_token_count`, input_tokens: response.input_tokens });
          return { trusted: true, inputTokens: response.input_tokens, contextTokens: response.input_tokens };
        }
        return tokenizeRaw(body, signal);
      } };
  }

  try {
    checkCancelled();
    await sampleResources('before-launch');
    if (observeResources) resourceTimer = setInterval(() => { if (!resourceFailure) void sampleResources('admission-running').catch(() => {}); }, 2000);
    onProgress(`Admitting exact ${model.artifact}`);
    if (model.id !== 'minicpm' && runtime.packages?.['mlx-vlm'] !== '0.7.11') throw fail('MLX_RUNTIME_VERSION_UNVERIFIED');
    await launch();
    const document = await jsonResponse(await fetch(`${upstream}/openapi.json`, { signal: selectedSignal(undefined, 10_000), redirect: 'error' }));
    record({ type: 'server_openapi', document });
    const nativeSchemas = model.id === 'minicpm' ? undefined : await subprocess(['-I', '-B', '-c', NATIVE_SCHEMAS], undefined);
    if (nativeSchemas) record({ type: 'installed_native_schemas', schemas: nativeSchemas });
    if (model.id !== 'minicpm') cacheEvidence = verifyMlxCacheConfiguration(document, nativeSchemas);
    profile = servingProfile(document, model, nativeSchemas); record({ type: 'frozen_serving_profile', profile, messages_protocol: messagesProtocol, cache_policy: cachePolicy, cache_policy_evidence: cacheEvidence, runtime_lock_sha256: runtime.lock_sha256, model_revision: preparedModel.revision });
    if (model.id === 'minicpm' && !profile.chat_token_endpoint) throw fail('MINICPM_PROCESSOR_ACCOUNTING_UNVERIFIED');
    // Exercise the actual management contract before any calibrated generation.
    // A broken or unobserved cache route cannot become a scored-row surprise.
    await admittedResult().resetConversationCache({ idle: true });
    if (reuseAdmission !== undefined) {
      const prior = reuseAdmission;
      if (prior?.status !== 'admitted' || prior.artifact !== model.artifact || prior.revision !== preparedModel.revision ||
          prior.runtime_lock_sha256 !== runtime.lock_sha256 || prior.wire_model !== preparedModel.directory || JSON.stringify(prior.cache_policy) !== JSON.stringify(cachePolicy) ||
          JSON.stringify(prior.messages_protocol) !== JSON.stringify(messagesProtocol) ||
          prior.runtime_identity?.sha256 !== runtimeIdentity?.sha256 ||
          JSON.stringify(prior.sampling) !== JSON.stringify(profile.sampling) || prior.seed_behavior !== profile.seed_behavior ||
          JSON.stringify(prior.native_protocol_fields ?? prior.protocol_fields) !== JSON.stringify(profile.protocol_fields) ||
          (prior.translation_evidence?.runtime_lock_sha256 ?? null) !== (translationRuntime?.lock_sha256 ?? null) ||
          prior.context_envelope !== 16384 || prior.extended_context_envelope !== (prior.capabilities?.extended_context ? 32768 : null) ||
          prior.admission_kind !== 'mechanical' || !['text', 'ordinary_context', 'cancellation'].every(key => prior.capabilities?.[key] === true) ||
          typeof prior.capabilities?.tools !== 'boolean' ||
          typeof prior.capabilities?.images !== 'boolean' || typeof prior.capabilities?.extended_context !== 'boolean' ||
          !Array.isArray(prior.capabilities?.protocols) || !Object.keys(profile.protocol_fields).every(protocol => prior.capabilities.protocols.includes(protocol))) throw fail('REUSED_ADMISSION_IDENTITY_MISMATCH');
      Object.assign(capability, structuredClone(prior.capabilities));
      calibrationObservations = structuredClone(prior.calibration_observations ?? {});
      record({ type: 'reused_admission', previous_evidence_directory: prior.evidence_directory, artifact: prior.artifact, revision: prior.revision,
        runtime_lock_sha256: prior.runtime_lock_sha256, calibration_inference_requests: 0 });
      await activateTranslation();
      await finishResourceMonitoring();
      return admittedResult();
    }
    const initial = [{ role: 'user', content: 'This is a protocol calibration. Call calibration_echo with value "ready".' }];
    const ordinary = await completion({ messages: initial, tools: [PROBE_TOOL], max_tokens: 128 }, 'compact-tool-transport');
    capability.text = true; capability.ordinary_context = true;
    const choice = ordinary.response.choices[0], call = choice.message.tool_calls?.[0];
    let args; try { args = JSON.parse(call?.function?.arguments); } catch { /* A model answer is evidence, not a transport failure. */ }
    capability.tools = choice.finish_reason === 'tool_calls' && choice.message.tool_calls?.length === 1 && call?.type === 'function' && call.function?.name === 'calibration_echo' && typeof call.id === 'string' && !!call.id && args?.value === 'ready' && Object.keys(args).length === 1;
    calibrationObservations.tool_call = { observed: capability.tools, response: choice.message };
    // This independent fixture verifies that the transport accepts tool history.
    // It never repairs a model response or becomes part of a scored conversation.
    const fixtureCall = { role: 'assistant', content: null, tool_calls: [{ id: 'calibration-fixture', type: 'function', function: { name: 'calibration_echo', arguments: '{"value":"ready"}' } }] };
    const continued = [...initial, fixtureCall, { role: 'tool', tool_call_id: 'calibration-fixture', content: 'ready' }, { role: 'user', content: 'The tool returned ready. Briefly acknowledge the result.' }];
    record({ type: 'tool_history_fixture', origin: 'independent-inert-protocol-fixture', synthetic: true });
    const configuration = JSON.parse(readFileSync(path.join(preparedModel.directory, 'config.json'), 'utf8'));
    const declaredContext = (configuration.text_config ?? configuration.llm_config ?? configuration).max_position_embeddings;
    if (!integer(declaredContext) || declaredContext < 16384) throw fail('DECLARED_CONTEXT_CAPACITY_UNVERIFIED');
    const ordinaryCapacity = await contextBody(continued, 16384);
    calibrationObservations.context = { evidence_kind: 'configuration-and-tokenizer-only', inference: false, declared_model_capacity: declaredContext,
      enforced_ordinary_envelope: 16384, ordinary_input_tokens: ordinaryCapacity.count.inputTokens, ordinary_context_tokens: ordinaryCapacity.count.contextTokens, output_reserve: 512,
      enforced_extended_envelope: null, semantic_and_latency_verification: 'deferred-to-scored-native-workflows' };
    try {
      if (declaredContext < 32768) throw fail('DECLARED_EXTENDED_CONTEXT_CAPACITY_UNVERIFIED');
      const extendedCapacity = await contextBody(continued, 32768);
      capability.extended_context = true;
      calibrationObservations.context.enforced_extended_envelope = 32768;
      calibrationObservations.context.extended_input_tokens = extendedCapacity.count.inputTokens;
      calibrationObservations.context.extended_context_tokens = extendedCapacity.count.contextTokens;
    } catch (error) {
      checkCancelled();
      record({ type: 'extended_context_blocked', evidence_kind: 'configuration-and-tokenizer-only', inference: false, reason: error.code ?? error.message, enforced_ordinary_envelope: 16384 });
    }
    const continuedResponse = await completion({ messages: continued, tools: [PROBE_TOOL], max_tokens: 128 }, 'compact-tool-history-transport');
    calibrationObservations.tool_history = { transport_accepted: true, response: continuedResponse.response.choices[0].message };
    capability.protocols = Object.keys(profile.protocol_fields);

    // Count image preprocessing before requesting generation. Unsupported accounting
    // stays explicit and cannot certify a pixel-dependent episode.
    const beforeImage = requests;
    try {
      if (requests >= 3) throw fail('IMAGE_PROBE_NOT_ADMITTED_WITHIN_CALIBRATION_BUDGET');
      const image = readFileSync(path.join(root, 'evals/local/fixtures/diagram.png')).toString('base64');
      const body = { messages: [{ role: 'user', content: [{ type: 'text', text: 'Name the highlighted dependency relation.' }, { type: 'image_url', image_url: { url: `data:image/png;base64,${image}` } }] }], max_tokens: 128 };
      const observed = await completion(body, 'image-input');
      calibrationObservations.image = { transport_accepted: true, response: observed.response.choices[0].message, semantic_verification: 'deferred-to-independent-S5-oracle' };
      capability.images = true;
    } catch (error) {
      checkCancelled();
      record({ type: 'image_capability_blocked', reason: error.code ?? error.message });
      if (requests > beforeImage) { await stop('image-probe-failed'); await launch(); }
    }

    const controller = new AbortController(), request = { model: preparedModel.directory, messages: [{ role: 'user', content: 'Keep counting positive integers in order until the output limit. Do not stop early.' }], ...profile.sampling, seed: 23, stream: true, max_tokens: 512, context_management: [] };
    const cancellationTokens = await tokenizeRaw(request);
    await charge('owned-generation-cancellation');
    record({ type: 'calibration_request', label: 'owned-generation-cancellation', request, token_count: cancellationTokens });
    const response = await fetch(`${upstream}${profile.endpoint}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request), signal: selectedSignal(controller.signal, 90_000), redirect: 'error' });
    if (!response.ok || !response.headers.get('content-type')?.includes('text/event-stream')) throw fail('STREAM_CANCELLATION_UNVERIFIED');
    const reader = response.body.getReader(); let stream = '', generating = false;
    while (stream.length < 1024 * 1024) {
      const next = await reader.read(); if (next.done) break; stream += Buffer.from(next.value).toString('utf8');
      if (stream.includes('[DONE]')) break;
      if (/"content"\s*:\s*"[^"\s]/.test(stream)) { generating = true; break; }
    }
    record({ type: 'cancellation_stream_prefix', stream, generating });
    controller.abort(); void reader.cancel().catch(() => {});
    const cancelled = await stop('calibration-cancellation');
    if (!generating || cancelled.elapsed_ms > 5000) throw fail('STREAM_CANCELLATION_UNVERIFIED');
    capability.cancellation = true;
    await launch();
    await activateTranslation();
    await finishResourceMonitoring();
    return admittedResult();
  } catch (error) {
    clearInterval(resourceTimer); resourceTimer = undefined;
    let cleanup;
    try { cleanup = await stop('admission-failed'); } catch (failure) { cleanup = { stopped: false, cleanupVerified: false, reason: failure.code ?? failure.message }; }
    const reason = resourceFailure ? resourceFailure.code ?? resourceFailure.message : admissionSignal?.aborted ? 'ADMISSION_CANCELLED' : error.code ?? error.message; record({ type: 'admission_blocked', reason, cleanup, capabilities: capability });
    return { status: /CONTEXT|TOKENIZER|TOKEN_ACCOUNTING/.test(reason) ? 'context_resource_blocked' : 'model_blocked', reason, evidence_directory: directory, capabilities: capability, cleanup };
  } finally {
    clearInterval(resourceTimer);
  }
}
