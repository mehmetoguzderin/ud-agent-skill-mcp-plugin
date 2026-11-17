/** Frozen causal diagnostic studies. No inference, process or installation on import. MIT. */
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { assertOptIn } from './preparation.mjs';
import { MODELS, SEEDS } from './registry.mjs';

const minute = 60_000;
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const LEGACY_STUDY_POLICY = freeze({ duration_ms: 480 * minute, model_ms: 145 * minute, reconciliation_ms: 45 * minute,
  expected_units: { probe: 252, native: 108, forward: 72 }, maximum_inference_requests: 1332,
  calibration_limit: 12, calibration_per_model: 4, maximum_total_inference_requests: 1344,
  maximum_generated_tokens: 350208, maximum_instrumented_forwards: 72,
  episode: { duration_ms: 90_000, cancellation_grace_ms: 5000, inference_requests: 10, visible_calls: 12, ud_operations: 12,
    output_per_request: 512, output_per_episode: 2048, input_envelope: 16384, cumulative_input: 6 * 16384 } });
export const STUDY_POLICY = freeze({ ...LEGACY_STUDY_POLICY, lifecycle_version: 2, native_setup_ms: 60_000 });
export const STUDY_CONDITIONS = Object.freeze([
  'unchanged', 'neutral-framing', 'metadata-near-request', 'reduced-narrative', 'activated-skill', 'actionable-guidance',
]);
export const STUDY_STAGES = Object.freeze(['exposure', 'activation', 'discovery', 'valid_call', 'dispatch', 'interpretation', 'verified_completion']);
const harnesses = ['qwen-code', 'mini-swe-agent'];
const hash = value => sha256(JSON.stringify(value));
const plain = value => JSON.parse(JSON.stringify(value));
const isHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const ensure = (value, message) => { if (!value) throw new Error(message); };
function immutable(file, value) { writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o400 }); chmodSync(file, 0o400); }
function checkedTime(value) { ensure(Number.isSafeInteger(value) && value >= 0, 'Study time must be an integer timestamp.'); return value; }

/** All seeds cross both native harnesses and both positive intents. Same-seed
 * repeat is an exact-request repeat, not an additional sampler seed. */
export function buildStudyRows() {
  const rows = [];
  const add = value => rows.push({ id: hash(value), ...value });
  for (const model of MODELS) for (const seed of SEEDS) {
    for (const harness of harnesses) for (const scenario of ['S2', 'S3']) {
      const block = `${model.id}/${harness}/${scenario}/seed-${seed}`;
      for (const condition of [...STUDY_CONDITIONS, 'unchanged-repeat']) add({ kind: 'probe', model_id: model.id, model_artifact: model.artifact,
        harness_id: harness, scenario_id: scenario, seed, block, condition, exact_repeat_of: condition === 'unchanged-repeat' ? `${block}/unchanged` : null,
        diagnostic_only: true, implicit_selection_credit: false, maximum_inference_requests: 1, maximum_generated_tokens: 512 });
    }
    for (const harness of harnesses) for (const scenario of ['S2', 'S3', 'S7']) for (const condition of ['current', 'task-neutral-actionable']) add({
      kind: 'native', model_id: model.id, model_artifact: model.artifact, harness_id: harness, scenario_id: scenario, seed,
      block: `${model.id}/${harness}/${scenario}/seed-${seed}`, condition, diagnostic_only: true, implicit_selection_credit: true,
      maximum_inference_requests: 10, maximum_generated_tokens: 2048,
    });
    for (const harness of harnesses) for (const scenario of ['S2', 'S3']) for (const condition of ['reference-forward', 'instrumented-forward']) add({
      kind: 'forward', model_id: model.id, model_artifact: model.artifact, harness_id: harness, scenario_id: scenario, seed,
      block: `${model.id}/${harness}/${scenario}/seed-${seed}`, condition, diagnostic_only: true, implicit_selection_credit: false,
      maximum_inference_requests: 0, maximum_generated_tokens: 0,
    });
  }
  return rows;
}
function validateBindings(bindings) {
  ensure(bindings && typeof bindings === 'object', 'Frozen study identity bindings are required.');
  for (const key of ['evaluator', 'oracle', 'fixtures', 'product', 'models', 'clients', 'runtimes', 'interventions', 'analysis'])
    ensure(isHash(bindings[key]), `Study binding requires SHA256: ${key}.`);
  return plain(bindings);
}
function studyPath(root, directory) {
  const base = path.resolve(root, '.artifacts/local-evals/studies'), full = path.resolve(directory);
  ensure(full.startsWith(base + path.sep), 'Study storage must be repository-owned under .artifacts/local-evals/studies.');
  return full;
}
/** Preparation does not start either clock. The first model admission does. */
export function createStudy({ root, directory, optIn = false, environment = process.env, bindings, now = Date.now(), metadata = {} }) {
  assertOptIn({ optIn }, environment); checkedTime(now);
  const location = studyPath(root, directory), rows = buildStudyRows();
  ensure(!existsSync(location), 'Study directory already exists; resume it without replenishing allowances.');
  const manifest = { schema_version: 1, kind: 'ud-causal-diagnostic-study', id: randomUUID(), created_at: now,
    bindings: validateBindings(bindings), metadata: plain(metadata), policy: STUDY_POLICY, conditions: STUDY_CONDITIONS,
    stages: STUDY_STAGES, rows, qualification_evidence: false, models: MODELS, seeds: SEEDS };
  mkdirSync(location, { recursive: true, mode: 0o700 }); mkdirSync(path.join(location, 'journal'), { mode: 0o700 });
  immutable(path.join(location, 'manifest.json'), manifest);
  immutable(path.join(location, 'manifest.sha256.json'), { sha256: hash(manifest), bytes_sha256: sha256(readFileSync(path.join(location, 'manifest.json'))) });
  return { directory: location, manifest, manifest_sha256: hash(manifest), clock_started: false };
}
function readManifest(directory, bindings) {
  const manifestBytes = readFileSync(path.join(directory, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const receipt = JSON.parse(readFileSync(path.join(directory, 'manifest.sha256.json'), 'utf8'));
  ensure(receipt.sha256 === hash(manifest) && receipt.bytes_sha256 === sha256(manifestBytes), 'Study manifest bytes changed.');
  ensure(manifest.schema_version === 1 && manifest.kind === 'ud-causal-diagnostic-study', 'Unsupported study manifest.');
  ensure([hash(STUDY_POLICY), hash(LEGACY_STUDY_POLICY)].includes(hash(manifest.policy)) && hash(manifest.rows) === hash(buildStudyRows()), 'Frozen study schedule or ceilings changed.');
  ensure(hash(manifest.conditions) === hash(STUDY_CONDITIONS) && hash(manifest.stages) === hash(STUDY_STAGES), 'Frozen study analysis changed.');
  if (bindings) ensure(hash(validateBindings(bindings)) === hash(manifest.bindings), 'Frozen study identity changed.');
  return manifest;
}
function readJournal(directory) {
  const journal = path.join(directory, 'journal'), names = readdirSync(journal).sort();
  let prior = null;
  return names.map((name, index) => {
    ensure(name === `${String(index).padStart(6, '0')}.json`, 'Study journal is incomplete or reordered.');
    const event = JSON.parse(readFileSync(path.join(journal, name), 'utf8'));
    const { entry_sha256, ...payload } = event;
    ensure(event.sequence === index && event.previous_sha256 === prior && entry_sha256 === hash(payload), 'Study journal chain changed.');
    prior = hash(event); return event;
  });
}
function replay(manifest, events) {
  const state = { started_at: null, deadline: null, active_model: null, active_row: null, models: {}, rows: {}, closed: false,
    charged: { inference_requests: 0, generated_tokens: 0, forwards: 0 } };
  for (const event of events) {
    const value = event.value;
    if (event.type === 'model_started') {
      if (state.started_at === null) { state.started_at = event.at; state.deadline = event.at + manifest.policy.duration_ms; }
      state.active_model = value.model_id;
      state.models[value.model_id] = { started_at: event.at, deadline: Math.min(event.at + manifest.policy.model_ms, state.deadline - manifest.policy.reconciliation_ms), released: false };
    } else if (event.type === 'row_claimed') {
      state.active_row = value.row_id; state.rows[value.row_id] = { status: 'running', claimed_at: event.at, reservation: value };
      state.charged.inference_requests += value.inference_requests;
      state.charged.generated_tokens += value.generated_tokens;
      state.charged.forwards += value.forwards;
    } else if (event.type === 'row_recorded') {
      state.rows[value.row_id] = { ...state.rows[value.row_id], status: 'recorded', recorded_at: event.at, result: value.result };
      state.active_row = null;
    } else if (event.type === 'unit_cleanup_reconciled') {
      state.rows[value.row_id].cleanup_reconciliation = value.proof;
    } else if (event.type === 'model_released') {
      state.models[value.model_id].released = true; state.models[value.model_id].release = value.proof;
      state.active_model = null;
    } else if (event.type === 'reconciled') state.closed = true;
  }
  return state;
}
function verifyFileEvidence(item, root, directory) {
  ensure(item && typeof item.path === 'string' && isHash(item.sha256), 'Positive observations require hash-bound file evidence.');
  const file = path.isAbsolute(item.path) ? path.resolve(item.path) : path.resolve(directory, item.path);
  const realRoot = realpathSync(root);
  let bytes;
  try {
    ensure(lstatSync(file).isFile() && !lstatSync(file).isSymbolicLink(), 'Study evidence must be a regular file.');
    ensure(realpathSync(file).startsWith(realRoot + path.sep), 'Study evidence must remain repository-owned.');
    bytes = readFileSync(file);
  } catch (error) { throw new Error(`Study evidence unavailable: ${item.path}: ${error.message}`); }
  ensure(sha256(bytes) === item.sha256, `Study evidence bytes changed: ${item.path}`);
  return bytes;
}
function normalizedResult(row, result, { root, directory, state }) {
  ensure(result && ['observed', 'blocked', 'failed', 'cancelled', 'incomplete'].includes(result.status), 'A terminal diagnostic status is required.');
  if (result.status !== 'observed') ensure(typeof result.reason === 'string' && result.reason.trim(), 'Unexecuted or failed study units require an explicit reason.');
  ensure(result.owned_cleanup_verified === true || result.owned_cleanup_verified === false, 'Study unit cleanup must be observed explicitly.');
  const stages = Object.fromEntries(STUDY_STAGES.map(name => [name, result.stages?.[name] === true ? true : result.stages?.[name] === false ? false : null]));
  if (Object.values(stages).includes(true) || result.status === 'observed') ensure(Array.isArray(result.evidence) && result.evidence.length > 0, 'Positive stage observations require hash-bound evidence.');
  for (const item of result.evidence ?? []) verifyFileEvidence(item, root, directory);
  if (stages.verified_completion === true) {
    ensure(result.independent_verification?.status === 'passed' && isHash(result.independent_verification?.sha256), 'Completion requires independent oracle evidence.');
    verifyFileEvidence(result.independent_verification, root, directory);
  }
  if (row.kind !== 'native') ensure(result.qualification_claim !== true, 'Diagnostic probes cannot establish native qualification.');
  const limits = { inference: row.maximum_inference_requests, tools: row.kind === 'forward' ? 0 : 12, ud_operations: row.kind === 'native' ? 12 : 0,
    output: row.maximum_generated_tokens, input: row.kind === 'native' ? 6 * 16384 : 16384 };
  if (result.status === 'observed') ensure(result.counters && Object.keys(limits).every(key => key in result.counters), 'Observed units require measured counters; unknown values must be null.');
  for (const [key, limit] of Object.entries(limits)) if (result.counters && key in result.counters && result.counters[key] !== null)
    ensure(Number.isSafeInteger(result.counters[key]) && result.counters[key] >= 0 && result.counters[key] <= limit, `Study observed counter exceeds reservation: ${key}.`);
  if (row.kind === 'probe' && result.status === 'observed') {
    const identity = result.request_identity;
    ensure(identity && isHash(identity.body_sha256) && typeof identity.body_path === 'string' && Number.isSafeInteger(identity.derived_seed), 'Observed probes require actual request and seed identity.');
    const expectedSeed = Number.parseInt(sha256(`${row.seed}:0`).slice(0, 8), 16) & 0x7fffffff;
    ensure(identity.derived_seed === expectedSeed, 'Probe seed does not match its frozen root seed and request ordinal.');
    const file = path.isAbsolute(identity.body_path) ? identity.body_path : path.resolve(directory, identity.body_path);
    const request = JSON.parse(readFileSync(file, 'utf8'));
    verifyFileEvidence({ path: file, sha256: sha256(readFileSync(file)) }, root, directory);
    ensure(hash(request) === identity.body_sha256 && request.seed === identity.derived_seed, 'Forwarded probe request identity differs from its evidence.');
    if (row.condition === 'unchanged-repeat') {
      const original = buildStudyRows().find(item => item.kind === 'probe' && item.block === row.block && item.condition === 'unchanged');
      const previous = state.rows[original.id]?.result;
      ensure(previous?.status === 'observed' && previous.request_identity?.body_sha256 === identity.body_sha256 && previous.request_identity?.derived_seed === identity.derived_seed, 'Unchanged repeat must use the identical forwarded request and effective seed.');
    }
  }
  return { ...plain(result), stages, qualification_claim: false, missing_observations_are_passes: false };
}

/** Lock + hash-chain journal prevents concurrent CLI processes from resetting or
 * duplicating a claim. A crashed lock is not automatically broken; an operator
 * must first verify owned process release. Row reservations never refund. */
export function openStudy({ root, directory, bindings, optIn = false, environment = process.env, now = () => Date.now() }) {
  const location = studyPath(root, directory), manifest = readManifest(location, bindings);
  const snapshot = () => replay(manifest, readJournal(location));
  const mutate = action => {
    assertOptIn({ optIn }, environment);
    const lock = path.join(location, '.lock');
    try { mkdirSync(lock, { mode: 0o700 }); } catch (error) { if (error.code === 'EEXIST') throw new Error('Study journal is locked by another process or an unreconciled interruption.'); throw error; }
    try {
      readManifest(location, bindings);
      const events = readJournal(location), state = replay(manifest, events), at = checkedTime(now());
      ensure(!events.length || at >= events.at(-1).at, 'Study clock moved backwards; allowances cannot be replenished.');
      const entry = action(state, at);
      const payload = { schema_version: 1, sequence: events.length, previous_sha256: events.length ? hash(events.at(-1)) : null, at, ...entry };
      immutable(path.join(location, 'journal', `${String(events.length).padStart(6, '0')}.json`), { ...payload, entry_sha256: hash(payload) });
      return snapshot();
    } finally { rmdirSync(lock); }
  };
  return { manifest, directory: location, snapshot,
    startModel(modelId) { return mutate((state, at) => {
      ensure(!state.closed && !state.active_model && !state.active_row, 'Only one resident model and active unit are allowed.');
      const expected = MODELS.find(model => !state.models[model.id]);
      ensure(expected?.id === modelId, 'Models must be admitted once in the frozen supplied order.');
      ensure(!state.deadline || at < state.deadline - manifest.policy.reconciliation_ms, 'Study execution deadline reached.');
      return { type: 'model_started', value: { model_id: modelId } };
    }); },
    claimRow(rowId) { return mutate((state, at) => {
      const row = manifest.rows.find(item => item.id === rowId);
      ensure(row && row.model_id === state.active_model && !state.active_row && !state.rows[rowId] && !state.closed, 'Study unit cannot be repeated or run outside its model block.');
      const pending = manifest.rows.find(item => item.model_id === state.active_model && !state.rows[item.id]);
      ensure(pending?.id === rowId, 'Study units follow the frozen seed-first schedule.');
      ensure(at < state.models[row.model_id].deadline, 'Model block deadline reached; reconcile remaining units as unfinished.');
      const reservation = { row_id: rowId, inference_requests: row.maximum_inference_requests, generated_tokens: row.maximum_generated_tokens, forwards: row.kind === 'forward' ? 1 : 0,
        deadline: Math.min(at + manifest.policy.episode.duration_ms + (row.kind === 'native' ? manifest.policy.native_setup_ms ?? 0 : 0), state.models[row.model_id].deadline),
        output_per_request: 512, input_envelope: 16384, cumulative_input: row.kind === 'native' ? 6 * 16384 : 16384 };
      ensure(state.charged.inference_requests + reservation.inference_requests <= manifest.policy.maximum_inference_requests &&
        state.charged.generated_tokens + reservation.generated_tokens <= manifest.policy.maximum_generated_tokens &&
        state.charged.forwards + reservation.forwards <= manifest.policy.maximum_instrumented_forwards, 'Study shared resource ceiling reached.');
      return { type: 'row_claimed', value: reservation };
    }); },
    recordRow(rowId, result) { return mutate((state) => {
      ensure(state.active_row === rowId && state.rows[rowId]?.status === 'running', 'Only the currently claimed study unit can be recorded.');
      const row = manifest.rows.find(item => item.id === rowId);
      return { type: 'row_recorded', value: { row_id: rowId, result: normalizedResult(row, result, { root, directory: location, state }) } };
    }); },
    reconcileUnitCleanup(rowId, proof) { return mutate(state => {
      ensure(manifest.policy.lifecycle_version >= 2 && !state.closed && !state.active_row && state.rows[rowId]?.status === 'recorded' && state.rows[rowId].result.owned_cleanup_verified === false, 'Only a terminal unresolved unit can receive independent release evidence.');
      ensure(!state.rows[rowId].cleanup_reconciliation && proof?.owned_cleanup_verified === true && proof.scope === 'episode' && proof.row_id === rowId, 'Independent release proof must bind the complete episode and cannot replace its grade.');
      verifyFileEvidence(proof, root, location);
      return { type: 'unit_cleanup_reconciled', value: { row_id: rowId, proof: plain(proof) } };
    }); },
    releaseModel(modelId, proof) { return mutate(state => {
      ensure(state.active_model === modelId && !state.active_row, 'Finish or cancel the active unit before releasing its model.');
      if (manifest.policy.lifecycle_version >= 2) ensure(!manifest.rows.some(row => row.model_id === modelId && state.rows[row.id]?.result?.owned_cleanup_verified === false && !state.rows[row.id].cleanup_reconciliation), 'Unit cleanup remains unresolved; retain the model block for independent reconciliation.');
      ensure(proof?.owned_cleanup_verified === true && isHash(proof.sha256), 'Model switching requires hash-bound verified owned release.');
      verifyFileEvidence(proof, root, location);
      return { type: 'model_released', value: { model_id: modelId, proof: plain(proof) } };
    }); },
    reconcile(reason) { return mutate(state => {
      ensure(!state.active_model && !state.active_row && !state.closed, 'Release owned work before final reconciliation.');
      ensure(typeof reason === 'string' && reason.trim(), 'Reconciliation needs an explicit completion or stopping reason.');
      return { type: 'reconciled', value: { reason, qualification_claim: false } };
    }); },
    report() {
      const state = snapshot(), errors = [];
      for (const row of manifest.rows) if (state.rows[row.id]?.status === 'recorded') {
        try { normalizedResult(row, state.rows[row.id].result, { root, directory: location, state }); state.rows[row.id].evidence_status = 'verified'; }
        catch (error) { state.rows[row.id].evidence_status = 'invalid'; errors.push({ row_id: row.id, reason: error.message }); }
      }
      for (const [rowId, record] of Object.entries(state.rows)) if (record.cleanup_reconciliation) {
        try { verifyFileEvidence(record.cleanup_reconciliation, root, location); }
        catch (error) { errors.push({ row_id: rowId, reason: error.message }); }
      }
      for (const [model, record] of Object.entries(state.models)) if (record.released) {
        try { verifyFileEvidence(record.release, root, location); }
        catch (error) { errors.push({ model_id: model, reason: error.message }); }
      }
      state.evidence_verification = { status: errors.length ? 'unmet' : 'passed', errors };
      return buildStudyReport(manifest, state);
    },
  };
}
export function buildStudyReport(manifest, state) {
  const rows = manifest.rows.map(row => ({ ...row, ...(state.rows[row.id] ?? { status: 'unattempted', reason: 'No immutable execution record; no success inferred.' }) }));
  const counts = Object.fromEntries(['probe', 'native', 'forward'].map(kind => [kind, {
    expected: rows.filter(row => row.kind === kind).length,
    recorded: rows.filter(row => row.kind === kind && row.status === 'recorded').length,
    unfinished: rows.filter(row => row.kind === kind && row.status !== 'recorded').length,
  }]));
  const paired = [];
  for (const row of rows.filter(item => item.condition === ({ probe: 'unchanged', native: 'current', forward: 'reference-forward' })[item.kind])) {
    const peers = rows.filter(item => item.kind === row.kind && item.block === row.block);
    paired.push({ kind: row.kind, block: row.block, comparisons: peers.filter(item => item.id !== row.id).map(treatment => ({ condition: treatment.condition,
      complete: row.status === 'recorded' && treatment.status === 'recorded' && row.result?.status === 'observed' && treatment.result?.status === 'observed' && row.evidence_status === 'verified' && treatment.evidence_status === 'verified',
      stages: Object.fromEntries(STUDY_STAGES.map(stage => {
        const a = row.result?.stages?.[stage], b = treatment.result?.stages?.[stage];
        return [stage, { unchanged: a ?? null, treatment: b ?? null, difference: row.evidence_status === 'verified' && treatment.evidence_status === 'verified' && typeof a === 'boolean' && typeof b === 'boolean' ? Number(b) - Number(a) : null }];
      })),
    })) });
  }
  return { schema_version: 1, kind: 'ud-causal-diagnostic-report', study_id: manifest.id, manifest_sha256: hash(manifest),
    harness_inventory: manifest.metadata.harness_inventory ?? [], harness_coverage: { scheduled_native_surfaces: 2, required_native_surfaces: 18, qualification_evidence: false },
    qualification_evidence: false, status: state.closed ? 'reconciled' : 'incomplete', clock: { started_at: state.started_at, deadline: state.deadline },
    models: state.models, evidence_verification: state.evidence_verification ?? { status: 'unverified', errors: [] }, charged_reservations: state.charged, counts, rows, paired,
    inference: 'Only captured provider/backend evidence establishes real inference; reservations are not measured usage.',
    analysis_limits: ['Harness and intent are crossed; model effects remain architecture/runtime/tokenizer/precision bundles.',
      'Seeds are repeated trials of fixed tasks, not independent task samples.', 'Constant outcomes do not identify success correlations.',
      'Forced activation and forward probes never establish implicit native selection or starter qualification.'] };
}

/** The executor must supply actual provider/native/forward evidence. There is no
 * synthetic default. Resuming a running claim requires externally verified
 * cleanup and a terminal record before this helper can continue. */
export async function runStudy({ study, admit, execute, release, onProgress = () => {}, shouldStart = () => true }) {
  ensure(typeof admit === 'function' && typeof execute === 'function' && typeof release === 'function', 'Real study execution callbacks are required.');
  let state = study.snapshot();
  ensure(!state.active_row, 'Unreconciled running study unit; verify owned cancellation and record its terminal outcome first.');
  if (study.manifest.policy.lifecycle_version >= 2) ensure(!Object.values(state.rows).some(record => record.result?.owned_cleanup_verified === false && !record.cleanup_reconciliation), 'Unresolved owned unit cleanup; independent episode release evidence is required before resume.');
  for (const model of MODELS) {
    state = study.snapshot(); if (state.models[model.id]?.released) continue;
    if (!state.active_model) study.startModel(model.id);
    let resident;
    try {
      resident = await admit(model, study.manifest);
      for (const row of study.manifest.rows.filter(item => item.model_id === model.id)) {
        if (study.snapshot().rows[row.id]) continue;
        if (!await shouldStart(row, study.snapshot())) break;
        const claimed = study.claimRow(row.id), reservation = claimed.rows[row.id].reservation;
        onProgress({ type: 'unit_started', row, reservation });
        // Callback failures leave the reserved unit running until independent
        // cancellation verification. No optimistic cleanup or retry is invented.
        const result = await execute({ row, reservation, resident, manifest: study.manifest });
        study.recordRow(row.id, result); onProgress({ type: 'unit_recorded', row, result });
        ensure(result.owned_cleanup_verified === true, 'Study unit cleanup unresolved; stop before the next unit.');
      }
    } finally {
      const proof = await release(resident, model);
      const current = study.snapshot(), unresolved = study.manifest.policy.lifecycle_version >= 2 && study.manifest.rows.some(row => row.model_id === model.id && current.rows[row.id]?.result?.owned_cleanup_verified === false && !current.rows[row.id].cleanup_reconciliation);
      if (!current.active_row && !unresolved) study.releaseModel(model.id, proof);
    }
  }
  if (!study.snapshot().active_model) study.reconcile('Frozen model blocks exhausted or forecast stopped further units.');
  return study.report();
}
