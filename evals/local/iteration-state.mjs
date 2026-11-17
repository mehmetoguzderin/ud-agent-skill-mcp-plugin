// SPDX-License-Identifier: MIT
/** Immutable, bounded diagnostic rounds. Importing this module runs no models. */
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { assertOptIn } from './preparation.mjs';
import { DEFAULT_LIMITS } from './budget.mjs';
import { HARNESSES, MODELS, SEEDS } from './registry.mjs';
import { PROFILE, HEADLESS_POLICY, buildHeadlessRows, buildHeadlessCoverage, headlessReferenceRows, headlessQualification } from './headless-profile.mjs';

const minute = 60_000;
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const clone = value => JSON.parse(JSON.stringify(value));
const hash = value => sha256(JSON.stringify(value));
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const ensure = (value, message) => { if (!value) throw new Error(message); };
export const ITERATION_STAGES = freeze(['exposure', 'activation', 'discovery', 'valid_call', 'dispatch', 'interpretation', 'verified_completion']);
export const ITERATION_POLICY = freeze({ duration_ms: 180 * minute, reconciliation_ms: 15 * minute, maximum_scored_episodes: 69,
  maximum_repair_rounds: 2, calibration_limit: 12, calibration_per_model: 4, maximum_inference_requests: 690,
  maximum_total_inference_requests: 702, maximum_generated_tokens: 69 * 2048, seeds: SEEDS,
  episode: { ...DEFAULT_LIMITS, input_envelope: 16384, cumulative_input: 6 * 16384, native_setup_ms: 60_000 },
  qualification_evidence: false });
const sharedKeys = ['evaluator', 'oracle', 'tasks', 'model_configuration'];
const counterLimits = { inference: 10, tools: 12, ud_operations: 12, output: 2048, input: 6 * 16384 };
const outcomes = new Set(['passed', 'failed', 'model_blocked', 'interface_unsupported', 'timed_out', 'token_budget_exceeded', 'context_resource_blocked', 'incomplete', 'not_run']);
const positiveObservations = ['real_inference', 'native_loop', 'model_attribution', 'independent_verification', 'budget_enforced', 'final_answer_verified', 'no_user_hints'];
export function policyForProfile(profile) {
  if (profile === undefined) return ITERATION_POLICY;
  ensure(profile === PROFILE, 'Unknown iteration profile.');
  return HEADLESS_POLICY;
}
const rowCounterLimits = (row, profile) => profile === PROFILE ? { ...counterLimits, input: 6 * (row.scenario_id === 'S4' ? 32768 : 16384) } : counterLimits;

/** Crossed intents deliberately remain diagnostic rows, outside the fixed171 registry. */
export function buildIterationRows({ kind = 'baseline', roundId = kind, profile } = {}) {
  if (profile !== undefined) { policyForProfile(profile); return buildHeadlessRows({ kind, roundId }); }
  ensure(['baseline', 'repair', 'transfer', 'claude-transfer'].includes(kind), 'Unknown iteration round kind.');
  ensure(typeof roundId === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(roundId), 'Invalid iteration round identity.');
  const definitions = kind === 'transfer'
    ? [['lfm3', ['S2'], ['qwen-code', 'mini-swe-agent']], ['minicpm', ['S3', 'S7'], ['qwen-code', 'mini-swe-agent']], ['bonsai', ['S3', 'S7'], ['qwen-code', 'mini-swe-agent']]]
    : kind === 'claude-transfer' ? [['lfm3', ['S2'], ['claude-code']]] : [['lfm3', ['S3', 'S7'], ['qwen-code', 'mini-swe-agent']]];
  const rows = [];
  for (const [modelId, scenarios, harnesses] of definitions) for (const seed of SEEDS) for (const harnessId of harnesses) for (const scenarioId of scenarios) {
    const cell = `${modelId}/${harnessId}/${scenarioId}/seed-${seed}`, id = `${roundId}/${cell}`;
    rows.push({ id, row_id: id, cell_id: cell, round_id: roundId, snapshot: kind === 'baseline' ? 'baseline' : 'candidate',
      model_id: modelId, model_artifact: MODELS.find(model => model.id === modelId).artifact, harness_id: harnessId,
      scenario_id: scenarioId, seed, skills_enabled: true, kind: 'iteration-native', diagnostic_only: true });
  }
  return rows;
}
function identities(value) {
  ensure(value && sharedKeys.every(key => digest(value[key])), 'Iteration evaluator, oracle, tasks and model_configuration hashes are required.');
  return clone(value);
}
function locationFor(root, directory) {
  const base = path.resolve(root, '.artifacts/local-evals/iterations'), target = path.resolve(directory);
  ensure(target.startsWith(base + path.sep), 'Iteration storage must be repository-owned under .artifacts/local-evals/iterations.');
  for (let current = target; ; current = path.dirname(current)) {
    if (existsSync(current)) ensure(!lstatSync(current).isSymbolicLink(), 'Iteration storage cannot traverse symlinks.');
    if (current === path.dirname(current)) break;
  }
  return target;
}
function immutable(file, value) { writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o400 }); chmodSync(file, 0o400); }
function readRegular(file, maximum = 128 * 1024 * 1024) {
  const stat = lstatSync(file);
  let canonical = false;
  if (process.platform === 'win32') {
    // Avoid repeated ancestor walks for already canonical Windows paths. Keep
    // the existing check for short spellings and any native lookup failure.
    try { canonical = realpathSync.native(file) === path.resolve(file); } catch { /* Fall back to the existing path check. */ }
  }
  ensure(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maximum && (canonical || realpathSync(file) === path.resolve(file)), 'Iteration evidence must be a bounded regular file without symlink ancestors.');
  return readFileSync(file);
}
function reference(root, directory, value) {
  ensure(value && typeof value.path === 'string' && digest(value.sha256), 'Hash-bound iteration evidence is required.');
  const file = path.resolve(directory, value.path);
  ensure(file.startsWith(realpathSync(root) + path.sep), 'Iteration evidence must remain repository-owned.');
  const bytes = readRegular(file);
  ensure(sha256(bytes) === value.sha256, 'Iteration evidence bytes changed.');
  return { reference: { path: file, sha256: value.sha256 }, bytes };
}
function readManifest(directory, expected) {
  const bytes = readRegular(path.join(directory, 'manifest.json')), manifest = JSON.parse(bytes), receipt = JSON.parse(readRegular(path.join(directory, 'manifest.sha256.json')));
  ensure(sha256(bytes) === receipt.sha256, 'Iteration manifest bytes changed.');
  const headless = manifest.schema_version === 2 && manifest.profile === PROFILE;
  ensure((headless || manifest.schema_version === 1 && manifest.profile === undefined) && manifest.kind === 'ud-iterative-diagnostic-session'
    && hash(manifest.policy) === hash(policyForProfile(manifest.profile)), 'Iteration policy changed.');
  if (headless) ensure(hash(manifest.coverage_rows) === hash(buildHeadlessCoverage()) && hash(manifest.reference_rows) === hash(headlessReferenceRows()), 'Frozen headless coverage changed.');
  identities(manifest.identities);
  if (expected) ensure(hash(identities(expected)) === hash(manifest.identities), 'Frozen iteration identity changed.');
  return freeze(manifest);
}
function journal(directory, cache = new Map()) {
  let previous = null;
  return readdirSync(path.join(directory, 'journal')).sort().map((name, index) => {
    ensure(name === `${String(index).padStart(6, '0')}.json`, 'Iteration journal is incomplete or reordered.');
    // Always re-read and hash current bytes. The cache only avoids parsing and
    // serializing an unchanged immutable entry; metadata alone is never proof.
    const bytes = readRegular(path.join(directory, 'journal', name)), digest = sha256(bytes);
    let checked = cache.get(name);
    if (checked?.digest !== digest) {
      const event = JSON.parse(bytes), { entry_sha256, ...payload } = event;
      ensure(hash(payload) === entry_sha256, 'Iteration journal chain changed.');
      checked = { digest, event: freeze(event), eventHash: hash(event) }; cache.set(name, checked);
    }
    const event = checked.event;
    ensure(event.sequence === index && event.previous_sha256 === previous, 'Iteration journal chain changed.');
    previous = checked.eventHash; return event;
  });
}
function replay(events, policy = ITERATION_POLICY) {
  const state = { started_at: null, deadline: null, execution_deadline: null, active_model: null, active_episode: null, rounds: [], decisions: {}, admissions: {}, admission_history: [], releases: [],
    calibration: { used: 0, per_model: {}, request_ids: [] }, reserved: { episodes: 0, inference: 0, tools: 0, ud_operations: 0, output: 0, input: 0 }, episodes: {}, closed: false };
  for (const event of events) {
    const value = event.value;
    if (event.type === 'round_frozen') {
      state.rounds.push({ ...value, finished_at: null });
      if (value.kind === 'baseline') state.decisions[value.id] = { retained: true, implicit: true, reason: 'Initial product is the retained reference until a reviewed repair replaces it.' };
    }
    else if (event.type === 'admission_started') {
      if (state.started_at === null) { state.started_at = event.at; state.deadline = event.at + policy.duration_ms; state.execution_deadline = state.deadline - policy.reconciliation_ms; }
      state.active_model = value.model_id;
    } else if (event.type === 'calibration_charged') {
      state.calibration.used++; state.calibration.per_model[value.model_id] = (state.calibration.per_model[value.model_id] ?? 0) + 1; state.calibration.request_ids.push(value.request_id);
    } else if (event.type === 'admission_recorded') {
      state.admissions[value.model_id] = value.reference;
      state.admission_history.push({ ...value, recorded_at: event.at });
    } else if (event.type === 'model_released') {
      state.active_model = null; state.releases.push({ ...value, released_at: event.at });
    }
    else if (event.type === 'episode_claimed') {
      state.active_episode = value.row_id; state.episodes[value.row_id] = { status: 'running', claimed_at: event.at, reservation: value };
      state.reserved.episodes++; for (const key of Object.keys(counterLimits)) state.reserved[key] += value[key];
    } else if (event.type === 'episode_recorded') { state.episodes[value.row_id] = { ...state.episodes[value.row_id], status: 'recorded', recorded_at: event.at, reference: value.reference, projection: value.projection }; state.active_episode = null; }
    else if (event.type === 'episode_cleanup_reconciled') state.episodes[value.row_id].cleanup_reconciliation = value.proof;
    else if (event.type === 'round_finished') state.rounds.find(round => round.id === value.round_id).finished_at = event.at;
    else if (event.type === 'round_decided') state.decisions[value.round_id] = { ...value.decision, decided_at: event.at };
    else if (event.type === 'session_closed') { state.closed = true; state.reason = value.reason; }
    else throw new Error('Unknown iteration journal event.');
  }
  return state;
}
function projectEpisode(row, episode, installation, profile) {
  ensure(episode && outcomes.has(episode.outcome), 'An actual terminal native episode outcome is required.');
  for (const key of ['row_id', 'model_id', 'model_artifact', 'harness_id', 'scenario_id', 'seed', 'skills_enabled'])
    ensure(episode[key] === row[key], `Iteration episode identity differs: ${key}.`);
  ensure(episode.candidate_installation_sha256 === installation.sha256, 'Iteration installation identity differs.');
  ensure(typeof episode.owned_cleanup_verified === 'boolean', 'Iteration cleanup must be explicitly observed.');
  if (episode.outcome !== 'passed') ensure(typeof episode.reason === 'string' && episode.reason.trim(), 'Nonpassing episodes require an explicit reason.');
  const observations = Object.fromEntries([...positiveObservations, 'skill_activation'].map(key => [key, typeof episode.observations?.[key] === 'boolean' ? episode.observations[key] : null]));
  const counters = Object.fromEntries(Object.keys(counterLimits).map(key => [key, integer(episode.metrics?.counters?.[key]) ? episode.metrics.counters[key] : null]));
  const limits = rowCounterLimits(row, profile);
  const violations = Object.keys(limits).filter(key => counters[key] !== null && counters[key] > limits[key]);
  const stages = Object.fromEntries(ITERATION_STAGES.map(key => [key, typeof episode.stages?.[key] === 'boolean' ? episode.stages[key] : null]));
  stages.activation ??= observations.skill_activation;
  stages.dispatch ??= counters.ud_operations === null ? null : counters.ud_operations > 0;
  stages.verified_completion ??= observations.independent_verification === true && observations.final_answer_verified === true ? true
    : observations.independent_verification === false || observations.final_answer_verified === false ? false : null;
  const requiredMissing = positiveObservations.filter(key => observations[key] !== true);
  const activationValid = profile === PROFILE
    ? observations.skill_activation !== null && (row.scenario_id !== 'S7' && row.skills_enabled || observations.skill_activation === false)
    : row.scenario_id !== 'S7' || observations.skill_activation === false;
  const qualified = !requiredMissing.length && activationValid && !violations.length && Object.values(counters).every(integer)
    && episode.owned_cleanup_verified && episode.verification?.status === 'passed' && typeof episode.final_answer === 'string' && !!episode.final_answer.trim();
  const outcome = episode.outcome === 'passed' && !qualified ? 'incomplete' : episode.outcome;
  // Activation is descriptive: direct correct execution need not load a skill.
  const relevant = row.scenario_id === 'S7' ? ['verified_completion'] : ITERATION_STAGES.filter(stage => stage !== 'activation');
  const failedStage = outcome === 'passed' && stages.verified_completion === true ? null : relevant.find(key => stages[key] === false) ?? null;
  return { outcome, reported_outcome: episode.outcome, reason: episode.reason ?? null, observations, stages,
    first_failure: { stage: failedStage, status: failedStage ? 'known_failure' : stages.verified_completion === true ? 'none_observed' : 'unknown',
      earlier_unknown_stages: failedStage ? relevant.slice(0, relevant.indexOf(failedStage)).filter(key => stages[key] === null) : [], activation_optional: true },
    counters, budget_violations: violations, owned_cleanup_verified: episode.owned_cleanup_verified,
    elapsed_ms: integer(episode.metrics?.total_elapsed_ms) ? episode.metrics.total_elapsed_ms : null,
    negative_activation_cost: row.scenario_id === 'S7' ? observations.skill_activation : null,
    missing_positive_observations: requiredMissing, final_answer_verified: observations.final_answer_verified, qualification_evidence: false };
}
const unresolved = state => Object.values(state.episodes).some(value => value.projection?.owned_cleanup_verified === false && !value.cleanup_reconciliation);
const completed = (round, state) => round.rows.every(row => state.episodes[row.id]?.status === 'recorded');
const retainedCore = state => state.rounds.filter(round => ['baseline', 'repair'].includes(round.kind) && state.decisions[round.id]?.retained === true).at(-1);
function retentionMetrics(state, round, documents) {
  const parent = state.rounds.find(value => value.id === round.parent_round), regressions = [], gains = [], advances = [];
  for (const row of round.rows) {
    const beforeRow = parent.rows.find(value => value.cell_id === row.cell_id), before = state.episodes[beforeRow.id], after = state.episodes[row.id];
    if (before.projection.outcome === 'passed' && after.projection.outcome !== 'passed') regressions.push({ cell_id: row.cell_id, kind: 'verified-completion-regression' });
    if (row.scenario_id === 'S7' && after.projection.negative_activation_cost === true && before.projection.negative_activation_cost !== true) regressions.push({ cell_id: row.cell_id, kind: 'negative-selection-activation' });
    if (before.projection.outcome !== 'passed' && after.projection.outcome === 'passed') gains.push(row.cell_id);
    for (const stage of ITERATION_STAGES.filter(value => !['activation', 'verified_completion'].includes(value))) {
      if (row.scenario_id !== 'S7' && before.projection.stages[stage] === false && after.projection.stages[stage] === true) advances.push({ cell_id: row.cell_id, seed: row.seed, stage, source: 'episode-observations' });
    }
  }
  // A separately reviewed raw-traffic analysis may resolve previously unknown
  // stage summaries, but cannot contradict observed stages or substitute rows.
  for (const document of documents.filter(value => value.kind === 'iteration-retention-review')) {
    ensure(document.round_id === round.id && document.parent_round === parent.id && Array.isArray(document.stage_advances), 'Retention review must bind the exact paired rounds.');
    for (const advance of document.stage_advances) {
      const row = round.rows.find(value => value.cell_id === advance.cell_id), beforeRow = row && parent.rows.find(value => value.cell_id === row.cell_id);
      ensure(row && row.scenario_id !== 'S7' && row.seed === advance.seed && ITERATION_STAGES.includes(advance.stage) && !['activation', 'verified_completion'].includes(advance.stage)
        && advance.before === false && advance.after === true, 'Retention review stage advance is not a valid positive-workflow pair.');
      const before = state.episodes[beforeRow.id], after = state.episodes[row.id];
      ensure(advance.before_episode_sha256 === before.reference.sha256 && advance.after_episode_sha256 === after.reference.sha256
        && before.projection.stages[advance.stage] !== true && after.projection.stages[advance.stage] !== false, 'Retention review episode hashes or observed stages differ.');
      advances.push({ cell_id: row.cell_id, seed: row.seed, stage: advance.stage, source: 'hash-bound-reviewed-observation' });
    }
  }
  const grouped = new Map();
  for (const advance of advances) {
    const key = advance.cell_id.replace(/\/seed-\d+(?:\/skills(?:-disabled)?)?$/, ''), seeds = grouped.get(key) ?? new Set(); seeds.add(advance.seed); grouped.set(key, seeds);
  }
  return { regressions, completion_gains: gains, stage_advances: advances,
    action_stage_advance_in_two_seeds: [...grouped.values()].some(seeds => seeds.size >= 2), independent_seed_samples: false };
}

/** Preparation/freeze is clock-free; only beginAdmission starts180min once. */
export function createIterationSession({ root, directory, identities: bindings, metadata = {}, profile, optIn = false, environment = process.env, now = Date.now() }) {
  assertOptIn({ optIn }, environment); ensure(integer(now), 'Iteration timestamp must be an integer.');
  const location = locationFor(root, directory); ensure(!existsSync(location), 'Iteration session already exists; resume without replenishing allowances.');
  const policy = policyForProfile(profile);
  const manifest = { schema_version: profile === PROFILE ? 2 : 1, kind: 'ud-iterative-diagnostic-session', id: randomUUID(), created_at: now, identities: identities(bindings),
    metadata: clone(metadata), policy, models: MODELS, harnesses: HARNESSES, seeds: SEEDS, qualification_evidence: false,
    ...(profile === PROFILE ? { profile, coverage_rows: buildHeadlessCoverage(), reference_rows: headlessReferenceRows() } : {}) };
  mkdirSync(location, { recursive: true, mode: 0o700 }); mkdirSync(path.join(location, 'journal'), { mode: 0o700 });
  immutable(path.join(location, 'manifest.json'), manifest);
  immutable(path.join(location, 'manifest.sha256.json'), { sha256: sha256(readFileSync(path.join(location, 'manifest.json'))) });
  return openIterationSession({ root, directory: location, identities: bindings, optIn, environment, now: () => now });
}
export function openIterationSession({ root, directory, identities: bindings, optIn = false, environment = process.env, now = Date.now }) {
  const location = locationFor(root, directory), manifest = readManifest(location, bindings);
  const policy = manifest.policy, headless = manifest.profile === PROFILE;
  const journalCache = new Map();
  const snapshot = () => replay(journal(location, journalCache), policy);
  function mutate(action, explicitOptIn = optIn) {
    assertOptIn({ optIn: explicitOptIn }, environment);
    const lock = path.join(location, '.lock');
    try { mkdirSync(lock, { mode: 0o700 }); } catch (error) { if (error.code === 'EEXIST') throw new Error('Iteration journal is locked; independently reconcile interruption before resume.'); throw error; }
    try {
      readManifest(location, bindings); const events = journal(location, journalCache), state = replay(events, policy), at = now();
      ensure(integer(at) && (!events.length || at >= events.at(-1).at), 'Iteration clock moved backwards.');
      ensure(!state.closed, 'Iteration session is closed.');
      const entry = action(state, at), payload = { sequence: events.length, previous_sha256: events.length ? hash(events.at(-1)) : null, at, ...entry };
      immutable(path.join(location, 'journal', `${String(events.length).padStart(6, '0')}.json`), { ...payload, entry_sha256: hash(payload) });
      return snapshot();
    } finally { rmdirSync(lock); }
  }
  const store = { manifest, directory: location, manifest_sha256: sha256(readFileSync(path.join(location, 'manifest.json'))), snapshot,
    get state() { return snapshot(); }, get rounds() { return snapshot().rounds; }, get decisions() { return snapshot().decisions; }, get clock_started() { return snapshot().started_at !== null; },
    round(id) { return snapshot().rounds.find(round => round.id === id); },
    freezeRound({ kind, product, installation, parentRound, repairEvidence }) {
      let round;
      mutate((state, at) => {
        ensure(!state.active_episode && !unresolved(state), 'Resolve active work and unknown cleanup before freezing another round.');
        ensure(!state.execution_deadline || at < state.execution_deadline, 'Iteration execution deadline reached.');
        ensure(digest(product?.sha256) && digest(installation?.sha256), 'Round product and installation hashes are required.');
        const previous = state.rounds.at(-1), core = retainedCore(state);
        ensure(!previous || previous.finished_at !== null && completed(previous, state), 'Complete and finish the preceding round first.');
        ensure(!previous || previous.kind !== 'repair' || state.decisions[previous.id], 'Record the immutable repair retention decision before another round.');
        for (const decision of Object.values(state.decisions)) for (const item of decision.evidence ?? []) reference(root, location, item);
        let id;
        if (kind === 'baseline') { ensure(!state.rounds.length && !parentRound, 'A session has exactly one initial baseline.'); id = 'baseline'; }
        else {
          ensure(core && parentRound === core.id, 'Round must reference the last retained core product round.');
          if (kind === 'repair') {
            const number = state.rounds.filter(value => value.kind === 'repair').length + 1;
            ensure(number <= policy.maximum_repair_rounds && !state.rounds.some(value => value.kind.includes('transfer')), headless ? 'At most one repair round precedes transfer.' : 'At most two repair rounds precede transfer.');
            ensure(core.rows.some(row => (!headless || row.skills_enabled) && state.episodes[row.id]?.projection?.outcome !== 'passed'), 'A passing core round needs no repair; proceed to transfer.');
            ensure(product.sha256 !== core.product.sha256 && repairEvidence && typeof repairEvidence.reason === 'string' && repairEvidence.reason.trim()
              && Array.isArray(repairEvidence.evidence) && repairEvidence.evidence.length, 'Repairs require changed product bytes and demonstrated-failure evidence.');
            for (const item of repairEvidence.evidence) reference(root, location, item);
            id = `repair-${number}`;
          } else {
            ensure((headless ? kind === 'transfer' : ['transfer', 'claude-transfer'].includes(kind)) && product.sha256 === core.product.sha256 && installation.sha256 === core.installation.sha256, 'Transfer must use the latest frozen product and installation.');
            if (!headless) ensure(core.rows.every(row => {
              const record = state.episodes[row.id];
              return record?.projection?.outcome === 'passed' && projectEpisode(row, JSON.parse(reference(root, location, record.reference).bytes), core.installation).outcome === 'passed';
            }), 'Transfer requires all six comparison and six negative-selection milestones to pass.');
            ensure(!state.rounds.some(value => value.kind === kind), 'Transfer round cannot be repeated.');
            if (kind === 'claude-transfer') ensure(state.rounds.some(value => value.kind === 'transfer' && value.finished_at !== null), 'Complete the ordinary transfer before optional Claude coverage.');
            id = kind;
          }
        }
        round = { schema_version: manifest.schema_version, kind, id, frozen_at: at, identities: manifest.identities, product: clone(product), installation: clone(installation),
          parent_round: parentRound ?? null, repair_evidence: repairEvidence ? clone(repairEvidence) : null, rows: buildIterationRows({ kind, roundId: id, profile: manifest.profile }), qualification_evidence: false };
        ensure(state.rounds.reduce((sum, value) => sum + value.rows.length, 0) + round.rows.length <= policy.maximum_scored_episodes, `Iteration scored inventory exceeds${policy.maximum_scored_episodes}.`);
        return { type: 'round_frozen', value: round };
      });
      return store.round(round.id);
    },
    beginAdmission({ modelId, optIn: explicit = optIn } = {}) { return mutate((state, at) => {
      ensure(MODELS.some(model => model.id === modelId) && !state.active_model && !state.active_episode && !unresolved(state), 'Only one model and episode may be active; cleanup must be verified.');
      ensure(state.rounds.length && (!state.execution_deadline || at < state.execution_deadline), 'Freeze a round before admission; execution deadline must remain.');
      return { type: 'admission_started', value: { model_id: modelId } };
    }, explicit); },
    chargeCalibration(modelId, requestId) { return mutate((state, at) => {
      ensure(state.active_model === modelId && typeof requestId === 'string' && requestId && !state.calibration.request_ids.includes(requestId), 'Calibration request must be unique and belong to the active model.');
      ensure(state.calibration.used < 12 && (state.calibration.per_model[modelId] ?? 0) < 4, 'Iteration calibration allowance exhausted.');
      ensure(at < state.execution_deadline, 'Iteration execution deadline reached.');
      return { type: 'calibration_charged', value: { model_id: modelId, request_id: requestId } };
    }); },
    recordAdmission(modelId, receipt) { return mutate(state => {
      ensure(state.active_model === modelId && !state.active_episode, 'Admission must belong to the idle active model.');
      const bound = reference(root, location, receipt), document = JSON.parse(bound.bytes);
      ensure(['admitted', 'model_blocked', ...(headless ? ['context_resource_blocked'] : [])].includes(document.status), 'A recorded mechanical admission result is required.');
      if (document.model?.id) ensure(document.model.id === modelId, 'Mechanical admission model identity differs.');
      return { type: 'admission_recorded', value: { model_id: modelId, reference: bound.reference } };
    }); },
    releaseModel(modelId, proof) { return mutate(state => {
      ensure(state.active_model === modelId && !state.active_episode && !unresolved(state), 'Release active work and reconcile cleanup before switching models.');
      ensure(proof?.owned_cleanup_verified === true, 'Model release requires explicitly verified owned cleanup.');
      const bound = reference(root, location, proof), document = JSON.parse(bound.bytes);
      ensure(document.owned_cleanup_verified === true || document.cleanupVerified === true, 'Model release file must record actual verified cleanup.');
      return { type: 'model_released', value: { model_id: modelId, proof: { ...bound.reference, owned_cleanup_verified: true } } };
    }); },
    claimEpisode(roundId, rowId) { return mutate((state, at) => {
      const round = state.rounds.find(value => value.id === roundId), row = round?.rows.find(value => value.id === rowId);
      ensure(row && state.rounds.at(-1).id === roundId && round.finished_at === null && !state.active_episode && !state.episodes[rowId] && !unresolved(state), 'Episode cannot be repeated or claimed outside the active round.');
      ensure(state.active_model === row.model_id && state.admissions[row.model_id], 'Episode requires the selected model and recorded mechanical admission.');
      ensure(round.rows.find(value => !state.episodes[value.id])?.id === rowId, 'Episodes must follow frozen model/seed order.');
      ensure(at + (headless ? policy.forecast_episode_ms : 95_000) <= state.execution_deadline && state.reserved.episodes < policy.maximum_scored_episodes, 'Iteration execution deadline or scored allowance reached.');
      return { type: 'episode_claimed', value: { round_id: roundId, row_id: rowId, ...rowCounterLimits(row, manifest.profile), deadline: Math.min(at + 155_000, state.execution_deadline) } };
    }); },
    recordEpisode(roundId, rowId, value) { return mutate(state => {
      ensure(state.active_episode === rowId && state.episodes[rowId]?.status === 'running', 'Only the active claimed episode can be recorded.');
      const round = state.rounds.find(item => item.id === roundId), row = round?.rows.find(item => item.id === rowId);
      ensure(row, 'Unknown iteration round episode.');
      const bound = reference(root, location, value.episode ?? value), episode = JSON.parse(bound.bytes);
      if (headless) ensure(episode.outcome !== 'not_run', 'Unattempted headless rows cannot be recorded as completed episodes.');
      return { type: 'episode_recorded', value: { row_id: rowId, reference: bound.reference, projection: projectEpisode(row, episode, round.installation, manifest.profile) } };
    }); },
    reconcileEpisodeCleanup(rowId, proof) { return mutate(state => {
      ensure(!state.active_episode && state.episodes[rowId]?.projection?.owned_cleanup_verified === false && !state.episodes[rowId].cleanup_reconciliation, 'Only terminal unresolved cleanup may be reconciled.');
      ensure(proof?.owned_cleanup_verified === true && proof.row_id === rowId, 'Independent cleanup proof must bind the exact row.');
      const bound = reference(root, location, proof), document = JSON.parse(bound.bytes);
      ensure(document.owned_cleanup_verified === true && document.row_id === rowId && document.episode_sha256 === state.episodes[rowId].reference.sha256, 'Cleanup proof file must bind the actual failed episode and verified release.');
      return { type: 'episode_cleanup_reconciled', value: { row_id: rowId, proof: { ...bound.reference, row_id: rowId, owned_cleanup_verified: true } } };
    }); },
    finishRound(roundId) { return mutate(state => { const round = state.rounds.find(value => value.id === roundId); ensure(round && !round.finished_at && !state.active_episode && !unresolved(state) && completed(round, state), 'Every selected episode must be terminal and owned cleanup resolved before finishing.'); return { type: 'round_finished', value: { round_id: roundId } }; }); },
    decideRound(roundId, { retained, reason, evidence } = {}) { return mutate(state => {
      const round = state.rounds.find(value => value.id === roundId);
      ensure(round?.kind === 'repair' && round.finished_at !== null && completed(round, state) && !state.active_model && !state.active_episode && !unresolved(state), 'Repair retention requires a complete round and verified model release.');
      ensure(!state.decisions[roundId] && typeof retained === 'boolean' && typeof reason === 'string' && reason.trim() && Array.isArray(evidence) && evidence.length, 'Repair decision is immutable and requires a rationale and evidence.');
      for (const candidate of [round, state.rounds.find(value => value.id === round.parent_round)]) for (const row of candidate.rows) {
        const record = state.episodes[row.id], actual = projectEpisode(row, JSON.parse(reference(root, location, record.reference).bytes), candidate.installation, manifest.profile);
        ensure(hash(actual) === hash(record.projection), 'Retention episode evidence changed.');
      }
      const bound = evidence.map(value => reference(root, location, value)), documents = bound.flatMap(value => { try { const document = JSON.parse(value.bytes); return document && typeof document === 'object' ? [document] : []; } catch { return []; } });
      const metrics = retentionMetrics(state, round, documents);
      if (retained) ensure(!metrics.regressions.length && (metrics.completion_gains.length > 0 || !headless && metrics.action_stage_advance_in_two_seeds), headless
        ? 'A retained headless repair requires a verified completion gain, with no completion or negative-selection regressions.'
        : 'A retained repair requires a completion gain or action-stage advance in two seeds, with no completion or negative-selection regressions.');
      return { type: 'round_decided', value: { round_id: roundId, decision: { retained, reason, evidence: bound.map(value => value.reference), metrics } } };
    }); },
    close(reason) { return mutate(state => { ensure(!state.active_episode && !state.active_model && !unresolved(state) && typeof reason === 'string' && reason.trim(), 'Close requires verified owned release and an explicit reason.'); return { type: 'session_closed', value: { reason } }; }); },
    report() { return buildIterationReport(manifest, snapshot(), { root, directory: location }); },
  };
  return store;
}

/** Paired seed blocks are descriptive, never independent task samples. */
export function buildIterationReport(manifest, state, { root, directory } = {}) {
  const errors = [];
  if (manifest.profile === PROFILE) {
    for (const admission of state.admission_history) try {
      ensure(root && directory, 'Lifecycle evidence verification requires repository and session roots.');
      const document = JSON.parse(reference(root, directory, admission.reference).bytes);
      ensure(['admitted', 'model_blocked', 'context_resource_blocked'].includes(document.status), 'Recorded admission status changed.');
      if (document.model?.id) ensure(document.model.id === admission.model_id, 'Recorded admission model identity differs.');
    } catch (error) { errors.push({ model_id: admission.model_id, evidence_kind: 'admission', reason: error.message }); }
    for (const release of state.releases) try {
      ensure(root && directory, 'Lifecycle evidence verification requires repository and session roots.');
      const document = JSON.parse(reference(root, directory, release.proof).bytes);
      ensure(release.proof.owned_cleanup_verified === true && (document.owned_cleanup_verified === true || document.cleanupVerified === true), 'Recorded model release is unverified.');
      if (document.model_id) ensure(document.model_id === release.model_id, 'Recorded release model identity differs.');
    } catch (error) { errors.push({ model_id: release.model_id, evidence_kind: 'release', reason: error.message }); }
  }
  for (const [roundId, decision] of Object.entries(state.decisions)) for (const item of decision.evidence ?? []) try {
    ensure(root && directory, 'Decision evidence verification requires repository and session roots.'); reference(root, directory, item);
  } catch (error) { errors.push({ round_id: roundId, reason: error.message }); }
  const rounds = state.rounds.map(round => ({ ...round, decision: state.decisions[round.id] ?? null, rows: round.rows.map(row => {
    const record = state.episodes[row.id];
    if (!record) return { ...row, status: 'unattempted', outcome: 'not_run', reason: 'No scored execution record; no success inferred.' };
    let verified = false, projection = record.projection;
    if (record.status === 'recorded') try {
      ensure(root && directory, 'Actual evidence verification requires repository and session roots.');
      const episode = JSON.parse(reference(root, directory, record.reference).bytes);
      const actual = projectEpisode(row, episode, round.installation, manifest.profile); ensure(hash(actual) === hash(projection), 'Stored episode projection changed.');
      if (record.cleanup_reconciliation) reference(root, directory, record.cleanup_reconciliation);
      verified = true;
    } catch (error) { errors.push({ row_id: row.id, reason: error.message }); }
    return { ...row, ...projection, status: record.status, outcome: verified ? projection.outcome : 'incomplete', evidence_verified: verified,
      episode: record.reference ?? null, cleanup_reconciliation: record.cleanup_reconciliation ?? null };
  }) }));
  const paired = rounds.filter(round => round.kind === 'repair').map(round => {
    const parent = rounds.find(value => value.id === round.parent_round);
    return { before_round: parent.id, after_round: round.id, independent_seed_samples: false, rows: round.rows.map(after => {
      const before = parent.rows.find(value => value.cell_id === after.cell_id), complete = before?.evidence_verified === true && after.evidence_verified === true;
      return { cell_id: after.cell_id, seed: after.seed, complete, before: before?.outcome ?? 'not_run', after: after.outcome,
        stages: Object.fromEntries(ITERATION_STAGES.map(stage => [stage, { before: before?.stages?.[stage] ?? null, after: after.stages?.[stage] ?? null,
          difference: complete && typeof before.stages?.[stage] === 'boolean' && typeof after.stages?.[stage] === 'boolean' ? Number(after.stages[stage]) - Number(before.stages[stage]) : null }])),
        first_failure_before: before?.first_failure ?? null, first_failure_after: after.first_failure ?? null };
    }) };
  });
  const rows = rounds.flatMap(round => round.rows), recorded = rows.filter(row => row.status === 'recorded');
  const allPassed = rows.length > 0 && recorded.length === rows.length && recorded.every(row => row.outcome === 'passed');
  const retainedId = errors.some(error => error.round_id) ? null : retainedCore(state)?.id ?? null;
  const headless = manifest.profile === PROFILE ? headlessQualification(manifest, rounds, retainedId, {
    evidenceValid: errors.length === 0, released: !state.active_model && !state.active_episode && !unresolved(state) }) : undefined;
  const status = !rows.length ? 'not_started' : headless ? headless.status === 'passed' ? 'passed_headless_coverage'
    : headless.coverage_complete ? 'completed_with_failures_or_blockers' : 'incomplete'
    : allPassed ? 'passed_selected_rows' : recorded.length !== rows.length || recorded.some(row => row.outcome === 'incomplete') ? 'incomplete' : 'completed_with_failures_or_blockers';
  return { schema_version: manifest.schema_version, kind: 'ud-iterative-diagnostic-report', status, session_id: manifest.id, identities: manifest.identities,
    decisions: state.decisions, retained_product_round: retainedId,
    started_at: state.started_at, deadline: state.deadline, execution_deadline: state.execution_deadline, closed: state.closed,
    reserved: state.reserved, calibration: { used: state.calibration.used, per_model: state.calibration.per_model, maximum: 12 },
    counts: { scheduled: rows.length, recorded: recorded.length, unfinished: rows.length - recorded.length, passed: recorded.filter(row => row.outcome === 'passed').length },
    actual_counters: Object.fromEntries(Object.keys(counterLimits).map(key => [key, recorded.length && recorded.every(row => row.evidence_verified && integer(row.counters?.[key])) ? recorded.reduce((sum, row) => sum + row.counters[key], 0) : null])),
    evidence_verification: { status: errors.length ? 'invalid' : 'verified', errors }, rounds, paired,
    harness_inventory: manifest.harnesses, model_inventory: manifest.models, qualification_evidence: false, full_starter_qualification: false,
    ...(headless ? { profile: manifest.profile, headless_qualification: headless, final_headless_qualification: headless.status === 'passed',
      reference_rows: manifest.reference_rows, coverage_rows: manifest.coverage_rows,
      lifecycle_evidence: { admissions: state.admission_history, releases: state.releases } } : {}),
    limitations: ['Selected diagnostic rows do not certify the171-row starter matrix or desktop/IDE applications.', 'Seed blocks are paired repetitions, not independent tasks.', 'Missing observations and interrupted work remain unknown.'] };
}
