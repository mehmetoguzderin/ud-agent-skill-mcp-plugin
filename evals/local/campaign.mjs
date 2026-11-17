/** Finite local campaign orchestration. No inference on import. MIT. */
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, lstatSync, realpathSync, writeFileSync, chmodSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { reserveStorage } from '../../scripts/quality/storage-lifecycle.mjs';
import { MODELS, buildMatrix, operationCoverage } from './registry.mjs';
import { writeReport, buildReport, compareReports } from './report.mjs';
import { assertOptIn, localPaths, prepare, readPreparation, writeNew } from './preparation.mjs';
import { inspectHarnesses, startNative } from './native.mjs';
import { createBudgetAuthority } from './budget.mjs';
import { createGateway, redactTraffic } from './gateway.mjs';
import { admitModel } from './serving.mjs';
import { openCalibrationLedger } from './calibration.mjs';
import { SCENARIOS, createScenario, gradeScenario, observeScenario } from './scenarios.mjs';
import { captureWorkspace } from '../../scripts/quality/workflow-grader.mjs';
import { bindRuntimeAssets, prepareRuntimeFixture, observeRuntimeFixture, cleanupRuntimeFixture } from './runtime-assets.mjs';
import { measureEpisodeContext } from './measurements.mjs';
import { prepareNativeClients } from './native-clients.mjs';
import { sampleResourceMemory, assertResourceMemory } from './resource-memory.mjs';
import { prepareNativeContainers } from './container-preparation.mjs';
import { collectGenerationEvidence, summarizeGenerationEvidence } from './generation-evidence.mjs';
import { cleanupObservation, failureObservation, observedCounters } from './lifecycle.mjs';
import { scientificStudyStorage } from './study-storage.mjs';
import { prepareCampaignSnapshot, assertCandidatePreparationWindow, verifyCampaignPreflight } from './campaign-preflight.mjs';

export function campaignPolicy(windows = 1, mode = 'paired') {
  if (![1, 3].includes(windows)) throw new Error('Campaign windows must be 1 or 3.');
  return { windows, duration_ms: windows * 240 * 60_000, checkpoint_ms: 240 * 60_000,
    phases: windows === 3 ? { admission: 30 * 60_000, baseline: 315 * 60_000, diagnosis: 30 * 60_000, replay: 300 * 60_000, reconciliation: 45 * 60_000 }
      : { admission: 1_800_000, baseline: mode === 'paired' ? 5_400_000 : 10_800_000, diagnosis: 1_200_000, replay: mode === 'paired' ? 5_400_000 : 0, reconciliation: 600_000 } };
}
export function forecast({ rows, episodeSeconds, switchSeconds = 30, startupSeconds = 60, verifierSeconds = 6, accountingSeconds = 20, blockedRows = 0, controls = false, windows = 1 }) {
  if (![episodeSeconds, switchSeconds, startupSeconds, verifierSeconds, accountingSeconds].every(value => Number.isFinite(value) && value >= 0) || !Number.isSafeInteger(blockedRows) || blockedRows < 0) throw new Error('Finite measured forecast inputs are required.');
  const count = rows.length, controlsCount = controls ? 18 : 0;
  const blockedSeconds = blockedRows * (accountingSeconds + 2);
  const requiredBaseline = count * (episodeSeconds + startupSeconds + verifierSeconds + accountingSeconds) + MODELS.length * switchSeconds + blockedSeconds;
  const baselineWithControls = requiredBaseline + controlsCount * (episodeSeconds + startupSeconds + verifierSeconds + accountingSeconds);
  const replaySeconds = requiredBaseline;
  const policy = campaignPolicy(windows), fits = requiredBaseline <= policy.phases.baseline / 1000 && replaySeconds <= policy.phases.replay / 1000;
  const controlsAdmitted = controls && fits && baselineWithControls <= policy.phases.baseline / 1000;
  return { baselineSeconds: controlsAdmitted ? baselineWithControls : requiredBaseline, replaySeconds, mode: fits ? 'paired' : 'diagnostic',
    controls_admitted: controlsAdmitted, blocked_row_reconciliation_seconds: blockedSeconds, assumptions: { episodeSeconds, startupSeconds, verifierSeconds, accountingSeconds, blockedRows, switchSeconds } };
}
export function deriveSeed(rootSeed, ordinal) {
  if (![17, 23, 47].includes(rootSeed) || !Number.isSafeInteger(ordinal) || ordinal < 0) throw new Error('Invalid request seed.');
  return Number.parseInt(sha256(`${rootSeed}:${ordinal}`).slice(0, 8), 16) & 0x7fffffff;
}

/** Execution and grading are separate: unresolved grades remain nonpassing. */
export function assertReplayBaseline(manifest, report) {
  if (manifest?.mode !== 'paired' || report?.snapshot !== 'baseline' ||
      report.execution_complete !== true || report.coverage?.complete_starter_inventory !== true ||
      report.counts?.missing !== 0 || report.status === 'passed') {
    throw new Error('A fully executed nonpassing paired baseline is required before a product patch replay.');
  }
}
export function frozenHashes(root, preparation) {
  const source = sourceReceipt(root), select = predicate => sha256(JSON.stringify(source.files.filter(predicate)));
  // Shared storage, process, source-receipt and fixture helpers execute outside
  // evals/local too. Freeze them without binding canonical product/skill bytes.
  return { evaluator: select(row => /^(evals\/local\/|scripts\/(?:quality|release)\/)/.test(row.path)),
    oracle: select(row => /^(?:evals\/local\/(?:scenarios\.mjs|wording-oracle\.mjs|fixtures\/)|scripts\/quality\/workflow-grader\.mjs$)/.test(row.path)),
    tasks: select(row => /^evals\/local\/(scenarios\.mjs|fixtures\/)/.test(row.path)), model_configuration: sha256(JSON.stringify({ models: MODELS, preparation })) };
}
export function verifyFrozen(root, manifest, preparation, { allowExpired = false } = {}) {
  const hashes = frozenHashes(root, preparation);
  for (const key of Object.keys(hashes)) if (hashes[key] !== manifest.hashes[key]) throw new Error(`Frozen campaign input changed: ${key}. Start a new campaign; prior evidence is retained.`);
  if (sourceReceipt(root).sha256 !== manifest.product.sha256) throw new Error('Product source changed during this snapshot.');
  if (manifest.mechanical_preflight) verifyCampaignPreflight(root, manifest.mechanical_preflight, manifest.product.sha256);
  if (manifest.installation_root) for (const record of manifest.installation.files) {
    const file = path.join(manifest.installation_root, record.path);
    if (record.link_target) {
      if (path.relative(manifest.installation_root, realpathSync(file)) !== record.link_target) throw new Error('Installed candidate link changed.');
    } else if (fileReceipt(manifest.installation_root, record.path).sha256 !== record.sha256) throw new Error('Installed candidate bytes changed.');
  }
  if (!allowExpired && Date.now() >= manifest.deadline) throw new Error('Campaign deadline reached; use report to reconcile existing evidence.');
}
// A failed mechanical attempt is retained as diagnostic evidence, never rescored.
// This narrow escape hatch spends the original clock, calibration and row allowance.
export function validateMechanicalRebaseline({ prior, product, hashes, preparation, episodes, now = Date.now() }) {
  if (prior.snapshot !== 'baseline' || prior.baseline || prior.mechanical_rebaseline || prior.deadline <= now) throw new Error('Only one unfinished baseline mechanical rebaseline is permitted before the original deadline.');
  if (episodes.length === 0 || episodes.length > 18 || episodes.length >= prior.rows.length) throw new Error('Mechanical rebaseline must retain diagnostic rows and leave room for both complete 171-row snapshots within 360 scored episodes.');
  if (JSON.stringify(prior.preparation) !== JSON.stringify(preparation)) throw new Error('Mechanical rebaseline cannot change model/runtime preparation.');
  for (const key of ['oracle', 'tasks', 'model_configuration']) if (prior.hashes[key] !== hashes[key]) throw new Error(`Mechanical rebaseline cannot change ${key}.`);
  if (JSON.stringify(prior.rows) !== JSON.stringify(buildMatrix())) throw new Error('Mechanical rebaseline requires the unchanged 171-row assignment without controls.');
  const old = new Map(prior.product.files.map(file => [file.path, JSON.stringify(file)]));
  const current = new Map(product.files.map(file => [file.path, JSON.stringify(file)]));
  const changed = [...new Set([...old.keys(), ...current.keys()])].filter(file => old.get(file) !== current.get(file));
  if (!changed.length || changed.some(file => !/^(evals\/local\/|tests\/evals\/|scripts\/quality\/run-local-model-evals\.mjs$|contracts\/implementation-inventory\.json$)/.test(file))) throw new Error('Mechanical rebaseline permits evaluator corrections and their generated evidence inventory only; UD product bytes must remain unchanged.');
  return { previous_scored_episodes: episodes.length, maximum_scored_episodes: 360, changed_evaluator_files: changed,
    remaining_after_complete_pair: 360 - episodes.length - 342, calibration_allowance_replenished: false, deadline_replenished: false };
}
export function campaignStorage(root, { onCancel, includeEngine = false } = {}) {
  const paths = localPaths(root); mkdirSync(paths.base, { recursive: true, mode: 0o700 });
  if (includeEngine) return scientificStudyStorage(root, 'run', { onCancel });
  return reserveStorage({ root, plannedBytes: 512_000_000, plannedOutputBytes: 12_000_000_000, externalOwnedBytes: 0, outputParent: paths.base, outputPath: paths.base, label: 'local-model-evaluation', onCancel });
}
export async function inventory(root) {
  return { schema_version: 1, inference: false, models: MODELS, harnesses: await inspectHarnesses(root), operations: operationCoverage(root),
    rows: buildMatrix(), references_policy: 'first-listed-harness/seed-17/rotating-models', ordinary_context: 16384, extended_context: 32768 };
}
export async function prepareCampaign(root, options) {
  assertOptIn(options); const lease = campaignStorage(root);
  try {
    const preparation = await prepare(root, options);
    if (options.containers) return { preparation, containers: await prepareNativeContainers(root, { optIn: true, onProgress: options.onProgress }) };
    return options.clients ? { preparation, clients: await prepareNativeClients(root, { optIn: true, onProgress: event => options.onProgress?.(`${event.client}: ${event.stage}`) }) } : preparation;
  } finally { lease.cleanup(); }
}
function captureFiles(directory) {
  const result = {};
  function walk(current) {
    for (const name of readdirSync(current)) {
      const file = path.join(current, name), info = lstatSync(file), relative = path.relative(directory, file).split(path.sep).join('/');
      if (info.isSymbolicLink()) throw new Error('Task output contains a symbolic link.');
      if (info.isDirectory()) walk(file);
      else if (info.isFile()) { if (info.size > 16 * 1024 ** 2) throw new Error('Task artifact exceeds evidence budget.'); result[relative] = readFileSync(file); }
    }
  }
  walk(directory); return result;
}
export async function installSnapshot(root, directory) {
  mkdirSync(directory, { mode: 0o700 });
  for (const name of ['dist', 'contracts', 'runtime', 'workers', 'registry', 'skills', 'packaging', 'package.json', 'node_modules']) {
    if (!existsSync(path.join(root, name))) throw new Error(`Build the unchanged local candidate first; missing ${name}.`);
    cpSync(path.join(root, name), path.join(directory, name), { recursive: true, verbatimSymlinks: true, filter: file => !file.includes('__pycache__') });
  }
  await bindRuntimeAssets(root, directory);
  const runtimeFile = path.join(directory, 'runtime/runtime.lock.json'), runtime = JSON.parse(readFileSync(runtimeFile));
  if (!runtime.native_helpers?.[`${process.platform}/${process.arch}`]?.guard) {
    const guard = path.join(root, 'target/debug/ud-agent-guard');
    if (!existsSync(guard)) throw new Error('Build the native guard with cargo build --locked -p ud-agent-launcher --bin ud-agent-guard before local evaluation.');
    mkdirSync(path.join(directory, 'native'), { mode: 0o700 });
    cpSync(guard, path.join(directory, 'native/ud-agent-guard'));
    const receipt = fileReceipt(directory, 'native/ud-agent-guard');
    runtime.native_helpers = { ...runtime.native_helpers, [`${process.platform}/${process.arch}`]: { guard: { path: receipt.path, sha256: `sha256:${receipt.sha256}`, size_bytes: receipt.size } } };
    writeFileSync(runtimeFile, JSON.stringify(runtime, null, 2) + '\n');
    writeNew(path.join(directory, 'LOCAL-EVAL-INSTALLATION.json'), { qualification: 'diagnostic-source-build-not-release-acceptance', source_sha256: sourceReceipt(root).sha256, guard: receipt, runtime_state: runtime.state });
  }
  const files = [];
  const visit = current => {
    for (const name of readdirSync(current).sort()) {
      const file = path.join(current, name), info = lstatSync(file), relative = path.relative(directory, file).split(path.sep).join('/');
      if (info.isSymbolicLink()) {
        const target = realpathSync(file);
        if (!target.startsWith(directory + path.sep)) throw new Error('Installed candidate link escapes its snapshot.');
        files.push({ path: relative, link_target: path.relative(directory, target) });
      } else if (info.isDirectory()) visit(file);
      else files.push(fileReceipt(directory, relative));
    }
  };
  visit(directory);
  return { algorithm: 'sha256-installed-file-inventory-v1', sha256: sha256(JSON.stringify(files)), files };
}
export async function runEpisode(root, manifest, row, model, harness, installation, directory) {
  const generationStartedAtMs = Date.now();
  const profile = path.join(directory, 'profile'), taskRoot = path.join(directory, 'task');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const scenario = await createScenario(row.scenario_id, taskRoot);
  let before = captureWorkspace(taskRoot);
  const events = [];
  let generationEvidence;
  function captureTranslationEvents() {
    if (!model.translation_evidence?.traffic || !existsSync(model.translation_evidence.traffic)) return;
    const requestIds = new Set(events.filter(event => event.type === 'provider_request').map(event => event.id));
    const captured = new Set(events.filter(event => event.type?.startsWith('translation_')).map(event => JSON.stringify(event)));
    for (const line of readFileSync(model.translation_evidence.traffic, 'utf8').split('\n').filter(Boolean)) {
      try {
        const event = JSON.parse(line), identity = JSON.stringify(event);
        if (requestIds.has(event.id) && !captured.has(identity)) { events.push(event); captured.add(identity); }
      } catch { events.push({ type: 'backend_generation_evidence_error', reason: 'TRANSLATION_TRAFFIC_INVALID' }); }
    }
  }
  async function observeBackendGenerations() {
    if (generationEvidence || row.model_id !== 'minicpm' && model.model?.id !== 'minicpm') return;
    captureTranslationEvents();
    generationEvidence = await collectGenerationEvidence({ events, evidenceDirectory: typeof model.evidence_directory === 'string' ? path.join(model.evidence_directory, 'private-generations') : undefined,
      modelPath: model.wire_model, startedAtMs: generationStartedAtMs, endedAtMs: Date.now() });
    for (const event of generationEvidence.observations) {
      events.push(event);
      writeFileSync(path.join(directory, 'traffic.jsonl'), JSON.stringify(event) + '\n', { flag: 'a', mode: 0o600 });
    }
  }
  const resourceSamples = [];
  const resourceController = new AbortController();
  const episodeSignal = manifest.signal ? AbortSignal.any([manifest.signal, resourceController.signal]) : resourceController.signal;
  let resourcePending, resourceTimer, resourceFailure;
  async function sampleResources(includeContainer = false) {
    if (manifest.profile !== 'headless-12h-v2') return;
    if (resourceFailure) throw resourceFailure;
    const task = (resourcePending ?? Promise.resolve()).then(async () => {
      const container = includeContainer && native?.resourceContainer;
      const sample = await sampleResourceMemory({ processes: model.ownedProcesses?.() ?? [],
        ...(container ? { container } : {}) });
      resourceSamples.push(sample);
      writeFileSync(path.join(directory, 'resources.jsonl'), JSON.stringify(sample) + '\n', { flag: 'a', mode: 0o600 });
      assertResourceMemory(sample);
    });
    resourcePending = task;
    try { await task; } catch (error) { resourceFailure ??= error; resourceController.abort(error); throw error; } finally { if (resourcePending === task) resourcePending = undefined; }
  }
  let native, gateway, authority, runtimeFixture, fixturePreparationStarted = false, preAuthorityCleanup, fixtureCleanupVerified = row.scenario_id === 'S7';
  async function releaseFixture() {
    const receipt = await cleanupRuntimeFixture(runtimeFixture, { nativeCleanupVerified: true, pendingOperations: 0 });
    events.push(receipt); fixtureCleanupVerified = receipt.verified === true; return receipt;
  }
  const externalAbort = () => { void authority?.stop('PARENT_STUDY_CANCELLED'); };
  let countInFlight = 0;
  const episodeStartedAt = Date.now(); let started = episodeStartedAt;
  let fixtureElapsed = 0;
  try {
    await sampleResources();
    if (manifest.profile === 'headless-12h-v2') {
      resourceTimer = setInterval(() => { if (!resourcePending && !resourceFailure) void sampleResources().catch(error => { resourceFailure = error; void authority?.stop('resource-memory-blocked'); }); }, 2000);
      resourceTimer.unref();
    }
    if (model.resetConversationCache) events.push({ type: 'model_cache_reset', ...await model.resetConversationCache({ idle: true }) });
    fixturePreparationStarted = row.scenario_id !== 'S7';
    runtimeFixture = row.scenario_id === 'S7' ? undefined : await prepareRuntimeFixture(root, installation, profile, { warm: row.scenario_id !== 'S1', workingTree: taskRoot, requiredTools: row.scenario_id === 'S5' ? ['validation_report', 'sentence_render'] : ['validation_report'], signal: episodeSignal });
    fixtureElapsed = Date.now() - started; started = Date.now();
    if (resourceFailure) throw resourceFailure;
    await resourcePending;
    authority = await createBudgetAuthority({ directory: path.join(directory, 'budget'), contextEnvelope: row.scenario_id === 'S4' ? 32768 : 16384,
      deferredStart: true, deadline: manifest.deadline - manifest.phase_allocations_ms.reconciliation,
      faults: { lostResponseAfterCommit: row.scenario_id === 'S2' }, onEvent: event => events.push(event), onStop: async reason => {
        const mustStopBackend = Boolean(resourceFailure) || /resource-memory/.test(reason) || countInFlight > 0 || !authority || authority.snapshot().pending_requests > 0;
        const [agent, backend] = await Promise.allSettled([native?.stop('budget-stopped'), mustStopBackend ? model.stop() : Promise.resolve({ cleanupVerified: true, retained_idle_model: true })]);
        const cleanup = { cleanupVerified: (!native || agent.status === 'fulfilled' && agent.value?.cleanupVerified === true) && backend.status === 'fulfilled' && backend.value?.cleanupVerified === true,
          native: agent.status === 'fulfilled' ? cleanupObservation(agent.value) : { failure: failureObservation(agent.reason) }, backend: backend.status === 'fulfilled' ? cleanupObservation(backend.value) : { failure: failureObservation(backend.reason) } };
        events.push({ type: 'episode_cancellation_cleanup', ...cleanup }); return cleanup;
      } });
    episodeSignal.addEventListener('abort', externalAbort, { once: true });
    if (episodeSignal.aborted) { await authority.stop('PARENT_STUDY_CANCELLED'); throw new Error('PARENT_STUDY_CANCELLED'); }
    let ordinal = 0;
    gateway = await createGateway({ upstream: model.upstream, model: row.model_artifact, wireModel: model.wire_model ?? row.model_artifact, budget: authority, tokenize: async request => { countInFlight++; try { await sampleResources(true); return await model.tokenize(request); } finally { countInFlight--; } },
      supportedSampling: model.protocol_fields,
      customResponses: Boolean(model.translation_evidence?.custom_responses),
      sampling: model.sampling, seed: () => deriveSeed(row.seed, ordinal++),
      nativeResults: () => native?.observedResults?.() ?? [],
      record: event => { events.push(event); writeFileSync(path.join(directory, 'traffic.jsonl'), JSON.stringify(redactTraffic(event)) + '\n', { flag: 'a', mode: 0o600 }); } });
    if (resourceFailure) throw resourceFailure;
    native = await startNative({ root, harness, model: row.model_artifact, endpoint: gateway.url, taskRoot, profile, prompt: scenario.prompt, studyVariant: row.study_variant,
      modelContextCapacity: model.calibration_observations?.context?.declared_model_capacity,
      image: scenario.images?.[0] ? path.join(taskRoot, scenario.images[0].path) : undefined, skillsEnabled: row.skills_enabled, installation, signal: authority.signal,
      beforeStart: () => { before = captureWorkspace(taskRoot); },
      beforeLaunch: async () => { await sampleResources(); if (resourceFailure) throw resourceFailure; authority.begin(); events.push({ type: 'native_loop_started', started_at: authority.snapshot().started, deadline: authority.snapshot().deadline }); },
      hostBudgetEnvironment: { ...runtimeFixture?.environment, UD_AGENT_EVAL_BUDGET: JSON.stringify({ socketPath: authority.socketPath, token: authority.token }) },
      record: event => events.push(event),
      budgetEnvironment: { ...(harness.execution_location === 'arm64-container' ? {} : runtimeFixture?.environment), UD_AGENT_EVAL_BUDGET: JSON.stringify(harness.execution_location === 'arm64-container'
        ? { url: gateway.url.replace('127.0.0.1', 'host.docker.internal') + '/__eval_budget', token: authority.token }
        : { socketPath: authority.socketPath, token: authority.token }) } });
    const result = await native.done;
    clearInterval(resourceTimer); await resourcePending; if (resourceFailure) throw resourceFailure;
    const finalAnswer = native.finalAnswer(result), nativeFinishedAt = Date.now(), nativeElapsed = nativeFinishedAt - (authority.snapshot().started ?? started);
    if (!authority.signal.aborted) await gateway.reconcileNativeResults();
    // The abort listener may still be releasing inference when the native client exits.
    // Reconcile its stable stop promise before taking any cleanup/budget snapshot.
    if (authority.signal.aborted || result.cleanupVerified !== true || authority.snapshot().pending_requests > 0) await authority.stop('native-finished-with-pending-work');
    if (result.cleanupVerified === true && authority.snapshot().pending_operations === 0 && authority.snapshot().pending_requests === 0) await authority.close();
    events.push(...(native.events ? native.events(result) : result.stdout.split('\n').filter(Boolean).flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } })));
    events.push({ type: 'native_identity', ...native.identity, cleanupVerified: result.cleanupVerified, cleanup: cleanupObservation(result) });
    captureTranslationEvents();
    await observeBackendGenerations();
    if (runtimeFixture) events.push(await observeRuntimeFixture(runtimeFixture, events));
    if (runtimeFixture && result.cleanupVerified === true && authority.snapshot().pending_operations === 0) await releaseFixture();
    // A transcript alone cannot establish skill activation or per-scenario observations.
    // Native events and coordinator evidence must supply these independently.
    const after = captureWorkspace(taskRoot);
    const projected = observeScenario(row.scenario_id, { events, before, after, taskRoot, installation, finalAnswer, contextEnvelope: row.scenario_id === 'S4' ? 32768 : 16384, outputReserve: 512, modelBinding: { publicModel: row.model_artifact, wireModel: model.wire_model ?? row.model_artifact } });
    const budgetState = authority.snapshot();
    const observations = { ...projected.observations, no_user_hints: projected.observations.no_user_hints, budget_enforced: result.cleanupVerified === true && budgetState.cleanup !== 'unverified' && budgetState.pending_requests === 0 && budgetState.pending_operations === 0 && budgetState.output_usage_verified === true && budgetState.native_recovery?.verified === true && budgetState.native_recovery.pending_results === 0,
      independent_verification: false, final_answer_verified: false };
    const verdict = await gradeScenario(row.scenario_id, { before, after, finalAnswer, events: projected.events, observations, taskRoot });
    observations.independent_verification = verdict.status === 'passed';
    observations.final_answer_verified = verdict.status === 'passed';
    const rejection = events.findLast(event => event.type === 'gateway_rejection');
    const verificationElapsed = Date.now() - nativeFinishedAt;
    const contextMeasurements = await measureEpisodeContext({ events, tokenize: model.tokenize, installation, operations: operationCoverage(root).map(item => item.operation) });
    return { ...row, outcome: rejection?.outcome ?? (result.stop_reason === 'timed-out' ? 'timed_out' : result.code !== 0 ? 'failed' : verdict.status),
      reason: verdict.reason ?? result.stderr.slice(-1000), final_answer: finalAnswer, observations, verification: verdict, events: redactTraffic(events),
      metrics: { ...(manifest.profile === 'headless-12h-v2' ? { resources: resourceSamples } : {}), ...authority.snapshot(), known_counters: authority.snapshot().counters, counters: observedCounters(authority.snapshot()), elapsed_ms: nativeElapsed, fixture_elapsed_ms: fixtureElapsed,
        native_setup_elapsed_ms: (authority.snapshot().started ?? Date.now()) - started, total_elapsed_ms: Date.now() - episodeStartedAt, verification_elapsed_ms: verificationElapsed, context: contextMeasurements,
        ...(generationEvidence ? { backend_generation: summarizeGenerationEvidence(generationEvidence) } : {}) }, owned_cleanup_verified: fixtureCleanupVerified && result.cleanupVerified === true && budgetState.pending_operations === 0 && budgetState.pending_requests === 0 && budgetState.cleanup !== 'unverified',
      evidence: { before, after, task_root: taskRoot, ...(generationEvidence ? { backend_generations: generationEvidence.receipts } : {}) }, candidate_installation_sha256: manifest.installation.sha256 };
  } catch (error) {
    if (!authority) {
      let release;
      try { release = await model.stop('pre-authority-episode-failure'); }
      catch (releaseError) { release = { cleanupVerified: false, reason: releaseError.message }; }
      const preparationReleased = runtimeFixture ? runtimeFixture.preparation_processes?.every(process => process.cleanupVerified === true) && runtimeFixture.jobs?.verified === true : !fixturePreparationStarted || error.owned_cleanup_verified === true;
      preAuthorityCleanup = { verified: release?.cleanupVerified === true && preparationReleased === true, model_release: release,
        fixture_preparation: error.runtime_fixture_cleanup ?? null };
      if (!runtimeFixture) fixtureCleanupVerified = !fixturePreparationStarted || error.runtime_fixture_cleanup?.verified === true;
      events.push({ type: 'preauthority_failure_cleanup', ...preAuthorityCleanup });
      if (runtimeFixture && preAuthorityCleanup.verified) {
        try { await releaseFixture(); }
        catch (cleanupError) { events.push({ type: 'runtime_fixture_cleanup_failed', reason: cleanupError.message }); }
      }
    }
    if (authority) await authority.stop('episode-exception');
    await observeBackendGenerations();
    const state = authority?.snapshot();
    const failedNativeLaunch = error.native_cleanup && error.native_cleanup.cleanupVerified !== true;
    if (error.native_cleanup) events.push({ type: 'native_launch_cleanup', ...error.native_cleanup });
    if (runtimeFixture && state?.cleanup === 'verified' && state.pending_operations === 0 && state.pending_requests === 0 && !events.some(event => event.type === 'runtime_fixture_cleanup' && event.verified)) {
      try { await releaseFixture(); }
      catch (cleanupError) { events.push({ type: 'runtime_fixture_cleanup_failed', reason: cleanupError.message }); }
    }
    return { ...row, outcome: /TOKEN|INPUT_BUDGET|OUTPUT_BUDGET/.test(error.message) ? 'token_budget_exceeded' : /CONTEXT|TOKEN_ACCOUNTING|RESOURCE_MEMORY/.test(error.message) ? 'context_resource_blocked' : 'failed', reason: error.message, failure: failureObservation(error), events: redactTraffic(events), candidate_installation_sha256: manifest.installation.sha256,
      metrics: { ...(manifest.profile === 'headless-12h-v2' ? { resources: resourceSamples } : {}), ...state, counters: observedCounters(state), known_counters: state?.counters ?? null, total_elapsed_ms: Date.now() - episodeStartedAt, ...(generationEvidence ? { backend_generation: summarizeGenerationEvidence(generationEvidence) } : {}) },
      ...(generationEvidence ? { evidence: { backend_generations: generationEvidence.receipts } } : {}),
      owned_cleanup_verified: !failedNativeLaunch && fixtureCleanupVerified && (authority ? state.cleanup === 'verified' && state.pending_requests === 0 && state.pending_operations === 0 : preAuthorityCleanup?.verified === true) };
  } finally { clearInterval(resourceTimer); await resourcePending?.catch(() => {});
    if (manifest.profile === 'headless-12h-v2') {
      const finalSample = await sampleResourceMemory(); resourceSamples.push({ ...finalSample, phase: 'after-episode-cleanup-attempt' });
      writeFileSync(path.join(directory, 'resources.jsonl'), JSON.stringify(resourceSamples.at(-1)) + '\n', { flag: 'a', mode: 0o600 });
    } episodeSignal.removeEventListener('abort', externalAbort); await Promise.allSettled([native?.stop('episode-finished'), gateway?.close()]); await authority?.close(); }
}
export async function runCampaign(root, { optIn, campaign, baseline, patches, admissionRestart, mechanicalRebaseline, controls = true, windows = 1, onProgress = () => {} } = {}) {
  assertOptIn({ optIn });
  campaignPolicy(windows);
  const paths = localPaths(root), preparation = readPreparation(root);
  let restartManifest, rebaselineEvidence;
  const restartFrom = mechanicalRebaseline ?? admissionRestart;
  if (restartFrom) {
    const prior = path.resolve(restartFrom);
    if (campaign || baseline || !prior.startsWith(paths.campaigns + path.sep)) throw new Error('Admission restart requires an owned prior admission and a fresh baseline directory.');
    if (mechanicalRebaseline && (admissionRestart || controls)) throw new Error('Mechanical rebaseline requires --no-controls and cannot be combined with admission restart.');
    const recorded = path.join(prior, 'episodes');
    if (!mechanicalRebaseline && existsSync(recorded) && readdirSync(recorded).length) throw new Error('A scored campaign cannot be restarted with a changed evaluator.');
    restartManifest = JSON.parse(readFileSync(path.join(prior, 'manifest.json')));
    if (restartManifest.snapshot !== 'baseline' || restartManifest.deadline <= Date.now()) throw new Error('The prior baseline admission deadline cannot be reset.');
    if (JSON.stringify(restartManifest.preparation) !== JSON.stringify(preparation)) throw new Error('Admission restart model/runtime bytes differ from the prior campaign.');
    if (mechanicalRebaseline) {
      if (existsSync(path.join(prior, 'mechanical-rebaseline.json')) || existsSync(path.join(prior, 'candidate-replay.json'))) throw new Error('This prior attempt already spent its rebaseline or replay allowance.');
      const rows = readdirSync(recorded).map(file => JSON.parse(readFileSync(path.join(recorded, file))));
      rebaselineEvidence = validateMechanicalRebaseline({ prior: restartManifest, product: sourceReceipt(root), hashes: frozenHashes(root, preparation), preparation, episodes: rows });
      const releaseFile = path.join(prior, 'post-stop-release.json');
      if (!existsSync(releaseFile) || JSON.parse(readFileSync(releaseFile)).cleanupVerified !== true) throw new Error('Mechanical rebaseline requires an independent owned-process release receipt.');
      rebaselineEvidence.release_receipt_sha256 = fileReceipt(prior, 'post-stop-release.json').sha256;
      rebaselineEvidence.admissions = MODELS.map(model => ({ id: model.id, ...fileReceipt(prior, `admission-${model.id}.json`) }));
      rebaselineEvidence.calibration_receipt = fileReceipt(prior, 'calibration.json');
      rebaselineEvidence.phase_receipt = fileReceipt(prior, 'phase-baseline.json');
      rebaselineEvidence.previous_rows = readdirSync(recorded).sort().map(file => fileReceipt(prior, `episodes/${file}`));
    }
  }
  const directory = campaign ? path.resolve(campaign) : path.join(paths.campaigns, randomUUID());
  if (!directory.startsWith(paths.campaigns + path.sep)) throw new Error('Campaign output must be inside the repository campaign directory.');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  let manifest;
  const manifestFile = path.join(directory, 'manifest.json');
  const campaignController = new AbortController(); let currentModel;
  const lease = campaignStorage(root, { includeEngine: true, onCancel: async () => {
    campaignController.abort(new Error('CAMPAIGN_STORAGE_CANCELLED'));
    const released = await currentModel?.stop?.('campaign-storage-cancelled');
    if (currentModel?.stop && released?.cleanupVerified !== true) throw new Error('CAMPAIGN_STORAGE_CLEANUP_UNVERIFIED');
  } });
  lease.watch([directory, path.join(paths.base, 'admission')]);
  const episodes = [];
  try {
    if (existsSync(manifestFile)) {
      manifest = JSON.parse(readFileSync(manifestFile)); verifyFrozen(root, manifest, preparation);
      for (const file of readdirSync(path.join(directory, 'episodes'))) episodes.push(JSON.parse(readFileSync(path.join(directory, 'episodes', file))));
    } else {
      const product = sourceReceipt(root);
      let original, attribution, baselineCompletedAt;
      if (baseline) {
        const baselineDirectory = path.resolve(baseline);
        if (!baselineDirectory.startsWith(paths.campaigns + path.sep)) throw new Error('Baseline must be a repository-owned campaign.');
        original = JSON.parse(readFileSync(path.join(baselineDirectory, 'manifest.json')));
        const priorEpisodes = readdirSync(path.join(baselineDirectory, 'episodes')).map(file => JSON.parse(readFileSync(path.join(baselineDirectory, 'episodes', file))));
        const prior = buildReport(original, priorEpisodes);
        assertReplayBaseline(original, prior);
        if (!patches) throw new Error('Candidate replay requires --patches with one attributable patch batch.');
        attribution = JSON.parse(readFileSync(patches));
        if (!Array.isArray(attribution.defects) || attribution.defects.length < 1 || attribution.defects.length > 2 || attribution.defects.some(defect => !['observed_failure', 'layer', 'reproduction', 'remedy', 'tests'].every(key => typeof defect[key] === 'string' && defect[key].trim()))) throw new Error('Patch batch must document one or two observed, reproduced, tested defects.');
        if (existsSync(path.join(baselineDirectory, 'candidate-replay.json'))) throw new Error('The baseline already has its one candidate replay.');
        const baselineCompletion = JSON.parse(readFileSync(path.join(baselineDirectory, 'baseline-complete.json')));
        if (!Number.isSafeInteger(baselineCompletion.completed_at)) throw new Error('Baseline completion timestamp is missing.');
        baselineCompletedAt = baselineCompletion.completed_at; assertCandidatePreparationWindow(original, baselineCompletedAt);
        const hashes = frozenHashes(root, preparation);
        for (const key of Object.keys(hashes)) if (hashes[key] !== original.hashes[key]) throw new Error(`Evaluator/oracles/model settings changed: ${key}. Candidate is not comparable.`);
      }
      const preflightDeadline = original ? Math.min(baselineCompletedAt + original.phase_allocations_ms.diagnosis, original.deadline - original.forecast.replaySeconds * 1000 - original.phase_allocations_ms.reconciliation) : Date.now() + 30 * 60_000;
      lease.watch([directory, path.join(paths.base, 'admission'), path.join(paths.base, 'native-conformance')]);
      const { installationRoot, installation, harnesses, mechanicalPreflight } = await prepareCampaignSnapshot({ root, directory, product, install: installSnapshot,
        signal: campaignController.signal, deadline: preflightDeadline, beforeRoute: () => lease.check(), onProgress });
      lease.watch([directory, path.join(paths.base, 'admission')]);
      if (original) assertCandidatePreparationWindow(original, baselineCompletedAt);
      // Deadline is persisted before any model load. Conservative initial forecast never assumes a 31s episode.
      const available = new Set(harnesses.filter(harness => harness.status === 'mechanically-admitted').map(harness => harness.id));
      const liveRows = buildMatrix().filter(row => available.has(row.harness_id));
      const controlRoutesAvailable = ['codex-cli', 'mini-swe-agent'].every(id => available.has(id));
      const selectedWindows = original?.windows ?? restartManifest?.windows ?? windows;
      const started = original ? Date.parse(original.started_at) : restartManifest ? Date.parse(restartManifest.started_at) : Date.now(), timing = original?.forecast ?? forecast({ rows: liveRows, blockedRows: 171 - liveRows.length, episodeSeconds: 90, controls: controls && controlRoutesAvailable, windows: selectedWindows });
      timing.nominal_rows = 171; timing.mechanically_executable_rows = liveRows.length;
      let policy = campaignPolicy(selectedWindows, timing.mode);
      policy = campaignPolicy(selectedWindows, timing.mode);
      manifest = { schema_version: 1, id: path.basename(directory), snapshot: original ? 'candidate' : 'baseline', started_at: new Date(started).toISOString(), deadline: original?.deadline ?? restartManifest?.deadline ?? started + policy.duration_ms,
        windows: selectedWindows, checkpoints: Array.from({ length: selectedWindows - 1 }, (_, index) => started + (index + 1) * policy.checkpoint_ms),
        host: { platform: process.platform, architecture: process.arch, os_release: os.release(), memory_bytes: os.totalmem(), cpu: os.cpus()[0]?.model, node: process.version },
        phase_allocations_ms: original?.phase_allocations_ms ?? policy.phases,
        hashes: frozenHashes(root, preparation), product, installation, installation_root: installationRoot, mechanical_preflight: mechanicalPreflight, harnesses, mode: timing.mode, forecast: timing,
        rows: buildMatrix({ controls: !original && timing.controls_admitted, snapshot: original ? 'candidate' : 'baseline' }), preparation, contexts: { ordinary: 16384, extended: 32768 },
        ...(original ? { baseline: path.resolve(baseline), patch_batch: attribution } : {}),
        ...(restartManifest ? { [mechanicalRebaseline ? 'mechanical_rebaseline' : 'admission_restart']: { previous_campaign: path.resolve(restartFrom), previous_manifest_sha256: fileReceipt(path.resolve(restartFrom), 'manifest.json').sha256,
          ...(rebaselineEvidence ?? {}), reason: mechanicalRebaseline ? 'Evaluator-only cleanup/startup correction; prior diagnostic rows, deadline and calibration spending retained.' : 'Evaluator corrected before any scored episode; original deadline and calibration spending retained.' } } : {}),
        ...(original?.mechanical_rebaseline ? { mechanical_rebaseline: original.mechanical_rebaseline } : {}),
        calibration_limit: 12, opt_in: { explicit: true, scope: 'owned-local-preparation-and-evaluation', global_changes: false }, limitations: ['Initial forecast uses the episode ceiling until measured throughput exists.'] };
      manifest.total_ceilings = { model_requests: manifest.rows.length * 10 + 12, generated_tokens: manifest.rows.length * 2048 + 12 * 512,
        input_tokens: manifest.rows.reduce((sum, row) => sum + 6 * (row.scenario_id === 'S4' ? 32768 : 16384), 0) + 12 * 32768,
        model_visible_tools: manifest.rows.length * 12, underlying_ud_operations: manifest.rows.length * 12 };
      writeNew(manifestFile, manifest); chmodSync(manifestFile, 0o400);
      if (mechanicalRebaseline) writeNew(path.join(path.resolve(mechanicalRebaseline), 'mechanical-rebaseline.json'), { campaign: directory, ...rebaselineEvidence });
      if (original) writeNew(path.join(path.resolve(baseline), 'candidate-replay.json'), { campaign: directory, patch_batch: attribution });
    }
    mkdirSync(path.join(directory, 'episodes'), { recursive: true, mode: 0o700 });
    const completed = new Set(episodes.map(row => row.row_id));
    // The persisted calibration ledger prevents resume from granting a fresh allowance.
    const calibrationFile = path.join(manifest.baseline ?? directory, 'calibration.json');
    if (restartManifest && !existsSync(calibrationFile) && existsSync(path.join(restartFrom, 'calibration.json'))) cpSync(path.join(restartFrom, 'calibration.json'), calibrationFile, { errorOnExist: true, force: false });
    const rebaselineFrom = manifest.mechanical_rebaseline?.previous_campaign;
    if (!manifest.baseline && rebaselineFrom) {
      for (const model of MODELS) {
        const target = path.join(directory, `admission-${model.id}.json`);
        if (!existsSync(target)) cpSync(path.join(rebaselineFrom, `admission-${model.id}.json`), target, { errorOnExist: true, force: false });
      }
      const phaseTarget = path.join(directory, 'phase-baseline.json');
      if (!existsSync(phaseTarget)) cpSync(path.join(rebaselineFrom, 'phase-baseline.json'), phaseTarget, { errorOnExist: true, force: false });
    }
    const calibration = openCalibrationLedger(calibrationFile);
    const admissionDeadline = Math.min(manifest.deadline - manifest.phase_allocations_ms.reconciliation, Date.parse(manifest.started_at) + manifest.phase_allocations_ms.admission);
    const admissions = {};
    // Assess every model before scoring any baseline conversation.
    for (const specification of MODELS) {
      const admissionPath = path.join(manifest.baseline ?? directory, `admission-${specification.id}.json`);
      if (existsSync(admissionPath)) { admissions[specification.id] = JSON.parse(readFileSync(admissionPath)); continue; }
      const prepared = preparation.models.find(model => model.id === specification.id);
      calibration.selectModel(specification.id);
      onProgress(`Admitting ${specification.artifact}`);
      currentModel = prepared?.status === 'prepared' && Date.now() < admissionDeadline
        ? await admitModel(root, prepared, preparation.runtimes.find(runtime => runtime.id === prepared.runtime_id), { deadline: admissionDeadline, calibration, onProgress, translationRuntime: preparation.runtimes.find(runtime => runtime.id === 'mlx') })
        : { status: 'model_blocked', reason: prepared?.reason ?? 'Exact artifact is not prepared or admission allocation expired.' };
      const cleanup = await currentModel.stop?.();
      if (currentModel.status === 'admitted' && cleanup?.cleanupVerified !== true || currentModel.cleanup?.cleanupVerified === false) {
        writeNew(admissionPath, { status: 'model_blocked', reason: 'Admission could not verify model resource release.', cleanup });
        throw new Error('OWNED_MODEL_CLEANUP_UNVERIFIED: another model must not load.');
      }
      admissions[specification.id] = JSON.parse(JSON.stringify(currentModel));
      writeNew(admissionPath, admissions[specification.id]); currentModel = undefined;
    }
    const phaseFile = path.join(directory, 'phase-baseline.json');
    if (!existsSync(phaseFile)) writeNew(phaseFile, { started: Date.now(), deadline: Math.min(manifest.deadline - manifest.phase_allocations_ms.reconciliation, Date.now() + manifest.phase_allocations_ms[manifest.baseline ? 'replay' : 'baseline']) });
    const baselineEnd = JSON.parse(readFileSync(phaseFile)).deadline;
    for (const specification of MODELS) {
      const rows = manifest.rows.filter(row => row.model_id === specification.id && !completed.has(row.row_id));
      if (!rows.length) continue;
      if (Date.now() >= baselineEnd) break;
      verifyFrozen(root, manifest, preparation);
      const prepared = preparation.models.find(model => model.id === specification.id);
      const admission = admissions[specification.id];
      currentModel = admission.status === 'admitted' ? await admitModel(root, prepared, preparation.runtimes.find(runtime => runtime.id === prepared.runtime_id), { deadline: baselineEnd, calibration, onProgress, reuseAdmission: admission, translationRuntime: preparation.runtimes.find(runtime => runtime.id === 'mlx') }) : admission;
      let modelStopped = false, modelCleanupVerified = true;
      const trackStop = () => {
        if (!currentModel.stop) return;
        const stop = currentModel.stop;
        currentModel.stop = async (...args) => { modelStopped = true; modelCleanupVerified = false; const value = await stop(...args); modelCleanupVerified = value?.cleanupVerified === true; return value; };
      };
      trackStop();
      try {
        for (const row of rows) {
          if (Date.now() >= baselineEnd) break;
          await lease.check(); verifyFrozen(root, manifest, preparation);
          for (const checkpoint of manifest.checkpoints ?? []) if (Date.now() >= checkpoint) {
            const checkpointFile = path.join(directory, `checkpoint-${checkpoint}.json`);
            if (!existsSync(checkpointFile)) writeNew(checkpointFile, { at: Date.now(), checkpoint, deadline: manifest.deadline, completed_rows: episodes.length, calibration: calibration.used, qualification: 'progress-only-no-budget-reset' });
          }
          const harness = manifest.harnesses.find(item => item.id === row.harness_id);
          if (modelStopped && harness.status === 'mechanically-admitted') {
            if (!modelCleanupVerified) throw new Error('OWNED_MODEL_CLEANUP_UNVERIFIED: restart is prohibited.');
            currentModel = await admitModel(root, prepared, preparation.runtimes.find(runtime => runtime.id === prepared.runtime_id), { deadline: baselineEnd, calibration, onProgress, reuseAdmission: admission, translationRuntime: preparation.runtimes.find(runtime => runtime.id === 'mlx') });
            modelStopped = false; trackStop();
          }
          const capabilityBlocker = row.scenario_id === 'S4' && currentModel.capabilities?.extended_context !== true ? 'The frozen extended context was not admitted.'
            : row.scenario_id === 'S5' && currentModel.capabilities?.images !== true ? 'The exact image/processor route was not admitted.' : null;
          const episode = currentModel.status !== 'admitted' ? { ...row, outcome: currentModel.status, reason: currentModel.reason }
            : harness.status !== 'mechanically-admitted' ? { ...row, outcome: 'interface_unsupported', reason: harness.reason }
              : capabilityBlocker ? { ...row, outcome: 'context_resource_blocked', reason: capabilityBlocker }
              : await runEpisode(root, { ...manifest, signal: campaignController.signal }, row, currentModel, harness, manifest.installation_root, path.join(directory, 'work', sha256(row.id).slice(0, 16)));
          episode.intent = SCENARIOS.find(scenario => scenario.id === row.scenario_id).prompt;
          episode.discovery ??= { harness: harness.id, skill_mechanism: harness.skill_mechanism, native_status: harness.status, reason: harness.reason };
          writeNew(path.join(directory, 'episodes', sha256(row.id) + '.json'), episode); episodes.push(episode);
          if (episode.owned_cleanup_verified === false) throw new Error('OWNED_NATIVE_CLEANUP_UNVERIFIED: another episode must not start.');
          onProgress(`${row.model_id}/${row.harness_id}/${row.scenario_id}/${row.seed}: ${episode.outcome}`);
        }
      } finally {
        const cleanup = await currentModel.stop?.();
        if (currentModel.status === 'admitted' && cleanup?.cleanupVerified !== true) throw new Error('OWNED_MODEL_CLEANUP_UNVERIFIED: another model must not load.');
        currentModel = undefined;
      }
    }
    verifyFrozen(root, manifest, preparation, { allowExpired: true });
    // Rows unfinished at the deadline remain incomplete in the reconciled report.
    const output = await writeReport(path.join(directory, 'reports', randomUUID()), manifest, episodes);
    if (!manifest.baseline && output.report.counts.missing === 0 && !existsSync(path.join(directory, 'baseline-complete.json'))) {
      writeNew(path.join(directory, 'baseline-complete.json'), { completed_at: Date.now(), report: output.json, product_sha256: manifest.product.sha256, deadline: manifest.deadline });
    }
    if (manifest.baseline) {
      const baselineManifest = JSON.parse(readFileSync(path.join(manifest.baseline, 'manifest.json')));
      const baselineEpisodes = readdirSync(path.join(manifest.baseline, 'episodes')).map(file => JSON.parse(readFileSync(path.join(manifest.baseline, 'episodes', file))));
      writeNew(path.join(directory, 'comparison.json'), compareReports(buildReport(baselineManifest, baselineEpisodes), output.report));
    }
    return { directory, report: output.report, report_path: output.json };
  } finally { await currentModel?.stop?.(); await lease.cleanup(); }
}
