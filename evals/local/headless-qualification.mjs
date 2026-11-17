// SPDX-License-Identifier: MIT
/** Final read-only replay of retained headless evidence. Never launches a process. */
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { captureWorkspace } from '../../scripts/quality/workflow-grader.mjs';
import { openIterationSession } from './iteration-state.mjs';
import { PROFILE, HEADLESS_POLICY, HEADLESS_HARNESS_IDS, buildHeadlessCoverage } from './headless-profile.mjs';
import { readPreparation, localPaths } from './preparation.mjs';
import { frozenHashes, deriveSeed } from './campaign.mjs';
import { verifyCampaignPreflight } from './campaign-preflight.mjs';
import { completedBudgetEvidence } from './qualification.mjs';
import { observeScenario, gradeScenario } from './scenarios.mjs';
import { verifyLoadedRuntimeIdentity } from './serving.mjs';
import { MODELS } from './registry.mjs';
import { DEFAULT_LIMITS } from './budget.mjs';
import { redactTraffic } from './gateway.mjs';
import { assertResourceMemory } from './resource-memory.mjs';

const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const referenceKey = value => `${value?.path}#${value?.sha256}`;
const ensure = (condition, code) => { if (!condition) throw new Error(code); };
const fixtureOnly = value => Boolean(value && typeof value === 'object' && (value.fixture_only === true || Object.values(value).some(fixtureOnly)));
function regular(base, file) {
  ensure(typeof file === 'string', 'EVIDENCE_PATH_INVALID');
  const target = path.resolve(base, file), info = lstatSync(target);
  ensure(target.startsWith(realpathSync(base) + path.sep) && info.isFile() && !info.isSymbolicLink() && realpathSync(target) === target && info.size <= 128 * 1024 ** 2, 'EVIDENCE_PATH_INVALID');
  return readFileSync(target);
}
function bound(base, reference) {
  ensure(reference && /^[a-f0-9]{64}$/.test(reference.sha256 ?? ''), 'EVIDENCE_REFERENCE_INVALID');
  const bytes = regular(base, reference.path);
  ensure(sha256(bytes) === reference.sha256, 'EVIDENCE_BYTES_CHANGED');
  return JSON.parse(bytes);
}
function installationInventory(directory, receipt) {
  ensure(Array.isArray(receipt.files) && receipt.files.length && sha256(JSON.stringify(receipt.files)) === receipt.sha256, 'INSTALLATION_RECEIPT_INVALID');
  ensure(realpathSync(directory) === directory && lstatSync(directory).isDirectory(), 'INSTALLATION_PATH_INVALID');
  const files = [];
  const visit = current => { for (const name of readdirSync(current).sort()) {
    const file = path.join(current, name), info = lstatSync(file), relative = path.relative(directory, file).split(path.sep).join('/');
    if (info.isSymbolicLink()) {
      const target = realpathSync(file); ensure(target.startsWith(directory + path.sep), 'INSTALLATION_LINK_ESCAPES');
      files.push({ path: relative, link_target: path.relative(directory, target) });
    } else if (info.isDirectory()) visit(file);
    else { ensure(info.isFile(), 'INSTALLATION_SPECIAL_FILE'); files.push(fileReceipt(directory, relative)); }
  } };
  visit(directory); ensure(same(files, receipt.files), 'INSTALLATION_BYTES_CHANGED');
}
export function verifiedProcessAbsence(result, pid) {
  if (result?.cleanupVerified !== true || !Array.isArray(result.cleanup_evidence)) return false;
  const observations = result.cleanup_evidence.filter(item => ['signal-zero', 'process-table'].includes(item.method)), last = observations.at(-1);
  const signal = observations.findLast(item => item.method === 'signal-zero'), selected = pid ?? signal?.pgid;
  if (!integer(selected) || selected < 1 || signal?.pgid !== selected) return false;
  return Boolean(last && (last.method === 'signal-zero' && last.outcome === 'failed' && last.code === 'ESRCH'
    || last.method === 'process-table' && signal.code === 'EPERM' && last.outcome === 'absent' && last.status === 0 && !last.signal && !last.error
      && last.same_owner === true && Array.isArray(last.matching) && last.matching.length === 0 && Array.isArray(last.rows) && last.rows.length > 0
      && last.rows.every(row => integer(row.pid) && row.pid > 0 && integer(row.pgid) && row.pgid !== selected)));
}
function nativeRelease(event, harness) {
  const cleanup = event.cleanup;
  ensure(event.execution_location === 'arm64-container' && event.runtime_location === 'native-macos' && event.harness_id === harness.id
    && event.image_id === harness.container?.image_id && /^sha256:[a-f0-9]{64}$/.test(event.image_id ?? '')
    && typeof event.container_id === 'string' && event.container_id.startsWith('ud-agent-local-eval-') && event.cleanupVerified === true
    && cleanup?.container_id === event.container_id && cleanup.image_id === event.image_id && cleanup.network_id === event.network_id
    && cleanup.cleanupVerified === true && cleanup.bridge_cleanup?.cleanupVerified === true && verifiedProcessAbsence(cleanup), 'NATIVE_RELEASE_UNVERIFIED');
  ensure(integer(cleanup.deadline) && integer(cleanup.finished_at) && cleanup.finished_at <= cleanup.deadline, 'NATIVE_RELEASE_DEADLINE_UNVERIFIED');
  const steps = cleanup.container_cleanup;
  ensure(Array.isArray(steps) && ['container-inspect-initial', 'container-inspect-stopped', 'container-absence-final', 'network-remove'].every(step => steps.findLast(item => item.step === step)?.outcome === 'completed')
    && steps.findLast(item => item.step === 'host-process-release')?.cleanupVerified === true, 'NATIVE_CONTAINER_RELEASE_UNVERIFIED');
}

/** The report is a proposal; canonical journal, current bytes and replay decide. */
export async function verifyHeadlessEvidence(root, directory, proposed) {
  const failures = [], fail = (code, identity) => failures.push(identity ? `${code}:${identity}` : code);
  const checked = (code, action, identity) => { try { return action(); } catch { fail(code, identity); return undefined; } };
  let store, state, report;
  checked('SESSION_JOURNAL_INVALID', () => {
    store = openIterationSession({ root, directory }); state = store.snapshot(); report = store.report();
    ensure(store.manifest.profile === PROFILE, 'PROFILE_INVALID');
  });
  if (!report || !state) return { status: 'unmet', failures };
  const base = localPaths(root).base, required = buildHeadlessCoverage();
  checked('PRELIMINARY_COVERAGE_UNVERIFIED', () => ensure(report.final_headless_qualification === true && proposed?.final_headless_qualification === true, 'COVERAGE_UNMET'));
  checked('REPORT_DIFFERS_FROM_JOURNAL', () => {
    for (const key of ['session_id', 'identities', 'retained_product_round', 'started_at', 'deadline', 'execution_deadline', 'rounds', 'headless_qualification', 'lifecycle_evidence']) ensure(same(report[key], proposed?.[key]), 'REPORT_CHANGED');
  });
  let preparation;
  checked('PREPARATION_OR_FROZEN_IDENTITY_CHANGED', () => {
    preparation = readPreparation(root);
    ensure(MODELS.every(model => preparation.models.some(item => item.id === model.id && item.artifact === model.artifact && item.status === 'prepared')), 'MODEL_PREPARATION_INCOMPLETE');
    ensure(preparation.runtimes.every(runtime => runtime.status === 'prepared' && runtime.preflight?.inference === false && runtime.preflight?.model_weights_loaded === false), 'RUNTIME_PREFLIGHT_MISSING');
    ensure(same(frozenHashes(root, preparation), store.manifest.identities), 'FROZEN_IDENTITY_CHANGED');
  });
  const core = report.rounds.find(round => round.id === report.retained_product_round), transfer = report.rounds.find(round => round.kind === 'transfer');
  let snapshot;
  checked('RETAINED_SNAPSHOT_OR_PREFLIGHT_CHANGED', () => {
    ensure(core && transfer && transfer.parent_round === core.id && same(core.installation, transfer.installation) && same(core.product, transfer.product), 'RETAINED_LINEAGE_INVALID');
    snapshot = JSON.parse(regular(directory, path.join(directory, 'snapshots', `${core.id}.json`)));
    const transferSnapshot = JSON.parse(regular(directory, path.join(directory, 'snapshots', `${transfer.id}.json`)));
    ensure(same(snapshot, transferSnapshot) && same(snapshot.product, core.product) && same(snapshot.installation, core.installation)
      && snapshot.installationRoot === snapshot.installation.root && same(snapshot.mechanicalPreflight, snapshot.installation.mechanical_preflight), 'SNAPSHOT_BINDING_INVALID');
    ensure(sourceReceipt(root).sha256 === core.product.sha256, 'CURRENT_SOURCE_CHANGED');
    ensure(snapshot.installationRoot.startsWith(path.resolve(directory) + path.sep), 'INSTALLATION_ESCAPES_SESSION');
    installationInventory(snapshot.installationRoot, snapshot.installation);
    const proof = verifyCampaignPreflight(root, snapshot.mechanicalPreflight, core.product.sha256, { harnessIds: HEADLESS_HARNESS_IDS });
    ensure(proof.installation_root === snapshot.installationRoot && proof.installation_sha256 === core.installation.sha256 && proof.headless_inventory.every(row => ['verified', 'current-proof-reused'].includes(row.status)), 'MECHANICAL_ROUTES_UNVERIFIED');
    ensure(!fixtureOnly(snapshot) && !fixtureOnly(proof), 'FIXTURE_ONLY_SNAPSHOT');
    for (const row of proof.headless_inventory) {
      const native = bound(base, row.proof), release = bound(base, row.release);
      ensure(!fixtureOnly(native) && !fixtureOnly(release) && native.status === 'mechanically-admitted' && native.harness_id === row.harness_id
        && native.execution_location === 'arm64-container' && native.source === 'native-client-with-inert-provider', 'MECHANICAL_NATIVE_PROOF_INVALID');
    }
    ensure(HEADLESS_HARNESS_IDS.every(id => snapshot.harnesses.some(harness => harness.id === id && harness.status === 'mechanically-admitted' && harness.execution_location === 'arm64-container')), 'NATIVE_ROUTES_UNVERIFIED');
  });

  const admissions = new Map(), rowAdmissions = new Map();
  checked('LIFECYCLE_SEQUENCE_OR_CLOCK_INVALID', () => {
    let active = null, activeEpisode = null, first = null, lastAt = -Infinity, latestAdmission;
    const calibrationRequests = new Set();
    for (const name of readdirSync(path.join(directory, 'journal')).sort()) {
      const event = JSON.parse(regular(directory, path.join(directory, 'journal', name))), value = event.value;
      ensure(integer(event.at) && event.at >= lastAt, 'JOURNAL_CLOCK_REVERSED'); lastAt = event.at;
      if (first !== null) ensure(event.at <= first + HEADLESS_POLICY.duration_ms, 'ORIGINAL_DEADLINE_EXCEEDED');
      if (event.type === 'admission_started') {
        ensure(active === null && activeEpisode === null && MODELS.some(model => model.id === value.model_id), 'CONCURRENT_MODEL_ADMISSION');
        first ??= event.at; active = value.model_id; latestAdmission = undefined;
        ensure(event.at < first + HEADLESS_POLICY.duration_ms - HEADLESS_POLICY.reconciliation_ms, 'ADMISSION_AFTER_EXECUTION_DEADLINE');
      } else if (event.type === 'admission_recorded') {
        ensure(active === value.model_id && activeEpisode === null && !latestAdmission && !admissions.has(referenceKey(value.reference)), 'ADMISSION_SEQUENCE_INVALID');
        latestAdmission = value.reference; admissions.set(referenceKey(value.reference), { model_id: active, reference: value.reference, recorded_at: event.at });
      } else if (event.type === 'calibration_charged') {
        ensure(active === value.model_id && typeof value.request_id === 'string' && value.request_id.length > 0 && !calibrationRequests.has(value.request_id), 'CALIBRATION_SEQUENCE_INVALID');
        calibrationRequests.add(value.request_id);
      } else if (event.type === 'episode_claimed') {
        const row = report.rounds.flatMap(round => round.rows).find(row => row.id === value.row_id);
        ensure(row && activeEpisode === null && active === row.model_id && latestAdmission && !rowAdmissions.has(value.row_id), 'EPISODE_WITHOUT_ADMISSION');
        ensure(value.round_id === row.round_id && ['inference', 'tools', 'ud_operations', 'output'].every(key => value[key] === DEFAULT_LIMITS[key])
          && value.input === 6 * row.context_envelope, 'EPISODE_RESERVATION_CHANGED');
        activeEpisode = value.row_id; rowAdmissions.set(value.row_id, latestAdmission);
        ensure(event.at + HEADLESS_POLICY.forecast_episode_ms <= state.execution_deadline, 'EPISODE_STARTED_TOO_LATE');
      } else if (event.type === 'episode_recorded') {
        ensure(activeEpisode === value.row_id, 'EPISODE_SEQUENCE_INVALID'); activeEpisode = null;
      } else if (event.type === 'model_released') {
        ensure(active === value.model_id && activeEpisode === null && latestAdmission, 'RELEASE_SEQUENCE_INVALID');
        const admission = admissions.get(referenceKey(latestAdmission)); admission.release = value.proof; admission.released_at = event.at;
        active = null; latestAdmission = undefined;
      }
    }
    ensure(active === null && activeEpisode === null && first === state.started_at && state.deadline === first + HEADLESS_POLICY.duration_ms
      && state.execution_deadline === state.deadline - HEADLESS_POLICY.reconciliation_ms, 'UNRELEASED_OR_RETIMED_SESSION');
    ensure(state.reserved.episodes === rowAdmissions.size && state.reserved.episodes <= 189 && state.calibration.used === calibrationRequests.size && state.calibration.used <= 12
      && Object.entries(state.calibration.per_model).every(([id, count]) => MODELS.some(model => model.id === id) && integer(count) && count <= 4), 'GLOBAL_BUDGET_EXCEEDED');
  });
  const documents = new Map();
  for (const admission of admissions.values()) {
    const document = checked('ADMISSION_REFERENCE_CHANGED', () => bound(base, admission.reference), admission.model_id);
    if (!document) continue;
    documents.set(referenceKey(admission.reference), document);
    if (fixtureOnly(document)) fail('FIXTURE_ONLY_ADMISSION', admission.model_id);
    checked('ADMISSION_CONTENT_UNVERIFIED', () => {
      ensure(['admitted', 'model_blocked', 'context_resource_blocked'].includes(document.status), 'ADMISSION_STATUS_INVALID');
      if (document.status !== 'admitted') return;
      const model = MODELS.find(item => item.id === admission.model_id), prepared = preparation?.models.find(item => item.id === admission.model_id), runtime = preparation?.runtimes.find(item => item.id === prepared?.runtime_id);
      ensure(document.admission_kind === 'mechanical' && document.model?.id === model.id && document.artifact === model.artifact
        && document.model.artifact === model.artifact && document.revision === prepared?.revision && document.model.revision === prepared.revision
        && document.wire_model === prepared.directory && document.runtime_lock_sha256 === runtime?.lock_sha256
        && document.context_envelope === 16384 && document.seed_behavior === 'explicit-request-seed', 'MODEL_IDENTITY_INVALID');
      verifyLoadedRuntimeIdentity(document.runtime_identity, model, prepared, runtime);
    }, admission.model_id);
    if (!admission.release) { fail('ADMISSION_RELEASE_REFERENCE_MISSING', admission.model_id); continue; }
    const release = checked('RELEASE_REFERENCE_CHANGED', () => bound(base, admission.release), admission.model_id);
    if (!release) continue;
    if (fixtureOnly(release)) fail('FIXTURE_ONLY_RELEASE', admission.model_id);
    checked('MODEL_RELEASE_UNVERIFIED', () => {
      ensure(release.kind === 'iteration-owned-model-release' && release.model_id === admission.model_id && release.owned_cleanup_verified === true
        && release.cleanup?.stopped === true && release.cleanup.cleanupVerified === true, 'RELEASE_FLAGS_INVALID');
      if (document.status !== 'admitted' && document.cleanup?.no_owned_processes_launched === true) {
        ensure(document.cleanup.launches === 0 && document.cleanup.evidence_kind === 'prelaunch-control-flow', 'PRELAUNCH_RELEASE_INVALID'); return;
      }
      const evidence = release.admission_evidence;
      ensure(evidence?.path === path.join(document.evidence_directory, 'admission.jsonl'), 'RELEASE_LOG_BINDING_MISSING');
      const bytes = regular(base, evidence.path); ensure(sha256(bytes) === evidence.sha256, 'RELEASE_LOG_CHANGED');
      const log = bytes.toString('utf8').trim().split('\n').map(line => JSON.parse(line)), stopped = log.findLast(event => event.type === 'owned_server_stopped');
      ensure(stopped?.cleanupVerified === true && Array.isArray(stopped.pids) && stopped.pids.length > 0 && Array.isArray(stopped.outcomes)
        && stopped.outcomes.length === stopped.pids.length && stopped.outcomes.every((outcome, index) => verifiedProcessAbsence(outcome, stopped.pids[index]))
        && (document.status !== 'admitted' || Date.parse(stopped.at) >= admission.recorded_at) && Date.parse(stopped.at) <= admission.released_at
        && integer(stopped.elapsed_ms) && stopped.elapsed_ms <= 5000, 'PROCESS_ABSENCE_UNVERIFIED');
    }, admission.model_id);
  }
  const retainedRows = [...(core?.rows.filter(row => row.skills_enabled) ?? []), ...(transfer?.rows ?? [])];
  checked('EXACT_COVERAGE_UNVERIFIED', () => ensure(retainedRows.length === 117 && new Set(retainedRows.map(row => row.cell_id)).size === 117
    && required.every(expected => retainedRows.some(row => ['cell_id', 'model_id', 'model_artifact', 'harness_id', 'scenario_id', 'seed', 'skills_enabled', 'context_envelope'].every(key => row[key] === expected[key]))), 'COVERAGE_CHANGED'));
  for (const row of retainedRows) {
    const episode = checked('EPISODE_REFERENCE_CHANGED', () => bound(base, row.episode), row.cell_id);
    if (!episode) continue;
    if (fixtureOnly(episode)) { fail('FIXTURE_ONLY_EPISODE', row.cell_id); continue; }
    try {
      ensure(row.evidence_verified && episode.outcome === 'passed' && episode.owned_cleanup_verified === true && episode.candidate_installation_sha256 === core.installation.sha256, 'EPISODE_BINDING_INVALID');
      ensure(['row_id', 'model_id', 'model_artifact', 'harness_id', 'scenario_id', 'seed', 'skills_enabled'].every(key => episode[key] === row[key]), 'EPISODE_IDENTITY_CHANGED');
      ensure(same(redactTraffic(episode), episode), 'UNREDACTED_CREDENTIAL_EVIDENCE');
      const admission = documents.get(referenceKey(rowAdmissions.get(row.id))), evidence = episode.evidence, metrics = episode.metrics, events = episode.events;
      ensure(admission?.status === 'admitted' && admission.model?.id === row.model_id && (row.scenario_id !== 'S4' || admission.extended_context_envelope === 32768 && admission.capabilities?.extended_context === true), 'EPISODE_MODEL_UNADMITTED');
      ensure(snapshot && evidence?.before && evidence.after && typeof evidence.task_root === 'string' && evidence.task_root.startsWith(path.resolve(directory, 'work', row.round_id) + path.sep)
        && realpathSync(evidence.task_root) === evidence.task_root, 'WORKSPACE_EVIDENCE_MISSING');
      ensure(same(captureWorkspace(evidence.task_root), evidence.after), 'WORKSPACE_BYTES_CHANGED');
      ensure(completedBudgetEvidence(metrics) && Array.isArray(events), 'BUDGET_EVIDENCE_MISSING');
      const requests = events.filter(event => event.type === 'provider_request'), responses = events.filter(event => event.type === 'model_visible_response'), forwards = events.filter(event => event.type === 'upstream_request');
      const observed = { inference: requests.length, input: requests.reduce((sum, event) => sum + event.tokens?.inputTokens, 0), output: responses.reduce((sum, event) => sum + event.outputTokens, 0),
        tools: responses.reduce((sum, event) => sum + event.toolCalls, 0), ud_operations: events.filter(event => event.type === 'operation_start' || event.type === 'operation_step' && event.charge === true).length };
      ensure(requests.length > 0 && new Set(requests.map(event => event.id)).size === requests.length && responses.length === requests.length
        && requests.every(request => request.tokens?.trusted === true && integer(request.tokens.inputTokens) && integer(request.tokens.contextTokens ?? request.tokens.inputTokens)
          && (request.tokens.contextTokens ?? request.tokens.inputTokens) + 512 <= row.context_envelope && responses.filter(response => response.id === request.id).length === 1), 'REQUEST_TOKEN_ACCOUNTING_UNVERIFIED');
      for (const [key, value] of Object.entries(observed)) ensure(integer(value) && value === metrics.counters[key] && value <= (key === 'input' ? row.context_envelope * 6 : DEFAULT_LIMITS[key]), 'COUNTER_CAPTURE_MISMATCH');
      ensure(responses.every(event => integer(event.outputTokens) && event.outputTokens <= 512 && integer(event.toolCalls)), 'RESPONSE_LIMIT_EXCEEDED');
      ensure(forwards.length === requests.length && forwards.every((event, ordinal) => requests.some(request => request.id === event.id)
        && event.effective_sampling?.seed === deriveSeed(row.seed, ordinal) && Object.entries(admission.sampling).every(([key, value]) => event.effective_sampling[key] === value)), 'FROZEN_SAMPLING_UNVERIFIED');
      const native = events.filter(event => event.type === 'native_identity'); ensure(native.length === 1, 'NATIVE_IDENTITY_MISSING');
      nativeRelease(native[0], snapshot.harnesses.find(harness => harness.id === row.harness_id));
      ensure(Array.isArray(metrics.resources) && metrics.resources.length > 0, 'RESOURCE_OBSERVATIONS_MISSING');
      for (const sample of metrics.resources) assertResourceMemory(sample);
      ensure(metrics.resources.some(sample => sample.containers.some(container => container.id === native[0].container_id)), 'OWNED_CONTAINER_MEMORY_UNOBSERVED');
      const projected = observeScenario(row.scenario_id, { events, ...evidence, taskRoot: evidence.task_root, installation: snapshot.installationRoot,
        finalAnswer: episode.final_answer, contextEnvelope: row.context_envelope, outputReserve: 512, modelBinding: { publicModel: row.model_artifact, wireModel: admission.wire_model } });
      const verdict = await gradeScenario(row.scenario_id, { before: evidence.before, after: evidence.after, finalAnswer: episode.final_answer,
        events: projected.events, observations: projected.observations, taskRoot: evidence.task_root });
      ensure(verdict.status === 'passed' && projected.observations.complete === true && projected.observations.model_attribution === true
        && projected.observations.no_user_hints === true, 'INDEPENDENT_REPLAY_FAILED');
    } catch (error) {
      // Codes only: malformed evidence, native answers and paths never become a credential leak in reports.
      fail(/^[A-Z][A-Z0-9_]+$/.test(error.message) ? error.message : 'EPISODE_EVIDENCE_UNVERIFIED', row.cell_id);
    }
  }
  return { status: failures.length ? 'unmet' : 'passed', failures };
}
