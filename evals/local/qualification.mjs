// SPDX-License-Identifier: MIT
/** Read-only model evidence verification. Import and CI inspection never generate. */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { sourceReceipt, sha256, fileReceipt } from '../../scripts/release/candidate.mjs';
import { captureWorkspace } from '../../scripts/quality/workflow-grader.mjs';
import { buildReport } from './report.mjs';
import { observeScenario, gradeScenario } from './scenarios.mjs';
import { DEFAULT_LIMITS } from './budget.mjs';
import { validateMechanicalRebaseline } from './campaign.mjs';
import { buildMatrix } from './registry.mjs';

/** A verified release cannot turn unknown interrupted output into known usage. */
export function completedBudgetEvidence(metrics) {
  return Boolean(metrics?.counters && metrics.pending_requests === 0 && metrics.pending_operations === 0
    && ['not_requested', 'verified'].includes(metrics.cleanup) && metrics.stopped === null
    && metrics.output_usage_verified === true && Array.isArray(metrics.abandoned_inference) && metrics.abandoned_inference.length === 0
    && metrics.reserved_output === 0 && metrics.unknown_output_tokens_upper_bound === 0 && metrics.output_tokens_upper_bound === metrics.counters.output
    && Number.isFinite(metrics.elapsed_ms) && metrics.elapsed_ms >= 0 && metrics.elapsed_ms <= 95_000);
}

/** Reconcile the spent diagnostic attempt without modifying or rescoring it. */
export function verifyMechanicalRebaseline(root, directory, manifest, episodes) {
  if (!manifest.mechanical_rebaseline) return [];
  const failures = [], read = file => JSON.parse(readFileSync(file, 'utf8'));
  const require = (condition, code) => { if (!condition) throw new Error(code); };
  const bound = (base, record) => {
    require(record && typeof record.path === 'string' && !path.isAbsolute(record.path) && path.resolve(base, record.path).startsWith(path.resolve(base) + path.sep), 'REBASELINE_RECEIPT_PATH_INVALID');
    const actual = fileReceipt(base, record.path);
    require(actual.sha256 === record.sha256 && actual.size === record.size, `REBASELINE_RECEIPT_CHANGED:${record.path}`);
    return read(path.join(base, record.path));
  };
  try {
    const baselineDirectory = manifest.snapshot === 'candidate' ? manifest.baseline : directory;
    require(typeof baselineDirectory === 'string' && path.resolve(baselineDirectory).startsWith(path.resolve(root, '.artifacts/local-evals/campaigns') + path.sep), 'REBASELINE_DIRECTORY_INVALID');
    const baseline = manifest.snapshot === 'candidate' ? read(path.join(baselineDirectory, 'manifest.json')) : manifest;
    require(JSON.stringify(baseline.mechanical_rebaseline) === JSON.stringify(manifest.mechanical_rebaseline), 'REBASELINE_CANDIDATE_LINEAGE_MISMATCH');
    const lineage = baseline.mechanical_rebaseline, previousDirectory = lineage.previous_campaign;
    require(typeof previousDirectory === 'string' && path.resolve(previousDirectory).startsWith(path.resolve(root, '.artifacts/local-evals/campaigns') + path.sep) && path.resolve(previousDirectory) !== path.resolve(baselineDirectory), 'REBASELINE_PREVIOUS_DIRECTORY_INVALID');
    require(fileReceipt(previousDirectory, 'manifest.json').sha256 === lineage.previous_manifest_sha256, 'REBASELINE_MANIFEST_CHANGED');
    const prior = read(path.join(previousDirectory, 'manifest.json'));
    const previousFiles = readdirSync(path.join(previousDirectory, 'episodes')).filter(file => file.endsWith('.json')).sort().map(file => `episodes/${file}`);
    require(Array.isArray(lineage.previous_rows) && JSON.stringify(lineage.previous_rows.map(row => row.path).sort()) === JSON.stringify(previousFiles), 'REBASELINE_PRIOR_ROWS_CHANGED');
    const previousRows = lineage.previous_rows.map(record => bound(previousDirectory, record));
    const expected = validateMechanicalRebaseline({ prior, product: baseline.product, hashes: baseline.hashes, preparation: baseline.preparation, episodes: previousRows, now: Date.parse(prior.started_at) });
    for (const [key, value] of Object.entries(expected)) require(JSON.stringify(lineage[key]) === JSON.stringify(value), `REBASELINE_ALLOWANCE_MISMATCH:${key}`);
    require(JSON.stringify(baseline.rows) === JSON.stringify(buildMatrix()), 'REBASELINE_ASSIGNMENT_CHANGED');
    for (const key of ['started_at', 'deadline', 'windows', 'phase_allocations_ms']) require(JSON.stringify(baseline[key]) === JSON.stringify(prior[key]) && JSON.stringify(manifest[key]) === JSON.stringify(prior[key]), `REBASELINE_CLOCK_CHANGED:${key}`);
    const marker = read(path.join(previousDirectory, 'mechanical-rebaseline.json'));
    require(path.resolve(marker.campaign) === path.resolve(baselineDirectory), 'REBASELINE_SPENT_MARKER_MISMATCH');
    const phase = bound(previousDirectory, lineage.phase_receipt), calibration = bound(previousDirectory, lineage.calibration_receipt);
    require(JSON.stringify(read(path.join(baselineDirectory, 'phase-baseline.json'))) === JSON.stringify(phase), 'REBASELINE_PHASE_CHANGED');
    require(JSON.stringify(read(path.join(baselineDirectory, 'calibration.json'))) === JSON.stringify(calibration), 'REBASELINE_CALIBRATION_CHANGED');
    require(Array.isArray(lineage.admissions) && JSON.stringify(lineage.admissions.map(row => row.id).sort()) === JSON.stringify(['bonsai', 'lfm3', 'minicpm']), 'REBASELINE_ADMISSIONS_MISSING');
    for (const admission of lineage.admissions) {
      require(admission.path === `admission-${admission.id}.json`, 'REBASELINE_ADMISSION_PATH_INVALID');
      bound(previousDirectory, admission);
      require(fileReceipt(baselineDirectory, admission.path).sha256 === admission.sha256, `REBASELINE_ADMISSION_CHANGED:${admission.id}`);
    }
    require(fileReceipt(previousDirectory, 'post-stop-release.json').sha256 === lineage.release_receipt_sha256, 'REBASELINE_RELEASE_RECEIPT_CHANGED');
    const release = read(path.join(previousDirectory, 'post-stop-release.json'));
    require(release.cleanupVerified === true && typeof release.evidence?.path === 'string' && path.resolve(release.evidence.path).startsWith(path.resolve(root, '.artifacts/local-evals') + path.sep), 'REBASELINE_RELEASE_UNVERIFIED');
    require(fileReceipt(path.dirname(release.evidence.path), path.basename(release.evidence.path)).sha256 === release.evidence.sha256, 'REBASELINE_RELEASE_PROOF_CHANGED');
    const proof = read(release.evidence.path);
    require(proof.current_owned_compute_absence_verified === true, 'REBASELINE_RELEASE_UNVERIFIED');
    require(proof.campaign_manifest?.sha256 === lineage.previous_manifest_sha256 && Array.isArray(proof.episodes)
      && JSON.stringify(proof.episodes.map(row => row.sha256).sort()) === JSON.stringify(lineage.previous_rows.map(row => row.sha256).sort()), 'REBASELINE_RELEASE_IDENTITY_MISMATCH');
    const baselineFiles = readdirSync(path.join(baselineDirectory, 'episodes')).filter(file => file.endsWith('.json'));
    let totalRows = previousRows.length + baselineFiles.length;
    if (manifest.snapshot === 'candidate') totalRows += episodes.length;
    else if (existsSync(path.join(baselineDirectory, 'candidate-replay.json'))) {
      const replay = read(path.join(baselineDirectory, 'candidate-replay.json'));
      require(typeof replay.campaign === 'string' && path.resolve(replay.campaign).startsWith(path.resolve(root, '.artifacts/local-evals/campaigns') + path.sep), 'REBASELINE_REPLAY_DIRECTORY_INVALID');
      const candidate = read(path.join(replay.campaign, 'manifest.json'));
      require(path.resolve(candidate.baseline) === path.resolve(baselineDirectory) && JSON.stringify(candidate.mechanical_rebaseline) === JSON.stringify(lineage), 'REBASELINE_REPLAY_LINEAGE_MISMATCH');
      totalRows += readdirSync(path.join(replay.campaign, 'episodes')).filter(file => file.endsWith('.json')).length;
    }
    require(totalRows <= 360, 'REBASELINE_GLOBAL_EPISODE_LIMIT_EXCEEDED');
  } catch (error) { failures.push(error.message); }
  return failures;
}

export async function verifyCampaignEvidence(root, directory) {
  const failures = [], read = file => JSON.parse(readFileSync(file, 'utf8'));
  const manifest = read(path.join(directory, 'manifest.json'));
  const episodes = readdirSync(path.join(directory, 'episodes')).filter(file => file.endsWith('.json')).map(file => read(path.join(directory, 'episodes', file)));
  const report = buildReport(manifest, episodes);
  failures.push(...verifyMechanicalRebaseline(root, directory, manifest, episodes));
  if (report.gates.complete_starter_campaign.status !== 'passed' || report.gates.provider_neutral_declared_coverage.status !== 'passed') failures.push('REQUIRED_MODEL_COVERAGE_UNMET');
  if (sourceReceipt(root).sha256 !== manifest.product?.sha256) failures.push('CURRENT_PRODUCT_IDENTITY_MISMATCH');
  for (const record of manifest.installation?.files ?? []) {
    const file = path.join(manifest.installation_root, record.path);
    if (!record.link_target && (!existsSync(file) || sha256(readFileSync(file)) !== record.sha256)) failures.push(`INSTALLATION_CHANGED:${record.path}`);
  }
  if (!manifest.installation?.files?.length) failures.push('INSTALLATION_IDENTITY_MISSING');
  const calibration = read(path.join(manifest.baseline ?? directory, 'calibration.json'));
  if (!Number.isInteger(calibration.used) || calibration.used > 12 || calibration.used < 0 || calibration.maximum !== 12 || !calibration.per_model
    || Object.entries(calibration.per_model).some(([key, value]) => !['minicpm', 'lfm3', 'bonsai'].includes(key) || !Number.isInteger(value) || value > 4 || value < 0)
    || Object.values(calibration.per_model ?? {}).reduce((sum, value) => sum + value, 0) !== calibration.used) failures.push('CALIBRATION_LIMIT_UNVERIFIED');
  for (const row of report.rows.filter(row => row.skills_enabled)) {
    if (row.outcome !== 'passed') continue;
    const episode = episodes.find(item => item.row_id === row.id), evidence = episode.evidence, metrics = episode.metrics;
    if (!evidence?.before || !evidence.after || typeof evidence.task_root !== 'string' || !path.resolve(evidence.task_root).startsWith(path.resolve(directory, 'work') + path.sep)) { failures.push(`STATE_EVIDENCE_MISSING:${row.id}`); continue; }
    if (episode.candidate_installation_sha256 !== manifest.installation.sha256) failures.push(`INSTALLATION_BINDING_MISMATCH:${row.id}`);
    if (JSON.stringify(captureWorkspace(evidence.task_root)) !== JSON.stringify(evidence.after)) failures.push(`TASK_STATE_CHANGED:${row.id}`);
    if (!completedBudgetEvidence(metrics)) failures.push(`BUDGET_EVIDENCE_MISSING:${row.id}`);
    for (const key of ['inference', 'tools', 'ud_operations', 'output']) if (!Number.isSafeInteger(metrics?.counters?.[key]) || metrics.counters[key] < 0 || metrics.counters[key] > DEFAULT_LIMITS[key]) failures.push(`BUDGET_UNVERIFIED:${row.id}/${key}`);
    const requests = episode.events.filter(event => event.type === 'provider_request');
    const responses = episode.events.filter(event => event.type === 'model_visible_response');
    const observed = { inference: requests.length, input: requests.reduce((sum, event) => sum + event.tokens?.inputTokens, 0), output: responses.reduce((sum, event) => sum + event.outputTokens, 0),
      tools: responses.reduce((sum, event) => sum + event.toolCalls, 0), ud_operations: episode.events.filter(event => event.type === 'operation_start' || event.type === 'operation_step' && event.charge === true).length };
    for (const [key, value] of Object.entries(observed)) if (!Number.isSafeInteger(value) || value !== metrics?.counters?.[key]) failures.push(`BUDGET_CAPTURE_MISMATCH:${row.id}/${key}`);
    if (responses.some(event => !Number.isInteger(event.outputTokens) || event.outputTokens > 512) || observed.input > 6 * (row.scenario_id === 'S4' ? 32768 : 16384)) failures.push(`TOKEN_LIMIT_UNVERIFIED:${row.id}`);
    if (!episode.events.some(event => event.type === 'native_identity' && event.cleanupVerified === true)) failures.push(`NATIVE_CLEANUP_UNVERIFIED:${row.id}`);
    const projected = observeScenario(row.scenario_id, { events: episode.events, ...evidence, taskRoot: evidence.task_root, installation: manifest.installation_root, finalAnswer: episode.final_answer,
      contextEnvelope: row.scenario_id === 'S4' ? 32768 : 16384, outputReserve: 512, modelBinding: { publicModel: row.model_artifact, wireModel: manifest.preparation.models.find(item => item.id === row.model_id)?.directory } });
    const verdict = await gradeScenario(row.scenario_id, { before: evidence.before, after: evidence.after, finalAnswer: episode.final_answer, events: projected.events, observations: projected.observations, taskRoot: evidence.task_root });
    if (verdict.status !== 'passed' || projected.observations.complete !== true || projected.observations.model_attribution !== true) failures.push(`INDEPENDENT_REPLAY_FAILED:${row.id}`);
  }
  return { schema_version: 1, kind: 'verified-local-model-evidence', status: failures.length ? 'unmet' : 'passed', source_tree_sha256: manifest.product?.sha256, required_rows: 171, failures,
    predicates: { local_native_models: failures.length ? 'unmet' : 'passed', external_hosting: 'separate', release_certification: 'separate' } };
}
