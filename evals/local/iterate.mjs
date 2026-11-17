/** Short selected native workflow rounds. No inference on import. MIT. */
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, chmodSync, rmSync, realpathSync, lstatSync } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { scientificStudyStorage } from './study-storage.mjs';
import { assertOptIn, localPaths, readPreparation, writeNew } from './preparation.mjs';
import { frozenHashes, installSnapshot, runEpisode } from './campaign.mjs';
import { prepareCampaignSnapshot, verifyCampaignPreflight } from './campaign-preflight.mjs';
import { inspectHarnesses } from './native.mjs';
import { verifyNativeChatRoute } from './native-conformance.mjs';
import { MODELS, HARNESSES, buildMatrix, operationCoverage } from './registry.mjs';
import { admitModel } from './serving.mjs';
import { openCalibrationLedger } from './calibration.mjs';
import { SCENARIOS } from './scenarios.mjs';
import { buildIterationRows, createIterationSession, openIterationSession } from './iteration-state.mjs';
import { observeIterationEpisode } from './iteration-observations.mjs';
import { sampleResourceMemory, assertResourceMemory } from './resource-memory.mjs';
import { PROFILE, buildHeadlessRows, buildHeadlessCoverage, headlessReferenceRows } from './headless-profile.mjs';

const selectedRoutes = ['qwen-code', 'mini-swe-agent'];
const reference = file => ({ path: file, sha256: sha256(readFileSync(file)) });
const read = file => JSON.parse(readFileSync(file));
function safeDirectory(root, directory) {
  const base = path.join(localPaths(root).base, 'iterations');
  const result = path.resolve(directory ?? path.join(base, new Date().toISOString().replace(/[:.]/g, '-')));
  if (!result.startsWith(base + path.sep)) throw new Error('Iteration evidence must remain in repository-owned iterations storage.');
  return result;
}
function assertIdentities(root, store, preparation) {
  const hashes = frozenHashes(root, preparation);
  for (const [key, value] of Object.entries(hashes)) if (store.manifest.identities[key] !== value) throw new Error(`Frozen iteration input changed: ${key}`);
}
function verifyInstallation(directory, receipt) {
  if (sha256(JSON.stringify(receipt.files)) !== receipt.sha256) throw new Error('ITERATION_INSTALLATION_RECEIPT_CHANGED');
  const files = [];
  const visit = current => { for (const name of readdirSync(current).sort()) {
    const file = path.join(current, name), info = lstatSync(file), relative = path.relative(directory, file).split(path.sep).join('/');
    if (info.isSymbolicLink()) {
      const target = realpathSync(file); if (!target.startsWith(directory + path.sep)) throw new Error('ITERATION_INSTALLATION_LINK_ESCAPES');
      files.push({ path: relative, link_target: path.relative(directory, target) });
    } else if (info.isDirectory()) visit(file);
    else if (info.isFile()) files.push(fileReceipt(directory, relative));
    else throw new Error('ITERATION_INSTALLATION_SPECIAL_FILE');
  } };
  visit(directory);
  if (sha256(JSON.stringify(files)) !== receipt.sha256) throw new Error('ITERATION_INSTALLED_BYTES_CHANGED');
}
async function snapshot(root, directory, harnessIds, onProgress, signal, deadline) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const product = sourceReceipt(root);
  const result = await prepareCampaignSnapshot({ root, directory, product, install: installSnapshot, ...(harnessIds.length === 11 ? { inspect: root => inspectHarnesses(root, { includeDesktops: false }) } : {}), harnessIds, onProgress, signal, ...(deadline ? { deadline } : {}) });
  verifyCampaignPreflight(root, result.mechanicalPreflight, product.sha256);
  return { product, ...result, installation: { ...result.installation, root: result.installationRoot, mechanical_preflight: result.mechanicalPreflight } };
}
export async function prepareIteration(root, { directory, profile, optIn, onProgress = () => {} } = {}) {
  assertOptIn({ optIn }); directory = safeDirectory(root, directory);
  if (existsSync(directory)) throw new Error('Iteration preparation requires a new directory.');
  const lease = scientificStudyStorage(root, 'iterate');
  try {
    const preparation = readPreparation(root);
    const store = createIterationSession({ root, directory, optIn: true, profile, identities: frozenHashes(root, preparation) });
    const routes = profile === PROFILE ? HARNESSES.filter(row => row.execution_location === 'arm64-container').map(row => row.id) : selectedRoutes;
    const prepared = await snapshot(root, path.join(directory, 'prepared'), routes, onProgress);
    writeNew(path.join(directory, 'prepared.json'), prepared);
    writeNew(path.join(directory, 'coverage.json'), { qualification_evidence: false, required_rows: profile === PROFILE ? buildHeadlessCoverage() : buildMatrix(), ...(profile === PROFILE ? { reference_rows: headlessReferenceRows() } : {}), harnesses: HARNESSES, operations: operationCoverage(root) });
    return { directory, manifest_sha256: store.manifest_sha256, clock_started: false, selected_routes: routes, installation_sha256: prepared.installation.sha256 };
  } finally { await lease.cleanup(); }
}

// Receipt reuse is still validated by admitModel against exact current settings,
// model revision, runtime, processor route and protocol closure before generation.
function priorAdmission(root, directory, modelId) {
  const local = path.join(directory, 'admissions');
  for (const base of [local, path.join(localPaths(root).campaigns, '20261112-native-repair-baseline')]) {
    if (!existsSync(base)) continue;
    const files = base === local ? readdirSync(base).filter(name => name.startsWith(modelId + '-') && name.endsWith('.json')).reverse() : [`admission-${modelId}.json`];
    for (const name of files) {
      const file = path.join(base, name); if (!existsSync(file)) continue;
      const value = read(file); if (value.status === 'admitted' && value.admission_kind === 'mechanical') return value;
    }
  }
}
function cellKey(row) { return `${row.model_id}/${row.harness_id}/${row.scenario_id}`; }
export function forecastIterationCell(rows, episodes = [], profile) {
  const measured = episodes.map(row => row.metrics?.total_elapsed_ms).filter(value => Number.isFinite(value) && value > 0);
  // Include fixture setup, accounting and grading; never forecast only inference.
  const perEpisode = Math.max(profile === PROFILE ? 181_000 : 150_000, ...measured);
  return { rows: rows.length, per_episode_ms: perEpisode, duration_ms: rows.length * perEpisode + 60_000, basis: measured.length ? 'measured-total-with-conservative-floor' : profile === PROFILE ? '181-second-setup-conversation-cancellation-verification-accounting' : '150-second-total-plus-cell-overhead' };
}
async function sessionLock(directory, callback) {
  const lock = path.join(directory, 'execution.lock');
  try { mkdirSync(lock, { mode: 0o700 }); } catch { throw new Error('ITERATION_EXECUTION_LOCKED: reconcile the owned prior process before resuming.'); }
  writeNew(path.join(lock, 'owner.json'), { pid: process.pid, started_at: Date.now() });
  try { return await callback(); } finally { rmSync(lock, { recursive: true }); }
}
export async function runIteration(root, { directory, optIn, kind = 'baseline', repairEvidence, onProgress = () => {} } = {}) {
  assertOptIn({ optIn }); directory = safeDirectory(root, directory);
  return sessionLock(directory, async () => {
    const store = openIterationSession({ root, directory, optIn: true });
    const preparation = readPreparation(root); assertIdentities(root, store, preparation);
    const profile = store.manifest.profile, policy = store.manifest.policy;
    const routes = profile === PROFILE ? HARNESSES.filter(row => row.execution_location === 'arm64-container').map(row => row.id) : selectedRoutes;
    const forecast = (rows, measurements = []) => forecastIterationCell(rows, measurements, profile);
    const observeResources = profile === PROFILE ? async ({ processes, stage, signal }) => {
      const memory = await sampleResourceMemory({ processes, signal });
      writeNew(path.join(directory, 'resources', `${stage}-${randomUUID()}.json`), memory);
      assertResourceMemory(memory);
    } : undefined;
    let currentModel, admissionPending, activeEpisode, lease;
    const controller = new AbortController();
    const cancel = () => controller.abort(new Error('ITERATION_OPERATOR_CANCELLED'));
    const stopOwned = async () => {
      cancel();
      const model = currentModel ?? await admissionPending;
      const release = await model?.stop?.();
      const episode = await activeEpisode;
      if (model?.status === 'admitted' && release?.cleanupVerified !== true || model?.cleanup?.cleanupVerified === false || episode && episode.owned_cleanup_verified !== true) throw new Error('ITERATION_OWNED_RELEASE_UNVERIFIED');
      return release;
    };
    process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
    const episodes = store.report().rounds.flatMap(item => item.rows).map(item => ({ metrics: { total_elapsed_ms: item.elapsed_ms } }));
    try {
      lease = scientificStudyStorage(root, kind.includes('transfer') ? 'iterate-transfer' : 'iterate', { onCancel: stopOwned });
      lease.watch(root);
      let round = store.rounds.find(item => item.kind === kind && item.finished_at === null);
      let prepared;
      if (round) {
        prepared = read(path.join(directory, 'snapshots', round.id + '.json'));
        if (sourceReceipt(root).sha256 !== prepared.product.sha256) throw new Error('ITERATION_PRODUCT_CHANGED_DURING_ROUND');
      } else {
        const product = sourceReceipt(root);
        const initial = read(path.join(directory, 'prepared.json'));
        const retainedId = store.report().retained_product_round;
        const parent = retainedId ? store.round(retainedId) : store.rounds.filter(item => ['baseline', 'repair'].includes(item.kind)).at(-1);
        if (kind === 'repair') {
          const report = store.report(), measurements = report.rounds.flatMap(item => item.rows).map(item => ({ metrics: { total_elapsed_ms: item.elapsed_ms } }));
          const required = buildIterationRows({ kind, profile });
          if (profile === PROFILE) required.push(...buildHeadlessRows({ kind: 'transfer' }));
          const checksMs = profile === PROFILE ? 30 * 60_000 : 120_000;
          if (profile === PROFILE && Date.now() >= parent.finished_at + checksMs) throw new Error('The diagnosis and repair allocation expired.');
          if (Date.now() + forecast(required, measurements).duration_ms + checksMs + (profile === PROFILE ? 6 * 150_000 : 0) >= report.execution_deadline) throw new Error('A complete matched repair panel, breadth and checks cannot fit the persisted deadline.');
        }
        if (kind.includes('transfer')) prepared = read(path.join(directory, 'snapshots', parent.id + '.json'));
        else if (kind === 'baseline' && product.sha256 === initial.product.sha256) prepared = initial;
        else prepared = await snapshot(root, path.join(directory, 'snapshots', randomUUID()), kind === 'claude-transfer' ? ['claude-code'] : routes, onProgress, controller.signal, profile === PROFILE && kind === 'repair' ? Math.min(parent.finished_at + 30 * 60_000, store.report().execution_deadline) : undefined);
        if (sourceReceipt(root).sha256 !== prepared.product.sha256) throw new Error('ITERATION_PRODUCT_CHANGED_DURING_TRANSFER');
        if (kind === 'claude-transfer') {
          const inventory = await inspectHarnesses(root), harness = inventory.find(item => item.id === 'claude-code');
          await verifyNativeChatRoute(root, harness, { optIn: true, installation: prepared.installationRoot, onProgress, signal: controller.signal });
          prepared = { ...prepared, harnesses: await inspectHarnesses(root) };
        }
        const evidence = typeof repairEvidence === 'string' ? read(repairEvidence) : repairEvidence;
        const roundId = kind === 'repair' ? `repair-${store.rounds.filter(item => item.kind === 'repair').length + 1}` : kind;
        const snapshotFile = path.join(directory, 'snapshots', roundId + '.json');
        if (existsSync(snapshotFile)) {
          if (sha256(JSON.stringify(read(snapshotFile))) !== sha256(JSON.stringify(prepared))) throw new Error('Orphaned round snapshot differs; reconcile before freezing.');
        } else writeNew(snapshotFile, prepared);
        round = store.freezeRound({ kind, product: prepared.product, installation: prepared.installation, parentRound: parent?.id, repairEvidence: evidence });
      }
      const rows = round.rows;
      if (sha256(JSON.stringify(round.product)) !== sha256(JSON.stringify(prepared.product)) || sha256(JSON.stringify(round.installation)) !== sha256(JSON.stringify(prepared.installation))) throw new Error('ITERATION_ROUND_SNAPSHOT_CHANGED');
      if (prepared.installationRoot !== prepared.installation.root || JSON.stringify(prepared.mechanicalPreflight) !== JSON.stringify(prepared.installation.mechanical_preflight)) throw new Error('ITERATION_INSTALLATION_ROUTE_CHANGED');
      verifyCampaignPreflight(root, prepared.mechanicalPreflight, prepared.product.sha256);
      verifyInstallation(prepared.installationRoot, prepared.installation);
      const calibration = openCalibrationLedger(path.join(directory, 'calibration.json'));
      const charged = calibration.onCharge.bind(calibration);
      calibration.onCharge = () => { charged(); store.chargeCalibration(calibration.activeModel, `calibration-${calibration.used}`); };
      const recorded = () => store.snapshot().episodes ?? store.snapshot().rows ?? {};
      const allRecorded = row => {
        const state = recorded(); return state[`${round.id}/${row.row_id}`]?.status === 'recorded' || state[row.row_id]?.status === 'recorded';
      };
      for (const modelId of [...new Set(rows.map(row => row.model_id))]) {
        const pending = rows.filter(row => row.model_id === modelId && !allRecorded(row));
        if (!pending.length) continue;
        if (Date.now() + forecast(pending, episodes).duration_ms >= (store.report().execution_deadline ?? Infinity)) { onProgress(`Unfinished: complete ${modelId} block cannot fit the fixed deadline.`); break; }
        assertIdentities(root, store, preparation);
        if (sourceReceipt(root).sha256 !== prepared.product.sha256) throw new Error('ITERATION_PRODUCT_CHANGED_DURING_ROUND');
        if (profile === PROFILE) {
          const memory = await sampleResourceMemory({ signal: controller.signal });
          writeNew(path.join(directory, 'resources', `${modelId}-${randomUUID()}-before.json`), memory);
          assertResourceMemory(memory);
        }
        store.beginAdmission({ modelId, optIn: true });
        calibration.selectModel(modelId); calibration.activeModel = modelId;
        const model = preparation.models.find(item => item.id === modelId);
        const deadline = store.report().execution_deadline;
        currentModel = await (admissionPending = admitModel(root, model, preparation.runtimes.find(item => item.id === model?.runtime_id), { deadline, calibration, onProgress, observeResources, signal: controller.signal,
          reuseAdmission: priorAdmission(root, directory, modelId), translationRuntime: preparation.runtimes.find(item => item.id === 'mlx') }));
        admissionPending = undefined;
        let admissionFile = path.join(directory, 'admissions', `${modelId}-${randomUUID()}.json`);
        if (profile === PROFILE && currentModel.status === 'admitted') {
          const memory = await sampleResourceMemory({ processes: currentModel.ownedProcesses?.() ?? [], signal: controller.signal });
          writeNew(path.join(directory, 'resources', `${modelId}-${randomUUID()}-loaded.json`), memory);
          if (memory.guard !== 'admitted') {
            const cleanup = await currentModel.stop('resource-memory-blocked');
            if (cleanup?.cleanupVerified !== true) throw new Error('ITERATION_RESOURCE_MEMORY_RELEASE_UNVERIFIED');
            currentModel = { ...currentModel, status: 'model_blocked', reason: `RESOURCE_MEMORY_BLOCKED:${memory.guard}`, cleanup };
          }
        }
        writeNew(admissionFile, JSON.parse(JSON.stringify(currentModel))); store.recordAdmission(modelId, reference(admissionFile));
        let stopped = false;
        const wrapStop = () => { const stop = currentModel.stop?.bind(currentModel); if (stop) currentModel.stop = async (...args) => { stopped = true; return stop(...args); }; };
        wrapStop();
        const releaseCurrentModel = async () => {
          if (!currentModel) return;
          const cleanup = await currentModel.stop?.();
          const verified = currentModel.status === 'admitted' ? cleanup?.cleanupVerified === true : currentModel.cleanup?.cleanupVerified === true;
          const releaseFile = path.join(directory, 'releases', `${modelId}-${randomUUID()}.json`);
          const admissionLog = currentModel.evidence_directory && path.join(currentModel.evidence_directory, 'admission.jsonl');
          writeNew(releaseFile, { kind: 'iteration-owned-model-release', model_id: modelId, owned_cleanup_verified: verified, cleanup: cleanup ?? currentModel.cleanup ?? null,
            ...(admissionLog && existsSync(admissionLog) ? { admission_evidence: reference(admissionLog) } : {}) });
          store.releaseModel(modelId, { ...reference(releaseFile), owned_cleanup_verified: verified }); currentModel = undefined;
        };
        try {
          // Seed-major scheduling retains a model across all its selected cells.
          for (const row of pending) {
            const cellRemaining = pending.filter(item => cellKey(item) === cellKey(row) && !allRecorded(item));
            const remainingThroughAllSeeds = pending.filter(item => !allRecorded(item));
            const estimate = forecast(remainingThroughAllSeeds, episodes);
            if (Date.now() + estimate.duration_ms >= deadline) { onProgress(`Unfinished cell ${cellKey(row)}: ${JSON.stringify(estimate)}`); break; }
            await lease.check(); assertIdentities(root, store, preparation);
            if (sourceReceipt(root).sha256 !== prepared.product.sha256) throw new Error('ITERATION_PRODUCT_CHANGED_DURING_ROUND');
            if (stopped && currentModel.status === 'admitted') {
              const previousAdmission = read(admissionFile);
              await releaseCurrentModel(); store.beginAdmission({ modelId, optIn: true });
              currentModel = await (admissionPending = admitModel(root, model, preparation.runtimes.find(item => item.id === model.runtime_id), { deadline, calibration, onProgress, observeResources, signal: controller.signal, reuseAdmission: previousAdmission, translationRuntime: preparation.runtimes.find(item => item.id === 'mlx') })); admissionPending = undefined; stopped = false; wrapStop();
              admissionFile = path.join(directory, 'admissions', `${modelId}-${randomUUID()}.json`);
              writeNew(admissionFile, JSON.parse(JSON.stringify(currentModel))); store.recordAdmission(modelId, reference(admissionFile));
            }
            const harness = prepared.harnesses.find(item => item.id === row.harness_id);
            store.claimEpisode(round.id, row.row_id);
            let result = currentModel.status !== 'admitted' ? { ...row, outcome: currentModel.status === 'context_resource_blocked' ? 'context_resource_blocked' : 'model_blocked', reason: currentModel.reason, owned_cleanup_verified: currentModel.cleanup?.cleanupVerified === true, candidate_installation_sha256: prepared.installation.sha256 }
              : harness?.status !== 'mechanically-admitted' ? { ...row, outcome: 'interface_unsupported', reason: harness?.reason ?? 'Selected native route is unavailable.', owned_cleanup_verified: true, candidate_installation_sha256: prepared.installation.sha256 }
                : await (activeEpisode = runEpisode(root, { profile, deadline: store.report().deadline, phase_allocations_ms: { reconciliation: policy.reconciliation_ms }, installation: prepared.installation, signal: controller.signal }, row, currentModel, harness, prepared.installationRoot, path.join(directory, 'work', round.id, sha256(row.row_id).slice(0, 16))));
            activeEpisode = undefined;
            result.intent = SCENARIOS.find(item => item.id === row.scenario_id)?.prompt;
            if (result.outcome !== 'passed' && !result.reason?.trim()) result.reason = 'Native episode returned no failure explanation; cause remains unknown.';
            result = observeIterationEpisode(root, prepared.installationRoot, row, result);
            const file = path.join(directory, 'episodes', round.id, sha256(row.row_id) + '.json'); writeNew(file, result); chmodSync(file, 0o400);
            store.recordEpisode(round.id, row.row_id, reference(file)); episodes.push(result);
            onProgress(`${round.id} ${cellKey(row)}/seed-${row.seed}: ${result.outcome}; UD=${result.metrics?.counters?.ud_operations ?? 'unknown'}`);
            if (cellRemaining.length === 1) onProgress(`Cell complete: ${cellKey(row)}; report=${JSON.stringify(store.report().counts)}`);
            if (result.owned_cleanup_verified !== true) throw new Error('ITERATION_EPISODE_RELEASE_UNVERIFIED');
            controller.signal.throwIfAborted();
          }
        } finally { await releaseCurrentModel(); }
      }
      if (rows.every(allRecorded)) store.finishRound(round.id);
      const report = store.report();
      const output = await reportIteration(root, { directory, output: path.join(directory, 'reports', randomUUID()) });
      return { directory, round: round.id, ...output, counts: report.counts, qualification_evidence: false };
    } finally {
      const cleanup = await currentModel?.stop?.();
      if (currentModel?.status === 'admitted' && cleanup?.cleanupVerified !== true || currentModel?.cleanup?.cleanupVerified === false) throw new Error('ITERATION_FINAL_MODEL_RELEASE_UNVERIFIED');
      await lease?.cleanup();
      process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
    }
  });
}
export async function reportIteration(root, { directory, output, requireHeadlessQualified = false } = {}) {
  directory = safeDirectory(root, directory);
  const session = openIterationSession({ root, directory });
  let report = session.report();
  if (session.manifest.profile === PROFILE && report.final_headless_qualification === true) {
    const { verifyHeadlessEvidence } = await import('./headless-qualification.mjs');
    const verification = await verifyHeadlessEvidence(root, directory, report);
    const qualified = verification.status === 'passed';
    report = { ...report, status: qualified ? report.status : 'incomplete', final_headless_qualification: qualified,
      headless_qualification: { ...report.headless_qualification, status: qualified ? 'passed' : 'unmet', verification } };
  }
  if (requireHeadlessQualified && session.manifest.profile !== PROFILE) throw new Error('Headless qualification requires a headless-12h-v2 session.');
  if (existsSync(output)) throw new Error('Iteration report requires a new output directory.');
  mkdirSync(output, { recursive: true, mode: 0o700 });
  writeNew(path.join(output, 'report.json'), report);
  if (session.manifest.profile === PROFILE) writeHeadlessEvidence(output, report);
  const lines = ['# Selected UD workflow iteration', '', 'Selected diagnostic coverage; full 171-row qualification remains unmet.', '',
    `Recorded: ${report.counts.recorded}/${report.counts.scheduled}; verified completions: ${report.counts.passed}; unfinished: ${report.counts.unfinished}.`,
    `Deadline: ${report.deadline ? new Date(report.deadline).toISOString() : 'not started'}. Retained product round: ${report.retained_product_round ?? 'none'}.`, '',
    '| Round | Model / harness / scenario | Seed | Outcome | UD ops | Requests | Calls | Input / output tokens | First observed failure |',
    '|---|---|---:|---|---:|---:|---:|---|---|'];
  for (const round of report.rounds) for (const row of round.rows) {
    const c = row.counters ?? {}, known = value => value ?? 'unknown';
    lines.push(`| ${round.id} | ${row.model_id} / ${row.harness_id} / ${row.scenario_id} | ${row.seed} | ${row.outcome} | ${known(c.ud_operations)} | ${known(c.inference)} | ${known(c.tools)} | ${known(c.input)} / ${known(c.output)} | ${row.first_failure?.stage ?? row.first_failure?.status ?? 'unknown'} |`);
    if (row.seed === 17 && row.episode?.path && row.evidence_verified) {
      const episode = read(row.episode.path), trace = [`# ${round.id}: ${row.model_id}/${row.harness_id}/${row.scenario_id}/seed-17`, '',
        `Outcome: ${row.outcome}. Verified workflow: ${row.outcome === 'passed'}.`, '', '## User request', '', episode.intent ?? '', '', '## Actual tool calls', ''];
      for (const event of episode.events ?? []) if (event.type === 'native_calls_admitted') for (const call of event.calls ?? []) trace.push('```json', JSON.stringify(call, null, 2), '```', '');
      trace.push('## Final answer', '', episode.final_answer ?? '(No final answer observed.)', '', '## Independent verification', '', '```json', JSON.stringify(episode.verification ?? null, null, 2), '```', '');
      const traceName = `${round.id}-${row.model_id}-${row.harness_id}-${row.scenario_id}-seed-17.md`;
      writeFileSync(path.join(output, traceName), trace.join('\n'));
    }
  }
  lines.push('', '## Paired changes', '', '```json', JSON.stringify(report.paired, null, 2), '```', '', '## Evidence verification', '', '```json', JSON.stringify(report.evidence_verification, null, 2), '```', '');
  writeFileSync(path.join(output, 'report.md'), lines.join('\n'));
  if (requireHeadlessQualified && report.final_headless_qualification !== true) process.exitCode = 1;
  return { ...(session.manifest.profile === PROFILE ? { headless_qualification: report.headless_qualification, final_headless_qualification: report.final_headless_qualification } : {}), report: path.join(output, 'report.json'), readable_report: path.join(output, 'report.md'), status: report.status, counts: report.counts, qualification_evidence: false };
}

/** Deterministic reference selection includes failed and unstarted cases. */
function writeHeadlessEvidence(output, report) {
  const rows = report.rounds.flatMap(round => round.rows.map(row => ({ ...row, round_id: round.id })));
  const references = headlessReferenceRows();
  const ledger = rows.filter(row => row.outcome !== 'passed').map(row => ({ row_id: row.row_id, outcome: row.outcome, first_failure: row.first_failure, reason: row.reason, evidence: row.episode }));
  writeNew(path.join(output, 'failure-ledger.json'), ledger);
  writeNew(path.join(output, 'context-and-resources.json'), rows.map(row => {
    const episode = row.evidence_verified && row.episode?.path ? read(row.episode.path) : null;
    return { row_id: row.row_id, model: row.model_id, harness: row.harness_id, counters: row.counters, elapsed_ms: row.elapsed_ms,
      context: episode?.metrics?.context ?? null, resources: episode?.metrics?.resources ?? null };
  }));
  for (const selected of references) {
    const row = rows.find(row => row.cell_id === selected.cell_id && row.round_id === 'baseline');
    const episode = row?.evidence_verified && row.episode?.path ? read(row.episode.path) : null;
    const trace = [`# ${selected.scenario_id}: ${selected.model_id}/${selected.harness_id}`, '',
      `Predetermined reference: ${selected.cell_id}`, `Outcome: ${row?.outcome ?? 'not_run'}`, '',
      '## User intent', '', episode?.intent ?? SCENARIOS.find(item => item.id === selected.scenario_id)?.prompt ?? '', '',
      '## Captured native trajectory', '', '```json', JSON.stringify(episode?.events ?? null, null, 2), '```', '',
      '## Final answer', '', episode?.final_answer ?? '(No final answer observed.)', '',
      '## Independent verdict and resources', '', '```json', JSON.stringify({ verification: episode?.verification ?? null, metrics: episode?.metrics ?? null, cleanup: episode?.owned_cleanup_verified ?? null }, null, 2), '```'];
    writeFileSync(path.join(output, `reference-${selected.scenario_id}.md`), trace.join('\n'));
  }
}
