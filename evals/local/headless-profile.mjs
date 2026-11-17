// SPDX-License-Identifier: MIT
/** Frozen native headless coverage. Importing this module performs no inference. */
import { DEFAULT_LIMITS } from './budget.mjs';
import { HARNESSES, MODELS, SEEDS } from './registry.mjs';

const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
export const PROFILE = 'headless-12h-v2';
export const CORE_ROUTES = freeze({ S1: 'gemini-cli', S2: 'qwen-code', S3: 'mini-swe-agent', S4: 'pi', S5: 'codex-cli', S6: 'kimi-code', S7: 'qwen-code' });
export const HEADLESS_HARNESS_IDS = freeze(HARNESSES.filter(host => host.execution_location === 'arm64-container').map(host => host.id));
export const HEADLESS_POLICY = freeze({ duration_ms: 720 * 60_000, reconciliation_ms: 45 * 60_000, diagnosis_ms: 30 * 60_000,
  admission_ms: 30 * 60_000, maximum_scored_episodes: 189, maximum_repair_rounds: 1, calibration_limit: 12, calibration_per_model: 4,
  maximum_inference_requests: 1890, maximum_total_inference_requests: 1902, maximum_generated_tokens: 189 * 2048,
  forecast_episode_ms: 181_000, seeds: SEEDS,
  episode: { ...DEFAULT_LIMITS, input_envelope: 16384, extended_input_envelope: 32768, cumulative_input: 6 * 16384, native_setup_ms: 60_000 },
  qualification_evidence: false, qualification_scope: 'retained-product-headless-assigned-workflows' });

function row(kind, roundId, model, seed, harness, scenario, skillsEnabled = true) {
  const cell = `${model.id}/${harness}/${scenario}/seed-${seed}/${skillsEnabled ? 'skills' : 'skills-disabled'}`, id = `${roundId}/${cell}`;
  const context = scenario === 'S4' ? 32768 : 16384;
  return { id, row_id: id, cell_id: cell, round_id: roundId, snapshot: kind === 'baseline' ? 'baseline' : 'candidate',
    model_id: model.id, model_artifact: model.artifact, harness_id: harness, scenario_id: scenario, seed, skills_enabled: skillsEnabled,
    kind: skillsEnabled ? 'iteration-native' : 'skill-disabled-control', diagnostic_only: true,
    context_envelope: context, cumulative_input: 6 * context };
}

export function buildHeadlessRows({ kind = 'baseline', roundId = kind } = {}) {
  if (!['baseline', 'repair', 'transfer'].includes(kind)) throw new Error('Unknown headless iteration round kind.');
  if (typeof roundId !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(roundId)) throw new Error('Invalid headless round identity.');
  const rows = [];
  for (const [modelIndex, model] of MODELS.entries()) for (const [seedIndex, seed] of SEEDS.entries()) {
    if (kind === 'transfer') {
      for (const host of HARNESSES.filter(host => HEADLESS_HARNESS_IDS.includes(host.id))) {
        if (CORE_ROUTES[host.scenario_id] !== host.id) rows.push(row(kind, roundId, model, seed, host.id, host.scenario_id));
      }
    } else for (const [scenario, harness] of Object.entries(CORE_ROUTES)) {
      // Alternate the adjacent enabled/control order across model/seed blocks.
      // Nine pairs cannot be split exactly equally; the frozen split is 5/4.
      const control = kind === 'baseline' && scenario === 'S3';
      const controlFirst = (modelIndex + seedIndex) % 2 === 0;
      if (control && controlFirst) rows.push(row(kind, roundId, model, seed, harness, scenario, false));
      rows.push(row(kind, roundId, model, seed, harness, scenario));
      if (control && !controlFirst) rows.push(row(kind, roundId, model, seed, harness, scenario, false));
    }
  }
  return rows;
}

/** Required final cells, independent of whether the optional repair is admitted. */
export function buildHeadlessCoverage() {
  return [...buildHeadlessRows().filter(row => row.skills_enabled), ...buildHeadlessRows({ kind: 'transfer' })];
}

export function headlessReferenceRows() {
  const baseline = buildHeadlessRows();
  return Object.keys(CORE_ROUTES).map((scenario, index) => baseline.find(row => row.skills_enabled && row.scenario_id === scenario
    && row.model_id === MODELS[index % MODELS.length].id && row.seed === SEEDS[0]));
}

/** Assemble only the retained core and its unpaired breadth on identical bytes. */
export function headlessQualification(manifest, rounds, retainedId, { evidenceValid = true, released = true } = {}) {
  const core = rounds.find(round => round.id === retainedId && ['baseline', 'repair'].includes(round.kind));
  const transfer = rounds.find(round => round.kind === 'transfer');
  const sameProduct = !!core && !!transfer && transfer.parent_round === core.id
    && transfer.product.sha256 === core.product.sha256 && transfer.installation.sha256 === core.installation.sha256;
  const observed = [...(core?.rows.filter(row => row.skills_enabled) ?? []), ...(sameProduct ? transfer.rows : [])];
  const required = manifest.coverage_rows ?? buildHeadlessCoverage(), indexed = new Map(), duplicates = [];
  for (const row of observed) { if (indexed.has(row.cell_id)) duplicates.push(row.cell_id); indexed.set(row.cell_id, row); }
  const rows = required.map(expected => {
    const actual = indexed.get(expected.cell_id);
    return actual ?? { ...expected, outcome: 'not_run', status: 'unattempted', evidence_verified: false, reason: 'Required retained-product coverage has no verified episode.' };
  });
  const missing = rows.filter(row => !row.evidence_verified || row.status !== 'recorded').map(row => row.cell_id);
  const failed = rows.filter(row => row.outcome !== 'passed').map(row => row.cell_id);
  const groups = new Map();
  for (const row of rows) {
    const key = `${row.model_id}/${row.harness_id}/${row.scenario_id}`, selected = groups.get(key) ?? [];
    selected.push(row); groups.set(key, selected);
  }
  const qualifications = [...groups].map(([cell, selected]) => ({ cell, qualified: SEEDS.every(seed => selected.some(row => row.seed === seed && row.evidence_verified && row.outcome === 'passed')) }));
  const complete = required.length === 117 && indexed.size === 117 && !duplicates.length && !missing.length && sameProduct
    && core.finished_at !== null && transfer.finished_at !== null;
  const passed = complete && !failed.length && qualifications.every(row => row.qualified) && evidenceValid && released;
  return { status: passed ? 'passed' : 'unmet', scope: 'retained-product-headless-assigned-workflows', required_rows: 117,
    coverage_complete: complete, retained_product_round: core?.id ?? null, product_sha256: core?.product.sha256 ?? null,
    installation_sha256: core?.installation.sha256 ?? null, transfer_paired: false, rows, missing_cells: missing,
    failed_cells: failed, duplicate_cells: duplicates, qualifications, evidence_valid: evidenceValid, owned_release_verified: released,
    full_starter_qualification: false, desktop_qualification: false };
}
