/** Descriptive paired analysis of frozen diagnostic evidence. No inference. MIT. */
import path from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { writeNew } from './preparation.mjs';
import { readObservation } from './study-observation.mjs';
import { STUDY_STAGES } from './study.mjs';
const finite = value => typeof value === 'number' && Number.isFinite(value);
const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
const dimensions = row => ({ model: row.model_id, harness: row.harness_id, intent: row.scenario_id });
const groupKey = row => `${row.kind}/${row.model_id}/${row.harness_id}/${row.scenario_id}/${row.condition}`;
function summary(values) { const numbers = values.filter(finite); return { observed: numbers.length, missing: values.length - numbers.length,
  minimum: numbers.length ? Math.min(...numbers) : null, maximum: numbers.length ? Math.max(...numbers) : null,
  mean: numbers.length ? numbers.reduce((a, b) => a + b, 0) / numbers.length : null }; }
function ranks(values) {
  const order = values.map((value, index) => ({ value, index })).sort((a, b) => a.value - b.value), output = [];
  for (let start = 0; start < order.length;) { let end = start + 1; while (end < order.length && order[end].value === order[start].value) end++;
    for (let index = start; index < end; index++) output[order[index].index] = (start + end - 1) / 2; start = end; }
  return output;
}
export function spearman(pairs, minimum = 6) {
  const known = pairs.filter(([a, b]) => finite(a) && finite(b));
  if (known.length < minimum) return { status: 'undefined', reason: 'insufficient_observational_blocks', n: known.length, minimum, rho: null };
  const x = ranks(known.map(pair => pair[0])), y = ranks(known.map(pair => pair[1]));
  const avg = values => values.reduce((a, b) => a + b, 0) / values.length, mx = avg(x), my = avg(y);
  let xx = 0, yy = 0, xy = 0;
  x.forEach((value, index) => { xx += (value - mx) ** 2; yy += (y[index] - my) ** 2; xy += (value - mx) * (y[index] - my); });
  if (xx === 0 || yy === 0) return { status: 'undefined', reason: 'constant_variable', n: known.length, minimum, rho: null };
  return { status: 'exploratory', n: known.length, minimum, rho: xy / Math.sqrt(xx * yy),
    limitation: 'Fixed tasks and harness/intent differences remain confounded; heads and layers are not independent samples.' };
}
export function pairedBinary(pairs) {
  const known = pairs.filter(([a, b]) => typeof a === 'boolean' && typeof b === 'boolean');
  const wins = known.filter(([a, b]) => !a && b).length, losses = known.filter(([a, b]) => a && !b).length, discordant = wins + losses;
  let probability = null;
  if (discordant) { const tail = Math.min(wins, losses); let combinations = 1, sum = 1;
    for (let index = 1; index <= tail; index++) { combinations *= (discordant - index + 1) / index; sum += combinations; }
    probability = Math.min(1, 2 * sum / 2 ** discordant); }
  return { complete_pairs: known.length, unknown_pairs: pairs.length - known.length, wins, losses, ties: known.length - discordant, discordant_pairs: discordant,
    mean_paired_difference: known.length ? (wins - losses) / known.length : null,
    exact_sign_under_exchangeability: probability,
    interpretation: 'Descriptive only. Independent/exchangeable signs are not established for repeated seeds of fixed tasks; no task-population inference.' };
}
function defaultArtifact(item, directory) {
  const selected = path.isAbsolute(item.path) ? item.path : path.resolve(directory, item.path);
  return readObservation({ ...item, path: selected });
}
function signature(artifact) {
  const calls = artifact?.events?.filter(event => event.type === 'native_calls_admitted').flatMap(event => event.calls ?? []);
  if (!calls) return null;
  return sha256(canonical(calls.map(call => ({ name: call.name, arguments: call.arguments }))));
}
export function analyzeStudy(report, { studyDirectory = process.cwd(), readArtifact = item => defaultArtifact(item, studyDirectory) } = {}) {
  const errors = [], artifacts = new Map();
  const rows = (report.rows ?? []).map(row => {
    let evidenceValid = row.status === 'recorded' && row.evidence_status === 'verified';
    if (evidenceValid && row.result?.evidence?.length) try { artifacts.set(row.id, readArtifact(row.result.evidence[0])); }
    catch (error) { evidenceValid = false; errors.push({ row_id: row.id, reason: error.message }); }
    return { ...row, analysis_evidence_valid: evidenceValid };
  });
  const observed = row => row.analysis_evidence_valid && Boolean(row.result?.evidence?.length);
  const stage = (row, name) => observed(row) && typeof row.result?.stages?.[name] === 'boolean' ? row.result.stages[name] : null;
  const groups = [];
  for (const key of new Set(rows.map(groupKey))) {
    const selected = rows.filter(row => groupKey(row) === key), first = selected[0];
    const metric = getter => summary(selected.map(row => observed(row) ? getter(row, artifacts.get(row.id)) : null));
    groups.push({ ...dimensions(first), kind: first.kind, condition: first.condition, required_rows: selected.length,
      recorded: selected.filter(row => row.status === 'recorded').length, observed: selected.filter(observed).length,
      seeds: selected.map(row => row.seed),
      stages: Object.fromEntries(STUDY_STAGES.map(name => [name, { true: selected.filter(row => stage(row, name) === true).length,
        false: selected.filter(row => stage(row, name) === false).length, unknown: selected.filter(row => stage(row, name) === null).length }])),
      metrics: {
        inference_requests: metric(row => row.result?.counters?.inference), visible_calls: metric(row => row.result?.counters?.tools), ud_operations: metric(row => row.result?.counters?.ud_operations),
        backend_known_generated_tokens: metric((row, artifact) => (row.result?.backend_generation ?? artifact?.metrics?.backend_generation)?.known_generated_tokens),
        backend_fully_observed_generated_tokens: metric((row, artifact) => (row.result?.backend_generation ?? artifact?.metrics?.backend_generation)?.generated_tokens),
        backend_parser_rejections: metric((row, artifact) => (row.result?.backend_generation ?? artifact?.metrics?.backend_generation)?.parser_rejections),
        repeated_exact_calls: metric(row => row.result?.native_observation?.repeated_exact_call_count), generated_tokens: metric(row => row.result?.counters?.output), cumulative_input_tokens: metric(row => row.result?.counters?.input),
        elapsed_ms: metric((row, artifact) => row.result?.elapsed_ms ?? artifact?.metrics?.elapsed_ms ?? artifact?.response?.elapsed_ms),
        peak_context_tokens: metric((_row, artifact) => {
          const values = artifact?.events?.filter(event => event.type === 'token_accounting').map(event => event.tokens?.contextTokens ?? event.tokens?.inputTokens).filter(finite) ?? [];
          return values.length ? Math.max(...values) : null;
        }),
      } });
  }
  const contrasts = [];
  for (const first of rows.filter(row => row.condition === ({ probe: 'unchanged', native: 'current', forward: 'reference-forward' })[row.kind])) {
    const peers = rows.filter(row => row.kind === first.kind && row.block === first.block && row.condition !== first.condition);
    for (const peer of peers) {
      let group = contrasts.find(item => item.kind === first.kind && item.model === first.model_id && item.harness === first.harness_id && item.intent === first.scenario_id && item.condition === peer.condition);
      if (!group) { group = { ...dimensions(first), kind: first.kind, condition: peer.condition, seed_pairs: [], stages: {} }; contrasts.push(group); }
      group.seed_pairs.push({ seed: first.seed, base_row: first.id, treatment_row: peer.id,
        stages: Object.fromEntries(STUDY_STAGES.map(name => [name, [stage(first, name), stage(peer, name)]])) });
    }
  }
  for (const group of contrasts) group.stages = Object.fromEntries(STUDY_STAGES.map(name => [name, pairedBinary(group.seed_pairs.map(pair => pair.stages[name]))]));
  const repeats = [];
  for (const repeat of rows.filter(row => row.kind === 'probe' && row.condition === 'unchanged-repeat')) {
    const base = rows.find(row => row.kind === 'probe' && row.block === repeat.block && row.condition === 'unchanged');
    const valid = base && observed(base) && observed(repeat) && base.result?.status === 'observed' && repeat.result?.status === 'observed', left = valid ? signature(artifacts.get(base.id)) : null, right = valid ? signature(artifacts.get(repeat.id)) : null;
    repeats.push({ ...dimensions(repeat), seed: repeat.seed, complete: Boolean(valid),
      request_and_seed_equal: valid ? base.result.request_identity?.body_sha256 === repeat.result.request_identity?.body_sha256 && base.result.request_identity?.derived_seed === repeat.result.request_identity?.derived_seed : null,
      proposed_action_changed: left !== null && right !== null ? left !== right : null,
      stage_changes: Object.fromEntries(STUDY_STAGES.map(name => [name, typeof stage(base ?? {}, name) === 'boolean' && typeof stage(repeat, name) === 'boolean' ? stage(base, name) !== stage(repeat, name) : null])) });
  }
  const forwards = rows.filter(row => row.kind === 'forward').map(row => {
    const artifact = artifacts.get(row.id), response = observed(row) ? artifact?.response : null;
    return { ...dimensions(row), row_id: row.id, block: row.block, seed: row.seed, condition: row.condition,
      status: response?.status ?? row.result?.status ?? 'unattempted', prefix_source: artifact?.request?.prefix_source ?? row.result?.prefix_source ?? null,
      context_sha256: response?.prefix_token_ids_sha256 ?? artifact?.request?.prefix_source?.context_sha256 ?? null, parity: row.result?.parity ?? null, component_effect: row.result?.component_effect ?? null,
      span_observations: response?.span_observations ?? null, attention: response?.attention ?? null,
      hybrid: response?.hybrid ?? null, cache_states: response?.cache_states ?? null,
      instrumented: response?.instrumented ?? null, input_intervention: artifact?.request?.input_intervention ?? row.result?.input_intervention ?? null, intervention: response?.intervention ?? null,
      scope: 'Selected query row; hybrid paths reported separately. Lexical marker likelihood is not complete action probability.' };
  });
  const correlations = [];
  for (const model of new Set(rows.map(row => row.model_id))) {
    const parity = forwards.filter(row => row.model === model && row.seed === 17 && row.condition === 'instrumented-forward');
    const parityVerified = parity.length === 4 && parity.every(row => row.parity?.status === 'passed');
    const selected = forwards.filter(row => row.model === model && row.instrumented === true && !row.intervention && !row.input_intervention && row.status === 'observed' && parityVerified);
    const names = new Set(selected.flatMap(row => (row.attention ?? []).flatMap(layer => (layer.spans ?? []).map(span => span.name))));
    if (!names.size) correlations.push({ model, feature: 'attention-span-mass', ...spearman([]), reason: 'No verified observational span attention available.', instrumentation_parity_verified: parityVerified });
    for (const name of names) {
      const contexts = new Map();
      for (const row of selected) {
        if (!row.context_sha256) continue;
        const values = row.attention.flatMap(layer => (layer.spans ?? []).filter(span => span.name === name).map(span => span.mean_mass_per_token)).filter(finite);
        const choice = row.prefix_source?.observed_valid_next_action;
        const item = contexts.get(row.context_sha256) ?? { values: [], choices: [], repeats: 0 };
        if (values.length) item.values.push(values.reduce((a, b) => a + b, 0) / values.length);
        if (typeof choice === 'boolean') item.choices.push(Number(choice));
        item.repeats++; contexts.set(row.context_sha256, item);
      }
      const average = values => values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
      const samples = [...contexts.values()].map(item => [average(item.values), average(item.choices)]);
      correlations.push({ model, feature: `${name}:mean_mass_per_token_across_observed_layers`, raw_observations: selected.length,
        unique_contexts: contexts.size, duplicate_contexts_collapsed: selected.length - contexts.size, context_aggregation: 'Mean observational mass and actual next-action rate per exact input-token context.',
        ...spearman(samples) });
    }
  }

  return { schema_version: 1, kind: 'ud-scientific-diagnostic-analysis', study_id: report.study_id, qualification_evidence: false,
    evidence_status: report.evidence_verification?.status === 'passed' && !errors.length ? 'verified' : 'unmet', evidence_errors: errors,
    stage_funnel_definition: 'Stagewise true/false/unknown observations; alternative routes can omit skill activation. No cumulative pass is inferred.',
    backend_generation_observations: rows.filter(row => row.kind !== 'forward').map(row => ({ ...dimensions(row), seed: row.seed, condition: row.condition,
      summary: row.analysis_evidence_valid ? row.result?.backend_generation ?? artifacts.get(row.id)?.metrics?.backend_generation ?? null : null })),
    harness_inventory: report.harness_inventory ?? [], harness_coverage: report.harness_coverage ?? null, groups, contrasts, same_seed_repeats: repeats,
    negative_activation: groups.filter(group => group.kind === 'native' && group.intent === 'S7').map(group => ({ ...dimensions({ model_id: group.model, harness_id: group.harness, scenario_id: group.intent }), condition: group.condition,
      activation: group.stages.activation, verified_completion: group.stages.verified_completion, costs: group.metrics })),
    native_failure_observations: rows.filter(row => row.kind === 'native').map(row => ({ ...dimensions(row), seed: row.seed, condition: row.condition,
      observations: row.analysis_evidence_valid ? row.result?.native_observation ?? null : null })),
    forwards, exploratory_attention_correlations: correlations,
    limits: ['All results concern fixed tasks; seeds are repeated stochastic trials.', 'Conditions execute in fixed order; carryover and timing are not independently randomized.',
      'Models bundle architecture, tokenizer, runtime and quantization.', 'No significance or general task-population claim follows from descriptive sign statistics.',
      'Missing or invalid evidence remains unknown; reservations are not measured usage.'] };
}
const number = value => value === null || value === undefined ? 'unknown' : typeof value === 'number' ? Number.isInteger(value) ? String(value) : value.toFixed(3) : String(value);
export function renderStudyAnalysis(analysis) {
  const lines = ['# Scientific diagnostic analysis', '', `Evidence: **${analysis.evidence_status}**. Qualification evidence: **false**.`, '', `Native study targets: **2 / 18** advertised surfaces. All frozen harness records remain in analysis.json; unsupported routes receive no execution credit.`, '', analysis.stage_funnel_definition, '',
    '| Kind | Model | Harness | Intent | Condition | Observed / required | Activation T/F/? | Valid call T/F/? | Completion T/F/? |', '| --- | --- | --- | --- | --- | ---: | --- | --- | --- |'];
  const counts = item => `${item.true}/${item.false}/${item.unknown}`;
  for (const group of analysis.groups) lines.push(`| ${group.kind} | ${group.model} | ${group.harness} | ${group.intent} | ${group.condition} | ${group.observed}/${group.required_rows} | ${counts(group.stages.activation)} | ${counts(group.stages.valid_call)} | ${counts(group.stages.verified_completion)} |`);
  lines.push('', '## Paired native completion', '', '| Model | Harness | Intent | Complete seed pairs | Improved / worsened / tied | Mean difference |', '| --- | --- | --- | ---: | --- | ---: |');
  for (const group of analysis.contrasts.filter(item => item.kind === 'native')) { const value = group.stages.verified_completion; lines.push(`| ${group.model} | ${group.harness} | ${group.intent} | ${value.complete_pairs} | ${value.wins}/${value.losses}/${value.ties} | ${number(value.mean_paired_difference)} |`); }
  lines.push('', '## Same-seed repeat stability', '', `Complete repeats: ${analysis.same_seed_repeats.filter(row => row.complete).length}/${analysis.same_seed_repeats.length}. Proposed-action changes: ${analysis.same_seed_repeats.filter(row => row.proposed_action_changed === true).length}; unknown: ${analysis.same_seed_repeats.filter(row => row.proposed_action_changed === null).length}.`, '', '## Mechanistic observations', '',
    `Forward records: ${analysis.forwards.length}. Verified parity: ${analysis.forwards.filter(row => row.parity?.status === 'passed').length}. Component effects observed: ${analysis.forwards.filter(row => row.component_effect?.status === 'observed').length}.`, '',
    '| Model | Attention feature | Blocks | Spearman rho | Status / reason |', '| --- | --- | ---: | ---: | --- |');
  for (const row of analysis.exploratory_attention_correlations) lines.push(`| ${row.model} | ${row.feature} | ${row.n} | ${number(row.rho)} | ${row.status}: ${row.reason ?? 'exploratory/confounded'} |`);
  lines.push('', '## Interpretation limits', '', ...analysis.limits.map(value => '- ' + value));
  return lines.join('\n') + '\n';
}
export function writeStudyAnalysis(directory, report, options) {
  const analysis = analyzeStudy(report, options), json = path.join(directory, 'analysis.json'), markdown = path.join(directory, 'ANALYSIS.md');
  writeNew(json, analysis); writeFileSync(markdown, renderStudyAnalysis(analysis), { flag: 'wx', mode: 0o600 }); return { json, markdown, analysis };
}
