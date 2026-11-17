/** Reconcile immutable native episode evidence without treating missing work as success. */
import { mkdir, open, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { buildMatrix, HARNESSES, MODELS, referenceRows, SEEDS } from './registry.mjs';

export const OUTCOMES = Object.freeze(['passed', 'failed', 'model_blocked', 'interface_unsupported', 'timed_out', 'token_budget_exceeded', 'context_resource_blocked', 'incomplete', 'not_run']);
const REQUIRED_OBSERVATIONS = ['real_inference', 'native_loop', 'model_attribution', 'independent_verification', 'budget_enforced', 'final_answer_verified', 'no_user_hints'];
const HASH_KEYS = ['evaluator', 'oracle', 'tasks', 'model_configuration'];
const HASH = /^[a-f0-9]{64}$/;

function redact(value) {
  if (typeof value === 'string') return value.replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]');
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key,
    /^(authorization|proxy-authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)$/i.test(key) ? '[REDACTED]' : redact(item)]));
}

function normalizedOutcome(value) {
  const outcome = typeof value === 'string' ? value.replace(/[ -]+/g, '_') : '';
  if (!OUTCOMES.includes(outcome)) throw new Error(`Unknown local evaluation outcome: ${String(value)}`);
  return outcome;
}

function declaredRows(manifest) {
  if (!manifest || !['baseline', 'candidate'].includes(manifest.snapshot) || !Array.isArray(manifest.rows) || !manifest.rows.length) throw new Error('A frozen snapshot and nonempty declared row inventory are required.');
  const canonical = new Map(buildMatrix({ snapshot: manifest.snapshot, controls: true }).map(row => [row.id, row]));
  const seen = new Set();
  return manifest.rows.map(row => {
    const id = row.row_id ?? row.id, expected = canonical.get(id);
    if (!expected || seen.has(id)) throw new Error(`Unknown or duplicate declared evaluation row: ${String(id)}`);
    for (const key of ['model_id', 'harness_id', 'scenario_id', 'seed', 'skills_enabled', 'snapshot']) {
      if (row[key] !== expected[key]) throw new Error(`Declared row identity differs: ${id}/${key}`);
    }
    seen.add(id);
    return { ...expected, ...row, id, row_id: id, cell_id: expected.cell_id };
  });
}

function observedRow(row, episode) {
  if (!episode) return { ...row, outcome: 'incomplete', recorded: false, reason: 'No episode evidence was recorded for this frozen row.', qualification_failures: ['EPISODE_MISSING'] };
  const outcome = normalizedOutcome(episode.outcome ?? episode.status);
  for (const key of ['model_id', 'harness_id', 'scenario_id', 'seed', 'snapshot', 'skills_enabled']) {
    if (Object.hasOwn(episode, key) && episode[key] !== row[key]) throw new Error(`Episode identity differs: ${row.id}/${key}`);
  }
  const observed = redact(episode), observations = observed.observations ?? observed.observation ?? {};
  const missing = [], contradicted = [];
  if (outcome === 'passed') {
    for (const key of REQUIRED_OBSERVATIONS) {
      if (observations[key] === false) contradicted.push(key);
      else if (observations[key] !== true) missing.push(key);
    }
    const expectedActivation = row.scenario_id !== 'S7' && row.skills_enabled;
    if (typeof observations.skill_activation !== 'boolean') missing.push('skill_activation');
    else if (observations.skill_activation !== expectedActivation) contradicted.push('skill_activation');
    if (typeof observed.final_answer !== 'string' || !observed.final_answer.trim()) missing.push('final_answer');
  }
  const effective = contradicted.length ? 'failed' : missing.length ? 'incomplete' : outcome;
  return { ...observed, ...row, recorded: true, outcome: effective, reported_outcome: outcome, observations,
    qualification_failures: [...contradicted.map(key => `OBSERVATION_FALSE:${key}`), ...missing.map(key => `OBSERVATION_MISSING:${key}`)],
    ...(effective !== outcome ? { reason: 'Claimed pass lacks the required native workflow evidence.' } : {}) };
}

/** Every declared row remains visible, including blocked, unattempted, and missing rows. */
export function buildReport(manifest, episodes) {
  const declared = declaredRows(manifest);
  if (!Array.isArray(episodes)) throw new Error('Episode evidence must be an array.');
  const known = new Set(declared.map(row => row.id)), indexed = new Map();
  for (const episode of episodes) {
    const id = episode?.row_id ?? episode?.id;
    if (!known.has(id) || indexed.has(id)) throw new Error(`Unknown or duplicate episode evidence: ${String(id)}`);
    indexed.set(id, episode);
  }
  const rows = declared.map(row => observedRow(row, indexed.get(row.id)));
  const counts = { scheduled: rows.length, recorded: indexed.size, missing: rows.length - indexed.size,
    by_outcome: Object.fromEntries(OUTCOMES.map(outcome => [outcome, rows.filter(row => row.outcome === outcome).length])) };
  const grouped = new Map();
  for (const row of rows) {
    const key = `${row.harness_id}/${row.scenario_id}/${row.model_id}/${row.skills_enabled ? 'skills' : 'skills-disabled'}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(row);
  }
  const qualifications = [...grouped.entries()].map(([cell, attempts]) => ({ cell,
    qualified: SEEDS.every(seed => attempts.some(row => row.seed === seed && row.outcome === 'passed')),
    missing_seeds: SEEDS.filter(seed => !attempts.some(row => row.seed === seed)),
    seeds: attempts.map(row => ({ seed: row.seed, row_id: row.id, outcome: row.outcome })) }));
  const fullStarter = buildMatrix({ snapshot: manifest.snapshot }).every(expected => known.has(expected.id));
  // A terminal record may have an incomplete independent grade. That is still
  // completed execution and can support a paired replay; it can never qualify.
  const executionComplete = counts.missing === 0 && rows.every(row => row.outcome !== 'not_run');
  const complete = executionComplete && rows.every(row => row.outcome !== 'incomplete');
  const enabled = rows.filter(row => row.skills_enabled);
  const passed = enabled.length > 0 && enabled.every(row => row.outcome === 'passed') && qualifications.filter(item => !item.cell.endsWith('/skills-disabled')).every(item => item.qualified);
  const starterPassed = fullStarter && rows.filter(row => row.skills_enabled).every(row => row.outcome === 'passed');
  return { schema_version: 1, kind: 'local-native-model-evaluation', snapshot: manifest.snapshot,
    status: passed ? 'passed' : complete ? 'completed_with_failures_or_blockers' : 'incomplete',
    execution_complete: executionComplete, grading_complete: complete,
    hashes: redact(manifest.hashes ?? {}), manifest: redact(manifest), counts, rows, qualifications,
    coverage: { nominal_starter_episodes: 171, complete_starter_inventory: fullStarter,
      harnesses: HARNESSES.map(host => ({ ...host, scheduled_rows: rows.filter(row => row.harness_id === host.id).map(row => row.id) })),
      models: MODELS, seeds: SEEDS,
      limitations: ['The starter matrix does not test every workflow in every harness.', 'Registration variants remain untested unless separately observed.', 'Negative selection is tested only in Qwen Code.', 'Image and extended-context evidence applies only to the assigned cells.', 'Three seeds provide starter evidence, not a general reliability guarantee.'] },
    gates: {
      provider_neutral_declared_coverage: { status: passed ? 'passed' : 'unmet', predicates: [...REQUIRED_OBSERVATIONS, 'correct_skill_activation', 'all_three_seeds'] },
      complete_starter_campaign: { status: starterPassed ? 'passed' : 'unmet', required_episodes: 171 },
      external_hosted_provider: { status: 'unmet', reason: 'Local inference does not demonstrate an external provider, cloud execution, or a vendor-specific hosted-model requirement.' },
    },
    reference_rows: referenceRows({ snapshot: manifest.snapshot }).map(row => row.id) };
}

/** A repaired candidate is comparable only under the same frozen evaluator and inputs. */
export function compareReports(baseline, candidate) {
  if (baseline?.snapshot !== 'baseline' || candidate?.snapshot !== 'candidate') throw new Error('Comparison requires baseline and candidate reports.');
  for (const key of HASH_KEYS) if (!HASH.test(baseline.hashes?.[key] ?? '') || baseline.hashes[key] !== candidate.hashes?.[key]) throw new Error(`Snapshot comparison identity differs or is absent: ${key}`);
  const original = new Map(baseline.rows.filter(row => row.skills_enabled).map(row => [row.cell_id, row]));
  const changed = new Map(candidate.rows.filter(row => row.skills_enabled).map(row => [row.cell_id, row]));
  if (original.size !== changed.size || [...original.keys()].some(key => !changed.has(key))) throw new Error('Candidate replay differs from the frozen baseline matrix.');
  return { schema_version: 1, kind: 'local-native-model-comparison', hashes: baseline.hashes,
    comparable: true, complete: [...original.values(), ...changed.values()].every(row => !['incomplete', 'not_run'].includes(row.outcome)),
    execution_complete: baseline.execution_complete === true && candidate.execution_complete === true,
    rows: [...original.entries()].map(([cell, before]) => {
      const after = changed.get(cell);
      return { cell_id: cell, baseline_row: before.id, candidate_row: after.id, baseline_outcome: before.outcome, candidate_outcome: after.outcome,
        change: before.outcome === after.outcome ? 'unchanged' : before.outcome === 'passed' ? 'regression' : after.outcome === 'passed' ? 'improvement' : 'different_nonpassing_outcome' };
    }), controls: { baseline_rows: baseline.rows.filter(row => !row.skills_enabled).map(row => row.id), candidate_controls_required: false } };
}

function inline(value) { return String(value ?? '').replaceAll('|', '\\|').replace(/[\r\n]+/g, ' '); }
function block(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? null, null, 2);
  const fence = '`'.repeat(Math.max(3, ...[...text.matchAll(/`+/g)].map(match => match[0].length + 1)));
  return `${fence}\n${text}\n${fence}`;
}
function reportMarkdown(report) {
  return `# Local native model evaluation\n\nSnapshot: ${report.snapshot}. Status: ${report.status}.\n\n${report.counts.recorded}/${report.counts.scheduled} frozen rows have records; ${report.counts.missing} are missing.\n\n| Harness | Scenario | Model | Seed | Skills | Outcome |\n| --- | --- | --- | ---: | --- | --- |\n${report.rows.map(row => `| ${row.harness_id} | ${row.scenario_id} | ${row.model_id} | ${row.seed} | ${row.skills_enabled ? 'enabled' : 'disabled control'} | ${row.outcome} |`).join('\n')}\n\n## Qualification\n\n${report.qualifications.map(item => `- ${inline(item.cell)}: ${item.qualified ? 'all three seeds passed' : 'not qualified'}`).join('\n')}\n\n## Evidence limits\n\n${report.coverage.limitations.map(value => `- ${value}`).join('\n')}\n- Provider-neutral declared coverage: ${report.gates.provider_neutral_declared_coverage.status}.\n- Complete 171-episode starter campaign: ${report.gates.complete_starter_campaign.status}.\n- External hosted-provider requirement: unmet by local inference.\n`;
}
function traceMarkdown(selected, observed) {
  const row = observed ?? { ...selected, outcome: 'incomplete', reason: 'The predetermined row is absent from the declared inventory.' };
  const events = row.events ?? [];
  const actions = row.actions ?? row.tool_calls ?? events.filter(event => ['operation_start', 'operation_step', 'response_loss'].includes(event.type));
  const results = row.results ?? row.model_visible_results ?? events.filter(event => event.type === 'operation_result').map(event => {
    const envelope = event.response?.structuredContent ?? {}, result = envelope.result ?? {};
    return { operation: envelope.operation ?? event.name, operation_id: event.operation_id, execution: envelope.execution, passed: result.passed,
      summary: result.summary, coverage: envelope.coverage ?? result.coverage, inputs: envelope.inputs, findings: result.incidents,
      resources: result.report_resource, artifacts: envelope.artifacts, limitations: envelope.limitations };
  });
  return `# ${selected.scenario_id} reference trace\n\nPredetermined row: ${selected.id}. Outcome: ${row.outcome}.\n\n## Intent\n\n${block(row.intent ?? row.prompt ?? 'Intent text is unavailable in this episode record.')}\n\n## Discovery\n\n${block(row.discovery ?? row.skill_evidence ?? row.observations ?? 'Discovery evidence unavailable.')}\n\n## Useful actions\n\n${block(actions)}\n\n## Observed results\n\n${block(results)}\n\n## Final answer\n\n${block(row.final_answer ?? 'No final answer recorded.')}\n\n## Independent verdict\n\n${block({ outcome: row.outcome, reason: row.reason ?? null, verification: row.verification ?? null, qualification_failures: row.qualification_failures ?? [] })}\n`;
}

/** Publish one new immutable report directory; an existing destination is never replaced. */
export async function writeReport(directory, manifest, episodes) {
  const report = buildReport(manifest, episodes), destination = path.resolve(directory);
  await mkdir(path.dirname(destination), { recursive: true });
  // Exclusive ownership prevents a competing writer from replacing this report.
  await mkdir(destination, { mode: 0o700 });
  const staging = path.join(destination, `.pending-${randomUUID()}`);
  await mkdir(staging, { mode: 0o700 });
  async function write(relative, contents) {
    const file = path.join(staging, relative);
    await mkdir(path.dirname(file), { recursive: true });
    const handle = await open(file, 'wx', 0o600);
    try { await handle.writeFile(contents); await handle.sync(); } finally { await handle.close(); }
  }
  try {
    await write('report.json', JSON.stringify(report, null, 2) + '\n');
    await write('report.md', reportMarkdown(report));
    for (const selected of referenceRows({ snapshot: manifest.snapshot })) await write(`traces/${selected.scenario_id}.md`, traceMarkdown(selected, report.rows.find(row => row.id === selected.id)));
    await rename(path.join(staging, 'traces'), path.join(destination, 'traces'));
    await rename(path.join(staging, 'report.md'), path.join(destination, 'report.md'));
    // report.json is the final commit marker; consumers reject its absence.
    await rename(path.join(staging, 'report.json'), path.join(destination, 'report.json'));
    await rm(staging, { recursive: true });
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
  return { report, directory: destination, json: path.join(destination, 'report.json'), markdown: path.join(destination, 'report.md') };
}
