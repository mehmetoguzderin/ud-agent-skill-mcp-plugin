import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildMatrix, referenceRows } from '../../evals/local/registry.mjs';
import { buildReport, compareReports, OUTCOMES, writeReport } from '../../evals/local/report.mjs';

const hashes = { evaluator: 'a'.repeat(64), oracle: 'b'.repeat(64), tasks: 'c'.repeat(64), model_configuration: 'd'.repeat(64) };
function manifest(snapshot = 'baseline', controls = false) { return { snapshot, hashes: { ...hashes }, rows: buildMatrix({ snapshot, controls }) }; }
function passed(row) {
  return { row_id: row.id, outcome: 'passed', final_answer: 'Completed with the stated findings and coverage.',
    observations: { real_inference: true, native_loop: true, model_attribution: true, independent_verification: true,
      budget_enforced: true, final_answer_verified: true, no_user_hints: true, skill_activation: row.scenario_id !== 'S7' && row.skills_enabled } };
}

test('report qualification requires every seed and never hides missing or blocked rows', () => {
  const frozen = manifest(), complete = frozen.rows.map(passed);
  const full = buildReport(frozen, complete);
  assert.equal(full.status, 'passed');
  assert.equal(full.execution_complete, true); assert.equal(full.grading_complete, true);
  assert.equal(full.gates.complete_starter_campaign.status, 'passed');
  assert.equal(full.gates.provider_neutral_declared_coverage.status, 'passed');
  assert.equal(full.gates.external_hosted_provider.status, 'unmet');
  assert.ok(full.qualifications.every(item => item.qualified));
  const incomplete = buildReport(frozen, complete.slice(1));
  assert.equal(incomplete.rows.length, 171);
  assert.equal(incomplete.rows[0].outcome, 'incomplete');
  assert.equal(incomplete.counts.missing, 1);
  assert.equal(incomplete.execution_complete, false); assert.equal(incomplete.grading_complete, false);
  assert.equal(incomplete.gates.complete_starter_campaign.status, 'unmet');
  const blocked = buildReport(frozen, complete.map((row, index) => index ? row : { ...row, outcome: 'model_blocked', reason: 'Exact artifact cannot load.' }));
  assert.equal(blocked.status, 'completed_with_failures_or_blockers');
  assert.equal(blocked.counts.by_outcome.model_blocked, 1);
  assert.equal(blocked.qualifications[0].qualified, false);
  const oneSeed = buildReport({ ...frozen, rows: [frozen.rows[0]] }, [complete[0]]);
  assert.equal(oneSeed.gates.provider_neutral_declared_coverage.status, 'unmet');
  assert.deepEqual(oneSeed.qualifications[0].missing_seeds, [23, 47]);
});

test('claimed passes require real native inference, independently correct final answers and enforced budgets', () => {
  const frozen = manifest(), row = frozen.rows[0], selected = { ...frozen, rows: [row] };
  for (const key of ['real_inference', 'native_loop', 'model_attribution', 'independent_verification', 'budget_enforced', 'final_answer_verified', 'no_user_hints', 'skill_activation']) {
    const incomplete = passed(row); delete incomplete.observations[key];
    assert.equal(buildReport(selected, [incomplete]).rows[0].outcome, 'incomplete', key);
    const failed = passed(row); failed.observations[key] = false;
    assert.equal(buildReport(selected, [failed]).rows[0].outcome, 'failed', key);
  }
  const noAnswer = passed(row); delete noAnswer.final_answer;
  assert.equal(buildReport(selected, [noAnswer]).rows[0].outcome, 'incomplete');
});

test('negative selection and disabled controls require evidence of no skill activation', () => {
  const frozen = manifest('baseline', true);
  for (const row of [frozen.rows.find(item => item.scenario_id === 'S7'), frozen.rows.find(item => !item.skills_enabled)]) {
    const selected = { ...frozen, rows: [row] }, episode = passed(row);
    assert.equal(buildReport(selected, [episode]).rows[0].outcome, 'passed');
    episode.observations.skill_activation = true;
    assert.equal(buildReport(selected, [episode]).rows[0].outcome, 'failed');
  }
});
test('a failed skills-disabled control remains visible without disqualifying enabled product coverage', () => {
  const frozen = manifest('baseline', true);
  const report = buildReport(frozen, frozen.rows.map(row => row.skills_enabled ? passed(row) : { row_id: row.id, outcome: 'failed', reason: 'No skill guidance.' }));
  assert.equal(report.counts.by_outcome.failed, 18);
  assert.equal(report.gates.complete_starter_campaign.status, 'passed');
  assert.equal(report.gates.provider_neutral_declared_coverage.status, 'passed');
  assert.ok(report.qualifications.filter(row => row.cell.endsWith('/skills-disabled')).every(row => !row.qualified));
});

test('all nonpassing outcomes remain distinct and malformed evidence is rejected', () => {
  const frozen = manifest();
  const evidence = frozen.rows.map((row, index) => ({ row_id: row.id, outcome: OUTCOMES[1 + index % (OUTCOMES.length - 1)] }));
  const report = buildReport(frozen, evidence);
  for (const outcome of OUTCOMES.slice(1)) assert.ok(report.counts.by_outcome[outcome] > 0, outcome);
  assert.throws(() => buildReport(frozen, [{ row_id: 'foreign', outcome: 'passed' }]), /Unknown/);
  assert.throws(() => buildReport(frozen, [passed(frozen.rows[0]), passed(frozen.rows[0])]), /duplicate/);
  assert.throws(() => buildReport(frozen, [{ ...passed(frozen.rows[0]), seed: 99 }]), /identity/);
  assert.throws(() => buildReport(frozen, [{ row_id: frozen.rows[0].id, outcome: 'skipped-but-passed' }]), /Unknown/);
  assert.throws(() => buildReport({ ...frozen, rows: [...frozen.rows, frozen.rows[0]] }, []), /duplicate/);
});

test('candidate comparison rejects changed evaluators, oracles, models or missing replay cells', () => {
  const before = manifest('baseline', true), after = manifest('candidate');
  const baseline = buildReport(before, before.rows.map(passed));
  const candidate = buildReport(after, after.rows.map(passed));
  const comparison = compareReports(baseline, candidate);
  assert.equal(comparison.rows.length, 171);
  assert.equal(comparison.controls.baseline_rows.length, 18);
  assert.ok(comparison.rows.every(row => row.change === 'unchanged'));
  for (const key of Object.keys(hashes)) assert.throws(() => compareReports(baseline, { ...candidate, hashes: { ...candidate.hashes, [key]: '0'.repeat(64) } }), /identity/);
  assert.throws(() => compareReports(baseline, { ...candidate, hashes: {} }), /identity/);
  assert.throws(() => compareReports(baseline, { ...candidate, rows: candidate.rows.slice(1) }), /matrix/);
  const regression = buildReport(after, after.rows.map((row, index) => index ? passed(row) : { row_id: row.id, outcome: 'timed_out' }));
  assert.equal(compareReports(baseline, regression).rows[0].change, 'regression');
});

test('report publication keeps seven predetermined traces, redacts credentials and refuses overwrites', async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-local-report-'));
  try {
    const frozen = manifest(), chosen = referenceRows()[0], target = path.join(temporary, 'baseline');
    const episodes = frozen.rows.map(row => row.id === chosen.id
      ? { row_id: row.id, outcome: 'interface_unsupported', reason: 'Native model endpoint unavailable.', headers: { Authorization: 'Bearer private-secret' }, api_key: 'private-secret' }
      : passed(row));
    const saved = await writeReport(target, frozen, episodes);
    assert.equal(saved.report.rows.find(row => row.id === chosen.id).outcome, 'interface_unsupported');
    assert.deepEqual((await readdir(path.join(target, 'traces'))).sort(), ['S1.md', 'S2.md', 'S3.md', 'S4.md', 'S5.md', 'S6.md', 'S7.md']);
    const trace = await readFile(path.join(target, 'traces/S1.md'), 'utf8');
    assert.match(trace, /interface_unsupported/);
    assert.match(trace, new RegExp(chosen.id));
    assert.doesNotMatch(await readFile(saved.json, 'utf8'), /private-secret/);
    await assert.rejects(writeReport(target, frozen, episodes), { code: 'EEXIST' });
    assert.equal(JSON.parse(await readFile(saved.json, 'utf8')).counts.scheduled, 171);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
