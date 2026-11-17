/** Descriptive science on inert evidence; no provider or private oracle. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { analyzeStudy, pairedBinary, spearman, writeStudyAnalysis } from '../../evals/local/study-analysis.mjs';
function row(id, condition, seed, stages, extra = {}) {
  return { id, kind: 'native', model_id: 'model', harness_id: 'native', scenario_id: 'S2', seed, block: `model/native/S2/${seed}`, condition,
    status: 'recorded', evidence_status: 'verified', result: { status: 'incomplete', stages, evidence: [{ path: id, sha256: 'a'.repeat(64) }], counters: { inference: 2, tools: 1, ud_operations: 0, output: 20, input: 120 } }, ...extra };
}
const analyze = rows => analyzeStudy({ study_id: 'inert', evidence_verification: { status: 'passed' }, rows }, { readArtifact: () => ({ metrics: { elapsed_ms: 90 } }) });
test('paired effects preserve unknown signs and exact statistics remain explicitly descriptive', () => {
  const stats = pairedBinary([[false, true], [false, true], [false, true], [false, true], [null, true]]);
  assert.equal(stats.complete_pairs, 4); assert.equal(stats.unknown_pairs, 1); assert.equal(stats.wins, 4); assert.equal(stats.mean_paired_difference, 1);
  assert.equal(stats.exact_sign_under_exchangeability, 0.125); assert.ok(stats.interpretation.includes('Descriptive only'));
  assert.equal(pairedBinary([[false, false]]).exact_sign_under_exchangeability, null);
});
test('rank correlation handles ties, missingness, constants and insufficient independent blocks', () => {
  assert.equal(spearman([[1, 1], [1, 1], [2, 2], [3, 3], [4, 4], [5, 5], [null, 6]]).rho, 1);
  assert.equal(spearman(Array.from({ length: 6 }, (_, index) => [index, 0])).reason, 'constant_variable');
  assert.equal(spearman([[1, 1], [2, 0]]).reason, 'insufficient_observational_blocks');
});
test('stage funnels retain observations in failed workflows and comparisons preserve each seed', () => {
  const rows = [];
  for (const [seed, before, after] of [[17, false, true], [23, false, false], [47, null, true]]) {
    rows.push(row('a' + seed, 'current', seed, { activation: false, verified_completion: before }));
    rows.push(row('b' + seed, 'task-neutral-actionable', seed, { activation: true, verified_completion: after }));
  }
  const analysis = analyze(rows), group = analysis.groups.find(item => item.condition === 'current'), contrast = analysis.contrasts[0];
  assert.deepEqual(group.stages.verified_completion, { true: 0, false: 2, unknown: 1 });
  assert.equal(group.metrics.visible_calls.mean, 1); assert.deepEqual(contrast.seed_pairs.map(pair => pair.seed), [17, 23, 47]);
  assert.equal(contrast.stages.verified_completion.complete_pairs, 2); assert.equal(contrast.stages.verified_completion.mean_paired_difference, 0.5);
  assert.equal(analysis.qualification_evidence, false);
});
test('tampered source evidence becomes unknown and cannot produce a paired improvement', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-study-analysis-'));
  try {
    const file = path.join(directory, 'evidence.json'), content = JSON.stringify({ events: [] }); writeFileSync(file, content);
    const sample = row('one', 'current', 17, { verified_completion: true }); sample.result.evidence = [{ path: file, sha256: sha256(content) }];
    writeFileSync(file, '{}'); const result = analyzeStudy({ rows: [sample], evidence_verification: { status: 'passed' } });
    assert.equal(result.evidence_status, 'unmet'); assert.equal(result.groups[0].stages.verified_completion.true, 0); assert.equal(result.groups[0].stages.verified_completion.unknown, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('same-seed action stability ignores generated call IDs but detects argument changes', () => {
  const base = row('base', 'unchanged', 17, { valid_call: true }, { kind: 'probe' }), repeat = row('repeat', 'unchanged-repeat', 17, { valid_call: true }, { kind: 'probe' });
  for (const item of [base, repeat]) { item.result.status = 'observed'; item.result.request_identity = { body_sha256: 'same', derived_seed: 3 }; }
  const artifact = (id, argument) => ({ events: [{ type: 'native_calls_admitted', calls: [{ id, name: 'bash', arguments: { command: argument } }] }] });
  let analysis = analyzeStudy({ rows: [base, repeat] }, { readArtifact: item => artifact(item.path, 'ud-agent --help') });
  assert.equal(analysis.same_seed_repeats[0].request_and_seed_equal, true); assert.equal(analysis.same_seed_repeats[0].proposed_action_changed, false);
  analysis = analyzeStudy({ rows: [base, repeat] }, { readArtifact: item => artifact(item.path, item.path === 'base' ? 'ud-agent --help' : 'ls') });
  assert.equal(analysis.same_seed_repeats[0].proposed_action_changed, true);
});
test('readable and machine-readable analysis export without JSON-quoting Markdown', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-study-analysis-export-'));
  try {
    const result = writeStudyAnalysis(directory, { rows: [], evidence_verification: { status: 'passed' } });
    assert.ok(readFileSync(result.markdown, 'utf8').startsWith('# Scientific')); assert.equal(JSON.parse(readFileSync(result.json, 'utf8')).qualification_evidence, false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('attention correlations deduplicate context hashes instead of counting repeated seeds or heads as independent samples', () => {
  const rows = [];
  for (let index=0;index<12;index++) {
    const sample = row('forward'+index,index<4?'instrumented-forward':'reference-forward',index<4?17:23,{},{kind:'forward'});
    if(index<4)sample.result.parity={status:'passed'};
    rows.push(sample);
  }
  const result=analyzeStudy({rows,evidence_verification:{status:'passed'}},{readArtifact:item=>({request:{prefix_source:{context_sha256:'same-content',observed_valid_next_action:true}},response:{status:'observed',instrumented:true,intervention:null,attention:[{spans:[{name:'skill',mean_mass_per_token:0.1}]}]}})});
  const statistic=result.exploratory_attention_correlations[0]; assert.equal(statistic.raw_observations,12);assert.equal(statistic.unique_contexts,1);assert.equal(statistic.duplicate_contexts_collapsed,11);assert.equal(statistic.rho,null);assert.equal(statistic.reason,'insufficient_observational_blocks');
});
