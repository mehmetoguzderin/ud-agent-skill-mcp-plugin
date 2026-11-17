/** Inert protocol/process fixtures only. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from '../../scripts/release/candidate.mjs';
import { buildStudyRows, createStudy, openStudy, runStudy, STUDY_POLICY } from '../../evals/local/study.mjs';
const bindings = Object.fromEntries(['evaluator', 'oracle', 'fixtures', 'product', 'models', 'clients', 'runtimes', 'interventions', 'analysis'].map(key => [key, 'a'.repeat(64)]));
function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-study-')), directory = path.join(root, '.artifacts/local-evals/studies/test');
  let clock = 1_000_000;
  createStudy({ root, directory, bindings, optIn: true, environment: {}, now: clock });
  return { root, directory, get clock() { return clock; }, set clock(value) { clock = value; },
    open: (options = {}) => openStudy({ root, directory, bindings, optIn: true, environment: {}, now: () => clock, ...options }),
    cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
const blocked = { status: 'blocked', reason: 'Inert unavailable fixture', owned_cleanup_verified: true };
function fileEvidence(f, name, text = 'independent evidence') { const file = path.join(f.directory, name); writeFileSync(file, text); return { path: file, sha256: sha256(text) }; }
function releaseProof(f) { return { owned_cleanup_verified: true, ...fileEvidence(f, 'release.json') }; }
function observed(f, row, extra = {}) {
  const seed = Number.parseInt(sha256(`${row.seed}:0`).slice(0, 8), 16) & 0x7fffffff;
  const body = { model: row.model_artifact, messages: [{ role: 'user', content: 'Natural fixture request' }], seed };
  const request = fileEvidence(f, 'request.json', JSON.stringify(body));
  return { status: 'observed', owned_cleanup_verified: true, evidence: [request], counters: { inference: 1, tools: 0, ud_operations: 0, output: 1, input: 25 },
    request_identity: { body_path: request.path, body_sha256: sha256(JSON.stringify(body)), derived_seed: seed }, ...extra };
}

test('causal study crosses intents and harnesses, preserves all seeds and exact repeats', () => {
  const rows = buildStudyRows(); assert.equal(rows.length, 432);
  for (const [kind, count] of Object.entries({ probe: 252, native: 108, forward: 72 })) assert.equal(rows.filter(row => row.kind === kind).length, count);
  assert.equal(new Set(rows.map(row => row.id)).size, rows.length);
  assert.equal(new Set(rows.filter(row => row.kind === 'probe').map(row => row.block)).size, 36);
  for (const model of ['minicpm', 'lfm3', 'bonsai']) {
    const selected = rows.filter(row => row.model_id === model); assert.equal(selected.length, 144);
    assert.deepEqual([...new Set(selected.map(row => row.seed))], [17, 23, 47]);
    for (const seed of [17, 23, 47]) for (const harness of ['qwen-code', 'mini-swe-agent']) for (const scenario of ['S2', 'S3']) {
      const probes = selected.filter(row => row.kind === 'probe' && row.seed === seed && row.harness_id === harness && row.scenario_id === scenario);
      assert.equal(probes.length, 7); assert.equal(probes.find(row => row.condition === 'unchanged-repeat').exact_repeat_of, `${probes[0].block}/unchanged`);
    }
  }
  assert.equal(rows.reduce((sum, row) => sum + row.maximum_inference_requests, 0), STUDY_POLICY.maximum_inference_requests);
  assert.equal(rows.reduce((sum, row) => sum + row.maximum_generated_tokens, 0), STUDY_POLICY.maximum_generated_tokens);
  assert.equal(STUDY_POLICY.model_ms * 3 + STUDY_POLICY.reconciliation_ms, STUDY_POLICY.duration_ms);
});
test('study preparation is explicit, local and clock-free; manifest and identity are immutable', () => {
  const f = fixture();
  try {
    const study = f.open(); assert.equal(study.snapshot().started_at, null); assert.equal(study.report().counts.probe.unfinished, 252);
    assert.throws(() => createStudy({ root: f.root, directory: path.join(f.root, 'outside'), bindings, optIn: true, environment: {} }), /repository-owned/);
    assert.throws(() => createStudy({ root: f.root, directory: f.directory, bindings, environment: {} }), /opt-in/);
    assert.throws(() => createStudy({ root: f.root, directory: f.directory + '-ci', bindings, optIn: true, environment: { CI: 'true' } }), /CI/);
    assert.throws(() => createStudy({ root: f.root, directory: f.directory, bindings, optIn: true, environment: {} }), /already exists/);
    assert.throws(() => f.open({ bindings: { ...bindings, oracle: 'c'.repeat(64) } }), /identity changed/);
    const manifest = path.join(f.directory, 'manifest.json'); chmodSync(manifest, 0o600);
    writeFileSync(manifest, readFileSync(manifest, 'utf8').replace('252', '253'));
    assert.throws(() => f.open(), /manifest bytes changed/);
  } finally { f.cleanup(); }
});
test('cross-process resume cannot duplicate active work, change residency, refund counters or reset deadlines', () => {
  const f = fixture();
  try {
    let study = f.open(); assert.throws(() => study.startModel('bonsai'), /supplied order/);
    study.startModel('minicpm'); const row = study.manifest.rows[0];
    const start = study.snapshot(); assert.equal(start.deadline, f.clock + 8 * 60 * 60_000);
    assert.throws(() => study.startModel('minicpm'), /one resident/);
    assert.throws(() => study.claimRow(study.manifest.rows[1].id), /seed-first/);
    study.claimRow(row.id);
    study = f.open(); assert.equal(study.snapshot().charged.inference_requests, 1); assert.equal(study.snapshot().charged.generated_tokens, 512);
    assert.throws(() => study.claimRow(row.id), /cannot be repeated/);
    assert.throws(() => study.releaseModel('minicpm', releaseProof(f)), /active unit/);
    assert.throws(() => study.recordRow(row.id, { status: 'failed', owned_cleanup_verified: true }), /explicit reason/);
    study.recordRow(row.id, blocked);
    assert.throws(() => study.claimRow(row.id), /cannot be repeated/);
    assert.equal(study.report().rows[0].result.stages.activation, null);
    study.releaseModel('minicpm', releaseProof(f));
    f.clock += 5000; study = f.open(); study.startModel('lfm3');
    assert.equal(study.snapshot().deadline, start.deadline); assert.equal(study.snapshot().charged.generated_tokens, 512);
    assert.throws(() => study.startModel('minicpm'), /one resident/);
    study.releaseModel('lfm3', releaseProof(f));
    f.clock = start.started_at - 1; assert.throws(() => study.startModel('bonsai'), /clock moved backwards/);
  } finally { f.cleanup(); }
});
test('model deadlines and evidence gaps fail closed; forced activation cannot grant qualification', () => {
  const f = fixture();
  try {
    const study = f.open(); study.startModel('minicpm'); const row = study.manifest.rows[0]; study.claimRow(row.id);
    assert.throws(() => study.recordRow(row.id, { status: 'observed', owned_cleanup_verified: true, stages: { activation: true } }), /hash-bound evidence/);
    const evidence = [fileEvidence(f, 'private-traffic.json')];
    assert.throws(() => study.recordRow(row.id, { status: 'observed', owned_cleanup_verified: true, evidence, stages: { verified_completion: true } }), /independent oracle/);
    assert.throws(() => study.recordRow(row.id, { status: 'observed', owned_cleanup_verified: true, evidence, qualification_claim: true }), /cannot establish native/);
    study.recordRow(row.id, observed(f, row, { stages: { activation: true } }));
    const report = study.report(); assert.equal(report.qualification_evidence, false); assert.equal(report.rows[0].result.qualification_claim, false);
    assert.equal(report.paired[0].comparisons[0].complete, false); assert.equal(report.paired[0].comparisons[0].stages.activation.difference, null);
    f.clock += STUDY_POLICY.model_ms; assert.throws(() => study.claimRow(study.manifest.rows[1].id), /deadline/);
    study.releaseModel('minicpm', releaseProof(f)); study.reconcile('Model deadline exhausted');
    assert.equal(study.report().counts.probe.unfinished, 251); assert.equal(study.report().status, 'reconciled');
    assert.throws(() => study.startModel('lfm3'), /one resident/);
  } finally { f.cleanup(); }
});
test('journal deletion or altered entries are detected on resume', () => {
  const f = fixture();
  try {
    const study = f.open(); study.startModel('minicpm'); study.claimRow(study.manifest.rows[0].id); study.recordRow(study.manifest.rows[0].id, blocked);
    const event = path.join(f.directory, 'journal/000001.json'); chmodSync(event, 0o600);
    writeFileSync(event, readFileSync(event, 'utf8').replace('512', '0'));
    assert.throws(() => f.open().snapshot(), /chain changed/);
  } finally { f.cleanup(); }
});
test('real executor lifecycle persists all inert outcomes without claiming inference or qualification', async () => {
  const f = fixture();
  try {
    const calls = [];
    const report = await runStudy({ study: f.open(),
      admit: async model => { calls.push(`admit:${model.id}`); return { fixture: true }; },
      execute: async ({ row }) => { calls.push(`execute:${row.model_id}`); return blocked; },
      release: async (_resident, model) => { calls.push(`release:${model.id}`); return releaseProof(f); },
      shouldStart: (_row, state) => Object.keys(state.rows).filter(id => state.rows[id].status === 'recorded').length < 1,
    });
    assert.equal(report.qualification_evidence, false); assert.equal(report.counts.probe.recorded, 1);
    assert.deepEqual(calls, ['admit:minicpm', 'execute:minicpm', 'release:minicpm', 'admit:lfm3', 'release:lfm3', 'admit:bonsai', 'release:bonsai']);
    assert.equal(report.rows.filter(row => row.status === 'unattempted').length, 431);
  } finally { f.cleanup(); }
});

test('future lifecycle retains an ambiguously cleaned model block and resumes only after independent episode proof', async () => {
  const f = fixture();
  try {
    const study = f.open(), row = study.manifest.rows[0]; let admissions = 0;
    const callbacks = { study, admit: async () => { admissions++; return {}; }, execute: async () => ({ ...blocked, owned_cleanup_verified: false }), release: async () => releaseProof(f) };
    await assert.rejects(runStudy(callbacks), /cleanup unresolved/);
    assert.equal(study.snapshot().active_model, 'minicpm'); assert.equal(study.snapshot().models.minicpm.released, false);
    const before = study.snapshot(); await assert.rejects(runStudy(callbacks), /independent episode release/); assert.equal(admissions, 1);
    const proof = { ...releaseProof(f), scope: 'episode', row_id: row.id }; study.reconcileUnitCleanup(row.id, proof);
    assert.equal(study.snapshot().rows[row.id].result.owned_cleanup_verified, false); assert.deepEqual(study.snapshot().charged, before.charged); assert.equal(study.snapshot().deadline, before.deadline);
    study.releaseModel('minicpm', releaseProof(f)); assert.equal(study.snapshot().models.minicpm.released, true);
  } finally { f.cleanup(); }
});

test('missing or tampered evidence invalidates report comparisons and counters cannot exceed reservations', () => {
  const f = fixture();
  try {
    const study = f.open(); study.startModel('minicpm'); const row = study.manifest.rows[0]; study.claimRow(row.id);
    assert.throws(() => study.recordRow(row.id, observed(f, row, { counters: { inference: 2, tools: 0, ud_operations: 0, output: 1, input: 25 } })), /exceeds reservation: inference/);
    assert.throws(() => study.recordRow(row.id, observed(f, row, { counters: { inference: 1, tools: 0, ud_operations: 0, output: 513, input: 25 } })), /exceeds reservation: output/);
    assert.throws(() => study.recordRow(row.id, observed(f, row, { counters: { inference: 1, tools: 0, ud_operations: 1, output: 1, input: 25 } })), /exceeds reservation: ud_operations/);
    const valid = observed(f, row, { stages: { exposure: true } }); study.recordRow(row.id, valid);
    assert.equal(study.report().evidence_verification.status, 'passed');
    writeFileSync(valid.evidence[0].path, 'altered');
    const report = f.open().report(); assert.equal(report.evidence_verification.status, 'unmet');
    assert.equal(report.rows[0].evidence_status, 'invalid'); assert.equal(report.paired[0].comparisons[0].stages.exposure.difference, null);
    assert.ok(report.evidence_verification.errors[0].reason.includes('bytes changed'));
  } finally { f.cleanup(); }
});
test('same-seed repeated probe requires identical effective body and reports all comparison kinds', () => {
  const f = fixture();
  try {
    const study = f.open(); study.startModel('minicpm'); const first = study.manifest.rows[0];
    study.claimRow(first.id); const original = observed(f, first); study.recordRow(first.id, original);
    for (const row of study.manifest.rows.slice(1, 6)) { study.claimRow(row.id); study.recordRow(row.id, blocked); }
    const repeat = study.manifest.rows[6]; study.claimRow(repeat.id);
    const wrong = observed(f, repeat); wrong.request_identity.derived_seed += 1;
    assert.throws(() => study.recordRow(repeat.id, wrong), /frozen root seed/);
    const different = observed(f, repeat), body = JSON.parse(readFileSync(different.request_identity.body_path, 'utf8')); body.messages[0].content = 'Different request';
    const file = fileEvidence(f, 'different-request.json', JSON.stringify(body)); different.evidence = [file]; different.request_identity.body_path = file.path; different.request_identity.body_sha256 = sha256(JSON.stringify(body));
    assert.throws(() => study.recordRow(repeat.id, different), /identical forwarded request/);
    study.recordRow(repeat.id, observed(f, repeat));
    const report = study.report(); const pair = report.paired[0].comparisons.find(item => item.condition === 'unchanged-repeat');
    assert.equal(pair.complete, true); assert.deepEqual([...new Set(report.paired.map(item => item.kind))], ['probe', 'native', 'forward']);
    assert.equal(report.qualification_evidence, false); assert.equal(STUDY_POLICY.maximum_total_inference_requests, STUDY_POLICY.maximum_inference_requests + 12);
  } finally { f.cleanup(); }
});
