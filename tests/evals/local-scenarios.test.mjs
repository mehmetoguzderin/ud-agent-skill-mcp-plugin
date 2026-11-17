import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCENARIOS, createScenario, gradeScenario, createResponseLossInjector, observeScenario } from '../../evals/local/scenarios.mjs';
import { captureWorkspace } from '../../scripts/quality/workflow-grader.mjs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const byId = (id) => SCENARIOS.find((scenario) => scenario.id === id);
async function episode(t, id, options) {
  const parent = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-local-scenario-'));
  t.onTestFinished(() => rmSync(parent, { force: true, recursive: true }));
  const created = await createScenario(id, path.join(parent, 'task'), options);
  return { ...created, events: id === 'S7' ? [] : [{ type: 'ud_operation', name: 'actual-domain-operation' }], observations: { complete: true }, finalAnswer: '' };
}
function grade(id, evidence) { return gradeScenario(id, { ...evidence, after: captureWorkspace(evidence.taskRoot) }); }
function inputHashes(id) { return Object.fromEntries(Object.entries(byId(id).files).map(([name, bytes]) => [name, sha(bytes)])); }
function tar(files) {
  const chunks = [];
  for (const [name, content] of Object.entries(files)) {
    const bytes = Buffer.from(content), header = Buffer.alloc(512);
    header.write(name, 0, 100); header.write('0000600\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
    header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124); header.write('00000000000\0', 136);
    header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257); header.write('00', 263);
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148);
    chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}

test('seven fresh input-only fixtures exclude private answers and verifiers', async (t) => {
  assert.equal(SCENARIOS.length, 7);
  assert.deepEqual(SCENARIOS.map(({ id }) => id), ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7']);
  for (const scenario of SCENARIOS) {
    const e = await episode(t, scenario.id, { extendedTokens: 256 });
    assert.deepEqual(readdirSync(e.taskRoot).sort(), [...Object.keys(scenario.files), ...(scenario.id === 'S4' ? ['project-brief.txt'] : [])].sort());
    assert.equal(e.fixtureSha256.length, 64);
    assert.notEqual((await grade(scenario.id, e)).status, 'passed');
    await assert.rejects(createScenario(scenario.id, e.taskRoot), /TASK_ROOT_NOT_EMPTY/);
  }
});

test('S1 verifies actual untouched bytes, independent failures, readiness, and truthful invalid result', async (t) => {
  const e = await episode(t, 'S1');
  e.observations.runtime = { initiallyReady: false, preparationAttempts: 1, resumed: true, reusedAssets: true };
  e.observations.validation = { execution: 'completed', passed: false, inputHashes: inputHashes('S1'), checkedFiles: ['a.conllu', 'b.conllu'], checks: ['content', 'identifiers'], findings: [{ kind: 'duplicate-sent-id', sentId: 'duplicate' }, { kind: 'head-out-of-range', file: 'b.conllu', tokenId: '1', head: '9' }] };
  e.finalAnswer = 'Validation completed and found errors. Both a.conllu and b.conllu use sentence ID duplicate. In b.conllu, duplicate token 1 has invalid head 9. Content and identifier checks completed; inputs are unchanged.';
  assert.equal((await grade('S1', e)).status, 'passed');
  e.observations.runtime.preparationAttempts = 2;
  assert.equal((await grade('S1', e)).status, 'failed');
  e.observations.runtime.preparationAttempts = 1;
  writeFileSync(path.join(e.taskRoot, 'b.conllu'), 'replacement bytes\n');
  assert.equal((await grade('S1', e)).status, 'failed');
});

test('S2 needs changed candidate validation and observed reconciliation after one lost committed response', async (t) => {
  const e = await episode(t, 'S2'), scenario = byId('S2');
  writeFileSync(path.join(e.taskRoot, 'edit.conllu'), scenario.expected.bytes);
  e.observations.validation = { execution: 'completed', passed: true, inputHashes: { 'edit.conllu': sha(scenario.expected.bytes) } };
  e.observations.mutation = { responseLosses: 1, reconciled: true, duplicateEffects: 0, commits: [{ operationId: 'stable-logical-operation', beforeSha256: sha(scenario.files['edit.conllu']), afterSha256: sha(scenario.expected.bytes) }] };
  e.finalAnswer = 'Applied the edit: FORM Swallows, lemma swallow, and sentence text Swallows fly. Validation passed for the resulting candidate.';
  assert.equal((await grade('S2', e)).status, 'passed');
  e.observations.validation.inputHashes['edit.conllu'] = sha(scenario.files['edit.conllu']);
  assert.equal((await grade('S2', e)).status, 'failed');
  e.observations.validation.inputHashes['edit.conllu'] = sha(scenario.expected.bytes);
  e.observations.mutation.commits.push({ ...e.observations.mutation.commits[0], operationId: 'second-effect' });
  assert.equal((await grade('S2', e)).status, 'failed');
});

test('response loss transforms delivery only, preserves replay identity, and drops once', () => {
  const injector = createResponseLossInjector();
  const result = { result: 'committed' };
  const meta = { committed: true, operationId: 'op-1', beforeSha256: 'a'.repeat(64), afterSha256: 'b'.repeat(64) };
  assert.deepEqual(injector.transform(result), { delivered: true, result });
  assert.throws(() => injector.transform(result, { committed: true }), /COMMIT_EVIDENCE_REQUIRED/);
  const lost = injector.transform(result, meta);
  assert.equal(lost.delivered, false); assert.equal(lost.result, undefined);
  assert.equal(lost.event.operationId, 'op-1');
  assert.deepEqual(injector.transform(result, meta), { delivered: true, result });
  assert.equal(injector.observation().responseLosses, 1);
});

test('S3 independently fixes scores, gold roles, denominator and mismatch IDs without prescribing calls', async (t) => {
  const e = await episode(t, 'S3');
  const words = (name) => byId('S3').files[name].toString().split('\n').filter((line) => /^\d+\t/.test(line)).map((line) => line.split('\t'));
  const gold = words('gold.conllu'), prediction = words('predictions.conllu');
  assert.equal(gold.length, 5);
  assert.equal(gold.filter((word, index) => word[6] === prediction[index][6]).length, 4);
  assert.equal(gold.filter((word, index) => word[6] === prediction[index][6] && word[7] === prediction[index][7]).length, 3);
  e.observations.comparison = { gold: 'gold.conllu', prediction: 'predictions.conllu', denominator: 5, uasCorrect: 4, lasCorrect: 3, mismatchTokenIds: ['2', '1'] };
  e.finalAnswer = 'Against gold.conllu: UAS 80%, LAS 60%; denominator 5 ordinary tokens, including root. In compare-1 token 1 has head 3 instead of 2. Token 2 has obj instead of nsubj.';
  assert.equal((await grade('S3', e)).status, 'passed');
  e.observations.comparison.gold = 'predictions.conllu';
  assert.equal((await grade('S3', e)).status, 'failed');
  e.observations.comparison.gold = 'gold.conllu'; e.finalAnswer = 'The comparison is complete.';
  assert.equal((await grade('S3', e)).status, 'incomplete');
});

test('S4 retains selection through the extended brief and requires measured envelope evidence', async (t) => {
  const e = await episode(t, 'S4');
  assert.ok(readFileSync(path.join(e.taskRoot, 'project-brief.txt')).length > 70_000);
  assert.equal(e.context.requiresMeasuredTokens, true);
  e.observations.investigation = { scope: ['news-1', 'news-2', 'news-3'], numerator: 2, denominator: 3, examples: [{ sentId: 'news-1', tokenId: '1', head: '2' }, { sentId: 'news-2', tokenId: '2', head: '1' }] };
  e.observations.context = { inputTokens: 22_000, outputReserve: 512, envelope: 32_768 };
  e.finalAnswer = '2 of 3 eligible nsubj relations precede their heads. news-1 token 1 precedes head 2; news-2 token 2 follows head 1. Only news was included; fiction was excluded.';
  assert.equal((await grade('S4', e)).status, 'passed');
  delete e.observations.context;
  assert.equal((await grade('S4', e)).status, 'incomplete');
  e.observations.context = { inputTokens: 32_500, outputReserve: 512, envelope: 32_768 };
  assert.equal((await grade('S4', e)).status, 'failed');
});

test('S5 requires image delivery and a real graph preview; PNG has no answer-bearing metadata', async (t) => {
  const e = await episode(t, 'S5');
  const bytes = readFileSync(path.join(e.taskRoot, 'diagram.png'));
  assert.deepEqual([...bytes.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  let offset = 8; const chunks = [];
  while (offset < bytes.length) { chunks.push(bytes.toString('ascii', offset + 4, offset + 8)); offset += bytes.readUInt32BE(offset) + 12; }
  assert.deepEqual(chunks, ['IHDR', 'IDAT', 'IEND']);
  assert.deepEqual(e.images, [{ path: 'diagram.png', mediaType: 'image/png' }]);
  mkdirSync(path.join(e.taskRoot, 'preview'));
  writeFileSync(path.join(e.taskRoot, 'preview', 'graph.svg'), '<svg><text>Cats chased mice</text><text>nsubj obj</text></svg>');
  e.observations.vision = { modelReceivedImage: true, imageSha256: sha(bytes), relation: 'obj', head: 'chased', dependent: 'mice', checkedGuideline: 'guidelines.md', previewPaths: ['preview/graph.svg'] };
  e.finalAnswer = 'The red obj arc links head chased to dependent mice, the direct object. It agrees with guidelines.md. The local preview is preview/graph.svg.';
  assert.equal((await grade('S5', e)).status, 'passed');
  e.observations.vision.modelReceivedImage = false;
  assert.equal((await grade('S5', e)).status, 'failed');
  e.observations.vision.modelReceivedImage = true;
  writeFileSync(path.join(e.taskRoot, 'preview', 'graph.svg'), 'not a rendered graph');
  assert.equal((await grade('S5', e)).status, 'failed');
});

test('S6 reopens the tar and checks contents and validation byte binding independently', async (t) => {
  const e = await episode(t, 'S6'), scenario = byId('S6');
  const manifest = { target_release: 'local-eval-1', files: Object.entries(scenario.files).map(([name, bytes]) => ({ path: name, size_bytes: bytes.length, sha256: sha(bytes) })) };
  const archive = tar({ ...scenario.files, '.ud-agent-release-manifest.json': JSON.stringify(manifest) });
  mkdirSync(path.join(e.taskRoot, 'handover'));
  writeFileSync(path.join(e.taskRoot, 'handover', 'candidate.tar'), archive);
  e.observations.release = { archivePath: 'handover/candidate.tar', archiveSha256: sha(archive), validation: { execution: 'completed', passed: true, inputHashes: { 'treebank.conllu': sha(scenario.files['treebank.conllu']) } }, missingChecks: ['Official registry acceptance was not assessed.'] };
  e.finalAnswer = `Prepared the local archive with treebank.conllu, README.md, LICENSE, and generated metadata. Validation passed against the packaged bytes. Official registry acceptance was not assessed. Archive SHA256: ${sha(archive)}.`;
  assert.equal((await grade('S6', e)).status, 'passed');
  const changed = tar({ ...scenario.files, 'treebank.conllu': 'different bytes', '.ud-agent-release-manifest.json': JSON.stringify(manifest) });
  writeFileSync(path.join(e.taskRoot, 'handover', 'candidate.tar'), changed);
  e.observations.release.archiveSha256 = sha(changed);
  assert.equal((await grade('S6', e)).status, 'failed');
});

test('S7 distinguishes startup metadata from activation and detects inappropriate UD work', async (t) => {
  const e = await episode(t, 'S7');
  e.events = [{ type: 'skill_metadata', name: 'ud-validate' }];
  e.finalAnswer = 'Because the team completed the planned interviews, we can finalize the summary. The response rate increased from 40 percent to 55 percent. The next review is Friday.';
  assert.equal((await grade('S7', e)).status, 'passed');
  e.events.push({ type: 'skill_activation', name: 'ud-validate' });
  assert.equal((await grade('S7', e)).status, 'failed');
  e.events = [{ type: 'ud_operation', name: 'validation_report' }];
  assert.equal((await grade('S7', e)).status, 'failed');
});

test('missing telemetry, user hints, unexpected files, and symlink outputs never pass', async (t) => {
  const e = await episode(t, 'S7');
  e.finalAnswer = 'Because interviews are complete, we can finalize the summary. The response rate rose from 40 to 55 percent. The next review is Friday.';
  e.observations.complete = false;
  assert.equal((await grade('S7', e)).status, 'incomplete');
  e.observations.complete = true; e.events.push({ type: 'user_hint' });
  assert.equal((await grade('S7', e)).status, 'failed');
  e.events = []; writeFileSync(path.join(e.taskRoot, 'extra.txt'), 'unexpected');
  assert.equal((await grade('S7', e)).status, 'failed');
  rmSync(path.join(e.taskRoot, 'extra.txt'));
  symlinkSync('report.txt', path.join(e.taskRoot, 'alias'));
  assert.equal((await gradeScenario('S7', e)).status, 'failed');
});

function completeTraffic() {
  return [
    { type: 'provider_request', id: 'request-1', tokens: { trusted: true, inputTokens: 100 }, body: { model: 'exact-local-model', messages: [{ role: 'user', content: 'A natural request.' }] } },
    { type: 'provider_response', id: 'request-1', status: 200, body: { model: 'exact-local-model', choices: [] } },
    { type: 'model_visible_response', id: 'request-1', outputTokens: 20 },
    { type: 'turn.completed', usage: { input_tokens: 100, output_tokens: 20 } },
  ];
}
function operation(name, operationId, result, inputs, extra = {}) {
  return [
    { type: 'operation_start', operation_id: operationId, name, arguments: {} },
    { type: 'operation_result', operation_id: operationId, name, response: { structuredContent: { operation: name, execution: { status: 'completed' }, inputs: { files: inputs }, result } }, ...extra },
  ];
}
test('observation projection preserves actual validation findings and does not invent cold-cache evidence', async (t) => {
  const e = await episode(t, 'S1');
  const inputs = e.before.files.map(({ path: name, sha256 }) => ({ path: name, sha256 }));
  const raw = operation('validation_report', 'validate-1', { passed: false, scope: { file_paths: ['a.conllu', 'b.conllu'], sentence_only: false, filtered: false }, coverage: { content: 'completed', repository: 'not_requested' }, incidents: [{ testid: 'non-unique-sent-id', sentid: 'observed-id' }, { testid: 'unknown-head', filename: '/staged/b.conllu', nodeid: 1, head: 7 }] }, inputs);
  raw.splice(1, 0, { type: 'operation_step', operation_id: 'validate-1', step: 'check_ud_environment' }, { type: 'operation_step', operation_id: 'validate-1', step: 'setup_ud_environment' }, { type: 'operation_step', operation_id: 'validate-1', step: 'check_ud_environment' });
  const projected = observeScenario('S1', { ...e, events: [...completeTraffic(), ...raw] });
  assert.equal(projected.observations.complete, true);
  assert.equal(projected.observations.runtime.initiallyReady, false);
  assert.equal(projected.observations.runtime.preparationAttempts, 1);
  assert.equal(projected.observations.runtime.resumed, true);
  assert.equal(projected.observations.runtime.reusedAssets, undefined);
  assert.deepEqual(projected.observations.validation.checks, ['content', 'identifiers']);
  assert.equal(projected.observations.validation.findings[0].sentId, 'observed-id');
  assert.equal(projected.observations.validation.findings[1].head, '7');
  assert.ok(projected.events.some((event) => event.type === 'ud_operation' && event.name === 'validation_report'));
  const missing = observeScenario('S1', { ...e, events: raw });
  assert.equal(missing.observations.complete, false);
  assert.equal(missing.observations.real_inference, undefined);
});

test('observation projection binds recovered mutations to actual transaction IDs and candidate validation', async (t) => {
  const e = await episode(t, 'S2'), scenario = byId('S2');
  const transaction = { status: 'completed', transaction_id: 'durable-transaction', files: [{ path: 'edit.conllu', before_sha256: sha(scenario.files['edit.conllu']), after_sha256: sha(scenario.expected.bytes) }], candidate_validation: { completed: true, passed: true } };
  const result = { transaction, validation: { status: 'completed', passed: true } };
  const original = operation('treebank_edit', 'first-invocation', result, e.before.files, { committed: true });
  const replay = operation('treebank_edit', 'second-invocation', { ...result, replayed: true }, e.before.files, { committed: false });
  const projected = observeScenario('S2', { ...e, events: [...completeTraffic(), ...original, { type: 'response_loss', operation_id: 'first-invocation', committed: true }, ...replay] });
  assert.equal(projected.observations.mutation.responseLosses, 1);
  assert.equal(projected.observations.mutation.reconciled, true);
  assert.equal(projected.observations.mutation.duplicateEffects, 0);
  assert.equal(projected.observations.mutation.commits.length, 1);
  assert.equal(projected.observations.mutation.commits[0].operationId, 'durable-transaction');
  assert.equal(projected.observations.validation.inputHashes['edit.conllu'], sha(scenario.expected.bytes));
  const noLossEvidence = observeScenario('S2', { ...e, events: [...completeTraffic(), ...original, ...replay] });
  assert.equal(noLossEvidence.observations.mutation.responseLosses, undefined);
});

test('real upstream unknown-head incidents derive only an unambiguous token from exact checked bytes', async (t) => {
  const e = await episode(t, 'S1');
  const raw = operation('validation_report', 'real-shape', { passed: false, scope: { file_paths: ['a.conllu', 'b.conllu'], sentence_only: false, filtered: false }, coverage: { content: 'completed' }, incidents: [{ testid: 'unknown-head', filename: 'b.conllu', sentid: 'duplicate', nodeid: 'None', message: "Undefined HEAD (no such ID): '9'." }] }, e.before.files);
  const options = { ...e, events: [...completeTraffic(), ...raw] };
  const observed = observeScenario('S1', options).observations;
  assert.deepEqual(observed.validation.findings, [{ kind: 'head-out-of-range', file: 'b.conllu', sentId: 'duplicate', tokenId: '1', head: '9' }]);
  assert.deepEqual(observed.validation.checks, ['content']);
  writeFileSync(path.join(e.taskRoot, 'b.conllu'), 'changed');
  assert.equal(observeScenario('S1', options).observations.validation.findings[0].tokenId, undefined);
});

test('S1 permits an independently correct duplicate conclusion after actual file exposure', async (t) => {
  const e = await episode(t, 'S1'), traffic = completeTraffic();
  const a = readFileSync(path.join(e.taskRoot, 'a.conllu'), 'utf8'), b = readFileSync(path.join(e.taskRoot, 'b.conllu'), 'utf8');
  traffic[0].body.messages.push({ role: 'tool', content: a + '\n' + b });
  const raw = operation('validation_report', 'syntax-only', { passed: false, scope: { file_paths: ['a.conllu', 'b.conllu'] }, coverage: { content: 'completed' }, incidents: [{ testid: 'unknown-head', filename: 'b.conllu', sentid: 'duplicate', nodeid: 'None', message: "Undefined HEAD (no such ID): '9'." }] }, e.before.files);
  const options = { ...e, events: [...traffic, ...raw], finalAnswer: 'a.conllu and b.conllu repeat the sentence identifier duplicate. Token 1 in b.conllu has invalid head 9.' };
  const findings = observeScenario('S1', options).observations.validation.findings;
  assert.deepEqual(findings.filter((item) => item.kind === 'duplicate-sent-id').map((item) => item.file), ['a.conllu', 'b.conllu']);
  traffic[0].body.messages.at(-1).content = a;
  assert.ok(!observeScenario('S1', options).observations.validation.findings.some((item) => item.kind === 'duplicate-sent-id'));
});

test('observation projection reads scoring roles/counts and derives differences from byte-bound actual inputs', async (t) => {
  const e = await episode(t, 'S3');
  const raw = operation('predictions_evaluate', 'score-1', { roles: { gold: ['gold.conllu'], system: ['predictions.conllu'] }, scores: { UAS: { correct: 4, gold_total: 5 }, LAS: { correct: 3, gold_total: 5 } } }, e.before.files);
  const projected = observeScenario('S3', { ...e, events: [...completeTraffic(), ...raw] });
  assert.deepEqual(projected.observations.comparison, { gold: 'gold.conllu', prediction: 'predictions.conllu', denominator: 5, uasCorrect: 4, lasCorrect: 3, mismatchTokenIds: ['1', '2'] });
  raw[1].response.structuredContent.result.scores.UAS.correct = 2;
  assert.equal(observeScenario('S3', { ...e, events: [...completeTraffic(), ...raw] }).observations.comparison.uasCorrect, 2);
  writeFileSync(path.join(e.taskRoot, 'gold.conllu'), 'changed after scoring');
  assert.equal(observeScenario('S3', { ...e, events: [...completeTraffic(), ...raw] }).observations.comparison.mismatchTokenIds, undefined);
});

test('skill activation requires full actual-request content rather than a metadata name', () => {
  const installation = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
  const events = completeTraffic();
  events[0].body.messages[0].content = 'Available skill: ud-validate';
  assert.equal(observeScenario('S7', { events, installation }).observations.skill_activation, false);
  events[0].body.messages[0].content = readFileSync(new URL('../../skills/ud-validate/SKILL.md', import.meta.url), 'utf8');
  const projected = observeScenario('S7', { events, installation });
  assert.equal(projected.observations.skill_activation, true);
  assert.ok(projected.events.some((event) => event.type === 'skill_activation' && event.name === 'ud-validate' && event.contentSha256));
  events[0].body.messages[0].content = JSON.stringify({ returncode: 0, output: readFileSync(new URL('../../skills/ud-validate/SKILL.md', import.meta.url), 'utf8') });
  assert.equal(observeScenario('S7', { events, installation }).observations.skill_activation, true);
  assert.equal(observeScenario('S7', { events: events.filter((event) => event.type !== 'model_visible_response') }).observations.complete, false);
});

test('activation binds the installed baseline bytes and rejects asserted activation hashes', async (t) => {
  const e = await episode(t, 'S7'), installation = path.join(path.dirname(e.taskRoot), 'installed');
  mkdirSync(path.join(installation, 'skills/ud-validate'), { recursive: true });
  const installed = '# Installed earlier skill\n' + 'Inspect the selected input and report its actual annotation status.\n'.repeat(3);
  writeFileSync(path.join(installation, 'skills/ud-validate/SKILL.md'), installed);
  const events = completeTraffic();
  events[0].body.messages[0].content = readFileSync(new URL('../../skills/ud-validate/SKILL.md', import.meta.url), 'utf8');
  events.push({ type: 'skill_activation', name: 'ud-validate', observed: true, contentSha256: sha(installed) });
  assert.equal(observeScenario('S7', { events, installation }).observations.skill_activation, false);
  events[0].body.messages[0].content = installed;
  const projected = observeScenario('S7', { events, installation });
  assert.equal(projected.observations.skill_activation, true);
  assert.equal(projected.events.at(-1).installedFileSha256, sha(installed));
  assert.equal(observeScenario('S7', { events }).observations.skill_activation, false);
});

test('S4 projects evidence-supported subject order without using expected answers or inventing context limits', async (t) => {
  const e = await episode(t, 'S4');
  const occurrences = { before_head: [{ file_path: 'corpus.conllu', sent_id: 'news-1', token_id: '1' }, { file_path: 'corpus.conllu', sent_id: 'news-3', token_id: '1' }], after_head: [{ file_path: 'corpus.conllu', sent_id: 'news-2', token_id: '2' }, { file_path: 'corpus.conllu', sent_id: 'fiction-1', token_id: '2' }] };
  const events = [...completeTraffic(), ...operation('dependency_order_profile', 'order-1', { occurrences }, e.before.files)];
  events[0].tokens.inputTokens = 20_000;
  const options = { ...e, events, finalAnswer: 'Only news was included; fiction excluded. 2 of 3 nsubj relations precede their heads. news-1 token 1 head 2; news-2 token 2 head 1.', contextEnvelope: 32768, outputReserve: 512 };
  const projected = observeScenario('S4', options);
  assert.equal(projected.observations.investigation.numerator, 2);
  assert.equal(projected.observations.investigation.denominator, 3);
  assert.deepEqual(projected.observations.investigation.scope, ['news-1', 'news-2', 'news-3']);
  assert.equal((await grade('S4', { ...e, finalAnswer: options.finalAnswer, ...projected })).status, 'passed');
  assert.equal(observeScenario('S4', { ...options, finalAnswer: 'The analysis completed.' }).observations.investigation, undefined);
  assert.equal(observeScenario('S4', { ...options, contextEnvelope: undefined }).observations.context.envelope, undefined);
  writeFileSync(path.join(e.taskRoot, 'corpus.conllu'), 'changed bytes');
  assert.equal(observeScenario('S4', options).observations.investigation, undefined);
});

test('S5 requires identical image delivery through provider and backend plus bound exported preview bytes', async (t) => {
  const e = await episode(t, 'S5');
  const png = readFileSync(path.join(e.taskRoot, 'diagram.png')), markup = readFileSync(path.join(e.taskRoot, 'guidelines.md'));
  const html = Buffer.from('<html><svg><text>Cats chased mice</text></svg></html>');
  mkdirSync(path.join(e.taskRoot, 'preview')); writeFileSync(path.join(e.taskRoot, 'preview/index.html'), html);
  const image = { type: 'image_url', image_url: { url: `data:image/png;base64,${png.toString('base64')}` } };
  const events = completeTraffic(); events[0].body.messages[0].content = [image];
  events.push({ type: 'upstream_request', id: 'request-1', body: events[0].body });
  events.push(...operation('guideline_example_preview', 'preview-1', { source: { file_path: 'guidelines.md', sha256: sha(markup) }, exports: [{ path: path.join(e.taskRoot, 'preview/index.html'), sha256: sha(html), size_bytes: html.length }] }, e.before.files));
  const options = { ...e, events, finalAnswer: 'The red obj arc has head chased and dependent mice. It matches guidelines.md; preview/index.html contains the preview.' };
  const projected = observeScenario('S5', options);
  assert.equal((await grade('S5', { ...e, finalAnswer: options.finalAnswer, ...projected })).status, 'passed');
  assert.equal(observeScenario('S5', { ...options, events: events.filter((event) => event.type !== 'upstream_request') }).observations.vision.modelReceivedImage, undefined);
  events.push({ type: 'translation_request', id: 'request-1', translated: true, backend: { messages: [{ role: 'user', content: 'Image omitted by a broken translator.' }] } });
  assert.equal(observeScenario('S5', options).observations.vision.modelReceivedImage, undefined);
  events.pop();
  writeFileSync(path.join(e.taskRoot, 'preview/index.html'), 'tampered');
  assert.deepEqual(observeScenario('S5', options).observations.vision.previewPaths, []);
});

test('S6 projects only verified exports with archive-member validation and observed external requirements', async (t) => {
  const e = await episode(t, 'S6'), scenario = byId('S6');
  const manifest = { target_release: 'local-eval-1', files: Object.entries(scenario.files).map(([name, bytes]) => ({ path: name, size_bytes: bytes.length, sha256: sha(bytes) })) };
  const archive = tar({ ...scenario.files, '.ud-agent-release-manifest.json': JSON.stringify(manifest) });
  mkdirSync(path.join(e.taskRoot, 'handover')); writeFileSync(path.join(e.taskRoot, 'handover/candidate.tar'), archive);
  const events = [...completeTraffic(), ...operation('release_plan', 'plan-1', { external_requirements: ['Official registry acceptance requires separate authority.'] }, e.before.files), ...operation('release_candidate_build', 'candidate-1', { manifest, validation: { status: 'completed', passed: true }, exports: [{ path: path.join(e.taskRoot, 'handover/candidate.tar'), size_bytes: archive.length, sha256: sha(archive) }] }, e.before.files)];
  const projected = observeScenario('S6', { ...e, events });
  assert.equal(projected.observations.release.validation.inputHashes['treebank.conllu'], sha(scenario.files['treebank.conllu']));
  assert.equal(projected.observations.release.archiveSha256, sha(archive));
  assert.equal(projected.observations.release.missingChecks.length, 1);
  events.at(-1).response.structuredContent.result.manifest.files[0].sha256 = 'a'.repeat(64);
  assert.equal(observeScenario('S6', { ...e, events }).observations.release.validation, undefined);
});

test('S4 accepts relation-profile occurrences with the same byte-bound investigation outcome', async (t) => {
  const e = await episode(t, 'S4');
  const occurrences = [['news-1', '1'], ['news-2', '2'], ['news-3', '1']].map(([sent_id, token_id]) => ({ file_path: 'corpus.conllu', sent_id, token_id }));
  const events = [...completeTraffic(), ...operation('relation_profile', 'relations-1', { relations: [{ relation: 'nsubj', count: 3, occurrences }] }, e.before.files)];
  events[0].tokens.inputTokens = 20_000;
  const finalAnswer = 'Only news was included; fiction excluded. 2 of 3 nsubj relations precede their heads. news-1 token 1 head 2; news-2 token 2 head 1.';
  const projected = observeScenario('S4', { ...e, events, finalAnswer, contextEnvelope: 32768, outputReserve: 512 });
  assert.equal((await grade('S4', { ...e, finalAnswer, ...projected })).status, 'passed');
});

test('S6 accepts handover metadata plus independent validation only for identical packaged bytes', async (t) => {
  const e = await episode(t, 'S6'), scenario = byId('S6');
  const manifest = { files: Object.entries(scenario.files).map(([name, bytes]) => ({ path: name, size_bytes: bytes.length, sha256: sha(bytes) })), limitations: ['Remote permissions, credentials, and account transfers are not included.'] };
  const archive = tar({ ...scenario.files, 'handover-manifest.json': JSON.stringify(manifest) });
  mkdirSync(path.join(e.taskRoot, 'handover')); writeFileSync(path.join(e.taskRoot, 'handover/handover.tar'), archive);
  const events = [...completeTraffic(), ...operation('handover_package_build', 'handover-1', { manifest, exports: [{ path: 'handover/handover.tar', size_bytes: archive.length, sha256: sha(archive) }] }, e.before.files), ...operation('validation_report', 'validate-1', { passed: true }, e.before.files)];
  const finalAnswer = `Prepared local package for target release local-eval-1: treebank.conllu, README.md, LICENSE. Validation passed for the packaged bytes. Official registry acceptance remains unassessed. Archive SHA-256: ${sha(archive)}.`;
  const projected = observeScenario('S6', { ...e, events, finalAnswer });
  assert.equal((await grade('S6', { ...e, finalAnswer, ...projected })).status, 'passed');
  events.at(-1).response.structuredContent.inputs.files.find((file) => file.path === 'treebank.conllu').sha256 = 'b'.repeat(64);
  assert.equal(observeScenario('S6', { ...e, events, finalAnswer }).observations.release.validation, undefined);
});

test('Gemini model attribution joins the validated route to exact translated backend requests and responses', () => {
  const events = completeTraffic();
  events[0].selected_model = 'public-model'; events[0].body = { contents: [{ role: 'user', parts: [{ text: 'A natural request.' }] }] };
  events[1].body = { modelVersion: 'public-model', candidates: [] };
  events.push({ type: 'upstream_request', id: 'request-1', body: events[0].body },
    { type: 'translation_request', id: 'request-1', translated: true, backend: { model: '/exact/local/artifact' } },
    { type: 'translation_response', id: 'request-1', translated: true, backend: { model: '/exact/local/artifact' } });
  const modelBinding = { publicModel: 'public-model', wireModel: '/exact/local/artifact' };
  assert.equal(observeScenario('S7', { events, modelBinding }).observations.model_attribution, true);
  assert.equal(observeScenario('S7', { events: events.slice(0, -1), modelBinding }).observations.model_attribution, false);
  events.at(-1).backend.model = 'unrelated-model';
  assert.equal(observeScenario('S7', { events, modelBinding }).observations.model_attribution, false);
});

test('adapter completion requires captured identity, verified cleanup, final output, and real provider traffic', () => {
  const events = completeTraffic().filter((event) => event.type !== 'turn.completed');
  events.push({ type: 'native.adapter.completed', source: 'owned-process-and-native-final-output', harness_id: 'qwen-code' }, { type: 'native_identity', harness_id: 'qwen-code', execution_location: 'arm64-container', cleanupVerified: true });
  const options = { events, finalAnswer: 'The native conversation finished.' };
  assert.equal(observeScenario('S7', options).observations.complete, true);
  assert.equal(observeScenario('S7', { ...options, finalAnswer: '' }).observations.complete, false);
  assert.equal(observeScenario('S7', { ...options, events: events.filter((event) => event.type !== 'native_identity') }).observations.complete, false);
  assert.equal(observeScenario('S7', { ...options, events: events.filter((event) => event.type !== 'provider_request') }).observations.complete, false);
  events.at(-1).cleanupVerified = false;
  assert.equal(observeScenario('S7', options).observations.complete, false);
});
