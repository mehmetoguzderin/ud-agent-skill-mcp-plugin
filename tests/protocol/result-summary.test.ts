/** Factual projection regression; no model or process fixtures needed. MIT. */
import { test } from 'vitest';
import { posixTest } from '../fixtures/native-scope.mjs';
import assert from 'node:assert/strict';
import { summarizeOperationResult } from '../../packages/coordinator/src/result-summary.js';
const envelope = (result: Record<string, unknown>, status = 'completed') => ({ operation: 'inert_operation', operation_id: 'inert', execution: { status }, result, diagnostics: [], artifacts: [], coverage: { requested: ['content'], completed: ['content'], skipped: [] }, limitations: [] });
test('projection reports exact returned counts and findings without equating execution with validity', () => {
  const source = envelope({ status: 'complete', passed: false, metrics: { score: { correct: 8, total: 11 } }, incidents: [{ message: 'Explicit fixture finding' }] });
  const before = structuredClone(source), result = JSON.parse(summarizeOperationResult(source));
  assert.equal(result.execution, 'completed'); assert.equal(result.facts['/result/passed'], false);
  assert.equal(result.facts['/result/metrics/score/correct'], 8); assert.equal(result.facts['/result/metrics/score/total'], 11);
  assert.equal(result.collections['/result/incidents'].count, 1); assert.equal(result.projection, true);
  assert.equal(result.authoritative_result, 'structuredContent');
  assert.deepEqual(source, before, 'Authoritative structured content must remain unchanged.');
  const unknown = JSON.parse(summarizeOperationResult(envelope({ status: 'incomplete', reason: 'missing prerequisite' }, 'incomplete')));
  assert.equal(unknown.execution, 'incomplete'); assert.equal(unknown.facts['/result/reason'], 'missing prerequisite'); assert.equal('/result/passed' in unknown.facts, false);
});
test('large and untrusted content remains bounded and explicit with exact immutable resource references', () => {
  const uri = 'ud://reports/52a4d03a-3146-4c4f-934d-c45c16131af6';
  const source = envelope({ status: 'resource', report_resource: { uri, mime_type: 'application/json', size_bytes: 500000, sha256: 'a'.repeat(64) }, text: 'untrusted content\n'.repeat(30000), rows: Array.from({ length: 6000 }, (_, i) => ({ value: i, text: 'data' })) });
  const before = structuredClone(source), text = summarizeOperationResult(source), result = JSON.parse(text);
  assert.ok(Buffer.byteLength(text) <= 4096); assert.equal(result.resources[0].uri, uri); assert.equal(result.resources[0].sha256, 'a'.repeat(64));
  assert.match(result.authoritative_result, /returned report_resource/);
  assert.equal(result.collections['/result/text'].content_omitted, true); assert.equal(result.collections['/result/rows'].count, 6000); assert.ok(result.omitted_nodes > 0);
  assert.deepEqual(source, before);
});
test('a rejected call points to the skill instructions that document it; completed calls carry no guidance', async () => {
  const { rejectionGuidance, SKILL_ROUTES } = await import('../../packages/coordinator/src/skill-routes.js');
  const { readFileSync } = await import('node:fs');
  const read = (file: string) => JSON.parse(readFileSync(file, 'utf8'));
  const names = new Map([...read('contracts/ud-interfaces.json'), ...read('contracts/environment.json')].map((item: { id: string; name: string }) => [item.id, item.name]));
  const expected: Record<string, string[]> = {};
  for (const skill of read('quality/skills.json').skills as { name: string; operation_ids: string[] }[]) for (const id of skill.operation_ids) (expected[names.get(id)!] ??= []).push(skill.name);
  assert.deepEqual(Object.fromEntries(Object.entries(SKILL_ROUTES).map(([key, value]) => [key, [...value]])), Object.fromEntries(Object.entries(expected).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => [key, value.sort()])), 'skill routes match quality/skills.json');
  assert.equal(rejectionGuidance('validation_report'), 'Exact arguments for validation_report are in the ud-validate skill instructions; load it with the skill loader (not as a tool), then retry.');
  assert.match(rejectionGuidance('plan_apply')!, /ud-edit or ud-validate skill instructions; load one/);
  assert.equal(rejectionGuidance('unknown_operation'), undefined);
  const rejected = JSON.parse(summarizeOperationResult(envelope({ status: 'rejected', reason: 'bad input' }, 'rejected'), { guidance: rejectionGuidance('validation_report') }));
  assert.match(rejected.guidance, /ud-validate skill/);
  assert.equal('guidance' in JSON.parse(summarizeOperationResult(envelope({ status: 'complete' }))), false);
});

test('a skill or operation name typed as a CLI command gets the exact next command, other names stay unknown', async () => {
  const { commandGuidance } = await import('../../packages/coordinator/src/skill-routes.js');
  const options = { operations: ['validation_report'], skillFile: (skill: string) => `.agents/skills/${skill}/SKILL.md`, describes: () => 'validation_report' };
  assert.equal(commandGuidance('ud-validate', options), 'ud-validate is a skill (an instructions document), not a command. Read it first: cat .agents/skills/ud-validate/SKILL.md, then run the ud-agent commands it gives (start with: ud-agent describe validation_report). It is for CoNLL-U .conllu work only.');
  assert.equal(commandGuidance('validation_report', options), 'validation_report is an operation, not a command. Run: ud-agent describe validation_report (it prints the exact Run: or Call: line to use).');
  assert.equal(commandGuidance('unknown-command', options), undefined);
  assert.equal(commandGuidance('ud-validate', { ...options, arguments: ['report.txt'] }), 'ud-validate is a skill for CoNLL-U .conllu files, not a command, and report.txt is not CoNLL-U, so no UD skill or tool applies. Run: cat report.txt');
  assert.match(commandGuidance('ud-validate', { ...options, arguments: ['a.conllu', 'notes.txt'] })!, /^ud-validate is a skill \(an instructions document\)/);
  assert.equal(commandGuidance('--version', options), undefined);
});

test('scorer count records are projected as one fact that states the denominator', async () => {
  const { scoreFact } = await import('../../packages/coordinator/src/result-summary.js');
  assert.equal(scoreFact({ correct: 4, gold_total: 5, system_total: 5, aligned_total: 5, precision: 0.8, recall: 0.8, f1: 0.8, aligned_accuracy: 0.8 }), '4 of 5 gold correct (denominator gold_total 5; system_total 5; aligned_total 5; precision 0.8, recall 0.8, f1 0.8, aligned_accuracy 0.8)');
  assert.equal(scoreFact({ correct: 1, gold_total: 3, system_total: 2, aligned_total: null, precision: 0.5, recall: 1 / 3, f1: 0.4, aligned_accuracy: null }), '1 of 3 gold correct (denominator gold_total 3; system_total 2; precision 0.5, recall 0.3333, f1 0.4)');
  assert.equal(scoreFact({ correct: 1, total: 3 }), undefined);
  const envelope = { operation: 'predictions_evaluate', operation_id: '081', execution: { status: 'completed' }, diagnostics: [], coverage: {}, artifacts: [], limitations: [],
    result: { pair_count: 1, scores: Object.fromEntries(['AllTags', 'BLEX', 'CLAS', 'LAS', 'Lemmas', 'MLAS', 'Sentences', 'Tokens', 'UAS', 'UFeats', 'UPOS', 'Words', 'XPOS'].map(metric => [metric, { correct: 3, gold_total: 5, system_total: 5, aligned_total: 5, precision: 0.6, recall: 0.6, f1: 0.6, aligned_accuracy: 0.6 }])) } };
  const summary = JSON.parse(summarizeOperationResult(envelope));
  assert.equal(summary.omitted_nodes, 0);
  assert.match(summary.facts['/result/scores/UAS'], /^3 of 5 gold correct \(denominator gold_total 5;/);
});

test('skill-name shell alias bytes quote the launcher and reject invalid names on every host', async () => {
  const { skillCommandAlias } = await import('../../packages/coordinator/src/skill-routes.js');
  assert.equal(skillCommandAlias(['/n/node', "/i/it's/entry.js"], 'ud-validate'), `#!/bin/sh\n'/n/node' '/i/it'\\''s/entry.js' 'ud-validate' "$@"\nexit 127\n`);
  assert.throws(() => skillCommandAlias(['/n/node'], 'x; rm -rf /'), /Invalid skill name/);
});

posixTest('skill-name shell aliases forward arguments to ud-agent NAME and exit 127', async () => {
  const { skillCommandAlias } = await import('../../packages/coordinator/src/skill-routes.js');
  const { spawnSync } = await import('node:child_process');
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const os = await import('node:os'), path = await import('node:path');
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-alias-')), file = path.join(directory, 'ud-validate');
  try {
    writeFileSync(file, skillCommandAlias(['/bin/echo'], 'ud-validate'));
    const result = spawnSync('/bin/sh', [file, 'a b.conllu'], { encoding: 'utf8' });
    assert.equal(result.stdout, 'ud-validate a b.conllu\n'); assert.equal(result.status, 127);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('deep small scalar records are stated as one line instead of omitted', async () => {
  const { flatRecordLine } = await import('../../packages/coordinator/src/result-summary.js');
  assert.equal(flatRecordLine({ count: 3, before_head: 2, example: 'c.conllu sent_id n1 token 1' }), 'count 3, before_head 2, example c.conllu sent_id n1 token 1');
  assert.equal(flatRecordLine({ nested: { a: 1 } }), undefined); assert.equal(flatRecordLine([1]), undefined);
  const result = JSON.parse(summarizeOperationResult(envelope({ relations: [{ relation: 'nsubj', occurrences: [{ file_path: 'c.conllu', sent_id: 'n1', token_id: '1' }, { file_path: 'c.conllu', sent_id: 'n2', token_id: '2' }, { file_path: 'c.conllu', sent_id: 'f1', token_id: '2' }],
    by_sentence_metadata: { genre: { fiction: { count: 1, after_head: 1 }, news: { count: 2, before_head: 1, after_head: 1 } } } }] })));
  assert.equal(result.facts['/result/relations/0/occurrences/0'], 'file_path c.conllu, sent_id n1, token_id 1');
  assert.equal(result.collections['/result/relations/0/occurrences'].count, 3);
  assert.equal(result.facts['/result/relations/0/occurrences/2'], 'file_path c.conllu, sent_id f1, token_id 2');
  const manifest = JSON.parse(summarizeOperationResult(envelope({ manifest: { files: ['treebank.conllu', 'README.md', 'LICENSE'].map(path => ({ path, sha256: 'a'.repeat(64), size_bytes: 1 })) } })));
  assert.equal(manifest.facts['/result/manifest/files/2'], `path LICENSE, sha256 ${'a'.repeat(64)}, size_bytes 1`);
  assert.equal(result.facts['/result/relations/0/by_sentence_metadata/genre'], 'fiction: count 1, after_head 1; news: count 2, before_head 1, after_head 1');
});
