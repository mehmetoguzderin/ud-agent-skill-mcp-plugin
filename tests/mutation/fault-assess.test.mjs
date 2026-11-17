import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { assessBoundedFaults, boundedFaultDefinitions } from '../../scripts/quality/fault-assess.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const sha = value => createHash('sha256').update(value).digest('hex');
function fixture() {
  const manifest = JSON.parse(readFileSync(path.join(root, 'tests/mutation/fault-cases.json')));
  const files = new Map([...new Set(manifest.cases.flatMap(item => [item.file, item.test.split('::')[0]]))].map(name => [name, readFileSync(path.join(root, name))]));
  const sourceHashes = Object.fromEntries([...files].map(([name, bytes]) => [name, sha(bytes)]));
  const input = { manifest, sourceHashes, sourceSha256: 'a'.repeat(64), readSource: name => files.get(name) };
  const inventory = boundedFaultDefinitions(manifest, input.readSource, sourceHashes);
  const tests = manifest.cases.map(item => ({ id: item.runner === 'pytest' ? item.test : item.test + '#' + item.id, source: item.test.split('::')[0], source_sha256: sourceHashes[item.test.split('::')[0]], name: item.assertion }));
  const metadata = { profile: 'bounded', policy: 'bounded-reviewed-v1', qualification: 'bounded-reviewed-corpus', exhaustive: false };
  const plan = { schema_version: 1, ...metadata, tool: 'fault-canary', tool_version: '1.0.0', inventory_only: true, scope_complete: true, source_tree_sha256: input.sourceSha256, inventory, scheduled: 18, tests };
  const outcomes = inventory.map((item, index) => ({ id: item.id, definition_sha256: item.definition_sha256, status: 'Killed', failure_kind: 'assertion', killed_by: [tests[index].id], evidence: item.definition.runner === 'rust'
    ? { baseline: { phase: { process_status: 'Success' } }, source_restored: true, assertion_evidence: { valid: true, artifacts_complete: true }, phase_results: [{ process_status: 'Success' }, { process_status: 'Success' }, { process_status: { Failure: 101 }, artifacts_complete: true }] }
    : { baseline: { status: 0, timed_out: false }, execution: { status: 1, timed_out: false } } }));
  return { ...input, plan, report: { schema_version: 1, ...metadata, tool: 'fault-canary', source_tree_sha256: input.sourceSha256, complete: true, outcomes } };
}

test('bounded corpus reconstructs all 18 exact edits and reports four languages without exhaustive claims', () => {
  const input = fixture(), result = assessBoundedFaults(input);
  assert.deepEqual(result.errors, []); assert.equal(result.total, 18); assert.equal(result.killed, 18); assert.equal(result.exhaustive, false);
  assert.deepEqual(result.per_language, { typescript: { scheduled: 11, killed: 11 }, python: { scheduled: 3, killed: 3 }, rust: { scheduled: 2, killed: 2 }, perl: { scheduled: 1, killed: 1 }, data: { scheduled: 1, killed: 1 } });
  for (const item of input.plan.inventory) {
    const bytes = input.readSource(item.file), definition = item.definition;
    assert.equal(bytes.subarray(definition.start, definition.end).toString('hex'), definition.original_hex);
    assert.notEqual(definition.original_hex, definition.replacement_hex);
  }
});

test('independent Python replay reconstructs the same exact 18 definitions without generating or executing variants', () => {
  const input = fixture();
  const program = "import importlib.util,json,pathlib,sys\nr=pathlib.Path(sys.argv[1]);s=importlib.util.spec_from_file_location('replay',r/'scripts/quality/prove-source-generation.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps(m.reconstruct(r,r,'faults')))";
  const result = spawnSync(process.env.UD_AGENT_PYTHON ?? 'python3', ['-I', '-B', '-c', program, root], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.error, undefined);
  assert.deepEqual(JSON.parse(result.stdout), input.plan.inventory);
});

test('bounded acceptance rejects stale or changed definitions, omissions, duplicated outcomes and false scope claims', () => {
  for (const change of [
    input => { input.plan.inventory[0].definition.replace = 'forged'; },
    input => { input.sourceHashes[input.manifest.cases[0].file] = 'b'.repeat(64); },
    input => { input.manifest.cases.pop(); },
    input => { input.report.outcomes.pop(); },
    input => { input.report.outcomes[1] = input.report.outcomes[0]; },
    input => { input.report.exhaustive = true; },
    input => { input.plan.tests[0].source_sha256 = 'b'.repeat(64); },
    input => { input.manifest.cases.find(item => item.language === 'perl').language = 'python'; },
    input => { input.report.outcomes[0].killed_by = ['unobserved-test']; },
  ]) {
    const input = fixture(); change(input); assert.ok(assessBoundedFaults(input).errors.length > 0);
  }
});

test('bounded acceptance never counts survivors, runtime failures, compilation failures or timeouts as kills', () => {
  for (const status of ['Survived', 'Timeout', 'RunnerError', 'CompileError', 'Uncovered']) {
    const input = fixture(); input.report.outcomes[0].status = status; assert.ok(assessBoundedFaults(input).errors.length > 0, status);
  }
  for (const change of [
    input => { input.report.outcomes[0].failure_kind = 'runtime'; },
    input => { input.report.outcomes[0].evidence.execution.status = 125; },
    input => { input.report.outcomes[0].evidence.execution.timed_out = true; },
    input => { input.report.outcomes[0].evidence.baseline.status = 1; },
    input => { input.report.outcomes[14].evidence.phase_results[0].process_status = { Failure: 1 }; },
    input => { input.report.outcomes[14].evidence.assertion_evidence.valid = false; },
    input => { input.report.outcomes[14].evidence.source_restored = false; },
  ]) {
    const input = fixture(); change(input); assert.ok(assessBoundedFaults(input).errors.length > 0);
  }
});
