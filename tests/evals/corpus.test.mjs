import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { loadWorkflowCorpus, substituteWorkflow } from '../../scripts/quality/workflow-corpus.mjs';
import { loadWorkflowHost, workflowHostEntry, workflowProfile, verifyWorkflowCleanup, verifyWorkflowQualification } from '../../scripts/quality/workflow-host.mjs';
import { userspaceStateRoot } from '../../packages/runtime-manager/src/userspace.js';
import { gradeWorkflow, captureWorkspace } from '../../evals/graders/workflow.mjs';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

const root = process.cwd();
function temporary(run) {
  const folder = mkdtempSync(path.join(os.tmpdir(), 'ud-corpus-'));
  try { return run(folder); } finally { rmSync(folder, { recursive: true, force: true }); }
}
function copied(run) { return temporary(folder => {
  for (const name of ['evals', 'quality', 'contracts', 'tests']) writableFixtureCopy(path.join(root, name), path.join(folder, name), folder);
  return run(folder);
}); }
test('canonical corpus has actual schema-valid replays for every skill and distinct model-routing scenarios', () => {
  const corpus = loadWorkflowCorpus(root);
  assert.equal(corpus.routing_cases.length, 24); assert.equal(corpus.replay_cases.length, 10);
  assert.equal(corpus.routing_cases.filter(item => item.expected_skill === null).length, 6);
  for (const host of ['codex', 'claude', 'gemini']) assert.equal(loadWorkflowHost(root, host).model_execution, 'external-not-run');
  const actual = substituteWorkflow({ a: ['${WORKSPACE}/a.conllu', 2], b: null }, '/tmp/selected');
  assert.deepEqual(actual, { a: ['/tmp/selected/a.conllu', 2], b: null });
});
test('private replay state matches the actual product path contract on every native OS', () => {
  for (const [platform, home] of [['darwin', '/private/tmp/ud-profile'], ['linux', '/tmp/ud-profile'], ['win32', 'C:\\Private\\ud-profile']]) {
    const profile = workflowProfile(home, platform);
    assert.equal(profile.state, userspaceStateRoot({ platform, arch: 'arm64' }, profile.env));
    assert.equal(profile.env.HOME, home);
  }
  assert.throws(() => workflowProfile('relative', 'linux'));
  assert.throws(() => workflowProfile('/tmp/profile', 'unavailable'));
});
test('successful command exit cannot conceal protected or incomplete cleanup', () => {
  const good = { action: 'owned-runtime', dry_run: false, paths: [], providers: [{ status: 'complete', protected_paths: [] }] };
  assert.equal(verifyWorkflowCleanup(good, 'docker'), good);
  assert.equal(verifyWorkflowCleanup({ ...good, providers: [] }, 'userspace').providers.length, 0);
  for (const change of [{ dry_run: true }, { action: 'cache' }, { providers: [] }, { providers: [{ status: 'complete', protected_paths: ['retain-foreign'] }] }, { providers: [{ status: 'recovery_required', protected_paths: [] }] }]) assert.throws(() => verifyWorkflowCleanup({ ...good, ...change }, 'docker'));
});
test('development payloads require explicit diagnostic scope and cannot become final acceptance', () => temporary(folder => {
  const file = path.join(folder, 'BUILD-RECEIPT.json');
  writeFileSync(file, JSON.stringify({ qualification: 'local_candidate' }));
  assert.throws(() => verifyWorkflowQualification(folder), /qualification/);
  assert.deepEqual(verifyWorkflowQualification(folder, 'diagnostic'), { qualification: 'diagnostic-scripted-replay-not-final-acceptance', acceptance_eligible: false });
  writeFileSync(file, JSON.stringify({ qualification: 'preacceptance_candidate' }));
  assert.equal(verifyWorkflowQualification(folder).acceptance_eligible, true);
  assert.throws(() => verifyWorkflowQualification(folder, 'diagnostic'), /qualification/);
  assert.throws(() => verifyWorkflowQualification(folder, 'accepted'), /candidate or diagnostic/);
}));
test('missing or duplicate required corpus scenarios cannot pass discovery', () => copied(folder => {
  const file = path.join(folder, 'evals/cases/workflows.json'), corpus = JSON.parse(readFileSync(file));
  const original = JSON.stringify(corpus);
  corpus.routing_cases.pop(); writeFileSync(file, JSON.stringify(corpus));
  assert.throws(() => loadWorkflowCorpus(folder), /scenario missing/);
  const duplicate = JSON.parse(original); duplicate.replay_cases[0].id = duplicate.routing_cases[0].id;
  writeFileSync(file, JSON.stringify(duplicate)); assert.throws(() => loadWorkflowCorpus(folder), /duplicate/);
}));
test('unsafe fixtures, invalid arguments and circularly unconstrained outputs are rejected', () => copied(folder => {
  const file = path.join(folder, 'evals/cases/workflows.json'), original = readFileSync(file, 'utf8');
  for (const change of [
    x => { x.replay_cases[0].files['../escape'] = 'bad'; },
    x => { x.replay_cases[0].steps[0].arguments.options.level = 0; },
    x => { x.replay_cases[0].expected_files['unapproved.txt'] = 'bad'; },
    x => { x.replay_cases[0].steps[0].expected.assertions = []; },
  ]) {
    const corpus = JSON.parse(original); change(corpus); writeFileSync(file, JSON.stringify(corpus));
    assert.throws(() => loadWorkflowCorpus(folder));
  }
}));
test('host adapters execute only the candidate entry and exact granted workspace', () => temporary(folder => {
  const workspace = path.join(folder, 'workspace'), installation = path.join(folder, 'installation'), node = path.join(folder, 'node');
  mkdirSync(workspace); mkdirSync(path.join(installation, 'lib'), { recursive: true }); writeFileSync(path.join(installation, 'lib/coordinator.mjs'), 'candidate');
  for (const host of ['codex', 'claude', 'gemini']) {
    const adapter = loadWorkflowHost(root, host), file = path.join(workspace, adapter.configuration); mkdirSync(path.dirname(file), { recursive: true });
    const entry = { command: node, args: [path.join(installation, 'lib/coordinator.mjs'), 'mcp', '--allow-root', workspace] };
    const text = adapter.format === 'toml' ? `[mcp_servers.ud]\ncommand = ${JSON.stringify(node)}\nargs = ${JSON.stringify(entry.args)}\n` : JSON.stringify({ [adapter.server_key]: { ud: entry } });
    writeFileSync(file, text); assert.deepEqual(workflowHostEntry(adapter, workspace, installation, node), entry);
    writeFileSync(file, text.replace('mcp', 'shell'));
    assert.throws(() => workflowHostEntry(adapter, workspace, installation, node));
  }
  assert.throws(() => loadWorkflowHost(root, '../outside'));
}));
test('non-validation workflows require independent semantic expectations and inspect actual file effects', () => temporary(folder => {
  writeFileSync(path.join(folder, 'a.conllu'), 'original');
  const before = captureWorkspace(folder), outcome = { execution: { status: 'completed' }, result: { word_count: 2 }, artifacts: [] };
  const expected = { execution_status: 'completed', assertions: [{ pointer: '/result/word_count', value: 2 }], artifacts: [], required_tools: ['treebank_profile'], allowed_tools: ['treebank_profile'], allowed_writes: [], allow_network: true, allowed_processes: [] };
  const observation = { source: 'mcp-client', complete: true, events: [{ type: 'tool_call', name: 'treebank_profile' }] };
  const grade = changes => gradeWorkflow({ workspaceRoot: folder, artifactRoot: folder, before, outcome, expected, observation, ...changes });
  assert.equal(grade({}).passed, true);
  assert.ok(grade({ expected: { ...expected, assertions: [] } }).diagnostics.includes('DOMAIN_EXPECTATION_MISSING'));
  assert.equal(grade({ outcome: { ...outcome, result: { word_count: 3 } } }).passed, false);
  writeFileSync(path.join(folder, 'a.conllu'), 'unexpected mutation');
  assert.ok(grade({}).diagnostics.includes('UNEXPECTED_WORKSPACE_CHANGE:a.conllu'));
}));
