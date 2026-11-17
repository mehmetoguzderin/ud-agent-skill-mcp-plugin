import { test } from 'vitest';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { captureWorkspace, gradeWorkflow } from '../../scripts/quality/workflow-grader.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-grade-'));
  const workspace = path.join(root, 'workspace');
  const artifacts = path.join(root, 'artifacts');
  mkdirSync(workspace); mkdirSync(artifacts);
  writeFileSync(path.join(workspace, 'source.conllu'), 'unchanged input\n');
  const before = captureWorkspace(workspace);
  const bytes = Buffer.from('{"finding_count":2}\n');
  writeFileSync(path.join(artifacts, 'report.json'), bytes);
  const artifact = { path: 'report.json', sha256: sha256(bytes), size: bytes.length };
  const expected = { execution_status: 'completed', passed: false,
    assertions: [{ pointer: '/result/finding_count', value: 2 }],
    artifacts: [artifact], required_tools: ['validation_report'], allowed_tools: ['validation_report'],
    allowed_writes: [], allow_network: false, allowed_processes: [] };
  const outcome = { execution: { status: 'completed' }, result: { passed: false, finding_count: 2 }, artifacts: [artifact] };
  const observation = { source: 'broker', complete: true, events: [{ type: 'tool_call', name: 'validation_report' }] };
  return { root, workspaceRoot: workspace, artifactRoot: artifacts, before, expected, outcome, observation,
    cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
function result(f, overrides = {}) { return gradeWorkflow({ ...f, ...overrides }); }

test('accepts exact observed outcomes and byte-verified artifacts', () => {
  const f = fixture();
  try {
    const grade = result(f);
    assert.equal(grade.passed, true);
    assert.deepEqual(grade.diagnostics, []);
    assert.equal(grade.coverage.workspace_files, 1);
    assert.match(grade.limitations[0], /instrumentation/);
  } finally { f.cleanup(); }
});

test('rejects wrong artifact bytes even when the report repeats the expected hash', () => {
  const f = fixture();
  try {
    writeFileSync(path.join(f.artifactRoot, 'report.json'), '{"finding_count":3}\n');
    const grade = result(f);
    assert.equal(grade.passed, false);
    assert.ok(grade.diagnostics.includes('ARTIFACT_HASH_MISMATCH:report.json'));
  } finally { f.cleanup(); }
});

test('rejects unexpected file and directory changes even with no reported write event', () => {
  const f = fixture();
  try {
    writeFileSync(path.join(f.workspaceRoot, 'source.conllu'), 'changed\n');
    mkdirSync(path.join(f.workspaceRoot, 'unreported'));
    const grade = result(f);
    assert.equal(grade.passed, false);
    assert.ok(grade.diagnostics.includes('UNEXPECTED_WORKSPACE_CHANGE:source.conllu'));
    assert.ok(grade.diagnostics.includes('UNEXPECTED_WORKSPACE_CHANGE:unreported'));
  } finally { f.cleanup(); }
});

test('rejects changed source permissions', () => {
  const f = fixture();
  const file = path.join(f.workspaceRoot, 'source.conllu');
  const original = f.before.files[0].mode;
  try {
    chmodSync(file, original ^ 0o200);
    const grade = result(f);
    assert.equal(grade.passed, false);
    assert.ok(grade.diagnostics.includes('UNEXPECTED_WORKSPACE_CHANGE:source.conllu'));
  } finally { chmodSync(file, original); f.cleanup(); }
});

test('allows an explicitly named output and rejects an uninstrumented observation', () => {
  const f = fixture();
  try {
    writeFileSync(path.join(f.workspaceRoot, 'result.txt'), 'allowed\n');
    const expected = { ...f.expected, allowed_writes: ['result.txt'] };
    const observation = { ...f.observation, events: [...f.observation.events, { type: 'file_write', path: 'result.txt' }] };
    assert.equal(result(f, { expected, observation }).passed, true);
    const missing = result(f, { expected, observation: { ...observation, complete: false } });
    assert.equal(missing.passed, false);
    assert.ok(missing.diagnostics.includes('OBSERVATION_INCOMPLETE'));
  } finally { f.cleanup(); }
});

test('rejects unapproved network, tool calls, processes, and missing required tools', () => {
  const f = fixture();
  try {
    const observation = { ...f.observation, events: [{ type: 'network' }, { type: 'tool_call', name: 'unknown' }, { type: 'process', name: 'shell' }] };
    const grade = result(f, { observation });
    for (const issue of ['UNEXPECTED_NETWORK', 'UNEXPECTED_TOOL:unknown', 'UNEXPECTED_PROCESS:shell', 'REQUIRED_TOOL_MISSING:validation_report']) assert.ok(grade.diagnostics.includes(issue));
    assert.equal(grade.passed, false);
  } finally { f.cleanup(); }
});

test('rejects incorrect execution outcome and numeric assertions', () => {
  const f = fixture();
  try {
    const outcome = { ...f.outcome, execution: { status: 'incomplete' }, result: { passed: true, finding_count: 3 } };
    const grade = result(f, { outcome });
    for (const issue of ['EXECUTION_STATUS_MISMATCH', 'DOMAIN_OUTCOME_MISMATCH', 'ASSERTION_MISMATCH:/result/finding_count']) assert.ok(grade.diagnostics.includes(issue));
  } finally { f.cleanup(); }
});

test('rejects missing baseline and unsafe artifact paths', () => {
  const f = fixture();
  try {
    const expected = { ...f.expected, artifacts: [{ path: '../outside', sha256: 'a'.repeat(64), size: 1 }] };
    const outcome = { ...f.outcome, artifacts: expected.artifacts };
    const grade = result(f, { expected, outcome, before: null });
    assert.equal(grade.passed, false);
    assert.ok(grade.diagnostics.includes('BASELINE_INVALID'));
    assert.ok(grade.diagnostics.includes('ARTIFACT_UNREADABLE:../outside'));
  } finally { f.cleanup(); }
});
