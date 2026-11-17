import { test, expect } from 'vitest';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { availableOriginalCandidate } from '../fixtures/available-original-candidate.mjs';
import { mutationGateOptions, prepareMutationBaseline, recheckMutationCandidate, runMutationGate, verifyMutationOriginalBaseline } from '../../scripts/quality/mutation-gate.mjs';

function fixture(action) {
  const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-mutation-candidate-'))), source = path.join(base, 'source'), candidateRoot = path.join(base, 'candidate'), snapshot = path.join(base, 'execution-copy'), runDir = path.join(base, 'run');
  mkdirSync(path.join(source, 'tests'), { recursive: true });
  writeFileSync(path.join(source, 'tests/original.test.mjs'), '// Original collection fixture; no real execution claims.\n');
  try {
    const held = availableOriginalCandidate(source, candidateRoot);
    cpSync(source, snapshot, { recursive: true }); mkdirSync(runDir);
    action({ ...held, snapshot, runDir });
  } finally { rmSync(base, { recursive: true, force: true }); }
}

test('candidate-bound gate requires an explicitly sealed full session while legacy source diagnostics remain available', async () => {
  expect(mutationGateOptions([])).toEqual({});
  expect(mutationGateOptions(['--preflight'])).toEqual({ preflightOnly: true });
  expect(mutationGateOptions(['--backend', 'python'])).toEqual({ backend: 'python' });
  expect(mutationGateOptions(['--candidate', '/candidate.json', '--candidate-root', '/artifacts', '--session', '/sealed'])).toEqual({ candidatePath: '/candidate.json', candidateRoot: '/artifacts', sessionDirectory: '/sealed' });
  for (const args of [
    ['--candidate', '/candidate.json'], ['--candidate-root', '/artifacts'],
    ['--candidate', '/candidate.json', '--session', '/sealed', '--backend', 'python'],
    ['--candidate', '/candidate.json', '--session', '/sealed', '--preflight'],
    ['--session', '/first', '--session', '/second'], ['--candidate'], ['--other', 'value'],
  ]) expect(() => mutationGateOptions(args)).toThrow();
  // Refuse before creating a run, collecting tests or executing a backend.
  await expect(runMutationGate('/nonexistent-source', { candidate: {} })).rejects.toThrow(/explicitly sealed complete session/);
  await expect(runMutationGate('/nonexistent-source', { candidateRoot: '/artifacts' })).rejects.toThrow(/requires a candidate manifest/);
});

test('one candidate-bound original profile replaces the legacy baseline and keeps artifacts outside the writable source copy', () => fixture(({ sourceRoot, candidateRoot, manifest, snapshot, runDir }) => {
  const baseline = prepareMutationBaseline(sourceRoot, snapshot, runDir, { candidate: manifest, candidateRoot, python: '/locked/python', cargo: '/locked/cargo' });
  expect(baseline.args).toEqual([path.join(snapshot, 'scripts/quality/original-acceptance.mjs'), '--output', path.join(runDir, 'original-baseline'), '--python', '/locked/python', '--cargo', '/locked/cargo', '--candidate', path.join(runDir, 'candidate-manifest.json'), '--candidate-root', candidateRoot]);
  expect(baseline.args).not.toContain('scripts/quality/test.mjs');
  expect(JSON.parse(readFileSync(path.join(runDir, 'candidate-manifest.json')))).toEqual(manifest);
  expect(baseline.binding.subjects.source_tree_sha256).toBe(manifest.source_tree_sha256);
  expect(baseline.binding.qualification).toBe('available-target-original-candidate-byte-bindings-only');
  expect(baseline.binding.acceptance_eligible).toBe(false);
  expect(baseline.binding.production_ready).toBe(false);
  expect(baseline.binding.candidate_bindings.source_replay_performed).toBe(false);
  expect(baseline.binding.candidate_bindings.source_replay_required).toBe(true);
  expect(() => recheckMutationCandidate(sourceRoot, baseline)).not.toThrow();
}));

test('source-only baseline keeps failed producer diagnostics after its execution source is removed', () => fixture(({ sourceRoot, snapshot, runDir }) => {
  const producer = path.join(snapshot, 'scripts/quality/original-acceptance.mjs');
  mkdirSync(path.dirname(producer), { recursive: true });
  // This failing producer models diagnostic transport, never acceptance.
  writeFileSync(producer, `import {mkdirSync,writeFileSync} from 'node:fs';import path from 'node:path';
const args=process.argv.slice(2),output=args[args.indexOf('--output')+1];
mkdirSync(output,{recursive:false});
writeFileSync(path.join(output,'report.json'),JSON.stringify({status:'failed-or-incomplete'}));
writeFileSync(path.join(output,'python-6.stdout'),'collected original cases');
writeFileSync(path.join(output,'python-6.stderr'),'original assertion failed');
process.exitCode=1;\n`);
  const python = path.join(snapshot, 'selected-python'), cargo = path.join(snapshot, 'selected-cargo');
  const baseline = prepareMutationBaseline(sourceRoot, snapshot, runDir, { python, cargo });
  const original = [producer, '--output', path.join(runDir, 'original-baseline'), '--python', python, '--cargo', cargo];
  expect(baseline.program).toBe(process.platform === 'win32' ? python : process.execPath);
  expect(baseline.args).toEqual(process.platform === 'win32' ? ['-I', '-B', path.join(snapshot, 'scripts/quality/windows-original-token.py'), '--cwd', snapshot, '--', process.execPath, ...original] : original);
  // Exercise the producer argument boundary on every native host. The Windows
  // token wrapper has its own native process/ownership tests.
  const result = spawnSync(process.execPath, baseline.args.slice(baseline.args.indexOf(producer)), { cwd: snapshot, encoding: 'utf8', timeout: 10000 });
  expect(result.status, result.stderr).toBe(1); expect(result.error).toBeUndefined();
  rmSync(snapshot, { recursive: true }); expect(existsSync(snapshot)).toBe(false);
  expect(JSON.parse(readFileSync(path.join(baseline.reportDirectory, 'report.json'), 'utf8')).status).toBe('failed-or-incomplete');
  expect(readFileSync(path.join(baseline.reportDirectory, 'python-6.stdout'), 'utf8')).toBe('collected original cases');
  expect(readFileSync(path.join(baseline.reportDirectory, 'python-6.stderr'), 'utf8')).toBe('original assertion failed');
}));

test('baseline admission and final recheck refuse missing roots, changed source, changed installed bytes and changed candidate manifests', () => fixture(({ sourceRoot, candidateRoot, manifest, snapshot, runDir }) => {
  expect(() => prepareMutationBaseline(sourceRoot, snapshot, runDir, { candidate: manifest })).toThrow(/explicit absolute candidate root/);
  const baseline = prepareMutationBaseline(sourceRoot, snapshot, runDir, { candidate: manifest, candidateRoot });
  for (const filename of [path.join(sourceRoot, 'tests/original.test.mjs'), path.join(candidateRoot, manifest.artifacts.find(row => row.id === 'npm').path), path.join(candidateRoot, 'native-installation/RELEASE-CANDIDATE.md'), path.join(candidateRoot, 'available-candidate.json')]) {
    const before = readFileSync(filename); writeFileSync(filename, 'tampered');
    expect(() => recheckMutationCandidate(sourceRoot, baseline)).toThrow();
    writeFileSync(filename, before);
  }
  writeFileSync(path.join(snapshot, 'tests/original.test.mjs'), '// Different actual execution source.\n');
  expect(() => prepareMutationBaseline(sourceRoot, snapshot, runDir, { candidate: manifest, candidateRoot })).toThrow(/snapshot differs/);
}));

test('legacy local artifact roots remain explicit when the baseline executes from a temporary source copy', () => fixture(({ sourceRoot, manifest, snapshot, runDir }) => {
  // .artifacts is outside the source receipt and intentionally absent from the
  // execution copy; resolution must stay at the original artifact root.
  mkdirSync(path.join(sourceRoot, '.artifacts')); writeFileSync(path.join(sourceRoot, '.artifacts/local.bin'), 'local fixture');
  const candidate = { schema_version: 1, status: 'local_candidate', production_ready: false, source_tree_sha256: manifest.source_tree_sha256, runtime_lock_sha256: manifest.runtime_lock_sha256, artifacts: [{ id: 'local', ...fileReceipt(sourceRoot, '.artifacts/local.bin') }] };
  const baseline = prepareMutationBaseline(sourceRoot, snapshot, runDir, { candidate });
  expect(baseline.args.slice(-2)).toEqual(['--candidate-root', sourceRoot]);
  expect(baseline.binding.qualification).toBe('local-original-candidate-byte-bindings-only');
  expect(() => recheckMutationCandidate(sourceRoot, baseline)).not.toThrow();
}));

// These synthetic records calibrate the consumer. They are not retained as
// execution evidence and never run a mutant or invoke the original producer.
function recordedBaseline(baseline) {
  mkdirSync(baseline.reportDirectory);
  const tests = [{ id: 'original-1', status: 'passed' }];
  const evidence = { suite_id: 'unit', verdict: 'passed', executed: 1, skipped: 0, errors: 0, tests, ...baseline.binding.subjects, candidate_binding: structuredClone(baseline.binding) };
  const report = { kind: 'original-test-acceptance', status: 'passed-locally', suite_id: 'unit', source_tree_sha256: baseline.binding.subjects.source_tree_sha256, source_unchanged: true, executed: 1, scheduled: 1, skipped: 0, tests: structuredClone(tests), candidate_binding: structuredClone(baseline.binding) };
  const write = (next = report, proof = evidence) => {
    writeFileSync(path.join(baseline.reportDirectory, 'unit-evidence.unsigned.json'), JSON.stringify(proof));
    writeFileSync(path.join(baseline.reportDirectory, 'report.json'), JSON.stringify({ ...next, unsigned_evidence: fileReceipt(baseline.reportDirectory, 'unit-evidence.unsigned.json') }));
  };
  write(); return { report, evidence, write };
}

test('original baseline consumer rejects incomplete cases, foreign subjects and altered retained evidence before mutation execution', () => fixture(({ sourceRoot, candidateRoot, manifest, snapshot, runDir }) => {
  const baseline = prepareMutationBaseline(sourceRoot, snapshot, runDir, { candidate: manifest, candidateRoot }), recorded = recordedBaseline(baseline);
  expect(verifyMutationOriginalBaseline(sourceRoot, baseline)).toEqual(fileReceipt(baseline.reportDirectory, 'report.json'));
  for (const mutate of [
    row => { row.status = 'incomplete'; }, row => { row.source_unchanged = false; }, row => { row.skipped = 1; },
    row => { row.scheduled = 2; }, row => { row.tests[0].status = 'skipped'; }, row => { row.tests = []; },
    row => { row.candidate_binding.subjects.artifact_set_sha256 = '0'.repeat(64); },
  ]) {
    const altered = structuredClone(recorded.report); mutate(altered); recorded.write(altered);
    expect(() => verifyMutationOriginalBaseline(sourceRoot, baseline)).toThrow(/complete source-bound passing evidence/);
  }
  const foreign = structuredClone(recorded.evidence); foreign.artifact_set_sha256 = 'f'.repeat(64); recorded.write(recorded.report, foreign);
  expect(() => verifyMutationOriginalBaseline(sourceRoot, baseline)).toThrow(/subjects or retained evidence differ/);
  recorded.write();
  writeFileSync(path.join(baseline.reportDirectory, 'unit-evidence.unsigned.json'), 'changed');
  expect(() => verifyMutationOriginalBaseline(sourceRoot, baseline)).toThrow();
}));
