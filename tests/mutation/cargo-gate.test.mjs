import { afterAll, beforeAll, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { assessCargo } from '../../scripts/quality/mutation-gate.mjs';
import { nativeRustSourceParser, nativeRustCfgParser } from '../../scripts/quality/rust-native-parser.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';

const root = process.cwd(), temporary = mkdtempSync(path.join(os.tmpdir(), 'ud-cargo-gate-'));
const digest = value => createHash('sha256').update(value).digest('hex');
const suffix = process.platform === 'win32' ? '.exe' : '';
const parser = path.join(temporary, 'private-original-parser' + suffix);
let parseSource;
beforeAll(() => {
  const args = ['build', '--locked', '--manifest-path', path.join(root, 'scripts/quality/rust-assertion-parser/Cargo.toml'), '--target-dir', path.join(temporary, 'target')];
  const sdkVendor = '/opt/mutation/rust/vendor';
  const vendor = existsSync(sdkVendor) ? sdkVendor : path.join(root, '.artifacts/mutation-rust-assets/export/vendor');
  if (existsSync(vendor)) args.push('--offline', '--config', 'source.crates-io.replace-with="verified-vendor"', '--config', 'source.verified-vendor.directory=' + JSON.stringify(vendor));
  const result = spawnSync('cargo', args, { encoding: 'utf8', timeout: 120_000 });
  expect(result.error, result.stderr).toBeUndefined(); expect(result.status, result.stderr).toBe(0);
  cpSync(path.join(temporary, 'target/debug/ud-rust-assertion-parser' + suffix), parser);
  const inventory = Object.fromEntries(['Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/cfg_regions.rs'].map(name => { const file = 'scripts/quality/rust-assertion-parser/' + name; return [file, digest(readFileSync(path.join(root, file)))]; }));
  parseSource = nativeRustSourceParser(root, parser, inventory);
}, 120_000);
afterAll(() => rmSync(temporary, { recursive: true, force: true }));

const main = 'packages/launcher/src/main.rs', guard = 'packages/launcher/src/fs_guard.rs', integration = 'packages/launcher/tests/contracts.rs', ast = 'scripts/quality/rust-assertion-parser/src/main.rs';
const manifests = ['Cargo.toml', 'scripts/quality/rust-assertion-parser/Cargo.toml'];
const workspaceFor = file => file.startsWith('packages/launcher/') ? manifests[0] : manifests[1];
const code = {
  [main]: 'fn value()->bool{true}\nfn main(){}\n',
  [guard]: '#[cfg(test)] mod tests { #[test] fn guard(){assert!(true);} }\n',
  [integration]: '#[test] fn contract(){assert_eq!(1,2);}\n',
  [ast]: 'fn value()->bool{true}\n#[cfg(test)] mod tests { #[test] fn parse(){assert!(true);} }\n',
};
const names = { [main]: [], [guard]: ['tests::guard'], [integration]: ['contract'], [ast]: ['tests::parse'] };
const sourceRoot = '/tmp/ud-mutation-jobs/0123456789abcdef/tree';
function invocation(artifact, failed) {
  const failedName = artifact.expected_tests[0];
  const source = code[artifact.artifact_id], lines = source.split('\n'), line = lines.findIndex(value => value.includes('assert'));
  const location = artifact.artifact_id + ':' + (line + 1) + ':' + (lines[line]?.indexOf('assert') + 1);
  const log = `\nrunning ${artifact.expected_tests.length} tests\n` + artifact.expected_tests.map(name => `test ${name} ... ${failed && name === failedName ? 'FAILED' : 'ok'}\n`).join('') +
    (failed ? `\nthread '${failedName}' panicked at ${location}:\nassertion failed: false\n` : '') +
    `\ntest result: ${failed ? 'FAILED' : 'ok'}. ${artifact.expected_tests.length - Number(failed)} passed; ${Number(failed)} failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`;
  return { ...artifact, status: failed ? 101 : 0, timed_out: false, cancelled: false, owned_descendants_cancelled: false, cleanup_verified: true, log };
}
function fixture(run) {
  const directory = mkdtempSync(path.join(temporary, 'source-'));
  for (const [file, bytes] of Object.entries(code)) { mkdirSync(path.dirname(path.join(directory, file)), { recursive: true }); writeFileSync(path.join(directory, file), bytes); }
  const hashes = Object.fromEntries(Object.entries(code).map(([file, bytes]) => [file, digest(bytes)]));
  const tests = Object.entries(names).flatMap(([source, cases]) => cases.map(name => ({ id: `rust:${source}#${digest(canonicalJson([name, 0])).slice(0, 24)}`, source, source_sha256: hashes[source], name, occurrence: 0, runner: 'rust' })));
  const phase = (workspace, failed) => {
    const expected_artifacts = Object.entries(names).filter(([file]) => workspaceFor(file) === workspace).map(([artifact_id, expected_tests]) => ({ artifact_id, artifact_sha256: digest(artifact_id), expected_tests }));
    return { phase: 'Test', workspace_manifest: workspace, process_status: failed ? { Failure: 101 } : 'Success', artifacts_complete: true, compile_source_root: sourceRoot, expected_artifacts, invocations: expected_artifacts.map(artifact => invocation(artifact, failed && artifact.artifact_id === (workspace === manifests[1] ? ast : integration))) };
  };
  const build = workspace_manifest => ({ phase: 'Build', workspace_manifest, process_status: 'Success' });
  const mutants = [main, ast].map((file, index) => ({ name: file + ':1:18: replace true', file, workspace_manifest: manifests[index], replacement: 'false', span: { start: { line: 1, column: 18 }, end: { line: 1, column: 22 } } }));
  const outcomes = [{ scenario: 'Baseline', summary: 'Success', log_path: 'baseline', phase_results: manifests.flatMap(workspace => [build(workspace), phase(workspace, false)]) }, ...mutants.map((mutant, index) => ({ scenario: { Mutant: mutant }, summary: 'CaughtMutant', log_path: 'mutant-' + index, phase_results: [build(manifests[index]), phase(manifests[index], true)] }))];
  const report = { total_mutants: mutants.length, end_time: '2026-11-09T00:00:00Z', outcomes };
  const logs = Object.fromEntries(outcomes.map(outcome => [outcome.log_path, outcome.phase_results.filter(value => value.phase === 'Test').flatMap(value => value.invocations.map(item => item.log)).join('')]));
  const grade = (context = {}) => assessCargo(mutants, report, name => logs[name], [main, ast], hashes, [], new Set(), () => null, { root: directory, parseSource, tests, ...context });
  try { return run({ grade, report, logs, tests, mutants, hashes }); } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('Cargo gate reconciles both complete workspaces against real AST assertions', () => fixture(({ grade }) => expect(grade()).toEqual({ total: 2, killed: 2, equivalent: 0, total_scheduled: 2, applicable_current: 2, killed_current: 2, equivalent_current: 0, pending_native: 0, qualification: 'passed-locally', applicability_verified: false, errors: [] })));

function nativeProof(mutants, hashes) {
  return {current_target:'aarch64-unknown-linux-gnu',proof_sha256:'a'.repeat(64),generation_sha256:'b'.repeat(64),proof:{inventory:mutants.map((mutant,index)=>({id:mutant.name,file:mutant.file,source_sha256:hashes[mutant.file],candidate_sha256:'d'.repeat(64),definition_sha256:digest(canonicalJson({tool:'cargo-mutants',version:'27.1.0',...mutant})),applicable_targets:[index===1?'aarch64-pc-windows-msvc':'aarch64-unknown-linux-gnu'],target_evidence:[{target:index===1?'aarch64-pc-windows-msvc':'aarch64-unknown-linux-gnu',mode:'test',variant:'original'}]}))}};
}
function pending(outcome,proof,index) {
  outcome.summary='PendingNativeTarget';outcome.phase_results=[];delete outcome.log_path;
  Object.assign(outcome,{source_sha256:proof.proof.inventory[index].source_sha256,definition_sha256:proof.proof.inventory[index].definition_sha256,applicability:{proof_sha256:proof.proof_sha256,generation_sha256:proof.generation_sha256,row:structuredClone(proof.proof.inventory[index])}});
}
test('native-only definitions remain in the complete union and never count as current-platform kills',()=>fixture(({grade,report,mutants,hashes})=>{
  const proof=nativeProof(mutants,hashes);pending(report.outcomes[2],proof,1);
  expect(grade({verifyApplicability:()=>proof})).toMatchObject({total_scheduled:2,applicable_current:1,killed_current:1,equivalent_current:0,pending_native:1,qualification:'pending-native',applicability_verified:true,errors:[]});
  expect(grade().errors).toContainEqual(expect.stringContaining('PendingNativeTarget'));
}));
test('pending-native cannot waive a current row, incomplete baseline, executed foreign row or altered proof',()=>fixture(({grade,report,mutants,hashes})=>{
  const proof=nativeProof(mutants,hashes),original=structuredClone(report.outcomes);
  pending(report.outcomes[1],proof,0);expect(grade({verifyApplicability:()=>proof}).errors.length).toBeGreaterThan(0);
  report.outcomes=structuredClone(original);pending(report.outcomes[2],proof,1);
  report.outcomes[0].summary='Failure';expect(grade({verifyApplicability:()=>proof}).pending_native).toBe(0);
  report.outcomes[0]=structuredClone(original[0]);report.outcomes[2].phase_results=[original[2].phase_results[0]];expect(grade({verifyApplicability:()=>proof}).pending_native).toBe(0);
  report.outcomes[2].phase_results=[];report.outcomes[2].applicability.row.applicable_targets=['aarch64-apple-darwin'];expect(grade({verifyApplicability:()=>proof}).pending_native).toBe(0);
  report.outcomes=structuredClone(original);expect(grade({verifyApplicability:()=>proof}).errors).toContainEqual(expect.stringContaining('foreign-target row'));
  expect(grade({verifyApplicability:()=>{throw new Error('stale compiler');}}).errors).toContainEqual(expect.stringContaining('independently replayed authority'));
}));

test('Cargo gate rejects omitted workspaces, omitted tests and duplicate phase claims', () => fixture(({ grade, report, tests }) => {
  const original = structuredClone(report.outcomes[0].phase_results);
  report.outcomes[0].phase_results = original.slice(0, 2); expect(grade().errors).toContainEqual(expect.stringContaining('baseline lacks complete'));
  report.outcomes[0].phase_results = [...original.slice(0, 2), ...original.slice(0, 2)]; expect(grade().errors).toContainEqual(expect.stringContaining('baseline lacks complete'));
  report.outcomes[0].phase_results = original;
  tests.pop(); expect(grade().errors).toContainEqual(expect.stringContaining('baseline lacks complete'));
}));

test('Cargo gate never masks another artifact crash, ignored test or altered aggregate log', () => fixture(({ grade, report, logs }) => {
  const phase = report.outcomes[1].phase_results[1], original = structuredClone(phase);
  phase.invocations[0].status = 125; expect(grade().killed).toBe(1);
  Object.assign(phase, structuredClone(original)); phase.invocations[1].log = phase.invocations[1].log.replace('0 ignored', '1 ignored'); expect(grade().killed).toBe(1);
  Object.assign(phase, structuredClone(original)); logs['mutant-0'] += '\nextra runner failure\n'; expect(grade().killed).toBe(1);
}));

test('Cargo gate rejects a survivor mislabeled as a kill and substituted workspace or source span', () => fixture(({ grade, report, mutants }) => {
  report.outcomes[1].phase_results[1].process_status = 'Success'; expect(grade().killed).toBe(1);
  mutants[1].workspace_manifest = manifests[0]; expect(grade().killed).toBe(0);
}));

test('malformed phase and artifact claims reject without crashing the grader', () => fixture(({ grade, report }) => {
  const original = structuredClone(report.outcomes[1].phase_results);
  for (const value of [null, [], false, 'Test']) {
    report.outcomes[1].phase_results = [original[0], value];
    expect(grade().errors).toContainEqual(expect.stringContaining('lacks clean'));
  }
  report.outcomes[1].phase_results = original;
  original[1].expected_artifacts[0] = null;
  expect(grade().errors).toContainEqual(expect.stringContaining('lacks clean'));
  expect(assessCargo([null], report, () => '', [main], {} ).errors).toContainEqual(expect.stringContaining('missing, empty, or incomplete'));
}));

test('trusted native parser rejects source and executable changes, including cached requests', () => {
  const sourceFiles = ['Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/cfg_regions.rs'].map(name => 'scripts/quality/rust-assertion-parser/' + name);
  const inventory = Object.fromEntries(sourceFiles.map(name => [name, digest(readFileSync(path.join(root, name)))]));
  expect(() => nativeRustSourceParser(root, parser, { ...inventory, [sourceFiles[0]]: '0'.repeat(64) })).toThrow(/source differs/);
  const copied = path.join(temporary, 'private-parser' + (process.platform === 'win32' ? '.exe' : '')); cpSync(parser, copied);
  const parse = nativeRustSourceParser(root, copied, inventory);
  expect(parse(Buffer.from('#[test] fn one(){assert!(true);}'), true).tests).toEqual(['one']);
  writeFileSync(copied, Buffer.concat([readFileSync(copied), Buffer.from('\n')]));
  expect(() => parse(Buffer.from('#[test] fn one(){assert!(true);}'), true)).toThrow(/executable changed/);
});

test('native cfg mode requires the fourth source and rechecks its executable on cached input',()=>{
  const sourceFiles=['Cargo.toml','Cargo.lock','src/main.rs','src/cfg_regions.rs'].map(name=>'scripts/quality/rust-assertion-parser/'+name);
  const inventory=Object.fromEntries(sourceFiles.map(name=>[name,digest(readFileSync(path.join(root,name)))]));
  const omitted={...inventory};delete omitted[sourceFiles[3]];
  expect(()=>nativeRustCfgParser(root,parser,omitted)).toThrow(/source differs/);
  const copied=path.join(temporary,'private-cfg-parser'+suffix);cpSync(parser,copied);
  const parse=nativeRustCfgParser(root,copied,inventory),source=Buffer.from('#[cfg(windows)] fn one(){}');
  const result=parse(source);expect(result.regions).toHaveLength(1);expect(result.regions[0].predicate.items[0].items[1]).toEqual({kind:'flag',name:'windows'});
  writeFileSync(copied,Buffer.concat([readFileSync(copied),Buffer.from('\n')]));
  expect(()=>parse(source)).toThrow(/executable changed/);
});
