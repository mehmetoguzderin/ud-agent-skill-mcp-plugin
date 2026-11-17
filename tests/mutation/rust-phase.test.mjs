import { afterAll, beforeAll, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { rustPhaseEvidence } from '../../scripts/quality/rust-assertions.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';

const root = process.cwd(), temporary = mkdtempSync(path.join(os.tmpdir(), 'ud-rust-phase-'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const parser = path.join(temporary, 'target/debug/ud-rust-assertion-parser' + (process.platform === 'win32' ? '.exe' : ''));
const sourceRoot = '/tmp/ud-mutation-jobs/0123456789abcdef/tree';
const main = 'packages/launcher/src/main.rs', guard = 'packages/launcher/src/fs_guard.rs', integration = 'packages/launcher/tests/contracts.rs';
const integrationSource = 'fn helper(){ assert_eq!(1,2); }\n#[test] fn first(){helper();}\n#[test] fn second(){assert!(true);}\n';

beforeAll(() => {
  const vendor = existsSync('/opt/mutation/rust/vendor') ? '/opt/mutation/rust/vendor' : path.join(root, '.artifacts/mutation-rust-assets/export/vendor');
  const arguments_ = ['build', '--locked', '--manifest-path', path.join(root, 'scripts/quality/rust-assertion-parser/Cargo.toml'), '--target-dir', path.join(temporary, 'target')];
  if (existsSync(vendor)) arguments_.push('--offline', '--config', 'source.crates-io.replace-with="verified-vendor"', '--config', 'source.verified-vendor.directory=' + JSON.stringify(vendor));
  const built = spawnSync('cargo', arguments_, { encoding: 'utf8', timeout: 120_000 });
  expect(built.error, built.stderr).toBeUndefined(); expect(built.status, built.stderr).toBe(0);
}, 120_000);
afterAll(() => rmSync(temporary, { recursive: true, force: true }));

function parseSource(source, scope) {
  const parsed = spawnSync(parser, ['--source', ...(scope ? ['--test-scope'] : [])], { input: source, encoding: 'utf8', timeout: 10_000 });
  if (parsed.error || parsed.status !== 0) throw new Error('Actual AST parser rejected fixture: ' + parsed.stderr);
  return JSON.parse(parsed.stdout);
}
function summary(names, failed = [], location = 'tests/contracts.rs:1:14', message = 'assertion `left == right` failed') {
  return `\nrunning ${names.length} tests\n` + names.map(name => `test ${name} ... ${failed.includes(name) ? 'FAILED' : 'ok'}\n`).join('') +
    (failed.length ? failed.map(name => `\nthread '${name}' panicked at ${location}:\n${message}\n`).join('') : '') +
    `\ntest result: ${failed.length ? 'FAILED' : 'ok'}. ${names.length - failed.length} passed; ${failed.length} failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`;
}
function fixture(run) {
  const directory = mkdtempSync(path.join(temporary, 'source-'));
  for (const [name, source] of [[main, 'fn main(){}\n'], [guard, '#[cfg(test)] mod tests { #[test] fn inner(){ assert!(true); } }\n'], [integration, integrationSource]]) {
    mkdirSync(path.dirname(path.join(directory, name)), { recursive: true }); writeFileSync(path.join(directory, name), source);
  }
  const artifacts = [[main, []], [guard, ['tests::inner']], [integration, ['first', 'second']]].map(([artifact_id, expected_tests]) => ({ artifact_id, artifact_sha256: digest(artifact_id), expected_tests }));
  const phase = { artifacts_complete: true, compile_source_root: sourceRoot, expected_artifacts: artifacts, invocations: artifacts.map(artifact => ({ ...artifact, status: artifact.artifact_id === integration ? 101 : 0, timed_out: false, cancelled: false, owned_descendants_cancelled: false, cleanup_verified: true, log: summary(artifact.expected_tests, artifact.artifact_id === integration ? ['first'] : []) })) };
  try { return run(directory, phase); } finally { rmSync(directory, { recursive: true, force: true }); }
}
const grade = (directory, phase, item = null) => rustPhaseEvidence(directory, item, phase, { parseSource });

test('actual AST source sites and all required artifacts bind a clean assertion kill', () => fixture((directory, phase) => {
  const result = grade(directory, phase);
  expect(result.artifacts_complete).toBe(true); expect(result.valid).toBe(true);
  expect(result.failures).toEqual([expect.objectContaining({ test: 'first', source: integration, line: 1, column: 14, macro: 'assert_eq', source_sha256: digest(integrationSource) })]);
  for (const location of [integration + ':1:14', sourceRoot + '/' + integration + ':1:14']) {
    const changed = structuredClone(phase); changed.invocations[2].log = summary(['first', 'second'], ['first'], location);
    expect(grade(directory, changed).valid).toBe(true);
  }
}));

test('baseline and surviving mutants require complete execution while no failure is not a kill', () => fixture((directory, phase) => {
  phase.invocations[2].status = 0; phase.invocations[2].log = summary(['first', 'second']);
  expect(grade(directory, phase)).toEqual(expect.objectContaining({ artifacts_complete: true, valid: false, failures: [] }));
}));

test('malformed native JSON identities fail closed without coercion or a baseline fallback', () => fixture((directory, phase) => {
  for (const item of [false, 0, '', [], {}, { file: integration, source_sha256: { toString: null }, definition_sha256: 'f'.repeat(64) }]) expect(grade(directory, phase, item).artifacts_complete).toBe(false);
  for (const key of ['artifact_id','artifact_sha256']) { const changed = structuredClone(phase); changed.expected_artifacts[0][key] = { toString: null }; expect(grade(directory, changed).artifacts_complete).toBe(false); }
}));

test('a clean assertion cannot hide another artifact crash, timeout, cancellation or missing invocation', () => fixture((directory, phase) => {
  for (const patch of [{ status: 125 }, { status: 137 }, { status: null }, { timed_out: true }, { cancelled: true }, { owned_descendants_cancelled: true }, { cleanup_verified: false }, { artifact_sha256: 'f'.repeat(64) }]) {
    const changed = structuredClone(phase); Object.assign(changed.invocations[0], patch);
    expect(grade(directory, changed).artifacts_complete, JSON.stringify(patch)).toBe(false);
  }
  for (const edit of [changed => changed.invocations.pop(), changed => changed.invocations.push(changed.invocations[0]), changed => { changed.invocations[0] = changed.invocations[1]; }, changed => { changed.expected_artifacts.pop(); changed.invocations.pop(); }]) {
    const changed = structuredClone(phase); edit(changed); expect(grade(directory, changed).artifacts_complete).toBe(false);
  }
}));

test('filtered, ignored, duplicate, extra, absent and inconsistent libtest outcomes cannot pass', () => fixture((directory, phase) => {
  const log = phase.invocations[2].log;
  const corrupt = [log.replace('0 filtered out', '1 filtered out'), log.replace('0 ignored', '1 ignored'), log.replace('second ... ok', 'second ... ignored'), log.replace('second ... ok', 'first ... ok'), log.replace('second ... ok', 'unknown ... ok'), log.replace('test second ... ok\n', ''), log + 'test second ... ok\n', log.replace('1 passed; 1 failed', '0 passed; 2 failed'), log.replace('running 2 tests', 'running 3 tests'), log.replace(/^test result:.*$/m, ''), log + log];
  for (const changedLog of corrupt) { const changed = structuredClone(phase); changed.invocations[2].log = changedLog; expect(grade(directory, changed).artifacts_complete).toBe(false); }
  const early = structuredClone(phase); early.invocations[2].status = 0; early.invocations[2].log = summary(['first']); expect(grade(directory, early).artifacts_complete).toBe(false);
}));

test('forged names, nonexistent files, production assertions, strings and arbitrary absolute paths fail AST binding', () => fixture((directory, phase) => {
  for (const location of ['nonexistent.rs:1:14', '/foreign/' + integration + ':1:14', 'tests/contracts.rs:2:14', 'tests/contracts.rs:1:15', '../tests/contracts.rs:1:14']) {
    const changed = structuredClone(phase); changed.invocations[2].log = summary(['first', 'second'], ['first'], location); expect(grade(directory, changed).artifacts_complete, location).toBe(false);
  }
  const forged = structuredClone(phase); forged.expected_artifacts[2].expected_tests = ['forged', 'second']; forged.invocations[2].expected_tests = ['forged', 'second']; forged.invocations[2].log = summary(['forged', 'second'], ['forged']); expect(grade(directory, forged).artifacts_complete).toBe(false);
  writeFileSync(path.join(directory, main), 'fn main(){assert!(false);}\n');
  const production = structuredClone(phase); production.invocations[2].log = summary(['first', 'second'], ['first'], 'src/main.rs:1:11'); expect(grade(directory, production).artifacts_complete).toBe(false);
  writeFileSync(path.join(directory, integration), integrationSource.replace('assert_eq!(1,2)', 'let _ = "assert_eq!(1,2)"'));
  expect(grade(directory, phase).artifacts_complete).toBe(false);
}));

test('runtime panic messages remain failures even alongside a real test assertion', () => fixture((directory, phase) => {
  for (const message of ['index out of bounds: the len is 0 but the index is 1', 'called `Option::unwrap()` on a `None` value', 'synthetic runtime failure']) {
    const changed = structuredClone(phase); changed.invocations[2].log = summary(['first', 'second'], ['first'], 'tests/contracts.rs:1:14', message); expect(grade(directory, changed).artifacts_complete).toBe(false);
  }
  const mixed = structuredClone(phase); mixed.invocations[2].log += "\nthread 'second' panicked at tests/contracts.rs:3:21:\nindex out of bounds\n"; expect(grade(directory, mixed).artifacts_complete).toBe(false);
}));

test('Rust explicit paths beside non-mod-rs files and beneath inline modules resolve to exact owned sources', () => fixture((directory, phase) => {
  writeFileSync(path.join(directory, guard), 'mod stream;\n');
  writeFileSync(path.join(directory, 'packages/launcher/src/stream.rs'), '#[path="stream_impl.rs"] mod native;\nmod inline { #[path="other.rs"] mod child; }\n');
  writeFileSync(path.join(directory, 'packages/launcher/src/stream_impl.rs'), '#[cfg(test)] mod tests { #[test] fn native(){ assert!(true); } }\n');
  mkdirSync(path.join(directory, 'packages/launcher/src/stream/inline'), { recursive: true });
  writeFileSync(path.join(directory, 'packages/launcher/src/stream/inline/other.rs'), '#[cfg(test)] mod tests { #[test] fn nested(){ assert_ne!(1,2); } }\n');
  const names = ['stream::native::tests::native', 'stream::inline::child::tests::nested'];
  // Compile only this authored, unmutated fixture to independently establish
  // Rust's module resolution and actual libtest names; no variant executes.
  const executable = path.join(directory, 'original-module-fixture' + (process.platform === 'win32' ? '.exe' : ''));
  const compiled = spawnSync('rustc', ['--test', path.join(directory, guard), '--edition=2024', '-o', executable], { encoding: 'utf8', timeout: 15_000 });
  expect(compiled.error, compiled.stderr).toBeUndefined(); expect(compiled.status, compiled.stderr).toBe(0);
  const listed = spawnSync(executable, ['--list', '--format', 'terse'], { encoding: 'utf8', timeout: 5000 });
  expect(listed.status, listed.stderr).toBe(0); expect(listed.stdout.trim().split(/\r?\n/).map(line => line.replace(/: test$/, '')).sort()).toEqual([...names].sort());
  phase.expected_artifacts[1].expected_tests = names; phase.invocations[1].expected_tests = names; phase.invocations[1].log = summary(names);
  expect(grade(directory, phase).valid).toBe(true);
  rmSync(path.join(directory,'packages/launcher/src/stream_impl.rs')); // A similarly named stem-dir file cannot substitute for an explicit sibling.
  writeFileSync(path.join(directory,'packages/launcher/src/stream/stream_impl.rs'),'#[test] fn native(){}\n');
  expect(grade(directory,phase).artifacts_complete).toBe(false);
}));

test('original compiler locates custom assertions separately from operand, tracked-call and formatter panics', () => {
  const cases = [
    ['legitimate', '#[test] fn first(){ assert!(false,"specific independent invariant {}",7); }\n', true],
    ['condition-unwrap', '#[test] fn first(){ assert!(None::<bool>.unwrap(),"unreachable"); }\n', false],
    ['tracked-operand', '#[track_caller] fn operand()->bool {panic!("assertion failed: tracked operand");}\n#[test] fn first(){ assert!(operand(),"unreachable"); }\n', false],
    ['formatter', 'struct Bad; impl std::fmt::Display for Bad { fn fmt(&self,_:&mut std::fmt::Formatter)->std::fmt::Result {panic!("assertion failed: formatter");} }\n#[test] fn first(){ assert!(false,"{}",Bad); }\n', false],
    ['format-argument', 'struct Bad; impl std::fmt::Display for Bad { fn fmt(&self,_:&mut std::fmt::Formatter)->std::fmt::Result {panic!("assertion failed: formatter");} }\n#[test] fn first(){ assert!(false,"{}",format!("{}",Bad)); }\n', false],
    ['tracked-format-argument', '#[track_caller] fn argument()->i32 {panic!("assertion failed: format argument");}\n#[test] fn first(){ assert!(false,"{}",argument()); }\n', false],
    ['forged-message', '#[test] fn first(){ panic!("assertion failed: forged runtime"); }\n', false],
  ];
  for (const [name, source, expected] of cases) fixture((directory, phase) => {
    writeFileSync(path.join(directory,integration),source);
    const executable=path.join(directory,'original-'+name+(process.platform==='win32'?'.exe':''));
    const compiled=spawnSync('rustc',['--test',path.join(directory,integration),'--edition=2024','-o',executable],{encoding:'utf8',timeout:15000});
    expect(compiled.error,compiled.stderr).toBeUndefined();expect(compiled.status,compiled.stderr).toBe(0);
    const executed=spawnSync(executable,['--test-threads=1'],{encoding:'utf8',timeout:5000});
    expect(executed.error,name).toBeUndefined();
    if(name==='formatter')expect(executed.signal!==null||executed.status!==0).toBe(true); // Panic while formatting a panic may abort.
    else expect(executed.status,name).toBe(101);
    phase.expected_artifacts[2].expected_tests=['first'];phase.invocations[2].expected_tests=['first'];
    phase.invocations[2].status=executed.status??-1;
    const nativeLocation=path.join(directory,integration);
    phase.invocations[2].log=(executed.stdout+executed.stderr).replaceAll(nativeLocation,sourceRoot+'/'+integration);
    expect(grade(directory,phase).valid,name).toBe(expected);
  });
},30000);

test('candidate reconstruction accounts for shifted inline test assertion lines and rejects stale definitions', () => fixture((directory, phase) => {
  const before = 'fn ordinary() -> bool {\n true\n}\n#[cfg(test)] mod tests {\n #[test] fn inner(){ assert!(true); }\n}\n';
  writeFileSync(path.join(directory, guard), before);
  const definition = { tool: 'cargo-mutants', version: '27.1.0', file: guard, replacement: 'false', span: { start: { line: 1, column: 24 }, end: { line: 3, column: 1 } } };
  const item = { file: guard, source_sha256: digest(before), definition, definition_sha256: digest(canonicalJson(definition)) };
  // The replacement removes two line breaks; the immutable test moves 5->3.
  phase.invocations[1].status = 101; phase.invocations[1].log = summary(['tests::inner'], ['tests::inner'], 'src/fs_guard.rs:3:22', 'assertion failed: true');
  expect(grade(directory, phase, item).valid).toBe(true);
  const stale = structuredClone(phase); stale.invocations[1].log = stale.invocations[1].log.replace(':3:22', ':5:22'); expect(grade(directory, stale, item).artifacts_complete).toBe(false);
  for (const changed of [{ ...item, source_sha256: 'f'.repeat(64) }, { ...item, definition_sha256: 'a'.repeat(64) }, { ...item, definition: { ...definition, replacement: 'true' } }]) expect(grade(directory, phase, changed).artifacts_complete).toBe(false);
}));

test('parser workspace grading discovers its test declarations without product artifact substitution', () => fixture((directory) => {
  const artifact_id = 'scripts/quality/rust-assertion-parser/src/main.rs'; mkdirSync(path.dirname(path.join(directory, artifact_id)), { recursive: true }); writeFileSync(path.join(directory, artifact_id), '#[cfg(test)] mod tests { #[test] fn original(){ assert!(true); } }\n');
  const artifact = { artifact_id, artifact_sha256: 'a'.repeat(64), expected_tests: ['tests::original'] };
  const phase = { artifacts_complete: true, compile_source_root: sourceRoot, expected_artifacts: [artifact], invocations: [{ ...artifact, status: 0, timed_out: false, cancelled: false, owned_descendants_cancelled: false, cleanup_verified: true, log: summary(artifact.expected_tests) }] };
  expect(grade(directory, phase)).toEqual(expect.objectContaining({ artifacts_complete: true, valid: false }));
  phase.expected_artifacts[0].expected_tests = []; phase.invocations[0].expected_tests = []; phase.invocations[0].log = summary([]); expect(grade(directory, phase).artifacts_complete).toBe(false);
}));

test('parser workspace requires its own complete artifacts and module assertion inventory', () => fixture((directory) => {
  const prefix = 'scripts/quality/rust-assertion-parser';
  const mainId = prefix + '/src/main.rs', testId = prefix + '/tests/boundary.rs';
  for (const [name, content] of [[mainId, 'mod windows_policy; fn main(){}\n'], [prefix + '/src/windows_policy.rs', '#[cfg(test)] mod tests { #[test] fn bounded(){assert!(false,"bound violated");} }\n'], [testId, '#[test] fn protocol(){assert_eq!(1,1);}\n']]) {
    mkdirSync(path.dirname(path.join(directory,name)),{recursive:true});writeFileSync(path.join(directory,name),content);
  }
  const artifacts = [[mainId,['windows_policy::tests::bounded']],[testId,['protocol']]].map(([artifact_id,expected_tests])=>({artifact_id,artifact_sha256:digest(artifact_id),expected_tests}));
  const phase={artifacts_complete:true,compile_source_root:sourceRoot,expected_artifacts:artifacts,invocations:artifacts.map(artifact=>({...artifact,status:artifact.artifact_id===mainId?101:0,timed_out:false,cancelled:false,owned_descendants_cancelled:false,cleanup_verified:true,log:summary(artifact.expected_tests,artifact.artifact_id===mainId?artifact.expected_tests:[],'src/windows_policy.rs:1:47','bound violated')}))};
  const accepted=grade(directory,phase);expect(accepted.artifacts_complete).toBe(true);expect(accepted.valid).toBe(true);
  expect(accepted.source_inventory).toHaveProperty(prefix+'/src/windows_policy.rs');
  const missing=structuredClone(phase);missing.expected_artifacts.pop();missing.invocations.pop();expect(grade(directory,missing).artifacts_complete).toBe(false);
  const substitute=structuredClone(phase);substitute.expected_artifacts[1].artifact_id=integration;substitute.invocations[1].artifact_id=integration;expect(grade(directory,substitute).artifacts_complete).toBe(false);
}));
