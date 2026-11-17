import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { compiledSourceInventory, completedAssertionExitCode, materializeExactMutation, offlineCargoEnvironment, requireCompiledTestCases, serializeScheduledMutation, summarizeChildRun } from '../../scripts/quality/stryker-child.mjs';
import { bridgeResponse, normalizeProtectedReport, protectedTimeout, ProtectedVitestTestRunner, retainProtectedBaseline, retainHarvestedReport, scheduledMaterialization } from '../../scripts/quality/stryker-protected-runner.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';

function fixture() {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-protected-stryker-')));
  mkdirSync(path.join(root, 'tests'));
  const source = 'tests/example.test.mjs', bytes = 'immutable test source\n'; writeFileSync(path.join(root, source), bytes);
  const tests = ['same display name', 'same display name'].map(name => ({ id: `${source}#${name}`, name, fileName: path.join(root, source), status: 0, timeSpentMs: 1 }));
  return { root, source, bytes, tests, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test('baseline retention preserves exact harvested bytes and refuses identity reuse or foreign writable state', () => {
  const f = fixture();
  try {
    const bytes = Buffer.from('{"tests":["exact\\r\\nbytes"],"failed":false}\n');
    const execution = { uid: 100013, status: 0, timed_out: false, owned_descendants_cancelled: [] };
    const receipt = retainProtectedBaseline(f.root, '1', bytes, execution);
    assert.equal(receipt.result.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.equal(receipt.result.size, bytes.length);
    assert.deepEqual(readFileSync(path.join(f.root, receipt.result.path)), bytes);
    assert.deepEqual(JSON.parse(readFileSync(path.join(f.root, 'stryker-baseline-1.receipt.json'))), receipt);
    assert.throws(() => retainProtectedBaseline(f.root, '1', Buffer.from('replacement'), execution), /EEXIST/);
    assert.deepEqual(readFileSync(path.join(f.root, receipt.result.path)), bytes);
    for (const id of ['../outside', '0', '-1', '', 1, '1\n']) assert.throws(() => retainProtectedBaseline(f.root, id, bytes, execution), /retention contract/);
    assert.throws(() => retainProtectedBaseline(f.root, '2', Buffer.alloc(0), execution), /retention contract/);
    const mutation = { path: 'packages/fixture.mjs', after_sha256: 'a'.repeat(64), size: 7 };
    const compressed = retainProtectedBaseline(f.root, '2', bytes, execution, { kind: 'mutant', materialization: mutation });
    assert.match(compressed.result.path, /^stryker-mutant-2\.json\.gz$/);
    assert.deepEqual(gunzipSync(readFileSync(path.join(f.root, compressed.result.path))), bytes);
    assert.deepEqual(compressed.raw_result, { sha256: receipt.result.sha256, size: bytes.length });
    assert.deepEqual(compressed.materialization, mutation);
    assert.equal(compressed.result.sha256, createHash('sha256').update(readFileSync(path.join(f.root, compressed.result.path))).digest('hex'));
    assert.throws(() => retainProtectedBaseline(f.root, '3', bytes, execution, { kind: '../escape' }), /invocation kind/);
    if (process.platform !== 'win32') {
      chmodSync(f.root, 0o777);
      assert.throws(() => retainProtectedBaseline(f.root, '3', bytes, execution), /supervisor storage/);
      chmodSync(f.root, 0o700);
      const link = path.join(f.root, 'linked'); symlinkSync(f.root, link);
      assert.throws(() => retainProtectedBaseline(link, '2', bytes, execution), /supervisor storage/);
    }
  } finally { f.cleanup(); }
});

test('fixture compilers use a private offline Cargo home and never replace pre-existing authority', () => {
  const value = fixture();
  try {
    const environment = offlineCargoEnvironment(value.root), home = path.join(value.root, 'cargo-home');
    assert.equal(environment.CARGO_HOME, home); assert.equal(environment.CARGO_NET_OFFLINE, 'true'); assert.equal(environment.RUSTC, '/opt/mutation/rust/bin/rustc');
    const config = readFileSync(path.join(home, 'config.toml'), 'utf8');
    assert.match(config, /offline = true/); assert.match(config, /replace-with = "verified-vendor"/); assert.match(config, /directory = "\/opt\/mutation\/rust\/vendor"/);
    if (process.platform !== 'win32') { assert.equal(lstatSync(home).mode & 0o777, 0o700); assert.equal(lstatSync(path.join(home, 'config.toml')).mode & 0o777, 0o600); }
    assert.throws(() => offlineCargoEnvironment(value.root), /EEXIST/);
    assert.equal(readFileSync(path.join(home, 'config.toml'), 'utf8'), config);
  } finally { value.cleanup(); }
});

test('fractional measured timeouts round upwards without weakening the bounded wire contract', () => {
  for (const [value, expected] of [[0.01, 1], [1, 1], [2741.517, 2742], [539999.99, 540000], [540000, 540000]]) assert.equal(protectedTimeout(value), expected);
  for (const value of [0, -1, NaN, Infinity, -Infinity, 540000.01, '1000', null]) assert.throws(() => protectedTimeout(value), /execution timeout/);
});

test('compiled observations require every executed module and reject missing, foreign or conflicting file metadata',()=>{
  const root='/tmp/ud-mutation-jobs/'+'a'.repeat(32)+'/tree',entry={source:'tests/original.test.mjs',identity_sha256:'b'.repeat(64),native_hash:'c'.repeat(64)},meta={schema_version:1,normalization:'ud-job-root-and-inline-map-1',child_root:root,entries:[entry]},file=value=>({meta:{ud_agent_compiled_sources_v1:value}});
  const result=compiledSourceInventory([file(meta),file(structuredClone(meta))],root);
  assert.deepEqual(result,{...meta,entries:[entry]});requireCompiledTestCases(result,[{source:entry.source},{source:entry.source}]);
  for(const files of [[{meta:{}}],[file({...meta,child_root:'/other'})],[file(meta),file({...meta,entries:[{...entry,native_hash:'d'.repeat(64)}]})]])assert.throws(()=>compiledSourceInventory(files,root),/compiled assertion/);
  assert.throws(()=>requireCompiledTestCases(result,[{source:'tests/omitted.test.mjs'}]),/absent/);
  assert.throws(()=>requireCompiledTestCases(result,[]),/missing/);
});

test('controller protocol failures expose bounded diagnostics without accepting mismatched identities', () => {
  const encoded = value => Buffer.from(JSON.stringify(value));
  assert.deepEqual(bridgeResponse(encoded({ schema_version: 1, id: '7', execution: {} }), '7'), { schema_version: 1, id: '7', execution: {} });
  assert.throws(() => bridgeResponse(encoded({ schema_version: 1, id: null, error: 'filtered, unbounded or malformed execution options' }), '7'), /rejected its request: filtered, unbounded or malformed/);
  try { bridgeResponse(encoded({ schema_version: 1, id: null, error: 'x'.repeat(10000) }), '7'); assert.fail('malformed response accepted'); }
  catch (error) { assert.ok(error.message.length < 4200); }
  for (const value of [{ schema_version: 1, id: '8', error: 'wrong nonce' }, { schema_version: 2, id: '7' }, { schema_version: 1, id: null }, { schema_version: 1, id: '7', error: {} }]) assert.throws(() => bridgeResponse(encoded(value), '7'), /bridge/);
  assert.throws(() => bridgeResponse(encoded({ schema_version: 1, id: '7' }), undefined), /unexpected bridge/);
});

test('fresh child inventory retains duplicate display names and the exact test bytes', () => {
  const f = fixture();
  try {
    const report = summarizeChildRun({ kind: 'dry-run', result: { status: 'complete' }, tests: f.tests, errors: [[], []] }, f.root);
    assert.equal(report.result.status, 'complete'); assert.equal(report.tests.length, 2);
    assert.equal(new Set(report.tests.map(test => test.id)).size, 2);
    assert.deepEqual(report.tests.map(test => test.occurrence), [0, 1]);
    assert.equal(report.tests[0].source_sha256, createHash('sha256').update(f.bytes).digest('hex'));
    const normalized = normalizeProtectedReport(report, f.root);
    assert.equal(normalized.result.tests[0].fileName, path.join(f.root, f.source));
    assert.equal(normalized.result.tests.length, 2);
  } finally { f.cleanup(); }
});

test('only complete assertion failures become kills; runtime, skipped and collection failures stay errors', () => {
  const f = fixture();
  try {
    const tests = structuredClone(f.tests); tests[0].status = 1;
    const assertion = { name: 'AssertionError', code: 'ERR_ASSERTION', message: 'expected protected output' };
    const passed = summarizeChildRun({ kind: 'mutant', result: { status: 'killed', duration: 2 }, tests, errors: [[assertion], []] }, f.root);
    assert.equal(passed.result.status, 'killed'); assert.equal(passed.result.nrOfTests, 2);
    assert.deepEqual(passed.result.killedBy, [passed.tests[0].id]);
    assert.equal(normalizeProtectedReport(passed, f.root, passed.tests).result.status, 'killed');
    assert.equal(completedAssertionExitCode(passed, 1), 0, 'A full assertion manifest completes the protocol even when Vitest sets its test-failure exit code.');
    for (const code of [undefined, 0, 2, 126, 137]) assert.equal(completedAssertionExitCode(passed, code), code);
    for (const changed of [{ ...passed, result: { status: 'error' } }, { ...passed, result: { status: 'timeout' } }, { ...passed, result: { status: 'survived' } }, { ...passed, failures: [] }, { ...passed, outside_errors: ['unhandled rejection'] }, { ...passed, failures: [{ failure_kind: 'runtime', errors: [{ name: 'TypeError', code: 'ERR_ASSERTION' }] }] }]) assert.equal(completedAssertionExitCode(changed, 1), 1, 'An error or incomplete report must retain its failing process exit code.');
    const forged = structuredClone(passed); forged.failures[0].errors[0] = { name: 'TypeError', message: 'misclassified runtime error' };
    assert.throws(() => normalizeProtectedReport(forged, f.root, passed.tests), /assertion evidence/);
    forged.failures[0].errors[0].code = 'ERR_ASSERTION';
    assert.throws(() => normalizeProtectedReport(forged, f.root, passed.tests), /assertion evidence/);
    const globalError = structuredClone(passed); globalError.outside_errors = ['module import failed'];
    assert.throws(() => normalizeProtectedReport(globalError, f.root, passed.tests), /assertion evidence/);
    for (const errors of [[{ name: 'TypeError', message: 'unexpected runtime crash' }], [{ name: 'TypeError', code: 'ERR_ASSERTION', message: 'runtime exception with an assertion-like code' }], [{ name: 'AssertionError', code: 'ERR_MODULE_NOT_FOUND', message: 'non-assertion failure code' }], [assertion, { name: 'Error', message: 'also crashed' }], []]) {
      const report = summarizeChildRun({ kind: 'mutant', result: { status: 'killed' }, tests, errors: [errors, []] }, f.root);
      assert.equal(report.result.status, 'error');
    }
    const skipped = structuredClone(f.tests); skipped[0].status = 2;
    assert.equal(summarizeChildRun({ kind: 'mutant', result: { status: 'survived' }, tests: skipped, errors: [[], []] }, f.root).result.status, 'error');
    assert.equal(summarizeChildRun({ kind: 'mutant', result: { status: 'killed' }, tests, errors: [[assertion], []], outsideErrors: ['module collection failed'] }, f.root).result.status, 'error');
    assert.equal(summarizeChildRun({ kind: 'mutant', result: { status: 'killed' }, tests: f.tests, errors: [[], []] }, f.root).result.status, 'error');
  } finally { f.cleanup(); }
});

test('large assertion diagnostics retain fingerprints without overflowing the complete test manifest', () => {
  const f = fixture();
  try {
    const message = 'expected lossless output: λ\n'.repeat(20000), tests = structuredClone(f.tests); tests[0].status = 1; tests[0].failureMessage = message;
    const report = summarizeChildRun({ kind: 'mutant', result: { status: 'killed' }, tests, errors: [[{ name: 'AssertionError', code: 'ERR_ASSERTION', message }], []] }, f.root);
    const error = report.failures[0].errors[0], expectedHash = createHash('sha256').update(message).digest('hex');
    assert.equal(report.result.status, 'killed'); assert.equal(error.message.length, 4096); assert.equal(error.message_truncated, true);
    assert.equal(error.message_sha256, expectedHash); assert.equal(error.message_bytes, Buffer.byteLength(message));
    assert.equal(report.tests[0].failure_message_sha256, expectedHash); assert.equal(report.tests[0].failure_message_truncated, true);
    assert.equal(report.tests[0].failureMessage.length, 4096); assert.ok(Buffer.byteLength(JSON.stringify(report)) < 20000);
    assert.equal(normalizeProtectedReport(report, f.root, report.tests).result.status, 'killed');
  } finally { f.cleanup(); }
});

test('trusted parent rejects omitted tests, changed bytes, path escapes and forged kill attribution', () => {
  const f = fixture();
  try {
    const report = summarizeChildRun({ kind: 'mutant', result: { status: 'survived' }, tests: f.tests, errors: [[], []] }, f.root);
    assert.throws(() => normalizeProtectedReport({ ...report, tests: report.tests.slice(0, 1) }, f.root, report.tests), /omitted/);
    assert.throws(() => normalizeProtectedReport({ ...report, tests: [report.tests[0], report.tests[0]] }, f.root), /duplicate/);
    assert.throws(() => normalizeProtectedReport({ ...report, tests: [{ ...report.tests[0], source: '../escape' }] }, f.root), /unsafe/);
    const forged = structuredClone(report); forged.result = { status: 'killed', killedBy: ['invented'], nrOfTests: 2 };
    assert.throws(() => normalizeProtectedReport(forged, f.root), /assertion evidence/);
    writeFileSync(path.join(f.root, f.source), 'modified test');
    assert.throws(() => normalizeProtectedReport(report, f.root), /source differs/);
  } finally { f.cleanup(); }
});

test('the runner refuses execution on an ordinary host before starting a controller', async () => {
  if (process.platform === 'linux' && process.arch === 'arm64' && process.getuid?.() === 0) {
    const runner = new ProtectedVitestTestRunner({ coverageAnalysis: 'perTest', disableBail: false, incremental: true }, { debug() {} });
    await assert.rejects(runner.init(), /full nonincremental/);
  } else {
    const runner = new ProtectedVitestTestRunner({}, { debug() {} });
    await assert.rejects(runner.init(), /OCI supervisor/);
  }
});

test('materializes exactly one source-bound replacement with CRLF and Unicode intact for subprocess execution', async () => {
  const f = fixture();
  try {
    mkdirSync(path.join(f.root, 'packages'));
    const original = '// 🌲 λ\r\nexport const answer = true;\r\nexport const neighbor = true;\r\n';
    const expected = '// 🌲 λ\r\nexport const answer = false;\r\nexport const neighbor = true;\r\n';
    const location = { start: { line: 1, column: 22 }, end: { line: 1, column: 26 } };
    const definition = { tool: 'stryker', version: '10.1.1', operator: 'BooleanLiteral', location, original: 'true', replacement: 'false' };
    assert.equal(materializeExactMutation(original, definition), expected);
    writeFileSync(path.join(f.root, 'packages/source.mjs'), original);
    const options = { activeMutant: { id: '7', fileName: path.join(f.root, 'packages/source.mjs'), mutatorName: 'BooleanLiteral', location, replacement: 'false' }, sandboxFileName: path.join(f.root, 'sandbox/packages/source.mjs') };
    const hash = value => createHash('sha256').update(value).digest('hex');
    const schedule = { tool: 'stryker', tool_version: '10.1.1', mutants: [{ id: 'packages/source.mjs#7', file: 'packages/source.mjs', source_sha256: hash(original), definition, definition_sha256: hash(canonicalJson(definition)) }] };
    const changed = await scheduledMaterialization(options, schedule, f.root, path.join(f.root, 'sandbox'));
    assert.equal(Buffer.from(changed.content_base64, 'base64').toString(), expected);
    assert.equal(changed.before_sha256, hash(original)); assert.equal(changed.after_sha256, hash(expected));
    assert.equal(changed.path, 'packages/source.mjs');
    assert.throws(() => materializeExactMutation(original, { ...definition, original: 'wrong' }), /original range/);
    assert.throws(() => materializeExactMutation(original, { ...definition, location: { ...location, end: { line: 99, column: 0 } } }), /coordinates/);
    await assert.rejects(scheduledMaterialization({ ...options, activeMutant: { ...options.activeMutant, replacement: '0' } }, schedule, f.root, path.join(f.root, 'sandbox')), /pre-outcome/);
    const damaged = structuredClone(schedule); damaged.mutants[0].definition_sha256 = 'a'.repeat(64);
    await assert.rejects(scheduledMaterialization(options, damaged, f.root, path.join(f.root, 'sandbox')), /pre-outcome/);
    writeFileSync(path.join(f.root, 'packages/source.mjs'), 'stale source');
    await assert.rejects(scheduledMaterialization(options, schedule, f.root, path.join(f.root, 'sandbox')), /source hash/);
  } finally { f.cleanup(); }
});

test('the AST serializer preserves precedence, token seams, JSX expressions, templates and directives', async () => {
  const cases = [
    { source: 'export function f(a,b,c){return~(a+b)*c}', original: '~(a+b)', replacement: 'a + b', operator: 'UnaryOperator', expected: 'export function f(a,b,c){return( a + b )*c}', filename: 'source.mjs' },
    { source: '"use strict";export const value=true;', original: 'true', replacement: 'false', operator: 'BooleanLiteral', expected: '"use strict";export const value=false;', filename: 'source.mjs' },
    { source: 'export const value=<div hidden={true}/>;', original: 'true', replacement: 'false', operator: 'BooleanLiteral', expected: 'export const value=<div hidden={false}/>;', filename: 'source.jsx' },
    { source: 'export const value=tag`abc`;', original: '`abc`', replacement: '``', operator: 'StringLiteral', expected: 'export const value=tag``;', filename: 'source.mjs' },
    { source: 'export const value: boolean=true;', original: 'true', replacement: 'false', operator: 'BooleanLiteral', expected: 'export const value: boolean=false;', filename: 'source.ts' },
  ];
  for (const item of cases) {
    const start = item.source.indexOf(item.original), end = start + item.original.length;
    const definition = { tool: 'stryker', version: '10.1.1', operator: item.operator, original: item.original, replacement: item.replacement, location: { start: { line: 0, column: start }, end: { line: 0, column: end } } };
    const result = await serializeScheduledMutation(item.source, definition, item.filename);
    assert.equal(result.content, item.expected);
    assert.equal(result.materializer_version, 'stryker-ast-materializer-v1');
  }
  const source = 'export const value=<div title="abc"/>;', start = source.indexOf('"abc"');
  await assert.rejects(serializeScheduledMutation(source, { tool: 'stryker', version: '10.1.1', operator: 'StringLiteral', original: '"abc"', replacement: '""', location: { start: { line: 0, column: start }, end: { line: 0, column: start + 5 } } }, 'source.jsx'), /uniquely applicable/);
  const identical = 'export function f(){if(true)return 1;return 0;}', begin = identical.indexOf('true');
  const identity = await serializeScheduledMutation(identical, { tool: 'stryker', version: '10.1.1', operator: 'ConditionalExpression', original: 'true', replacement: 'true', location: { start: { line: 0, column: begin }, end: { line: 0, column: begin + 4 } } }, 'source.mjs');
  assert.equal(identity.content, identical, 'An upstream identical program remains executable and requires independent equivalence review; it is not a runner error or automatic kill.');
});

test('verified setup-error and malformed result bytes are retained before missing SDK evidence rejects them',()=>{
 const f=fixture(),execution={execution_id:'a'.repeat(32),uid:100013,status:1},sdk={schema_version:1,root:'/opt/mutation/node_modules',receipt_sha256:'b'.repeat(64)};
 try{
  const error={schema_version:1,child_root:'/tmp/ud-mutation-jobs/'+execution.execution_id+'/tree',result:{status:'error',errorMessage:'exact original setup fault'},tests:[],failures:[],outside_errors:[]},bytes=Buffer.from(JSON.stringify(error));
  assert.throws(()=>retainHarvestedReport(f.root,'1','selection-baseline',bytes,execution,sdk),/exact original setup fault/);assert.deepEqual(readFileSync(path.join(f.root,'stryker-baseline-1.json')),bytes);
  assert.throws(()=>retainHarvestedReport(f.root,'2','mutant',bytes,execution,sdk),/child status=error/);assert.deepEqual(gunzipSync(readFileSync(path.join(f.root,'stryker-mutant-2.json.gz'))),bytes);
  const malformed=Buffer.from('{not json');assert.throws(()=>retainHarvestedReport(f.root,'3','selection-baseline',malformed,execution,sdk),/malformed.*retained/);assert.deepEqual(readFileSync(path.join(f.root,'stryker-baseline-3.json')),malformed);
  const valid=Buffer.from(JSON.stringify({...error,assertion_sdk_context:{receipt_sha256:sdk.receipt_sha256,root:sdk.root,schema_version:1}}));assert.equal(retainHarvestedReport(f.root,'4','selection-baseline',valid,execution,sdk).report.result.status,'error');
  for(const status of ['error','timeout'])for(const code of [undefined,0,1,2,137])assert.equal(completedAssertionExitCode({result:{status}},code),code===undefined||code===0?1:code);
 }finally{f.cleanup();}
});
