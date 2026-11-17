import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { assessCargo, assessMutmut, assessStatic, assessStryker, assessStrykerDiscovery, validateExceptions } from '../../scripts/quality/mutation-gate.mjs';
import {canonicalJson} from '../../scripts/release/http-transports.mjs';
import {mutationDefinition} from '../../scripts/quality/mutation-inventory.mjs';
import { runFaultCanaries } from './fault-runner.mjs';

const digest = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const filename = 'packages/example.ts';
const content = 'export const value = 1;';
const testFile = 'tests/example.test.ts';
const testContent = 'test source';
const hashes = { [filename]: digest(content), [testFile]: digest(testContent) };
function report(status: string, extras: Record<string, unknown> = {}) {
  return {
    config: { mutate: ['packages/**/*.{ts,tsx,mts,cts,js,mjs,cjs}', 'scripts/**/*.{ts,tsx,mts,cts,js,mjs,cjs}'],
      incremental: false, ignoreStatic: false, allowEmpty: false, inPlace: false, disableBail: true, disableTypeChecks: false,
      coverageAnalysis: 'off', thresholds: { break: 100 } },
    testFiles: { [testFile]: { source: testContent, tests: [{ id: 't1' }] } },
    files: { [filename]: { source: content, mutants: [{ id: '1', status, mutatorName:'NumericLiteral',replacement:'0',location:{start:{line:1,column:21},end:{line:1,column:22}},...extras }] } },
  };
}
function exception(tool: string, id: string, file = filename) {
  return { tool, id, file, source_sha256: hashes[file as keyof typeof hashes], author: 'implementer', reviewed_by: 'reviewer',
    reviewed_at: '2026-11-09T00:00:00Z', definition_sha256:'f'.repeat(64),review:{path:'quality/reviews/example.json',sha256:'e'.repeat(64)},proof: 'Independent proof describes equivalent observable behavior for all reachable inputs.' };
}

describe('strict mutation evidence', () => {
  it('accepts only an identified Stryker kill in a complete full-scope report', () => {
    const ok = assessStryker(report('Killed', { killedBy: ['t1'], testsCompleted: 1 }), [filename], hashes, [], new Set(), [testFile]);
    expect(ok.errors).toEqual([]);
    expect(ok.killed).toBe(1);
    expect(assessStryker(report('Killed', { killedBy: ['unknown'], testsCompleted: 1 }), [filename], hashes).errors).toContainEqual(expect.stringContaining('identified test evidence'));
    expect(assessStryker(report('Killed'), [filename], hashes).errors).toContainEqual(expect.stringContaining('identified test evidence'));
    expect(assessStryker(report('Killed', { killedBy: ['t1'], testsCompleted: 1 }), [filename, 'scripts/missing.mjs'], hashes).errors).toContainEqual(expect.stringContaining('omitted'));
    const partial = report('Killed', { killedBy: ['t1'], testsCompleted: 1 });
    partial.config.mutate = [filename];
    expect(assessStryker(partial, [filename], hashes).errors).toContainEqual(expect.stringContaining('full clean configuration'));
  });

  it('requires actual complete per-source generation to admit a zero-mutant declaration file', () => {
    const zero='packages/types.d.ts',zeroSource='export interface Empty {}\n',allHashes={...hashes,[zero]:digest(zeroSource)};
    const raw=mutationDefinition(filename,content,{id:'88',mutatorName:'NumericLiteral',replacement:'0',location:{start:{line:0,column:20},end:{line:0,column:21}}});
    const mutant={...raw,id:filename+'#'+raw.definition_sha256,raw_id:raw.id};
    const projected=({id,raw_id,source_sha256,definition_sha256}:typeof mutant)=>({id,raw_id,source_sha256,definition_sha256});
    const discovery={tool:'stryker',tool_version:'10.1.1',qualification:'complete-operator-discovery-no-outcomes',inventory_only:true,scheduled:1,source_scope:[{path:filename,source_sha256:hashes[filename]},{path:zero,source_sha256:allHashes[zero]}],mutants:[mutant],materialization:[{path:filename,source_sha256:hashes[filename],generated:1,inventory_sha256:digest(canonicalJson([projected(mutant)]))},{path:zero,source_sha256:allHashes[zero],generated:0,inventory_sha256:digest(canonicalJson([]))}]};
    const output=report('Killed',{killedBy:['t1'],testsCompleted:1});
    expect(assessStrykerDiscovery(discovery,[filename,zero],allHashes).errors).toEqual([]);
    expect(assessStryker(output,[filename,zero],allHashes,[],new Set(),[testFile],()=>null,discovery).errors).toEqual([]);
    expect(assessStryker(output,[filename,zero],allHashes).errors.length).toBeGreaterThan(0);
    for(const invalid of[{...discovery,materialization:discovery.materialization.slice(0,1)},{...discovery,source_scope:discovery.source_scope.slice(0,1)},{...discovery,mutants:[]},{...discovery,materialization:discovery.materialization.map(row=>({...row,generated:0}))}])expect(assessStrykerDiscovery(invalid,[filename,zero],allHashes).errors.length).toBeGreaterThan(0);
    const wrong=report('Killed',{killedBy:['t1'],testsCompleted:1,replacement:'2'});
    expect(assessStryker(wrong,[filename,zero],allHashes,[],new Set(),[testFile],()=>null,discovery).errors).toContainEqual(expect.stringContaining('definition differs'));
  });

  it.each(['NoCoverage', 'Timeout', 'CompileError', 'RuntimeError', 'Ignored', 'Pending'])('rejects %s even if an exception exists', status => {
    const proof = exception('stryker', `${filename}#1`);
    expect(assessStryker(report(status), [filename], hashes, [proof]).errors.length).toBeGreaterThan(0);
  });

  it('accepts a reviewed equivalent only for the exact surviving mutant and frozen source', () => {
    const definition=mutationDefinition(filename,content,{id:'1',mutatorName:'NumericLiteral',replacement:'0',location:{start:{line:0,column:20},end:{line:0,column:21}}}).definition;
    const proof = {...exception('stryker', `${filename}#1`),definition_sha256:digest(canonicalJson(definition))};
    const review=Buffer.from(JSON.stringify({reviewer:proof.reviewed_by,reviews:[{id:proof.id,equivalent:true,source_sha256:proof.source_sha256,definition_sha256:proof.definition_sha256,definition,reason:proof.proof}]}));
    proof.review.sha256=digest(review);
    const reviewedHashes={...hashes,[proof.review.path]:digest(review)};
    expect(validateExceptions({ schema_version: 1, equivalents: [proof] }).errors).toEqual([]);
    const used = new Set<string>();
    expect(assessStryker(report('Survived'), [filename], reviewedHashes, [proof], used,[],()=>review).equivalent).toBe(1);
    expect(used.size).toBe(1);
    expect(assessStryker(report('Survived'), [filename], { ...hashes, [filename]: 'a'.repeat(64) }, [proof]).errors.length).toBeGreaterThan(0);
    expect(validateExceptions({ schema_version: 1, equivalents: [{ ...proof, reviewed_by: 'implementer' }] }).errors.length).toBeGreaterThan(0);
    expect(validateExceptions({ schema_version: 1, equivalents: [{ ...proof, proof: 'equivalent' }] }).errors.length).toBeGreaterThan(0);
  });

  it('never counts pytest internal errors, unchecked mutants or absent assertions as kills', () => {
    const file = 'workers/ud/src/ud_agent/domain/a.py';
    const metadata = (code: number | null) => ({ [file]: { exit_code_by_key: { 'ud_agent.a.x_foo__mutmut_1': code } } });
    const key = 'ud_agent.a.x_foo__mutmut_1';
    const source='tests/test_rule.py', body='def test_rule():\n    assert False\n', sourceHash=digest(body), testId=source+'::test_rule';
    const plan={tests:[{id:testId,source,source_sha256:sourceHash}]};
    const origin={contract:'python-test-source-origin-v2',source,source_sha256:sourceHash,line:2,test_id:testId,test_source:source,test_source_sha256:sourceHash,test_line:2};
    const validEvent = [{ mutant: key, event: 'failure',phase:'call',assertion_contract:'python-test-source-origin-v2',exception_type:'builtins.AssertionError',nodeid:testId,assertion_origin:origin }];
    const assess=(meta:Record<string,unknown>,events:unknown[])=>assessMutmut(meta,events,[file],{[source]:sourceHash},[],new Set(),plan,()=>body);
    expect(assess(metadata(1), validEvent).killed).toBe(1);
    expect(assess(metadata(1), []).errors).toContainEqual(expect.stringContaining('lacks clean'));
    expect(assess(metadata(1), [{ mutant: key, event: 'error' }]).errors).toContainEqual(expect.stringContaining('lacks clean'));
    for(const changed of[{...validEvent[0],assertion_contract:null},{...validEvent[0],phase:'setup'},{...validEvent[0],exception_type:null}])expect(assess(metadata(1),[changed]).errors).toContainEqual(expect.stringContaining('lacks clean'));
    for (const code of [null, 0, 2, 3, 5, 33, 34, 35, 36, 37, -11]) {
      expect(assess(metadata(code), validEvent).errors.length).toBeGreaterThan(0);
    }
    expect(assess({}, []).errors).toContainEqual(expect.stringContaining('metadata missing'));
  });

  it('rejects historical Rust logs without source-bound per-artifact invocation evidence', () => {
    const file = 'packages/launcher/src/main.rs';
    const mutant = { name: `${file}:1:1: example`, file, workspace_manifest: 'Cargo.toml' };
    const baseline = { scenario: 'Baseline', log_path: 'log/baseline', summary: 'Success', phase_results: [{ phase: 'Test', process_status: 'Success' }] };
    const outcome = { scenario: { Mutant: mutant }, summary: 'CaughtMutant', log_path: 'log/a',
      phase_results: [{ phase: 'Build', process_status: 'Success' }, { phase: 'Test', process_status: { Failure: 101 } }] };
    const result = { end_time: '2026-11-09T00:00:00Z', total_mutants: 1, outcomes: [baseline, outcome] };
    const readLog = (name: string) => name === 'log/baseline' ? 'test result: ok. 1 passed; 0 failed; 0 ignored' : "thread 'tests::example' panicked at packages/launcher/src/main.rs:1:1:\nassertion `left == right` failed\ntest result: FAILED. 0 passed; 1 failed; 0 ignored";
    const ok = assessCargo([mutant], result, readLog, [file], {});
    expect(ok.errors).toContainEqual(expect.stringContaining('baseline lacks complete'));
    expect(ok.killed).toBe(0);
    expect(assessCargo([mutant], { ...result, outcomes: [baseline] }, () => '', [file], {}).errors).toContainEqual(expect.stringContaining('counts do not match'));
    expect(assessCargo([mutant], { ...result, outcomes: [baseline, { ...outcome, summary: 'Unviable' }] }, () => '', [file], {}).errors).toContainEqual(expect.stringContaining('Unviable'));
    expect(assessCargo([mutant], result, () => 'error[E0001]: syntax', [file], {}).killed).toBe(0);
    expect(assessCargo([mutant], result, name => readLog(name).replace('assertion `left == right` failed', 'called `Result::unwrap()` on an `Err` value'), [file], {}).killed).toBe(0);
  });

  it('rejects incomplete static reports and non-kill fault cases', () => {
    expect(assessStatic({ tool: 'python-static', complete: false, scheduled: 1, outcomes: [] }, {}).errors).toContainEqual(expect.stringContaining('incomplete'));
    const outcomes = runFaultCanaries({ root: '/tmp/copy', originalRoot: '/tmp/original', reportDir: '/tmp', python: '/no-python', env: {}, cases: [{ id: 'nonroot', unavailable: 'No implementation.' }] });
    expect(outcomes).toEqual([{ id: 'nonroot', status: 'Uncovered', reason: 'No implementation.' }]);
    expect(() => runFaultCanaries({ root: '/tmp/same', originalRoot: '/tmp/same', reportDir: '/tmp', python: '/no-python', env: {}, cases: [] })).toThrow('disposable');
  });
});
