import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mutationDefinition, reconcileScheduledMutations, reconcilePythonSchedule } from '../../scripts/quality/mutation-inventory.mjs';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('scheduled mutations bind exact source text and reconcile every clean assertion outcome', () => {
  const source = 'export const add = (a, b) => a + b;\n';
  const mutant = { id: '0', mutatorName: 'ArithmeticOperator', replacement: 'a - b', location: { start: { line: 0, column: 29 }, end: { line: 0, column: 34 } } };
  const item = mutationDefinition('scripts/example.js', source, mutant);
  assert.equal(item.definition.original, 'a + b');
  const test = { id: 'tests/example.test.mjs#adds two values', source: 'tests/example.test.mjs', source_sha256: sha('test'), status: 'Success' };
  const schedule = { schema_version: 1, tool: 'stryker', tool_version: '10.1.1', tests: [test], mutants: [item] };
  const outcome = { id: '0', file: item.file, definition_sha256: item.definition_sha256, status: 'Killed', killedBy: [test.id],testsCompleted:1 };
  const failure = { mutant_id: '0', test_id: test.id, failure_kind: 'assertion',errors:[{name:'AssertionError',code:'ERR_ASSERTION',message:'expected 2'}] };
  const hashes = { [item.file]: item.source_sha256, [test.source]: test.source_sha256 };
  assert.deepEqual(reconcileScheduledMutations(schedule, [outcome], [failure], hashes), { total: 1, killed: 1, equivalent: 0, errors: [] });
  assert.match(reconcileScheduledMutations(schedule, [], [], hashes).errors.join('\n'), /no outcome/);
  assert.match(reconcileScheduledMutations(schedule, [outcome, outcome], [failure], hashes).errors.join('\n'), /duplicate/);
  assert.match(reconcileScheduledMutations(schedule, [outcome], [{ ...failure, failure_kind: 'runtime' }], hashes).errors.join('\n'), /clean structured assertion/);
  for(const errors of[[],[{name:'TypeError',code:'ERR_ASSERTION'}],[{name:'AssertionError',code:'ERR_MODULE_NOT_FOUND'}]])assert.match(reconcileScheduledMutations(schedule,[outcome],[{...failure,errors}],hashes).errors.join('\n'),/clean structured assertion/);
  for(const testsCompleted of[undefined,0,2,1.5,'1'])assert.match(reconcileScheduledMutations(schedule,[{...outcome,testsCompleted}],[failure],hashes).errors.join('\n'),/complete every independently scheduled test/);
  assert.match(reconcileScheduledMutations(schedule, [{ ...outcome, status: 'Timeout' }], [], hashes).errors.join('\n'), /Unresolved scheduled mutation Timeout/);
  assert.match(reconcileScheduledMutations({ ...schedule, mutants: [{ ...item, definition_sha256: 'f'.repeat(64) }] }, [outcome], [failure], hashes).errors.join('\n'), /Invalid or duplicate scheduled/);
  assert.throws(() => mutationDefinition('../escape', source, mutant), /source identity/);
  assert.throws(() => mutationDefinition(item.file, source, { ...mutant, location: { start: { line: 100, column: 0 }, end: { line: 100, column: 1 } } }), /exceeds/);
});


test('Python scheduling rejects missing, duplicate, stale and unscheduled definitions before accepting outcomes', () => {
  const file='scripts/example.py', id='scripts.example.x_allowed__mutmut_1', snapshot='a'.repeat(64);
  const definition={tool:'mutmut',version:'3.8.1',file,location:{line:1,end_line:2,column:0},original_function:'def allowed(x):\n return x > 2\n',replacement_function:'def allowed(x):\n return x >= 2\n',diff:'- return x > 2\n+ return x >= 2'};
  const canonical=value=>JSON.stringify(value&&typeof value==='object'?Array.isArray(value)?value.map(sort):sort(value):value);
  function sort(value){return value&&typeof value==='object'?Array.isArray(value)?value.map(sort):Object.fromEntries(Object.keys(value).sort().map(key=>[key,sort(value[key])])):value;}
  const hashes={[file]:sha('source'),'tests/test_example.py':sha('test')};
  const item={id,file,source_sha256:hashes[file],definition,definition_sha256:sha(canonical(definition))};
  const plan={tool:'mutmut',tool_version:'3.8.1',source_tree_sha256:snapshot,scheduled:1,inventory:[item],tests:[{id:'tests/test_example.py::test_allowed',source:'tests/test_example.py',source_sha256:hashes['tests/test_example.py']}]};
  const outcome={id,file,exit_code:1,type_check_error:null};
  const report={source_tree_sha256:snapshot,outcomes:[outcome]};
  const metadata={[file]:{exit_code_by_key:{[id]:1}}};
  assert.deepEqual(reconcilePythonSchedule(plan,report,metadata,hashes,snapshot),[]);
  for(const changed of [{...plan,inventory:[]},{...plan,tests:[]},{...plan,source_tree_sha256:'f'.repeat(64)},{...plan,inventory:[item,item],scheduled:2},{...plan,inventory:[{...item,definition_sha256:'f'.repeat(64)}]}]) assert.ok(reconcilePythonSchedule(changed,report,metadata,hashes,snapshot).length);
  for(const changed of [{...report,outcomes:[]},{...report,outcomes:[outcome,outcome]},{...report,outcomes:[{...outcome,exit_code:2}]},{...report,outcomes:[{...outcome,type_check_error:'compile error'}]}]) assert.ok(reconcilePythonSchedule(plan,changed,metadata,hashes,snapshot).length);
  assert.ok(reconcilePythonSchedule(plan,report,{[file]:{exit_code_by_key:{[id]:1,unscheduled:0}}},hashes,snapshot).length);
});

test('structural kills retain their count while integrity-only and unclassified assertions fail behavior certification',()=>{
 const file='packages/behavior.ts',source='export const allowed=true;',item=mutationDefinition(file,source,{id:'1',mutatorName:'BooleanLiteral',replacement:'false',location:{start:{line:0,column:21},end:{line:0,column:25}}}),testCase={id:'tests/behavior.test.mjs#original',source:'tests/behavior.test.mjs',source_sha256:'b'.repeat(64),status:'Success'},schedule={schema_version:1,tool:'stryker',tool_version:'10.1.1',mutants:[item],tests:[testCase]},outcome={file,id:'1',definition_sha256:item.definition_sha256,status:'Killed',testsCompleted:1,killedBy:[testCase.id]},failure={mutant_id:'1',test_id:testCase.id,failure_kind:'assertion',errors:[{name:'AssertionError',message:'actual original assertion'}]},hashes={[file]:item.source_sha256,[testCase.source]:testCase.source_sha256};
 for(const classification of ['source_integrity','unclassified','invalid_assertion']){
  const result=reconcileScheduledMutations(schedule,[outcome],[failure],hashes,{requireIndependentBehavior:true,assertionClassifier:()=>({classification})});
  assert.equal(result.killed,1);assert.equal(result.independent_behavior_killed,0);assert.equal(result.behavior_pending,1);assert.match(result.errors.join('\n'),/reviewed behavior/);assert.equal(result.assertion_obligations[0].definition_sha256,item.definition_sha256);
 }
 const passed=reconcileScheduledMutations(schedule,[outcome],[failure],hashes,{requireIndependentBehavior:true,assertionClassifier:(test,error,context)=>{assert.equal(test.id,testCase.id);assert.equal(context.mutant_id,item.id);assert.equal(error,failure.errors[0]);return{classification:'behavior',requirement:'independent policy decision'};}});
 assert.equal(passed.killed,1);assert.equal(passed.independent_behavior_killed,1);assert.equal(passed.behavior_pending,0);assert.deepEqual(passed.errors,[]);
 const missing=reconcileScheduledMutations(schedule,[outcome],[failure],hashes,{requireIndependentBehavior:true});assert.equal(missing.killed,1);assert.match(missing.errors.join('\n'),/authority is missing/);
 const runtime=reconcileScheduledMutations(schedule,[outcome],[{...failure,failure_kind:'runtime'}],hashes,{requireIndependentBehavior:true,assertionClassifier:()=>({classification:'behavior'})});assert.equal(runtime.killed,0);assert.equal(runtime.independent_behavior_killed,0);assert.match(runtime.errors.join('\n'),/clean structured assertion/);
});
