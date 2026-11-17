/** Synthetic root-record fixtures; no certificate or mutant is produced. */
import {createHash} from 'node:crypto';
import {chmodSync,mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {expect,test} from 'vitest';
import {retainPristineAuthority,restorePristineAuthority} from '../../scripts/quality/stryker-baseline-authority.mjs';
import {childTestInventory,normalizeProtectedCoverage} from '../../scripts/quality/stryker-child.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
function fixture(action,{coverageEnabled=true}={}){
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-pristine-authority-'))),source=path.join(root,'source'),state=path.join(root,'state');mkdirSync(source);mkdirSync(path.join(source,'tests'));mkdirSync(state,{mode:0o700});mkdirSync(path.join(state,'control'));mkdirSync(path.join(state,'control/jobs'));
  try{
    writeFileSync(path.join(source,'tests/a.test.mjs'),"import {test} from 'vitest';test('one',()=>{});\n",{mode:0o600});
    const tests=childTestInventory([{id:'tests/a.test.mjs#one',name:'one',fileName:path.join(source,'tests/a.test.mjs'),status:0}],source),id='a'.repeat(32),sdkContext={schema_version:1,root:'/opt/mutation/node_modules',receipt_sha256:'b'.repeat(64)},sourceTreeSha256='c'.repeat(64);
    const opacity={schema_version:1,contract:'pristine-subprocess-opacity-source-v1',files:[{source:tests[0].source,source_sha256:tests[0].source_sha256,case_tasks:[{native_id:'native-case',case_id:tests[0].id}],observations:{schema_version:1,contract:'pristine-subprocess-opacity-v1',qualification:'entrypoint-observations-not-unique-process-counts',complete:true,calls:0,uncertainties:[],records:[]}}]};
    const coverage=normalizeProtectedCoverage({perTest:{[tests[0].upstream_id]:{'1':1}},static:{}},tests,{},opacity),childRoot=`/tmp/ud-mutation-jobs/${id}/tree`,program=readFileSync(path.join(source,'tests/a.test.mjs'),'utf8');
    // Synthetic source/transport data, independently replayed against the exact
    // original bytes. This is not an actual compiled-job or mutation receipt.
    const compiled={schema_version:1,normalization:'ud-job-root-and-inline-map-1',child_root:childRoot,entries:[{source:tests[0].source,source_sha256:sha(program),native_hash:sha(program),compiled_sha256:sha(program),identity_sha256:sha(JSON.stringify([program,null])),source_map_sha256:null,compiled_source:program}]};
    const report={schema_version:1,child_root:childRoot,result:{status:'complete',tests,...(coverageEnabled?{mutantCoverage:coverage}:{})},tests,failures:[],outside_errors:[],subprocess_opacity:opacity,assertion_sdk_context:sdkContext,assertion_compiled_sources:compiled},data=Buffer.from(JSON.stringify(report));
    const actual={qualification:'protected-exec',collected:true,uid:100001,status:0,timed_out:false,owned_descendants_cancelled:[],execution_id:id,command:['/opt/mutation/node/bin/node','/opt/mutation/harness/stryker-child.mjs',`/tmp/ud-mutation-jobs/${id}/request.json`,`/tmp/ud-mutation-jobs/${id}/result.json`],handoff:{readonly_tree:true,source_inventory_sha256:'d'.repeat(64),inventory_sha256:'d'.repeat(64)},result_sha256:sha(data),result_size:data.length};
    const baseline={result:{path:'stryker-baseline-1.json',sha256:sha(data),size:data.length},execution:structuredClone(actual)},record=path.join(state,`control/jobs/${id}.exec.json`);
    writeFileSync(path.join(state,baseline.result.path),data,{mode:0o600});writeFileSync(record,JSON.stringify(actual),{mode:0o600});writeFileSync(path.join(state,'stryker-schedule.json'),JSON.stringify({tool:'stryker',tool_version:'10.1.1',source_tree_sha256:sourceTreeSha256,tests:tests.map(({upstream_id,...test})=>({...test,status:'Success'}))}),{mode:0o600});
    const options={sourceTreeSha256,sourceRoot:source,sdkContext,sourceInventory:{[tests[0].source]:tests[0].source_sha256}};
    const reissue=()=>{const bytes=Buffer.from(JSON.stringify(report));baseline.result.sha256=sha(bytes);baseline.result.size=bytes.length;actual.result_sha256=sha(bytes);actual.result_size=bytes.length;baseline.execution=structuredClone(actual);writeFileSync(path.join(state,baseline.result.path),bytes);writeFileSync(record,JSON.stringify(actual));};
    return action({root,source,state,baseline,record,actual,report,options,reissue,store:()=>retainPristineAuthority(state,{sourceTreeSha256,baseline,sdkContext}),load:()=>restorePristineAuthority(state,options)});
  }finally{rmSync(root,{recursive:true,force:true});}
}
test('a fresh runner restores only the actual complete source-bound pristine report and opaque closure',()=>fixture(({store,load,baseline,report})=>{
  expect(load()).toBeNull();store();const restored=load();expect(restored.baseline).toEqual(baseline);expect(restored.coverage).toEqual(report.result.mutantCoverage);expect(restored.tests).toEqual(report.tests.map(({id,source,source_sha256,name,occurrence,upstream_id})=>({id,source,source_sha256,name,occurrence,upstream_id})));
  expect(()=>store()).toThrow('EEXIST');
}));
test('full-suite coverage-off execution still restores the exact pristine compiled-source authority',()=>fixture(({store,load,report})=>{
  store();const restored=load();expect(restored.coverage).toBeUndefined();expect(restored.compiledSources).toEqual(report.assertion_compiled_sources);expect(restored.tests).toHaveLength(1);
},{coverageEnabled:false}));
test('JSON member order from the Python controller does not change a pristine SDK identity',()=>fixture(({report,reissue,store,load})=>{
  const context=report.assertion_sdk_context;
  report.assertion_sdk_context={receipt_sha256:context.receipt_sha256,root:context.root,schema_version:context.schema_version};
  reissue();store();expect(load().tests).toHaveLength(1);
}));
test('rebound root records cannot conceal missing, changed, duplicated or foreign compiled source authority',()=>{
  for(const edit of [report=>delete report.assertion_compiled_sources,report=>report.assertion_compiled_sources.child_root='/another/tree',report=>delete report.assertion_compiled_sources.entries[0].compiled_source,report=>report.assertion_compiled_sources.entries[0].native_hash='f'.repeat(64),report=>report.assertion_compiled_sources.entries[0].identity_sha256='f'.repeat(64),report=>report.assertion_compiled_sources.entries.push({...report.assertion_compiled_sources.entries[0]})])fixture(({report,reissue,store,load})=>{edit(report);reissue();store();expect(()=>load()).toThrow(/compiled|Native/);});
});
test('actual execution mismatch, runtime failure, timeout, missing cleanup and another command never restore authority',()=>{
  for(const edit of [value=>value.status=1,value=>value.timed_out=true,value=>value.collected=false,value=>value.owned_descendants_cancelled=[123],value=>value.command=['other'],value=>value.result_sha256='f'.repeat(64),value=>value.handoff.inventory_sha256='f'.repeat(64),value=>value.uid=1000])fixture(({store,load,actual,record})=>{store();edit(actual);writeFileSync(record,JSON.stringify(actual));expect(()=>load()).toThrow('actual root execution');});
});
test('source changes, stale SDK/snapshot, altered report bytes, omitted case schedules and missing records are fatal',()=>{
  for(const kind of ['source','sdk','snapshot','bytes','schedule','record'])fixture(({store,load,source,state,options,record})=>{
    store();
    if(kind==='source')writeFileSync(path.join(source,'tests/a.test.mjs'),'changed source');
    if(kind==='sdk')options.sdkContext={...options.sdkContext,receipt_sha256:'e'.repeat(64)};
    if(kind==='snapshot')options.sourceTreeSha256='e'.repeat(64);
    if(kind==='bytes')writeFileSync(path.join(state,'stryker-baseline-1.json'),'{}');
    if(kind==='schedule'){const file=path.join(state,'stryker-schedule.json'),schedule=JSON.parse(readFileSync(file));schedule.tests=[];writeFileSync(file,JSON.stringify(schedule));}
    if(kind==='record')rmSync(record);
    expect(()=>load()).toThrow();
  });
});
