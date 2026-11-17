/** Exact original fixture bytes and synthetic owned-control data; no variant runs. */
import {expect,test} from 'vitest';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync,realpathSync} from 'node:fs';
import {gzipSync} from 'node:zlib';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {symlinkSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import os from 'node:os';
import path from 'node:path';
import {canonicalJson} from '../../scripts/release/http-transports.mjs';
import {childTestInventory,normalizeProtectedCoverage,protectedCoverageSelection} from '../../scripts/quality/stryker-child.mjs';
import {verifyProtectedSelections,verifiedSelectionTests,verifiedAssertionOrigin} from '../../scripts/quality/stryker-selection-evidence.mjs';
import {reconcileScheduledMutations} from '../../scripts/quality/mutation-inventory.mjs';
import {createStrykerAssertionVerifier} from '../../scripts/quality/stryker-assertions.mjs';
import {sourceReceipt} from '../../scripts/release/candidate.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const pick=({id,source,source_sha256,name,occurrence,upstream_id})=>({id,source,source_sha256,name,occurrence,upstream_id});
const clone=value=>structuredClone(value);

async function fixture(action,{fallback=false,opaque=false,fullMode=false,forgedChildOrigin=false}={}){
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-selection-evidence-'))),evidence=path.join(root,'.artifacts/evidence');mkdirSync(evidence,{recursive:true});
  const file='packages/example/src/value.ts',source='export const left = true;\nexport const right = false;\n';
  mkdirSync(path.dirname(path.join(root,file)),{recursive:true});writeFileSync(path.join(root,file),source);
  const testSources={
    'tests/a.test.mjs':"import assert from 'node:assert/strict';\nimport {test} from 'vitest';\nexport function one(){assert.equal(globalThis.__udActual,true); }\nexport function two(){assert.equal(globalThis.__udActual,true); }\nif(false)test('one',one);\nif(false)test('two',two);\n",
    'tests/b.test.mjs':"import assert from 'node:assert/strict';\nimport {test} from 'vitest';\nexport function three(){assert.equal(globalThis.__udActual,true); }\nif(false)test('three',three);\n",
  };
  for(const[name,bytes]of Object.entries(testSources)){mkdirSync(path.dirname(path.join(root,name)),{recursive:true});writeFileSync(path.join(root,name),bytes);}
  const tests=childTestInventory([['tests/a.test.mjs','one'],['tests/a.test.mjs','two'],['tests/b.test.mjs','three']].map(([file,name])=>{const position=testSources[file].indexOf("test('"+name+"'"),before=testSources[file].slice(0,position).split('\n');return{id:file+'#'+name,name,fileName:path.join(root,file),status:0,timeSpentMs:1,startPosition:{line:before.length-1,column:before.at(-1).length}};}),root);
  // Execute only original calibration functions with alternate fixture data.
  // All later execution/control receipts remain explicitly synthetic transport
  // fixtures and confer no production mutation authority.
  symlinkSync(path.dirname(path.dirname(createRequire(import.meta.url).resolve('vitest/package.json'))),path.join(root,'node_modules'),'dir');
  const script=`import{installStrykerAssertionCapture,captureStrykerError,exportCompiledSources}from ${JSON.stringify(pathToFileURL(path.resolve('scripts/quality/stryker-assertions.mjs')).href)};const root=process.argv[1],inventory=JSON.parse(process.argv[2]);await installStrykerAssertionCapture({sourceRoot:root,sourceInventory:inventory});const modules={};for(const file of Object.keys(inventory))modules[file]=await import('file://'+root+'/'+file);const compiled=exportCompiledSources({includeSources:true}),errors={};globalThis.__udActual=false;for(const[file,module]of Object.entries(modules))for(const[name,action]of Object.entries(module)){try{action();throw Error('original calibration unexpectedly passed');}catch(error){if(error.code!=='ERR_ASSERTION')throw error;errors[name]=captureStrykerError(error);}}console.log(JSON.stringify({compiled,errors}));`;
  const captured=spawnSync(process.execPath,['--input-type=module','-e',script,root,JSON.stringify(Object.fromEntries(Object.entries(testSources).map(([name,text])=>[name,sha(text)])))],{encoding:'utf8',timeout:10000,maxBuffer:2*1024**2});
  expect(captured.error).toBeUndefined();expect(captured.status,captured.stderr).toBe(0);const calibration=JSON.parse(captured.stdout);
  const mutants=[['11',0,'true','false'],['12',1,'false','true']].map(([id,line,original,replacement])=>{
    const column=source.split('\n')[line].indexOf(original),definition={tool:'stryker',version:'10.1.1',operator:'BooleanLiteral',original,replacement,location:{start:{line,column},end:{line,column:column+original.length}}};
    return{id:file+'#'+id,file,source_sha256:sha(source),definition_sha256:sha(canonicalJson(definition)),definition};
  });
  const schedule={schema_version:1,tool:'stryker',tool_version:'10.1.1',source_tree_sha256:sourceReceipt(root).sha256,mutants,tests:tests.map(test=>({...pick(test),status:'Success'}))};
  const opacity={schema_version:1,contract:'pristine-subprocess-opacity-source-v1',files:Object.keys(testSources).map(source=>({source,source_sha256:sha(testSources[source]),case_tasks:tests.filter(test=>test.source===source).map(test=>({native_id:test.id,case_id:test.id})),observations:{schema_version:1,contract:'pristine-subprocess-opacity-v1',qualification:'entrypoint-observations-not-unique-process-counts',complete:true,calls:opaque&&source===tests[2].source?1:0,uncertainties:[],records:opaque&&source===tests[2].source?[{scope:{kind:'case',id:tests[2].id},methods:[{name:'spawnSync',count:1}]}]:[]}}))};
  const coverage=normalizeProtectedCoverage({perTest:{[tests[0].upstream_id]:fallback?{}:{'11':1},[tests[1].upstream_id]:{'12':1},[tests[2].upstream_id]:{'12':1}},static:{}},tests,{},opacity);
  schedule.execution_policy={schema_version:1,kind:'pristine-per-test-with-conservative-full-fallback',unattributed_full_suite:true,hit_limits:'disabled',fresh_environment:true,opaque_executions:'all-observed-cases-and-file-fixtures;global-uncertainty-full-suite',test_source_preprocessing:'disabled',fallback_mutant_ids:fallback?['11']:[],full_suite_timeout_ms:30000};
  const controls=new Map(),reports=new Map();let sequence=0;
  function retained(report,role,materialization=null){
    const number=++sequence,id=number.toString(16).padStart(32,'0'),uid=100000+number;
    report.child_root='/tmp/ud-mutation-jobs/'+id+'/tree';
    const compiled=clone(calibration.compiled);compiled.child_root=report.child_root;if(role==='mutant')for(const entry of compiled.entries)delete entry.compiled_source;report.assertion_compiled_sources=compiled;
    if(role==='mutant')for(const failure of report.failures){const test=report.tests.find(test=>test.id===failure.test_id);failure.errors=[JSON.parse(JSON.stringify(calibration.errors[test.name]).replaceAll(root,report.child_root))];const error=failure.errors[0],capture=error.assertion_capture;if(forgedChildOrigin)error.assertion_origin={valid:true,assertion_site:{source:'tests/claimed-behavior.mjs',source_sha256:'f'.repeat(64),line:1,column:1}};for(const value of [error,capture.error]){value.stack_sha256=sha(value.stack);value.stack_bytes=Buffer.byteLength(value.stack);}const{capture_sha256,...record}=capture;capture.capture_sha256=sha(JSON.stringify(record));}
    const bytes=Buffer.from(JSON.stringify(report)),compressed=role==='mutant'?gzipSync(bytes):bytes;
    const filename=(role==='mutant'?'stryker-mutant-':'stryker-baseline-')+number+'.json'+(role==='mutant'?'.gz':'');
    writeFileSync(path.join(evidence,filename),compressed);
    const execution={qualification:'protected-exec',identity:{pid:100+number,uid:0,start_ticks:1000+number},execution_id:id,uid,
      command:['/opt/mutation/node/bin/node','/opt/mutation/harness/stryker-child.mjs','/tmp/ud-mutation-jobs/'+id+'/request.json','/tmp/ud-mutation-jobs/'+id+'/result.json'],
      status:0,timed_out:false,cancelled:false,owned_descendants_cancelled:[],collected:true,stdout:'',stderr:'',
      handoff:{readonly_tree:true,inventory_sha256:sha(materialization?'mutant-'+number:'original-source'),source_inventory_sha256:sha('original-source'),files:4,cwd:'.',
        ...(materialization?{materializations:[{path:file,before_sha256:sha('instrumented-source'),after_sha256:materialization.after_sha256,size:materialization.size}]}:{})},
      result_sha256:sha(bytes),result_size:bytes.length};
    controls.set(id,clone(execution));reports.set(filename,report);
    const receipt={result:{path:filename,sha256:sha(compressed),size:compressed.length},execution:clone(execution)};
    if(role==='mutant'){receipt.raw_result={sha256:sha(bytes),size:bytes.length};receipt.materialization=clone(materialization);}
    return receipt;
  }
  const fullReport={schema_version:1,subprocess_opacity:opacity,result:{status:'complete',tests:clone(tests),mutantCoverage:coverage},tests:clone(tests),failures:[],outside_errors:[]};
  if(fullMode)delete fullReport.result.mutantCoverage;
  const original=retained(fullReport,'baseline'),records=[];
  for(const mutant of mutants){
    const rawId=mutant.id.slice(file.length+1),selected=fullMode?{cases:tests}:protectedCoverageSelection(rawId,coverage,tests,{unattributedFullSuite:fallback&&rawId==='11'}),selection=fullMode?null:{...selected,all_cases:tests.map(pick),baseline_sha256:original.result.sha256,coverage_sha256:sha(JSON.stringify(coverage))};
    const wanted=new Set((fullMode?tests:selection.cases).map(test=>test.id)),chosen=tests.filter(test=>wanted.has(test.id));
    const selectedReport={schema_version:1,result:{status:'complete',tests:clone(chosen)},tests:clone(chosen),failures:[],outside_errors:[],...(selection?{selection_sha256:selection.sha256,not_selected:tests.filter(test=>!wanted.has(test.id)).map(test=>test.id)}:{})};
    const selectedReceipt=fullMode?null:retained(selectedReport,'baseline');
    const changed=source.replace(mutant.definition.original,mutant.definition.replacement),materialization={path:file,before_sha256:sha(source),after_sha256:sha(changed),materializer_version:'stryker-ast-materializer-v1',serialized_replacement:mutant.definition.replacement,size:Buffer.byteLength(changed)};
    const failed=chosen.map((test,index)=>({...test,status:index===0?1:0}));
    const failure={test_id:failed[0].id,failure_kind:'assertion',errors:[{name:'AssertionError',code:'ERR_ASSERTION',message:'independent expected boolean',stack:`AssertionError: independent expected boolean\n    at ${failed[0].source}:2:17`}]};
    const mutantReport={schema_version:1,result:{status:'killed',killedBy:[failed[0].id],nrOfTests:failed.length,duration:1,failureMessage:'independent expected boolean'},tests:failed,failures:[failure],outside_errors:[],...(selection?{selection_sha256:selection.sha256,not_selected:selectedReport.not_selected}:{}),materialization};
    const mutantReceipt=retained(mutantReport,'mutant',materialization);
    records.push({schema_version:1,mutant_id:rawId,definition_sha256:mutant.definition_sha256,selection,original_baseline:clone(original),selected_baseline:selectedReceipt,
      mutant_report:mutantReceipt,execution:mutantReceipt.execution.execution_id,uid:mutantReceipt.execution.uid,required_tests_completed:chosen.length});
  }
  for(const record of records){const report=reports.get(record.mutant_report.result.path),origin=await createStrykerAssertionVerifier({sourceRoot:root,childRoot:report.child_root,sourceInventory:Object.fromEntries(Object.entries(testSources).map(([name,text])=>[name,sha(text)])),compiledSources:fullReport.assertion_compiled_sources}),failure=report.failures[0],proof=origin(report.tests.find(test=>test.id===failure.test_id),failure.errors[0]);expect(proof.valid,JSON.stringify(proof)).toBe(true);}
  const arguments_={schedule,records,coverageAnalysis:fullMode?'off':'perTest',sourceRoot:root,readBaseline:receipt=>readFileSync(path.join(evidence,receipt.path)),readExecution:id=>clone(controls.get(id))};
  const verify=changes=>verifyProtectedSelections({...arguments_,...changes});
  const rewrite=(receipt,role,mutate)=>{
    const report=clone(reports.get(receipt.result.path));mutate(report);
    const bytes=Buffer.from(JSON.stringify(report)),encoded=role==='mutant'?gzipSync(bytes):bytes;
    writeFileSync(path.join(evidence,receipt.result.path),encoded);reports.set(receipt.result.path,report);
    receipt.result.sha256=sha(encoded);receipt.result.size=encoded.length;
    if(receipt.raw_result){receipt.raw_result.sha256=sha(bytes);receipt.raw_result.size=bytes.length;}
    receipt.execution.result_sha256=sha(bytes);receipt.execution.result_size=bytes.length;
    controls.get(receipt.execution.execution_id).result_sha256=sha(bytes);controls.get(receipt.execution.execution_id).result_size=bytes.length;
  };
  try{return await action({root,evidence,source,file,tests,mutants,schedule,records,controls,reports,verify,rewrite,calibration});}finally{rmSync(root,{recursive:true,force:true});}
}
const invalid=async(value)=>{const proof=await value;expect(proof.errors.length).toBeGreaterThan(0);return proof;};

test('independent replay brands exact per-mutant required counts while retaining the complete global test inventory',async()=>fixture(async({verify,schedule,records,reports})=>{
  const proof=await verify();expect(proof.errors).toEqual([]);expect(proof.total).toBe(2);
  const view=verifiedSelectionTests(proof,schedule);expect(view.get(schedule.mutants[0].id).size).toBe(1);expect(view.get(schedule.mutants[1].id).size).toBe(2);expect(schedule.tests).toHaveLength(3);
  const failures=records.flatMap(record=>reports.get(record.mutant_report.result.path).failures.map(failure=>({...clone(failure),mutant_id:record.mutant_id})));
  const outcomes=records.map((record,index)=>({file:schedule.mutants[index].file,id:record.mutant_id,definition_sha256:record.definition_sha256,status:'Killed',testsCompleted:record.required_tests_completed,killedBy:[record.selection.cases[0].id]}));
  const hashes=Object.fromEntries([...schedule.tests.map(test=>[test.source,test.source_sha256]),...schedule.mutants.map(item=>[item.file,item.source_sha256])]);
  expect(reconcileScheduledMutations(schedule,outcomes,failures,hashes,{selectionProof:proof}).errors).toEqual([]);
  outcomes[0].testsCompleted=3;expect(reconcileScheduledMutations(schedule,outcomes,failures,hashes,{selectionProof:proof}).errors).toContainEqual(expect.stringContaining('complete every'));
}));
test('independent replay keeps opaque CLI cases even when the same mutant has a direct coveredBy test',async()=>fixture(async({verify,schedule,records})=>{
  const proof=await verify();expect(proof.errors).toEqual([]);expect(verifiedSelectionTests(proof,schedule).get(schedule.mutants[0].id).size).toBe(2);
  expect(records[0].selection.strategy).toBe('observed-original-coverage-plus-opaque-cases');
  expect(records[0].selection.cases.map(test=>test.name)).toEqual(['one','three']);
},{opaque:true}));
test('missing raw opacity, truncated task maps and falsified closure cannot acquire narrowed authority',async()=>fixture(async({verify,records,rewrite})=>{
  const receipt=records[0].original_baseline;rewrite(receipt,'baseline',report=>{report.subprocess_opacity.files[0].case_tasks.pop();});records[1].original_baseline=clone(receipt);await invalid(verify());
}));
test('JSON copies and forged authority cannot manufacture or mutate a verified selection brand',async()=>fixture(async({verify,schedule})=>{
  const proof=await verify();expect(proof.errors).toEqual([]);
  for(const forged of [{total:2,errors:[]},clone(proof)])expect(verifiedSelectionTests(forged,schedule)).toBeNull();
  const changed=clone(schedule);changed.mutants[0].definition_sha256='f'.repeat(64);expect(verifiedSelectionTests(proof,changed)).toBeNull();
  const view=verifiedSelectionTests(proof,schedule),set=view.get(schedule.mutants[0].id);set.clear();expect(view.get(schedule.mutants[0].id).size).toBe(1);
}));
test('missing duplicate or changed mutation records preserve unresolved inventory errors',async()=>fixture(async({verify,records})=>{
  await invalid(verify({records:records.slice(1)}));await invalid(verify({records:[records[0],records[0]]}));
  const changed=clone(records);changed[0].definition_sha256='e'.repeat(64);await invalid(verify({records:changed}));
}));
test('owned execution controls independently bind baseline metadata instead of trusting embedded receipts',async()=>fixture(async({verify,records,controls})=>{
  const id=records[0].original_baseline.execution.execution_id;controls.get(id).timed_out=true;await invalid(verify());
}));
test('unrelated or reused clean executions cannot stand in for scheduled mutant invocations',async()=>fixture(async({verify,records,controls})=>{
  const changed=clone(records);changed[1].execution=changed[0].execution;changed[1].uid=changed[0].uid;changed[1].mutant_report.execution=clone(changed[0].mutant_report.execution);await invalid(verify({records:changed}));
  const execution=controls.get(records[0].execution);execution.command=['/opt/mutation/python/bin/python3','-c','pass'];await invalid(verify());
}));
test('retained report and harvested result identities must match exact owned execution bytes',async()=>fixture(async({verify,records,evidence})=>{
  const receipt=records[0].mutant_report;writeFileSync(path.join(evidence,receipt.result.path),gzipSync(Buffer.from('{}')));await invalid(verify());
}));
test('omitted selected cases and failing unmutated baselines cannot acquire authority',async()=>fixture(async({verify,records,rewrite})=>{
  rewrite(records[0].selected_baseline,'baseline',report=>{report.tests=[];report.result.tests=[];});await invalid(verify());
}));
test('uncovered or inconsistent pristine static maps cannot be narrowed by supplied record lists',async()=>fixture(async({verify,records,rewrite})=>{
  const receipt=records[0].original_baseline;
  rewrite(receipt,'baseline',report=>{report.result.mutantCoverage.perTest={};report.result.mutantCoverage.static={};report.result.mutantCoverage.staticByFile={};});
  records[1].original_baseline=clone(receipt);await invalid(verify());
}));
test('changed test source and stale scheduled definition are rejected against exact original files',async()=>fixture(async({verify,root,tests,schedule})=>{
  const original=readFileSync(path.join(root,tests[0].source));writeFileSync(path.join(root,tests[0].source),'changed source');await invalid(verify());
  writeFileSync(path.join(root,tests[0].source),original);
  const changed=clone(schedule);changed.mutants[0].definition.replacement='true';await invalid(verify({schedule:changed}));
}));
test('wrong materialized program and false completed-case count cannot borrow a valid execution',async()=>fixture(async({verify,records,controls})=>{
  const wrong=clone(records);wrong[0].required_tests_completed=3;await invalid(verify({records:wrong}));
  controls.get(records[0].execution).handoff.materializations[0].after_sha256='0'.repeat(64);await invalid(verify());
}));

test('a failed original selected baseline remains invalid even with complete selected-case identities',async()=>fixture(async({verify,records,rewrite})=>{
  rewrite(records[0].selected_baseline,'baseline',report=>{
    report.tests[0].status=1;report.result.status='error';report.result.tests=clone(report.tests);
    report.failures=[{test_id:report.tests[0].id,failure_kind:'assertion',errors:[{name:'AssertionError',message:'original baseline failed'}]}];
  });
  await invalid(verify());
}));
test('all retained reports must agree with the independently supplied immutable assertion SDK',async()=>fixture(async({verify,records,rewrite})=>{
  const context={schema_version:1,root:'/opt/mutation/node_modules',receipt_sha256:'a'.repeat(64)};
  await invalid(verify({immutableSdkContext:context}));
  rewrite(records[0].mutant_report,'mutant',report=>{report.assertion_sdk_context=context;});
  await invalid(verify());
}));
test('missing or truncated mutant reports cannot be replaced by embedded successful control metadata',async()=>fixture(async({verify,records,evidence})=>{
  const missing=clone(records);delete missing[0].mutant_report;await invalid(verify({records:missing}));
  const receipt=records[0].mutant_report,file=path.join(evidence,receipt.result.path),bytes=readFileSync(file);
  const truncated=bytes.subarray(0,Math.max(1,bytes.length-8));writeFileSync(file,truncated);receipt.result.sha256=sha(truncated);receipt.result.size=truncated.length;
  await invalid(verify());
}));
test('per-file static maps cannot claim more hits than the independently retained global coverage',async()=>fixture(async({verify,records,rewrite})=>{
  const receipt=records[0].original_baseline;
  rewrite(receipt,'baseline',report=>{const coverage=report.result.mutantCoverage;coverage.static={'11':1};coverage.staticByFile={'tests/a.test.mjs':{'11':2}};});
  records[1].original_baseline=clone(receipt);await invalid(verify());
}));
test('the complete original test handoff must remain identical across selected baseline and candidate',async()=>fixture(async({verify,records,controls})=>{
  const selected=records[0].selected_baseline;controls.get(selected.execution.execution_id).handoff.source_inventory_sha256='e'.repeat(64);
  selected.execution.handoff.source_inventory_sha256='e'.repeat(64);await invalid(verify());
}));

test('pre-outcome opaque-child fallback independently replays the full catalog without manufacturing observed coverage',async()=>fixture(async({verify,schedule,records,reports})=>{
  const proof=await verify();expect(proof.errors).toEqual([]);
  const view=verifiedSelectionTests(proof,schedule);expect(view.get(schedule.mutants[0].id).size).toBe(3);expect(view.get(schedule.mutants[1].id).size).toBe(2);
  expect(records[0].selection.strategy).toBe('unattributed-original-full-suite');
  const original=reports.get(records[0].original_baseline.result.path);expect(Object.values(original.result.mutantCoverage.perTest).every(counts=>!(counts['11']>0))).toBe(true);
  expect(original.result.mutantCoverage.static).toEqual({});
},{fallback:true}));
test('fallback cannot be enabled after outcomes or narrow a required full-suite baseline',async()=>fixture(async({verify,schedule,records})=>{
  const absent=clone(schedule);delete absent.execution_policy;await invalid(verify({schedule:absent}));
  for(const patch of [{unattributed_full_suite:false},{fresh_environment:false},{hit_limits:'virtual'},{fallback_mutant_ids:[]},{fallback_mutant_ids:['11','11']},{fallback_mutant_ids:['999']},{full_suite_timeout_ms:1}]){
    const altered=clone(schedule);Object.assign(altered.execution_policy,patch);await invalid(verify({schedule:altered}));
  }
  const altered=clone(records);altered[0].selection.strategy='observed-original-coverage';await invalid(verify({records:altered}));
},{fallback:true}));
test('a measured-covered mutant cannot borrow the opaque fallback policy to misrepresent its selection strategy',async()=>fixture(async({verify,schedule})=>{
  const altered=clone(schedule);altered.execution_policy={schema_version:1,kind:'pristine-per-test-with-conservative-full-fallback',unattributed_full_suite:true,hit_limits:'disabled',fresh_environment:true,fallback_mutant_ids:['11'],full_suite_timeout_ms:30000};
  await invalid(verify({schedule:altered}));
}));

test('full-suite mode independently binds every case and returns only privately host-replayed origins',async()=>fixture(async({verify,schedule,records,reports,rewrite})=>{
  const proof=await verify();expect(proof.errors).toEqual([]);const view=verifiedSelectionTests(proof,schedule);
  for(const mutant of schedule.mutants)expect(view.get(mutant.id).size).toBe(schedule.tests.length);
  const report=reports.get(records[0].mutant_report.result.path),failure=report.failures[0],error=failure.errors[0],origin=verifiedAssertionOrigin(proof,schedule,schedule.mutants[0].id,failure.test_id,error);
  expect(origin.valid).toBe(true);expect(origin.assertion_site.source).toBe('tests/a.test.mjs');expect(error.assertion_origin.assertion_site.source).toBe('tests/claimed-behavior.mjs');
  expect(verifiedAssertionOrigin(structuredClone(proof),schedule,schedule.mutants[0].id,failure.test_id,error)).toBeNull();
  expect(verifiedAssertionOrigin(proof,schedule,schedule.mutants[0].id,failure.test_id,{...error,message:'different'})).toBeNull();
  origin.assertion_site.source='changed';expect(verifiedAssertionOrigin(proof,schedule,schedule.mutants[0].id,failure.test_id,error).assertion_site.source).toBe('tests/a.test.mjs');
  rewrite(records[0].mutant_report,'mutant',report=>{report.tests.pop();report.result.nrOfTests--;});await invalid(verify());
},{fullMode:true,forgedChildOrigin:true}));
test('full-suite authority rejects narrowing, missing association, changed case positions and unknown execution modes',async()=>fixture(async({verify,records,rewrite})=>{
  await invalid(verify({records:records.slice(1)}));await invalid(verify({coverageAnalysis:'all-but-some'}));
  const narrowed=structuredClone(records);narrowed[0].selection={cases:[]};await invalid(verify({records:narrowed}));
  rewrite(records[0].mutant_report,'mutant',report=>report.tests[0].startPosition.line++);await invalid(verify());
},{fullMode:true}));
