/** Original data fixtures only; this suite never executes a mutant. */
import {afterAll,expect,test} from 'vitest';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {childTestInventory,normalizeProtectedCoverage,protectedCoverageSelection,protectedSelectionFingerprint,summarizeChildRun,protectedVitestSetupFiles} from '../../scripts/quality/stryker-child.mjs';
import {normalizeSubprocessOpacity} from '../../scripts/quality/stryker-opacity.mjs';

const root=mkdtempSync(path.join(os.tmpdir(),'ud-stryker-selection-'));
afterAll(()=>rmSync(root,{recursive:true,force:true}));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
test('fixed pre-rewrite capture precedes every original setup while retaining scalar and array configurations',()=>{
  const fixed=protectedVitestSetupFiles(undefined);
  expect(fixed).toHaveLength(1); expect(fixed[0]).toBe(path.resolve('scripts/quality/stryker-assertion-setup.mjs'));
  expect(protectedVitestSetupFiles('./original.ts')).toEqual([...fixed,'./original.ts']);
  expect(protectedVitestSetupFiles(['first.ts',...fixed,'second.mjs'])).toEqual([...fixed,'first.ts','second.mjs']);
  for(const invalid of [null,3,{},['']])expect(()=>protectedVitestSetupFiles(invalid)).toThrow();
});
for(const[name,bytes]of [['a.test.mjs','// source A\n'],['b.test.mjs','// source B\n'],['unicode.test.mjs','// unicode source\n']]){mkdirSync(path.join(root,'tests'),{recursive:true});writeFileSync(path.join(root,'tests',name),bytes);}
const specs=[['a.test.mjs','suite > hit'],['a.test.mjs','suite > hit'],['a.test.mjs','other > suite > hit'],['a.test.mjs','suite > unrelated'],['b.test.mjs','exact > b'],['b.test.mjs','different > suite > hit']];
const raw=()=>specs.map(([source,name])=>({id:'tests/'+source+'#'+name,fileName:path.join(root,'tests',source),name,status:0,timeSpentMs:1}));
const full=()=>childTestInventory(raw(),root).map(({id,source,source_sha256,name,occurrence,upstream_id})=>({id,source,source_sha256,name,occurrence,upstream_id}));
function coverage({perTest={},static:staticHits={},staticByFile={}}={}){return normalizeProtectedCoverage({perTest,static:staticHits},full(),staticByFile);}
function selection(){const all_cases=full();return{...protectedCoverageSelection('7',coverage({perTest:{[all_cases[0].upstream_id]:{'7':1}}}),all_cases),all_cases,baseline_sha256:'b'.repeat(64),coverage_sha256:'c'.repeat(64)};}
function opacityFor(tests,records=[],uncertainties=[]){return{schema_version:1,contract:'pristine-subprocess-opacity-source-v1',files:[...new Set(tests.map(test=>test.source))].map(source=>({source,source_sha256:tests.find(test=>test.source===source).source_sha256,case_tasks:tests.filter(test=>test.source===source).map(test=>({native_id:test.id,case_id:test.id})),observations:{schema_version:1,contract:'pristine-subprocess-opacity-v1',qualification:'entrypoint-observations-not-unique-process-counts',complete:true,calls:source===tests[0].source?records.reduce((sum,row)=>sum+row.methods.reduce((count,method)=>count+method.count,0),0):0,uncertainties:source===tests[0].source?uncertainties:[],records:source===tests[0].source?records:[]}}))};}
function run({kind='mutant',status='survived',edit=()=>{},selection:chosen=selection()}={}){
  const tests=raw(),wanted=new Set(chosen.cases.map(test=>test.id));
  const ids=childTestInventory(tests,root);tests.forEach((test,index)=>{if(!wanted.has(ids[index].id))test.status=2;});
  const state={kind,result:{status,duration:1},tests,errors:tests.map(()=>[]),selection:chosen,outsideErrors:[]};edit(state,ids);return summarizeChildRun(state,root);
}

test('selection fingerprint matches an independently calculated UTF-8 Python golden vector',()=>{
  const cases=[{id:'tests/unicode.test.mjs#ud-case-1a70a0f0304e2161195048e9',source:'tests/unicode.test.mjs',source_sha256:'a5b09eb24dbf9c7c3c381c8278429dacaed92d181edd8e29c602c1671cd3a85f',name:'suite > 漢字 [a-z].*',occurrence:0,upstream_id:'tests/unicode.test.mjs#suite > 漢字 [a-z].*'}];
  expect(protectedSelectionFingerprint(cases)).toBe('0cd2c8cf4b43cde15b95918ea59bdd699fe68c71bc388ee7a8fc6246246abe04');
  for(const key of ['id','source','source_sha256','name','upstream_id']){const changed=structuredClone(cases);changed[0][key]+='changed';expect(protectedSelectionFingerprint(changed)).not.toBe(protectedSelectionFingerprint(cases));}
  const changed=structuredClone(cases);changed[0].occurrence=1;expect(protectedSelectionFingerprint(changed)).not.toBe(protectedSelectionFingerprint(cases));
  expect(protectedSelectionFingerprint(full())).not.toBe(protectedSelectionFingerprint(full().reverse()));
});
test('duplicate upstream names map to every independently numbered real occurrence without mutating coverage',()=>{
  const tests=full(),original={perTest:{[tests[0].upstream_id]:{'7':2,'8':0}},static:{'9':1}},before=structuredClone(original);
  const normalized=normalizeProtectedCoverage(original,tests,{'tests/b.test.mjs':{'9':1}});
  expect(normalized.perTest).toEqual({[tests[0].id]:{'7':2,'8':0},[tests[1].id]:{'7':2,'8':0}});
  expect(original).toEqual(before);expect(tests[0].id).not.toBe(tests[1].id);expect(tests.slice(0,2).map(test=>test.occurrence)).toEqual([0,1]);
});
test('literal suffix closure is complete across every already selected file and duplicate group',()=>{
  const tests=full(),normalized=coverage({perTest:{[tests[0].upstream_id]:{'7':1},[tests[4].upstream_id]:{'7':1}}});
  const selected=protectedCoverageSelection('7',normalized,tests);
  expect(selected.cases.map(test=>test.id)).toEqual([tests[0],tests[1],tests[2],tests[4],tests[5]].map(test=>test.id));
  expect(selected.sha256).toBe(protectedSelectionFingerprint(selected.cases));
  const names=['literal.*[x](a)$','prefix > literal.*[x](a)$','literalZZx(a)'];
  const rows=childTestInventory(names.map(name=>({id:'tests/a.test.mjs#'+name,name,fileName:path.join(root,'tests/a.test.mjs'),status:0})),root);
  const cov=normalizeProtectedCoverage({perTest:{[rows[0].upstream_id]:{'7':1}},static:{}},rows);
  expect(protectedCoverageSelection('7',cov,rows).cases.map(test=>test.name)).toEqual(names.slice(0,2));
});
test('static file coverage selects its complete file and unattributed startup coverage selects the full suite',()=>{
  const tests=full();
  const attributed=coverage({static:{'7':2},staticByFile:{'tests/a.test.mjs':{'7':2}}});
  expect(protectedCoverageSelection('7',attributed,tests).cases.map(test=>test.id)).toEqual(tests.slice(0,4).map(test=>test.id));
  for(const staticByFile of [{},{'tests/a.test.mjs':{'7':2}}]){
    expect(protectedCoverageSelection('7',coverage({static:{'7':3},staticByFile}),tests).cases.map(test=>test.id)).toEqual(tests.map(test=>test.id));
  }
});
test('opaque CLI and Worker cases join even nonempty direct coverage, while file/global/addon uncertainty stays conservative',()=>{
  const tests=full(),base=coverage({perTest:{[tests[3].upstream_id]:{'7':1}}});
  expect(()=>protectedCoverageSelection('7',base,tests,{requireOpacity:true})).toThrow('opacity');
  const raw=opacityFor(tests,[{scope:{kind:'case',id:tests[4].id},methods:[{name:'spawnSync',count:1}]}]),withCases={...base,opacity:normalizeSubprocessOpacity(raw,tests)};
  const selected=protectedCoverageSelection('7',withCases,tests,{requireOpacity:true});
  expect(selected.cases.map(test=>test.id)).toEqual([tests[3].id,tests[4].id]);expect(selected.strategy).toBe('observed-original-coverage-plus-opaque-cases');
  for(const [scope,expected]of [[{kind:'file',path:tests[4].source},[tests[3].id,tests[4].id,tests[5].id]],[{kind:'global'},tests.map(test=>test.id)]]){
    const observations=opacityFor(tests,[{scope,methods:[{name:'worker_threads.Worker',count:1}]}]),coverage_={...base,opacity:normalizeSubprocessOpacity(observations,tests)};
    expect(protectedCoverageSelection('7',coverage_,tests,{requireOpacity:true}).cases.map(test=>test.id)).toEqual(expected);
  }
  const uncertain={...base,opacity:normalizeSubprocessOpacity(opacityFor(tests,[],['preexisting-native-addon']),tests)};
  expect(protectedCoverageSelection('7',uncertain,tests,{requireOpacity:true})).toMatchObject({strategy:'opaque-original-full-suite',cases:tests});
  // Opaque calls never fabricate observed hits: an otherwise uncovered mutant
  // still requires its explicit pre-outcome complete-suite fallback policy.
  expect(()=>protectedCoverageSelection('8',withCases,tests,{requireOpacity:true})).toThrow('no trustworthy original test coverage');
});
test('unknown, excessive, malformed and uncovered mappings cannot produce a required selection',()=>{
  const tests=full();
  expect(()=>protectedCoverageSelection('7',coverage({static:{'7':1},staticByFile:{'tests/a.test.mjs':{'7':2}}}),tests)).toThrow(/static|attribut/i);
  expect(()=>protectedCoverageSelection('7',coverage(),tests)).toThrow(/no trustworthy/);
  for(const counts of [{'07':1},{'7':-1},{'7':1.5},{'7':true},{'7':Number.MAX_SAFE_INTEGER+1}])expect(()=>normalizeProtectedCoverage({perTest:{[tests[0].upstream_id]:counts},static:{}},tests)).toThrow(/coverage/);
  expect(()=>normalizeProtectedCoverage({perTest:{'tests/foreign.test.mjs#one':{'7':1}},static:{}},tests)).toThrow(/undiscovered/);
  expect(()=>normalizeProtectedCoverage({perTest:{},static:{}},tests,{'tests/foreign.test.mjs':{'7':1}})).toThrow(/undiscovered/);
  const foreign=coverage();foreign.perTest.unknown={'7':1};expect(()=>protectedCoverageSelection('7',foreign,tests)).toThrow(/unknown case/);
});
test('explicit opaque-child fallback retains zero observed hits and requires the entire original test catalog',()=>{
  const tests=full(),missing=coverage(),before=structuredClone(missing);
  const chosen=protectedCoverageSelection('7',missing,tests,{unattributedFullSuite:true});
  expect(chosen.strategy).toBe('unattributed-original-full-suite');expect(chosen.cases).toEqual(tests);expect(missing).toEqual(before);
  expect(chosen.sha256).toBe(protectedSelectionFingerprint(tests));
  for(const flag of [false,'true',1,null])expect(()=>protectedCoverageSelection('7',missing,tests,{unattributedFullSuite:flag})).toThrow(/no trustworthy/);
  const observed=coverage({perTest:{[tests[4].upstream_id]:{'7':1}}});
  const measured=protectedCoverageSelection('7',observed,tests,{unattributedFullSuite:true});
  expect(measured.strategy).toBe('observed-original-coverage');expect(measured.cases).toEqual([tests[4]]);
  const malformed=structuredClone(missing);malformed.perTest.foreign={'7':1};expect(()=>protectedCoverageSelection('7',malformed,tests,{unattributedFullSuite:true})).toThrow(/unknown case/);
});
test('source, exact upstream name, canonical occurrence and full identity fields are checked before selection',()=>{
  for(const change of [test=>{test.upstream_id=test.source+'#different';},test=>{test.source='../outside';},test=>{test.source_sha256='not-sha';},test=>{test.occurrence=true;},test=>{test.id='foreign';}]){
    const tests=full();change(tests[0]);expect(()=>protectedCoverageSelection('7',coverage(),tests)).toThrow(/identity|case/);
  }
  const tests=full();tests[0].upstream_id=tests[0].source+'#different';expect(()=>normalizeProtectedCoverage({perTest:{},static:{}},tests)).toThrow(/identity/);
  for(const source of ['../outside','tests/../outside','tests//outside','tests/C:outside','tests/a\\outside']){
    const invalid=full();invalid[0].source=source;invalid[0].id=source+'#ud-case-'+sha(JSON.stringify([invalid[0].name,invalid[0].occurrence])).slice(0,24);invalid[0].upstream_id=source+'#'+invalid[0].name;
    expect(()=>protectedCoverageSelection('7',coverage(),invalid)).toThrow(/case/);
  }
  const duplicate=full();duplicate.push(duplicate[0]);expect(()=>protectedCoverageSelection('7',coverage(),duplicate)).toThrow(/case/);
});
test('selected passing baseline reconciles every required case and explicitly records unselected cases',()=>{
  const chosen=selection(),report=run({kind:'selection-baseline',selection:chosen});
  expect(report.result.status).toBe('complete');expect(report.tests.map(test=>test.id)).toEqual(chosen.cases.map(test=>test.id));
  expect(report.not_selected).toEqual(chosen.all_cases.filter(test=>!chosen.cases.some(row=>row.id===test.id)).map(test=>test.id));
  expect(report.selection_sha256).toBe(chosen.sha256);
});
test('selected assertion kills stay distinct from runtime errors, missing/skipped cases and outside failures',()=>{
  const clean=run({status:'killed',edit(state){state.tests[0].status=1;state.errors[0]=[{name:'AssertionError',code:'ERR_ASSERTION',message:'independent expected value'}];}});
  expect(clean.result.status).toBe('killed');expect(clean.result.nrOfTests).toBe(selection().cases.length);expect(clean.failures[0].failure_kind).toBe('assertion');
  for(const error of [{name:'TypeError',message:'unexpected runtime'},{name:'AssertionError',code:'OTHER',message:'foreign assertion code'}])expect(run({status:'killed',edit(state){state.tests[0].status=1;state.errors[0]=[error];}}).result.status).toBe('error');
  for(const invalid of [2,true,null,undefined])expect(run({edit(state){state.tests[0].status=invalid;}}).result.status).toBe('error');
  expect(()=>run({edit(state){state.tests.splice(0,1);state.errors.splice(0,1);}})).toThrow(/missing|duplicated|identity/);
  expect(run({edit(state){state.outsideErrors=['suite setup failed'];}}).result.status).toBe('error');
});
test('passing or filtered cases cannot hide errors and unmutated baselines cannot certify assertions',()=>{
  expect(run({edit(state){state.errors[0]=[{name:'TypeError',message:'passed with runtime error'}];}}).result.status).toBe('error');
  expect(run({edit(state){state.errors[3]=[{name:'TypeError',message:'filtered with collection error'}];}}).result.status).toBe('error');
  expect(run({kind:'selection-baseline',edit(state){state.tests[0].status=1;state.errors[0]=[{name:'AssertionError',message:'unmutated baseline failed'}];}}).result.status).toBe('error');
  const tests=raw(),errors=tests.map(()=>[]);tests[0].status=1;errors[0]=[{name:'AssertionError',message:'full baseline failed'}];
  expect(summarizeChildRun({kind:'dry-run',result:{status:'complete'},tests,errors},root).result.status).toBe('error');
});
test('selection fingerprints, source hashes, required membership and unexpected execution cannot be weakened',()=>{
  for(const edit of [chosen=>{chosen.sha256='0'.repeat(64);},chosen=>{chosen.cases[0].source_sha256='f'.repeat(64);chosen.sha256=protectedSelectionFingerprint(chosen.cases);},chosen=>{chosen.cases.push(chosen.cases[0]);chosen.sha256=protectedSelectionFingerprint(chosen.cases);},chosen=>{chosen.cases.reverse();chosen.sha256=protectedSelectionFingerprint(chosen.cases);}]){
    const chosen=selection();edit(chosen);expect(()=>run({selection:chosen})).toThrow(/selection|selected/);
  }
  expect(()=>run({edit(state){state.tests[3].status=0;}})).toThrow(/nonselected/);
});
