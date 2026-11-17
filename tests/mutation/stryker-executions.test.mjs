/** Original journal/storage fixtures. No protected execution is fabricated as
 * acceptance and no generated variant runs in this test process.
 */
import{test,expect,vi}from'vitest';
import{mkdtempSync,realpathSync,readFileSync,writeFileSync,chmodSync,symlinkSync,linkSync,renameSync,rmSync,existsSync,lstatSync}from'node:fs';
import os from'node:os';import path from'node:path';
const race=vi.hoisted(()=>({beforeOpen:undefined,afterOpen:undefined}));
vi.mock('node:fs',async original=>{const actual=await original();return{...actual,constants:{...actual.constants,O_NOFOLLOW:0},openSync:(...args)=>{race.beforeOpen?.(args[0]);const fd=actual.openSync(...args);race.afterOpen?.(args[0]);return fd;}};});
import{retainProtectedExecution}from'../../scripts/quality/stryker-protected-runner.mjs';
function fixture(action){const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-stryker-executions-'))),execution={execution_id:'a'.repeat(32),uid:100001},receipt={result:{path:'stryker-mutant-1.json.gz',sha256:'b'.repeat(64),size:7},execution},record={schema_version:1,mutant_id:'1',definition_sha256:'c'.repeat(64),selection:null,original_baseline:{result:{path:'stryker-baseline-1.json',sha256:'d'.repeat(64),size:9}},selected_baseline:null,mutant_report:receipt,execution:execution.execution_id,uid:execution.uid,required_tests_completed:3};try{return action({root,record});}finally{rmSync(root,{recursive:true,force:true});}}
test('full-suite executions always retain their exact association and selected runs preserve the legacy journal',()=>fixture(({root,record})=>{
 expect(retainProtectedExecution(root,record)).toBe(record);expect(JSON.parse(readFileSync(path.join(root,'stryker-executions.jsonl')))).toEqual(record);expect(existsSync(path.join(root,'stryker-selections.jsonl'))).toBe(false);
 const selected={...structuredClone(record),mutant_id:'2',selection:{sha256:'e'.repeat(64),cases:[{id:'one'}]},selected_baseline:{result:{path:'stryker-baseline-2.json',sha256:'f'.repeat(64),size:10}}};retainProtectedExecution(root,selected);
 expect(readFileSync(path.join(root,'stryker-executions.jsonl'),'utf8').trim().split('\n').map(JSON.parse)).toEqual([record,selected]);expect(JSON.parse(readFileSync(path.join(root,'stryker-selections.jsonl')))).toEqual(selected);
 if(process.platform!=='win32')expect(lstatSync(path.join(root,'stryker-executions.jsonl')).mode&0o777).toBe(0o600);
}));
test('missing identity, mixed modes and foreign execution receipts fail before any association is written',()=>fixture(({root,record})=>{
 for(const change of [value=>value.mutant_id='../x',value=>value.definition_sha256='invalid',value=>value.execution='b'.repeat(32),value=>value.uid++,value=>value.required_tests_completed=0,value=>value.selection={cases:[]},value=>value.selected_baseline={result:{}},value=>delete value.original_baseline]){const changed=structuredClone(record);change(changed);expect(()=>retainProtectedExecution(root,changed)).toThrow(/association/);expect(existsSync(path.join(root,'stryker-executions.jsonl'))).toBe(false);}
}));
test('append refuses symlink targets and nonprivate existing journal modes without touching their bytes',()=>fixture(({root,record})=>{
 const outside=path.join(root,'outside.jsonl');writeFileSync(outside,'owned unrelated bytes');symlinkSync(outside,path.join(root,'stryker-executions.jsonl'));expect(()=>retainProtectedExecution(root,record)).toThrow();expect(readFileSync(outside,'utf8')).toBe('owned unrelated bytes');rmSync(path.join(root,'stryker-executions.jsonl'));
 if(process.platform!=='win32'){writeFileSync(path.join(root,'stryker-executions.jsonl'),'existing');chmodSync(path.join(root,'stryker-executions.jsonl'),0o644);expect(()=>retainProtectedExecution(root,record)).toThrow(/identity/);expect(readFileSync(path.join(root,'stryker-executions.jsonl'),'utf8')).toBe('existing');}
}));

test('append refuses multiply linked journals before changing unrelated bytes',()=>fixture(({root,record})=>{
 const outside=path.join(root,'outside.jsonl');writeFileSync(outside,'preserve',{mode:0o600});linkSync(outside,path.join(root,'stryker-executions.jsonl'));
 expect(()=>retainProtectedExecution(root,record)).toThrow(/identity/);expect(readFileSync(outside,'utf8')).toBe('preserve');
}));
test('a named journal replacement between inspection and open is rejected before append',()=>fixture(({root,record})=>{
 const journal=path.join(root,'stryker-executions.jsonl'),retired=path.join(root,'retired.jsonl');writeFileSync(journal,'original',{mode:0o600});
 race.beforeOpen=filename=>{if(filename!==journal)return;race.beforeOpen=undefined;renameSync(journal,retired);writeFileSync(journal,'replacement',{mode:0o600});};
 try{expect(()=>retainProtectedExecution(root,record)).toThrow(/identity/);expect(readFileSync(journal,'utf8')).toBe('replacement');expect(readFileSync(retired,'utf8')).toBe('original');}
 finally{race.beforeOpen=undefined;}
}));

test('an alias substituted after open cannot redirect or receive the pending append without O_NOFOLLOW',()=>fixture(({root,record})=>{
 const journal=path.join(root,'stryker-executions.jsonl'),retired=path.join(root,'retired.jsonl'),foreign=path.join(root,'foreign.jsonl');
 writeFileSync(journal,'original',{mode:0o600});writeFileSync(foreign,'foreign',{mode:0o600});
 race.afterOpen=filename=>{if(filename!==journal)return;race.afterOpen=undefined;renameSync(journal,retired);symlinkSync(foreign,journal);};
 try{expect(()=>retainProtectedExecution(root,record)).toThrow(/identity/);expect(readFileSync(retired,'utf8')).toBe('original');expect(readFileSync(foreign,'utf8')).toBe('foreign');}
 finally{race.afterOpen=undefined;}
}));
