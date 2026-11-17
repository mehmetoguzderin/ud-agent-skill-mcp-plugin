import { test } from 'vitest';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { activeUserspaceLeases, operationMatrixSummary, requireUserspaceProjectRejection, userspaceAcceptanceProfile, userspaceGitEvidence, userspaceInstallerEvidence } from '../../scripts/quality/userspace-acceptance.mjs';
import { requireFixtureExpectations } from '../../scripts/quality/native-provider-acceptance.mjs';
import { guardedIdentity, guardedStateLock } from '../../packages/workspace/src/guard.js';
import { JournalStore } from '../../packages/workspace/src/journal.js';

test('userspace acceptance explicitly identifies installer, native architecture and isolated search paths',()=>{
  assert.deepEqual(userspaceAcceptanceProfile('darwin','arm64','uv','/private/python:/private/bin'),{target:'darwin-arm64',engine:'userspace',worker:'darwin/arm64',installer:'uv',searchPath:'/private/python:/private/bin'});
  assert.equal(userspaceAcceptanceProfile('win32','x64','venv','C:\\private\\python;D:\\private\\bin').worker,'win32/x64');
  for(const args of[['linux','arm64',undefined,'/private/bin'],['linux','arm64','pip','/private/bin'],['linux','arm64','venv','relative'],['linux','arm64','uv','/private/bin:'],['darwin','amd64','uv','/private/bin'],['unknown','arm64','uv','/private/bin']])assert.throws(()=>userspaceAcceptanceProfile(...args));
});

test('missing or invalid isolated Git remains a concrete prerequisite without acquisition or ambient PATH search',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'ud-explicit-git-'));
 try{
  await assert.rejects(userspaceGitEvidence(root),/GIT_SNAPSHOT_PREREQUISITE_MISSING/);
  const file=path.join(root,process.platform==='win32'?'git.exe':'git');await writeFile(file,'not an executable',{mode:0o600});
  await assert.rejects(userspaceGitEvidence(root));
  assert.equal(await readFile(file,'utf8'),'not an executable');
 }finally{await rm(root,{recursive:true,force:true});}
});

test('actual installer evidence requires the exact manifest marker and supported interpreter branch',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'ud-installer-evidence-'));
 try{
  const manifest='sha256:'+'a'.repeat(64),name='current-'+manifest.slice(7)+'.json';
  const value={schema_version:1,manifest,environment:'env-'+randomUUID(),fingerprint:'sha256:'+'b'.repeat(64),installer:'uv',python_version:'3.15.2'};
  await writeFile(path.join(root,name),JSON.stringify(value));
  const evidence=await userspaceInstallerEvidence(root,'uv',manifest);assert.equal(evidence.installer,'uv');assert.equal(evidence.python_version,'3.15.2');assert.equal(evidence.environment,value.environment);
  assert.equal((await userspaceInstallerEvidence(root,'uv',manifest,'3.15')).python_version,'3.15.2');
  await assert.rejects(userspaceInstallerEvidence(root,'uv',manifest,'3.14'),/differs from the requested/);
  await assert.rejects(userspaceInstallerEvidence(root,'uv',manifest,'3.13'),/must be 3.14 or 3.15/);
  await assert.rejects(userspaceInstallerEvidence(root,'venv',manifest),/another installer/);
  for(const change of[{schema_version:2},{manifest:'sha256:'+'c'.repeat(64)},{environment:'../outside'},{fingerprint:'bad'},{python_version:'3.13.10'}]){await writeFile(path.join(root,name),JSON.stringify({...value,...change}));await assert.rejects(userspaceInstallerEvidence(root,'uv',manifest));}
 }finally{await rm(root,{recursive:true,force:true});}
});

test('project-code rejection is separate from successful userspace domain behavior',()=>{
 const response={isError:true,structuredContent:{execution:{status:'incomplete'},provenance:{runtime:'userspace'},result:{code:'ENVIRONMENT_NOT_READY',environment:{status:'blocked_by_policy',unsupported_operations:['project_consistency_report'],runtime:{engine:'userspace',project_code_allowed:false}}}}};
 assert.equal(requireUserspaceProjectRejection(response).status,'capability-rejection-verified');
 for(const change of[x=>x.isError=false,x=>x.structuredContent.execution.status='completed',x=>x.structuredContent.result.environment.status='setup_needed',x=>x.structuredContent.result.environment.unsupported_operations=[],x=>x.structuredContent.result.environment.runtime.project_code_allowed=true,x=>x.structuredContent.provenance.worker='pretended-worker']){const copy=structuredClone(response);change(copy);assert.throws(()=>requireUserspaceProjectRejection(copy));}
 const operations=['validation_report','project_consistency_report'],formats=['native','mcpb'],rows=formats.flatMap(format=>[{format,operation:'validation_report',status:'passed'},{format,operation:'project_consistency_report',status:'capability-rejection-verified'}]);
 assert.deepEqual(operationMatrixSummary(rows,operations,formats,'userspace'),{complete:true,completed_operations:2,capability_rejections:2,scheduled:4});
 for(const changed of[rows.slice(1),[...rows,rows[0]],rows.map((row,index)=>index===1?{...row,status:'passed'}:row),rows.map((row,index)=>index===1?{...row,format:'foreign'}:row),rows.map((row,index)=>index===1?{...row,operation:'validation_report'}:row)])assert.equal(operationMatrixSummary(changed,operations,formats,'userspace').complete,false);
 assert.equal(operationMatrixSummary(rows,operations,formats,'docker').complete,false);
});

test('every operation must retain an independent expected result or artifact',()=>{
 const operations=Array.from({length:102},(_,i)=>'operation_'+i),cases=operations.map(operation=>({operation,files:[],prerequisites:[],expected_fields:{answer:42}}));
 assert.doesNotThrow(()=>requireFixtureExpectations({cases},operations));
 const artifact=structuredClone(cases);artifact[0].expected_fields={};artifact[0].expected_artifacts=[{sha256:'a'.repeat(64)}];assert.doesNotThrow(()=>requireFixtureExpectations({cases:artifact},operations));
 for(const changed of[cases.slice(1),[...cases.slice(1),cases[1]],cases.map((row,i)=>i===0?{...row,expected_fields:{}}:row),cases.map((row,i)=>i===0?{...row,expected_fields:undefined}:row)])assert.throws(()=>requireFixtureExpectations({cases:changed},operations));
});

test('userspace cancellation observation requires actual kernel contention, not an owner record alone',async()=>{
 const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-userspace-live-lease-')));
 try{
  const guard=path.join(root,'guard'+(process.platform==='win32'?'.exe':''));await copyFile(path.resolve(process.platform==='win32'?'target/debug/ud-agent-guard.exe':'target/debug/ud-agent-guard'),guard);await chmod(guard,0o700);
  const state=path.join(root,'state');await mkdir(state,{mode:0o700});await JournalStore.open(state,guard);
  const name='.lease-'+randomUUID(),record={schema_version:1,pid:process.pid,kernel_lock:name+'.native'};await writeFile(path.join(state,name),JSON.stringify(record),{mode:0o600});
  // No kernel lock file exists; a live-looking PID record proves no activity.
  assert.equal((await activeUserspaceLeases(state,guard)).size,0);
  const release=await guardedStateLock(guard,state,record.kernel_lock,await guardedIdentity(guard,state));
  try{const observed=await activeUserspaceLeases(state,guard);assert.equal(observed.size,1);assert.equal(observed.get(name).kernel_lock_verified,true);assert.deepEqual(observed.get(name).record,record);}finally{await release();}
  assert.equal((await activeUserspaceLeases(state,guard)).size,0);
  assert.equal(JSON.parse(await readFile(path.join(state,name))).pid,process.pid);
  await writeFile(path.join(state,name),JSON.stringify({...record,kernel_lock:'.foreign.native'}));await assert.rejects(activeUserspaceLeases(state,guard));
 }finally{await rm(root,{recursive:true,force:true});}
},30000);
