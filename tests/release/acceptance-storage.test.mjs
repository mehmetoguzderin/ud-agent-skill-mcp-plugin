import { test, expect } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { withAcceptanceStorage, runAcceptanceCommand } from '../../scripts/quality/native-provider-acceptance.mjs';
import { recoverStorage, reserveStorage } from '../../scripts/quality/storage-lifecycle.mjs';
import { posixTest } from '../fixtures/native-scope.mjs';

function fixture(){return realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-provider-storage-test-')));}
for(const mode of ['pass','fail'])test(`provider ${mode} retains its report and removes the profile`,async()=>{
  const root=fixture(),reportPath=path.join(root,'report.json');let profile;
  try{
    const run=withAcceptanceStorage({root,reportPath,label:'provider-fixture'},async storage=>{
      profile=storage.profile;writeFileSync(path.join(profile,'case'),'input');storage.check();
      writeFileSync(reportPath,JSON.stringify({status:mode==='pass'?'passed':'failed-or-incomplete',profile}));
      if(mode==='fail')throw new Error('expected fixture failure');
      return 'completed';
    });
    if(mode==='fail')await expect(run).rejects.toThrow('expected fixture failure');else expect(await run).toBe('completed');
    const report=JSON.parse(readFileSync(reportPath));expect(report.scratch_cleanup).toBe('verified');expect(report.peak_scratch_bytes).toBeGreaterThan(0);
    expect(existsSync(profile)).toBe(false);expect(existsSync(path.join(root,'.artifacts/.storage-reservation'))).toBe(false);
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('existing reports are never rewritten on admission failure',async()=>{
  const root=fixture(),reportPath=path.join(root,'report.json');
  try{writeFileSync(reportPath,'existing report');await expect(withAcceptanceStorage({root,reportPath,label:'existing'},async()=>{})).rejects.toThrow(/new file/);expect(readFileSync(reportPath,'utf8')).toBe('existing report');expect(existsSync(path.join(root,'.artifacts/.storage-reservation'))).toBe(false);}
  finally{rmSync(root,{recursive:true,force:true});}
});

test('engine storage is admitted before profile creation and monitored without counting an existing image twice',async()=>{
  const root=fixture(),reportPath=path.join(root,'report.json');let entered=false;
  try{
    await expect(withAcceptanceStorage({root,reportPath,label:'engine-reject',engineAdmission:{ownedBytes:Number.MAX_SAFE_INTEGER-1,reservedBytes:1,measure:()=>0}},async()=>{entered=true;})).rejects.toThrow(/storage|budget|total/i);
    expect(entered).toBe(false);expect(existsSync(path.join(root,'.artifacts/.storage-reservation'))).toBe(false);
    let imported=25;
    await withAcceptanceStorage({root,reportPath,label:'engine-ok',engineAdmission:{ownedBytes:10,reservedBytes:100,measure:()=>imported}},async storage=>{
      storage.check();imported=101;expect(()=>storage.check()).toThrow(/exceeds/);imported=50;
      writeFileSync(reportPath,JSON.stringify({status:'passed'}));
    });
    expect(JSON.parse(readFileSync(reportPath)).engine_storage).toEqual({baseline_bytes:10,import_reservation_bytes:100,peak_imported_image_bytes:50,peak_engine_growth_bytes:50});
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('host replay can share a parent reservation while retaining its caller-owned installation',async()=>{
  const root=fixture(),reportPath=path.join(root,'report.json'),parent=reserveStorage({root,plannedBytes:4096});
  const priorLease=process.env.UD_STORAGE_LEASE,priorSize=process.env.UD_ACCEPTANCE_SCRATCH_BYTES;
  try{
    const installation=parent.write('npm-installed','shared payload');process.env.UD_STORAGE_LEASE=parent.env.UD_STORAGE_LEASE;process.env.UD_ACCEPTANCE_SCRATCH_BYTES='2048';let profile;
    await withAcceptanceStorage({root,reportPath,label:'host-child'},async storage=>{profile=storage.profile;writeFileSync(path.join(profile,'case'),'fixture');writeFileSync(reportPath,JSON.stringify({status:'passed'}));});
    expect(existsSync(profile)).toBe(false);expect(readFileSync(installation,'utf8')).toBe('shared payload');expect(JSON.parse(readFileSync(reportPath)).scratch_cleanup).toBe('verified');
  }finally{
    if(priorLease===undefined)delete process.env.UD_STORAGE_LEASE;else process.env.UD_STORAGE_LEASE=priorLease;
    if(priorSize===undefined)delete process.env.UD_ACCEPTANCE_SCRATCH_BYTES;else process.env.UD_ACCEPTANCE_SCRATCH_BYTES=priorSize;
    parent.cleanup();rmSync(root,{recursive:true,force:true});
  }
});

test('acceptance subprocesses return bounded output and time out as failures',async()=>{
  const root=fixture(),reportPath=path.join(root,'report.json');
  try{await withAcceptanceStorage({root,reportPath,label:'process-fixture'},async storage=>{
    const ok=await runAcceptanceCommand(process.execPath,['-e',"console.log('ok')"],{storage,env:process.env,timeout:5000});expect(ok.status).toBe(0);expect(ok.stdout.trim()).toBe('ok');
    await expect(runAcceptanceCommand(process.execPath,['-e','setInterval(()=>{},1000)'],{storage,env:process.env,timeout:100})).rejects.toThrow(/timed out/);
    writeFileSync(reportPath,JSON.stringify({status:'passed',profile:storage.profile}));
  });expect(JSON.parse(readFileSync(reportPath)).scratch_cleanup).toBe('verified');}
  finally{rmSync(root,{recursive:true,force:true});}
});

posixTest('cancelled provider closes the active client, preserves an incomplete report and cleans scratch',async()=>{
  const root=fixture(),reportPath=path.join(root,'report.json'),module=pathToFileURL(path.resolve('scripts/quality/native-provider-acceptance.mjs')).href;
  const code=`import{withAcceptanceStorage}from ${JSON.stringify(module)};import{writeFileSync}from'node:fs';import path from'node:path';
await withAcceptanceStorage({root:process.argv[1],reportPath:process.argv[2],label:'cancel-fixture'},async s=>{writeFileSync(path.join(s.profile,'case'),'input');writeFileSync(process.argv[2],JSON.stringify({status:'incomplete',profile:s.profile}));writeFileSync(process.argv[2]+'.ready','ready');await new Promise(resolve=>{const interval=setInterval(()=>{},10000);s.setClient({close:async()=>{clearInterval(interval);resolve();}})});s.check();});`;
  let child;
  try{
    child=spawn(process.execPath,['--input-type=module','-e',code,root,reportPath],{stdio:'ignore',env:{...process.env,UD_AGENT_STORAGE_ROOT:root,UD_STORAGE_LEASE:''}});
    const exited=new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
    for(let n=0;n<200&&!existsSync(reportPath+'.ready');n++)await new Promise(resolve=>setTimeout(resolve,20));
    expect(existsSync(reportPath+'.ready')).toBe(true);expect(existsSync(reportPath)).toBe(true);child.kill('SIGTERM');expect(await exited).toEqual({code:143,signal:null});
    const report=JSON.parse(readFileSync(reportPath));expect(report.status).toBe('failed-or-incomplete');expect(report.scratch_cleanup).toBe('verified');expect(existsSync(report.profile)).toBe(false);expect(readdirSync(path.join(root,'.artifacts'))).toEqual([]);
  }finally{child?.kill('SIGKILL');rmSync(root,{recursive:true,force:true});}
});

test('forced provider termination retains incomplete evidence and recovers only its stopped owned scratch',async()=>{
  const root=fixture(),reportPath=path.join(root,'report.json'),module=pathToFileURL(path.resolve('scripts/quality/native-provider-acceptance.mjs')).href;
  const code=`import{withAcceptanceStorage}from ${JSON.stringify(module)};import{writeFileSync}from'node:fs';import path from'node:path';
await withAcceptanceStorage({root:process.argv[1],reportPath:process.argv[2],label:'forced-cancel-fixture'},async s=>{writeFileSync(path.join(s.profile,'case'),'input');writeFileSync(process.argv[2],JSON.stringify({status:'incomplete',profile:s.profile}));writeFileSync(process.argv[2]+'.ready','ready');await new Promise(()=>setInterval(()=>{},10000));});`;
  let child,exited;
  try{
    child=spawn(process.execPath,['--input-type=module','-e',code,root,reportPath],{stdio:'ignore',env:{...process.env,UD_AGENT_STORAGE_ROOT:root,UD_STORAGE_LEASE:''}});
    exited=new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
    for(let n=0;n<200&&!existsSync(reportPath+'.ready');n++)await new Promise(resolve=>setTimeout(resolve,20));
    expect(existsSync(reportPath+'.ready')).toBe(true);expect(existsSync(reportPath)).toBe(true);const original=readFileSync(reportPath),report=JSON.parse(original);
    expect(report.status).toBe('incomplete');expect(existsSync(path.join(report.profile,'case'))).toBe(true);
    expect(()=>recoverStorage(root)).toThrow(/active or ambiguous/);
    const signal=process.platform==='win32'?'SIGTERM':'SIGKILL';expect(child.kill(signal)).toBe(true);expect(await exited).toEqual({code:null,signal});
    expect(readFileSync(reportPath)).toEqual(original);expect(existsSync(report.profile)).toBe(true);
    expect(recoverStorage(root)).toBe(true);expect(existsSync(report.profile)).toBe(false);
    expect(readFileSync(reportPath)).toEqual(original);expect(readdirSync(path.join(root,'.artifacts'))).toEqual([]);
  }finally{
    child?.kill('SIGKILL');if(exited)await exited;
    if(existsSync(path.join(root,'.artifacts/.storage-reservation')))recoverStorage(root);
    rmSync(root,{recursive:true,force:true});
  }
},15_000);
