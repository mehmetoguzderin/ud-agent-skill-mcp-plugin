import { spawn } from 'node:child_process';
import { copyFile, chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { expect, test } from 'vitest';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';
import { guardedIdentity, guardedStateLock } from '../../packages/workspace/src/guard.js';
import { sha256 } from '../../packages/workspace/src/journal.js';

test('independent coordinator processes serialize fresh resource keys and inventories under the existing native lock',async()=>{
 const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-resource-processes-')));
 let executionError: unknown;
 try{
  const state=path.join(root,'state'),guard=path.join(root,'guard'+(process.platform==='win32'?'.exe':''));await copyFile(path.resolve(process.platform==='win32'?'target/debug/ud-agent-guard.exe':'target/debug/ud-agent-guard'),guard);await chmod(guard,0o700);
  const module=path.join(root,'resources.mjs');await build({entryPoints:[path.resolve('packages/coordinator/src/resources.ts')],outfile:module,bundle:true,platform:'node',format:'esm',target:'node24'});
  const program=path.join(root,'writer.mjs');await writeFile(program,`import {ResourceStore} from ${JSON.stringify(pathToFileURL(module).href)};const store=await ResourceStore.open(process.argv[2],['/same-grant'],process.argv[3]);const refs=[];for(let i=0;i<5;i++)refs.push(await store.put('reports',Buffer.from(process.argv[4]+':'+i),'text/plain'));process.stdout.write(JSON.stringify(refs));`);
  const settled=await Promise.allSettled(['alpha','beta','gamma','delta'].map(label=>new Promise<{label:string;refs:{uri:string}[]}>((resolve,reject)=>{
   const child=spawn(process.execPath,[program,state,guard,label],{env:{PATH:process.platform==='win32'?(process.env.SystemRoot??'C:\\Windows')+'\\System32':'/usr/bin:/bin',HOME:root,TMPDIR:root,TMP:root,TEMP:root,...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{})},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',bytes=>{stdout+=bytes;});child.stderr.on('data',bytes=>{stderr+=bytes;});let timedOut=false;const timeout=setTimeout(()=>{timedOut=true;child.kill();},process.platform==='win32'?90000:20000);child.once('error',reject);child.once('close',code=>{clearTimeout(timeout);if(timedOut||code!==0){reject(new Error(timedOut?'Resource child timed out: '+label:stderr||'Resource child failed: '+code));return;}try{resolve({label,refs:JSON.parse(stdout)});}catch(error){reject(error);}});
  })));
  const failures=settled.filter((result): result is PromiseRejectedResult=>result.status==='rejected');
  if(failures.length)throw new AggregateError(failures.map(result=>result.reason),'Resource child processes failed after every child closed.');
  const runs=settled.map(result=>(result as PromiseFulfilledResult<{label:string;refs:{uri:string}[]}>).value);
  const store=await ResourceStore.open(state,['/same-grant'],guard);expect(new Set(runs.flatMap(run=>run.refs.map(ref=>ref.uri))).size).toBe(20);
  for(const run of runs){expect(run.refs.length).toBe(5);for(const[index,ref]of run.refs.entries())expect((await store.read(new URL(ref.uri))).contents[0]).toMatchObject({text:run.label+':'+index});}
  expect((await readFile(path.join(state,'cursor.key'))).length).toBe(32);
 }catch(error){executionError=error;throw error;}finally{
  try{await rm(root,{recursive:true,force:true,maxRetries:10,retryDelay:100});}
  catch(cleanupError){if(executionError)throw new AggregateError([executionError,cleanupError],'Resource test failed and owned cleanup also failed.');throw cleanupError;}
 }
},process.platform==='win32'?180000:60000);

test('resource contention is cancellable while old directory locks remain protected recovery state',async()=>{
 const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-resource-lock-policy-')));
 try{
  const guard=path.join(root,'guard'+(process.platform==='win32'?'.exe':''));await copyFile(path.resolve(process.platform==='win32'?'target/debug/ud-agent-guard.exe':'target/debug/ud-agent-guard'),guard);await chmod(guard,0o700);
  const state=path.join(root,'state'),store=await ResourceStore.open(state,['/grant'],guard),name=sha256('resource-inventory'),identity=await guardedIdentity(guard,state);
  const release=await guardedStateLock(guard,state,'locks/'+name+'.native',identity),controller=new AbortController();
  try{const pending=store.put('reports',Buffer.from('cancelled'),'text/plain',undefined,controller.signal);setTimeout(()=>controller.abort(),30);await expect(pending).rejects.toThrow('WORKER_CANCELLED');}finally{await release();}
  const legacy=path.join(state,'locks',name);await mkdir(legacy,{mode:0o700});await writeFile(path.join(legacy,'owner'),'unproven older owner');
  await expect(store.put('reports',Buffer.from('must not steal'),'text/plain')).rejects.toThrow('older directory lock requires explicit recovery');expect(await readFile(path.join(legacy,'owner'),'utf8')).toBe('unproven older owner');
  // Test teardown owns the deliberately injected obsolete fixture lock.
  await rm(legacy,{recursive:true});const ref=await store.put('reports',Buffer.from('usable after rejection'),'text/plain');expect((await store.read(new URL(ref.uri))).contents[0]).toMatchObject({text:'usable after rejection'});
 }finally{await rm(root,{recursive:true,force:true});}
},30000);
