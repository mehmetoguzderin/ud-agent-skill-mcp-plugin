/** Original owned controller lifecycle fixtures; no mutation executes on host. */
import { posixTest } from '../fixtures/native-scope.mjs';
import { test, expect, vi } from 'vitest';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ProtectedVitestTestRunner } from '../../scripts/quality/stryker-protected-runner.mjs';

async function fixture(mode,action){
 const root=await mkdtemp(path.join(os.tmpdir(),'ud-stryker-controller-')),marker=path.join(root,'cleaned');
 const code=mode==='hang'?'process.on("SIGTERM",()=>{});process.stdin.resume();setInterval(()=>{},1000);console.log("ready");':`const fs=require('node:fs');let ending=false;const finish=()=>{if(ending)return;ending=true;setTimeout(()=>{fs.writeFileSync(process.argv[1],'owned cleanup finished');process.exit(${mode==='cancel'?1:mode==='bad-exit'?7:0});},20);};process.on('SIGTERM',finish);process.stdin.on('end',finish);process.stdin.resume();console.log('ready');`;
 const child=spawn(process.execPath,['-e',code,marker],{stdio:['pipe','pipe','pipe'],env:{PATH:'',HOME:root,TMPDIR:root,TMP:root,TEMP:root,...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{})}});
 const runner=new ProtectedVitestTestRunner({}, {debug(){}});runner.child=child;runner.closed=false;
 child.once('close',(code,signal)=>{runner.closed=true;clearTimeout(runner.killTimer);runner.fail(new Error('Controller ended '+code+'/'+signal));});
 try{const[ready]=await once(child.stdout,'data');expect(ready.toString()).toBe('ready\n');await action({runner,child,marker});}
 finally{vi.useRealTimers();if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await once(child,'close');}await rm(root,{recursive:true,force:true});}
}

test('idle disposal waits for controller EOF cleanup before returning',()=>fixture('idle',async({runner,marker})=>{
 await runner.dispose();expect(runner.closed).toBe(true);expect(await readFile(marker,'utf8')).toBe('owned cleanup finished');
}));

posixTest('active disposal revokes the control lease and waits for owned cleanup instead of refusing cancellation',()=>fixture('cancel',async({runner,marker})=>{
 let failure;const pending=new Promise((resolve,reject)=>{runner.pending={id:'1',timer:setTimeout(()=>{},30000),resolve,reject};}).catch(error=>{failure=error;});
 await runner.dispose();await pending;expect(failure.message).toContain('cancelled during disposal');expect(runner.closed).toBe(true);expect(await readFile(marker,'utf8')).toBe('owned cleanup finished');
}));

test('a controller failure on ordinary disposal remains an error',()=>fixture('bad-exit',async({runner})=>{
 await expect(runner.dispose()).rejects.toThrow('did not finish owned disposal cleanly');
}));

test('forced termination of an unresponsive active controller remains a runner failure',()=>fixture('hang',async({runner})=>{
 vi.useFakeTimers({toFake:['setTimeout','clearTimeout']});
 const pending=new Promise((resolve,reject)=>{runner.pending={id:'1',timer:setTimeout(()=>{},30000),resolve,reject};}).catch(()=>{});
 const disposed=expect(runner.dispose()).rejects.toThrow('did not finish owned disposal cleanly');
 await vi.advanceTimersByTimeAsync(15000);await disposed;await pending;expect(runner.forcedControllerExit).toBe(true);
}));

if(process.platform==='win32')test('active Windows controller termination remains a failure without fabricating graceful cleanup',()=>fixture('cancel',async({runner,marker})=>{
 let failure;const pending=new Promise((resolve,reject)=>{runner.pending={id:'1',timer:setTimeout(()=>{},30000),resolve,reject};}).catch(error=>{failure=error;});
 await expect(runner.dispose()).rejects.toThrow('did not finish owned disposal cleanly');await pending;
 expect(failure.message).toContain('cancelled during disposal');expect(runner.closed).toBe(true);
 await expect(readFile(marker)).rejects.toMatchObject({code:'ENOENT'});
}));
