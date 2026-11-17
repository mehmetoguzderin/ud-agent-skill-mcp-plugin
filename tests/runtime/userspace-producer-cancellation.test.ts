import { spawnSync } from 'node:child_process';
import { copyFile, readdir, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it, vi } from 'vitest';

const stalled = vi.hoisted(() => ({ executable: '', enabled: false, observedSignal: undefined as AbortSignal | undefined, frameSignal: undefined as AbortSignal | undefined, failSpawn: false, missingExecutable: '', started: undefined as (() => void) | undefined }));
vi.mock('node:child_process', async importOriginal => {
  const original = await importOriginal<typeof import('node:child_process')>();
  return { ...original, spawn: ((executable: string, args: string[], options: Parameters<typeof original.spawn>[2]) => original.spawn(stalled.failSpawn && ['contained-run','-I'].includes(args[0] ?? '') ? stalled.missingExecutable : executable, args, options)) as typeof original.spawn };
});
vi.mock('../../packages/workspace/src/snapshot-transfer.js', async importOriginal => {
  const original = await importOriginal<typeof import('../../packages/workspace/src/snapshot-transfer.js')>();
  return { ...original, streamVerifiedSnapshot: (...args: Parameters<typeof original.streamVerifiedSnapshot>) => { stalled.frameSignal=args[2]; return original.streamVerifiedSnapshot(...args); } };
});
vi.mock('../../packages/workspace/src/guard.js', async importOriginal => {
  const original = await importOriginal<typeof import('../../packages/workspace/src/guard.js')>();
  return { ...original, guardedRead: (...args: Parameters<typeof original.guardedRead>) => {
    if (stalled.enabled && path.basename(args[1]).startsWith('ud-agent-snapshot-')) {
      stalled.observedSignal = args[5]; stalled.started?.();
      // This is a real, single-process native executable. The ordinary guard
      // adapter must terminate and reap it when the frame signal is revoked.
      return original.guardedRead(stalled.executable, ...args.slice(1) as [string,string,number,Parameters<typeof original.guardedRead>[4],AbortSignal?]);
    }
    return original.guardedRead(...args);
  } };
});
import { runUserspaceValidation } from '../../packages/coordinator/src/userspace-worker.js';
const realTimeout = globalThis.setTimeout;
const delay = (ms: number) => new Promise<void>(resolve => realTimeout(resolve, ms));
async function fixture(test: (runtime: Parameters<typeof runUserspaceValidation>[0], root:string, marker:string) => Promise<void>) {
  const base = await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-userspace-producer-')));
  try {
    const root=path.join(base,'workspace'), worker=path.join(base,'worker'), marker=path.join(base,'guard-started');await mkdir(root);await mkdir(path.join(worker,'ud_agent'),{recursive:true});await writeFile(path.join(root,'a.conllu'),'# text = a\n');
    for(const name of ['__init__.py','contexts.py','evidence.py','errors.py','snapshot_receiver.py','unicode_paths.py','unicode_casefold.json','userspace_operations.json'])await copyFile(path.resolve('workers/ud/src/ud_agent',name),path.join(worker,'ud_agent',name));
    await writeFile(path.join(worker,'ud_agent/wire.py'),'MAX_REQUEST_BYTES=16777216\ndef encode(v):return b"{}\\n"\ndef process(v):return {}\n');
    const context=path.join(base,'context.json');await writeFile(context,'{}');
    const source=path.join(base,'hanging-guard.rs'), executable=path.join(base,process.platform==='win32'?'hanging-guard.exe':'hanging-guard');
    await writeFile(source,`fn main(){std::fs::write(r###"${marker}"###,std::process::id().to_string()).expect("fixture marker");loop{std::thread::sleep(std::time::Duration::from_secs(1));}}`);
    const compiled=spawnSync('rustc',[source,'-o',executable],{encoding:'utf8',timeout:60000});expect(compiled.status,compiled.stderr).toBe(0);
    stalled.executable=executable;stalled.enabled=true;
    await test({python:await realpath(process.env.UD_AGENT_PYTHON??path.resolve(process.platform==='win32'?'.venv/Scripts/python.exe':'.venv/bin/python')),workerPath:worker,upstreamPath:base,contextPath:context,bootstrap:path.resolve('workers/ud/src/ud_agent/userspace_bootstrap.py'),guard:path.resolve(process.platform==='win32'?'target/debug/ud-agent-guard.exe':'target/debug/ud-agent-guard')},root,marker);
  } finally {stalled.enabled=false;stalled.started=undefined;stalled.observedSignal=undefined;stalled.frameSignal=undefined;stalled.failSpawn=false;vi.restoreAllMocks();await rm(base,{recursive:true,force:true});}
}
async function nativeReadStarted(marker:string,timeoutMs=5000,pending?:Promise<unknown>):Promise<number>{
  const completion:{settled:boolean;rejected:boolean;value:unknown}={settled:false,rejected:false,value:undefined};
  pending?.then(value=>{completion.settled=true;completion.value=value;},error=>{completion.settled=true;completion.rejected=true;completion.value=error;});
  const deadline=Date.now()+timeoutMs;
  for(;;){
    if(completion.settled){
      if(completion.rejected)throw completion.value;
      throw new Error('Public dispatch completed before the controlled native read started: '+JSON.stringify(completion.value));
    }
    if(Date.now()>=deadline)throw new Error('Controlled native read did not start');
    try{const text=await readFile(marker,'utf8');if(/^[1-9][0-9]*$/.test(text))return Number(text);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    await delay(10);
  }
}
async function assertReaped(pid:number){let absent=false;for(let at=0;at<100;at++){try{process.kill(pid,0);}catch(error){if((error as NodeJS.ErrnoException).code==='ESRCH'){absent=true;break;}throw error;}await delay(10);}expect(absent,'The controlled native helper must be reaped').toBe(true);}
function request(root:string,signal:AbortSignal){return{operation:'validation_report',arguments:{working_tree_path:root,file_paths:['a.conllu'],ud_context_path:''},allowedRoots:[root],signal};}

it('the unchanged300s worker watchdog aborts and reaps a pending guarded frame read',async()=>fixture(async(runtime,root,marker)=>{
  let fire:(()=>void)|undefined;const requested:number[]=[];
  vi.spyOn(globalThis,'setTimeout').mockImplementation(((callback:(...args:unknown[])=>void,ms?:number,...args:unknown[])=>{if(ms===300000){requested.push(ms);fire=()=>callback(...args);return realTimeout(()=>{},ms);}return realTimeout(callback,ms,...args);})as typeof setTimeout);
  const caller=new AbortController();const pending=runUserspaceValidation(runtime,request(root,caller.signal)).then(()=>({ok:true,error:''}),error=>({ok:false,error:String(error)}));
  const pid=await nativeReadStarted(marker);expect(fire).toBeTypeOf('function');expect(requested).toEqual([300000]);
  await delay(25);fire!();const result=await Promise.race([pending,delay(1000).then(()=>undefined)]);if(!result)caller.abort();await pending;
  expect(result,'Timeout must not wait for the guard own30s timer').toMatchObject({ok:false,error:expect.stringContaining('WORKER_TIMEOUT')});expect(stalled.observedSignal?.aborted).toBe(true);expect(caller.signal.aborted).toBe(false);await assertReaped(pid);
}),15000);

it('caller cancellation revokes the pending native producer and preserves the cancellation reason',async()=>fixture(async(runtime,root,marker)=>{
  const caller=new AbortController(),pending=runUserspaceValidation(runtime,request(root,caller.signal)).then(()=>({ok:true,error:''}),error=>({ok:false,error:String(error)}));const pid=await nativeReadStarted(marker);await delay(25);caller.abort();const result=await Promise.race([pending,delay(1000).then(()=>undefined)]);await pending;
  expect(result).toMatchObject({ok:false,error:expect.stringContaining('WORKER_CANCELLED')});expect(stalled.observedSignal?.aborted).toBe(true);await assertReaped(pid);
}),15000);

it('an already exited nonzero worker revokes its pending producer before close can wait on FD3',async()=>fixture(async(runtime,root,marker)=>{
  const rejected=path.join(path.dirname(root),'reject.py');await writeFile(rejected,`import pathlib,time\np=pathlib.Path(${JSON.stringify(marker)})\nwhile not p.exists():time.sleep(.01)\nraise SystemExit(7)\n`);
  const caller=new AbortController(),pending=runUserspaceValidation({...runtime,bootstrap:rejected},request(root,caller.signal)).then(()=>({ok:true,error:''}),error=>({ok:false,error:String(error)}));const pid=await nativeReadStarted(marker);const result=await Promise.race([pending,delay(1000).then(()=>undefined)]);if(!result)caller.abort();await pending;
  expect(result).toMatchObject({ok:false,error:expect.stringContaining('WORKER_EXECUTION_FAILED')});expect(stalled.observedSignal?.aborted).toBe(true);await assertReaped(pid);
}),15000);

it('spawn failure revokes the frame signal and retains the original spawn error',async()=>fixture(async(runtime,root)=>{
  stalled.failSpawn=true;stalled.missingExecutable=path.join(path.dirname(root),'missing-executable');
  const caller=new AbortController();const pending=runUserspaceValidation(runtime,request(root,caller.signal)).then(()=>({ok:true,error:''}),error=>({ok:false,error:String(error)}));const result=await Promise.race([pending,delay(1500).then(()=>undefined)]);if(!result)caller.abort();await pending;
  expect(result).toMatchObject({ok:false,error:expect.stringMatching(/ENOENT|no such file|WORKER_EXECUTION_FAILED/i)});expect(caller.signal.aborted).toBe(false);expect(stalled.frameSignal?.aborted).toBe(true);
}),15000);

it('public dispatch rejects stalled transfer timeout/cancellation and releases its real runtime lease',async()=>fixture(async(_runtime,_root,marker)=>{
  stalled.enabled=false;
  const {withFrozenUserspacePack}=await import('../protocol/userspace-fixture.js');
  const {executeOperation}=await import('../../packages/coordinator/src/operations.js');
  await withFrozenUserspacePack(async({ready,workspace,options,domain,contract,args,bytes,state})=>{
    expect(ready).toMatchObject({status:'ready',ready:true,runtime:{engine:'userspace'}});
    for(const mode of ['timeout','cancel']) {
      await rm(marker,{force:true});stalled.enabled=true;let fire:(()=>void)|undefined;
      const timer=vi.spyOn(globalThis,'setTimeout').mockImplementation(((callback:(...args:unknown[])=>void,ms?:number,...args:unknown[])=>{if(ms===300000){fire=()=>callback(...args);return realTimeout(()=>{},ms);}return realTimeout(callback,ms,...args);})as typeof setTimeout);
      const caller=new AbortController(),pending=executeOperation(contract,args,domain,options,caller.signal);
      try {
        // Windows performs real lease and helper verification before streaming.
        const pid=await nativeReadStarted(marker,process.platform==='win32'?60000:5000,pending);
        expect(fire).toBeTypeOf('function');await delay(25);if(mode==='timeout')fire!();else caller.abort();
        const result=await Promise.race([pending,delay(1500).then(()=>undefined)]);if(!result)caller.abort();await pending;
        expect(result,'Public dispatch must await bounded native cleanup').toMatchObject({isError:true,structuredContent:{execution:{status:'rejected'},result:{status:'rejected',reason:mode==='timeout'?'WORKER_TIMEOUT':'WORKER_CANCELLED'}}});
        expect(stalled.observedSignal?.aborted).toBe(true);expect((await readdir(state)).filter(name=>/^\.lease-/.test(name))).toEqual([]);expect(await readFile(path.join(workspace,'sample.conllu'))).toEqual(bytes);await assertReaped(pid);
      } finally {
        caller.abort();await pending.catch(()=>undefined);timer.mockRestore();stalled.enabled=false;
      }
    }
  });
}),process.platform === 'win32' ? 180000 : 30000);
