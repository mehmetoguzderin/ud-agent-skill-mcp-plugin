/** Original entrypoint observations, not mutant execution or coverage claims. */
import {expect,test} from 'vitest';
import {createRequire} from 'node:module';
import {spawn,spawnSync} from 'node:child_process';
import {Worker} from 'node:worker_threads';
import {promisify} from 'node:util';
import {createSubprocessOpacityRecorder,installSubprocessOpacityCapture,validateSubprocessOpacity,normalizeSubprocessOpacity} from '../../scripts/quality/stryker-opacity.mjs';

test('transparent wrappers preserve receiver, argument identities, return values, errors and function metadata',async()=>{
  const recorder=createSubprocessOpacityRecorder(),receiver={},args=[{},[]],output={},fault=new TypeError('actual fixture fault'),custom=()=>{};
  function original(a,b){expect(this).toBe(receiver);expect(a).toBe(args[0]);expect(b).toBe(args[1]);return output;}
  original[promisify.custom]=custom;
  const wrapped=recorder.wrap('spawn',original);expect(wrapped.name).toBe(original.name);expect(wrapped.length).toBe(original.length);expect(wrapped[promisify.custom]).toBe(custom);
  await recorder.runScope({kind:'case',id:'native-task-1'},async()=>{expect(wrapped.apply(receiver,args)).toBe(output);await Promise.resolve();expect(()=>recorder.wrap('exec',()=>{throw fault;})()).toThrow(fault);});
  expect(validateSubprocessOpacity(recorder.snapshot())).toMatchObject({complete:true,calls:2,records:[{scope:{kind:'case',id:'native-task-1'},methods:[{name:'spawn',count:1},{name:'exec',count:1}]}]});
});
test('concurrent async scopes keep actual case identity and closed-scope callbacks become global',async()=>{
  const recorder=createSubprocessOpacityRecorder(),wrapped=recorder.wrap('spawnSync',()=>{});let finish,late;
  const wait=new Promise(resolve=>finish=resolve);
  await Promise.all([recorder.runScope({kind:'case',id:'one'},async()=>{await wait;wrapped();}),recorder.runScope({kind:'case',id:'two'},async()=>{wrapped();finish();})]);
  await recorder.runScope({kind:'case',id:'ended'},async()=>{late=new Promise(resolve=>setTimeout(()=>{wrapped();resolve();},10));});await late;
  const value=validateSubprocessOpacity(recorder.snapshot());expect(value.calls).toBe(3);expect(value.records.map(row=>row.scope)).toEqual([{kind:'case',id:'one'},{kind:'case',id:'two'},{kind:'global'}]);
});
test('file fixtures, case calls and unassigned collection calls remain distinct conservative scopes',async()=>{
  const recorder=createSubprocessOpacityRecorder(),wrapped=recorder.wrap('fork',()=>{});wrapped();
  await recorder.runScope({kind:'file',path:'tests/cli.test.ts'},async()=>{wrapped();await recorder.runScope({kind:'case',id:'actual-task'},async()=>wrapped());wrapped();});
  const report=validateSubprocessOpacity(recorder.snapshot());expect(report.calls).toBe(4);expect(report.records).toEqual([{scope:{kind:'case',id:'actual-task'},methods:[{name:'fork',count:1}]},{scope:{kind:'file',path:'tests/cli.test.ts'},methods:[{name:'fork',count:2}]},{scope:{kind:'global'},methods:[{name:'fork',count:1}]}]);
});
test('malformed, truncated, duplicated or incomplete opacity evidence cannot certify selection',()=>{
  const recorder=createSubprocessOpacityRecorder();recorder.wrap('execFileSync',()=>{})();const original=recorder.snapshot();
  for(const edit of [value=>value.complete=false,value=>value.calls++,value=>value.records.push(value.records[0]),value=>value.records[0].methods.push(value.records[0].methods[0]),value=>value.records[0].methods[0].count=0,value=>value.records[0].methods[0].name='unknown',value=>value.records[0].scope={kind:'file',path:'../tests/escape.ts'},value=>value.records[0].scope={kind:'global',id:'fake-narrow-scope'},value=>delete value.records]){
    const changed=structuredClone(original);edit(changed);expect(()=>validateSubprocessOpacity(changed)).toThrow(/opacity|Opacity/);
  }
  expect(()=>recorder.wrap('unknown',()=>{})).toThrow('supported');
});
test('actual original subprocess calls preserve sync and async results and are observable through existing ESM imports',async()=>{
  const recorder=createSubprocessOpacityRecorder(),capture=installSubprocessOpacityCapture(recorder),require=createRequire(import.meta.url),module=require('node:child_process'),custom=module.exec[promisify.custom];
  try{
    await capture.runScope({kind:'case',id:'real-subprocess'},async()=>{
      const sync=spawnSync(process.execPath,['-e','process.stdout.write("actual-sync");process.exitCode=7'],{encoding:'utf8'});expect(sync.error).toBeUndefined();expect(sync.status).toBe(7);expect(sync.stdout).toBe('actual-sync');
      const asynchronous=spawn(process.execPath,['-e','process.stdout.write("actual-async")']);let text='';asynchronous.stdout.on('data',chunk=>text+=chunk);const code=await new Promise((resolve,reject)=>{asynchronous.once('error',reject);asynchronous.once('close',resolve);});expect(code).toBe(0);expect(text).toBe('actual-async');
    });
    expect(module.exec[promisify.custom]).toBe(custom);
    const value=validateSubprocessOpacity(capture.snapshot());expect(value.complete).toBe(true);expect(value.records).toHaveLength(1);expect(value.records[0].scope).toEqual({kind:'case',id:'real-subprocess'});expect(value.records[0].methods).toEqual([{name:'spawn',count:1},{name:'spawnSync',count:1},{name:'ChildProcess.spawn',count:1}]);
  }finally{capture.restore();}
});
test('actual original Worker construction preserves identity and messages while native-addon uncertainty remains explicit',async()=>{
  const recorder=createSubprocessOpacityRecorder(),capture=installSubprocessOpacityCapture(recorder);
  try{
    await capture.runScope({kind:'case',id:'thread-case'},async()=>{
      const worker=new Worker('require("node:worker_threads").parentPort.postMessage("original-worker");',{eval:true});expect(worker).toBeInstanceOf(Worker);
      const message=await new Promise((resolve,reject)=>{worker.once('message',resolve);worker.once('error',reject);});expect(message).toBe('original-worker');await worker.terminate();
    });
    const value=validateSubprocessOpacity(capture.snapshot());expect(value.records.find(row=>row.scope.id==='thread-case').methods).toEqual([{name:'worker_threads.Worker',count:1}]);
    recorder.markNativeUncertainty('native-addon-load');expect(capture.snapshot().uncertainties).toContain('native-addon-load');
  }finally{capture.restore();}
});
test('source-bound task replay includes all colliding native identities and fails closed on missing or stale inventories',()=>{
  const tests=[{id:'case1',source:'tests/a.ts',source_sha256:'a'.repeat(64)},{id:'case2',source:'tests/a.ts',source_sha256:'a'.repeat(64)},{id:'case3',source:'tests/b.ts',source_sha256:'b'.repeat(64)}];
  const observations=()=>({schema_version:1,contract:'pristine-subprocess-opacity-v1',qualification:'entrypoint-observations-not-unique-process-counts',complete:true,calls:0,uncertainties:[],records:[]});
  const raw={schema_version:1,contract:'pristine-subprocess-opacity-source-v1',files:['tests/a.ts','tests/b.ts'].map(source=>({source,source_sha256:tests.find(test=>test.source===source).source_sha256,observations:observations(),case_tasks:tests.filter(test=>test.source===source).map(test=>({native_id:test.id==='case2'?'case1':test.id,case_id:test.id}))}))};
  raw.files[0].observations.calls=1;raw.files[0].observations.records=[{scope:{kind:'case',id:'case1'},methods:[{name:'spawn',count:1}]}];
  expect(normalizeSubprocessOpacity(raw,tests)).toMatchObject({global:false,case_ids:['case1','case2'],files:[]});
  const missing=structuredClone(raw);missing.files.pop();expect(()=>normalizeSubprocessOpacity(missing,tests)).toThrow('omitted');
  const stale=structuredClone(raw);stale.files[0].source_sha256='f'.repeat(64);expect(()=>normalizeSubprocessOpacity(stale,tests)).toThrow('stale');
  const unknown=structuredClone(raw);unknown.files[0].observations.records[0].scope.id='unassigned';expect(normalizeSubprocessOpacity(unknown,tests)).toMatchObject({global:true,uncertainties:['unmapped-case']});
  const native=structuredClone(raw);native.files[0].observations.uncertainties=['native-addon-load'];expect(normalizeSubprocessOpacity(native,tests)).toMatchObject({global:true,uncertainties:['native-addon-load']});
});
