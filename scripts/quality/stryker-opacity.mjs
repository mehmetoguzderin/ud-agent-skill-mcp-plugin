/** Observed original subprocess entrypoints; these are not fabricated hits. */
import {AsyncLocalStorage} from 'node:async_hooks';
import {createRequire,syncBuiltinESMExports} from 'node:module';
import {createHash} from 'node:crypto';

const METHODS=['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork','ChildProcess.spawn','worker_threads.Worker'];
const UNCERTAINTIES=['preexisting-native-addon','unbounded-native-library','native-addon-state-unavailable','native-addon-load','concurrent-test-attribution'];
const CONTROL=Object.freeze({schema_version:1,contract:'pristine-subprocess-opacity-v1',qualification:'entrypoint-observations-not-unique-process-counts'});
const safePath=value=>typeof value==='string'&&value.startsWith('tests/')&&!/[\\\0:]/.test(value)&&value.split('/').every(part=>part&&part!=='.'&&part!=='..');
const scopes=new Set(['case','file','global']);

function scopeRecord(value){
  if(!value||!scopes.has(value.kind))throw new Error('Opacity observation requires an actual case, file or global scope.');
  if(value.kind==='case'){
    if(Object.keys(value).sort().join(',')!=='id,kind'||typeof value.id!=='string'||!value.id||value.id.length>65536||/[\0\r\n]/.test(value.id))throw new Error('Opacity case scope must bind the actual Vitest task identity.');
    return{kind:'case',id:value.id};
  }
  if(value.kind==='file'){
    if(Object.keys(value).sort().join(',')!=='kind,path'||!safePath(value.path))throw new Error('Opacity fixture scope must bind a canonical original test file.');
    return{kind:'file',path:value.path};
  }
  if(Object.keys(value).join(',')!=='kind')throw new Error('Global opacity cannot claim a narrower identity.');
  return{kind:'global'};
}

/** ALS retains the originating case across awaits/concurrent tests. A callback
 * after its scope closed is deliberately global, never attributed to a later
 * current test or silently discarded. Exceeding bounds marks evidence invalid.
 */
export function createSubprocessOpacityRecorder(){
  const current=new AsyncLocalStorage(),records=new Map(),uncertainties=new Set();let calls=0,complete=true;
  const observe=method=>{
    if(!METHODS.includes(method)){complete=false;return;}
    if(++calls>1000000){complete=false;return;}
    const active=current.getStore(),scope=active?.active?active.scope:{kind:'global'},key=JSON.stringify(scope);
    if(!records.has(key)){
      if(records.size>=50000){complete=false;return;}
      records.set(key,{scope,methods:new Map()});
    }
    const entry=records.get(key);entry.methods.set(method,(entry.methods.get(method)??0)+1);
  };
  return{
    markNativeUncertainty(reason){if(!UNCERTAINTIES.includes(reason))throw new Error('Unknown native-addon opacity uncertainty.');uncertainties.add(reason);},
    async runScope(scope,action){
      const token={scope:scopeRecord(scope),active:true};
      if(typeof action!=='function')throw new Error('Opacity scope requires the unchanged runner callback.');
      try{return await current.run(token,action);}finally{token.active=false;}
    },
    wrap(method,original){
      if(!METHODS.includes(method)||typeof original!=='function')throw new Error('Opacity wrapper requires a supported original subprocess function.');
      // Proxy preserves constructor identity/prototype metadata and custom
      // promisification properties while retaining the exact invocation.
      return new Proxy(original,{apply(target,receiver,args){observe(method);return Reflect.apply(target,receiver,args);},construct(target,args,newTarget){observe(method);return Reflect.construct(target,args,newTarget);}});
    },
    snapshot(){return{...CONTROL,complete,calls,uncertainties:[...uncertainties].sort(),records:[...records.values()].map(({scope,methods})=>({scope:{...scope},methods:METHODS.filter(name=>methods.has(name)).map(name=>({name,count:methods.get(name)}))})).sort((a,b)=>JSON.stringify(a.scope)<JSON.stringify(b.scope)?-1:JSON.stringify(a.scope)>JSON.stringify(b.scope)?1:0)};},
  };
}

/** Install only in a fixed worker setup before project modules. Every argument,
 * receiver, return value and thrown exception is passed through unchanged.
 * Restore is intended for original calibration tests; changed hooks fail closed.
 */
export function installSubprocessOpacityCapture(recorder){
  if(!recorder||typeof recorder.wrap!=='function')throw new Error('Opacity recorder is missing.');
  const require=createRequire(import.meta.url),module=require('node:child_process'),threads=require('node:worker_threads'),installed=[];
  for(const name of METHODS){
    const target=name==='ChildProcess.spawn'?module.ChildProcess.prototype:name==='worker_threads.Worker'?threads:module,key=name==='ChildProcess.spawn'?'spawn':name==='worker_threads.Worker'?'Worker':name;
    const descriptor=Object.getOwnPropertyDescriptor(target,key);
    if(!descriptor||!descriptor.writable||typeof descriptor.value!=='function')throw new Error('Node subprocess observation boundary changed.');
    const wrapper=recorder.wrap(name,descriptor.value);installed.push({target,key,descriptor,wrapper});
  }
  const loader=Object.getOwnPropertyDescriptor(process,'dlopen');
  if(!loader||!loader.writable||typeof loader.value!=='function')throw new Error('Node native-addon observation boundary changed.');
  const loaderWrapper=new Proxy(loader.value,{apply(target,receiver,args){recorder.markNativeUncertainty('native-addon-load');return Reflect.apply(target,receiver,args);}});
  installed.push({target:process,key:'dlopen',descriptor:loader,wrapper:loaderWrapper});
  try{
    const libraries=process.report?.getReport()?.sharedObjects;
    if(!Array.isArray(libraries)||libraries.some(value=>typeof value!=='string'))recorder.markNativeUncertainty('native-addon-state-unavailable');
    else{
      if(libraries.some(value=>value.endsWith('.node')))recorder.markNativeUncertainty('preexisting-native-addon');
      // No broad native-library allowlist is inferred from a filename. Until
      // a frozen provider proves those bindings cannot hide test execution,
      // additional loaded native code makes narrowing unprovable.
      if(libraries.some(value=>value!==process.execPath&&!value.endsWith('.node')))recorder.markNativeUncertainty('unbounded-native-library');
    }
  }catch{recorder.markNativeUncertainty('native-addon-state-unavailable');}
  for(const {target,key,descriptor,wrapper}of installed)Object.defineProperty(target,key,{...descriptor,value:wrapper});
  syncBuiltinESMExports();
  const verify=()=>{
    if(installed.some(({target,key,wrapper})=>Object.getOwnPropertyDescriptor(target,key)?.value!==wrapper))throw new Error('Node subprocess observation boundary was replaced after installation.');
  };
  return{runScope:recorder.runScope,snapshot(){verify();return recorder.snapshot();},restore(){
    verify();
    for(const {target,key,descriptor}of installed.reverse())Object.defineProperty(target,key,descriptor);
    syncBuiltinESMExports();
  }};
}

/** Reject truncated/forged counters before mapping native task IDs to frozen
 * case identities. Unknown calls are intentionally global full-suite opacity.
 */
export function validateSubprocessOpacity(value){
  if(!value||Object.keys(value).sort().join(',')!=='calls,complete,contract,qualification,records,schema_version,uncertainties'||value.schema_version!==1||value.contract!==CONTROL.contract||value.qualification!==CONTROL.qualification||value.complete!==true||!Number.isSafeInteger(value.calls)||value.calls<0||value.calls>1000000||!Array.isArray(value.records)||value.records.length>50000||!Array.isArray(value.uncertainties)||new Set(value.uncertainties).size!==value.uncertainties.length||value.uncertainties.some(reason=>!UNCERTAINTIES.includes(reason)))throw new Error('Original subprocess opacity evidence is incomplete or invalid.');
  const keys=new Set();let total=0;
  for(const row of value.records){
    if(!row||Object.keys(row).sort().join(',')!=='methods,scope'||!Array.isArray(row.methods)||!row.methods.length||row.methods.length>METHODS.length)throw new Error('Original subprocess opacity record is malformed.');
    const scope=scopeRecord(row.scope),key=JSON.stringify(scope),seen=new Set();
    if(keys.has(key))throw new Error('Original subprocess opacity scope is duplicated.');keys.add(key);
    for(const item of row.methods){
      if(!item||Object.keys(item).sort().join(',')!=='count,name'||!METHODS.includes(item.name)||seen.has(item.name)||!Number.isSafeInteger(item.count)||item.count<1||item.count>1000000)throw new Error('Original subprocess opacity method counter is invalid.');
      total+=item.count;seen.add(item.name);
    }
  }
  if(total!==value.calls)throw new Error('Original subprocess opacity evidence omits observed calls.');
  return value;
}

/** Replay native-task attribution against the complete frozen case catalog.
 * Colliding task IDs include every matching case. Unmapped/global/addon
 * uncertainty requires the whole suite rather than an invented attribution.
 */
export function normalizeSubprocessOpacity(raw,tests){
  if(!raw||Object.keys(raw).sort().join(',')!=='contract,files,schema_version'||raw.schema_version!==1||raw.contract!=='pristine-subprocess-opacity-source-v1'||!Array.isArray(raw.files)||!raw.files.length||raw.files.length>50000||!Array.isArray(tests)||!tests.length)throw new Error('Complete source-bound original opacity evidence is required.');
  const known=new Map(),sources=new Map(),aliases=new Map(),mapped=new Set();
  for(const test of tests){
    if(!test||typeof test.id!=='string'||known.has(test.id)||!safePath(test.source)||!/^[a-f0-9]{64}$/.test(test.source_sha256??''))throw new Error('Original opacity requires a unique frozen test inventory.');
    known.set(test.id,test);if(sources.has(test.source)&&sources.get(test.source)!==test.source_sha256)throw new Error('Original opacity source fingerprints conflict.');sources.set(test.source,test.source_sha256);
  }
  for(const file of raw.files){
    if(!file||Object.keys(file).sort().join(',')!=='case_tasks,observations,source,source_sha256'||!sources.has(file.source)||file.source_sha256!==sources.get(file.source)||!Array.isArray(file.case_tasks)||!file.case_tasks.length)throw new Error('Original opacity file identity is missing or stale.');
    validateSubprocessOpacity(file.observations);
    for(const task of file.case_tasks){
      const test=known.get(task?.case_id);
      if(!task||Object.keys(task).sort().join(',')!=='case_id,native_id'||typeof task.native_id!=='string'||!task.native_id||task.native_id.length>65536||/[\0\r\n]/.test(task.native_id)||!test||test.source!==file.source||mapped.has(task.case_id))throw new Error('Original opacity task identity is missing, foreign or duplicated.');
      mapped.add(task.case_id);const ids=aliases.get(task.native_id)??new Set();ids.add(task.case_id);aliases.set(task.native_id,ids);
    }
  }
  if(mapped.size!==known.size)throw new Error('Original opacity omitted required test task identities.');
  const cases=new Set(),files=new Set(),uncertainties=new Set();let global=false;
  for(const file of raw.files){
    for(const reason of file.observations.uncertainties){global=true;uncertainties.add(reason);}
    for(const row of file.observations.records){
      if(row.scope.kind==='global')global=true;
      else if(row.scope.kind==='file'){
        if(sources.has(row.scope.path))files.add(row.scope.path);else{global=true;uncertainties.add('unmapped-file');}
      }else{
        const ids=aliases.get(row.scope.id);
        if(!ids){global=true;uncertainties.add('unmapped-case');}else for(const id of ids)cases.add(id);
      }
    }
  }
  return{schema_version:1,contract:'pristine-opaque-execution-closure-v1',observations_sha256:createHash('sha256').update(JSON.stringify(raw)).digest('hex'),global,case_ids:tests.filter(test=>cases.has(test.id)).map(test=>test.id),files:[...files].sort(),uncertainties:[...uncertainties].sort()};
}

export function validateOpaqueExecutionClosure(value,tests){
  if(!value||Object.keys(value).sort().join(',')!=='case_ids,contract,files,global,observations_sha256,schema_version,uncertainties'||value.schema_version!==1||value.contract!=='pristine-opaque-execution-closure-v1'||!/^[a-f0-9]{64}$/.test(value.observations_sha256??'')||typeof value.global!=='boolean'||!Array.isArray(value.case_ids)||new Set(value.case_ids).size!==value.case_ids.length||!Array.isArray(value.files)||new Set(value.files).size!==value.files.length||!Array.isArray(value.uncertainties)||new Set(value.uncertainties).size!==value.uncertainties.length||value.uncertainties.some(reason=>![...UNCERTAINTIES,'unmapped-file','unmapped-case'].includes(reason))||value.uncertainties.length&&!value.global)throw new Error('Original opaque execution closure is invalid.');
  const ids=new Set(tests.map(test=>test.id)),sources=new Set(tests.map(test=>test.source));
  if(value.case_ids.some(id=>!ids.has(id))||value.files.some(source=>!sources.has(source)))throw new Error('Original opaque execution closure identifies unknown cases/files.');
  return value;
}
