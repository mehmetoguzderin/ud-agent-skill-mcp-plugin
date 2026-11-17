/** Build bounded acceptance shards from actual complete backend generation. */
import {existsSync,lstatSync,mkdirSync,readFileSync,rmSync,writeFileSync}from'node:fs';
import path from'node:path';import{fileURLToPath}from'node:url';
import{spawn}from'node:child_process';import{createInterface}from'node:readline';import{createHash}from'node:crypto';
import{fileReceipt,readRecordedBytes,safeRelative,sha256,sourceReceipt}from'../release/candidate.mjs';
import{canonicalJson}from'../release/http-transports.mjs';
import{acceptanceInputHash}from'../release/discover-acceptance.mjs';
import{authorityFromGeneration,verifyMutationBackendDiscovery}from'../release/mutation-backends.mjs';
const insist=(value,message)=>{if(!value)throw new Error('Mutation normalization: '+message);};
const order=items=>[...items].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
const compact=({id,file,source_sha256,definition_sha256})=>({id,file,source_sha256,definition_sha256});

/** Stryker's process-global numbers are aliases, never definition identities. */
export function normalizeStrykerAliases(plan,generation){
 insist(plan?.tool==='stryker'&&generation?.backend?.tool==='stryker'&&Array.isArray(plan.mutants)&&Array.isArray(generation.inventory),'Stryker generation and execution plan required');
 const expected=new Map(),rawIds=new Set(),rawGlobalIds=new Set(),seen=new Set(),aliases=[],mutants=[];
 for(const item of generation.inventory){
  const key=item.file+'\0'+item.definition_sha256;
  insist(item.id===item.file+'#'+item.definition_sha256&&!expected.has(key),'invalid or duplicate canonical Stryker generation identity');expected.set(key,item);
 }
 for(const item of plan.mutants){
  const key=item?.file+'\0'+item?.definition_sha256,wanted=expected.get(key),prefix=item?.file+'#';
  insist(wanted&&item.source_sha256===wanted.source_sha256&&item.definition&&sha256(canonicalJson(item.definition))===item.definition_sha256&&!seen.has(key)&&typeof item.id==='string'&&item.id.startsWith(prefix)&&item.id.length>prefix.length&&!rawIds.has(item.id),'execution definition differs from independent Stryker generation');
  const globalId=item.id.slice(prefix.length);insist(!rawGlobalIds.has(globalId),'duplicate process-global Stryker alias');rawGlobalIds.add(globalId);rawIds.add(item.id);seen.add(key);
  aliases.push({raw_id:item.id,canonical_id:wanted.id,file:item.file,source_sha256:item.source_sha256,definition_sha256:item.definition_sha256});
  mutants.push({...item,id:wanted.id});
 }
 insist(expected.size>0&&seen.size===expected.size,'Stryker alias union omits independent generated definitions');
 aliases.sort((a,b)=>a.canonical_id<b.canonical_id?-1:a.canonical_id>b.canonical_id?1:0);
 return{plan:{...plan,mutants:order(mutants)},aliases};
}

/** Translate a complete raw outcome set without altering any status or evidence. */
export function normalizeStrykerOutcomeAliases(outcomes,aliases){
 insist(Array.isArray(outcomes)&&Array.isArray(aliases)&&aliases.length>0,'complete raw Stryker outcomes and aliases required');
 const expected=new Map(),canonical=new Set(),seen=new Set();
 for(const item of aliases){
  insist(item&&typeof item.raw_id==='string'&&!expected.has(item.raw_id)&&item.canonical_id===item.file+'#'+item.definition_sha256&&!canonical.has(item.canonical_id),'invalid or duplicate Stryker alias proof');expected.set(item.raw_id,item);canonical.add(item.canonical_id);
 }
 const normalized=outcomes.map(item=>{
  const raw=item?.file+'#'+item?.id,wanted=expected.get(raw);
  insist(wanted&&!seen.has(raw)&&item.definition_sha256===wanted.definition_sha256,'unknown, duplicate or changed raw Stryker outcome');seen.add(raw);
  return{...item,id:wanted.canonical_id};
 });
 insist(seen.size===expected.size,'raw Stryker outcomes omit scheduled aliases');return order(normalized);
}

function runnerFor(tool){return tool==='stryker'?'vitest':tool==='cargo-mutants'?'rust':'python';}
export function normalizeTests(plan,catalog,backend){
 const all=catalog.tests,runner=runnerFor(backend.tool),used=new Set(),occurrences=new Map(),mapped=new Set();
 insist(Array.isArray(all)&&all.length>0,'independent test catalog is empty');
 function match(raw){
  insist(raw&&typeof raw.id==='string'&&raw.id&&!used.has(raw.id),'duplicate or missing backend test ID');used.add(raw.id);
  let source=raw.source,name=raw.name;
  const selectedRunner=backend.tool==='fault-canary'?raw.runner:runner;
  insist(['python','vitest','rust'].includes(selectedRunner),'unknown independent test runner');
  if(['mutmut','python-static','fault-canary'].includes(backend.tool)&&raw.id.includes('::')){
   const parts=raw.id.split('::');source=source??parts.shift()?.replace(/^mutants\//,'');if(parts[0]===source)parts.shift();
   // unittest loads each directory independently, retaining its module basename.
   if(!name)name=path.posix.basename(source,'.py')+'.'+raw.id.split('::').slice(1).join('.');
  }else if(backend.tool==='stryker'){
   const marker=raw.id.indexOf('#');insist(marker>0,'Stryker ID lacks its declared source');source=source??raw.id.slice(0,marker);name=name??raw.id.slice(marker+1);
  }else name=name??raw.id;
  const key=source+'\0'+name,inferred=occurrences.get(key)??0,occurrence=raw.occurrence??inferred;
  insist(Number.isSafeInteger(occurrence)&&occurrence>=0,'invalid backend test occurrence');
  const mappedKey=key+'\0'+occurrence;insist(!mapped.has(mappedKey),'duplicate backend test occurrence');mapped.add(mappedKey);
  occurrences.set(key,Math.max(inferred,occurrence+1));
  const candidates=all.filter(item=>item.runner===selectedRunner&&(!source||item.source===source)&&item.name===name&&item.occurrence===occurrence);
  insist(candidates.length===1,'backend test is missing or ambiguous in independent collection: '+raw.id);
  const selected=candidates[0];
  insist(!raw.source_sha256||raw.source_sha256===selected.source_sha256,'backend test source hash is stale');
  return{id:raw.id,source:selected.source,source_sha256:selected.source_sha256,discovered_id:selected.id};
 }
 let tests;
 if(Array.isArray(plan.tests))tests=plan.tests.map(match);
 else{
  insist(plan.tests&&typeof plan.tests==='object'&&Object.keys(plan.tests).length>0,'backend test discovery is missing');
  const selected=all.filter(item=>item.runner===runner&&Object.hasOwn(plan.tests,item.source));
  for(const[source,fingerprint]of Object.entries(plan.tests))insist(selected.some(item=>item.source===source&&item.source_sha256===fingerprint),'backend test file is absent from independent collection');
  tests=selected.map(item=>match({id:item.name,source:item.source,source_sha256:item.source_sha256,name:item.name}));
 }
 insist(tests.length>0,'backend selected no independently discovered tests');
 return order(tests);
}

export function normalizeSchedule(root,{plan,catalog,suiteId,generation,output,maxShardBytes=8*1024**2}){
 insist(plan?.definition_representation===undefined,'compact Python plans require the bounded file-stream normalizer');
 root=path.resolve(root);output=path.resolve(output);
 const outputRelative=path.relative(root,output).split(path.sep).join('/');
 insist(outputRelative.startsWith('.artifacts/')&&!existsSync(output),'output must be a new directory inside owned source artifacts');
 safeRelative(outputRelative);
 insist(/^mutation-[a-z][a-z-]*$/.test(suiteId),'invalid acceptance suite');
 insist(Number.isSafeInteger(maxShardBytes)&&maxShardBytes>=1024&&maxShardBytes<=16*1024**2,'invalid bounded shard size');
 const source=sourceReceipt(root),input=acceptanceInputHash(source);
 insist(catalog?.schema_version===1&&catalog.kind==='acceptance-discovery'&&catalog.qualification==='inventory-only-no-outcomes'&&catalog.input_sha256===input,'independent discovery catalog is missing or stale');
 for(const field of['outcomes','results','baseline'])if(Object.hasOwn(plan,field))insist(plan[field]&&Object.keys(plan[field]).length===0,'backend plan contains supplied outcomes');
 const actual=JSON.parse(readRecordedBytes(root,generation,64*1024**2));
 insist(actual.kind==='mutation-backend-generation'&&actual.scope_complete===true&&actual.input_sha256===input,'actual complete generation is missing or stale');
 const backend=actual.backend;
 const compatible=plan.tool===backend.tool||backend.tool==='cargo-mutants'&&plan.tool==='cargo-mutants-27.1.0+ud-literal-1';
 insist(compatible,'plan tool differs from actual generator');
 const mutants=order(plan.inventory??plan.mutants??[]),ids=new Set(),definitions=new Set();
 insist(mutants.length>0&&(!Object.hasOwn(plan,'scheduled')||plan.scheduled===mutants.length),'empty or incomplete backend plan');
 for(const item of mutants){
  insist(item&&typeof item.id==='string'&&!ids.has(item.id)&&item.definition&&sha256(canonicalJson(item.definition))===item.definition_sha256,'invalid or duplicate exact backend definition');
  safeRelative(item.file);const key=item.file+'\0'+item.definition_sha256;insist(!definitions.has(key),'duplicate applicable backend definition');ids.add(item.id);definitions.add(key);
  insist(!Object.hasOwn(item,'status')&&!Object.hasOwn(item,'exit_code'),'backend mutant includes supplied outcomes');
 }
 const fingerprints=mutants.map(compact),digest=sha256(canonicalJson(fingerprints));
 insist(canonicalJson(fingerprints)===canonicalJson(actual.inventory)&&digest===actual.inventory_sha256,'schedule is truncated or differs from actual full generation');
 const tests=normalizeTests(plan,catalog,backend);
 let parent=root;for(const part of outputRelative.split('/').slice(0,-1)){parent=path.join(parent,part);if(!existsSync(parent))mkdirSync(parent,{mode:0o700});const info=lstatSync(parent);insist(info.isDirectory()&&!info.isSymbolicLink(),'artifact parent must be an ordinary directory');}
 mkdirSync(output,{mode:0o700});writeFileSync(path.join(output,'INCOMPLETE'),'Mutation normalization has not completed.\n');
 const authority=authorityFromGeneration(root,source,input,generation),authorityFile=path.join(output,'backend-discovery.json');
 writeFileSync(authorityFile,JSON.stringify(authority,null,2)+'\n',{flag:'wx'});
 const authorityReceipt=fileReceipt(root,path.relative(root,authorityFile).split(path.sep).join('/'));
 verifyMutationBackendDiscovery(root,authorityReceipt,source,input);
 const base={schema_version:1,inventory_only:true,suite_id:suiteId,backend_discovery:authorityReceipt,tests};
 const overhead=Buffer.byteLength(JSON.stringify({...base,shard:{index:Number.MAX_SAFE_INTEGER,count:Number.MAX_SAFE_INTEGER,scheduled:mutants.length,inventory_sha256:digest},mutants:[]}))+1;
 const batches=[];let batch=[],batchBytes=overhead;
 for(const item of mutants){
  const selected=compact(item);selected.definition=item.definition;
  const bytes=Buffer.byteLength(JSON.stringify(selected));
  if(batchBytes+bytes+(batch.length?1:0)>maxShardBytes){
   insist(batch.length>0,'one exact mutant or its test inventory exceeds the shard bound');batches.push(batch);batch=[];batchBytes=overhead;
  }
  insist(batchBytes+bytes+(batch.length?1:0)<=maxShardBytes,'one exact mutant exceeds the shard bound');
  batchBytes+=bytes+(batch.length?1:0);
  batch.push(selected);
 }
 if(batch.length)batches.push(batch);
 const shards=[];
 for(const[index,items]of batches.entries()){
  const value={...base,shard:{index,count:batches.length,scheduled:mutants.length,inventory_sha256:digest},mutants:items};
  const file=path.join(output,'schedule-'+String(index).padStart(5,'0')+'.json');
  writeFileSync(file,JSON.stringify(value)+'\n',{flag:'wx'});
  const receipt=fileReceipt(root,path.relative(root,file).split(path.sep).join('/'));insist(receipt.size<=maxShardBytes,'serialized shard exceeds its exact bound');shards.push(receipt);
 }
 insist(acceptanceInputHash(sourceReceipt(root))===input,'source changed during normalization');
 const manifest={schema_version:1,qualification:'unsigned-local-inventory-only',suite_id:suiteId,backend,input_sha256:input,inventory_sha256:digest,scheduled:mutants.length,tests:tests.length,backend_discovery:authorityReceipt,shards,production_inventory_signature_required:true};
 writeFileSync(path.join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});rmSync(path.join(output,'INCOMPLETE'));return manifest;
}

/** Large plans are parsed once by the verified developer interpreter, then
 * streamed as sorted bounded records; no V8 allocation contains the full plan. */
export async function normalizeScheduleFile(root,{planFile,catalog,suiteId,generation,output,python,maxShardBytes=8*1024**2}){
 root=path.resolve(root);output=path.resolve(output);const outputRelative=path.relative(root,output).split(path.sep).join('/');
 insist(outputRelative.startsWith('.artifacts/')&&!existsSync(output)&&/^mutation-[a-z][a-z-]*$/.test(suiteId),'new owned output and suite required');safeRelative(outputRelative);
 insist(Number.isSafeInteger(maxShardBytes)&&maxShardBytes>=1024&&maxShardBytes<=16*1024**2&&typeof python==='string'&&path.isAbsolute(python),'bounded shards and absolute developer interpreter required');
 const source=sourceReceipt(root),input=acceptanceInputHash(source);
 insist(catalog?.schema_version===1&&catalog.kind==='acceptance-discovery'&&catalog.qualification==='inventory-only-no-outcomes'&&catalog.input_sha256===input,'independent discovery catalog is stale');
 const actual=JSON.parse(readRecordedBytes(root,generation,64*1024**2)),authority=authorityFromGeneration(root,source,input,generation);
 insist(actual.kind==='mutation-backend-generation'&&actual.scope_complete===true&&actual.input_sha256===input,'actual full generation required');
 let parent=root;for(const part of outputRelative.split('/').slice(0,-1)){parent=path.join(parent,part);if(!existsSync(parent))mkdirSync(parent,{mode:0o700});const info=lstatSync(parent);insist(info.isDirectory()&&!info.isSymbolicLink(),'ordinary artifact parent required');}
 mkdirSync(output,{mode:0o700});writeFileSync(path.join(output,'INCOMPLETE'),'Streaming normalization has not completed.\n');
 const authorityFile=path.join(output,'backend-discovery.json');writeFileSync(authorityFile,JSON.stringify(authority,null,2)+'\n',{flag:'wx'});
 const authorityReceipt=fileReceipt(root,path.relative(root,authorityFile).split(path.sep).join('/'));verifyMutationBackendDiscovery(root,authorityReceipt,source,input);
 const expected=actual.inventory,seen=new Set(),definitions=new Set(),digest=actual.inventory_sha256,definitionHash=createHash('sha256'),drafts=[];
 const child=spawn(python,[path.join(path.dirname(fileURLToPath(import.meta.url)),'stream-plan.py'),path.resolve(planFile)],{stdio:['ignore','pipe','pipe'],env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
 let stderr='',ended=false,header,base,batch=[],bytes=0,overhead=0,received=0,lastId;
 const completion=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});
 completion.catch(()=>{}); // The awaited lifecycle below owns setup failures.
 child.stderr.on('data',value=>{stderr+=value;if(Buffer.byteLength(stderr)>65536)child.kill('SIGKILL');});
 const flush=()=>{if(!batch.length)return;const file=path.join(output,'draft-'+String(drafts.length).padStart(5,'0')+'.json');writeFileSync(file,JSON.stringify(batch),{flag:'wx'});drafts.push(file);batch=[];bytes=overhead;};
 try{
  for await(const line of createInterface({input:child.stdout,crlfDelay:Infinity})){
   insist(Buffer.byteLength(line)<=64*1024**2,'generation frame exceeds its bound');const frame=JSON.parse(line);
   if(!header){
    insist(frame.type==='header'&&frame.count===expected.length,'stream header differs from actual inventory');header=frame.plan;
    for(const field of['outcomes','results','baseline'])if(Object.hasOwn(header,field))insist(header[field]&&Object.keys(header[field]).length===0,'stream plan contains supplied outcomes');
    insist(header.tool===actual.backend.tool||actual.backend.tool==='cargo-mutants'&&header.tool==='cargo-mutants-27.1.0+ud-literal-1','stream tool differs from generator');
    if(Object.hasOwn(header,'scheduled'))insist(header.scheduled===expected.length,'stream scheduling count differs');
    base={schema_version:1,inventory_only:true,suite_id:suiteId,backend_discovery:authorityReceipt,tests:normalizeTests(header,catalog,actual.backend)};
    overhead=Buffer.byteLength(JSON.stringify({...base,shard:{index:Number.MAX_SAFE_INTEGER,count:Number.MAX_SAFE_INTEGER,scheduled:expected.length,inventory_sha256:digest},mutants:[]}))+1;bytes=overhead;continue;
   }
   if(frame.type==='end'){
    insist(!ended&&frame.count===received&&received===expected.length&&frame.definition_stream_sha256===definitionHash.digest('hex'),'incomplete or changed definition stream');ended=true;continue;
   }
   insist(!ended&&frame.type==='mutant'&&Buffer.byteLength(line)<=4*1024**2,'unexpected, extra or oversized definition frame');
   const item=frame.value,projected=compact(item),wanted=expected[received];
   insist(item&&typeof item.id==='string'&&!seen.has(item.id)&&(lastId===undefined||lastId<item.id)&&canonicalJson(projected)===canonicalJson(wanted)&&item.definition&&sha256(canonicalJson(item.definition))===item.definition_sha256,'stream definition is duplicate, stale, reordered or unbound');
   insist(!Object.hasOwn(item,'status')&&!Object.hasOwn(item,'exit_code'),'stream mutant contains outcomes');
   const key=item.file+'\0'+item.definition_sha256;insist(!definitions.has(key),'duplicate applicable stream definition');seen.add(item.id);definitions.add(key);lastId=item.id;
   definitionHash.update(canonicalJson(item)+'\n');received++;
   const selected={...projected,definition:item.definition},size=Buffer.byteLength(JSON.stringify(selected));if(bytes+size+(batch.length?1:0)>maxShardBytes)flush();insist(bytes+size+(batch.length?1:0)<=maxShardBytes,'one exact mutation exceeds shard bound');bytes+=size+(batch.length?1:0);batch.push(selected);
  }
  const status=await completion;insist(status.code===0&&!status.signal&&stderr.length===0&&ended&&received===expected.length,'generation stream failed: '+stderr.slice(-16384));flush();
  const shards=[];
  for(const[index,draft]of drafts.entries()){
   const mutants=JSON.parse(readFileSync(draft,'utf8')),file=path.join(output,'schedule-'+String(index).padStart(5,'0')+'.json');writeFileSync(file,JSON.stringify({...base,shard:{index,count:drafts.length,scheduled:expected.length,inventory_sha256:digest},mutants})+'\n',{flag:'wx'});const receipt=fileReceipt(root,path.relative(root,file).split(path.sep).join('/'));insist(receipt.size<=maxShardBytes,'stream shard exceeds exact bound');shards.push(receipt);rmSync(draft);
  }
  insist(acceptanceInputHash(sourceReceipt(root))===input,'source changed during streaming normalization');
  const manifest={schema_version:1,qualification:'unsigned-local-inventory-only',suite_id:suiteId,backend:actual.backend,input_sha256:input,inventory_sha256:digest,scheduled:received,tests:base.tests.length,backend_discovery:authorityReceipt,shards,production_inventory_signature_required:true};writeFileSync(path.join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});rmSync(path.join(output,'INCOMPLETE'));return manifest;
 }catch(error){child.kill('SIGKILL');await completion.catch(()=>{});throw error;}
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const args=process.argv.slice(2),options={};for(let index=0;index<args.length;index+=2){const flag=args[index],value=args[index+1];insist(['--root','--plan','--catalog','--generation','--suite','--output','--python'].includes(flag)&&value,'invalid normalization arguments');options[flag.slice(2)]=value;}
 insist(['root','plan','catalog','generation','suite','output'].every(key=>options[key]),'Usage: normalize-schedule.mjs --root SOURCE --plan PLAN --catalog CATALOG --generation RAW_GENERATION --suite mutation-NAME --output NEW_DIRECTORY');
 const root=path.resolve(options.root),raw=path.resolve(options.generation);insist(raw.startsWith(root+path.sep),'raw generation must be a recorded source-tree artifact');
 const read=file=>{const info=lstatSync(file);insist(info.isFile()&&!info.isSymbolicLink()&&info.size<=512*1024**2,'bounded ordinary JSON input required');return JSON.parse(readFileSync(file,'utf8'));};
 const shared={catalog:read(options.catalog),generation:fileReceipt(root,path.relative(root,raw).split(path.sep).join('/')),suiteId:options.suite,output:options.output};
 console.log(JSON.stringify(await normalizeScheduleFile(root,{...shared,planFile:options.plan,python:path.resolve(options.python??process.env.UD_RELEASE_PYTHON??'.venv/bin/python')})));
}
