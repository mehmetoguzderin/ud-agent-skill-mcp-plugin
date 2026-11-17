import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, chmod, rm, copyFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { checkedFixture, providerProfile, providerEvidenceScope, jobRecords, readArtifact, readResourceBytes, seedOfflineProviderAssets, substitute, dockerAcceptanceAdmission, existingAcceptanceDockerAdmission } from '../../scripts/quality/native-provider-acceptance.mjs';
import { createOciFixture, fixtureTar } from './oci-fixture.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
test('userspace acceptance avoids Docker for a fresh checkout but never discards historical engine usage',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'ud-provider-no-engine-'));
  try{
    const absent=()=>({error:Object.assign(new Error('not found'),{code:'ENOENT'})});
    assert.equal(existingAcceptanceDockerAdmission(root,{run:absent}).ownedBytes,0);
    await mkdir(path.join(root,'.artifacts'));await writeFile(path.join(root,'.artifacts','historical.json'),'{}');
    assert.throws(()=>existingAcceptanceDockerAdmission(root,{run:absent}),/cannot verify project-owned Docker data/);
  }finally{await rm(root,{recursive:true,force:true});}
});
test('Docker acceptance reserves verified expanded worker bytes before import and measures owned images',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'ud-provider-engine-budget-'));
  try{
    await mkdir(path.join(root,'runtime'));await mkdir(path.join(root,'assets'));
    const worker='linux/'+(process.arch==='x64'?'amd64':process.arch),packs={},assets=[],ids=[];
    for(const name of ['core','render']){
      const f=createOciFixture(name),index=JSON.parse(f.entries.find(([key])=>key==='index.json')[1]);index.manifests=index.manifests.filter(item=>item.platform.os+'/'+item.platform.architecture===worker);
      const indexBytes=Buffer.from(JSON.stringify(index)),bytes=fixtureTar(f.entries.map(([key,value])=>[key,key==='index.json'?indexBytes:value]));
      const descriptor=index.manifests[0],manifest=JSON.parse(f.entries.find(([key])=>key==='blobs/sha256/'+descriptor.digest.slice(7))[1]),config=JSON.parse(f.entries.find(([key])=>key==='blobs/sha256/'+manifest.config.digest.slice(7))[1]);
      const transport={format:'oci-archive',index_digest:'sha256:'+sha(indexBytes),sha256:'sha256:'+sha(bytes),size_bytes:bytes.length};
      packs[name]={images:{[worker]:{digest:descriptor.digest,config_digest:manifest.config.digest,diff_ids:config.rootfs.diff_ids,transports:[transport]}}};
      ids.push(manifest.config.digest);assets.push({path:'assets/'+name+'.tar',sha256:sha(bytes),size_bytes:bytes.length});await writeFile(path.join(root,assets.at(-1).path),bytes);
    }
    const lockBytes=Buffer.from(JSON.stringify({packs}));await writeFile(path.join(root,'runtime/runtime.lock.json'),lockBytes);
    await writeFile(path.join(root,'candidate-inputs.json'),JSON.stringify({runtime_lock_sha256:sha(lockBytes),offline_assets:assets}));
    let images=[{ID:ids[0],Repository:'<none>',Tag:'<none>'}],unavailable=false,importedBytes=55,writableBytes=0,daemon='engine-A';
    const run=(_binary,args,options)=>{
      if(unavailable)return{status:1,stderr:'engine unavailable'};
      if(args[0]==='context')return{status:0,stdout:'unix:///var/run/docker.sock\n'};
      assert.equal(options.env.DOCKER_HOST,'unix:///var/run/docker.sock');assert.equal(options.env.DOCKER_CONTEXT,undefined);
      if(args[0]==='info')return{status:0,stdout:daemon+'\n'};
      if(args[0]==='image'&&args[1]==='ls')return{status:0,stdout:images.map(item=>JSON.stringify(item)).join('\n')};
      if(args[0]==='image'&&args[1]==='inspect')return{status:0,stdout:JSON.stringify([{Id:args[2],Size:args[2]===ids[0]?10:importedBytes}])};
      if(args[0]==='system'&&args[1]==='df')return{status:0,stdout:['Images','Containers','Local Volumes','Build Cache'].map(type=>JSON.stringify({Type:type,Size:(type==='Containers'?writableBytes:0)+'B'})).join('\n')};
      if(args[0]==='ps'||args[0]==='volume')return{status:0,stdout:''};
      throw new Error('unexpected Docker command '+JSON.stringify(args));
    };
    const admission=dockerAcceptanceAdmission(root,root,{run});assert.equal(admission.ownedBytes,10);assert.ok(admission.reservedBytes>128*1024**2);assert.equal(admission.measure(),0);
    images.push({ID:ids[1],Repository:'localhost/ud-agent-render',Tag:'test'});assert.equal(admission.measure(),55);
    importedBytes=admission.reservedBytes+1;assert.throws(()=>admission.measure(),/exceed/);importedBytes=55;
    writableBytes=admission.reservedBytes+1;assert.throws(()=>admission.measure(),/writable engine storage exceed/);writableBytes=0;
    daemon='different-engine';assert.throws(()=>admission.measure(),/daemon changed/);daemon='engine-A';
    images.push({ID:'sha256:'+'f'.repeat(64),Repository:'localhost/ud-agent-foreign',Tag:'test'});assert.throws(()=>admission.measure(),/Unexpected/);images.pop();
    unavailable=true;assert.throws(()=>admission.measure(),/unavailable/);unavailable=false;
    await writeFile(path.join(root,assets[1].path),'altered');assert.throws(()=>dockerAcceptanceAdmission(root,root,{run}),/receipt mismatch/);
  }finally{await rm(root,{recursive:true,force:true});}
});
test('diagnostic installed inputs cannot become final native acceptance or silently enter the default route',()=>{
  assert.deepEqual(providerEvidenceScope({qualification:'preacceptance-runtime-inputs'}),{qualification:'native-provider-preacceptance-execution',acceptance_eligible:true});
  assert.deepEqual(providerEvidenceScope({qualification:'diagnostic-runtime-inputs'},'diagnostic'),{qualification:'diagnostic-installed-provider-execution-not-final-acceptance',acceptance_eligible:false});
  assert.throws(()=>providerEvidenceScope({qualification:'diagnostic-runtime-inputs'}));
  assert.throws(()=>providerEvidenceScope({qualification:'preacceptance-runtime-inputs'},'diagnostic'));
  assert.throws(()=>providerEvidenceScope({qualification:'diagnostic-runtime-inputs'},'accepted'));
});
test('native provider profiles preserve actual OS/architecture and refuse unsupported substitutions',()=>{
  for(const [target,engine]of Object.entries({'darwin-arm64':'apple-container','darwin-x64':'lima-nerdctl','linux-arm64':'podman','linux-x64':'podman','win32-arm64':'wslc','win32-x64':'wslc'})){const [platform,arch]=target.split('-');assert.deepEqual(providerProfile(platform,arch),{target,engine,worker:'linux/'+(arch==='x64'?'amd64':'arm64')});assert.equal(providerProfile(platform,arch,'docker').engine,'docker');}
  for(const args of [['linux','arm64','wslc'],['darwin','x64','apple-container'],['darwin','arm64','userspace'],['unknown','arm64']])assert.throws(()=>providerProfile(...args));
});
test('live-job observations include actual Docker, Podman and VM journal layouts without inventing absent jobs',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'ud-provider-job-layouts-'));
  try{
    assert.equal((await jobRecords(root)).size,0);
    for(const [directory,nested]of [['docker-jobs',true],['podman-jobs',true],['platform-jobs',false]]){
      const folder=path.join(root,directory,...(nested?['a-job']:[]));await mkdir(folder,{recursive:true});
      await writeFile(path.join(folder,nested?'job.json':'a-job.json'),JSON.stringify({id:directory+'-owned',phase:'running'}));
    }
    await writeFile(path.join(root,'platform-jobs','unrelated.json'),JSON.stringify({phase:'running'}));
    const jobs=await jobRecords(root);assert.deepEqual([...jobs.values()].map(row=>row.record.id).sort(),['docker-jobs-owned','platform-jobs-owned','podman-jobs-owned']);
    for(const row of jobs.values())assert.match(row.sha256,/^[a-f0-9]{64}$/);
  }finally{await rm(root,{recursive:true,force:true});}
});
test('closed authored bytes, hashes, paths and request substitution are independently checked',()=>{
  const file={path:'a/main.conllu',content_base64:Buffer.from('1\r\n').toString('base64'),size_bytes:3,sha256:sha('1\r\n')};assert.deepEqual(checkedFixture(file),Buffer.from('1\r\n'));
  for(const change of [{path:'../escape'},{path:'a\\escape'},{path:'.git/config'},{sha256:'a'.repeat(64)},{size_bytes:2},{content_base64:'MR=='}])assert.throws(()=>checkedFixture({...file,...change}));
  assert.deepEqual(substitute({a:['${WORKSPACE}/a',3,'${OUTPUT}']},'/w','/o'),{a:['/w/a',3,'/o']});
});
test('public resources retain exact URI, immutable pagination, byte hashes and artifact-only grants',async()=>{
  const bytes=Buffer.from('abcdef'),reference={uri:'ud://reports/id',sha256:sha(bytes),size_bytes:6};const seen=[];
  const client={readResource:async({uri})=>{seen.push(uri);const second=uri.includes('?');return{contents:[{text:JSON.stringify({encoding:'base64',resource:reference,offset:second?3:0,content_base64:bytes.subarray(second?3:0,second?6:3).toString('base64'),next_cursor:second?null:'bound cursor'})}]};}};
  assert.deepEqual(await readResourceBytes(client,reference),bytes);assert.deepEqual(seen,['ud://reports/id','ud://reports/id?cursor=bound%20cursor']);
  await assert.rejects(readArtifact(client,reference));
  await assert.rejects(readResourceBytes({readResource:async()=>({contents:[{text:JSON.stringify({encoding:'base64',resource:reference,offset:3,content_base64:'YWJj',next_cursor:null})}]})},reference));
  await assert.rejects(readResourceBytes({readResource:async()=>({contents:[{blob:Buffer.from('wrong!').toString('base64')}]})},reference));
});
test('offline provider staging uses selected frozen architecture and never modifies installed bytes',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'ud-provider-input-test-'));
  try{
    const installation=path.join(root,'installed'),state=path.join(root,'state');await mkdir(path.join(installation,'runtime'),{recursive:true});
    const first=Buffer.from('frozen core'),second=Buffer.from('frozen render'),assets=[first,second];
    const transport=bytes=>({format:'oci-archive',sha256:'sha256:'+sha(bytes),size_bytes:bytes.length});
    const lock={packs:{core:{images:{'linux/arm64':{transports:[transport(first)]}}},render:{images:{'linux/arm64':{transports:[transport(second)]}}}}};
    if(process.platform==='win32'){const helper=path.resolve('target/debug/ud-agent-guard.exe');await copyFile(helper,path.join(installation,'runtime/guard.exe'));lock.native={['win32/'+process.arch]:{guard:{path:'runtime/guard.exe',sha256:'sha256:'+sha(await readFile(helper)),size_bytes:(await readFile(helper)).length}}};}
    const lockfile=path.join(installation,'runtime/runtime.lock.json');await writeFile(lockfile,JSON.stringify(lock));
    const manifest={offline_assets:[]};for(const [index,bytes]of assets.entries()){await writeFile(path.join(root,'asset-'+index),bytes);manifest.offline_assets.push({path:'asset-'+index,sha256:sha(bytes),size_bytes:bytes.length});}
    const rejectedState=path.join(root,'rejected');const checked=[];
    await assert.rejects(seedOfflineProviderAssets(root,manifest,installation,rejectedState,providerProfile('darwin','arm64'),{check:size=>{checked.push(size);throw new Error('insufficient scratch');}}),/insufficient scratch/);
    assert.deepEqual(checked,[first.length]);await assert.rejects(readFile(path.join(rejectedState+'-apple-container','images',sha(first)+'.tar')),{code:'ENOENT'});
    await seedOfflineProviderAssets(root,manifest,installation,state,providerProfile('darwin','arm64'));
    assert.equal(await readFile(lockfile,'utf8'),JSON.stringify(lock));assert.deepEqual(await readFile(path.join(state+'-apple-container','images',sha(first)+'.tar')),first);
    await assert.rejects(seedOfflineProviderAssets(root,{offline_assets:[]},installation,path.join(root,'missing'),providerProfile('darwin','arm64')),/offline asset is missing/);
    await assert.rejects(seedOfflineProviderAssets(root,manifest,installation,path.join(root,'wrong-arch'),providerProfile('darwin','x64')),/Pending native build/);
    await chmod(path.join(root,'asset-0'),0o600);await writeFile(path.join(root,'asset-0'),'corrupt');await assert.rejects(seedOfflineProviderAssets(root,manifest,installation,path.join(root,'corrupt'),providerProfile('darwin','arm64')));
  }finally{await rm(root,{recursive:true,force:true});}
});

test('userspace offline seeding distinguishes uv and real venv routes with closed vendor recipe authority',async()=>{
  const {seedOfflineUserspaceAssets}=await import('../../scripts/quality/native-provider-acceptance.mjs');
  const root=await mkdtemp(path.join(os.tmpdir(),'ud-userspace-input-test-'));
  try{
    const installation=path.join(root,'installed');await mkdir(path.join(installation,'runtime'),{recursive:true});
    const host=process.platform+'/'+process.arch,platform=process.platform,arch=process.arch,payloads={core:Buffer.from('core'),render:Buffer.from('render'),uv:Buffer.from('native uv fixture'),python:Buffer.from('python'),browser:Buffer.from('browser'),perl:Buffer.from('vc runtime'),supplier:Buffer.from('supplier Perl')};
    const descriptor=name=>({url:'https://example.invalid/'+name,sha256:'sha256:'+sha(payloads[name]),size:payloads[name].length});
    const supplierFormat=arch==='arm64'?'tar.bz2':'conda';
    const recipe={provider:'conda-vc-runtime',platform:host,archive:{sha256:sha(payloads.perl),size_bytes:payloads.perl.length,url:'https://example.invalid/private.conda'},supplier:{archive:{sha256:sha(payloads.supplier),size_bytes:payloads.supplier.length,url:'https://example.invalid/perl.'+supplierFormat}}},recipeBytes=Buffer.from(JSON.stringify(recipe));await writeFile(path.join(installation,'runtime/perl-recipe.json'),recipeBytes);
    const selected={files:[{path:'runtime/perl-recipe.json',sha256:'sha256:'+sha(recipeBytes),size:recipeBytes.length}],lazy_core:descriptor('core'),lazy_render:descriptor('render'),uv_download:descriptor('uv'),python_download:{...descriptor('python'),url:'https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.14.10%2B20261026-fixture.tar.gz'},perl:{deferred_runtime:{provider:'conda-vc-runtime',recipe:'runtime/perl-recipe.json'}}};
    const userspace=Buffer.from(JSON.stringify({platforms:{[host]:selected}})),runtime={userspace_sha256:'sha256:'+sha(userspace)};await writeFile(path.join(installation,'runtime/userspace.lock.json'),userspace);
    if(process.platform==='win32'){const helper=path.resolve('target/debug/ud-agent-guard.exe'),bytes=await readFile(helper);await copyFile(helper,path.join(installation,'runtime/guard.exe'));runtime.native={[host]:{guard:{path:'runtime/guard.exe',sha256:'sha256:'+sha(bytes),size_bytes:bytes.length}}};}
    await writeFile(path.join(installation,'runtime/runtime.lock.json'),JSON.stringify(runtime));
    const vendorRoles={browser:{cache_role:'render-vendor',platform:host,recipe_sha256:'a'.repeat(64),archive_format:'zip'},perl:{cache_role:'perl-vendor',platform:host,recipe_sha256:sha(recipeBytes),archive_format:'conda'},supplier:{cache_role:'perl-supplier',platform:host,recipe_sha256:sha(recipeBytes),archive_format:supplierFormat}};
    const manifest={offline_assets:[]};for(const [name,bytes]of Object.entries(payloads)){await writeFile(path.join(root,name),bytes);manifest.offline_assets.push({path:name,sha256:sha(bytes),size_bytes:bytes.length,...vendorRoles[name]});}
    const checkPerl=async state=>{assert.deepEqual(await readFile(path.join(state,'perl-vendor-cache',sha(payloads.perl)+'.conda')),payloads.perl);assert.deepEqual(await readFile(path.join(state,'perl-vendor-cache',sha(payloads.supplier)+'.'+supplierFormat)),payloads.supplier);};
    for(const installer of ['uv','venv']){const state=path.join(root,'state-'+installer),result=await seedOfflineUserspaceAssets(root,manifest,installation,state,{installer,platform,arch});assert.equal(result.network_requests,0);assert.equal(result.installer,installer);await checkPerl(state);if(installer==='uv')assert.deepEqual(await readFile(path.join(state,'tools','uv-'+sha(payloads.uv)+(platform==='win32'?'.exe':''))),payloads.uv);else await assert.rejects(readFile(path.join(state,'tools','uv-'+sha(payloads.uv)+(platform==='win32'?'.exe':''))),{code:'ENOENT'});}
    assert.deepEqual(await readFile(path.join(installation,'runtime/userspace.lock.json')),userspace);
    await assert.rejects(seedOfflineUserspaceAssets(root,{offline_assets:[]},installation,path.join(root,'missing'),{installer:'uv'}),/offline asset is missing/);
    await rm(path.join(installation,'runtime/perl-recipe.json'));
    const thinState=path.join(root,'state-thin');
    await seedOfflineUserspaceAssets(root,manifest,installation,thinState,{installer:'venv',platform,arch});
    await checkPerl(thinState);
  }finally{await rm(root,{recursive:true,force:true});}
});
