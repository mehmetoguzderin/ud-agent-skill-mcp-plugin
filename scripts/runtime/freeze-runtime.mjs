#!/usr/bin/env node
/** Compose verified immutable runtime inputs in a new local source staging tree. */
import { releasePlatforms } from '../release/host-adapters.mjs';
import {chmodSync,copyFileSync,existsSync,lstatSync,mkdirSync,readFileSync,readdirSync,rmSync,writeFileSync}from'node:fs';
import path from'node:path';import{fileURLToPath}from'node:url';import{spawnSync}from'node:child_process';
import {Ajv2020 as Ajv}from'ajv/dist/2020.js';
import{fileReceipt,safeRelative,sha256,sourceReceipt}from'../release/candidate.mjs';
import{resolveCrossBuildInputs}from'../release/cross-build-inputs.mjs';
import{auxiliaryArtifacts}from'../release/auxiliary-artifacts.mjs';
import{verifyOciArchive}from'../release/oci.mjs';
import{copyContextAssets}from'../release/context-assets.mjs';
import{sourceArtifacts}from'../release/source-artifacts.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const need=(condition,message)=>{if(!condition)throw new Error(`Runtime freeze: ${message}`);};
const read=file=>JSON.parse(readFileSync(file,'utf8'));
function receipt(file){const item=fileReceipt(path.dirname(file),path.basename(file));return{path:file,sha256:`sha256:${item.sha256}`,size_bytes:item.size};}
function copy(source,target){need(!lstatSync(source).isSymbolicLink(),'input cannot be a symbolic link');mkdirSync(path.dirname(target),{recursive:true});copyFileSync(source,target);chmodSync(target,lstatSync(source).mode&0o111?0o755:0o644);}
function launcherHash(){const files=[];function walk(folder){for(const name of readdirSync(folder).sort()){const file=path.join(folder,name),info=lstatSync(file);need(!info.isSymbolicLink(),'native source contains a link');if(info.isDirectory())walk(file);else if(info.isFile())files.push(file);else throw new Error('native source contains a special file');}}walk(path.join(root,'packages/launcher'));files.push(path.join(root,'Cargo.toml'),path.join(root,'Cargo.lock'));files.sort();const chunks=[];for(const file of files)chunks.push(path.relative(root,file),'\0',readFileSync(file),'\0');return sha256(Buffer.concat(chunks.map(value=>Buffer.isBuffer(value)?value:Buffer.from(value))));}

/** Reuse only a source-bound frozen runtime whose build inputs still match. */
export function verifyRetainedRuntimeCompatibility(sourceRoot,retainedRoot){
 const source=sourceReceipt(sourceRoot),retained=sourceReceipt(retainedRoot),composition=read(path.join(retainedRoot,'freeze-composition.json'));
 need(composition.schema_version===1&&composition.qualification==='available-target-inputs'&&composition.production_ready===false&&composition.source_tree_sha256===retained.sha256&&!existsSync(path.join(retainedRoot,'INCOMPLETE')),'retained runtime composition is incomplete or stale');
 const previous=new Map(retained.files.map(row=>[row.path,row]));
 const generatedRuntime=name=>['runtime/runtime.lock.json','runtime/source-materials.lock.json','runtime/userspace.lock.json','runtime/auxiliary-artifacts.json','runtime/engine-distributions.lock.json'].includes(name)||['runtime/pack/','runtime/contexts/','runtime/helpers/','runtime/bootstrap/'].some(prefix=>name.startsWith(prefix));
 const protectedInput=name=>name.startsWith('workers/ud/src/')||name.startsWith('packages/launcher/')||['Cargo.toml','Cargo.lock','package.json','package-lock.json','pyproject.toml','uv.lock'].includes(name)||name.startsWith('runtime/')&&!generatedRuntime(name)||name.startsWith('scripts/runtime/')&&!['scripts/runtime/freeze-runtime.mjs','scripts/runtime/prepare-userspace.py'].includes(name);
 const current=new Map(source.files.filter(row=>protectedInput(row.path)).map(row=>[row.path,row]));
 for(const [name,row]of current){const old=previous.get(name);need(old&&old.sha256===row.sha256&&old.size===row.size&&old.executable===row.executable,`retained runtime input changed: ${name}`);}
 for(const row of retained.files)if(protectedInput(row.path)&&!current.has(row.path))need(false,`retained runtime input was removed: ${row.path}`);
 const runtime=read(path.join(retainedRoot,'runtime/runtime.lock.json')),userspace=read(path.join(retainedRoot,'runtime/userspace.lock.json'));
 need(runtime.schema_version===1&&runtime.state==='frozen'&&userspace.schema_version===1&&userspace.state==='frozen','retained runtime locks are not frozen');
 return{source,retained,composition,runtime,userspace};
}

export function refreshStagedImplementationInventory(stage,python){
 const script=path.join(stage,'scripts/generate/implementation-inventory.py');
 need(existsSync(script)&&!lstatSync(script).isSymbolicLink(),'staged implementation inventory generator is missing');
 for(const suffix of[[],['--check']]){
  const result=spawnSync(python,['-I','-S','-B',script,...suffix],{cwd:stage,encoding:'utf8',timeout:120000,maxBuffer:1024*1024});
  need(!result.error&&result.status===0,`staged implementation inventory failed: ${result.error?.message??result.stderr}`);
 }
 return fileReceipt(stage,'contracts/implementation-inventory.json');
}

function selectCoreContexts(options, packs) {
 const platforms = Object.keys(packs.core.images ?? {}).sort();
 need(platforms.length > 0 && platforms.every(value => ['linux/arm64', 'linux/amd64'].includes(value))
   && JSON.stringify(platforms) === JSON.stringify(Object.keys(packs.render.images ?? {}).sort()), 'worker packs select different or unsupported build platforms');
 const perPlatform = options.coreContexts;
 need(Boolean(options.coreContext) !== Boolean(perPlatform), 'supply one shared core context or an exact set of per-platform core contexts');
 if (perPlatform) need(JSON.stringify(platforms) === JSON.stringify(Object.keys(perPlatform).sort()), 'per-platform core contexts must cover exactly the selected worker platforms');
 const directories = {};
 let ruleContextSha256;
 for (const platform of platforms) {
  const directory = path.resolve(perPlatform ? perPlatform[platform] : options.coreContext);
  const input = read(path.join(directory, 'input-manifest.json'));
  need(/^[a-f0-9]{64}$/.test(input.rule_context_sha256 ?? ''), `invalid rule context identity for ${platform}`);
  ruleContextSha256 ??= input.rule_context_sha256;
  need(input.rule_context_sha256 === ruleContextSha256, 'worker build contexts have different rule identities');
  for (const [name, hash] of Object.entries(input.files ?? {})) {
   if (name.startsWith('worker/')) need(fileReceipt(root, 'workers/ud/src/' + name.slice(7)).sha256 === hash, `worker sources changed after the ${platform} image build`);
  }
  directories[platform] = directory;
 }
 return { directories, ruleContextSha256 };
}

export function composeRuntime(options){
 const output=path.resolve(options.output);need(!existsSync(output)&&output!==root,'output must be a new source staging directory');
 need(!(options.availableTargets&&(options.diagnosticPartial||options.diagnosticWorkerPlatform)),'available-target inputs cannot relabel a diagnostic composition');
 need(!options.retainedRuntime||options.availableTargets&&!options.providers,'retained runtime reuse requires available-target mode and no separate provider inputs');
 const workerPlatform=options.availableWorkerPlatform??options.diagnosticWorkerPlatform;
 need(!options.availableWorkerPlatform||options.availableTargets,'available worker selection requires available-target mode');
 const retained=options.retainedRuntime?verifyRetainedRuntimeCompatibility(root,path.resolve(options.retainedRuntime)):undefined;
 const workers=read(path.resolve(options.workers));
 need(workers.schema_version===1&&workers.qualification==='local-build-unaccepted'&&workers.packs?.core&&workers.packs?.render,'complete verified worker exports are required');
 const { directories: coreContexts, ruleContextSha256 } = selectCoreContexts(options, workers.packs);
 const original=sourceReceipt(root),crossInputs=resolveCrossBuildInputs(root,'.artifacts/cross-build-receipt.json',{names:['ud-agent-guard']}),cross=crossInputs.cross;
 need(cross.source_sha256===launcherHash(),'native helper cross-build receipt is stale');
 const userspaceRoot=path.resolve(options.userspace),userspace=read(path.join(userspaceRoot,'runtime/userspace.lock.json'));
 const hosts=releasePlatforms.map(platform=>platform.replace('-','/'));
 need(userspace.schema_version===1&&userspace.format_revision===2&&userspace.state==='frozen','complete versioned private runtime manifest is required');
 const selected=Object.keys(userspace.platforms??{}).sort();need(selected.length>0&&selected.every(value=>hosts.includes(value)),'userspace platforms are invalid');
 need(options.diagnosticPartial||options.availableTargets||JSON.stringify(selected)===JSON.stringify([...hosts].sort()),'all five published userspace dependency packs are required');
 mkdirSync(output,{recursive:false,mode:0o700});writeFileSync(path.join(output,'INCOMPLETE'),'Composition has not finished.\n');
 for(const item of original.files){const from=path.join(root,item.path),to=path.join(output,item.path);copy(from,to);need(fileReceipt(output,item.path).sha256===item.sha256,'source changed during capture');}
 const materials=options.availableTargets?[]:sourceArtifacts(root);if(!Array.isArray(materials))throw new Error('Runtime freeze: source artifact array is required');for(const item of materials){copy(path.join(root,item.path),path.join(output,item.path));need(fileReceipt(output,item.path).sha256===item.sha256,'source material changed during staging capture');}
 need(sourceReceipt(root).sha256===original.sha256,'source changed during staging capture');
 const images={schema_version:1,format_revision:workerPlatform?1:2,product_version:'0.1.0-beta.1',state:'frozen',packs:{},native_helpers:{}};
 const imageEvidence=[];
 const python=process.env.UD_AGENT_PYTHON??path.join(root,'.venv/bin/python');
 for(const pack of['core','render']){
  const data=structuredClone(workers.packs[pack]);need(data.index_transport,'worker index transport is missing');
  if(workerPlatform)need(Object.keys(data.platforms).length===1&&data.platforms[workerPlatform],'selected worker platform does not match its actual index');
  verifyOciArchive(path.join(root,data.index_transport.path),data.index_digest,data.platforms,{sha256:data.index_transport.sha256.slice(7),size:data.index_transport.size_bytes},data.images,{diagnosticSinglePlatform:!!workerPlatform});
  for(const[platform,image]of Object.entries(data.images)){
   for(const descriptor of image.transports){const actual=fileReceipt(root,descriptor.path);need(`sha256:${actual.sha256}`===descriptor.sha256&&actual.size===descriptor.size_bytes,'worker transport is stale');copy(path.join(root,descriptor.path),path.join(output,descriptor.path));}
   const run=spawnSync(python,[path.join(root,'scripts/runtime/verify-worker-contents.py'),'--archive',path.join(root,data.index_transport.path),'--manifest',image.digest,'--context',coreContexts[platform],...(pack==='render'?['--render']:[])],{encoding:'utf8',timeout:180000,maxBuffer:1024*1024});
   need(!run.error&&run.status===0,`actual ${pack}/${platform} source inventory failed: ${run.stderr??run.error?.message}`);imageEvidence.push({pack,platform,...JSON.parse(run.stdout)});
  }
  copy(path.join(root,data.index_transport.path),path.join(output,data.index_transport.path));data.context_sha256=`sha256:${ruleContextSha256}`;images.packs[pack]=data;
 }
 // A portable context supplies the same rule identity and its own complete asset closure.
 const context=path.resolve(options.context),manifest=read(path.join(context,'context.json'));
 need(manifest.context_sha256===ruleContextSha256,'portable and OCI contexts have different rule identities');
 const contextRelative=`runtime/contexts/${manifest.context_sha256}`,contextDescriptor={...receipt(path.join(context,'context.json')),path:'context.json'};
 const portableDestination=path.join(output,contextRelative);mkdirSync(portableDestination,{recursive:true});
 copyContextAssets(context,portableDestination,contextDescriptor);
 const boundContext=receipt(path.join(portableDestination,'context.json'));boundContext.path=`${contextRelative}/context.json`;
 for(const pack of Object.values(images.packs))pack.context_manifest=boundContext;
 const policy='runtime/policies/render-seccomp.json';images.packs.render.seccomp_profile={...receipt(path.join(output,policy)),path:policy};
 for(const host of hosts){const platform=host.replace('/','-'),item=crossInputs.binaries.find(value=>value.platform===platform&&value.name==='ud-agent-guard');need(item,'native helper inventory is incomplete');const relative=`runtime/helpers/${host}/ud-agent-guard${host.startsWith('win32/')?'.exe':''}`;copy(item.path,path.join(output,relative));images.native_helpers[host]={guard:{path:relative,sha256:`sha256:${item.sha256}`,size_bytes:item.size}};}
 const copied=new Map();for(const platform of Object.values(userspace.platforms)){
  need(platform.perl&&Array.isArray(platform.files)&&platform.files.length>0,'userspace platform has no private Perl or closed dependency inventory');
  for(const item of platform.files){safeRelative(item.path);const actual=fileReceipt(userspaceRoot,item.path);need(`sha256:${actual.sha256}`===item.sha256&&actual.size===item.size,'private runtime asset is stale');
   if(item.path.startsWith(platform.worker+'/'))need(fileReceipt(root,'workers/ud/src/'+item.path.slice(platform.worker.length+1)).sha256===actual.sha256,'userspace worker sources are stale');
   if(item.path.startsWith('runtime/helpers/'))need(fileReceipt(output,item.path).sha256===actual.sha256,'userspace native helper differs from the cross-build');if(copied.has(item.path)){need(copied.get(item.path)===item.sha256,'conflicting private runtime assets');continue;}copied.set(item.path,item.sha256);copy(path.join(userspaceRoot,item.path),path.join(output,item.path));}
 }
 for(const item of userspace.bootstrap_assets??[]){safeRelative(item.path);const actual=fileReceipt(userspaceRoot,item.path);need(`sha256:${actual.sha256}`===item.sha256&&actual.size===item.size,'bootstrap asset is stale');copy(path.join(userspaceRoot,item.path),path.join(output,item.path));}
 copy(path.join(userspaceRoot,'runtime/userspace.lock.json'),path.join(output,'runtime/userspace.lock.json'));images.userspace_sha256=receipt(path.join(output,'runtime/userspace.lock.json')).sha256;
 const auxiliary=[];for(const[host,platform]of Object.entries(userspace.platforms)){if(!platform.lazy_render)continue;const source=options.lazyRender?.[host];need(source,'every lazy render pack requires a verified release transport');const contract=platform.lazy_render,actual=receipt(path.resolve(source));need(actual.sha256===contract.sha256&&actual.size_bytes===contract.size,'lazy render archive differs from acquisition contract');const filename=new URL(contract.url).pathname.split('/').at(-1);need(filename===`ud-agent-render-${host.replace('/','-')}.tar.gz`,'lazy render release filename is invalid');const relative='.artifacts/release-inputs/'+filename;copy(path.resolve(source),path.join(output,relative));auxiliary.push({id:'render-assets-'+host.replace('/','-'),platform:host.replace('/','-'),path:relative,sha256:actual.sha256,size_bytes:actual.size_bytes,url:contract.url});}
 const coreAssets=existsSync(path.join(userspaceRoot,'runtime/core-artifacts.json'))?read(path.join(userspaceRoot,'runtime/core-artifacts.json')).assets:retained?read(path.join(options.retainedRuntime,'runtime/auxiliary-artifacts.json')).assets:[];
 for(const[host,platform]of Object.entries(userspace.platforms)){if(!platform.lazy_core)continue;const item=coreAssets.find(value=>value.id==='userspace-core-'+host.replace('/','-'));need(item,'lazy core release transport is missing');safeRelative(item.path);const actual=receipt(path.join(userspaceRoot,item.path));need(actual.sha256===platform.lazy_core.sha256&&actual.size_bytes===platform.lazy_core.size&&item.url===platform.lazy_core.url,'lazy core transport differs from its acquisition contract');copy(path.join(userspaceRoot,item.path),path.join(output,item.path));auxiliary.push(item);}
 if(retained){
  const retainedRoot=path.resolve(options.retainedRuntime),selected=Object.keys(userspace.platforms).map(value=>value.replace('/','-'));
  need(userspaceRoot===retainedRoot,'retained composition must use its own verified userspace inputs');
  const old=retained.runtime;need(old.provider_receipts&&Object.keys(old.provider_receipts).length>0,'retained provider receipts are absent');
  images.provider_receipts=old.provider_receipts;
  copy(path.join(retainedRoot,'runtime/engine-distributions.lock.json'),path.join(output,'runtime/engine-distributions.lock.json'));
  // Verify the complete retained contracts; copy the same selected transports
  // that the available-target candidate will actually ship.
  const verified=auxiliaryArtifacts(retainedRoot,userspace,old,{targets:selected});
  for(const item of verified.filter(value=>value.id.startsWith('provider-assets-'))){const target=path.join(output,item.path);copy(path.join(retainedRoot,item.path),target);const copied=receipt(target);need(copied.sha256===item.sha256&&copied.size_bytes===item.size_bytes,'retained provider transport changed during composition');auxiliary.push(item);}
  // Keep all provider acquisition contracts and their exact inventory entries;
  // unavailable target archives stay in the retained source, not this stage.
  const full=read(path.join(retainedRoot,'runtime/auxiliary-artifacts.json')).assets;
  for(const item of full.filter(value=>value.id.startsWith('provider-assets-')&&!auxiliary.some(existing=>existing.id===value.id)))auxiliary.push(item);
 }else if(options.providers){
  const providerFile=path.resolve(options.providers),providerRoot=path.dirname(providerFile),providers=read(providerFile);need(providers.schema_version===1&&providers.provider_receipts&&Array.isArray(providers.files),'provider asset receipt is incomplete');
  for(const item of providers.files){safeRelative(item.path);const actual=receipt(path.join(providerRoot,item.path));need(actual.sha256===item.sha256&&actual.size_bytes===item.size_bytes,'provider asset differs from its frozen input');}
  images.provider_receipts=Object.fromEntries(Object.entries(providers.provider_receipts).filter(([name])=>hosts.includes(name.split('/').slice(-2).join('/'))));
  const engineLock='runtime/engine-distributions.lock.json';need(providers.files.some(value=>value.path===engineLock),'provider engine-distribution receipt is absent');copy(path.join(providerRoot,engineLock),path.join(output,engineLock));
  for(const[name,provider]of Object.entries(images.provider_receipts)){
   if(provider.lazy_assets){const id='provider-assets-'+name.replaceAll('/','-'),item=providers.lazy_archive_assets?.find(value=>value.id===id);need(item,'provider lazy archive transport is absent');safeRelative(item.path);const actual=receipt(path.join(providerRoot,item.path));need(actual.sha256===provider.lazy_assets.sha256&&actual.size_bytes===provider.lazy_assets.size&&item.url===provider.lazy_assets.url,'provider lazy archive differs from its contract');copy(path.join(providerRoot,item.path),path.join(output,item.path));auxiliary.push(item);}
   else{const[engine,platform,architecture]=name.split('/'),prefix=`runtime/providers/${engine}/${platform}-${architecture}/`;for(const item of providers.files)if(item.path.startsWith(prefix)||engine==='apple-container'&&item.path==='runtime/images/init-linux-arm64.tar')copy(path.join(providerRoot,item.path),path.join(output,item.path));}
  }
 }
 writeFileSync(path.join(output,'runtime/auxiliary-artifacts.json'),JSON.stringify({schema_version:1,assets:auxiliary},null,2)+'\n');
 const validate=new Ajv({strict:true}).compile(read(path.join(root,'contracts/schema/runtime-lock.schema.json')));need(validate(images),JSON.stringify(validate.errors));
 writeFileSync(path.join(output,'runtime/runtime.lock.json'),JSON.stringify(images,null,2)+'\n');
 // The retained assets were built with this earlier authored recipe. Preserve
 // its exact source in the new snapshot even when the current replay helper
 // has since changed; the old stage remains an input, not final evidence.
 let retainedProducer;
 if(retained){const name='runtime/materials/retained-userspace-producer.py',originalProducer=retained.retained.files.find(row=>row.path==='scripts/runtime/prepare-userspace.py');need(originalProducer&&!existsSync(path.join(output,name)),'retained producer source is missing or its output already exists');copy(path.join(path.resolve(options.retainedRuntime),originalProducer.path),path.join(output,name));retainedProducer=fileReceipt(output,name);need(retainedProducer.sha256===originalProducer.sha256&&retainedProducer.size===originalProducer.size&&retainedProducer.executable===originalProducer.executable,'retained producer source changed during composition');}
 refreshStagedImplementationInventory(output,python);
 const staged=sourceReceipt(output),result={schema_version:1,qualification:options.availableTargets?'available-target-inputs':options.diagnosticPartial||options.diagnosticWorkerPlatform?'diagnostic-partial-composition':'local-candidate-inputs',production_ready:false,source_tree_sha256:staged.sha256,original_source_tree_sha256:original.sha256,userspace_platforms:selected,image_evidence:imageEvidence,source_materials:{artifact_count:materials.length,complete_product_coverage:materials[0]?.complete_product_coverage??false},...(retained?{retained_runtime:{source_tree_sha256:retained.retained.sha256,composition_sha256:fileReceipt(path.resolve(options.retainedRuntime),'freeze-composition.json').sha256,userspace_producer:retainedProducer}}:{}),...(workerPlatform?{worker_platform:workerPlatform,deferred_worker_platforms:['linux/arm64','linux/amd64'].filter(value=>value!==workerPlatform)}:{})};
 writeFileSync(path.join(output,'freeze-composition.json'),JSON.stringify(result,null,2)+'\n');rmSync(path.join(output,'INCOMPLETE'));return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
 try {
  const args = process.argv.slice(2), options = {};
  const keys = {
   '--workers':'workers', '--userspace':'userspace', '--context':'context', '--core-context':'coreContext',
   '--output':'output', '--diagnostic-worker-platform':'diagnosticWorkerPlatform', '--available-worker-platform':'availableWorkerPlatform',
   '--providers':'providers', '--retained-runtime':'retainedRuntime'
  };
  for (let i = 0; i < args.length; i++) {
   const flag = args[i];
   if (flag === '--lazy-render') {
    const value = args[++i], split = value?.indexOf('=');
    need(split > 0, '--lazy-render requires HOST=ARCHIVE');
    options.lazyRender ??= {};
    options.lazyRender[value.slice(0, split)] = value.slice(split + 1);
    continue;
   }
   if (flag === '--core-context-platform') {
    const value = args[++i], split = value?.indexOf('=');
    need(split > 0 && split < value.length - 1, '--core-context-platform requires PLATFORM=DIRECTORY');
    const platform = value.slice(0, split);
    options.coreContexts ??= Object.create(null);
    need(!Object.hasOwn(options.coreContexts, platform), 'duplicate per-platform core context');
    options.coreContexts[platform] = value.slice(split + 1);
    continue;
   }
   if (flag === '--diagnostic-partial-userspace') { options.diagnosticPartial = true; continue; }
   if (flag === '--available-targets') { options.availableTargets = true; continue; }
   need(Object.hasOwn(keys, flag) && args[i + 1], 'invalid arguments');
   options[keys[flag]] = args[++i];
  }
  need(['workers', 'userspace', 'context', 'output'].every(key => options[key]) && (options.coreContext || options.coreContexts),
    'Usage: freeze-runtime.mjs --workers RECEIPT --userspace PACK --context PORTABLE_CONTEXT [--core-context BUILD_CONTEXT | --core-context-platform PLATFORM=DIRECTORY ...] --output NEW_SOURCE_TREE [--providers RECEIPT | --retained-runtime SOURCE_STAGE] [--lazy-render HOST=ARCHIVE] [--diagnostic-partial-userspace] [--diagnostic-worker-platform linux/arm64]');
  console.log(JSON.stringify(composeRuntime(options)));
 } catch (error) {
  console.error(String(error));
  process.exitCode = 1;
 }
}
