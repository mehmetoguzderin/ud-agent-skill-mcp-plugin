import { test, expect } from 'vitest';
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { availablePlatforms, availableScope, copyCandidatePayload, createMaterialStage, planAvailableStorage, prepareAvailableCandidate, recoverMaterialStage, replayStorageBytes, stageAvailableMaterials, validateAvailableCandidate, verifyAvailableCandidateBindings, verifyAvailableCandidateCoverage } from '../../scripts/release/available-candidate.mjs';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { bundleCoordinator, packageInventory, retainSourceSnapshot } from '../../scripts/release/prepare.mjs';
import { fixtureTar } from './oci-fixture.mjs';
import { pathToFileURL } from 'node:url';
import { posixTest } from '../fixtures/native-scope.mjs';
const required = JSON.parse(readFileSync('quality/requirements.json','utf8')).required_artifacts;

test('available packaging separately budgets candidate output and sequential scratch',()=>{
  const input={sourceBytes:10,runtimeBytes:20,nativeBytes:30,transportBytes:40,auxiliaryBytes:50,materialBytes:60,targetCount:2,crossBytes:70,helperBytes:80,maxUserspace:90};
  const result=planAvailableStorage(input);
  expect(result.plannedOutputBytes).toBe(128*1024**2+3*10+2*20+30+2*40+2*50+60+2*3*(70+80));
  expect(result.plannedBytes).toBe(1024**3+2*10+90+2*70+80);
  for(const [key,value] of [['sourceBytes',-1],['maxUserspace',Infinity],['targetCount',0],['targetCount',7]]) expect(()=>planAvailableStorage({...input,[key]:value})).toThrow(/invalid/);
});

posixTest('material-stage recovery removes only a stopped, exactly owned incomplete stage',()=>{
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-material-recovery-'))),output=path.join(root,'stage');
  try{
    mkdirSync(output);const info=lstatSync(output),marker=path.join(output,'.ud-material-stage-owner.json');writeFileSync(path.join(output,'INCOMPLETE'),'interrupted');
    const record={schema_version:1,owner_root:root,output,device:info.dev,inode:info.ino,uid:info.uid,pid:process.pid};writeFileSync(marker,JSON.stringify(record),{mode:0o600});
    expect(()=>recoverMaterialStage(root,output)).toThrow(/still active/);expect(existsSync(output)).toBe(true);
    writeFileSync(marker,JSON.stringify({...record,output:path.join(root,'foreign'),pid:2147483647}));expect(()=>recoverMaterialStage(root,output)).toThrow(/ownership differs/);expect(existsSync(output)).toBe(true);
    writeFileSync(marker,JSON.stringify({...record,pid:2147483647}));expect(recoverMaterialStage(root,output)).toBe(true);expect(existsSync(output)).toBe(false);expect(recoverMaterialStage(root,output)).toBe(false);
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('material-stage initialization failure removes only its new directory',()=>{
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-material-init-'))),output=path.join(root,'stage'),foreign=path.join(root,'foreign');
  try{
    mkdirSync(foreign);writeFileSync(path.join(foreign,'data'),'preserve');
    for(const failAt of [1,2]){let count=0;expect(()=>createMaterialStage(root,output,(...args)=>{if(++count===failAt)throw new Error('write failed');writeFileSync(...args);})).toThrow(/write failed/);expect(existsSync(output)).toBe(false);}
    expect(()=>createMaterialStage(root,foreign)).toThrow();expect(readFileSync(path.join(foreign,'data'),'utf8')).toBe('preserve');
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('candidate payload deduplication shares only candidate-owned equal bytes',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-candidate-dedup-'));
  try {
    const input=path.join(root,'input'), candidate=path.join(root,'candidate');mkdirSync(input);mkdirSync(candidate);
    writeFileSync(path.join(input,'one'),'same bytes');writeFileSync(path.join(input,'two'),'same bytes');
    const copies=new Map(),one=fileReceipt(input,'one'),two=fileReceipt(input,'two');
    copyCandidatePayload(input,one,candidate,candidate,'artifacts/one',copies);
    copyCandidatePayload(input,two,candidate,candidate,'runtime/two',copies);
    const first=lstatSync(path.join(candidate,'artifacts/one')),second=lstatSync(path.join(candidate,'runtime/two'));
    expect(first.ino).toBe(second.ino);expect(first.ino).not.toBe(lstatSync(path.join(input,'one')).ino);
    writeFileSync(path.join(input,'one'),'changed externally');expect(readFileSync(path.join(candidate,'artifacts/one'),'utf8')).toBe('same bytes');
    writeFileSync(path.join(candidate,'artifacts/one'),'changed candidate');
    expect(()=>copyCandidatePayload(input,two,candidate,candidate,'artifacts/three',copies)).toThrow(/changed before deduplication/);
    expect(()=>copyCandidatePayload(input,two,candidate,root,'outside',copies)).toThrow(/escapes/);
  } finally {rmSync(root,{recursive:true,force:true});}
});

posixTest('candidate payload deduplication preserves executable metadata',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-candidate-mode-'));
  try {
    const input=path.join(root,'input'),candidate=path.join(root,'candidate');mkdirSync(input);mkdirSync(candidate);
    writeFileSync(path.join(input,'plain'),'same');writeFileSync(path.join(input,'run'),'same');chmodSync(path.join(input,'plain'),0o644);chmodSync(path.join(input,'run'),0o755);
    const copies=new Map();for(const name of ['plain','run'])copyCandidatePayload(input,fileReceipt(input,name),candidate,candidate,name,copies);
    expect(lstatSync(path.join(candidate,'plain')).ino).not.toBe(lstatSync(path.join(candidate,'run')).ino);
    expect(fileReceipt(candidate,'run').executable).toBe(true);expect(fileReceipt(candidate,'plain').executable).toBe(false);
  } finally {rmSync(root,{recursive:true,force:true});}
});

if(process.platform==='win32')test('Windows candidate deduplication preserves observed equal byte receipts without claiming POSIX execute bits',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-candidate-win-mode-'));
  try {
    const input=path.join(root,'input'),candidate=path.join(root,'candidate');mkdirSync(input);mkdirSync(candidate);
    writeFileSync(path.join(input,'plain'),'same');writeFileSync(path.join(input,'run'),'same');chmodSync(path.join(input,'plain'),0o644);chmodSync(path.join(input,'run'),0o755);
    const copies=new Map();for(const name of ['plain','run']){
      const receipt=fileReceipt(input,name);expect(receipt.executable).toBe(false);
      copyCandidatePayload(input,receipt,candidate,candidate,name,copies);
      expect(fileReceipt(candidate,name)).toEqual(receipt);expect(readFileSync(path.join(candidate,name),'utf8')).toBe('same');
    }
    const first=lstatSync(path.join(candidate,'plain'),{bigint:true}),second=lstatSync(path.join(candidate,'run'),{bigint:true}),original=lstatSync(path.join(input,'plain'),{bigint:true});
    expect([first.dev,first.ino]).toEqual([second.dev,second.ino]);expect([first.dev,first.ino]).not.toEqual([original.dev,original.ino]);
    writeFileSync(path.join(input,'plain'),'changed input');expect(readFileSync(path.join(candidate,'plain'),'utf8')).toBe('same');
  } finally {rmSync(root,{recursive:true,force:true});}
});

test('copied source verification loads without builder node_modules or sibling checkout access',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-standalone-import-'));
  try {
    const files=[...readdirSync('scripts/release').filter(name=>name.endsWith('.mjs')).map(name=>'scripts/release/'+name),'scripts/quality/storage-lifecycle.mjs','scripts/quality/windows-storage.mjs','scripts/quality/windows-storage-acl.py','scripts/generate/skill-files.mjs','packages/workspace/src/portable-path.ts','workers/ud/src/ud_agent/unicode_casefold.json'];
    for(const name of files){mkdirSync(path.dirname(path.join(root,name)),{recursive:true});copyFileSync(name,path.join(root,name));}writeFileSync(path.join(root,'package.json'),'{"type":"module"}');
    const result=spawnSync(process.execPath,['--input-type=module','-e','const m=await import(process.argv[1]);console.log(typeof m.verifyAvailableCandidateBindings,typeof m.verifyAvailableCandidateCoverage)',pathToFileURL(path.join(root,'scripts/release/available-candidate.mjs')).href],{cwd:root,encoding:'utf8',env:{PATH:path.dirname(process.execPath)}});
    expect(result.status,result.stderr).toBe(0);expect(result.stdout.trim()).toBe('function function');
  } finally{rmSync(root,{recursive:true,force:true});}
});

test('replay storage includes unique outputs, retained originals and sequential OCI expansion',()=>{
  const report={inspection_inputs:{inputs:[{path:'source/file',size_bytes:3,sha256:'a',retention:{kind:'corresponding-source-blob'}},{path:'member',size_bytes:5,retention:{kind:'corresponding-source-member',blob_sha256:'a'}}]},required_materials:[{sha256:'a',size_bytes:11}],subjects:[{id:'core-oci-index',bindings:[{size_bytes:7},{size_bytes:13}]}]};
  expect(replayStorageBytes({files:[{path:'source/file',size:3}]},[{id:'core-oci-index',path:'artifact',size:17}],report)).toBe(3+5+17+11+20+128*1024**2);
  // Compact replay reads the source and released artifacts in place and
  // materializes at most one original source blob at a time.
  expect(replayStorageBytes({files:[{path:'source/file',size:3}]},[{id:'core-oci-index',path:'artifact',size:17}],report,{compact:true})).toBe(3+5+20+128*1024**2);
  expect(()=>replayStorageBytes({files:[]},[],{...report,required_materials:[]})).toThrow(/finite byte inventory/);
  expect(()=>replayStorageBytes({files:[{path:'source/file',size:99}]},[],report)).toThrow(/conflicting sizes/);
  expect(()=>replayStorageBytes({files:[]},[{id:'core-linux-arm64-docker-archive-0',path:'image',size:1}],report,{compact:true})).toThrow(/OCI workspace/);
  const dockerReport={...report,subjects:[...report.subjects,{id:'core-linux-arm64-docker-archive-0',bindings:[{size_bytes:30}]}]};
  expect(replayStorageBytes({files:[]},[{id:'core-oci-index',path:'image',size:1},{id:'core-linux-arm64-docker-archive-0',path:'docker',size:1}],dockerReport,{compact:true})).toBe(3+5+30+2+64*1024**2+128*1024**2);
  expect(()=>replayStorageBytes({files:[]},[],{...report,required_materials:[...report.required_materials,...report.required_materials]},{compact:true})).toThrow(/duplicate/);
  expect(()=>replayStorageBytes({files:[]},[],{...report,inspection_inputs:{inputs:[{path:'huge',size_bytes:4_000_000_000,retention:{kind:'retained-json-metadata'}}]},subjects:[]},{compact:true})).toThrow(/4 GB/);
});

test('bundle compiles retained off-root source with the selected immutable dependency tree',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-bundle-'));
  try {
    mkdirSync(path.join(root,'packages/coordinator/src'),{recursive:true});
    writeFileSync(path.join(root,'packages/coordinator/src/entry.ts'),'import path from "node:path"; import { parse } from "smol-toml"; console.log(path.basename("/retained/source"),parse("answer=41").answer);');
    const target=path.join(root,'candidate.mjs');bundleCoordinator(root,process.cwd(),target);
    const result=spawnSync(process.execPath,[target],{encoding:'utf8'});expect(result.status).toBe(0);expect(result.stdout.trim()).toBe('source 41');
  } finally {rmSync(root,{recursive:true,force:true});}
});
function fixture(root, sourceLock) {
  const authorities = path.join(root,'authorities'); mkdirSync(path.join(authorities,'quality'),{recursive:true});mkdirSync(path.join(authorities,'runtime'));
  writeFileSync(path.join(authorities,'LICENSE'),'fixture original license');writeFileSync(path.join(authorities,'quality/requirements.json'),JSON.stringify({required_artifacts:required}));
  mkdirSync(path.join(authorities,'scripts/generate'),{recursive:true});
  writeFileSync(path.join(authorities,'scripts/generate/implementation-inventory.py'), 'import hashlib,json,sys\nfrom pathlib import Path\nr=Path(__file__).resolve().parents[2];p=r/"contracts/implementation-inventory.json";body=json.dumps({"lock":hashlib.sha256((r/"runtime/source-materials.lock.json").read_bytes()).hexdigest()})\nif "--check" in sys.argv:\n assert p.read_text()==body\nelse:\n p.parent.mkdir(exist_ok=True);p.write_text(body)\n');
  const runtime={schema_version:1,state:'frozen',packs:{core:{images:{'linux/arm64':{digest:'sha256:'+'a'.repeat(64)}}},render:{images:{'linux/arm64':{digest:'sha256:'+'b'.repeat(64)}}}}};
  writeFileSync(path.join(authorities,'runtime/runtime.lock.json'),JSON.stringify(runtime));writeFileSync(path.join(authorities,'runtime/userspace.lock.json'),JSON.stringify({platforms:{'darwin/arm64':{},'linux/arm64':{}}}));
  if(sourceLock)writeFileSync(path.join(authorities,'runtime/source-materials.lock.json'),JSON.stringify(sourceLock));
  const candidateRoot=path.join(root,'candidate');mkdirSync(candidateRoot);const source=sourceReceipt(authorities);retainSourceSnapshot(authorities,source,path.join(candidateRoot,'source-snapshot'));
  mkdirSync(path.join(candidateRoot,'runtime-inputs/runtime'),{recursive:true});
  const files=['runtime/runtime.lock.json','runtime/userspace.lock.json'].map(name=>{writeFileSync(path.join(candidateRoot,'runtime-inputs',name),readFileSync(path.join(authorities,name)));return fileReceipt(path.join(candidateRoot,'runtime-inputs'),name);});
  writeFileSync(path.join(candidateRoot,'RUNTIME-INVENTORY.json'),JSON.stringify({schema_version:1,files}));
  const artifacts=[],installations=[],runtimeHash=fileReceipt(authorities,'runtime/runtime.lock.json').sha256;mkdirSync(path.join(candidateRoot,'artifacts'));
  const artifact=(id,platform)=>{const name='artifacts/'+id+'.archive';writeFileSync(path.join(candidateRoot,name),'original-'+id);artifacts.push({id,platform,...fileReceipt(candidateRoot,name)});};
  artifact('npm','all');
  for(const platform of ['darwin-arm64','linux-arm64']){
    const publication=platform.replace('darwin','macos');for(const format of ['native','mcpb'])artifact(format+'-'+publication,publication);
    const name='installations/'+platform,install=path.join(candidateRoot,name);mkdirSync(install,{recursive:true});writeFileSync(path.join(install,'RELEASE-CANDIDATE.md'),'immutable');packageInventory(install,'native',platform,source.sha256,runtimeHash,'preacceptance_candidate');
    installations.push({platform,formats:{native:{root:name,artifact_id:'native-'+publication},mcpb:{root:name,artifact_id:'mcpb-'+publication},npm:{root:'npm-installation',artifact_id:'npm'}}});
  }
  const npm=path.join(candidateRoot,'npm-installation');mkdirSync(npm);writeFileSync(path.join(npm,'RELEASE-CANDIDATE.md'),'immutable');packageInventory(npm,'npm','all',source.sha256,runtimeHash,'preacceptance_candidate');
  const manifest={schema_version:1,qualification:'available-target-preacceptance',status:'preacceptance_candidate',production_ready:false,material_phase:'provisional',source_tree_sha256:source.sha256,runtime_lock_sha256:runtimeHash,scope:availableScope(authorities,['darwin-arm64','linux-arm64'],artifacts),artifacts,installations,source_snapshot:{root:'source-snapshot',receipt:fileReceipt(candidateRoot,'source-snapshot/SOURCE-RECEIPT.json')},runtime_root:'runtime-inputs',runtime_inventory:fileReceipt(candidateRoot,'RUNTIME-INVENTORY.json')};
  return {root:candidateRoot,manifest};
}

test('available immutable scope retains the five native targets and sixteen production subjects',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-scope-'));try{const f=fixture(root);expect(validateAvailableCandidate(f.root,f.manifest).targets).toEqual(['darwin-arm64','linux-arm64']);expect(f.manifest.scope.required_targets).toEqual(availablePlatforms);expect(f.manifest.scope.required_artifacts).toEqual(required);expect(f.manifest.scope.pending_targets).toHaveLength(3);expect(f.manifest.scope.pending_artifacts).toHaveLength(11);expect(f.manifest.production_ready).toBe(false);
  for(const mutate of [m=>{m.qualification='diagnostic-partial-composition';},m=>{m.production_ready=true;},m=>{m.scope.pending_targets=[];},m=>{m.scope.required_artifacts=m.scope.required_artifacts.slice(1);},m=>{m.scope.available_targets.push('linux-x64');},m=>{m.installations[0].formats.mcpb.artifact_id='native-macos-arm64';},m=>{m.artifacts.push(m.artifacts[0]);}]){const bad=structuredClone(f.manifest);mutate(bad);expect(()=>validateAvailableCandidate(f.root,bad)).toThrow();}
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('source/runtime and complete installed inventories are checked at candidate-owned paths',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-bytes-'));try{const f=fixture(root);writeFileSync(path.join(f.root,'runtime-inputs/runtime/unlisted'),'extra');expect(()=>validateAvailableCandidate(f.root,f.manifest)).toThrow(/runtime inventory/);rmSync(path.join(f.root,'runtime-inputs/runtime/unlisted'));writeFileSync(path.join(f.root,'installations/darwin-arm64/unlisted'),'extra');expect(()=>validateAvailableCandidate(f.root,f.manifest)).toThrow(/complete original inventory/);rmSync(path.join(f.root,'installations/darwin-arm64/unlisted'));writeFileSync(path.join(f.root,'source-snapshot/LICENSE'),'substituted');expect(()=>validateAvailableCandidate(f.root,f.manifest)).toThrow(/retained source/);}finally{rmSync(root,{recursive:true,force:true});}
});

test('public available coverage entry refuses provisional, unfinished and missing actual replay evidence',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-final-'));try{const f=fixture(root);expect(()=>verifyAvailableCandidateCoverage(f.root,f.manifest,{})).toThrow(/final source material/);f.manifest.material_phase='final';writeFileSync(path.join(f.root,'INCOMPLETE'),'unfinished');expect(()=>verifyAvailableCandidateCoverage(f.root,f.manifest,{})).toThrow(/assembly is incomplete/);rmSync(path.join(f.root,'INCOMPLETE'));expect(()=>verifyAvailableCandidateCoverage(f.root,f.manifest,{})).toThrow(/source coverage is missing/);}finally{rmSync(root,{recursive:true,force:true});}
});

test('available producer rejects an existing diagnostic composition before producing any output',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-no-relabel-'));
  try {const f=fixture(root);writeFileSync(path.join(f.root,'runtime-inputs/freeze-composition.json'),JSON.stringify({qualification:'diagnostic-partial-composition'}));const output=path.join(root,'new-output');expect(()=>prepareAvailableCandidate({sourceRoot:path.join(f.root,'source-snapshot'),runtimeRoot:path.join(f.root,'runtime-inputs'),buildRoot:root,output,python:'python3'})).toThrow(/diagnostic composition cannot be relabeled/);expect(()=>readFileSync(path.join(output,'INCOMPLETE'))).toThrow();}
  finally{rmSync(root,{recursive:true,force:true});}
});

test('available producer validates required runtime inputs before retiring inputs or writing output',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-supervision-'));
  try{
    const f=fixture(root),runtimeRoot=path.join(f.root,'runtime-inputs'),sourceRoot=path.join(f.root,'source-snapshot'),output=path.join(root,'new-output');
    writeFileSync(path.join(runtimeRoot,'freeze-composition.json'),JSON.stringify({qualification:'available-target-inputs',source_tree_sha256:f.manifest.source_tree_sha256}));
    expect(()=>prepareAvailableCandidate({sourceRoot,runtimeRoot,buildRoot:root,output,python:'python3'})).toThrow();
    expect(existsSync(output)).toBe(false);expect(readFileSync(path.join(f.root,'artifacts/npm.archive'),'utf8')).toBe('original-npm');
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('native byte-binding verification records the separate source replay gate without certifying its claim',()=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-available-bindings-'));
  try {
    const body=Buffer.from('original upstream source'),digest=sha256(body),receipt=Buffer.from('{"upstream":"original"}');
    const material={schema_version:1,qualification:'verified-corresponding-source-subinventories',complete_product_coverage:false,files:[{path:'blobs/'+digest,sha256:digest,size_bytes:body.length}],collections:[{id:'original',receipt_path:'receipts/original.json',receipt_sha256:sha256(receipt),receipt_size_bytes:receipt.length,members:[{path:'blobs/'+digest,sha256:digest,size_bytes:body.length}]}]};
    const materialBytes=Buffer.from(JSON.stringify(material)),part=fixtureTar([['MATERIALS.json',materialBytes],['receipts/original.json',receipt],['blobs/'+digest,body]]),partRow={id:'corresponding-source-0000',path:'artifacts/source.part',sha256:sha256(part),size:part.length};
    const index={schema_version:1,qualification:material.qualification,complete_product_coverage:false,format:'concatenated-ustar',manifest_sha256:sha256(materialBytes),stream_sha256:sha256(part),stream_size_bytes:part.length,parts:[{...partRow,path:'source.part'}],collections:[{id:'original',sha256:sha256(receipt)}],unique_source_files:1};
    const indexBytes=Buffer.from(JSON.stringify(index)),indexRow={path:'artifacts/source-index.json',sha256:sha256(indexBytes),size:indexBytes.length};
    const f=fixture(root,{schema_version:1,index:indexRow,parts:[partRow]});writeFileSync(path.join(f.root,indexRow.path),indexBytes);writeFileSync(path.join(f.root,partRow.path),part);f.manifest.artifacts.push({id:'corresponding-source-index',platform:'all',...indexRow},{platform:'all',...partRow});f.manifest.material_phase='final';
    const report={schema_version:1,qualification:'replayed-actual-shipped-component-source-license-closure',source_inventory_sha256:f.manifest.source_tree_sha256,runtime_lock_sha256:f.manifest.runtime_lock_sha256,complete_available_shipped_component_coverage:true,complete_product_coverage:false,unresolved_shipped_members:[],missing_distribution_subjects:f.manifest.scope.pending_artifacts.map(row=>({code:'REQUIRED_DISTRIBUTION_MISSING',artifact:row.id})).sort((a,b)=>a.artifact.localeCompare(b.artifact)),subjects:f.manifest.artifacts.map(row=>({id:row.id,artifact_sha256:row.sha256})),inspection_inputs:{qualification:'observed-component-replay-inputs-no-unretained-input-waiver',unretained_inputs:[]},required_materials:[{sha256:digest,size_bytes:body.length}]};
    const name='artifacts/coverage.json';writeFileSync(path.join(f.root,name),JSON.stringify(report));const coverage={id:'component-source-coverage',platform:'all',...fileReceipt(f.root,name)};f.manifest.artifacts.push(coverage);
    const result=verifyAvailableCandidateBindings(f.root,f.manifest);expect(result.source_replay_performed).toBe(false);expect(result.source_replay_required).toBe(true);expect(result.source_coverage_receipt.sha256).toBe(coverage.sha256);expect(result.material_bindings_verified).toBe(true);expect(result).not.toHaveProperty('complete_available_shipped_component_coverage');
    expect(()=>verifyAvailableCandidateCoverage(f.root,f.manifest,{})).toThrow(/authenticated privately staged/);
    report.inspection_inputs={schema_version:2,qualification:'compact-family-replay-inputs-no-unretained-input-waiver',source_inventory_sha256:f.manifest.source_tree_sha256,subjects:f.manifest.artifacts.filter(row=>row.id!=='component-source-coverage').map(row=>({id:row.id,sha256:row.sha256})),input_count:1,inventory_sha256:'c'.repeat(64),metadata:[],tools:[],unretained_count:0,unretained_sha256:sha256(Buffer.from('[]'))};
    writeFileSync(path.join(f.root,name),JSON.stringify(report));Object.assign(coverage,fileReceipt(f.root,name));
    expect(verifyAvailableCandidateBindings(f.root,f.manifest)).toMatchObject({source_replay_performed:false,source_replay_required:true});
    expect(()=>verifyAvailableCandidateCoverage(f.root,f.manifest,{})).toThrow(/recipe-based input reconstruction/);
    report.inspection_inputs.unretained_count=1;writeFileSync(path.join(f.root,name),JSON.stringify(report));Object.assign(coverage,fileReceipt(f.root,name));
    expect(()=>verifyAvailableCandidateBindings(f.root,f.manifest)).toThrow(/incomplete/);
  } finally {rmSync(root,{recursive:true,force:true});}
});

test('second material pass creates a new source stage from the selected original stream before regenerating its inventory',()=>{
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-available-material-pass-')));
  try {
    const f=fixture(root),before=sourceReceipt(path.join(f.root,'source-snapshot'));writeFileSync(path.join(f.root,'available-candidate.json'),JSON.stringify(f.manifest));
    const plan=path.join(root,'plan');mkdirSync(path.join(plan,'runtime'),{recursive:true});
    const bytes=Buffer.from('exact original upstream source'),digest=sha256(bytes),proof=Buffer.from('{"original":"receipt"}');
    const material={schema_version:1,qualification:'verified-corresponding-source-subinventories',complete_product_coverage:false,files:[{path:'blobs/'+digest,sha256:digest,size_bytes:bytes.length}],collections:[{id:'original',receipt_path:'receipts/original.json',receipt_sha256:sha256(proof),receipt_size_bytes:proof.length,members:[{path:'blobs/'+digest,sha256:digest,size_bytes:bytes.length}]}]};
    const manifestBytes=Buffer.from(JSON.stringify(material)),archive=fixtureTar([['MATERIALS.json',manifestBytes],['receipts/original.json',proof],['blobs/'+digest,bytes]]);
    writeFileSync(path.join(plan,'source.part'),archive);const part={id:'corresponding-source-0000',...fileReceipt(plan,'source.part')};
    const index={schema_version:1,qualification:material.qualification,format:'concatenated-ustar',complete_product_coverage:false,manifest_sha256:sha256(manifestBytes),stream_sha256:sha256(archive),stream_size_bytes:archive.length,collections:[{id:'original',sha256:sha256(proof)}],unique_source_files:1,parts:[part]};
    writeFileSync(path.join(plan,'source-index.json'),JSON.stringify(index));const lock={schema_version:1,index:fileReceipt(plan,'source-index.json'),parts:[part]};writeFileSync(path.join(plan,'runtime/source-materials.lock.json'),JSON.stringify(lock));
    writeFileSync(path.join(plan,'coverage.json'),JSON.stringify({complete_available_shipped_component_coverage:true,required_materials:[{sha256:digest,size_bytes:bytes.length}]}));
    writeFileSync(path.join(plan,'ASSEMBLY.json'),JSON.stringify({qualification:'actual-shipped-component-selected-original-source-assembly',source_tree_sha256:f.manifest.source_tree_sha256,runtime_lock_sha256:f.manifest.runtime_lock_sha256,complete_available_shipped_component_coverage:true,component_source_coverage:fileReceipt(plan,'coverage.json')}));
    const output=path.join(root,'final-source'),realPlan=realpathSync(plan),realOutput=path.join(realpathSync(root),'final-source'),source=path.join(realPlan,'source.part');
    // Model large NTFS Number identities only in this worker's selected paths.
    // Real byte verification, hardlink creation and parent inode checks remain.
    const preload=path.join(root,'large-file-identity.mjs');
    writeFileSync(preload,`import fs from 'node:fs';import{syncBuiltinESMExports}from'node:module';const selected=new Set(${JSON.stringify([source,path.join(realOutput,'.artifacts/selected-source-materials/source.part')])}),original=fs.lstatSync;let modeled=0;fs.lstatSync=(file,options)=>{const info=original(file,options);if(info&&selected.has(file)&&!options?.bigint){info.ino=Number.MAX_SAFE_INTEGER+1;modeled++;}return info;};syncBuiltinESMExports();process.on('exit',()=>{if(!modeled)process.exitCode=71;});\n`);
    const request=Buffer.from(JSON.stringify({provisionalRoot:realpathSync(f.root),planRoot:realPlan,output:realOutput,python:process.env.UD_AGENT_PYTHON??'python3'})).toString('base64url');
    const supervisor=path.resolve('scripts/quality/storage-lifecycle.mjs'),worker=path.resolve('scripts/release/available-candidate.mjs');
    const run=spawnSync(process.execPath,[supervisor,'--run',realPlan,String(128*1024**2),'release','--owned-root',realpathSync(f.root),'--output',realOutput,'--output-bytes',String(128*1024**2+before.files.reduce((sum,row)=>sum+row.size,0)+1024**2),'--',process.execPath,'--import',pathToFileURL(preload).href,worker,'--material-stage-worker',request],{encoding:'utf8',timeout:30000});
    expect(run.status,run.stderr).toBe(0);const result=JSON.parse(run.stdout);
    expect(result.material_phase).toBe('final');expect(sourceReceipt(path.join(f.root,'source-snapshot'))).toEqual(before);expect(result.source_tree_sha256).not.toBe(before.sha256);
    const installed=JSON.parse(readFileSync(path.join(output,'runtime/source-materials.lock.json'),'utf8'));expect(installed.parts[0].path).toBe('.artifacts/selected-source-materials/source.part');expect(readFileSync(path.join(output,installed.parts[0].path))).toEqual(archive);
    expect(lstatSync(path.join(output,installed.parts[0].path)).ino).toBe(lstatSync(path.join(plan,'source.part')).ino);
    expect(JSON.parse(readFileSync(path.join(output,'contracts/implementation-inventory.json'),'utf8')).lock).toBe(fileReceipt(output,'runtime/source-materials.lock.json').sha256);
    expect(JSON.parse(readFileSync(path.join(output,'freeze-composition.json'),'utf8')).source_tree_sha256).toBe(result.source_tree_sha256);
    expect(()=>stageAvailableMaterials(f.root,plan,output,{python:'python3'})).toThrow(/must be new/);
  } finally {rmSync(root,{recursive:true,force:true});}
});

if(process.platform==='win32')test('material-stage recovery refuses unproved POSIX marker privacy and preserves incomplete bytes',()=>{
 const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-material-refusal-'))),output=path.join(root,'stage');
 try{
  mkdirSync(output);const info=lstatSync(output),marker=path.join(output,'.ud-material-stage-owner.json');writeFileSync(path.join(output,'INCOMPLETE'),'interrupted');
  const record={schema_version:1,owner_root:root,output,device:info.dev,inode:info.ino,uid:info.uid,pid:2147483647};writeFileSync(marker,JSON.stringify(record),{mode:0o600});
  expect(()=>recoverMaterialStage(root,output)).toThrow('Material stage ownership is ambiguous.');
  expect(JSON.parse(readFileSync(marker,'utf8'))).toEqual(record);expect(readFileSync(path.join(output,'INCOMPLETE'),'utf8')).toBe('interrupted');
 }finally{rmSync(root,{recursive:true,force:true});}
});
