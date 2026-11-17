/** Verify actual generation artifacts; emit an unsigned, outcome-free master. */
import{copyFileSync,existsSync,lstatSync,mkdirSync,readFileSync,writeFileSync}from'node:fs';
import{spawnSync}from'node:child_process';import path from'node:path';import{fileURLToPath}from'node:url';
import{fileReceipt,readRecordedBytes,safeRelative,sourceReceipt}from'../release/candidate.mjs';
import{acceptanceInputHash}from'../release/discover-acceptance.mjs';
import{mutationBackendContract,authorityFromGeneration,verifyMutationBackendDiscovery}from'../release/mutation-backends.mjs';
const insist=(value,message)=>{if(!value)throw new Error('Generation proof: '+message);};
const read=(root,name,maximum=64*1024**2)=>JSON.parse(readRecordedBytes(root,fileReceipt(root,name),maximum));

export function provePythonGeneration(root,state,output,python){return proveGeneratedBackend(root,state,output,python,'python');}
export function provePerlGeneration(root,state,output,python){return proveGeneratedBackend(root,state,output,python,'perl');}
export function verifyGenerationHarness(root,state,harness){
 for(const item of harness??[]){safeRelative(item.path);const source=item.path==='pytest_evidence.py'?'tests/mutation/pytest_evidence.py':'scripts/quality/'+item.path;
  insist(fileReceipt(state,'verified-harness/'+item.path).sha256===item.sha256&&fileReceipt(root,source).sha256===item.sha256,'actual image harness differs from its frozen source');}
}
function proveGeneratedBackend(root,state,output,python,selectedBackend){
 root=path.resolve(root);state=path.resolve(state);output=path.resolve(output);
 const relative=path.relative(root,output).split(path.sep).join('/');safeRelative(relative);insist(relative.startsWith('.artifacts/')&&!existsSync(output),'new owned artifact output required');
 insist(typeof python==='string'&&path.isAbsolute(python),'absolute pinned developer Python required');
 const source=sourceReceipt(root),input=acceptanceInputHash(source),runner=read(state,'runner.json'),runtime=read(state,'runtime-input-receipt.json');
 insist(runner.backend===selectedBackend&&runner.source_tree_sha256===source.sha256&&/^sha256:[a-f0-9]{64}$/.test(runner.image),'actual full source/image execution binding is missing');
 insist(runtime.package_lock_sha256===fileReceipt(root,'package-lock.json').sha256&&
  (selectedBackend==='python'?runtime.python_packages?.some(item=>item.name==='mutmut'&&item.version==='3.8.1'):runtime.perl_parser?.files>0&&typeof runtime.perl_parser?.receipt_sha256==='string'),'generator dependency identity differs');
 verifyGenerationHarness(root,state,runtime.harness);
 insist(read(state,'isolation-proof.json').status==='passed'&&read(state,'exec-isolation-proof.json').status==='passed','actual generator isolation was not established');
 let parent=root;for(const part of relative.split('/').slice(0,-1)){parent=path.join(parent,part);if(!existsSync(parent))mkdirSync(parent,{mode:0o700});const info=lstatSync(parent);insist(info.isDirectory()&&!info.isSymbolicLink(),'ordinary output parent required');}
 mkdirSync(output,{mode:0o700});writeFileSync(path.join(output,'INCOMPLETE'),'Generation reconstruction has not completed.\n');
 const subject=path.join(output,'source-subject.json');writeFileSync(subject,JSON.stringify(source)+'\n',{flag:'wx'});
 const reconstruction=path.join(output,'reconstructed.json'),helper=path.join(path.dirname(fileURLToPath(import.meta.url)),selectedBackend==='python'?'prove-python-generation.py':'prove-perl-generation.py');
 const reconstructed=spawnSync(python,['-B',helper,'--source-root',root,'--state',state,'--source-receipt',subject,'--output',reconstruction],{encoding:'utf8',timeout:20*60*1000,maxBuffer:1024*1024,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
 insist(!reconstructed.error&&reconstructed.status===0&&!reconstructed.signal,'actual generated definitions did not reconstruct: '+(reconstructed.stderr??reconstructed.error?.message));
 const proof=JSON.parse(readFileSync(reconstruction,'utf8'));
 insist(proof.qualification==='reconstructed-actual-generated-definitions-no-outcomes'&&proof.source_tree_sha256===source.sha256,'reconstructed generation subject differs');
 const inspected=spawnSync('docker',['image','inspect',runner.image],{encoding:'utf8',timeout:30000,maxBuffer:4*1024**2});
 insist(!inspected.error&&inspected.status===0&&!inspected.signal,'immutable local generation image is unavailable');
 const images=JSON.parse(inspected.stdout),image=images[0];
 insist(images.length===1&&image.Id===runner.image&&image.Os==='linux'&&image.Architecture==='arm64'&&JSON.stringify(image.Config.Entrypoint)===JSON.stringify(['/opt/mutation/python/bin/python3','/opt/mutation/harness/oci-mutation.py']),'actual generation image entrypoint or architecture differs');
 const imageFile=path.join(output,'image-inspection.json');writeFileSync(imageFile,inspected.stdout,{flag:'wx'});
 const artifacts=new Map(),copied=new Map();
 function record(file){const value=fileReceipt(root,path.relative(root,file).split(path.sep).join('/'));artifacts.set(value.path,value);return value;}
 for(const file of[subject,reconstruction,imageFile])record(file);
 function copyRaw(expected){
  const name=typeof expected==='string'?expected:expected.path;
  safeRelative(name);if(copied.has(name)){const prior=copied.get(name);if(typeof expected!=='string')insist(prior.sha256===expected.sha256&&prior.size===expected.size,'reconstruction used different raw bytes');return prior;}
  const before=fileReceipt(state,name);insist(before.size<=1024**3,'raw generation artifact exceeds its bound');
  if(typeof expected!=='string')insist(before.sha256===expected.sha256&&before.size===expected.size,'raw generated bytes differ from the exact bytes reconstructed');
  const target=path.join(output,'raw',name);mkdirSync(path.dirname(target),{recursive:true});copyFileSync(path.join(state,name),target);
  const after=record(target);insist(after.sha256===before.sha256&&after.size===before.size,'raw generation artifact changed during proof capture');copied.set(name,after);return after;
 }
 for(const name of proof.raw_artifacts)copyRaw(name);
 for(const name of[...(selectedBackend==='python'?['discovery.json']:[]),'runner.json','runtime-input-receipt.json','isolation-proof.json','exec-isolation-proof.json'])copyRaw(name);
 for(const item of runtime.harness??[])copyRaw('verified-harness/'+item.path);
 const backend=selectedBackend==='python'?{tool:'mutmut',version:'3.8.1'}:{tool:'ppi-perl',version:'1.0.0'},contract=mutationBackendContract(root,source,backend);
 const generation={schema_version:1,kind:'mutation-backend-generation',qualification:'complete-backend-generation-no-outcomes',scope_complete:true,input_sha256:input,backend,...contract,
  execution:{command:[...image.Config.Entrypoint,'--backend',selectedBackend],runtime:{kind:'oci',image_id:runner.image}},
  inventory:proof.inventory,inventory_sha256:proof.inventory_sha256,source_materializations:proof.source_materializations.map(item=>({...item,artifacts:item.artifacts.map(copyRaw)})),raw_artifacts:[...artifacts.values()].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0)};
 const generationFile=path.join(output,'raw-generation.json');writeFileSync(generationFile,JSON.stringify(generation)+'\n',{flag:'wx'});const generationReceipt=record(generationFile);
 const authority=authorityFromGeneration(root,source,input,generationReceipt),authorityFile=path.join(output,'backend-discovery.json');writeFileSync(authorityFile,JSON.stringify(authority)+'\n',{flag:'wx'});const authorityReceipt=record(authorityFile);
 const validated=verifyMutationBackendDiscovery(root,authorityReceipt,source,input);
 insist(acceptanceInputHash(sourceReceipt(root))===input,'source changed during generation reconstruction');
 const result={schema_version:1,qualification:'unsigned-local-generation-proof; not-outcome-acceptance',backend,input_sha256:input,mutants:validated.inventory.length,sources:contract.sources.length,generation:generationReceipt,backend_discovery:authorityReceipt,production_inventory_signature_required:true};
 writeFileSync(path.join(output,'manifest.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});__removeMarker(output);return result;
}
import{unlinkSync as unlink}from'node:fs';function __removeMarker(output){unlink(path.join(output,'INCOMPLETE'));}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const args=process.argv.slice(2),options={};for(let index=0;index<args.length;index+=2){insist(['--root','--state','--output','--python','--backend'].includes(args[index])&&args[index+1],'invalid proof arguments');options[args[index].slice(2)]=args[index+1];}
 insist(['root','state','output'].every(key=>options[key])&&['python','perl'].includes(options.backend??'python'),'Usage: prove-generation.mjs --root SOURCE --state ACTUAL_RUN --output NEW_ARTIFACT_DIRECTORY [--backend python|perl] [--python PINNED_PYTHON]');
 const prove=options.backend==='perl'?provePerlGeneration:provePythonGeneration;
 console.log(JSON.stringify(prove(options.root,options.state,options.output,path.resolve(options.python??process.env.UD_RELEASE_PYTHON??'.venv/bin/python'))));
}
