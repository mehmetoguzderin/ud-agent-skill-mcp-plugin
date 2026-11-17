/** Generate and bind the complete official Stryker inventory before outcomes. */
import{existsSync,lstatSync,mkdirSync,readFileSync,writeFileSync}from'node:fs';
import path from'node:path';import{fileURLToPath}from'node:url';
import{createHash}from'node:crypto';
import{discoverStryker}from'./discover-stryker.mjs';
import{fileReceipt,safeRelative,sourceReceipt}from'../release/candidate.mjs';
import{acceptanceInputHash}from'../release/discover-acceptance.mjs';
import{canonicalJson}from'../release/http-transports.mjs';
import{mutationBackendContract,authorityFromGeneration,verifyMutationBackendDiscovery}from'../release/mutation-backends.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const demand=(value,message)=>{if(!value)throw Error('Stryker generation proof: '+message);};
const sorted=rows=>[...rows].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
const project=({id,file,source_sha256,definition_sha256})=>({id,file,source_sha256,definition_sha256});

export function reconcileStrykerGeneration(raw,source,contract){
 demand(raw?.qualification==='complete-operator-discovery-no-outcomes'&&raw.inventory_only===true&&raw.tool==='stryker'&&raw.tool_version==='10.1.1'&&raw.source_tree_sha256===source.sha256,'actual official full discovery identity differs');
 demand(JSON.stringify(raw.options)===JSON.stringify({excludedMutations:[],ignorers:[]}),'mutation operators were filtered');
 const scope=contract.sources.map(item=>({path:item.path,source_sha256:item.sha256}));
 demand(canonicalJson(raw.source_scope)===canonicalJson(scope),'source scope omitted a current applicable source');
 demand(Array.isArray(raw.mutants)&&raw.mutants.length===raw.scheduled&&raw.scheduled>0&&Array.isArray(raw.materialization)&&raw.materialization.length===scope.length,'discovery counts or per-source generation are incomplete');
 const files=new Map(scope.map(item=>[item.path,item.source_sha256])),ids=new Set(),aliases=new Set(),globalAliases=new Set(),groups=new Map();
 for(const item of raw.mutants){
  demand(item&&typeof item.file==='string'&&typeof item.raw_id==='string','source or raw alias is absent');
  const alias=item.raw_id?.slice(item.file.length+1);
  demand(files.get(item.file)===item.source_sha256&&item.id===item.file+'#'+item.definition_sha256&&item.raw_id?.startsWith(item.file+'#')&&/^[0-9]+$/.test(alias??'')&&!ids.has(item.id)&&!aliases.has(item.raw_id)&&!globalAliases.has(alias)&&sha(canonicalJson(item.definition))===item.definition_sha256,'source, canonical definition, or unique raw alias differs');
  ids.add(item.id);aliases.add(item.raw_id);globalAliases.add(alias);const rows=groups.get(item.file)??[];rows.push(item);groups.set(item.file,rows);
 }
 const materialized=new Set();
 for(const item of raw.materialization){
  const rows=(groups.get(item.path)??[]).map(({id,raw_id,source_sha256,definition_sha256})=>({id,raw_id,source_sha256,definition_sha256}));
  demand(files.get(item.path)===item.source_sha256&&!materialized.has(item.path)&&item.generated===rows.length&&item.inventory_sha256===sha(canonicalJson(rows)),'per-source generated definitions are incomplete or changed');materialized.add(item.path);
 }
 return sorted(raw.mutants.map(project));
}

export async function proveStrykerGeneration(root,output){
 root=path.resolve(root);output=path.resolve(output);const relative=path.relative(root,output).split(path.sep).join('/');safeRelative(relative);
 demand(relative.startsWith('.artifacts/')&&!existsSync(output),'new owned artifact directory required');
 const source=sourceReceipt(root),input=acceptanceInputHash(source),backend={tool:'stryker',version:'10.1.1'},contract=mutationBackendContract(root,source,backend);
 const raw=await discoverStryker(root),inventory=reconcileStrykerGeneration(raw,source,contract);
 demand(raw.runtime.executable_sha256===sha(readFileSync(process.execPath))&&raw.runtime.node_version===process.version&&raw.runtime.package_lock_sha256===fileReceipt(root,'package-lock.json').sha256,'actual generator runtime differs');
 let parent=root;for(const part of relative.split('/').slice(0,-1)){parent=path.join(parent,part);if(!existsSync(parent))mkdirSync(parent,{mode:0o700});const info=lstatSync(parent);demand(info.isDirectory()&&!info.isSymbolicLink(),'ordinary artifact parent required');}
 mkdirSync(output,{mode:0o700});const artifacts=[];
 function save(name,value){const file=path.join(output,name);mkdirSync(path.dirname(file),{recursive:true});writeFileSync(file,JSON.stringify(value)+'\n',{flag:'wx'});const receipt=fileReceipt(root,path.relative(root,file).split(path.sep).join('/'));artifacts.push(receipt);return receipt;}
 const runtime=save('runtime.json',raw.runtime),discovery=save('actual-discovery.json',raw);
 const source_materializations=contract.sources.map(item=>({source:item.path,source_sha256:item.sha256,mutant_ids:inventory.filter(row=>row.file===item.path).map(row=>row.id),artifacts:[discovery,save('sources/'+item.path+'.json',{schema_version:1,source:item.path,source_sha256:item.sha256,generated:raw.materialization.find(row=>row.path===item.path),definitions:raw.mutants.filter(row=>row.file===item.path)})]}));
 const generation={schema_version:1,kind:'mutation-backend-generation',qualification:'complete-backend-generation-no-outcomes',scope_complete:true,input_sha256:input,backend,...contract,
  execution:{command:[process.execPath,'scripts/quality/prove-stryker-generation.mjs','--output',relative],runtime:{kind:'native',executable_sha256:raw.runtime.executable_sha256,version_receipt:runtime}},inventory,inventory_sha256:sha(canonicalJson(inventory)),source_materializations,raw_artifacts:[...artifacts]};
 const generationReceipt=save('raw-generation.json',generation),authority=authorityFromGeneration(root,source,input,generationReceipt),authorityReceipt=save('backend-discovery.json',authority);
 const verified=verifyMutationBackendDiscovery(root,authorityReceipt,source,input);
 demand(acceptanceInputHash(sourceReceipt(root))===input,'source changed during generation');
 const result={schema_version:1,qualification:'unsigned-local-generation-proof; not-outcome-acceptance',backend,input_sha256:input,mutants:verified.inventory.length,sources:contract.sources.length,generation:generationReceipt,backend_discovery:authorityReceipt,production_inventory_signature_required:true};
 save('manifest.json',result);return result;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const args=process.argv.slice(2);demand(args.length===2&&args[0]==='--output','Usage: prove-stryker-generation.mjs --output NEW_ARTIFACT_DIRECTORY');
 console.log(JSON.stringify(await proveStrykerGeneration(process.cwd(),args[1])));
}
