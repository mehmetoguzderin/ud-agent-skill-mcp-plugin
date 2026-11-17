/** Source-bound Rust target applicability. No mutation is executed or omitted. */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { canonicalJson } from '../release/http-transports.mjs';
import { fileReceipt, safeRelative } from '../release/candidate.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const HASH = /^[0-9a-f]{64}$/;
const fingerprint = value => typeof value === 'string' && HASH.test(value);
const TARGETS = ['aarch64-apple-darwin','x86_64-apple-darwin','aarch64-unknown-linux-gnu','x86_64-unknown-linux-gnu','aarch64-pc-windows-msvc','x86_64-pc-windows-msvc'];
const WORKSPACES = new Map([
  ['Cargo.toml', { prefix:'packages/launcher', primary:['src/main.rs','src/fs_guard.rs'] }],
  ['scripts/quality/rust-assertion-parser/Cargo.toml', { prefix:'scripts/quality/rust-assertion-parser', primary:['src/main.rs'] }],
]);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());

/** Null means a runtime operand is unknown, never proof of inactivity. */
export function evaluateRustCfg(predicate, atoms, depth = 0) {
  if (!predicate || typeof predicate !== 'object' || depth > 128) throw new Error('Invalid or excessive Rust cfg predicate.');
  if (predicate.kind === 'flag' && exact(predicate,['kind','name']) && typeof predicate.name === 'string' && /^[_A-Za-z][_A-Za-z0-9]*$/.test(predicate.name)) return atoms.flags.has(predicate.name);
  if (predicate.kind === 'value' && exact(predicate,['kind','name','value']) && typeof predicate.name === 'string' && /^[_A-Za-z][_A-Za-z0-9]*$/.test(predicate.name) && typeof predicate.value === 'string') return atoms.values.get(predicate.name)?.has(predicate.value) ?? false;
  if (predicate.kind === 'unknown' && exact(predicate,['kind'])) return null;
  if (predicate.kind === 'not' && exact(predicate,['kind','item'])) { const value=evaluateRustCfg(predicate.item,atoms,depth+1); return value===null?null:!value; }
  if (['all','any'].includes(predicate.kind) && exact(predicate,['kind','items']) && Array.isArray(predicate.items) && predicate.items.length <= 1024) {
    const values=predicate.items.map(item=>evaluateRustCfg(item,atoms,depth+1));
    if(predicate.kind==='all') return values.includes(false)?false:values.includes(null)?null:true;
    return values.includes(true)?true:values.includes(null)?null:false;
  }
  throw new Error('Unsupported Rust cfg predicate grammar.');
}

export function parseRustCfgFacts(stdout) {
  if(typeof stdout!=='string'||!stdout.endsWith('\n')||Buffer.byteLength(stdout)>1024*1024)throw new Error('Rust target cfg output is missing or exceeds its bound.');
  const flags=new Set(),values=new Map(),seen=new Set();
  for(const line of stdout.slice(0,-1).split('\n')) {
    if(!line||line.includes('\r')||seen.has(line))throw new Error('Rust target cfg output contains an empty/duplicate/noncanonical atom.');seen.add(line);
    const match=/^([_A-Za-z][_A-Za-z0-9]*)(?:=("(?:[^"\\]|\\.)*"))?$/.exec(line);
    if(!match)throw new Error('Rust target cfg output contains unsupported syntax.');
    if(match[2]===undefined)flags.add(match[1]);else {
      const value=JSON.parse(match[2]);if(typeof value!=='string')throw new Error('Invalid Rust target cfg string.');
      if(!values.has(match[1]))values.set(match[1],new Set());values.get(match[1]).add(value);
    }
  }
  return {flags,values};
}

/** Replay only a root-issued immutable compiler transcript, never self-attest it. */
export function verifyRustCfgGeneration(generation,{compiler_sha256,sdk_receipt_sha256,source_tree_sha256}={}) {
  if(![compiler_sha256,sdk_receipt_sha256,source_tree_sha256].every(fingerprint))throw new Error('Rust cfg generation requires exact independently issued source/SDK/compiler hashes.');
  if(!exact(generation,['schema_version','source_tree_sha256','sdk_receipt_sha256','compiler_sha256','records'])||generation.schema_version!==1||generation.source_tree_sha256!==source_tree_sha256||generation.sdk_receipt_sha256!==sdk_receipt_sha256||generation.compiler_sha256!==compiler_sha256||!Array.isArray(generation.records)||generation.records.length!==TARGETS.length*2)throw new Error('Rust cfg generation source/SDK/compiler or complete target inventory differs.');
  const seen=new Set(),receipts=[];
  for(const row of generation.records){
    if(!exact(row,['target','mode','command','status','stderr','stdout','stdout_sha256','generation_sha256'])||!TARGETS.includes(row.target)||!['normal','test'].includes(row.mode)||row.status!==0||row.stderr!==''||typeof row.stdout!=='string'||!fingerprint(row.stdout_sha256)||!fingerprint(row.generation_sha256))throw new Error('Rust cfg generation has invalid, failed, or incomplete execution fields.');
    const key=row.target+'/'+row.mode,command=['/opt/mutation/rust/bin/rustc','--print','cfg','--target',row.target,...(row.mode==='test'?['--test']:[])];
    const {generation_sha256:recordHash,...record}=row;
    if(seen.has(key)||canonicalJson(row.command)!==canonicalJson(command)||row.stdout_sha256!==hash(row.stdout)||recordHash!==hash(canonicalJson(record)))throw new Error('Rust cfg generation command, bytes, identity, or unique target binding differs.');
    seen.add(key);const atoms=parseRustCfgFacts(row.stdout),os=row.target.includes('apple')?'macos':row.target.includes('windows')?'windows':'linux',arch=row.target.startsWith('aarch64')?'aarch64':'x86_64';
    if(atoms.values.get('target_os')?.size!==1||!atoms.values.get('target_os').has(os)||atoms.values.get('target_arch')?.size!==1||!atoms.values.get('target_arch').has(arch)||atoms.flags.has('test')!==(row.mode==='test')||atoms.flags.has('windows')!==(os==='windows')||atoms.flags.has('unix')!==(os!=='windows'))throw new Error('Rust cfg generation facts describe a different target or normal/test profile.');
    receipts.push({target:row.target,mode:row.mode,compiler_sha256,stdout:row.stdout,stdout_sha256:row.stdout_sha256,generation_sha256:recordHash});
  }
  // Fixed order makes the replay independent of incidental backend scheduling.
  return TARGETS.flatMap(target=>['normal','test'].map(mode=>receipts.find(row=>row.target===target&&row.mode===mode)));
}

function point(value){
  if(!exact(value,['line','column'])||!Number.isSafeInteger(value.line)||!Number.isSafeInteger(value.column)||value.line<1||value.column<1)throw new Error('Rust cfg source position is invalid.');return value;
}
const compare=(a,b)=>a.line-b.line||a.column-b.column;
function span(value){if(!exact(value,['start','end']))throw new Error('Rust cfg source span is invalid.');point(value.start);point(value.end);if(compare(value.start,value.end)>=0)throw new Error('Rust cfg region has an empty/reversed source span.');return value;}
function position(bytes,point_){point(point_);const lines=bytes.toString('utf8').split(/(?<=\n)/);if(point_.line>lines.length||point_.column>Buffer.byteLength(lines[point_.line-1])+1)throw new Error('Rust definition exceeds its source.');return lines.slice(0,point_.line-1).reduce((sum,line)=>sum+Buffer.byteLength(line),0)+point_.column-1;}
function candidate(original,item){
  if(item.source_sha256!==hash(original)||!item.definition||item.definition.file!==item.file||typeof item.definition.replacement!=='string'||hash(canonicalJson(item.definition))!==item.definition_sha256)throw new Error('Rust applicability definition/source binding is stale.');
  const definition=span(item.definition.span),start=position(original,definition.start),end=position(original,definition.end);
  new TextDecoder('utf-8',{fatal:true}).decode(original.subarray(start,end));
  const replacement=Buffer.from(item.definition.replacement),bytes=Buffer.concat([original.subarray(0,start),replacement,original.subarray(end)]);
  new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  if(bytes.equals(original))throw new Error('Rust applicability cannot accept an unchanged mutation.');
  return bytes;
}
function targetOnly(predicate){
  // This backend compiles default debug and default debug tests. It cannot
  // certify release-only or custom-feature paths merely by changing OS facts.
  if(predicate.kind==='flag'&&!['unix','windows','test'].includes(predicate.name)||predicate.kind==='value'&&(!predicate.name.startsWith('target_')||predicate.name==='target_feature'))throw new Error('Rust cfg source depends on a release, feature, or unsupported compiler profile; native-target pending is not authority for that branch.');
  if(predicate.kind==='not')targetOnly(predicate.item);
  if(['all','any'].includes(predicate.kind))for(const child of predicate.items)targetOnly(child);
}
function syntax(value,atoms){
  if(!exact(value,['schema_version','file_predicate','regions','external_modules'])||value.schema_version!==1||!Array.isArray(value.regions)||!Array.isArray(value.external_modules)||value.regions.length>100000||value.external_modules.length>10000)throw new Error('Rust cfg parser returned an incomplete inventory.');
  evaluateRustCfg(value.file_predicate,atoms);targetOnly(value.file_predicate);
  for(const region of value.regions){if(!exact(region,['span','predicate']))throw new Error('Rust cfg region fields are invalid.');span(region.span);evaluateRustCfg(region.predicate,atoms);targetOnly(region.predicate);}
  for(const module of value.external_modules){
    if(!exact(module,['modules','path','path_overrides','predicate'])||!Array.isArray(module.modules)||!module.modules.length||module.modules.some(name=>typeof name!=='string'||!/^[_\p{ID_Start}][_\p{ID_Continue}]*$/u.test(name))||!(module.path===null||typeof module.path==='string')||!Array.isArray(module.path_overrides))throw new Error('Rust external module cfg binding is invalid.');
    evaluateRustCfg(module.predicate,atoms);targetOnly(module.predicate);
    for(const override of module.path_overrides){if(!exact(override,['predicate','path'])||typeof override.path!=='string')throw new Error('Rust cfg_attr module path is invalid.');evaluateRustCfg(override.predicate,atoms);targetOnly(override.predicate);}
  }
  return value;
}
function roots(root,workspace){
  const tests=path.join(root,workspace.prefix,'tests');
  return [...workspace.primary.map(name=>workspace.prefix+'/'+name),...(existsSync(tests)?readdirSync(tests).filter(name=>/^[A-Za-z0-9_-]+\.rs$/.test(name)).map(name=>workspace.prefix+'/tests/'+name):[])];
}
function modulePath(root,file,module,atoms,workspace,crateRoot){
  const chosen=module.path_overrides.filter(value=>evaluateRustCfg(value.predicate,atoms)!==false);
  if(chosen.length>1||chosen.some(value=>evaluateRustCfg(value.predicate,atoms)===null))throw new Error('Rust cfg_attr module path is ambiguous for this target.');
  const override=chosen[0]?.path??module.path;
  const base=crateRoot||path.posix.basename(file)==='mod.rs'?path.posix.dirname(file):file.slice(0,-3);
  const parents=module.modules.slice(0,-1),name=module.modules.at(-1);
  let choices;
  if(override!==null){if(override.includes('\\')||override.includes(':')||override.startsWith('/')||override.includes('\0'))throw new Error('Rust module path is not a confined relative source.');choices=[path.posix.normalize(path.posix.join(parents.length?base:path.posix.dirname(file),...parents,override))];}
  else choices=[path.posix.join(base,...parents,name+'.rs'),path.posix.join(base,...parents,name,'mod.rs')].filter(name=>existsSync(path.join(root,name)));
  if(choices.length!==1||!choices[0].startsWith(workspace.prefix+'/')||!choices[0].endsWith('.rs'))throw new Error('Rust module path escapes its workspace or is missing/ambiguous.');
  safeRelative(choices[0]);return choices[0];
}

/**
 * verifyTargetCfg is mandatory independent authority: the actual protected
 * backend verifies each receipt against its issued immutable compiler and
 * generation transcript. Self-hashes or caller lists are not authority.
 * Targets contain both normal and test --print cfg executions for all six OS/
 * architecture pairs. Returned rows preserve every input definition exactly.
 */
export function discoverRustApplicability(root,inventory,targetReceipts,{parseCfg,verifyTargetCfg}={}){
  if(typeof parseCfg!=='function'||typeof verifyTargetCfg!=='function')throw new Error('Rust applicability requires independently verified parser/compiler authority.');
  if(!Array.isArray(inventory)||!inventory.length||!Array.isArray(targetReceipts)||targetReceipts.length!==TARGETS.length*2)throw new Error('Rust applicability requires the complete definition and target-profile inventories.');
  const targetKeys=new Set(),targets=targetReceipts.map(receipt=>{
    if(!exact(receipt,['target','mode','compiler_sha256','stdout','stdout_sha256','generation_sha256'])||!TARGETS.includes(receipt.target)||!['normal','test'].includes(receipt.mode)||!fingerprint(receipt.compiler_sha256)||!fingerprint(receipt.stdout_sha256)||!fingerprint(receipt.generation_sha256)||typeof receipt.stdout!=='string'||receipt.stdout_sha256!==hash(receipt.stdout)||verifyTargetCfg(receipt)!==true||targetKeys.has(receipt.target+'/'+receipt.mode))throw new Error('Rust compiler target receipt is missing, duplicate, stale, or lacks independent authority.');
    targetKeys.add(receipt.target+'/'+receipt.mode);const atoms=parseRustCfgFacts(receipt.stdout);
    if(atoms.values.get('target_os')?.size!==1||atoms.values.get('target_arch')?.size!==1||atoms.flags.has('test')!==(receipt.mode==='test'))throw new Error('Rust compiler receipt does not describe its declared normal/test target profile.');
    const os=receipt.target.includes('apple')?'macos':receipt.target.includes('windows')?'windows':'linux',arch=receipt.target.startsWith('aarch64')?'aarch64':'x86_64';
    if(!atoms.values.get('target_os').has(os)||!atoms.values.get('target_arch').has(arch))throw new Error('Rust compiler cfg facts describe a different OS/architecture.');
    return {receipt,atoms};
  });
  if(new Set(targetReceipts.map(value=>value.compiler_sha256)).size!==1)throw new Error('Rust target receipts splice different compiler identities.');
  const sources={},originals=new Map(),parsed=new Map(),ids=new Set();
  function bytes(file){safeRelative(file);if(!originals.has(file)){const receipt=fileReceipt(root,file),value=readFileSync(path.join(root,file));if(value.length>16*1024*1024||hash(value)!==receipt.sha256)throw new Error('Rust cfg source changed while reading.');sources[file]=receipt.sha256;originals.set(file,value);}return originals.get(file);}
  const rows=[];
  for(const item of inventory){
    if(!item||typeof item.id!=='string'||!item.id||ids.has(item.id)||typeof item.file!=='string'||!fingerprint(item.source_sha256)||!fingerprint(item.definition_sha256))throw new Error('Rust applicability inventory has missing or duplicate definition identities.');ids.add(item.id);
    const workspace=WORKSPACES.get(item.definition?.workspace_manifest);if(!workspace||!item.file.startsWith(workspace.prefix+'/')||!item.file.endsWith('.rs'))throw new Error('Rust mutation has no supported source-bound workspace.');
    const original=bytes(item.file),changed=candidate(original,item),location=point(item.definition.span.start),applicable=new Set(),evidence=[];
    for(const {receipt,atoms} of targets){
      for(const variant of ['original','candidate']){
        const visiting=new Set();let reachable=false;
        const load=(file,crateRoot=false)=>{
          if(visiting.has(file))throw new Error('Rust cfg module graph contains a cycle.');visiting.add(file);
          const content=variant==='candidate'&&file===item.file?changed:bytes(file),key=file+':'+hash(content);
          if(!parsed.has(key))parsed.set(key,parseCfg(content));const ast=syntax(parsed.get(key),atoms);
          if(evaluateRustCfg(ast.file_predicate,atoms)!==false){
            if(file===item.file&&ast.regions.filter(region=>compare(region.span.start,location)<=0&&compare(location,region.span.end)<0).every(region=>evaluateRustCfg(region.predicate,atoms)!==false))reachable=true;
            for(const module of ast.external_modules)if(evaluateRustCfg(module.predicate,atoms)!==false)load(modulePath(root,file,module,atoms,workspace,crateRoot));
          }
          visiting.delete(file);
        };
        for(const artifact of roots(root,workspace))load(artifact,true);
        if(reachable){applicable.add(receipt.target);evidence.push({target:receipt.target,mode:receipt.mode,variant});}
      }
    }
    if(!applicable.size)throw new Error('Rust mutation is unreachable on all supported targets; unsupported/orphaned code cannot be silently waived.');
    rows.push({id:item.id,file:item.file,source_sha256:item.source_sha256,candidate_sha256:hash(changed),definition_sha256:item.definition_sha256,applicable_targets:TARGETS.filter(target=>applicable.has(target)),target_evidence:evidence});
  }
  const lexical=(left,right)=>left<right?-1:left>right?1:0;
  const region_materializations=[...parsed].map(([key,value])=>{const index=key.lastIndexOf(':');return {file:key.slice(0,index),source_sha256:key.slice(index+1),inventory_sha256:hash(canonicalJson(value))};}).sort((a,b)=>lexical(a.file,b.file)||lexical(a.source_sha256,b.source_sha256));
  return {schema_version:1,qualification:'source-bound-target-applicability-not-mutation-outcomes',source_inventory:Object.fromEntries(Object.entries(sources).sort()),region_materializations,parser_receipt:parseCfg.receipt??null,target_receipts:targetReceipts.map(({stdout,...receipt})=>receipt),inventory:rows};
}
