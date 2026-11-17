import {afterAll,beforeAll,expect,test} from 'vitest';
import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import {canonicalJson} from '../../scripts/release/http-transports.mjs';
import {discoverRustApplicability,evaluateRustCfg,parseRustCfgFacts} from '../../scripts/quality/rust-applicability.mjs';

const temporary=mkdtempSync(path.join(os.tmpdir(),'ud-rust-cfg-')),prefix='scripts/quality/rust-assertion-parser';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const parser=path.join(temporary,'target/debug/ud-rust-assertion-parser'+(process.platform==='win32'?'.exe':''));
const targets=['aarch64-apple-darwin','x86_64-apple-darwin','aarch64-unknown-linux-gnu','x86_64-unknown-linux-gnu','aarch64-pc-windows-msvc','x86_64-pc-windows-msvc'];
const windows=targets.slice(4),linux=targets.slice(2,4),mac=targets.slice(0,2);
const receipts=targets.flatMap(target=>['normal','test'].map(mode=>{
  const os=target.includes('apple')?'macos':target.includes('windows')?'windows':'linux';
  const stdout=(os==='windows'?'windows\n':'unix\n')+`target_os="${os}"\ntarget_arch="${target.startsWith('aarch64')?'aarch64':'x86_64'}"\n`+(mode==='test'?'test\n':'');
  return {target,mode,compiler_sha256:'c'.repeat(64),stdout,stdout_sha256:hash(stdout),generation_sha256:hash(target+'/'+mode)};
}));
const issued=new Set(receipts.map(canonicalJson));
beforeAll(()=>{
  const vendor=existsSync('/opt/mutation/rust/vendor')?'/opt/mutation/rust/vendor':path.join(process.cwd(),'.artifacts/mutation-rust-assets/export/vendor');
  const args=['build','--locked','--manifest-path','scripts/quality/rust-assertion-parser/Cargo.toml','--target-dir',path.join(temporary,'target')];
  if(existsSync(vendor))args.push('--offline','--config','source.crates-io.replace-with="verified-vendor"','--config','source.verified-vendor.directory='+JSON.stringify(vendor));
  const built=spawnSync('cargo',args,{encoding:'utf8',timeout:120000});expect(built.error,built.stderr).toBeUndefined();expect(built.status,built.stderr).toBe(0);
},120000);
afterAll(()=>rmSync(temporary,{recursive:true,force:true}));
const parseCfg=source=>{const parsed=spawnSync(parser,['--cfg-regions'],{input:source,encoding:'utf8',timeout:10000});if(parsed.error||parsed.status!==0)throw new Error(parsed.stderr||'original cfg parser failed');return JSON.parse(parsed.stdout);};
const options={parseCfg,verifyTargetCfg:receipt=>issued.has(canonicalJson(receipt))};
function fixture(action){
  const root=mkdtempSync(path.join(temporary,'source-'));
  const sources={
    'main.rs':'#[cfg(windows)] mod windows;\n#[cfg(target_os="macos")] mod mac;\nmod windows_policy;\n#[cfg_attr(windows,path="win_alt.rs")] mod platform;\nfn main(){}\n',
    'windows.rs':'pub fn native()->bool{true}\n',
    'mac.rs':'pub fn native()->bool{true}\n',
    'windows_policy.rs':'pub fn common()->bool{true}\n#[cfg(target_os="linux")] pub fn linux()->bool{true}\n#[cfg(windows)] pub fn guarded()->bool{true}\nfn runtime()->u8{if cfg!(windows){1}else{2}}\nfn dynamic(value:bool)->bool{if cfg!(windows)&&value{true}else{false}}\n',
    'platform.rs':'pub fn platform()->bool{true}\n',
    'win_alt.rs':'pub fn platform()->bool{true}\n',
  };
  for(const[name,value]of Object.entries(sources)){mkdirSync(path.join(root,prefix,'src'),{recursive:true});writeFileSync(path.join(root,prefix,'src',name),value);}
  function mutation(name,needle,replacement,occurrence=0){
    const file=prefix+'/src/'+name,source=readFileSync(path.join(root,file),'utf8');let index=-1;
    for(let i=0;i<=occurrence;i++)index=source.indexOf(needle,index+1);if(index<0)throw new Error('fixture needle absent');
    const before=source.slice(0,index).split('\n'),start={line:before.length,column:Buffer.byteLength(before.at(-1))+1};
    const end={line:start.line,column:start.column+Buffer.byteLength(needle)};
    const definition={tool:'cargo-mutants',version:'27.1.0',file,workspace_manifest:prefix+'/Cargo.toml',replacement,span:{start,end}};
    return {id:file+'#'+index,file,source_sha256:hash(source),definition,definition_sha256:hash(canonicalJson(definition))};
  }
  try{return action({root,mutation,sources});}finally{rmSync(root,{recursive:true,force:true});}
}
const discover=(root,items,targetReceipts=receipts,control=options)=>discoverRustApplicability(root,items,targetReceipts,control);

test('real AST follows platform module ancestry while common Windows policies remain locally applicable',()=>fixture(({root,mutation})=>{
  const items=[mutation('windows.rs','true','false'),mutation('mac.rs','true','false'),mutation('windows_policy.rs','true','false'),mutation('windows_policy.rs','true','false',1)];
  const result=discover(root,items);expect(result.inventory.map(row=>row.applicable_targets)).toEqual([windows,mac,targets,linux]);
  expect(result.inventory.map(row=>row.id)).toEqual(items.map(row=>row.id));expect(result.source_inventory).toHaveProperty(prefix+'/src/windows_policy.rs');
  expect(result.qualification).toBe('source-bound-target-applicability-not-mutation-outcomes');
}));
test('exact candidate guard evaluation prevents hiding a mutated cfg behind its original inactive branch',()=>fixture(({root,mutation})=>{
  const item=mutation('windows_policy.rs','windows','unix');const result=discover(root,[item]);
  expect(result.inventory[0].applicable_targets).toEqual(targets);
  expect(result.inventory[0].target_evidence).toEqual(expect.arrayContaining([expect.objectContaining({target:windows[0],variant:'original'}),expect.objectContaining({target:linux[0],variant:'candidate'})]));
}));
test('cfg_attr selects the actual source path per target without waiving other files',()=>fixture(({root,mutation})=>{
  expect(discover(root,[mutation('win_alt.rs','true','false')]).inventory[0].applicable_targets).toEqual(windows);
  expect(discover(root,[mutation('platform.rs','true','false')]).inventory[0].applicable_targets).toEqual(targets.slice(0,4));
}));
test('constant cfg macro branches and dynamic conjunctions retain exact target scope',()=>fixture(({root,mutation})=>{
  expect(discover(root,[mutation('windows_policy.rs','{1}','{9}')]).inventory[0].applicable_targets).toEqual(windows);
  expect(discover(root,[mutation('windows_policy.rs','{2}','{9}')]).inventory[0].applicable_targets).toEqual(targets.slice(0,4));
  expect(discover(root,[mutation('windows_policy.rs','true','false',3)]).inventory[0].applicable_targets).toEqual(windows);
}));
test('release and feature predicates cannot disguise locally untested branches as foreign-native pending',()=>fixture(({root,mutation})=>{
  for(const predicate of ['any(windows,not(debug_assertions))','any(windows,feature="x")','any(windows,panic="abort")','all(windows,target_feature="neon")']){
    writeFileSync(path.join(root,prefix,'src/windows_policy.rs'),`#[cfg(${predicate})]pub fn profile()->bool{true}\n`);
    const item=mutation('windows_policy.rs','true','false');
    expect(()=>discover(root,[item])).toThrow(/compiler profile/);
  }
  writeFileSync(path.join(root,prefix,'src/windows_policy.rs'),'#[cfg(windows)]pub fn profile()->bool{true}\n');
  // Candidate-only profile dependencies must be rejected as well.
  expect(()=>discover(root,[mutation('windows_policy.rs','windows','any(windows,not(debug_assertions))')])).toThrow(/compiler profile/);
  for(const source of ['#![cfg(any(windows,feature="x"))]\npub fn profile()->bool{true}\n','#[cfg_attr(feature="x",path="windows.rs")]mod selected;\npub fn profile()->bool{true}\n']){
    writeFileSync(path.join(root,prefix,'src/windows_policy.rs'),source);expect(()=>discover(root,[mutation('windows_policy.rs','true','false')])).toThrow(/compiler profile/);
  }
}));
test('every six-target normal/test profile requires independent exact compiler generation authority',()=>fixture(({root,mutation})=>{
  const item=mutation('windows.rs','true','false');
  for(const bad of [receipts.slice(1),[...receipts.slice(1),receipts[1]],receipts.map((r,i)=>i===0?{...r,stdout:r.stdout+'other\n'}:r)])expect(()=>discover(root,[item],bad)).toThrow(/target|compiler/i);
  expect(()=>discover(root,[item],receipts,{parseCfg})).toThrow(/authority/);
  expect(()=>discover(root,[item],receipts,{parseCfg,verifyTargetCfg:()=>false})).toThrow(/authority/);
  const forged=receipts.map((r,i)=>i===0?{...r,stdout:r.stdout.replace('macos','windows')}:r);forged[0].stdout_sha256=hash(forged[0].stdout);
  expect(()=>discover(root,[item],forged,{parseCfg,verifyTargetCfg:()=>true})).toThrow(/different OS/);
  const mixed=receipts.map((r,i)=>i===0?{...r,compiler_sha256:'d'.repeat(64)}:r);expect(()=>discover(root,[item],mixed,{parseCfg,verifyTargetCfg:()=>true})).toThrow(/splice/);
}));
test('definition/source changes, duplicate IDs, no-op edits and source orphans cannot be silently accepted',()=>fixture(({root,mutation})=>{
  const item=mutation('windows.rs','true','false');
  for(const bad of [{...item,source_sha256:'d'.repeat(64)},{...item,definition_sha256:'d'.repeat(64)}])expect(()=>discover(root,[bad])).toThrow(/binding/);
  expect(()=>discover(root,[item,item])).toThrow(/duplicate/);
  const unchanged=mutation('windows.rs','true','true');expect(()=>discover(root,[unchanged])).toThrow(/unchanged/);
  writeFileSync(path.join(root,prefix,'src/orphan.rs'),'fn orphan(){true;}\n');const orphan=mutation('orphan.rs','true','false');expect(()=>discover(root,[orphan])).toThrow(/orphaned/);
  writeFileSync(path.join(root,prefix,'src/windows.rs'),'#[cfg(any())] pub fn never()->bool{true}\n');const never=mutation('windows.rs','true','false');expect(()=>discover(root,[never])).toThrow(/unreachable/);
}));
test('unsupported predicates, ambiguous paths, cycles and workspace escapes fail closed',()=>fixture(({root,mutation})=>{
  const item=mutation('windows_policy.rs','true','false');
  expect(()=>discover(root,[item],receipts,{...options,parseCfg:source=>({...parseCfg(source),file_predicate:{kind:'xor'}})})).toThrow(/Unsupported/);
  writeFileSync(path.join(root,prefix,'src/main.rs'),'#[path="../../../../outside.rs"]mod bad;fn main(){}\n');expect(()=>discover(root,[item])).toThrow(/escapes/);
  writeFileSync(path.join(root,prefix,'src/main.rs'),'#[path="main.rs"]mod recursive;fn main(){}\n');expect(()=>discover(root,[item])).toThrow(/cycle/);
  writeFileSync(path.join(root,prefix,'src/main.rs'),'#[cfg_attr(unix,path="mac.rs")]#[cfg_attr(unix,path="windows_policy.rs")]mod platform;fn main(){}\n');expect(()=>discover(root,[item])).toThrow(/ambiguous/);
}));
test('strict cfg atom grammar and three-valued logic distinguish inactivity from runtime uncertainty',()=>{
  const atoms=parseRustCfgFacts('unix\ntarget_os="linux"\nfeature="a"\nfeature="b"\n');
  const flag=name=>({kind:'flag',name}),unknown={kind:'unknown'};
  for(const[predicate,expected]of [[{kind:'all',items:[]},true],[{kind:'any',items:[]},false],[{kind:'not',item:unknown},null],[{kind:'all',items:[flag('windows'),unknown]},false],[{kind:'any',items:[flag('unix'),unknown]},true],[{kind:'all',items:[flag('unix'),unknown]},null],[{kind:'value',name:'feature',value:'b'},true]])expect(evaluateRustCfg(predicate,atoms)).toBe(expected);
  for(const bad of ['','unix','unix\n\n','unix\nunix\n','unix\r\n','target_os=linux\n'])expect(()=>parseRustCfgFacts(bad)).toThrow();
  for(const bad of [{kind:'not',item:unknown,extra:true},{kind:'flag',name:{toString:null}},{kind:'all',items:{}},{kind:'xor',items:[]}])expect(()=>evaluateRustCfg(bad,atoms)).toThrow();
});
