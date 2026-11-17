/** Original compiler transcript fixtures only; no target or mutant is run. */
import {expect,test} from 'vitest';
import {createHash} from 'node:crypto';
import {canonicalJson} from '../../scripts/release/http-transports.mjs';
import {verifyRustCfgGeneration} from '../../scripts/quality/rust-applicability.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const targets=['aarch64-apple-darwin','x86_64-apple-darwin','aarch64-unknown-linux-gnu','x86_64-unknown-linux-gnu','aarch64-pc-windows-msvc','x86_64-pc-windows-msvc'];
const authority={compiler_sha256:'a'.repeat(64),sdk_receipt_sha256:'b'.repeat(64),source_tree_sha256:'c'.repeat(64)};
const bind=row=>{const {generation_sha256,...record}=row;return {...record,stdout_sha256:sha(record.stdout),generation_sha256:sha(canonicalJson({...record,stdout_sha256:sha(record.stdout)}))};};
function transcript(){return {schema_version:1,...authority,records:targets.flatMap(target=>['normal','test'].map(mode=>{
  const os=target.includes('apple')?'macos':target.includes('windows')?'windows':'linux';
  const stdout=`${os==='windows'?'windows':'unix'}\ntarget_os="${os}"\ntarget_arch="${target.startsWith('aarch64')?'aarch64':'x86_64'}"\ntarget_endian="little"\n`+(mode==='test'?'test\n':'');
  return bind({target,mode,command:['/opt/mutation/rust/bin/rustc','--print','cfg','--target',target,...(mode==='test'?['--test']:[])],status:0,stderr:'',stdout});
}))};}
const replay=value=>verifyRustCfgGeneration(value,authority);

test('complete issued twelve-profile cfg transcript replays to deterministic legacy-compatible receipts',()=>{
  const generation=transcript(),receipts=replay(generation);
  expect(receipts.map(row=>row.target+'/'+row.mode)).toEqual(targets.flatMap(target=>[target+'/normal',target+'/test']));
  expect(receipts[0]).toEqual({target:targets[0],mode:'normal',compiler_sha256:authority.compiler_sha256,stdout:generation.records[0].stdout,stdout_sha256:generation.records[0].stdout_sha256,generation_sha256:generation.records[0].generation_sha256});
  generation.records.reverse();expect(replay(generation)).toEqual(receipts);
});
test('missing duplicate foreign or extra target/profile rows never acquire source-bound authority',()=>{
  for(const change of [g=>g.records.pop(),g=>g.records[0]=g.records[1],g=>g.records.push(g.records[0]),g=>{g.records[0]=bind({...g.records[0],target:'aarch64-unknown-freebsd'});},g=>{g.records[0]=bind({...g.records[0],mode:'profile'});},g=>{g.extra=true;},g=>{g.records[0].extra=true;}]){
    const value=transcript();change(value);expect(()=>replay(value)).toThrow(/Rust cfg/);
  }
});
test('source SDK compiler and complete generation hashes require independent exact inputs',()=>{
  for(const name of Object.keys(authority)){
    const value=transcript();value[name]='d'.repeat(64);expect(()=>replay(value)).toThrow(/source\/SDK\/compiler/);
    expect(()=>verifyRustCfgGeneration(transcript(),{...authority,[name]:'not-a-hash'})).toThrow(/independently issued/);
  }
  const value=transcript();value.records[0].generation_sha256='d'.repeat(64);expect(()=>replay(value)).toThrow(/binding differs/);
  expect(()=>verifyRustCfgGeneration(transcript())).toThrow(/independently issued/);
});
test('every invocation uses only the fixed frozen compiler argv and clean terminal result',()=>{
  for(const command of [[],['rustc','--print','cfg','--target',targets[0]],['/evil/rustc','--print','cfg','--target',targets[0]],['/opt/mutation/rust/bin/rustc','--print','cfg','--target',targets[0],'--cfg','windows'],['/opt/mutation/rust/bin/rustc','--print','cfg','--target',targets[1]],['/opt/mutation/rust/bin/rustc','--print','cfg','--target',targets[0],'input.rs']]){
    const value=transcript();value.records[0]=bind({...value.records[0],command});expect(()=>replay(value)).toThrow(/command/);
  }
  for(const patch of [{status:1},{status:125},{status:null},{stderr:'warning'},{stdout:null}]){
    const value=transcript();Object.assign(value.records[0],patch);expect(()=>replay(value)).toThrow(/invalid, failed/);
  }
});
test('hash-correct target-spliced facts and malformed cfg syntax still fail closed',()=>{
  const original=transcript().records[0].stdout;
  for(const stdout of [original.replace('macos','windows'),original.replace('aarch64','x86_64'),original+'test\n',original.replace('unix\n','windows\n'),original+'windows\n',original.slice(0,-1),original+'unix\n',original+'invalid(foo)\n']){
    const value=transcript();value.records[0]=bind({...value.records[0],stdout});expect(()=>replay(value)).toThrow(/Rust (cfg|target)/);
  }
  const value=transcript();value.records[1]=bind({...value.records[1],stdout:value.records[1].stdout.replace('test\n','')});expect(()=>replay(value)).toThrow(/normal\/test profile/);
});
test('stdout content must match its recorded bytes before any semantic replay',()=>{
  const value=transcript();value.records[0].stdout+='feature="forged"\n';expect(()=>replay(value)).toThrow(/bytes/);
});
