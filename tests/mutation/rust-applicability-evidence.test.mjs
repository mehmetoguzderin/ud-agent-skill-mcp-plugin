import { expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { replayRustApplicability, verifyRustApplicabilityEvidence } from '../../scripts/quality/rust-applicability-cli.mjs';
const hash=value=>createHash('sha256').update(value).digest('hex');
const targets=['aarch64-apple-darwin','x86_64-apple-darwin','aarch64-unknown-linux-gnu','x86_64-unknown-linux-gnu','aarch64-pc-windows-msvc','x86_64-pc-windows-msvc'];
test('unadmitted CLI and unknown arguments reject before reading any SDK or candidate',()=>{
  const result=spawnSync(process.execPath,['scripts/quality/rust-applicability-cli.mjs','--unknown'],{input:'{}',encoding:'utf8',timeout:10000,env:{PATH:process.env.PATH}});
  expect(result.error).toBeUndefined();expect(result.status).toBe(1);expect(result.stdout).toBe('');expect(result.stderr).toContain('requires its trusted OCI coordinator');
});
function fixture(run) {
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-cfg-evidence-'));
  try {
    const name='scripts/quality/rust-assertion-parser/src/main.rs',source='fn main(){true;}\n';mkdirSync(path.dirname(path.join(root,name)),{recursive:true});writeFileSync(path.join(root,name),source);
    const definition={tool:'cargo-mutants',version:'27.1.0',file:name,workspace_manifest:'scripts/quality/rust-assertion-parser/Cargo.toml',replacement:'false',span:{start:{line:1,column:11},end:{line:1,column:15}}};
    const item={id:'original-bool',file:name,source_sha256:hash(source),definition,definition_sha256:hash(canonicalJson(definition))};
    const source_inventory=Object.fromEntries(['Cargo.toml','Cargo.lock','src/main.rs','src/cfg_regions.rs'].map(file=>['scripts/quality/rust-assertion-parser/'+file,'d'.repeat(64)]));
    const sdk={qualification:'development-mutation-toolchain',platform:'linux/arm64',assertion_parser:{schema_version:1,source_inventory},files:[{path:'bin/rustc',sha256:'a'.repeat(64)},{path:'bin/ud-rust-assertion-parser',sha256:'b'.repeat(64)}]};
    const sdkBytes=Buffer.from(JSON.stringify(sdk)),authority={compiler_sha256:'a'.repeat(64),sdk_receipt_sha256:hash(sdkBytes),source_tree_sha256:'c'.repeat(64)};
    const generation={schema_version:1,...authority,records:targets.flatMap(target=>['normal','test'].map(mode=>{
      const target_os=target.includes('windows')?'windows':target.includes('apple')?'macos':'linux';
      const stdout=`${target_os==='windows'?'windows':'unix'}\ntarget_os="${target_os}"\ntarget_arch="${target.startsWith('aarch64')?'aarch64':'x86_64'}"\n`+(mode==='test'?'test\n':'');
      const row={target,mode,command:['/opt/mutation/rust/bin/rustc','--print','cfg','--target',target,...(mode==='test'?['--test']:[])],status:0,stderr:'',stdout,stdout_sha256:hash(stdout)};
      return {...row,generation_sha256:hash(canonicalJson(row))};
    }))};
    // The AST for this fixed literal fixture has no attributes or modules.
    const parseCfg=()=>({schema_version:1,file_predicate:{kind:'all',items:[]},regions:[],external_modules:[]});
    parseCfg.receipt={source_inventory,qualification:'unmutated-native-AST-parser-only'};
    const proof=replayRustApplicability(root,[item],generation,authority,parseCfg);
    proof.parser_receipt={executable_sha256:'b'.repeat(64),source_inventory,qualification:'immutable-SDK-AST-parser-only',parser_mode:'cfg-regions'};
    const generationBytes=Buffer.from(JSON.stringify(generation)),proofBytes=Buffer.from(JSON.stringify(proof));
    const schedule={source_tree_sha256:'c'.repeat(64),current_target:'aarch64-unknown-linux-gnu',inventory:[item],applicability:{path:'applicability.json',sha256:hash(proofBytes),generation_path:'target-cfg-generation.json',generation_sha256:hash(generationBytes),sdk_receipt_path:'rust-sdk-receipt.json',sdk_receipt_sha256:hash(sdkBytes)}};
    const input={root,schedule,runtime:{rust:{sha256:hash(sdkBytes),size_bytes:sdkBytes.length}},sdkBytes,generationBytes,proofBytes,source_sha256:'c'.repeat(64),parseCfg};
    run({input,proof,verify:()=>verifyRustApplicabilityEvidence(input)});
  } finally {rmSync(root,{recursive:true,force:true});}
}
test('host reconciliation replays the complete source/candidate target union against the original parser',()=>fixture(({verify})=>{
  const result=verify();expect(result.current_target).toBe('aarch64-unknown-linux-gnu');expect(result.proof.inventory).toHaveLength(1);expect(result.proof.inventory[0].applicable_targets).toEqual(targets);
}));
test('self-consistent tampering with target union or candidate bytes still fails independent replay',()=>fixture(({input,proof,verify})=>{
  for(const change of [row=>row.applicable_targets=['aarch64-pc-windows-msvc'],row=>row.candidate_sha256='f'.repeat(64),row=>row.target_evidence.pop()]) {
    const changed=structuredClone(proof);change(changed.inventory[0]);input.proofBytes=Buffer.from(JSON.stringify(changed));input.schedule.applicability.sha256=hash(input.proofBytes);
    expect(verify).toThrow(/does not replay/);
  }
}));
test('source SDK generation parser identity and exact evidence files cannot be substituted',()=>fixture(({input,proof,verify})=>{
  const original=structuredClone(input.schedule.applicability);
  for(const field of ['sha256','generation_sha256','sdk_receipt_sha256']) {input.schedule.applicability={...original,[field]:'f'.repeat(64)};expect(verify).toThrow(/does not bind/);}
  input.schedule.applicability=original;input.runtime.rust.size_bytes++;expect(verify).toThrow(/does not bind/);input.runtime.rust.size_bytes--;
  const changed=structuredClone(proof);changed.parser_receipt.executable_sha256='f'.repeat(64);input.proofBytes=Buffer.from(JSON.stringify(changed));input.schedule.applicability.sha256=hash(input.proofBytes);expect(verify).toThrow(/parser differs/);
}));
