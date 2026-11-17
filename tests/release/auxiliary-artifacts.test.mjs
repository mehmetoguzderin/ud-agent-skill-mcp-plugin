import{test}from'vitest';import assert from'node:assert/strict';import{mkdtempSync,mkdirSync,writeFileSync,rmSync}from'node:fs';import os from'node:os';import path from'node:path';
import{auxiliaryArtifacts}from'../../scripts/release/auxiliary-artifacts.mjs';import{sha256}from'../../scripts/release/candidate.mjs';
test('requires and verifies each lazy render release asset without substituting another platform',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-auxiliary-'));
 try{const data=Buffer.from('verified offline archive'),item={url:'https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-render-darwin-arm64.tar.gz',sha256:'sha256:'+sha256(data),size:data.length};const manifest={platforms:{'darwin/arm64':{lazy_render:item}}};
 assert.deepEqual(auxiliaryArtifacts(root,undefined),[]);assert.throws(()=>auxiliaryArtifacts(root,manifest),/missing/);
 mkdirSync(path.join(root,'runtime'));mkdirSync(path.join(root,'assets'));const record={id:'render-assets-darwin-arm64',platform:'darwin-arm64',path:'assets/ud-agent-render-darwin-arm64.tar.gz',url:item.url,sha256:item.sha256,size_bytes:data.length};writeFileSync(path.join(root,record.path),data);const file=path.join(root,'runtime/auxiliary-artifacts.json');writeFileSync(file,JSON.stringify({schema_version:1,assets:[record]}));assert.deepEqual(auxiliaryArtifacts(root,manifest),[record]);writeFileSync(path.join(root,record.path),'corrupt');assert.throws(()=>auxiliaryArtifacts(root,manifest),/bytes/);writeFileSync(path.join(root,record.path),data);writeFileSync(file,JSON.stringify({schema_version:1,assets:[record,record]}));assert.throws(()=>auxiliaryArtifacts(root,manifest),/incomplete/);writeFileSync(file,JSON.stringify({schema_version:1,assets:[{...record,platform:'linux-arm64'}]}));assert.throws(()=>auxiliaryArtifacts(root,manifest),/identity/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('binds core and provider archives independently and refuses substituted bytes or missing rows',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-auxiliary-mixed-'));
 try{
  mkdirSync(path.join(root,'runtime'));mkdirSync(path.join(root,'assets'));
  const names=[['userspace-core-darwin-arm64','darwin-arm64','ud-agent-userspace-darwin-arm64.tar.gz'],['provider-assets-wslc-win32-x64','wslc-win32-x64','ud-agent-provider-wslc-win32-x64.tar.gz']];
  const records=names.map(([id,platform,filename],index)=>{const bytes=Buffer.from(`independent transport ${index}`),url=`https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/${filename}`,record={id,platform,path:'assets/'+filename,url,sha256:'sha256:'+sha256(bytes),size_bytes:bytes.length};writeFileSync(path.join(root,record.path),bytes);return record;});
  const manifest={platforms:{'darwin/arm64':{lazy_core:{url:records[0].url,sha256:records[0].sha256,size:records[0].size_bytes}}}},runtime={provider_receipts:{'wslc/win32/x64':{lazy_assets:{url:records[1].url,sha256:records[1].sha256,size:records[1].size_bytes,files:[]}}}};
  const inventory=path.join(root,'runtime/auxiliary-artifacts.json');writeFileSync(inventory,JSON.stringify({schema_version:1,assets:records}));assert.deepEqual(auxiliaryArtifacts(root,manifest,runtime),records);
  rmSync(path.join(root,records[1].path));assert.deepEqual(auxiliaryArtifacts(root,manifest,runtime,{targets:['darwin-arm64']}),[records[0]]);assert.throws(()=>auxiliaryArtifacts(root,manifest,runtime));assert.throws(()=>auxiliaryArtifacts(root,manifest,runtime,{targets:['win32-x64']}));
  writeFileSync(path.join(root,records[1].path),Buffer.from('independent transport 1'));
  writeFileSync(inventory,JSON.stringify({schema_version:1,assets:[records[0]]}));assert.throws(()=>auxiliaryArtifacts(root,manifest,runtime),/incomplete/);
  writeFileSync(inventory,JSON.stringify({schema_version:1,assets:[records[0],{...records[1],sha256:records[0].sha256}]}));assert.throws(()=>auxiliaryArtifacts(root,manifest,runtime),/identity/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
