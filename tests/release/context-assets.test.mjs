import {test}from'vitest';
import assert from'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync,symlinkSync}from'node:fs';
import os from'node:os';import path from'node:path';
import{copyContextAssets}from'../../scripts/release/context-assets.mjs';
import{sha256}from'../../scripts/release/candidate.mjs';

test('packages exact manifest-bound rules and repository assets and rejects tampering and escapes',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-context-package-')),destination=path.join(root,'output');
 try{
  const directory=path.join(root,'runtime/context');mkdirSync(path.join(directory,'rules'),{recursive:true});mkdirSync(path.join(directory,'docs/_en'),{recursive:true});
  const rules={};for(const name of['data.json','deprels.json','edeprels.json','feats.json','tospace.json','udeprels.json','upos.json']){const content=Buffer.from(name);rules[name]=sha256(content);writeFileSync(path.join(directory,'rules',name),content);}
  const asset=Buffer.from('English documentation\n');writeFileSync(path.join(directory,'docs/_en/index.md'),asset);
  const manifest={schema_version:1,context_sha256:sha256(JSON.stringify(rules)),rules,rule_dir:'rules',repository_checks:{assets:{'docs/_en/index.md':{sha256:sha256(asset),size_bytes:asset.length}}}};
  const write=()=>{const data=JSON.stringify(manifest);writeFileSync(path.join(directory,'context.json'),data);return{path:'runtime/context/context.json',sha256:'sha256:'+sha256(data),size_bytes:Buffer.byteLength(data)};};
  let descriptor=write();assert.equal(copyContextAssets(root,destination,descriptor).length,9);assert.deepEqual(readFileSync(path.join(destination,'runtime/context/docs/_en/index.md')),asset);
  writeFileSync(path.join(directory,'docs/_en/index.md'),'tampered');assert.throws(()=>copyContextAssets(root,destination,descriptor),/differs/);writeFileSync(path.join(directory,'docs/_en/index.md'),asset);
  manifest.rule_dir='../outside';descriptor=write();assert.throws(()=>copyContextAssets(root,destination,descriptor),/Unsafe relative/);manifest.rule_dir='rules';
  manifest.repository_checks.assets['../outside']={sha256:sha256(asset),size_bytes:asset.length};descriptor=write();assert.throws(()=>copyContextAssets(root,destination,descriptor),/Unsafe relative/);delete manifest.repository_checks.assets['../outside'];
  descriptor=write();rmSync(path.join(directory,'docs/_en/index.md'));symlinkSync(path.join(destination,'runtime/context/docs/_en/index.md'),path.join(directory,'docs/_en/index.md'));assert.throws(()=>copyContextAssets(root,destination,descriptor),/Symbolic link/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
