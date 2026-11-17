/** Copy only context bytes independently bound by the immutable manifest. */
import { chmodSync, copyFileSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, readRecordedBytes, safeRelative, sha256 } from './candidate.mjs';

export function copyContextAssets(root,destination,descriptor) {
  const insist=(value,message)=>{if(!value)throw new Error(`Context package: ${message}`);};
  insist(descriptor&&/^sha256:[a-f0-9]{64}$/.test(descriptor.sha256??''),'invalid manifest descriptor');
  const manifestBytes=readRecordedBytes(root,{path:descriptor.path,sha256:descriptor.sha256.slice(7),size:descriptor.size_bytes},8*1024*1024);
  const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(manifestBytes)), directory=path.posix.dirname(descriptor.path);
  insist(manifest.schema_version===1&&manifest.rules&&typeof manifest.rules==='object'&&!Array.isArray(manifest.rules),'invalid rule inventory');
  safeRelative(manifest.rule_dir);
  const files=new Map();let total=0;
  const add=(relative,hash,size)=>{
    safeRelative(relative);const full=path.posix.join(directory,relative);safeRelative(full);
    const actual=fileReceipt(root,full);
    insist(actual.sha256===hash&&(size===undefined||actual.size===size),'rule or repository asset differs from its manifest');
    if(files.has(full)){insist(files.get(full).sha256===hash,'conflicting context inventories');return;}
    total+=actual.size;insist(total<=128*1024*1024&&files.size<10000,'context asset inventory exceeds its bounds');files.set(full,actual);
  };
  const rules=Object.fromEntries(Object.entries(manifest.rules).sort(([a],[b])=>a<b?-1:a>b?1:0));
  insist(JSON.stringify(Object.keys(rules))===JSON.stringify(['data.json','deprels.json','edeprels.json','feats.json','tospace.json','udeprels.json','upos.json'])&&Object.values(rules).every(value=>/^[a-f0-9]{64}$/.test(value)),'incomplete rule identities');
  insist(sha256(Buffer.from(JSON.stringify(rules)))===manifest.context_sha256,'rule context identity mismatch');
  for(const [name,hash]of Object.entries(rules)){safeRelative(name);add(path.posix.join(manifest.rule_dir,name),hash);}
  const assets=manifest.repository_checks?.assets??{};
  insist(assets&&typeof assets==='object'&&!Array.isArray(assets),'invalid repository asset inventory');
  for(const [name,item]of Object.entries(assets)){
    insist(item&&/^[a-f0-9]{64}$/.test(item.sha256??'')&&Number.isSafeInteger(item.size_bytes)&&item.size_bytes>=0,'invalid repository asset descriptor');
    add(name,item.sha256,item.size_bytes);
  }
  files.set(descriptor.path,{path:descriptor.path,sha256:descriptor.sha256.slice(7),size:descriptor.size_bytes,executable:false});
  for(const item of files.values()){
    const target=path.join(destination,...item.path.split('/'));mkdirSync(path.dirname(target),{recursive:true});
    copyFileSync(path.join(root,...item.path.split('/')),target);chmodSync(target,0o644);
  }
  return [...files.values()];
}
