/** Verify lazy dependency archives that must accompany the published coordinator. */
import {existsSync,readFileSync}from'node:fs';import path from'node:path';
import{fileReceipt,safeRelative}from'./candidate.mjs';
/** @param {{targets?:string[]}} [options] */
export function auxiliaryArtifacts(root,userspace,runtime,options={}){
 const {targets}=options;
 const file=path.join(root,'runtime/auxiliary-artifacts.json');
 const selected=targets===undefined?undefined:new Set(targets);
 if(selected&&(!Array.isArray(targets)||!targets.length||selected.size!==targets.length||targets.some(value=>!['darwin-arm64','darwin-x64','linux-arm64','linux-x64','win32-arm64','win32-x64'].includes(value))))throw new Error('Available auxiliary targets are invalid.');
 const expected=new Map();
 for(const[host,item]of Object.entries(userspace?.platforms??{}))for(const[key,prefix,filename]of[['lazy_render','render-assets','ud-agent-render'],['lazy_core','userspace-core','ud-agent-userspace']])if(item[key]){const slug=host.replace('/','-'),id=`${prefix}-${slug}`;expected.set(id,{contract:item[key],platform:slug,host:slug,filename:`${filename}-${slug}.tar.gz`});}
 for(const[name,item]of Object.entries(runtime?.provider_receipts??{}))if(item.lazy_assets){const slug=name.replaceAll('/','-'),parts=name.split('/'),host=parts.slice(-2).join('-');if(selected&&!['darwin-arm64','darwin-x64','linux-arm64','linux-x64','win32-arm64','win32-x64'].includes(host))throw new Error('Provider acquisition target is invalid.');expected.set(`provider-assets-${slug}`,{contract:item.lazy_assets,platform:slug,host,filename:`ud-agent-provider-${slug}.tar.gz`});}
 if(!existsSync(file)){if(expected.size)throw new Error('Lazy render dependency release archives are missing.');return[];}
 const manifest=JSON.parse(readFileSync(file,'utf8'));
 if(manifest.schema_version!==1||!Array.isArray(manifest.assets)||manifest.assets.length!==expected.size)throw new Error('Auxiliary release inventory is incomplete.');
 const seen=new Set(),result=[];
 for(const item of manifest.assets){
  const expectedItem=expected.get(item?.id),contract=expectedItem?.contract;
  if(!contract||seen.has(item.id)||item.platform!==expectedItem.platform||item.url!==contract.url||item.sha256!==contract.sha256||item.size_bytes!==contract.size)throw new Error('Auxiliary release identity differs from its acquisition contract.');
  safeRelative(item.path);const filename=expectedItem.filename;
  if(path.posix.basename(item.path)!==filename||new URL(item.url).pathname.split('/').at(-1)!==filename)throw new Error('Auxiliary release filename is invalid.');
  if(!selected||selected.has(expectedItem.host)){const actual=fileReceipt(root,item.path);if(`sha256:${actual.sha256}`!==item.sha256||actual.size!==item.size_bytes)throw new Error('Auxiliary release bytes differ from the frozen receipt.');result.push(item);}
  seen.add(item.id);
 }
 return result;
}
