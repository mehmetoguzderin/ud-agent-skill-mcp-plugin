/** Inventory the immutable native Node dependency closure for confined tests. */
import {lstatSync, readFileSync, readdirSync, realpathSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {safeRelative, sha256} from '../release/candidate.mjs';

/** Vitest's generated transform cache is not part of the installed closure. */
export function isNodeDependencyInput(directory, filename) {
  const relative = path.relative(path.resolve(directory), path.resolve(filename));
  return relative !== '.vitest-cache' && !relative.startsWith('.vitest-cache' + path.sep);
}

/** Optional native dependencies are mandatory when their target matches. */
export function validateNodeTargetPackages(directory,lock,{os,cpu,libc}) {
  if(!['linux','darwin','win32'].includes(os)||!['arm64','x64'].includes(cpu)||!['glibc','musl',undefined].includes(libc)||!lock?.packages)throw new Error('Unsupported Node dependency target or lock.');
  const matches=(constraint,selected)=>{
    if(constraint===undefined)return true;
    if(!Array.isArray(constraint)||!constraint.length||constraint.some(value=>typeof value!=='string'||!value))throw new Error('Invalid locked Node platform constraint.');
    const positive=constraint.filter(value=>!value.startsWith('!'));
    return !constraint.includes('!'+selected)&&(positive.length===0||positive.includes(selected)||positive.includes('any'));
  };
  const packages=[];
  for(const[name,item]of Object.entries(lock.packages).sort(([a],[b])=>a<b?-1:a>b?1:0)){
    if(name==='')continue;
    safeRelative(name);
    if(!name.startsWith('node_modules/')||typeof item.version!=='string')throw new Error('Unsupported locked Node package record.');
    if(!matches(item.os,os)||!matches(item.cpu,cpu)||!matches(item.libc,libc))continue;
    const relative=name.slice('node_modules/'.length),file=path.join(directory,relative,'package.json');
    let info;try{info=lstatSync(file);}catch{throw new Error('Missing target Node package: '+name);}
    if(info.isSymbolicLink()||!info.isFile()||info.size>4*1024**2)throw new Error('Invalid target Node package manifest: '+name);
    const raw=readFileSync(file),manifest=JSON.parse(raw.toString('utf8'));
    if(manifest.version!==item.version)throw new Error('Stale target Node package version: '+name);
    packages.push({path:name,version:item.version,package_sha256:sha256(raw),...(item.integrity?{integrity:item.integrity}:{})});
  }
  if(!packages.length)throw new Error('Locked target Node package inventory is empty.');
  return {schema_version:1,target:{os,cpu,...(libc?{libc}:{})},packages};
}

export function nodeDependencyInventory(directory) {
  const requested=path.resolve(directory),info=lstatSync(requested);
  if(info.isSymbolicLink()||!info.isDirectory())throw new Error('Node dependency root must be an ordinary directory.');
  const root=realpathSync(requested);
  const files=[],links=[];
  function walk(folder) {
    for(const name of readdirSync(folder).sort()) {
      const file=path.join(folder,name),relative=path.relative(root,file).split(path.sep).join('/'),item=lstatSync(file);
      if(!isNodeDependencyInput(root,file))continue;
      safeRelative(relative);
      if(item.isSymbolicLink()) {
        const target=readLink(file);
        if(!target||path.isAbsolute(target)||target.includes('\\')||target.includes('\0'))throw new Error('Node dependency link has a foreign root.');
        let resolved;
        try{resolved=realpathSync(file);}catch{throw new Error('Node dependency link is broken or cyclic.');}
        if(resolved!==root&&!resolved.startsWith(root+path.sep))throw new Error('Node dependency link escapes its immutable closure.');
        links.push({path:relative,target});
      } else if(item.isDirectory())walk(file);
      else if(item.isFile()) {
        if(item.size>512*1024**2||(item.mode&0o7000)!==0)throw new Error('Node dependency file exceeds its mode/size contract.');
        files.push({path:relative,sha256:sha256(readFileSync(file)),size:item.size,mode:(item.mode&0o777)&~0o222});
      } else throw new Error('Node dependency closure contains a special file.');
    }
  }
  walk(root);
  if(!files.length||files.length+links.length>200000)throw new Error('Node dependency inventory is empty or oversized.');
  return {schema_version:1,files,links};
}
import {readlinkSync as readLink} from 'node:fs';

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv.length!==4)throw new Error('Usage: node-dependencies.mjs NODE_MODULES NEW_RECEIPT');
  const result=nodeDependencyInventory(process.argv[2]);
  writeFileSync(process.argv[3],JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o644});
  console.log(JSON.stringify({files:result.files.length,links:result.links.length}));
}
