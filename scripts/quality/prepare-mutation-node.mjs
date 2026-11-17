#!/usr/bin/env node
/** Rebuild the locked Linux SDK without executing dependency lifecycle scripts. */
import{spawnSync}from'node:child_process';
import{existsSync,lstatSync,mkdirSync,readFileSync,realpathSync,rmSync,unlinkSync,writeFileSync}from'node:fs';
import path from'node:path';import{fileURLToPath}from'node:url';
import{safeRelative,sha256}from'../release/candidate.mjs';
import{nodeDependencyInventory,validateNodeTargetPackages}from'./node-dependencies.mjs';
const insist=(value,message)=>{if(!value)throw new Error('Mutation Node preparation: '+message);};

export function prepareMutationNode(root,output,{npmCli=path.join(path.dirname(process.execPath),'npm'),target={os:'linux',cpu:'arm64',libc:'glibc'}}={}){
 root=realpathSync(root);output=path.resolve(output);const relative=path.relative(root,output).split(path.sep).join('/');safeRelative(relative);
 insist(relative.startsWith('.artifacts/')&&!existsSync(output),'new product-owned artifact profile required');
 insist(target.os==='linux'&&['arm64','x64'].includes(target.cpu)&&target.libc==='glibc','only declared Linux data profiles are supported');
 let parent=root;for(const part of relative.split('/').slice(0,-1)){parent=path.join(parent,part);if(!existsSync(parent))mkdirSync(parent,{mode:0o700});const item=lstatSync(parent);insist(item.isDirectory()&&!item.isSymbolicLink(),'ordinary profile parents required');}
 npmCli=realpathSync(npmCli);const npmInfo=lstatSync(npmCli);insist(npmInfo.isFile()&&npmInfo.size<=1024**2,'ordinary bounded npm CLI required');
 mkdirSync(output,{mode:0o700});const created=lstatSync(output);let completed=false;
 try{
 writeFileSync(path.join(output,'INCOMPLETE'),'The exact target dependency inventory has not completed.\n',{flag:'wx'});
 const inputs={};for(const name of['package.json','package-lock.json']){const file=path.join(root,name),item=lstatSync(file);insist(item.isFile()&&!item.isSymbolicLink()&&item.size<=16*1024**2,'bounded package input required');const raw=readFileSync(file);inputs[name]=sha256(raw);writeFileSync(path.join(output,name),raw,{flag:'wx'});}
 for(const name of['user.npmrc','global.npmrc'])writeFileSync(path.join(output,name),'',{flag:'wx',mode:0o600});
 const environment={PATH:path.dirname(process.execPath)+':/usr/bin:/bin',HOME:path.join(output,'home'),LANG:'C.UTF-8',CI:'true',npm_config_userconfig:path.join(output,'user.npmrc'),npm_config_globalconfig:path.join(output,'global.npmrc'),npm_config_update_notifier:'false'};
 mkdirSync(environment.HOME,{mode:0o700});
 const invoke=args=>spawnSync(process.execPath,[npmCli,...args],{cwd:output,env:environment,encoding:'utf8',timeout:600000,maxBuffer:16*1024**2});
 const version=invoke(['--version']);insist(!version.error&&version.status===0&&!version.signal&&/^\d+\.\d+\.\d+\s*$/.test(version.stdout),'npm version probe failed');
 const args=['ci','--ignore-scripts','--include=optional','--os='+target.os,'--cpu='+target.cpu,'--libc='+target.libc,'--no-audit','--no-fund','--cache',path.join(output,'cache')];
 const installed=invoke(args);writeFileSync(path.join(output,'install.log'),(installed.stdout??'')+(installed.stderr??''),{flag:'wx'});
 insist(!installed.error&&installed.status===0&&!installed.signal,'exact npm ci failed: '+String(installed.stderr||installed.stdout||installed.error?.message||'unknown failure').slice(-2000));
 for(const[name,digest]of Object.entries(inputs))insist(sha256(readFileSync(path.join(root,name)))===digest&&sha256(readFileSync(path.join(output,name)))===digest,'package input changed during preparation');
 const lock=JSON.parse(readFileSync(path.join(output,'package-lock.json'))),packages=validateNodeTargetPackages(path.join(output,'node_modules'),lock,target),closure=nodeDependencyInventory(path.join(output,'node_modules'));
 writeFileSync(path.join(output,'target-packages.json'),JSON.stringify(packages)+'\n',{flag:'wx'});
 writeFileSync(path.join(output,'node-dependencies.json'),JSON.stringify(closure)+'\n',{flag:'wx'});
 const receipt={schema_version:1,qualification:'locked-native-sdk-data-preparation-no-lifecycle-execution',target,inputs,
  node:{version:process.version,executable_sha256:sha256(readFileSync(process.execPath))},npm:{version:version.stdout.trim(),cli_sha256:sha256(readFileSync(npmCli))},command:[process.execPath,npmCli,...args],
  packages:packages.packages.length,closure:{files:closure.files.length,links:closure.links.length,sha256:sha256(JSON.stringify(closure)+'\n')},target_inventory_sha256:sha256(JSON.stringify(packages)+'\n'),install_log_sha256:sha256(readFileSync(path.join(output,'install.log')))};
 writeFileSync(path.join(output,'installation-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});
 // npm's download cache duplicates the installed closure and is not used by
 // the SDK. The exact install log and lock-bound receipt remain in the profile.
 rmSync(path.join(output,'cache'),{recursive:true,force:true});
 unlinkSync(path.join(output,'INCOMPLETE'));completed=true;return receipt;
 }finally{
  if(!completed){
   // Only remove the directory created by this invocation. A failed profile
   // cannot be reused and otherwise grows on each interrupted setup attempt.
   const current=lstatSync(output,{throwIfNoEntry:false});
   if(current?.isDirectory()&&!current.isSymbolicLink()&&current.dev===created.dev&&current.ino===created.ino)rmSync(output,{recursive:true,force:true});
  }
 }
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const args=process.argv.slice(2);insist(args.length===2&&args[0]==='--output','Usage: prepare-mutation-node.mjs --output NEW_PROFILE');
 const result=prepareMutationNode('.',args[1]);console.log(JSON.stringify({target:result.target,packages:result.packages,files:result.closure.files,npm:result.npm.version}));
}
