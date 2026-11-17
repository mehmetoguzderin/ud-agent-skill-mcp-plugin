import {test,expect} from 'vitest';
import {chmodSync,mkdirSync,mkdtempSync,readFileSync,readlinkSync,rmSync,symlinkSync,writeFileSync}from'node:fs';
import os from'node:os';import path from'node:path';
import {nodeDependencyInventory,validateNodeTargetPackages}from'../../scripts/quality/node-dependencies.mjs';
import {posixTest}from'../fixtures/native-scope.mjs';

posixTest('records exact files and confined links with final immutable image modes',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-node-deps-'));
 try{mkdirSync(path.join(root,'.bin'));mkdirSync(path.join(root,'package'));writeFileSync(path.join(root,'package/tool'),Buffer.from('binary'));chmodSync(path.join(root,'package/tool'),0o755);symlinkSync('../package/tool',path.join(root,'.bin/tool'));
  const receipt=nodeDependencyInventory(root);
  expect(receipt).toEqual({schema_version:1,files:[{path:'package/tool',sha256:'9a3a45d01531a20e89ac6ae10b0b0beb0492acd7216a368aa062d1a5fecaf9cd',size:6,mode:0o555}],links:[{path:'.bin/tool',target:'../package/tool'}]});
 }finally{rmSync(root,{recursive:true,force:true});}
});

if(process.platform==='win32')test('Windows refuses native backslash dependency links without rewriting link or target bytes',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-node-deps-refusal-'));
 try{
  mkdirSync(path.join(root,'.bin'));mkdirSync(path.join(root,'package'));const file=path.join(root,'package/tool'),link=path.join(root,'.bin/tool'),bytes=Buffer.from('binary');
  writeFileSync(file,bytes);symlinkSync('../package/tool',link);
  const target=readlinkSync(link);expect(target).toContain('\\');
  expect(()=>nodeDependencyInventory(root)).toThrow('Node dependency link has a foreign root.');
  expect(readlinkSync(link)).toBe(target);expect(readFileSync(file)).toEqual(bytes);
 }finally{rmSync(root,{recursive:true,force:true});}
});

test('refuses external, broken and cyclic dependency links',()=>{
 for(const kind of ['external','broken','cycle']){
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-node-deps-'));
  try{writeFileSync(path.join(root,'ordinary'),'bytes');symlinkSync(kind==='external'?'/etc/passwd':kind==='broken'?'missing':'link',path.join(root,'link'));expect(()=>nodeDependencyInventory(root)).toThrow(/foreign|broken|cyclic|escape/);}
  finally{rmSync(root,{recursive:true,force:true});}
 }
});

test('ignores only the disposable top-level Vitest transform cache',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-node-cache-'));
 try{
  mkdirSync(path.join(root,'.vitest-cache'));mkdirSync(path.join(root,'package','.vitest-cache'),{recursive:true});
  writeFileSync(path.join(root,'.vitest-cache','transform'),'old');
  writeFileSync(path.join(root,'package','.vitest-cache','required'),'dependency');
  const before=nodeDependencyInventory(root);
  expect(before.files.map(item=>item.path)).toEqual(['package/.vitest-cache/required']);
  writeFileSync(path.join(root,'.vitest-cache','transform'),'new');
  expect(nodeDependencyInventory(root)).toEqual(before);
  writeFileSync(path.join(root,'package','.vitest-cache','required'),'changed');
  expect(nodeDependencyInventory(root)).not.toEqual(before);
 }finally{rmSync(root,{recursive:true,force:true});}
});

test('requires matching optional native packages while excluding other target binaries',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-node-target-'));
 const put=(name,version)=>{mkdirSync(path.join(root,name),{recursive:true});writeFileSync(path.join(root,name,'package.json'),JSON.stringify({version}));};
 const lock={packages:{'':{},'node_modules/pure':{version:'1.0.0'},'node_modules/@native/linux':{version:'2.0.0',optional:true,os:['linux'],cpu:['arm64'],libc:['glibc'],integrity:'sha512-frozen'},'node_modules/@native/musl':{version:'2.0.0',optional:true,os:['linux'],cpu:['arm64'],libc:['musl']},'node_modules/@native/darwin':{version:'2.0.0',optional:true,os:['darwin'],cpu:['arm64']},'node_modules/not-linux':{version:'1.0.0',os:['!linux']}}};
 try{
  put('pure','1.0.0');
  expect(()=>validateNodeTargetPackages(root,lock,{os:'linux',cpu:'arm64',libc:'glibc'})).toThrow(/Missing target.*@native\/linux/);
  put('@native/linux','2.0.0');
  const result=validateNodeTargetPackages(root,lock,{os:'linux',cpu:'arm64',libc:'glibc'});
  expect(result.packages.map(item=>[item.path,item.version])).toEqual([['node_modules/@native/linux','2.0.0'],['node_modules/pure','1.0.0']]);
  expect(result.packages[0].integrity).toBe('sha512-frozen');
  expect(result.target).toEqual({os:'linux',cpu:'arm64',libc:'glibc'});
  put('@native/linux','1.9.0');expect(()=>validateNodeTargetPackages(root,lock,{os:'linux',cpu:'arm64',libc:'glibc'})).toThrow(/Stale target/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
