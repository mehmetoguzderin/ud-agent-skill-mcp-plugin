import{test,expect}from'vitest';
import{existsSync,mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,writeFileSync}from'node:fs';
import os from'node:os';import path from'node:path';
import{prepareMutationNode}from'../../scripts/quality/prepare-mutation-node.mjs';

function fixture(){
 const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-mutation-sdk-'))),npmCli=path.join(root,'fixed-npm.cjs');
 writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'fixture',version:'1.0.0'}));
 writeFileSync(path.join(root,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/native':{version:'2.3.4',optional:true,os:['linux'],cpu:['arm64'],libc:['glibc']}}}));
 const script=`const fs=require('node:fs');if(process.argv[2]==='--version'){console.log('11.19.1');process.exit(0)}const args=process.argv.slice(2);if(args[0]!=='ci'||!args.includes('--ignore-scripts')||!args.includes('--include=optional')||!args.includes('--os=linux')||!args.includes('--cpu=arm64')||!args.includes('--libc=glibc'))throw Error('unsafe install');if(fs.readFileSync(process.env.npm_config_userconfig,'utf8')!==''||fs.readFileSync(process.env.npm_config_globalconfig,'utf8')!==''||process.env.npm_config_userconfig===process.env.npm_config_globalconfig)throw Error('ambient config');const cache=args[args.indexOf('--cache')+1];fs.mkdirSync(cache,{recursive:true});fs.writeFileSync(cache+'/download','temporary duplicate');console.log(JSON.stringify({secret:process.env.UD_FAKE_SECRET??null,options:process.env.NODE_OPTIONS??null}));fs.mkdirSync('node_modules/native',{recursive:true});fs.writeFileSync('node_modules/native/package.json',JSON.stringify({version:'2.3.4'}));`;
 writeFileSync(npmCli,script);return{root,npmCli,script};
}

test('rebuilds only the exact target closure with scripts disabled and a sanitized private npm profile',()=>{
 const value=fixture(),previous=process.env.UD_FAKE_SECRET;process.env.UD_FAKE_SECRET='must-not-leak';
 try{
  const output=path.join(value.root,'.artifacts/sdk'),receipt=prepareMutationNode(value.root,output,{npmCli:value.npmCli});
  expect(receipt.qualification).toBe('locked-native-sdk-data-preparation-no-lifecycle-execution');
  expect(receipt.npm.version).toBe('11.19.1');expect(receipt.packages).toBe(1);expect(receipt.closure.files).toBe(1);
  expect(receipt.command).toContain('--ignore-scripts');expect(receipt.command).toContain('--include=optional');
  expect(JSON.parse(readFileSync(path.join(output,'install.log'),'utf8'))).toEqual({secret:null,options:null});
  expect(JSON.parse(readFileSync(path.join(output,'target-packages.json'),'utf8')).packages[0]).toEqual(expect.objectContaining({path:'node_modules/native',version:'2.3.4'}));
  expect(readFileSync(path.join(output,'package-lock.json'))).toEqual(readFileSync(path.join(value.root,'package-lock.json')));
  expect(existsSync(path.join(output,'cache'))).toBe(false);
  expect(existsSync(path.join(output,'INCOMPLETE'))).toBe(false);
  expect(()=>prepareMutationNode(value.root,output,{npmCli:value.npmCli})).toThrow(/new product-owned/);
 }finally{if(previous===undefined)delete process.env.UD_FAKE_SECRET;else process.env.UD_FAKE_SECRET=previous;rmSync(value.root,{recursive:true,force:true});}
});

test('missing optional target bytes remove the incomplete payload and allow retry',()=>{
 const value=fixture();try{
  writeFileSync(value.npmCli,value.script.slice(0,value.script.indexOf("fs.mkdirSync('node_modules/native'"))+"fs.mkdirSync('node_modules');");
  const output=path.join(value.root,'.artifacts/sdk');
  expect(()=>prepareMutationNode(value.root,output,{npmCli:value.npmCli})).toThrow(/Missing target Node package/);
  expect(existsSync(output)).toBe(false);
  writeFileSync(value.npmCli,value.script);
  expect(prepareMutationNode(value.root,output,{npmCli:value.npmCli}).packages).toBe(1);
  expect(existsSync(path.join(output,'cache'))).toBe(false);
 }finally{rmSync(value.root,{recursive:true,force:true});}
});

test('a failed npm subprocess removes its private downloaded and installed bytes',()=>{
 const value=fixture();try{
  const failed=value.script.slice(0,value.script.indexOf("fs.mkdirSync('node_modules/native'"))+"fs.mkdirSync('node_modules/native',{recursive:true});fs.writeFileSync('node_modules/native/incomplete','payload');console.error('registry unavailable');process.exit(2);";
  writeFileSync(value.npmCli,failed);
  const output=path.join(value.root,'.artifacts/sdk');
  expect(()=>prepareMutationNode(value.root,output,{npmCli:value.npmCli})).toThrow(/registry unavailable/);
  expect(existsSync(output)).toBe(false);
  writeFileSync(value.npmCli,value.script);
  expect(prepareMutationNode(value.root,output,{npmCli:value.npmCli}).packages).toBe(1);
 }finally{rmSync(value.root,{recursive:true,force:true});}
});
