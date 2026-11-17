/** Original native-loader/Vite boundary calibration, no variant execution. */
import {posixTest} from '../fixtures/native-scope.mjs';
import{test,expect}from'vitest';import{createRequire}from'node:module';import{spawnSync}from'node:child_process';import{mkdirSync,mkdtempSync,realpathSync,writeFileSync,readFileSync,rmSync,symlinkSync}from'node:fs';import os from'node:os';import path from'node:path';import{prepareNativeAssertionFixture}from'../fixtures/native-assertion-loader.mjs';
posixTest('Vite setup and the native serializer share the native capture instance through the fixed CJS bridge',()=>{
 const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-native-assertion-loader-'))),require=createRequire(import.meta.url);
 try{
  const prepared=prepareNativeAssertionFixture(root);mkdirSync(path.join(root,'tests'));mkdirSync(path.join(root,'tmp'));symlinkSync(path.dirname(path.dirname(require.resolve('vitest/package.json'))),path.join(root,'node_modules'),'dir');
  writeFileSync(path.join(root,'package.json'),'{"type":"module"}');
  writeFileSync(path.join(root,'tests/identity.test.mjs'),`import{test,expect}from'vitest';import assert from'node:assert/strict';import{createRequire}from'node:module';import*as transformed from ${JSON.stringify(prepared.captureModule)};const native=await createRequire(import.meta.url)(${JSON.stringify(prepared.loader)});test('original native capture survives native serialization',async()=>{expect(native.installStrykerAssertionCapture).not.toBe(transformed.installStrykerAssertionCapture);await native.installStrykerAssertionCapture();let error;try{assert.equal(1,2);}catch(caught){error=caught;}expect(native.captureStrykerError(error).assertion_capture).toBeDefined();expect(native.serializeStrykerAssertionOrigin(error,{name:error.name}).ud_stryker_assertion_origin).toBeDefined();expect(transformed.serializeStrykerAssertionOrigin(error,{name:error.name})).toEqual({name:error.name});});`);
  writeFileSync(path.join(root,'vitest.config.mjs'),`export default{root:${JSON.stringify(root)},cacheDir:${JSON.stringify(path.join(root,'cache'))},test:{include:['tests/identity.test.mjs'],pool:'forks',maxWorkers:1}};`);
  const result=spawnSync(process.execPath,[path.join(path.dirname(require.resolve('vitest/package.json')),'vitest.mjs'),'run','--config',path.join(root,'vitest.config.mjs'),'--configLoader','runner'],{cwd:root,env:{...process.env,HOME:root,TMPDIR:path.join(root,'tmp'),TMP:path.join(root,'tmp'),TEMP:path.join(root,'tmp')},encoding:'utf8',timeout:20000,maxBuffer:1024**2});
  expect(result.error).toBeUndefined();expect(result.status,result.stdout+'\n'+result.stderr).toBe(0);expect(result.stdout).toContain('1 passed');
 }finally{rmSync(root,{recursive:true,force:true});}
},30000);

if(process.platform==='win32')test('native assertion loader refuses Windows metadata without treating it as immutable POSIX authority',()=>{
 const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-native-loader-refusal-'))),require=createRequire(import.meta.url);
 try{
  const prepared=prepareNativeAssertionFixture(root),receipt=path.join(prepared.runtime,'input-receipt.json');
  const original=[prepared.loader,prepared.captureModule,receipt].map(file=>[file,readFileSync(file)]);
  expect(()=>require(prepared.loader)).toThrow('Native assertion loader directory is not immutable authority.');
  for(const[file,bytes]of original)expect(readFileSync(file)).toEqual(bytes);
 }finally{rmSync(root,{recursive:true,force:true});}
});
