/** Pure derivation and original-code CLI calibration; no variant is executed. */
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {chmodSync,existsSync,linkSync,mkdirSync,mkdtempSync,readFileSync,renameSync,rmSync,statSync,symlinkSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import os from 'node:os';
import {expect,test} from 'vitest';
import {deriveStrykerAssertionSdk,verifyStrykerAssertionSdk,verifyStrykerAssertionSdkClosure,STRYKER_ASSERTION_SDK_FILE,STRYKER_ASSERTION_SDK_UPSTREAM_SHA256,STRYKER_ASSERTION_SERIALIZER_FILE,STRYKER_ASSERTION_CHAI_FILE,verifyStrykerFreshScript} from '../../scripts/quality/stryker-assertion-sdk.mjs';
import {verifyProtectedAssertionSdkEvidence} from '../../scripts/quality/stryker-protected-runner.mjs';
import {originalVitestAssertionSdk,originalVitestSerializerSdk,originalChaiAssertionSdk} from '../fixtures/assertion-sdk.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const require=createRequire(import.meta.url),upstream=originalVitestAssertionSdk(path.dirname(require.resolve('vitest/package.json'))),serializer=originalVitestSerializerSdk(path.dirname(require.resolve('vitest/package.json'))),chai=originalChaiAssertionSdk(path.dirname(require.resolve('chai/package.json')));
function fixture(){
  const result=deriveStrykerAssertionSdk(upstream,{serializerOriginal:serializer,chaiOriginal:chai});expect(result).toEqual(expect.objectContaining({original:expect.any(Buffer),derived:expect.any(Buffer),receipt:expect.any(Object)}));
  const before={schema_version:1,files:[{path:STRYKER_ASSERTION_SDK_FILE,sha256:sha(upstream),size:upstream.length,mode:0o444},{path:STRYKER_ASSERTION_SERIALIZER_FILE,sha256:sha(serializer),size:serializer.length,mode:0o444},{path:STRYKER_ASSERTION_CHAI_FILE,sha256:sha(chai),size:chai.length,mode:0o444}],links:[{path:'.bin/vitest',target:'../vitest/vitest.mjs'}]},after=structuredClone(before);
  after.files[0]={...after.files[0],sha256:sha(result.derived),size:result.derived.length};after.files[1]={...after.files[1],sha256:sha(result.serializerDerived),size:result.serializerDerived.length};
  after.files[2]={...after.files[2],sha256:sha(result.chaiDerived),size:result.chaiDerived.length};
  const bytes={receiptBytes:Buffer.from(JSON.stringify(result.receipt)),originalBytes:upstream,upstreamBytes:Buffer.from(JSON.stringify(before)),closureBytes:Buffer.from(JSON.stringify(after)),currentBytes:result.derived,serializerOriginalBytes:serializer,serializerCurrentBytes:result.serializerDerived,chaiOriginalBytes:chai,chaiCurrentBytes:result.chaiDerived};
  const descriptor=(name,data)=>({path:name,sha256:sha(data),size_bytes:data.length}),runtime={node_dependencies:descriptor('node-dependencies.json',bytes.closureBytes),node_assertion_sdk:{receipt:descriptor('node-assertion-sdk.json',bytes.receiptBytes),upstream_source:descriptor('node-assertion-sdk-upstream.js',upstream),serializer_upstream_source:descriptor('node-assertion-sdk-serializer-upstream.js',serializer),chai_upstream_source:descriptor('node-assertion-sdk-chai-upstream.js',chai),upstream_dependencies:descriptor('node-upstream-dependencies.json',bytes.upstreamBytes)}};
  return{result,before,after,bytes,runtime};
}
test('the fixed derivation retains exact upstream bytes and inserts only the two fresh polarity constructions',()=>{
  const {result}=fixture();expect(sha(result.original)).toBe(STRYKER_ASSERTION_SDK_UPSTREAM_SHA256);expect(result.original.equals(upstream)).toBe(true);
  const text=result.derived.toString('utf8');expect(text.split('__udCaptureFreshAsync(')).toHaveLength(3);expect(text).not.toContain('__udRecordStrykerAsyncError');
  expect(text.startsWith('import { registerStrykerFreshRecorder as __udRegisterStrykerFreshRecorder } from "file:///opt/mutation/harness/stryker-assertions.mjs";\n')).toBe(true);
  expect(text).toContain('throw __udCaptureFreshAsync(_error)');expect(text).toContain('throw __udCaptureFreshAsync(new AssertionError(');
  expect(result.receipt.recipe.fresh_async.positions).toHaveLength(6);expect(result.receipt.original).toEqual({sha256:STRYKER_ASSERTION_SDK_UPSTREAM_SHA256,size_bytes:upstream.length});
  expect(verifyStrykerAssertionSdk(upstream,result.derived,result.receipt,{serializerOriginal:serializer,serializerDerived:result.serializerDerived,chaiOriginal:chai,chaiDerived:result.chaiDerived})).toEqual(result.receipt);
});
test('upstream drift, repeat derivation and invalid capture paths cannot produce accepted SDK bytes',()=>{
  const {result}=fixture(),changed=Buffer.from(upstream);changed[0]^=1;
  for(const bytes of [changed,result.derived,Buffer.alloc(1024**2+1),'not bytes'])expect(()=>deriveStrykerAssertionSdk(bytes)).toThrow('upstream bytes differ');
  for(const captureModule of ['relative/stryker-assertions.mjs','/tmp/foreign.mjs','/tmp/stryker-assertions.mjs\n'])expect(()=>deriveStrykerAssertionSdk(upstream,{captureModule})).toThrow('fixed harness');
  for(const patch of [value=>value.derived.sha256='f'.repeat(64),value=>value.recipe.fresh_async.positions.pop(),value=>value.recipe.capture_module='file:///foreign/module.mjs',value=>value.recipe_sha256='f'.repeat(64)]){
    const record=structuredClone(result.receipt);patch(record);expect(()=>verifyStrykerAssertionSdk(upstream,result.derived,record,{serializerOriginal:serializer,serializerDerived:result.serializerDerived,chaiOriginal:chai,chaiDerived:result.chaiDerived})).toThrow('stale, incomplete or forged');
  }
});
test('the complete dependency inventories allow exactly the three declared source changes and preserve every other file and link',()=>{
  const {result,before,after}=fixture();expect(verifyStrykerAssertionSdkClosure(before,after,result.receipt)).toBe(true);
  for(const patch of [value=>value.files.pop(),value=>value.files[1].sha256='b'.repeat(64),value=>value.files[1].mode=0o400,value=>value.files[0].size++,value=>value.files[0].path='foreign.js',value=>value.links[0].target='../chai/index.js',value=>value.files.push(value.files[1]),value=>value.files[0].mode=0o644,value=>value.links.push({path:'foreign',target:'/tmp/shared'}),value=>delete value.links]){
    const changed=structuredClone(after);patch(changed);expect(()=>verifyStrykerAssertionSdkClosure(before,changed,result.receipt)).toThrow(/Assertion SDK/);
  }
});
test('production SDK verification rejects an otherwise authentic legacy one-file derivation',()=>{
  const {runtime,bytes}=fixture(),legacy=deriveStrykerAssertionSdk(upstream),receiptBytes=Buffer.from(JSON.stringify(legacy.receipt));
  const changed=structuredClone(runtime);changed.node_assertion_sdk.receipt={path:'node-assertion-sdk.json',sha256:sha(receiptBytes),size_bytes:receiptBytes.length};
  expect(()=>verifyProtectedAssertionSdkEvidence(changed,{...bytes,receiptBytes})).toThrow('authenticated fresh-error construction authority');
});
test('serializer bytes and the exact private-WeakMap boundary remain independently source-bound',()=>{
  const {result}=fixture();expect(result.receipt.schema_version).toBe(3);
  expect(result.serializerDerived.toString()).toContain('return __udSerializeStrykerAssertionOrigin(err, serializeValue(err));');
  const altered=Buffer.from(serializer);altered[0]^=1;expect(()=>deriveStrykerAssertionSdk(upstream,{serializerOriginal:altered})).toThrow('serializer upstream');
  expect(()=>verifyStrykerAssertionSdk(upstream,result.derived,result.receipt,{serializerOriginal:serializer,serializerDerived:Buffer.from('forged serializer'),chaiOriginal:chai,chaiDerived:result.chaiDerived})).toThrow('serializer derivation');
  const receipt=structuredClone(result.receipt);receipt.recipe.serializer.boundary.start++;
  expect(()=>verifyStrykerAssertionSdk(upstream,result.derived,receipt,{serializerOriginal:serializer,serializerDerived:result.serializerDerived,chaiOriginal:chai,chaiDerived:result.chaiDerived})).toThrow('stale, incomplete or forged');
});
test('parent verification binds retained source, recipe, upstream inventory and actual derived bytes to immutable image descriptors',()=>{
  const {runtime,bytes,result}=fixture();expect(verifyProtectedAssertionSdkEvidence(runtime,bytes)).toEqual(result.receipt);
  for(const name of Object.keys(bytes)){
    const changed={...bytes,[name]:Buffer.concat([bytes[name],Buffer.from('changed')])};expect(()=>verifyProtectedAssertionSdkEvidence(runtime,changed)).toThrow();
  }
  for(const change of [value=>delete value.node_assertion_sdk,value=>value.node_assertion_sdk.upstream_source.path='../foreign.js',value=>value.node_assertion_sdk.receipt.sha256='0'.repeat(64),value=>value.node_assertion_sdk.extra={},value=>delete value.node_dependencies.size_bytes]){
    const changed=structuredClone(runtime);change(changed);expect(()=>verifyProtectedAssertionSdkEvidence(changed,bytes)).toThrow(/assertion SDK/);
  }
});
test.each([0o600,0o444])('the original preparer CLI preserves upstream bytes and source mode %i in a new owned SDK context',mode=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-assertion-sdk-'));
  try{
    const copied=path.join(root,'node_modules',STRYKER_ASSERTION_SDK_FILE),copiedSerializer=path.join(root,'node_modules',STRYKER_ASSERTION_SERIALIZER_FILE),copiedChai=path.join(root,'node_modules',STRYKER_ASSERTION_CHAI_FILE);mkdirSync(path.dirname(copied),{recursive:true});writeFileSync(copied,upstream,{mode:0o600});writeFileSync(copiedSerializer,serializer,{mode:0o600});mkdirSync(path.dirname(copiedChai),{recursive:true});writeFileSync(copiedChai,chai,{mode:0o600});
    const files=[copied,copiedSerializer,copiedChai];for(const file of files)chmodSync(file,mode);const modes=files.map(file=>statSync(file).mode&0o777);
    const run=()=>spawnSync(process.execPath,[path.resolve('scripts/quality/stryker-assertion-sdk.mjs'),root],{encoding:'utf8',timeout:10000});
    const missing=run();expect(missing.error).toBeUndefined();expect(missing.status).not.toBe(0);expect(readFileSync(copied).equals(upstream)).toBe(true);expect(existsSync(path.join(root,'node-assertion-sdk.json'))).toBe(false);
    writeFileSync(path.join(root,'node-installation-receipt.json'),JSON.stringify({qualification:'locked-native-sdk-data-preparation-no-lifecycle-execution'}));
    const prepared=run();expect(prepared.error).toBeUndefined();expect(prepared.status,prepared.stderr).toBe(0);
    expect(files.map(file=>statSync(file).mode&0o777)).toEqual(modes);
    const receipt=JSON.parse(readFileSync(path.join(root,'node-assertion-sdk.json')));expect(verifyStrykerAssertionSdk(readFileSync(path.join(root,'node-assertion-sdk-upstream.js')),readFileSync(copied),receipt,{serializerOriginal:readFileSync(path.join(root,'node-assertion-sdk-serializer-upstream.js')),serializerDerived:readFileSync(copiedSerializer),chaiOriginal:readFileSync(path.join(root,'node-assertion-sdk-chai-upstream.js')),chaiDerived:readFileSync(copiedChai)})).toEqual(receipt);
    const second=run();expect(second.status).not.toBe(0);expect(readFileSync(path.join(root,'node-assertion-sdk-upstream.js')).equals(upstream)).toBe(true);
  }finally{rmSync(root,{recursive:true,force:true});}
});

test.each(['parent-link','leaf-link','hard-link'])('the original preparer rejects shared source paths through %s before derivation',alias=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-assertion-sdk-alias-'));
  try{
    const modules=path.join(root,'node_modules'),copied=path.join(modules,STRYKER_ASSERTION_SDK_FILE),external=path.join(root,'external.js');
    mkdirSync(path.dirname(copied),{recursive:true});writeFileSync(external,upstream,{mode:0o444});
    if(alias==='parent-link'){
      const packagePath=path.join(modules,'vitest'),externalPackage=path.join(root,'external-vitest');renameSync(packagePath,externalPackage);writeFileSync(path.join(externalPackage,'dist/chunks',path.basename(copied)),upstream,{mode:0o444});symlinkSync(externalPackage,packagePath,'junction');
    }else if(alias==='leaf-link')symlinkSync(external,copied,'file');else linkSync(external,copied);
    const sourceMode=statSync(copied).mode&0o777;
    writeFileSync(path.join(root,'node-installation-receipt.json'),JSON.stringify({qualification:'locked-native-sdk-data-preparation-no-lifecycle-execution'}));
    const result=spawnSync(process.execPath,[path.resolve('scripts/quality/stryker-assertion-sdk.mjs'),root],{encoding:'utf8',timeout:10000});
    expect(result.error).toBeUndefined();expect(result.status).not.toBe(0);expect(result.stderr).toMatch(/owned ordinary|ELOOP/);
    expect(readFileSync(copied).equals(upstream)).toBe(true);expect(readFileSync(external).equals(upstream)).toBe(true);expect(statSync(copied).mode&0o777).toBe(sourceMode);expect(existsSync(path.join(root,'node-assertion-sdk.json'))).toBe(false);
  }finally{rmSync(root,{recursive:true,force:true});}
});

test.each(['reopen-failure','write-failure','path-replacement'])('the original preparer restores the held source mode after %s without writing a replacement',failure=>{
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-assertion-sdk-restore-'));
  try{
    const copied=path.join(root,'node_modules',STRYKER_ASSERTION_SDK_FILE),retained=path.join(root,'held-original.js');
    for(const [relative,bytes]of [[STRYKER_ASSERTION_SDK_FILE,upstream],[STRYKER_ASSERTION_SERIALIZER_FILE,serializer],[STRYKER_ASSERTION_CHAI_FILE,chai]]){const file=path.join(root,'node_modules',relative);mkdirSync(path.dirname(file),{recursive:true});writeFileSync(file,bytes,{mode:0o444});}
    const mode=statSync(copied).mode&0o777;writeFileSync(path.join(root,'node-installation-receipt.json'),JSON.stringify({qualification:'locked-native-sdk-data-preparation-no-lifecycle-execution'}));
    const preload=path.join(root,'original-fs-failure.mjs');
    writeFileSync(preload,`import fs from 'node:fs';import{syncBuiltinESMExports}from'node:module';
const target=${JSON.stringify(copied)},retained=${JSON.stringify(retained)},failure=${JSON.stringify(failure)},open=fs.openSync,chmod=fs.fchmodSync,write=fs.writeSync,targetInfo=fs.statSync(target);let injected=false;
if(failure==='reopen-failure')fs.openSync=function(file,flags,...rest){if(file===target&&(flags&fs.constants.O_RDWR)!==0)throw new Error('injected writable reopen failure');return open(file,flags,...rest);};
else if(failure==='write-failure')fs.writeSync=function(fd,...rest){const info=fs.fstatSync(fd);if(info.dev===targetInfo.dev&&info.ino===targetInfo.ino)throw new Error('injected source write failure');return write(fd,...rest);};
else fs.fchmodSync=function(fd,mode){chmod(fd,mode);if(!injected){injected=true;fs.renameSync(target,retained);fs.copyFileSync(retained,target);}};
syncBuiltinESMExports();`);
    const result=spawnSync(process.execPath,['--import',pathToFileURL(preload).href,path.resolve('scripts/quality/stryker-assertion-sdk.mjs'),root],{encoding:'utf8',timeout:10000});
    expect(result.error).toBeUndefined();expect(result.status).not.toBe(0);expect(result.stderr).toContain(failure==='reopen-failure'?'injected writable reopen failure':failure==='write-failure'?'injected source write failure':'source identity changed');
    expect(readFileSync(copied).equals(upstream)).toBe(true);const original=failure==='path-replacement'?retained:copied;expect(readFileSync(original).equals(upstream)).toBe(true);expect(statSync(original).mode&0o777).toBe(mode);
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('compiled-script authentication replays all fresh sites and rejects claimed URLs or altered SDK source',()=>{
  const {result}=fixture();
  for(const [source,boundary,count]of [[result.derived,'vitest-5.1.0/async-before-stack-rewrite',6],[result.chaiDerived,'chai-6.3.0/Assertion.prototype.assert',1]]){
    const options={captureModule:'file:///opt/mutation/harness/stryker-assertions.mjs'},proof=verifyStrykerFreshScript(source.toString(),boundary,options);
    expect(proof.script_sha256).toBe(sha(source));expect(proof.positions).toHaveLength(count);
    for(const text of [source.toString()+'\n//# sourceURL=/opt/mutation/node_modules/chai/index.js',source.toString().replace('AssertionError','ForeignError'),source.toString().slice(1)])expect(()=>verifyStrykerFreshScript(text,boundary,options)).toThrow();
    expect(()=>verifyStrykerFreshScript(source.toString(),boundary,{captureModule:'file:///foreign/stryker-assertions.mjs'})).toThrow();
  }
});
