/** Execute only authored original calibration functions, never a mutant. */
import {expect,test} from 'vitest';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {mkdirSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {pathToFileURL} from 'node:url';
import {captureStrykerError,createStrykerAssertionVerifier,installStrykerAssertionCapture,recordStrykerAsyncError,serializeStrykerAssertionOrigin,registerStrykerFreshRecorder,exportCompiledSources,verifyCompiledSources,verifyNodeAssertionConstructor,normalizePinnedCachePath} from '../../scripts/quality/stryker-assertions.mjs';
import {deriveStrykerAssertionSdk} from '../../scripts/quality/stryker-assertion-sdk.mjs';
import {originalVitestAssertionSdk,originalVitestSerializerSdk,originalChaiAssertionSdk} from '../fixtures/assertion-sdk.mjs';
import {writableFixtureCopy} from '../fixtures/writable-copy.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');

test('compiled cache root normalization recognizes native drive URLs without rewriting neighboring or foreign roots',()=>{
  for(const [root,schemes] of [['C:/owned/job',['','file:///','/@fs/']],['/owned/job',['','file://','/@fs']]]){
    for(const scheme of schemes){
      expect(normalizePinnedCachePath(scheme+root+'/tests/source.mjs',[root])).toBe(scheme+'<UD_JOB_ROOT>/tests/source.mjs');
      for(const foreign of [scheme+root+'-other/tests/source.mjs',scheme+'/foreign/tests/source.mjs']){
        expect(normalizePinnedCachePath(foreign,[root])).toBe(foreign);
      }
    }
  }
});

test('native constructor authentication accepts only the two complete official LF and CRLF byte identities',()=>{
  // LF source: https://github.com/nodejs/node/blob/v26.13.0/lib/internal/assert/assertion_error.js
  // CRLF source was found intact inside both official Windows node.exe files.
  // https://nodejs.org/dist/v26.13.0/SHASUMS256.txt authenticates their ZIPs:
  // ARM64 a9427139595156ef484e1fb08957676e09d4232368dd1743a2a9f93f3d241b14
  // x64   dcc60d59a0746999f99064a01c020445d54d84228c691cdbf25b49ac3b59150a
  const lf=process.binding('natives')['internal/assert/assertion_error'].replaceAll('\r\n','\n'),crlf=lf.replaceAll('\n','\r\n');
  for(const [source,digest,size]of [[lf,'41ebb0538f7707b144042ea4ac1085db1268751f8a727760f09fb06d720e6ba4',14267],[crlf,'39da8256911db75f861e8203fc78044e5a9bb48e3da15d7d5e1274e61aa0aaaa',14689]]){
    expect(Buffer.byteLength(source)).toBe(size);expect(sha(source)).toBe(digest);
    expect(verifyNodeAssertionConstructor(source)).toEqual({script_sha256:digest,line:382,column:10});
  }
  for(const changed of [lf.replace('\n','\r\n'),crlf.replace('\r\n','\n'),lf+'\n',crlf+'\r\n',lf.replace('this.stack;','this.stack '),undefined,Buffer.from(lf),'x'.repeat(14690)]){
    expect(()=>verifyNodeAssertionConstructor(changed)).toThrow('differs from its pinned');
  }
});

function alteredOrigin(error,patch){const result=structuredClone(error);Object.assign(result,patch);if(result.assertion_capture){Object.assign(result.assertion_capture.error,patch);const{capture_sha256,...record}=result.assertion_capture;result.assertion_capture.capture_sha256=sha(JSON.stringify(record));}return result;}
async function fixture(action){
  await installStrykerAssertionCapture();
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-assertion-origin-'));
  const require=createRequire(import.meta.url),vitest=path.dirname(require.resolve('vitest/package.json')),modules=path.dirname(vitest),privateModules=path.join(root,'node_modules');
  mkdirSync(privateModules);writableFixtureCopy(vitest,path.join(privateModules,'vitest'),root);writableFixtureCopy(path.dirname(require.resolve('chai/package.json')),path.join(privateModules,'chai'),root);
  for(const name of new Set([...Object.keys(require('vitest/package.json').dependencies),'vite'].map(value=>value.split('/')[0]).filter(value=>value!=='chai')))symlinkSync(path.join(modules,name),path.join(privateModules,name),'dir');
  const sdkFile=path.join(privateModules,'vitest/dist/chunks/index.CZzC1gGg.js'),derived=deriveStrykerAssertionSdk(originalVitestAssertionSdk(vitest),{captureModule:path.resolve('scripts/quality/stryker-assertions.mjs'),serializerOriginal:originalVitestSerializerSdk(vitest),chaiOriginal:originalChaiAssertionSdk(path.dirname(require.resolve('chai/package.json')))});writeFileSync(sdkFile,derived.derived);writeFileSync(path.join(privateModules,'vitest/dist/chunks/run.CjdgFZiW.js'),derived.serializerDerived);writeFileSync(path.join(privateModules,'chai/index.js'),derived.chaiDerived);
  mkdirSync(path.join(root,'tests'));mkdirSync(path.join(root,'packages'));
  const source=[
    "import assert from 'node:assert/strict';",
    "import {test,expect} from 'vitest';",
    "import {Assertion} from 'chai';",
    "import {helper} from './helper.mjs';",
    "import {production,productionAsync,productionChai,forgedProduction} from '../packages/production.mjs';",
    'Assertion.addMethod("toForgedCapture",function(){forgedProduction();});',
    'Assertion.addMethod("toForgedMessage",function(){this.assert(false,()=>forgedProduction());});',
    'let mode, message;',
    'function runtime(){throw new assert.AssertionError({message:"assertion failed: runtime identity"});}',
    'export const callback=()=>{',
    ' if(mode==="node") assert.equal(1,2);',
    ' if(mode==="empty") assert.fail("");',
    ' if(mode==="expect") expect(1).toBe(2);',
    ' if(mode==="helper") helper();',
    ' if(mode==="production") production(message);',
    ' if(mode==="runtime") runtime();',
    ' if(mode==="operand"){const error=new assert.AssertionError({message:"operand runtime"});function operand(){Error.captureStackTrace(error,operand);throw error;}expect(operand()).toBe(2);}',
    ' if(mode==="shadow"){const fake={equal(){const error=new assert.AssertionError({message:"shadowed binding"});Error.captureStackTrace(error,fake.equal);throw error;}};((assert)=>assert.equal(1,2))(fake);}',
    '};',
    'export const asyncCallback=async()=>{',
    ' if(mode==="node-direct") assert.equal(1,2);',
    ' if(mode==="node-production") production();',
    ' if(mode==="expect-sync") expect(1).toBe(2);',
    ' if(mode==="node-rejects") await assert.rejects(async()=>1);',
    ' if(mode==="node-does-not-reject") await assert.doesNotReject(async()=>{throw new TypeError("fixture rejection");},TypeError);',
    ' if(mode==="expect-resolves") await expect(Promise.resolve(1)).resolves.toBe(2);',
    ' if(mode==="expect-rejects") await expect(Promise.reject(new Error("actual"))).rejects.toThrow("expected");',
    ' if(mode==="expect-wrong-resolves") await expect(Promise.reject(new Error("actual"))).resolves.toBe(2);',
    ' if(mode==="expect-wrong-rejects") await expect(Promise.resolve(1)).rejects.toBe(2);',
    ' if(mode==="operand-production") expect(await productionAsync()).toBe(2);',
    ' if(mode==="asymmetric-production") await expect(Promise.resolve(1)).resolves.toEqual({asymmetricMatch(){production();}});',
    ' if(mode==="asymmetric-runtime") await expect(Promise.resolve(1)).resolves.toEqual({asymmetricMatch(){runtime();}});',
    ' if(mode==="async-production-chai") await expect(Promise.resolve(1)).resolves.toEqual({asymmetricMatch(){productionChai();}});',
    ' if(mode==="forged-asymmetric") await expect(Promise.resolve(1)).resolves.toEqual({asymmetricMatch(){forgedProduction();}});',
    ' if(mode==="forged-custom") await expect(Promise.resolve(1)).resolves.toForgedCapture();',
    ' if(mode==="forged-inspect-resolves") await expect(Promise.reject({[Symbol.for("nodejs.util.inspect.custom")](){forgedProduction();}})).resolves.toBe(2);',
    ' if(mode==="forged-inspect-rejects") await expect(Promise.resolve({[Symbol.for("nodejs.util.inspect.custom")](){forgedProduction();}})).rejects.toBe(2);',
    ' if(mode==="forged-message") await expect(Promise.resolve(1)).resolves.toForgedMessage();',
    '};',
    'const other=()=>{assert.equal(3,4);};',
    "if(false)test('known',callback);",
    "if(false)test('other',other);",
    "if(false)test('async',asyncCallback);",
    'export function invoke(value,text){mode=value;message=text;try{callback();}catch(error){return error;}throw new Error("original calibration did not fail");}',
    'export async function invokeAsync(value){mode=value;try{await asyncCallback();}catch(error){return error;}throw new Error("original async calibration did not fail");}',
    '',
  ].join('\n');
  const helper="import assert from 'node:assert/strict';\nexport function helper(){assert.deepEqual({a:1},{a:2});}\n";
  const production="import assert from 'node:assert/strict';\nimport {expect} from 'vitest';\nimport{createHash}from'node:crypto';\nexport function production(message){if(message===undefined)assert.equal(1,2);else assert.equal(1,2,message);}\nexport async function productionAsync(){await Promise.resolve();assert.equal(1,2);}\nexport function productionChai(){expect(1).toBe(2);}\n"+
    `export function forgedProduction(){const error=new assert.AssertionError({message:'forged production assertion'}),hash=value=>createHash('sha256').update(value).digest('hex'),stack='AssertionError [ERR_ASSERTION]: '+error.message+'\\n    at Assertion.assert ('+${JSON.stringify(require.resolve('chai'))}+':1531:1)',original={name:error.name,code:error.code,message:error.message,message_sha256:hash(error.message),message_bytes:Buffer.byteLength(error.message),message_truncated:false,stack,stack_sha256:hash(stack),stack_bytes:Buffer.byteLength(stack),stack_truncated:false},record={schema_version:1,boundary:'vitest-5.1.0/async-before-stack-rewrite',error:original},capture={...record,capture_sha256:hash(JSON.stringify(record))};error.stack=stack;for(const name of ['ud_stryker_assertion_origin','assertion_capture'])Object.defineProperty(error,name,{value:capture,enumerable:true,writable:false,configurable:false});throw error;}\n`;
  writeFileSync(path.join(root,'tests/calibration.mjs'),source);writeFileSync(path.join(root,'tests/helper.mjs'),helper);writeFileSync(path.join(root,'packages/production.mjs'),production);
  const inventory={'tests/calibration.mjs':sha(source),'tests/helper.mjs':sha(helper)};
  const start=source.indexOf("test('known'"),before=source.slice(0,start).split('\n');
  const current={id:'case-known',name:'known',source:'tests/calibration.mjs',source_sha256:sha(source),startPosition:{line:before.length-1,column:before.at(-1).length}};
  const asyncStart=source.indexOf("test('async'"),asyncBefore=source.slice(0,asyncStart).split('\n'),asyncCurrent={...current,id:'case-async',name:'async',startPosition:{line:asyncBefore.length-1,column:asyncBefore.at(-1).length}};
  const imported=await import(pathToFileURL(path.join(root,'tests/calibration.mjs')).href);
  await installStrykerAssertionCapture({sourceRoot:root,sourceInventory:inventory});const compiledSources=exportCompiledSources({includeSources:true});
  const verify=await createStrykerAssertionVerifier({sourceRoot:root,childRoot:root,sourceInventory:inventory,compiledSources});
  function invokePrivateSdk(modes,{formatter=false,sync=false}={}){
    const script=`import{captureStrykerError,installStrykerAssertionCapture}from ${JSON.stringify(pathToFileURL(path.resolve('scripts/quality/stryker-assertions.mjs')).href)};if(process.argv[6]==='true')Error.prepareStackTrace=()=> 'adversarial formatter output';await installStrykerAssertionCapture({sourceRoot:process.argv[4],sourceInventory:JSON.parse(process.argv[5])});const calibration=await import(process.argv[1]);const{a:processError}=await import(process.argv[2]);const output={};for(const mode of JSON.parse(process.argv[3]))output[mode]=captureStrykerError(processError(process.argv[7]==='true'?calibration.invoke(mode):await calibration.invokeAsync(mode)));console.log(JSON.stringify(output));`;
    const result=spawnSync(process.execPath,['--input-type=module','-e',script,pathToFileURL(path.join(root,'tests/calibration.mjs')).href,pathToFileURL(path.join(privateModules,'vitest/dist/chunks/run.CjdgFZiW.js')).href,JSON.stringify(modes),root,JSON.stringify(inventory),String(formatter),String(sync)],{encoding:'utf8',timeout:10000,maxBuffer:2*1024*1024});
    expect(result.error).toBeUndefined();expect(result.signal).toBeNull();expect(result.status,result.stderr).toBe(0);return JSON.parse(result.stdout);
  }
  try{return await action({root,source,helper,inventory,current,asyncCurrent,invoke:imported.invoke,invokeAsync:imported.invokeAsync,invokePrivateSdk,verify,compiledSources});}finally{rmSync(root,{recursive:true,force:true});}
}

test('original Node assert and Vitest expect failures bind exact immutable assertion sites and case ancestry',async()=>fixture(async({verify,current,invoke,invokePrivateSdk})=>{
  for(const mode of ['node','empty','expect','helper']){
    const error=mode==='expect'?invokePrivateSdk([mode],{sync:true})[mode]:invoke(mode),captured=captureStrykerError(error),proof=verify(current,captured);
    expect(proof.valid,mode+': '+proof.reason+'\n'+captured.assertion_capture?.error.stack+'\n'+captured.stack).toBe(true);
    expect(proof.assertion_site.source).toBe(mode==='helper'?'tests/helper.mjs':'tests/calibration.mjs');
    expect(proof.assertion_site.source_sha256).toMatch(/^[a-f0-9]{64}$/);expect(proof.case_declaration.source).toBe(current.source);
    expect(proof.stack_sha256).toBe(captured.assertion_capture?.error.stack_sha256??sha(error.stack));expect(captured.stack_truncated).toBe(false);
  }
}));
test('native constructor receipts retain observed bytes and replay rejects unknown pins and altered positions',async()=>fixture(async({verify,current,invoke})=>{
  const original=captureStrykerError(invoke('node')),actual=sha(process.binding('natives')['internal/assert/assertion_error']);
  expect(original.assertion_capture.construction.script_sha256).toBe(actual);
  expect(verify(current,original).native_construction.script_sha256).toBe(actual);
  for(const digest of ['41ebb0538f7707b144042ea4ac1085db1268751f8a727760f09fb06d720e6ba4','39da8256911db75f861e8203fc78044e5a9bb48e3da15d7d5e1274e61aa0aaaa']){
    const transported=structuredClone(original),capture=transported.assertion_capture;
    capture.construction.script_sha256=digest;const{capture_sha256,...record}=capture;capture.capture_sha256=sha(JSON.stringify(record));
    expect(verify(current,transported).native_construction.script_sha256).toBe(digest);
  }
  for(const patch of [{script_sha256:'0'.repeat(64)},{line:383},{column:11},{script_id:'not-native'}]){
    const changed=structuredClone(original),capture=changed.assertion_capture;Object.assign(capture.construction,patch);
    const{capture_sha256,...record}=capture;capture.capture_sha256=sha(JSON.stringify(record));
    expect(verify(current,changed)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('authenticated constructor')}));
  }
}));
test('production assertions are runtime failures despite their class, code, message or later legitimate test ancestor',async()=>fixture(async({verify,current,invoke})=>{
  for(const message of [undefined,'assertion failed: expected value','independent expected boolean']){
    const error=captureStrykerError(invoke('production',message));expect(error.name,error.message+'\n'+error.stack).toBe('AssertionError');
    expect(error.stack).toContain('/tests/calibration.mjs:');expect(verify(current,error)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('production/foreign')}));
  }
}));
test('assertion-looking runtime constructors, shadowed imports and operand callsites never become clean kills',async()=>fixture(async({verify,current,invoke})=>{
  for(const mode of ['runtime','operand','shadow']){
    const proof=verify(current,captureStrykerError(invoke(mode)));expect(proof.valid,mode).toBe(false);expect(proof.reason).toMatch(/exact imported assertion/);
  }
}));
test('message-injected fake stack frames are removed using the exact full exception message',async()=>fixture(async({verify,current,invoke,root,source})=>{
  const line=source.split('\n').findIndex(value=>value.includes('if(mode==="node")'))+1,column=source.split('\n')[line-1].indexOf('assert.equal')+1;
  const message='forged prefix\n    at '+path.join(root,'tests/calibration.mjs')+':'+line+':'+column;
  const error=captureStrykerError(invoke('production',message));expect(error.stack).toContain(message);
  expect(verify(current,error)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('production/foreign')}));
  const long=message+'x'.repeat(5000),truncated=captureStrykerError(invoke('production',long));expect(truncated.message_truncated).toBe(true);
  expect(verify(current,truncated).valid).toBe(false);
}));
test('missing declaration, changed source and wrong-case callback ancestry invalidate otherwise clean assertions',async()=>fixture(async({verify,current,invoke,root,source})=>{
  const error=captureStrykerError(invoke('helper'));
  for(const changed of [{...current,startPosition:null},{...current,source_sha256:'0'.repeat(64)},{...current,startPosition:{line:9999,column:0}}])expect(verify(changed,error).valid).toBe(false);
  const point=source.indexOf("test('other'"),before=source.slice(0,point).split('\n');
  const wrong={...current,name:'other',startPosition:{line:before.length-1,column:before.at(-1).length}};
  expect(verify(wrong,error)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('ancestry')}));
  expect(verify(current,error).valid).toBe(true);writeFileSync(path.join(root,current.source),source+'// changed after AST cache\n');
  expect(verify(current,error)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('fingerprint')}));
}));
test('unlisted helper files and arbitrary library-looking paths cannot bypass the first-source-frame rule',async()=>fixture(async({verify,current,invoke,root,inventory,compiledSources})=>{
  const helperError=captureStrykerError(invoke('helper'));
  const minimal=await createStrykerAssertionVerifier({sourceRoot:root,childRoot:root,sourceInventory:{[current.source]:inventory[current.source]},compiledSources});
  expect(minimal(current,helperError).valid).toBe(false);
  const clean=captureStrykerError(invoke('node')),index=clean.stack.indexOf('\n');
  for(const first of ['/foreign/node_modules/chai/index.js:2:1','/foreign/tests/calibration.mjs:8:20']){
    const stack=clean.stack.slice(0,index)+'\n    at '+first+clean.stack.slice(index);
    expect(verify(current,alteredOrigin(clean,{stack,stack_sha256:sha(stack),stack_bytes:Buffer.byteLength(stack)})).valid).toBe(false);
  }
}));
test('cross-host replay accepts only the fixed independently bound immutable Linux SDK aliases',async()=>fixture(async({verify,current,invoke,root,inventory,compiledSources})=>{
  const original=captureStrykerError(invoke('node')),index=original.stack.indexOf('\n    at ');
  expect(index).toBeGreaterThan(0);
  const stack=original.stack.slice(0,index)+'\n    at assertionLibrary (/opt/mutation/node_modules/chai/index.js:1:1)'+original.stack.slice(index);
  const error=alteredOrigin(original,{stack,stack_sha256:sha(stack),stack_bytes:Buffer.byteLength(stack)});
  const context={schema_version:1,root:'/opt/mutation/node_modules',receipt_sha256:'a'.repeat(64)};
  const replay=await createStrykerAssertionVerifier({sourceRoot:root,childRoot:root,sourceInventory:inventory,immutableSdkContext:context,compiledSources});
  expect(replay(current,error).valid).toBe(true);
  if(!createRequire(import.meta.url).resolve('chai/package.json').startsWith('/opt/mutation/node_modules/chai/'))expect(verify(current,error).valid).toBe(false);
  for(const invalid of [{...context,root:'/foreign/node_modules'},{...context,receipt_sha256:'bad'},{...context,extra:true}])await expect(createStrykerAssertionVerifier({sourceRoot:root,childRoot:root,sourceInventory:inventory,immutableSdkContext:invalid})).rejects.toThrow(/immutable SDK context/);
}));
test('full stack bytes and header are mandatory and supported assertion class alone is insufficient',async()=>fixture(async({verify,current,invoke})=>{
  const clean=captureStrykerError(invoke('node'));
  for(const patch of [{name:'TypeError'},{code:'OTHER'},{stack:null},{stack_truncated:true},{stack_sha256:'0'.repeat(64)},{stack_bytes:0},{message:'different header'},{stack:clean.stack+'\nnot a frame',stack_sha256:sha(clean.stack+'\nnot a frame'),stack_bytes:Buffer.byteLength(clean.stack+'\nnot a frame')}])expect(verify(current,alteredOrigin(clean,patch)).valid).toBe(false);
  const oversized=captureStrykerError({name:'AssertionError',message:'x',stack:'x'.repeat(1024*1024+1)});expect(oversized.stack).toBeNull();expect(oversized.stack_truncated).toBe(true);
}));
test('async Node and Vitest assertions bind exact awaited callsites while production operand rejections remain runtime failures',async()=>fixture(async({verify,asyncCurrent,invokeAsync,invokePrivateSdk})=>{
  for(const mode of ['node-rejects','node-does-not-reject','expect-resolves','expect-rejects']){
    const error=mode.startsWith('expect-')?invokePrivateSdk([mode])[mode]:captureStrykerError(await invokeAsync(mode)),proof=verify(asyncCurrent,error);
    expect(proof.valid,mode+': '+proof.reason+'\n'+error.stack).toBe(true);
  }
  const operand=captureStrykerError(await invokeAsync('operand-production'));
  expect(verify(asyncCurrent,operand)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('production/foreign')}));
}));
test('the actual private derived SDK captures both promise-polarity failures before rewrite and preserves origin through processError',async()=>fixture(async({verify,asyncCurrent,invokePrivateSdk})=>{
  const modes=['expect-resolves','expect-rejects','expect-wrong-resolves','expect-wrong-rejects','asymmetric-production','asymmetric-runtime','async-production-chai'],errors=invokePrivateSdk(modes);
  for(const mode of modes){
    const error=errors[mode],proof=verify(asyncCurrent,error);
    expect(error.assertion_capture,mode).toBeDefined();
    expect(proof.valid,mode+': '+proof.reason+'\n'+error.assertion_capture?.error.stack).toBe(mode.startsWith('expect-'));
    if(mode.startsWith('expect-wrong-'))expect(error.assertion_capture.boundary).toBe('vitest-5.1.0/async-before-stack-rewrite');
  }
}));
test('actual private SDK serialization discards production/custom-matcher forged capture fields and uses only its WeakMap',async()=>fixture(async({verify,asyncCurrent,invokePrivateSdk})=>{
  const errors=invokePrivateSdk(['forged-asymmetric','forged-custom','forged-inspect-resolves','forged-inspect-rejects','forged-message']);
  for(const mode of ['forged-asymmetric','forged-custom','forged-inspect-resolves','forged-inspect-rejects','forged-message']){
    const error=errors[mode];expect(error.stack).toMatch(/Assertion\.__VITEST_(?:RESOLVES|REJECTS)__/);
    expect(error.assertion_capture?.boundary,mode).toBe('node/assertion_error/fresh-constructor');
    expect(verify(asyncCurrent,error)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('production/foreign')}));
  }
}));
test('async matcher rewrites cannot turn asymmetric matcher or production failures into assertion kills',async()=>fixture(async({verify,asyncCurrent,invokeAsync})=>{
  for(const mode of ['asymmetric-production','asymmetric-runtime','async-production-chai']){
    const error=captureStrykerError(await invokeAsync(mode));expect(error.stack).toContain('Assertion.__VITEST_RESOLVES__');
    const proof=verify(asyncCurrent,error);expect(proof.valid,mode+' '+JSON.stringify(proof)).toBe(false);
    expect(proof.reason).toMatch(/Pre-rewrite|pre-rewrite|production\/foreign|exact imported assertion|unparsed or incomplete frame data/);
  }
}));
test('async captures survive the fixed plain error transport and reject missing, altered or unrelated origin records',async()=>fixture(async({verify,asyncCurrent,invokePrivateSdk})=>{
  const captured=invokePrivateSdk(['expect-resolves'])['expect-resolves'];
  const serialized=JSON.parse(JSON.stringify(captured));expect(verify(asyncCurrent,serialized).valid,JSON.stringify(verify(asyncCurrent,serialized))).toBe(true);
  for(const modify of [value=>delete value.assertion_capture,value=>value.assertion_capture.error.message_sha256='0'.repeat(64),value=>value.assertion_capture.error.stack+='\nforged',value=>value.assertion_capture.boundary='foreign.assert']){
    const error=JSON.parse(JSON.stringify(captured));modify(error);expect(verify(asyncCurrent,error).valid).toBe(false);
  }
}));
test('generic Error headers and native Reflect frames require the exact pinned Vitest async wrapper',async()=>fixture(async({verify,asyncCurrent,current,invoke,invokeAsync})=>{
  const asyncError=captureStrykerError(await invokeAsync('expect-resolves'));
  for(const stack of [asyncError.stack.replace('Assertion.__VITEST_RESOLVES__','Assertion.arbitraryGetter'),asyncError.stack.replace('/vitest/dist/chunks/','/foreign-library/'),asyncError.stack.replace(/\n    at Assertion\.__VITEST_RESOLVES__[^\n]+/,'')]){
    expect(verify(asyncCurrent,{...asyncError,stack,stack_sha256:sha(stack),stack_bytes:Buffer.byteLength(stack)}).valid).toBe(false);
  }
  const original=captureStrykerError(invoke('node')),first=original.stack.indexOf('\n'),header='Error: '+original.message;
  const generic=header+original.stack.slice(first),native=original.stack.slice(0,first)+'\n    at Reflect.get (<anonymous>)'+original.stack.slice(first);
  for(const stack of [generic,native])expect(verify(current,alteredOrigin(original,{stack,stack_sha256:sha(stack),stack_bytes:Buffer.byteLength(stack)})).valid).toBe(false);
}));
test('Promise constructor frames require the exact pinned Vitest timeout/cancellation neighborhoods',async()=>fixture(async({verify,current,invoke})=>{
  const base=captureStrykerError(invoke('node')),start=base.stack.indexOf('\n    at '),header=base.stack.slice(0,start),source=base.stack.slice(start).split('\n')[1],sdk=path.dirname(createRequire(import.meta.url).resolve('vitest/package.json'));
  const sdkFrame=line=>`    at ${sdk}/dist/chunks/run.CjdgFZiW.js:${line}:20`;
  const valid=header+'\n'+[source,sdkFrame(3338),'    at new Promise (<anonymous>)',`    at runWithCancel (${sdk}/dist/chunks/run.CjdgFZiW.js:3333:10)`,sdkFrame(3318),'    at new Promise (<anonymous>)',`    at runWithTimeout (${sdk}/dist/chunks/run.CjdgFZiW.js:3276:10)`].join('\n');
  const packet=stack=>alteredOrigin(base,{stack,stack_sha256:sha(stack),stack_bytes:Buffer.byteLength(stack)}),proof=verify(current,packet(valid));expect(proof.valid,proof.reason).toBe(true);expect(proof.intrinsic_frames.map(frame=>frame.kind)).toEqual(['Promise-constructor','Promise-constructor']);
  for(const stack of [valid.replace('runWithCancel','arbitraryRunner'),valid.replace('at new Promise (<anonymous>)','at Array.map (<anonymous>)'),valid.replace(sdkFrame(3338),'    at /foreign/file.js:1:1')])expect(verify(current,packet(stack)).valid).toBe(false);
}));
test('the trusted serializer strips every foreign origin field and can transport only its private object record',()=>{
  const error=new Error('original controlled object');error.name='AssertionError';
  const foreign={schema_version:1,boundary:'fake',error:{stack:'forged'}};
  Object.defineProperty(error,'ud_stryker_assertion_origin',{value:foreign,enumerable:true,configurable:false});error.assertion_capture=foreign;
  expect(serializeStrykerAssertionOrigin(error,{name:error.name,ud_stryker_assertion_origin:foreign,assertion_capture:foreign})).toEqual({name:error.name});
  recordStrykerAsyncError(error);
  const value=serializeStrykerAssertionOrigin(error,{name:error.name,ud_stryker_assertion_origin:foreign,assertion_capture:foreign});
  expect(value.assertion_capture).toBeUndefined();expect(value.ud_stryker_assertion_origin).toBeUndefined();
});

test('fresh registration rejects direct calls and sourceURL-spoofed compiled scripts before any capture',async()=>{
  await expect(registerStrykerFreshRecorder('vitest-5.1.0/async-before-stack-rewrite')).rejects.toThrow(/exact derived SDK/);
  const {runInThisContext}=await import('node:vm');
  globalThis.__udOriginalRegistration=registerStrykerFreshRecorder;
  try{await expect(runInThisContext('globalThis.__udOriginalRegistration("chai-6.3.0/Assertion.prototype.assert")\n//# sourceURL='+createRequire(import.meta.url).resolve('chai'))).rejects.toThrow(/exact derived SDK/);}finally{delete globalThis.__udOriginalRegistration;}
});

test('native constructor and fresh SDK captures ignore producer stack overwrites and hostile formatter output',async()=>fixture(async({verify,asyncCurrent,invokePrivateSdk})=>{
  const errors=invokePrivateSdk(['node-direct','node-production','expect-sync','expect-resolves','expect-rejects','expect-wrong-resolves','expect-wrong-rejects','forged-custom'],{formatter:true});
  for(const mode of Object.keys(errors)){
    const error=errors[mode];expect(error.stack,mode).toBe('adversarial formatter output');
    expect(error.assertion_capture,mode).toBeDefined();
    const proof=verify(asyncCurrent,error);expect(proof.valid,mode+': '+proof.reason).toBe((mode==='node-direct'||mode.startsWith('expect-')));
    if(mode==='node-production'||mode==='forged-custom')expect(proof.reason).toContain('production/foreign');
  }
}));

test('native compiled inventories replay exact bodies and reject native hashes detached from source',async()=>fixture(async({root,inventory,compiledSources})=>{
  expect(compiledSources.entries.length).toBeGreaterThan(0);
  const current=structuredClone(compiledSources);for(const entry of current.entries)delete entry.compiled_source;
  expect(verifyCompiledSources(compiledSources,current,{sourceRoot:root,sourceInventory:inventory})).toBe(true);
  for(const edit of [value=>value.entries[0].native_hash='0'.repeat(64),value=>value.entries[0].compiled_sha256='0'.repeat(64),value=>value.entries[0].identity_sha256='0'.repeat(64),value=>value.entries[0].source_sha256='0'.repeat(64),value=>value.entries.push(value.entries[0])]){
    const changed=structuredClone(current);edit(changed);expect(()=>verifyCompiledSources(compiledSources,changed,{sourceRoot:root,sourceInventory:inventory})).toThrow(/compiled|compilation/);
  }
  const missing=structuredClone(compiledSources);delete missing.entries[0].compiled_source;expect(()=>verifyCompiledSources(missing,current,{sourceRoot:root,sourceInventory:inventory})).toThrow(/compiled|program/);
  const foreign=structuredClone(current);foreign.child_root='/another/authenticated/job';foreign.entries[0].identity_sha256='f'.repeat(64);expect(()=>verifyCompiledSources(compiledSources,foreign,{sourceRoot:root,sourceInventory:inventory})).toThrow(/pristine/);
}));
test('sourceURL and matching sourcesContent cannot admit a second forged compiled test program',async()=>fixture(async({root,source,inventory})=>{
  const {runInThisContext}=await import('node:vm');
  const map={version:3,sources:['calibration.mjs'],sourcesContent:[source],names:[],mappings:'AAAA'},script='void 0;\n//# sourceURL='+path.join(root,'tests/calibration.mjs')+'\n//# sourceMappingURL=data:application/json;base64,'+Buffer.from(JSON.stringify(map)).toString('base64');
  runInThisContext(script);
  expect(()=>exportCompiledSources({sourceRoot:root,sourceInventory:inventory,includeSources:true})).toThrow('multiple native compiled programs');
}));
test('native mapped assertion locations reject changed maps, missing pristine compilation and raw unattested claims',async()=>fixture(async({verify,current,invoke,root,inventory,compiledSources})=>{
  const error=captureStrykerError(invoke('node'));expect(verify(current,error).valid).toBe(true);
  const raw={...error};delete raw.assertion_capture;expect(verify(current,raw)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('authenticated')}));
  const missing=await createStrykerAssertionVerifier({sourceRoot:root,childRoot:root,sourceInventory:inventory});expect(missing(current,error)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('pristine compilation')}));
  const changed=structuredClone(error),capture=changed.assertion_capture;capture.error.compiled_frames[0].mapped_line++;const{capture_sha256,...record}=capture;capture.capture_sha256=sha(JSON.stringify(record));
  expect(verify(current,changed)).toEqual(expect.objectContaining({valid:false,reason:expect.stringContaining('mapped position')}));
}));

test('pinned Vitest flatted cache metadata rebases only authenticated roots and preserves every non-root change',async()=>fixture(async({root,inventory,compiledSources})=>{
  const normalized=value=>value.replaceAll('\\','/');
  const current=structuredClone(compiledSources),next=normalized(path.resolve(path.parse(root).root,'tmp/ud-mutation-jobs','c'.repeat(32),'tree')),aliases=[root,await import('node:fs').then(module=>module.realpathSync(root))].map(normalized).sort((a,b)=>b.length-a.length),replace=value=>{if(typeof value==='string'){for(const alias of aliases)value=value.replaceAll(alias+'/',next+'/');return value;}if(Array.isArray(value))return value.map(replace);if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,replace(item)]));return value;};
  expect(current.entries.some(entry=>entry.compiled_source.includes('//# vitestCache='))).toBe(true);current.child_root=next;
  const patch=(text,transform)=>text.replace(/^\/\/# vitestCache=([^\r\n]+)$/m,(_all,encoded)=>'//# vitestCache='+Buffer.from(JSON.stringify(transform(JSON.parse(Buffer.from(encoded,'base64').toString())))).toString('base64'));
  for(const entry of current.entries){let source=entry.compiled_source.replace(/^\/\/# sourceMappingURL=data:application\/json;base64,([^\r\n]+)$/m,(_all,encoded)=>'//# sourceMappingURL=data:application/json;base64,'+Buffer.from(JSON.stringify(replace(JSON.parse(Buffer.from(encoded,'base64').toString())))).toString('base64'));source=patch(source,replace);source=replace(source);entry.compiled_source=source;entry.native_hash=entry.compiled_sha256=sha(source);}
  expect(verifyCompiledSources(compiledSources,current,{sourceRoot:root,sourceInventory:inventory})).toBe(true);
  const mutate=(change)=>{const candidate=structuredClone(current),entry=candidate.entries.find(entry=>entry.compiled_source.includes('//# vitestCache='));entry.compiled_source=change(entry.compiled_source);entry.native_hash=entry.compiled_sha256=sha(entry.compiled_source);return candidate;};
  const changed=mutate(source=>patch(source,graph=>{graph[0].hasCoverageData=!graph[0].hasCoverageData;return graph;}));expect(()=>verifyCompiledSources(compiledSources,changed,{sourceRoot:root,sourceInventory:inventory})).toThrow(/compiled|pristine/);
  const program=mutate(source=>';void 0;'+source);expect(()=>verifyCompiledSources(compiledSources,program,{sourceRoot:root,sourceInventory:inventory})).toThrow(/compiled|pristine/);
  for(const change of [
    source=>source.replace('//# vitestCache=','//# vitestCache=!'),
    source=>source.replace(/^\/\/# vitestCache=([^\r\n]+)$/m,match=>match+'\n'+match),
    source=>patch(source,graph=>{graph[0].file='0';return graph;}),
    source=>patch(source,graph=>{graph.push('unreferenced');return graph;}),
    source=>patch(source,graph=>{graph[0].foreign=true;return graph;}),
    source=>patch(source,graph=>{graph[0].imports='01';return graph;}),
  ])expect(()=>verifyCompiledSources(compiledSources,mutate(change),{sourceRoot:root,sourceInventory:inventory})).toThrow(/cache/);
}));
