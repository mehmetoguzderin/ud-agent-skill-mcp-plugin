/** Exact derivation of the frozen quality SDK; never edit shared node_modules. */
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';

const sha=value=>createHash('sha256').update(value).digest('hex');
const FROZEN_CAPTURE_MODULE='/opt/mutation/harness/stryker-assertions.mjs';
export const STRYKER_ASSERTION_SDK_FILE='vitest/dist/chunks/index.CZzC1gGg.js';
export const STRYKER_ASSERTION_SDK_UPSTREAM_SHA256='abf79e430d545f69e3a732e816e0d3d3fc26c6bb56e29aa9337102ee673d02a1';
export const STRYKER_ASSERTION_SERIALIZER_FILE='vitest/dist/chunks/run.CjdgFZiW.js';
export const STRYKER_ASSERTION_SERIALIZER_UPSTREAM_SHA256='695282581b97d7049132e1097f9c7421931cb00b9308bd533b4f7f709f5fedc3';
const before='\t\t\t\t}).catch((err) => {\n\t\t\t\t\tif (isError(err) && error.stack) err.stack = error.stack.replace(error.message, err.message);';
const after='\t\t\t\t}).catch((err) => {\n\t\t\t\t\t__udRecordStrykerAsyncError(err);\n\t\t\t\t\tif (isError(err) && error.stack) err.stack = error.stack.replace(error.message, err.message);';

export const STRYKER_ASSERTION_CHAI_FILE='chai/index.js';
export const STRYKER_ASSERTION_CHAI_UPSTREAM_SHA256='89e5418f06b7871fadf9230618d78a7eb352c62840fd576b51db3509ccb96a1f';
const freshAsyncA='\t\t\t\t\t_error.cause = err;\n\t\t\t\t\tthrow _error;';
const freshAsyncANext='\t\t\t\t\t_error.cause = err;\n\t\t\t\t\tthrow __udCaptureFreshAsync(_error);';
const freshAsyncB='\t\t\t\t\tthrow new AssertionError(`promise resolved "${utils.inspect(value)}" instead of rejecting`, {\n\t\t\t\t\t\tshowDiff: true,\n\t\t\t\t\t\texpected: /* @__PURE__ */ new Error("rejected promise"),\n\t\t\t\t\t\tactual: value\n\t\t\t\t\t});';
const freshAsyncBNext=freshAsyncB.replace('throw new AssertionError(', 'throw __udCaptureFreshAsync(new AssertionError(').replace('});','}));');
const freshChai='      throw new AssertionError(\n        msg,\n        assertionErrorObjectProperties,\n        config.includeStack ? this.assert : flag(this, "ssfi")\n      );';
const freshChaiNext=freshChai.replace('throw new AssertionError(', 'throw __udCaptureFreshChai(new AssertionError(').replace('      );','      ));');
const freshHeader=(moduleUrl,boundary,name)=>`import { registerStrykerFreshRecorder as __udRegisterStrykerFreshRecorder } from ${JSON.stringify(moduleUrl)};\nconst ${name} = await __udRegisterStrykerFreshRecorder(${JSON.stringify(boundary)});\n`+(name==='__udCaptureFreshAsync'?'const __udCaptureFreshAsyncSite = __udCaptureFreshAsync;\nconst __udBindAsyncAssertionSite = __udCaptureFreshAsync;\n':'');
const freshSpecs={
  'vitest-5.1.0/async-before-stack-rewrite':{hash:STRYKER_ASSERTION_SDK_UPSTREAM_SHA256,name:'__udCaptureFreshAsync',names:{__udCaptureFreshAsync:'fresh',__udCaptureFreshAsyncSite:'site',__udBindAsyncAssertionSite:'bind'},patches:[[freshAsyncA,freshAsyncANext],[freshAsyncB,freshAsyncBNext],['const error = /* @__PURE__ */ new Error("resolves");','const error = /* @__PURE__ */ __udCaptureFreshAsyncSite(new Error("resolves"));'],['const error = /* @__PURE__ */ new Error("rejects");','const error = /* @__PURE__ */ __udCaptureFreshAsyncSite(new Error("rejects"));'],[before,before.replace('if (isError(err)', '__udBindAsyncAssertionSite(err, error);\n\t\t\t\t\tif (isError(err)'),2]]},
  'chai-6.3.0/Assertion.prototype.assert':{hash:STRYKER_ASSERTION_CHAI_UPSTREAM_SHA256,name:'__udCaptureFreshChai',names:{__udCaptureFreshChai:'fresh'},patches:[[freshChai,freshChaiNext]]},
};
function freshProgram(source,boundary,moduleUrl){
  const spec=freshSpecs[boundary];if(!spec)throw new Error('Unknown fresh assertion boundary.');
  let result=source;
  for(const[from,to,count=1]of spec.patches){if(result.split(from).length!==count+1)throw new Error('Pinned fresh assertion construction is absent or ambiguous: '+JSON.stringify({sha256:sha(from),expected:count,actual:result.split(from).length-1}));result=result.replaceAll(from,to);}
  return freshHeader(moduleUrl,boundary,spec.name)+result;
}
/** Authenticate the actual compiled script, never its claimed URL or stack. */
export function verifyStrykerFreshScript(source,boundary,{captureModule}={}){
  const spec=freshSpecs[boundary];if(!spec||typeof source!=='string'||Buffer.byteLength(source)>1024**2||typeof captureModule!=='string')throw new Error('Fresh assertion script contract is invalid.');
  const header=freshHeader(captureModule,boundary,spec.name);if(!source.startsWith(header))throw new Error('Fresh assertion registration is not from the exact derived SDK.');
  let original=source.slice(header.length);
  for(const[from,to,count=1]of spec.patches){if(original.split(to).length!==count+1)throw new Error('Fresh assertion SDK body is incomplete.');original=original.replaceAll(to,from);}
  if(sha(original)!==spec.hash||freshProgram(original,boundary,captureModule)!==source)throw new Error('Fresh assertion compiled source differs from frozen upstream derivation.');
  const positions=[];
  for(const[name,kind]of Object.entries(spec.names)){let offset=0;while((offset=source.indexOf(name+'(',offset))!==-1){const prior=source.slice(0,offset).split('\n');positions.push({line:prior.length,column:prior.at(-1).length+1,kind});offset+=name.length+1;}}
  if(positions.length!==spec.patches.reduce((total,patch)=>total+(patch[2]??1),0))throw new Error('Fresh assertion SDK has an unexpected recorder call.');
  positions.sort((a,b)=>a.line-b.line||a.column-b.column);
  return {script_sha256:sha(source),positions};
}

/** This transform is pure. The builder supplies a new private SDK copy and
 * persists both returned original bytes and the full derivation receipt.
 */
export function deriveStrykerAssertionSdk(original,{captureModule=FROZEN_CAPTURE_MODULE,serializerOriginal,chaiOriginal}={}){
  if(!Buffer.isBuffer(original)||original.length>1024*1024||sha(original)!==STRYKER_ASSERTION_SDK_UPSTREAM_SHA256)throw new Error('Assertion SDK upstream bytes differ from the frozen Vitest5.1.0 source.');
  if(typeof captureModule!=='string'||captureModule!==FROZEN_CAPTURE_MODULE&&!path.isAbsolute(captureModule)||/[\0\r\n]/.test(captureModule)||path.basename(captureModule)!=='stryker-assertions.mjs')throw new Error('Assertion SDK capture module must be the explicit fixed harness module.');
  const source=new TextDecoder('utf-8',{fatal:true}).decode(original),positions=[];let cursor=0;
  while((cursor=source.indexOf(before,cursor))!==-1){positions.push(cursor);cursor+=before.length;}
  if(positions.length!==2||source.includes('__udRecordStrykerAsyncError'))throw new Error('Pinned Vitest async rewrite boundaries are absent, duplicated or already derived.');
  const moduleUrl=captureModule===FROZEN_CAPTURE_MODULE?'file:///opt/mutation/harness/stryker-assertions.mjs':pathToFileURL(captureModule).href,importLine=`import { recordStrykerAsyncError as __udRecordStrykerAsyncError } from ${JSON.stringify(moduleUrl)};\n`;
  let derived=Buffer.from(importLine+source.replaceAll(before,after));
  const recipe={version:'ud-vitest-async-origin-1',package:{name:'vitest',version:'5.1.0'},path:STRYKER_ASSERTION_SDK_FILE,capture_module:moduleUrl,
    insertion:{position:0,bytes:Buffer.byteLength(importLine),sha256:sha(importLine)},boundaries:positions.map(start=>({start,end:start+before.length,before_sha256:sha(before),after_sha256:sha(after)}))};
  let serializerDerived,serializer;
  if(serializerOriginal!==undefined){
    if(!Buffer.isBuffer(serializerOriginal)||serializerOriginal.length>1024**2||sha(serializerOriginal)!==STRYKER_ASSERTION_SERIALIZER_UPSTREAM_SHA256)throw new Error('Assertion SDK serializer upstream bytes differ from the frozen Vitest5.1.0 source.');
    const text=new TextDecoder('utf-8',{fatal:true}).decode(serializerOriginal),from='\t\treturn serializeValue(err);',to='\t\treturn __udSerializeStrykerAssertionOrigin(err, serializeValue(err));';
    if(text.split(from).length!==2)throw new Error('Pinned Vitest original-error serialization boundary changed.');
    const header=`import { serializeStrykerAssertionOrigin as __udSerializeStrykerAssertionOrigin } from ${JSON.stringify(moduleUrl)};\n`;
    serializerDerived=Buffer.from(header+text.replace(from,to));
    recipe.version='ud-vitest-assertion-origin-2';recipe.serializer={path:STRYKER_ASSERTION_SERIALIZER_FILE,insertion:{position:0,bytes:Buffer.byteLength(header),sha256:sha(header)},boundary:{start:text.indexOf(from),end:text.indexOf(from)+from.length,before_sha256:sha(from),after_sha256:sha(to)}};
    serializer={original:{sha256:sha(serializerOriginal),size_bytes:serializerOriginal.length},derived:{sha256:sha(serializerDerived),size_bytes:serializerDerived.length}};
  }
  let chaiDerived,chai;
  if(chaiOriginal!==undefined){
    if(serializerOriginal===undefined||!Buffer.isBuffer(chaiOriginal)||chaiOriginal.length>1024**2||sha(chaiOriginal)!==STRYKER_ASSERTION_CHAI_UPSTREAM_SHA256)throw new Error('Assertion SDK Chai upstream bytes differ from the frozen source.');
    derived=Buffer.from(freshProgram(source,'vitest-5.1.0/async-before-stack-rewrite',moduleUrl));
    const chaiText=new TextDecoder('utf-8',{fatal:true}).decode(chaiOriginal);
    chaiDerived=Buffer.from(freshProgram(chaiText,'chai-6.3.0/Assertion.prototype.assert',moduleUrl));
    chai={original:{sha256:sha(chaiOriginal),size_bytes:chaiOriginal.length},derived:{sha256:sha(chaiDerived),size_bytes:chaiDerived.length}};
    recipe.version='ud-vitest-assertion-origin-4';delete recipe.insertion;delete recipe.boundaries;
    recipe.fresh_async={boundary:'vitest-5.1.0/async-before-stack-rewrite',...verifyStrykerFreshScript(derived.toString(),'vitest-5.1.0/async-before-stack-rewrite',{captureModule:moduleUrl})};
    recipe.chai={path:STRYKER_ASSERTION_CHAI_FILE,boundary:'chai-6.3.0/Assertion.prototype.assert',...verifyStrykerFreshScript(chaiDerived.toString(),'chai-6.3.0/Assertion.prototype.assert',{captureModule:moduleUrl})};
  }
  return {original:Buffer.from(original),derived,...(chai?{chaiOriginal:Buffer.from(chaiOriginal),chaiDerived}:{}),...(serializer?{serializerOriginal:Buffer.from(serializerOriginal),serializerDerived}:{}),receipt:{schema_version:chai?3:serializer?2:1,qualification:'quality-sdk-derived-assertion-origin',recipe,recipe_sha256:sha(JSON.stringify(recipe)),
    original:{sha256:sha(original),size_bytes:original.length},derived:{sha256:sha(derived),size_bytes:derived.length},...(serializer?{serializer}:{}),...(chai?{chai}:{})}};
}

/** Replay all declared derivation details against retained original bytes. */
export function verifyStrykerAssertionSdk(original,derived,receipt,{captureModule=FROZEN_CAPTURE_MODULE,serializerOriginal,serializerDerived,chaiOriginal,chaiDerived}={}){
  const expected=deriveStrykerAssertionSdk(original,{captureModule,...(serializerOriginal===undefined?{}:{serializerOriginal}),...(chaiOriginal===undefined?{}:{chaiOriginal})});
  if(!Buffer.isBuffer(derived)||!expected.derived.equals(derived)||JSON.stringify(receipt)!==JSON.stringify(expected.receipt))throw new Error('Assertion SDK derivation is stale, incomplete or forged.');
  if(expected.serializerDerived&&(!Buffer.isBuffer(serializerDerived)||!expected.serializerDerived.equals(serializerDerived)))throw new Error('Assertion SDK serializer derivation is stale, incomplete or forged.');
  if(expected.chaiDerived&&(!Buffer.isBuffer(chaiDerived)||!expected.chaiDerived.equals(chaiDerived)))throw new Error('Assertion SDK Chai derivation is stale, incomplete or forged.');
  return expected.receipt;
}

/** The verified upstream npm closure may differ at exactly the derived chunk.
 * All package metadata, other bytes, modes and link identities stay identical.
 */
export function verifyStrykerAssertionSdkClosure(upstream,derived,receipt){
  const validate=value=>{
    if(!value||Object.keys(value).sort().join(',')!=='files,links,schema_version'||value.schema_version!==1||!Array.isArray(value.files)||!Array.isArray(value.links)||!value.files.length||value.files.length+value.links.length>200000)throw new Error('Assertion SDK closure inventory is incomplete.');
    const seen=new Set();
    for(const row of [...value.files,...value.links]){
      if(!row||typeof row.path!=='string'||!row.path||/[\\\0:]/.test(row.path)||row.path.startsWith('/')||row.path.split('/').some(part=>!part||part==='.'||part==='..')||seen.has(row.path))throw new Error('Assertion SDK closure path is invalid or duplicated.');
      seen.add(row.path);
    }
    for(const row of value.files)if(Object.keys(row).sort().join(',')!=='mode,path,sha256,size'||!/^[a-f0-9]{64}$/.test(row.sha256??'')||!Number.isSafeInteger(row.size)||row.size<0||!Number.isSafeInteger(row.mode)||row.mode<0||row.mode>0o777||(row.mode&0o222)!==0)throw new Error('Assertion SDK file inventory is invalid.');
    for(const row of value.links)if(Object.keys(row).sort().join(',')!=='path,target'||typeof row.target!=='string'||!row.target||row.target.startsWith('/')||/[\\\0]/.test(row.target))throw new Error('Assertion SDK link inventory is invalid.');
  };
  validate(upstream);validate(derived);
  if(!receipt||![1,2,3].includes(receipt.schema_version)||receipt.recipe?.path!==STRYKER_ASSERTION_SDK_FILE||JSON.stringify(upstream.links)!==JSON.stringify(derived.links)||upstream.files.length!==derived.files.length)throw new Error('Assertion SDK derivation changed unrelated dependency closure.');
  const changed=new Map([[STRYKER_ASSERTION_SDK_FILE,{original:receipt.original,derived:receipt.derived}]]);
  if(receipt.schema_version>=2){if(receipt.recipe.serializer?.path!==STRYKER_ASSERTION_SERIALIZER_FILE||!receipt.serializer)throw new Error('Assertion SDK serializer derivation is missing.');changed.set(STRYKER_ASSERTION_SERIALIZER_FILE,receipt.serializer);}
  if(receipt.schema_version===3){if(receipt.recipe.chai?.path!==STRYKER_ASSERTION_CHAI_FILE||!receipt.chai)throw new Error('Assertion SDK Chai derivation is missing.');changed.set(STRYKER_ASSERTION_CHAI_FILE,receipt.chai);}
  let changes=0;
  for(let index=0;index<upstream.files.length;index++){
    const before=upstream.files[index],after=derived.files[index];
    if(before.path!==after.path||before.mode!==after.mode)throw new Error('Assertion SDK derivation changed dependency paths or modes.');
    if(changed.has(before.path)){
      changes++;
      const selected=changed.get(before.path);
      if(before.sha256!==selected.original.sha256||before.size!==selected.original.size_bytes||after.sha256!==selected.derived.sha256||after.size!==selected.derived.size_bytes||before.sha256===after.sha256)throw new Error('Assertion SDK derived chunk differs from its exact receipt.');
    }else if(JSON.stringify(before)!==JSON.stringify(after))throw new Error('Assertion SDK derivation changed unrelated dependency bytes.');
  }
  if(changes!==changed.size)throw new Error('Assertion SDK derived chunk is missing from the complete closure.');
  return true;
}

// CLI materializes only inside one builder-owned context: node_modules is a
// direct ordinary child of that context, never an arbitrary external target.
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const {constants,lstatSync,openSync,closeSync,fstatSync,fchmodSync,ftruncateSync,fsyncSync,readFileSync,writeFileSync,writeSync}=await import('node:fs');
  if(process.argv.length!==3)throw new Error('Usage: stryker-assertion-sdk.mjs NEW_PREPARED_CONTEXT');
  const root=path.resolve(process.argv[2]),rootInfo=lstatSync(root),modules=path.join(root,'node_modules'),info=lstatSync(modules);
  if(rootInfo.isSymbolicLink()||!rootInfo.isDirectory()||info.isSymbolicLink()||!info.isDirectory()||typeof process.getuid==='function'&&(rootInfo.uid!==process.getuid()||info.uid!==process.getuid()))throw new Error('Assertion SDK builder context is not an owned ordinary directory.');
  const provenanceFile=path.join(root,'node-installation-receipt.json'),provenanceInfo=lstatSync(provenanceFile);
  if(!provenanceInfo.isFile()||provenanceInfo.isSymbolicLink()||provenanceInfo.nlink!==1||provenanceInfo.size>1024*1024||JSON.parse(readFileSync(provenanceFile)).qualification!=='locked-native-sdk-data-preparation-no-lifecycle-execution')throw new Error('Assertion SDK builder lacks the retained original installation provenance.');
  const owned=stat=>typeof process.getuid!=='function'||stat.uid===process.getuid();
  const openSource=(relative,flags)=>{
    let parent=modules;
    for(const part of relative.split('/').slice(0,-1)){
      parent=path.join(parent,part);const stat=lstatSync(parent);
      if(stat.isSymbolicLink()||!stat.isDirectory()||!owned(stat))throw new Error('Assertion SDK source parent is not an owned ordinary directory.');
    }
    const file=path.join(modules,relative),expected=lstatSync(file);
    if(expected.isSymbolicLink()||!expected.isFile())throw new Error('Assertion SDK source is not an owned ordinary bounded single-link file.');
    const fd=openSync(file,flags|constants.O_NOFOLLOW);
    try{
      const stat=fstatSync(fd);
      if(!stat.isFile()||stat.nlink!==1||stat.size>1024*1024||!owned(stat)||(stat.mode&0o7000)!==0||stat.dev!==expected.dev||stat.ino!==expected.ino)throw new Error('Assertion SDK source is not an owned ordinary bounded single-link file.');
      return {fd,stat};
    }catch(error){closeSync(fd);throw error;}
  };
  const sourceBytes=relative=>{const {fd}=openSource(relative,constants.O_RDONLY);try{return readFileSync(fd);}finally{closeSync(fd);}};
  const rewriteSource=(relative,original,derived)=>{
    const held=openSource(relative,constants.O_RDONLY),mode=held.stat.mode&0o777;let writable,changedMode=false;
    try{
      if(!readFileSync(held.fd).equals(original))throw new Error('Assertion SDK source changed before derivation.');
      // Frozen upstream copies can be mode 0444. Temporarily permit writes to
      // this authenticated owned inode, never to shared package source paths.
      fchmodSync(held.fd,mode|0o200);changedMode=true;
      writable=openSource(relative,constants.O_RDWR);
      if(writable.stat.dev!==held.stat.dev||writable.stat.ino!==held.stat.ino||writable.stat.uid!==held.stat.uid||!readFileSync(writable.fd).equals(original))throw new Error('Assertion SDK source identity changed before derivation.');
      // Do not truncate through a pathname before its inode has been checked.
      let offset=0;while(offset<derived.length){const written=writeSync(writable.fd,derived,offset,derived.length-offset,offset);if(written===0)throw new Error('Assertion SDK derivation write made no progress.');offset+=written;}
      ftruncateSync(writable.fd,derived.length);fsyncSync(writable.fd);
    }finally{
      try{if(changedMode)fchmodSync(held.fd,mode);}finally{try{if(writable)closeSync(writable.fd);}finally{closeSync(held.fd);}}
    }
  };
  const file=path.join(modules,STRYKER_ASSERTION_SDK_FILE),serializerFile=path.join(modules,STRYKER_ASSERTION_SERIALIZER_FILE),chaiFile=path.join(modules,STRYKER_ASSERTION_CHAI_FILE),output=deriveStrykerAssertionSdk(sourceBytes(STRYKER_ASSERTION_SDK_FILE),{serializerOriginal:sourceBytes(STRYKER_ASSERTION_SERIALIZER_FILE),chaiOriginal:sourceBytes(STRYKER_ASSERTION_CHAI_FILE)});
  writeFileSync(path.join(root,'node-assertion-sdk-upstream.js'),output.original,{flag:'wx',mode:0o444});
  writeFileSync(path.join(root,'node-assertion-sdk-serializer-upstream.js'),output.serializerOriginal,{flag:'wx',mode:0o444});
  writeFileSync(path.join(root,'node-assertion-sdk-chai-upstream.js'),output.chaiOriginal,{flag:'wx',mode:0o444});
  writeFileSync(path.join(root,'node-assertion-sdk.json'),JSON.stringify(output.receipt,null,2)+'\n',{flag:'wx',mode:0o444});
  // The context is unpublished and private; derive exactly this copied file.
  rewriteSource(STRYKER_ASSERTION_SDK_FILE,output.original,output.derived);
  rewriteSource(STRYKER_ASSERTION_SERIALIZER_FILE,output.serializerOriginal,output.serializerDerived);
  rewriteSource(STRYKER_ASSERTION_CHAI_FILE,output.chaiOriginal,output.chaiDerived);
  verifyStrykerAssertionSdk(readFileSync(path.join(root,'node-assertion-sdk-upstream.js')),readFileSync(file),JSON.parse(readFileSync(path.join(root,'node-assertion-sdk.json'))),{serializerOriginal:readFileSync(path.join(root,'node-assertion-sdk-serializer-upstream.js')),serializerDerived:readFileSync(serializerFile),chaiOriginal:readFileSync(path.join(root,'node-assertion-sdk-chai-upstream.js')),chaiDerived:readFileSync(chaiFile)});
}
