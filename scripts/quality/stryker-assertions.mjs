/** Bind an assertion to immutable test syntax and its actual case callback. */
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {closeSync,constants,fstatSync,lstatSync,openSync,readFileSync,realpathSync} from 'node:fs';
import path from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {getCallSites as nativeCallSites} from 'node:util';
import {Session as NativeInspectorSession} from 'node:inspector';
import {runInNewContext as nativeRunInNewContext} from 'node:vm';
import {parse as parseCompiledJavaScript} from '@babel/parser';
import {parseTree as parseJsonTree} from 'jsonc-parser';
import {TraceMap,originalPositionFor} from '@jridgewell/trace-mapping';
import {verifyStrykerFreshScript} from './stryker-assertion-sdk.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const HASH=/^[a-f0-9]{64}$/;
const MAX_STACK=1024*1024;
const assertNames=new Set(['ok','fail','equal','notEqual','strictEqual','notStrictEqual','deepEqual','notDeepEqual','deepStrictEqual','notDeepStrictEqual','partialDeepStrictEqual','throws','doesNotThrow','rejects','doesNotReject','ifError','match','doesNotMatch']);
const testModifiers=new Set(['each','for','concurrent','sequential','skipIf','runIf','only','skip','todo','fails','extend','scoped']);
const normalize=value=>value.replaceAll('\\','/').replace(/\/$/,'');
const confined=value=>typeof value==='string'&&value.startsWith('tests/')&&!/[\\\0:]/.test(value)&&!value.split('/').some(part=>!part||part==='.'||part==='..');
const isAssertion=error=>error&&typeof error==='object'&&!Array.isArray(error)&&['AssertionError','AssertionError [ERR_ASSERTION]','VitestAssertionError'].includes(error.name)&&(error.code===undefined||error.code===null||error.code==='ERR_ASSERTION');
class ProvenanceError extends Error {}
const capturedOrigins=new WeakMap();
const ORIGIN_PROPERTY='ud_stryker_assertion_origin';
const ORIGIN_BOUNDARY='chai-6.3.0/Assertion.prototype.assert';
const ASYNC_ORIGIN_BOUNDARY='vitest-5.1.0/async-before-stack-rewrite';
const NODE_ORIGIN_BOUNDARY='node/assertion_error/fresh-constructor';
// Official v26.13.0 Windows ARM64/x64 node.exe binaries embed the CRLF bytes;
// Unix releases embed LF. Both complete sources are pinned, never normalized.
const NODE_CONSTRUCTORS=new Map([
  ['41ebb0538f7707b144042ea4ac1085db1268751f8a727760f09fb06d720e6ba4',{size:14267,anchor:'    this.stack; // eslint-disable-line no-unused-expressions'}],
  ['39da8256911db75f861e8203fc78044e5a9bb48e3da15d7d5e1274e61aa0aaaa',{size:14689,anchor:'    this.stack; // eslint-disable-line no-unused-expressions\r'}],
]);
const pendingFresh=new WeakMap(),nativeStackOrigins=new WeakMap(),asyncSiteOrigins=new WeakMap();
let nativeStackHook,nativeDefaultFormatter,nativeErrorToString,nodeConstructorScript,compiledContext;
const initialFormatter=Error.prepareStackTrace;
const initialNativeFormatter=typeof initialFormatter==='function'&&Function.prototype.toString.call(initialFormatter)==='function ErrorPrepareStackTrace(error, trace) {\n  return internalPrepareStackTrace(error, trace);\n}'?initialFormatter:null;
let sourceInspector;const nativeScripts=new Map(),compiledScriptCache=new Map(),compiledContexts=new Map();
let captureInstalled;

function stackRecord(error,override){
  const stack=override??(typeof error?.stack==='string'?error.stack:typeof error?.stackStr==='string'?error.stackStr:null);
  const message=typeof error?.message==='string'?error.message:'';
  return {name:typeof error?.name==='string'?error.name:null,code:error?.code??null,message:message.slice(0,4096),message_sha256:sha(message),message_bytes:Buffer.byteLength(message),message_truncated:message.length>4096,
    stack:stack!==null&&Buffer.byteLength(stack)<=MAX_STACK?stack:null,stack_sha256:stack===null?null:sha(stack),stack_bytes:stack===null?0:Buffer.byteLength(stack),stack_truncated:stack!==null&&Buffer.byteLength(stack)>MAX_STACK};
}

function recordOrigin(error,boundary,construction){
  if(!isAssertion(error)||capturedOrigins.has(error))return;
  if(!nativeStackOrigins.has(error))void error.stack;
  const pristine=nativeStackOrigins.get(error);if(!pristine)return;
  const record={schema_version:2,boundary,construction,error:pristine};
  const evidence=Object.freeze({...record,capture_sha256:sha(JSON.stringify(record))});
  capturedOrigins.set(error,evidence);

}

/** Legacy callers cannot adopt a caught exception. SDK3 captures only a new
 * assertion at an authenticated constructor call, before any caller sees it.
 */
export function recordStrykerAsyncError(_error){}

function inspector(){
  if(!sourceInspector){
    sourceInspector=new NativeInspectorSession();sourceInspector.connect();sourceInspector.on('Debugger.scriptParsed',({params})=>{if(params.hash){const values=nativeScripts.get(params.hash)??[];values.push({id:params.scriptId,url:params.url});nativeScripts.set(params.hash,values);}});
    let failed,complete=false;sourceInspector.post('Debugger.enable',{},error=>{failed=error;complete=true;});if(failed||!complete)throw failed??new Error('Native debugger inventory did not initialize synchronously.');
  }
  return sourceInspector;
}
function originalCompiledSource(scriptId){
  if(compiledScriptCache.has(scriptId))return compiledScriptCache.get(scriptId);
  let source,failure,complete=false;inspector().post('Debugger.getScriptSource',{scriptId},(error,result)=>{failure=error;source=result?.scriptSource;complete=true;});
  if(failure)throw failure;if(!complete||typeof source!=='string'||Buffer.byteLength(source)>16*1024**2)throw new Error('Native compiled script is unavailable or exceeds its bound.');compiledScriptCache.set(scriptId,source);return source;
}
function configureCompiledContext({sourceRoot,sourceInventory}={}){
  if(sourceRoot===undefined&&sourceInventory===undefined)return;
  if(typeof sourceRoot!=='string'||!path.isAbsolute(sourceRoot)||!sourceInventory||typeof sourceInventory!=='object'||Array.isArray(sourceInventory)||Object.entries(sourceInventory).some(([name,hash])=>!confined(name)||!HASH.test(hash)))throw new ProvenanceError('Native compiled sources require the frozen test/helper inventory.');
  compiledContext={root:normalize(realpathSync(sourceRoot)),supplied:normalize(sourceRoot),inventory:{...sourceInventory}};const key=compiledContext.root;const previous=compiledContexts.get(key);if(previous&&JSON.stringify(previous.inventory)!==JSON.stringify(compiledContext.inventory))throw new ProvenanceError('A compiled root was reconfigured with another frozen source inventory.');compiledContexts.set(key,compiledContext);inspector();
}
function sourceName(value,context){
  let name=value;try{if(name.startsWith('file:'))name=fileURLToPath(name);}catch{return null;}
  name=normalize(name);
  for(const root of [context.root,context.supplied])if(name.startsWith(root+'/'))return name.slice(root.length+1);
  return null;
}
function replayContext(childRoot,sourceRoot,inventory){let canonical=normalize(childRoot);try{const actual=normalize(realpathSync(childRoot));if(actual===normalize(realpathSync(sourceRoot)))canonical=actual;}catch{}return {root:canonical,supplied:normalize(childRoot),inventory};}
function normalizedRoots(value,context){let result=value;for(const root of [...new Set([context.root,context.supplied])].sort((a,b)=>b.length-a.length))result=result.replaceAll(root+'/','<UD_JOB_ROOT>/');return result;}
export function normalizePinnedCachePath(value,roots){
  for(const prefix of roots){
    const schemes=/^[A-Za-z]:\//.test(prefix)?['','file:///','/@fs/']:['','file://','/@fs'];
    for(const scheme of schemes)if(value.startsWith(scheme+prefix+'/'))return scheme+'<UD_JOB_ROOT>/'+value.slice((scheme+prefix+'/').length);
  }
  return value;
}
function pinnedCacheGraph(text,context,source){
  const errors=[],tree=parseJsonTree(text,errors,{disallowComments:true,allowTrailingComma:false});
  if(errors.length||!tree)throw new ProvenanceError('Pinned Vitest cache JSON is malformed.');
  const check=node=>{if(node.type==='object'){const names=new Set();for(const child of node.children??[]){const name=child.children?.[0]?.value;if(names.has(name))throw new ProvenanceError('Pinned Vitest cache JSON repeats a key.');names.add(name);}}for(const child of node.children??[])check(child);};check(tree);
  const graph=JSON.parse(text);if(!Array.isArray(graph)||graph.length===0||graph.length>200000)throw new ProvenanceError('Pinned Vitest cache graph is not bounded.');
  const visited=new Map(),active=new Set();
  const index=(id,depth=0)=>{
    if(!Number.isSafeInteger(id)||id<0||id>=graph.length||depth>128||active.has(id))throw new ProvenanceError('Pinned Vitest cache graph contains invalid or cyclic references.');
    if(visited.has(id))return visited.get(id);active.add(id);const raw=graph[id];
    const value=item=>typeof item==='string'?(/^0$|^[1-9][0-9]*$/.test(item)?index(Number(item),depth+1):(()=>{throw new ProvenanceError('Pinned Vitest cache graph has a noncanonical reference.');})()):item!==null&&typeof item==='object'?walk(item):item;
    const walk=item=>Array.isArray(item)?item.map(value):Object.fromEntries(Object.entries(item).map(([key,entry])=>[key,value(entry)]));
    const result=raw!==null&&typeof raw==='object'?walk(raw):raw;active.delete(id);visited.set(id,result);return result;
  };
  const metadata=index(0),required=['file','id','imports','mappings','hasCoverageData'],allowed=new Set([...required,'moduleType','deps','dynamicDeps','staticMocks']);
  if(!metadata||typeof metadata!=='object'||Array.isArray(metadata)||Object.keys(metadata).some(key=>!allowed.has(key))||required.some(key=>!Object.hasOwn(metadata,key))||typeof metadata.file!=='string'||typeof metadata.id!=='string'||sourceName(metadata.file,context)!==source||sourceName(metadata.id,context)!==source||typeof metadata.hasCoverageData!=='boolean'||metadata.mappings!==null&&typeof metadata.mappings!=='boolean'||!metadata.imports||typeof metadata.imports!=='object'||Array.isArray(metadata.imports)||Object.keys(metadata.imports).sort().join(',')!=='ids,urls'||!Array.isArray(metadata.imports.urls)||metadata.imports.urls.some(item=>typeof item!=='string')||!metadata.imports.ids||typeof metadata.imports.ids!=='object'||Array.isArray(metadata.imports.ids)||Object.values(metadata.imports.ids).some(item=>typeof item!=='string'))throw new ProvenanceError('Pinned Vitest cache metadata differs from the frozen producer shape.');
  for(const name of ['deps','dynamicDeps'])if(Object.hasOwn(metadata,name)&&metadata[name]!==null&&(!Array.isArray(metadata[name])||metadata[name].some(item=>typeof item!=='string')))throw new ProvenanceError('Pinned Vitest cache dependency inventory is malformed.');
  if(Object.hasOwn(metadata,'moduleType')&&typeof metadata.moduleType!=='string'||Object.hasOwn(metadata,'staticMocks')&&metadata.staticMocks!==null&&typeof metadata.staticMocks!=='object'||visited.size!==graph.length)throw new ProvenanceError('Pinned Vitest cache graph contains unknown data.');
  const normalize=value=>{if(typeof value==='string')return normalizePinnedCachePath(value,[context.root,context.supplied]);if(Array.isArray(value))return value.map(normalize);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,normalize(value[key])]));return value;};
  // Keep every flatted index/reference and array order. Only authenticated
  // path prefixes inside decoded data receive the canonical job-root token.
  return JSON.stringify(normalize(graph));
}

function compiledProgram(compiled,context,source){
  if(typeof compiled!=='string'||Buffer.byteLength(compiled)>16*1024**2)throw new ProvenanceError('Native compiled program exceeds the source bound.');
  const expression=/^\/\/[#@] sourceMappingURL=data:application\/json(?:;charset=utf-8)?;base64,([^\r\n]+)\r?$/gm,matches=[...compiled.matchAll(expression)],last=matches.at(-1);let map=null,body=compiled;const removed=[];
  if(last){
    const raw=Buffer.from(last[1],'base64');if(raw.toString('base64')!==last[1]||raw.length>16*1024**2)throw new ProvenanceError('Native inline source map encoding is invalid.');
    map=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
    if(map?.version!==3||!Array.isArray(map.sources)||!Array.isArray(map.sourcesContent)||map.sources.length!==map.sourcesContent.length||map.sources.length===0||typeof map.mappings!=='string')throw new ProvenanceError('Native source map is incomplete.');
    for(let index=0;index<map.sources.length;index++){
      const declared=map.sources[index];if(typeof declared!=='string'||typeof map.sourcesContent[index]!=='string')throw new ProvenanceError('Native source map omits its original source bytes.');
      const original=path.resolve(path.dirname(path.join(context.root,source)),map.sourceRoot??'',declared),name=sourceName(original,context);
      if(!name||context.inventory[name]!==sha(map.sourcesContent[index]))throw new ProvenanceError('Native source map differs from the frozen test/helper bytes.');
    }
    removed.push({start:last.index,end:last.index+last[0].length});
  }
  let cacheText=null;
  if(compiled.includes('vitestCache')){
    const ast=parseCompiledJavaScript(compiled,{sourceType:'unambiguous'}),comments=(ast.comments??[]).filter(comment=>comment.type==='CommentLine'&&/^#\s*vitestCache/.test(comment.value));
    if(comments.length>1)throw new ProvenanceError('Pinned Vitest cache marker is duplicated.');
    if(comments.length){
      const comment=comments[0],literal=compiled.slice(comment.start,comment.end),match=/^\/\/# vitestCache=([A-Za-z0-9+/]+={0,2})$/.exec(literal);
      if(!match||comment.start===0||compiled[comment.start-1]!=='\n'||!last||comment.start<last.index+last[0].length||!/^\s*\}\}\s*$/.test(compiled.slice(comment.end)))throw new ProvenanceError('Pinned Vitest cache marker has an invalid syntax or location.');
      const bytes=Buffer.from(match[1],'base64');if(bytes.length>16*1024**2||bytes.toString('base64')!==match[1])throw new ProvenanceError('Pinned Vitest cache encoding is invalid.');
      cacheText=pinnedCacheGraph(new TextDecoder('utf-8',{fatal:true}).decode(bytes),context,source);removed.push({start:comment.start,end:comment.end});
    }
  }
  for(const range of removed.sort((a,b)=>b.start-a.start))body=body.slice(0,range.start)+body.slice(range.end);
  const canonical=value=>{if(typeof value==='string')return normalizedRoots(value,context);if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));return value;},mapText=map?JSON.stringify(canonical(map)):null;
  return {map,compiled_sha256:sha(compiled),source_map_sha256:mapText===null?null:sha(mapText),identity_sha256:sha(JSON.stringify(cacheText===null?[normalizedRoots(body,context),mapText]:[normalizedRoots(body,context),mapText,cacheText]))};
}
function compiledEntry(nativeHash,source,context){
  const candidates=nativeScripts.get(nativeHash)??[];if(!candidates.length)throw new ProvenanceError('Native script hash is absent from the engine debugger inventory.');
  const bodies=[...new Set(candidates.map(row=>originalCompiledSource(row.id)))];if(bodies.length!==1)throw new ProvenanceError('Native script hash identifies ambiguous compiled bytes.');
  const compiled=bodies[0],program=compiledProgram(compiled,context,source);if(nativeHash!==program.compiled_sha256)throw new ProvenanceError('Native script hash differs from its actual compiled bytes.');
  if(!program.map&&sha(compiled)!==context.inventory[source])throw new ProvenanceError('Unmapped native test script differs from its frozen source bytes.');
  return {source,source_sha256:context.inventory[source],native_hash:nativeHash,...program,compiled_source:compiled};
}
/** The pristine original job retains actual compiled bytes once. Later jobs
 * report bounded fingerprints; mappings are accepted only against this issue.
 */
export function exportCompiledSources({includeSources=false,sourceRoot,sourceInventory}={}){
  const context=sourceRoot===undefined?compiledContext:{root:normalize(realpathSync(sourceRoot)),supplied:normalize(sourceRoot),inventory:sourceInventory};
  if(!context)throw new ProvenanceError('Native compiled source context was not configured.');inspector();const entries=[],seen=new Map();
  for(const[hash,records]of nativeScripts){const names=new Set(records.map(row=>sourceName(row.url,context)).filter(name=>name&&context.inventory[name]));for(const name of names){const row=compiledEntry(hash,name,context);delete row.map;if(!includeSources)delete row.compiled_source;const previous=seen.get(name);if(previous&&previous.identity_sha256!==row.identity_sha256)throw new ProvenanceError('One frozen test/helper path has multiple native compiled programs.');if(!previous){seen.set(name,row);entries.push(row);}}}
  entries.sort((a,b)=>a.source.localeCompare(b.source));return {schema_version:1,normalization:'ud-job-root-and-inline-map-1',child_root:context.supplied,entries};
}
export function verifyCompiledSources(pristine,current,{sourceRoot,sourceInventory}={}){
  const validate=(value,full)=>{if(!value||value.schema_version!==1||value.normalization!=='ud-job-root-and-inline-map-1'||typeof value.child_root!=='string'||!path.isAbsolute(value.child_root)||!Array.isArray(value.entries)||value.entries.length>100000)throw new ProvenanceError('Native compiled inventory is missing or invalid.');const context=replayContext(value.child_root,sourceRoot,sourceInventory),seen=new Map();for(const entry of value.entries){if(!entry||!confined(entry.source)||entry.source_sha256!==sourceInventory[entry.source]||!HASH.test(entry.native_hash??'')||!HASH.test(entry.compiled_sha256??'')||entry.native_hash!==entry.compiled_sha256||!HASH.test(entry.identity_sha256??'')||entry.source_map_sha256!==null&&!HASH.test(entry.source_map_sha256??'')||seen.has(entry.source))throw new ProvenanceError('Native compiled inventory contains duplicate or unbound source identities.');if(full||entry.compiled_source!==undefined){const program=compiledProgram(entry.compiled_source,context,entry.source);if(program.compiled_sha256!==entry.compiled_sha256||program.identity_sha256!==entry.identity_sha256||program.source_map_sha256!==entry.source_map_sha256)throw new ProvenanceError('Native compiled inventory differs from its retained program bytes.');if(!program.map&&sha(entry.compiled_source)!==entry.source_sha256)throw new ProvenanceError('Unmapped pristine script differs from immutable source.');}seen.set(entry.source,entry);}return seen;};
  if(typeof sourceRoot!=='string'||!sourceInventory||typeof sourceInventory!=='object')throw new ProvenanceError('Native compiled verification needs the frozen source context.');
  const before=validate(pristine,true),after=validate(current,false);for(const[name,row]of after){const expected=before.get(name);if(!expected||expected.source_sha256!==row.source_sha256||expected.identity_sha256!==row.identity_sha256||expected.source_map_sha256!==row.source_map_sha256)throw new ProvenanceError('Current native compilation differs from its pre-outcome pristine program.');}return true;
}
function pristineTrace(error,trace,format){
  const compiled_frames=[],lines=trace.map((site,index)=>{
    const url=site.getFileName()??site.getScriptNameOrSourceURL(),context=typeof url==='string'?[...compiledContexts.values()].sort((a,b)=>b.root.length-a.root.length).find(value=>{const name=sourceName(url,value);return name&&value.inventory[name];}):null,name=context?sourceName(url,context):null;
    if(!context||!name)return format(site);
    const row=compiledEntry(site.getScriptHash(),name,context),line=site.getLineNumber(),column=site.getColumnNumber();let point={source:path.join(context.root,name),line,column};
    if(row.map){const mapped=originalPositionFor(new TraceMap(row.map,pathToFileURL(path.join(context.root,name)).href),{line,column:column-1});if(!mapped.source||mapped.line===null||mapped.column===null)throw new ProvenanceError('Native assertion site is not mapped to an original source position.');point={source:mapped.source,line:mapped.line,column:mapped.column+1};}
    const source=sourceName(point.source,context);if(!source||!context.inventory[source])throw new ProvenanceError('Native assertion map leaves immutable test/helper scope.');
    const {map,...receipt}=row;compiled_frames.push({frame:index,...receipt,native_line:line,native_column:column,mapped_source:source,mapped_line:point.line,mapped_column:point.column});
    const method=site.getFunctionName()??site.getMethodName(),position=`${path.join(context.root,source)}:${point.line}:${point.column}`;return method?`${method} (${position})`:position;
  });
  return {stack:Reflect.apply(nativeErrorToString,error,[])+(lines.length?'\n    at '+lines.join('\n    at '):''),compiled_frames};
}

export function verifyNodeAssertionConstructor(source){
  const digest=typeof source==='string'&&source.length<=14689?sha(source):null,pinned=NODE_CONSTRUCTORS.get(digest);
  if(!pinned||Buffer.byteLength(source)!==pinned.size||source.split('\n')[381]!==pinned.anchor)throw new Error('Native Node assertion constructor differs from its pinned 24/26 source.');
  return Object.freeze({script_sha256:digest,line:382,column:10});
}

function nodeConstruction(frames){
  // Manual formatter invocations and user callback failures have no exact
  // immediate constructor chain and cannot acquire Node assertion authority.
  const callback=frames[1],site=frames[2];
  if(callback?.functionName!=='prepareStackTraceCallback'||callback.scriptName!=='node:internal/errors'||site?.functionName!=='AssertionError'||site.scriptName!=='node:internal/assert/assertion_error'||site.lineNumber!==382||site.columnNumber!==10)return null;
  if(nodeConstructorScript?.script_id!==site.scriptId){
    const source=originalCompiledSource(site.scriptId);
    nodeConstructorScript=Object.freeze({script_id:site.scriptId,...verifyNodeAssertionConstructor(source)});
  }
  return nodeConstructorScript;
}

function installNativeStackCapture(){
  if(Error.prepareStackTrace===nativeStackHook)return;
  // A fresh, empty realm exposes the engine's original formatter even when
  // the surrounding test framework has installed its own formatting function.
  // This literal does not read or execute project source.
  if(!nativeDefaultFormatter){
    const errorToString=nativeRunInNewContext('Error.prototype.toString'),saved=Error.prepareStackTrace;nativeErrorToString=errorToString;let callSiteToString;
    try{Error.prepareStackTrace=(_error,trace)=>{callSiteToString=Object.getPrototypeOf(trace[0]).toString;return '';};void new Error('trusted callsite API calibration').stack;}finally{Error.prepareStackTrace=saved;}
    if(typeof errorToString!=='function'||typeof callSiteToString!=='function')throw new Error('Pinned Node does not expose its pristine stack formatter APIs.');
    nativeDefaultFormatter=(error,trace)=>pristineTrace(error,trace,site=>Reflect.apply(callSiteToString,site,[]));
  }
  const previous=Error.prepareStackTrace;
  nativeStackHook=function prepareVerifiedAssertionStack(error,trace){
    const construction=nodeConstruction(nativeCallSites(4,{sourceMap:false})),fresh=pendingFresh.get(error);
    if((construction||fresh)&&(isAssertion(error)||fresh)&&!nativeStackOrigins.has(error)){
      const pristine=Reflect.apply(nativeDefaultFormatter,Error,[error,trace]);
      if(typeof pristine.stack!=='string')throw new Error('Native assertion formatter returned a non-string stack.');
      const original={...stackRecord(error,pristine.stack),compiled_frames:pristine.compiled_frames};
      if(construction&&original.name==='AssertionError [ERR_ASSERTION]')original.name='AssertionError';
      nativeStackOrigins.set(error,Object.freeze(original));
      if(construction)recordOrigin(error,NODE_ORIGIN_BOUNDARY,construction);
    }
    return typeof previous==='function'?Reflect.apply(previous,Error,[error,trace]):initialNativeFormatter?Reflect.apply(initialNativeFormatter,Error,[error,trace]):Reflect.apply(nativeDefaultFormatter,Error,[error,trace]).stack;
  };
  Error.prepareStackTrace=nativeStackHook;
}

/** Registration authenticates the engine's actual script ID and full compiled
 * bytes. Neither Error.stack nor sourceURL/file-name claims are authority.
 * The returned recorder remains lexical to the frozen SDK module.
 */
export async function registerStrykerFreshRecorder(boundary){
  if(![ORIGIN_BOUNDARY,ASYNC_ORIGIN_BOUNDARY].includes(boundary))throw new Error('Unknown fresh assertion registration boundary.');
  const caller=nativeCallSites(3,{sourceMap:false})[1];
  if(!caller||!/^\d+$/.test(caller.scriptId??''))throw new Error('Fresh assertion registration has no native script identity.');
  const session=new NativeInspectorSession();session.connect();
  let source;
  try{
    const post=(method,parameters)=>new Promise((resolve,reject)=>session.post(method,parameters,(error,result)=>error?reject(error):resolve(result)));
    await post('Debugger.enable',{});
    source=(await post('Debugger.getScriptSource',{scriptId:caller.scriptId})).scriptSource;
  }finally{session.disconnect();}
  const verified=verifyStrykerFreshScript(source,boundary,{captureModule:import.meta.url});
  return function captureFreshAssertion(error,asyncSite){
    const site=nativeCallSites(3,{sourceMap:false})[1],position=site&&verified.positions.find(point=>point.line===site.lineNumber&&point.column===site.columnNumber);
    if(!site||site.scriptId!==caller.scriptId||!position)throw new Error('Fresh assertion recorder was invoked outside its authenticated construction site.');
    const construction=Object.freeze({script_id:site.scriptId,script_sha256:verified.script_sha256,line:site.lineNumber,column:site.columnNumber});
    if(position.kind==='bind'){
      const previous=capturedOrigins.get(error),originalSite=asyncSiteOrigins.get(asyncSite);
      if(previous&&originalSite){const record={schema_version:previous.schema_version,boundary:previous.boundary,construction:previous.construction,error:Object.freeze({...previous.error,async_site:originalSite})};capturedOrigins.set(error,Object.freeze({...record,capture_sha256:sha(JSON.stringify(record))}));}
      return error;
    }
    pendingFresh.set(error,construction);
    try{if(position.kind==='site'){void error.stack;const original=nativeStackOrigins.get(error);if(original)asyncSiteOrigins.set(error,original);}else recordOrigin(error,boundary,construction);}finally{pendingFresh.delete(error);}
    return error;
  };
}

/** Exact pinned Vitest processError boundary calls this on the ORIGINAL object.
 * Never preserve an error-owned transport claim. Only this module's private
 * WeakMap can supply a pre-rewrite record across the trusted serializer.
 */
export function serializeStrykerAssertionOrigin(error,serialized){
  if(!serialized||typeof serialized!=='object'||Array.isArray(serialized))throw new Error('Pinned Vitest serializer returned a non-object error.');
  const clean={...serialized};delete clean[ORIGIN_PROPERTY];delete clean.assertion_capture;
  const origin=error&&typeof error==='object'?capturedOrigins.get(error):null;
  if(origin)clean[ORIGIN_PROPERTY]=origin;
  return clean;
}

/** Compatibility setup validates the pinned package. Capturing a broad
 * prototype catch would bless arbitrary exceptions from inspect/message
 * callbacks, so all capture happens inside the source-derived SDK3 instead.
 */
export async function installStrykerAssertionCapture(context={}){
  configureCompiledContext(context);installNativeStackCapture();
  if(!captureInstalled)captureInstalled=(async()=>{
    const require=createRequire(import.meta.url);
    if(require('chai/package.json').version!=='6.3.0')throw new Error('Assertion capture requires the frozen Chai boundary.');
  })();
  return captureInstalled;
}

/** The full stack is retained, not inferred from an assertion-like message. */
export function captureStrykerError(error){
  const record=stackRecord(error),descriptor=error&&typeof error==='object'?Object.getOwnPropertyDescriptor(error,ORIGIN_PROPERTY):null;
  const capture=error&&typeof error==='object'?capturedOrigins.get(error)??descriptor?.value??error.assertion_capture:null;
  return{...record,...(capture?{assertion_capture:capture}:{})};
}

let tools;
async function assertionTools(){
  if(!tools)tools=(async()=>{
    const require=createRequire(import.meta.url),vitest=path.dirname(require.resolve('vitest/package.json')),chai=path.dirname(require.resolve('chai/package.json'));
    if(require('vitest/package.json').version!=='5.1.0'||require('chai/package.json').version!=='6.3.0'||require('@babel/parser/package.json').version!=='8.0.10')throw new Error('Assertion SDK versions differ from their frozen contract.');
    const entry=readFileSync(path.join(vitest,'dist/node.js'),'utf8'),matches=[...entry.matchAll(/import ['"]\.\/(chunks\/source-map\.[A-Za-z0-9_-]+\.js)['"]/g)];
    if(matches.length!==1)throw new Error('Pinned Vitest stack-parser export is absent or ambiguous.');
    const [stack,parser,babel]=await Promise.all([import(pathToFileURL(path.join(vitest,'dist',matches[0][1])).href),import('@babel/parser'),import('@babel/core')]);
    if(typeof stack.f!=='function'||typeof parser.parse!=='function'||typeof babel.traverse!=='function')throw new Error('Pinned assertion SDK API changed.');
    // Individual primary parser calls intentionally avoid Vitest's default
    // node_modules filters and __VITEST_HELPER__ stack slicing.
    return {parseFrame:stack.f,parse:parser.parse,traverse:babel.traverse,vitest:normalize(realpathSync(vitest)),chai:normalize(realpathSync(chai)),sdk_sources:{[normalize(path.join(vitest,'dist',matches[0][1]))]:sha(readFileSync(path.join(vitest,'dist',matches[0][1])) )}};
  })();
  return tools;
}

function moduleBinding(binding,seen=new Set()){
  if(!binding||seen.has(binding))return null;seen.add(binding);
  const declaration=binding.path;
  if(declaration.isImportSpecifier()||declaration.isImportDefaultSpecifier()||declaration.isImportNamespaceSpecifier()){
    const source=declaration.parentPath.node.source.value;
    if(declaration.node.importKind==='type'||declaration.parentPath.node.importKind==='type')return null;
    const imported=declaration.isImportDefaultSpecifier()?'default':declaration.isImportNamespaceSpecifier()?'*':declaration.node.imported.name??declaration.node.imported.value;
    if(['node:assert','node:assert/strict','assert','assert/strict'].includes(source))return imported==='*'||imported==='default'||imported==='strict'?{kind:'assert',family:'node-assert'}:assertNames.has(imported)?{kind:'assert-function',family:'node-assert'}:null;
    if(source==='vitest'||source==='chai'){
      if(imported==='*')return{kind:'namespace',family:source};
      if(imported==='expect')return{kind:'expect',family:source};
      if(imported==='assert')return{kind:'assert',family:source};
      if(source==='vitest'&&['test','it'].includes(imported))return{kind:'test',family:source};
    }
    return null;
  }
  if(declaration.isVariableDeclarator()){
    if(!binding.constant)return null;
    const init=declaration.get('init');
    if(init.isIdentifier())return moduleBinding(init.scope.getBinding(init.node.name),seen);
    if(init.isCallExpression()){
      const callee=init.get('callee');
      if(callee.isMemberExpression()&&property(callee.node)==='extend'&&origin(callee.get('object'),seen)?.kind==='test')return{kind:'test',family:'vitest'};
      if(callee.isIdentifier({name:'require'})&&!callee.scope.getBinding('require')&&init.node.arguments.length===1&&init.node.arguments[0].type==='StringLiteral'){
        const source=init.node.arguments[0].value;
        if(['node:assert','node:assert/strict','assert','assert/strict'].includes(source)&&declaration.node.id.type==='Identifier')return{kind:'assert',family:'node-assert'};
      }
    }
  }
  return null;
}
function property(node){return !node.computed&&node.property.type==='Identifier'?node.property.name:node.computed&&node.property.type==='StringLiteral'?node.property.value:null;}
function origin(node,seen=new Set()){
  if(node.isIdentifier())return moduleBinding(node.scope.getBinding(node.node.name),seen);
  if(node.isMemberExpression()){
    const object=origin(node.get('object'),seen),name=property(node.node);if(!object||!name)return null;
    if(object.kind==='namespace'){
      if(name==='expect')return{kind:'expect',family:object.family};if(name==='assert')return{kind:'assert',family:object.family};
      if(object.family==='vitest'&&['test','it'].includes(name))return{kind:'test',family:'vitest'};
    }
    if(object.kind==='test'&&testModifiers.has(name))return object;
    if(object.kind==='expect'&&['soft','poll'].includes(name))return object;
    if(object.kind==='expect'&&['fail','unreachable','assertions','hasAssertions'].includes(name))return{kind:'assert-function',family:object.family};
    if(object.kind==='assert'&&(object.family!=='node-assert'||assertNames.has(name)))return{kind:'assert-function',family:object.family};
    if(object.kind==='expect-chain')return{kind:'expect-chain',family:object.family};
  }
  if(node.isCallExpression()){
    const callee=origin(node.get('callee'),seen);
    if(callee?.kind==='expect')return{kind:'expect-chain',family:callee.family};
    if(callee?.kind==='test')return callee;
  }
  return null;
}
function location(node){return{start:{line:node.loc.start.line,column:node.loc.start.column+1},end:{line:node.loc.end.line,column:node.loc.end.column+1}};}
const compare=(a,b)=>a.line-b.line||a.column-b.column;
const inside=(point,span)=>compare(span.start,point)<=0&&compare(point,span.end)<0;
function callback(node){
  if(node.isFunctionExpression()||node.isArrowFunctionExpression()||node.isFunctionDeclaration())return node;
  if(node.isIdentifier()){
    const binding=node.scope.getBinding(node.node.name);if(binding?.path.isFunctionDeclaration())return binding.path;
    if(binding?.path.isVariableDeclarator()){const value=binding.path.get('init');if(value.isFunctionExpression()||value.isArrowFunctionExpression())return value;}
  }
  return null;
}

/** Initialize once per fixed handoff; syntax is parsed lazily only on failures. */
export async function createStrykerAssertionVerifier({sourceRoot,childRoot,sourceInventory,immutableSdkContext=null,compiledSources=null}){
  if(typeof sourceRoot!=='string'||typeof childRoot!=='string'||!sourceInventory||typeof sourceInventory!=='object'||Array.isArray(sourceInventory))throw new Error('Assertion origin requires a complete frozen test/helper source inventory.');
  const root=normalize(realpathSync(sourceRoot)),child=normalize(childRoot),sdk=await assertionTools(),cache=new Map();
  // The caller supplies this only after independently verifying the immutable
  // image's node-dependencies receipt. No caller-selected library path exists:
  // only the fixed mutation image layout may be replayed across host OSes.
  if(immutableSdkContext!==null&&(!immutableSdkContext||Object.keys(immutableSdkContext).sort().join(',')!=='receipt_sha256,root,schema_version'||immutableSdkContext.schema_version!==1||immutableSdkContext.root!=='/opt/mutation/node_modules'||typeof immutableSdkContext.receipt_sha256!=='string'||!HASH.test(immutableSdkContext.receipt_sha256)))throw new Error('Cross-host assertion libraries require the exact independently verified immutable SDK context.');
  if(!path.isAbsolute(root)||!child||/[\0\r\n]/.test(child))throw new Error('Invalid assertion source root.');
  for(const[name,fingerprint]of Object.entries(sourceInventory))if(!confined(name)||typeof fingerprint!=='string'||!HASH.test(fingerprint))throw new Error('Assertion helper source inventory is invalid.');
  function load(name){
    if(!confined(name)||!HASH.test(sourceInventory[name]??''))throw new ProvenanceError('Assertion frame is not in the immutable test/helper closure.');
    const filename=path.join(root,name);let fd;
    try{fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));}catch(error){if(['ENOENT','ENOTDIR','ELOOP','EACCES'].includes(error?.code))throw new ProvenanceError('Frozen assertion source is unavailable.');throw error;}
    let bytes;
    try{const before=fstatSync(fd),named=lstatSync(filename);if(!before.isFile()||before.nlink!==1||before.size>16*1024*1024||named.isSymbolicLink()||named.dev!==before.dev||named.ino!==before.ino)throw new ProvenanceError('Assertion source is not an ordinary frozen file.');bytes=readFileSync(fd);const after=fstatSync(fd);if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||sha(bytes)!==sourceInventory[name])throw new ProvenanceError('Assertion source differs from its frozen fingerprint.');}finally{closeSync(fd);}
    if(cache.has(name))return cache.get(name);
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),ast=sdk.parse(text,{sourceType:'unambiguous',plugins:[...(/\.(?:ts|tsx|mts|cts)$/.test(name)?['typescript']:[]),...(/\.(?:tsx|jsx)$/.test(name)?['jsx']:[])]}),sites=[],cases=[];
    sdk.traverse(ast,{CallExpression(node){
      const callee=node.get('callee'),value=origin(callee);
      if(value?.kind==='test'){
        for(const argument of [...node.get('arguments')].reverse()){const fn=callback(argument);if(fn){cases.push({declaration:location(node.node),callee:location(callee.node),callback:location(fn.node)});break;}}
      }
      const awaited=node.parentPath.isAwaitExpression()?location(node.parentPath.node).start:null;
      if(value?.kind==='assert'||value?.kind==='assert-function')sites.push({callee:location(callee.node),...(awaited?{points:[awaited]}:{}),family:value.family});
      else if(value?.kind==='expect-chain'&&callee.isMemberExpression()){
        // Match the root expect position or final matcher token, never an
        // arbitrary point inside an operand/callback expression.
        const start=location(node.node).start,member=location(callee.get('property').node);
        const asyncPoints=[];let chain=callee;
        while(chain.isMemberExpression()){
          if(['resolves','rejects'].includes(property(chain.node))&&origin(chain.get('object'))?.kind==='expect-chain')asyncPoints.push(location(chain.get('object').node).end,location(chain.get('property').node).start);
          chain=chain.get('object');
        }
        sites.push({points:[start,...(awaited?[awaited]:[])],async_points:asyncPoints,callee:member,family:value.family});
      }
    }});
    const value={sites,cases,sha256:sourceInventory[name]};cache.set(name,value);return value;
  }
  function frameFile(filename){
    const value=normalize(filename);
    for(const prefix of [child,root])if(value.startsWith(prefix+'/'))return value.slice(prefix.length+1);
    return null;
  }
  function library(filename){
    const value=normalize(filename);if(value.startsWith('node:internal/')||value==='node:assert'||value==='node:assert/strict'||value.startsWith('node:internal/assert'))return true;
    for(const[name,folder]of [['vitest',sdk.vitest],['chai',sdk.chai]]){
      if(value.startsWith(folder+'/'))return true;
      if(immutableSdkContext&&value.startsWith(immutableSdkContext.root+'/'+name+'/'))return true;
      for(const prefix of [child,root])if(value.startsWith(prefix+'/node_modules/'+name+'/'))return true;
    }
    return false;
  }
  function verify(test,error,trustedOriginal=false){
    const reject=reason=>({valid:false,reason});
    try{
      if(!isAssertion(error))return reject('Failure is not a supported assertion class/code.');
      const nativeFrames=[];
      if(trustedOriginal&&error.compiled_frames){
        if(!Array.isArray(error.compiled_frames))return reject('Native assertion compiled frames are invalid.');
        const context=replayContext(child,root,sourceInventory);
        if(error.compiled_frames.length>512)return reject('Native assertion compiled frame inventory exceeds its bound.');
        for(const frame of error.compiled_frames){
          if(!frame||!confined(frame.source)||!Number.isSafeInteger(frame.frame)||frame.frame<0||!Number.isSafeInteger(frame.native_line)||frame.native_line<1||!Number.isSafeInteger(frame.native_column)||frame.native_column<1||!confined(frame.mapped_source)||!Number.isSafeInteger(frame.mapped_line)||frame.mapped_line<1||!Number.isSafeInteger(frame.mapped_column)||frame.mapped_column<1)return reject('Native assertion compiled frame position is invalid.');
          const program=compiledProgram(frame.compiled_source,context,frame.source);
          if(frame.native_hash!==frame.compiled_sha256||program.compiled_sha256!==frame.compiled_sha256||program.identity_sha256!==frame.identity_sha256||program.source_map_sha256!==frame.source_map_sha256||frame.source_sha256!==sourceInventory[frame.source])return reject('Native assertion compiled program differs from its source receipt.');
          if(program.map){
            if(!compiledSources)return reject('Transformed assertion has no pre-outcome pristine compilation binding.');
            verifyCompiledSources(compiledSources,{schema_version:1,normalization:'ud-job-root-and-inline-map-1',child_root:child,entries:[frame]},{sourceRoot:root,sourceInventory});
          }else if(sha(frame.compiled_source)!==sourceInventory[frame.source])return reject('Native assertion script differs from immutable source.');
          let expected={source:frame.source,line:frame.native_line,column:frame.native_column};
          if(program.map){const mapped=originalPositionFor(new TraceMap(program.map,pathToFileURL(path.join(context.root,frame.source)).href),{line:frame.native_line,column:frame.native_column-1});expected={source:typeof mapped.source==='string'?sourceName(mapped.source,context):null,line:mapped.line,column:mapped.column===null?null:mapped.column+1};}
          if(expected.source!==frame.mapped_source||expected.line!==frame.mapped_line||expected.column!==frame.mapped_column)return reject('Native assertion mapped position differs from the attested compiled program.');nativeFrames.push(frame);
        }
      }
      const outerCapture=error.assertion_capture??Object.getOwnPropertyDescriptor(error,ORIGIN_PROPERTY)?.value;
      if(!trustedOriginal&&outerCapture?.boundary===NODE_ORIGIN_BOUNDARY){
        const capture=outerCapture,construction=capture.construction,record={schema_version:capture.schema_version,boundary:capture.boundary,construction,error:capture.error};
        if(Object.keys(capture).sort().join(',')!=='boundary,capture_sha256,construction,error,schema_version'||capture.schema_version!==2||!construction||Object.keys(construction).sort().join(',')!=='column,line,script_id,script_sha256'||!/^\d{1,16}$/.test(construction.script_id??'')||!NODE_CONSTRUCTORS.has(construction.script_sha256)||construction.line!==382||construction.column!==10||capture.error?.name!==error.name||capture.error?.code!==error.code||capture.error?.message_sha256!==(error.message_sha256??sha(error.message))||!HASH.test(capture.capture_sha256??'')||sha(JSON.stringify(record))!==capture.capture_sha256)return reject('Node assertion has invalid authenticated constructor evidence.');
        const origin=verify(test,capture.error,true);
        return origin.valid?{...origin,assertion_capture_sha256:capture.capture_sha256,native_construction:construction}:reject('Native Node assertion origin is invalid: '+origin.reason);
      }
      if(!trustedOriginal&&outerCapture&&[ORIGIN_BOUNDARY,ASYNC_ORIGIN_BOUNDARY].includes(outerCapture.boundary)){
        const capture=outerCapture,construction=capture.construction,record={schema_version:capture.schema_version,boundary:capture.boundary,construction,error:capture.error};
        if(Object.keys(capture).sort().join(',')!=='boundary,capture_sha256,construction,error,schema_version'||capture.schema_version!==2||!construction||!HASH.test(construction.script_sha256??'')||capture.error?.name!==error.name||(capture.error?.code??null)!==(error.code??null)||capture.error?.message_sha256!==(error.message_sha256??sha(error.message))||sha(JSON.stringify(record))!==capture.capture_sha256)return reject('Fresh assertion capture differs from authenticated constructor evidence.');
        const original=verify(test,capture.error,true);
        if(original.valid)return{...original,assertion_capture_sha256:capture.capture_sha256,native_construction:construction};
        if(original.reason!=='Assertion has no independent test source origin.')return reject('Pre-rewrite assertion origin is invalid: '+original.reason);
        const site=capture.error.async_site;if(site){const siteProof=verify(test,{...site,name:error.name,code:error.code??null},true);if(!siteProof.valid)return reject('Authenticated async getter origin is invalid: '+siteProof.reason);return {...siteProof,assertion_capture_sha256:capture.capture_sha256,pre_rewrite_stack_sha256:capture.error.stack_sha256,async_site_stack_sha256:site.stack_sha256,native_construction:construction};}
      }
      const stack=typeof error.stack==='string'?error.stack:typeof error.stackStr==='string'?error.stackStr:null;
      if(stack===null||Buffer.byteLength(stack)===0||Buffer.byteLength(stack)>MAX_STACK||error.stack_truncated===true)return reject('Full assertion stack is missing or truncated.');
      if(error.stack_sha256!==undefined&&error.stack_sha256!==sha(stack)||error.stack_bytes!==undefined&&error.stack_bytes!==Buffer.byteLength(stack))return reject('Assertion stack differs from its recorded bytes.');
      if(typeof error.message!=='string')return reject('Assertion has no exact message for stack-header separation.');
      const labels=[error.name,...(error.name==='AssertionError'&&error.code==='ERR_ASSERTION'?['AssertionError [ERR_ASSERTION]']:[]),...(['AssertionError','VitestAssertionError'].includes(error.name)?['Error']:[])];
      let frameText=null,headerLabel=null;
      for(const label of labels){for(const prefix of error.message===''?[label,label+': ']:[label+': ']){
        if(!stack.startsWith(prefix))continue;
        let message=error.message;
        if(error.message_truncated===true){
          if(!Number.isSafeInteger(error.message_bytes)||error.message_bytes<0||error.message_bytes>MAX_STACK||!HASH.test(error.message_sha256??''))return reject('Truncated message has no exact bounded header binding.');
          const body=Buffer.from(stack.slice(prefix.length));message=new TextDecoder('utf-8',{fatal:true}).decode(body.subarray(0,error.message_bytes));
          if(sha(message)!==error.message_sha256||!message.startsWith(error.message))return reject('Truncated assertion message differs from its complete stack header.');
        }
        const header=prefix+message;
        if(stack.startsWith(header)&&(stack.length===header.length||stack[header.length]==='\n')){frameText=stack.slice(header.length);headerLabel=label;break;}
      }if(frameText!==null)break;}
      if(frameText===null)return reject('Assertion stack header is inconsistent with the full exception message.');
      if(!test||!confined(test.source)||test.source_sha256!==sourceInventory[test.source]||!test.startPosition||!Number.isSafeInteger(test.startPosition.line)||!Number.isSafeInteger(test.startPosition.column)||test.startPosition.line<0||test.startPosition.column<0)return reject('Current case lacks a bound source/declaration position.');
      const current=load(test.source),declarationPoint={line:test.startPosition.line+1,column:test.startPosition.column+1};
      const declarations=current.cases.filter(value=>inside(declarationPoint,value.callee));
      if(declarations.length!==1)return reject('Current case declaration is absent or ambiguous in the exact test AST.');
      const lines=frameText.split('\n').filter(line=>line.trim());
      const firstParsed=sdk.parseFrame(lines[0]??''),asyncWrapper=firstParsed&&['Assertion.__VITEST_RESOLVES__','Assertion.__VITEST_REJECTS__'].includes(firstParsed.method)&&library(firstParsed.file)&&normalize(firstParsed.file).includes('/vitest/dist/chunks/');
      let preRewrite=null;
      if(asyncWrapper&&!trustedOriginal){
        const capture=error.assertion_capture??Object.getOwnPropertyDescriptor(error,ORIGIN_PROPERTY)?.value;
        if(!capture||Object.keys(capture).sort().join(',')!=='boundary,capture_sha256,construction,error,schema_version'||capture.schema_version!==2||![ORIGIN_BOUNDARY,ASYNC_ORIGIN_BOUNDARY].includes(capture.boundary)||!capture.error||typeof capture.error!=='object'||Array.isArray(capture.error))return reject('Async assertion lacks a fixed pre-rewrite failure capture.');
        const construction=capture.construction;
        if(!construction||Object.keys(construction).sort().join(',')!=='column,line,script_id,script_sha256'||!/^\d{1,16}$/.test(construction.script_id??'')||!HASH.test(construction.script_sha256??'')||!Number.isSafeInteger(construction.line)||construction.line<1||!Number.isSafeInteger(construction.column)||construction.column<1)return reject('Async assertion capture has no authenticated fresh construction.');
        const record={schema_version:capture.schema_version,boundary:capture.boundary,construction,error:capture.error};
        if(!HASH.test(capture.capture_sha256??'')||sha(JSON.stringify(record))!==capture.capture_sha256||capture.error.name!==error.name||(capture.error.code??null)!==(error.code??null)||capture.error.message_sha256!==(error.message_sha256??sha(error.message))||capture.error.stack===stack||capture.error.assertion_capture!==undefined)return reject('Async assertion capture differs from the original exception or was recursively rewritten.');
        const original=verify(test,capture.error,true);
        // Promise callbacks can have a stack containing only the frozen SDK
        // and Node internals. That is evidence that Chai itself failed, but
        // still needs the independently checked rewritten test callsite below.
        // Any actual foreign/test source frame must pass the normal AST proof.
        if(!original.valid&&original.reason!=='Assertion has no independent test source origin.')return reject('Pre-rewrite assertion origin is invalid: '+original.reason);
        preRewrite={pre_rewrite_stack_sha256:capture.error.stack_sha256,assertion_capture_sha256:capture.capture_sha256};
      }
      // Chai's pinned Proxy getter contributes this one native Reflect frame
      // between SDK frames. It carries no source location and is accepted only
      // under the independently identified async matcher wrapper.
      const parsed=lines.map(line=>sdk.parseFrame(line)),intrinsics=[];
      const frames=lines.map((line,index)=>{
        if(parsed[index])return parsed[index];
        const previous=parsed[index-1],next=parsed[index+1],isSdk=(frame,suffix)=>frame&&library(frame.file)&&normalize(frame.file).endsWith(suffix);
        if(line.trim()==='at new Promise (<anonymous>)'&&isSdk(previous,'/vitest/dist/chunks/run.CjdgFZiW.js')&&isSdk(next,'/vitest/dist/chunks/run.CjdgFZiW.js')&&['runWithCancel','runWithTimeout'].includes(next.method)){intrinsics.push({kind:'Promise-constructor',frame:index});return{intrinsic:true};}
        if(line.trim()==='at Reflect.get (<anonymous>)'&&asyncWrapper&&isSdk(previous,'/chai/index.js')&&isSdk(next,'/chai/index.js')&&previous.method==='Assertion.propertyGetter'&&/^Object\.proxyGetter(?: \[as get\])?$/.test(next.method)){intrinsics.push({kind:'Chai-Reflect-get',frame:index});return{intrinsic:true};}
        return null;
      });
      if(frames.some(frame=>!frame))return reject('Assertion stack contains unparsed or incomplete frame data.');
      if(!frames.length||frames.length>512)return reject('Assertion stack has no bounded complete source frames.');
      // Pinned Vitest async matchers retain their AssertionError class but
      // replace its stack with the Error created by the resolves/rejects getter.
      // Only that exact SDK wrapper may explain the different header class.
      if(headerLabel==='Error'&&!asyncWrapper)return reject('Generic Error header has no pinned Vitest async assertion origin.');
      const relevant=frames.filter(frame=>!frame.intrinsic&&!library(frame.file));
      if(!relevant.length)return reject('Assertion has no independent test source origin.');
      const first=relevant[0],name=frameFile(first.file);
      if(!name||!confined(name)||!Number.isSafeInteger(first.line)||!Number.isSafeInteger(first.column)||first.line<1||first.column<1)return reject('First relevant assertion frame originates in production/foreign code.');
      if(trustedOriginal&&!nativeFrames.some(frame=>frame.mapped_source===name&&frame.mapped_line===first.line&&frame.mapped_column===first.column))return reject('Independent assertion frame lacks native compiled-source provenance.');
      const origin=load(name),point={line:first.line,column:first.column};
      const sites=origin.sites.filter(site=>inside(point,site.callee)||site.points?.some(value=>compare(value,point)===0)||asyncWrapper&&site.async_points?.some(value=>compare(value,point)===0));
      if(sites.length!==1)return reject('First source frame is not an exact imported assertion callee site.');
      const ancestry=relevant.some(frame=>frameFile(frame.file)===test.source&&inside({line:frame.line,column:frame.column},declarations[0].callback));
      if(!ancestry)return reject('Assertion stack has no ancestry in the current immutable case callback.');
      if(!trustedOriginal&&!preRewrite)return reject('Assertion lacks authenticated fresh-constructor evidence.');
      return{valid:true,assertion_site:{source:name,source_sha256:origin.sha256,line:first.line,column:first.column,family:sites[0].family},case_declaration:{source:test.source,source_sha256:current.sha256,...declarations[0].declaration},stack_sha256:sha(stack),source_inventory:{[name]:origin.sha256,[test.source]:current.sha256},...(intrinsics.length?{intrinsic_frames:intrinsics}:{}),...(preRewrite??{}),...(immutableSdkContext?{immutable_sdk_context:immutableSdkContext}:{})};
    }catch(error){if(error instanceof ProvenanceError)return reject(error.message);throw error;}
  }
  return (test,error)=>verify(test,error,false);
}
