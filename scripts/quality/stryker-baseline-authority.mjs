/** Restore a pristine baseline only from actual protected execution evidence. */
import {createHash} from 'node:crypto';
import {constants,openSync,closeSync,fstatSync,lstatSync,readFileSync,realpathSync,writeFileSync,fsyncSync} from 'node:fs';
import path from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {normalizeSubprocessOpacity} from './stryker-opacity.mjs';
import {verifyCompiledSources} from './stryker-assertions.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const HASH=/^[a-f0-9]{64}$/;
const fail=message=>{throw new Error('Pristine Stryker authority: '+message);};
function ownedRoot(directory){
  const real=realpathSync(directory),info=lstatSync(directory);
  if(real!==path.resolve(directory)||info.isSymbolicLink()||!info.isDirectory()||typeof process.getuid==='function'&&(info.uid!==process.getuid()||info.mode&0o022))fail('evidence directory is not private owned supervisor storage');
  return real;
}
function bytes(root,relative,max=32*1024**2){
  if(typeof relative!=='string'||!relative||/[\\\0:]/.test(relative)||relative.startsWith('/')||relative.split('/').some(part=>!part||part==='.'||part==='..'))fail('evidence path is not confined');
  const filename=path.join(root,relative),fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    const before=fstatSync(fd,{bigint:true}),named=lstatSync(filename,{bigint:true});
    if(!before.isFile()||before.nlink!==1n||before.size<=0n||before.size>BigInt(max)||named.isSymbolicLink()||before.dev!==named.dev||before.ino!==named.ino||typeof process.getuid==='function'&&(before.uid!==BigInt(process.getuid())||(before.mode&0o022n)!==0n))fail('evidence file is not bounded ordinary owned storage');
    const data=readFileSync(fd),after=fstatSync(fd,{bigint:true});
    if(data.length!==Number(before.size)||before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs)fail('evidence changed while reading');
    return data;
  }finally{closeSync(fd);}
}
const equal=isDeepStrictEqual;
const identity=({id,source,source_sha256,name,occurrence,upstream_id})=>({id,source,source_sha256,name,occurrence,upstream_id});

export function retainPristineAuthority(directory,{sourceTreeSha256,baseline,sdkContext}){
  const root=ownedRoot(directory);
  if(!HASH.test(sourceTreeSha256??'')||!baseline?.result||!sdkContext)fail('source, baseline and immutable SDK binding are required');
  const document={schema_version:1,qualification:'root-issued-pristine-baseline-not-outcomes',source_tree_sha256:sourceTreeSha256,baseline,sdk_context:sdkContext};
  const fd=openSync(path.join(root,'stryker-pristine-authority.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|(constants.O_NOFOLLOW??0),0o400);
  try{writeFileSync(fd,JSON.stringify(document)+'\n');fsyncSync(fd);}finally{closeSync(fd);}
  if(process.platform!=='win32'){const parent=openSync(root,constants.O_RDONLY);try{fsyncSync(parent);}finally{closeSync(parent);}}
}

/** No caller-provided case list or coverage is adopted. Read the retained raw
 * baseline and its root execution record, then bind each case to current bytes.
 */
export function restorePristineAuthority(directory,{sourceTreeSha256,sourceRoot,sdkContext,sourceInventory}){
  const root=ownedRoot(directory);let raw;
  try{raw=bytes(root,'stryker-pristine-authority.json');}catch(error){if(error.code==='ENOENT')return null;throw error;}
  const document=JSON.parse(raw),baseline=document?.baseline;
  if(document.schema_version!==1||document.qualification!=='root-issued-pristine-baseline-not-outcomes'||document.source_tree_sha256!==sourceTreeSha256||!HASH.test(sourceTreeSha256??'')||!equal(document.sdk_context,sdkContext)||!baseline?.result||!/^stryker-baseline-[1-9][0-9]{0,15}\.json$/.test(baseline.result.path??'')||!HASH.test(baseline.result.sha256??''))fail('pristine authority source or SDK identity changed');
  const reportBytes=bytes(root,baseline.result.path);
  if(reportBytes.length!==baseline.result.size||sha(reportBytes)!==baseline.result.sha256)fail('retained pristine report bytes changed');
  const claimed=baseline.execution,id=claimed?.execution_id;
  if(typeof id!=='string'||!/^[a-f0-9]{32}$/.test(id))fail('root execution identity is missing');
  const actual=JSON.parse(bytes(root,`control/jobs/${id}.exec.json`,64*1024**2));
  if(actual.qualification!=='protected-exec'||actual.collected!==true||actual.status!==0||actual.timed_out!==false||actual.cancelled===true||!Array.isArray(actual.owned_descendants_cancelled)||actual.owned_descendants_cancelled.length||!Number.isSafeInteger(actual.uid)||actual.uid<100001||actual.execution_id!==id||actual.handoff?.readonly_tree!==true||!HASH.test(actual.handoff?.source_inventory_sha256??'')||actual.handoff.source_inventory_sha256!==actual.handoff.inventory_sha256||actual.handoff.materializations?.length||!equal(actual.command,['/opt/mutation/node/bin/node','/opt/mutation/harness/stryker-child.mjs',`/tmp/ud-mutation-jobs/${id}/request.json`,`/tmp/ud-mutation-jobs/${id}/result.json`])||Object.entries(claimed).some(([key,value])=>!Object.hasOwn(actual,key)||!equal(actual[key],value))||actual.result_size!==reportBytes.length||actual.result_sha256!==sha(reportBytes))fail('pristine report does not match a complete clean actual root execution');
  const report=JSON.parse(reportBytes),tests=report.tests;
  if(report.schema_version!==1||report.child_root!==`/tmp/ud-mutation-jobs/${id}/tree`||report.result?.status!=='complete'||!Array.isArray(tests)||!tests.length||tests.some(test=>test.status!==0)||!equal(report.result.tests,tests)||!Array.isArray(report.failures)||report.failures.length||!Array.isArray(report.outside_errors)||report.outside_errors.length||!equal(report.assertion_sdk_context,sdkContext)||report.selection_sha256!==undefined||report.not_selected!==undefined)fail('pristine report is incomplete, selected or failed');
  const schedule=JSON.parse(bytes(root,'stryker-schedule.json'));
  if(schedule.tool!=='stryker'||schedule.tool_version!=='10.1.1'||schedule.source_tree_sha256!==sourceTreeSha256||!Array.isArray(schedule.tests)||schedule.tests.some(test=>test.status!=='Success')||!equal(schedule.tests.map(test=>identity({...test,upstream_id:test.upstream_id??test.source+'#'+test.name})),tests.map(identity)))fail('pristine cases differ from the complete pre-outcome schedule');
  const seen=new Set(),source=realpathSync(sourceRoot);
  for(const test of tests){
    if(!test||typeof test.source!=='string'||!test.source.startsWith('tests/')||!HASH.test(test.source_sha256??'')||typeof test.name!=='string'||!test.name||!Number.isSafeInteger(test.occurrence)||test.occurrence<0||test.upstream_id!==test.source+'#'+test.name||test.id!==`${test.source}#ud-case-${sha(JSON.stringify([test.name,test.occurrence])).slice(0,24)}`||seen.has(test.id))fail('pristine test identity is malformed or duplicated');
    seen.add(test.id);
    if(sha(bytes(source,test.source,16*1024**2))!==test.source_sha256)fail('current test bytes differ from the pristine source');
  }
  if(report.result.mutantCoverage&&(!report.result.mutantCoverage.opacity||!equal(report.result.mutantCoverage.opacity,normalizeSubprocessOpacity(report.subprocess_opacity,tests))))fail('pristine opaque execution closure is missing or changed');
  if(report.assertion_compiled_sources?.child_root!==report.child_root)fail('pristine compiled assertions identify another actual execution tree');
  if(!sourceInventory||typeof sourceInventory!=='object'||Array.isArray(sourceInventory))fail('root-issued complete test/helper source inventory is missing');
  verifyCompiledSources(report.assertion_compiled_sources,report.assertion_compiled_sources,{sourceRoot:source,sourceInventory});
  const compiledCases=new Set(report.assertion_compiled_sources.entries.map(entry=>entry.source));
  if(tests.some(test=>!compiledCases.has(test.source)))fail('an executed pristine test module lacks compiled-source evidence');
  return{baseline,coverage:report.result.mutantCoverage,compiledSources:report.assertion_compiled_sources,tests:tests.map(identity)};
}
