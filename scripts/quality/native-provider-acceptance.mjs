#!/usr/bin/env node
/** Execute original assembled bytes through public MCP on an actual native provider. */
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import Ajv2020 from 'ajv/dist/2020.js';
import { createHash } from 'node:crypto';
import { constants, createReadStream, existsSync, readFileSync, realpathSync } from 'node:fs';
import { chmod, copyFile, cp, lstat, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runtimeInputFormats, verifyRuntimeInputs } from '../release/runtime-inputs.mjs';
import { fileReceipt, readRecordedBytes, sourceReceipt, verifyRecordedFile } from '../release/candidate.mjs';
import { verifyOciArchive } from '../release/oci.mjs';
import { closeReleaseInterpreter, preflightReleaseInterpreter, verifyReleaseInterpreter, releaseVerifierReceipt, releasePythonCommand } from '../release/verifier-runtime.mjs';
import { installedMcpLaunch, verifyInstalledPayload } from './installed-payload.mjs';
import { verifyRuntimeExecutionProfile } from './runtime-execution-profile.mjs';
import { localDockerAuthority } from './mutation-scope.mjs';
import { activeUserspaceLeases, operationMatrixSummary, requireUserspaceProjectRejection, userspaceAcceptanceProfile, userspaceGitEvidence, userspaceInstallerEvidence } from './userspace-acceptance.mjs';
import { reserveStorage, STORAGE_LIMITS, storageTreeBytes } from './storage-lifecycle.mjs';
import { inspectOwnedDockerStorage, lockedDockerImages } from './docker-owned-storage.mjs';
import { originalDockerBytes } from './original-storage.mjs';
import { dockerStorageGrowth, dockerStorageSnapshot } from './mutation-sdk-storage.mjs';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

function acceptanceOwner(root){
  let owner=realpathSync(process.env.UD_AGENT_STORAGE_ROOT??root);
  for(let current=owner;path.dirname(current)!==current;current=path.dirname(current))if(path.basename(current)==='.artifacts')owner=path.dirname(current);
  return owner;
}
function acceptanceDocker(run){
  const environment={...process.env};
  const docker=args=>{
    const result=run('docker',args,{env:environment,encoding:'utf8',timeout:30000,maxBuffer:4*1024**2});
    if(result.error?.code==='ENOENT')throw Object.assign(new Error('Docker CLI is absent'),{code:'ENOENT'});
    if(args[0]==='image'&&args[1]==='ls'&&result.status!==0&&/cannot connect to the docker daemon|the system cannot find the file specified.*docker_engine/i.test(result.stderr??''))throw Object.assign(new Error('Docker engine is unavailable'),{code:'UD_ENGINE_UNAVAILABLE'});
    assert.ok(!result.error&&result.status===0,'Acceptance Docker storage inspection failed: '+(result.error?.message??result.stderr??result.status));return result.stdout;
  };
  const authority=localDockerAuthority(environment,context=>docker(['context','inspect','--format','{{.Endpoints.docker.Host}}',...(context?[context]:[])]).trim());
  // A later context switch must not redirect checks or jobs to another daemon.
  delete environment.DOCKER_CONTEXT;environment.DOCKER_HOST=authority.endpoint;docker.endpoint=authority.endpoint;
  return docker;
}
function acceptanceBaseline(root,lock,docker){
  const known=lockedDockerImages(lock),sdk=path.join(acceptanceOwner(root),'.artifacts/mutation-ci-sdk/ci-sdk.json');
  if(existsSync(sdk)){const id=JSON.parse(readFileSync(sdk,'utf8')).image_id;assert.match(id??'',/^sha256:[a-f0-9]{64}$/);known.push(id);}
  return inspectOwnedDockerStorage(docker,{selectedImages:[],knownImageIds:known});
}
/** Keep a live reconciled engine charge while userspace performs no engine writes. */
export function existingAcceptanceDockerAdmission(root,{run=spawnSync}={}){
  try{
    const docker=acceptanceDocker(run),lock=JSON.parse(readFileSync(path.join(root,'runtime/runtime.lock.json'),'utf8'));
    const baseline=acceptanceBaseline(root,lock,docker);
    return{ownedBytes:baseline.image_bytes,reservedBytes:0,measure:()=>0};
  }catch(error){
    if(!['ENOENT','UD_ENGINE_UNAVAILABLE'].includes(error?.code))throw error;
    // Only the real owning checkout can establish a fresh, artifact-free
    // history. A detached QA source under .artifacts is never itself proof.
    return{ownedBytes:originalDockerBytes(acceptanceOwner(root),process.env,run),reservedBytes:0,measure:()=>0};
  }
}

/** Account for already owned images and admit only exact, bounded worker imports. */
export function dockerAcceptanceAdmission(root,candidateRoot,{run=spawnSync}={}){
  const docker=acceptanceDocker(run);
  const sourceLock=fileReceipt(root,'runtime/runtime.lock.json'),lock=JSON.parse(readFileSync(path.join(root,sourceLock.path),'utf8'));
  const manifest=JSON.parse(readFileSync(path.join(candidateRoot,'candidate-inputs.json'),'utf8'));
  assert.equal(manifest.runtime_lock_sha256,sourceLock.sha256,'Acceptance runtime lock differs from candidate inputs');
  assert.ok(Array.isArray(manifest.offline_assets),'Acceptance offline assets are missing');
  const worker='linux/'+(process.arch==='x64'?'amd64':process.arch),ids=new Set(),plans=[];
  for(const packName of ['core','render']){
    const image=lock.packs?.[packName]?.images?.[worker],transport=image?.transports?.find(row=>row.format==='oci-archive');
    assert.ok(image&&transport&&typeof transport.index_digest==='string','Selected immutable worker image transport is missing');
    const hash=(transport.sha256??'').replace(/^sha256:/,''),matches=manifest.offline_assets.filter(item=>item.sha256?.replace(/^sha256:/,'')===hash&&item.size_bytes===transport.size_bytes);
    assert.equal(matches.length,1,'Worker import needs one exact offline transport');
    const asset=verifyRecordedFile(candidateRoot,{...matches[0],sha256:hash,size:transport.size_bytes});
    const graph=verifyOciArchive(path.join(candidateRoot,asset.path),transport.index_digest,{[worker]:image.digest},asset,{[worker]:{...image,engine_descriptor_digests:[]}},{diagnosticSinglePlatform:true,includeLayerSizes:true});
    const layers=graph.layer_sizes[worker];assert.ok(Array.isArray(layers)&&layers.length>0);
    const bytes=layers.reduce((sum,row)=>sum+row.size_bytes+row.uncompressed_size_bytes,0);assert.ok(Number.isSafeInteger(bytes)&&bytes>0);
    assert.match(image.config_digest,/^sha256:[a-f0-9]{64}$/);assert.ok(!ids.has(image.config_digest),'Worker image identities collide');ids.add(image.config_digest);plans.push({image_id:image.config_digest,bytes});
  }
  const baseline=acceptanceBaseline(root,lock,docker),held=new Set(baseline.image_ids),daemon=docker(['info','--format','{{.ID}}']).trim();
  assert.match(daemon,/^[A-Za-z0-9:_-]{1,128}$/,'Acceptance Docker daemon identity is unavailable');
  const engineBefore=dockerStorageSnapshot(docker(['system','df','--format','{{json .}}']));
  // Charge both compressed and expanded layers twice for import overlap; shared
  // layers are deliberately not credited. Existing exact image IDs are held once.
  const reserved=plans.filter(row=>!held.has(row.image_id)).reduce((sum,row)=>sum+2*row.bytes,0)+128*1024**2;
  assert.ok(Number.isSafeInteger(reserved)&&reserved>0,'Worker import reservation is invalid');
  let importedImageBytes=0;
  const measure=()=>{
    assert.equal(docker(['info','--format','{{.ID}}']).trim(),daemon,'Acceptance Docker daemon changed during the job');
    const lines=docker(['image','ls','--all','--no-trunc','--format','{{json .}}']).trim(),rows=lines?lines.split(/\r?\n/).map(line=>JSON.parse(line)):[];
    assert.ok(rows.length<=50000,'Acceptance Docker image inventory exceeds its bound');let imported=0;const seen=new Set();
    for(const row of rows){
      assert.match(row.ID??'',/^sha256:[a-f0-9]{64}$/);assert.equal(typeof row.Repository,'string');assert.equal(typeof row.Tag,'string');
      if((row.Repository.startsWith('localhost/ud-agent-')||row.Repository.startsWith('ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin')||row.Repository==='<none>'&&row.Tag==='<none>')&&!held.has(row.ID)&&!ids.has(row.ID))throw new Error('Unexpected project or dangling Docker image appeared during acceptance');
      if(!ids.has(row.ID)||held.has(row.ID)||seen.has(row.ID))continue;seen.add(row.ID);
      const item=JSON.parse(docker(['image','inspect',row.ID]));assert.ok(Array.isArray(item)&&item.length===1&&item[0].Id===row.ID&&Number.isSafeInteger(item[0].Size)&&item[0].Size>=0,'Imported Docker image size is unavailable');imported+=item[0].Size;
    }
    // Docker's aggregate counters include writable layers, volumes and build
    // cache that image inspection does not see. Charge their conservative
    // growth against the same reservation without counting images twice.
    const growth=dockerStorageGrowth(engineBefore,dockerStorageSnapshot(docker(['system','df','--format','{{json .}}']))),observed=Math.max(imported,growth);
    assert.ok(Number.isSafeInteger(observed)&&observed<=reserved,'Docker images or writable engine storage exceed their admitted storage');importedImageBytes=imported;return observed;
  };
  return{ownedBytes:baseline.image_bytes,reservedBytes:reserved,measure,images:plans,endpoint:docker.endpoint,get importedImageBytes(){return importedImageBytes;}};
}

/** Own one bounded profile and retain only its external report. */
export async function withAcceptanceStorage({root,reportPath,label,engineAdmission,defaultScratchBytes=STORAGE_LIMITS.ordinaryBytes},execute){
  root=acceptanceOwner(root);
  const target=path.resolve(reportPath);
  if(existsSync(target))throw new Error('Acceptance report must be a new file');
  let activeClient,activeProcess,finished,storageError,cancelled=false,cleanupMode=false,peak=0;
  const complete=new Promise(resolve=>{finished=resolve;});
  const closeClient=async()=>{try{await activeClient?.close();}catch{/* The actual runner records the failed request. */}};
  const stopProcess=()=>{if(!activeProcess)return;const child=activeProcess;try{if(process.platform==='win32')child.kill('SIGTERM');else process.kill(-child.pid,'SIGTERM');}catch(error){if(error.code!=='ESRCH')throw error;}const timer=setTimeout(()=>{try{if(process.platform==='win32')child.kill('SIGKILL');else process.kill(-child.pid,'SIGKILL');}catch{/* Already stopped. */}},2000);timer.unref();child.once('close',()=>clearTimeout(timer));};
  const requested=process.env.UD_ACCEPTANCE_SCRATCH_BYTES??String(defaultScratchBytes);
  assert.match(requested,/^[1-9][0-9]*$/,'Acceptance scratch requires an explicit positive byte bound');
  const plannedBytes=Number(requested);
  const profileName=plannedBytes>STORAGE_LIMITS.ordinaryBytes?'release':'ordinary';
  const transientAllowance=plannedBytes>STORAGE_LIMITS.releaseBytes?plannedBytes:undefined;
  const externalOwnedBytes=engineAdmission===undefined?0:engineAdmission.ownedBytes+engineAdmission.reservedBytes;
  assert.ok(Number.isSafeInteger(externalOwnedBytes)&&externalOwnedBytes>=0,'Acceptance engine storage is not bounded');
  const storage=reserveStorage({root,plannedBytes,profile:profileName,transientAllowance,label,externalOwnedBytes,onCancel:async()=>{cancelled=true;stopProcess();await closeClient();await complete;}});
  let peakEngine=0,peakImages=0;
  const check=(additionalBytes=0)=>{if(cleanupMode)return{usedBytes:peak};if(cancelled)throw new Error('Acceptance was cancelled');if(storageError)throw storageError;if(engineAdmission){const observed=engineAdmission.measure();assert.ok(Number.isSafeInteger(observed)&&observed>=0&&observed<=engineAdmission.reservedBytes,'Acceptance engine usage exceeds its reservation');peakEngine=Math.max(peakEngine,observed);peakImages=Math.max(peakImages,engineAdmission.importedImageBytes??observed);}const sample=storage.check(additionalBytes);peak=Math.max(peak,sample.usedBytes);return sample;};
  const profile=storage.directory;
  if(target===profile||target.startsWith(profile+path.sep)){storage.cleanup();finished();throw new Error('Acceptance report must be outside disposable scratch');}
  const monitor=setInterval(()=>{try{check();}catch(error){storageError??=error;stopProcess();void closeClient();}},5000);monitor.unref();
  let result,failure,cleanupError;
  try{result=await execute({profile,check,beginCleanup:()=>{cleanupMode=true;},setClient:value=>{activeClient=value;},setProcess:value=>{activeProcess=value;},env:storage.env,engineEndpoint:engineAdmission?.endpoint});cleanupMode=false;check();}
  catch(error){failure=error;}
  finally{
    clearInterval(monitor);await closeClient();
    try{storage.cleanup();}catch(error){cleanupError=error;}
    try{
      const report=JSON.parse(await readFile(target,'utf8'));
      report.scratch_cleanup=cleanupError?'failed':'verified';report.peak_scratch_bytes=peak;
      if(engineAdmission)report.engine_storage={baseline_bytes:engineAdmission.ownedBytes,import_reservation_bytes:engineAdmission.reservedBytes,peak_imported_image_bytes:peakImages,peak_engine_growth_bytes:peakEngine};
      if(failure||storageError||cancelled||cleanupError){report.status='failed-or-incomplete';report.storage_error=String((cleanupError??storageError??failure)?.message??'Acceptance was cancelled');}
      await writeFile(target,JSON.stringify(report,null,2)+'\n');
      if(result&&typeof result==='object')Object.assign(result,report);
    }catch(error){if(error.code!=='ENOENT')failure??=error;}
    finished();
  }
  if(cleanupError)throw cleanupError;if(failure)throw failure;return result;
}

/** Run potentially writing subprocesses asynchronously so the lease can stop them. */
export async function runAcceptanceCommand(command,args,{env,cwd,timeout=180000,maxBuffer=4*1024**2,storage}={}){
  storage?.check();
  const child=spawn(command,args,{cwd,env,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});storage?.setProcess(child);
  const stdoutParts=[],stderrParts=[];let outputBytes=0,tooLarge=false,timedOut=false;
  const stop=()=>{try{if(process.platform==='win32')child.kill('SIGKILL');else process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}};
  const capture=(chunk,kind)=>{outputBytes+=chunk.length;if(outputBytes>maxBuffer){tooLarge=true;stop();return;}(kind==='stdout'?stdoutParts:stderrParts).push(chunk);};
  child.stdout.on('data',chunk=>capture(chunk,'stdout'));child.stderr.on('data',chunk=>capture(chunk,'stderr'));
  const timer=setTimeout(()=>{timedOut=true;stop();},timeout);timer.unref();
  let result;try{result=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(status,signal)=>resolve({status,signal}));});}
  finally{clearTimeout(timer);storage?.setProcess(undefined);}
  storage?.check();
  if(tooLarge)throw new Error('Acceptance subprocess exceeded its output limit');if(timedOut)throw new Error('Acceptance subprocess timed out');
  return {...result,stdout:Buffer.concat(stdoutParts).toString('utf8'),stderr:Buffer.concat(stderrParts).toString('utf8')};
}
async function digestFile(file,maximum){const hash=createHash('sha256');let size=0;for await(const chunk of createReadStream(file,{flags:constants.O_RDONLY|(constants.O_NOFOLLOW??0)})){size+=chunk.length;assert.ok(size<=maximum,'Asset exceeds its frozen bound');hash.update(chunk);}assert.equal(size,maximum);return hash.digest('hex');}
const ENGINES=['apple-container','lima-nerdctl','wslc','podman','docker','docker-rootless'];
export function providerEvidenceScope(manifest,qualification='candidate'){
  assert.ok(['candidate','diagnostic','available-target'].includes(qualification),'Provider evidence scope must be candidate, diagnostic or available-target');
  if(qualification==='available-target'){assert.equal(manifest.qualification,'available-target-runtime-inputs','Actual runtime inputs differ from requested evidence scope');return{qualification:'available-target-provider-preacceptance-execution',acceptance_eligible:false,target_execution_eligible:true};}
  const diagnostic=qualification==='diagnostic';assert.equal(manifest.qualification,diagnostic?'diagnostic-runtime-inputs':'preacceptance-runtime-inputs','Actual runtime inputs differ from requested evidence scope');
  return{qualification:diagnostic?'diagnostic-installed-provider-execution-not-final-acceptance':'native-provider-preacceptance-execution',acceptance_eligible:!diagnostic};
}
export function providerMatrixFormats(row,format='all'){
  const formats=runtimeInputFormats(row);assert.ok(['native','mcpb','npm','all'].includes(format),'Unsupported installed entrypoint format');
  assert.ok(format==='all'||formats.includes(format),'Requested installed entrypoint is absent from the immutable candidate');return format==='all'?formats:[format];
}
/** Select only the requested provider's directory, Node, and fixed OS utilities. */
export async function providerAcceptanceSearchPath(profile,{searchPath=process.env.PATH??'',platform=process.platform,node=process.execPath,systemRoot=process.env.SystemRoot??'C:\\Windows'}={}){
  if(profile.engine==='userspace')return{path:profile.searchPath};
  const commands={'apple-container':'container','lima-nerdctl':'limactl',wslc:'wsl',podman:'podman',docker:'docker','docker-rootless':'docker'},command=commands[profile.engine];assert.ok(command,'Unsupported explicit provider executable');
  let selected,executable,info;
  for(const directory of searchPath.split(path.delimiter)){if(!path.isAbsolute(directory))continue;const file=path.join(directory,command+(platform==='win32'?'.exe':''));try{const actual=await realpath(file),stat=await lstat(actual);assert.ok(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=256*1024**2,'Selected provider CLI is not an ordinary bounded executable');assert.ok(platform==='win32'||(stat.mode&0o111)!==0,'Selected provider CLI is not executable');selected=file;executable=actual;info=stat;break;}catch(error){if(error.code==='ENOENT')continue;throw error;}}
  assert.ok(executable,'Explicit provider CLI prerequisite is absent from the selected search path');
  const directories=[path.dirname(node),path.dirname(selected),...(platform==='win32'?[path.join(systemRoot,'System32')]:['/usr/bin','/bin'])];
  return{path:[...new Set(directories)].join(path.delimiter),engine:{selected_path:selected,executable,sha256:await digestFile(executable,info.size),size_bytes:info.size}};
}
export function providerProfile(platform,arch,engine){
  const preferred={ 'darwin-arm64':'apple-container','darwin-x64':'lima-nerdctl','linux-arm64':'podman','linux-x64':'podman','win32-arm64':'wslc','win32-x64':'wslc' };
  const target=platform+'-'+arch;assert.ok(Object.hasOwn(preferred,target),'Unsupported native acceptance target');
  const selected=engine??preferred[target];assert.ok(ENGINES.includes(selected),'Unsupported provider acceptance engine');
  assert.ok(!['apple-container','lima-nerdctl'].includes(selected)||selected===preferred[target], 'Provider profile is not native on this target');
  assert.ok(selected!=='wslc'||platform==='win32','WSLc requires actual Windows');
  return{target,engine:selected,worker:'linux/'+(arch==='arm64'?'arm64':'amd64')};
}
export function substitute(value,workspace,output){if(typeof value==='string')return value.replaceAll('${WORKSPACE}',workspace).replaceAll('${OUTPUT}',output);if(Array.isArray(value))return value.map(item=>substitute(item,workspace,output));if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,substitute(item,workspace,output)]));return value;}
export function checkedFixture(file){assert.ok(typeof file.path==='string'&&!path.isAbsolute(file.path)&&!file.path.includes('\\')&&file.path.split('/').every(part=>part&&!['.','..','.git'].includes(part)),'Unsafe authored fixture path');const bytes=Buffer.from(file.content_base64,'base64');assert.equal(bytes.toString('base64'),file.content_base64);assert.equal(bytes.length,file.size_bytes);assert.equal(digest(bytes),file.sha256);return bytes;}
export function requireFixtureExpectations(fixtures,operations){
  assert.ok(Array.isArray(fixtures?.cases)&&Array.isArray(operations)&&operations.length===102,'The complete operation fixture catalog is required');
  assert.deepEqual(fixtures.cases.map(item=>item.operation).sort(),[...operations].sort(),'Fixtures must identify every operation exactly once');
  assert.equal(new Set(operations).size,102);
  for(const fixture of fixtures.cases){assert.ok(Array.isArray(fixture.files)&&Array.isArray(fixture.prerequisites),'Operation fixture inputs are incomplete');
    assert.ok(fixture.expected_fields&&typeof fixture.expected_fields==='object'&&!Array.isArray(fixture.expected_fields),'Independent expected fields are required');
    assert.ok(Object.keys(fixture.expected_fields).length>0||Array.isArray(fixture.expected_artifacts)&&fixture.expected_artifacts.length>0,'Empty independent expectations cannot establish operation behavior');
  }
}
function stateBase(profile,platform){return platform==='win32'?path.join(profile,'ud-agent','data','userspace'):platform==='darwin'?path.join(profile,'Library','Application Support','ud-agent','userspace'):path.join(profile,'ud-agent','userspace');}
function selectedRecord(lock,engine,target){return lock.provider_receipts?.[engine+'/'+target.replace('-', '/')];}
async function offlineStager(candidateRoot,manifest,installation,state,storage){
  const lock=JSON.parse(await readFile(path.join(installation,'runtime/runtime.lock.json'))),rows=manifest.offline_assets;
  assert.ok(Array.isArray(rows),'Candidate inputs must include a closed offline asset inventory');
  const native=(lock.native_helpers??lock.native)?.[process.platform+'/'+process.arch]?.guard;
  const privateDirectory=async(directory)=>{await mkdir(directory,{recursive:true,mode:0o700});if(process.platform==='win32'){
    assert.ok(native,'Packaged Windows guard is required for private cache fixture preparation');const helper=path.join(installation,native.path);assert.equal(await digestFile(helper,native.size_bytes),native.sha256.slice(7));
    const invoke=args=>{const result=spawnSync(helper,args,{encoding:'utf8',timeout:30000,maxBuffer:65536});assert.equal(result.error,undefined,result.stderr);assert.equal(result.status,0,result.stderr);return result.stdout;};
    const identity=JSON.parse(invoke(['identity','--root',directory]));assert.match(identity.device,/^\d+$/);assert.match(identity.inode,/^\d+$/);
    invoke(['state-private-init','--root',directory,'--path','.','--root-device',identity.device,'--root-inode',identity.inode]);
  }};
  await privateDirectory(state);
  const seed=async(descriptor,destination)=>{
    const hash=(descriptor.sha256??'').replace(/^sha256:/,'');const size=descriptor.size_bytes??descriptor.size;
    assert.match(hash,/^[a-f0-9]{64}$/);assert.ok(Number.isSafeInteger(size)&&size>0);
    const matches=rows.filter(row=>row.sha256.replace(/^sha256:/,'')===hash&&row.size_bytes===size);assert.ok(matches.length>=1,'Required selected offline asset is missing');
    const source=path.join(candidateRoot,matches[0].path),info=await lstat(source);assert.ok(info.isFile()&&!info.isSymbolicLink()&&info.size===size);
    assert.equal(await digestFile(source,size),hash);storage?.check(existsSync(destination)?0:size);await privateDirectory(path.dirname(destination));
    try{await copyFile(source,destination,constants.COPYFILE_EXCL);}catch(error){if(error.code!=='EEXIST')throw error;const cached=await lstat(destination);assert.ok(cached.isFile()&&!cached.isSymbolicLink()&&cached.size===size);assert.equal(await digestFile(destination,size),hash);}
    await chmod(destination,0o444);assert.equal(await digestFile(destination,size),hash);storage?.check();return destination;
  };
  const pinnedNode=path.join(installation,'runtime/windows-node.json');
  if(process.platform==='win32'&&existsSync(pinnedNode)){
    const pin=JSON.parse(await readFile(pinnedNode,'utf8'));
    await seed(pin,path.join(path.dirname(state),'node-cache',`node-${pin.sha256.slice(7)}.exe`));
  }
  return{lock,seed,privateDirectory};
}
export async function seedOfflineProviderAssets(candidateRoot,manifest,installation,state,profile,storage){
  const {lock,seed,privateDirectory}=await offlineStager(candidateRoot,manifest,installation,state,storage);await privateDirectory(state+'-'+(profile.engine==='docker-rootless'?'docker':profile.engine));
  for(const pack of ['core','render']){
    const image=lock.packs?.[pack]?.images?.[profile.worker];assert.ok(image,'Pending native build: selected worker architecture is absent');
    const format=['docker','docker-rootless','podman'].includes(profile.engine)?'docker-archive':'oci-archive';
    const transport=image.transports?.find(row=>row.format===format);assert.ok(transport,'Required per-architecture offline transport is absent');
    await seed(transport,path.join(state+'-'+(profile.engine==='docker-rootless'?'docker':profile.engine),'images',transport.sha256.slice(7)+'.tar'));
  }
  const record=selectedRecord(lock,profile.engine,profile.target);
  if(record?.lazy_assets)await seed(record.lazy_assets,path.join(state+'-'+(profile.engine==='docker-rootless'?'docker':profile.engine),'provider-cache',record.lazy_assets.sha256.slice(7)+'.tar.gz'));
  return{runtime_lock_sha256:digest(await readFile(path.join(installation,'runtime/runtime.lock.json'))),selected_engine:profile.engine,worker_architecture:profile.worker};
}
/** Seed exact frozen artifacts only; setup still performs real extraction/install/probes. */
export async function seedOfflineUserspaceAssets(candidateRoot,manifest,installation,state,{installer,platform=process.platform,arch=process.arch,storage}={}){
  assert.ok(['uv','venv'].includes(installer),'Forced userspace installer is required');const {seed}=await offlineStager(candidateRoot,manifest,installation,state,storage),bytes=await readFile(path.join(installation,'runtime/userspace.lock.json')),runtime=JSON.parse(await readFile(path.join(installation,'runtime/runtime.lock.json')));
  assert.equal('sha256:'+digest(bytes),runtime.userspace_sha256);const selected=JSON.parse(bytes).platforms?.[platform+'/'+arch];assert.ok(selected,'Pending native build: selected userspace platform is absent');const seeded=[];
  for(const [field,directory]of [['lazy_core','core-cache'],['lazy_render','render-cache']])if(selected[field]){const descriptor=selected[field];seeded.push(await seed(descriptor,path.join(state,directory,descriptor.sha256.slice(7)+'.tar.gz')));}
  if(installer==='uv'&&selected.uv_download){const descriptor=selected.uv_download,target=await seed(descriptor,path.join(state,'tools','uv-'+descriptor.sha256.slice(7)+(platform==='win32'?'.exe':'')));await chmod(target,0o500);seeded.push(target);}
  if(installer==='uv'&&selected.uv_vendor_download){const descriptor=selected.uv_vendor_download;seeded.push(await seed(descriptor,path.join(state,'tools','uv-'+descriptor.sha256.slice(7)+'.zip')));}
  if(installer==='venv')assert.equal(selected.uv,undefined,'The original package mandates bundled uv, so it cannot exercise genuine venv fallback');
  if(selected.python_download){const descriptor=selected.python_download,url=new URL(descriptor.url),match=/^\/astral-sh\/python-build-standalone\/releases\/download\/(\d{8})\/([^/]+)$/.exec(url.pathname);assert.equal(url.protocol,'https:');assert.equal(url.hostname,'github.com');assert.ok(match,'Pinned managed Python release layout is invalid');const filename=decodeURIComponent(match[2]);assert.ok(!filename.includes('/')&&!filename.includes('\\')&&!filename.includes('..')&&!filename.includes('\0'));seeded.push(await seed(descriptor,path.join(state,'python-mirror',match[1],filename)));}
  if(selected.perl?.deferred_runtime){
    const relative=selected.perl.deferred_runtime.recipe??selected.perl.deferred_runtime,host=platform+'/'+arch;
    const entry=selected.files.find(row=>row.path===relative);assert.ok(entry,'Private Perl vendor recipe is outside the selected closed inventory');
    const recipeSha256=entry.sha256.slice(7);
    let recipe;
    try{recipe=JSON.parse(readRecordedBytes(installation,{path:relative,sha256:recipeSha256,size:entry.size},4*1024**2).toString('utf8'));}
    catch(error){if(error.code!=='ENOENT'||!selected.lazy_core)throw error;}
    let archives;
    if(recipe){
      assert.equal(recipe.provider,'conda-vc-runtime');assert.equal(recipe.platform,host);
      archives=[{...recipe.archive,archive_format:'conda'}];
      if(recipe.supplier){
        const archive=recipe.supplier.archive,archiveFormat=archive.url.match(/\.(conda|tar\.bz2)$/)?.[1];
        assert.ok(archiveFormat,'Unsupported private Perl supplier archive format');
        archives.push({...archive,archive_format:archiveFormat});
      }
    }else{
      // The suite's already verified runtime inputs bind both archives to
      // the same recipe even when the thin npm install holds only the lock.
      archives=manifest.offline_assets.filter(row=>row.platform===host&&['perl-vendor','perl-supplier'].includes(row.cache_role)&&row.recipe_sha256===recipeSha256);
      assert.equal(archives.filter(row=>row.cache_role==='perl-vendor'&&row.archive_format==='conda').length,1,'Frozen private Perl vendor recipe join is missing');
      assert.equal(new Set(archives.map(row=>row.cache_role)).size,archives.length,'Frozen private Perl vendor recipe joins are duplicated');
    }
    for(const asset of archives){
      assert.ok(['conda','tar.bz2'].includes(asset.archive_format),'Unsupported private Perl archive format');
      seeded.push(await seed(asset,path.join(state,'perl-vendor-cache',asset.sha256.replace(/^sha256:/,'')+'.'+asset.archive_format)));
    }
  }
  // These roles are issued only by verifyRuntimeInputs after exact frozen recipe joins.
  for(const asset of manifest.offline_assets.filter(row=>row.platform===platform+'/'+arch&&row.cache_role==='render-vendor')){assert.match(asset.recipe_sha256??'',/^[a-f0-9]{64}$/);assert.ok(['msi','zip'].includes(asset.archive_format));const hash=asset.sha256.replace(/^sha256:/,'');seeded.push(await seed(asset,path.join(state,'render-vendor-cache',hash+'.'+asset.archive_format)));}
  return{installer,platform:platform+'/'+arch,seeded,userspace_lock_sha256:digest(bytes),network_requests:0};
}
function field(value,name){return name.split('.').reduce((item,key)=>item?.[key],value);}
export async function readResourceBytes(client,reference){
  assert.match(reference?.uri??'',/^ud:\/\/(?:artifacts|reports|plans|contexts|operations)\//);const parts=[];let uri=reference.uri,total=0;const cursors=new Set();
  for(let page=0;uri&&page<1025;page++){
    assert.ok(!cursors.has(uri),'Repeated artifact cursor');cursors.add(uri);const response=await client.readResource({uri});assert.equal(response.contents.length,1);const content=response.contents[0];
    let bytes,next;
    if(typeof content.blob==='string')bytes=Buffer.from(content.blob,'base64');
    else{assert.equal(typeof content.text,'string');let value;try{value=JSON.parse(content.text);}catch{}if(value?.encoding==='base64'&&value?.resource?.uri===reference.uri){assert.equal(value.offset,total);assert.equal(value.resource.sha256,reference.sha256);assert.equal(value.resource.size_bytes,reference.size_bytes);bytes=Buffer.from(value.content_base64,'base64');assert.equal(bytes.toString('base64'),value.content_base64);next=value.next_cursor;}else bytes=Buffer.from(content.text);}
    total+=bytes.length;assert.ok(total<=reference.size_bytes);parts.push(bytes);uri=next?reference.uri+'?cursor='+encodeURIComponent(next):undefined;
  }
  assert.equal(uri,undefined,'Artifact pagination is incomplete');const bytes=Buffer.concat(parts);assert.equal(bytes.length,reference.size_bytes);assert.equal(digest(bytes),reference.sha256);return bytes;
}
export async function readArtifact(client,reference){assert.ok(reference?.uri?.startsWith('ud://artifacts/'));return readResourceBytes(client,reference);}
async function readResult(client,response){const value=response.structuredContent?.result;return value?.status==='resource'?JSON.parse((await readResourceBytes(client,value.report_resource)).toString()):value;}
export async function jobRecords(root){
  const records=new Map();
  async function visit(directory,depth){if(depth>4)return;let entries;try{entries=await readdir(directory,{withFileTypes:true});}catch(error){if(error.code==='ENOENT')return;throw error;}
    for(const entry of entries){if(entry.isSymbolicLink())throw new Error('Owned acceptance state contains a linked job entry');const file=path.join(directory,entry.name);if(entry.isDirectory())await visit(file,depth+1);else if(entry.isFile()&&entry.name.endsWith('.json')){const info=await lstat(file);if(info.size>1048576)continue;const bytes=await readFile(file);let value;try{value=JSON.parse(bytes);}catch{continue;}if(typeof value.phase==='string'&&(value.id||value.name))records.set(file,{record:value,sha256:digest(bytes)});}}
  }for(const directory of ['platform-jobs','docker-jobs','podman-jobs','jobs'])await visit(path.join(root,directory),0);return records;
}
async function exerciseCancellation(client,fixture,privateRoot,state,engine){
  const workspace=path.join(privateRoot,'cancel','workspace'),output=path.join(privateRoot,'cancel','output');await mkdir(workspace,{recursive:true});await mkdir(output);
  for(const file of fixture.files){const target=path.join(workspace,...file.path.split('/'));await mkdir(path.dirname(target),{recursive:true});await writeFile(target,checkedFixture(file),{flag:'wx'});}
  const args=substitute(fixture.arguments,workspace,output);assert.equal(typeof args.validator_module_path,'string');assert.ok(!path.isAbsolute(args.validator_module_path)&&!args.validator_module_path.split('/').includes('..'));
  await writeFile(path.join(workspace,args.validator_module_path),'import time\ntime.sleep(60)\n');
  const providerRoot=state+'-'+(engine==='docker-rootless'?'docker':engine),before=await jobRecords(providerRoot),controller=new AbortController();let settled=false;
  const running=client.callTool({name:'project_consistency_report',arguments:args},{signal:controller.signal,timeout:120000}).then(value=>{settled=true;return value;},error=>{settled=true;return{cancel_error:error.message};});
  let observed;const deadline=performance.now()+30000;
  while(performance.now()<deadline&&!settled&&!observed){for(const [file,value]of await jobRecords(providerRoot))if(!before.has(file)&&['loader','worker','loader_created','worker_created','running'].includes(value.record.phase)){observed={path:file,...value};break;}if(!observed)await new Promise(resolve=>setTimeout(resolve,25));}
  controller.abort();const outcome=await running;assert.ok(observed,'Cancellation must observe an actual newly owned provider job before aborting');assert.ok(outcome.cancel_error||outcome.structuredContent?.execution?.status!=='completed','Cancelled operation unexpectedly reported completed');return{observed_job:observed,outcome,cleanup:'verified separately by ownership-bound maintenance'};
}
async function exerciseUserspaceCancellation(client,privateRoot,state,guard){
  const workspace=path.join(privateRoot,'cancel','workspace');await mkdir(workspace,{recursive:true,mode:0o700});
  const bytes=Buffer.from(Array.from({length:30000},(_,index)=>`# sent_id = cancel-${index}\n# text = I run\n1\tI\tI\tPRON\t_\t_\t2\tnsubj\t2:nsubj\t_\n2\trun\trun\tVERB\t_\t_\t0\troot\t0:root\t_\n\n`).join(''));
  await writeFile(path.join(workspace,'cancel.conllu'),bytes,{flag:'wx'});
  const before=await activeUserspaceLeases(state,guard),controller=new AbortController();let settled=false;
  const running=client.callTool({name:'validation_report',arguments:{working_tree_path:workspace,file_paths:['cancel.conllu'],ud_context_path:'',options:{language_code:'en',level:2}}},{signal:controller.signal,timeout:120000}).then(value=>{settled=true;return value;},error=>{settled=true;return{cancel_error:error.message};});
  let observed;const deadline=performance.now()+30000;
  try{
    while(performance.now()<deadline&&!settled&&!observed){for(const[name,value]of await activeUserspaceLeases(state,guard))if(!before.has(name)){observed={name,...value};break;}if(!observed)await new Promise(resolve=>setTimeout(resolve,25));}
  }finally{controller.abort();}
  const outcome=await running;assert.ok(observed,'Cancellation must observe a newly held actual userspace operation lease');assert.ok(outcome.cancel_error||outcome.structuredContent?.execution?.status!=='completed','Cancelled userspace validation unexpectedly reported completed');
  const cleanupDeadline=performance.now()+30000;
  while((await activeUserspaceLeases(state,guard)).has(observed.name)){assert.ok(performance.now()<cleanupDeadline,'Cancelled userspace operation did not release its owned lease');await new Promise(resolve=>setTimeout(resolve,25));}
  return{operation:'validation_report',input:{sha256:digest(bytes),size_bytes:bytes.length,sentences:30000},observed_lease:observed,outcome,lease_released:true,observation_scope:'Actual product runtime lease with held kernel lock; process-tree cleanup is also enforced by the verified worker supervisor.'};
}
async function cacheFootprint(state,engine){const root=state+'-'+(engine==='docker-rootless'?'docker':engine),files=[];let bytes=0;
  async function walk(directory,prefix){let entries;try{entries=await readdir(directory,{withFileTypes:true});}catch(error){if(error.code==='ENOENT')return;throw error;}
    for(const entry of entries){assert.ok(!entry.isSymbolicLink(),'Owned cache contains a link');const relative=prefix+'/'+entry.name,file=path.join(directory,entry.name);if(entry.isDirectory())await walk(file,relative);else{const info=await lstat(file);assert.ok(info.isFile());if(prefix.startsWith('providerpacks')||/\.tar(?:\.gz)?$/.test(entry.name)||prefix==='perl-vendor-cache'&&/\.(?:conda|tar\.bz2)$/.test(entry.name)){bytes+=info.size;files.push({path:relative,size_bytes:info.size});}}}
  }const selectedRoot=engine==='userspace'?state:root;
  for(const name of engine==='userspace'?['core-cache','render-cache','tools','python-mirror','render-vendor-cache','perl-vendor-cache']:['images','provider-cache','providerpacks'])await walk(path.join(selectedRoot,name),name);return{files:files.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0),logical_bytes:bytes};
}
export async function runInstalledCli(launch,args,env,storage){const result=await runAcceptanceCommand(launch.command,[...launch.args.slice(0,-3),...args],{env,timeout:180000,maxBuffer:4*1024**2,storage});assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);}
export async function installNpmPayloadBounded(candidateRoot,item,privateRoot,npmCli,storage){
  assert.ok(Number.isSafeInteger(item.artifact.size)&&item.artifact.size>=0,'npm candidate must supply a bounded artifact size');
  const expanded=item.root===undefined?item.expanded_size:storageTreeBytes(path.join(candidateRoot,item.root));
  assert.ok(Number.isSafeInteger(expanded)&&expanded>0&&expanded<=STORAGE_LIMITS.ordinaryBytes,'npm candidate must supply a bounded expanded size');
  storage.check(expanded+2*item.artifact.size+64*1024**2);
  const code=`import{installNpmPayload}from ${JSON.stringify(new URL('./installed-npm.mjs',import.meta.url).href)};const[root,item,dest,cli]=process.argv.slice(1);console.log(JSON.stringify(installNpmPayload(root,JSON.parse(item),dest,{npmCli:cli||undefined})));`;
  const env={PATH:path.dirname(process.execPath),LANG:'C',LC_ALL:'C',...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{}),...(process.env.WINDIR?{WINDIR:process.env.WINDIR}:{})};
  const result=await runAcceptanceCommand(process.execPath,['--input-type=module','-e',code,candidateRoot,JSON.stringify(item),privateRoot,npmCli??''],{env,timeout:360000,storage});
  assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);
}
/** Extract exactly one verified native/MCPB archive in the owned profile. */
export async function extractProviderPackage(candidateRoot,item,platform,sourceHash,runtimeHash,expandedSize,destination,verifierRuntime,storage,{diagnostic=false}={}){
  assert.ok(Number.isSafeInteger(expandedSize)&&expandedSize>0&&expandedSize<=STORAGE_LIMITS.ordinaryBytes,'Package expanded size is missing or exceeds the acceptance budget');
  assert.ok(path.resolve(destination).startsWith(path.resolve(storage.profile)+path.sep),'Package extraction must stay inside the owned acceptance profile');
  storage.check(expandedSize);
  const args=[fileURLToPath(new URL('../release/inspect-package.py',import.meta.url)),path.join(candidateRoot,item.artifact.path),'--kind','native','--platform',platform,'--source-sha256',sourceHash,'--runtime-sha256',runtimeHash,'--extract-to',destination,'--archive-sha256',item.artifact.sha256,'--archive-size',String(item.artifact.size),'--max-output-bytes',String(expandedSize),...(diagnostic?[]:['--require-candidate'])];
  const command=releasePythonCommand(verifierRuntime,args),result=await runAcceptanceCommand(command.executable,command.args,{env:{...command.env,...storage.env,TMPDIR:storage.profile,TMP:storage.profile,TEMP:storage.profile},timeout:300000,storage});
  assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr);const verified=JSON.parse(result.stdout);
  assert.equal(verified.qualification,'verified-original-package-extraction');assert.equal(verified.expanded_size,expandedSize);
  assert.equal(verified.inventory_sha256,item.inventory_sha256);assert.equal(verified.build_receipt_sha256,item.build_receipt_sha256);
  const installed=verifyInstalledPayload(destination);assert.equal(installed.inventory_sha256,item.inventory_sha256);assert.equal(installed.source_tree_sha256,sourceHash);assert.equal(installed.runtime_lock_sha256,runtimeHash);
  return {root:destination,evidence:verified};
}
async function packagedGuard(installation){
  const lock=JSON.parse(await readFile(path.join(installation,'runtime/runtime.lock.json'))),target=process.platform+'/'+process.arch;
  const record=lock.native_helpers?.[target]?.guard??lock.native?.[target]?.guard;
  assert.ok(record&&typeof record.path==='string'&&!path.isAbsolute(record.path)&&record.path.split('/').every(part=>part&&!['.','..'].includes(part)),'Original packaged native guard is required');
  const guard=path.join(installation,record.path);assert.equal(await digestFile(guard,record.size_bytes),record.sha256.slice(7));return guard;
}
export async function runNativeProviderAcceptance(options){
  const root=fileURLToPath(new URL('../../',import.meta.url));
  const qa=options.qaProfile===undefined?undefined:providerQaExecution(options.qaProfile);
  if(options.qualification==='available-target')assert.ok(qa,'Available-target runtime execution requires an explicit closed QA execution profile');
  const verifierSource=sourceReceipt(root);
  // Preserve read-only interpreter rejection before storage admission; staging
  // itself happens only after the bounded profile has been reserved.
  preflightReleaseInterpreter(root,verifierSource,options.python);
  const selected=options.engine??providerProfile(process.platform,process.arch).engine;
  const engineAdmission=['docker','docker-rootless'].includes(selected)?dockerAcceptanceAdmission(root,options.candidateRoot):existingAcceptanceDockerAdmission(root);
  // Reserve for the expanded provider and both OCI packs alongside the installed archives.
  return withAcceptanceStorage({root,reportPath:options.reportPath,label:'native-provider-acceptance',engineAdmission,defaultScratchBytes:8_000_000_000},async storage=>{
    const verifierRuntime=verifyReleaseInterpreter(root,verifierSource,{python:options.python,scratchParent:storage.profile,beforeStage:storage.check});
    try{return await runNativeProviderWithRuntime(options,verifierRuntime,verifierSource,root,qa,storage);}finally{closeReleaseInterpreter(verifierRuntime);}
  });
}
export function providerQaExecution(profileRoot){
  const root=fileURLToPath(new URL('../../',import.meta.url)),qa=verifyRuntimeExecutionProfile(profileRoot,{sourceRoot:root});
  const modules=['@modelcontextprotocol/client','@modelcontextprotocol/client/stdio','ajv/dist/2020.js'].map(specifier=>{const executable=realpathSync(fileURLToPath(import.meta.resolve(specifier)));assert.ok(executable.startsWith(qa.qa_node_modules+path.sep),'Driver dependency resolved outside the explicit QA prefix');const relative=path.relative(qa.qa_node_modules,executable).split(path.sep).join('/');return{specifier,...fileReceipt(qa.qa_node_modules,relative)};});
  return{...qa,module_resolution:modules};
}
async function runNativeProviderWithRuntime({candidateRoot,python,reportPath,engine,format='all',qualification='candidate',installer,searchPath,npmCli,expectedPython,jobs=1},verifierRuntime,verifierSource,verifierRoot,qa,storage){
  assert.ok(Number.isSafeInteger(jobs)&&jobs>=1&&jobs<=3,'Acceptance concurrency must be an explicit integer from1 to3');
  assert.ok(typeof python==='string'&&path.isAbsolute(python),'Exact locked original archive-verifier Python is required');assert.ok(['native','mcpb','npm','all'].includes(format));
  assert.ok(['candidate','diagnostic','available-target'].includes(qualification),'Provider evidence scope must be candidate, diagnostic or available-target');
  assert.ok(engine==='userspace'||installer===undefined&&searchPath===undefined,'Userspace installer/search path cannot override an OCI profile');
  assert.ok(expectedPython===undefined||engine==='userspace'&&['3.14','3.15'].includes(expectedPython),'Expected Python is supported only for the 3.14/3.15 userspace profiles');
  const profile=engine==='userspace'?userspaceAcceptanceProfile(process.platform,process.arch,installer,searchPath):providerProfile(process.platform,process.arch,engine),row=verifyRuntimeInputs(candidateRoot,profile.target,{python,verifierRuntime,allowDiagnostic:qualification==='diagnostic',allowAvailable:qualification==='available-target'}),scope=providerEvidenceScope(row.candidate,qualification),formats=providerMatrixFormats(row,format);
  if(qualification==='available-target')assert.ok(row.available_bindings?.candidate_bindings_verified===true&&row.available_bindings.material_bindings_verified===true&&row.available_bindings.source_replay_performed===false&&row.available_bindings.source_replay_required===true,'Available-target candidate/material byte bindings were not verified');
  const providerSearch=await providerAcceptanceSearchPath(profile);
  if(scope.acceptance_eligible||scope.target_execution_eligible)assert.equal(verifierSource.sha256,row.candidate.source_sha256,'Acceptance driver source must match the frozen candidate source');
  if(profile.engine.startsWith('docker'))localDockerAuthority(process.env,context=>{const result=spawnSync('docker',['context','inspect',...(context?[context]:[]),'--format','{{json .Endpoints.docker.Host}}'],{encoding:'utf8',timeout:10000,maxBuffer:65536});assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout.trim());});
  const privateRoot=storage.profile,state=stateBase(privateRoot,process.platform),rows=[],lifecycle=[];
  const report={schema_version:1,...scope,status:'failed-or-incomplete',verifier_source_sha256:verifierSource.sha256,verifier_runtime:releaseVerifierReceipt(verifierRuntime),concurrency:jobs,host:{os:process.platform,process_architecture:process.arch,emulation:false},provider:profile.engine,provider_executable:providerSearch.engine,worker_architecture:profile.worker,candidate:row.candidate_receipt,source_sha256:row.candidate.source_sha256,runtime_lock_sha256:row.candidate.runtime_lock_sha256,private_profile:privateRoot,rows,lifecycle,limitations:['Actual native provider execution is separate from signing, publication, directory approval and hosted-model evaluation.']};
  if(qa)report.qa_execution=qa;
  if(profile.engine==='userspace'){report.installer=profile.installer;if(expectedPython!==undefined)report.expected_python=expectedPython;report.limitations.push('Trusted built-ins execute in product-owned userspace; operation050 is a separately verified OCI-policy rejection, never a successful domain execution.');}
  let saves=Promise.resolve();const save=()=>{const bytes=JSON.stringify(report,null,2)+'\n';saves=saves.then(()=>writeFile(reportPath,bytes));return saves;};await mkdir(path.dirname(reportPath),{recursive:true});await writeFile(reportPath,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  report.driver_inputs=await Promise.all(['./native-provider-acceptance.mjs','./userspace-acceptance.mjs','./installed-payload.mjs','./installed-npm.mjs','./runtime-execution-profile.mjs','./node-dependencies.mjs','./mutation-scope.mjs','../release/runtime-inputs.mjs','../release/available-candidate.mjs'].map(async file=>({path:file,sha256:digest(await readFile(new URL(file,import.meta.url)))})));report.formats=formats;if(row.candidate.available_candidate){report.available_candidate=row.candidate.available_candidate;report.available_bindings=row.available_bindings;report.source_replay_performed=false;report.source_coverage_receipt=row.available_bindings.source_coverage_receipt;report.source_replay_required=true;report.limitations.push('Only exact candidate/material/coverage byte bindings and the available runtime target were checked here; independent full source replay remains a separate final release gate. Pending platforms/artifacts, mutation acceptance and publisher authority remain separate obligations.');}await save();
  const environment={PATH:providerSearch.path,HOME:privateRoot,USERPROFILE:privateRoot,LOCALAPPDATA:privateRoot,XDG_DATA_HOME:privateRoot,TMPDIR:privateRoot,TMP:privateRoot,TEMP:privateRoot,...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{}),...(process.env.WINDIR?{WINDIR:process.env.WINDIR}:{}),...(profile.engine.startsWith('docker')?{DOCKER_CONFIG:process.env.DOCKER_CONFIG??path.join(os.homedir(),'.docker'),DOCKER_HOST:storage.engineEndpoint}:{}),...(process.env.XDG_RUNTIME_DIR?{XDG_RUNTIME_DIR:process.env.XDG_RUNTIME_DIR}:{})};
  if(process.platform==='win32')environment.UD_AGENT_OFFLINE='1';
  const fixtures=JSON.parse(await readFile(path.join(candidateRoot,row.candidate.fixtures.path))),ajv=new Ajv2020({strict:true,allErrors:true}),npmInstallations=[];let cleanupLaunch,cleanupGuard;
  const gitSearchPath=profile.engine==='userspace'?profile.searchPath:process.env.PATH??'';
  const packageRoot=row.package_root??candidateRoot;
  requireFixtureExpectations(fixtures,row.operation_names);
  const archiveBacked=row.formats.native.root===undefined;
  async function cleanupOwned(){
    if(!cleanupLaunch)return;
    const started=performance.now();
    try{const maintenance=await runInstalledCli(cleanupLaunch,['uninstall','--owned-runtime','--engine',profile.engine],environment,storage);assert.ok(maintenance.providers.every(item=>item.status==='complete'&&item.protected_paths.length===0),'Owned provider cleanup remains incomplete');if(profile.engine==='userspace'){assert.equal(maintenance.scope,'userspace');assert.equal(maintenance.action,'owned-runtime');assert.equal(maintenance.dry_run,false);assert.ok((await activeUserspaceLeases(state,cleanupGuard)).size===0,'Userspace cleanup left a held operation lease');}lifecycle.push({stage:'owned-cleanup',status:'passed',elapsed_ms:performance.now()-started,result:maintenance});cleanupLaunch=undefined;cleanupGuard=undefined;}
    catch(error){lifecycle.push({stage:'owned-cleanup',status:'failed',error:error.message});throw error;}
  }
  try{
    report.host_prerequisites={git:await userspaceGitEvidence(gitSearchPath)};if(profile.engine!=='userspace')environment.PATH=[...new Set([...environment.PATH.split(path.delimiter),path.dirname(report.host_prerequisites.git.selected_path)])].join(path.delimiter);await save();
    for(const selectedFormat of formats){
      storage.check();
      let installation,node=process.execPath;
      if(selectedFormat==='npm'){const begin=performance.now(),installed=await installNpmPayloadBounded(packageRoot,{...row.formats.npm,expanded_size:row.archive_expanded_sizes.npm},path.join(privateRoot,'npm-installation'),npmCli,storage);installation=installed.root;node=installed.node;npmInstallations.push({root:installation,payload:installed.receipt.payload});lifecycle.push({format:selectedFormat,stage:'actual-offline-npm-installation',status:'passed',elapsed_ms:performance.now()-begin,evidence:installed.receipt});await save();}
      else {const begin=performance.now(),extracted=await extractProviderPackage(packageRoot,row.formats[selectedFormat],profile.target,row.candidate.source_sha256,row.candidate.runtime_lock_sha256,row.archive_expanded_sizes[selectedFormat],path.join(privateRoot,'package-'+selectedFormat),verifierRuntime,storage,{diagnostic:qualification==='diagnostic'});installation=extracted.root;lifecycle.push({format:selectedFormat,stage:'verified-original-package-extraction',status:'passed',elapsed_ms:performance.now()-begin,evidence:extracted.evidence});await save();}
      const launch=installedMcpLaunch(installation,privateRoot,{format:selectedFormat,node,localAppData:privateRoot});cleanupLaunch=selectedFormat==='npm'?launch:installedMcpLaunch(archiveBacked?installation:path.join(packageRoot,row.formats.native.root),privateRoot,{format:'native',localAppData:privateRoot});
      if(profile.engine==='userspace')cleanupGuard=await packagedGuard(archiveBacked?installation:path.join(packageRoot,row.formats.native.root));
      if(profile.engine==='userspace')await seedOfflineUserspaceAssets(candidateRoot,row.candidate,installation,state,{installer:profile.installer,storage});else await seedOfflineProviderAssets(candidateRoot,row.candidate,installation,state,profile,storage);
      const client=new Client({name:'ud-native-provider-acceptance',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});storage.setClient(client);const transport=new StdioClientTransport({command:launch.command,args:launch.args,env:environment,stderr:'pipe'});let stderr='';transport.stderr?.on('data',chunk=>{stderr+=chunk;if(stderr.length>1024**2)stderr=stderr.slice(-(1024**2));});
      const started=performance.now();
      try{
        await client.connect(transport);const actualTools=(await client.listTools()).tools,registered=[...JSON.parse(await readFile(path.join(installation,'contracts/ud-interfaces.json'))),...JSON.parse(await readFile(path.join(installation,'contracts/environment.json')))];assert.equal(actualTools.length,104);assert.equal(new Set(actualTools.map(item=>item.name)).size,104);assert.deepEqual(actualTools.map(item=>item.name).sort(),registered.map(item=>item.name).sort());report.registered_operations??=registered.map(item=>item.name);assert.deepEqual(report.registered_operations,registered.map(item=>item.name));
        const setupArguments={working_tree_path:privateRoot,engine:profile.engine,required_tools:['validation_report','sentence_render'],network:'offline'};
        const setup=await client.callTool({name:'setup_ud_environment',arguments:setupArguments},{timeout:600000});assert.notEqual(setup.isError,true,JSON.stringify(setup));assert.equal(setup.structuredContent.result.ready,true,JSON.stringify(setup));assert.equal(setup.structuredContent.result.runtime.engine,profile.engine);lifecycle.push({format:selectedFormat,stage:'initial-session-setup',state_before_setup:formats.indexOf(selectedFormat)>0?'reused-prior-format-state':'fresh-profile',elapsed_ms:performance.now()-started,result:setup.structuredContent.result});
        if(profile.engine==='userspace')lifecycle.push({format:selectedFormat,stage:'actual-installer-verified',status:'passed',evidence:await userspaceInstallerEvidence(state,profile.installer,setup.structuredContent.result.runtime.runtime_manifest_sha256,expectedPython)});
        const coldCache=await cacheFootprint(state,profile.engine);const warmStart=performance.now(),warm=await client.callTool({name:'setup_ud_environment',arguments:setupArguments},{timeout:600000});assert.equal(warm.structuredContent.result.ready,true);assert.equal(warm.structuredContent.result.runtime.engine,profile.engine);assert.deepEqual(await cacheFootprint(state,profile.engine),coldCache,'Warm setup changed the frozen cache inventory');assert.deepEqual(warm.structuredContent.result.runtime.virtual_machine,setup.structuredContent.result.runtime.virtual_machine,'Warm setup replaced its verified VM');lifecycle.push({format:selectedFormat,stage:'warm-setup',elapsed_ms:performance.now()-warmStart,cache:coldCache,result:warm.structuredContent.result});
        const inquiryStarted=performance.now(),inquiry=await client.callTool({name:'check_ud_environment',arguments:{working_tree_path:privateRoot,engine:profile.engine,required_tools:['validation_report','sentence_render'],offline:true}},{timeout:600000});assert.notEqual(inquiry.isError,true,JSON.stringify(inquiry));assert.equal(inquiry.structuredContent.execution.status,'completed');assert.equal(inquiry.structuredContent.result.ready,true);assert.equal(inquiry.structuredContent.result.runtime.engine,profile.engine);assert.deepEqual(await cacheFootprint(state,profile.engine),coldCache,'Readiness inquiry changed the frozen cache inventory');lifecycle.push({format:selectedFormat,stage:'explicit-readiness-inquiry',operation:'check_ud_environment',status:'passed',elapsed_ms:performance.now()-inquiryStarted,result:inquiry.structuredContent.result});
        const cancellation=profile.engine==='userspace'?await exerciseUserspaceCancellation(client,path.join(privateRoot,selectedFormat),state,cleanupGuard):await exerciseCancellation(client,fixtures.cases.find(row=>row.operation==='project_consistency_report'),path.join(privateRoot,selectedFormat),state,profile.engine);lifecycle.push({format:selectedFormat,stage:'live-job-cancellation',status:'passed',...cancellation});await save();
        const runCase=async fixture=>{
          const fixtureBytes=fixture.files.reduce((sum,file)=>sum+file.size_bytes,0)+(fixture.expected_artifacts??[]).reduce((sum,item)=>sum+item.size_bytes,0);
          storage.check(fixtureBytes);
          const workspace=path.join(privateRoot,selectedFormat,fixture.operation,'workspace'),output=path.join(privateRoot,selectedFormat,fixture.operation,'output');await mkdir(workspace,{recursive:true,mode:0o700});await mkdir(output,{mode:0o700});const begin=performance.now();
          try{
            for(const file of fixture.files){const bytes=checkedFixture(file),target=path.join(workspace,...file.path.split('/'));await mkdir(path.dirname(target),{recursive:true});await writeFile(target,bytes,{flag:'wx'});}
            const args=substitute(fixture.arguments,workspace,output);
            for(const prerequisite of fixture.prerequisites){assert.equal(prerequisite.type,'existing_git_repository');const history=path.join(candidateRoot,row.candidate.git_history.path),metadata=path.join(workspace,'.git');storage.check(storageTreeBytes(history));await cp(history,metadata,{recursive:true,dereference:false});await writeFile(path.join(metadata,'config'),'[core]\nrepositoryformatversion = 0\nbare = false\n');args.base_revision=prerequisite.requested_revision;}
            const response=await client.callTool({name:fixture.operation,arguments:args},{timeout:300000});
            if(profile.engine==='userspace'&&fixture.operation==='project_consistency_report'){rows.push({format:selectedFormat,operation:fixture.operation,elapsed_ms:performance.now()-begin,...requireUserspaceProjectRejection(response)});await save();return;}
            assert.notEqual(response.isError,true,JSON.stringify(response));assert.equal(response.structuredContent.execution.status,'completed');
            const validate=ajv.compile(JSON.parse(await readFile(path.join(installation,'contracts/schema/results',fixture.operation+'.schema.json'))));assert.ok(validate(response.structuredContent),JSON.stringify(validate.errors));const result=await readResult(client,response);
            for(const [name,expected]of Object.entries(fixture.expected_fields))assert.deepEqual(field(result,name),expected,fixture.operation+': '+name);
            if(args.options?.mode==='preview'||args.edit_options?.mode==='preview')for(const file of fixture.files)assert.equal(digest(await readFile(path.join(workspace,file.path))),file.sha256,'Preview changed source bytes');
            for(const expected of fixture.expected_artifacts??[]){const bytes=await readArtifact(client,result.artifacts[expected.index]);assert.equal(bytes.length,expected.size_bytes);assert.equal(digest(bytes),expected.sha256);assert.equal(bytes.toString('base64'),expected.content_base64);const exported=result.exports?.find(item=>item.sha256===expected.sha256);if(exported)assert.deepEqual(await readFile(exported.path),bytes);}
            rows.push({format:selectedFormat,operation:fixture.operation,status:'passed',elapsed_ms:performance.now()-begin,execution:response.structuredContent.execution,provenance:response.structuredContent.provenance});
          }catch(error){rows.push({format:selectedFormat,operation:fixture.operation,status:'failed',elapsed_ms:performance.now()-begin,error:error.message});}
          finally{await rm(path.dirname(workspace),{recursive:true,force:true});}
          storage.check();await save();
        };
        const pending=[...fixtures.cases],workers=await Promise.allSettled(Array.from({length:jobs},async()=>{for(;;){const fixture=pending.shift();if(!fixture)return;await runCase(fixture);}}));
        for(const worker of workers)if(worker.status==='rejected')throw worker.reason;
      }finally{
        await client.close();storage.setClient(undefined);lifecycle.push({format:selectedFormat,stage:'protocol-closed',stderr});
        if(archiveBacked){await cleanupOwned();if(selectedFormat==='npm'){const installed=npmInstallations.at(-1);assert.deepEqual(verifyInstalledPayload(installed.root),installed.payload);installed.verified=true;await rm(path.join(privateRoot,'npm-installation'),{recursive:true,force:true});}else await rm(installation,{recursive:true,force:true});}
        else if(selectedFormat!=='npm')await rm(installation,{recursive:true,force:true});
        await save();
      }
    }
  }catch(error){report.failure={name:error.name,message:error.message};await save();throw error;}finally{
    storage.beginCleanup();
    try{await cleanupOwned();}catch{/* The failure is recorded and prevents acceptance. */}
    try{verifyRuntimeInputs(candidateRoot,profile.target,{python,verifierRuntime,allowDiagnostic:qualification==='diagnostic',allowAvailable:qualification==='available-target'});for(const installed of npmInstallations)if(!installed.verified)assert.deepEqual(verifyInstalledPayload(installed.root),installed.payload);lifecycle.push({stage:'immutable-candidate-recheck',status:'passed'});}catch(error){lifecycle.push({stage:'immutable-candidate-recheck',status:'failed',error:error.message});}
    report.verifier_source_unchanged=sourceReceipt(verifierRoot).sha256===verifierSource.sha256;if((scope.acceptance_eligible||scope.target_execution_eligible)&&!report.verifier_source_unchanged)lifecycle.push({stage:'immutable-verifier-source-recheck',status:'failed',error:'Verifier source changed during acceptance'});
    if(qa)try{assert.deepEqual(providerQaExecution(qa.profile_root),qa);lifecycle.push({stage:'closed-QA-source-and-dependency-recheck',status:'passed'});}catch(error){lifecycle.push({stage:'closed-QA-source-and-dependency-recheck',status:'failed',error:error.message});}
    if(report.host_prerequisites)try{assert.deepEqual(await userspaceGitEvidence(gitSearchPath),report.host_prerequisites.git);lifecycle.push({stage:'host-git-recheck',status:'passed'});}catch(error){lifecycle.push({stage:'host-git-recheck',status:'failed',error:error.message});}
    report.operation_coverage=operationMatrixSummary(rows,fixtures.cases.map(item=>item.operation),formats,profile.engine);
    report.registered_operation_coverage={expected:104,formats:formats.map(format=>({format,domain:rows.filter(item=>item.format===format).map(item=>item.operation),environment:['setup_ud_environment','check_ud_environment'].map(operation=>({operation,executed:operation==='setup_ud_environment'?lifecycle.some(item=>item.format===format&&item.stage==='warm-setup'):lifecycle.some(item=>item.format===format&&item.operation===operation&&item.status==='passed')}))}))};report.registered_operation_coverage.complete=report.registered_operations?.length===104&&report.operation_coverage.complete&&report.registered_operation_coverage.formats.every(item=>item.environment.every(row=>row.executed));
    report.status=report.registered_operation_coverage.complete&&lifecycle.some(item=>item.stage==='owned-cleanup'&&item.status==='passed')&&lifecycle.every(item=>item.status!=='failed')?(qualification==='available-target'?'passed-available-target-preacceptance':'passed'):'failed-or-incomplete';await save();
  }
  assert.equal(report.status,qualification==='available-target'?'passed-available-target-preacceptance':'passed','Native provider acceptance has failed or incomplete rows; inspect '+reportPath);return report;
}
if(import.meta.url===pathToFileURL(process.argv[1]??'').href){
  const args=process.argv.slice(2);
  if(args.length===2&&args[0]==='--qa-preflight'){
    try{console.log(JSON.stringify({schema_version:1,qualification:'detached-QA-driver-import-preflight-not-installed-execution',qa_execution:providerQaExecution(path.resolve(args[1]))}));}
    catch(error){console.error(error.message);process.exitCode=1;}
  }else{
    const flags={};
    try{
      assert.ok(args.length%2===0);
      for(let i=0;i<args.length;i+=2){assert.ok(['--candidate-root','--python','--report','--engine','--format','--qualification','--installer','--search-path','--npm-cli','--qa-profile','--jobs','--expected-python'].includes(args[i])&&!Object.hasOwn(flags,args[i]));flags[args[i]]=args[i+1];}
      assert.ok(flags['--candidate-root']&&flags['--report']&&flags['--python']);
      await runNativeProviderAcceptance({candidateRoot:path.resolve(flags['--candidate-root']),python:path.resolve(flags['--python']),reportPath:path.resolve(flags['--report']),engine:flags['--engine'],format:flags['--format']??'all',qualification:flags['--qualification']??'candidate',installer:flags['--installer'],searchPath:flags['--search-path'],npmCli:flags['--npm-cli'],expectedPython:flags['--expected-python'],qaProfile:flags['--qa-profile']===undefined?undefined:path.resolve(flags['--qa-profile']),jobs:flags['--jobs']===undefined?1:['1','2','3'].includes(flags['--jobs'])?Number(flags['--jobs']):NaN});
    }catch(error){
      if(flags['--report']){const target=path.resolve(flags['--report']);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,JSON.stringify({schema_version:1,qualification:flags['--qualification']==='diagnostic'?'diagnostic-installed-provider-execution-not-final-acceptance':flags['--qualification']==='available-target'?'available-target-provider-preacceptance-execution':'native-provider-preacceptance-execution',acceptance_eligible:flags['--qualification']===undefined||flags['--qualification']==='candidate',status:'failed-or-incomplete',classification:/Pending native build/.test(error.message)?'pending-native-build':'failed-or-incomplete',host:{os:process.platform,process_architecture:process.arch,emulation:false},error:error.message},null,2)+'\n',{flag:'wx'}).catch(writeError=>{if(writeError.code!=='EEXIST')throw writeError;});}
      console.error(error.message);process.exitCode=1;
    }
  }
}
