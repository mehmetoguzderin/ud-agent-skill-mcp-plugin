#!/usr/bin/env node
/** Immutable subset preacceptance. This never authorizes a production release. */
import { chmodSync, copyFileSync, existsSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { MAX_COMPONENT_SOURCE_REPORT_BYTES } from './component-closure.mjs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fileReceipt, readRecordedBytes, safeRelative, sourceReceipt, verifyRecordedFile } from './candidate.mjs';
import { prepareNpmDiagnostic, preparePlatformDiagnostic, packageInventory, retainSourceSnapshot } from './prepare.mjs';
import { sourceArtifacts, verifyRequiredSourceMaterials } from './source-artifacts.mjs';
import { auxiliaryArtifacts } from './auxiliary-artifacts.mjs';
import { verifyOciArchive } from './oci.mjs';
import { writeSkillSupport } from './skill-support.mjs';
import { canonicalJson } from './http-transports.mjs';
import { releasePythonCommand, releaseVerifierOwnedRoot } from './verifier-runtime.mjs';
import { portablePathKey, validPortablePath } from './portable-policy.mjs';
import { resolveCrossBuildInputs, verifyRetainedCrossBuildInputs } from './cross-build-inputs.mjs';
import { inheritedOutputStorage, inheritedScratchStorage, recoverStorage, storageTreeBytes, STORAGE_LIMITS, transferredOutputBytes, watchStorageSupervisor } from '../quality/storage-lifecycle.mjs';
import { selectedUserspaceFiles } from './userspace-assets.mjs';
import { selectedNativeHelpers } from './native-helpers.mjs';
import { beginCandidate, completeCandidate, abortCandidate, abortCandidateIfActive, recoverAbandonedCandidate } from './candidate-retention.mjs';
import { beginSourcePartTransfer, moveSourcePart, planSourcePartTransfer, recoverSourcePartTransfer, sourceTransferJournal } from './source-part-transfer.mjs';
import { validateInspectionReceipt } from './component-preparation.mjs';

import { releasePlatforms, releasePlatformIds as ids } from './host-adapters.mjs';

export const availablePlatforms = releasePlatforms;
const omitted = new Set(['component-source-coverage','publisher-authority','checksum-manifest']);
const recipeName = 'runtime/materials/component-source-replay.json';
const need = (value, message) => { if (!value) throw new Error(message); };
const json = file => JSON.parse(readFileSync(file, 'utf8'));
const equal = (left, right) => canonicalJson(left) === canonicalJson(right);
/** Separate retained output from the one-at-a-time packaging workspace. */
export function planAvailableStorage({sourceBytes,runtimeBytes,nativeBytes,transportBytes,auxiliaryBytes,materialBytes,targetCount,crossBytes,helperBytes,maxUserspace}) {
  const values=[sourceBytes,runtimeBytes,nativeBytes,transportBytes,auxiliaryBytes,materialBytes,targetCount,crossBytes,helperBytes,maxUserspace];
  need(values.every(value=>Number.isSafeInteger(value)&&value>=0)&&targetCount>0&&targetCount<=6,'Available candidate storage inputs are invalid.');
  const plannedOutputBytes=3*sourceBytes+2*runtimeBytes+nativeBytes+2*transportBytes+2*auxiliaryBytes+materialBytes+targetCount*3*(crossBytes+helperBytes)+128*1024**2;
  const plannedBytes=2*sourceBytes+maxUserspace+2*crossBytes+helperBytes+1024**3;
  need(Number.isSafeInteger(plannedOutputBytes)&&Number.isSafeInteger(plannedBytes),'Available candidate storage plan exceeds numeric bounds.');
  return {plannedBytes,plannedOutputBytes};
}
function storageRoot(directory) {
  let owner = path.resolve(directory);
  for (let current = owner; path.dirname(current) !== current; current = path.dirname(current)) if (path.basename(current) === '.artifacts') owner = path.dirname(current);
  return realpathSync(owner);
}
function canonicalOutput(filename) {
  let parent=path.resolve(filename); const suffix=[];
  while(!existsSync(parent)){const next=path.dirname(parent);need(next!==parent,'Available candidate output has no existing parent.');suffix.unshift(path.basename(parent));parent=next;}
  return path.join(realpathSync(parent),...suffix);
}
/** Exact retained files plus the largest sequential OCI inspection workspace. */
export function replayStorageBytes(source, subjects, report, { compact = false } = {}) {
  need(Array.isArray(report.inspection_inputs?.inputs),'Compact v2 replay needs recipe-based input reconstruction, which is not yet available.');
  const outputs = new Map();
  for (const row of [...(compact ? [] : [...source.files, ...subjects]), ...report.inspection_inputs.inputs]) {
    safeRelative(row.path);
    const size = row.size_bytes ?? row.size;
    need(Number.isSafeInteger(size) && size >= 0 && size <= STORAGE_LIMITS.releaseBytes, 'Replay input has no finite byte inventory.');
    const prior = outputs.get(row.path); need(prior === undefined || prior === size, 'Replay paths have conflicting sizes.'); outputs.set(row.path, size);
  }
  const materials = new Map(), blobs = new Map();
  for (const row of report.required_materials) {
    need(Number.isSafeInteger(row.size_bytes) && row.size_bytes >= 0 && row.size_bytes <= STORAGE_LIMITS.releaseBytes && !materials.has(row.sha256), 'Replay original byte inventory is duplicate or invalid.');
    materials.set(row.sha256, row.size_bytes);
  }
  for (const row of report.inspection_inputs.inputs) {
    const ref = row.retention, hash = ref.kind === 'corresponding-source-blob' ? row.sha256 : ref.kind === 'corresponding-source-member' ? ref.blob_sha256 : undefined;
    if (hash !== undefined && hash !== null) { const size = materials.get(hash); need(Number.isSafeInteger(size) && size >= 0, 'Replay original has no finite byte inventory.'); blobs.set(hash, size); }
  }
  const inspections = new Map(report.subjects.map(row => [row.id, row]));
  let oci = 0;
  for (const subject of subjects) {
    need(typeof subject.id === 'string', 'Replay subject identity is missing.');
    if (!/^(?:core|render)-(?:oci-index|linux-(?:arm64|amd64)-(?:oci-archive|docker-archive)-[0-9]+)$/.test(subject.id)) continue;
    const row = inspections.get(subject.id);
    need(Array.isArray(row?.bindings) && row.bindings.every(file => Number.isSafeInteger(file.size_bytes) && file.size_bytes >= 0), 'Replay OCI workspace has no finite byte inventory.');
    const transport = /-linux-(?:arm64|amd64)-(?:oci-archive|docker-archive)-[0-9]+$/.test(subject.id);
    if (transport) need(Number.isSafeInteger(subject.size) && subject.size >= 0, 'Replay OCI transport has no finite byte inventory.');
    const size = row.bindings.reduce((sum, file) => sum + file.size_bytes, 0) + (transport ? 2 * subject.size + 64 * 1024 ** 2 : 0);
    need(Number.isSafeInteger(size), 'Replay OCI workspace exceeds numeric bounds.'); oci = Math.max(oci, size);
  }
  // Compact replay reads source blobs in place from verified source parts;
  // only legacy replay retains an additional copy of the original blobs.
  const originalBytes = compact ? 0 : [...blobs.values()].reduce((sum, size) => sum + size, 0);
  const planned = [...outputs.values()].reduce((sum, size) => sum + size, 0) + originalBytes + oci + 128 * 1024 ** 2;
  need(Number.isSafeInteger(planned), 'Replay byte inventory exceeds numeric bounds.');
  if (compact) need(planned <= STORAGE_LIMITS.releaseBytes, 'Compact replay exceeds the 4 GB scratch budget.');
  return planned;
}
function directory(root, name) {
  safeRelative(name); let current = path.resolve(root);
  for (const component of name.split('/')) { current = path.join(current, component); const info = lstatSync(current); need(info.isDirectory() && !info.isSymbolicLink(), 'Available candidate directory is linked or special.'); }
  return current;
}
function copyFile(root, row, destination, name = row.path) {
  const actual = verifyRecordedFile(root, row), output = path.join(destination, safeRelative(name));
  mkdirSync(path.dirname(output), { recursive: true });
  if (existsSync(output)) { const held = fileReceipt(destination, name); need(held.sha256 === actual.sha256 && held.size === actual.size && held.executable === actual.executable, 'Available candidate input paths conflict.'); return; }
  copyFileSync(path.join(root, row.path), output); chmodSync(output, actual.executable ? 0o755 : 0o644);
  const copied = fileReceipt(destination, name); need(copied.sha256 === actual.sha256 && copied.size === actual.size, 'Available candidate input changed during copy.');
}

/**
 * Store equal candidate payloads once, while preserving the paths and byte
 * receipts consumed by existing candidate verifiers. Links are only ever made
 * between files already copied into this candidate: an external build input
 * must remain unable to change the candidate through a shared inode.
 */
export function copyCandidatePayload(root, row, candidateRoot, destination, name, copies) {
  const actual = verifyRecordedFile(root, row), relative = safeRelative(name ?? row.path);
  const candidate = path.resolve(candidateRoot), output = path.resolve(destination, relative);
  need(output.startsWith(candidate + path.sep), 'Candidate payload destination escapes its owned candidate.');
  mkdirSync(path.dirname(output), { recursive: true });
  if (existsSync(output)) {
    const held = fileReceipt(destination, relative);
    need(held.sha256 === actual.sha256 && held.size === actual.size && held.executable === actual.executable, 'Available candidate input paths conflict.');
    return;
  }
  const key = `${actual.sha256}:${actual.size}:${actual.executable}`;
  const previous = copies.get(key);
  if (previous) {
    // Verify the candidate-owned source again before sharing its inode.
    const held = fileReceipt(candidate, previous);
    need(held.sha256 === actual.sha256 && held.size === actual.size && held.executable === actual.executable, 'Candidate payload changed before deduplication.');
    try { linkSync(path.join(candidate, previous), output); }
    catch (error) {
      // Some filesystems do not support hard links; a normal bounded copy
      // preserves correctness there and storage admission must budget it.
      if (!['EXDEV', 'EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'EMLINK'].includes(error.code)) throw error;
      copyFile(root, row, destination, relative);
    }
  } else {
    copyFile(root, row, destination, relative);
    copies.set(key, path.relative(candidate, output).split(path.sep).join('/'));
  }
  const held = fileReceipt(destination, relative);
  need(held.sha256 === actual.sha256 && held.size === actual.size && held.executable === actual.executable, 'Candidate payload differs after deduplication.');
}
function recordTreePath(names, name, kind) {
  need(validPortablePath(name), `Available candidate tree has an unsafe path: ${name}`);
  const components = name.split('/');
  for (let count = 1; count <= components.length; count++) {
    const current = components.slice(0,count).join('/'), currentKind = count === components.length ? kind : 'directory';
    const key = portablePathKey(current), prior = names.get(key);
    // Directory spellings can merge on a case-insensitive filesystem. Every
    // ordinary-file key and every file/directory prefix must remain distinct.
    need(!prior || (prior.kind === 'directory' && currentKind === 'directory'), `Available candidate tree has a Unicode file or directory conflict: ${prior?.name} (${prior?.kind}) and ${current} (${currentKind})`);
    if (!prior) names.set(key,{name:current,kind:currentKind});
  }
}
/** Pure admission also exercises names unavailable together on some host filesystems. */
export function validateAvailableTreePaths(entries) {
  const names = new Map();
  for (const row of entries) { need(row?.kind === 'file' || row?.kind === 'directory','Available candidate tree entry has an invalid kind.'); recordTreePath(names,row.path,row.kind); }
  return true;
}
function treeFiles(root) {
  const rows = [], names = new Map();
  function walk(name) { const file = path.join(root, name), info = lstatSync(file); need(!info.isSymbolicLink(), 'Available candidate tree contains a link.'); if(name)recordTreePath(names,name,info.isDirectory()?'directory':'file'); if (info.isDirectory()) for (const child of readdirSync(file).sort()) walk(name ? name + '/' + child : child); else { need(info.isFile()&&rows.length<100000, 'Available candidate tree contains a special file or exceeds its bound.'); rows.push(fileReceipt(root, name)); } }
  walk(''); return rows;
}
export function copyAvailableTree(root, destination) { mkdirSync(destination, { recursive: true }); for (const row of treeFiles(root)) copyFile(root, row, destination); }
const copyTree = copyAvailableTree;
function run(python, scriptRoot, script, args, timeout = 180000, env = process.env) {
  const result = spawnSync(python, ['-I','-S','-B',path.join(scriptRoot, script), ...args], { cwd: scriptRoot, env, encoding:'utf8', timeout, maxBuffer:1024 ** 2 });
  need(!result.error && result.status === 0, `Available candidate ${script} failed: ${result.error?.message ?? result.stderr?.slice(-2000)}`); return result.stdout;
}
function ownedEngineBytes(root) {
  const helper = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../quality/original-storage.mjs');
  const code = 'const m=await import(process.argv[1]);process.stdout.write(String(m.originalDockerBytes(process.argv[2])))';
  const result = spawnSync(process.execPath, ['--input-type=module','-e',code,pathToFileURL(helper).href,root], { encoding:'utf8', timeout:120000, maxBuffer:1024**2 });
  need(!result.error && result.status===0 && /^\d+$/.test(result.stdout), `Available candidate engine storage inspection failed: ${result.error?.message??result.stderr?.slice(-2000)}`);
  const value=Number(result.stdout); need(Number.isSafeInteger(value)&&value>=0,'Available candidate engine storage count is invalid.'); return value;
}
function requiredArtifacts(sourceRoot) { const rows = json(path.join(sourceRoot,'quality/requirements.json')).required_artifacts; need(Array.isArray(rows) && rows.length > 0 && new Set(rows).size === rows.length, 'Complete production distribution contract must have unique subjects.'); return rows; }
const stageMarker='.ud-material-stage-owner.json';
/** The newly created stage is removed if its initial ownership writes fail. */
export function createMaterialStage(owner,output,write=writeFileSync) {
  mkdirSync(output,{mode:0o700});const info=lstatSync(output);
  try {
    write(path.join(output,stageMarker),JSON.stringify({schema_version:1,owner_root:owner,output,device:info.dev,inode:info.ino,uid:info.uid,pid:process.pid})+'\n',{flag:'wx',mode:0o600});
    write(path.join(output,'INCOMPLETE'),'Selected material source stage incomplete.\n');
    return info;
  } catch(error) {
    const current=lstatSync(output,{throwIfNoEntry:false});
    if(current&&current.isDirectory()&&!current.isSymbolicLink()&&current.dev===info.dev&&current.ino===info.ino&&current.uid===info.uid)rmSync(output,{recursive:true});
    throw error;
  }
}
/** Reclaim only a stopped, exact-owned incomplete material stage. */
export function recoverMaterialStage(owner,output) {
  owner=realpathSync(owner);output=canonicalOutput(output);
  if(!existsSync(output)||!existsSync(path.join(output,'INCOMPLETE'))||!existsSync(path.join(output,stageMarker)))return false;
  const info=lstatSync(output),file=path.join(output,stageMarker),markerInfo=lstatSync(file);
  need(info.isDirectory()&&!info.isSymbolicLink()&&markerInfo.isFile()&&!markerInfo.isSymbolicLink()&&markerInfo.nlink===1&&markerInfo.size<=4096&&!(markerInfo.mode&0o077)&&markerInfo.uid===info.uid&&(process.getuid===undefined||info.uid===process.getuid()),'Material stage ownership is ambiguous.');
  const marker=json(file);
  need(marker.schema_version===1&&marker.owner_root===owner&&marker.output===output&&marker.device===info.dev&&marker.inode===info.ino&&marker.uid===info.uid&&Number.isSafeInteger(marker.pid)&&marker.pid>0,'Material stage ownership differs.');
  let active=true;try{process.kill(marker.pid,0);}catch(error){if(error.code==='ESRCH')active=false;else throw error;}need(!active,'Material stage is still active.');
  if(process.platform!=='win32'){let group=false;try{process.kill(-marker.pid,0);group=true;}catch(error){if(error.code!=='ESRCH')throw error;}need(!group,'Material stage process group is still active.');}
  rmSync(output,{recursive:true});return true;
}

/** A second source stage, never a rewrite of the inspected provisional bytes. */
/** @param {{python?: string}} [options] */
export function stageAvailableMaterials(provisionalRoot, planRoot, output, options = {}) {
  return stageAvailableMaterialsInternal(provisionalRoot,planRoot,output,options,false);
}
function stageAvailableMaterialsInternal(provisionalRoot, planRoot, output, options = {}, worker) {
  provisionalRoot=realpathSync(provisionalRoot);planRoot=realpathSync(planRoot);output=canonicalOutput(output);
  const owner=storageRoot(planRoot);if(!worker){recoverStorage(owner);recoverMaterialStage(owner,output);}
  const { python } = options;
  const original = json(path.join(provisionalRoot,'available-candidate.json')), checked = validateAvailableCandidate(provisionalRoot,original);
  need(original.material_phase === 'provisional' && !existsSync(path.join(provisionalRoot,'INCOMPLETE')), 'Material installation requires a complete provisional available candidate.');
  need(!existsSync(output) && ![provisionalRoot,planRoot].some(value => path.resolve(output) === path.resolve(value)), 'Final material source stage must be new.');
  const assembly = json(path.join(planRoot,'ASSEMBLY.json')), report = JSON.parse(readRecordedBytes(planRoot,assembly.component_source_coverage,MAX_COMPONENT_SOURCE_REPORT_BYTES).toString('utf8'));
  need(assembly.qualification === 'actual-shipped-component-selected-original-source-assembly' && assembly.source_tree_sha256 === original.source_tree_sha256 && assembly.runtime_lock_sha256 === original.runtime_lock_sha256 && assembly.complete_available_shipped_component_coverage === true && report.complete_available_shipped_component_coverage === true, 'Source plan is unresolved or does not describe the original provisional bytes.');
  verifyRequiredSourceMaterials(planRoot,report.required_materials);
  const planned=sourceArtifacts(planRoot,{required:true}),prefix='.artifacts/selected-source-materials/',runtimeFiles=treeFiles(checked.runtimeRoot);
  const otherRoots=[provisionalRoot].filter(file=>file!==owner&&!file.startsWith(owner+path.sep));
  const plannedBytes=128*1024**2,plannedOutputBytes=checked.source.files.reduce((sum,row)=>sum+row.size,0)+runtimeFiles.reduce((sum,row)=>sum+row.size,0)+planned.filter(row=>row.id==='corresponding-source-index').reduce((sum,row)=>sum+row.size,0)+128*1024**2;
  if(!worker){
    const supervisor=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../quality/storage-lifecycle.mjs');
    const request=Buffer.from(JSON.stringify({provisionalRoot,planRoot,output,python})).toString('base64url');
    const result=spawnSync(process.execPath,[supervisor,'--run',owner,String(plannedBytes),'release','--external-owned-bytes',String(ownedEngineBytes(owner)),'--output',output,'--output-bytes',String(plannedOutputBytes),'--caller-pid',String(process.pid),...otherRoots.flatMap(file=>['--owned-root',file]),'--',process.execPath,fileURLToPath(import.meta.url),'--material-stage-worker',request],{encoding:'utf8',maxBuffer:1024**2,timeout:30*60*1000});
    need(!result.error&&result.status===0,`Supervised material staging failed: ${result.error?.message??result.stderr?.slice(-2000)}`);return JSON.parse(result.stdout);
  }
  const lease=inheritedOutputStorage({root:owner,output,plannedBytes,plannedOutputBytes}),watchdog=watchStorageSupervisor(lease.supervisorPid);
  try {
  const stageInfo=createMaterialStage(owner,output);
  try {
  for (const row of checked.source.files) copyFile(checked.sourceRoot,row,output);
  for (const row of runtimeFiles) copyFile(checked.runtimeRoot,row,output);
  for (const row of planned) {
    const name=prefix+path.posix.basename(row.path);
    if(row.id==='corresponding-source-index'){copyFile(planRoot,row,output,name);continue;}
    // The material stage and retained plan share one verified inode. The final
    // candidate's explicit transfer removes all registered aliases before it
    // becomes immutable; no whole source bundle is copied in the meantime.
    const actual=verifyRecordedFile(planRoot,row),target=path.join(output,name);mkdirSync(path.dirname(target),{recursive:true});
    try{linkSync(path.join(planRoot,row.path),target);}catch(error){throw new Error(`Selected source parts require a same-filesystem staging directory: ${error.message}`);}
    const staged=fileReceipt(output,name);need(staged.sha256===actual.sha256&&staged.size===actual.size&&staged.executable===actual.executable,'Staged source part differs from its verified plan.');
  }
  const index = planned.find(row => row.id === 'corresponding-source-index');
  const projection = row => ({path:prefix+path.posix.basename(row.path),sha256:row.sha256,size:row.size});
  writeFileSync(path.join(output,'runtime/source-materials.lock.json'),JSON.stringify({schema_version:1,index:projection(index),parts:planned.filter(row=>row.id!=='corresponding-source-index').map(row=>({id:row.id,...projection(row)}))},null,2)+'\n');
  // Keep verification imports independent of builder-only npm dependencies.
  lease.check();run(python,output,'scripts/generate/implementation-inventory.py',[],180000,{...process.env,...lease.env,TMPDIR:lease.directory,TMP:lease.directory,TEMP:lease.directory});
  run(python,output,'scripts/generate/implementation-inventory.py',['--check'],180000,{...process.env,...lease.env,TMPDIR:lease.directory,TMP:lease.directory,TEMP:lease.directory});lease.check();
  verifyRequiredSourceMaterials(output,report.required_materials);
  const source = sourceReceipt(output);
  writeFileSync(path.join(output,'freeze-composition.json'),JSON.stringify({schema_version:1,qualification:'available-target-inputs',production_ready:false,source_tree_sha256:source.sha256,original_source_tree_sha256:original.source_tree_sha256,userspace_platforms:checked.targets.map(value=>value.replace('-','/')),material_derivation:{provisional_candidate:fileReceipt(provisionalRoot,'available-candidate.json'),assembly:fileReceipt(planRoot,'ASSEMBLY.json'),source_plan_sha256:assembly.source_tree_sha256,physical_source_materials:report.required_materials.length}},null,2)+'\n');
  rmSync(path.join(output,'INCOMPLETE'));rmSync(path.join(output,stageMarker));return {output,source_tree_sha256:source.sha256,runtime_lock_sha256:original.runtime_lock_sha256,material_phase:'final'};
  } catch(error) { const current=lstatSync(output,{throwIfNoEntry:false});if(current&&current.isDirectory()&&!current.isSymbolicLink()&&current.dev===stageInfo.dev&&current.ino===stageInfo.ino&&current.uid===stageInfo.uid)rmSync(output,{recursive:true});throw error; }
  } finally {watchdog.kill();lease.cleanup();}
}

/** Closed scope is derived from real immutable inputs, never caller completeness. */
export function availableScope(sourceRoot, targets, artifacts) {
  need(Array.isArray(targets) && targets.length > 0 && targets.length <= availablePlatforms.length && targets.every(value => availablePlatforms.includes(value)) && new Set(targets).size === targets.length, 'Available native targets are invalid.');
  const required = requiredArtifacts(sourceRoot), present = new Set(artifacts.map(row => row.id));
  return { kind:'available-target-subset', available_targets:[...targets].sort(), required_targets:[...availablePlatforms], pending_targets:availablePlatforms.filter(value => !targets.includes(value)).map(platform => ({ platform, code:'PENDING_NATIVE_BUILD', reason:'No current frozen userspace and same-architecture worker inputs are available for this native target.' })), required_artifacts:required, pending_artifacts:required.filter(id => !present.has(id)).map(id => ({ id, code:'PENDING_NATIVE_BUILD', reason:'The exact required distribution subject has no current native build; no older bytes or synthesized image digest are substituted.' })) };
}
function pendingProviderAssets(runtime,targets) {
  return Object.entries(runtime?.provider_receipts??{}).filter(([name,item])=>item.lazy_assets&&!targets.includes(name.split('/').slice(-2).join('-'))).map(([name])=>({id:'provider-assets-'+name.replaceAll('/','-'),code:'PENDING_NATIVE_BUILD',platform:name.split('/').slice(-2).join('-')})).sort((a,b)=>a.id.localeCompare(b.id));
}
/** The legacy copy path remains available unless transfer is explicitly selected. */
export function selectedSourceTransfers(owner,sourceRoot,output,parts,roots) {
  need(Array.isArray(roots),'Source transfer roots must be an array.');
  return roots.length?planSourcePartTransfer(owner,sourceRoot,output,parts,roots):[];
}

/** Data/byte checks; no interpreter, archive content replay or publisher grant. */
export function validateAvailableCandidate(root, manifest) {
  need([1,2].includes(manifest?.schema_version) && manifest.qualification === 'available-target-preacceptance' && manifest.status === 'preacceptance_candidate' && manifest.production_ready === false && ['provisional','final'].includes(manifest.material_phase), 'Explicit available-target preacceptance authority is required.');
  need(manifest.source_snapshot && typeof manifest.source_snapshot.root === 'string' && manifest.source_snapshot.receipt && typeof manifest.runtime_root === 'string' && manifest.runtime_inventory, 'Available candidate source snapshot and runtime inventory bindings are missing.');
  const sourceRoot = directory(root, manifest.source_snapshot.root), runtimeRoot = directory(root, manifest.runtime_root);
  const source = sourceReceipt(sourceRoot); need(source.sha256 === manifest.source_tree_sha256, 'Available candidate retained source differs.');
  const retained = JSON.parse(readRecordedBytes(root, manifest.source_snapshot.receipt, 64 * 1024 ** 2).toString('utf8')); need(equal(retained, source), 'Available candidate source receipt differs from actual files.');
  need(fileReceipt(runtimeRoot,'runtime/runtime.lock.json').sha256 === manifest.runtime_lock_sha256 && fileReceipt(sourceRoot,'runtime/runtime.lock.json').sha256 === manifest.runtime_lock_sha256, 'Available candidate frozen runtime differs from its source.');
  const runtimeInventory = JSON.parse(readRecordedBytes(root, manifest.runtime_inventory, 64 * 1024 ** 2).toString('utf8'));
  need(runtimeInventory.schema_version === 1 && equal(runtimeInventory.files, treeFiles(runtimeRoot)), 'Available candidate runtime inventory omits or changes actual input bytes.');
  need(Array.isArray(manifest.artifacts) && manifest.artifacts.length <= 2000, 'Available candidate artifact inventory is missing or oversized.');
  const artifacts = new Map(), names = new Set();
  for (const row of manifest.artifacts) { need(typeof row.id === 'string' && !artifacts.has(row.id) && typeof row.path==='string' && validPortablePath(row.path) && row.path.startsWith('artifacts/') && !names.has(row.path), 'Available candidate artifact identities collide or escape their root.'); verifyRecordedFile(root,row); artifacts.set(row.id,row); names.add(row.path); }
  need(equal([...names].sort(),treeFiles(directory(root,'artifacts')).map(row=>'artifacts/'+row.path).sort()),'Available candidate artifacts contain unlisted bytes.');
  if (manifest.native_inputs) { readRecordedBytes(root,manifest.native_inputs,32 * 1024 ** 2); verifyRetainedCrossBuildInputs(directory(root,'native-inputs')); }
  const targets = Object.keys(json(path.join(runtimeRoot,'runtime/userspace.lock.json')).platforms ?? {}).map(value => value.replace('/','-')).sort();
  need(equal(manifest.scope, availableScope(sourceRoot, targets, manifest.artifacts)), 'Available candidate omitted, altered or fabricated pending native scope.');
  const runtime = json(path.join(runtimeRoot,'runtime/runtime.lock.json'));
  if(manifest.pending_provider_assets!==undefined) {
    need(equal(manifest.pending_provider_assets,pendingProviderAssets(runtime,targets)),'Available candidate pending provider scope differs.');
    for(const[name,provider]of Object.entries(runtime.provider_receipts??{}))if(provider.lazy_assets&&targets.includes(name.split('/').slice(-2).join('-'))){const item=artifacts.get('provider-assets-'+name.replaceAll('/','-'));need(item&&item.sha256===provider.lazy_assets.sha256.replace(/^sha256:/,'')&&item.size===provider.lazy_assets.size,'Available candidate selected provider asset differs.');}
  }
  need(runtime.state === 'frozen' && runtime.packs?.core?.images && runtime.packs?.render?.images, 'Available candidate runtime is not frozen.');
  for (const target of targets) { const worker = 'linux/' + (target.endsWith('-x64') ? 'amd64' : 'arm64'); need(runtime.packs.core.images[worker] && runtime.packs.render.images[worker], 'Available target has no current same-architecture worker.'); }
  need(Array.isArray(manifest.installations) && manifest.installations.length === targets.length && new Set(manifest.installations.map(row => row.platform)).size === targets.length, 'Available candidate installation targets are incomplete or duplicated.');
  for (const row of manifest.installations) {
    need(targets.includes(row.platform) && equal(Object.keys(row.formats).sort(),['mcpb','native','npm']), 'Available candidate installed formats differ.');
    for (const format of ['native','mcpb','npm']) {
      const item = row.formats[format], expected = format === 'npm' ? 'npm' : `${format}-${ids[row.platform]}`;
      need(item.artifact_id === expected && artifacts.has(expected), 'Available candidate installation is not bound to its original format artifact.');
      if (manifest.schema_version === 2) {
        need(equal(Object.keys(item).sort(),['artifact_id','build_receipt_sha256','inventory_sha256']) && /^[a-f0-9]{64}$/.test(item.inventory_sha256) && /^[a-f0-9]{64}$/.test(item.build_receipt_sha256), 'Archive-backed package contract is missing or invalid.');
        continue;
      }
      const install = directory(root,item.root), build = json(path.join(install,'BUILD-RECEIPT.json'));
      need(build.qualification === 'preacceptance_candidate' && build.source_tree_sha256 === source.sha256 && build.runtime_lock_sha256 === manifest.runtime_lock_sha256 && build.kind === (format === 'npm' ? 'npm' : 'native') && build.platform === (format === 'npm' ? 'all' : row.platform), 'Available candidate installation is local, stale or relabeled.');
      const inventory = json(path.join(install,'PACKAGE-INVENTORY.json')), files = treeFiles(install).filter(value => value.path !== 'PACKAGE-INVENTORY.json');
      need(inventory.schema_version === 1 && equal(inventory.files,files), 'Available candidate installation differs from its complete original inventory.');
    }
  }
  return { sourceRoot, runtimeRoot, source, targets, artifacts };
}

/** Shared byte binding preflight; none of these checks runs source replay. */
function availableCoverageInputs(root, manifest) {
  const checked = validateAvailableCandidate(root,manifest); need(!existsSync(path.join(root,'INCOMPLETE')), 'Available candidate assembly is incomplete.'); need(manifest.material_phase === 'final','Available-target execution requires final source material packages.');
  const descriptor = checked.artifacts.get('component-source-coverage'); need(descriptor, 'Available candidate source coverage is missing.');
  const report = JSON.parse(readRecordedBytes(root,descriptor,MAX_COMPONENT_SOURCE_REPORT_BYTES).toString('utf8')), subjects = manifest.artifacts.filter(row => !omitted.has(row.id));
  need(report.schema_version === 1 && report.qualification === 'replayed-actual-shipped-component-source-license-closure' && report.complete_available_shipped_component_coverage === true && report.complete_product_coverage === (manifest.scope.pending_artifacts.length === 0) && report.source_inventory_sha256 === checked.source.sha256 && report.runtime_lock_sha256 === manifest.runtime_lock_sha256 && report.unresolved_shipped_members?.length === 0 && equal(report.missing_distribution_subjects,manifest.scope.pending_artifacts.map(row => ({code:'REQUIRED_DISTRIBUTION_MISSING',artifact:row.id})).sort((a,b) => a.artifact.localeCompare(b.artifact))), 'Available candidate actual component/source coverage is unresolved or has a foreign pending scope.');
  validateInspectionReceipt(report.inspection_inputs,checked.source.sha256,subjects);
  need(Array.isArray(report.subjects) && report.subjects.length === subjects.length && subjects.every((row,index) => report.subjects[index]?.id === row.id && report.subjects[index]?.artifact_sha256 === row.sha256), 'Available candidate source coverage subjects differ.');
  const materials = verifyRequiredSourceMaterials(checked.sourceRoot,report.required_materials,{candidate:manifest,artifactRoot:root});
  return {checked,descriptor,report,materials};
}

/** Platform evidence binds these bytes; source replay is a separate release gate. */
export function verifyAvailableCandidateBindings(root, manifest) {
  const {descriptor,materials}=availableCoverageInputs(root,manifest);
  return {verified:true,qualification:'available-target-candidate-and-material-byte-bindings-only',candidate_bindings_verified:true,material_bindings_verified:true,target_execution_eligible:true,source_replay_performed:false,source_replay_required:true,source_coverage_receipt:{...descriptor},original_source_materials:materials.original_source_materials,pending_artifacts:manifest.scope.pending_artifacts};
}

/** Read-only calculation by the candidate's own materializer before admission. */
function planCandidateReplay(root, checked, descriptor, command) {
  const script=path.join(checked.sourceRoot,'scripts/release/materialize-replay-inputs.py');
  const args=['--root',checked.sourceRoot,'--candidate-root',root,'--candidate',path.join(root,'available-candidate.json'),'--source',path.join(checked.sourceRoot,'SOURCE-RECEIPT.json'),'--report',path.join(root,descriptor.path),'--output',path.join(root,'.unused-replay-plan'),'--compact','--stream-source','--plan'];
  const result=spawnSync(command.executable,[...command.args,script,...args],{env:command.env,encoding:'utf8',timeout:180000,maxBuffer:1024**2});
  need(!result.error&&result.status===0,`Available candidate replay plan failed: ${result.error?.message??result.stderr?.slice(-2000)??result.status}`);
  const plan=JSON.parse(result.stdout);
  need(Number.isSafeInteger(plan.storage_plan_bytes)&&plan.storage_plan_bytes>0&&plan.storage_plan_bytes<=STORAGE_LIMITS.releaseBytes,'Available candidate replay plan exceeds its release budget.');
  return plan.storage_plan_bytes;
}

/** Independent private replay on the declared admitted inspection host. */
export function verifyAvailableCandidateCoverage(root, manifest, verifierRuntime) {
  const {checked,descriptor,report}=availableCoverageInputs(root,manifest);
  need(report.inspection_inputs.schema_version!==2,'Compact v2 source replay requires recipe-based input reconstruction, which is not yet available.');
  const command=releasePythonCommand(verifierRuntime,[]), verifierRoot=releaseVerifierOwnedRoot(verifierRuntime);
  const owner=storageRoot(root);
  need(equal(json(path.join(root,'available-candidate.json')),manifest),'Available candidate manifest changed before supervised replay.');
  const plannedBytes=planCandidateReplay(root,checked,descriptor,command);
  const supervisor=path.join(checked.sourceRoot,'scripts/quality/storage-lifecycle.mjs'), worker=path.join(checked.sourceRoot,'scripts/release/available-candidate.mjs');
  const request=Buffer.from(JSON.stringify({root:path.resolve(root),command})).toString('base64url');
  const ownedRoots=[verifierRoot].filter(value=>value!==owner&&!value.startsWith(owner+path.sep));
  const result=spawnSync(process.execPath,[supervisor,'--run',owner,String(plannedBytes),'release','--external-owned-bytes',String(ownedEngineBytes(owner)),'--caller-pid',String(process.pid),...ownedRoots.flatMap(value=>['--owned-root',value]),'--',process.execPath,worker,'--coverage-worker',request],{encoding:'utf8',timeout:4*60*60*1000,maxBuffer:1024**2});
  need(!result.error&&result.status===0,`Available candidate independent source replay failed: ${result.error?.message??result.stderr?.slice(-2000)??result.status}`);
  const replay=JSON.parse(result.stdout);
  need(replay.verified===true&&replay.source_replay_performed===true&&replay.report_sha256===descriptor.sha256,'Supervised replay returned a foreign or incomplete report.');
  return replay;
}

/** Worker borrows the supervisor's scratch; the monitor stays responsive while Python runs. */
function replayAvailableCandidateCoverage(root, manifest, command) {
  const {checked,descriptor,report}=availableCoverageInputs(root,manifest);
  need(command&&typeof command.executable==='string'&&path.isAbsolute(command.executable)&&Array.isArray(command.args)&&command.args.every(value=>typeof value==='string')&&command.env&&typeof command.env==='object','Available candidate verifier command is invalid.');
  const lease=inheritedScratchStorage({root:storageRoot(root),plannedBytes:planCandidateReplay(root,checked,descriptor,command)});
  const watchdog=watchStorageSupervisor(lease.supervisorPid);
  const temporary = lease.directory;
  try {
    const candidateFile=path.join(temporary,'candidate.json'), sourceFile=path.join(temporary,'source.json'), inputs=path.join(temporary,'inputs');
    writeFileSync(candidateFile,JSON.stringify(manifest)); writeFileSync(sourceFile,JSON.stringify(checked.source));
    const invoke = args => { lease.check(); const result=spawnSync(command.executable,[...command.args,...args],{env:{...command.env,...lease.env,TMPDIR:temporary,TMP:temporary,TEMP:temporary},encoding:'utf8',timeout:1800000,maxBuffer:1024 ** 2}); lease.check(); need(!result.error && result.status===0,`Available candidate independent source replay failed: ${result.error?.message ?? result.stderr?.slice(-2000)}`); return result; };
    invoke([path.join(checked.sourceRoot,'scripts/release/materialize-replay-inputs.py'),'--root',checked.sourceRoot,'--candidate-root',root,'--candidate',candidateFile,'--source',sourceFile,'--report',path.join(root,descriptor.path),'--output',inputs,'--compact','--stream-source']);
    const result=invoke([path.join(checked.sourceRoot,'scripts/release/component-closure.py'),'--root',checked.sourceRoot,'--candidate-root',root,'--runtime-root',checked.runtimeRoot,'--assets-root',inputs,'--available-targets','--stream-source','--candidate',candidateFile,'--recipe',path.join(checked.sourceRoot,recipeName),'--verify-report',path.join(root,descriptor.path)]);
    need(JSON.parse(result.stdout).complete_available_shipped_component_coverage===true,'Independent replay did not prove available coverage.');
    readRecordedBytes(root,descriptor,MAX_COMPONENT_SOURCE_REPORT_BYTES); validateAvailableCandidate(root,manifest);
    return {verified:true,qualification:'available-target-source-coverage-only',source_replay_performed:true,source_coverage_receipt:{...descriptor},complete_available_shipped_component_coverage:true,complete_product_coverage:report.complete_product_coverage,pending_artifacts:manifest.scope.pending_artifacts,report_sha256:descriptor.sha256};
  } finally { watchdog.kill(); lease.cleanup(); }
}

/** New payloads only; a diagnostic archive can never be upgraded in place. */
export function prepareAvailableCandidate({sourceRoot,runtimeRoot=sourceRoot,buildRoot,output,python,materialPhase='provisional',sourceTransferRoots=[],transientBytes=undefined}) {
  return prepareAvailableCandidateInternal({sourceRoot,runtimeRoot,buildRoot,output,python,materialPhase,sourceTransferRoots,transientBytes},false);
}

/** The worker can borrow only the supervisor's exact output and byte plan. */
function prepareAvailableCandidateInternal({sourceRoot,runtimeRoot=sourceRoot,buildRoot,output,python,materialPhase='provisional',sourceTransferRoots=[],transientBytes=undefined},worker) {
  sourceRoot=realpathSync(sourceRoot); runtimeRoot=realpathSync(runtimeRoot); buildRoot=realpathSync(buildRoot); output=canonicalOutput(output);
  const owner=storageRoot(buildRoot);
  if(!worker){recoverStorage(owner);recoverSourcePartTransfer(owner);recoverAbandonedCandidate(owner);}
  need(!existsSync(output) && ![sourceRoot,runtimeRoot,buildRoot].includes(output) && ['provisional','final'].includes(materialPhase),'Available candidate requires a new independent output and explicit material phase.');
  const composition=json(path.join(runtimeRoot,'freeze-composition.json'));
  need(composition.qualification==='available-target-inputs' && !existsSync(path.join(runtimeRoot,'INCOMPLETE')),'Available packages require newly composed explicit available-target inputs; diagnostic composition cannot be relabeled.');
  const source=sourceReceipt(sourceRoot), runtime=json(path.join(runtimeRoot,'runtime/runtime.lock.json')), runtimeHash=fileReceipt(runtimeRoot,'runtime/runtime.lock.json').sha256;
  need(source.sha256===composition.source_tree_sha256 && fileReceipt(sourceRoot,'runtime/runtime.lock.json').sha256===runtimeHash,'Available composition source/runtime binding is stale.');
  const targets=Object.keys(json(path.join(runtimeRoot,'runtime/userspace.lock.json')).platforms).map(value=>value.replace('/','-')).sort();
  for(const target of targets) { const platform='linux/'+(target.endsWith('-x64')?'amd64':'arm64'); need(runtime.packs.core.images[platform]&&runtime.packs.render.images[platform],'Available native target requires its real same-architecture worker.'); }
  availableScope(sourceRoot,targets,[]);
  const sourceBytes=source.files.reduce((sum,row)=>sum+row.size,0), userspace=json(path.join(runtimeRoot,'runtime/userspace.lock.json'));
  const transports=new Map();
  for(const pack of Object.values(runtime.packs)) for(const item of [pack.index_transport,...Object.values(pack.images).flatMap(image=>image.transports)]) transports.set(item.path,item.size_bytes);
  const auxiliary=auxiliaryArtifacts(runtimeRoot,userspace,runtime,{targets});
  const materials=materialPhase==='final'?sourceArtifacts(sourceRoot,{required:true}):[];
  const parts=materials.filter(row=>/^corresponding-source-[0-9]{4}$/.test(row.id));
  const transfers=materialPhase==='final'?selectedSourceTransfers(owner,sourceRoot,output,parts,sourceTransferRoots):[];
  const transferredBytes=transfers.reduce((sum,row)=>sum+row.size,0);
  need(Number.isSafeInteger(transferredBytes),'Transferred source part total is invalid.');
  // Native payload, two archive formats, one sequential build workspace and
  // the bounded Node extraction are charged at their uncompressed sizes.
  const payloadSizes=targets.map(target=>sourceBytes+512*1024**2+selectedUserspaceFiles(userspace,target).reduce((n,row)=>n+row.size,0));
  // Two retained archives per target plus the universal npm archive; the
  // expanded build is disposable and charged separately to scratch.
  const nativeBytes=payloadSizes.reduce((sum,size)=>sum+2*size,0)+128*1024**2;
  const crossInputs=resolveCrossBuildInputs(buildRoot,'.artifacts/cross-build-receipt.json');
  const crossBytes=crossInputs.binaries.reduce((sum,row)=>sum+row.size,0);
  const helpers=selectedNativeHelpers(runtime,'all').reduce((sum,row)=>{need(Number.isSafeInteger(row.guard.size_bytes)&&row.guard.size_bytes>=0,'Native helper storage subject is invalid.');return sum+row.guard.size_bytes;},0);
  const maxUserspace=Math.max(0,...[...targets,'all'].map(target=>selectedUserspaceFiles(userspace,target).reduce((sum,row)=>sum+row.size,0)));
  // Retained output and the sequential package workspace are distinct. Keep
  // the legacy full-copy output allowance until package-backed output exists.
  const plan=planAvailableStorage({sourceBytes,runtimeBytes:storageTreeBytes(path.join(runtimeRoot,'runtime')),nativeBytes,transportBytes:[...transports.values()].reduce((sum,size)=>sum+size,0),auxiliaryBytes:auxiliary.reduce((sum,row)=>sum+row.size_bytes,0),materialBytes:materials.reduce((sum,row)=>sum+row.size,0)-transferredBytes,targetCount:targets.length,crossBytes,helperBytes:helpers,maxUserspace});
  // Diagnostic builders may hold the source snapshot, expanded payload and
  // both uncompressed-size archive upper bounds at once.
  const plannedBytes=Math.max(plan.plannedBytes,sourceBytes+crossBytes+3*Math.max(...payloadSizes)+128*1024**2),plannedOutputBytes=plan.plannedOutputBytes;
  if(!worker) {
    const otherRoots=[sourceRoot,runtimeRoot,buildRoot].filter(file=>file!==owner&&!file.startsWith(owner+path.sep));
    const externalOwnedBytes=ownedEngineBytes(owner);
    const supervisor=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../quality/storage-lifecycle.mjs');
    const request=Buffer.from(JSON.stringify({sourceRoot,runtimeRoot,buildRoot,output,python,materialPhase,sourceTransferRoots})).toString('base64url');
    const args=[supervisor,'--run',owner,String(plannedBytes),'release',...(transientBytes===undefined?[]:['--transient-bytes',String(transientBytes)]),'--external-owned-bytes',String(externalOwnedBytes),'--output',output,'--output-bytes',String(plannedOutputBytes),'--caller-pid',String(process.pid),...(transfers.length?['--output-transfer-journal',sourceTransferJournal(owner)]:[]),...otherRoots.flatMap(file=>['--owned-root',file]),'--',process.execPath,fileURLToPath(import.meta.url),'--assembly-worker',request];
    const result=spawnSync(process.execPath,args,{encoding:'utf8',maxBuffer:2*1024**2,timeout:4*60*60*1000});
    if(result.error||result.status!==0){
      recoverSourcePartTransfer(owner);
      if(existsSync(output)) abortCandidateIfActive(owner,output);
      throw new Error(`Supervised available candidate assembly failed: ${result.error?.message??result.stderr?.slice(-2000)??result.status}`);
    }
    recoverSourcePartTransfer(owner);
    return json(path.join(output,'available-candidate.json'));
  }
  let begun=false;
  const lease=inheritedOutputStorage({root:owner,output,plannedBytes,plannedOutputBytes});
  const watchdog=watchStorageSupervisor(lease.supervisorPid);
  const checkStorage=()=>{const credit=transferredOutputBytes(owner,output,transfers.length?sourceTransferJournal(owner):undefined);return lease.check(storageTreeBytes(output,plannedOutputBytes+credit)-credit);};
  const buildRun=(script,args,timeout)=>{checkStorage();const value=run(python,sourceRoot,script,args,timeout,{...process.env,...lease.env,TMPDIR:lease.directory,TMP:lease.directory,TEMP:lease.directory});checkStorage();return value;};
  const artifactDir=path.join(output,'artifacts'); const records=[],installations=[],payloadCopies=new Map();
  const add=(id,base,row,platform='all')=>{const name='artifacts/'+path.posix.basename(safeRelative(row.path));need(!records.some(value=>value.id===id||value.path===name),'Available artifacts collide.');copyCandidatePayload(base,row,output,output,name,payloadCopies);const actual=fileReceipt(output,name);records.push({id,platform,...actual});};
  try {
    beginCandidate(owner,output); begun=true; writeFileSync(path.join(output,'INCOMPLETE'),'Available candidate assembly incomplete.\n'); mkdirSync(artifactDir);
    retainSourceSnapshot(sourceRoot,source,path.join(output,'source-snapshot'));
    const runtimeDestination=path.join(output,'runtime-inputs'); mkdirSync(runtimeDestination); copyTree(path.join(runtimeRoot,'runtime'),path.join(runtimeDestination,'runtime'));
    for(const target of targets) {
      checkStorage();
      const built=path.join(lease.directory,'build-'+target),report=preparePlatformDiagnostic(runtimeRoot,target,built,{sourceRoot,buildRoot,qualification:'preacceptance_candidate',python,tempRoot:lease.directory});
      const install=path.join(built,'installation'),contract={inventory_sha256:fileReceipt(install,'PACKAGE-INVENTORY.json').sha256,build_receipt_sha256:fileReceipt(install,'BUILD-RECEIPT.json').sha256};
      for(const row of report.artifacts){
        const inspected=JSON.parse(buildRun('scripts/release/inspect-package.py',[path.join(built,row.path),'--kind','native','--platform',target,'--source-sha256',source.sha256,'--runtime-sha256',runtimeHash,'--require-candidate']));
        need(inspected.inventory_sha256===contract.inventory_sha256&&inspected.build_receipt_sha256===contract.build_receipt_sha256,'Original platform archive differs from its built package contract.');
        add(`${row.format}-${ids[target]}`,built,row,ids[target]);
      }
      if(!existsSync(path.join(output,'native-inputs')))renameSync(path.join(built,'native-inputs'),path.join(output,'native-inputs'));
      installations.push({platform:target,formats:{native:{artifact_id:'native-'+ids[target],...contract},mcpb:{artifact_id:'mcpb-'+ids[target],...contract}}}); rmSync(built,{recursive:true,force:true});
    }
    checkStorage();
    const npmBuild=path.join(lease.directory,'build-npm'),npm=prepareNpmDiagnostic(runtimeRoot,npmBuild,{sourceRoot,buildRoot,qualification:'preacceptance_candidate',python,tempRoot:lease.directory});const npmInstall=path.join(npmBuild,'npm-installation'),npmContract={artifact_id:'npm',inventory_sha256:fileReceipt(npmInstall,'PACKAGE-INVENTORY.json').sha256,build_receipt_sha256:fileReceipt(npmInstall,'BUILD-RECEIPT.json').sha256};const inspectedNpm=JSON.parse(buildRun('scripts/release/inspect-package.py',[path.join(npmBuild,npm.artifact.path),'--kind','npm','--platform','all','--source-sha256',source.sha256,'--runtime-sha256',runtimeHash,'--require-candidate']));need(inspectedNpm.inventory_sha256===npmContract.inventory_sha256&&inspectedNpm.build_receipt_sha256===npmContract.build_receipt_sha256,'Original npm archive differs from its built package contract.');add('npm',npmBuild,npm.artifact);for(const row of installations)row.formats.npm={...npmContract};rmSync(npmBuild,{recursive:true,force:true});
    const common=path.join(lease.directory,'common-work'); mkdirSync(common); const skills=path.join(common,'skills');mkdirSync(skills);copyTree(path.join(sourceRoot,'skills'),path.join(skills,'skills'));writeSkillSupport(sourceRoot,skills);for(const name of ['LICENSE','NOTICE'])copyFile(sourceRoot,fileReceipt(sourceRoot,name),skills);copyTree(path.join(sourceRoot,'licenses'),path.join(skills,'licenses'));writeFileSync(path.join(skills,'RELEASE-CANDIDATE.md'),'Immutable subset preacceptance; no production certification.\n');packageInventory(skills,'skills','all',source.sha256,runtimeHash,'preacceptance_candidate');
    const skillsName='ud-agent-skill-mcp-plugin-skills.tar.gz';buildRun('scripts/release/archive-dev.py',[skills,path.join(artifactDir,skillsName),'--format','tar.gz']);records.push({id:'standalone-skills',platform:'all',...fileReceipt(output,'artifacts/'+skillsName)});
    const archivedSource=path.join(common,'source');copyTree(path.join(output,'source-snapshot'),archivedSource);rmSync(path.join(archivedSource,'SOURCE-RECEIPT.json'));writeFileSync(path.join(archivedSource,'SOURCE-MANIFEST.json'),JSON.stringify(source,null,2)+'\n');const sourceName='ud-agent-skill-mcp-plugin-source.tar.gz';buildRun('scripts/release/archive-dev.py',[archivedSource,path.join(artifactDir,sourceName),'--format','tar.gz']);records.push({id:'source-archive',platform:'all',...fileReceipt(output,'artifacts/'+sourceName)});
    const sbomName='ud-agent-skill-mcp-plugin-sbom.spdx.json';buildRun('scripts/release/sbom.py',['--root',sourceRoot,'--source-receipt',path.join(output,'source-snapshot/SOURCE-RECEIPT.json'),'--created',new Date().toISOString().replace(/\.\d{3}Z$/,'Z'),'--output',path.join(artifactDir,sbomName),...(materialPhase==='provisional'?['--provisional-materials']:[])]);records.push({id:'sbom',platform:'all',...fileReceipt(output,'artifacts/'+sbomName)});
    for(const [id,from,name]of [['mcp-registry-record','registry/server.json','ud-agent-skill-mcp-plugin-mcp-registry.json'],['catalog-claude','.claude-plugin/marketplace.json','ud-agent-catalog-claude.json'],['catalog-codex','packaging/codex/marketplace.json','ud-agent-catalog-codex.json'],['catalog-grok','.grok-plugin/marketplace.json','ud-agent-catalog-grok.json'],['catalog-grok-index','.grok-plugin/plugin-index.json','ud-agent-catalog-grok-index.json']]){const bytes=readFileSync(path.join(sourceRoot,from));writeFileSync(path.join(artifactDir,name),id==='mcp-registry-record'?canonicalJson(JSON.parse(bytes.toString())):bytes);records.push({id,platform:'all',...fileReceipt(output,'artifacts/'+name)});}
    for(const name of ['core','render']) {
      checkStorage();
      const pack=runtime.packs[name],descriptor=pack.index_transport,actual=verifyRecordedFile(runtimeRoot,{...descriptor,sha256:descriptor.sha256.replace(/^sha256:/,''),size:descriptor.size_bytes});verifyOciArchive(path.join(runtimeRoot,descriptor.path),pack.index_digest,pack.platforms,actual,pack.images,{diagnosticSinglePlatform:Object.keys(pack.images).length===1});add(name+'-oci-index',runtimeRoot,actual,'linux-available');copyCandidatePayload(runtimeRoot,actual,output,runtimeDestination,undefined,payloadCopies);
      for(const[platform,image]of Object.entries(pack.images))for(const[number,item]of image.transports.entries()){const row={...item,sha256:item.sha256.replace(/^sha256:/,''),size:item.size_bytes};add(`${name}-${platform.replace('/','-')}-${item.format}-${number}`,runtimeRoot,row,platform);copyCandidatePayload(runtimeRoot,row,output,runtimeDestination,undefined,payloadCopies);}
    }
    for(const row of userspace.bootstrap_assets??[]){const checked={...row,sha256:row.sha256.replace(/^sha256:/,'')};add(row.id,runtimeRoot,checked,row.id.replace(/^uv-/,''));copyCandidatePayload(runtimeRoot,checked,output,runtimeDestination,undefined,payloadCopies);}
    for(const row of auxiliary){const checked={...row,sha256:row.sha256.replace(/^sha256:/,''),size:row.size_bytes};add(row.id,runtimeRoot,checked,row.platform);copyCandidatePayload(runtimeRoot,checked,output,runtimeDestination,undefined,payloadCopies);}
    // Provisional inspection discovers the selected source universe from real
    // payloads. It does not copy a stale, broader historical source union.
    if(materialPhase==='final') {
      if(transfers.length)beginSourcePartTransfer(owner,output,transfers);
      for(const row of materials) {
        const transfer=transfers.find(value=>value.id===row.id);
        if(transfer){moveSourcePart(owner,transfer);const name='artifacts/'+path.posix.basename(safeRelative(row.path));need(!records.some(value=>value.id===row.id||value.path===name),'Available artifacts collide.');records.push({id:row.id,platform:'all',...fileReceipt(output,name)});}
        else add(row.id,sourceRoot,row);
      }
    }
    rmSync(common,{recursive:true,force:true});writeFileSync(path.join(output,'RUNTIME-INVENTORY.json'),JSON.stringify({schema_version:1,files:treeFiles(runtimeDestination)},null,2)+'\n');
    const manifest={schema_version:2,qualification:'available-target-preacceptance',status:'preacceptance_candidate',production_ready:false,material_phase:materialPhase,source_tree_sha256:source.sha256,runtime_lock_sha256:runtimeHash,scope:availableScope(sourceRoot,targets,records),pending_provider_assets:pendingProviderAssets(runtime,targets),artifacts:records,installations,source_snapshot:{root:'source-snapshot',receipt:fileReceipt(output,'source-snapshot/SOURCE-RECEIPT.json')},runtime_root:'runtime-inputs',runtime_inventory:fileReceipt(output,'RUNTIME-INVENTORY.json'),native_inputs:fileReceipt(output,'native-inputs/INPUTS.json')};
    validateAvailableCandidate(output,manifest);
    const manifestFile=path.join(output,'available-candidate.json');writeFileSync(manifestFile,JSON.stringify(manifest,null,2)+'\n');
    const coverageName='artifacts/ud-agent-component-source-coverage.json';buildRun('scripts/release/component-closure.py',['--root',path.join(output,'source-snapshot'),'--assets-root',buildRoot,'--candidate-root',output,'--runtime-root',runtimeDestination,'--available-targets','--candidate',manifestFile,'--recipe',path.join(output,'source-snapshot',recipeName),'--output',path.join(output,coverageName)],1800000);records.push({id:'component-source-coverage',platform:'all',...fileReceipt(output,coverageName)});
    const coverage=json(path.join(output,coverageName)); if(materialPhase==='final'){need(coverage.complete_available_shipped_component_coverage===true&&coverage.unresolved_shipped_members.length===0&&coverage.inspection_inputs.unretained_inputs.length===0,'Final available materials remain unresolved.');verifyRequiredSourceMaterials(path.join(output,'source-snapshot'),coverage.required_materials,{candidate:manifest,artifactRoot:output});}
    writeFileSync(path.join(artifactDir,'SHA256SUMS'),records.map(row=>`${row.sha256}  ${path.posix.basename(row.path)}`).join('\n')+'\n');records.push({id:'checksum-manifest',platform:'all',...fileReceipt(output,'artifacts/SHA256SUMS')});manifest.scope=availableScope(sourceRoot,targets,records);writeFileSync(manifestFile,JSON.stringify(manifest,null,2)+'\n');
    need(sourceReceipt(sourceRoot).sha256===source.sha256,'Available source changed during assembly.');validateAvailableCandidate(output,manifest);checkStorage();rmSync(path.join(output,'INCOMPLETE'));completeCandidate(owner,output,manifest);begun=false;return manifest;
  } catch(error){if(begun)try{recoverSourcePartTransfer(owner);abortCandidate(owner,output);}catch(cleanupError){throw new AggregateError([error,cleanupError],'Candidate assembly or retained-payload cleanup failed.');}throw error;}
  finally{watchdog.kill();lease.cleanup();}
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) try {
  if(process.argv[2]==='--material-stage-worker') {
    need(process.argv.length===4,'Invalid supervised material-stage request.');
    let request;try{request=JSON.parse(Buffer.from(process.argv[3],'base64url').toString('utf8'));}catch{throw new Error('Invalid supervised material-stage request.');}
    console.log(JSON.stringify(stageAvailableMaterialsInternal(request.provisionalRoot,request.planRoot,request.output,{python:request.python},true)));
  } else if(process.argv[2]==='--coverage-worker') {
    need(process.argv.length===4,'Invalid supervised replay request.');
    let request; try { request=JSON.parse(Buffer.from(process.argv[3],'base64url').toString('utf8')); } catch { throw new Error('Invalid supervised replay request.'); }
    need(request&&typeof request.root==='string'&&path.isAbsolute(request.root),'Invalid supervised replay root.');
    const manifest=json(path.join(request.root,'available-candidate.json'));
    console.log(JSON.stringify(replayAvailableCandidateCoverage(request.root,manifest,request.command)));
  } else if(process.argv[2]==='--assembly-worker') {
    need(process.argv.length===4,'Invalid supervised assembly request.');
    let request; try { request=JSON.parse(Buffer.from(process.argv[3],'base64url').toString('utf8')); } catch { throw new Error('Invalid supervised assembly request.'); }
    const result=prepareAvailableCandidateInternal(request,true);
    console.log(JSON.stringify({qualification:result.qualification,material_phase:result.material_phase,artifacts:result.artifacts.length}));
  } else {
  /** @type {any} */
  const options = {};
  const installing = process.argv[2] === '--install-materials';
  const keys = installing
    ? {'--provisional':'provisional','--materials':'materials','--output':'output','--python':'python'}
    : {'--source-root':'sourceRoot','--runtime-root':'runtimeRoot','--build-root':'buildRoot','--output':'output','--python':'python','--material-phase':'materialPhase','--transient-bytes':'transientBytes'};
  for (let index = installing ? 3 : 2; index < process.argv.length; index++) {
    if (!installing && process.argv[index] === '--transfer-root') {
      need(process.argv[index + 1] && path.isAbsolute(process.argv[index + 1]), 'Transfer root must be an explicit absolute path.');
      (options.sourceTransferRoots ??= []).push(process.argv[++index]); continue;
    }
    const key = keys[process.argv[index]];
    need(key && process.argv[index + 1] && options[key] === undefined, 'Unknown or duplicated available candidate argument.');
    options[key] = process.argv[++index];
  }
  if (installing) {
    need(['provisional','materials','output','python'].every(key => options[key]), 'Usage: available-candidate.mjs --install-materials --provisional CANDIDATE --materials PLAN --output NEW_SOURCE --python PYTHON');
    console.log(JSON.stringify(stageAvailableMaterials(path.resolve(options.provisional),path.resolve(options.materials),path.resolve(options.output),{python:options.python})));
  } else {
    need(['sourceRoot','buildRoot','output','python'].every(key => options[key]), 'Usage: available-candidate.mjs --source-root FROZEN --build-root INPUTS --output NEW --python PYTHON [--runtime-root FROZEN] [--material-phase provisional|final] [--transfer-root RETAINED_PART_DIRECTORY] [--transient-bytes BYTES]');
    if (options.transientBytes !== undefined) {
      need(/^\d+$/.test(options.transientBytes),'Transient byte allowance must be an integer.');
      options.transientBytes = Number(options.transientBytes);
    }
    const result = prepareAvailableCandidate(options);
    console.log(JSON.stringify({qualification:result.qualification,material_phase:result.material_phase,artifacts:result.artifacts.length,pending:result.scope.pending_artifacts}));
  }
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
