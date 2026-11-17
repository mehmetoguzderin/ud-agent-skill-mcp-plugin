/** Two-pass source planning and immutable candidate coverage production. */
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { MAX_COMPONENT_SOURCE_REPORT_BYTES } from './component-closure.mjs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileReceipt, readRecordedBytes, safeRelative, sha256, sourceReceipt } from './candidate.mjs';
import { verifyRetainedCrossBuildInputs } from './cross-build-inputs.mjs';
import { verifyRequiredSourceMaterials } from './source-artifacts.mjs';

const omitted = new Set(['component-source-coverage', 'publisher-authority', 'checksum-manifest']);
export const componentRecipePath = 'runtime/materials/component-source-replay.json';
function insist(value, message) { if (!value) throw new Error(message); }
const legacyInspection = 'observed-component-replay-inputs-no-unretained-input-waiver';
const compactInspection = 'compact-family-replay-inputs-no-unretained-input-waiver';
const sha = /^[a-f0-9]{64}$/;
const closed = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
const codepointOrder = (left,right) => { const a=[...left],b=[...right];for(let i=0;i<Math.min(a.length,b.length);i++){const difference=a[i].codePointAt(0)-b[i].codePointAt(0);if(difference)return difference;}return a.length-b.length; };

/** Check only report shape and byte-bound metadata, never claim replay occurred. */
export function validateInspectionReceipt(value, sourceSha256, subjects, { requireComplete = true } = {}) {
  if (value?.qualification === legacyInspection) {
    insist(!requireComplete || Array.isArray(value.unretained_inputs) && value.unretained_inputs.length === 0, 'Component replay still depends on unretained local inspection inputs.');
    return { version: 1, source_replay_performed: false };
  }
  const keys=['schema_version','qualification','source_inventory_sha256','subjects','input_count','inventory_sha256','metadata','tools','unretained_count','unretained_sha256'];
  insist(closed(value,keys)&&value.schema_version===2&&value.qualification===compactInspection&&sha.test(sourceSha256??'')&&value.source_inventory_sha256===sourceSha256&&sha.test(value.inventory_sha256??'')&&sha.test(value.unretained_sha256??''), 'Compact inspection receipt has a foreign or malformed identity.');
  insist(Array.isArray(subjects)&&Array.isArray(value.subjects)&&value.subjects.length===subjects.length&&subjects.every((row,index)=>closed(value.subjects[index],['id','sha256'])&&value.subjects[index].id===row.id&&value.subjects[index].sha256===row.sha256), 'Compact inspection receipt has different artifact subjects.');
  insist(Number.isSafeInteger(value.input_count)&&value.input_count>=0&&value.input_count<=100000&&Number.isSafeInteger(value.unretained_count)&&value.unretained_count>=0&&value.unretained_count<=value.input_count&&(!requireComplete||value.input_count>0&&value.unretained_count===0), 'Compact inspection receipt is incomplete.');
  insist(value.unretained_count!==0||value.unretained_sha256===sha256(Buffer.from('[]')), 'Compact inspection unresolved digest differs.');
  insist(Array.isArray(value.metadata)&&value.metadata.length<=value.input_count&&Array.isArray(value.tools)&&value.tools.length<=100000, 'Compact inspection metadata or tool inventory is invalid.');
  let metadataBytes=0,previous;
  for(const row of value.metadata){
    insist(closed(row,['path','sha256','size_bytes','executable','retention'])&&typeof row.path==='string'&&safeRelative(row.path)===row.path&&(previous===undefined||codepointOrder(previous,row.path)<0)&&sha.test(row.sha256??'')&&Number.isSafeInteger(row.size_bytes)&&row.size_bytes>=0&&row.size_bytes<=8*1024**2&&typeof row.executable==='boolean'&&closed(row.retention,['kind','base64'])&&row.retention.kind==='retained-json-metadata'&&typeof row.retention.base64==='string','Compact inspection metadata receipt is invalid.');
    previous=row.path;const bytes=Buffer.from(row.retention.base64,'base64');
    insist(bytes.toString('base64')===row.retention.base64&&bytes.length===row.size_bytes&&sha256(bytes)===row.sha256,'Compact inspection metadata bytes differ.');
    metadataBytes+=bytes.length;insist(metadataBytes<=32*1024**2,'Compact inspection metadata exceeds its bound.');
    try{JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new Error('Compact inspection metadata is not valid JSON.');}
  }
  for(const tool of value.tools) insist(closed(tool,['name','sha256','size_bytes','distribution'])&&typeof tool.name==='string'&&tool.name.length>0&&!/[\\/\0]/.test(tool.name)&&tool.name!=='.'&&tool.name!=='..'&&sha.test(tool.sha256??'')&&Number.isSafeInteger(tool.size_bytes)&&tool.size_bytes>=0&&tool.distribution==='nonredistributed-inspection-tool-prerequisite','Compact inspection tool receipt is invalid.');
  return { version: 2, source_replay_performed: false };
}

/** Verify exact on-disk subjects before giving the Python verifier their paths. */
export function projectCoverageCandidate(root, candidate, stage, { requireComplete = false } = {}) {
  const required = JSON.parse(readFileSync(path.join(root, 'quality/requirements.json'), 'utf8')).required_artifacts, ids = new Set(), names = new Set(), artifacts = [];
  insist((candidate?.schema_version === 1 || candidate?.schema_version === 2 && candidate.qualification === 'available-target-preacceptance') && Array.isArray(candidate.artifacts), 'Coverage preparation requires an actual artifact inventory.');
  for (const item of candidate.artifacts) {
    insist(typeof item.id === 'string' && !ids.has(item.id), 'Coverage artifact identity is missing or duplicate.'); ids.add(item.id);
    const name = path.posix.basename(safeRelative(item.path)); insist(!names.has(name), 'Coverage artifact filenames collide.'); names.add(name);
    const actual = fileReceipt(stage, name); insist(actual.sha256 === item.sha256 && actual.size === item.size, 'Actual staged artifact differs from the candidate.');
    if (!omitted.has(item.id)) artifacts.push({ ...item, path: safeRelative(path.relative(root, path.join(stage, name)).split(path.sep).join('/')) });
  }
  for (const name of readdirSync(stage)) {
    const info = lstatSync(path.join(stage, name)); insist(!info.isSymbolicLink(), 'Artifact staging contains a link.');
    if (info.isDirectory() && name === 'native-inputs') { verifyRetainedCrossBuildInputs(path.join(stage, name)); continue; }
    if (info.isDirectory() && name === 'source-snapshot') { insist(sourceReceipt(path.join(stage, name)).sha256 === candidate.source_tree_sha256, 'Retained provisional source differs from the actual artifact source.'); continue; }
    insist(info.isFile() && names.has(name), 'Artifact staging has an undeclared file or directory.');
  }
  if (requireComplete) insist(Array.isArray(required) && required.length > 0 && new Set(required).size === required.length && required.every(id => ids.has(id)), 'Source material planning requires every declared distribution subject.');
  return { ...candidate, artifacts };
}

/** @param {{python?: string, requireComplete?: boolean}} [options] */
export function writeComponentCoverage(root, candidate, stage, options = {}) {
  const { python, requireComplete = true } = options;
  const original = sourceReceipt(root), recipe = original.files.find(row => row.path === componentRecipePath); insist(recipe, 'Frozen actual component-source replay recipe is missing.'); readRecordedBytes(root, recipe);
  insist(candidate.source_tree_sha256 === original.sha256, 'Source changed before actual component replay.');
  const projected = projectCoverageCandidate(root, candidate, stage, { requireComplete }), temporary = mkdtempSync(path.join(root, '.artifacts/.component-preparation-'));
  const output = path.join(stage, 'ud-agent-component-source-coverage.json'); insist(!existsSync(output), 'Component coverage output must be new.');
  try {
    const manifest = path.join(temporary, 'subjects.json'); writeFileSync(manifest, JSON.stringify(projected));
    const result = spawnSync(python, ['-I', path.join(root, 'scripts/release/component-closure.py'), '--root', root, '--candidate', manifest, '--recipe', path.join(root, componentRecipePath), '--output', output, ...(requireComplete ? [] : ['--diagnostic'])], { cwd: root, encoding: 'utf8', timeout: 1800000, maxBuffer: 1024 ** 2 });
    insist(!result.error && result.status === 0, `Actual shipped-component source replay failed: ${result.error?.message ?? result.stderr?.slice(-2000)}`);
    const descriptor = fileReceipt(stage, path.basename(output)), report = JSON.parse(readRecordedBytes(stage, descriptor, MAX_COMPONENT_SOURCE_REPORT_BYTES).toString('utf8'));
    insist(report.schema_version === 1 && report.qualification === 'replayed-actual-shipped-component-source-license-closure' && report.source_inventory_sha256 === original.sha256 && report.runtime_lock_sha256 === candidate.runtime_lock_sha256, 'Produced source coverage has a foreign subject.');
    insist(!requireComplete || report.complete_available_shipped_component_coverage === true && report.complete_product_coverage === true && report.unresolved_shipped_members.length === 0 && report.missing_distribution_subjects.length === 0, 'Actual available or complete-product component coverage is unresolved.');
    const inspection=validateInspectionReceipt(report.inspection_inputs,original.sha256,projected.artifacts,{requireComplete});
    insist(!requireComplete||inspection.version===1,'Compact production source replay is not yet available.');
    if (requireComplete) verifyRequiredSourceMaterials(root, report.required_materials);
    insist(sourceReceipt(root).sha256 === original.sha256, 'Source changed during actual component replay.');
    return { id: 'component-source-coverage', platform: 'all', ...descriptor };
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

/** Planning never relabels or overwrites the provisional payloads it inspects. */
export function planSourceMaterials(root, { sourceRoot = root, candidateRoot = root, runtimeRoot = sourceRoot, candidate, recipe, collections, output, python, diagnostic = false, available = false }) {
  insist(!existsSync(output) && Array.isArray(collections) && collections.length > 0, 'A new source plan output and original collections are required.');
  insist(!(diagnostic && available), 'Available-target material planning cannot relabel diagnostic payloads.');
  const args = ['-I', '-S', '-B', path.join(sourceRoot, 'scripts/release/assemble-component-sources.py'), '--root', sourceRoot, '--assets-root', root, '--candidate-root', candidateRoot, '--runtime-root', runtimeRoot, '--candidate', candidate, '--recipe', recipe, '--output', output, ...(diagnostic ? ['--diagnostic'] : []), ...(available ? ['--available-targets'] : [])];
  for (const item of collections) args.push('--collection', item);
  const result = spawnSync(python, args, { cwd: root, encoding: 'utf8', timeout: 1800000, maxBuffer: 1024 ** 2 });
  insist(!result.error && result.status === 0, `Original source-material planning failed: ${result.error?.message ?? result.stderr?.slice(-2000)}`);
  return JSON.parse(result.stdout);
}
