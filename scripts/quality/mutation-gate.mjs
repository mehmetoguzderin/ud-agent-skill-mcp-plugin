/** Strict multi-language mutation gate. Missing, stale, incomplete, or error
 * evidence is failure. Mutations run only in a disposable source snapshot.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import os from 'node:os';
import { assessPerl } from './perl-assess.mjs';
import { assessPerlGuards } from './perl-guard-assess.mjs';
import { sourceReceipt, fileReceipt, readRecordedBytes, SOURCE_ROOTS } from '../release/candidate.mjs';
import { PROTECTED_MUTATION_SCRATCH_BYTES, reserveStorage, STORAGE_LIMITS } from './storage-lifecycle.mjs';
import { localDockerAuthority } from './mutation-scope.mjs';
import { inspectOwnedDockerStorage, lockedDockerImages } from './docker-owned-storage.mjs';
import { verifyRecordedStrykerSdk } from './stryker-sdk-evidence.mjs';
import { mutationDefinition, reconcileScheduledMutations, reconcilePythonSchedule } from './mutation-inventory.mjs';
import { reviewedEquivalent } from './equivalents.mjs';
import {canonicalJson} from '../release/http-transports.mjs';
import { rustAssertionEvidence as reviewedRustAssertions, rustPhaseEvidence } from './rust-assertions.mjs';
import { nativeRustSourceParser, nativeRustCfgParser } from './rust-native-parser.mjs';
import { verifyRustApplicabilityEvidence } from './rust-applicability-cli.mjs';
import { createAssertionObligationClassifier, verifyAssertionObligationReview } from './assertion-obligations.mjs';
import { verifyProtectedSelections, verifiedSelectionTests, verifiedAssertionOrigin } from './stryker-selection-evidence.mjs';
import { acquireMutationSessionLease, discoverMutationSession, openMutationSession, sealMutationSession, discoverBoundedMutationSession, openBoundedMutationSession, sealBoundedMutationSession } from './mutation-session.mjs';
import { resolveOriginalExecutable } from './test.mjs';
import { bindOriginalCandidate } from './original-candidate-binding.mjs';
import { acceptanceInputHash } from '../release/discover-acceptance.mjs';
import { verifyMutationBackendDiscovery, verifiedMutationMaterializations } from '../release/mutation-backends.mjs';
import { assessBoundedFaults } from './fault-assess.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const IGNORE = new Set(['.git', '.aws', '.codex', '.npmrc', '.netrc', '.pypirc', 'node_modules', '.venv', '.artifacts', '.stryker-tmp', 'target', 'dist', 'reports', 'mutants', 'mutants.out', '__pycache__', '.pytest_cache', '.mypy_cache', 'coverage']);
const JS_EXT = /\.(?:ts|tsx|mts|cts|js|mjs|cjs)$/;
const PY_EXT = /\.py$/;
const RUST_EXT = /\.rs$/;
const PERL_EXT = /\.(?:pl|pm)$/;
const canonicalPythonShards = new WeakMap();

function hash(data) { return createHash('sha256').update(data).digest('hex'); }
function relative(root, value) { return path.relative(root, value).split(path.sep).join('/'); }
function isOwnedSource(name) { return /^(?:packages|workers|scripts|evals)\//.test(name); }

/** Inspect only the local, already-present protected image before reserving. */
export function mutationImageFootprint(image, environment = process.env, run = spawnSync, knownImageIds = []) {
  if (typeof image !== 'string' || !image) throw new Error('Mutation image identity is missing.');
  const docker = args => {
    const result = run('docker', args, { env: environment, encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 ** 2 });
    if (result.error || result.status !== 0) throw new Error('Could not inspect the local mutation image: ' + (result.error?.message ?? result.stderr ?? result.status));
    return result.stdout;
  };
  localDockerAuthority(environment, context => docker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', ...(context ? [context] : [])]).trim());
  const images = JSON.parse(docker(['image', 'inspect', image]));
  const item = Array.isArray(images) && images.length === 1 ? images[0] : null;
  if (!item || item.Os !== 'linux' || item.Architecture !== 'arm64' || !/^sha256:[a-f0-9]{64}$/.test(item.Id ?? '') || !Number.isSafeInteger(item.Size) || item.Size < 0 || image.startsWith('sha256:') && image !== item.Id) throw new Error('Local mutation image identity, architecture or size differs.');
  const inventory = inspectOwnedDockerStorage(docker, { selectedImages: [{ image_id: item.Id, size_bytes: item.Size }], knownImageIds, ...(environment.UD_AGENT_LOCAL_ACTIONS_OWNER ? { activeActionsOwner: environment.UD_AGENT_LOCAL_ACTIONS_OWNER } : {}) });
  return { image_id: item.Id, size_bytes: inventory.image_bytes };
}

/** Inventory all project inputs; symlinked first-party sources fail closed. */
export function inventoryTree(root) {
  const files = {};
  const problems = [];
  function walk(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (dir === root && !SOURCE_ROOTS.includes(entry.name)) continue;
      if (IGNORE.has(entry.name) || /^\.env(?:\.|$)/.test(entry.name) || entry.name.endsWith('.pyc') || entry.name === '.DS_Store') continue;
      const full = path.join(dir, entry.name);
      const name = relative(root, full);
      if (entry.isSymbolicLink()) {
        if (isOwnedSource(name)) problems.push(`First-party source symlink cannot be inventoried safely: ${name}`);
      } else if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) files[name] = hash(readFileSync(full));
      else if (isOwnedSource(name)) problems.push(`Non-regular first-party source: ${name}`);
    }
  }
  walk(root);
  return { files, problems };
}

/** Verify full-suite dispatch separately from the real observed coverage. */
export function pythonFullSuiteDispatchErrors(report, schedule, sourceSha256) {
  const failure = ['Python complete-suite dispatch evidence is missing, stale, or incomplete.'];
  try {
    const same = (a, b) => canonicalJson(a) === canonicalJson(b);
    const sorted = values => [...new Set(values)].sort();
    const tests = sorted(schedule.tests.map(item => item.id));
    const functions = sorted(schedule.inventory.map(item => item.id.split('__mutmut_')[0]));
    if (!tests.length || !functions.length || report?.schema_version !== 1 || report.strategy !== 'full-discovered-original-suite-not-coverage-selection' || report.source_tree_sha256 !== sourceSha256 ||
        !same(Object.keys(report).sort(), ['schema_version', 'strategy', 'source_tree_sha256', 'tests', 'function_names', 'observed_associations', 'observed_durations'].sort()) ||
        !same(report.tests, tests) || !same(report.function_names, functions) ||
        !report.observed_durations || typeof report.observed_durations !== 'object' || Array.isArray(report.observed_durations) || !same(Object.keys(report.observed_durations).sort(), tests) ||
        Object.values(report.observed_durations).some(value => typeof value !== 'number' || !Number.isFinite(value) || value < 0) ||
        !report.observed_associations || typeof report.observed_associations !== 'object' || Array.isArray(report.observed_associations) ||
        Object.entries(report.observed_associations).some(([name, values]) => !name || !Array.isArray(values) || !same(values, sorted(values)) || values.some(value => !tests.includes(value)))) return failure;
    return [];
  } catch { return failure; }
}

export function treeDigest(files) {
  const digest = createHash('sha256');
  for (const [name, value] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) digest.update(`${name}\0${value}\n`);
  return digest.digest('hex');
}

export function mutationSnapshotIdentity(root, inventory = inventoryTree(root)) {
  return { inventory_tree_sha256: treeDigest(inventory.files), snapshot_sha256: sourceReceipt(root).sha256 };
}

export function assessProtectedProvider(runner,source,backend,{isolation,execution,backendRunner}={}){
  const errors=[];
  if(runner?.scope_complete===false||runner?.diagnostic_scope!==undefined||runner?.qualification==='selected-diagnostic'||backendRunner?.scope_complete===false||backendRunner?.diagnostic_scope!==undefined||backendRunner?.qualification==='selected-diagnostic')errors.push('A selected diagnostic cannot satisfy complete protected mutation acceptance.');
  if(!runner||runner.inventory_only===true||runner.backend!==backend||runner.source_tree_sha256!==source||!/^sha256:[a-f0-9]{64}$/.test(runner.image??'')||
     runner.worker?.platform!=='linux'||runner.worker?.architecture!=='arm64'||runner.worker?.emulation!==false||
     runner.container_state?.OOMKilled!==false||runner.container_state?.Running!==false||!(backend==='rust'?[0,1,2]:[0,1]).includes(runner.container_state?.ExitCode)||
     runner.execution?.status!==runner.container_state?.ExitCode||runner.execution?.signal||runner.execution?.error||
     !Array.isArray(runner.cleanup)||runner.cleanup.length!==4||runner.cleanup.some(item=>item.status!=='removed-owned')||
     new Set(runner.cleanup.map(item=>item.kind+'\0'+item.name)).size!==4)errors.push('Protected mutation provider, native architecture, source binding, execution or owned cleanup is incomplete.');
  for(const proof of[isolation,execution])if(proof?.status!=='passed'||proof.source_tree_sha256!==source)errors.push('Protected mutation isolation proof is missing or belongs to another source.');
  if(backendRunner!==undefined&&(backendRunner?.status!=='executed-not-reconciled'||backendRunner.source_tree_sha256!==source))errors.push('Protected mutation backend did not complete its bound execution.');
  return errors;
}

function protectedProviderEvidence(directory,source,backend,backendFile){
 return assessProtectedProvider(maybeJson(path.join(directory,'runner.json')),source,backend,{isolation:maybeJson(path.join(directory,'isolation-proof.json')),execution:maybeJson(path.join(directory,'exec-isolation-proof.json')),...(backendFile?{backendRunner:maybeJson(path.join(directory,backendFile))}:{})});
}

export function validateExceptions(data) {
  const errors = [];
  if (!data || data.schema_version !== 1 || !Array.isArray(data.equivalents)) return { exceptions: [], errors: ['Invalid reviewed-equivalence ledger.'] };
  const seen = new Set();
  for (const item of data.equivalents) {
    if (!item || !['stryker', 'mutmut', 'cargo-mutants', 'python-static', 'ppi-perl'].includes(item.tool) || typeof item.id !== 'string' || !item.id ||
        typeof item.file !== 'string' || !isOwnedSource(item.file) || !/^[0-9a-f]{64}$/.test(item.source_sha256 ?? '') ||
        typeof item.author !== 'string' || !item.author.trim() || typeof item.reviewed_by !== 'string' || !item.reviewed_by.trim() || item.author === item.reviewed_by ||
        typeof item.reviewed_at !== 'string' || !Number.isFinite(Date.parse(item.reviewed_at)) || typeof item.proof !== 'string' || item.proof.trim().length < 40 || (!/^[a-f0-9]{64}$/.test(item.definition_sha256 ?? '') || typeof item.review?.path !== 'string' || !/^[a-f0-9]{64}$/.test(item.review?.sha256 ?? ''))) {
      errors.push(`Invalid or insufficiently reviewed equivalence record: ${item?.id ?? '<missing>'}`);
      continue;
    }
    const key = `${item.tool}\0${item.file}\0${item.definition_sha256}`;
    if (seen.has(key)) errors.push(`Duplicate equivalence record: ${item.id}`);
    seen.add(key);
  }
  return { exceptions: data.equivalents, errors };
}

function equivalent(exceptions, used, tool, id, file, hashes, definition, readReview) {
  return reviewedEquivalent({exceptions,used,tool,id,file,hashes,definition,readReview});
}
function reportDefinition(file,source,mutant){
  try {const location={start:{line:mutant.location.start.line-1,column:mutant.location.start.column-1},end:{line:mutant.location.end.line-1,column:mutant.location.end.column-1}};return mutationDefinition(file,source,{...mutant,location}).definition;}catch{return undefined;}
}

export function assessStrykerDiscovery(discovery,expectedFiles,hashes){
  const errors=[],zeroFiles=new Set(),definitions=new Map();
  if(discovery?.tool!=='stryker'||discovery.tool_version!=='10.1.1'||discovery.qualification!=='complete-operator-discovery-no-outcomes'||discovery.inventory_only!==true||!Array.isArray(discovery.source_scope)||!Array.isArray(discovery.materialization)||!Array.isArray(discovery.mutants)||!discovery.mutants.length||discovery.scheduled!==discovery.mutants.length)return{errors:['Complete actual Stryker source generation is missing.'],zeroFiles,definitions};
  const expected=new Set(expectedFiles),seen=new Set(),rawIds=new Set();
  for(const row of discovery.source_scope)if(!expected.has(row?.path)||seen.has(row.path)||hashes[row.path]!==row.source_sha256)errors.push('Stryker generation source scope is duplicate, stale or unexpected.');else seen.add(row.path);
  if(seen.size!==expected.size)errors.push('Stryker generation omitted an applicable source.');
  for(const item of discovery.mutants){
    const key=item?.file+'\0'+item?.definition_sha256;
    if(!seen.has(item?.file)||hashes[item.file]!==item.source_sha256||!item.definition||hash(canonicalJson(item.definition))!==item.definition_sha256||item.id!==item.file+'#'+item.definition_sha256||definitions.has(key)||typeof item.raw_id!=='string'||rawIds.has(item.raw_id))errors.push('Stryker generated definition is duplicate, stale or unbound.');
    else{definitions.set(key,item);rawIds.add(item.raw_id);}
  }
  const materialized=new Set();
  for(const row of discovery.materialization){
    const items=discovery.mutants.filter(item=>item.file===row?.path).map(({id,raw_id,source_sha256,definition_sha256})=>({id,raw_id,source_sha256,definition_sha256}));
    if(!seen.has(row?.path)||materialized.has(row.path)||hashes[row.path]!==row.source_sha256||row.generated!==items.length||row.inventory_sha256!==hash(canonicalJson(items)))errors.push('Stryker per-source materialization differs from complete generated definitions.');
    else{materialized.add(row.path);if(!items.length)zeroFiles.add(row.path);}
  }
  if(materialized.size!==expected.size)errors.push('Stryker per-source generation coverage is incomplete.');
  return{errors,zeroFiles,definitions};
}

export function assessStryker(report, expectedFiles, hashes, exceptions = [], used = new Set(), expectedTests = [], readReview = () => null, discovery = undefined, selectionProof = null, selectionSchedule = undefined) {
  const errors = [];
  let total = 0; let killed = 0; let equivalentCount = 0;
  if (!report || !report.files || typeof report.files !== 'object' || !report.testFiles || typeof report.testFiles !== 'object') {
    return { total, killed, equivalent: equivalentCount, errors: ['Stryker JSON report is missing or malformed.'] };
  }
  const config = report.config ?? {};
  const generated=discovery===undefined?null:assessStrykerDiscovery(discovery,expectedFiles,hashes);
  if(generated)errors.push(...generated.errors);
  const expectedPatterns = ['packages/**/*.{ts,tsx,mts,cts,js,mjs,cjs}', 'scripts/**/*.{ts,tsx,mts,cts,js,mjs,cjs}', ...(expectedFiles.some(file => file.startsWith('workers/')) ? ['workers/**/*.{ts,tsx,mts,cts,js,mjs,cjs}'] : []), ...(expectedFiles.some(file => file.startsWith('evals/')) ? ['evals/**/*.{ts,tsx,mts,cts,js,mjs,cjs}'] : [])];
  if (JSON.stringify(config.mutate) !== JSON.stringify(expectedPatterns) || config.incremental !== false || config.ignoreStatic !== false ||
      config.allowEmpty !== false || config.inPlace !== false || config.disableBail !== true || config.disableTypeChecks !== false || !['off', 'perTest'].includes(config.coverageAnalysis) ||
      config.thresholds?.break !== 100 || (Array.isArray(config.testFiles) && config.testFiles.length)) {
    errors.push('Stryker report does not prove the required full clean configuration.');
  }
  if (config.coverageAnalysis === 'perTest' && (!selectionProof || selectionProof.errors?.length !== 0 || !verifiedSelectionTests(selectionProof, selectionSchedule))) errors.push('Stryker per-test execution lacks independently verified pristine selection authority.');
  const testIds = Object.values(report.testFiles).flatMap(file => Array.isArray(file.tests) ? file.tests.map(test => String(test.id)) : []);
  const tests = new Set(testIds);
  if (tests.size === 0) errors.push('Stryker reported no tests.');
  if (tests.size !== testIds.length) errors.push('Stryker reported duplicate test identities.');
  for (const file of expectedTests) {
    const testFile = report.testFiles[file];
    if (!testFile || !Array.isArray(testFile.tests) || testFile.tests.length === 0 || typeof testFile.source !== 'string' || hash(Buffer.from(testFile.source, 'utf8')) !== hashes[file]) errors.push(`Stryker omitted or changed a required test file: ${file}`);
  }
  for (const file of expectedFiles) {
    const entry = report.files[file];
    if ((!entry||Array.isArray(entry.mutants)&&entry.mutants.length===0)&&generated?.errors.length===0&&generated.zeroFiles.has(file)) {
      if(entry&&(typeof entry.source!=='string'||hash(Buffer.from(entry.source,'utf8'))!==hashes[file]))errors.push(`Stryker source differs from frozen snapshot: ${file}`);
      continue;
    }
    if (!entry || !Array.isArray(entry.mutants) || entry.mutants.length === 0) { errors.push(`Stryker omitted or produced no mutants for ${file}`); continue; }
    if (typeof entry.source !== 'string' || hash(Buffer.from(entry.source, 'utf8')) !== hashes[file]) errors.push(`Stryker source differs from frozen snapshot: ${file}`);
    const ids = new Set();
    for (const mutant of entry.mutants) {
      total++;
      const id = `${file}#${mutant.id}`;
      if(generated){const definition=reportDefinition(file,entry.source,mutant),key=file+'\0'+hash(canonicalJson(definition??null));if(!generated.definitions.delete(key))errors.push(`Stryker report definition differs from complete independent generation: ${id}`);}
      if (mutant.id === undefined || ids.has(String(mutant.id))) { errors.push(`Stryker has missing/duplicate mutant identity: ${id}`); continue; }
      ids.add(String(mutant.id));
      if (mutant.status === 'Killed') {
        if (!Number.isInteger(mutant.testsCompleted) || mutant.testsCompleted < 1 || !Array.isArray(mutant.killedBy) || mutant.killedBy.length === 0 || mutant.killedBy.some(test => !tests.has(String(test)))) errors.push(`Stryker kill lacks identified test evidence: ${id}`);
        else killed++;
      } else if (mutant.status === 'Survived' && equivalent(exceptions, used, 'stryker', id, file, hashes, reportDefinition(file,entry.source,mutant), readReview)) equivalentCount++;
      else errors.push(`Stryker ${mutant.status ?? 'missing status'}: ${id}`);
    }
  }
  for (const file of Object.keys(report.files)) if (!expectedFiles.includes(file)) errors.push(`Unexpected Stryker report source: ${file}`);
  if(generated?.definitions.size)errors.push('Stryker report omitted independently generated definitions.');
  if (!total) errors.push('Stryker scheduled no mutants.');
  return { total, killed, equivalent: equivalentCount, errors };
}

/** Resolve authority through hash-bound shards of the canonical sealed inventory. */
export function canonicalMutmutGeneration(root, source, inventoryReceipt) {
  const actual = fileReceipt(root, 'quality/acceptance-inventory.json');
  if (!inventoryReceipt || actual.sha256 !== inventoryReceipt.sha256 || actual.size !== inventoryReceipt.size) throw new Error('Canonical mutation inventory differs from the sealed source.');
  const inventory = JSON.parse(readRecordedBytes(root, inventoryReceipt, 256 * 1024 ** 2).toString('utf8'));
  if (inventory.schema_version !== 1 || inventory.state !== 'frozen' || !Array.isArray(inventory.discovery?.schedules) || !inventory.discovery.schedules.length) throw new Error('Canonical mutation discovery is missing.');
  const authorities = new Map(), inspected = new Map(), shards = [];
  for (const receipt of inventory.discovery.schedules) {
    const shard = JSON.parse(readRecordedBytes(root, receipt, 16 * 1024 ** 2).toString('utf8'));
    if (shard.suite_id !== 'mutation-python') continue;
    const authorityReceipt = shard.backend_discovery;
    const identity = canonicalJson(authorityReceipt);
    if (!inspected.has(identity)) inspected.set(identity,JSON.parse(readRecordedBytes(root, authorityReceipt, 64 * 1024 ** 2).toString('utf8')).backend?.tool);
    if (inspected.get(identity) !== 'mutmut') continue;
    shards.push(receipt);
    authorities.set(identity, authorityReceipt);
  }
  if (authorities.size !== 1) throw new Error('Canonical Python suite lacks one complete mutmut authority.');
  const verified = verifyMutationBackendDiscovery(root, [...authorities.values()][0], source, acceptanceInputHash(source));
  if (verified.backend.tool !== 'mutmut' || verified.backend.version !== '3.8.1') throw new Error('Canonical Python generation backend differs.');
  canonicalPythonShards.set(verified,{root,shards,authority:[...authorities.values()][0]});
  return verified;
}

/** Expand only an explicitly reviewed survivor, from its sealed full-definition shard. */
export function canonicalMutmutDefinition(generation, id) {
  const binding=canonicalPythonShards.get(generation),verified=verifiedMutationMaterializations(generation);
  const known=verified.inventory.find(row=>row.id===id);
  if(!binding||!known)throw Error('Canonical Python definition authority is missing.');
  let definition;
  for(const receipt of binding.shards){
    const shard=JSON.parse(readRecordedBytes(binding.root,receipt,16*1024**2).toString('utf8'));
    if(canonicalJson(shard.backend_discovery)!==canonicalJson(binding.authority)||!Array.isArray(shard.mutants))throw Error('Canonical Python definition shard differs.');
    for(const row of shard.mutants)if(row.id===id){
      if(definition||!['id','file','source_sha256','definition_sha256'].every(field=>known[field]===row[field])||!row.definition||hash(canonicalJson(row.definition))!==known.definition_sha256)throw Error('Canonical Python full definition differs.');
      definition=row.definition;
    }
  }
  if(!definition)throw Error('Canonical Python full definition is absent.');
  return definition;
}

/** Replay the fixed Python producer's test/source binding, never its message. */
export function pythonAssertionOrigin(event, schedule, hashes, readSource) {
  try{
    const origin=event?.assertion_origin,contract='python-test-source-origin-v2';
    if(event?.assertion_contract!==contract||origin?.contract!==contract||origin.test_id!==event.nodeid||!Array.isArray(schedule?.tests))return false;
    const test=schedule.tests.find(test=>test.id===event.nodeid);
    if(!test||origin.test_source!==test.source||origin.test_source_sha256!==test.source_sha256)return false;
    for(const[field,shaField,lineField]of[['source','source_sha256','line'],['test_source','test_source_sha256','test_line']]){
      const name=origin[field];
      if(typeof name!=='string'||!name.startsWith('tests/')||!name.endsWith('.py')||/[\\\0:]/.test(name)||name.split('/').some(part=>!part||part==='.'||part==='..')||hashes[name]!==origin[shaField]||!Number.isInteger(origin[lineField])||origin[lineField]<1)return false;
      const raw=readSource(name);if(!Buffer.isBuffer(raw)&&typeof raw!=='string')return false;
      const bytes=Buffer.from(raw),lines=bytes.toString('utf8').split(/\r\n?|\n/);if(bytes.length>4*1024**2||hash(bytes)!==origin[shaField]||origin[lineField]>lines.length-(lines.at(-1)===''?1:0))return false;
    }
    return true;
  }catch{return false;}
}

export function assessMutmut(metaByFile, events, expectedFiles, hashes, exceptions = [], used = new Set(), schedule = undefined, readReview = () => null, generation = undefined) {
  const errors = [];
  let total = 0; let killed = 0; let equivalentCount = 0;
  const plainRecord = value => value !== null && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value));
  const zeroSources = new Set(), provenZeroSources = [];
  if (generation !== undefined) {
    try {
      const materialized = verifiedMutationMaterializations(generation);
      if (materialized.backend.tool !== 'mutmut' || materialized.backend.version !== '3.8.1' || materialized.source_materializations.some(item => hashes[item.source] !== item.source_sha256)) throw new Error('stale source or different backend');
      for (const item of materialized.source_materializations) if (item.mutant_ids.length === 0) zeroSources.add(item.source);
    } catch { errors.push('mutmut complete source-bound materialization authority is missing or stale.'); }
  }
  const eventMap = new Map();
  for (const event of events) {
    if (!event || typeof event.mutant !== 'string' || !['failure', 'error', 'skipped'].includes(event.event)) { errors.push('Malformed mutmut test-evidence event.'); continue; }
    const list = eventMap.get(event.mutant) ?? [];
    list.push(event);
    eventMap.set(event.mutant, list);
  }
  const seen = new Set();
  for (const file of expectedFiles) {
    const meta = metaByFile[file];
    if (!meta || !plainRecord(meta.exit_code_by_key)) {
      errors.push(`mutmut metadata missing for ${file}`); continue;
    }
    const entries = Object.entries(meta.exit_code_by_key);
    if (entries.length === 0) {
      if (zeroSources.has(file) && Array.isArray(schedule?.inventory) && !schedule.inventory.some(item => item.file === file) && (meta.type_check_error_by_key === undefined || plainRecord(meta.type_check_error_by_key) && Object.keys(meta.type_check_error_by_key).length === 0)) provenZeroSources.push(file);
      else errors.push(`mutmut generated no mutants for ${file} without independent zero-operator evidence`);
      continue;
    }
    if (zeroSources.has(file)) errors.push(`mutmut outcomes contradict zero-operator generation for ${file}`);
    for (const [id, code] of entries) {
      total++;
      if (seen.has(id)) { errors.push(`Duplicate mutmut identity: ${id}`); continue; }
      seen.add(id);
      const recorded = eventMap.get(id) ?? [];
      if (code === 1) {
        if (recorded.some(event => event.event === 'failure') && recorded.every(event => event.event === 'failure'&&event.phase==='call'&&typeof event.exception_type==='string'&&event.exception_type.length>0&&pythonAssertionOrigin(event,schedule,hashes,readReview))) killed++;
        else errors.push(`mutmut kill lacks clean assertion-failure evidence: ${id}`);
      } else if (code === 0) {
        const scheduled=schedule?.inventory?.find(item=>item.id===id);
        let definition=scheduled?.definition;
        if(!definition&&schedule?.definition_representation==='mutmut-control-spans-v1'&&exceptions.some(item=>item.tool==='mutmut'&&item.file===file&&item.definition_sha256===scheduled?.definition_sha256)){
          try{definition=canonicalMutmutDefinition(generation,id);}catch(cause){errors.push(`mutmut equivalent definition replay failed: ${id}: ${cause.message}`);}
        }
        if(equivalent(exceptions,used,'mutmut',id,file,hashes,definition,readReview))equivalentCount++;
        else errors.push(`mutmut unresolved exit ${String(code)}: ${id}`);
      } else errors.push(`mutmut unresolved exit ${String(code)}: ${id}`);
      if (meta.type_check_error_by_key?.[id]) errors.push(`mutmut recorded a type/compile error: ${id}`);
    }
  }
  for (const id of eventMap.keys()) if (!seen.has(id)) errors.push(`Unexpected mutmut test evidence: ${id}`);
  if (!total) errors.push('mutmut scheduled no mutants.');
  return { total, killed, equivalent: equivalentCount, errors, ...(generation === undefined ? {} : { proven_zero_sources: provenZeroSources }) };
}

/** Stable libtest emits panic blocks; classify each before accepting a kill. */
export function rustAssertionEvidence(log, contracts = []) { return reviewedRustAssertions(log, contracts); }

export function assessCargo(mutants, report, readLog, expectedFiles, hashes, exceptions = [], used = new Set(), readReview = () => null, context = {}) {
  const errors = [];
  let total = 0; let killed = 0; let equivalentCount = 0; let pendingNative = 0;
  if (!Array.isArray(mutants) || !mutants.length || mutants.some(item => !item || typeof item !== 'object' || typeof item.name !== 'string' || !item.name || typeof item.file !== 'string') || !Array.isArray(expectedFiles) || !expectedFiles.length || expectedFiles.some(file => typeof file !== 'string') || !hashes || typeof hashes !== 'object' || !report || !Array.isArray(report.outcomes) || report.outcomes.some(item => !item || typeof item !== 'object') || !report.end_time) {
    return { total, killed, equivalent: equivalentCount, errors: ['cargo-mutants report is missing, empty, or incomplete.'] };
  }
  const manifestFor = file => typeof file !== 'string' ? null : file.startsWith('packages/launcher/') ? 'Cargo.toml' : file.startsWith('scripts/quality/rust-assertion-parser/') ? 'scripts/quality/rust-assertion-parser/Cargo.toml' : null;
  const requiredWorkspaces = [...new Set(expectedFiles.map(manifestFor))].sort();
  if (!requiredWorkspaces.length || requiredWorkspaces.includes(null)) errors.push('Rust workspace source contract is missing or invalid.');
  let applicability = null;
  if (context.verifyApplicability !== undefined) {
    try {
      if (typeof context.verifyApplicability !== 'function') throw new Error('missing independent verifier');
      applicability = context.verifyApplicability();
      if (applicability?.current_target !== 'aarch64-unknown-linux-gnu' || !Array.isArray(applicability?.proof?.inventory) || applicability.proof.inventory.length !== mutants.length || !/^[a-f0-9]{64}$/.test(applicability.proof_sha256) || !/^[a-f0-9]{64}$/.test(applicability.generation_sha256)) throw new Error('missing complete current-target proof');
      for (const [index, row] of applicability.proof.inventory.entries()) {
        const mutant = mutants[index], definition = { tool: 'cargo-mutants', version: '27.1.0', ...mutant };
        if (row.id !== mutant.name || row.file !== mutant.file || row.source_sha256 !== hashes[mutant.file] || row.definition_sha256 !== hash(canonicalJson(definition)) || !Array.isArray(row.applicable_targets) || !row.applicable_targets.length) throw new Error('source/definition inventory differs');
      }
    } catch (error) { applicability = null; errors.push(`Rust target applicability lacks independently replayed authority: ${error.message}`); }
  }
  const requiredTests = new Map(), testIds = new Set();
  let testInventoryValid = Array.isArray(context.tests) && context.tests.length > 0;
  for (const test of Array.isArray(context.tests) ? context.tests : []) {
    if (!test || test.runner !== 'rust' || test.occurrence !== 0 || typeof test.name !== 'string' || !test.name || typeof test.source !== 'string' || !requiredWorkspaces.includes(manifestFor(test.source)) || test.source_sha256 !== hashes[test.source] || test.id !== `rust:${test.source}#${hash(canonicalJson([test.name, 0])).slice(0, 24)}` || testIds.has(test.id)) { testInventoryValid = false; continue; }
    testIds.add(test.id);
    const names = requiredTests.get(test.source) ?? []; names.push(test.name); requiredTests.set(test.source, names);
  }
  if (!testInventoryValid) errors.push('Rust independently discovered test inventory is missing or invalid.');
  const phaseEvidence = (outcome, item, manifests, caught) => {
    if (!testInventoryValid || typeof context.root !== 'string' || typeof context.parseSource !== 'function' || !Array.isArray(outcome.phase_results) || outcome.phase_results.length !== manifests.length * 2 || outcome.phase_results.some(phase => !phase || typeof phase !== 'object' || Array.isArray(phase))) return false;
    const tests = [], seen = new Set();
    for (const manifest of manifests) {
      const phases = outcome.phase_results.filter(phase => phase.workspace_manifest === manifest);
      const builds = phases.filter(phase => phase.phase === 'Build'), runs = phases.filter(phase => phase.phase === 'Test');
      if (phases.length !== 2 || builds.length !== 1 || runs.length !== 1 || builds[0].process_status !== 'Success') return false;
      const phase = runs[0];
      if (caught ? canonicalJson(phase.process_status) !== canonicalJson({ Failure: 101 }) : phase.process_status !== 'Success') return false;
      if (!Array.isArray(phase.expected_artifacts) || phase.expected_artifacts.some(artifact => !artifact || typeof artifact !== 'object' || manifestFor(artifact.artifact_id) !== manifest)) return false;
      const discoveredArtifacts = [...requiredTests.keys()].filter(source => manifestFor(source) === manifest);
      if (discoveredArtifacts.some(source => !phase.expected_artifacts.some(artifact => artifact.artifact_id === source)) || phase.expected_artifacts.some(artifact => !Array.isArray(artifact.expected_tests) || canonicalJson([...artifact.expected_tests].sort()) !== canonicalJson([...(requiredTests.get(artifact.artifact_id) ?? [])].sort()))) return false;
      let evidence;
      try { evidence = rustPhaseEvidence(context.root, item, phase, { parseSource: context.parseSource }); } catch { return false; }
      if (evidence.artifacts_complete !== true || evidence.valid !== caught || (!caught && evidence.failures.length !== 0)) return false;
      tests.push(phase); seen.add(manifest);
    }
    if (seen.size !== manifests.length) return false;
    // Bind the public log to the individually supervised invocations. A clean
    // assertion in one executable must never mask another executable's crash.
    try {
      const ordered = outcome.phase_results.filter(phase => phase.phase === 'Test');
      return ordered.length === tests.length && readLog(outcome.log_path) === ordered.flatMap(phase => phase.invocations.map(invocation => invocation.log)).join('');
    } catch { return false; }
  };
  const baseline = report.outcomes.filter(outcome => outcome.scenario === 'Baseline');
  const baselineValid = baseline.length === 1 && baseline[0].summary === 'Success' && phaseEvidence(baseline[0], null, requiredWorkspaces, false);
  if (!baselineValid) errors.push('cargo-mutants baseline lacks complete source-bound workspace and artifact evidence.');
  const outcomes = report.outcomes.filter(outcome => outcome.scenario?.Mutant);
  if (report.total_mutants !== mutants.length || outcomes.length !== mutants.length || report.outcomes.length !== mutants.length + 1) errors.push('cargo-mutants scheduled and recorded counts do not match.');
  const seen = new Set();
  const scheduled = new Map(mutants.map(mutant => [mutant.name, mutant]));
  if (scheduled.size !== mutants.length) errors.push('cargo-mutants contains duplicate scheduled identities.');
  for (const file of expectedFiles) if (!mutants.some(mutant => mutant.file === file)) errors.push(`cargo-mutants generated no mutants for ${file}`);
  for (const outcome of outcomes) {
    total++;
    const mutant = outcome.scenario.Mutant;
    const id = mutant.name;
    if (!scheduled.has(id) || seen.has(id) || !expectedFiles.includes(mutant.file)) { errors.push(`Unknown or duplicate Rust mutant: ${id}`); continue; }
    if (canonicalJson(mutant) !== canonicalJson(scheduled.get(id))) { errors.push(`Rust outcome definition differs from its schedule: ${id}`); continue; }
    seen.add(id);
    const definition = { tool: 'cargo-mutants', version: '27.1.0', ...scheduled.get(id) };
    const item = { file: mutant.file, source_sha256: hashes[mutant.file], definition, definition_sha256: hash(canonicalJson(definition)) };
    const manifest = manifestFor(mutant.file);
    if (mutant.workspace_manifest !== manifest) { errors.push(`Rust scheduled workspace differs from its source: ${id}`); continue; }
    const targetRow = applicability?.proof.inventory.find(row => row.id === id);
    if (targetRow && !targetRow.applicable_targets.includes(applicability.current_target)) {
      if (outcome.summary !== 'PendingNativeTarget' || !baselineValid || !Array.isArray(outcome.phase_results) || outcome.phase_results.length || outcome.applicability?.proof_sha256 !== applicability.proof_sha256 || outcome.applicability?.generation_sha256 !== applicability.generation_sha256 || canonicalJson(outcome.applicability?.row) !== canonicalJson(targetRow) || outcome.source_sha256 !== item.source_sha256 || outcome.definition_sha256 !== item.definition_sha256) errors.push(`Rust foreign-target row lacks exact pending-native evidence: ${id}`);
      else pendingNative++;
      continue;
    }
    if (outcome.summary === 'CaughtMutant') {
      if (!phaseEvidence(outcome, item, [manifest], true)) errors.push(`Rust kill lacks clean source-bound test-failure evidence: ${id}`);
      else killed++;
    } else if (outcome.summary === 'MissedMutant' && baselineValid && phaseEvidence(outcome, item, [manifest], false) && equivalent(exceptions, used, 'cargo-mutants', id, mutant.file, hashes, definition, readReview)) equivalentCount++;
    else errors.push(`Rust ${outcome.summary ?? 'missing status'}: ${id}`);
  }
  for (const id of scheduled.keys()) if (!seen.has(id)) errors.push(`Rust mutant has no outcome: ${id}`);
  const applicableCurrent = applicability ? applicability.proof.inventory.filter(row => row.applicable_targets.includes(applicability.current_target)).length : mutants.length;
  if (killed + equivalentCount !== applicableCurrent && !errors.length) errors.push('Rust current-target mutation detection is incomplete.');
  return { total, killed, equivalent: equivalentCount, total_scheduled: mutants.length, applicable_current: applicableCurrent, killed_current: killed, equivalent_current: equivalentCount, pending_native: pendingNative, qualification: errors.length ? 'failed' : pendingNative ? 'pending-native' : 'passed-locally', applicability_verified: applicability !== null, errors };
}

export function assessStatic(report, hashes, exceptions = [], used = new Set(), readReview = () => null, schedule = undefined) {
  const errors = [];
  let total = 0; let killed = 0; let equivalentCount = 0;
  if (!report || report.tool !== 'python-static' || report.complete !== true || !Array.isArray(report.outcomes) || report.scheduled !== report.outcomes.length) {
    return { total, killed, equivalent: equivalentCount, errors: ['Python module-scope mutation report is missing or incomplete.'] };
  }
  if (!schedule?.inventory_only || !Array.isArray(schedule.inventory) || !schedule.inventory.length || canonicalJson(report.inventory) !== canonicalJson(schedule.inventory) || schedule.scheduled !== report.scheduled) errors.push('Python module-scope independent scheduling is missing or changed.');
  const definitions=new Map((schedule?.inventory??[]).map(item=>[item.id,item]));
  if(definitions.size!==(schedule?.inventory??[]).length) errors.push('Duplicate Python module-scope scheduled definitions.');
  const seen = new Set();
  for (const item of report.outcomes) {
    total++;
    const expected=definitions.get(item.id);
    if(!expected || canonicalJson(item.definition)!==canonicalJson(expected.definition) || hash(canonicalJson(item.definition))!==item.definition_sha256 || item.definition_sha256!==expected.definition_sha256) errors.push(`Python module-scope exact definition differs: ${item.id}`);
    if (seen.has(item.id) || hashes[item.file] !== item.source_sha256) { errors.push(`Static mutation identity or source mismatch: ${item.id}`); continue; }
    seen.add(item.id);
    if (item.status === 'Killed' && Number.isInteger(item.tests) && item.tests > 0 && Number.isInteger(item.failures) && item.failures > 0) killed++;
    else if (item.status === 'Survived' && equivalent(exceptions, used, 'python-static', item.id, item.file, hashes, item.definition, readReview)) equivalentCount++;
    else errors.push(`Python module-scope ${item.status ?? 'missing status'}: ${item.id}`);
  }
  if (!total) errors.push('Python module-scope mutation inventory is empty.');
  return { total, killed, equivalent: equivalentCount, errors };
}

function readJson(filename) { return JSON.parse(readFileSync(filename, 'utf8')); }
function maybeJson(filename) { try { return readJson(filename); } catch { return null; } }
function toolPath(root, directory, name) {
  const suffix = process.platform === 'win32' ? '.exe' : '';
  return path.join(root, directory, `${name}${suffix}`);
}
function lineEvents(filename) {
  if (!existsSync(filename)) return [];
  return readFileSync(filename, 'utf8').split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
}
function metadataFor(root, files) {
  const result = {};
  for (const file of files) {
    const mapped = file.startsWith('workers/ud/src/ud_agent/')
      ? `src/ud_agent/${file.slice('workers/ud/src/ud_agent/'.length)}`
      : file;
    const meta = path.join(root, 'mutants', `${mapped}.meta`);
    if (existsSync(meta)) result[file] = maybeJson(meta);
    else result[file] = undefined;
  }
  return result;
}
function hasName(name, regex) { return regex.test(name); }
function expectedSources(files, regex) {
  return Object.keys(files).filter(name => isOwnedSource(name) && hasName(name, regex) && !name.includes('/tests/')).sort();
}
function expectedVitest(files) {
  return Object.keys(files).filter(name => /^tests\//.test(name) && /\.(?:test|spec)\.(?:ts|tsx|mts|cts|js|mjs|cjs)$/.test(name)).sort();
}
function fileCopyAllowed(root, source) {
  const rel = relative(root, source);
  if (!rel) return true;
  if (!SOURCE_ROOTS.includes(rel.split('/')[0])) return false;
  if (rel.split('/').some(part => IGNORE.has(part) || /^\.env(?:\.|$)/.test(part) || part.endsWith('.pyc') || part === '.DS_Store')) return false;
  return !lstatSync(source).isSymbolicLink();
}

/** @param {AbortSignal} [signal] */
export async function runMutationCommand(label, executable, args, cwd, env, logFile, timeoutMs = 3_600_000, _checkStorage = () => {}, signal) {
  signal?.throwIfAborted();
  console.log(`mutation: ${label}`);
  const chunks = [];
  let captured = 0;
  const child = spawn(executable, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32', windowsHide: true });
  let failed;
  let timeout = false;
  let cancelled = false, stopping = false, closed = false, stopTimer;
  const stop = () => {
    // A detached group may outlive its leader while retaining output pipes.
    // Continue to stop that owned group until the close event, not merely exit.
    if (stopping || closed) return;
    stopping = true;
    const kill = selected => { try { if (process.platform === 'win32') child.kill(selected); else process.kill(-child.pid, selected); } catch (error) { if (error.code !== 'ESRCH') failed ??= error.message; } };
    // Give the owned OCI driver time to stop its worker and remove its named
    // volumes before escalating an unresponsive subprocess group.
    kill('SIGTERM'); stopTimer = setTimeout(() => kill('SIGKILL'), 10_000); stopTimer.unref();
  };
  const cancel = () => { cancelled = true; failed = 'Mutation quality command was cancelled.'; stop(); };
  signal?.addEventListener('abort', cancel, { once: true });
  const out = [];
  const record = chunk => {
    const data = Buffer.from(chunk);
    if (captured < 16 * 1024 * 1024) { chunks.push(data.subarray(0, 16 * 1024 * 1024 - captured)); captured += data.length; }
    out.push(data.toString('utf8'));
    if (out.length > 100) out.shift();
  };
  child.stdout.on('data', record);
  child.stderr.on('data', record);
  child.on('error', error => { failed = error.message; });
  const timer = setTimeout(() => {
    timeout = true;
    stop();
  }, timeoutMs);
  const code = await new Promise(resolve => child.once('close', (status, signal) => { closed = true; resolve({ status, signal }); }));
  clearTimeout(timer); clearTimeout(stopTimer); signal?.removeEventListener('abort', cancel);
  const capturedText = Buffer.concat(chunks).toString('utf8');
  writeFileSync(logFile, capturedText);
  const result = { ...code, timeout, ...(cancelled ? { cancelled: true } : {}), ...(failed ? { error: failed } : {}), tail: out.join('').slice(-8000), log: logFile };
  console.log(`mutation: ${label}: ${timeout ? 'timeout' : failed ?? `exit ${code.status}`}`);
  return result;
}

function requireTool(result, expected, tool, errors) {
  if (result.error || result.signal || result.timeout || result.status !== 0 || !result.tail.includes(expected)) errors.push(`${tool} version check failed or does not match ${expected}.`);
}
export function reviewedAssertionObligations(sourceRoot,sourceHashes){
  const classifier='scripts/quality/assertion-obligations.mjs',metadata='quality/assertion-obligations.json',reviewPath='quality/reviews/assertion-obligations-root-review.json';
  const read=name=>{const receipt=fileReceipt(sourceRoot,name);if(receipt.sha256!==sourceHashes[name])throw new Error('Assertion obligation authority differs from frozen source: '+name);return readRecordedBytes(sourceRoot,receipt,4*1024**2);};
  const classifierBytes=read(classifier),bytes=read(metadata),reviewBytes=read(reviewPath),obligations=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),review=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(reviewBytes));
  verifyAssertionObligationReview(review,{classifierSha256:hash(classifierBytes),obligationsSha256:hash(bytes),obligations});return obligations;
}

export function appendAssessment(summary, label, assessment) {
  const applicability = label === 'cargo-mutants'
    ? Object.fromEntries(['total_scheduled', 'applicable_current', 'killed_current', 'equivalent_current', 'pending_native', 'qualification', 'applicability_verified'].map(name => [name, assessment[name]]))
    : {};
  summary.backends[label] = { total: assessment.total, killed: assessment.killed, equivalent: assessment.equivalent, errors: assessment.errors, ...applicability,...(assessment.reported_killed!==undefined?{reported_killed:assessment.reported_killed}:{}),...(assessment.assertion_obligations?{independent_behavior_killed:assessment.independent_behavior_killed,behavior_pending:assessment.behavior_pending,assertion_obligations:assessment.assertion_obligations}:{}) };
  if (assessment.proven_zero_sources !== undefined) summary.backends[label].proven_zero_sources = assessment.proven_zero_sources;
  summary.errors.push(...assessment.errors);
}

/** Native gaps are a separate incomplete certification state, never a pass or
 * a substitute for complete locally applicable outcomes. */
export function finalizeMutationSummary(summary) {
  if (!Array.isArray(summary.errors)) throw new Error('Mutation summary has no complete error inventory.');
  if (summary.profile === 'bounded') {
    const corpus = summary.backends?.bounded;
    const languages = corpus?.per_language && Object.entries(corpus.per_language);
    const complete = languages && languages.every(([name, row]) => ['typescript', 'python', 'rust', 'perl', 'data'].includes(name) && Number.isSafeInteger(row.scheduled) && row.scheduled > 0 && row.scheduled === row.killed)
      && languages.reduce((sum, [, row]) => sum + row.scheduled, 0) === 18;
    if (summary.exhaustive !== false || summary.qualification !== 'bounded-reviewed-corpus' || !corpus || corpus.total !== 18 || corpus.killed !== 18 || !Array.isArray(corpus.errors) || corpus.errors.length || !complete || ['typescript', 'python', 'rust', 'perl'].some(language => !corpus.per_language[language])) summary.errors.push('Bounded all-language corpus is incomplete or does not have 100% detection.');
  }
  const rust = summary.backends?.['cargo-mutants'];
  if (rust) {
    const fields = ['total_scheduled','applicable_current','killed_current','equivalent_current','pending_native'];
    const valid = fields.every(name => Number.isSafeInteger(rust[name]) && rust[name] >= 0) && rust.total_scheduled > 0
      && rust.total_scheduled === rust.applicable_current + rust.pending_native
      && rust.applicable_current === rust.killed_current + rust.equivalent_current
      && rust.total === rust.total_scheduled && rust.killed === rust.killed_current && rust.equivalent === rust.equivalent_current
      && Array.isArray(rust.errors) && rust.errors.length === 0
      && rust.qualification === (rust.pending_native ? 'pending-native' : 'passed-locally')
      && (!rust.pending_native || rust.applicability_verified === true);
    summary.rust_mutation = { ...Object.fromEntries(fields.map(name => [name, rust[name] ?? null])), qualification: valid ? rust.qualification : 'failed', errors: Array.isArray(rust.errors) ? rust.errors.length : null };
    if (!valid) summary.errors.push('Rust aggregate current-target detection or verified native-pending union is incomplete.');
  }
  summary.status = summary.errors.length ? 'failed' : rust?.pending_native ? 'pending-native' : 'passed';
  if (summary.status === 'pending-native') summary.qualification = 'pending-native';
  return summary;
}
/** Parse paths without reading candidate bytes or starting discovery. */
export function mutationGateOptions(args) {
  const options = {}, keys = { '--profile': 'profile', '--runner': 'runner', '--image': 'image', '--backend': 'backend', '--session': 'sessionDirectory', '--candidate': 'candidatePath', '--candidate-root': 'candidateRoot' };
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--preflight' && !options.preflightOnly) { options.preflightOnly = true; continue; }
    const key = keys[args[index]], value = args[++index];
    if (!key || !value || value.startsWith('--') || options[key] !== undefined) throw new Error('Invalid or duplicate mutation gate option.');
    options[key] = value;
  }
  validateGateMode({ ...options, candidate: options.candidatePath });
  return options;
}

function validateGateMode({ profile = 'exhaustive', image, preflightOnly, backend, sessionDirectory, candidate, candidateRoot, runner }) {
  if (!['bounded', 'exhaustive'].includes(profile)) throw new Error('Unknown mutation profile.');
  if (runner !== undefined && !['protected', 'portable'].includes(runner)) throw new Error('Unknown mutation runner.');
  if (runner === 'portable' && (profile !== 'bounded' || image !== undefined || sessionDirectory !== undefined || candidate !== undefined)) throw new Error('The portable runner executes only the bounded corpus without protected images, sessions or candidates.');
  if (image !== undefined && !/^sha256:[a-f0-9]{64}$/.test(image)) throw new Error('An explicit mutation image must be an immutable local image identity.');
  if (profile === 'bounded' && (preflightOnly || backend !== undefined)) throw new Error('The bounded profile runs its complete reviewed corpus.');
  if (backend !== undefined && !['typescript', 'python', 'rust', 'perl', 'faults'].includes(backend)) throw new Error('Unknown diagnostic mutation backend.');
  if (preflightOnly && (backend !== undefined || sessionDirectory !== undefined) || backend !== undefined && sessionDirectory !== undefined) throw new Error('Frozen sessions require the complete gate.');
  if (candidateRoot !== undefined && candidate === undefined) throw new Error('A mutation candidate root requires a candidate manifest.');
  if (candidate !== undefined && (preflightOnly || backend !== undefined || sessionDirectory === undefined)) throw new Error('Candidate-bound mutations require an explicitly sealed complete session.');
}

/** Retain original diagnostics outside the disposable execution source, with
 * exact candidate bindings when supplied. */
export function prepareMutationBaseline(root, snapshot, runDir, { python, cargo, candidate, candidateRoot } = {}) {
  if (candidate === undefined) {
    if (candidateRoot !== undefined) throw new Error('A mutation candidate root requires a candidate manifest.');
    const reportDirectory = path.join(runDir, 'original-baseline');
    const original = [path.join(snapshot, 'scripts/quality/original-acceptance.mjs'), '--output', reportDirectory, '--python', python, '--cargo', cargo];
    // Preserve the default test command's current-user token on Windows.
    const program = process.platform === 'win32' ? python : process.execPath;
    const args = process.platform === 'win32' ? ['-I', '-B', path.join(snapshot, 'scripts/quality/windows-original-token.py'), '--cwd', snapshot, '--', process.execPath, ...original] : original;
    return { label: 'full baseline tests', program, args, reportDirectory };
  }
  const binding = bindOriginalCandidate(root, { candidate, candidateRoot });
  if (sourceReceipt(snapshot).sha256 !== binding.subjects.source_tree_sha256) throw new Error('Original baseline snapshot differs from the bound candidate source.');
  candidateRoot = realpathSync(candidateRoot ?? root);
  const manifest = path.join(runDir, 'candidate-manifest.json'), reportDirectory = path.join(runDir, 'original-baseline');
  writeFileSync(manifest, JSON.stringify(candidate, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { label: 'candidate-bound original baseline', args: [path.join(snapshot, 'scripts/quality/original-acceptance.mjs'), '--output', reportDirectory, '--python', python, '--cargo', cargo, '--candidate', manifest, '--candidate-root', candidateRoot], candidate, candidateRoot, binding, reportDirectory };
}

export function recheckMutationCandidate(root, baseline) {
  if (!baseline.binding) return;
  if (canonicalJson(bindOriginalCandidate(root, { candidate: baseline.candidate, candidateRoot: baseline.candidateRoot })) !== canonicalJson(baseline.binding)) throw new Error('Mutation candidate binding changed during execution.');
}

export function verifyMutationOriginalBaseline(root, baseline) {
  recheckMutationCandidate(root, baseline);
  const receipt = fileReceipt(baseline.reportDirectory, 'report.json');
  const report = JSON.parse(readRecordedBytes(baseline.reportDirectory, receipt, 64 * 1024 ** 2).toString('utf8'));
  if (report.kind !== 'original-test-acceptance' || report.status !== 'passed-locally' || report.suite_id !== 'unit' || report.source_tree_sha256 !== baseline.binding.subjects.source_tree_sha256 || report.source_unchanged !== true || !Number.isSafeInteger(report.executed) || report.executed < 1 || report.executed !== report.scheduled || report.skipped !== 0 || !Array.isArray(report.tests) || report.tests.length !== report.executed || report.tests.some(test => test.status !== 'passed') || new Set(report.tests.map(test => test.id)).size !== report.executed || canonicalJson(report.candidate_binding) !== canonicalJson(baseline.binding)) throw new Error('Candidate original baseline lacks complete source-bound passing evidence.');
  const evidence = JSON.parse(readRecordedBytes(baseline.reportDirectory, report.unsigned_evidence, 64 * 1024 ** 2).toString('utf8'));
  if (evidence.verdict !== 'passed' || evidence.suite_id !== 'unit' || evidence.executed !== report.executed || evidence.skipped !== 0 || evidence.errors !== 0 || canonicalJson(evidence.tests) !== canonicalJson(report.tests) || canonicalJson(evidence.candidate_binding) !== canonicalJson(baseline.binding) || Object.entries(baseline.binding.subjects).some(([key, value]) => canonicalJson(evidence[key]) !== canonicalJson(value))) throw new Error('Candidate original baseline subjects or retained evidence differ.');
  return receipt;
}

/** @param {string} root @param {{profile?:string,image?:string,preflightOnly?:boolean,backend?:string,sessionDirectory?:string,candidate?:any,candidateRoot?:string}} options */
export async function runMutationGate(root = ROOT, { profile = 'exhaustive', image, preflightOnly = false, backend, sessionDirectory, candidate, candidateRoot, runner } = {}) {
  validateGateMode({ profile, image, preflightOnly, backend, sessionDirectory, candidate, candidateRoot, runner });
  // The protected OCI SDK is native Linux arm64. Elsewhere the bounded corpus
  // runs through the portable host runner with the same definitions and kill
  // criteria; `--runner protected|portable` selects explicitly.
  const portable = (runner ?? (profile === 'bounded' && image === undefined && sessionDirectory === undefined && candidate === undefined && !(process.platform === 'linux' && process.arch === 'arm64') ? 'portable' : 'protected')) === 'portable';
  if (backend !== undefined && !['typescript', 'python', 'rust', 'perl', 'faults'].includes(backend)) throw new Error('Unknown diagnostic mutation backend.');
  const selected = new Set(profile === 'bounded' ? ['faults'] : backend ? [backend] : ['typescript', 'python', 'rust', 'perl', 'faults']);
  root = path.resolve(root);
  let ownerRoot=root;
  for(let current=root;path.dirname(current)!==current;current=path.dirname(current))if(path.basename(current)==='.artifacts')ownerRoot=path.dirname(current);
  const sessionRows = sessionDirectory === undefined ? undefined : readJson(path.join(sessionDirectory, 'sealed-session.json')).rows;
  if (sessionRows !== undefined && (!Array.isArray(sessionRows) || !sessionRows.length || new Set(sessionRows.map(row => row.image_id)).size !== 1)) throw new Error('Frozen session mutation image identity is incomplete.');
  const selectedImage = image ?? sessionRows?.[0]?.image_id ?? 'localhost/ud-agent-mutation-runtime:arm64-final3';
  const imageFootprint = preflightOnly || portable ? { size_bytes: 0 } : mutationImageFootprint(selectedImage, process.env, spawnSync, lockedDockerImages(readJson(path.join(root, 'runtime/runtime.lock.json'))));
  const cancellation = new AbortController();
  let activeCommand, recordCancellation = () => {};
  // Protected runs reserve space for the native snapshot and one serial OCI
  // worker. The worker also charges the Docker state against this reservation.
  const scratchPlan = !portable && !preflightOnly
    ? { profile: 'release', plannedBytes: PROTECTED_MUTATION_SCRATCH_BYTES, transientAllowance: PROTECTED_MUTATION_SCRATCH_BYTES }
    : { plannedBytes: STORAGE_LIMITS.ordinaryBytes };
  const storage=reserveStorage({root:ownerRoot,...scratchPlan,plannedOutputBytes:128*1024**2,externalOwnedBytes:imageFootprint.size_bytes,inputRoots:[root],scratchParent:process.platform==='darwin'?'/private/tmp':os.tmpdir(),label:'mutation-acceptance',onCancel:async()=>{
    cancellation.abort(new Error('Mutation acceptance was cancelled.'));
    try { if(activeCommand) await activeCommand; } finally { recordCancellation(); }
  }});
  const runDir = path.join(root, '.artifacts', 'mutation', 'runs', randomUUID());
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  const scratch = storage.directory;
  const execute = (label, executable, args, cwd, env, logFile, timeout = 3_600_000) => {
    activeCommand=runMutationCommand(label, executable, args, cwd, env, logFile, timeout, undefined, cancellation.signal);
    return activeCommand.finally(()=>{activeCommand=undefined;});
  };
  let snapshot = path.join(scratch, 'not-yet-captured');
  const output = path.join(runDir, 'summary.json');
  const summary = { schema_version: 1, profile, runner: portable ? { kind: 'portable-host', isolation: 'host-process', platform: process.platform, arch: process.arch } : { kind: 'protected-oci' }, ...(profile === 'bounded' ? { policy: 'bounded-reviewed-v1' } : {}), exhaustive: profile === 'exhaustive' && backend === undefined, started_at: new Date().toISOString(), status: 'failed', snapshot_sha256: null, scope_complete: profile === 'exhaustive' && backend === undefined, qualification: profile === 'bounded' ? 'bounded-reviewed-corpus' : backend ? 'diagnostic-backend-only' : 'full-gate', backends: {}, errors: backend ? ['A diagnostic backend subset does not satisfy the complete mutation gate.'] : [] };
  function save() { writeFileSync(output, JSON.stringify(summary, null, 2) + '\n'); }
  recordCancellation=()=>{summary.status='failed';summary.errors.push('Mutation acceptance was cancelled after stopping its active command.');summary.finished_at=new Date().toISOString();save();};
  const used = new Set();
  let releaseSession, originalBaseline;
  try {
    let session;
    if (!preflightOnly && backend === undefined && !portable) {
      if (sessionDirectory === undefined) {
        sessionDirectory = path.join(root, '.artifacts/mutation/sessions', randomUUID());
        await (profile === 'bounded' ? discoverBoundedMutationSession : discoverMutationSession)(root, sessionDirectory, {
          environment: { ...process.env, ...storage.env },
          python: resolveOriginalExecutable(process.env.UD_MUTATION_PYTHON ?? path.join(root, process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python')),
          cargo: resolveOriginalExecutable(process.platform === 'win32' ? 'cargo.exe' : 'cargo'),
          ...(image === undefined ? {} : { image }),
        });
        (profile === 'bounded' ? sealBoundedMutationSession : sealMutationSession)(root, sessionDirectory, { install: true });
      }
      session = await (profile === 'bounded' ? openBoundedMutationSession : openMutationSession)(root, sessionDirectory);
      if (image !== undefined && session.authority.rows.some(row => row.image_id !== image)) throw new Error('Explicit mutation image differs from the sealed session.');
      summary.frozen_session = { directory: session.directory, authority_sha256: session.authority_sha256 };
    } else if (sessionDirectory !== undefined) throw new Error('Frozen sessions require the complete gate.');
    const executions = new Map();
    async function protectedRun(selectedBackend, fallback, log) {
      const selected = session ? await session.backend(selectedBackend) : { output: fallback, reused: false };
      executions.set(selectedBackend, selected);
      if (selected.reused) {
        const runner = maybeJson(path.join(selected.output, 'runner.json'));
        return { output: selected.output, result: { status: runner?.execution?.status, signal: runner?.execution?.signal, error: runner?.execution?.error, timeout: false }, reused: true };
      }
      const result = await execute('kernel-confined ' + selectedBackend + ' full mutation', process.execPath,
        [path.join(snapshot, 'scripts/quality/oci-python-diagnostic.mjs'), selected.output, '--source-root', snapshot, '--backend', selectedBackend,
          ...(session ? ['--image', selected.image, '--frozen-plan', selected.frozen] : image === undefined ? [] : ['--image', image])], snapshot, env, log, 12 * 60 * 60 * 1000 + 180000);
      return { output: selected.output, result, reused: false };
    }
    async function portableFaults() {
      const output = path.join(runDir, 'fault-portable');
      const result = await execute('portable bounded fault canaries', python, [path.join(snapshot, 'scripts/quality/fault-portable.py'), '--source-root', snapshot, '--output', output, '--python', python, '--node', process.execPath, '--cargo', resolveOriginalExecutable(process.platform === 'win32' ? 'cargo.exe' : 'cargo'), ...(env.UD_MUTATION_GUARD ? ['--guard', env.UD_MUTATION_GUARD] : [])], snapshot, { ...env, UD_FAULT_SOURCE_SHA256: summary.snapshot_sha256 }, path.join(runDir, 'faults.log'), 4 * 60 * 60 * 1000);
      return { output, result, reused: false };
    }
    async function retain(selectedBackend, errors) {
      const selected = executions.get(selectedBackend);
      if (session && selected && !selected.reused && errors.length === 0) await session.retain(selectedBackend, selected.output);
    }
    const before = inventoryTree(root);
    summary.errors.push(...before.problems);
    Object.assign(summary, mutationSnapshotIdentity(root, before));
    snapshot = path.join(scratch, summary.snapshot_sha256);
    cpSync(root, snapshot, { recursive: true, filter: source => fileCopyAllowed(root, source), errorOnExist: true });
    const copied = inventoryTree(snapshot);
    const afterCopy = inventoryTree(root);
    if (treeDigest(copied.files) !== summary.inventory_tree_sha256 || treeDigest(afterCopy.files) !== summary.inventory_tree_sha256 || sourceReceipt(snapshot).sha256 !== summary.snapshot_sha256 || sourceReceipt(root).sha256 !== summary.snapshot_sha256) throw new Error('Source or tests changed while the mutation snapshot was captured.');
    if (!existsSync(path.join(root, 'node_modules'))) throw new Error('Pinned Node dependencies are not installed.');
    const privateTemp = path.join(scratch, 'tmp'); mkdirSync(privateTemp, { mode: 0o700 });
    const env = { ...process.env, ...storage.env, TMPDIR: privateTemp, TMP: privateTemp, TEMP: privateTemp, CARGO_NET_OFFLINE: 'true', PYTHONDONTWRITEBYTECODE: '1', PYTEST_DISABLE_PLUGIN_AUTOLOAD: '1', UD_MUTATION_PARENT: '1' };
    delete env.NODE_OPTIONS;
    delete env.PYTEST_PLUGINS;
    delete env.PYTHONPATH;
    delete env.SSH_AUTH_SOCK;
    for (const key of Object.keys(env)) if (/(?:TOKEN|PASSWORD|SECRET|CREDENTIAL|API_KEY)/i.test(key)) delete env[key];
    env.GIT_TERMINAL_PROMPT = '0';
    env.GIT_CONFIG_NOSYSTEM = '1';
    env.GIT_CONFIG_GLOBAL = path.join(scratch, 'no-git-config');
    env.npm_config_userconfig = path.join(scratch, 'no-npm-config');
    const copiedDependencies = await execute('private original dependencies', process.execPath, [path.join(snapshot, 'scripts/quality/original-storage.mjs'), '--copy', root, path.join(snapshot, 'node_modules')], snapshot, env, path.join(runDir, 'original-dependencies.log'));
    if (copiedDependencies.status !== 0 || copiedDependencies.signal || copiedDependencies.timeout || copiedDependencies.error) throw new Error('Private original dependency preparation failed: ' + (copiedDependencies.error ?? copiedDependencies.tail));
    const ledger = validateExceptions(maybeJson(path.join(snapshot, 'quality/mutation-equivalents.json')));
    summary.errors.push(...ledger.errors);
    const exceptions = ledger.errors.length ? [] : ledger.exceptions;
    const python = process.env.UD_MUTATION_PYTHON ?? toolPath(root, process.platform === 'win32' ? '.venv/Scripts' : '.venv/bin', 'python');
    const mutmut = process.env.UD_MUTATION_MUTMUT ?? toolPath(root, process.platform === 'win32' ? '.venv/Scripts' : '.venv/bin', 'mutmut');
    const cargoMutants = process.env.UD_MUTATION_CARGO_MUTANTS ?? toolPath(root, '.artifacts/cargo/bin', 'cargo-mutants');
    for (const [name, executable] of profile === 'bounded' ? [['Python', python]] : [['Python', python], ['mutmut', mutmut], ['cargo-mutants', cargoMutants]]) {
      if (!path.isAbsolute(executable) || !existsSync(executable)) summary.errors.push(`${name} executable is missing or not absolute: ${executable}`);
    }
    const versionRuns = profile === 'bounded' ? [] : [
      ['Stryker', process.execPath, [path.join(snapshot, 'node_modules/@stryker-mutator/core/bin/stryker.js'), '--version'], '10.1.1'],
      ['mutmut', mutmut, ['--version'], '3.8.1'],
      ['cargo-mutants', cargoMutants, ['mutants', '--version'], '27.1.0'],
    ];
    for (const [name, executable, args, expected] of versionRuns) {
      const result = await execute(`${name} version`, executable, args, snapshot, env, path.join(runDir, `version-${name}.log`), 30_000);
      requireTool(result, expected, name, summary.errors);
    }
    const packageJson = readJson(path.join(snapshot, 'package.json'));
    if (packageJson.devDependencies?.typescript !== '7.0.2' || packageJson.devDependencies?.['typescript-compat'] !== 'npm:typescript@6.0.3') summary.errors.push('TypeScript compiler or Stryker compatibility API is not pinned to the accepted versions.');
    env.UD_AGENT_PYTHON = python;
    env.UD_RELEASE_PYTHON = python;
    originalBaseline = prepareMutationBaseline(root, snapshot, runDir, { python: resolveOriginalExecutable(python), cargo: resolveOriginalExecutable(process.platform === 'win32' ? 'cargo.exe' : 'cargo'), candidate, candidateRoot });
    if (originalBaseline.binding) { summary.candidate_binding = originalBaseline.binding; summary.acceptance_eligible = false; summary.production_ready = false; }
    const baseline = await execute(originalBaseline.label, originalBaseline.program ?? process.execPath, originalBaseline.args, snapshot, env, path.join(runDir, 'baseline.log'));
    summary.baseline = { status: baseline.status, signal: baseline.signal, timeout: baseline.timeout, error: baseline.error };
    if (baseline.status !== 0 || baseline.signal || baseline.timeout || baseline.error) throw new Error('Full baseline tests did not pass; no mutants will execute against a failed baseline.');
    if (originalBaseline.binding) {
      const report = verifyMutationOriginalBaseline(root, originalBaseline);
      summary.baseline.original_report = fileReceipt(root, relative(root, path.join(originalBaseline.reportDirectory, report.path)));
      summary.baseline.original_profiles = 1;
    }
    let guard = path.join(snapshot, 'target', 'debug', process.platform === 'win32' ? 'ud-agent-guard.exe' : 'ud-agent-guard');
    if (!existsSync(guard)) summary.errors.push('Baseline did not produce the native guard needed by mutation tests.');
    else {
      // The baseline's compiled target is disposable. Retain only its exact
      // native guard while the subsequent protected job occupies scratch.
      const retainedGuard = path.join(scratch, process.platform === 'win32' ? 'baseline-guard.exe' : 'baseline-guard');
      const expectedGuard = hash(readFileSync(guard)); copyFileSync(guard, retainedGuard); chmodSync(retainedGuard, 0o700);
      if (hash(readFileSync(retainedGuard)) !== expectedGuard) throw new Error('Retained baseline guard differs from its compiled bytes.');
      rmSync(path.join(snapshot, 'target'), { recursive: true });
      guard = retainedGuard; env.UD_MUTATION_GUARD = guard;
    }
    if (session) releaseSession = await acquireMutationSessionLease(session.directory, guard);
    const faultManifest = maybeJson(path.join(snapshot, 'tests/mutation/fault-cases.json'));
    if (selected.has('faults')) {
    if (!faultManifest || faultManifest.schema_version !== 1 || !Array.isArray(faultManifest.cases)) {
      summary.errors.push('Fault-canary inventory is missing or malformed.');
    } else {
      const beforeFaults = summary.errors.length;
      const faultJob = portable ? await portableFaults() : await protectedRun('faults', path.join(runDir,'fault-oci'), path.join(runDir,'faults.log'));
      const faultOutput = faultJob.output, faultRun = faultJob.result;
      const report=maybeJson(path.join(faultOutput,'fault-outcomes.json')),plan=maybeJson(path.join(faultOutput,'fault-schedule.json')),outcomes=report?.outcomes??[];
      summary.backends.fault_canaries = { outcomes };
      if (!portable) summary.errors.push(...protectedProviderEvidence(faultOutput,summary.snapshot_sha256,'faults','secondary-runner.json'));
      if(faultRun.error||faultRun.signal||faultRun.timeout||![0,1].includes(faultRun.status)||report?.complete!==true||report?.source_tree_sha256!==summary.snapshot_sha256||plan?.scheduled!==faultManifest.cases.length||outcomes.length!==faultManifest.cases.length||new Set(outcomes.map(item=>item.id)).size!==faultManifest.cases.length||outcomes.some(item=>!plan?.inventory?.some(row=>row.id===item.id&&row.definition_sha256===item.definition_sha256)))summary.errors.push('Targeted defect schedule or complete exact outcome union is missing.');
      for (const item of outcomes) if (item.status !== 'Killed') summary.errors.push(`Fault canary ${item.status}: ${item.id}: ${item.reason ?? ''}`);
      if (profile === 'bounded') {
        const assessed = assessBoundedFaults({ manifest: faultManifest, plan, report, sourceSha256: summary.snapshot_sha256, sourceHashes: before.files, readSource: name => readFileSync(path.join(snapshot, name)) });
        summary.backends.bounded = assessed;
        summary.errors.push(...assessed.errors);
        Object.assign(summary, { corpus_sha256: fileReceipt(snapshot, 'tests/mutation/fault-cases.json').sha256, scheduled: assessed.total, killed: assessed.killed, equivalent: 0, per_language: assessed.per_language });
        summary.mutation_coverage = { qualification: 'bounded mutation corpus', detection_percent: assessed.total > 0 ? 100 * assessed.killed / assessed.total : 0, exhaustive: false, scheduled: assessed.total, killed: assessed.killed, per_language: assessed.per_language };
      }
      await retain('faults', summary.errors.slice(beforeFaults));
    }
    }
    save();
    const perlFiles = expectedSources(before.files, PERL_EXT);
    if (perlFiles.length && selected.has('perl')) {
      const perlJob = await protectedRun('perl', path.join(runDir, 'perl-protected'), path.join(runDir, 'perl-full.log'));
      const protectedOutput = perlJob.output;
      const perlReport = path.join(protectedOutput, 'perl-full.json');
      const perlPlan = path.join(protectedOutput, 'perl-schedule.json');
      const perlRun = perlJob.result;
      const sources = Object.fromEntries(perlFiles.map(file => [file, readFileSync(path.join(snapshot, file))]));
      const assessment = assessPerl(maybeJson(perlReport), maybeJson(perlPlan), sources, before.files, exceptions, used, name => readFileSync(path.join(snapshot, name)), sourceReceipt(snapshot));
      if (!maybeJson(perlPlan)) assessment.errors.push('Perl independent scheduling failed.');
      if (perlRun.signal || perlRun.timeout || perlRun.error || ![0, 1].includes(perlRun.status)) assessment.errors.push('Perl full runner failed or was interrupted.');
      assessment.errors.push(...protectedProviderEvidence(protectedOutput,summary.snapshot_sha256,'perl'));
      const retained=maybeJson(path.join(protectedOutput,'perl-guard-fixture.json'));
      const guards=assessPerlGuards(retained,sources['workers/ud/src/ud_agent/perl/graph_bridge.pl'],before.files);
      if(retained?.qualification!=='protected-retained-guard-regression-not-full-language-acceptance'||retained.source_tree_sha256!==summary.snapshot_sha256)guards.errors.push('Retained guard regression is missing its protected source binding.');
      assessment.retained_guard_regression=guards;
      assessment.errors.push(...guards.errors.map(value=>'Retained Perl guard regression: '+value));
      appendAssessment(summary, 'ppi-perl', assessment);
      await retain('perl', assessment.errors);
    }
    save();
    if (preflightOnly) throw new Error('Preflight-only run: full mutation backends were not executed.');
    if (selected.has('typescript')) {
    const obligations=reviewedAssertionObligations(snapshot,before.files);
    const generationFile=path.join(runDir,'stryker-generation.json');
    const generationRun=await execute('complete independent Stryker source generation',process.execPath,[path.join(snapshot,'scripts/quality/discover-stryker.mjs'),'--output',generationFile],snapshot,env,path.join(runDir,'stryker-generation.log'));
    const generation=maybeJson(generationFile),jsFiles=expectedSources(before.files,JS_EXT);
    if(generationRun.status!==0||generationRun.error||generationRun.signal||generationRun.timeout||generation?.source_tree_sha256!==summary.snapshot_sha256||assessStrykerDiscovery(generation,jsFiles,before.files).errors.length)throw new Error('Complete independent Stryker generation failed before mutant execution.');
    const strykerJob = await protectedRun('typescript', path.join(runDir, 'stryker-oci'), path.join(runDir, 'stryker.log'));
    const strykerOutput = strykerJob.output, stryker = strykerJob.result;
    const strykerReport = maybeJson(path.join(strykerOutput, 'stryker-report.json'));
    if (strykerReport) writeFileSync(path.join(runDir, 'stryker.json'), JSON.stringify(strykerReport));
    const schedule = maybeJson(path.join(strykerOutput, 'stryker-schedule.json'));
    let selectionProof = null;
    if (['off','perTest'].includes(strykerReport?.config?.coverageAnalysis)) {
      let records = [];
      try { records = lineEvents(path.join(strykerOutput, 'stryker-executions.jsonl')); } catch { /* verifier rejects missing records */ }
      const readBounded = name => {
        const filename = path.join(strykerOutput, name), info = lstatSync(filename);
        if (!info.isFile() || info.isSymbolicLink() || info.size > 32 * 1024 ** 2 + 65536) throw new Error('Selection evidence is not a bounded ordinary file.');
        return readFileSync(filename);
      };
      let immutableSdkContext;
      try {
        immutableSdkContext = verifyRecordedStrykerSdk(maybeJson(path.join(strykerOutput, 'runtime-input-receipt.json')), readBounded);
      } catch { /* Missing verified context cannot authenticate SDK stack aliases. */ }
      selectionProof = await verifyProtectedSelections({ schedule, records, sourceRoot: snapshot, readBaseline: receipt => readBounded(receipt.path), readExecution: id => JSON.parse(readBounded(`control/jobs/${id}.exec.json`).toString('utf8')), immutableSdkContext,coverageAnalysis:strykerReport.config.coverageAnalysis });
    }
    const strykerAssessment = assessStryker(strykerReport, jsFiles, before.files, exceptions, used, expectedVitest(before.files), name=>readFileSync(path.join(snapshot,name)),generation,selectionProof,schedule);
    if (selectionProof) strykerAssessment.errors.push(...selectionProof.errors);
    let strykerOutcomes = [], strykerFailures = [];
    try { strykerOutcomes = lineEvents(path.join(strykerOutput, 'stryker-outcomes.jsonl')); strykerFailures = lineEvents(path.join(strykerOutput, 'stryker-test-failures.jsonl')); }
    catch { strykerAssessment.errors.push('Structured Stryker evidence is malformed.'); }
    const assertionClassifier=await createAssertionObligationClassifier({sourceRoot:snapshot,sourceInventory:Object.fromEntries(Object.entries(before.files).filter(([name])=>name.startsWith('tests/'))),obligations,verifyAssertion:(test,error,context)=>verifiedAssertionOrigin(selectionProof,schedule,context.mutant_id,test.id,error)??{valid:false,reason:'No independently replayed owned assertion origin'}});
    const reconciled = reconcileScheduledMutations(schedule, strykerOutcomes, strykerFailures, before.files, {exceptions,used,readReview:name=>readFileSync(path.join(snapshot,name)), ...(selectionProof ? { selectionProof } : {}),assertionClassifier,requireIndependentBehavior:true});
    strykerAssessment.errors.push(...reconciled.errors);
    strykerAssessment.reported_killed=strykerAssessment.killed;strykerAssessment.killed=reconciled.killed;
    for(const field of ['independent_behavior_killed','behavior_pending','assertion_obligations'])strykerAssessment[field]=reconciled[field];
    if (schedule?.source_tree_sha256 !== summary.snapshot_sha256) strykerAssessment.errors.push('Stryker scheduling source differs from the frozen snapshot.');
    strykerAssessment.errors.push(...protectedProviderEvidence(strykerOutput,summary.snapshot_sha256,'typescript','stryker-runner.json'));
    if (stryker.error || stryker.signal || stryker.timeout || ![0, 1].includes(stryker.status)) strykerAssessment.errors.push('Stryker protected runner failed independently of the strict threshold.');
    appendAssessment(summary, 'stryker', strykerAssessment);
    await retain('typescript', strykerAssessment.errors);
    save();
    }
    if (selected.has('python')) {
    const pythonGeneration = session ? canonicalMutmutGeneration(root, sourceReceipt(snapshot), session.authority.inventory) : undefined;
    const pythonJob = await protectedRun('python', path.join(runDir, 'python-oci'), path.join(runDir, 'mutmut.log'));
    const protectedOutput = pythonJob.output;
    const pythonWorktree = path.join(protectedOutput, 'work');
    const pythonSchedule = path.join(protectedOutput, 'schedule.json'), pythonOutcomes = path.join(protectedOutput, 'outcomes.json');
    const evidence = path.join(protectedOutput, 'pytest-events.jsonl');
    if (process.platform === 'win32') summary.errors.push('Run the native Linux mutation OCI provider from a supported local Linux/macOS host.');
    else {
      const pythonRun = pythonJob.result;
      let events = [];
      try { events = lineEvents(evidence); } catch { summary.errors.push('mutmut per-test evidence is malformed.'); }
      const pythonFiles = expectedSources(before.files, PY_EXT).filter(name => /^(?:workers\/ud\/src\/ud_agent|scripts)\//.test(name));
      const meta = metadataFor(pythonWorktree, pythonFiles);
      writeFileSync(path.join(runDir, 'mutmut-metadata.json'), JSON.stringify(meta));
      const assessment = assessMutmut(meta, events, pythonFiles, before.files, exceptions, used, maybeJson(pythonSchedule), name=>readFileSync(path.join(snapshot,name)), pythonGeneration);
      assessment.errors.push(...reconcilePythonSchedule(maybeJson(pythonSchedule), maybeJson(pythonOutcomes), meta, before.files, summary.snapshot_sha256, pythonGeneration));
      assessment.errors.push(...pythonFullSuiteDispatchErrors(maybeJson(path.join(protectedOutput, 'full-suite-dispatch.json')), maybeJson(pythonSchedule), summary.snapshot_sha256));
      if (pythonRun.status !== 0 || pythonRun.signal || pythonRun.timeout || pythonRun.error) assessment.errors.push('mutmut runner failed or was interrupted.');
      assessment.errors.push(...protectedProviderEvidence(protectedOutput,summary.snapshot_sha256,'python'));
      appendAssessment(summary, 'mutmut', assessment);
      await retain('python', assessment.errors);
    }
    save();
    const staticJob = await protectedRun('python-static', path.join(runDir,'python-static-oci'), path.join(runDir,'python-static.log'));
    const staticOutput=staticJob.output;
    const staticReport = path.join(staticOutput, 'python-static.json');
    const staticPlan = path.join(staticOutput, 'python-static-schedule.json');
    const staticRun = staticJob.result;
    const staticAssessment = assessStatic(maybeJson(staticReport), before.files, exceptions, used, name=>readFileSync(path.join(snapshot,name)), maybeJson(staticPlan));
    staticAssessment.errors.push(...protectedProviderEvidence(staticOutput,summary.snapshot_sha256,'python-static','secondary-runner.json'));
    if (staticRun.signal || staticRun.timeout || staticRun.error || ![0, 1].includes(staticRun.status)) staticAssessment.errors.push('Python module-scope runner failed or was interrupted.');
    appendAssessment(summary, 'python-static', staticAssessment);
    await retain('python-static', staticAssessment.errors);
    save();
    }
    if (selected.has('rust')) {
    const parserTarget = path.join(scratch, 'trusted-rust-parser');
    const parserBuild = await execute('build original native Rust AST parser', 'cargo', ['build', '--locked', '--offline', '--manifest-path', 'scripts/quality/rust-assertion-parser/Cargo.toml', '--target-dir', parserTarget], snapshot, env, path.join(runDir, 'rust-parser-build.log'), 300_000);
    if (parserBuild.error || parserBuild.signal || parserBuild.timeout || parserBuild.status !== 0) throw new Error('Original native Rust AST parser build failed.');
    const parserExecutable = path.join(scratch, 'trusted-rust-parser-bin' + (process.platform === 'win32' ? '.exe' : ''));
    cpSync(path.join(parserTarget, 'debug', 'ud-rust-assertion-parser' + (process.platform === 'win32' ? '.exe' : '')), parserExecutable);
    chmodSync(parserExecutable, 0o500);
    const parseRustSource = nativeRustSourceParser(snapshot, parserExecutable, before.files);
    summary.rust_assertion_parser = parseRustSource.receipt;
    const rustJob = await protectedRun('rust', path.join(runDir, 'rust-oci'), path.join(runDir,'cargo-mutants.log'));
    const rustOutput = rustJob.output, rustRun = rustJob.result;
    const rustReport = path.join(rustOutput,'rust');
    const rustFiles = expectedSources(before.files, RUST_EXT);
    const rustSchedule=maybeJson(path.join(rustReport,'schedule.json'));
    const rustOutcomes = maybeJson(path.join(rustReport, 'outcomes.json'));
    let cfgEvidence = null;
    if (rustSchedule?.applicability) {
      try {
        const bounded = (name, max) => {
          const file = path.join(rustReport, name), info = lstatSync(file);
          if (!info.isFile() || info.isSymbolicLink() || info.size > max) throw new Error('Rust applicability evidence is not a bounded ordinary artifact.');
          return readFileSync(file);
        };
        cfgEvidence = verifyRustApplicabilityEvidence({ root: snapshot, schedule: rustSchedule,
          runtime: maybeJson(path.join(rustOutput, 'runtime-input-receipt.json')),
          sdkBytes: bounded('rust-sdk-receipt.json', 16 * 1024 ** 2),
          generationBytes: bounded('target-cfg-generation.json', 1024 ** 2),
          proofBytes: bounded('applicability.json', 64 * 1024 ** 2),
          source_sha256: summary.snapshot_sha256,
          parseCfg: nativeRustCfgParser(snapshot, parserExecutable, before.files) });
      } catch (error) { summary.errors.push(`Rust applicability replay failed: ${error.message}`); }
    }
    const rustAssessment = assessCargo(rustSchedule?.inventory?.map(item=>item.mutant), rustOutcomes, file => {
      const resolved = path.resolve(rustReport, file);
      if (!resolved.startsWith(rustReport + path.sep)) throw new Error('Invalid Rust log path.');
      return readFileSync(resolved, 'utf8');
    }, rustFiles, before.files, exceptions, used, name=>readFileSync(path.join(snapshot,name)), { root: snapshot, parseSource: parseRustSource, tests: rustSchedule?.tests, ...(cfgEvidence ? { verifyApplicability: () => cfgEvidence } : {}) });
    if(rustSchedule?.scheduled!==rustSchedule?.inventory?.length||rustSchedule?.source_tree_sha256!==summary.snapshot_sha256||rustSchedule?.scope_complete!==true||rustSchedule?.shard_count!==1||!rustSchedule?.tests?.length)rustAssessment.errors.push('Rust independently scheduled source/test inventory is incomplete.');
    if (rustOutcomes?.source_tree_sha256 !== summary.snapshot_sha256 || rustSchedule?.inventory?.some(item => item.file !== item.mutant?.file || item.source_sha256 !== before.files[item.file] || canonicalJson(item.definition) !== canonicalJson({ tool: 'cargo-mutants', version: '27.1.0', ...item.mutant }) || item.definition_sha256 !== hash(canonicalJson(item.definition)))) rustAssessment.errors.push('Rust report or exact mutation definitions differ from the frozen source schedule.');
    rustAssessment.errors.push(...protectedProviderEvidence(rustOutput,summary.snapshot_sha256,'rust'));
    if (rustRun.signal || rustRun.timeout || rustRun.error || ![0,1,2].includes(rustRun.status)) rustAssessment.errors.push('cargo-mutants runner failed or was interrupted.');
    appendAssessment(summary, 'cargo-mutants', rustAssessment);
    await retain('rust', rustAssessment.errors);
    const conditionalRust = rustFiles.filter(file => /#\s*\[\s*cfg(?:_attr)?\s*\([^\]]*\b(?:unix|windows|target_os|target_arch|target_env|feature)\b/.test(readFileSync(path.join(snapshot, file), 'utf8')));
    if (conditionalRust.length && !rustAssessment.applicability_verified) {
      summary.backends['cargo-mutants'].conditional_sources = conditionalRust;
      summary.errors.push('Platform-conditional Rust source requires independently reconciled native matrix mutation evidence; a single host cannot certify every branch.');
    }
    }
    if (profile === 'exhaustive' && backend === undefined) for (const entry of exceptions) if (!used.has(`${entry.tool}\0${entry.id}`)) summary.errors.push(`Unused or stale equivalence record: ${entry.tool} ${entry.id}`);
  } catch (error) {
    summary.errors.push(`Mutation gate setup or execution failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (releaseSession) try { await releaseSession(); } catch (error) { summary.errors.push('Mutation session lease failed: ' + error.message); }
  if (summary.snapshot_sha256) {
    try {
      if (treeDigest(inventoryTree(root).files) !== summary.inventory_tree_sha256 || sourceReceipt(root).sha256 !== summary.snapshot_sha256) summary.errors.push('Working-tree source or tests changed during mutation testing; all evidence is stale.');
    } catch (error) { summary.errors.push(`Could not verify final source inventory: ${error instanceof Error ? error.message : String(error)}`); }
  }
  if (originalBaseline?.binding) try { recheckMutationCandidate(root, originalBaseline); } catch (error) { summary.errors.push(`Could not verify final candidate subjects: ${error.message}`); }
  summary.storage = { admission: 'checked-before-execution', runtime_budget_monitoring: false, owned_cleanup: 'required' };
  try { storage.cleanup(); } catch (error) { summary.errors.push(`Could not remove isolated mutation scratch: ${error instanceof Error ? error.message : String(error)}`); }
  summary.finished_at = new Date().toISOString();
  finalizeMutationSummary(summary);
  save();
  console.log(`Strict mutation gate ${summary.status}. Evidence: ${output}`);
  for (const issue of summary.errors.slice(0, 50)) console.error(` - ${issue}`);
  if (summary.errors.length > 50) console.error(` - ${summary.errors.length - 50} additional issues in ${output}`);
  return summary;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  if (process.env.UD_MUTATION_PARENT === '1') throw new Error('Nested mutation gate execution is prohibited.');
  const { candidatePath, ...options } = mutationGateOptions(process.argv.slice(2));
  const summary = await runMutationGate(ROOT, { ...options, ...(candidatePath ? { candidate: readJson(path.resolve(candidatePath)) } : {}) });
  process.exitCode = summary.status === 'passed' ? 0 : 1;
}
