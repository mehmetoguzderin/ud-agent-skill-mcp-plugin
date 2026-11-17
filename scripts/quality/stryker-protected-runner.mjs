/** Trusted Stryker adapter. Mutant code runs only in a fresh OCI exec job. */
import { declareClassPlugin, PluginKind, commonTokens } from '@stryker-mutator/api/plugin';
import { spawn } from 'node:child_process';
import { appendFileSync, constants, closeSync, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import path from 'node:path';
import { mutationDefinitionFingerprint, protectedCoverageSelection, requireCompiledTestCases, serializeScheduledMutation } from './stryker-child.mjs';
import { createStrykerAssertionVerifier, verifyCompiledSources } from './stryker-assertions.mjs';
import { STRYKER_ASSERTION_SDK_FILE, STRYKER_ASSERTION_SERIALIZER_FILE, STRYKER_ASSERTION_CHAI_FILE, verifyStrykerAssertionSdk, verifyStrykerAssertionSdkClosure } from './stryker-assertion-sdk.mjs';
import { normalizeSubprocessOpacity } from './stryker-opacity.mjs';
import { retainPristineAuthority, restorePristineAuthority } from './stryker-baseline-authority.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const demand = (value, message) => { if (!value) throw new Error(`Protected Stryker: ${message}`); };
const MAX_FRAME = 64 * 1024 * 1024;
const BRIDGE = '/opt/mutation/harness/stryker-exec.py';
const PYTHON = '/opt/mutation/python/bin/python3';

/** Pure replay of source-bound image derivation; callers obtain these bytes
 * only through immutable root-owned image descriptors before any test job.
 */
export function verifyProtectedAssertionSdkEvidence(runtime,{receiptBytes,originalBytes,serializerOriginalBytes,serializerCurrentBytes,chaiOriginalBytes,chaiCurrentBytes,upstreamBytes,closureBytes,currentBytes}){
  const bind=(descriptor,expected,bytes,max)=>{
    demand(descriptor&&Object.keys(descriptor).sort().join(',')==='path,sha256,size_bytes'&&descriptor.path===expected&&/^[a-f0-9]{64}$/.test(descriptor.sha256??'')&&Number.isSafeInteger(descriptor.size_bytes)&&descriptor.size_bytes>0&&descriptor.size_bytes<=max&&Buffer.isBuffer(bytes)&&bytes.length===descriptor.size_bytes&&sha(bytes)===descriptor.sha256,'assertion SDK derivation descriptor or bytes differ');
  };
  const derivation=runtime.node_assertion_sdk;
  demand(derivation&&Object.keys(derivation).sort().join(',')==='chai_upstream_source,receipt,serializer_upstream_source,upstream_dependencies,upstream_source','assertion SDK derivation authority is missing or incomplete');
  bind(derivation.receipt,'node-assertion-sdk.json',receiptBytes,1024**2);
  bind(derivation.upstream_source,'node-assertion-sdk-upstream.js',originalBytes,1024**2);
  bind(derivation.serializer_upstream_source,'node-assertion-sdk-serializer-upstream.js',serializerOriginalBytes,1024**2);
  bind(derivation.chai_upstream_source,'node-assertion-sdk-chai-upstream.js',chaiOriginalBytes,1024**2);
  bind(derivation.upstream_dependencies,'node-upstream-dependencies.json',upstreamBytes,32*1024**2);
  bind(runtime.node_dependencies,'node-dependencies.json',closureBytes,32*1024**2);
  const receipt=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(receiptBytes));
  demand(receipt.schema_version===3,'assertion SDK lacks authenticated fresh-error construction authority');
  verifyStrykerAssertionSdk(originalBytes,currentBytes,receipt,{serializerOriginal:serializerOriginalBytes,serializerDerived:serializerCurrentBytes,chaiOriginal:chaiOriginalBytes,chaiDerived:chaiCurrentBytes});
  verifyStrykerAssertionSdkClosure(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(upstreamBytes)),JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(closureBytes)),receipt);
  return receipt;
}

function immutableImageBytes(descriptor,max){
  demand(descriptor&&typeof descriptor.path==='string'&&/^[a-f0-9]{64}$/.test(descriptor.sha256??'')&&Number.isSafeInteger(descriptor.size_bytes)&&descriptor.size_bytes>0&&descriptor.size_bytes<=max,'immutable assertion SDK descriptor is invalid');
  const filename=path.join('/opt/mutation',safeRelative(descriptor.path)),fd=openSync(filename,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try{
    const before=fstatSync(fd,{bigint:true}),named=lstatSync(filename,{bigint:true});
    demand(before.isFile()&&before.uid===0n&&before.nlink===1n&&!(before.mode&0o222n)&&before.size===BigInt(descriptor.size_bytes)&&!named.isSymbolicLink()&&named.dev===before.dev&&named.ino===before.ino,'immutable assertion SDK file identity differs');
    const bytes=readFileSync(fd),after=fstatSync(fd,{bigint:true});
    demand(bytes.length===descriptor.size_bytes&&sha(bytes)===descriptor.sha256&&before.dev===after.dev&&before.ino===after.ino&&before.size===after.size&&before.mtimeNs===after.mtimeNs&&before.ctimeNs===after.ctimeNs,'immutable assertion SDK file changed while reading');
    return bytes;
  }finally{closeSync(fd);}
}

export function protectedTimeout(value) {
  demand(typeof value === 'number' && Number.isFinite(value) && value > 0 && value <= 540000, 'invalid isolated execution timeout');
  // Stryker derives mutant timeouts from measured test durations and can supply
  // fractional milliseconds. Round upwards at the integer wire boundary.
  return Math.ceil(value);
}

export function bridgeResponse(bytes, expectedId) {
  const response = JSON.parse(bytes.toString('utf8'));
  if (response?.schema_version === 1 && response.id === null && typeof response.error === 'string') {
    throw new Error(`Protected Stryker controller rejected its request: ${response.error.slice(0, 4096)}`);
  }
  demand(typeof expectedId === 'string' && response?.id === expectedId && response.schema_version === 1, 'unexpected bridge response');
  demand(response.error === undefined || typeof response.error === 'string', 'invalid bridge error');
  return response;
}

/** Retain exact harvested baseline bytes, including failed retry diagnostics. */
export function retainProtectedBaseline(directory, id, bytes, execution, options = {}) {
  demand(typeof id === 'string' && /^[1-9][0-9]{0,15}$/.test(id) && Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 32 * 1024 ** 2, 'invalid baseline retention contract');
  const kind = options.kind ?? 'baseline';
  demand(['baseline', 'mutant'].includes(kind), 'invalid retained invocation kind');
  const real = realpathSync(directory), info = lstatSync(directory), uid = process.getuid?.();
  demand(real === path.resolve(directory) && info.isDirectory() && !info.isSymbolicLink() && (uid === undefined || info.uid === uid && !(info.mode & 0o022)), 'baseline evidence directory is not private supervisor storage');
  const stored = kind === 'mutant' ? gzipSync(bytes, { level: 9 }) : bytes;
  demand(stored.length <= 32 * 1024 ** 2 + 65536, 'compressed result exceeds its byte bound');
  const name = `stryker-${kind}-${id}.json${kind === 'mutant' ? '.gz' : ''}`, filename = path.join(real, name);
  const fd = openSync(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    writeFileSync(fd, stored); fsyncSync(fd);
    const observed = fstatSync(fd);
    demand(observed.isFile() && observed.nlink === 1 && observed.size === stored.length && (uid === undefined || observed.uid === uid && (observed.mode & 0o777) === 0o600), 'retained baseline identity changed');
  } finally { closeSync(fd); }
  const receipt = { schema_version: 1, qualification: 'exact-harvested-invocation-not-mutation-acceptance', result: { path: name, sha256: sha(stored), size: stored.length }, ...(kind === 'mutant' ? { raw_result: { sha256: sha(bytes), size: bytes.length }, materialization: options.materialization } : {}), execution };
  writeFileSync(path.join(real, `stryker-${kind}-${id}.receipt.json`), JSON.stringify(receipt) + '\n', { flag: 'wx', mode: 0o600 });
  return receipt;
}

function safeRelative(filename) {
  demand(typeof filename === 'string' && filename.length > 0 && !/[\\\0:]/.test(filename) && !path.isAbsolute(filename) && !filename.split('/').some(part => !part || part === '.' || part === '..'), 'unsafe workspace path');
  return filename;
}

/** Retain verified harvested bytes before checking success-only fields. */
export function retainHarvestedReport(directory,id,kind,bytes,execution,sdkContext){
  let parsed;try{parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{}
  const baselineReceipt = kind !== 'mutant' ? retainProtectedBaseline(directory,id,bytes,execution) : null;
  const mutantReceipt = kind === 'mutant' ? retainProtectedBaseline(directory,id,bytes,execution,{kind:'mutant',...(parsed?.materialization?{materialization:parsed.materialization}:{})}) : null;
  demand(parsed&&typeof parsed==='object'&&!Array.isArray(parsed),'isolated result JSON is malformed; exact harvested bytes retained');
  const report=parsed;demand(report.child_root===`/tmp/ud-mutation-jobs/${execution.execution_id}/tree`,'isolated report identifies another private execution tree');
  const context=report.assertion_sdk_context;
  if(!(context&&Object.keys(context).sort().join(',')==='receipt_sha256,root,schema_version'&&context.schema_version===1&&context.root===sdkContext.root&&context.receipt_sha256===sdkContext.receipt_sha256))throw new Error('Protected Stryker: isolated assertion SDK context changed; exact harvested report retained; child status='+String(report.result?.status)+'; child error='+String(report.result?.errorMessage??'missing SDK authority').slice(0,65536));
  return {report,baselineReceipt,mutantReceipt};
}

/** Runtime fixture input is prepared by the trusted parent before sealing. */
function stageSandboxHelper(root, bytes, expected) {
  let directory = root;
  for (const name of ['target', 'debug']) {
    directory = path.join(directory, name);
    try { mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const info = lstatSync(directory);
    demand(info.isDirectory() && !info.isSymbolicLink() && info.uid === 0 && (info.mode & 0o022) === 0, 'native fixture input directory was substituted');
  }
  const filename = path.join(directory, 'ud-agent-guard');
  try {
    const fd = openSync(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o500);
    try { writeFileSync(fd, bytes); fchmodSync(fd, 0o555); fsyncSync(fd); } finally { closeSync(fd); }
  } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd, { bigint: true });
    demand(before.isFile() && before.uid === 0n && before.nlink === 1n && (before.mode & 0o777n) === 0o555n && before.size === BigInt(bytes.length), 'native fixture input is not immutable');
    const observed = readFileSync(fd), after = fstatSync(fd, { bigint: true });
    demand(sha(observed) === expected && before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs, 'native fixture input identity changed');
  } finally { closeSync(fd); }
}

/** Read and fingerprint the same immutable sandbox files passed to the broker. */
export function sandboxInventory(root) {
  root = realpathSync(root);
  const files = [];
  function walk(relative = '') {
    for (const entry of readdirSync(path.join(root, relative), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (name === 'node_modules') {
        demand(realpathSync(path.join(root, name)) === '/opt/mutation/node_modules', 'dependencies do not resolve to the pinned read-only closure');
        continue;
      }
      safeRelative(name);
      demand(!entry.isSymbolicLink(), 'unregistered source symlink');
      if (entry.isDirectory()) walk(name);
      else {
        demand(entry.isFile(), 'non-file source input');
        const fd = openSync(path.join(root, name), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        try {
          const before = fstatSync(fd, { bigint: true });
          demand(before.isFile() && before.nlink === 1n && before.uid === 0n && before.size <= 64n * 1024n * 1024n, 'sandbox input is not a bounded root-owned file');
          const bytes = readFileSync(fd), after = fstatSync(fd, { bigint: true });
          demand(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs && BigInt(bytes.length) === before.size, 'sandbox changed while fingerprinting');
          files.push({ path: name, sha256: sha(bytes), size: bytes.length, mode: Number(before.mode & 0o777n) });
        } finally { closeSync(fd); }
      }
    }
  }
  walk(); demand(files.length > 0, 'empty source handoff');
  return { root, files };
}

export function normalizeProtectedReport(report, root, expectedTests, selection = null, verifyAssertion = null) {
  demand(report?.schema_version === 1 && typeof report.child_root === 'string' && Array.isArray(report.tests) && Array.isArray(report.failures) && Array.isArray(report.outside_errors) && report.result, 'invalid isolated report');
  const ids = new Set();
  const tests = report.tests.map(test => {
    demand(test && typeof test.id === 'string' && !ids.has(test.id) && typeof test.source_sha256 === 'string' && /^[a-f0-9]{64}$/.test(test.source_sha256), 'duplicate or unbound isolated test');
    ids.add(test.id);
    const source = safeRelative(test.source);
    demand(source.startsWith('tests/') && sha(readFileSync(path.join(root, source))) === test.source_sha256, 'isolated test source differs from trusted sandbox');
    return { ...test, fileName: path.join(root, source) };
  });
  if (expectedTests) {
    const expected = new Set(expectedTests.map(test => test.id));
    demand(expected.size === expectedTests.length && ids.size === expected.size && [...ids].every(id => expected.has(id)), 'isolated invocation omitted or added required tests');
  }
  if (selection) {
    demand(report.selection_sha256 === selection.sha256 && Array.isArray(report.not_selected), 'selected report lost its required inventory binding');
    const required = new Set(selection.cases.map(test => test.id));
    const expected = selection.all_cases.filter(test => !required.has(test.id)).map(test => test.id);
    demand(JSON.stringify(report.not_selected) === JSON.stringify(expected), 'selected report omitted its explicitly nonselected inventory');
  } else demand(report.selection_sha256 === undefined && report.not_selected === undefined, 'unexpected test selection');
  const failedIds = new Set();
  for (const failure of report.failures) {
    demand(ids.has(failure?.test_id) && !failedIds.has(failure.test_id) && tests.find(test => test.id === failure.test_id).status === 1 && ['assertion', 'runtime'].includes(failure.failure_kind) && Array.isArray(failure.errors), 'failure identifies an unknown or duplicate test');
    failedIds.add(failure.test_id);
    if (verifyAssertion && failure.failure_kind === 'assertion') {
      const test = tests.find(test => test.id === failure.test_id);
      demand(failure.errors.length > 0 && failure.errors.every(error => verifyAssertion(test, error).valid === true), 'failure does not originate in the immutable current test assertion');
    }
  }
  demand(tests.every(test => test.status !== 1 || failedIds.has(test.id)), 'failed test lacks its exact structured evidence');
  if (report.result.status === 'killed') demand(report.outside_errors.length === 0 && report.failures.length > 0 && report.failures.every(item => item.failure_kind === 'assertion' && item.errors.length > 0 && item.errors.every(error => error && ['AssertionError', 'AssertionError [ERR_ASSERTION]', 'VitestAssertionError'].includes(error.name) && (error.code === undefined || error.code === null || error.code === 'ERR_ASSERTION'))) && tests.every(test => test.status === 0 || test.status === 1) && report.result.nrOfTests === tests.length && Array.isArray(report.result.killedBy) && report.result.killedBy.length === failedIds.size && new Set(report.result.killedBy).size === failedIds.size && report.result.killedBy.every(id => failedIds.has(id)), 'kill lacks complete clean assertion evidence');
  if (report.result.status === 'survived') demand(report.outside_errors.length === 0 && tests.length > 0 && tests.every(test => test.status === 0) && report.failures.length === 0 && report.result.nrOfTests === tests.length, 'survival lacks complete passing tests');
  if (report.result.status === 'complete') demand(report.outside_errors.length === 0 && tests.length > 0 && tests.every(test => test.status === 0), 'dry-run baseline did not pass');
  demand(['complete', 'killed', 'survived', 'timeout', 'error'].includes(report.result.status), 'unknown isolated outcome');
  return { result: report.result.status === 'complete' ? { ...report.result, tests } : report.result, tests, failures: report.failures };
}

/** Bind every validated invocation, including full-suite runs, to its exact
 * scheduled identity. This is a receipt journal, never acceptance by itself.
 */
export function retainProtectedExecution(directory,record){
  demand(record?.schema_version===1&&typeof record.mutant_id==='string'&&/^(?:0|[1-9][0-9]*)$/.test(record.mutant_id)&&/^[a-f0-9]{64}$/.test(record.definition_sha256??'')&&record.original_baseline?.result&&record.mutant_report?.result&&/^[a-f0-9]{32}$/.test(record.execution??'')&&record.mutant_report.execution?.execution_id===record.execution&&record.mutant_report.execution?.uid===record.uid&&Number.isSafeInteger(record.uid)&&record.uid>=100001&&Number.isSafeInteger(record.required_tests_completed)&&record.required_tests_completed>0&&(record.selection===null?record.selected_baseline===null:record.selection&&record.selected_baseline?.result),'invalid scheduled execution association');
  const root=realpathSync(directory),info=lstatSync(directory,{bigint:true}),uid=process.getuid?.();demand(root===path.resolve(directory)&&info.isDirectory()&&!info.isSymbolicLink()&&(uid===undefined||info.uid===BigInt(uid)&&!(info.mode&0o022n)),'execution journal is not private supervisor storage');
  const bytes=Buffer.from(JSON.stringify(record)+'\n');demand(bytes.length<=8*1024**2,'execution association exceeds its bound');
  for(const name of ['stryker-executions.jsonl',...(record.selection?['stryker-selections.jsonl']:[])]){
    const filename=path.join(root,name);
    const valid=value=>value.isFile()&&!value.isSymbolicLink()&&value.nlink===1n&&(uid===undefined||value.uid===BigInt(uid)&&(value.mode&0o777n)===0o600n);
    const same=(left,right)=>['dev','ino','size','mtimeNs','ctimeNs','mode','uid','nlink'].every(key=>left[key]===right[key]);
    let named;try{named=lstatSync(filename,{bigint:true});}catch(error){if(error.code!=='ENOENT')throw error;}
    if(named)demand(valid(named),'execution journal identity is invalid');
    // Exclusive creation and named/held identity checks also reject aliases on
    // Windows, where O_NOFOLLOW does not supply the POSIX protection.
    const flags=constants.O_WRONLY|constants.O_APPEND|(constants.O_NOFOLLOW??0)|(named?0:constants.O_CREAT|constants.O_EXCL);
    const fd=openSync(filename,flags,0o600);
    try{
      const observed=fstatSync(fd,{bigint:true}),current=lstatSync(filename,{bigint:true});
      demand(valid(observed)&&valid(current)&&same(observed,current)&&(!named||same(named,observed)),'execution journal identity is invalid');
      const parent=lstatSync(root,{bigint:true});demand(parent.isDirectory()&&!parent.isSymbolicLink()&&parent.dev===info.dev&&parent.ino===info.ino&&realpathSync(root)===root,'execution journal parent changed');
      writeFileSync(fd,bytes);fsyncSync(fd);
      const after=fstatSync(fd,{bigint:true}),final=lstatSync(filename,{bigint:true});
      demand(valid(after)&&valid(final)&&same(after,final)&&after.dev===observed.dev&&after.ino===observed.ino&&after.size===observed.size+BigInt(bytes.length),'execution journal changed during append');
    }finally{closeSync(fd);}
  }
  return record;
}

export async function scheduledMaterialization(options, schedule, originalRoot, sandboxRoot) {
  demand(schedule?.tool === 'stryker' && schedule.tool_version === '10.1.1' && Array.isArray(schedule.mutants), 'trusted mutation schedule missing');
  const relative = safeRelative(path.relative(originalRoot, options.activeMutant.fileName).split(path.sep).join('/'));
  const sandbox = safeRelative(path.relative(sandboxRoot, options.sandboxFileName).split(path.sep).join('/'));
  demand(relative === sandbox, 'mutant source and sandbox target differ');
  const expected = schedule.mutants.find(item => item.id === `${relative}#${options.activeMutant.id}`);
  const definition = expected?.definition, active = options.activeMutant;
  demand(expected?.file === relative && definition && mutationDefinitionFingerprint(definition) === expected.definition_sha256 && definition.operator === active.mutatorName && definition.replacement === active.replacement && ['start', 'end'].every(end => ['line', 'column'].every(coordinate => definition.location?.[end]?.[coordinate] === active.location?.[end]?.[coordinate])), 'mutant differs from its exact pre-outcome definition');
  const filename = path.join(originalRoot, relative);
  demand(realpathSync(filename) === filename, 'original source contains a link');
  const bytes = readFileSync(filename), source = bytes.toString('utf8');
  demand(sha(bytes) === expected.source_sha256 && Buffer.from(source).equals(bytes), 'original source hash or UTF-8 differs from schedule');
  const materialized = await serializeScheduledMutation(source, definition, filename);
  const changed = Buffer.from(materialized.content);
  demand(changed.length <= 16 * 1024 * 1024, 'materialized program exceeds bound');
  demand(/^[a-f0-9]{64}$/.test(expected.definition_sha256), 'scheduled definition fingerprint missing');
  return { path: relative, before_sha256: expected.source_sha256, after_sha256: sha(changed), definition_sha256: expected.definition_sha256, materializer_version: materialized.materializer_version, serialized_replacement: materialized.serialized_replacement, size: changed.length, content_base64: changed.toString('base64') };
}

export class ProtectedVitestTestRunner {
  static inject = [commonTokens.options, commonTokens.logger];
  constructor(options, logger) { this.options = options; this.logger = logger; this.sequence = 0; this.pending = null; this.buffer = Buffer.alloc(0); this.selectionBaselines = new Map(); }
  capabilities() { return { reloadEnvironment: true }; }
  async init() {
    demand(process.platform === 'linux' && process.arch === 'arm64' && process.getuid?.() === 0, 'native ARM64 OCI supervisor required; host mutation execution is refused');
    demand(['off', 'perTest'].includes(this.options.coverageAnalysis) && this.options.disableBail === true && this.options.incremental === false && this.options.inPlace === false && this.options.disableTypeChecks === false, 'full nonincremental tests required');
    const root = realpathSync(process.cwd());
    demand(root.startsWith('/state/'), 'source sandbox must belong to the owned state volume');
    this.originalRoot = realpathSync(process.env.UD_STRYKER_SOURCE_ROOT ?? '');
    demand(this.originalRoot.startsWith('/state/') && root.startsWith(`${this.originalRoot}/`), 'original source root is not the owned mutation input');
    const runtime = JSON.parse(readFileSync('/opt/mutation/input-receipt.json', 'utf8'));
    const nodeClosure = runtime.node_dependencies, closurePath = '/opt/mutation/node-dependencies.json';
    const closureInfo = lstatSync(closurePath);
    demand(nodeClosure?.path === 'node-dependencies.json' && Number.isSafeInteger(nodeClosure.size_bytes) && nodeClosure.size_bytes > 0 && nodeClosure.size_bytes <= 32 * 1024 ** 2 && closureInfo.isFile() && !closureInfo.isSymbolicLink() && closureInfo.nlink === 1 && closureInfo.uid === 0 && !(closureInfo.mode & 0o222) && closureInfo.size === nodeClosure.size_bytes, 'assertion SDK closure differs from immutable runtime authority');
    const closureBytes = readFileSync(closurePath);
    demand(closureBytes.length === nodeClosure.size_bytes && sha(closureBytes) === nodeClosure.sha256, 'assertion SDK closure bytes changed');
    const derivation=runtime.node_assertion_sdk;
    demand(derivation,'source-bound assertion SDK derivation is required');
    const receiptBytes=immutableImageBytes(derivation.receipt,1024**2),receipt=JSON.parse(receiptBytes),current=receipt.derived;
    verifyProtectedAssertionSdkEvidence(runtime,{receiptBytes,originalBytes:immutableImageBytes(derivation.upstream_source,1024**2),upstreamBytes:immutableImageBytes(derivation.upstream_dependencies,32*1024**2),closureBytes,
      currentBytes:immutableImageBytes({path:'node_modules/'+STRYKER_ASSERTION_SDK_FILE,sha256:current?.sha256,size_bytes:current?.size_bytes},1024**2),
      serializerOriginalBytes:immutableImageBytes(derivation.serializer_upstream_source,1024**2),serializerCurrentBytes:immutableImageBytes({path:'node_modules/'+STRYKER_ASSERTION_SERIALIZER_FILE,sha256:receipt.serializer?.derived?.sha256,size_bytes:receipt.serializer?.derived?.size_bytes},1024**2),
      chaiOriginalBytes:immutableImageBytes(derivation.chai_upstream_source,1024**2),chaiCurrentBytes:immutableImageBytes({path:'node_modules/'+STRYKER_ASSERTION_CHAI_FILE,sha256:receipt.chai?.derived?.sha256,size_bytes:receipt.chai?.derived?.size_bytes},1024**2)});
    this.immutableSdkContext = { schema_version: 1, root: '/opt/mutation/node_modules', receipt_sha256: nodeClosure.sha256 };
    for (const filename of [BRIDGE, '/opt/mutation/harness/stryker-child.mjs', '/opt/mutation/harness/stryker-config.mjs', '/opt/mutation/harness/stryker-opacity.mjs', '/opt/mutation/harness/stryker-baseline-authority.mjs', '/opt/mutation/harness/stryker-assertions.mjs', '/opt/mutation/harness/stryker-assertion-setup.mjs', '/opt/mutation/harness/stryker-native-assertions.cjs', '/opt/mutation/harness/stryker-assertion-sdk.mjs', '/opt/mutation/harness/oci-exec.py']) {
      const info = lstatSync(filename), expected = runtime.harness.find(item => item.path === path.basename(filename));
      demand(info.isFile() && info.uid === 0 && !(info.mode & 0o222) && sha(readFileSync(filename)) === expected?.sha256, 'immutable execution harness differs from image receipt');
    }
    const helper = runtime.native_guard, helperPath = '/opt/mutation/bin/ud-agent-guard';
    demand(helper?.path === 'bin/ud-agent-guard' && /^[a-f0-9]{64}$/.test(helper.sha256) && Number.isSafeInteger(helper.size_bytes) && helper.size_bytes > 0 && helper.size_bytes <= 64 * 1024 * 1024, 'native fixture input receipt missing');
    const info = lstatSync(helperPath);
    demand(info.isFile() && !info.isSymbolicLink() && info.uid === 0 && !(info.mode & 0o222) && info.size === helper.size_bytes, 'immutable native fixture input differs from receipt');
    this.helperBytes = readFileSync(helperPath); this.helperSha256 = helper.sha256;
    demand(sha(this.helperBytes) === this.helperSha256, 'immutable native fixture input hash differs');
    this.workspace = sandboxInventory(root);
    const evidence=process.env.UD_STRYKER_EVIDENCE;
    demand(typeof evidence==='string'&&path.isAbsolute(evidence),'trusted evidence directory missing');
    for(const name of readdirSync(evidence)){
      const match=/^stryker-(?:baseline|mutant)-([1-9][0-9]{0,15})\.json(?:\.gz)?$/.exec(name);
      if(match){const value=Number(match[1]);demand(Number.isSafeInteger(value)&&value<Number.MAX_SAFE_INTEGER,'invocation evidence identity overflow');this.sequence=Math.max(this.sequence,value);}
    }
    const restored=restorePristineAuthority(evidence,{sourceTreeSha256:process.env.UD_MUTATION_SNAPSHOT_SHA256,sourceRoot:root,sdkContext:this.immutableSdkContext,sourceInventory:Object.fromEntries(this.workspace.files.filter(item=>item.path.startsWith('tests/')).map(item=>[item.path,item.sha256]))});
    if(restored){this.fullTests=restored.tests;this.coverage=restored.coverage;this.originalBaseline=restored.baseline;this.assertionCompiledSources=restored.compiledSources;}
    this.child = spawn(PYTHON, [BRIDGE, '--state', '/state', '--source-root', root], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/opt/mutation/bin:/opt/mutation/node/bin:/opt/mutation/python/bin:/usr/bin:/bin', LANG: 'C.UTF-8', PYTHONDONTWRITEBYTECODE: '1', ...(process.env.UD_MUTATION_GUARD ? { UD_MUTATION_GUARD: process.env.UD_MUTATION_GUARD } : {}) } });
    this.child.stderr.on('data', chunk => this.logger.debug(String(chunk).slice(0, 4096)));
    this.child.stdin.on('error', error => this.fail(error));
    this.child.stdout.on('data', chunk => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (this.buffer.length > MAX_FRAME) return this.fail(new Error('Protected Stryker bridge frame exceeds bound.'));
      let end;
      while ((end = this.buffer.indexOf(10)) >= 0) {
        const bytes = this.buffer.subarray(0, end); this.buffer = this.buffer.subarray(end + 1);
        try {
          const response = bridgeResponse(bytes, this.pending?.id);
          const pending = this.pending; this.pending = null; clearTimeout(pending.timer);
          if (response.error) pending.reject(new Error(response.error)); else pending.resolve(response);
        } catch (error) { this.fail(error); }
      }
    });
    this.child.once('error', error => this.fail(error));
    this.child.once('close', (code, signal) => { this.closed = true; clearTimeout(this.killTimer); if (this.pending || this.buffer.length) this.fail(this.failed ?? new Error(`Protected Stryker controller closed prematurely (${code}/${signal}).`)); });
    this.onExit = () => this.child?.kill('SIGTERM');
    process.once('exit', this.onExit);
  }
  fail(error) {
    this.failed ??= error;
    if (this.pending) clearTimeout(this.pending.timer);
    if (this.closed || !this.child) {
      if (this.pending) { this.pending.reject(this.failed); this.pending = null; }
    } else if (!this.stopping) {
      this.stopping = true;
      this.child.stdin.end(); this.child.kill('SIGTERM');
      // The controller first cancels and reaps its exact job. A forced controller
      // exit remains a runner failure; the outer owner must reconcile its journal.
      this.killTimer = setTimeout(() => { this.forcedControllerExit = true; this.child.kill('SIGKILL'); }, 15000);
    }
  }
  async invoke(kind, options, selection = null) {
    demand(this.child && !this.closed && !this.pending && !this.failed, 'execution controller unavailable or concurrent');
    demand(options.disableBail === true && !options.testFiles?.length && !options.hitLimit && (!options.testFilter?.length || this.options.coverageAnalysis === 'perTest' && selection), 'unbound filtered mutation execution refused');
    stageSandboxHelper(this.workspace.root, this.helperBytes, this.helperSha256);
    this.workspace = sandboxInventory(this.workspace.root);
    const directory = process.env.UD_STRYKER_EVIDENCE; demand(directory, 'trusted evidence directory missing');
    const schedule = kind === 'mutant' ? JSON.parse(readFileSync(path.join(directory, 'stryker-schedule.json'), 'utf8')) : null;
    const mutation = kind === 'mutant' ? await scheduledMaterialization(options, schedule, this.originalRoot, this.workspace.root) : null;
    const requestOptions = { timeout: protectedTimeout(options.timeout), disableBail: true, ...(kind === 'dry-run' ? { coverageAnalysis: this.options.coverageAnalysis } : kind === 'selection-baseline' ? {} : { activeMutant: { id: String(options.activeMutant.id) }, mutantActivation: options.mutantActivation, reloadEnvironment: true, sandboxFileName: safeRelative(path.relative(this.workspace.root, options.sandboxFileName).split(path.sep).join('/')) }), ...(selection ? { selection } : {}) };
    if(kind!=='dry-run'&&!this.assertionCompiledSources){
      const restored=restorePristineAuthority(directory,{sourceTreeSha256:process.env.UD_MUTATION_SNAPSHOT_SHA256,sourceRoot:this.workspace.root,sdkContext:this.immutableSdkContext,sourceInventory:Object.fromEntries(this.workspace.files.filter(item=>item.path.startsWith('tests/')).map(item=>[item.path,item.sha256]))});
      if(restored){this.fullTests=restored.tests;this.coverage=restored.coverage;this.originalBaseline=restored.baseline;this.assertionCompiledSources=restored.compiledSources;}
    }
    if(kind!=='dry-run')demand(this.assertionCompiledSources,'original compiled assertion authority is required before any variant execution');
    const id = String(++this.sequence), request = { schema_version: 1, id, kind, workspace: this.workspace, options: requestOptions, ...(kind!=='dry-run'?{assertion_compiled_sources:this.assertionCompiledSources}:{}), ...(mutation ? { mutation } : {}) };
    const frame = Buffer.from(JSON.stringify(request) + '\n'); demand(frame.length <= MAX_FRAME, 'source handoff exceeds frame bound');
    const response = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(new Error('Protected Stryker controller timed out.')), Math.min(600000, Math.max(30000, requestOptions.timeout + 45000)));
      this.pending = { id, resolve, reject, timer }; this.child.stdin.write(frame, error => { if (error) this.fail(error); });
    });
    const completed=response.execution?.status===0&&response.execution.timed_out===false&&response.execution.owned_descendants_cancelled?.length===0;
    const bytes = Buffer.from(response.result_base64, 'base64');
    demand(bytes.length === response.result_size && sha(bytes) === response.result_sha256, 'isolated result bytes differ from verified harvest');
    const {report,baselineReceipt,mutantReceipt}=retainHarvestedReport(directory,id,kind,bytes,response.execution,this.immutableSdkContext);
    if(!completed){
      // Preserve the exact harvested report before rejecting it. A controlled
      // runtime failure remains an error, never a kill or an excuse to discard
      // its original assertion-origin/cleanup diagnostics.
      return{status:response.execution?.timed_out?'timeout':'error',errorMessage:'Isolated process did not finish cleanly: '+JSON.stringify({execution_status:response.execution?.status,result:report.result,failures:report.failures}).slice(0,65536)};
    }
    if (mutation) demand(report.materialization?.path === mutation.path && report.materialization.before_sha256 === mutation.before_sha256 && report.materialization.after_sha256 === mutation.after_sha256 && report.materialization.materializer_version === mutation.materializer_version && report.materialization.serialized_replacement === mutation.serialized_replacement && report.materialization.size === mutation.size, 'isolated mutation identity differs from scheduled program');
    const sourceInventory = Object.fromEntries(this.workspace.files.filter(item => item.path.startsWith('tests/')).map(item => [item.path, item.sha256]));
    const compiledSources=kind==='dry-run'?report.assertion_compiled_sources:this.assertionCompiledSources;
    demand(report.assertion_compiled_sources?.child_root===report.child_root,'compiled assertions identify another private execution tree');
    verifyCompiledSources(compiledSources,report.assertion_compiled_sources,{sourceRoot:this.workspace.root,sourceInventory});
    const verifyAssertion = await createStrykerAssertionVerifier({ sourceRoot: this.workspace.root, childRoot: report.child_root, sourceInventory, immutableSdkContext: this.immutableSdkContext,compiledSources });
    const normalized = normalizeProtectedReport(report, this.workspace.root, selection?.cases ?? schedule?.tests, selection, verifyAssertion);
    requireCompiledTestCases(report.assertion_compiled_sources,normalized.tests);
    if (kind === 'dry-run' && normalized.result.status === 'complete') {
      this.fullTests = normalized.tests.map(({ id, source, source_sha256, name, occurrence, upstream_id }) => ({ id, source, source_sha256, name, occurrence, upstream_id }));
      this.coverage = normalized.result.mutantCoverage;
      this.originalBaseline = baselineReceipt;
      this.assertionCompiledSources=compiledSources;
      if (this.options.coverageAnalysis === 'perTest') {
        demand(this.coverage?.contract === 'pristine-per-test-coverage-v1', 'complete pristine coverage is missing');
        demand(JSON.stringify(this.coverage.opacity)===JSON.stringify(normalizeSubprocessOpacity(report.subprocess_opacity,report.tests)),'pristine coverage opacity differs from actual original task observations');
      }
      retainPristineAuthority(directory,{sourceTreeSha256:process.env.UD_MUTATION_SNAPSHOT_SHA256,baseline:baselineReceipt,sdkContext:this.immutableSdkContext});
    }
    if (kind === 'selection-baseline') {
      demand(normalized.result.status === 'complete', 'unmutated selected baseline did not pass');
      this.selectionBaselines.set(selection.sha256, baselineReceipt);
    }
    if (kind === 'mutant') for (const failure of normalized.failures) appendFileSync(path.join(directory, 'stryker-test-failures.jsonl'), JSON.stringify({ ...failure, mutant_id: String(options.activeMutant.id) }) + '\n', { mode: 0o600 });
    if (mutation) appendFileSync(path.join(directory, 'stryker-materializations.jsonl'), JSON.stringify({ mutant_id: String(options.activeMutant.id), ...report.materialization, definition_sha256: mutation.definition_sha256, uid: response.execution.uid, elapsed_seconds: response.execution.elapsed_seconds }) + '\n', { mode: 0o600 });
    if (mutation) retainProtectedExecution(directory,{ schema_version: 1, mutant_id: String(options.activeMutant.id), definition_sha256: mutation.definition_sha256, selection: selection ?? null, original_baseline: this.originalBaseline, selected_baseline: selection ? this.selectionBaselines.get(selection.sha256) : null, mutant_report: mutantReceipt, execution: response.execution.execution_id, uid: response.execution.uid, required_tests_completed: normalized.tests.length });
    return normalized.result.status === 'complete' ? { ...normalized.result, ...(this.options.coverageAnalysis === 'perTest' && normalized.result.mutantCoverage ? { mutantCoverage: { static: normalized.result.mutantCoverage.static, perTest: normalized.result.mutantCoverage.perTest } } : {}), tests: normalized.result.tests.map(test => ({ ...test, fileName: path.join(this.originalRoot, test.source) })) } : normalized.result;
  }
  dryRun(options) { return this.invoke('dry-run', options); }
  async mutantRun(options) {
    if (this.options.coverageAnalysis !== 'perTest') return this.invoke('mutant', options);
    demand(this.originalBaseline && this.fullTests?.length && this.coverage, 'pristine baseline authority missing');
    const schedule = JSON.parse(readFileSync(path.join(process.env.UD_STRYKER_EVIDENCE, 'stryker-schedule.json'), 'utf8'));
    const policy = schedule.execution_policy;
    demand(policy?.schema_version === 1 && policy.kind === 'pristine-per-test-with-conservative-full-fallback' && policy.unattributed_full_suite === true && policy.hit_limits === 'disabled' && policy.fresh_environment === true && policy.opaque_executions==='all-observed-cases-and-file-fixtures;global-uncertainty-full-suite' && policy.test_source_preprocessing==='disabled' && Array.isArray(policy.fallback_mutant_ids), 'pre-outcome mutation execution policy is missing');
    const fallback = policy.fallback_mutant_ids.includes(String(options.activeMutant.id));
    const selected = protectedCoverageSelection(String(options.activeMutant.id), this.coverage, this.fullTests, { unattributedFullSuite: fallback, requireOpacity:true });
    demand(!fallback || selected.strategy === 'unattributed-original-full-suite', 'full fallback contradicts measured original coverage');
    const selection = { ...selected, all_cases: this.fullTests, baseline_sha256: this.originalBaseline.result.sha256, coverage_sha256: sha(JSON.stringify(this.coverage)) };
    if (!this.selectionBaselines.has(selection.sha256)) await this.invoke('selection-baseline', { timeout: 540000, disableBail: true }, selection);
    const measured = this.selectionBaselines.get(selection.sha256).execution.elapsed_seconds;
    demand(typeof measured === 'number' && Number.isFinite(measured) && measured >= 0, 'selected original baseline timing is missing');
    return this.invoke('mutant', { ...options, timeout: Math.min(540000, Math.max(options.timeout, Math.ceil(measured * 2000 + 30000))) }, selection);
  }
  async dispose() {
    if (this.onExit) process.removeListener('exit', this.onExit);
    if (!this.child || this.closed) return;
    const active = this.pending !== null;
    // Upstream also disposes after its own deadline. Close the control lease
    // and unwind through the fixed controller's exact UID/job cleanup.
    if (active) this.fail(new Error('Protected Stryker invocation cancelled during disposal.'));
    else this.child.stdin.end();
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.forcedControllerExit = true; this.child.kill('SIGKILL'); reject(new Error('Protected Stryker controller failed to close.')); }, active ? 20000 : 10000);
      this.child.once('close', (code, signal) => {
        clearTimeout(timer);
        if (this.forcedControllerExit || signal || !(active ? [0, 1] : [0]).includes(code)) reject(new Error('Protected Stryker controller did not finish owned disposal cleanly.'));
        else resolve();
      });
    });
  }
}

export const strykerPlugins = [declareClassPlugin(PluginKind.TestRunner, 'ud-protected-vitest', ProtectedVitestTestRunner)];
