/** Run discovered Python mutants in a native ARM64 OCI job with private test UIDs. */
import { closeSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { assertProtectedMutationSources, diagnosticStrykerScope, localDockerAuthority } from './mutation-scope.mjs';
import { STRYKER_ASSERTION_SDK_FILE, STRYKER_ASSERTION_SERIALIZER_FILE, STRYKER_ASSERTION_CHAI_FILE } from './stryker-assertion-sdk.mjs';
import { verifyRecordedStrykerSdk } from './stryker-sdk-evidence.mjs';
import { sourceReceipt } from '../release/candidate.mjs';
import { mutationStoragePlan, reserveStorage } from './storage-lifecycle.mjs';
import { inspectOwnedDockerStorage, lockedDockerImages } from './docker-owned-storage.mjs';

const args = process.argv.slice(2);
if (!args.length) throw new Error('Usage: oci-python-diagnostic.mjs NEW_OUTPUT [--image LOCAL_IMAGE] [--backend BACKEND] [--file SOURCE] [--mutant-filter GLOB] [--diagnostic-stryker-range SOURCE:LINE:COLUMN-LINE:COLUMN]');
const output = path.resolve(args.shift());
const files = [], filters = [];
let image = 'localhost/ud-agent-mutation-runtime:arm64-final3';
let backend = 'python';
let inventoryOnly = false;
let sourceRoot = process.cwd();
let diagnosticStrykerRange;
let frozenPlan;
for (let index = 0; index < args.length;) {
  const flag = args[index++];
  if(flag==='--inventory-only'){if(inventoryOnly)throw Error('Repeated inventory-only option.');inventoryOnly=true;continue;}
  const value = args[index++];
  if (!value || !['--image', '--source-root', '--backend', '--file', '--mutant-filter', '--diagnostic-stryker-range', '--frozen-plan'].includes(flag)) throw new Error('Invalid protected mutation arguments.');
  if (flag === '--image') image = value;
  else if (flag === '--backend') { if (!['python','perl','typescript','python-static','faults','rust','catalog'].includes(value)) throw new Error('Unknown protected mutation backend.'); backend=value; }
  else if (flag === '--source-root') sourceRoot=path.resolve(value);
  else if (flag === '--frozen-plan') { if (frozenPlan) throw new Error('Repeated frozen plan.'); frozenPlan = path.resolve(value); }
  else if (flag === '--diagnostic-stryker-range') { if (diagnosticStrykerRange !== undefined) throw new Error('Repeated diagnostic Stryker range.'); diagnosticStrykerRange = value; }
  else (flag === '--file' ? files : filters).push(value);
}
if (frozenPlan && (inventoryOnly || files.length || filters.length || diagnosticStrykerRange)) throw new Error('Frozen execution requires an unfiltered full backend.');
if (backend === 'catalog' && (!inventoryOnly || files.length || filters.length || frozenPlan)) throw new Error('Protected catalog is complete collection only.');
if (diagnosticStrykerRange !== undefined && (backend !== 'typescript' || files.length || filters.length || inventoryOnly)) throw new Error('A diagnostic Stryker range is exclusive to the TypeScript backend.');
const actionsOwner = process.env.UD_AGENT_LOCAL_ACTIONS_OWNER;
if (actionsOwner !== undefined && !/^[a-f0-9]{32}$/.test(actionsOwner)) throw new Error('Local Actions owner is invalid.');
const owner = randomUUID(), label = `io.github.mehmetoguzderin.ud-agent.mutation=${owner}`;
const labelArgs = ['--label', label, ...(actionsOwner ? ['--label', 'io.github.mehmetoguzderin.ud-agent.act-owner=' + actionsOwner] : [])];
const names = { input: `ud-mutation-input-${owner}`, state: `ud-mutation-state-${owner}`, carrier: `ud-mutation-input-${owner}`, job: `ud-mutation-job-${owner}` };
const root = sourceRoot;
const sourcePlan = sourceReceipt(root);
assertProtectedMutationSources(backend, files, sourcePlan.files);
const dockerAuthority = localDockerAuthority(process.env, context => docker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', ...(context ? [context] : [])]).trim());
const inspected = JSON.parse(docker(['image', 'inspect', image]))[0];
if (inspected.Os !== 'linux' || inspected.Architecture !== 'arm64' || !/^sha256:[a-f0-9]{64}$/.test(inspected.Id)) throw new Error('Protected local mutation runner must be native Linux ARM64.');
const imageId = inspected.Id;
if (!Number.isSafeInteger(inspected.Size) || inspected.Size < 0) throw new Error('Protected mutation image byte size is missing.');
const imageBytes = process.env.UD_STORAGE_LEASE ? inspected.Size : inspectOwnedDockerStorage(docker, { selectedImages: [{ image_id: imageId, size_bytes: inspected.Size }], knownImageIds: lockedDockerImages(JSON.parse(readFileSync(path.join(root, 'runtime/runtime.lock.json'), 'utf8'))), ...(actionsOwner ? { activeActionsOwner: actionsOwner } : {}) }).image_bytes;
const artifactIndex = root.split(path.sep).indexOf('.artifacts');
const storageRoot = process.env.UD_AGENT_STORAGE_ROOT ?? (artifactIndex < 0 ? root : root.split(path.sep).slice(0, artifactIndex).join(path.sep) || path.sep);
const storagePlan = mutationStoragePlan(sourcePlan.files.reduce((sum, row) => sum + row.size, 0), sourcePlan.files.length);
let stopActive, finishStorage;
const storageFinished = new Promise(resolve => { finishStorage = resolve; });
const storage = reserveStorage({
  root: storageRoot, externalOwnedBytes: imageBytes, plannedBytes: storagePlan.plannedBytes, profile: storagePlan.profile,
  transientAllowance: storagePlan.transientAllowance, label: 'protected-mutation', inputRoots: [root],
  onCancel: async () => { if (stopActive) { stopActive(); await storageFinished; } },
});
mkdirSync(output, { recursive: true, mode: 0o700 });
const snapshot = { schema_version: 1, qualification: 'diagnostic-only', source_tree_sha256: sourcePlan.sha256, source: root, copy: root, files: sourcePlan.files, mutation_writes: 'copy-only' };
writeFileSync(path.join(output, 'snapshot.json'), JSON.stringify(snapshot, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
writeFileSync(path.join(output,'source-snapshot.json'),JSON.stringify(snapshot,null,2)+'\n',{flag:'wx',mode:0o600});
assertProtectedMutationSources(backend,files,snapshot.files);
const diagnosticScope = diagnosticStrykerRange === undefined ? undefined : diagnosticStrykerScope(diagnosticStrykerRange, snapshot.files, snapshot.source_tree_sha256, name => readFileSync(path.join(snapshot.copy, name)));
if (diagnosticScope) writeFileSync(path.join(output, 'diagnostic-scope.json'), JSON.stringify(diagnosticScope, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
function docker(parameters, options = {}) {
  const result = spawnSync('docker', parameters, { encoding: 'utf8', maxBuffer: 8 * 1024 ** 2, timeout: 120_000, ...options });
  if (result.error || result.status !== 0) throw new Error(`Docker ${parameters[0]} failed: ${result.error?.message ?? result.stderr ?? result.status}`);
  return result.stdout;
}
const journal = { schema_version: 1, qualification: 'diagnostic-only', backend, owner, image: imageId, source_tree_sha256: snapshot.source_tree_sha256,
  ...(diagnosticScope ? { qualification: 'selected-diagnostic', scope_complete: false, diagnostic_scope: diagnosticScope } : {}),
  ...(files.length || filters.length ? { qualification: 'selected-diagnostic', scope_complete: false, diagnostic_scope: { schema_version: 1, kind: 'selected-backend-diagnostic', scope_complete: false, source_tree_sha256: snapshot.source_tree_sha256, files, mutant_filters: filters } } : {}),
  inventory_only: inventoryOnly, ...(actionsOwner ? { actions_owner: actionsOwner } : {}),
  host: { platform: process.platform, architecture: process.arch }, worker: { platform: 'linux', architecture: 'arm64', provider: 'local-docker', emulation: false },
  isolation: { network: 'none', host_writable_mounts: [], source_handoff: 'owned-read-only-volume', tests: 'unique-uid-no-caps-Landlock-own-job-only' },
  docker_endpoint: dockerAuthority, resources: names, status: 'preparing', cleanup: [] };
const workerMemoryGiB = backend === 'rust' ? 2 : 3;
const workerMemory = `${workerMemoryGiB}g`;
const temporaryBytes = 2 * 1024 ** 3;
journal.resource_limits = { cpus: 2, memory_bytes: workerMemoryGiB * 1024 ** 3, processes: 256, temporary_bytes: temporaryBytes };
const evidenceProgram = readFileSync(new URL('./mutation-evidence.py', import.meta.url), 'utf8');
function inspectEvidence() {
  return JSON.parse(docker(['run', '--rm', '--name', names.job + '-evidence', '--pull=never', ...labelArgs, '--network', 'none', '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '64m', '--cpus', '0.25', '--mount', `type=volume,src=${names.state},dst=/state,readonly`, '--entrypoint', '/opt/mutation/python/bin/python3', imageId, '-I', '-S', '-c', evidenceProgram, '/state']));
}
function save() { writeFileSync(path.join(output, 'runner.json'), JSON.stringify(journal, null, 2) + '\n'); }
save();
let exitCode = 1;
try {
  for (const volume of [names.input, names.state]) docker(['volume', 'create', ...labelArgs, volume]);
  docker(['create', '--pull=never', '--name', names.carrier, ...labelArgs, '--network', 'none', '--mount', `type=volume,src=${names.input},dst=/input`, '--entrypoint', '/bin/true', imageId]);
  // Stream only receipted files into Docker; there is no second host source
  // snapshot or retained tarball. The worker rechecks every input hash.
  const python = process.env.UD_MUTATION_PYTHON ?? process.env.UD_AGENT_PYTHON ?? 'python3';
  const producer = spawn(python, ['-I', '-S', new URL('./stream-mutation-source.py', import.meta.url).pathname, root, path.join(output, 'snapshot.json')], { stdio: ['ignore', 'pipe', 'pipe'] });
  const consumer = spawn('docker', ['cp', '-', `${names.carrier}:/input`], { stdio: ['pipe', 'ignore', 'pipe'] });
  let streamError = '', streamFailure, forceStream;
  const stopStream = () => { producer.kill('SIGTERM'); consumer.kill('SIGTERM'); forceStream ??= setTimeout(() => { producer.kill('SIGKILL'); consumer.kill('SIGKILL'); }, 2000); forceStream.unref(); };
  stopActive = stopStream;
  const captureStreamError = chunk => { streamError += chunk.toString('utf8').slice(0, Math.max(0, 65536 - streamError.length)); };
  producer.stderr.on('data', captureStreamError); consumer.stderr.on('data', captureStreamError);
  consumer.stdin.on('error', error => { if (error.code !== 'EPIPE') streamFailure ??= error; producer.kill('SIGTERM'); });
  producer.stdout.pipe(consumer.stdin);
  const completed = child => new Promise(resolve => { child.once('error', error => resolve({ error })); child.once('close', (status, signal) => resolve({ status, signal })); });
  const streamTimeout = setTimeout(() => { streamFailure ??= new Error('Mutation source streaming timed out.'); stopStream(); }, 10 * 60 * 1000);
  let results;
  try { results = await Promise.all([completed(producer), completed(consumer)]); }
  finally { clearTimeout(streamTimeout); clearTimeout(forceStream); stopActive = undefined; }
  if (streamFailure || results.some(result => result.error || result.signal || result.status !== 0)) throw new Error('Verified source streaming failed: ' + (streamFailure?.message ?? streamError.slice(-2000)));
  if (sourceReceipt(root).sha256 !== snapshot.source_tree_sha256) throw new Error('Mutation source changed during transfer.');
  docker(['cp', path.join(output, 'snapshot.json'), `${names.carrier}:/input/snapshot.json`]);
  docker(['cp', `${names.carrier}:/opt/mutation/input-receipt.json`, path.join(output, 'runtime-input-receipt.json')]);
  const runtime = JSON.parse(readFileSync(path.join(output, 'runtime-input-receipt.json'), 'utf8'));
  if (frozenPlan) {
    const info = lstatSync(frozenPlan);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 128 * 1024 ** 2) throw new Error('Frozen schedule is not a bounded ordinary file.');
    const bytes = readFileSync(frozenPlan), authority = JSON.parse(bytes);
    if (authority.schema_version !== 1 || authority.image_id !== imageId || authority.runtime_sha256 !== createHash('sha256').update(readFileSync(path.join(output, 'runtime-input-receipt.json'))).digest('hex') || authority.plan?.backend !== backend || authority.plan.source_tree_sha256 !== snapshot.source_tree_sha256) throw new Error('Frozen schedule source, backend, image or SDK differs.');
    journal.frozen_plan_sha256 = createHash('sha256').update(bytes).digest('hex');
    docker(['cp', frozenPlan, `${names.carrier}:/input/frozen-plan.json`]);
  }
  if (runtime.package_lock_sha256 !== createHash('sha256').update(readFileSync(path.join(root, 'package-lock.json'))).digest('hex')) throw new Error('Mutation OCI dependency lock is stale.');
  const closure = runtime.node_dependencies;
  if (closure?.path !== 'node-dependencies.json' || !/^[a-f0-9]{64}$/.test(closure.sha256 ?? '') || !Number.isSafeInteger(closure.size_bytes) || closure.size_bytes < 1 || closure.size_bytes > 32 * 1024 ** 2) throw new Error('Mutation assertion SDK closure authority is invalid.');
  const closurePath = path.join(output, 'runtime-node-dependencies.json');
  docker(['cp', `${names.carrier}:/opt/mutation/node-dependencies.json`, closurePath]);
  const closureInfo = lstatSync(closurePath);
  if (!closureInfo.isFile() || closureInfo.isSymbolicLink() || closureInfo.size !== closure.size_bytes || createHash('sha256').update(readFileSync(closurePath)).digest('hex') !== closure.sha256) throw new Error('Mutation assertion SDK closure bytes differ from immutable image receipt.');
  if (backend === 'typescript' || runtime.node_assertion_sdk) {
    for (const name of ['node-installation-receipt.json', 'node-assertion-sdk.json', 'node-assertion-sdk-upstream.js', 'node-assertion-sdk-serializer-upstream.js', 'node-assertion-sdk-chai-upstream.js', 'node-upstream-dependencies.json']) docker(['cp', `${names.carrier}:/opt/mutation/${name}`, path.join(output, 'runtime-' + name)]);
    docker(['cp', `${names.carrier}:/opt/mutation/node_modules/${STRYKER_ASSERTION_SDK_FILE}`, path.join(output, 'runtime-node-assertion-sdk-derived.js')]);
    docker(['cp', `${names.carrier}:/opt/mutation/node_modules/${STRYKER_ASSERTION_SERIALIZER_FILE}`, path.join(output, 'runtime-node-assertion-sdk-serializer-derived.js')]);
    docker(['cp', `${names.carrier}:/opt/mutation/node_modules/${STRYKER_ASSERTION_CHAI_FILE}`, path.join(output, 'runtime-node-assertion-sdk-chai-derived.js')]);
    verifyRecordedStrykerSdk(runtime, name => {
      const file = path.join(output, name), info = lstatSync(file);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 32 * 1024 ** 2) throw new Error('Derived assertion SDK export is unsafe.');
      return readFileSync(file);
    });
  }
  mkdirSync(path.join(output, 'verified-harness'), { mode: 0o700 });
  const requiredHarness=['mutmut-driver.py','python-runtime-projection.py','oci-isolation.py','oci-mutation.py','oci-exec.py','perl-test-runtime.py','python-operators.py','pytest_evidence.py'];
  if(backend==='typescript')requiredHarness.push('stryker-child.mjs','stryker-config.mjs','stryker-opacity.mjs','stryker-baseline-authority.mjs','stryker-assertions.mjs','stryker-assertion-setup.mjs','stryker-native-assertions.cjs','stryker-assertion-sdk.mjs','stryker-protected-runner.mjs','stryker-exec.py','oci-stryker.py','oci-secondary.py','secondary-child.py');
  if(['python-static','faults','catalog'].includes(backend))requiredHarness.push('oci-secondary.py','secondary-child.py','oci-stryker.py');
  if(backend==='catalog')requiredHarness.push('collect-mutation-tests.mjs');
  if(backend==='rust')requiredHarness.push('rust-literal.py','rust-protected.py','rust-test-runtime.py','rust-compile-child.py');
  const supportedHarness=new Set([...requiredHarness,'stryker-child.mjs','stryker-config.mjs','stryker-opacity.mjs','stryker-baseline-authority.mjs','stryker-assertions.mjs','stryker-assertion-setup.mjs','stryker-native-assertions.cjs','stryker-assertion-sdk.mjs','stryker-protected-runner.mjs','stryker-exec.py','oci-stryker.py','oci-secondary.py','secondary-child.py','collect-mutation-tests.mjs','rust-literal.py','rust-protected.py','rust-test-runtime.py','rust-compile-child.py']);
  if(!Array.isArray(runtime.harness)||runtime.harness.length!==supportedHarness.size||new Set(runtime.harness.map(item=>item.path)).size!==runtime.harness.length||runtime.harness.some(item=>!supportedHarness.has(item.path))||requiredHarness.some(name=>!runtime.harness.some(item=>item.path===name)))throw new Error('Mutation OCI harness inventory is incomplete or unsupported.');
  for (const {path:name} of runtime.harness) {
    const expected = runtime.harness?.find(item => item.path === name);
    const actual = path.join(output, 'verified-harness', name);
    docker(['cp', `${names.carrier}:/opt/mutation/harness/${name}`, actual]);
    if (lstatSync(actual).isSymbolicLink() || !lstatSync(actual).isFile() || createHash('sha256').update(readFileSync(actual)).digest('hex') !== expected?.sha256) throw new Error('Mutation OCI harness bytes differ from their receipt.');
    const source = path.join(root, name === 'pytest_evidence.py' ? 'tests/mutation' : 'scripts/quality', name);
    if (!expected || expected.sha256 !== createHash('sha256').update(readFileSync(source)).digest('hex')) throw new Error('Mutation OCI harness is stale; rebuild the runner image.');
  }
  const projectionSdk = runtime.python_runtime_projection;
  if (projectionSdk?.schema_version !== 1 || projectionSdk.version !== 'ud-python-inert-projection-1' || projectionSdk.distribution !== 'mutmut' || projectionSdk.distribution_version !== '3.8.1' || projectionSdk.helper_sha256 !== runtime.harness.find(item => item.path === 'python-runtime-projection.py')?.sha256 || projectionSdk.installed_path !== 'python/lib/python3.14/site-packages/mutmut/mutation/trampoline.py') throw new Error('Fixed Python projection SDK identity is missing or stale.');
  const originalMutmut = runtime.python_packages.find(item => item.name === 'mutmut' && item.version === '3.8.1');
  if (!originalMutmut || projectionSdk.original_wheel?.sha256 !== originalMutmut.hash?.replace(/^sha256:/, '') || projectionSdk.original_wheel.size_bytes !== originalMutmut.size || projectionSdk.original_wheel.filename !== originalMutmut.url?.split('/').at(-1)) throw new Error('Python projection SDK is not bound to the exact retained original wheel.');
  for (const [field, name] of [['upstream_source', 'python-trampoline-upstream.py'], ['adapter_source', 'python-trampoline-adapter.py'], ['derived_source', 'python-trampoline-derived.py']]) {
    const expected = projectionSdk[field];
    if (expected?.path !== name || !/^[a-f0-9]{64}$/.test(expected.sha256) || !Number.isSafeInteger(expected.size_bytes) || expected.size_bytes < 1 || expected.size_bytes > 1024 ** 2) throw new Error('Python projection SDK source receipt is malformed.');
    const actual = path.join(output, 'runtime-' + name);
    docker(['cp', `${names.carrier}:/opt/mutation/${name}`, actual]);
    const info = lstatSync(actual);
    if (!info.isFile() || info.isSymbolicLink() || info.size !== expected.size_bytes || createHash('sha256').update(readFileSync(actual)).digest('hex') !== expected.sha256) throw new Error('Python projection SDK source differs from its receipt.');
  }
  const installedProjection = path.join(output, 'runtime-python-trampoline-installed.py');
  docker(['cp', `${names.carrier}:/opt/mutation/${projectionSdk.installed_path}`, installedProjection]);
  if (lstatSync(installedProjection).size !== projectionSdk.derived_source.size_bytes || createHash('sha256').update(readFileSync(installedProjection)).digest('hex') !== projectionSdk.derived_source.sha256 || !readFileSync(path.join(output, 'runtime-python-trampoline-derived.py')).equals(Buffer.concat([readFileSync(path.join(output, 'runtime-python-trampoline-upstream.py')), readFileSync(path.join(output, 'runtime-python-trampoline-adapter.py'))]))) throw new Error('Installed Python projection SDK is not the exact original plus fixed adapter.');
  const command = ['create', '--pull=never', '--name', names.job, ...labelArgs, '--platform', 'linux/arm64', '--init', '--user', '0:0', '--network', 'none', '--read-only', '--cap-drop', 'ALL'];
  for (const cap of ['SETUID', 'SETGID', 'CHOWN', 'DAC_OVERRIDE', 'KILL', 'SETPCAP']) command.push('--cap-add', cap);
  command.push('--security-opt', 'no-new-privileges', '--cpus', '2', '--memory', workerMemory, '--pids-limit', '256', '--tmpfs', `/tmp:rw,exec,nosuid,nodev,size=${temporaryBytes}`,
    '--mount', `type=volume,src=${names.input},dst=/input,readonly`, '--mount', `type=volume,src=${names.state},dst=/state`, imageId, '--backend',backend,
    ...files.flatMap(file => ['--file', file]), ...filters.flatMap(filter => ['--mutant-filter', filter]),...(inventoryOnly?['--inventory-only']:[]),...(diagnosticStrykerRange ? ['--diagnostic-stryker-range', diagnosticStrykerRange] : []));
  journal.generator_argv=[...(inspected.Config.Entrypoint??[]),'--backend',backend,...files.flatMap(file=>['--file',file]),...filters.flatMap(filter=>['--mutant-filter',filter]),...(inventoryOnly?['--inventory-only']:[]),...(diagnosticStrykerRange ? ['--diagnostic-stryker-range', diagnosticStrykerRange] : [])];
  docker(command);
  journal.status = 'running'; save();
  const log = openSync(path.join(output, 'runner.log'), 'wx', 0o600);
  const child = spawn('docker', ['start', '--attach', names.job], { stdio: ['ignore', 'pipe', 'pipe'] });
  let logBytes = 0, interrupted = false, timedOut = false, logTruncated = false;
  let forceStop;
  const terminateChild = () => { child.kill('SIGTERM'); forceStop ??= setTimeout(() => child.kill('SIGKILL'), 5000); forceStop.unref(); };
  const stop = () => { interrupted = true; terminateChild(); };
  stopActive = stop;
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  const capture = chunk => { const retained = Math.min(chunk.length, Math.max(0, 16 * 1024 ** 2 - logBytes)); if (retained) { writeSync(log, chunk.subarray(0, retained)); logBytes += retained; } if (retained < chunk.length) logTruncated = true; };
  child.stdout.on('data', capture); child.stderr.on('data', capture);
  const timeout = setTimeout(() => { timedOut = true; terminateChild(); }, 12 * 60 * 60 * 1000);
  let result;
  try { result = await new Promise(resolve => { child.once('error', error => resolve({ status: null, error })); child.once('close', (status, signal) => resolve({ status, signal })); }); }
  finally { clearTimeout(timeout); clearTimeout(forceStop); closeSync(log); process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
  if (interrupted || timedOut || result.error || result.signal) {
    const [held] = JSON.parse(docker(['inspect', names.job]));
    if (held.Config?.Labels?.['io.github.mehmetoguzderin.ud-agent.mutation'] !== owner) throw new Error('Mutation cancellation ownership differs.');
    if (held.State.Running) docker(['kill', names.job]);
    result.error ??= new Error(timedOut ? 'Mutation worker timed out.' : 'Mutation worker was interrupted.');
  }
  journal.log_capture = { size_bytes: logBytes, truncated: logTruncated };
  journal.execution = { status: result.status, signal: result.signal, error: result.error?.message ?? null };
  const container = JSON.parse(docker(['inspect', names.job]))[0];
  journal.container_state = container.State;
  exitCode = result.error || result.signal ? 1 : container.State.ExitCode;
  // Only verified evidence leaves the owned state volume. Source copies,
  // compiler caches and generated variants are never retained as reports.
  const exporter = evidenceProgram;
  journal.evidence_exporter_sha256 = createHash('sha256').update(exporter).digest('hex');
  const exported = inspectEvidence();
  if (exported.schema_version !== 1 || exported.qualification !== 'bounded-required-mutation-evidence' || !Array.isArray(exported.files) || exported.files.length > 50000 || !Number.isSafeInteger(exported.size_bytes) || exported.size_bytes > 64 * 1024 ** 2) throw new Error('Mutation evidence inventory is invalid.');
  const seen = new Set(); let exportedBytes = 0;
  for (const row of exported.files) {
    if (typeof row.path !== 'string' || row.path.includes('\\') || row.path.includes('\0') || row.path.includes(':') || row.path.startsWith('/') || row.path.split('/').some(part => !part || part === '.' || part === '..') || seen.has(row.path) || !Number.isSafeInteger(row.size_bytes) || row.size_bytes < 0 || row.size_bytes > 16 * 1024 ** 2 || !/^[a-f0-9]{64}$/.test(row.sha256)) throw new Error('Mutation evidence member is invalid.');
    seen.add(row.path); exportedBytes += row.size_bytes;
    if (exportedBytes > exported.size_bytes) throw new Error('Mutation evidence exceeds its inventory.');
    const destination = path.join(output, row.path); mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
    docker(['cp', `${names.job}:/state/${row.path}`, destination]);
    const actual = lstatSync(destination);
    if (!actual.isFile() || actual.isSymbolicLink() || actual.size !== row.size_bytes || createHash('sha256').update(readFileSync(destination)).digest('hex') !== row.sha256) throw new Error('Mutation evidence export differs from its manifest.');
  }
  if (exportedBytes !== exported.size_bytes) throw new Error('Mutation evidence inventory size differs.');
  journal.evidence_export = { files: exported.files.length, size_bytes: exportedBytes, manifest_sha256: createHash('sha256').update(JSON.stringify(exported)).digest('hex') };
  writeFileSync(path.join(output, 'evidence-inventory.json'), JSON.stringify(exported, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  journal.status = exitCode === 0 ? 'executed-not-reconciled' : 'failed';
} catch (error) {
  journal.status = 'runner-error'; journal.error = error.message;
} finally {
  try {
    for (const mode of ['evidence', 'usage', 'input-usage']) {
    const exportName = names.job + '-' + mode;
    const held = docker(['ps', '-aq', '--filter', `name=^/${exportName}$`]).trim();
    if (held) {
      const [container] = JSON.parse(docker(['inspect', held]));
      if (container.Name !== '/' + exportName || container.Config?.Labels?.['io.github.mehmetoguzderin.ud-agent.mutation'] !== owner) throw new Error('Evidence exporter ownership differs.');
      docker(['rm', '--force', held]);
    }
    }
    journal.evidence_cleanup = 'verified';
  } catch (error) { journal.evidence_cleanup = 'failed'; journal.status = 'runner-error'; journal.error ??= error.message; exitCode = 1; }
  for (const [kind, name] of [['container', names.job], ['container', names.carrier], ['volume', names.state], ['volume', names.input]]) {
    try {
      const inspected = JSON.parse(docker([kind, 'inspect', name]))[0];
      const labels = kind === 'container' ? inspected.Config.Labels : inspected.Labels;
      if (labels?.['io.github.mehmetoguzderin.ud-agent.mutation'] !== owner) throw new Error('Cleanup ownership mismatch.');
      docker(kind === 'container' ? ['rm', '--force', name] : ['volume', 'rm', name]);
      journal.cleanup.push({ kind, name, status: 'removed-owned' });
    } catch (error) { journal.cleanup.push({ kind, name, status: 'failed-or-absent', detail: error.message }); }
  }
  if (journal.cleanup.some(item => item.status !== 'removed-owned')) {
    journal.status = 'runner-error'; journal.error ??= 'Owned mutation resources were not all verified removed.'; exitCode = 1;
  }
  try { storage.cleanup(); journal.scratch_cleanup = 'verified'; } catch (error) { journal.status = 'runner-error'; journal.scratch_cleanup = 'failed'; journal.error ??= error.message; exitCode = 1; }
  save(); finishStorage();
}
console.log(JSON.stringify({ output, status: journal.status, source_tree_sha256: snapshot.source_tree_sha256 }));
process.exit(exitCode);
