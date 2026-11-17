/** Freeze complete protected inventories, then reuse only exact backend evidence. */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync, renameSync, writeFileSync, createReadStream } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../release/http-transports.mjs';
import { fileReceipt, sourceReceipt } from '../release/candidate.mjs';
import { acceptanceInputHash, verifyLocalAcceptanceDiscovery } from '../release/discover-acceptance.mjs';
import { normalizeTests } from './normalize-schedule.mjs';
import { exportMutationSchedules } from './mutation-generation.mjs';
import { boundedMutationPolicy } from '../release/mutation-backends.mjs';

export const MUTATION_BACKENDS = Object.freeze(['faults', 'perl', 'typescript', 'python', 'python-static', 'rust']);
const sessionBackends = profile => profile === 'bounded' ? ['faults'] : MUTATION_BACKENDS;
const sessionQualification = profile => profile === 'bounded' ? 'frozen-bounded-protected-mutation-schedule-no-outcomes' : 'frozen-complete-protected-mutation-schedules-no-outcomes';
const TOOLS = { faults: 'fault-canary', perl: 'ppi-perl', typescript: 'stryker', python: 'mutmut', 'python-static': 'python-static', rust: 'cargo-mutants' };
const sha = value => createHash('sha256').update(value).digest('hex');
const insist = (value, message) => { if (!value) throw new Error('Mutation session: ' + message); };
const read = (file, max = 256 * 1024 ** 2) => { const info = lstatSync(file); insist(info.isFile() && !info.isSymbolicLink() && info.size <= max, 'bounded ordinary evidence required'); return JSON.parse(readFileSync(file, 'utf8')); };
function inside(root, value) { const name = path.relative(root, value); insist(name && !name.startsWith('..' + path.sep) && !path.isAbsolute(name), 'evidence escapes owned session'); return name.split(path.sep).join('/'); }
const atomic = (file, value) => { const temporary = file + '.' + randomUUID(); writeFileSync(temporary, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); renameSync(temporary, file); };
const COMPOSITION = 'freeze-composition.json';
function compositionAtDiscovery(root, source) {
  if (!existsSync(path.join(root, COMPOSITION))) return null;
  const value = read(path.join(root, COMPOSITION), 8 * 1024 ** 2);
  insist(value.schema_version === 1 && value.production_ready === false && ['available-target-inputs', 'local-candidate-inputs', 'diagnostic-partial-composition'].includes(value.qualification) && value.source_tree_sha256 === source.sha256, 'composition source binding is stale before discovery');
  return fileReceipt(root, COMPOSITION);
}

function verifyReceipt(root, expected) {
  const actual = fileReceipt(root, expected.path);
  insist(canonicalJson(actual) === canonicalJson(expected), 'seal lineage receipt changed');
  return actual;
}

function prepareCompositionSeal(root, directory, original, finalSourceSha256) {
  const before = original.composition;
  if (!before) { insist(!existsSync(path.join(root, COMPOSITION)), 'composition appeared after discovery'); return undefined; }
  insist(before.path === COMPOSITION && before.executable === false, 'composition receipt is invalid');
  const retained = path.join(directory, 'composition-before-seal.json');
  if (!existsSync(retained)) {
    verifyReceipt(root, before);
    writeFileSync(retained, readFileSync(path.join(root, COMPOSITION)), { flag: 'wx', mode: 0o400 });
  }
  const prior = fileReceipt(root, inside(root, retained));
  insist(prior.sha256 === before.sha256 && prior.size === before.size && prior.executable === false, 'prior composition bytes were not retained exactly');
  const value = read(retained, 8 * 1024 ** 2);
  insist(value.schema_version === 1 && value.production_ready === false && ['available-target-inputs', 'local-candidate-inputs', 'diagnostic-partial-composition'].includes(value.qualification) && value.source_tree_sha256 === original.source_sha256, 'prior composition source binding is stale');
  const lineage = { schema_version: 1, discovery: fileReceipt(root, inside(root, path.join(directory, 'session.json'))), discovery_source_sha256: original.source_sha256, input_sha256: original.input_sha256, inventory: original.inventory };
  const next = Buffer.from(JSON.stringify({ ...value, source_tree_sha256: finalSourceSha256, acceptance_inventory_seal: lineage }, null, 2) + '\n');
  const after = { path: COMPOSITION, sha256: sha(next), size: next.length, executable: false };
  const current = fileReceipt(root, COMPOSITION);
  insist(canonicalJson(current) === canonicalJson(before) || canonicalJson(current) === canonicalJson(after), 'composition changed outside the exact inventory seal');
  return { prior, before, after, lineage };
}

function verifyCompositionSeal(root, authority, repair = false) {
  const binding = authority.composition_binding;
  if (!binding) { insist(!existsSync(path.join(root, COMPOSITION)), 'composition appeared after the source-only seal'); return; }
  verifyReceipt(root, binding.prior); verifyReceipt(root, binding.lineage.discovery); verifyReceipt(root, binding.lineage.inventory);
  const previous = read(path.join(root, binding.prior.path), 8 * 1024 ** 2);
  insist(previous.source_tree_sha256 === authority.discovery_source_sha256 && binding.lineage.discovery_source_sha256 === authority.discovery_source_sha256 && binding.lineage.input_sha256 === authority.input_sha256 && canonicalJson(binding.lineage.inventory) === canonicalJson(authority.inventory), 'composition seal lineage differs');
  const next = Buffer.from(JSON.stringify({ ...previous, source_tree_sha256: authority.source_sha256, acceptance_inventory_seal: binding.lineage }, null, 2) + '\n');
  insist(binding.after.path === COMPOSITION && binding.after.sha256 === sha(next) && binding.after.size === next.length && binding.after.executable === false, 'composition seal derivation differs');
  const current = fileReceipt(root, COMPOSITION);
  if (repair && canonicalJson(current) === canonicalJson(binding.before)) {
    const temporary = path.join(root, COMPOSITION + '.' + randomUUID()); writeFileSync(temporary, next, { flag: 'wx', mode: 0o600 }); renameSync(temporary, path.join(root, COMPOSITION));
  }
  verifyReceipt(root, binding.after);
}

/** Local replay binds the actual protected providers and immutable session
 * receipts. These unsigned bytes never satisfy production inventory authority. */
function verifyLocalSessionDiscovery(root, directory, authority, inventory) {
  const original = authority.sealed_from ? read(path.join(root, verifyReceipt(root, authority.sealed_from).path)) : authority;
  const profile = original.profile ?? 'exhaustive';
  insist(['bounded', 'exhaustive'].includes(profile), 'unknown frozen mutation profile');
  insist(original.schema_version === 1 && original.qualification === sessionQualification(profile) && original.source_sha256 === (authority.discovery_source_sha256 ?? authority.source_sha256) && original.input_sha256 === acceptanceInputHash(sourceReceipt(root)), 'local discovery source authority differs');
  insist(canonicalJson(inventory.discovery?.catalog) === canonicalJson(original.catalog), 'local discovery catalog receipt differs');
  insist(canonicalJson(authority.inventory) === canonicalJson(original.inventory), 'local discovery inventory receipt differs');
  const replay = verifyLocalAcceptanceDiscovery(root, inventory, read(path.join(root, 'quality/requirements.json')));
  if (profile === 'bounded') insist(inventory.profile === 'bounded' && canonicalJson(original.bounded_policy) === canonicalJson(boundedMutationPolicy(root, sourceReceipt(root))) && canonicalJson(inventory.mutation_policy) === canonicalJson(original.bounded_policy), 'bounded session corpus policy changed');
  insist(Array.isArray(original.rows) && canonicalJson(original.rows.map(row => row.backend)) === canonicalJson(sessionBackends(profile)), 'local discovery omitted a required backend');
  insist(new Set(original.rows.map(row => row.image_id)).size === 1 && new Set(original.rows.map(row => row.runtime_sha256)).size === 1, 'local discovery mixed image/SDK cohorts');
  const first = original.rows[0], providers = [], hashes = new Map(sourceReceipt(root).files.map(row => [row.path, row.sha256]));
  const scopes = [{ backend: 'catalog', directory: path.join(directory, 'catalog-discovery') }, ...original.rows.map(row => ({ backend: row.backend, directory: path.resolve(directory, row.discovery), row }))];
  for (const scope of scopes) {
    inside(directory, scope.directory);
    const names = ['runner.json', 'runtime-input-receipt.json', 'isolation-proof.json', 'exec-isolation-proof.json', ...(scope.row ? ['pre-outcome-plan.json'] : ['catalog.json'])];
    const records = names.map(name => fileReceipt(root, inside(root, path.join(scope.directory, name))));
    if (!scope.row) insist(canonicalJson(read(path.join(scope.directory, 'catalog.json'))) === canonicalJson(read(path.join(root, original.catalog.path))), 'protected catalog output differs from the session catalog');
    if (scope.row) {
      insist(Array.isArray(scope.row.evidence), 'local discovery evidence receipts are absent');
      for (const [index, name] of names.entries()) {
        const expected = scope.row.evidence.find(row => row.path === name), actual = records[index];
        insist(expected && expected.sha256 === actual.sha256 && expected.size === actual.size, 'local discovery provider bytes changed');
      }
      verifyReceipt(root, scope.row.frozen);
      const frozen = read(path.join(root, scope.row.frozen.path)), plan = read(path.join(scope.directory, 'pre-outcome-plan.json'));
      insist(frozen.image_id === first.image_id && frozen.runtime_sha256 === first.runtime_sha256 && frozen.plan?.source_tree_sha256 === original.source_sha256 && frozen.plan.backend === scope.backend && Number.isSafeInteger(scope.row.scheduled) && scope.row.scheduled > 0 && frozen.plan.mutants?.length === scope.row.scheduled && frozen.plan.mutants.every(row => hashes.get(row.file) === row.source_sha256) && canonicalJson(frozen.plan) === canonicalJson(plan), 'local discovery frozen schedule differs');
    }
    const runner = read(path.join(scope.directory, 'runner.json')), runtimeBytes = readFileSync(path.join(scope.directory, 'runtime-input-receipt.json'));
    insist(runner.image === first.image_id && sha(runtimeBytes) === first.runtime_sha256, 'local discovery provider image/SDK differs');
    verifyDiscoveryProvider(runner, scope.backend, original.source_sha256, JSON.parse(runtimeBytes.toString('utf8')), ['isolation-proof.json', 'exec-isolation-proof.json'].map(name => read(path.join(scope.directory, name))), sha(runtimeBytes));
    providers.push({ backend: scope.backend, records });
  }
  return { ...replay, session: fileReceipt(root, inside(root, path.join(directory, 'session.json'))), discovery_source_sha256: original.source_sha256, providers };
}

/** Existing native kernel lease: EOF/process death releases it, including after
 * an interrupted orchestrator. Never reclaim a lock based on a PID guess. */
export async function acquireMutationSessionLease(directory, guard) {
  directory = realpathSync(directory);
  const info = lstatSync(directory, { bigint: true });
  insist(info.isDirectory() && !info.isSymbolicLink(), 'session lease root is not ordinary');
  const child = spawn(guard, ['state-lock', '--root', directory, '--path', 'execution.native', '--root-device', String(info.dev), '--root-inode', String(info.ino)], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let text = '', stderr = '', closed = false;
  const complete = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => { closed = true; resolve({ code, signal }); }); });
  complete.catch(() => {});
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('session kernel lease admission timed out')), 5000);
      const finish = (error) => { clearTimeout(timer); error ? reject(error) : resolve(undefined); };
      child.once('error', finish);
      child.once('close', () => finish(new Error('session kernel lease is held or unavailable: ' + stderr)));
      child.stderr.on('data', bytes => { stderr += bytes; if (stderr.length > 65536) finish(new Error('session lease stderr exceeded bound')); });
      child.stdout.on('data', bytes => {
        text += bytes;
        if (text.length > 65536) return finish(new Error('session lease response exceeded bound'));
        if (!text.includes('\n')) return;
        try { insist(JSON.parse(text).locked === true, 'native kernel lease was not acquired'); finish(); } catch (error) { finish(error); }
      });
    });
    return async () => {
      insist(!closed, 'session kernel lease was lost during execution');
      child.stdin.end();
      let timer;
      const status = await Promise.race([complete, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('session lease did not release')), 5000); })]).finally(() => clearTimeout(timer));
      insist(status.code === 0 && !status.signal, 'session lease release failed');
    };
  } catch (error) { child.stdin.destroy(); child.kill('SIGTERM'); await complete.catch(() => {}); throw error; }
}

export function verifyDiscoveryProvider(runner, backend, source, runtime, proofs, runtimeSha256) {
  insist(runner?.inventory_only === true && runner.backend === backend && runner.source_tree_sha256 === source && /^sha256:[a-f0-9]{64}$/.test(runner.image ?? '') && runner.status === 'executed-not-reconciled', 'complete protected discovery did not finish');
  insist(runner.worker?.platform === 'linux' && runner.worker.architecture === 'arm64' && runner.worker.emulation === false && runner.container_state?.ExitCode === 0 && runner.container_state.Running === false && runner.container_state.OOMKilled === false && runner.execution?.status === 0 && !runner.execution.error && !runner.execution.signal, 'discovery runtime failed');
  insist(Array.isArray(runner.cleanup) && runner.cleanup.length === 4 && runner.cleanup.every(item => item.status === 'removed-owned') && new Set(runner.cleanup.map(item => item.kind + '\0' + item.name)).size === 4, 'discovery owned cleanup is incomplete');
  insist(runtime?.platform === 'linux/arm64' && /^[a-f0-9]{64}$/.test(runtimeSha256 ?? '') && Array.isArray(proofs) && proofs.length === 2 && proofs.every(item => item?.status === 'passed' && item.source_tree_sha256 === source && item.runtime_input_sha256 === runtimeSha256), 'discovery isolation or SDK evidence is missing');
}

/** Hash every retained ordinary evidence file with streaming I/O. Source copies,
 * generated variants and target trees are retained by the runner, not trusted as
 * executable resume inputs; only their metadata is subsequently read by graders. */
export async function evidenceInventory(directory) {
  const rows = [];
  async function visit(folder) {
    for (const item of readdirSync(folder, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      if (['node_modules', '__pycache__', 'target', '.pytest_cache'].includes(item.name)) continue;
      const full = path.join(folder, item.name), name = inside(directory, full);
      insist(!item.isSymbolicLink(), 'retained evidence contains a symbolic link');
      if (item.isDirectory()) await visit(full);
      else {
        const before = lstatSync(full); insist(before.isFile(), 'retained evidence is not ordinary');
        const hash = createHash('sha256'); for await (const chunk of createReadStream(full)) hash.update(chunk);
        const after = lstatSync(full); insist(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'evidence changed during capture');
        rows.push({ path: name, sha256: hash.digest('hex'), size: after.size });
      }
    }
  }
  await visit(directory); insist(rows.length > 0, 'empty evidence tree'); return rows;
}

/** Failure excerpts are diagnostics only, never a substitute for a provider,
 * schedule, isolation proof or outcome. Read fixed paths through held ordinary
 * files, without following even an intermediate alias supplied by a child. */
function discoveryFailure(output, directory, backend, status, source, image) {
  const limit = 8192;
  const names = [backend + '-discovery.log', ...['runner.json', 'runner.log', 'rust-named-faults/pristine-build.log', 'rust-named-faults/pristine-build.execution.json', 'rust-named-faults/pristine-list.log', 'secondary-execution-000001.json', 'secondary-execution-000002.json'].map(name => inside(output, path.join(directory, name)))];
  const diagnostics = names.map(name => {
    let descriptor;
    try {
      let parent = output;
      for (const part of name.split('/').slice(0, -1)) {
        parent = path.join(parent, part);
        const info = lstatSync(parent);
        insist(info.isDirectory() && !info.isSymbolicLink(), 'diagnostic parent is not ordinary');
      }
      const file = path.join(output, name), before = lstatSync(file, { bigint: true });
      insist(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n && before.size <= 16n * 1024n ** 2n, 'diagnostic file is not bounded and ordinary');
      descriptor = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      const held = fstatSync(descriptor, { bigint: true });
      const same = actual => ['dev', 'ino', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(key => actual[key] === before[key]);
      insist(same(held), 'diagnostic file changed before capture');
      const size = Number(before.size), bytes = Buffer.alloc(Math.min(size, limit));
      insist(readSync(descriptor, bytes, 0, bytes.length, size - bytes.length) === bytes.length && same(fstatSync(descriptor, { bigint: true })) && same(lstatSync(file, { bigint: true })), 'diagnostic file changed during capture');
      return { path: name, size, truncated: size > bytes.length, tail: bytes.toString('utf8') };
    } catch (error) {
      return { path: name, unavailable: String(error.code ?? error.message).slice(0, 1024) };
    } finally { if (descriptor !== undefined) closeSync(descriptor); }
  });
  const record = { schema_version: 1, qualification: 'failed-protected-discovery-diagnostics-no-execution-authority', backend, source_tree_sha256: source, image,
    execution: { status: status?.status ?? null, signal: status?.signal ?? null, error: status?.error ? String(status.error.message ?? status.error).slice(0, limit) : null }, diagnostics };
  const name = backend + '-discovery-failure.log', descriptor = openSync(path.join(output, name), 'wx', 0o600);
  try { writeFileSync(descriptor, JSON.stringify(record, null, 2) + '\n'); fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
  return `Failure diagnostics: ${path.join(output, name)}\n${JSON.stringify(record)}`;
}

function collectProtectedDiscovery(root, output, directory, backend, source, image, run, environment) {
  const log = openSync(path.join(output, backend + '-discovery.log'), 'wx', 0o600);
  let status;
  try {
    status = run(process.execPath, [path.join(root, 'scripts/quality/oci-python-diagnostic.mjs'), directory, '--source-root', root, '--backend', backend, '--image', image, '--inventory-only'], { cwd: root, env: environment, stdio: ['ignore', log, log], timeout: 12 * 60 * 60 * 1000 });
  } catch (error) { status = { status: null, error }; }
  finally { closeSync(log); }
  if (status?.status !== 0 || status.error || status.signal) {
    const message = backend === 'catalog' ? 'protected independent original test collection failed' : backend + ' protected discovery failed; no execution is authorized';
    throw new Error('Mutation session: ' + message + '\n' + discoveryFailure(output, directory, backend, status, source, image));
  }
}

/** @param {string} root @param {string} output @param {{python:string,cargo:string,image?:string,run?:typeof spawnSync,environment?:NodeJS.ProcessEnv}} options */
async function discoverSession(root, output, { python, cargo, image = 'localhost/ud-agent-mutation-runtime:arm64-final3', run = spawnSync, environment = process.env }, profile) {
  root = path.resolve(root); output = path.resolve(output);
  insist(inside(root, output).startsWith('.artifacts/') && !existsSync(output), 'discovery needs a new owned artifact directory');
  const source = sourceReceipt(root);
  const composition = compositionAtDiscovery(root, source);
  const bounded = profile === 'bounded' ? boundedMutationPolicy(root, source) : null;
  mkdirSync(output, { recursive: true, mode: 0o700 });
  const catalogDirectory = path.join(output, 'catalog-discovery');
  collectProtectedDiscovery(root, output, catalogDirectory, 'catalog', source.sha256, image, run, environment);
  const catalogRuntime = readFileSync(path.join(catalogDirectory, 'runtime-input-receipt.json'));
  verifyDiscoveryProvider(read(path.join(catalogDirectory, 'runner.json')), 'catalog', source.sha256, JSON.parse(catalogRuntime.toString('utf8')), ['isolation-proof.json', 'exec-isolation-proof.json'].map(name => read(path.join(catalogDirectory, name))), sha(catalogRuntime));
  const catalog = read(path.join(catalogDirectory, 'catalog.json'));
  writeFileSync(path.join(output, 'catalog.json'), JSON.stringify(catalog) + '\n', { flag: 'wx', mode: 0o600 });
  const rows = [];
  for (const backend of sessionBackends(profile)) {
    const directory = path.join(output, 'discovery', backend);
    mkdirSync(path.dirname(directory), { recursive: true });
    collectProtectedDiscovery(root, output, directory, backend, source.sha256, image, run, environment);
    const runner = read(path.join(directory, 'runner.json')), runtimeBytes = readFileSync(path.join(directory, 'runtime-input-receipt.json'));
    verifyDiscoveryProvider(runner, backend, source.sha256, JSON.parse(runtimeBytes.toString('utf8')), ['isolation-proof.json', 'exec-isolation-proof.json'].map(name => read(path.join(directory, name))), sha(runtimeBytes));
    const plan = read(path.join(directory, 'pre-outcome-plan.json'), 128 * 1024 ** 2);
    insist(plan.schema_version === 1 && plan.backend === backend && Array.isArray(plan.mutants) && plan.mutants.length > 0 && plan.source_tree_sha256 === source.sha256 && plan.tool.startsWith(TOOLS[backend]), 'pre-outcome schedule was altered or belongs to another backend');
    // Full definitions can be up to 1 GiB. Their original Python replayers and
    // existing normalization stream own those bytes; V8 reads only the compact
    // exact inventory and separately captured small test-discovery header.
    const tests = normalizeTests(read(path.join(directory, 'test-discovery.json')), catalog, { tool: TOOLS[backend] });
    const sources = new Map(source.files.map(item => [item.path, item.sha256]));
    insist(plan.mutants.every(item => sources.get(item.file) === item.source_sha256), 'scheduled mutation source differs from the frozen tree');
    const frozen = { schema_version: 1, image_id: runner.image, runtime_sha256: sha(runtimeBytes), plan };
    const filename = path.join(output, backend + '-frozen.json');
    writeFileSync(filename, JSON.stringify(frozen) + '\n', { flag: 'wx', mode: 0o400 });
    rows.push({ backend, frozen: fileReceipt(root, inside(root, filename)), image_id: runner.image, runtime_sha256: frozen.runtime_sha256, tests, scheduled: plan.mutants.length, discovery: inside(output, directory), evidence: await evidenceInventory(directory) });
    insist(sourceReceipt(root).sha256 === source.sha256, 'source changed during discovery');
  }
  insist(new Set(rows.map(item => item.image_id)).size === 1 && new Set(rows.map(item => item.runtime_sha256)).size === 1, 'discovery mixed mutation image or SDK cohorts');
  insist(rows[0].runtime_sha256 === sha(catalogRuntime) && rows[0].image_id === read(path.join(catalogDirectory, 'runner.json')).image, 'catalog and generators used different protected SDK cohorts');
  const inventory = await exportMutationSchedules(root, output, catalog, rows, python, { profile });
  if (composition) verifyReceipt(root, composition); else insist(!existsSync(path.join(root, COMPOSITION)), 'composition appeared during discovery');
  const authority = { schema_version: 1, qualification: sessionQualification(profile), ...(bounded ? { profile: 'bounded', bounded_policy: bounded } : {}), source_sha256: source.sha256, input_sha256: acceptanceInputHash(source), composition, catalog: fileReceipt(root, inside(root, path.join(output, 'catalog.json'))), inventory, rows };
  writeFileSync(path.join(output, 'session.json'), JSON.stringify(authority, null, 2) + '\n', { flag: 'wx', mode: 0o400 });
  return output;
}

/** Legacy full generation stays separate from the explicitly bounded corpus. */
export async function discoverMutationSession(root, output, options) { return discoverSession(root, output, options, 'exhaustive'); }
export async function discoverBoundedMutationSession(root, output, options) { return discoverSession(root, output, options, 'bounded'); }

/** Only the generated acceptance inventory may change between discovery and
 * execution. All executable/config/test inputs retain their original hashes. */
function sealSession(root, directory, { install = false } = {}, profile) {
  root = path.resolve(root); directory = path.resolve(directory); inside(root, directory);
  if (existsSync(path.join(directory, 'sealed-session.json'))) {
    const sealed = read(path.join(directory, 'sealed-session.json'));
    insist((sealed.profile ?? 'exhaustive') === profile, 'sealed mutation profile differs');
    insist(sealed.source_sha256 === sourceReceipt(root).sha256 && sealed.input_sha256 === acceptanceInputHash(sourceReceipt(root)), 'sealed source changed');
    verifyReceipt(root, sealed.sealed_from); verifyReceipt(root, sealed.inventory);
    insist(fileReceipt(root, 'quality/acceptance-inventory.json').sha256 === sealed.inventory.sha256, 'sealed inventory changed');
    verifyCompositionSeal(root, sealed, true);
    insist(canonicalJson(sealed.local_discovery_replay) === canonicalJson(verifyLocalSessionDiscovery(root, directory, sealed, read(path.join(root, sealed.inventory.path)))), 'sealed local discovery replay differs'); return directory;
  }
  const original = read(path.join(directory, 'session.json')), source = sourceReceipt(root);
  insist((original.profile ?? 'exhaustive') === profile, 'discovery mutation profile differs');
  insist(original.input_sha256 === acceptanceInputHash(source), 'source changed before the generated-inventory seal');
  const inventoryFile = path.join(root, original.inventory.path), inventoryBytes = readFileSync(inventoryFile);
  insist(sha(inventoryBytes) === original.inventory.sha256 && inventoryBytes.length === original.inventory.size, 'frozen acceptance inventory changed');
  const localDiscoveryReplay = verifyLocalSessionDiscovery(root, directory, original, JSON.parse(inventoryBytes.toString('utf8')));
  const projectedFiles = source.files.filter(item => item.path !== 'quality/acceptance-inventory.json');
  projectedFiles.push({ path: 'quality/acceptance-inventory.json', sha256: original.inventory.sha256, size: original.inventory.size, executable: false });
  projectedFiles.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const projectedSourceSha256 = sha(JSON.stringify(projectedFiles));
  const compositionBinding = prepareCompositionSeal(root, directory, original, projectedSourceSha256);
  const canonical = path.join(root, 'quality/acceptance-inventory.json');
  if (install) {
    const temporary = canonical + '.' + randomUUID(); writeFileSync(temporary, inventoryBytes, { flag: 'wx', mode: 0o644 }); renameSync(temporary, canonical);
  }
  insist(sha(readFileSync(canonical)) === original.inventory.sha256, 'install the exact frozen inventory before sealing');
  const sealedSource = sourceReceipt(root);
  insist(acceptanceInputHash(sealedSource) === original.input_sha256, 'only the generated acceptance inventory may change during seal');
  insist(sealedSource.sha256 === projectedSourceSha256, 'source differs from the exact inventory-only projection');
  const rows = original.rows.map(row => {
    const bytes = readFileSync(path.join(root, row.frozen.path));
    insist(sha(bytes) === row.frozen.sha256 && bytes.length === row.frozen.size, 'discovery schedule changed before seal');
    const frozen = JSON.parse(bytes.toString('utf8'));
    insist(frozen.plan.source_tree_sha256 === original.source_sha256, 'discovery source identity changed');
    frozen.plan.source_tree_sha256 = sealedSource.sha256;
    const file = path.join(directory, 'sealed', row.backend + '-frozen.json'); mkdirSync(path.dirname(file), { recursive: true });
    const bytesAfter = Buffer.from(JSON.stringify(frozen) + '\n');
    if (existsSync(file)) insist(readFileSync(file).equals(bytesAfter), 'interrupted seal contains different frozen bytes');
    else writeFileSync(file, bytesAfter, { flag: 'wx', mode: 0o400 });
    return { ...row, discovery_frozen: row.frozen, frozen: fileReceipt(root, inside(root, file)) };
  });
  const sealed = { ...original, local_discovery_replay: localDiscoveryReplay, source_sha256: sealedSource.sha256, sealed_from: fileReceipt(root, inside(root, path.join(directory, 'session.json'))), discovery_source_sha256: original.source_sha256, ...(compositionBinding ? { composition_binding: compositionBinding } : {}), rows };
  writeFileSync(path.join(directory, 'sealed-session.json'), JSON.stringify(sealed, null, 2) + '\n', { flag: 'wx', mode: 0o400 });
  verifyCompositionSeal(root, sealed, true);
  return directory;
}

export function sealMutationSession(root, directory, options) { return sealSession(root, directory, options, 'exhaustive'); }
export function sealBoundedMutationSession(root, directory, options) { return sealSession(root, directory, options, 'bounded'); }

async function openSession(root, directory, profile) {
  root = path.resolve(root); directory = path.resolve(directory);
  insist(inside(root, directory).startsWith('.artifacts/'), 'session must remain inside owned artifacts');
  const authority = read(path.join(directory, 'sealed-session.json'));
  insist(authority.schema_version === 1 && authority.qualification === sessionQualification(profile) && (authority.profile ?? 'exhaustive') === profile && authority.source_sha256 === sourceReceipt(root).sha256 && authority.input_sha256 === acceptanceInputHash(sourceReceipt(root)), 'frozen session source is stale');
  verifyCompositionSeal(root, authority);
  insist(Array.isArray(authority.rows) && canonicalJson(authority.rows.map(item => item.backend)) === canonicalJson(sessionBackends(profile)), 'frozen session omitted a required backend');
  insist(new Set(authority.rows.map(item => item.image_id)).size === 1 && new Set(authority.rows.map(item => item.runtime_sha256)).size === 1, 'frozen session mixed image/SDK cohorts');
  const verifyFile = record => { const actual = fileReceipt(root, record.path); insist(actual.sha256 === record.sha256 && actual.size === record.size, 'frozen authority bytes changed'); return path.join(root, record.path); };
  verifyFile(authority.sealed_from);
  const inventory = read(verifyFile(authority.inventory));
  insist(fileReceipt(root, 'quality/acceptance-inventory.json').sha256 === authority.inventory.sha256, 'canonical acceptance inventory differs from the sealed authority');
  insist(canonicalJson(authority.local_discovery_replay) === canonicalJson(verifyLocalSessionDiscovery(root, directory, authority, inventory)), 'sealed local discovery replay differs');
  const catalog = read(verifyFile(authority.catalog));
  insist(catalog.input_sha256 === authority.input_sha256, 'frozen independent catalog differs');
  for (const row of authority.rows) {
    verifyFile(row.discovery_frozen);
    const frozen = read(verifyFile(row.frozen));
    insist(frozen.plan?.source_tree_sha256 === authority.source_sha256 && frozen.plan.backend === row.backend && frozen.image_id === row.image_id && frozen.runtime_sha256 === row.runtime_sha256 && frozen.plan.mutants.length === row.scheduled, 'frozen backend binding differs');
    const discovery = path.resolve(directory, row.discovery); inside(directory, discovery);
    insist(canonicalJson(await evidenceInventory(discovery)) === canonicalJson(row.evidence), 'discovery evidence was changed');
  }
  const authority_sha256 = sha(readFileSync(path.join(directory, 'sealed-session.json')));
  function verifyExecution(output, row) {
    const runner = read(path.join(output, 'runner.json'));
    insist(runner.inventory_only === false && runner.source_tree_sha256 === authority.source_sha256 && runner.image === row.image_id && runner.frozen_plan_sha256 === row.frozen.sha256 && sha(readFileSync(path.join(output, 'runtime-input-receipt.json'))) === row.runtime_sha256, 'execution changed source/image/SDK authority');
    insist(canonicalJson(read(path.join(output, 'pre-outcome-plan.json'))) === canonicalJson(read(path.join(root, row.frozen.path)).plan), 'execution did not bind the frozen schedule');
  }
  return { directory, authority, authority_sha256, async backend(backend) {
    const row = authority.rows.find(item => item.backend === backend); insist(row, 'backend is absent');
    const record = path.join(directory, backend + '-execution.json');
    if (existsSync(record)) {
      const prior = read(record); insist(prior.authority_sha256 === authority_sha256, 'resume authority changed');
      const output = path.resolve(directory, prior.output); inside(directory, output);
      insist(canonicalJson(await evidenceInventory(output)) === canonicalJson(prior.evidence), 'retained execution evidence changed');
      verifyExecution(output, row);
      return { output, reused: true, frozen: path.join(root, row.frozen.path), image: row.image_id };
    }
    const output = path.join(directory, 'execution', backend + '-' + randomUUID()); mkdirSync(path.dirname(output), { recursive: true });
    return { output, reused: false, frozen: path.join(root, row.frozen.path), image: row.image_id };
  }, async retain(backend, output) {
    const row = authority.rows.find(item => item.backend === backend);
    insist(row, 'backend is absent'); verifyExecution(output, row);
    // This is only immutable evidence retention. Every invocation of the gate
    // re-runs all strict graders; no saved pass/kill is accepted here.
    atomic(path.join(directory, backend + '-execution.json'), { schema_version: 1, authority_sha256, output: inside(directory, output), evidence: await evidenceInventory(output) });
  } };
}

export async function openMutationSession(root, directory) { return openSession(root, directory, 'exhaustive'); }
export async function openBoundedMutationSession(root, directory) { return openSession(root, directory, 'bounded'); }

/** Select bounded discovery explicitly; the unqualified legacy CLI remains exhaustive. */
/** @returns {{profile:string,discover?:string,seal?:string,python?:string,cargo?:string,image?:string}} */
export function mutationSessionOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index], value = args[index + 1];
    insist(['--profile', '--discover', '--seal', '--python', '--cargo', '--image'].includes(key) && value && !Object.hasOwn(options, key), 'invalid or duplicate session argument');
    options[key] = value;
  }
  const profile = options['--profile'] ?? 'exhaustive';
  insist(['bounded', 'exhaustive'].includes(profile), 'unknown session profile');
  const discover = options['--discover'], seal = options['--seal'];
  insist(Boolean(discover) !== Boolean(seal), 'select exactly one of --discover or --seal');
  if (discover) insist(options['--python'] && options['--cargo'], 'discovery requires --python and --cargo');
  else insist(!options['--python'] && !options['--cargo'] && !options['--image'], 'seal does not accept discovery arguments');
  if (options['--image']) insist(/^sha256:[a-f0-9]{64}$/.test(options['--image']), 'discovery image must be immutable');
  return { profile, ...(discover ? { discover, python: options['--python'], cargo: options['--cargo'], ...(options['--image'] ? { image: options['--image'] } : {}) } : { seal }) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = mutationSessionOptions(process.argv.slice(2));
  if (options.seal) console.log((options.profile === 'bounded' ? sealBoundedMutationSession : sealMutationSession)(process.cwd(), options.seal, { install: true }));
  else console.log(await (options.profile === 'bounded' ? discoverBoundedMutationSession : discoverMutationSession)(process.cwd(), options.discover, { python: options.python, cargo: options.cargo, ...(options.image ? { image: options.image } : {}) }));
}
