/** MIT. Bind verified native worker bytes into a private diagnostic installation. */
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileReceipt, safeRelative, sha256 } from '../../scripts/release/candidate.mjs';
import { verifyOciArchive } from '../../scripts/release/oci.mjs';
import { copyContextAssets } from '../../scripts/release/context-assets.mjs';
import { runOwned } from './process.mjs';
import { executable, privateEnvironment } from './preparation.mjs';
import { seedOfflineProviderAssets } from '../../scripts/quality/native-provider-acceptance.mjs';

/** Native (never emulated) worker platforms the local evaluator can bind. */
export const WORKER_PLATFORMS = Object.freeze(['linux/arm64', 'linux/amd64']);

const need = (value, reason) => { if (!value) throw new Error(`LOCAL_EVAL_RUNTIME_ASSETS: ${reason}`); };
const read = (file) => JSON.parse(readFileSync(file, 'utf8'));
function owned(root, selected) {
  const absolute = path.resolve(selected);
  need(absolute.startsWith(path.join(root, '.artifacts') + path.sep), 'asset and installation paths must be repository-owned');
  let current = root;
  for (const segment of path.relative(root, absolute).split(path.sep)) {
    current = path.join(current, segment); const info = lstatSync(current, { throwIfNoEntry: false });
    need(!info || !info.isSymbolicLink(), 'asset path is aliased');
  }
  return absolute;
}
function receipt(root, name) {
  const row = fileReceipt(root, name);
  return { path: name, sha256: `sha256:${row.sha256}`, size_bytes: row.size };
}
function linkBound(root, installation, descriptor, { replace = false } = {}) {
  safeRelative(descriptor.path);
  const sourceFile = owned(root, path.join(root, descriptor.path));
  const source = receipt(root, descriptor.path);
  need(source.sha256 === descriptor.sha256 && source.size_bytes === descriptor.size_bytes, `transport changed: ${descriptor.path}`);
  const before = lstatSync(sourceFile);
  need(before.isFile() && !before.isSymbolicLink() && before.nlink >= 1 && (before.mode & 0o133) === 0 && (typeof process.getuid !== 'function' || before.uid === process.getuid()), 'transport source is not an owned ordinary archive');
  chmodSync(sourceFile, 0o400);
  const sealed = lstatSync(sourceFile);
  need(sealed.dev === before.dev && sealed.ino === before.ino && sealed.size === before.size && sealed.uid === before.uid && (sealed.mode & 0o777) === 0o400 && receipt(root, descriptor.path).sha256 === source.sha256, 'transport sealing changed its identity');
  const target = path.join(installation, descriptor.path); mkdirSync(path.dirname(target), { recursive: true });
  const existing = lstatSync(target, { throwIfNoEntry: false });
  if (existing) {
    need(replace && existing.isFile() && !existing.isSymbolicLink() && existing.uid === sealed.uid && (existing.mode & 0o777) === 0o400 && receipt(installation, descriptor.path).sha256 === source.sha256 && existing.size === sealed.size, 'existing private transport is not the exact known copy');
    if (existing.dev === sealed.dev && existing.ino === sealed.ino) return { ...descriptor, device: String(sealed.dev), inode: String(sealed.ino), reused: true };
    need(existing.nlink === 1, 'replacement private transport has unexpected aliases');
  }
  const temporary = target + '.link-' + randomUUID();
  try {
    linkSync(sourceFile, temporary);
    const linked = lstatSync(temporary), current = lstatSync(sourceFile);
    need(linked.dev === sealed.dev && linked.ino === sealed.ino && current.dev === sealed.dev && current.ino === sealed.ino && (current.mode & 0o777) === 0o400, 'transport link identity changed');
    if (existing) {
      const currentTarget = lstatSync(target);
      need(['dev', 'ino', 'uid', 'mode', 'size', 'nlink', 'mtimeMs', 'ctimeMs'].every((key) => currentTarget[key] === existing[key]), 'private transport changed before replacement');
    } else need(!existsSync(target), 'private transport appeared during binding');
    renameSync(temporary, target);
  } finally { if (existsSync(temporary)) unlinkSync(temporary); }
  need(receipt(installation, descriptor.path).sha256 === descriptor.sha256, 'linked transport differs');
  return { ...descriptor, device: String(sealed.dev), inode: String(sealed.ino), replaced_copy: Boolean(existing) };
}

/** Reconcile only transports already bound by this private diagnostic receipt.
 * Byte inventories remain identical; per-episode cached archives stay nlink=1. */
export function reconcileRuntimeAssetLinks(root, installation) {
  root = path.resolve(root); installation = owned(root, installation);
  const proof = read(path.join(installation, 'LOCAL-EVAL-RUNTIME.json')), runtime = read(path.join(installation, 'runtime/runtime.lock.json'));
  need(proof.qualification === 'local-eval-native-runtime-not-release-acceptance' && runtime.state === 'frozen', 'private runtime binding is absent');
  const workerReceipt = receipt(root, proof.worker_receipt.path);
  need(workerReceipt.sha256 === proof.worker_receipt.sha256 && workerReceipt.size_bytes === proof.worker_receipt.size_bytes, 'source worker receipt changed');
  const workers = read(path.join(root, proof.worker_receipt.path));
  const links = [];
  for (const name of ['core', 'render']) {
    const original = workers.packs?.[name], installed = runtime.packs?.[name];
    need(original && installed && original.index_digest === installed.index_digest, 'private worker identity differs');
    const originals = [original.index_transport, ...Object.values(original.images).flatMap((image) => image.transports)];
    const selected = new Map([installed.index_transport, ...Object.values(installed.images).flatMap((image) => image.transports)].map((descriptor) => [descriptor.path, descriptor]));
    for (const descriptor of selected.values()) {
      need(originals.some((item) => item.path === descriptor.path && item.sha256 === descriptor.sha256 && item.size_bytes === descriptor.size_bytes && item.format === descriptor.format), 'private transport differs from the verified export');
      links.push(linkBound(root, installation, descriptor, { replace: true }));
    }
  }
  return { qualification: 'verified-private-runtime-input-hardlinks', links };
}

/** This composes diagnostic runtime authority only; it never changes source locks. */
export async function bindRuntimeAssets(root, installation, { buildRoot = path.join(root, '.artifacts/local-evals/worker-build'), python = path.join(root, '.venv/bin/python') } = {}) {
  root = path.resolve(root); installation = owned(root, installation); buildRoot = owned(root, buildRoot);
  const lockPath = path.join(installation, 'runtime/runtime.lock.json'), previous = read(lockPath);
  if (!existsSync(path.join(buildRoot, 'build-receipt.json'))) throw new Error('LOCAL_EVAL_RUNTIME_BUILD_REQUIRED');
  need(!existsSync(path.join(buildRoot, 'INCOMPLETE')), 'worker build is incomplete');
  const build = read(path.join(buildRoot, 'build-receipt.json'));
  // Native worker builds exist for both Linux architectures; the build receipt names its own.
  need(build.schema_version === 1 && build.qualification === 'native-build-unaccepted' && WORKER_PLATFORMS.includes(build.platform) && build.emulated === false, 'native ARM64 build evidence is missing (a native linux/amd64 receipt is also accepted)');
  const platform = build.platform;
  const workerFile = owned(root, build.transports);
  need(workerFile === path.join(buildRoot, 'transports/worker-receipt.json'), 'worker receipt escapes the selected build');
  const workers = read(workerFile), core = path.join(buildRoot, 'core-context'), input = read(path.join(core, 'input-manifest.json'));
  need(workers.schema_version === 1 && workers.qualification === 'local-build-unaccepted' && Object.keys(workers.packs ?? {}).sort().join(',') === 'core,render', 'worker export is incomplete');
  // Reconstructing the core context binds dependency locks, upstream archives,
  // and every worker source to the current product before admitting the images.
  const contextCheck = await runOwned(python, [path.join(root, 'scripts/runtime/verify-core-build.py'), core], { cwd: root, timeout: 180_000 });
  need(JSON.parse(contextCheck.stdout).verified === true, 'core source reconstruction failed');
  const runtime = { ...previous, state: 'frozen', format_revision: 1, packs: {} }, evidence = [];
  for (const name of ['core', 'render']) {
    const pack = structuredClone(workers.packs[name]), image = pack.images?.[platform];
    need(image && Object.keys(pack.images).length === 1 && pack.platforms?.[platform] === image.digest && pack.index_digest === build.packs?.[name], 'worker build and export identities differ');
    const descriptor = pack.index_transport;
    need(descriptor && typeof descriptor.path === 'string', 'worker OCI archive is absent');
    safeRelative(descriptor.path);
    verifyOciArchive(path.join(root, descriptor.path), pack.index_digest, pack.platforms, { sha256: descriptor.sha256.slice(7), size: descriptor.size_bytes }, pack.images, { diagnosticSinglePlatform: true });
    const checked = await runOwned(python, [path.join(root, 'scripts/runtime/verify-worker-contents.py'), '--archive', path.join(root, descriptor.path), '--manifest', image.digest, '--context', core, ...(name === 'render' ? ['--render'] : [])], { cwd: root, timeout: 180_000 });
    const content = JSON.parse(checked.stdout); need(content.status === 'passed', 'actual image contents are unverified');
    const transports = new Map([descriptor, ...image.transports].map((item) => [item.path, item]));
    for (const item of transports.values()) linkBound(root, installation, item);
    pack.context_sha256 = `sha256:${input.rule_context_sha256}`;
    runtime.packs[name] = pack; evidence.push({ pack: name, content, index_transport: descriptor, image_digest: image.digest });
  }
  const prepared = await runOwned(python, [path.join(root, 'scripts/runtime/prepare-context.py')], { cwd: root, timeout: 60_000 });
  const manifestPath = owned(root, prepared.stdout.trim()), contextRoot = path.dirname(manifestPath), manifest = read(manifestPath);
  need(manifest.context_sha256 === input.rule_context_sha256, 'portable rules differ from the worker rules');
  const destination = `runtime/contexts/${manifest.context_sha256}`;
  copyContextAssets(contextRoot, path.join(installation, destination), receipt(contextRoot, 'context.json'));
  const context = receipt(installation, `${destination}/context.json`);
  for (const pack of Object.values(runtime.packs)) pack.context_manifest = context;
  runtime.packs.render.seccomp_profile = receipt(installation, 'runtime/policies/render-seccomp.json');
  const qualification = { schema_version: 1, qualification: 'local-eval-native-runtime-not-release-acceptance', platform, source_runtime_sha256: fileReceipt(root, 'runtime/runtime.lock.json').sha256,
    build_receipt: receipt(root, path.relative(root, path.join(buildRoot, 'build-receipt.json'))), worker_receipt: receipt(root, path.relative(root, workerFile)), context, evidence,
    limitations: [`Native ${platform} worker execution only; other architectures and release acceptance remain separate.`, 'Portable context contains the bound official rule files; repository readiness is not certified by its presence.'] };
  writeFileSync(lockPath, JSON.stringify(runtime, null, 2) + '\n');
  writeFileSync(path.join(installation, 'LOCAL-EVAL-RUNTIME.json'), JSON.stringify(qualification, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return qualification;
}

/** Snapshot reusable transport bytes; presence alone never implies runtime readiness. */
export function runtimeAssetInventory(installation) {
  const runtime = read(path.join(installation, 'runtime/runtime.lock.json')), files = new Map();
  need(runtime.state === 'frozen', 'installation runtime is not frozen');
  for (const pack of Object.values(runtime.packs ?? {})) for (const image of Object.values(pack.images ?? {})) for (const descriptor of image.transports ?? []) {
    const actual = receipt(installation, descriptor.path);
    need(actual.sha256 === descriptor.sha256 && actual.size_bytes === descriptor.size_bytes, 'runtime asset changed');
    files.set(actual.path, actual);
  }
  need(files.size > 0, 'no reusable runtime assets');
  const rows = [...files.values()].sort((a, b) => a.path.localeCompare(b.path));
  return { files: rows, sha256: sha256(Buffer.from(JSON.stringify(rows))) };
}

function cachedRows(installation, state) {
  const lock = read(path.join(installation, 'runtime/runtime.lock.json'));
  return ['core', 'render'].map((pack) => {
    const images = lock.packs?.[pack]?.images ?? {}, key = WORKER_PLATFORMS.find((item) => images[item]), image = key ? images[key] : undefined, transport = image?.transports?.find((item) => item.format === 'docker-archive');
    need(transport, 'selected Docker archive is missing');
    const file = path.join(state + '-docker', 'images', transport.sha256.slice(7) + '.tar'), info = lstatSync(file);
    need(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && (info.mode & 0o222) === 0 && (typeof process.getuid !== 'function' || info.uid === process.getuid()), 'cache identity is not private and immutable');
    const actual = receipt(path.dirname(file), path.basename(file));
    need(actual.sha256 === transport.sha256 && actual.size_bytes === transport.size_bytes, 'cached worker differs from its contract');
    return { pack, ...(key === 'linux/arm64' ? {} : { architecture: key.slice('linux/'.length) }), path: file, sha256: actual.sha256, size_bytes: actual.size_bytes, device: String(info.dev), inode: String(info.ino), image_digest: image.digest, config_digest: image.config_digest, engine_descriptor_digests: image.engine_descriptor_digests ?? [], diff_ids: image.diff_ids };
  });
}
export function verifyRuntimeEngineImage(row, value) {
  const identifiers = [row.config_digest, ...(row.engine_descriptor_digests ?? [])];
  need(value.length === 1 && identifiers.includes(value[0].Id) && value[0].Architecture === (row.architecture ?? 'arm64') && value[0].Os === 'linux' && JSON.stringify(value[0].RootFS?.Layers) === JSON.stringify(row.diff_ids), 'preexisting worker image differs from its receipt');
  return { pack: row.pack, image_digest: row.image_digest, config_digest: row.config_digest, engine_id: value[0].Id, diff_ids: value[0].RootFS.Layers };
}
async function engineImages(docker, environment, rows, signal, run = runOwned) {
  const identity = async () => (await run(docker, ['info', '--format', '{{.ID}}'], { env: environment, timeout: 10_000, ...(signal ? { signal } : {}) })).stdout.trim();
  const daemon = await identity(); need(/^[A-Za-z0-9._:-]{1,128}$/.test(daemon), 'Docker daemon identity is unavailable');
  const images = [];
  for (const row of rows) {
    const identities = [...new Set([row.image_digest, ...(row.engine_descriptor_digests ?? []), row.config_digest])];
    let observed;
    for (const identity of identities) {
      try {
        const value = JSON.parse((await run(docker, ['image', 'inspect', identity], { env: environment, timeout: 10_000, ...(signal ? { signal } : {}) })).stdout);
        observed = verifyRuntimeEngineImage(row, value); break;
      } catch (error) {
        if (!String(error.message).includes(`No such image: ${identity}`)) throw error;
      }
    }
    need(observed, 'preexisting worker image is unavailable under every receipt-bound identity');
    images.push(observed);
  }
  need(await identity() === daemon, 'Docker daemon changed during inspection');
  return { daemon, images };
}

/** Seed input assets only; never run doctor/setup or create a readiness probe. */
export function fixturePreparationRelease(processes, { setupStarted, jobs }) {
  return processes.every(process => process.cleanupVerified === true) && (!setupStarted || jobs?.verified === true);
}
async function fixtureJobRelease(installation, state) {
  const [{ loadNativeGuardReceipt }, { readMaintenanceJobs }, { withProviderMaintenance }] = await Promise.all([
    import(pathToFileURL(path.join(installation, 'dist/packages/runtime-manager/src/receipt.js')).href),
    import(pathToFileURL(path.join(installation, 'dist/packages/coordinator/src/maintenance-state.js')).href),
    import(pathToFileURL(path.join(installation, 'dist/packages/coordinator/src/provider-leases.js')).href),
  ]);
  const { guard } = await loadNativeGuardReceipt(installation, { platform: process.platform, arch: process.arch });
  return withProviderMaintenance(guard, state + '-docker', async leases => {
    const rows = await readMaintenanceJobs(state + '-docker', guard, 'docker');
    return { verified: leases.active_leases.length === 0 && rows.every(row => row.value.phase === 'cleaned'), leases,
      jobs: rows.map(row => ({ path: row.file, sha256: row.sha256, phase: row.value.phase })) };
  }, { dryRun: true });
}

export async function prepareRuntimeFixture(root, installation, profile, { warm = false, requiredTools = ['validation_report'], workingTree = profile, signal } = {}) {
  const started = performance.now(), processes = [];
  let seeded = false, cache, state, setupStarted = false;
  const run = async (command, args, options) => {
    try { const result = await runOwned(command, args, options); processes.push({ command, args, code: result.code, cleanupVerified: result.cleanupVerified }); return result; }
    catch (error) { processes.push({ command, args, code: error.result?.code ?? null, cleanupVerified: error.result?.cleanupVerified === true }); throw error; }
  };
  try {
  if (signal?.aborted) throw new Error('RUNTIME_FIXTURE_CANCELLED');
  need(process.platform === 'darwin', 'native macOS cache fixture is required');
  need(typeof warm === 'boolean' && Array.isArray(requiredTools) && requiredTools.length > 0 && requiredTools.every((name) => ['validation_report', 'sentence_render'].includes(name)), 'fixture setup capabilities are unsupported');
  profile = owned(root, profile); owned(root, installation);
  state = path.join(profile, 'Library/Application Support/ud-agent/userspace');
  need(!existsSync(state + '-docker'), 'runtime profile is not cold');
  const assets = runtimeAssetInventory(installation);
  await seedOfflineProviderAssets(installation, { offline_assets: assets.files.map((item) => ({ ...item, sha256: item.sha256.slice(7) })) }, installation, state, { engine: 'docker', worker: 'linux/arm64', target: 'macos-arm64' });
  seeded = true; cache = cachedRows(installation, state);
  if (signal?.aborted) throw new Error('RUNTIME_FIXTURE_CANCELLED');
  need(!existsSync(path.join(state + '-docker', 'probe.json')) && !existsSync(path.join(state + '-docker', 'probe-render.json')), 'fixture unexpectedly created runtime readiness');
  const docker = executable('docker'); need(docker, 'native Docker executable is missing');
  const endpoint = process.env.DOCKER_HOST ?? (await run(docker, ['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], { timeout: 10_000, ...(signal ? { signal } : {}) })).stdout.trim();
  need(endpoint.startsWith('unix:///') && !/\s/.test(endpoint) && !endpoint.includes(String.fromCharCode(0)), 'private cache fixture requires a local Docker Unix endpoint');
  const { DOCKER_CONTEXT: _context, ...environment } = process.env; environment.DOCKER_HOST = endpoint;
  cache = cachedRows(installation, state); const engine = await engineImages(docker, environment, cache, signal, run);
  let preparation;
  if (warm) {
    need(path.isAbsolute(workingTree) && workingTree.startsWith(root + path.sep), 'fixture working tree must be repository-owned');
    const args = [path.join(installation, 'dist/packages/coordinator/src/entry.js'), 'doctor', '--fix', '--offline', '--engine', 'docker', '--working-tree', workingTree, '--required-tools', requiredTools.join(','), '--json'];
    setupStarted = true;
    const result = await run(process.execPath, args, { cwd: workingTree, env: { ...privateEnvironment(root, profile), DOCKER_HOST: endpoint }, timeout: 90_000, maximumBytes: 4 * 1024 ** 2, ...(signal ? { signal } : {}) });
    const response = JSON.parse(result.stdout);
    need(response.operation === 'setup_ud_environment' && response.execution?.status === 'completed' && response.result?.ready === true && response.result?.runtime?.engine === 'docker', 'deterministic warm fixture setup did not complete');
    preparation = { qualification: 'deterministic-fixture-preparation-not-model-execution', command: process.execPath, args, response, stderr: result.stderr, cleanup_verified: result.cleanupVerified === true };
    need(preparation.cleanup_verified, 'deterministic preparation process release is unverified');
  }
  const jobs = setupStarted ? await fixtureJobRelease(installation, state) : { verified: true, reason: 'No setup or worker process was started.' };
  need(jobs.verified, 'fixture preparation left pending worker jobs');
  return { preparation_processes: processes, jobs, schema_version: 1, qualification: warm ? 'deterministic-warm-runtime-fixture' : 'input-only-cold-runtime-fixture', installation, profile, state, cache, engine, docker, endpoint, asset_inventory_sha256: assets.sha256,
    environment: { DOCKER_HOST: endpoint }, warm, preparation, prep_elapsed_ms: performance.now() - started, readiness_probes_created: warm, initial_readiness_absent: !warm, before_preparation_readiness_absent: true };  } catch (error) {
    let jobs = setupStarted ? { verified: false, reason: 'Setup began; worker release is unverified.' } : { verified: true, reason: 'No setup or worker process was started.' };
    if (setupStarted && processes.every(process => process.cleanupVerified === true)) {
      try { jobs = await fixtureJobRelease(installation, state); } catch (jobError) { jobs = { verified: false, reason: jobError.message }; }
    }
    const verified = fixturePreparationRelease(processes, { setupStarted, jobs });
    let partialCache;
    if (seeded && cache && verified) {
      try { partialCache = cleanupRuntimeFixture({ installation, state, cache }, { nativeCleanupVerified: true, pendingOperations: 0 }); }
      catch (cleanupError) { partialCache = { verified: false, reason: cleanupError.message }; }
    }
    error.owned_cleanup_verified = verified;
    error.runtime_fixture_cleanup = { owned_cleanup_verified: verified, processes, jobs, seeded, partial_cache_cleanup: partialCache ?? null, unknown_entries_preserved: true };
    throw error;
  }
}

/** Reconcile actual reuse of the preexisting immutable image, separately from setup. */
export async function observeRuntimeFixture(fixture, events) {
  const { DOCKER_CONTEXT: _context, ...environment } = process.env; environment.DOCKER_HOST = fixture.endpoint;
  const cache = cachedRows(fixture.installation, fixture.state), engine = await engineImages(fixture.docker, environment, cache);
  const probes = ['probe.json', 'probe-render.json'].filter((name) => existsSync(path.join(fixture.state + '-docker', name))).map((name) => {
    const relative = path.join(fixture.state + '-docker', name), info = lstatSync(relative);
    need(info.isFile() && !info.isSymbolicLink(), 'readiness proof is not an ordinary file');
    return { ...receipt(path.dirname(relative), path.basename(relative)), absolute_path: relative, value: read(relative) };
  });
  return reconcileRuntimeFixture(fixture, { cache, engine, probes, events });
}

export function reconcileRuntimeFixture(fixture, { cache, engine, probes, events }) {
  const cold = fixture.qualification === 'input-only-cold-runtime-fixture' && fixture.readiness_probes_created === false && fixture.initial_readiness_absent === true;
  const warm = fixture.qualification === 'deterministic-warm-runtime-fixture' && fixture.preparation?.response?.result?.ready === true && fixture.preparation?.cleanup_verified === true;
  need((cold || warm) && Array.isArray(cache) && cache.length > 0 && engine.images?.length > 0, 'runtime fixture evidence is absent');
  need(JSON.stringify(cache) === JSON.stringify(fixture.cache), 'cold cache bytes or file identities changed');
  need(JSON.stringify(engine) === JSON.stringify(fixture.engine), 'worker engine identity changed');
  const initial = events.find((event) => event.type === 'operation_step' && event.step === 'runtime_readiness' && event.observation?.stage === 'initial')?.observation.result;
  const executed = events.filter((event) => event.type === 'operation_result' && event.response?.structuredContent?.execution?.status === 'completed').map((event) => event.response.structuredContent);
  const reused = executed.filter((envelope) => fixture.engine.images.some((image) => image.image_digest === envelope.provenance?.image_digest));
  const bound = reused.filter((envelope) => probes.some((probe) => probe.value.image?.digest === envelope.provenance.image_digest));
  return { type: 'runtime_fixture', verified: bound.length > 0, ...(bound.length ? { initiallyReady: warm } : {}),
    ...(bound.length ? { reusedAssets: true } : {}), proof: { kind: 'preexisting-engine-image-used-with-unchanged-cached-transports', initial_readiness_absent: cold, first_domain_check: initial, cache, engine, probes: probes.map(({ value: _value, ...row }) => row), executed_image_digests: bound.map((envelope) => envelope.provenance.image_digest) } };
}

/** Caller must first verify native/bridge release and zero pending UD operations. */
export function cleanupRuntimeFixture(fixture, { nativeCleanupVerified, pendingOperations } = {}) {
  need(nativeCleanupVerified === true && pendingOperations === 0, 'runtime fixture cleanup requires verified execution release');
  const current = cachedRows(fixture.installation, fixture.state);
  need(JSON.stringify(current) === JSON.stringify(fixture.cache), 'seeded archive identity changed before cleanup');
  for (const row of current) unlinkSync(row.path);
  need(current.every((row) => !existsSync(row.path)), 'seeded archive cleanup is incomplete');
  return { type: 'runtime_fixture_cleanup', verified: true, removed: current, preserved: 'All readiness, cache metadata, task files, and unknown entries.' };
}
