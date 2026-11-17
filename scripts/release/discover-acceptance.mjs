#!/usr/bin/env node
/** Discover requirements before reading outcomes. Discovery is never a pass. */
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileReceipt, readRecordedBytes, safeRelative, sha256, sourceReceipt } from './candidate.mjs';
import { canonicalJson } from './http-transports.mjs';
import { requiredMutationBackends, verifyMutationBackendDiscovery, boundedMutationPolicy, mutationRequirements, BOUNDED_MUTATION_SUITE } from './mutation-backends.mjs';
import { inheritedStorageDirectory } from '../quality/storage-lifecycle.mjs';
import { isWithinStorage } from '../quality/original-storage.mjs';
import { nativeTestApplicability, verifyNativeTestApplicability } from '../quality/native-test-scopes.mjs';

const INVENTORY = 'quality/acceptance-inventory.json';
const SHA = /^[a-f0-9]{64}$/;
const PYTHON_LIST = String.raw`import inspect,json,pathlib,sys,unittest
root=pathlib.Path(sys.argv[1]).resolve();start=root/sys.argv[2]
sys.path.insert(0,str(root/'workers/ud/src'))
suite=unittest.TestLoader().discover(str(start),pattern='test_*.py')
def visit(node):
 if isinstance(node,unittest.TestSuite):
  for child in node:yield from visit(child)
 else:
  if node.__class__.__name__=='_FailedTest':raise RuntimeError('test discovery failed: '+str(node))
  source=pathlib.Path(inspect.getsourcefile(node.__class__)).resolve().relative_to(root).as_posix()
  yield {'name':node.id(),'source':source}
print(json.dumps(list(visit(suite)),sort_keys=True))`;

function insist(value, message) { if (!value) throw new Error(`Acceptance discovery: ${message}`); }
export function isAcceptanceSource(value) {
  return typeof value === 'string' && !value.includes('\\') && !value.includes('\0') && !value.includes(':') && !value.split('/').some(part => !part || part === '.' || part === '..') &&
    (/^tests\//.test(value) || /^packages\/[^/]+\/(?:tests|src)\/.*\.rs$/.test(value) || /^scripts\/quality\/rust-assertion-parser\/(?:src|tests)\/.*\.rs$/.test(value) || /^scripts\/(?:quality|release)\/[^/]+\.(?:mjs|py)$/.test(value));
}
export function acceptanceInputHash(source) {
  // Excluding only the generated output avoids a source-hash fixed point. The
  // final candidate's source hash still includes that output and its receipts.
  return sha256(canonicalJson(source.files.filter(item => item.path !== INVENTORY)));
}
const identity = (runner, source, name) => `${runner}:${source}#${sha256(name).slice(0, 24)}`;
const ordered = rows => rows.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const recordedPaths = root => /^(?:[A-Za-z]:[\\/]|\\\\)/.test(root) ? path.win32 : path.posix;
const recordedRelative = (root, filename) => recordedPaths(root).relative(root, filename).split(recordedPaths(root).sep).join('/');
const testFiles = source => source.files.filter(item => /^tests\/(?:.*\.test\.[cm]?[jt]sx?$|(?:.*\/)?test_[^/]+\.py$)/.test(item.path));
const pythonDirectories = source => [...new Set(testFiles(source).filter(item => /\/test_[^/]+\.py$/.test(item.path)).map(item => path.posix.dirname(item.path)))].sort();

/** Fixed first-party Rust workspaces, derived from source before outcomes. */
export function rustCollectionCommands(source) {
  const commands = [['test', '--locked', '-p', 'ud-agent-launcher', '--no-run', '--message-format=json']];
  for (const manifest of ['scripts/quality/rust-assertion-parser/Cargo.toml']) if (source.files.some(item => item.path === manifest)) commands.push(['test', '--locked', '--manifest-path', manifest, '--no-run', '--message-format=json']);
  return commands;
}
export function rustPreparationCommands() {
  return [['build', '--locked', '--bins', '-p', 'ud-agent-launcher', '--message-format=json']];
}

export function parseDiscoveryTranscript(root, transcript) {
  insist(transcript && ['vitest', 'python', 'rust'].includes(transcript.runner) && typeof transcript.stdout === 'string' && transcript.stdout_sha256 === sha256(transcript.stdout), 'invalid discovery transcript');
  let rows;
  if (transcript.runner === 'vitest') {
    insist(transcript.args?.includes('--staticParse=false') && transcript.args.includes('--json'), 'Vitest discovery must execute collection, including parameterized cases');
    const data = JSON.parse(transcript.stdout);
    insist(Array.isArray(data), 'invalid Vitest collection');
    rows = data.map(item => ({ source: recordedRelative(transcript.collection_root ?? root, item.file), name: item.name }));
  } else if (transcript.runner === 'python') {
    insist(transcript.args?.includes(PYTHON_LIST), 'Python collection must use the complete unittest loader');
    rows = JSON.parse(transcript.stdout);
    insist(Array.isArray(rows), 'invalid Python collection');
  } else {
    insist(isAcceptanceSource(transcript.source) && transcript.args?.join('\0') === '--list\0--format\0terse', 'invalid Rust collection');
    const lines = transcript.stdout.trim().split(/\r?\n/).filter(Boolean);
    insist(lines.every(line => /: test$/.test(line) || /^\d+ tests?, \d+ benchmarks?$/.test(line)), 'unexpected Rust collection output');
    rows = lines.filter(line => line.endsWith(': test')).map(line => ({ source: transcript.source, name: line.slice(0, -6) }));
  }
  const occurrences = new Map();
  return rows.map(item => {
    insist(item && isAcceptanceSource(item.source) && typeof item.name === 'string' && item.name.length > 0, 'unsafe or empty discovered test');
    const source = fileReceipt(root, item.source);
    const key = `${item.source}\0${item.name}`, occurrence = occurrences.get(key) ?? 0;
    occurrences.set(key, occurrence + 1);
    // Parameterized runners can print the same display name for distinct cases.
    // Preserve every occurrence in declaration order; never deduplicate tests.
    return { id: identity(transcript.runner, item.source, canonicalJson([item.name, occurrence])), source: item.source, source_sha256: source.sha256, name: item.name, occurrence, runner: transcript.runner };
  });
}

/** @param {string} root @param {NodeJS.ProcessEnv | Record<string, any>} [supplied] @param {{python?: string}} [options] */
export function discoveryEnvironment(root, supplied = process.env, { python } = {}) {
  const environment = { CI: 'true', PYTHONPATH: path.join(root, 'workers/ud/src'), CARGO_NET_OFFLINE: 'true', CARGO_TERM_COLOR: 'never', LANG: 'C', LC_ALL: 'C' };
  for (const key of ['PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'TMPDIR', 'TMP', 'TEMP', 'CARGO_HOME', 'RUSTUP_HOME']) if (typeof supplied[key] === 'string') environment[key] = supplied[key];
  if (supplied.UD_STORAGE_LEASE !== undefined) {
    const scratch = inheritedStorageDirectory(supplied);
    insist(scratch && typeof supplied.TMPDIR === 'string' && isWithinStorage(scratch, supplied.TMPDIR), 'original-test temporary files require the active private storage reservation');
    environment.UD_STORAGE_LEASE = supplied.UD_STORAGE_LEASE;
    environment.PYTHONDONTWRITEBYTECODE = '1';
  }
  if (python !== undefined) {
    insist(typeof python === 'string' && path.isAbsolute(python) && !python.includes('\0'), 'selected original Python must be an absolute executable path');
    environment.UD_AGENT_PYTHON = python; environment.UD_RELEASE_PYTHON = python;
  }
  if (supplied.RUSTUP_TOOLCHAIN !== undefined) {
    const selected = supplied.RUSTUP_TOOLCHAIN, allowed = new Set();
    const local = path.join(root, 'rust-toolchain.toml'), roles = path.join(root, 'quality/toolchain.lock.json');
    if (existsSync(local)) { const match = /^\s*channel\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$/m.exec(readFileSync(local, 'utf8')); if (match) allowed.add(match[1]); }
    if (existsSync(roles)) {
      const declared = JSON.parse(readFileSync(roles, 'utf8'));
      if (declared.schema_version === 1) for (const key of ['host_original_rust', 'release_and_ci_rust']) if (/^[0-9]+\.[0-9]+\.[0-9]+$/.test(declared.roles?.[key] ?? '')) allowed.add(declared.roles[key]);
    }
    insist(typeof selected === 'string' && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(selected) && allowed.has(selected), 'explicit Rust toolchain is not a source-pinned original/CI version');
    environment.RUSTUP_TOOLCHAIN = selected;
  }
  return environment;
}
function collect(root, program, args, extra = {}, python) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 180_000, maxBuffer: 64 * 1024 * 1024,
    env: discoveryEnvironment(root, process.env, { python }) });
  insist(!result.error && result.status === 0 && !result.signal, `collection failed: ${program}: ${result.error?.message ?? result.stderr}`);
  const executable = realpathSync(program);
  return { ...extra, collection_root: root, command: executable, executable_sha256: sha256(readFileSync(executable)), args,
    ...(python === undefined ? {} : { selected_python: python }),
    stdout: result.stdout, stdout_sha256: sha256(result.stdout), stderr: result.stderr };
}

export function protectedCollectionConfigSource(collectionRoot, cache, original) {
  const originalUrl = 'file://' + path.posix.join(collectionRoot, original).split('/').map(part => encodeURIComponent(part)).join('/');
  return 'import original from ' + JSON.stringify(originalUrl) + ';\nif(!original||typeof original!=="object"||Array.isArray(original))throw Error("Original collection config must be an object");\nexport default {...original,root:' + JSON.stringify(collectionRoot) + ',cacheDir:' + JSON.stringify(path.posix.join(cache, 'vite-cache')) + ',test:{...original.test,cache:false,fsModuleCache:false}};\n';
}
function protectedCollectionProfile(root, cache, originalSource) {
  insist(process.platform !== 'win32' && path.isAbsolute(cache) && cache === path.join(path.dirname(root), 'cache'), 'protected collection requires the exact private POSIX job cache');
  const info = lstatSync(cache); insist(info.isDirectory() && !info.isSymbolicLink() && (info.mode & 0o777) === 0o700 && info.uid === process.getuid(), 'protected collection cache is not a private owned directory');
  const names = ['vitest.config.mts', 'vitest.config.mjs', 'vitest.config.ts', 'vitest.config.js'].filter(name => existsSync(path.join(root, name))); insist(names.length === 1, 'one original collection configuration is required');
  const original = fileReceipt(root, names[0]), source = protectedCollectionConfigSource(root, cache, original.path), filename = path.join(cache, 'acceptance-vitest.config.mjs');
  writeFileSync(filename, source, { flag: 'wx', mode: 0o400 });
  return { schema_version: 1, kind: originalSource ? 'protected-private-original-collection' : 'protected-readonly-original-collection', collection_root: root, cache, original_config: original, wrapper: { ...fileReceipt(cache, 'acceptance-vitest.config.mjs'), source }, ...(originalSource ? { original_source: { root: originalSource.root, input_sha256: acceptanceInputHash(sourceReceipt(root)) } } : {}) };
}
function collectionArguments(root, profile) {
  return [recordedPaths(root).join(root, 'node_modules/vitest/vitest.mjs'), 'list', '--json', '--staticParse=false', ...(profile ? ['--config', recordedPaths(root).join(profile.cache, profile.wrapper.path), '--configLoader=runner'] : [])];
}
function verifyCollectionProfile(root, catalog) {
  const profile = catalog.collection_profile;
  if (profile === undefined) return;
  const recordedRoot = catalog.collection_root;
  const privateCopy = profile?.kind === 'protected-private-original-collection';
  insist(profile?.schema_version === 1 && Object.keys(profile).sort().join(',') === (privateCopy ? 'cache,collection_root,kind,original_config,original_source,schema_version,wrapper' : 'cache,collection_root,kind,original_config,schema_version,wrapper') && (privateCopy || profile.kind === 'protected-readonly-original-collection') && profile.collection_root === recordedRoot && recordedRoot.startsWith('/') && profile.cache === path.posix.join(path.posix.dirname(recordedRoot), 'cache'), 'invalid protected collection profile');
  if (privateCopy) insist(profile.original_source && Object.keys(profile.original_source).sort().join(',') === 'input_sha256,root' && typeof profile.original_source.root === 'string' && profile.original_source.root.startsWith('/') && profile.original_source.input_sha256 === acceptanceInputHash(sourceReceipt(root)), 'protected original source copy binding differs');
  const configurations = ['vitest.config.mts', 'vitest.config.mjs', 'vitest.config.ts', 'vitest.config.js'].filter(name => existsSync(path.join(root, name)));
  insist(configurations.length === 1 && configurations[0] === profile.original_config?.path && canonicalJson(fileReceipt(root, profile.original_config.path)) === canonicalJson(profile.original_config), 'protected collection configuration source differs');
  const source = protectedCollectionConfigSource(recordedRoot, profile.cache, profile.original_config.path);
  insist(profile.wrapper?.path === 'acceptance-vitest.config.mjs' && Object.keys(profile.wrapper).sort().join(',') === 'executable,path,sha256,size,source' && profile.wrapper.source === source && profile.wrapper.sha256 === sha256(source) && profile.wrapper.size === Buffer.byteLength(source) && profile.wrapper.executable === false, 'protected collection wrapper differs from the exact cache-only derivation');
}

/** Actual runner collection; test bodies and installed acceptance do not run. */
/** @param {string} root @param {{python?: string, cargo?: string, protectedCache?: string, protectedSource?: {root:string,sha256:string}}} [options] */
export function discoverAcceptance(root, { python, cargo, protectedCache, protectedSource } = {}) {
  root = realpathSync(root);
  const source = sourceReceipt(root), transcripts = [];
  const nativeApplicability = nativeTestApplicability(root, process.platform, source);
  const pythonFile = python ?? (existsSync(path.join(root, '.venv/bin/python')) ? path.join(root, '.venv/bin/python') : undefined);
  insist(pythonFile && cargo && path.isAbsolute(pythonFile) && path.isAbsolute(cargo), 'absolute Python and cargo executables are required');
  const pythonCanonical = realpathSync(pythonFile), pythonIdentity = { path: pythonFile, canonical_path: pythonCanonical, sha256: sha256(readFileSync(pythonCanonical)) };
  if (protectedSource) insist(protectedCache !== undefined && path.isAbsolute(protectedSource.root) && protectedSource.sha256 === source.sha256 && sourceReceipt(protectedSource.root).sha256 === source.sha256, 'protected collection copy differs from the immutable original');
  const collectionProfile = protectedCache === undefined ? undefined : protectedCollectionProfile(root, protectedCache, protectedSource);
  const preparations = rustPreparationCommands().map(args => collect(root, cargo, args, { runner: 'cargo-prerequisite-build' }, pythonFile));
  const builds = [];
  for (const args of rustCollectionCommands(source)) {
    const compiled = collect(root, cargo, args, { runner: 'cargo-build' }, pythonFile); builds.push(compiled);
    const targets = compiled.stdout.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).filter(item => item.reason === 'compiler-artifact' && item.profile?.test && item.executable);
    insist(targets.length > 0, 'cargo did not discover test binaries');
    for (const target of targets) transcripts.push(collect(root, target.executable, ['--list', '--format', 'terse'], { runner: 'rust', source: path.relative(root, target.target.src_path).split(path.sep).join('/') }, pythonFile));
  }
  // Original test modules may inspect their same-source native fixture binaries
  // while being imported. Reuse the complete Cargo builds before either JS or
  // Python collection; libtest --list still never runs a test body.
  transcripts.push(collect(root, process.execPath, collectionArguments(root, collectionProfile), { runner: 'vitest' }, pythonFile));
  const directories = pythonDirectories(source);
  for (const directory of directories) transcripts.push(collect(root, pythonFile, ['-I', '-B', '-c', PYTHON_LIST, root, directory], { runner: 'python', directory }, pythonFile));
  const tests = ordered(transcripts.flatMap(item => parseDiscoveryTranscript(root, item)));
  insist(new Set(tests.map(item => item.id)).size === tests.length && tests.length > 0, 'duplicate or empty discovered test identity');
  const discoveredFiles = new Set(tests.map(item => item.source));
  for (const file of testFiles(source)) {
    insist(discoveredFiles.has(file.path), `test file omitted by runners: ${file.path}`);
  }
  insist(acceptanceInputHash(sourceReceipt(root)) === acceptanceInputHash(source), 'source changed during discovery');
  if (collectionProfile) { const { source: _source, ...receipt } = collectionProfile.wrapper; insist(canonicalJson(fileReceipt(protectedCache, collectionProfile.wrapper.path)) === canonicalJson(receipt), 'protected collection wrapper changed during discovery'); }
  return { schema_version: 1, kind: 'acceptance-discovery', qualification: 'inventory-only-no-outcomes', collection_root: root, input_sha256: acceptanceInputHash(source),
    ...(collectionProfile ? { collection_profile: collectionProfile } : {}), ...(nativeApplicability ? { native_applicability: nativeApplicability } : {}), collection_python: pythonIdentity, prerequisite_build_transcripts: preparations, environment: { os: process.platform, process_arch: process.arch }, transcripts, build_transcript: builds[0], build_transcripts: builds, tests };
}

function task(source, name, execution_kind = 'installed', extra = {}) {
  return { id: identity('task', source, name), source, name, runner: 'task', execution_kind, ...extra };
}
function suiteTests(id, catalog) {
  const all = catalog.tests;
  if (id === 'unit') return all;
  if (id === 'contracts-104') return all.filter(item => item.source.startsWith('tests/contracts/'));
  if (id === 'static') return [task('scripts/quality/check.mjs', 'complete static and generated-contract gates', 'static')];
  if (id === 'security') return all.filter(item => item.source.startsWith('tests/runtime/') || item.runner === 'rust');
  if (id === 'protocol-modern' || id === 'protocol-legacy') return [24, 26].map(node => task('scripts/quality/installed-mcp-smoke.mjs', `${id}:Node${node}`, 'installed-protocol'));
  if (id === 'skills-hosts') return [...all.filter(item => /(?:connect|host-adapters)/.test(item.source)),
    task('scripts/quality/grok-native-smoke.mjs', 'native Grok catalog install and remove without model requests', 'host-fixture'),
    task('scripts/quality/codex-native-smoke.mjs', 'native Codex pinned catalog and local payload install and remove without model or network requests', 'host-fixture'),
    ...['codex','claude','gemini'].flatMap(host => ['oci','uv','venv'].map(runtime_route => task('scripts/quality/run-workflow-evals.mjs', `${host}:${runtime_route}:complete-scripted-workflow-replay`, 'scripted-host-replay', {host,runtime_route,model_requests:0,model_routing:'pending-external'})))];
  if (id === 'release-reconciliation') return all.filter(item => /^tests\/release\/(?:http-publication|release)\.test\./.test(item.source));
  if (/^worker-linux-(?:amd64|arm64)$/.test(id)) return [task('scripts/quality/installed-operation-matrix.mjs', `${id}:all102:OCI`, 'native-worker'), task('scripts/quality/installed-oci-workflows.mjs', `${id}:offline-render-and-project-code`, 'native-worker')];
  if (/^install-(?:linux|macos|windows)-(?:amd64|arm64)$/.test(id)) return ['native', 'npm', 'mcpb'].flatMap(format => [24, 26].map(node => task('scripts/quality/installed-mcp-smoke.mjs', `${id}:${format}:Node${node}`, 'native-install')));
  if (/^runtime-(?:linux|macos|windows)-(?:amd64|arm64)$/.test(id)) return [
    task('scripts/quality/native-provider-acceptance.mjs', `${id}:public-MCP:original-native-and-MCPB:all102-and-cleanup`, 'native-provider'),
    task('scripts/quality/installed-operation-matrix.mjs', `${id}:OCI:all102`, 'native-provider'),
    ...['uv', 'venv'].flatMap(installer => [task('scripts/quality/installed-operation-matrix.mjs', `${id}:${installer}:supported101-and-explicit050-rejection`, 'native-provider'), task('scripts/quality/installed-workflows.mjs', `${id}:${installer}:cold-warm-render-preview-apply-export`, 'native-provider')]),
  ];
  if (/^signing-(?:macos|windows)$/.test(id)) return [task('scripts/release/verify.mjs', `${id}:production-authority-and-native-verification`, 'external-signing')];
  throw new Error(`Acceptance discovery: no independent route for suite ${id}`);
}

/** Schedule receipts must be produced by backend discovery, before results. */
export function compileAcceptanceInventory(root, catalog, requirements, schedules = [], { verifyBackendDiscovery, profile = 'exhaustive' } = {}) {
  requirements = mutationRequirements(requirements, profile);
  const source = sourceReceipt(root), hashes = new Map(source.files.map(item => [item.path, item.sha256]));
  const bounded = profile === 'bounded' ? boundedMutationPolicy(root, source) : null;
  insist(catalog?.schema_version === 1 && catalog.kind === 'acceptance-discovery' && catalog.qualification === 'inventory-only-no-outcomes' && catalog.input_sha256 === acceptanceInputHash(source), 'stale discovery source');
  const nativeApplicability = verifyNativeTestApplicability(root, catalog.native_applicability, catalog.environment?.os, source);
  const recollected = ordered(catalog.transcripts.flatMap(item => parseDiscoveryTranscript(root, item)));
  insist(canonicalJson(recollected) === canonicalJson(catalog.tests), 'discovered tests differ from runner transcripts');
  insist(recollected.length > 0 && new Set(recollected.map(item => item.id)).size === recollected.length, 'duplicate or empty discovered tests');
  const collectionRoot = catalog.collection_root;
  insist(typeof collectionRoot === 'string' && recordedPaths(collectionRoot).isAbsolute(collectionRoot) && catalog.transcripts.every(item => item.collection_root === collectionRoot), 'missing collection root binding');
  const vitest = catalog.transcripts.filter(item => item.runner === 'vitest');
  verifyCollectionProfile(root, catalog);
  insist(vitest.length === 1 && canonicalJson(vitest[0].args) === canonicalJson(collectionArguments(collectionRoot, catalog.collection_profile)), 'filtered or missing Vitest collection');
  const python = catalog.transcripts.filter(item => item.runner === 'python');
  insist(canonicalJson(python.map(item => item.directory).sort()) === canonicalJson(pythonDirectories(source)), 'filtered, duplicate or missing Python collection');
  for (const item of python) insist([['-I', '-B', '-c', PYTHON_LIST, collectionRoot, item.directory], ['-I', '-c', PYTHON_LIST, collectionRoot, item.directory]].some(args => canonicalJson(item.args) === canonicalJson(args)), 'filtered Python collection');
  const build = catalog.build_transcript;
  const builds = catalog.build_transcripts ?? [build], requiredBuilds = rustCollectionCommands(source);
  insist(Array.isArray(builds) && builds.length === requiredBuilds.length && canonicalJson(builds[0]) === canonicalJson(build), 'missing complete Rust workspace discovery');
  if (catalog.collection_python !== undefined) {
    const selected = catalog.collection_python;
    const prerequisites = catalog.prerequisite_build_transcripts, required = rustPreparationCommands();
    insist(Array.isArray(prerequisites) && prerequisites.length === required.length && prerequisites.every((item, index) => item?.runner === 'cargo-prerequisite-build' && canonicalJson(item.args) === canonicalJson(required[index]) && item.collection_root === collectionRoot && item.stdout_sha256 === sha256(item.stdout) && typeof item.stderr === 'string' && recordedPaths(collectionRoot).isAbsolute(item.command) && SHA.test(item.executable_sha256)), 'missing exact original native binary preparation');
    insist(selected && Object.keys(selected).sort().join(',') === 'canonical_path,path,sha256' && recordedPaths(collectionRoot).isAbsolute(selected.path) && recordedPaths(collectionRoot).isAbsolute(selected.canonical_path) && SHA.test(selected.sha256) && [...catalog.transcripts, ...builds, ...prerequisites].every(item => item.selected_python === selected.path) && python.every(item => item.command === selected.canonical_path && item.executable_sha256 === selected.sha256), 'selected Python collection identity differs');
  } else insist(catalog.collection_profile?.kind !== 'protected-private-original-collection', 'protected collection is missing selected Python identity');
  for (const [index, compiled] of builds.entries()) insist(compiled?.runner === 'cargo-build' && compiled.stdout_sha256 === sha256(compiled.stdout) && canonicalJson(compiled.args) === canonicalJson(requiredBuilds[index]), 'missing complete Rust target discovery');
  const targets = builds.flatMap(compiled => {
    const discovered = compiled.stdout.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).filter(item => item.reason === 'compiler-artifact' && item.profile?.test && item.executable);
    insist(discovered.length > 0, 'empty Rust workspace target discovery'); return discovered;
  });
  const expectedRust = targets.map(item => ({ command: item.executable, source: recordedRelative(collectionRoot, item.target.src_path) })).sort((a, b) => a.command.localeCompare(b.command));
  const actualRust = catalog.transcripts.filter(item => item.runner === 'rust').map(({ command, source }) => ({ command, source })).sort((a, b) => a.command.localeCompare(b.command));
  insist(expectedRust.length > 0 && canonicalJson(expectedRust) === canonicalJson(actualRust), 'filtered, duplicate or missing Rust collection');
  const discoveredFiles = new Set(recollected.map(item => item.source));
  for (const file of testFiles(source)) insist(discoveredFiles.has(file.path), `test file omitted by runners: ${file.path}`);
  for (const item of [...catalog.transcripts, ...builds]) insist(typeof item.command === 'string' && recordedPaths(collectionRoot).isAbsolute(item.command) && SHA.test(item.executable_sha256 ?? '') && typeof item.stderr === 'string', 'unbound runner identity');
  insist(requirements?.schema_version === 1 && Array.isArray(requirements.required_suites) && requirements.required_suites.length > 0 && new Set(requirements.required_suites).size === requirements.required_suites.length, 'invalid required suites');
  const scheduleMap = new Map();
  const authorities = new Map();
  const inventorySigners = new Map();
  for (const schedule of schedules) {
    insist(schedule?.schema_version === 1 && schedule.inventory_only === true && typeof schedule.suite_id === 'string' && schedule.suite_id.startsWith('mutation-'), 'invalid independent mutation schedule');
    insist(Array.isArray(schedule.tests) && schedule.tests.length > 0 && Array.isArray(schedule.mutants) && schedule.mutants.length > 0, 'empty independent mutation schedule');
    const shard = schedule.shard;
    if (shard) insist(Number.isSafeInteger(shard.index) && Number.isSafeInteger(shard.count) && shard.count > 0 && shard.index >= 0 && shard.index < shard.count && Number.isSafeInteger(shard.scheduled) && shard.scheduled > 0 && SHA.test(shard.inventory_sha256 ?? ''), 'invalid mutation shard plan');
    const record = schedule.backend_discovery;
    insist(record && typeof record.path === 'string' && SHA.test(record.sha256 ?? ''), 'independent complete backend discovery missing');
    const authorityId = `${record.path}\0${record.sha256}\0${canonicalJson(record.signature ?? null)}`;
    let authority = authorities.get(authorityId);
    if (!authority) { authority = verifyMutationBackendDiscovery(root, record, source, acceptanceInputHash(source), verifyBackendDiscovery); authorities.set(authorityId, authority); }
    const tool = authority.backend.tool;
    if (bounded) insist(schedule.suite_id === BOUNDED_MUTATION_SUITE && tool === 'fault-canary', 'bounded discovery cannot claim an exhaustive backend suite');
    let combined = scheduleMap.get(schedule.suite_id);
    if (!combined) {
      combined = { tests: [], testMap: new Map(), mutants: [], ids: new Set(), definitions: new Set(), backends: new Map() };
      scheduleMap.set(schedule.suite_id, combined);
    }
    const previous = combined.backends.get(tool);
    insist(!previous || previous.authorityId === authorityId, 'multiple conflicting discovery masters for one backend');
    if (previous) insist(shard && previous.shard && !previous.indices.has(shard.index) && shard.count === previous.shard.count && shard.scheduled === previous.shard.scheduled && shard.inventory_sha256 === previous.shard.inventory_sha256 && canonicalJson(schedule.tests) === canonicalJson(previous.tests), 'duplicate or inconsistent mutation shard');
    else combined.backends.set(tool, { authorityId, authority, mutants: [], tests: schedule.tests, shard, indices: new Set() });
    const backend = combined.backends.get(tool);
    if (shard) backend.indices.add(shard.index);
    const tests = new Set();
    for (const test of schedule.tests) {
      insist(isAcceptanceSource(test?.source) && hashes.get(test.source) === test.source_sha256 && typeof test.id === 'string' && test.id.length > 0 && !tests.has(test.id), 'unbound or duplicate mutation test');
      insist(!('status' in test) && !('killed_by' in test), 'mutation discovery contains supplied outcomes');
      const independentlyDiscovered = recollected.find(item => item.id === (test.discovered_id ?? test.id));
      insist(independentlyDiscovered && independentlyDiscovered.source === test.source, 'mutation test is absent from independent runner discovery');
      tests.add(test.id);
      const prior = combined.testMap.get(test.id);
      insist(!prior || canonicalJson(prior) === canonicalJson(test), 'conflicting shared mutation test identity');
      if (!prior) { combined.testMap.set(test.id, test); combined.tests.push(test); }
    }
    for (const mutant of schedule.mutants) {
      const definition = `${mutant?.file}\0${mutant?.definition_sha256}`;
      insist(typeof mutant?.id === 'string' && mutant.id.length > 0 && !combined.ids.has(mutant.id) && !combined.definitions.has(definition) && hashes.get(mutant.file) === mutant.source_sha256 && SHA.test(mutant.source_sha256 ?? '') && mutant.definition && sha256(canonicalJson(mutant.definition)) === mutant.definition_sha256, 'unbound, duplicate or incomplete mutant definition');
      insist(!('status' in mutant) && !('killed_by' in mutant) && !('failure_kind' in mutant), 'mutation discovery contains supplied outcomes');
      if (bounded) {
        const declared = bounded.cases.find(row => row.id === mutant.id);
        insist(declared && declared.file === mutant.file && declared.source_sha256 === mutant.source_sha256 && declared.definition_sha256 === mutant.definition_sha256 && mutant.definition.operator === declared.id && mutant.definition.file === declared.file && mutant.definition.language === declared.language && mutant.definition.category === declared.category && mutant.definition.runner === declared.runner && mutant.definition.test === declared.test && mutant.definition.assertion === declared.assertion, 'bounded definition differs from its reviewed corpus');
      }
      combined.ids.add(mutant.id); combined.definitions.add(definition);
      // Definitions remain in bounded backend shards. The source-bound final
      // inventory needs only their exact identities and immutable fingerprints.
      combined.mutants.push({ id: mutant.id, file: mutant.file, source_sha256: mutant.source_sha256, definition_sha256: mutant.definition_sha256 });
    }
    backend.mutants.push(...schedule.mutants.map(({ id, file, source_sha256, definition_sha256 }) => ({ id, file, source_sha256, definition_sha256 })));
    if (authority.signer) inventorySigners.set(schedule.suite_id, [...new Set([...(inventorySigners.get(schedule.suite_id) ?? []), authority.signer])]);
  }
  for (const schedule of scheduleMap.values()) {
    ordered(schedule.mutants);
    for (const backend of schedule.backends.values()) {
      const mutants = ordered(backend.mutants);
      if (backend.shard) insist(backend.indices.size === backend.shard.count && mutants.length === backend.shard.scheduled && sha256(canonicalJson(mutants)) === backend.shard.inventory_sha256, 'incomplete mutation shard reconciliation');
      insist(canonicalJson(mutants) === canonicalJson(backend.authority.inventory), 'scheduled definitions differ from complete backend discovery');
    }
  }
  const suites = requirements.required_suites.map(id => {
    let tests, mutants;
    if (id.startsWith('mutation-')) {
      const schedule = scheduleMap.get(id); insist(schedule, `independent mutation schedule missing: ${id}`);
      insist(requiredMutationBackends[id]?.every(tool => schedule.backends.has(tool)), `required complete mutation backend missing: ${id}`);
      tests = schedule.tests; mutants = schedule.mutants;
      if (bounded) insist(mutants.length === 18 && bounded.cases.every(row => mutants.some(mutant => mutant.id === row.id) && tests.some(test => test.source === row.test_source)), 'bounded corpus definitions or required test sources are incomplete');
    } else tests = suiteTests(id, catalog);
    insist(tests.length > 0, `independently discovered suite is empty: ${id}`);
    tests = ordered(tests.map(test => ({ ...test, source_sha256: fileReceipt(root, test.source).sha256 })));
    return { id, tests, ...(mutants ? { mutants } : {}), ...(id === 'unit' && nativeApplicability ? { native_applicability: nativeApplicability } : {}), ...(bounded && id === BOUNDED_MUTATION_SUITE ? { profile: 'bounded', policy: bounded.policy, qualification: bounded.qualification, exhaustive: false, bounded_policy: bounded } : {}), ...(/^(?:install|runtime)-/.test(id) ? { native_platform: id.replace(/^(?:install|runtime)-/, '') } : {}) };
  });
  for (const id of scheduleMap.keys()) insist(requirements.required_suites.includes(id), `unscheduled mutation suite: ${id}`);
  insist(acceptanceInputHash(sourceReceipt(root)) === acceptanceInputHash(source), 'source changed while freezing the complete inventory');
  return { schema_version: 1, state: 'frozen', ...(bounded ? { profile: 'bounded', policy: bounded.policy, qualification: bounded.qualification, exhaustive: false, mutation_policy: bounded } : {}), ...(nativeApplicability ? { native_applicability: nativeApplicability } : {}), suites, ...(verifyBackendDiscovery ? { inventorySigners } : {}) };
}

export function acceptanceRequirements(requirements, inventory) {
  return mutationRequirements(requirements, inventory?.profile === undefined ? 'exhaustive' : inventory.profile);
}

function verifyProfileMetadata(expected, inventory) {
  if (expected.profile === 'bounded') for (const field of ['profile', 'policy', 'qualification', 'exhaustive', 'mutation_policy']) insist(canonicalJson(expected[field]) === canonicalJson(inventory[field]), 'bounded inventory policy differs from frozen source');
  insist(expected.native_applicability === undefined ? inventory.native_applicability === undefined : inventory.native_applicability !== undefined && canonicalJson(expected.native_applicability) === canonicalJson(inventory.native_applicability), 'frozen native obligations differ from independent discovery');
}

/** Replay unsigned local inventory bytes without granting production authority.
 * Every catalog, schedule and raw generation receipt is still checked by the
 * compiler; production callers must use the signature-requiring verifier. */
export function verifyLocalAcceptanceDiscovery(root, inventory, requirements) {
  const proof = inventory?.discovery;
  insist(proof?.schema_version === 1 && proof.algorithm === 'native-runner-discovery-v1' && Array.isArray(proof.schedules), 'independently discovered inventory is required');
  const read = record => JSON.parse(readRecordedBytes(root, record, 256 * 1024 * 1024).toString('utf8'));
  function* schedules() { for (const record of proof.schedules) yield read(record); }
  const expected = compileAcceptanceInventory(root, read(proof.catalog), requirements, schedules(), { profile: inventory.profile ?? 'exhaustive' });
  insist(canonicalJson(expected.suites) === canonicalJson(inventory.suites), 'frozen inventory differs from independent discovery');
  verifyProfileMetadata(expected, inventory);
  return { schema_version: 1, qualification: 'locally-replayed-unsigned-discovery-no-production-authority', input_sha256: acceptanceInputHash(sourceReceipt(root)), catalog: proof.catalog, schedules: proof.schedules };
}

/** No outcome list can add/remove required tests or scheduled mutant identities. */
export function verifyAcceptanceDiscovery(root, inventory, requirements, { verifyBackendDiscovery } = {}) {
  const proof = inventory?.discovery;
  insist(proof?.schema_version === 1 && proof.algorithm === 'native-runner-discovery-v1' && Array.isArray(proof.schedules), 'independently discovered inventory is required');
  const read = record => JSON.parse(readRecordedBytes(root, record, 256 * 1024 * 1024).toString('utf8'));
  function* schedules() { for (const record of proof.schedules) yield read(record); }
  insist(typeof verifyBackendDiscovery === 'function' || !requirements.required_suites.some(id => id.startsWith('mutation-')), 'independent inventory signature authority is required');
  const expected = compileAcceptanceInventory(root, read(proof.catalog), requirements, schedules(), { verifyBackendDiscovery, profile: inventory.profile ?? 'exhaustive' });
  insist(canonicalJson(expected.suites) === canonicalJson(inventory.suites), 'frozen inventory differs from independent discovery');
  verifyProfileMetadata(expected, inventory);
  return expected;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const root = realpathSync('.');
  let catalog, output, inventory;
  if (args[0] === '--freeze') {
    insist(args.length >= 4 && args.length % 2 === 0 && args[2] === '--output' && args.slice(4).every((arg, index) => index % 2 || arg === '--schedule'), 'usage: discover-acceptance.mjs --freeze CATALOG --output NEW_INVENTORY [--schedule DISCOVERED_SCHEDULE]...');
    const receipt = filename => fileReceipt(root, safeRelative(path.relative(root, path.resolve(filename)).split(path.sep).join('/')));
    const read = record => JSON.parse(readRecordedBytes(root, record, 256 * 1024 * 1024).toString('utf8'));
    const catalogReceipt = receipt(args[1]), scheduleReceipts = args.slice(4).filter((_, index) => index % 2).map(receipt);
    catalog = read(catalogReceipt);
    function* schedules() { for (const record of scheduleReceipts) yield read(record); }
    inventory = compileAcceptanceInventory(root, catalog, JSON.parse(readFileSync(path.join(root, 'quality/requirements.json'), 'utf8')), schedules());
    inventory.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: catalogReceipt, schedules: scheduleReceipts };
    output = args[3];
  } else {
    insist(args.length === 6 && args[0] === '--output' && args[2] === '--python' && args[4] === '--cargo', 'usage: discover-acceptance.mjs --output NEW_JSON --python ABSOLUTE_PYTHON --cargo ABSOLUTE_CARGO');
    output = args[1]; catalog = discoverAcceptance(root, { python: args[3], cargo: args[5] });
  }
  const relative = path.relative(root, path.resolve(output)).split(path.sep).join('/');
  safeRelative(relative); insist(!existsSync(path.join(root, relative)), 'discovery output already exists');
  mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
  writeFileSync(path.join(root, relative), JSON.stringify(inventory ?? catalog, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ qualification: inventory ? 'frozen-inventory-no-outcomes' : catalog.qualification, tests: catalog.tests.length, receipt: fileReceipt(root, relative) }));
}
