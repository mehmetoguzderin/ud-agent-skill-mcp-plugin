// SPDX-License-Identifier: MIT
import { test, expect } from 'vitest';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { sourceReceipt, fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { boundedFaultDefinitions } from '../../scripts/quality/fault-assess.mjs';
import { boundedMutationPolicy, mutationBackendFiles, mutationBackendContract, mutationRequirements, authorityFromGeneration } from '../../scripts/release/mutation-backends.mjs';
import { acceptanceInputHash, compileAcceptanceInventory, parseDiscoveryTranscript, verifyAcceptanceDiscovery, verifyLocalAcceptanceDiscovery } from '../../scripts/release/discover-acceptance.mjs';
import { validateAcceptanceInventory, reconcileSuiteInventory } from '../../scripts/release/acceptance.mjs';
import { discoverBoundedMutationSession, evidenceInventory, sealBoundedMutationSession, openBoundedMutationSession, sealMutationSession, openMutationSession, mutationSessionOptions } from '../../scripts/quality/mutation-session.mjs';
import { discoveryFixture } from '../release/discovery-fixture.mjs';

test('session CLI selects the bounded profile explicitly without changing legacy defaults', () => {
  expect(mutationSessionOptions(['--profile','bounded','--discover','session','--python','/python','--cargo','/cargo','--image','sha256:'+'a'.repeat(64)])).toEqual({profile:'bounded',discover:'session',python:'/python',cargo:'/cargo',image:'sha256:'+'a'.repeat(64)});
  expect(mutationSessionOptions(['--seal','session','--profile','bounded'])).toEqual({profile:'bounded',seal:'session'});
  expect(mutationSessionOptions(['--discover','session','--python','/python','--cargo','/cargo']).profile).toBe('exhaustive');
  expect(mutationSessionOptions(['--seal','session']).profile).toBe('exhaustive');
  for(const args of [['--profile','other','--seal','session'],['--profile','bounded','--seal','session','--image','sha256:'+'a'.repeat(64)],['--profile','bounded','--discover','session','--python','/python'],['--profile','bounded','--discover','session','--python','/python','--cargo','/cargo','--image','mutable:latest'],['--profile','bounded','--profile','exhaustive','--seal','session'],['--seal','session','--discover','other'],['--profile']])expect(()=>mutationSessionOptions(args)).toThrow();
});

async function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-bounded-session-'));
  const put = (name, value) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value)); return file; };
  const backend = { tool: 'fault-canary', version: '1.0.0' }, files = mutationBackendFiles(backend);
  for (const name of [...files.generators, ...files.configuration]) put(name, '// Synthetic source identity; never executed.\n');
  const requirements = { schema_version: 1, required_suites: ['unit', 'mutation-typescript'], mutation_profiles: { bounded: { policy: 'bounded-reviewed-v1', suite: 'mutation-bounded', scheduled: 18, exhaustive: false } } };
  put('quality/requirements.json', requirements); put('tests/fixture.test.mjs', '// Synthetic collection source.\n');
  const targets = [['typescript', 'packages/example/value.mjs'], ['python', 'scripts/example.py'], ['rust', 'packages/launcher/src/main.rs'], ['perl', 'workers/ud/src/ud_agent/example.pl'], ['data', 'contracts/example.json']];
  const manifest = { schema_version: 1, profile: 'bounded', policy: 'bounded-reviewed-v1', qualification: 'bounded-reviewed-corpus', exhaustive: false, cases: Array.from({ length: 18 }, (_, index) => {
    const [language, file] = targets[index % targets.length], rust = language === 'rust';
    return { id: 'case_' + index, file, find: 'anchor_' + index + ';', replace: 'changed_' + index + ';', runner: rust ? 'rust' : 'vitest', test: rust ? 'packages/launcher/tests/discovery.rs::native_case' : 'tests/fixture.test.mjs', assertion: rust ? 'native_case' : 'one', language, category: 'fixture' };
  }) };
  for (const [, name] of targets) put(name, manifest.cases.filter(row => row.file === name).map(row => row.find).join('\n'));
  put('tests/mutation/fault-cases.json', manifest);
  const catalog = discoveryFixture(root), rust = catalog.transcripts.find(row => row.runner === 'rust');
  rust.stdout = 'native_case: test\n'; rust.stdout_sha256 = sha256(rust.stdout);
  catalog.tests.push(...parseDiscoveryTranscript(root, rust)); catalog.tests.sort((a, b) => a.id < b.id ? -1 : 1);
  const source = sourceReceipt(root), prefix = '.artifacts/session', directory = path.join(root, prefix);
  put(prefix + '/catalog.json', catalog);
  const inventory = boundedFaultDefinitions(manifest, name => readFileSync(path.join(root, name)), new Map(source.files.map(row => [row.path, row.sha256])));
  const compact = inventory.map(({ id, file, source_sha256, definition_sha256 }) => ({ id, file, source_sha256, definition_sha256 })).sort((a, b) => a.id < b.id ? -1 : 1);
  const raw = put(prefix + '/raw.json', { qualification: 'synthetic-generation-fixture-not-acceptance', inventory });
  const contract = mutationBackendContract(root, source, backend), artifact = fileReceipt(root, path.relative(root, raw).split(path.sep).join('/'));
  const generation = { schema_version: 1, kind: 'mutation-backend-generation', qualification: 'complete-backend-generation-no-outcomes', scope_complete: true, input_sha256: acceptanceInputHash(source), backend, ...contract, execution: { command: ['synthetic-fixture', '--inventory-only'], runtime: { kind: 'oci', image_id: 'sha256:' + 'a'.repeat(64) } }, inventory: compact, inventory_sha256: sha256(canonicalJson(compact)), raw_artifacts: [artifact], source_materializations: contract.sources.map(row => ({ source: row.path, source_sha256: row.sha256, mutant_ids: compact.filter(item => item.file === row.path).map(item => item.id), artifacts: [artifact] })) };
  put(prefix + '/generation.json', generation);
  put(prefix + '/backend.json', authorityFromGeneration(root, source, acceptanceInputHash(source), fileReceipt(root, prefix + '/generation.json')));
  const schedule = { schema_version: 1, inventory_only: true, suite_id: 'mutation-bounded', tests: catalog.tests, mutants: inventory, backend_discovery: fileReceipt(root, prefix + '/backend.json') };
  put(prefix + '/schedule.json', schedule);
  const acceptance = compileAcceptanceInventory(root, catalog, requirements, [schedule], { profile: 'bounded' });
  acceptance.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: fileReceipt(root, prefix + '/catalog.json'), schedules: [fileReceipt(root, prefix + '/schedule.json')] };
  put(prefix + '/acceptance-inventory.json', acceptance);
  const runtime = JSON.stringify({ platform: 'linux/arm64', qualification: 'synthetic-test-fixture-only' }), sdk = sha256(runtime), image = 'sha256:' + 'a'.repeat(64);
  const provider = (selected, folder) => {
    put(prefix + '/' + folder + '/runtime-input-receipt.json', runtime);
    put(prefix + '/' + folder + '/runner.json', { inventory_only: true, backend: selected, source_tree_sha256: source.sha256, image, status: 'executed-not-reconciled', worker: { platform: 'linux', architecture: 'arm64', emulation: false }, execution: { status: 0 }, container_state: { ExitCode: 0, Running: false, OOMKilled: false }, cleanup: ['job', 'input', 'state', 'carrier'].map(name => ({ kind: 'synthetic-fixture', name, status: 'removed-owned' })) });
    for (const name of ['isolation-proof.json', 'exec-isolation-proof.json']) put(prefix + '/' + folder + '/' + name, { status: 'passed', source_tree_sha256: source.sha256, runtime_input_sha256: sdk });
  };
  provider('catalog', 'catalog-discovery'); put(prefix + '/catalog-discovery/catalog.json', catalog);
  provider('faults', 'discovery/faults');
  const plan = { schema_version: 1, backend: 'faults', tool: 'fault-canary', source_tree_sha256: source.sha256, mutants: compact, tests: catalog.tests };
  put(prefix + '/discovery/faults/pre-outcome-plan.json', plan);
  put(prefix + '/faults-frozen.json', { schema_version: 1, image_id: image, runtime_sha256: sdk, plan });
  const row = { backend: 'faults', frozen: fileReceipt(root, prefix + '/faults-frozen.json'), image_id: image, runtime_sha256: sdk, tests: catalog.tests, scheduled: 18, discovery: 'discovery/faults', evidence: await evidenceInventory(path.join(directory, 'discovery/faults')) };
  put(prefix + '/session.json', { schema_version: 1, qualification: 'frozen-bounded-protected-mutation-schedule-no-outcomes', profile: 'bounded', bounded_policy: boundedMutationPolicy(root, source), source_sha256: source.sha256, input_sha256: acceptanceInputHash(source), catalog: fileReceipt(root, prefix + '/catalog.json'), inventory: fileReceipt(root, prefix + '/acceptance-inventory.json'), rows: [row] });
  return { root, directory, put, source, manifest, requirements, acceptance, schedule, catalog };
}

test('protected discovery propagates the explicit parent storage reservation', async () => {
  const value = await fixture();
  try {
    let observed;
    const environment = { PATH: '/fixture-only', UD_STORAGE_LEASE: 'source-bound-parent-token' };
    await expect(discoverBoundedMutationSession(value.root, path.join(value.root, '.artifacts/new-discovery'), {
      python: '/fixture/python', cargo: '/fixture/cargo', environment,
      run: (_program, _args, options) => { observed = options.env; return { status: 1 }; },
    })).rejects.toThrow(/protected independent original test collection failed/);
    expect(observed).toEqual(environment);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('failed protected fault discovery retains bounded child diagnostics without authorizing a session', async () => {
  const value = await fixture();
  try {
    const output = path.join(value.root, '.artifacts/new-discovery'), invoked = [];
    let failure;
    try {
      await discoverBoundedMutationSession(value.root, output, {
        python: '/fixture/python', cargo: '/fixture/cargo', image: 'sha256:' + 'a'.repeat(64),
        run: (_program, args, options) => {
          const backend = args[args.indexOf('--backend') + 1]; invoked.push(backend);
          if (backend === 'catalog') { cpSync(path.join(value.directory, 'catalog-discovery'), args[1], { recursive: true }); return { status: 0 }; }
          mkdirSync(path.join(args[1], 'rust-named-faults'), { recursive: true });
          writeFileSync(options.stdio[1], 'outer coordinator failed\n');
          writeFileSync(path.join(args[1], 'runner.json'), JSON.stringify({ status: 'failed', execution: { status: 1, error: 'original compiler refused' } }));
          writeFileSync(path.join(args[1], 'runner.log'), 'Traceback: Rust named fault pristine compilation failed\n');
          writeFileSync(path.join(args[1], 'rust-named-faults/pristine-build.log'), 'x'.repeat(100_000) + '\ncompiler: exact diagnostic tail\n');
          return { status: 1, signal: null };
        },
      });
    } catch (error) { failure = error; }
    expect(invoked).toEqual(['catalog', 'faults']);
    expect(failure?.message).toContain('faults protected discovery failed; no execution is authorized');
    expect(failure?.message).toContain('original compiler refused');
    expect(failure?.message).toContain('compiler: exact diagnostic tail');
    const record = JSON.parse(readFileSync(path.join(output, 'faults-discovery-failure.log'), 'utf8'));
    expect(record).toMatchObject({ qualification: 'failed-protected-discovery-diagnostics-no-execution-authority', backend: 'faults', source_tree_sha256: value.source.sha256, execution: { status: 1, signal: null, error: null } });
    const build = record.diagnostics.find(row => row.path.endsWith('/pristine-build.log'));
    expect(build.truncated).toBe(true); expect(Buffer.byteLength(build.tail)).toBe(8192);
    expect(readFileSync(path.join(output, 'discovery/faults/rust-named-faults/pristine-build.log')).length).toBe(100_033);
    expect(existsSync(path.join(output, 'session.json'))).toBe(false);
    expect(existsSync(path.join(output, 'faults-frozen.json'))).toBe(false);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('discovery diagnostics preserve launch failures and refuse foreign aliased logs', async () => {
  const value = await fixture();
  try {
    const output = path.join(value.root, '.artifacts/new-discovery'), foreign = path.join(value.root, '.artifacts/foreign');
    mkdirSync(foreign); writeFileSync(path.join(foreign, 'runner.log'), 'foreign private bytes must not be read');
    await expect(discoverBoundedMutationSession(value.root, output, {
      python: '/fixture/python', cargo: '/fixture/cargo',
      run: (_program, args) => { symlinkSync(foreign, args[1], 'junction'); throw Object.assign(new Error('spawn original coordinator failed'), { code: 'EACCES' }); },
    })).rejects.toThrow(/spawn original coordinator failed/);
    const raw = readFileSync(path.join(output, 'catalog-discovery-failure.log'), 'utf8'), record = JSON.parse(raw);
    expect(raw).not.toContain('foreign private bytes');
    expect(record.execution).toEqual({ status: null, signal: null, error: 'spawn original coordinator failed' });
    expect(record.diagnostics.find(row => row.path === 'catalog-discovery/runner.log').unavailable).toMatch(/parent is not ordinary/);
    expect(existsSync(path.join(output, 'session.json'))).toBe(false);
    expect(readFileSync(path.join(foreign, 'runner.log'), 'utf8')).toBe('foreign private bytes must not be read');
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('bounded inventory selects exactly its named reviewed suite without relabelling exhaustive requirements', async () => {
  const value = await fixture();
  try {
    expect(mutationRequirements(value.requirements).required_suites).toEqual(['unit', 'mutation-typescript']);
    expect(mutationRequirements(value.requirements, 'bounded').required_suites).toEqual(['unit', 'mutation-bounded']);
    expect(value.acceptance.suites.map(row => row.id)).toEqual(['unit', 'mutation-bounded']);
    expect(value.acceptance.exhaustive).toBe(false);
    expect(verifyLocalAcceptanceDiscovery(value.root, value.acceptance, value.requirements).qualification).toMatch(/unsigned/);
    expect(() => verifyAcceptanceDiscovery(value.root, value.acceptance, value.requirements)).toThrow(/signature authority/);
    expect(() => compileAcceptanceInventory(value.root, value.catalog, value.requirements, [value.schedule])).toThrow(/missing|unscheduled/);
    expect(validateAcceptanceInventory(value.acceptance, ['unit', 'mutation-bounded']).size).toBe(2);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('bounded seal installs only inventory, verifies one protected fault provider, and rejects legacy opens', async () => {
  const value = await fixture();
  try {
    expect(() => sealMutationSession(value.root, value.directory, { install: true })).toThrow(/profile/);
    sealBoundedMutationSession(value.root, value.directory, { install: true });
    const sealed = await openBoundedMutationSession(value.root, value.directory);
    expect(sealed.authority.profile).toBe('bounded'); expect(sealed.authority.rows.map(row => row.backend)).toEqual(['faults']);
    expect(sealed.authority.source_sha256).not.toBe(value.source.sha256);
    expect(sealed.authority.input_sha256).toBe(acceptanceInputHash(value.source));
    await expect(openMutationSession(value.root, value.directory)).rejects.toThrow(/stale/);
    await expect(sealed.backend('python')).rejects.toThrow(/absent/);
    value.put('scripts/example.py', 'changed original source');
    await expect(openBoundedMutationSession(value.root, value.directory)).rejects.toThrow(/stale/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('bounded source, corpus, language and definition metadata cannot be omitted or changed', async () => {
  const value = await fixture();
  try {
    const changed = structuredClone(value.schedule); changed.mutants[0].definition.category = 'different';
    expect(() => compileAcceptanceInventory(value.root, value.catalog, value.requirements, [changed], { profile: 'bounded' })).toThrow(/definition/);
    const shortened = structuredClone(value.manifest); shortened.cases.pop(); value.put('tests/mutation/fault-cases.json', shortened);
    expect(() => boundedMutationPolicy(value.root, sourceReceipt(value.root))).toThrow(/eighteen/);
    expect(() => sealBoundedMutationSession(value.root, value.directory, { install: true })).toThrow(/source changed/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('bounded acceptance requires all eighteen kills and exact corpus and per-language counts', async () => {
  const value = await fixture();
  try {
    const suite = value.acceptance.suites.find(row => row.id === 'mutation-bounded');
    const report = { suite_id: suite.id, profile: 'bounded', policy: 'bounded-reviewed-v1', qualification: 'bounded-reviewed-corpus', exhaustive: false, corpus_sha256: suite.bounded_policy.corpus.sha256, scheduled: 18, killed: 18, survivors: 0, uncovered: 0, timeouts: 0, invalid: 0, missing: 0, equivalent_exceptions: [], per_language: Object.fromEntries(Object.entries(suite.bounded_policy.per_language).map(([key, count]) => [key, { scheduled: count, killed: count }])), tests: suite.tests.map(row => ({ ...row, status: 'passed' })), mutants: suite.mutants.map(row => ({ ...row, status: 'killed' })) };
    expect(() => reconcileSuiteInventory(suite, report)).not.toThrow();
    for (const altered of [{ ...report, exhaustive: true }, { ...report, corpus_sha256: '0'.repeat(64) }, { ...report, killed: 17 }, { ...report, per_language: {} }, { ...report, timeouts: 1 }]) expect(() => reconcileSuiteInventory(suite, altered)).toThrow(/bounded/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});
