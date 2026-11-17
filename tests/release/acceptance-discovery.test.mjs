import { test } from 'vitest';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { acceptanceInputHash, acceptanceRequirements, compileAcceptanceInventory, discoveryEnvironment, isAcceptanceSource, parseDiscoveryTranscript, rustCollectionCommands, verifyAcceptanceDiscovery } from '../../scripts/release/discover-acceptance.mjs';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { discoveryFixture } from './discovery-fixture.mjs';
import { mutationDiscoveryFixture, prepareMutationDiscoveryFixture } from './mutation-discovery-fixture.mjs';
import { mutationBackendContract, mutationBackendFiles, mutationRequirements } from '../../scripts/release/mutation-backends.mjs';

test('publisher beta drops only the legacy signing placeholders from the bounded inventory', () => {
  const requirements = JSON.parse(readFileSync('quality/requirements.json', 'utf8'));
  const bounded = mutationRequirements(requirements, 'bounded');
  const omitted = new Set(['signing-macos', 'signing-windows']);
  const expected = requirements.required_suites.filter(id => !id.startsWith('mutation-') && !omitted.has(id));
  assert.deepEqual(bounded.required_suites, [...expected, 'mutation-bounded']);
  assert.deepEqual(acceptanceRequirements(requirements, { profile: 'bounded' }), bounded);
  assert.deepEqual(acceptanceRequirements(requirements, {}), requirements);
  const legacy = structuredClone(requirements);
  delete legacy.mutation_profiles.bounded.signing_profile;
  assert.ok([...omitted].every(id => mutationRequirements(legacy, 'bounded').required_suites.includes(id)));
});

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-acceptance-discovery-'));
  for (const name of ['tests', 'packages', 'quality', '.artifacts']) mkdirSync(path.join(root, name));
  writeFileSync(path.join(root, 'tests/fixture.test.mjs'), 'test source bytes\n');
  writeFileSync(path.join(root, 'packages/fixture.js'), 'export const value = true;\n');
  prepareMutationDiscoveryFixture(root);
  const catalog = discoveryFixture(root);
  const definition = { tool: 'fixture', version: '1', operator: 'boolean', location: { line: 1, column: 21 }, original: 'true', replacement: 'false' };
  const schedule = { schema_version: 1, inventory_only: true, suite_id: 'mutation-typescript',
    tests: catalog.tests, mutants: [{ id: 'boolean-1', file: 'packages/fixture.js', source_sha256: fileReceipt(root, 'packages/fixture.js').sha256, definition, definition_sha256: sha256(canonicalJson(definition)) }] };
  schedule.backend_discovery = mutationDiscoveryFixture(root, schedule.mutants);
  const requirements = { schema_version: 1, required_suites: ['unit', schedule.suite_id] };
  return { root, catalog, schedule, requirements, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test('collects parameterized cases with stable source-bound identities before outcomes', () => {
  const f = fixture();
  try {
    const inventory = compileAcceptanceInventory(f.root, f.catalog, f.requirements, [f.schedule]);
    assert.equal(inventory.state, 'frozen');
    assert.deepEqual(inventory.suites[0].tests.map(item => item.name).sort(), ['one', 'two']);
    assert.equal(inventory.suites[1].mutants[0].definition_sha256, f.schedule.mutants[0].definition_sha256);
    assert.equal('status' in inventory.suites[0].tests[0], false);
    const staticTranscript = { ...f.catalog.transcripts[0], args: ['list', '--json'] };
    assert.throws(() => parseDiscoveryTranscript(f.root, staticTranscript), /parameterized/);
    assert.equal(isAcceptanceSource('packages/launcher/tests/fs_guard.rs'), true);
    assert.equal(isAcceptanceSource('scripts/quality/installed-workflows.mjs'), true);
    for (const unsafe of ['tests/../secret', 'tests\\secret', '/tests/a.py', 'packages/a.js']) assert.equal(isAcceptanceSource(unsafe), false);
  } finally { f.cleanup(); }
});

test('skills-host acceptance independently requires both pinned native Grok and Codex fixtures', () => {
  const f = fixture();
  try {
    for (const name of ['grok-native-smoke.mjs','codex-native-smoke.mjs','run-workflow-evals.mjs']) {
      const target=path.join(f.root,'scripts/quality',name);mkdirSync(path.dirname(target),{recursive:true});cpSync(path.resolve('scripts/quality',name),target);
    }
    const requirements={schema_version:1,required_suites:['skills-hosts']}, catalog=discoveryFixture(f.root);
    const inventory=compileAcceptanceInventory(f.root,catalog,requirements);
    const tasks=inventory.suites[0].tests;assert.equal(tasks.length,11);
    assert.deepEqual(tasks.filter(item=>item.execution_kind==='host-fixture').map(item=>item.source).sort(),['scripts/quality/codex-native-smoke.mjs','scripts/quality/grok-native-smoke.mjs']);
    const replay=tasks.filter(item=>item.execution_kind==='scripted-host-replay');assert.equal(replay.length,9);
    assert.deepEqual(replay.map(item=>item.host+':'+item.runtime_route).sort(),['claude:oci','claude:uv','claude:venv','codex:oci','codex:uv','codex:venv','gemini:oci','gemini:uv','gemini:venv']);
    for(const item of replay){assert.equal(item.source,'scripts/quality/run-workflow-evals.mjs');assert.equal(item.model_requests,0);assert.equal(item.model_routing,'pending-external');}
    for(const item of tasks)assert.equal(item.source_sha256,fileReceipt(f.root,item.source).sha256);
    writeFileSync(path.join(f.root,'.artifacts/catalog.json'),JSON.stringify(catalog));
    inventory.discovery={schema_version:1,algorithm:'native-runner-discovery-v1',catalog:fileReceipt(f.root,'.artifacts/catalog.json'),schedules:[]};
    assert.doesNotThrow(()=>verifyAcceptanceDiscovery(f.root,inventory,requirements));
    const missing=structuredClone(inventory);missing.suites[0].tests=missing.suites[0].tests.filter(item=>!item.source.includes('codex-native'));
    assert.throws(()=>verifyAcceptanceDiscovery(f.root,missing,requirements),/differs/);
  }finally{f.cleanup();}
});

test('collection uses explicit offline runner inputs without ambient filters, preload code or credentials', () => {
  const root = path.resolve('/tmp/immutable-source');
  const supplied = { PATH: '/verified/bin', HOME: '/private/profile', NODE_OPTIONS: '--import=/untrusted/preload.mjs', PYTHONPATH: '/untrusted', PYTEST_ADDOPTS: '-k selected', VITEST_POOL_ID: 'foreign', RUSTFLAGS: '--cfg omit_tests', RUSTC_WRAPPER: '/foreign-wrapper', CARGO_BUILD_TARGET: 'foreign-target', CARGO_HOME: '/verified/cargo', TOKEN: 'secret', AWS_SECRET_ACCESS_KEY: 'secret' };
  assert.deepEqual(discoveryEnvironment(root, supplied), { CI: 'true', PYTHONPATH: path.join(root, 'workers/ud/src'), CARGO_NET_OFFLINE: 'true', CARGO_TERM_COLOR: 'never', LANG: 'C', LC_ALL: 'C', PATH: '/verified/bin', HOME: '/private/profile', CARGO_HOME: '/verified/cargo' });
});

test('original collection honors only explicit source-pinned Rust versions without accepting paths or floating toolchains', () => {
  const root=mkdtempSync(path.join(os.tmpdir(),'ud-original-rust-env-'));
  try {
    mkdirSync(path.join(root,'quality'));
    writeFileSync(path.join(root,'rust-toolchain.toml'),'[toolchain]\nchannel = "1.99.0"\n');
    writeFileSync(path.join(root,'quality/toolchain.lock.json'),JSON.stringify({schema_version:1,roles:{host_original_rust:'1.99.0',release_and_ci_rust:'1.99.1'}}));
    for(const value of['1.99.0','1.99.1'])assert.equal(discoveryEnvironment(root,{RUSTUP_TOOLCHAIN:value}).RUSTUP_TOOLCHAIN,value);
    assert.equal('RUSTUP_TOOLCHAIN' in discoveryEnvironment(root,{}),false);
    for(const value of['stable','nightly','1.99.2','1.99.1-x86_64-unknown-linux-gnu','/private/foreign','../toolchain','1.99.1 --cfg bypass',null,1])assert.throws(()=>discoveryEnvironment(root,{RUSTUP_TOOLCHAIN:value}),/source-pinned/);
  }finally{rmSync(root,{recursive:true,force:true});}
});

test('requires independent targets and test collection for the separate Rust assertion parser workspace', () => {
  const f = fixture();
  try {
    const manifest = 'scripts/quality/rust-assertion-parser/Cargo.toml', source = 'scripts/quality/rust-assertion-parser/src/main.rs';
    mkdirSync(path.dirname(path.join(f.root, source)), { recursive: true });
    writeFileSync(path.join(f.root, manifest), '[package]\nname="synthetic-parser"\nversion="0.0.0"\n');
    writeFileSync(path.join(f.root, source), '// Immutable synthetic parser test target.\n');
    const catalog = discoveryFixture(f.root), requirements = { schema_version: 1, required_suites: ['unit'] };
    assert.equal(rustCollectionCommands(sourceReceipt(f.root)).length, 2);
    assert.throws(() => compileAcceptanceInventory(f.root, catalog, requirements), /workspace discovery/);
    const parserBuild = structuredClone(catalog.build_transcript), parserList = structuredClone(catalog.transcripts.find(item => item.runner === 'rust'));
    parserBuild.args = rustCollectionCommands(sourceReceipt(f.root))[1];
    parserList.source = source; parserList.command = path.join(f.root, 'parser-tests');
    parserBuild.stdout = JSON.stringify({ reason: 'compiler-artifact', profile: { test: true }, executable: parserList.command, target: { src_path: path.join(f.root, source) } }) + '\n';
    parserBuild.stdout_sha256 = sha256(parserBuild.stdout);
    parserList.stdout = 'rejects_fake_assertion_sites: test\n1 test, 0 benchmarks\n'; parserList.stdout_sha256 = sha256(parserList.stdout);
    catalog.build_transcripts = [catalog.build_transcript, parserBuild]; catalog.transcripts.push(parserList);
    catalog.tests.push(...parseDiscoveryTranscript(f.root, parserList)); catalog.tests.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    assert.doesNotThrow(() => compileAcceptanceInventory(f.root, catalog, requirements));
    for (const change of [copy => copy.build_transcripts.pop(), copy => copy.build_transcripts.push(copy.build_transcripts[1]), copy => copy.build_transcripts[1].args.push('--lib'), copy => { copy.transcripts = copy.transcripts.filter(item => item.source !== source); copy.tests = copy.tests.filter(item => item.source !== source); }]) {
      const changed = structuredClone(catalog); change(changed);
      assert.throws(() => compileAcceptanceInventory(f.root, changed, requirements), /Rust/);
    }
    assert.equal(isAcceptanceSource(source), true); assert.equal(isAcceptanceSource('scripts/unregistered-parser/src/main.rs'), false);
  } finally { f.cleanup(); }
});

test('retained Rust scope is the launcher and parser, with no abandoned administrator workspace', () => {
  const f = fixture();
  try {
    const parser = 'scripts/quality/rust-assertion-parser';
    mkdirSync(path.join(f.root, parser, 'src'), { recursive: true });
    writeFileSync(path.join(f.root, parser, 'Cargo.toml'), '[package]\nname="fixture"\nversion="0.0.0"\n');
    writeFileSync(path.join(f.root, parser, 'src/main.rs'), '// Original parser test-discovery fixture.\n');
    const commands = rustCollectionCommands(sourceReceipt(f.root));
    assert.equal(commands.length, 2);
    assert.ok(commands.every(command => !command.some(argument => argument.includes('native-quality-exec'))));
    assert.equal(isAcceptanceSource(parser + '/src/main.rs'), true);
    assert.equal(isAcceptanceSource('scripts/quality/native-quality-exec/src/mac.rs'), false);
    const contract = mutationBackendContract(path.resolve(import.meta.dirname, '../..'), sourceReceipt(path.resolve(import.meta.dirname, '../..')), {tool:'cargo-mutants',version:'27.1.0'});
    assert.ok([...contract.sources,...contract.configuration,...contract.generators].every(item => !item.path.includes('native-quality-exec')));
  } finally { f.cleanup(); }
}, 30_000);

test('only explicitly maintained backend identities can define an applicable source scope', () => {
  for (const backend of [{ tool: '__proto__' }, { tool: 'constructor' }, { tool: 'toString' }, { tool: 'stryker', version: 'old' }, null]) assert.throws(() => mutationBackendFiles(backend), /unsupported tool or version/);
});

test('every maintained backend binds existing production generators, configuration and applicable repository sources', () => {
  const root = path.resolve(import.meta.dirname, '../..'), source = sourceReceipt(root);
  for (const [tool, version] of [['stryker','10.1.1'], ['mutmut','3.8.1'], ['python-static','1.0.0'], ['cargo-mutants','27.1.0'], ['ppi-perl','1.0.0'], ['fault-canary','1.0.0']]) {
    const contract = mutationBackendContract(root, source, { tool, version });
    assert.ok(contract.sources.length > 0); assert.ok(contract.generators.length > 0); assert.ok(contract.configuration.length > 0);
    for (const receipt of [...contract.generators, ...contract.configuration]) assert.match(receipt.sha256,/^[a-f0-9]{64}$/);
    if (['python-static','fault-canary'].includes(tool)) {
      const actual = new Set(contract.generators.map(item => item.path));
      for (const name of ['oci-secondary.py','secondary-child.py','oci-exec.py','oci-isolation.py','oci-mutation.py','prepare-mutation-runtime.py']) assert.ok(actual.has('scripts/quality/'+name));
    }
    if (tool === 'cargo-mutants') {
      for (const name of ['packages/launcher/Cargo.toml','scripts/quality/rust-assertion-parser/Cargo.toml','scripts/quality/rust-assertion-parser/Cargo.lock']) assert.ok(contract.configuration.some(item=>item.path===name));
      assert.ok(contract.sources.some(item=>item.path==='scripts/quality/rust-assertion-parser/src/main.rs'));
      for (const name of ['rust-protected.py','rust-compile-child.py','rust-assertions.mjs','oci-exec.py']) assert.ok(contract.generators.some(item=>item.path==='scripts/quality/'+name));
    }
  }
}, 60_000);

test('rejects omitted files, filtered collections, duplicate identities and missing Rust targets', () => {
  const f = fixture();
  try {
    const changed = structuredClone(f.catalog); changed.tests.pop();
    assert.throws(() => compileAcceptanceInventory(f.root, changed, f.requirements, [f.schedule]), /differ/);
    const filtered = structuredClone(f.catalog); filtered.transcripts[0].args.push('only-this-file');
    assert.throws(() => compileAcceptanceInventory(f.root, filtered, f.requirements, [f.schedule]), /filtered/);
    const missingRust = structuredClone(f.catalog); missingRust.transcripts.pop();
    assert.throws(() => compileAcceptanceInventory(f.root, missingRust, f.requirements, [f.schedule]), /Rust collection/);
    const duplicate = structuredClone(f.catalog); duplicate.transcripts.push(duplicate.transcripts[0]); duplicate.tests = [...duplicate.tests, ...duplicate.tests].sort((a, b) => a.id.localeCompare(b.id));
    assert.throws(() => compileAcceptanceInventory(f.root, duplicate, f.requirements, [f.schedule]), /duplicate/);
    writeFileSync(path.join(f.root, 'tests/omitted.test.mjs'), 'test("omitted", () => {});\n');
    f.catalog.input_sha256 = acceptanceInputHash(sourceReceipt(f.root));
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, [f.schedule]), /omitted by runners/);
  } finally { f.cleanup(); }
});

test('preserves every parameterized case even when the runner prints identical names', () => {
  const f = fixture();
  try {
    const catalog = discoveryFixture(f.root, ['same display name', 'same display name']);
    assert.equal(catalog.tests.length, 2);
    assert.equal(new Set(catalog.tests.map(item => item.id)).size, 2);
    assert.deepEqual(catalog.tests.map(item => item.occurrence).sort(), [0, 1]);
    assert.doesNotThrow(() => compileAcceptanceInventory(f.root, catalog, { schema_version: 1, required_suites: ['unit'] }));
  } finally { f.cleanup(); }
});

test('rejects missing schedules, changed definitions, stale sources, duplicate programs and undiscovered tests', () => {
  const f = fixture();
  try {
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements), /schedule missing/);
    for (const change of [schedule => schedule.mutants.push(schedule.mutants[0]), schedule => schedule.mutants[0].definition.replacement = '0', schedule => schedule.tests[0].id = 'invented-test', schedule => schedule.mutants[0].source_sha256 = '0'.repeat(64), schedule => schedule.mutants[0].status = 'killed']) {
      const schedule = structuredClone(f.schedule); change(schedule);
      assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, [schedule]), /duplicate|definition|discovery|outcomes/);
    }
    writeFileSync(path.join(f.root, 'packages/fixture.js'), 'changed source\n');
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, [f.schedule]), /stale/);
  } finally { f.cleanup(); }
});

test('binds exact frozen inventory to bounded transcript and schedule receipts, independently of outcomes', () => {
  const f = fixture();
  try {
    const inventory = compileAcceptanceInventory(f.root, f.catalog, f.requirements, [f.schedule]);
    for (const [name, data] of [['catalog', f.catalog], ['schedule', f.schedule]]) writeFileSync(path.join(f.root, '.artifacts', `${name}.json`), JSON.stringify(data));
    inventory.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: fileReceipt(f.root, '.artifacts/catalog.json'), schedules: [fileReceipt(f.root, '.artifacts/schedule.json')] };
    writeFileSync(path.join(f.root, 'quality/acceptance-inventory.json'), JSON.stringify(inventory));
    assert.doesNotThrow(() => verifyAcceptanceDiscovery(f.root, inventory, f.requirements, { verifyBackendDiscovery: () => 'synthetic-inventory-authority' }));
    assert.throws(() => verifyAcceptanceDiscovery(f.root, inventory, f.requirements), /signature authority/);
    const missing = structuredClone(inventory); missing.suites[0].tests.pop();
    assert.throws(() => verifyAcceptanceDiscovery(f.root, missing, f.requirements, { verifyBackendDiscovery: () => 'synthetic-inventory-authority' }), /differs/);
    assert.throws(() => verifyAcceptanceDiscovery(f.root, { ...inventory, discovery: undefined }, f.requirements), /independently discovered/);
    writeFileSync(path.join(f.root, '.artifacts/catalog.json'), '{}');
    assert.throws(() => verifyAcceptanceDiscovery(f.root, inventory, f.requirements, { verifyBackendDiscovery: () => 'synthetic-inventory-authority' }), /receipt mismatch/);
  } finally { f.cleanup(); }
});

test('reconciles every planned shard exactly once and stores compact immutable definitions', () => {
  const f = fixture();
  try {
    const second = structuredClone(f.schedule.mutants[0]); second.id = 'boolean-2'; second.definition.replacement = '0'; second.definition_sha256 = sha256(canonicalJson(second.definition));
    const compact = [f.schedule.mutants[0], second].map(({ id, file, source_sha256, definition_sha256 }) => ({ id, file, source_sha256, definition_sha256 }));
    const backend_discovery = mutationDiscoveryFixture(f.root, [f.schedule.mutants[0], second]);
    const plan = { count: 2, scheduled: 2, inventory_sha256: sha256(canonicalJson(compact)) };
    const shards = [f.schedule.mutants[0], second].map((mutant, index) => ({ ...f.schedule, backend_discovery, mutants: [mutant], shard: { ...plan, index } }));
    const inventory = compileAcceptanceInventory(f.root, f.catalog, f.requirements, shards.values());
    assert.deepEqual(inventory.suites[1].mutants, compact);
    assert.equal('definition' in inventory.suites[1].mutants[0], false);
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, shards.slice(0, 1)), /incomplete mutation shard/);
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, [shards[0], shards[0]]), /duplicate|inconsistent/);
    const wrong = structuredClone(shards); wrong[1].shard.inventory_sha256 = '0'.repeat(64);
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, wrong), /inconsistent/);
    const changedTests = structuredClone(shards); changedTests[1].tests = [...changedTests[1].tests].reverse();
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, changedTests), /inconsistent/);
  } finally { f.cleanup(); }
});

test('a discovery receipt remains bound when the exact source and evidence move to another checkout', () => {
  const f = fixture(), relocated = mkdtempSync(path.join(os.tmpdir(), 'ud-discovery-relocated-'));
  try {
    cpSync(f.root, relocated, { recursive: true });
    assert.doesNotThrow(() => compileAcceptanceInventory(relocated, f.catalog, f.requirements, [f.schedule]));
    assert.equal(sha256(readFileSync(path.join(relocated, 'tests/fixture.test.mjs'))), f.catalog.tests[0].source_sha256);
  } finally { f.cleanup(); rmSync(relocated, { recursive: true, force: true }); }
});

test('rejects shortened unsharded lists against the independent complete backend master', () => {
  const f = fixture();
  try {
    const second = structuredClone(f.schedule.mutants[0]); second.id = 'second'; second.definition.replacement = '0'; second.definition_sha256 = sha256(canonicalJson(second.definition));
    f.schedule.backend_discovery = mutationDiscoveryFixture(f.root, [...f.schedule.mutants, second]);
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, [f.schedule]), /complete backend discovery/);
    const supplied = { ...f.schedule, backend_discovery: undefined };
    assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, [supplied]), /backend discovery missing/);
  } finally { f.cleanup(); }
});

test('requires actual generation for every applicable source including zero-mutant modules', () => {
  for (const change of [
    generation => generation.sources.pop(),
    generation => generation.source_materializations.pop(),
    generation => { generation.source_materializations[0].mutant_ids = ['invented']; },
    generation => { generation.source_materializations[0].artifacts = []; },
    generation => { generation.execution.command.push('--file=packages/fixture.js'); },
    generation => { generation.execution.runtime.image_id = 'unverified'; },
    generation => { generation.generators.pop(); },
    generation => { generation.inventory.pop(); },
    generation => { generation.scope_complete = false; },
  ]) {
    const f = fixture();
    try {
      const authority = JSON.parse(readFileSync(path.join(f.root, f.schedule.backend_discovery.path)));
      const generation = JSON.parse(readFileSync(path.join(f.root, authority.raw_generation.path)));
      change(generation);
      writeFileSync(path.join(f.root, authority.raw_generation.path), JSON.stringify(generation));
      authority.raw_generation = fileReceipt(f.root, authority.raw_generation.path);
      if (generation.execution) authority.execution = generation.execution;
      writeFileSync(path.join(f.root, f.schedule.backend_discovery.path), JSON.stringify(authority));
      f.schedule.backend_discovery = fileReceipt(f.root, f.schedule.backend_discovery.path);
      assert.throws(() => compileAcceptanceInventory(f.root, f.catalog, f.requirements, [f.schedule]), /generation|generated/);
    } finally { f.cleanup(); }
  }
});

test('verifies a native Windows collection on a Unix verifier without treating Windows paths as Unix paths', () => {
  const f = fixture();
  try {
    const catalog = structuredClone(f.catalog), original = catalog.collection_root;
    const windows = 'C:\\ud-source', convert = filename => path.win32.join(windows, path.relative(original, filename));
    catalog.collection_root = windows; catalog.environment.os = 'win32';
    for (const item of [...catalog.transcripts, catalog.build_transcript]) {
      item.collection_root = windows; item.command = convert(item.command);
      if (item.runner === 'vitest') {
        item.args[0] = path.win32.join(windows, 'node_modules/vitest/vitest.mjs');
        item.stdout = JSON.stringify(JSON.parse(item.stdout).map(test => ({ ...test, file: convert(test.file) })));
      } else if (item.runner === 'cargo-build') {
        const target = JSON.parse(item.stdout); target.executable = convert(target.executable); target.target.src_path = convert(target.target.src_path); item.stdout = JSON.stringify(target) + '\n';
      }
      item.stdout_sha256 = sha256(item.stdout);
    }
    assert.doesNotThrow(() => compileAcceptanceInventory(f.root, catalog, f.requirements, [f.schedule]));
  } finally { f.cleanup(); }
});
