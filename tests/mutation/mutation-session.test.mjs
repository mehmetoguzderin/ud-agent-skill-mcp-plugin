import { test, expect } from 'vitest';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { sourceReceipt, fileReceipt } from '../../scripts/release/candidate.mjs';
import { acceptanceInputHash, compileAcceptanceInventory, verifyAcceptanceDiscovery, verifyLocalAcceptanceDiscovery } from '../../scripts/release/discover-acceptance.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { mutationPlanIdentity, verifyFrozenMutationPlan } from '../../scripts/quality/mutation-plan.mjs';
import { acquireMutationSessionLease, MUTATION_BACKENDS, evidenceInventory, openMutationSession, sealMutationSession, verifyDiscoveryProvider } from '../../scripts/quality/mutation-session.mjs';
import { discoveryFixture } from '../release/discovery-fixture.mjs';
import { mutationDiscoveryFixture, prepareMutationDiscoveryFixture } from '../release/mutation-discovery-fixture.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const tools = { faults: 'fault-canary', perl: 'ppi-perl', typescript: 'stryker', python: 'mutmut', 'python-static': 'python-static', rust: 'cargo-mutants-27.1.0+ud-literal-1' };

function plan(backend = 'typescript') {
  const definition = { tool: tools[backend], operator: 'BooleanLiteral', original: 'true', replacement: 'false' };
  return { tool: tools[backend], scope_complete: true, source_tree_sha256: 'a'.repeat(64), inventory: [{ id: 'raw-17', file: 'packages/example/src/value.mjs', source_sha256: 'b'.repeat(64), definition, definition_sha256: hash(canonicalJson(definition)) }], tests: [{ id: 'test-alias', source: 'tests/value.test.mjs', source_sha256: 'c'.repeat(64), name: 'returns the specified value', occurrence: 0 }] };
}

test('frozen definitions and case occurrences survive alias changes but reject changed programs or missing tests', () => {
  const original = plan(), frozen = mutationPlanIdentity(original, 'typescript');
  expect(verifyFrozenMutationPlan({ ...original, inventory: original.inventory.map(item => ({ ...item, id: 'raw-999' })), tests: original.tests.map(item => ({ ...item, id: 'new-alias' })) }, frozen, 'typescript')).toEqual(frozen);
  for (const altered of [
    { ...original, inventory: [] }, { ...original, tests: [] }, { ...original, scope_complete: false },
    { ...original, tests: [{ ...original.tests[0], occurrence: 1 }] },
    { ...original, inventory: [original.inventory[0], original.inventory[0]] },
    { ...original, inventory: [{ ...original.inventory[0], definition: { ...original.inventory[0].definition, replacement: '0' } }] },
    { ...original, source_tree_sha256: 'd'.repeat(64) },
  ]) expect(() => verifyFrozenMutationPlan(altered, frozen, 'typescript')).toThrow();
});

function runner() {
  return { inventory_only: true, backend: 'perl', source_tree_sha256: 'a'.repeat(64), image: 'sha256:' + 'd'.repeat(64), status: 'executed-not-reconciled', worker: { platform: 'linux', architecture: 'arm64', emulation: false }, container_state: { ExitCode: 0, Running: false, OOMKilled: false }, execution: { status: 0, signal: null, error: null }, cleanup: ['job', 'carrier', 'input', 'state'].map(name => ({ kind: 'fixture-resource', name, status: 'removed-owned' })) };
}
test('discovery requires actual native completion, both isolation proofs and all owned cleanup before freezing', () => {
  const value = runner(), runtime = { platform: 'linux/arm64' }, runtimeHash = 'e'.repeat(64), proofs = [0, 1].map(() => ({ status: 'passed', source_tree_sha256: value.source_tree_sha256, runtime_input_sha256: runtimeHash }));
  expect(() => verifyDiscoveryProvider(value, 'perl', value.source_tree_sha256, runtime, proofs, runtimeHash)).not.toThrow();
  for (const altered of [{ ...value, inventory_only: false }, { ...value, container_state: { ...value.container_state, OOMKilled: true } }, { ...value, execution: { status: 0, signal: 'SIGTERM' } }, { ...value, cleanup: value.cleanup.slice(1) }, { ...value, worker: { ...value.worker, emulation: true } }]) expect(() => verifyDiscoveryProvider(altered, 'perl', value.source_tree_sha256, runtime, proofs, runtimeHash)).toThrow();
  expect(() => verifyDiscoveryProvider(value, 'perl', value.source_tree_sha256, runtime, proofs.slice(1), runtimeHash)).toThrow();
  expect(() => verifyDiscoveryProvider(value, 'perl', value.source_tree_sha256, runtime, proofs, 'f'.repeat(64))).toThrow();
});

async function fixture(seal = true) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-frozen-mutation-session-'));
  const put = (name, value) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value)); return file; };
  put('packages/example/src/value.mjs', 'export const value = true;\n');
  put('tests/fixture.test.mjs', '// Synthetic collection source, no outcome claims.\n');
  prepareMutationDiscoveryFixture(root);
  const requirements = { schema_version: 1, required_suites: ['unit', 'mutation-typescript'] }; put('quality/requirements.json', requirements);
  const catalog = discoveryFixture(root); put('.artifacts/session/catalog.json', catalog);
  const source = sourceReceipt(root), directory = path.join(root, '.artifacts/session'), rows = [], runtimeBytes = JSON.stringify({ platform: 'linux/arm64', qualification: 'unit-fixture-only' });
  const selectedPlan = backend => {
    const selected = plan(backend);
    return { ...selected, source_tree_sha256: source.sha256,
      inventory: selected.inventory.map(row => ({ ...row, source_sha256: fileReceipt(root, row.file).sha256 })),
      tests: catalog.tests };
  };
  const definition = selectedPlan('typescript').inventory[0];
  const schedule = { schema_version: 1, inventory_only: true, suite_id: 'mutation-typescript', tests: catalog.tests,
    mutants: [{ ...definition, id: definition.file + '#' + definition.definition_sha256 }] };
  schedule.backend_discovery = mutationDiscoveryFixture(root, schedule.mutants);
  put('.artifacts/session/typescript-schedule.json', schedule);
  const inventory = compileAcceptanceInventory(root, catalog, requirements, [schedule]);
  inventory.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: fileReceipt(root, '.artifacts/session/catalog.json'), schedules: [fileReceipt(root, '.artifacts/session/typescript-schedule.json')] };
  put('.artifacts/session/acceptance-inventory.json', inventory);
  const provider = (backend, relative) => {
    put(relative + '/runner.json', { ...runner(), backend, source_tree_sha256: source.sha256 });
    put(relative + '/runtime-input-receipt.json', runtimeBytes);
    for (const name of ['isolation-proof.json', 'exec-isolation-proof.json']) put(relative + '/' + name, { status: 'passed', source_tree_sha256: source.sha256, runtime_input_sha256: hash(runtimeBytes) });
  };
  provider('catalog', '.artifacts/session/catalog-discovery');
  put('.artifacts/session/catalog-discovery/catalog.json', catalog);
  for (const backend of MUTATION_BACKENDS) {
    const identity = mutationPlanIdentity(selectedPlan(backend), backend), frozen = { schema_version: 1, plan: identity, image_id: runner().image, runtime_sha256: hash(runtimeBytes) };
    put(`.artifacts/session/${backend}-frozen.json`, frozen);
    const discovery = `discovery/${backend}`, relative = `.artifacts/session/${discovery}`;
    provider(backend, relative); put(relative + '/pre-outcome-plan.json', identity);
    put(relative + '/raw.json', { fixture: 'pre-outcome source materialization' });
    rows.push({ backend, frozen: fileReceipt(root, `.artifacts/session/${backend}-frozen.json`), image_id: frozen.image_id, runtime_sha256: frozen.runtime_sha256, scheduled: 1, discovery, evidence: await evidenceInventory(path.join(directory, discovery)) });
  }
  put('.artifacts/session/session.json', { schema_version: 1, qualification: 'frozen-complete-protected-mutation-schedules-no-outcomes', source_sha256: source.sha256, input_sha256: acceptanceInputHash(source), catalog: fileReceipt(root, '.artifacts/session/catalog.json'), inventory: fileReceipt(root, '.artifacts/session/acceptance-inventory.json'), rows });
  if (seal) sealMutationSession(root, directory, { install: true });
  return { root, directory, put, source: sourceReceipt(root), discovery_source: source, runtimeBytes, requirements };
}

test('backend resume returns retained bytes for fresh strict grading, never a stored acceptance result', async () => {
  const value = await fixture();
  try {
    const session = await openMutationSession(value.root, value.directory), first = await session.backend('perl');
    expect(first.reused).toBe(false);
    const relative = path.relative(value.root, first.output).split(path.sep).join('/');
    value.put(relative + '/runner.json', { inventory_only: false, source_tree_sha256: value.source.sha256, image: runner().image, frozen_plan_sha256: hash(readFileSync(first.frozen)) });
    value.put(relative + '/runtime-input-receipt.json', value.runtimeBytes);
    value.put(relative + '/pre-outcome-plan.json', JSON.parse(readFileSync(first.frozen, 'utf8')).plan);
    value.put(relative + '/outcomes.json', { deliberately_not_an_acceptance_claim: true });
    await session.retain('perl', first.output);
    const next = await (await openMutationSession(value.root, value.directory)).backend('perl');
    expect(next.reused).toBe(true); expect(next.output).toBe(first.output); expect(next).not.toHaveProperty('status');
    value.put(relative + '/outcomes.json', { changed: true });
    await expect(session.backend('perl')).rejects.toThrow(/retained execution evidence changed/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('stale source, changed frozen schedule or changed discovery bytes refuse reuse before backend launch', async () => {
  for (const kind of ['source', 'schedule', 'discovery']) {
    const value = await fixture();
    try {
      if (kind === 'source') value.put('packages/example/src/value.mjs', 'export const value = false;\n');
      if (kind === 'schedule') value.put('.artifacts/session/perl-frozen.json', { forged: true });
      if (kind === 'discovery') value.put('.artifacts/session/discovery/perl/raw.json', { changed: true });
      await expect(openMutationSession(value.root, value.directory)).rejects.toThrow(/stale|changed/);
    } finally { rmSync(value.root, { recursive: true, force: true }); }
  }
});

test('an omitted backend or mixed SDK cohort is not a complete frozen session', async () => {
  for (const kind of ['missing', 'mixed']) {
    const value = await fixture();
    try {
      const manifest = JSON.parse(readFileSync(path.join(value.directory, 'session.json'), 'utf8'));
      if (kind === 'missing') manifest.rows.pop(); else manifest.rows[1].runtime_sha256 = 'f'.repeat(64);
      value.put('.artifacts/session/session.json', manifest);
      await expect(openMutationSession(value.root, value.directory)).rejects.toThrow(/required backend|mixed|changed/);
    } finally { rmSync(value.root, { recursive: true, force: true }); }
  }
});

test('the seal installs only the generated inventory and rejects unrelated source edits before execution', async () => {
  const value = await fixture(false);
  try {
    sealMutationSession(value.root, value.directory, { install: true });
    const sealed = await openMutationSession(value.root, value.directory);
    expect(sealed.authority.source_sha256).not.toBe(value.discovery_source.sha256);
    expect(sealed.authority.discovery_source_sha256).toBe(value.discovery_source.sha256);
    expect(sealed.authority.input_sha256).toBe(acceptanceInputHash(value.discovery_source));
  } finally { rmSync(value.root, { recursive: true, force: true }); }
  const changed = await fixture(false);
  try {
    changed.put('packages/example/src/value.mjs', 'export const value = false;\n');
    expect(() => sealMutationSession(changed.root, changed.directory, { install: true })).toThrow(/source changed/);
  } finally { rmSync(changed.root, { recursive: true, force: true }); }
});

test('local mutation-required seal and open replay unsigned evidence while production still requires inventory authority', async () => {
  const value = await fixture(false);
  try {
    const inventory = JSON.parse(readFileSync(path.join(value.directory, 'acceptance-inventory.json')));
    expect(inventory.suites.map(row => row.id)).toEqual(['unit', 'mutation-typescript']);
    expect(verifyLocalAcceptanceDiscovery(value.root, inventory, value.requirements).qualification).toBe('locally-replayed-unsigned-discovery-no-production-authority');
    expect(() => verifyAcceptanceDiscovery(value.root, inventory, value.requirements)).toThrow(/signature authority/);
    sealMutationSession(value.root, value.directory, { install: true });
    const local = (await openMutationSession(value.root, value.directory)).authority.local_discovery_replay;
    expect(local.qualification).toBe('locally-replayed-unsigned-discovery-no-production-authority');
    expect(local.session).toEqual(fileReceipt(value.root, '.artifacts/session/session.json'));
    expect(local.providers.map(row => row.backend)).toEqual(['catalog', ...MUTATION_BACKENDS]);
    expect(() => verifyAcceptanceDiscovery(value.root, inventory, value.requirements)).toThrow(/signature authority/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('local mutation seal rejects altered generation, inventory and protected providers before installation', async () => {
  for (const kind of ['generation', 'inventory', 'provider', 'unauthorized-provider', 'frozen-schedule']) {
    const value = await fixture(false);
    try {
      const manifest = JSON.parse(readFileSync(path.join(value.directory, 'session.json'))), row = manifest.rows[0];
      if (kind === 'generation') value.put('.artifacts/synthetic-generated-definitions.json', { altered: true });
      if (kind === 'inventory') {
        const inventory = JSON.parse(readFileSync(path.join(value.directory, 'acceptance-inventory.json')));
        inventory.suites[1].mutants[0].id = 'altered-definition';
        value.put('.artifacts/session/acceptance-inventory.json', inventory);
        manifest.inventory = fileReceipt(value.root, '.artifacts/session/acceptance-inventory.json');
        value.put('.artifacts/session/session.json', manifest);
      }
      if (kind === 'provider') value.put('.artifacts/session/discovery/faults/isolation-proof.json', { status: 'failed' });
      if (kind === 'unauthorized-provider') {
        const provider = JSON.parse(readFileSync(path.join(value.directory, row.discovery, 'runner.json')));
        provider.cleanup.pop(); value.put('.artifacts/session/' + row.discovery + '/runner.json', provider);
        row.evidence = await evidenceInventory(path.join(value.directory, row.discovery));
        value.put('.artifacts/session/session.json', manifest);
      }
      if (kind === 'frozen-schedule') {
        const frozen = JSON.parse(readFileSync(path.join(value.root, row.frozen.path)));
        frozen.plan.mutants[0].source_sha256 = '0'.repeat(64); value.put(row.frozen.path, frozen);
        row.frozen = fileReceipt(value.root, row.frozen.path); value.put('.artifacts/session/session.json', manifest);
      }
      expect(() => sealMutationSession(value.root, value.directory, { install: true })).toThrow(/changed|differ|receipt|cleanup/);
      expect(existsSync(path.join(value.root, 'quality/acceptance-inventory.json'))).toBe(false);
    } finally { rmSync(value.root, { recursive: true, force: true }); }
  }
}, 30_000);

test('sealed local replay receipts and protected catalog provider cannot be replaced before open', async () => {
  for (const kind of ['receipt', 'catalog-provider', 'catalog-output']) {
    const value = await fixture();
    try {
      if (kind === 'receipt') {
        const sealed = JSON.parse(readFileSync(path.join(value.directory, 'sealed-session.json')));
        sealed.local_discovery_replay.providers[0].records[0].sha256 = '0'.repeat(64);
        chmodSync(path.join(value.directory, 'sealed-session.json'), 0o600);
        value.put('.artifacts/session/sealed-session.json', sealed);
      } else if (kind === 'catalog-output') {
        const catalog = JSON.parse(readFileSync(path.join(value.directory, 'catalog-discovery/catalog.json')));
        catalog.tests.pop(); value.put('.artifacts/session/catalog-discovery/catalog.json', catalog);
      } else {
        const catalog = JSON.parse(readFileSync(path.join(value.directory, 'catalog-discovery/runner.json')));
        catalog.worker.emulation = true; value.put('.artifacts/session/catalog-discovery/runner.json', catalog);
      }
      await expect(openMutationSession(value.root, value.directory)).rejects.toThrow(/replay differs|runtime failed|catalog output differs/);
    } finally { rmSync(value.root, { recursive: true, force: true }); }
  }
}, 30_000);

test('the native kernel lease refuses concurrent backend execution and releases for a later resume', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-mutation-session-lease-'));
  const guard = process.env.UD_MUTATION_GUARD ?? path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
  let release;
  try {
    release = await acquireMutationSessionLease(directory, guard);
    await expect(acquireMutationSessionLease(directory, guard)).rejects.toThrow(/held|unavailable/);
    await release(); release = undefined;
    release = await acquireMutationSessionLease(directory, guard);
    await release(); release = undefined;
  } finally { if (release) await release(); rmSync(directory, { recursive: true, force: true }); }
});
