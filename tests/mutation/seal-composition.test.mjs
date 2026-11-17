import { test, expect } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { compileAcceptanceInventory, acceptanceInputHash } from '../../scripts/release/discover-acceptance.mjs';
import { sourceReceipt, fileReceipt } from '../../scripts/release/candidate.mjs';
import { MUTATION_BACKENDS, evidenceInventory, openMutationSession, sealMutationSession } from '../../scripts/quality/mutation-session.mjs';
import { discoveryFixture } from '../release/discovery-fixture.mjs';
import { mutationDiscoveryFixture, prepareMutationDiscoveryFixture } from '../release/mutation-discovery-fixture.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { mutationPlanIdentity } from '../../scripts/quality/mutation-plan.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');

const tools = { faults: 'fault-canary', perl: 'ppi-perl', typescript: 'stryker', python: 'mutmut', 'python-static': 'python-static', rust: 'cargo-mutants-27.1.0+ud-literal-1' };
const runner = (backend, source) => ({ inventory_only: true, backend, source_tree_sha256: source, image: 'sha256:' + 'c'.repeat(64), status: 'executed-not-reconciled', worker: { platform: 'linux', architecture: 'arm64', emulation: false }, container_state: { ExitCode: 0, Running: false, OOMKilled: false }, execution: { status: 0, signal: null, error: null }, cleanup: ['job', 'carrier', 'input', 'state'].map(name => ({ kind: 'fixture-resource', name, status: 'removed-owned' })) });

// Session verification replays the protected local discovery, so the fixture
// supplies the same definition-only provider records as the session tests.
async function fixture(composed = true) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-composition-seal-'));
  const put = (name, value) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)); return file; };
  put('packages/example/src/value.mjs', 'export const value = true;\n');
  put('tests/fixture.test.mjs', '// Synthetic collection transcript, no outcomes.\n');
  prepareMutationDiscoveryFixture(root);
  const requirements = { schema_version: 1, required_suites: ['unit', 'mutation-typescript'] }; put('quality/requirements.json', requirements);
  const catalog = discoveryFixture(root); put('.artifacts/session/catalog.json', catalog);
  const source = sourceReceipt(root), directory = path.join(root, '.artifacts/session'), runtimeBytes = JSON.stringify({ platform: 'linux/arm64', qualification: 'unit-fixture-only' });
  const selectedPlan = backend => {
    const definition = { tool: tools[backend], operator: 'BooleanLiteral', original: 'true', replacement: 'false' };
    return { tool: tools[backend], scope_complete: true, source_tree_sha256: source.sha256, inventory: [{ id: 'raw-17', file: 'packages/example/src/value.mjs', source_sha256: fileReceipt(root, 'packages/example/src/value.mjs').sha256, definition, definition_sha256: hash(canonicalJson(definition)) }], tests: catalog.tests };
  };
  const definition = selectedPlan('typescript').inventory[0];
  const schedule = { schema_version: 1, inventory_only: true, suite_id: 'mutation-typescript', tests: catalog.tests, mutants: [{ ...definition, id: definition.file + '#' + definition.definition_sha256 }] };
  schedule.backend_discovery = mutationDiscoveryFixture(root, schedule.mutants);
  put('.artifacts/session/typescript-schedule.json', schedule);
  const inventory = compileAcceptanceInventory(root, catalog, requirements, [schedule]);
  inventory.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: fileReceipt(root, '.artifacts/session/catalog.json'), schedules: [fileReceipt(root, '.artifacts/session/typescript-schedule.json')] };
  put('.artifacts/session/acceptance-inventory.json', inventory);
  const marker = { schema_version: 1, qualification: 'available-target-inputs', production_ready: false, source_tree_sha256: source.sha256, original_source_tree_sha256: 'b'.repeat(64), userspace_platforms: ['darwin/arm64'], material_derivation: { phase: 'original-data-only-fixture' } };
  if (composed) put('freeze-composition.json', JSON.stringify(marker, null, 4) + '\n');
  const originalBytes = composed ? readFileSync(path.join(root, 'freeze-composition.json')) : undefined;
  const provider = (backend, relative) => {
    put(relative + '/runner.json', runner(backend, source.sha256));
    put(relative + '/runtime-input-receipt.json', runtimeBytes);
    for (const name of ['isolation-proof.json', 'exec-isolation-proof.json']) put(relative + '/' + name, { status: 'passed', source_tree_sha256: source.sha256, runtime_input_sha256: hash(runtimeBytes) });
  };
  provider('catalog', '.artifacts/session/catalog-discovery');
  put('.artifacts/session/catalog-discovery/catalog.json', catalog);
  const rows = [];
  for (const backend of MUTATION_BACKENDS) {
    const identity = mutationPlanIdentity(selectedPlan(backend), backend), frozen = { schema_version: 1, plan: identity, image_id: 'sha256:' + 'c'.repeat(64), runtime_sha256: hash(runtimeBytes) };
    put(`.artifacts/session/${backend}-frozen.json`, frozen);
    const discovery = `discovery/${backend}`, relative = `.artifacts/session/${discovery}`;
    provider(backend, relative); put(relative + '/pre-outcome-plan.json', identity);
    put(relative + '/raw.json', { qualification: 'synthetic-not-execution-evidence' });
    rows.push({ backend, frozen: fileReceipt(root, `.artifacts/session/${backend}-frozen.json`), image_id: frozen.image_id, runtime_sha256: frozen.runtime_sha256, scheduled: 1, discovery, evidence: await evidenceInventory(path.join(directory, discovery)) });
  }
  put('.artifacts/session/session.json', { schema_version: 1, qualification: 'frozen-complete-protected-mutation-schedules-no-outcomes', source_sha256: source.sha256, input_sha256: acceptanceInputHash(source), composition: composed ? fileReceipt(root, 'freeze-composition.json') : null, catalog: fileReceipt(root, '.artifacts/session/catalog.json'), inventory: fileReceipt(root, '.artifacts/session/acceptance-inventory.json'), rows });
  return { root, directory, put, marker, source, originalBytes };
}

test('inventory seal updates only the composition source binding and retains the exact prior receipt', async () => {
  const value = await fixture();
  try {
    sealMutationSession(value.root, value.directory, { install: true });
    const sealed = await openMutationSession(value.root, value.directory), next = JSON.parse(readFileSync(path.join(value.root, 'freeze-composition.json'), 'utf8'));
    expect(next.source_tree_sha256).toBe(sourceReceipt(value.root).sha256);
    expect(next.source_tree_sha256).not.toBe(value.source.sha256);
    expect(next.qualification).toBe('available-target-inputs'); expect(next.production_ready).toBe(false);
    expect(next.original_source_tree_sha256).toBe(value.marker.original_source_tree_sha256);
    expect(next.userspace_platforms).toEqual(['darwin/arm64']); expect(next.material_derivation).toEqual(value.marker.material_derivation);
    const binding = sealed.authority.composition_binding;
    expect(readFileSync(path.join(value.root, binding.prior.path)).equals(value.originalBytes)).toBe(true);
    expect(binding.before.sha256).toBe(hash(value.originalBytes));
    expect(next.acceptance_inventory_seal.discovery_source_sha256).toBe(value.source.sha256);
    expect(next.acceptance_inventory_seal.input_sha256).toBe(acceptanceInputHash(value.source));
    expect(next.acceptance_inventory_seal.inventory.sha256).toBe(fileReceipt(value.root, 'quality/acceptance-inventory.json').sha256);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('a changed composition or unrelated source edit refuses seal before installing the inventory', async () => {
  for (const changed of ['composition', 'source', 'appeared']) {
    const value = await fixture(changed !== 'appeared');
    try {
      if (changed === 'composition') value.put('freeze-composition.json', { ...value.marker, source_tree_sha256: 'e'.repeat(64) });
      if (changed === 'source') value.put('packages/example/src/value.mjs', 'export const value = false;\n');
      if (changed === 'appeared') value.put('freeze-composition.json', value.marker);
      expect(() => sealMutationSession(value.root, value.directory, { install: true })).toThrow(/changed|stale|appeared/);
      expect(existsSync(path.join(value.root, 'quality/acceptance-inventory.json'))).toBe(false);
    } finally { rmSync(value.root, { recursive: true, force: true }); }
  }
});

test('only the exact interrupted composition transition is recoverable without source regeneration', async () => {
  const value = await fixture();
  try {
    sealMutationSession(value.root, value.directory, { install: true });
    const expected = readFileSync(path.join(value.root, 'freeze-composition.json'));
    value.put('freeze-composition.json', value.originalBytes);
    await expect(openMutationSession(value.root, value.directory)).rejects.toThrow(/receipt changed/);
    sealMutationSession(value.root, value.directory);
    expect(readFileSync(path.join(value.root, 'freeze-composition.json')).equals(expected)).toBe(true);
    await expect(openMutationSession(value.root, value.directory)).resolves.toBeTruthy();
    value.put('freeze-composition.json', { ...JSON.parse(expected), material_derivation: { changed: true } });
    expect(() => sealMutationSession(value.root, value.directory)).toThrow(/receipt changed/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});
