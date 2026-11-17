import { test, expect } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { appendAssessment, assessMutmut, canonicalMutmutGeneration } from '../../scripts/quality/mutation-gate.mjs';
import { acceptanceInputHash } from '../../scripts/release/discover-acceptance.mjs';
import { authorityFromGeneration, mutationBackendContract, mutationBackendFiles, verifiedMutationMaterializations, verifyMutationBackendDiscovery } from '../../scripts/release/mutation-backends.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { sourceReceipt, fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';

// These synthetic post-generation records exercise authority transport and gate
// policy. They neither run generated programs nor certify actual discovery.
function fixture(backend = { tool: 'mutmut', version: '3.8.1' }) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-python-zero-generation-'));
  const put = (name, value) => { const target = path.join(root, name); mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, value); return fileReceipt(root, name); };
  for (const name of Object.values(mutationBackendFiles(backend)).flat()) if (!existsSync(path.join(root, name))) put(name, name.endsWith('.json') ? '{}' : '# Synthetic source identity only\n');
  const changed = 'workers/ud/src/ud_agent/changed.py', zero = 'workers/ud/src/ud_agent/module_only.py';
  put(changed, 'def value():\n    return 1\n');
  put(zero, 'VALUE = 1\n');
  const testSource='tests/test_contract.py',testBody='def test_contract():\n    assert False\n';put(testSource,testBody);
  const source = sourceReceipt(root), input_sha256 = acceptanceInputHash(source), contract = mutationBackendContract(root, source, backend);
  const hashes = Object.fromEntries(source.files.map(item => [item.path, item.sha256]));
  const id = 'ud_agent.changed.x_value__mutmut_1';
  const inventory = [{ id, file: changed, source_sha256: hashes[changed], definition_sha256: sha256('Synthetic replacement identity, not an executed mutant') }];
  const raw = put('.artifacts/control.json', JSON.stringify({ qualification: 'synthetic-transport-fixture-no-outcomes', ids: [id], zero_source: zero }));
  const generation = { schema_version: 1, kind: 'mutation-backend-generation', qualification: 'complete-backend-generation-no-outcomes', scope_complete: true, input_sha256, backend, ...contract, execution: { command: ['synthetic-generator', 'discover'], runtime: { kind: 'oci', image_id: 'sha256:' + 'a'.repeat(64) } }, inventory, inventory_sha256: sha256(canonicalJson(inventory)), source_materializations: contract.sources.map(item => ({ source: item.path, source_sha256: item.sha256, mutant_ids: item.path === changed ? [id] : [], artifacts: [raw] })), raw_artifacts: [raw] };
  const generated = put('.artifacts/generation.json', JSON.stringify(generation));
  const authority = authorityFromGeneration(root, source, input_sha256, generated);
  const authorityReceipt = put('.artifacts/authority.json', JSON.stringify(authority));
  const shard = put('.artifacts/shard.json', JSON.stringify({ schema_version: 1, inventory_only: true, suite_id: 'mutation-python', backend_discovery: authorityReceipt }));
  const inventoryReceipt = put('quality/acceptance-inventory.json', JSON.stringify({ schema_version: 1, state: 'frozen', discovery: { schedules: [shard] } }));
  const metadata = { [changed]: { exit_code_by_key: { [id]: 1 } }, [zero]: { exit_code_by_key: {}, type_check_error_by_key: {} } };
  const testId=testSource+'::test_contract',origin={contract:'python-test-source-origin-v2',source:testSource,source_sha256:hashes[testSource],line:2,test_id:testId,test_source:testSource,test_source_sha256:hashes[testSource],test_line:2};
  const tests=[{id:testId,source:testSource,source_sha256:hashes[testSource]}];
  const events = [{ mutant: id, event: 'failure', phase: 'call', assertion_contract: 'python-test-source-origin-v2', exception_type: 'builtins.AssertionError',nodeid:testId,assertion_origin:origin }];
  const verify = () => verifyMutationBackendDiscovery(root, authorityReceipt, sourceReceipt(root), input_sha256);
  const assess = (proof, meta = metadata, schedule = { inventory,tests }, currentHashes = hashes) => assessMutmut(meta, events, [changed, zero], currentHashes, [], new Set(), schedule, () => testBody, proof);
  return { root, put, source, hashes, changed, zero, id, raw, generation, generated, authority, authorityReceipt, inventoryReceipt, inventory, metadata, events, verify, assess };
}

test('canonical verified generation permits present empty metadata only for a proven zero source without adding a kill', () => {
  const value = fixture();
  try {
    const verified = canonicalMutmutGeneration(value.root, sourceReceipt(value.root), value.inventoryReceipt);
    const assessment = value.assess(verified);
    expect(assessment).toEqual({ total: 1, killed: 1, equivalent: 0, errors: [], proven_zero_sources: [value.zero] });
    const summary = { backends: {}, errors: [] };
    appendAssessment(summary, 'mutmut', assessment);
    expect(summary.backends.mutmut).toEqual({ total: 1, killed: 1, equivalent: 0, errors: [], proven_zero_sources: [value.zero] });
    const exposed = verifiedMutationMaterializations(verified);
    expect(Object.isFrozen(exposed.source_materializations[0].mutant_ids)).toBe(true);
    expect(() => verifiedMutationMaterializations({ ...verified })).toThrow(/verified backend materialization identity/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('zero source exemptions reject missing or forged authority, stale source, absent metadata and schedule or compile contradictions', () => {
  const value = fixture(), other = fixture({ tool: 'python-static', version: '1.0.0' });
  try {
    const verified = value.verify();
    for (const proof of [undefined, JSON.parse(JSON.stringify(verified)), { source_materializations: value.generation.source_materializations }]) expect(value.assess(proof).errors.length).toBeGreaterThan(0);
    expect(value.assess(other.verify()).errors).toContain('mutmut complete source-bound materialization authority is missing or stale.');
    expect(value.assess(verified, value.metadata, { inventory: value.inventory }, { ...value.hashes, [value.zero]: '0'.repeat(64) }).errors).toContain('mutmut complete source-bound materialization authority is missing or stale.');
    for (const meta of [undefined, {}, { exit_code_by_key: [] }, { exit_code_by_key: new Date(0) }, { exit_code_by_key: {}, type_check_error_by_key: { unexpected: 'compile error' } }, { exit_code_by_key: {}, type_check_error_by_key: null }, { exit_code_by_key: { unexpected: 1 } }]) expect(value.assess(verified, { ...value.metadata, [value.zero]: meta }).errors.length).toBeGreaterThan(0);
    for (const schedule of [undefined, { inventory: [...value.inventory, { id: 'unexpected', file: value.zero }] }]) {
      const actual = assessMutmut(value.metadata, value.events, [value.changed, value.zero], value.hashes, [], new Set(), schedule, () => null, verified);
      expect(actual.errors.length).toBeGreaterThan(0);
    }
    value.put('.artifacts/control.json', 'Changed raw parser evidence\n');
    expect(value.verify).toThrow(/receipt mismatch/);
  } finally { for (const item of [value, other]) rmSync(item.root, { recursive: true, force: true }); }
});

test('zero proof never admits an empty complete inventory or globally empty runtime suite, and canonical bindings stay exact', () => {
  const value = fixture();
  try {
    const verified = value.verify();
    expect(assessMutmut({ [value.zero]: value.metadata[value.zero] }, [], [value.zero], value.hashes, [], new Set(), { inventory: value.inventory }, () => null, verified).errors).toContain('mutmut scheduled no mutants.');
    expect(() => canonicalMutmutGeneration(value.root, sourceReceipt(value.root), { ...value.inventoryReceipt, sha256: '0'.repeat(64) })).toThrow(/differs from the sealed source/);
    value.put(value.changed, 'def value():\n    return 2\n');
    expect(() => canonicalMutmutGeneration(value.root, sourceReceipt(value.root), value.inventoryReceipt)).toThrow(/source-bound authority/);
    value.put(value.changed, 'def value():\n    return 1\n');
    const empty = { ...value.generation, inventory: [], inventory_sha256: sha256(canonicalJson([])), source_materializations: value.generation.source_materializations.map(item => ({ ...item, mutant_ids: [] })) };
    const receipt = value.put('.artifacts/empty-generation.json', JSON.stringify(empty));
    const authority = value.put('.artifacts/empty-authority.json', JSON.stringify(authorityFromGeneration(value.root, sourceReceipt(value.root), acceptanceInputHash(sourceReceipt(value.root)), receipt)));
    expect(() => verifyMutationBackendDiscovery(value.root, authority, sourceReceipt(value.root), acceptanceInputHash(sourceReceipt(value.root)))).toThrow(/empty or oversized complete backend inventory/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});
