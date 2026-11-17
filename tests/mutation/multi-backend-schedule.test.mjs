import { test, expect } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { compileAcceptanceInventory, acceptanceInputHash } from '../../scripts/release/discover-acceptance.mjs';
import { mutationBackendContract, mutationBackendFiles, authorityFromGeneration } from '../../scripts/release/mutation-backends.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { sourceReceipt, fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { discoveryFixture } from '../release/discovery-fixture.mjs';

function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-multiple-python-backends-'));
  const put = (name, value) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, value); return file; };
  put('tests/fixture.test.mjs', '// Synthetic transcript fixture, never execution evidence.\n');
  put('workers/ud/src/ud_agent/source.py', 'VALUE = True\n');
  const backends = [{ tool: 'mutmut', version: '3.8.1' }, { tool: 'python-static', version: '1.0.0' }];
  for (const backend of backends) for (const file of Object.values(mutationBackendFiles(backend)).flat()) if (!existsSync(path.join(root, file))) put(file, file.endsWith('.json') ? '{}' : '# Synthetic generator identity only\n');
  const catalog = discoveryFixture(root), source = sourceReceipt(root), input_sha256 = acceptanceInputHash(source), all = [];
  for (const [index, backend] of backends.entries()) {
    const contract = mutationBackendContract(root, source, backend), sourceFile = contract.sources.find(item => item.path.endsWith('/source.py'));
    const mutants = Array.from({ length: index + 2 }, (_, ordinal) => {
      const definition = { tool: backend.tool, version: backend.version, operator: 'fixture_literal', ordinal, replacement: ordinal + 2 };
      return { id: backend.tool + '-' + ordinal, file: sourceFile.path, source_sha256: sourceFile.sha256, definition, definition_sha256: sha256(canonicalJson(definition)) };
    });
    const inventory = mutants.map(({ id, file, source_sha256, definition_sha256 }) => ({ id, file, source_sha256, definition_sha256 }));
    const relative = file => path.relative(root, file).split(path.sep).join('/');
    const rawFile = put('.artifacts/' + backend.tool + '-raw.json', JSON.stringify({ qualification: 'synthetic-fixture-not-real-generation', mutants })), raw = fileReceipt(root, relative(rawFile));
    const generation = { schema_version: 1, kind: 'mutation-backend-generation', qualification: 'complete-backend-generation-no-outcomes', scope_complete: true, input_sha256, backend, ...contract, execution: { command: ['synthetic-generator', 'discover'], runtime: { kind: 'oci', image_id: 'sha256:' + 'a'.repeat(64) } }, inventory, inventory_sha256: sha256(canonicalJson(inventory)), source_materializations: contract.sources.map(item => ({ source: item.path, source_sha256: item.sha256, mutant_ids: inventory.filter(row => row.file === item.path).map(row => row.id), artifacts: [raw] })), raw_artifacts: [raw] };
    const generationFile = put('.artifacts/' + backend.tool + '-generation.json', JSON.stringify(generation));
    const generationReceipt = fileReceipt(root, relative(generationFile));
    const authorityFile = put('.artifacts/' + backend.tool + '-authority.json', JSON.stringify(authorityFromGeneration(root, source, input_sha256, generationReceipt)));
    const backend_discovery = fileReceipt(root, relative(authorityFile));
    for (const [ordinal, mutant] of mutants.entries()) all.push({ schema_version: 1, inventory_only: true, suite_id: 'mutation-python', tests: [catalog.tests[index]], mutants: [mutant], backend_discovery, shard: { index: ordinal, count: mutants.length, scheduled: mutants.length, inventory_sha256: generation.inventory_sha256 } });
  }
  return { root, catalog, all, requirements: { schema_version: 1, required_suites: ['mutation-python'] } };
}

test('one required Python suite reconciles both full backends with independent shard counts and test inventories', () => {
  const value = fixture();
  try {
    const inventory = compileAcceptanceInventory(value.root, value.catalog, value.requirements, [value.all[2], value.all[0], value.all[3], value.all[1], value.all[4]]);
    expect(inventory.state).toBe('frozen');
    expect(inventory.suites[0].mutants.map(item => item.id).sort()).toEqual(['mutmut-0', 'mutmut-1', 'python-static-0', 'python-static-1', 'python-static-2']);
    expect(inventory.suites[0].tests.map(item => item.id).sort()).toEqual(value.catalog.tests.map(item => item.id).sort());
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});

test('multi-backend freezing still rejects missing, duplicate and changed same-backend shards', () => {
  const value = fixture();
  try {
    for (const schedules of [value.all.slice(1), [...value.all, value.all[0]], value.all.map((row, index) => index === 1 ? { ...row, shard: { ...row.shard, count: 3 } } : row), value.all.filter(row => row.backend_discovery.path.includes('mutmut-authority'))]) expect(() => compileAcceptanceInventory(value.root, value.catalog, value.requirements, schedules)).toThrow(/shard|required complete/);
  } finally { rmSync(value.root, { recursive: true, force: true }); }
});
