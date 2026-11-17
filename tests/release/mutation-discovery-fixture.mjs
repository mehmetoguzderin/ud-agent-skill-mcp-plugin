/** Synthetic generation/authority records for verifier tests, never acceptance. */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { acceptanceInputHash } from '../../scripts/release/discover-acceptance.mjs';
import { mutationBackendContract, mutationBackendFiles } from '../../scripts/release/mutation-backends.mjs';

export const fixtureBackend = { tool: 'stryker', version: '10.1.1' };
export function prepareMutationDiscoveryFixture(root) {
  const files = mutationBackendFiles(fixtureBackend);
  for (const name of [...files.generators, ...files.configuration]) {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    if (!existsSync(path.join(root, name))) writeFileSync(path.join(root, name), '// Synthetic fixed generator/config identity.\n');
  }
}
export function mutationDiscoveryFixture(root, mutants, signature = undefined, suffix = '') {
  const source = sourceReceipt(root), input_sha256 = acceptanceInputHash(source);
  const contract = mutationBackendContract(root, source, fixtureBackend);
  const inventory = mutants.map(({ id, file, source_sha256, definition_sha256 }) => ({ id, file, source_sha256, definition_sha256 })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const record = (name, value) => { const relative = `.artifacts/${name}${suffix}.json`; mkdirSync(path.dirname(path.join(root, relative)), { recursive: true }); writeFileSync(path.join(root, relative), JSON.stringify(value)); return fileReceipt(root, relative); };
  const raw = record('synthetic-generated-definitions', { qualification: 'synthetic-fixture-not-real-generation', mutants });
  const execution = { command: ['synthetic-fixture-generator', '--inventory-only'], runtime: { kind: 'oci', image_id: `sha256:${'a'.repeat(64)}` } };
  const source_materializations = contract.sources.map(source => ({ source: source.path, source_sha256: source.sha256, mutant_ids: inventory.filter(item => item.file === source.path).map(item => item.id).sort(), artifacts: [raw] }));
  const generation = { schema_version: 1, kind: 'mutation-backend-generation', qualification: 'complete-backend-generation-no-outcomes', scope_complete: true, input_sha256, backend: fixtureBackend, ...contract, execution, source_materializations, raw_artifacts: [raw], inventory, inventory_sha256: sha256(canonicalJson(inventory)) };
  const generationReceipt = record('synthetic-raw-generation', generation);
  const authority = { schema_version: 1, kind: 'mutation-backend-discovery', qualification: 'complete-backend-inventory-no-outcomes', scope_complete: true, input_sha256, backend: fixtureBackend, ...contract, execution, raw_generation: generationReceipt, inventory, inventory_sha256: generation.inventory_sha256 };
  const receipt = record('synthetic-backend-discovery', authority);
  return { ...receipt, ...(signature ? { signature: signature(Buffer.from(JSON.stringify(authority))) } : {}) };
}
