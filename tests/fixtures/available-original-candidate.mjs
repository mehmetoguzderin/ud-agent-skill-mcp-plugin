/** Synthetic complete byte-binding packet; no real source-replay/publisher claim. */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { availableScope } from '../../scripts/release/available-candidate.mjs';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { packageInventory, retainSourceSnapshot } from '../../scripts/release/prepare.mjs';
import { fixtureTar } from '../release/oci-fixture.mjs';

export function availableOriginalCandidate(sourceRoot, candidateRoot) {
  const put = (root, name, value) => { mkdirSync(path.dirname(path.join(root, name)), { recursive: true }); writeFileSync(path.join(root, name), typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)); };
  const required = JSON.parse(readFileSync(new URL('../../quality/requirements.json', import.meta.url))).required_artifacts;
  put(sourceRoot, 'quality/requirements.json', { required_artifacts: required });
  put(sourceRoot, 'runtime/runtime.lock.json', { schema_version: 1, state: 'frozen', packs: { core: { images: { 'linux/arm64': { digest: 'sha256:' + 'a'.repeat(64) } } }, render: { images: { 'linux/arm64': { digest: 'sha256:' + 'b'.repeat(64) } } } } });
  put(sourceRoot, 'runtime/userspace.lock.json', { platforms: { 'darwin/arm64': {} } });
  const body = Buffer.from('Synthetic original source member.'), digest = sha256(body), receipt = Buffer.from('{"fixture":"source"}');
  const materials = { schema_version: 1, qualification: 'verified-corresponding-source-subinventories', complete_product_coverage: false, files: [{ path: 'blobs/' + digest, sha256: digest, size_bytes: body.length }], collections: [{ id: 'fixture', receipt_path: 'receipts/fixture.json', receipt_sha256: sha256(receipt), receipt_size_bytes: receipt.length, members: [{ path: 'blobs/' + digest, sha256: digest, size_bytes: body.length }] }] };
  const materialsBytes = Buffer.from(JSON.stringify(materials)), part = fixtureTar([['MATERIALS.json', materialsBytes], ['receipts/fixture.json', receipt], ['blobs/' + digest, body]]);
  const partRow = { id: 'corresponding-source-0000', path: 'artifacts/source.part', sha256: sha256(part), size: part.length };
  const index = { schema_version: 1, qualification: materials.qualification, complete_product_coverage: false, format: 'concatenated-ustar', manifest_sha256: sha256(materialsBytes), stream_sha256: sha256(part), stream_size_bytes: part.length, parts: [{ ...partRow, path: 'source.part' }], collections: [{ id: 'fixture', sha256: sha256(receipt) }], unique_source_files: 1 };
  const indexBytes = Buffer.from(JSON.stringify(index)), indexRow = { id: 'corresponding-source-index', path: 'artifacts/source-index.json', sha256: sha256(indexBytes), size: indexBytes.length };
  put(sourceRoot, 'runtime/source-materials.lock.json', { schema_version: 1, index: indexRow, parts: [partRow] });
  const source = sourceReceipt(sourceRoot), runtimeHash = fileReceipt(sourceRoot, 'runtime/runtime.lock.json').sha256;
  mkdirSync(candidateRoot); retainSourceSnapshot(sourceRoot, source, path.join(candidateRoot, 'source-snapshot'));
  const runtimeRoot = path.join(candidateRoot, 'runtime-inputs');
  const runtimeFiles = ['runtime/runtime.lock.json', 'runtime/userspace.lock.json'].map(name => { put(runtimeRoot, name, readFileSync(path.join(sourceRoot, name))); return fileReceipt(runtimeRoot, name); });
  put(candidateRoot, 'RUNTIME-INVENTORY.json', { schema_version: 1, files: runtimeFiles });
  const artifacts = [], add = (id, bytes, filename = id + '.bin', platform = 'all') => { const name = 'artifacts/' + filename; put(candidateRoot, name, bytes); const row = { id, platform, ...fileReceipt(candidateRoot, name) }; artifacts.push(row); return row; };
  add('npm', 'Synthetic original npm archive'); add('native-macos-arm64', 'Synthetic original native archive', undefined, 'macos-arm64'); add('mcpb-macos-arm64', 'Synthetic original MCPB archive', undefined, 'macos-arm64');
  add(partRow.id, part, 'source.part'); add(indexRow.id, indexBytes, 'source-index.json');
  for (const [root, kind, platform] of [['native-installation', 'native', 'darwin-arm64'], ['npm-installation', 'npm', 'all']]) { put(candidateRoot, root + '/RELEASE-CANDIDATE.md', 'Synthetic immutable payload'); packageInventory(path.join(candidateRoot, root), kind, platform, source.sha256, runtimeHash, 'preacceptance_candidate'); }
  const manifest = { schema_version: 1, qualification: 'available-target-preacceptance', status: 'preacceptance_candidate', production_ready: false, material_phase: 'final', source_tree_sha256: source.sha256, runtime_lock_sha256: runtimeHash, artifacts, scope: availableScope(sourceRoot, ['darwin-arm64'], artifacts), installations: [{ platform: 'darwin-arm64', formats: { native: { root: 'native-installation', artifact_id: 'native-macos-arm64' }, mcpb: { root: 'native-installation', artifact_id: 'mcpb-macos-arm64' }, npm: { root: 'npm-installation', artifact_id: 'npm' } } }], source_snapshot: { root: 'source-snapshot', receipt: fileReceipt(candidateRoot, 'source-snapshot/SOURCE-RECEIPT.json') }, runtime_root: 'runtime-inputs', runtime_inventory: fileReceipt(candidateRoot, 'RUNTIME-INVENTORY.json') };
  const coverage = { schema_version: 1, qualification: 'replayed-actual-shipped-component-source-license-closure', source_inventory_sha256: source.sha256, runtime_lock_sha256: runtimeHash, complete_available_shipped_component_coverage: true, complete_product_coverage: false, unresolved_shipped_members: [], inspection_inputs: { qualification: 'observed-component-replay-inputs-no-unretained-input-waiver', unretained_inputs: [] }, required_materials: [{ sha256: digest, size_bytes: body.length }], missing_distribution_subjects: manifest.scope.pending_artifacts.map(row => ({ code: 'REQUIRED_DISTRIBUTION_MISSING', artifact: row.id })).sort((a, b) => a.artifact.localeCompare(b.artifact)), subjects: artifacts.map(row => ({ id: row.id, artifact_sha256: row.sha256 })) };
  add('component-source-coverage', JSON.stringify(coverage), 'coverage.json');
  put(candidateRoot, 'available-candidate.json', manifest);
  return { manifest, source, candidateRoot, sourceRoot, artifacts };
}
