/** Production replay of actual shipped bytes; no supplied completeness flag. */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { readRecordedBytes } from './candidate.mjs';
import { verifyRequiredSourceMaterials } from './source-artifacts.mjs';
import { releasePythonCommand } from './verifier-runtime.mjs';

export const MAX_COMPONENT_SOURCE_REPORT_BYTES = 192 * 1024 ** 2;

/** Cheap metadata rejection only; signature/ancestry still precede replay. */
export function preflightActualComponentCoverage(candidate, source, requirements) {
  const recipe = source.files.find(row => row.path === 'runtime/materials/component-source-replay.json');
  if (!recipe || recipe.size > 16 * 1024 ** 2) throw new Error('Frozen actual component-source recipe is missing or oversized.');
  if (!Array.isArray(candidate?.artifacts) || !Array.isArray(requirements?.required_artifacts) || requirements.required_artifacts.length === 0 || new Set(requirements.required_artifacts).size !== requirements.required_artifacts.length) throw new Error('Actual component-source artifact inventory is invalid.');
  const ids = new Set();
  for (const row of candidate.artifacts) { if (typeof row?.id !== 'string' || ids.has(row.id)) throw new Error('Actual component-source artifact identity is missing or duplicate.'); ids.add(row.id); }
  if (requirements.required_artifacts.some(id => !ids.has(id))) throw new Error('Actual component-source coverage requires every declared distribution subject.');
  const rows = candidate.artifacts.filter(row => row.id === 'component-source-coverage');
  if (rows.length !== 1 || !/^[a-f0-9]{64}$/.test(rows[0].sha256 ?? '') || !Number.isSafeInteger(rows[0].size) || rows[0].size <= 0 || rows[0].size > MAX_COMPONENT_SOURCE_REPORT_BYTES) throw new Error('Actual component-source coverage artifact is missing, duplicate or oversized.');
}

export function verifyActualComponentClosure(root, candidate, source, verifierRuntime) {
  const name = 'runtime/materials/component-source-replay.json', recipe = source.files.find(row => row.path === name);
  if (!recipe) throw new Error('Actual shipped component source-replay recipe is missing.');
  readRecordedBytes(root, recipe, 16 * 1024 ** 2);
  const rows = candidate.artifacts.filter(row => row.id === 'component-source-coverage');
  if (rows.length !== 1) throw new Error('Actual shipped component source-coverage report is missing or duplicated.');
  const bytes = readRecordedBytes(root, rows[0], MAX_COMPONENT_SOURCE_REPORT_BYTES), report = JSON.parse(bytes.toString('utf8'));
  if (report.schema_version !== 1 || report.qualification !== 'replayed-actual-shipped-component-source-license-closure' || report.complete_available_shipped_component_coverage !== true || report.complete_product_coverage !== true || report.source_inventory_sha256 !== source.sha256 || report.runtime_lock_sha256 !== candidate.runtime_lock_sha256 || report.unresolved_shipped_members?.length !== 0 || report.missing_distribution_subjects?.length !== 0) throw new Error('Actual available or full-product shipped component source coverage is incomplete.');
  if (report.inspection_inputs?.qualification !== 'observed-component-replay-inputs-no-unretained-input-waiver' || !Array.isArray(report.inspection_inputs.unretained_inputs) || report.inspection_inputs.unretained_inputs.length !== 0) throw new Error('Component replay has missing or unretained inspection inputs; workspace-only caches cannot satisfy a portable release.');
  const subjects = candidate.artifacts.filter(row => !['component-source-coverage', 'publisher-authority', 'checksum-manifest'].includes(row.id));
  if (!Array.isArray(report.subjects) || report.subjects.length !== subjects.length || subjects.some((row, index) => report.subjects[index]?.id !== row.id || report.subjects[index]?.artifact_sha256 !== row.sha256)) throw new Error('Source coverage omits, reorders or changes actual candidate artifact subjects.');
  verifyRequiredSourceMaterials(root, report.required_materials, { candidate });
  // This publisher-signed beta binds the full replay performed by the build.
  // Verify the published source parts without repeating the same derivation.
  if (candidate.signing_profile === 'publisher-beta') return { verified: true, report_sha256: rows[0].sha256 };
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'ud-component-source-replay-'));
  try {
    const manifest = path.join(temporary, 'candidate.json'); writeFileSync(manifest, JSON.stringify(candidate));
    const sourceFile = path.join(temporary, 'source.json'); writeFileSync(sourceFile, JSON.stringify(source));
    const replayRoot = path.join(temporary, 'inputs');
    const preparation = releasePythonCommand(verifierRuntime, [path.join(root, 'scripts/release/materialize-replay-inputs.py'), '--root', root, '--candidate', manifest, '--source', sourceFile, '--report', path.join(root, rows[0].path), '--output', replayRoot]);
    const materialized = spawnSync(preparation.executable, preparation.args, { encoding: 'utf8', timeout: 1800000, maxBuffer: 1024 ** 2, env: preparation.env });
    if (materialized.error || materialized.status !== 0) throw new Error(`Component inspection input materialization failed: ${materialized.error?.message ?? materialized.stderr.slice(-2000)}`);
    const replayCommand = releasePythonCommand(verifierRuntime, [path.join(root, 'scripts/release/component-closure.py'), '--root', root, '--assets-root', replayRoot, '--candidate', manifest, '--recipe', path.join(root, name), '--verify-report', path.join(root, rows[0].path)]);
    const result = spawnSync(replayCommand.executable, replayCommand.args, { encoding: 'utf8', timeout: 1800000, maxBuffer: 1024 ** 2, env: replayCommand.env });
    if (result.error || result.status !== 0) throw new Error(`Actual component source replay failed: ${result.error?.message ?? result.stderr.slice(-2000)}`);
    const replay = JSON.parse(result.stdout);
    if (replay.complete_product_coverage !== true || replay.complete_available_shipped_component_coverage !== true) throw new Error('Actual component source replay did not prove complete shipped coverage.');
    // Rehash the exact signed report after subprocess replay; the pathname is
    // never authority if concurrent input replacement occurred.
    readRecordedBytes(root, rows[0], MAX_COMPONENT_SOURCE_REPORT_BYTES);
    verifyRequiredSourceMaterials(root, report.required_materials, { candidate });
    return { verified: true, report_sha256: rows[0].sha256 };
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
