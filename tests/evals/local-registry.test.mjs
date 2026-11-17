import { test } from 'vitest';
import assert from 'node:assert/strict';
import { buildMatrix, HARNESSES, MODELS, operationCoverage, referenceRows, SEEDS } from '../../evals/local/registry.mjs';

test('starter matrix preserves all 18 native surfaces, three exact models and every common seed', () => {
  assert.deepEqual(MODELS.map(model => model.artifact), ['openbmb/MiniCPM-V-4.7-1B-int4', 'LiquidAI/LFM3-VL-2B-MLX-5bit', 'prism-ml/Ternary-Bonsai-2-2B-mlx-2bit']);
  assert.deepEqual(SEEDS, [17, 23, 47]);
  assert.equal(MODELS.find(model => model.id === 'bonsai').sampling.presence_context_size, 64);
  assert.equal(HARNESSES.length, 18);
  const matrix = buildMatrix();
  assert.equal(matrix.length, 171);
  assert.equal(new Set(matrix.map(row => row.id)).size, 171);
  for (const model of MODELS) for (const seed of SEEDS) {
    const selected = matrix.filter(row => row.model_id === model.id && row.seed === seed);
    assert.equal(selected.length, 19);
    assert.deepEqual(new Set(selected.map(row => row.harness_id)), new Set(HARNESSES.map(host => host.id)));
    assert.deepEqual(selected.filter(row => row.scenario_id === 'S7').map(row => row.harness_id), ['qwen-code']);
  }
  for (const scenario of ['S1', 'S2', 'S3', 'S4', 'S5', 'S6']) assert.equal(matrix.filter(row => row.scenario_id === scenario).length, 27);
  assert.equal(matrix.filter(row => row.scenario_id === 'S7').length, 9);
});

test('matrix scheduling does not interleave model residency or select a favorable seed', () => {
  const matrix = buildMatrix();
  const blocks = [];
  for (const row of matrix) {
    const block = `${row.model_id}/${row.seed}`;
    if (blocks.at(-1) !== block) blocks.push(block);
  }
  assert.deepEqual(blocks, MODELS.flatMap(model => SEEDS.map(seed => `${model.id}/${seed}`)));
  assert.deepEqual(buildMatrix(), matrix);
  assert.throws(() => buildMatrix({ snapshot: 'best-seed' }));
  assert.throws(() => buildMatrix({ controls: 'yes' }));
});

test('the full predefined control block adds eighteen baseline-only episodes', () => {
  const baseline = buildMatrix({ controls: true });
  const candidate = buildMatrix({ controls: true, snapshot: 'candidate' });
  assert.equal(baseline.length, 189);
  assert.equal(candidate.length, 171);
  assert.equal(baseline.length + candidate.length, 360);
  const controls = baseline.filter(row => !row.skills_enabled);
  assert.equal(controls.length, 18);
  assert.deepEqual(new Set(controls.map(row => `${row.harness_id}/${row.scenario_id}`)), new Set(['codex-cli/S2', 'mini-swe-agent/S3']));
  assert.equal(candidate.some(row => !row.skills_enabled), false);
});

test('references rotate models using fixed seed 17 without looking at outcomes', () => {
  const references = referenceRows();
  assert.deepEqual(references.map(row => row.scenario_id), ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7']);
  assert.deepEqual(references.map(row => row.model_id), ['minicpm', 'lfm3', 'bonsai', 'minicpm', 'lfm3', 'bonsai', 'minicpm']);
  assert.ok(references.every(row => row.seed === 17 && row.skills_enabled));
  assert.deepEqual(referenceRows({ snapshot: 'candidate' }).map(row => row.cell_id), references.map(row => row.cell_id));
  assert.ok(HARNESSES.every(host => host.variants.length && host.variants.every(variant => variant.evidence_status === 'untested')));
  assert.equal(HARNESSES.find(host => host.id === 'codex-desktop').execution_location, 'native-macos');
  assert.equal(HARNESSES.find(host => host.id === 'codex-cli').execution_location, 'arm64-container');
});

test('operation coverage maps the actual public catalog without inventing live results', () => {
  const coverage = operationCoverage(process.cwd());
  assert.equal(coverage.length, 104);
  assert.equal(new Set(coverage.map(row => row.operation_id)).size, 104);
  assert.ok(coverage.every(row => row.cli.arguments[1] === row.mcp.tool && row.operation === row.mcp.tool));
  assert.ok(coverage.every(row => row.evidence.native_model_execution === 'not_run' && row.evidence.deterministic_execution === 'not_run'));
  assert.deepEqual(coverage.find(row => row.operation === 'validation_report').skill_families, ['ud-validate']);
  assert.ok(coverage.filter(row => !row.operation_id.startsWith('ENV')).every(row => row.skill_families.length));
});
