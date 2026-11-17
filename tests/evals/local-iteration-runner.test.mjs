/** MIT. Inert orchestration fixtures; no native client or model is launched. */
import { test, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, realpathSync, rmSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const state = vi.hoisted(() => ({ stops: 0, admissions: 0, cancel: false, calls: 0 }));
vi.mock('../../scripts/release/candidate.mjs', async original => ({ ...await original(), sourceReceipt: () => ({ sha256: 'b'.repeat(64), files: [] }) }));
vi.mock('../../evals/local/campaign.mjs', () => ({ frozenHashes: () => Object.fromEntries(['evaluator', 'oracle', 'tasks', 'model_configuration'].map(key => [key, 'a'.repeat(64)])), installSnapshot: vi.fn(),
  runEpisode: async (_root, manifest, row) => { state.calls++; if (state.cancel) process.emit('SIGINT'); return { ...row, outcome: 'failed', reason: 'Inert no-dispatch trajectory', candidate_installation_sha256: manifest.installation.sha256, owned_cleanup_verified: true,
    observations: { real_inference: true, native_loop: true, no_user_hints: true, skill_activation: false },
    metrics: { counters: { inference: 1, tools: 1, ud_operations: 0, input: 100, output: 20 }, total_elapsed_ms: 10 } }; } }));
vi.mock('../../evals/local/resource-memory.mjs', () => ({ sampleResourceMemory: async () => ({ verified: true, guard: 'admitted', fixture_only: true }), assertResourceMemory() {} }));
vi.mock('../../evals/local/study-storage.mjs', () => ({ scientificStudyStorage: () => ({ watch() {}, async check() {}, async cleanup() {} }) }));
vi.mock('../../evals/local/campaign-preflight.mjs', () => ({ verifyCampaignPreflight() {}, prepareCampaignSnapshot: async ({ root }) => {
  const { mkdirSync } = await import('node:fs'); const { sha256 } = await import('../../scripts/release/candidate.mjs');
  const installationRoot = root + '/installed-inert'; mkdirSync(installationRoot, { recursive: true });
  return { installationRoot, installation: { sha256: sha256('[]'), files: [] }, harnesses: ['gemini-cli', 'codex-cli', 'claude-code', 'qwen-code', 'mini-swe-agent', 'hermes-agent', 'deepseek-harness', 'grok-build', 'pi', 'openclaw', 'kimi-code'].map(id => ({ id, status: 'mechanically-admitted' })), mechanicalPreflight: { fixture_only: true } };
} }));
vi.mock('../../evals/local/serving.mjs', () => ({ admitModel: async () => { state.admissions++; return { status: 'admitted', admission_kind: 'mechanical', fixture_only: true, stop: async () => { state.stops++; return { cleanupVerified: true }; } }; } }));
vi.mock('../../evals/local/iteration-observations.mjs', () => ({ observeIterationEpisode: (_root, _installation, _row, result) => result }));
vi.mock('../../evals/local/preparation.mjs', async original => ({ ...await original(), readPreparation: () => ({ models: [{ id: 'lfm3', runtime_id: 'mlx' }], runtimes: [{ id: 'mlx' }] }) }));
vi.mock('../../evals/local/registry.mjs', async original => ({ ...await original(), operationCoverage: () => [] }));
const roots = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); state.stops = state.admissions = state.calls = 0; state.cancel = false; vi.unstubAllEnvs(); });
async function fixture() { vi.stubEnv('CI', 'false'); const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-inert-iteration-'))); roots.push(root); const directory = path.join(root, '.artifacts/local-evals/iterations/session'); const api = await import('../../evals/local/iterate.mjs'); return { root, directory, api }; }
test('CI exclusion rejects before reaching the inert provider or preparing a session', async () => {
  const { root, directory, api } = await fixture(); vi.stubEnv('CI', 'true');
  await expect(api.prepareIteration(root, { directory, optIn: true })).rejects.toThrow(/disabled in CI/);
  expect(state.admissions).toBe(0); expect(state.calls).toBe(0); expect(existsSync(directory)).toBe(false);
});
test('selected runner prepares without a clock and records all12 inert trajectories once', async () => {
  const { root, directory, api } = await fixture();
  const preparation = await api.prepareIteration(root, { directory, optIn: true }); expect(preparation.clock_started).toBe(false); expect(state.admissions).toBe(0);
  const result = await api.runIteration(root, { directory, optIn: true });
  expect(result.counts).toMatchObject({ scheduled: 12, recorded: 12, passed: 0, unfinished: 0 }); expect(state.admissions).toBe(1); expect(state.calls).toBe(12); expect(state.stops).toBeGreaterThan(0);
  await expect(api.runIteration(root, { directory, optIn: true })).rejects.toThrow(/initial baseline/); expect(state.calls).toBe(12);
  expect(existsSync(path.join(directory, 'execution.lock'))).toBe(false);
});
test('cancellation records the attempted episode, releases the model and never advances another seed', async () => {
  const { root, directory, api } = await fixture(); await api.prepareIteration(root, { directory, optIn: true }); state.cancel = true;
  await expect(api.runIteration(root, { directory, optIn: true })).rejects.toThrow(/CANCELLED/); expect(state.calls).toBe(1); expect(state.stops).toBeGreaterThan(0);
  const { openIterationSession } = await import('../../evals/local/iteration-state.mjs'); const report = openIterationSession({ root, directory }).report();
  expect(report.counts.recorded).toBe(1); expect(report.reserved.episodes).toBe(1); expect(report.deadline).toBeGreaterThan(report.started_at); expect(existsSync(path.join(directory, 'execution.lock'))).toBe(false);
});
test('forecasts include setup/reset/verification and refuse a short inference-only estimate', async () => {
  const { api } = await fixture(); expect(api.forecastIterationCell([1, 2, 3], [{ metrics: { elapsed_ms: 1, total_elapsed_ms: 200000 } }])).toMatchObject({ duration_ms: 660000, per_episode_ms: 200000 });
  expect(api.forecastIterationCell([1, 2, 3]).duration_ms).toBe(510000);
});

// Both rounds retain their real durable journals and report verification for
// all 126 trajectories, without a Windows wall-clock cutoff for filesystem work.
test('headless profile prepares all routes, runs the symmetric core and permits honest breadth after failures', async () => {
  const { root, directory, api } = await fixture();
  const preparation = await api.prepareIteration(root, { directory, profile: 'headless-12h-v2', optIn: true });
  expect(preparation.selected_routes).toHaveLength(11); expect(state.admissions).toBe(0);
  const baseline = await api.runIteration(root, { directory, optIn: true });
  expect(baseline.counts).toMatchObject({ scheduled: 72, recorded: 72, passed: 0, unfinished: 0 });
  expect(state.admissions).toBe(3); expect(state.calls).toBe(72);
  const breadth = await api.runIteration(root, { directory, optIn: true, kind: 'transfer' });
  expect(breadth.counts).toMatchObject({ scheduled: 126, recorded: 126, passed: 0, unfinished: 0 });
  expect(breadth.final_headless_qualification).toBe(false);
  expect(breadth.headless_qualification.rows).toHaveLength(117);
  expect(breadth.headless_qualification.coverage_complete).toBe(true);
  expect(existsSync(path.join(path.dirname(breadth.report), 'reference-S5.md'))).toBe(true);
}, process.platform === 'win32' ? 0 : 360_000);
test('headless forecast charges full preparation, cancellation, verification and accounting', async () => {
  const { api } = await fixture();
  expect(api.forecastIterationCell([1, 2, 3], [], 'headless-12h-v2')).toMatchObject({ per_episode_ms: 181000, duration_ms: 603000 });
  expect(api.forecastIterationCell([1], [{ metrics: { total_elapsed_ms: 240000 } }], 'headless-12h-v2').per_episode_ms).toBe(240000);
});
