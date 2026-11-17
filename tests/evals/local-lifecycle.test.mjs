import { posixTest } from '../fixtures/native-scope.mjs';
/** Owned lifecycle regressions from the first frozen diagnostic. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { mkdtempSync, realpathSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { createBudgetAuthority } from '../../evals/local/budget.mjs';
import { removeOwnedNetwork } from '../../evals/local/container.mjs';
import { failureObservation, cleanupObservation, observedCounters } from '../../evals/local/lifecycle.mjs';
import { executeProbe } from '../../evals/local/study-execution.mjs';

posixTest('native setup has its own bounded clock and cannot spend the90second loop', async () => {
  const directory = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-lifecycle-')));
  const budget = await createBudgetAuthority({ directory, deferredStart: true, setupMs: 500, deadline: Date.now() + 1000, limits: { wall_ms: 100 } });
  try {
    assert.equal(budget.snapshot().started, null); assert.throws(() => budget.reserveInference({ inputTokens: 1 }), /NOT_STARTED/);
    await new Promise(resolve => setTimeout(resolve, 120));
    budget.begin(); const state = budget.snapshot(); assert.ok(state.deadline - state.started === 100); assert.ok(state.started - state.prepared_at >= 100);
    assert.throws(() => budget.begin(), /START_INVALID/);
    const request = budget.reserveInference({ inputTokens: 1 }); budget.finishInference({ id: request.id, outputTokens: 1 });
    assert.equal(budget.snapshot().counters.inference, 1);
  } finally { await budget.close(); rmSync(directory, { recursive: true, force: true }); }
});
test('empty-network race retries exact owned identity without force and stops on ownership change', async () => {
  const owner = 'owned', networkId = 'a'.repeat(64), network = 'owned-network', args = [];
  let removals = 0;
  const info = { Id: networkId, Name: network, Labels: { 'io.github.mehmetoguzderin.ud-agent.local-eval': owner }, Containers: {} };
  const runner = async (_cmd, argv) => { args.push(argv); if (argv[1] === 'inspect') return { stdout: JSON.stringify([info]) }; if (++removals === 1) throw new Error('network has active endpoints'); return { stdout: networkId }; };
  const result = await removeOwnedNetwork({ docker: 'fixture', runner, networkId, network, owner, deadline: Date.now() + 1000, sleep: async () => {} });
  assert.equal(result.cleanupVerified, true); assert.equal(removals, 2); assert.ok(result.steps.some(step => step.outcome === 'failed')); assert.ok(!args.flat().includes('--force'));
  info.Containers = { unrelated: {} }; const denied = await removeOwnedNetwork({ docker: 'fixture', runner, networkId, network, owner, deadline: Date.now() + 1000 });
  assert.equal(denied.cleanupVerified, false); assert.match(denied.failure.message, /OWNERSHIP_CHANGED/); assert.equal(removals, 2);
});
test('cleanup observations preserve failed substeps and nested transport causes, never replace unknown output with zero', () => {
  const error = Object.assign(new Error('fetch failed'), { cause: Object.assign(new Error('socket closed'), { code: 'ECONNRESET' }) });
  assert.equal(failureObservation(error).cause.code, 'ECONNRESET');
  const result = { cleanupVerified: false, container_cleanup: [{ step: 'network-remove', outcome: 'failed' }], cleanup_error: 'group still present', stdout: 'large transcript' };
  assert.deepEqual(cleanupObservation(result).container_cleanup, result.container_cleanup); assert.equal(cleanupObservation(result).stdout, undefined);
  assert.equal(observedCounters({ counters: { output: 0, inference: 1 }, output_usage_verified: false }).output, null);
  assert.equal(observedCounters({ counters: { output: 0, inference: 0 }, output_usage_verified: true }).output, 0);
});
test('a prebudget reset failure preserves cause and independently verified release without claiming inference', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-probe-reset-'))), directory = path.join(root, 'unit'), installation = path.join(root, 'installed'); mkdirSync(directory); mkdirSync(path.join(installation, 'skills/ud-edit'), { recursive: true });
  writeFileSync(path.join(installation, 'skills/ud-edit/SKILL.md'), '---\nname: ud-edit\n---\nUse the documented operation.\n\n## Connected tools\nInspect actual schemas.');
  const capture = path.join(root, 'capture.json'); writeFileSync(capture, JSON.stringify({ selected: { body: { messages: [{ role: 'user', content: 'Edit the provided data.' }], tools: [] } } }));
  let stops = 0;
  try {
    const result = await executeProbe({ root, directory, row: { model_id: 'bonsai', harness_id: 'qwen-code', scenario_id: 'S2', model_artifact: 'exact', condition: 'unchanged', seed: 17 }, reservation: { deadline: Date.now() + 90_000 },
      metadata: { variant_installation: installation, captures: { 'bonsai/qwen-code/S2': { original: { path: capture }, activated: { path: capture } } } },
      resident: { async resetConversationCache() { throw Object.assign(new Error('fetch failed'), { cause: Object.assign(new Error('closed'), { code: 'ECONNRESET' }) }); }, async stop() { stops++; return { cleanupVerified: true, steps: [{ step: 'port-absence', verified: true }] }; } } });
    assert.equal(stops, 1); assert.equal(result.owned_cleanup_verified, true); assert.equal(result.real_inference, false); assert.equal(result.counters, null); assert.equal(result.failure.cause.code, 'ECONNRESET');
    const evidence = JSON.parse(readFileSync(path.join(directory, 'probe.json'))); assert.equal(evidence.budget, null); assert.equal(evidence.cleanup.preauthority_release.steps[0].step, 'port-absence');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
