import { posixTest } from '../fixtures/native-scope.mjs';
// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import { lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createBudgetAuthority, connectBudgetAuthority } from '../../evals/local/budget.mjs';
import { openEvaluationOperation } from '../../packages/coordinator/src/eval-observer.ts';

async function fixture(action, options = {}) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-budget-')));
  const budget = await createBudgetAuthority({ directory, ...options });
  try { await action(budget); } finally { await budget.close(); await rm(directory, { recursive: true, force: true }); }
}
posixTest('private clients cannot race past the operation ceiling or spend with a wrong capability', () => fixture(async budget => {
  const denied = connectBudgetAuthority({ socketPath: budget.socketPath, token: 'wrong' });
  await assert.rejects(denied.charge('ud_operations'), /BUDGET_UNAUTHORIZED/);
  assert.equal(budget.snapshot().stopped, null);
  const client = connectBudgetAuthority(budget);
  const results = await Promise.allSettled([client.charge('ud_operations', 7), client.charge('ud_operations', 6)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.ok(budget.snapshot().counters.ud_operations <= 12);
  assert.match(budget.snapshot().stopped, /BUDGET_EXCEEDED_UD_OPERATIONS/);
}));
posixTest('inference reserves the effective output allowance and charges tools atomically before exposure', () => fixture(async budget => {
  const request = budget.reserveInference({ inputTokens: 100, maxOutputTokens: 1000 });
  assert.equal(request.maxOutputTokens, 512);
  assert.throws(() => budget.reserveInference({ inputTokens: 100 }), /INFERENCE_ALREADY_ACTIVE/);
  budget.finishInference({ id: request.id, outputTokens: 511, toolCalls: 2 });
  assert.deepEqual(budget.snapshot().counters, { inference: 1, input: 100, output: 511, tools: 2, ud_operations: 0 });
  const next = budget.reserveInference({ inputTokens: 100 });
  assert.throws(() => budget.finishInference({ id: next.id, outputTokens: 5, toolCalls: 11 }), /BUDGET_EXCEEDED_TOOLS/);
  assert.equal(budget.snapshot().counters.tools, 2);
}));
posixTest('context includes output reserve and cumulative input is independent from context', async () => {
  await fixture(async budget => { assert.throws(() => budget.reserveInference({ inputTokens: 16000 }), /CONTEXT_ENVELOPE_EXCEEDED/); });
  await fixture(async budget => {
    const request = budget.reserveInference({ inputTokens: 200 }); budget.finishInference({ id: request.id, outputTokens: 1 });
    assert.throws(() => budget.reserveInference({ inputTokens: 101 }), /BUDGET_EXCEEDED_INPUT/);
  }, { limits: { input: 300 } });
});
posixTest('unknown counts fail closed and actual backend output cannot exceed its reserved allowance', async () => {
  await fixture(async budget => { assert.throws(() => budget.reserveInference({ inputTokens: null }), /TOKEN_COUNT_UNVERIFIED/); assert.equal(budget.snapshot().counters.inference, 0); });
  await fixture(async budget => {
    const request = budget.reserveInference({ inputTokens: 1, maxOutputTokens: 3 });
    assert.throws(() => budget.finishInference({ id: request.id, outputTokens: 4 }), /BUDGET_EXCEEDED_OUTPUT_PER_REQUEST/);
  });
});
posixTest('retries bind to the failed condition and a second retry ends the episode', () => fixture(async budget => {
  budget.charge('retry', 1, { key: 'first' }); budget.charge('retry', 1, { key: 'second' });
  assert.throws(() => budget.charge('retry', 1, { key: 'first' }), /BUDGET_EXCEEDED_RETRIES/);
}));
posixTest('native failure lineage survives changed arguments and failed recovery before dispatch', () => fixture(async budget => {
  const calls = (id, command) => ({ calls: [{ id, name: 'bash', arguments: { command } }] });
  budget.admitNativeCalls(calls('first', 'cat missing'));
  budget.nativeResult({ id: 'first', failed: true });
  budget.admitNativeCalls(calls('recovery', 'ls different'));
  budget.nativeResult({ id: 'recovery', failed: true });
  assert.throws(() => budget.admitNativeCalls(calls('again', 'find elsewhere')), /BUDGET_EXCEEDED_RETRIES/);
  assert.equal(budget.snapshot().native_recovery.observed_calls, 2);
  assert.equal(budget.snapshot().counters.tools, 0, 'native admission must not double-charge finishInference');
  assert.deepEqual(budget.snapshot().native_recovery.failures, [{ id: 'first', name: 'bash', attempts: 1 }]);
}));
posixTest('successful native recovery clears its failure; parallel retry overflow is atomic', async () => {
  await fixture(async budget => {
    const client = connectBudgetAuthority(budget);
    await client.admitNativeCalls({ calls: [{ id: 'a', name: 'read', arguments: { path: 'x' } }] });
    await client.nativeResult({ id: 'a', failed: true });
    await client.admitNativeCalls({ calls: [{ id: 'b', name: 'read', arguments: { path: 'y' } }] });
    await client.nativeResult({ id: 'b', failed: false });
    assert.equal(budget.snapshot().native_recovery.failures.length, 0);
    await client.admitNativeCalls({ calls: [{ id: 'c', name: 'read', arguments: {} }, { id: 'd', name: 'read', arguments: {} }] });
    await client.nativeResult({ id: 'c', failed: false }); await client.nativeResult({ id: 'd', failed: false });
    assert.equal(budget.snapshot().native_recovery.verified, true);
  });
  await fixture(async budget => {
    budget.admitNativeCalls({ calls: [{ id: 'a', name: 'read', arguments: {} }] }); budget.nativeResult({ id: 'a', failed: true });
    assert.throws(() => budget.admitNativeCalls({ calls: [{ id: 'b', name: 'read', arguments: {} }, { id: 'c', name: 'read', arguments: {} }] }), /BUDGET_EXCEEDED_RETRIES/);
    assert.equal(budget.snapshot().native_recovery.observed_calls, 1);
    assert.equal(Object.keys(budget.snapshot().retries).length, 0);
  });
});
posixTest('unknown, duplicate, pending or ambiguous native results cannot establish observed recovery', async () => {
  await fixture(async budget => {
    budget.admitNativeCalls({ calls: [{ id: 'a', name: 'bash', arguments: {} }] });
    assert.equal(budget.snapshot().native_recovery.verified, false);
    assert.throws(() => budget.nativeResult({ id: 'a', failed: null }), /NATIVE_RESULT_UNVERIFIED/);
    assert.equal(budget.snapshot().native_recovery.verified, false);
  });
  await fixture(async budget => {
    budget.admitNativeCalls({ calls: [{ id: 'a', name: 'read', arguments: {} }] });
    assert.throws(() => budget.admitNativeCalls({ calls: [{ id: 'b', name: 'read', arguments: {} }] }), /NATIVE_RESULTS_PENDING/);
  });
  await fixture(async budget => {
    budget.admitNativeCalls({ calls: [{ id: 'a', name: 'read', arguments: {} }, { id: 'b', name: 'read', arguments: {} }] });
    budget.nativeResult({ id: 'a', failed: true }); budget.nativeResult({ id: 'b', failed: true });
    assert.throws(() => budget.nativeResult({ id: 'a', failed: false }), /NATIVE_RESULT_INVALID/);
    assert.throws(() => budget.admitNativeCalls({ calls: [{ id: 'c', name: 'read', arguments: {} }] }), /NATIVE_RECOVERY_AMBIGUOUS/);
    assert.equal(budget.snapshot().native_recovery.observed_calls, 2);
  });
});
posixTest('deadline aborts active work and records unverified cleanup after its grace period', () => fixture(async budget => {
  const request = budget.reserveInference({ inputTokens: 1 }); assert.ok(request.id);
  await new Promise(resolve => budget.signal.addEventListener('abort', resolve, { once: true }));
  const snapshot = await budget.stop('ignored-second-reason');
  assert.equal(snapshot.stopped, 'EPISODE_TIMEOUT'); assert.equal(snapshot.cleanup, 'unverified');
}, { limits: { wall_ms: 30, cancellation_ms: 10 }, onStop: () => new Promise(() => {}) }));
posixTest('verified process release abandons interrupted inference without inventing actual token usage', () => fixture(async budget => {
  const completed = budget.reserveInference({ inputTokens: 7, maxOutputTokens: 30 });
  budget.finishInference({ id: completed.id, outputTokens: 13, toolCalls: 2 });
  const interrupted = budget.reserveInference({ inputTokens: 19, maxOutputTokens: 27 });
  let recursiveStop;
  budget.signal.addEventListener('abort', () => { recursiveStop = budget.stop('recursive'); }, { once: true });
  const stopping = budget.stop('EPISODE_TIMEOUT');
  assert.equal(stopping, recursiveStop); assert.equal(stopping, budget.stop('later'));
  assert.equal(budget.snapshot().cleanup, 'pending'); assert.equal(budget.snapshot().pending_requests, 1);
  const state = await stopping;
  assert.equal(state.cleanup, 'verified'); assert.equal(state.pending_requests, 0); assert.equal(state.reserved_output, 0);
  assert.deepEqual(state.counters, { inference: 2, input: 26, output: 13, tools: 2, ud_operations: 0 });
  assert.deepEqual(state.abandoned_inference, [{ id: interrupted.id, usage: 'unknown', actual_output_tokens: null, reserved_output_tokens: 27, release_verified: true, reason: 'EPISODE_TIMEOUT' }]);
  assert.equal(state.output_usage_verified, false); assert.equal(state.unknown_output_tokens_upper_bound, 27); assert.equal(state.output_tokens_upper_bound, 40);
  assert.throws(() => budget.finishInference({ id: interrupted.id, outputTokens: 0 }), /EPISODE_TIMEOUT/);
  state.abandoned_inference[0].actual_output_tokens = 0;
  assert.equal(budget.snapshot().abandoned_inference[0].actual_output_tokens, null);
}, { onStop: async () => ({ cleanupVerified: true }) }));
posixTest('unverified cleanup and late verification preserve interrupted reservations', async () => {
  for (const outcome of ['false', 'throw', 'late']) {
    let release;
    await fixture(async budget => {
      budget.reserveInference({ inputTokens: 9, maxOutputTokens: 41 });
      const state = await budget.stop('EPISODE_TIMEOUT');
      assert.equal(state.cleanup, 'unverified'); assert.equal(state.pending_requests, 1);
      assert.equal(state.reserved_output, 41); assert.equal(state.output_tokens_upper_bound, 41); assert.equal(state.output_usage_verified, false);
      assert.deepEqual(state.abandoned_inference, []); assert.equal(state.counters.output, 0);
      if (release) { release(true); await new Promise(resolve => setTimeout(resolve, 0)); }
      assert.equal(budget.snapshot().pending_requests, 1); assert.equal(budget.snapshot().cleanup, 'unverified');
    }, { limits: { cancellation_ms: 10 }, onStop: () => outcome === 'late' ? new Promise(resolve => { release = resolve; }) : outcome === 'throw' ? Promise.reject(new Error('release failed')) : false });
  }
});
posixTest('verified process release cannot clear an operation without its authoritative terminal event', () => fixture(async budget => {
  await budget.event({ type: 'operation_start', operation_id: 'pending', name: 'validate', arguments: {} });
  budget.reserveInference({ inputTokens: 3, maxOutputTokens: 11 });
  const state = await budget.stop('EPISODE_TIMEOUT');
  assert.equal(state.cleanup, 'unverified'); assert.equal(state.pending_operations, 1); assert.equal(state.pending_requests, 0);
  assert.equal(state.counters.ud_operations, 1); assert.equal(state.abandoned_inference.length, 1);
  await budget.event({ type: 'operation_result', operation_id: 'pending', response: { isError: true, structuredContent: { execution: { status: 'incomplete' } } } });
  assert.equal(budget.snapshot().pending_operations, 0); assert.equal(budget.snapshot().cleanup, 'unverified');
}, { onStop: async () => true }));
posixTest('operation terminal events received during cancellation permit verified cleanup', async () => {
  let finish;
  await fixture(async budget => {
    await budget.event({ type: 'operation_start', operation_id: 'pending', name: 'validate', arguments: {} });
    finish = () => budget.event({ type: 'operation_result', operation_id: 'pending', response: { isError: true, structuredContent: { execution: { status: 'cancelled' } } } });
    const state = await budget.stop('EPISODE_TIMEOUT');
    assert.equal(state.cleanup, 'verified'); assert.equal(state.pending_operations, 0); assert.equal(state.output_usage_verified, true);
  }, { onStop: async () => { await finish(); return true; } });
});
posixTest('coordinator instrumentation charges before work and injects one committed response failure', async () => {
  const events = [], previous = process.env.UD_AGENT_EVAL_BUDGET;
  try {
    delete process.env.UD_AGENT_EVAL_BUDGET;
    assert.equal(await openEvaluationOperation('fixture', {}), undefined);
    await fixture(async budget => {
      process.env.UD_AGENT_EVAL_BUDGET = JSON.stringify({ socketPath: budget.socketPath, token: budget.token });
      const first = await openEvaluationOperation('token_edit', { edit_options: { idempotency_key: 'same', mode: 'apply' } });
      assert.equal(budget.snapshot().counters.ud_operations, 1);
      await first.step('candidate_validation', true);
      const complete = { structuredContent: { execution: { status: 'completed' }, result: { transaction: { status: 'completed' } } } };
      await assert.rejects(first.result(complete, true), /EVAL_TRANSPORT_RESPONSE_LOST/);
      const second = await openEvaluationOperation('token_edit', { edit_options: { idempotency_key: 'same', mode: 'apply' } });
      await second.result({ structuredContent: { ...complete.structuredContent, result: { transaction: { status: 'completed', replayed: true }, replayed: true } } }, true);
      assert.equal(budget.snapshot().counters.ud_operations, 3);
      assert.equal(events.filter(event => event.type === 'response_loss').length, 1);
      assert.equal(budget.snapshot().lost_response_injected, true);
      assert.equal(Object.values(budget.snapshot().retries)[0], 1);
    }, { onEvent: event => events.push(event), faults: { lostResponseAfterCommit: true } });
  } finally { if (previous === undefined) delete process.env.UD_AGENT_EVAL_BUDGET; else process.env.UD_AGENT_EVAL_BUDGET = previous; }
});
posixTest('repeated failed requests cannot receive a second recovery attempt', () => fixture(async budget => {
  for (const operationId of ['first', 'retry']) {
    await budget.event({ type: 'operation_start', operation_id: operationId, name: 'validate', arguments: {} });
    await budget.event({ type: 'operation_result', operation_id: operationId, response: { isError: true, structuredContent: { execution: { status: 'incomplete' } } } });
  }
  await assert.rejects(budget.event({ type: 'operation_start', operation_id: 'again', name: 'validate', arguments: {} }), /BUDGET_EXCEEDED_RETRIES/);
  assert.equal(budget.snapshot().counters.ud_operations, 2);
}));
posixTest('independent processes share one pre-dispatch budget', () => fixture(async budget => {
  const moduleUrl = new URL('../../evals/local/budget.mjs', import.meta.url).href;
  const source = `const {connectBudgetAuthority}=await import(${JSON.stringify(moduleUrl)}); try { await connectBudgetAuthority(JSON.parse(process.env.UD_TEST_CAPABILITY)).charge('ud_operations',7); process.stdout.write('admitted'); } catch { process.stdout.write('rejected'); }`;
  const child = () => new Promise((resolve, reject) => {
    const processHandle = spawn(process.execPath, ['--input-type=module', '-e', source], { env: { UD_TEST_CAPABILITY: JSON.stringify({ socketPath: budget.socketPath, token: budget.token }) }, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; processHandle.stdout.on('data', bytes => { output += bytes; }); processHandle.on('error', reject); processHandle.on('close', code => code === 0 ? resolve(output) : reject(new Error(`Child exited ${code}`)));
  });
  assert.deepEqual((await Promise.all([child(), child()])).sort(), ['admitted', 'rejected']);
  assert.equal(budget.snapshot().counters.ud_operations, 7);
}));
posixTest('long repository evidence paths use and remove a private short socket directory', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-budget-long-')));
  const budget = await createBudgetAuthority({ directory: path.join(root, 'campaign-evidence-'.repeat(8)) });
  const socketDirectory = path.dirname(budget.socketPath);
  try { assert.ok(Buffer.byteLength(budget.socketPath) <= 103); assert.equal((await lstat(socketDirectory)).mode & 0o077, 0); }
  finally { await budget.close(); await rm(root, { recursive: true, force: true }); }
  await assert.rejects(lstat(socketDirectory), error => error.code === 'ENOENT');
});

test('container observation transport preserves events and confines the private HTTP capability', async () => {
  const previous = process.env.UD_AGENT_EVAL_BUDGET, fetcher = globalThis.fetch, sent = [];
  try {
    globalThis.fetch = async (url, options) => { sent.push({ url: String(url), options, payload: JSON.parse(options.body) }); return new Response(JSON.stringify({ ok: true, value: {} })); };
    process.env.UD_AGENT_EVAL_BUDGET = JSON.stringify({ url: 'http://host.docker.internal:48123/__eval_budget', token: 'a'.repeat(64) });
    const operation = await openEvaluationOperation('validation_report', { file_paths: ['a.conllu'] });
    await operation.observation('runtime_readiness', { stage: 'initial', result: { ready: false } });
    assert.equal(sent.length, 2); assert.equal(sent[0].payload.arguments.event.type, 'operation_start');
    assert.deepEqual(sent[1].payload.arguments.event.observation, { stage: 'initial', result: { ready: false } });
    assert.equal(sent[1].payload.arguments.event.charge, false); assert.equal(sent[1].options.redirect, 'error');
    for (const url of ['https://host.docker.internal:48123/__eval_budget', 'http://example.com:48123/__eval_budget', 'http://127.0.0.1:48123/elsewhere', 'http://127.0.0.1:48123/__eval_budget?token=secret']) {
      process.env.UD_AGENT_EVAL_BUDGET = JSON.stringify({ url, token: 'a'.repeat(64) });
      await assert.rejects(openEvaluationOperation('validation_report', {}), /CAPABILITY_INVALID/);
    }
    assert.equal(sent.length, 2);
  } finally { globalThis.fetch = fetcher; if (previous === undefined) delete process.env.UD_AGENT_EVAL_BUDGET; else process.env.UD_AGENT_EVAL_BUDGET = previous; }
});

posixTest('namespaced native calls preserve exact failure identity and bounded recovery lineage', () => fixture(async budget => {
  budget.admitNativeCalls({ calls: [{ id: 'a', namespace: 'first', name: 'read', arguments: {} }] });
  budget.nativeResult({ id: 'a', failed: true });
  assert.deepEqual(budget.snapshot().native_recovery.failures, [{ id: 'a', namespace: 'first', name: 'read', attempts: 0 }]);
  // A different native action can be diagnostic recovery; it still spends the
  // original failure's sole allowance, rather than acquiring a namespace budget.
  budget.admitNativeCalls({ calls: [{ id: 'b', namespace: 'second', name: 'read', arguments: {} }] });
  budget.nativeResult({ id: 'b', failed: true });
  assert.deepEqual(budget.snapshot().native_recovery.failures, [{ id: 'a', namespace: 'first', name: 'read', attempts: 1 }]);
  assert.throws(() => budget.admitNativeCalls({ calls: [{ id: 'c', namespace: 'third', name: 'read', arguments: {} }] }), /BUDGET_EXCEEDED_RETRIES/);
}));
posixTest('malformed native namespace identity never reaches dispatch', () => fixture(async budget => {
  assert.throws(() => budget.admitNativeCalls({ calls: [{ id: 'a', namespace: 'not.a.namespace', name: 'read', arguments: {} }] }), /NATIVE_CALLS_INVALID/);
  assert.equal(budget.snapshot().native_recovery.observed_calls, 0);
}));

if (process.platform === 'win32') test('Windows cannot create a POSIX budget authority or charge an operation', async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-budget-refusal-')));
  let events = 0, stops = 0;
  try {
    await assert.rejects(createBudgetAuthority({ directory, onEvent: () => { events++; }, onStop: () => { stops++; } }), /BUDGET_PLATFORM_UNSUPPORTED/);
    assert.deepEqual(await (await import('node:fs/promises')).readdir(directory), []);
    assert.equal(events, 0); assert.equal(stops, 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
