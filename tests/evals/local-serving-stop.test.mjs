// SPDX-License-Identifier: MIT
import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import { stopAdmissionProcesses } from '../../evals/local/serving.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const owned = (pid, pending) => ({ child: { pid }, stop: vi.fn(() => pending.promise) });

test('admission stop starts group release while a slow resource observation drains, counting the entire interval', async () => {
  vi.useFakeTimers();
  try {
    const resource = deferred(), process = deferred(), worker = owned(101, process), events = [];
    const result = stopAdmissionProcesses({ owned: [worker], resourcePending: resource.promise, reason: 'calibration-cancellation', record: event => events.push(event) });
    await vi.advanceTimersByTimeAsync(0);
    assert.equal(worker.stop.mock.calls.length, 1, 'resource observation must not delay signalling the process');
    await vi.advanceTimersByTimeAsync(4000); resource.resolve();
    await vi.advanceTimersByTimeAsync(800); process.resolve({ cleanupVerified: true, cleanup_evidence: [{ method: 'signal-zero', outcome: 'failed', code: 'ESRCH' }] });
    const released = await result;
    assert.equal(released.cleanupVerified, true); assert.equal(released.elapsed_ms, 4800);
    assert.equal(events[0].elapsed_ms, 4800); assert.equal(events[0].resource_drain.status, 'fulfilled');
    assert.equal(events[0].deadline - events[0].started_at, 5000);
  } finally { vi.useRealTimers(); }
});

test('one five-second deadline retains unknown process and resource outcomes; late evidence cannot repair it', async () => {
  vi.useFakeTimers();
  try {
    const resource = deferred(), process = deferred(), events = [];
    const pending = stopAdmissionProcesses({ owned: [owned(202, process)], resourcePending: resource.promise, reason: 'stop', record: event => events.push(event) });
    const failed = pending.catch(error => error);
    await vi.advanceTimersByTimeAsync(5000);
    const failure = await failed;
    assert.equal(failure.code, 'CANCELLATION_UNVERIFIED');
    assert.equal(failure.cleanup.elapsed_ms, 5000); assert.equal(failure.cleanup.cleanupVerified, false);
    assert.equal(failure.cleanup.resource_drain.status, 'pending');
    assert.equal(failure.cleanup.outcomes[0].observation, 'pending');
    const retained = structuredClone(events[0]);
    await vi.advanceTimersByTimeAsync(1000);
    resource.resolve(); process.resolve({ cleanupVerified: true });
    await vi.advanceTimersByTimeAsync(0);
    assert.deepEqual(events[0], retained);
    assert.equal(failure.cleanup.cleanupVerified, false);
    assert.ok(events.some(event => event.type === 'owned_server_stop_late_outcome' && event.within_cancellation_allowance === false));
    assert.ok(events.some(event => event.type === 'owned_server_stop_late_resource_drain' && event.within_cancellation_allowance === false));
  } finally { vi.useRealTimers(); }
});

test('an observation that fails while draining remains failed evidence beside independently verified group absence', async () => {
  const events = [];
  const released = await stopAdmissionProcesses({ owned: [{ child: { pid: 303 }, stop: async () => ({ cleanupVerified: true }) }],
    resourcePending: Promise.reject(Object.assign(new Error('memory query denied'), { code: 'EPERM' })), reason: 'stop', record: event => events.push(event) });
  assert.equal(released.cleanupVerified, true);
  assert.equal(events[0].resource_drain.status, 'rejected');
  assert.equal(events[0].resource_drain.error.code, 'EPERM');
  assert.equal(events[0].outcomes[0].cleanupVerified, true);
});

test('an unverified or rejected group release fails even when resource drainage completes', async () => {
  const events = [];
  await assert.rejects(stopAdmissionProcesses({ owned: [
    { child: { pid: 404 }, stop: async () => ({ cleanupVerified: false, cleanup_error: 'group remains' }) },
    { child: { pid: 405 }, stop: async () => { throw Object.assign(new Error('signal failed'), { code: 'EPERM' }); } },
  ], resourcePending: Promise.resolve(), reason: 'stop', record: event => events.push(event) }), /CANCELLATION_UNVERIFIED/);
  assert.equal(events[0].cleanupVerified, false);
  assert.equal(events[0].resource_drain.status, 'fulfilled');
  assert.equal(events[0].outcomes[0].cleanup_error, 'group remains');
  assert.equal(events[0].outcomes[1].observation, 'rejected');
  assert.equal(events[0].outcomes[1].error.code, 'EPERM');
});

test('elapsed time starts at stop entry and no fresh allowance is granted after earlier draining work', async () => {
  vi.useFakeTimers();
  try {
    const process = deferred(), events = [], startedAt = Date.now() - 4000;
    const failed = stopAdmissionProcesses({ owned: [owned(505, process)], resourcePending: Promise.resolve(), reason: 'stop', startedAt, record: event => events.push(event) }).catch(error => error);
    await vi.advanceTimersByTimeAsync(1000);
    const error = await failed;
    assert.equal(error.code, 'CANCELLATION_UNVERIFIED');
    assert.equal(events[0].elapsed_ms, 5000); assert.equal(events[0].started_at, startedAt);
    process.resolve({ cleanupVerified: true }); await vi.advanceTimersByTimeAsync(0);
    assert.equal(events[0].cleanupVerified, false);
  } finally { vi.useRealTimers(); }
});
