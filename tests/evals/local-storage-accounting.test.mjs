/** Native I/O remains serviceable during complete storage inventories. MIT. */
import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, linkSync, symlinkSync, rmSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ownedStorageBytes } from '../../scripts/quality/storage-lifecycle.mjs';
import { measureOwnedStorage } from '../../evals/local/storage-accounting.mjs';
import { scientificStudyStorage } from '../../evals/local/study-storage.mjs';

test('worker inventories retain exact full-tree and hardlink rules while yielding native I/O', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-storage-worker-')));
  try {
    writeFileSync(path.join(root, 'one'), 'one');
    linkSync(path.join(root, 'one'), path.join(root, 'same-inode'));
    symlinkSync(path.join(root, 'missing-outside'), path.join(root, 'link'));
    let turn = false;
    const count = measureOwnedStorage([root, root]);
    setImmediate(() => { turn = true; });
    assert.equal(await count, ownedStorageBytes([root]));
    assert.equal(turn, true);
    await assert.rejects(measureOwnedStorage([root], 1), /byte budget/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('concurrent boundary checks share a complete scan and propagate failures without passing', async () => {
  let finish, scans = 0, checks = 0;
  const lease = scientificStudyStorage('/repo', 'run', {
    measure: () => 100, engine: () => 0,
    asyncMeasure: () => { scans++; return new Promise(resolve => { finish = resolve; }); },
    reserve: () => ({ check: amount => { checks++; assert.equal(amount, 25); }, cleanup() {} }),
  });
  const first = lease.check(), second = lease.check();
  assert.equal(scans, 1); assert.equal(checks, 0);
  finish(125); await Promise.all([first, second]); assert.equal(checks, 1);
  await lease.cleanup(); await assert.rejects(lease.check(), /already closed/);
  const failed = scientificStudyStorage('/repo', 'run', {
    measure: () => 100, engine: () => 0, asyncMeasure: async () => { throw new Error('inventory unavailable'); },
    reserve: () => ({ check() { assert.fail('Missing inventories cannot pass.'); }, cleanup() {} }),
  });
  await assert.rejects(failed.check(), /inventory unavailable/); await failed.cleanup();
});

test('live output guard inventories all declared roots and verifies cancellation on overflow', async () => {
  vi.useFakeTimers();
  let cancel = 0, roots, finished = false;
  const lease = scientificStudyStorage('/repo', 'run', {
    measure: () => 100, engine: () => 0, watchMeasure: value => { roots = value; return 10; },
    asyncWatchMeasure: async value => { assert.deepEqual(value, roots); return 31; },
    onCancel: async () => { cancel++; await Promise.resolve(); finished = true; },
    reserve: () => ({ check(amount) { if (amount > 20) throw new Error('output exceeds declared plan'); }, cleanup() { assert.equal(finished, true); } }),
  });
  try {
    lease.watch(['/repo/campaign', '/repo/admission']);
    await vi.advanceTimersByTimeAsync(2000);
    assert.equal(cancel, 1);
    await assert.rejects(lease.check(), /declared plan/);
    await assert.rejects(lease.cleanup(), /declared plan/);
    assert.equal(finished, true);
  } finally { vi.useRealTimers(); }
});
