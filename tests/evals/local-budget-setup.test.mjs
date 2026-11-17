import { posixTest } from '../fixtures/native-scope.mjs';
import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, mkdirSync, existsSync, rmSync, realpathSync } from 'node:fs';
import net from 'node:net';
import { once } from 'node:events';

const fault = vi.hoisted(() => ({ failChmod: true, failUnlink: false, socketPath: undefined }));
vi.mock('node:fs/promises', async original => {
  const actual = await original();
  return { ...actual,
    chmod: async (file, mode) => { if (fault.failChmod && String(file).endsWith('.sock')) { fault.socketPath = file; throw Object.assign(new Error('inert chmod fault after listen'), { code: 'EPERM' }); } return actual.chmod(file, mode); },
    unlink: async file => { if (fault.failUnlink && file === fault.socketPath) throw Object.assign(new Error('inert unlink fault'), { code: 'EACCES' }); return actual.unlink(file); },
  };
});
import { createBudgetAuthority } from '../../evals/local/budget.mjs';

posixTest.each([false, true])('authority creation cleans a bound socket after chmod failure, including short-path fallback=%s', async fallback => {
  // Keep the ordinary case below the Unix socket limit even when TMPDIR has
  // the longer macOS spelling; the other case deliberately exercises fallback.
  const temporary = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-b-'));
  const directory = path.join(temporary, fallback ? 'long-private-authority-directory-'.repeat(4) : 'authority');
  mkdirSync(directory, { mode: 0o700 }); fault.failChmod = true; fault.failUnlink = false; fault.socketPath = undefined;
  try {
    let caught;
    try { await createBudgetAuthority({ directory }); } catch (error) { caught = error; }
    assert.equal(caught?.code, 'EPERM');
    assert.equal(caught.budget_cleanup.cleanupVerified, true);
    assert.equal(existsSync(caught.budget_cleanup.socket_path), false);
    assert.equal(Boolean(caught.budget_cleanup.socket_directory), fallback);
    if (fallback) assert.equal(existsSync(caught.budget_cleanup.socket_directory), false);
    assert.ok(caught.budget_cleanup.steps.every(step => step.outcome === 'completed'));
    const client = net.createConnection(caught.budget_cleanup.socket_path);
    const [error] = await once(client, 'error');
    assert.ok(['ENOENT', 'ECONNREFUSED'].includes(error.code)); client.destroy();
    fault.failChmod = false;
    const retry = await createBudgetAuthority({ directory }); await retry.close();
    assert.equal(existsSync(retry.socketPath), false);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

posixTest('failed post-listen cleanup remains unverified rather than becoming an absent authority', async () => {
  const directory = mkdtempSync(path.join(realpathSync(os.tmpdir()), 'ud-budget-setup-failure-'));
  fault.failChmod = true; fault.failUnlink = true;
  try {
    await assert.rejects(createBudgetAuthority({ directory }), error => {
      assert.equal(error.code, 'EPERM'); assert.equal(error.budget_cleanup.cleanupVerified, false);
      assert.ok(error.budget_cleanup.steps.some(step => step.outcome === 'failed' && step.failure.code === 'EACCES'));
      return true;
    });
  } finally { fault.failUnlink = false; rmSync(directory, { recursive: true, force: true }); }
});

if (process.platform === 'win32') test('Windows refuses POSIX socket setup before creating its authority directory', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-budget-refusal-')), directory = path.join(root, 'authority');
  fault.socketPath = undefined;
  try {
    await assert.rejects(createBudgetAuthority({ directory }), /BUDGET_PLATFORM_UNSUPPORTED/);
    assert.equal(existsSync(directory), false); assert.equal(fault.socketPath, undefined);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
