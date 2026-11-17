import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import * as childProcess from 'node:child_process';
vi.mock('node:child_process', async original => ({ ...await original() }));
import os from 'node:os';
import path from 'node:path';
import { readObservation } from '../../evals/local/study-observation.mjs';
import { existsSync } from 'node:fs';
import { startOwned } from '../../evals/local/process.mjs';
import { createForwardSupervisor, compareForwardResults } from '../../evals/local/study-forward-process.mjs';

const artifact = 'LiquidAI/LFM3-VL-2B-MLX-5bit';
const processTest = (name, run) => test(process.platform === 'win32' ? `Windows refuses unsupported forward-worker startup: ${name}` : name, run);
const fixture = `const readline=require('node:readline');let used=0;console.log(JSON.stringify({event:'ready',artifact:${JSON.stringify(artifact)},maximum_forwards:24}));const lines=readline.createInterface({input:process.stdin});lines.on('line',line=>{let q=JSON.parse(line);if(q.hang)return;console.log(JSON.stringify({status:'observed',forward_ordinal:++used,next_logits:q.large?Array(300000).fill(0.25):[0,1,2],instrumented:!!q.instrument,generated_tokens:0}));});`;
async function temporary(run, source = fixture) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-forward-supervisor-'));
  mkdirSync(path.join(root, 'evals/local'), { recursive: true }); writeFileSync(path.join(root, 'evals/local/study_forward.py'), '# inert fixture');
  const directory = path.join(root, '.artifacts/local-evals/studies/fixture/forwards');
  const prepared = { status: 'prepared', directory: '/private/exact/model', artifact };
  const runtime = { status: 'prepared', python: '/private/runtime/python', lock_sha256: 'a'.repeat(64) };
  let worker;
  try {
    let attempted = 0;
    const start = () => createForwardSupervisor(root, prepared, runtime, { directory, deadline: Date.now() + 10000, optIn: true, environment: {}, readyTimeoutMs: 2000,
      start: (_command, _args, options) => { attempted++; return startOwned(process.execPath, ['-e', source], options); } });
    if (process.platform === 'win32') {
      const spawn = vi.spyOn(childProcess, 'spawn').mockImplementation(() => { throw new Error('Unsupported forward worker attempted to spawn.'); });
      const kill = vi.spyOn(process, 'kill').mockImplementation(() => { throw new Error('Unsupported forward worker attempted to signal.'); });
      try {
        await assert.rejects(start(), { message: 'OWNED_PROCESS_GROUP_UNSUPPORTED' });
        assert.equal(attempted, 1); assert.equal(spawn.mock.calls.length, 0); assert.equal(kill.mock.calls.length, 0);
        assert.equal(worker, undefined);
        assert.deepEqual(readdirSync(directory), ['home']); assert.deepEqual(readdirSync(path.join(directory, 'home')), []);
      } finally { spawn.mockRestore(); kill.mockRestore(); }
      return;
    }
    worker = await start();
    await run({ root, directory, worker });
  } finally { await worker?.stop(); rmSync(root, { recursive: true, force: true }); }
}

processTest('persistent forward worker records private large vectors, enforces ordinal and proves cleanup', async () => temporary(async ({ worker, directory }) => {
  const first = await worker.run({ request: {}, instrument: false });
  const second = await worker.run({ request: {}, instrument: true, large: true });
  assert.equal(first.forward_ordinal, 1); assert.equal(second.forward_ordinal, 2);
  assert.equal(second.next_logits.length, 300000); assert.equal(worker.used, 2);
  assert.equal(readObservation(second.evidence).response.instrumented, true);
  assert.ok(readFileSync(path.join(directory, 'ready.json'), 'utf8').includes('adapter_sha256'));
  const release = await worker.stop(); assert.equal(release.cleanupVerified, true);
  assert.equal(existsSync(path.join(directory, 'worker.log')), false); assert.equal(release.stdout, undefined); assert.ok(release.stdout_bytes > 1000);
  assert.equal(JSON.parse(readFileSync(path.join(directory, 'release.json'), 'utf8')).stdout, undefined);
  await assert.rejects(worker.run({ request: {} }), /FORWARD_WORKER_STOPPED/);
}));

processTest('deadline cancellation stops a hanging worker before returning and does not retry', async () => temporary(async ({ worker }) => {
  await assert.rejects(worker.run({ hang: true }, { deadline: Date.now() + 50 }), error => error.code === 'FORWARD_REQUEST_TIMEOUT' && error.cleanup.cleanupVerified === true);
  assert.equal(worker.used, 1); assert.equal((await worker.stop()).cleanupVerified, true);
}));

processTest('only one forward can be active and explicit cancellation owns cleanup', async () => temporary(async ({ worker }) => {
  const controller = new AbortController();
  const pending = worker.run({ hang: true }, { signal: controller.signal });
  await assert.rejects(worker.run({ request: {} }), /FORWARD_SINGLE_ACTIVE_REQUEST/);
  controller.abort();
  await assert.rejects(pending, error => error.code === 'FORWARD_REQUEST_CANCELLED' && error.cleanup.cleanupVerified === true);
}));

test('parity requires complete finite observations, numerical agreement and identical top choice', () => {
  const observation = values => ({ status: 'observed', next_logits: values });
  assert.equal(compareForwardResults(observation([1, 2]), observation([1, 2.00001])).status, 'passed');
  assert.equal(compareForwardResults(observation([1, 2]), observation([1, 3])).status, 'failed');
  assert.equal(compareForwardResults(observation([1, 1.000001]), observation([1.000001, 1])).status, 'failed');
  assert.equal(compareForwardResults(observation([1, 2]), observation([NaN, 2])).status, 'unverified');
  assert.equal(compareForwardResults(observation([1, 2]), { status: 'blocked' }).status, 'unverified');
});

test('Windows forward startup refusal leaves no successful evidence and never dispatches a request', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' });
  try { await temporary(() => assert.fail('An unsupported worker must not dispatch a request.')); }
  finally { Object.defineProperty(process, 'platform', descriptor); }
});
