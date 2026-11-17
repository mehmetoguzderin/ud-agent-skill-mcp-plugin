import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { resetMlxConversationCache } from '../../evals/local/serving.mjs';

test('inert wire fault after event-loop blocking recovers once with complete cache observations', async () => {
  // The idle close alone need not fail on every Node/Undici version. The torn
  // first metrics response is an explicit controlled transport fault, not a
  // claim that the historical LFM/Bonsai network cause has been recovered.
  const child = spawn(process.execPath, ['--input-type=module', '-e', String.raw`
import http from 'node:http';
let torn = false;
const server = http.createServer((request, response) => {
  const route = request.url;
  const value = route === '/v1/metrics' ? { summary: { in_flight: 0, requests_started: 0, requests_completed: 0, requests_failed: 0 }, server: { loaded_model: '/inert/model', request_queue_depth: 0, audio_queue_depth: 0, apc: { enabled: true } } }
    : route === '/v1/cache/reset' ? { enabled: true, status: 'cleared' }
    : route === '/v1/cache/stats' ? { enabled: true, resident_bytes: 0, exact_resident_bytes: 0, pool_used: 0, memory_max_bytes: 1073741824, block_size: 16, num_blocks: 2048, disk_writes: 0 } : { warm: true };
  const bytes = Buffer.from(JSON.stringify(value));
  response.setHeader('content-type', 'application/json');
  if (route === '/v1/metrics' && !torn) { torn = true; response.setHeader('content-length', bytes.length + 7); response.end(bytes); return; }
  response.end(bytes);
});
server.keepAliveTimeout = 100;
server.listen(0, '127.0.0.1', () => process.stdout.write(String(server.address().port) + '\n'));
process.on('SIGTERM', () => { server.closeAllConnections(); server.close(() => process.exit(0)); });
`], { stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = once(child, 'close'); let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  const lines = createInterface({ input: child.stdout });
  try {
    const port = await Promise.race([once(lines, 'line').then(([line]) => Number(line)), exited.then(() => { throw new Error('Inert fixture exited before ready: ' + stderr); })]);
    assert.ok(Number.isSafeInteger(port) && port > 0);
    const upstream = `http://127.0.0.1:${port}`;
    await (await fetch(upstream + '/warm')).json(); await delay(10);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
    const observations = [], proof = await resetMlxConversationCache({ upstream, model: '/inert/model', idle: true, deadline: Date.now() + 3000, onObservation: event => observations.push(event) });
    assert.equal(proof.verified, true); assert.equal(proof.inference, false); assert.equal(proof.transport.attempts, 2);
    assert.equal(observations[0].route, '/v1/metrics');
    assert.ok(['UND_ERR_SOCKET', 'UND_ERR_RES_CONTENT_LENGTH_MISMATCH'].includes(observations[0].error.cause.code));
    assert.equal(observations[1].type, 'cache_management_recovery');
    assert.equal(proof.after.summary.requests_started, 0);
  } finally {
    lines.close(); child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 4000);
    let outcome;
    try { outcome = await exited; } finally { clearTimeout(timer); }
    assert.ok(Number.isInteger(outcome[0]) || ['SIGTERM', 'SIGKILL'].includes(outcome[1]), 'Owned fixture parent termination must be observed');
    assert.equal(child.exitCode, outcome[0]); assert.equal(child.signalCode, outcome[1]);
  }
});
