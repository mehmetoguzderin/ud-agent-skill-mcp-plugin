/** Inert OS observations; no models, containers, or host pressure changes. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { MEMORY_RESERVE_BYTES, parseMacMemory, parseProcessMemory, sampleResourceMemory, assertResourceMemory } from '../../evals/local/resource-memory.mjs';

const pages = 'Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 100000.\nPages inactive: 100000.\nPages speculative: 10000.\nPages wired down: 150000.\nPages occupied by compressor: 40000.\n';
const processes = '10 1 10 100 evaluator\n20 1 20 200 model-server\n21 20 20 50 model-helper\n30 1 30 300 com.docker.backend\n';
const options = { platform: 'darwin', totalBytes: 16 * 1024 ** 3, observerPid: 10, processes: [{ role: 'model-server', pid: 20 }] };
function runner(overrides = {}) {
  return async (file, args) => ({ stdout: file.endsWith('vm_stat') ? pages : file.endsWith('sysctl') ? overrides.pressure ?? '1\n' : file.endsWith('/ps') ? processes
    : '{"ID":"abc123def456","Name":"owned-eval","MemUsage":"128MiB / 2GiB"}\n' });
}

test('measured host/page pressure guards preserve the two GiB reserve and unknown evidence', async () => {
  const sample = await sampleResourceMemory({ ...options, run: runner() });
  assert.equal(sample.guard, 'admitted'); assert.equal(assertResourceMemory(sample), sample);
  assert.equal(sample.host.available_bytes, 210000 * 16384); assert.equal(sample.reserve_bytes, MEMORY_RESERVE_BYTES);
  const critical = await sampleResourceMemory({ ...options, run: runner({ pressure: '4\n' }) });
  assert.equal(critical.guard, 'critical-pressure'); assert.throws(() => assertResourceMemory(critical), /critical-pressure/);
  const denied = await sampleResourceMemory({ ...options, run: async (file, args, opts) => {
    if (file.endsWith('sysctl')) throw Object.assign(new Error('permission denied'), { code: 'EPERM' });
    return runner()(file, args, opts);
  } });
  assert.equal(denied.guard, 'measurement-unavailable'); assert.equal(denied.host, null);
  assert.equal(denied.failures[0].code, 'EPERM'); assert.throws(() => assertResourceMemory(denied), /measurement-unavailable/);
  const small = await sampleResourceMemory({ ...options, run: async (file, args, opts) => file.endsWith('vm_stat')
    ? { stdout: pages.replace('Pages inactive: 100000.', 'Pages inactive: 0.') } : runner()(file, args, opts) });
  assert.equal(small.guard, 'reserve-exhausted'); assert.throws(() => assertResourceMemory(small), /reserve-exhausted/);
});

test('process groups and VM memory are measured once while container memory remains nested', async () => {
  const sample = await sampleResourceMemory({ ...options, processes: [...options.processes, { role: 'duplicate-reference', pid: 20 }],
    container: { executable: '/private/docker', ids: ['owned-eval'], env: {} }, run: runner() });
  assert.equal(sample.verified, true);
  assert.equal(sample.processes[1].rss_bytes, 250 * 1024);
  assert.equal(sample.observed_host_rss_bytes, 650 * 1024);
  assert.equal(sample.virtual_machines.length, 1); assert.equal(sample.containers[0].usage_bytes, 128 * 1024 ** 2);
  assert.equal(sample.containers[0].limit_bytes, 2 * 1024 ** 3);
  assert.match(sample.rss_basis, /not-added/);
  const missing = await sampleResourceMemory({ ...options, processes: [{ role: 'model-server', pid: 999 }], run: runner() });
  assert.equal(missing.verified, false); assert.equal(missing.failures[0].code, 'MEMORY_PROCESS_NOT_OBSERVED');
});

test('incomplete process, host and container inventories cannot become zero usage', async () => {
  assert.throws(() => parseProcessMemory('', 10), /OBSERVER_MISSING/);
  assert.throws(() => parseProcessMemory(processes + '10 1 10 100 duplicate\n', 10), /INVENTORY_INVALID/);
  assert.throws(() => parseMacMemory(pages, '', options.totalBytes), /MEASUREMENT_INVALID/);
  const sample = await sampleResourceMemory({ ...options, container: { executable: '/private/docker', ids: ['other-owned'] }, run: runner() });
  assert.equal(sample.guard, 'measurement-unavailable'); assert.match(sample.failures[0].message, /IDENTITY_UNVERIFIED/);
});
