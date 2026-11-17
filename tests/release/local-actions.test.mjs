import { test } from 'vitest';
import assert from 'node:assert/strict';
import path from 'node:path';
import { buildActArgs, checkActDockerStorage, isOwnedActMutationResource, LOCAL_ACTIONS_STORAGE_PLAN, measureActDockerUsage, resolveActJob } from '../../scripts/quality/run-act.mjs';
import { assertStorageAdmission, STORAGE_LIMITS } from '../../scripts/quality/storage-lifecycle.mjs';

test('local Actions admits SDK transfer and tool caches without widening shared storage limits', () => {
  const admitted = assertStorageAdmission({ ...LOCAL_ACTIONS_STORAGE_PLAN, ownedBytes: 8_000_000_000, freeBytes: 22_000_000_000 });
  assert.equal(admitted.plannedBytes, 12_000_000_000);
  assert.equal(admitted.limits.totalBytes, STORAGE_LIMITS.totalBytes);
  assert.equal(admitted.limits.freeReserveBytes, STORAGE_LIMITS.freeReserveBytes);
  assert.equal(STORAGE_LIMITS.ordinaryBytes, 2_000_000_000);
  assert.equal(STORAGE_LIMITS.releaseBytes, 4_000_000_000);
  assert.throws(() => assertStorageAdmission({ ...LOCAL_ACTIONS_STORAGE_PLAN, ownedBytes: 8_000_000_000, freeBytes: 21_999_999_999 }), /free reserve/);
  assert.throws(() => assertStorageAdmission({ ...LOCAL_ACTIONS_STORAGE_PLAN, ownedBytes: STORAGE_LIMITS.totalBytes - admitted.plannedBytes + 1, freeBytes: 22_000_000_000 }), /owned working total/);
  assert.throws(() => assertStorageAdmission({ ...LOCAL_ACTIONS_STORAGE_PLAN, plannedBytes: 12_000_000_001, ownedBytes: 0, freeBytes: 30_000_000_000 }), /scratch exceeds/);
});

test('native selection resolves the ARM workflow and SDK dependency only for ARM', () => {
  assert.deepEqual(resolveActJob({ job: 'native', architecture: 'amd64' }), { workflowJob: 'native', dependencyJobs: [] });
  assert.deepEqual(resolveActJob({ job: 'native', architecture: 'arm64' }), { workflowJob: 'native-arm', dependencyJobs: ['mutation-sdk'] });
  for (const job of ['node24', 'mutation']) for (const architecture of ['amd64', 'arm64']) {
    assert.deepEqual(resolveActJob({ job, architecture }), { workflowJob: job, dependencyJobs: [] });
  }
  assert.throws(() => resolveActJob({ job: 'native-arm', architecture: 'amd64' }), /Unsupported/);
});

test('local Actions uses the same job and pinned image with canonical isolated cache', () => {
  const args = buildActArgs({ overlay: '/owned/workflow.json', job: 'native', architecture: 'amd64', image: 'image@sha256:fixed', cacheRoot: '/owned/actions' });
  assert.deepEqual(args.slice(0, 5), ['workflow_dispatch', '--workflows', '/owned/workflow.json', '--job', 'native']);
  assert.ok(args.includes('linux/amd64'));
  assert.ok(args.includes('target:linux-x64'));
  assert.ok(args.includes('RUNNER_TOOL_CACHE=/opt/hostedtoolcache'));
  assert.equal(args[args.indexOf('--container-daemon-socket') + 1], '/var/run/docker.sock');
  assert.ok(!args.includes('--no-cache-server'));
  assert.ok(args.includes('--use-gitignore=false'), 'private source copy must include its explicitly staged SDK artifact bytes');
  assert.ok(args.includes('--pull=false'));
  assert.ok(args.includes('--secret-file'));
  assert.throws(() => buildActArgs({ job: 'native', architecture: 'x64' }), /Unsupported/);
});


test('local Actions enables real owned cache and artifact services with its verified socket', () => {
  const args = buildActArgs({ overlay: '/owned/workflow.json', job: 'native', architecture: 'arm64', image: 'image@sha256:fixed', cacheRoot: '/owned/actions', serviceRoot: '/owned/scratch/services', dockerSocket: 'unix:///owned/docker.sock' });
  assert.equal(args[args.indexOf('--job') + 1], 'native-arm');
  assert.ok(args.includes('linux_arm64=true'));
  assert.equal(args[args.indexOf('--container-daemon-socket') + 1], 'unix:///owned/docker.sock');
  assert.equal(args[args.indexOf('--cache-server-path') + 1], path.join('/owned/scratch/services', 'cache'));
  assert.equal(args[args.indexOf('--artifact-server-path') + 1], path.join('/owned/scratch/services', 'artifacts'));
  assert.equal(args[args.indexOf('--artifact-server-port') + 1], '34567', 'act advertises the supplied artifact port literally; port zero is not reachable');
  assert.ok(args.includes('target:linux-arm64'));
});

test('manual local Actions inputs select only the requested original job and its SDK dependency', () => {
  for (const [job, architecture, workflowJob, target] of [['native', 'amd64', 'native', 'linux-x64'], ['native', 'arm64', 'native-arm', 'linux-arm64'], ['node24', 'amd64', 'node24', undefined]]) {
    const args = buildActArgs({ overlay: '/owned/workflow.json', job, architecture, image: 'image@sha256:fixed', cacheRoot: '/owned/actions' });
    assert.equal(args[0], 'workflow_dispatch'); assert.equal(args[args.indexOf('--job') + 1], workflowJob);
    const selected = args.flatMap((value, index) => value === '--input' ? [args[index + 1]] : []);
    const inputs = Object.fromEntries(selected.map(value => { const split = value.indexOf('='); return [value.slice(0, split), value.slice(split + 1)]; }));
    assert.equal(selected.length, 5); assert.equal(Object.keys(inputs).length, 5);
    assert.deepEqual(JSON.parse(inputs.native_targets), workflowJob === 'native' ? ['linux-x64'] : []);
    assert.equal(inputs.linux_arm64, String(workflowJob === 'native-arm'));
    assert.equal(inputs.node24, String(workflowJob === 'node24'));
    assert.equal(inputs.sdk_run_id, workflowJob === 'native-arm' ? 'local-verified' : ''); assert.equal(inputs.sdk_run_attempt, '1');
    assert.deepEqual(args.flatMap((value, index) => value === '--matrix' ? [args[index + 1]] : []), target ? ['target:' + target] : []);
    assert.ok(args.includes('--pull=false')); assert.ok(args.includes('--action-offline-mode'));
    assert.ok(!args.some(value => value.startsWith('label:') || value.startsWith('arch:')));
  }
});


test('local Actions removes only precisely named mutation children with both ownership labels', () => {
  const owner = 'a'.repeat(32), mutation = '12345678-1234-1234-1234-123456789abc';
  const labels = { 'io.github.mehmetoguzderin.ud-agent.act-owner': owner, 'io.github.mehmetoguzderin.ud-agent.mutation': mutation };
  assert.equal(isOwnedActMutationResource({ Name: '/ud-mutation-job-' + mutation, Config: { Labels: labels } }, owner, 'container'), true);
  assert.equal(isOwnedActMutationResource({ Name: 'ud-mutation-state-' + mutation, Labels: labels }, owner, 'volume'), true);
  assert.equal(isOwnedActMutationResource({ Name: '/foreign', Config: { Labels: labels } }, owner, 'container'), false);
  assert.equal(isOwnedActMutationResource({ Name: 'ud-mutation-state-' + mutation, Labels: { ...labels, 'io.github.mehmetoguzderin.ud-agent.act-owner': 'b'.repeat(32) } }, owner, 'volume'), false);
  assert.equal(isOwnedActMutationResource({ Name: 'ud-mutation-state-' + mutation, Labels: { 'io.github.mehmetoguzderin.ud-agent.act-owner': owner } }, owner, 'volume'), false);
});

test('local Actions measures exact owned writable layers and read-only volume allocation', () => {
  const owner = 'a'.repeat(32), label = 'io.github.mehmetoguzderin.ud-agent.act-owner', volume = `ud-agent-act-${owner}-arm64`, id = 'c'.repeat(64), commands = [];
  const docker = args => {
    commands.push(args);
    if (args[0] === 'volume' && args[1] === 'ls') return volume + '\n';
    if (args[0] === 'volume' && args[1] === 'inspect') return JSON.stringify([{ Name: volume, Labels: { [label]: owner } }]);
    if (args[0] === 'ps') return id + '\n';
    if (args[0] === 'inspect') return JSON.stringify([{ Id: id, Name: '/owned-job', SizeRw: 128, Config: { Labels: { [label]: owner } }, Mounts: [{ Type: 'volume', Name: volume, Destination: '/opt/hostedtoolcache', RW: true }] }]);
    if (args[0] === 'run') return '4096\t/cache\nFilesystem 1B-blocks Used Available Capacity Mounted on\noverlay 20000000000 5000000000 15000000000 25% /cache\n';
    throw new Error('unexpected command');
  };
  assert.deepEqual(measureActDockerUsage(docker, owner, volume, 'runner'), { volume_bytes: 4096, writable_bytes: 128, size_bytes: 4224, engine_free_bytes: 15000000000 });
  const meter = commands.find(args => args[0] === 'run');
  assert.ok(meter.includes('type=volume,src=' + volume + ',dst=/cache,readonly'));
  assert.ok(!commands.some(args => args.includes('rm') && args[0] === 'volume'), 'measurement must not delete a volume');
});

test('local Actions accounts for act-managed workspace and environment volumes without claiming cleanup ownership', () => {
  const owner = 'a'.repeat(32), label = 'io.github.mehmetoguzderin.ud-agent.act-owner', cache = `ud-agent-act-${owner}-arm64`, id = 'c'.repeat(64);
  const workspace = 'act-native-workspace', environment = workspace + '-env', commands = [];
  const docker = args => {
    commands.push(args);
    if (args[0] === 'volume' && args[1] === 'ls') return cache;
    if (args[0] === 'volume' && args[1] === 'inspect') return JSON.stringify([{ Name: args[2], Labels: args[2] === cache ? { [label]: owner } : null }]);
    if (args[0] === 'ps') return id;
    if (args[0] === 'inspect') return JSON.stringify([{ Id: id, Name: '/act-native-job', SizeRw: 128, Config: { Labels: { [label]: owner } }, Mounts: [
      { Type: 'volume', Name: cache, Destination: '/opt/hostedtoolcache', RW: true },
      { Type: 'volume', Name: workspace, Destination: '/work', RW: true },
      { Type: 'volume', Name: environment, Destination: '/var/run/act', RW: true },
    ] }]);
    if (args[0] === 'run') return '4096\t/cache\nFilesystem 1B-blocks Used Available Capacity Mounted on\noverlay 20000000000 5000000000 15000000000 25% /cache\n';
    throw new Error('unexpected command');
  };
  assert.deepEqual(measureActDockerUsage(docker, owner, cache, 'runner'), { volume_bytes: 12288, writable_bytes: 128, size_bytes: 12416, engine_free_bytes: 15000000000 });
  for (const name of [cache, workspace, environment]) assert.ok(commands.some(args => args.includes(`type=volume,src=${name},dst=/cache,readonly`)));
  assert.ok(!commands.some(args => args[0] === 'volume' && ['rm', 'create'].includes(args[1])));
  assert.equal(isOwnedActMutationResource({ Name: workspace, Labels: null }, owner, 'volume'), false);
});

test('local Actions fails closed on foreign, unmeasurable or insufficient Docker storage', () => {
  const owner = 'a'.repeat(32), label = 'io.github.mehmetoguzderin.ud-agent.act-owner', volume = `ud-agent-act-${owner}-arm64`;
  assert.throws(() => measureActDockerUsage(args => args[0] === 'volume' && args[1] === 'ls' ? volume : JSON.stringify([{ Name: volume, Labels: { [label]: 'b'.repeat(32) } }]), owner, volume, 'runner'), /ownership/);
  const missingFree = args => {
    if (args[0] === 'volume' && args[1] === 'ls') return volume;
    if (args[0] === 'volume') return JSON.stringify([{ Name: volume, Labels: { [label]: owner } }]);
    if (args[0] === 'ps') return '';
    if (args[0] === 'run') return '4096 /cache\nnot a free-space observation\n';
    throw new Error('unexpected command');
  };
  assert.throws(() => measureActDockerUsage(missingFree, owner, volume, 'runner'), /free-space observation is unavailable/);
  const storage = { plannedBytes: 400, check: bytes => ({ usedBytes: 100, bytes }) };
  assert.equal(checkActDockerStorage(storage, { size_bytes: 100, engine_free_bytes: 10000000200 }, 0).bytes, 100);
  assert.throws(() => checkActDockerStorage(storage, { size_bytes: 100, engine_free_bytes: 10000000199 }, 0), /10 GB free reserve/);
});
