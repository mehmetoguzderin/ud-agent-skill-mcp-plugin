import { test, expect } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { copyOriginalDependencies, isWithinStorage, originalDockerBytes, localEvaluationImageDependencies } from '../../scripts/quality/original-storage.mjs';
import { originalStoragePlan } from '../../scripts/quality/original-acceptance.mjs';
import { assertStorageAdmission, inheritedStorageDirectory, reserveStorage, STORAGE_LIMITS } from '../../scripts/quality/storage-lifecycle.mjs';

function fixture(action) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-original-storage-')));
  try { return action(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

test('Windows original tests receive an explicit eight GB allowance without changing other storage limits', () => {
  const windows = originalStoragePlan('win32');
  expect(windows).toEqual({ plannedBytes: 8_000_000_000, profile: 'release', transientAllowance: 8_000_000_000 });
  for (const platform of ['darwin', 'linux']) expect(originalStoragePlan(platform)).toEqual({ plannedBytes: 2_000_000_000, profile: 'ordinary' });
  const observed = { ownedBytes: 1_000_000_000, freeBytes: 18_000_000_000 };
  expect(assertStorageAdmission({ ...windows, ...observed }).limits).toEqual({ ...STORAGE_LIMITS, releaseBytes: 8_000_000_000 });
  expect(() => assertStorageAdmission({ ...windows, ...observed, transientAllowance: undefined })).toThrow(/fixed budget/);
  expect(() => assertStorageAdmission({ ...windows, ...observed, ownedBytes: STORAGE_LIMITS.totalBytes - windows.plannedBytes + 1 })).toThrow(/owned working total/);
  expect(() => assertStorageAdmission({ ...windows, ...observed, freeBytes: 17_999_999_999 })).toThrow(/free reserve/);
  expect(STORAGE_LIMITS).toEqual({ totalBytes: 72_000_000_000, ordinaryBytes: 2_000_000_000, releaseBytes: 4_000_000_000, freeReserveBytes: 10_000_000_000 });
});

test('original dependencies are private byte-verified copies', () => fixture(root => {
  const modules = path.join(root, 'node_modules'), packageRoot = path.join(modules, 'tiny');
  mkdirSync(packageRoot, { recursive: true });
  writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({ name: 'tiny', version: '1.2.3' }));
  writeFileSync(path.join(packageRoot, 'index.js'), 'export default 4;\n');
  mkdirSync(path.join(modules, '.vitest-cache'));
  writeFileSync(path.join(modules, '.vitest-cache', 'transform.js'), 'generated, not a dependency');
  mkdirSync(path.join(packageRoot, '.vitest-cache'));
  writeFileSync(path.join(packageRoot, '.vitest-cache', 'required.js'), 'nested package file');
  writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ packages: { '': {}, 'node_modules/tiny': { version: '1.2.3' } } }));
  const privateModules = path.join(root, 'private-modules');
  const inventory = copyOriginalDependencies(root, privateModules);
  expect(inventory.files.length).toBe(3);
  expect(existsSync(path.join(privateModules, '.vitest-cache'))).toBe(false);
  expect(readFileSync(path.join(privateModules, 'tiny/.vitest-cache/required.js'), 'utf8')).toBe('nested package file');
  writeFileSync(path.join(privateModules, 'tiny/index.js'), 'changed');
  expect(readFileSync(path.join(packageRoot, 'index.js'), 'utf8')).toBe('export default 4;\n');
  expect(() => copyOriginalDependencies(root, privateModules)).toThrow();
  const foreign = path.join(root, 'foreign'); writeFileSync(foreign, 'not a dependency');
  symlinkSync(foreign, path.join(packageRoot, 'escape'));
  expect(() => copyOriginalDependencies(root, path.join(root, 'bad-copy'))).toThrow(/foreign root|escapes/);
  expect(existsSync(path.join(root, 'bad-copy'))).toBe(false);
}));

test('nested original jobs require a live verified owner and remain inside its scratch', () => fixture(root => {
  const lease = reserveStorage({ root, plannedBytes: 1024 });
  try {
    expect(inheritedStorageDirectory(lease.env)).toBe(lease.directory);
    expect(isWithinStorage(lease.directory, lease.directory)).toBe(true);
    expect(isWithinStorage(lease.directory, root)).toBe(false);
    expect(() => inheritedStorageDirectory({ UD_STORAGE_LEASE: 'invalid' })).toThrow(/invalid inherited reservation/);
  } finally { lease.cleanup(); }
  expect(() => inheritedStorageDirectory(lease.env)).toThrow();
}));

test('ordinary tests charge local project images without selecting or changing them', () => fixture(root => {
  mkdirSync(path.join(root, 'runtime'));
  const id = 'sha256:' + 'a'.repeat(64);
  writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ packs: { core: { images: { 'linux/arm64': { config_digest: id } } } } }));
  const calls = [], run = (_command, args) => {
    calls.push(args);
    if (args[0] === 'context') return { status: 0, stdout: 'unix:///tmp/docker.sock\n' };
    if (args[0] === 'image' && args[1] === 'ls') return { status: 0, stdout: JSON.stringify({ ID: id, Repository: '<none>', Tag: '<none>' }) };
    if (args[0] === 'image' && args[1] === 'inspect') return { status: 0, stdout: JSON.stringify([{ Id: id, Size: 321 }]) };
    return { status: 0, stdout: '' };
  };
  expect(originalDockerBytes(root, {}, run)).toBe(321);
  expect(calls.some(args => args.includes('rm') || args.includes('prune'))).toBe(false);
  expect(() => originalDockerBytes(root, { DOCKER_HOST: 'tcp://remote:2375' }, run)).toThrow(/local Unix socket/);
  const absent = () => ({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }), status: null, stdout: '', stderr: '' });
  mkdirSync(path.join(root, '.artifacts')); writeFileSync(path.join(root, '.artifacts', 'previous-job.json'), '{}');
  expect(() => originalDockerBytes(root, {}, absent)).toThrow(/cannot verify project-owned Docker data/);
}));

test('a fresh local native checkout needs no engine, but prior history is not assumed empty', () => fixture(root => {
  const absent = () => ({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }), status: null, stdout: '', stderr: '' });
  expect(originalDockerBytes(root, {}, absent)).toBe(0);
  mkdirSync(path.join(root, '.artifacts'));
  expect(originalDockerBytes(root, {}, absent)).toBe(0);
  writeFileSync(path.join(root, '.artifacts', 'old-resource.json'), '{}');
  expect(() => originalDockerBytes(root, {}, absent)).toThrow(/cannot verify project-owned Docker data/);
}));

test('client image ancestry requires a live owner binding and complete immutable parent chain', () => fixture(root => {
  const directory = path.join(root, '.artifacts/local-evals/client-images/fixture');
  mkdirSync(directory, { recursive: true });
  const id = 'sha256:' + 'a'.repeat(64), parent = 'sha256:' + 'b'.repeat(64), owner = 'a'.repeat(8) + '-aaaa-aaaa-aaaa-' + 'a'.repeat(12);
  writeFileSync(path.join(directory, 'receipt.json'), JSON.stringify({ image_id: id, created_by: owner }));
  const evidence = { image_id: id, relationship: 'immutable-dependencies-of-owned-client-image-not-deletion-authority', images: [{ image_id: id, size_bytes: 321, parent }, { image_id: parent, size_bytes: 123, parent: '' }] };
  const save = () => writeFileSync(path.join(directory, 'ancestry.json'), JSON.stringify(evidence));
  save();
  const images = new Map([[id, { Id: id, Size: 321, Parent: parent, Architecture: 'arm64', Os: 'linux', Config: { Labels: { 'io.github.mehmetoguzderin.ud-agent.local-eval': owner } } }], [parent, { Id: parent, Size: 123, Parent: '', Architecture: 'arm64', Os: 'linux' }]]);
  const docker = args => { expect(args.slice(0, 2)).toEqual(['image', 'inspect']); return JSON.stringify([images.get(args[2])]); };
  expect(localEvaluationImageDependencies(root, docker)).toEqual([{ image_id: id, size_bytes: 321 }, { image_id: parent, size_bytes: 123 }]);
  images.get(id).Config.Labels['io.github.mehmetoguzderin.ud-agent.local-eval'] = 'wrong-owner';
  expect(() => localEvaluationImageDependencies(root, docker)).toThrow(/changed/);
  images.get(id).Config.Labels['io.github.mehmetoguzderin.ud-agent.local-eval'] = owner;
  evidence.images.pop(); save();
  expect(() => localEvaluationImageDependencies(root, docker)).toThrow(/incomplete/);
  evidence.images[0].parent = ''; save();
  expect(() => localEvaluationImageDependencies(root, docker)).toThrow(/changed/);
}));

test('only exact missing ancestor responses omit resident bytes while preserving the live root and remaining chain', () => fixture(root => {
  mkdirSync(path.join(root, 'runtime'));
  writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ packs: {} }));
  const directory = path.join(root, '.artifacts/local-evals/client-images/fixture');
  mkdirSync(directory, { recursive: true });
  const id = 'sha256:' + 'a'.repeat(64), parent = 'sha256:' + 'b'.repeat(64), base = 'sha256:' + 'c'.repeat(64), foreign = 'sha256:' + 'd'.repeat(64), owner = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  writeFileSync(path.join(directory, 'receipt.json'), JSON.stringify({ image_id: id, created_by: owner }));
  writeFileSync(path.join(directory, 'ancestry.json'), JSON.stringify({ image_id: id, relationship: 'immutable-dependencies-of-owned-client-image-not-deletion-authority', images: [{ image_id: id, size_bytes: 321, parent }, { image_id: parent, size_bytes: 123, parent: base }, { image_id: base, size_bytes: 50, parent: '' }] }));
  const images = new Map([[id, { Id: id, Size: 321, Parent: parent, Architecture: 'arm64', Os: 'linux', Config: { Labels: { 'io.github.mehmetoguzderin.ud-agent.local-eval': owner } } }], [base, { Id: base, Size: 50, Parent: '', Architecture: 'arm64', Os: 'linux' }]]);
  let missing = parent, failure, dangling = false, phantom = false;
  const run = (_command, args) => {
    if (args[0] === 'context') return { status: 0, stdout: 'unix:///tmp/docker.sock\n' };
    if (args[0] === 'image' && args[1] === 'inspect') {
      if (args[2] === missing) return failure ?? { status: 1, stdout: '[]\n', stderr: `Error response from daemon: No such image: ${missing}\n` };
      return { status: 0, stdout: JSON.stringify([images.get(args[2])]) };
    }
    if (args[0] === 'image' && args[1] === 'ls') return { status: 0, stdout: [id, base, ...(phantom ? [parent] : []), ...(dangling ? [foreign] : [])].map(ID => JSON.stringify({ ID, Repository: '<none>', Tag: '<none>' })).join('\n') };
    return { status: 0, stdout: '' };
  };
  expect(originalDockerBytes(root, {}, run)).toBe(371);
  phantom = true;
  expect(originalDockerBytes(root, {}, run)).toBe(371);
  for (const result of [
    { status: 1, stderr: 'permission denied' },
    { status: 1, stderr: 'Cannot connect to the Docker daemon' },
    { status: 1, stderr: `Error response from daemon: No such image: ${foreign}` },
    { status: 1, stderr: `Error response from daemon: No such image: ${parent}`, error: new Error('transport failed') },
  ]) { failure = result; expect(() => originalDockerBytes(root, {}, run)).toThrow(); }
  failure = undefined;
  missing = id; expect(() => originalDockerBytes(root, {}, run)).toThrow(/image is absent/);
  missing = parent;
  images.get(base).Size = 51; expect(() => originalDockerBytes(root, {}, run)).toThrow(/ancestry changed/);
  images.get(base).Size = 50;
  dangling = true; expect(() => originalDockerBytes(root, {}, run)).toThrow(/unidentified dangling image/);
}));

test('a fresh GitHub-hosted native job does not require an absent CLI or stopped engine', () => fixture(root => {
  const absent = () => ({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }), status: null, stdout: '', stderr: '' });
  const environment = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_JOB: 'native', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', GITHUB_WORKSPACE: root };
  expect(originalDockerBytes(root, environment, absent)).toBe(0);
  expect(originalDockerBytes(root, { ...environment, GITHUB_JOB: 'node24' }, absent)).toBe(0);
  const stopped = (_command, args) => args[0] === 'context' ? { status: 0, stdout: 'unix:///tmp/docker.sock\n' } : { status: 1, stdout: '', stderr: 'Cannot connect to the Docker daemon at unix:///tmp/docker.sock. Is the docker daemon running?' };
  mkdirSync(path.join(root, 'runtime')); writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ packs: {} }));
  expect(originalDockerBytes(root, environment, stopped)).toBe(0);
  expect(originalDockerBytes(root, {}, stopped)).toBe(0);
  const permissionError = (_command, args) => args[0] === 'context' ? { status: 0, stdout: 'unix:///tmp/docker.sock\n' } : { status: 1, stdout: '', stderr: 'permission denied' };
  expect(() => originalDockerBytes(root, environment, permissionError)).toThrow(/permission denied/);
  for (const change of [{ RUNNER_ENVIRONMENT: 'self-hosted' }, { GITHUB_JOB: 'other' }, { GITHUB_RUN_ID: '' }, { GITHUB_WORKSPACE: os.tmpdir() }, { DOCKER_CONTEXT: 'previous' }]) {
    expect(() => originalDockerBytes(root, { ...environment, ...change }, absent)).toThrow(/cannot verify project-owned Docker data/);
  }
  mkdirSync(path.join(root, '.artifacts'));
  expect(originalDockerBytes(root, environment, absent)).toBe(0);
  writeFileSync(path.join(root, '.artifacts', 'old-resource.json'), '{}');
  expect(() => originalDockerBytes(root, environment, absent)).toThrow(/cannot verify project-owned Docker data/);
}));

const missingWindowsDaemon = 'failed to connect to the docker API at npipe:////./pipe/docker_engine; check if the path is correct and if the daemon is running: open //./pipe/docker_engine: The system cannot find the file specified.';

test('the observed Windows missing-pipe error admits only a fresh native checkout without claiming engine inspection', () => fixture(root => {
  mkdirSync(path.join(root, 'runtime')); writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ packs: {} }));
  const environment = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_JOB: 'native', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', GITHUB_WORKSPACE: root };
  const calls = [], run = (_command, args) => {
    calls.push(args);
    if (args[0] === 'context') return { status: 0, stdout: 'npipe:////./pipe/docker_engine\r\n' };
    return { status: 1, stdout: '', stderr: missingWindowsDaemon + '\r\n' };
  };
  expect(originalDockerBytes(root, environment, run)).toBe(0);
  expect(calls).toEqual([['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], ['image', 'ls', '--all', '--no-trunc', '--format', '{{json .}}']]);
  for (const change of [{ GITHUB_WORKSPACE: os.tmpdir() }, { RUNNER_ENVIRONMENT: 'self-hosted' }, { GITHUB_JOB: 'mutation-sdk' }, { DOCKER_CONTEXT: 'previous' }, { DOCKER_HOST: 'npipe:////./pipe/docker_engine' }]) {
    expect(() => originalDockerBytes(root, { ...environment, ...change }, run)).toThrow(/cannot verify project-owned Docker data/);
  }
  expect(() => originalDockerBytes(root, { ...environment, DOCKER_HOST: 'tcp://foreign.example:2375' }, run)).toThrow(/remote Docker endpoints are not authorized/);
  mkdirSync(path.join(root, '.artifacts')); writeFileSync(path.join(root, '.artifacts/previous-job.json'), 'retained engine ownership evidence');
  expect(() => originalDockerBytes(root, environment, run)).toThrow(/cannot verify project-owned Docker data/);
  expect(readFileSync(path.join(root, '.artifacts/previous-job.json'), 'utf8')).toBe('retained engine ownership evidence');
  expect(calls.every(args => ['context', 'image'].includes(args[0]))).toBe(true);
}));

test('fresh Windows checkout still refuses unknown, foreign-pipe, denied and failed-process Docker observations', () => fixture(root => {
  mkdirSync(path.join(root, 'runtime')); writeFileSync(path.join(root, 'runtime/runtime.lock.json'), JSON.stringify({ packs: {} }));
  const environment = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_JOB: 'native', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1', GITHUB_WORKSPACE: root };
  for (const failure of [
    { status: 1, stderr: missingWindowsDaemon.replace('The system cannot find the file specified.', 'Access is denied.') },
    { status: 1, stderr: missingWindowsDaemon.replaceAll('docker_engine', 'foreign_engine') },
    { status: 1, stderr: 'The system cannot find the file specified.' },
    { status: 1, stderr: 'unknown engine inspection failure' },
    { status: 2, stderr: missingWindowsDaemon },
    { status: null, stderr: missingWindowsDaemon, error: Object.assign(new Error('inspection timed out'), { code: 'ETIMEDOUT' }) },
  ]) {
    const calls = [], run = (_command, args) => {
      calls.push(args);
      return args[0] === 'context' ? { status: 0, stdout: 'npipe:////./pipe/docker_engine\n' } : { stdout: '', ...failure };
    };
    expect(() => originalDockerBytes(root, environment, run)).toThrow(/cannot inspect the local Docker engine/);
    expect(calls).toHaveLength(2); expect(calls[1].slice(0, 2)).toEqual(['image', 'ls']);
  }
  expect(() => originalDockerBytes(root, environment, () => ({ status: 1, stdout: '', stderr: missingWindowsDaemon }))).toThrow(/cannot inspect the local Docker engine/);
}));
