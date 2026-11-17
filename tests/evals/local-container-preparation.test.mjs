import { test } from 'vitest';
import { posixTest } from '../fixtures/native-scope.mjs';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, symlinkSync, realpathSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { CLIENT_LOCK } from '../../evals/local/native-clients.mjs';
import { containerBaseReferences, CONTAINER_BASES, prepareNativeContainers } from '../../evals/local/container-preparation.mjs';
import { prepareLinuxClientLock, verifyContainerBaseManifest, privateDockerBuildEnvironment, nativePackageLifecycleDockerfile, OPENCLAW_LIFECYCLE_RECIPE } from '../../evals/local/container.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';

async function fixture(run) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-container-prepare-'));
  const keys = ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILD_BUILDID', 'JENKINS_URL'];
  const saved = new Map(keys.map(key => [key, process.env[key]]));
  for (const key of keys) delete process.env[key];
  try { await run(root); }
  finally { for (const [key, value] of saved) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } rmSync(root, { recursive: true, force: true }); }
}

test('container acquisition rejects absent opt-in and CI before dependencies or Docker run', () => fixture(async root => {
  const options = { prepareClients: async () => { throw new Error('unexpected acquisition'); } };
  await assert.rejects(prepareNativeContainers(root, options), /opt-in/);
  process.env.CI = 'true';
  await assert.rejects(prepareNativeContainers(root, { ...options, optIn: true }), /disabled in CI/);
  assert.equal(existsSync(path.join(root, '.artifacts')), false);
}));

test('container base recipes require ARM64 and immutable official Node/Python identities', () => {
  const refs = containerBaseReferences();
  assert.match(refs.node, /^node:26\.13\.0-bookworm-slim@sha256:/);
  assert.match(refs.python, /^python:3\.12-slim-bookworm@sha256:/);
  for (const mutate of [lock => { lock.platform = 'linux/amd64'; }, lock => { lock.images.node.reference = 'node:latest'; }, lock => { lock.images.python.config_digest = 'unknown'; }]) {
    const lock = structuredClone(CONTAINER_BASES); mutate(lock);
    assert.throws(() => containerBaseReferences(lock), /BASE_LOCK_INVALID/);
  }
});

test('only pinned OpenClaw completes its native package lifecycle in a bounded networkless build layer', () => {
  const step = nativePackageLifecycleDockerfile('openclaw');
  assert.match(OPENCLAW_LIFECYCLE_RECIPE, /^openclaw-2026\.11\.3-native-lifecycle-v1$/);
  assert.match(step, /^RUN --network=none timeout --signal=KILL 150s node /);
  assert.match(step, /manifest\.version!=="2026\.11\.3"/);
  assert.match(step, /configureFsSafeNative\(\{mode:"require"\}\);await readCloneFileMetadata\(\[\]\)/);
  assert.match(step, /completePendingPackageLifecycle\(\{packageRoot:root,timeoutMs:60000\}\)/);
  assert.match(step, /\.openclaw-lifecycle-pending/); assert.match(step, /\.openclaw-lifecycle-lock/); assert.match(step, /OPENCLAW_LIFECYCLE_INCOMPLETE/);
  assert.doesNotMatch(step, /npm install|--ignore-scripts=false|rm -/);
  for (const pin of CLIENT_LOCK.clients.filter(client => client.id !== 'openclaw')) assert.equal(nativePackageLifecycleDockerfile(pin.id), '');
});

posixTest('private Docker builds discover installed Buildx without importing account config or credentials', () => fixture(async root => {
  const install = path.join(root, 'Docker.app/Contents/Resources'), bin = path.join(install, 'bin'), plugins = path.join(install, 'cli-plugins');
  mkdirSync(bin, { recursive: true }); mkdirSync(plugins);
  const docker = path.join(bin, 'docker'); writeFileSync(docker, 'fixture only', { mode: 0o700 });
  writeFileSync(path.join(plugins, 'docker-buildx'), 'fixture only', { mode: 0o700 });
  const account = path.join(root, 'account'); mkdirSync(account);
  const secret = JSON.stringify({ auths: { private: { auth: 'fixture-secret' } }, credsStore: 'desktop' });
  writeFileSync(path.join(account, 'config.json'), secret);
  const previous = process.env.DOCKER_CONFIG; process.env.DOCKER_CONFIG = account;
  try {
    const engineEnvironment = { DOCKER_HOST: 'unix:///fixture/docker.sock' };
    const env = privateDockerBuildEnvironment(root, docker, { engineEnvironment });
    assert.equal(env.HOME, path.join(root, '.artifacts/local-evals/build-home'));
    assert.equal(env.DOCKER_CONFIG, path.join(env.HOME, '.docker')); assert.equal(env.DOCKER_HOST, engineEnvironment.DOCKER_HOST);
    const file = path.join(env.DOCKER_CONFIG, 'config.json'), bytes = readFileSync(file, 'utf8');
    assert.deepEqual(JSON.parse(bytes), { cliPluginsExtraDirs: [realpathSync(plugins)] });
    assert.equal(readFileSync(path.join(account, 'config.json'), 'utf8'), secret);
    assert.deepEqual(privateDockerBuildEnvironment(root, docker, { engineEnvironment }), env);
    assert.equal(readFileSync(file, 'utf8'), bytes);
    writeFileSync(file, secret);
    assert.throws(() => privateDockerBuildEnvironment(root, docker, { engineEnvironment }), /DOCKER_CONFIG_CHANGED/);
    assert.equal(readFileSync(file, 'utf8'), secret);
  } finally { if (previous === undefined) delete process.env.DOCKER_CONFIG; else process.env.DOCKER_CONFIG = previous; }
}));

posixTest('private Docker config rejects missing Buildx and symlinked private config paths', () => fixture(async root => {
  const plugins = path.join(root, 'plugins'); mkdirSync(plugins);
  const docker = path.join(root, 'docker'); writeFileSync(docker, 'fixture only');
  const options = { engineEnvironment: {}, pluginDirectories: [plugins] };
  assert.throws(() => privateDockerBuildEnvironment(root, docker, options), /BUILDX_INSTALLATION_UNAVAILABLE/);
  writeFileSync(path.join(plugins, 'docker-buildx'), 'fixture only', { mode: 0o700 });
  const outside = path.join(root, 'account'); mkdirSync(outside);
  mkdirSync(path.join(root, '.artifacts/local-evals'), { recursive: true });
  symlinkSync(outside, path.join(root, '.artifacts/local-evals/build-home'));
  assert.throws(() => privateDockerBuildEnvironment(root, docker, options), /DOCKER_CONFIG_PATH_INVALID/);
  assert.equal(existsSync(path.join(outside, '.docker')), false);
}));

test('non-executable Buildx cannot create a private build environment or import account credentials', () => fixture(async root => {
  const plugins = path.join(root, 'plugins'), account = path.join(root, 'account'), docker = path.join(root, 'docker');
  mkdirSync(plugins); mkdirSync(account); writeFileSync(docker, 'inert Docker fixture');
  writeFileSync(path.join(plugins, 'docker-buildx'), 'inert non-executable Buildx', { mode: 0o600 });
  const credentials = JSON.stringify({ auths: { private: { auth: 'fixture-secret' } }, credsStore: 'desktop' });
  writeFileSync(path.join(account, 'config.json'), credentials);
  const previous = process.env.DOCKER_CONFIG; process.env.DOCKER_CONFIG = account;
  try {
    assert.throws(() => privateDockerBuildEnvironment(root, docker, { engineEnvironment: {}, pluginDirectories: [plugins] }), /CLIENT_BUILDX_INSTALLATION_UNAVAILABLE/);
    assert.equal(existsSync(path.join(root, '.artifacts')), false);
    assert.equal(readFileSync(path.join(account, 'config.json'), 'utf8'), credentials);
    assert.equal(readFileSync(path.join(plugins, 'docker-buildx'), 'utf8'), 'inert non-executable Buildx');
  } finally { if (previous === undefined) delete process.env.DOCKER_CONFIG; else process.env.DOCKER_CONFIG = previous; }
}));

test('all eleven native clients build sequentially with pinned bases and immutable preparation evidence', () => fixture(async root => {
  let active = 0, maximum = 0; const calls = [];
  const prepareClients = async (_root, options) => {
    assert.equal(options.optIn, true);
    return CLIENT_LOCK.clients.map(pin => ({ id: pin.id, version: pin.version, executable: '/inert/' + pin.command }));
  };
  const buildImage = async (_root, id, options) => {
    active++; maximum = Math.max(active, maximum); calls.push({ id, options });
    await new Promise(resolve => setTimeout(resolve, 1)); active--;
    return { id, image_id: 'sha256:' + sha256(id), platform: 'linux/arm64', inference: false };
  };
  const receipt = await prepareNativeContainers(root, { optIn: true, prepareClients, buildImage });
  assert.equal(maximum, 1); assert.equal(calls.length, 11); assert.equal(receipt.images.length, 11);
  assert.deepEqual(calls.map(call => call.id), CLIENT_LOCK.clients.map(pin => pin.id));
  for (const { id, options } of calls) {
    const python = CLIENT_LOCK.clients.find(pin => pin.id === id).manager === 'uv';
    assert.equal(options.baseImage, CONTAINER_BASES.images[python ? 'python' : 'node'].reference);
    assert.equal(options.baseConfigDigest, CONTAINER_BASES.images[python ? 'python' : 'node'].config_digest);
    assert.equal(options.nodeImage, python ? CONTAINER_BASES.images.node.reference : undefined);
  }
  assert.equal(receipt.status, 'prepared'); assert.equal(receipt.inference, false);
  assert.match(receipt.qualification, /native-conformance-required/);
  const bytes = readFileSync(receipt.receipt);
  const again = await prepareNativeContainers(root, { optIn: true, prepareClients, buildImage });
  assert.notEqual(again.receipt, receipt.receipt); assert.ok(readFileSync(receipt.receipt).equals(bytes));
}));

test('client and image failures remain blocked without dropping rows or stopping unaffected builds', () => fixture(async root => {
  const built = [];
  const result = await prepareNativeContainers(root, { optIn: true,
    prepareClients: async () => CLIENT_LOCK.clients.map((pin, index) => ({ id: pin.id, ...(index === 0 ? { status: 'blocked', reason: 'locked package unavailable' } : {}) })),
    buildImage: async (_root, id) => { built.push(id); if (id === CLIENT_LOCK.clients[1].id) throw new Error('ARM64 image build failed'); return { id }; } });
  assert.equal(result.status, 'blocked'); assert.equal(result.images.length, 11); assert.equal(built.length, 10);
  assert.equal(result.images[0].stage, 'private-client'); assert.equal(result.images[1].stage, 'arm64-image');
  assert.ok(result.images.slice(2).every(image => image.status === 'prepared'));
  await assert.rejects(prepareNativeContainers(root, { optIn: true, prepareClients: async () => [] }), /INVENTORY_INCOMPLETE/);
}));

test('unverified image-build process cleanup preserves the failure and prevents every remaining build', () => fixture(async root => {
  const built = [];
  const result = await prepareNativeContainers(root, { optIn: true,
    prepareClients: async () => CLIENT_LOCK.clients.map(pin => ({ id: pin.id })),
    buildImage: async (_root, id) => {
      built.push(id);
      if (built.length === 2) throw Object.assign(new Error('Owned build process absence unverified'), {
        result: { cleanupVerified: false, cleanup_error: 'Process query failed', cleanup_evidence: [{ method: 'signal-zero', pgid: 123, outcome: 'failed', code: 'EPERM' }] }
      });
      return { id };
    } });
  assert.equal(built.length, 2); assert.equal(result.images.length, 11); assert.equal(result.status, 'blocked');
  assert.equal(result.halted_for_unverified_cleanup, true); assert.equal(result.cleanup_blocker, CLIENT_LOCK.clients[1].id);
  assert.equal(result.images[0].status, 'prepared'); assert.equal(result.images[1].owned_cleanup_verified, false);
  assert.equal(result.images[1].failure.owned_process.cleanup_evidence[0].code, 'EPERM');
  assert.ok(result.images.slice(2).every(image => image.status === 'blocked' && image.stage === 'not-attempted' && image.blocked_by === CLIENT_LOCK.clients[1].id));
  const persisted = JSON.parse(readFileSync(result.receipt));
  assert.deepEqual(persisted.images, result.images); assert.equal(persisted.halted_for_unverified_cleanup, true);
}));

test('Python image locks resolve Linux ARM64 wheel dependencies independently of the host lock', () => fixture(async root => {
  const directory = path.join(root, 'image'), prepared = { directory: path.join(root, 'client') }; mkdirSync(directory);
  mkdirSync(prepared.directory); writeFileSync(path.join(prepared.directory, 'requirements.lock'), 'host-only-dependency==1\n');
  const pin = CLIENT_LOCK.clients.find(client => client.id === 'mini-swe-agent'); let command;
  const proof = await prepareLinuxClientLock(root, pin.id, directory, prepared, { runner: async (binary, args) => {
    command = { binary, args };
    writeFileSync(args[args.indexOf('--output-file') + 1], `${pin.package} @ ${pin.url} --hash=sha256:${pin.sha256}\nlinux-only-dependency==2 --hash=sha256:${'a'.repeat(64)}\n`);
    return { stdout: '' };
  } });
  assert.equal(command.binary, 'uv');
  assert.equal(command.args[command.args.indexOf('--python-platform') + 1], 'aarch64-manylinux_2_36');
  assert.equal(command.args[command.args.indexOf('--python-version') + 1], '3.12');
  assert.equal(command.args[command.args.indexOf('--only-binary') + 1], ':all:');
  assert.match(readFileSync(path.join(directory, 'requirements.lock'), 'utf8'), /linux-only-dependency/);
  assert.doesNotMatch(readFileSync(path.join(directory, 'requirements.lock'), 'utf8'), /host-only-dependency/);
  assert.equal(proof.platform, 'linux/arm64');
  assert.equal(proof.sha256, sha256(readFileSync(path.join(directory, 'requirements.lock'))));
}));

test('Python image Node bridge carries its ARM64 libatomic ABI from the same pinned stage without changing package locks', () => {
  const source = readFileSync(new URL('../../evals/local/container.mjs', import.meta.url), 'utf8');
  const literal = source.match(/: (`FROM \$\{nodeImage\} AS node.*?`);/s)?.[1];
  assert.ok(literal, 'The Python Docker recipe must retain its pinned Node stage.');
  // Evaluate only the original recipe literal with the fixed official bases;
  // no Docker command, package installation, model or generated variant runs.
  const dockerfile = Function('nodeImage', 'baseImage', `return ${literal}`)(CONTAINER_BASES.images.node.reference, CONTAINER_BASES.images.python.reference);
  const lines = dockerfile.trim().split('\n'), libraries = lines.filter(line => line.startsWith('COPY --from=node /usr/lib/')).join(' ');
  assert.equal(lines[0], `FROM ${CONTAINER_BASES.images.node.reference} AS node`);
  assert.equal(lines[1], `FROM ${CONTAINER_BASES.images.python.reference}`);
  assert.match(libraries, /\/usr\/lib\/aarch64-linux-gnu\/libstdc\+\+\.so\.6\*/);
  assert.match(libraries, /\/usr\/lib\/aarch64-linux-gnu\/libatomic\.so\.1\*/);
  assert.ok(lines.includes('COPY requirements.lock ./'));
  assert.match(dockerfile, /RUN node --version && python -m venv/);
  assert.match(dockerfile, /--only-binary=:all: --require-hashes -r requirements\.lock/);
  assert.doesNotMatch(dockerfile, /apt(?:-get)? (?:install|update)|pip install[^\n]*--upgrade/);
});

test('base verification hashes raw OCI manifest bytes and binds configuration without daemon image mutation', async () => {
  const config = CONTAINER_BASES.images.node.config_digest, calls = [];
  const raw = JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config: { digest: config },
    layers: [{ digest: 'sha256:' + 'a'.repeat(64), size: 123 }] }, null, 2);
  const reference = `node:26.13.0-bookworm-slim@sha256:${sha256(raw)}`;
  const runner = async (command, args, options) => {
    calls.push({ command, args }); assert.equal(options.maximumBytes, 1024 ** 2);
    // Docker's legacy command rejects some valid OCI manifests when conversion
    // changes their digest; only the exact-byte Buildx route is acceptable.
    if (args[0] === 'manifest') throw new Error('manifest verification failed for digest');
    return { stdout: raw };
  };
  const proof = await verifyContainerBaseManifest('/inert/docker', reference, config, { runner });
  assert.equal(proof.config_digest, config); assert.equal(proof.manifest_digest, `sha256:${sha256(raw)}`);
  assert.deepEqual(calls, [{ command: '/inert/docker', args: ['buildx', 'imagetools', 'inspect', '--raw', reference] }]);
  await assert.rejects(verifyContainerBaseManifest('/inert/docker', reference, 'sha256:' + 'b'.repeat(64), { runner }), /BASE_CONFIG_CHANGED/);
  await assert.rejects(verifyContainerBaseManifest('/inert/docker', 'node:latest', config, { runner }), /BASE_CONFIG_INVALID/);
  for (const changed of [raw + '\n', JSON.stringify(JSON.parse(raw)), raw.replace('123', '124')]) {
    await assert.rejects(verifyContainerBaseManifest('/inert/docker', reference, config, { runner: async () => ({ stdout: changed }) }), /BASE_MANIFEST_DIGEST_CHANGED/);
  }
});

test('a digest-valid index or malformed layer cannot substitute for a pinned base image manifest', async () => {
  const config = 'sha256:' + 'a'.repeat(64);
  const manifest = { schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config: { digest: config }, layers: [{ digest: config, size: 12 }] };
  for (const value of [{ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [{ digest: config }] },
    { ...manifest, schemaVersion: 1 }, { ...manifest, layers: [] }, { ...manifest, layers: [{ digest: 'unpinned', size: 12 }] }]) {
    const raw = JSON.stringify(value), reference = `python:3.12-slim-bookworm@sha256:${sha256(raw)}`;
    await assert.rejects(verifyContainerBaseManifest('/inert/docker', reference, config, { runner: async () => ({ stdout: raw }) }), /BASE_CONFIG_CHANGED/);
  }
});

test('a Python container lock cannot replace the pinned client wheel identity', () => fixture(async root => {
  const directory = path.join(root, 'image'); mkdirSync(directory);
  await assert.rejects(prepareLinuxClientLock(root, 'mini-swe-agent', directory, { directory: path.join(root, 'client') }, {
    runner: async (_binary, args) => { writeFileSync(args[args.indexOf('--output-file') + 1], 'unrelated==1\n'); return { stdout: '' }; }
  }), /LINUX_LOCK_IDENTITY_CHANGED/);
}));
