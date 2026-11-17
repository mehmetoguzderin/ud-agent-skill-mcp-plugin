// SPDX-License-Identifier: MIT
/** Inert Docker/process responses only; no daemon or child process is started. */
import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const fixtureDiscovery = vi.hoisted(() => ({ docker: undefined }));
// This suite injects every Docker/process response; model only its inert
// executable discovery on Windows, where the POSIX X-bit lookup is unavailable.
vi.mock('../../evals/local/preparation.mjs', async original => {
  const actual = await original();
  return { ...actual, executable: (name, ...args) => process.platform === 'win32' && name === 'docker' && fixtureDiscovery.docker ? fixtureDiscovery.docker : actual.executable(name, ...args) };
});
import { startContainer } from '../../evals/local/container.mjs';

async function fixture(mode, verify) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-container-release-')));
  const taskRoot = path.join(root, 'task'), profile = path.join(root, 'profile'), bin = path.join(root, 'bin');
  for (const directory of [taskRoot, profile, bin]) mkdirSync(directory);
  writeFileSync(path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')), '# inert executable placeholder', { mode: 0o700 });
  fixtureDiscovery.docker = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : ''));
  const prior = new Map(['PATH', 'DOCKER_HOST', 'DOCKER_CONTEXT'].map(key => [key, process.env[key]]));
  process.env.PATH = bin; process.env.DOCKER_HOST = 'unix:///inert/docker.sock'; delete process.env.DOCKER_CONTEXT;
  let clock = Date.now(); const fakeClock = mode === 'deadline-exceeded' ? vi.spyOn(Date, 'now').mockImplementation(() => clock) : undefined;
  const label = 'io.github.mehmetoguzderin.ud-agent.local-eval', image = 'sha256:' + 'a'.repeat(64), networkId = 'b'.repeat(64), id = 'c'.repeat(64);
  const calls = []; let owner, name, killed = false, removed = false, listCount = 0, resolveExit;
  const processResult = { code: 0, stdout: '', stderr: '', cleanupVerified: true, cleanup_evidence: [{ method: 'signal-zero', pgid: 123, outcome: 'failed', code: 'ESRCH' }] };
  const done = new Promise(resolve => { resolveExit = resolve; });
  const runner = async (_command, args, options) => {
    calls.push({ args, options });
    if (args[0] === 'image' && args[1] === 'inspect') return { stdout: JSON.stringify([{ Id: image, Architecture: 'arm64', Os: 'linux' }]) };
    if (args[0] === 'network' && args[1] === 'create') {
      name = args.at(-1); owner = args[args.indexOf('--label') + 1].slice(label.length + 1); return { stdout: networkId };
    }
    if (args[0] === 'network' && args[1] === 'inspect') return { stdout: JSON.stringify([{ Id: networkId, Name: name, Driver: 'bridge', Labels: { [label]: owner },
      Options: { 'com.docker.network.bridge.enable_icc': 'false' }, IPAM: { Config: [{ Subnet: '172.30.0.0/24' }] }, Containers: {} }]) };
    if (args[0] === 'network' && args[1] === 'rm') return { stdout: networkId };
    if (args[0] === 'ps') {
      listCount++;
      if (killed && mode === 'query-failed') throw new Error('inert container enumeration failure');
      return { stdout: removed || killed && mode === 'absent' ? '' : JSON.stringify({ ID: id, Names: name }) };
    }
    if (args[0] === 'inspect') return { stdout: JSON.stringify([{ Id: id, Image: image, Name: '/' + name,
      Config: { Labels: { [label]: killed && mode === 'owner-changed' ? 'unrelated-owner' : owner } },
      State: { ...(killed && mode === 'state-unknown' ? {} : { Running: !killed || mode === 'still-running' || mode === 'restarted' && listCount >= 3 }) } }]) };
    if (args[0] === 'kill') {
      killed = true;
      if (mode === 'deadline-exceeded') clock += 5000;
      throw Object.assign(new Error('container is not running'), { result: { code: 1, cleanupVerified: mode !== 'kill-process-unknown', stderr: 'container is not running' } });
    }
    if (args[0] === 'rm') { removed = true; return { stdout: id }; }
    throw new Error('Unexpected inert Docker command');
  };
  const start = () => ({ child: { pid: 123, stdin: { end() {} } }, done, stop: async () => { resolveExit(processResult); return processResult; } });
  try {
    const native = await startContainer({ root, image, taskRoot, profile, command: '/inert/client', args: [], env: {}, runner, start });
    const result = await native.stop('inert-cancel'); await native.done;
    await verify({ result, calls, networkId, id });
  } finally {
    fakeClock?.mockRestore(); fixtureDiscovery.docker = undefined;
    for (const [key, value] of prior) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(root, { recursive: true, force: true });
  }
}

test('a container stopped or removed during kill retains the failure and completes independent owned cleanup', async () => {
  for (const mode of ['stopped', 'absent']) await fixture(mode, ({ result, calls, networkId, id }) => {
    assert.equal(result.cleanupVerified, true);
    const steps = result.container_cleanup;
    assert.equal(steps.filter(step => step.step === 'container-kill').length, 1);
    assert.equal(steps.find(step => step.step === 'container-kill').outcome, 'failed');
    assert.equal(steps.find(step => step.step === 'container-kill').failure.owned_process.cleanupVerified, true);
    for (const step of ['container-inspect-after-kill-failure', 'container-inspect-stopped', 'network-inspect', 'network-remove', 'container-absence-final']) {
      assert.equal(steps.find(item => item.step === step)?.outcome, 'completed');
    }
    assert.ok(calls.some(call => call.args[0] === 'network' && call.args[1] === 'rm' && call.args[2] === networkId));
    assert.equal(calls.filter(call => call.args[0] === 'rm' && call.args[1] === id).length, mode === 'stopped' ? 1 : 0);
    assert.ok(result.finished_at <= result.deadline);
    assert.ok(calls.filter(call => ['kill', 'ps', 'inspect', 'rm'].includes(call.args[0])).every(call => call.options.timeout <= 500));
  });
});

test('kill error text cannot substitute for stopped state, ownership or verified command-process release', async () => {
  for (const mode of ['still-running', 'query-failed', 'owner-changed', 'state-unknown', 'kill-process-unknown', 'restarted', 'deadline-exceeded']) await fixture(mode, ({ result, calls }) => {
    assert.equal(result.cleanupVerified, false, mode);
    assert.equal(result.container_cleanup.find(step => step.step === 'container-kill').outcome, 'failed');
    assert.ok(result.container_cleanup.some(step => step.step === 'container-inspect-after-kill-failure'));
    assert.equal(calls.some(call => call.args[0] === 'network' && call.args[1] === 'rm'), false, mode);
    assert.equal(result.container_cleanup.some(step => step.step === 'container-absence-final'), false, mode);
    if (['query-failed', 'owner-changed', 'deadline-exceeded'].includes(mode)) assert.equal(result.container_cleanup.find(step => step.step === 'container-inspect-after-kill-failure').outcome, 'failed');
    else assert.equal(result.container_cleanup.find(step => step.step === 'container-inspect-after-kill-failure').outcome, 'completed');
    assert.equal(result.container_cleanup.find(step => step.step === 'host-process-release').cleanupVerified, true);
  });
});
