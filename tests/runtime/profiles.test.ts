import { describe, expect, it, vi } from 'vitest';
import { chmod, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
vi.mock('node:fs/promises', async original => (await import('./posix-policy-fixture.js')).posixPolicyFixture(await original<typeof import('node:fs/promises')>()));
vi.mock('../../packages/runtime-manager/src/profiles.js', async original => (await import('./posix-policy-fixture.js')).physicalExecutablePolicyFixture(await original<typeof import('../../packages/runtime-manager/src/profiles.js')>()));
import { candidateEngines, findExecutable, isEngineSupported, platformPreferred, selectEngine } from '../../packages/runtime-manager/src/profiles.js';
import { checkEnvironment, setupEnvironment } from '../../packages/runtime-manager/src/environment.js';

describe('platform profiles', () => {
  it.each([
    ['darwin', 'arm64', 'apple-container'], ['darwin', 'x64', 'lima-nerdctl'],
    ['win32', 'arm64', 'wslc'], ['win32', 'x64', 'wslc'],
    ['linux', 'arm64', 'podman'], ['linux', 'x64', 'podman'],
  ] as const)('prefers the lightweight profile on %s %s', (platform, arch, expected) => {
    expect(platformPreferred({ platform, arch })).toBe(expected);
  });

  it('honors a compatible saved profile, and rejects unsupported explicit profiles', () => {
    const host = { platform: 'darwin', arch: 'arm64' } as const;
    expect(selectEngine('auto', 'podman', host)).toBe('podman');
    expect(selectEngine('wslc', undefined, host)).toBeUndefined();
    expect(isEngineSupported('apple-container', { platform: 'darwin', arch: 'x64' })).toBe(false);
    expect(platformPreferred({ platform: 'linux', arch: 's390x' })).toBeUndefined();
    expect(candidateEngines(host, 'podman')).toEqual(['podman', 'apple-container', 'lima-nerdctl', 'docker', 'userspace']);
    expect(isEngineSupported('docker', host)).toBe(true);
    expect(isEngineSupported('userspace', host)).toBe(true);
  });

  it('inspects executable availability without executing it or searching relative PATH', async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-profile-'));
    try {
      const executable = path.join(temporary, 'podman' + (process.platform === 'win32' ? '.exe' : ''));
      await writeFile(executable, '#!/bin/sh\nexit 77\n');
      await chmod(executable, 0o700);
      expect(await findExecutable('podman', { platform: process.platform, arch: process.arch }, temporary)).toBe(await realpath(executable));
      expect(await findExecutable('podman', { platform: process.platform, arch: process.arch }, '.')).toBeUndefined();
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });
});

describe('environment checks', () => {
  const catalog = [{ id: '048', name: 'validation_report', runtime_pack: 'core' }, { id: '091', name: 'sentence_render', runtime_pack: 'render' }];

  it('reports missing prerequisites without starting an engine', async () => {
    const result = await checkEnvironment({}, catalog, { sourceRoot: '/no-such-release', userspaceStateRoot: path.resolve('/no-such-release/state'), host: { platform: 'darwin', arch: 'arm64' }, searchPath: '' });
    expect(result.status).toBe('setup_needed');
    expect(result.ready).toBe(false);
    expect(result.missing).toContain('trusted_runtime_lock');
    expect(result.runtime).toMatchObject({ engine: 'userspace', rootless_verified: null, worker_uid_verified: false, selection_reason: 'no_available_oci_engine' });
  });

  it('rejects mixed wildcard and unknown tool requests', async () => {
    const options = { sourceRoot: '/no-such-release', host: { platform: 'linux', arch: 'x64' } as const, searchPath: '' };
    await expect(checkEnvironment({ required_tools: ['*', 'validation_report'] }, catalog, options)).rejects.toThrow('wildcard');
    await expect(checkEnvironment({ required_tools: ['imaginary'] }, catalog, options)).rejects.toThrow('Unknown domain tool');
  });

  it('does not mutate state for dry runs or invent a ready result', async () => {
    const result = await setupEnvironment({ dry_run: true, required_tools: ['*'] }, catalog, { sourceRoot: '/no-such-release', host: { platform: 'linux', arch: 'x64' }, searchPath: '' });
    expect(result.dry_run).toBe(true);
    expect(result.ready).toBe(false);
    expect(result.requested_tools).toEqual(['validation_report', 'sentence_render']);
    expect(result.working_tree_changes).toEqual([]);
  });

  it('auto-selects an existing allowed alternative instead of installing a new runtime', async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-engine-'));
    try {
      const executable = path.join(temporary, 'limactl' + (process.platform === 'win32' ? '.exe' : ''));
      await writeFile(executable, '#!/bin/sh\nexit 77\n');
      await chmod(executable, 0o700);
      const result = await checkEnvironment({}, catalog, { sourceRoot: '/no-such-release', userspaceStateRoot: path.join(temporary, 'state'), host: { platform: 'darwin', arch: 'arm64' }, searchPath: temporary });
      expect(result.runtime).toMatchObject({ engine: 'lima-nerdctl', rootless_verified: null });
      expect(result.status).toBe('setup_needed');
      expect(result.ready).toBe(false);
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('reuses a running administrative Docker daemon and retains rootless as an explicit choice', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-docker-')));
    try {
      const executable = path.join(temporary, 'docker' + (process.platform === 'win32' ? '.exe' : ''));
      await writeFile(executable, '#!/bin/sh\nexit 77\n');
      await chmod(executable, 0o700);
      const runner = async (_exe: string, args: readonly string[]) => ({ code: 0, stdout: Buffer.from(JSON.stringify(args[0] === 'context' ? [{ Endpoints: { docker: { Host: 'unix:///run/docker.sock' } } }] : { ServerVersion: '29.0.0', SecurityOptions: ['name=seccomp'] })), stderr: Buffer.alloc(0) });
      const options = { sourceRoot: '/no-such-release', userspaceStateRoot: path.join(temporary, 'state'), host: { platform: 'linux', arch: 'x64' } as const, searchPath: temporary, dockerRunner: runner };
      const auto = await checkEnvironment({}, catalog, options);
      expect(auto.runtime).toMatchObject({ engine: 'docker', rootless_verified: false, availability: 'available', selection_reason: 'existing_oci_engine' });
      const rootless = await checkEnvironment({ engine: 'docker-rootless' }, catalog, options);
      expect(rootless.status).toBe('needs_host_prerequisite');
      expect(rootless.runtime).toMatchObject({ engine: 'docker-rootless', rootless_verified: false, availability: 'unavailable' });
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('does not connect to a remote Docker context and falls back to userspace', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-docker-')));
    try {
      const executable = path.join(temporary, 'docker' + (process.platform === 'win32' ? '.exe' : '')); await writeFile(executable, 'fixture'); await chmod(executable, 0o700);
      const calls: string[] = [];
      const runner = async (_exe: string, args: readonly string[]) => { calls.push(args[0] ?? ''); return { code: 0, stdout: Buffer.from(JSON.stringify([{ Endpoints: { docker: { Host: 'tcp://example.test:2375' } } }])), stderr: Buffer.alloc(0) }; };
      const result = await checkEnvironment({}, catalog, { sourceRoot: '/no-such-release', userspaceStateRoot: path.join(temporary, 'state'), host: { platform: 'linux', arch: 'x64' }, searchPath: temporary, dockerRunner: runner });
      expect(result.runtime).toMatchObject({ engine: 'userspace', selection_reason: 'no_available_oci_engine' });
      expect(calls).toEqual(['context']);
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('marks Docker ready only from matching internal containment evidence', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-docker-evidence-')));
    try {
      const executable = path.join(temporary, 'docker' + (process.platform === 'win32' ? '.exe' : '')); await writeFile(executable, 'fixture'); await chmod(executable, 0o700);
      const resolved = await realpath(executable);
      const runner = async (_exe: string, args: readonly string[]) => ({ code: 0, stdout: Buffer.from(JSON.stringify(args[0] === 'context' ? [{ Endpoints: { docker: { Host: 'unix:///run/docker.sock' } } }] : { ServerVersion: '29.0.0', SecurityOptions: ['name=seccomp'] })), stderr: Buffer.alloc(0) });
      const evidence = { engine: 'docker' as const, executable: resolved, rootless: false, verification: 'verified' as const, image_digest: 'sha256:' + 'a'.repeat(64), context_sha256: 'sha256:' + 'b'.repeat(64), available_operations: ['validation_report'] as const };
      const base = { sourceRoot: '/no-such-release', userspaceStateRoot: path.join(temporary, 'state'), host: { platform: 'linux', arch: 'x64' } as const, searchPath: temporary, dockerRunner: runner };
      const checked = await checkEnvironment({ engine: 'docker' }, catalog, { ...base, ociReadiness: async () => evidence });
      expect(checked).toMatchObject({ ready: true, status: 'ready', runtime: { engine: 'docker', rootless_verified: false, verification: 'verified' } });
      const setup = await setupEnvironment({ engine: 'docker' }, catalog, { ...base, ociSetup: async () => evidence });
      expect(setup).toMatchObject({ ready: true, status: 'ready', reused: false });
      await expect(checkEnvironment({ engine: 'docker' }, catalog, { ...base, ociReadiness: async () => ({ ...evidence, image_digest: 'latest' }) })).rejects.toThrow('INVALID_OCI_READINESS_EVIDENCE');
      await expect(checkEnvironment({ engine: 'docker' }, catalog, { ...base, ociReadiness: async () => ({ ...evidence, rootless: true }) })).rejects.toThrow('INVALID_OCI_READINESS_EVIDENCE');
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('requires continuation and exact update targets in their applicable modes', async () => {
    const options = { sourceRoot: '/no-such-release', host: { platform: 'linux', arch: 'x64' } as const, searchPath: '' };
    await expect(setupEnvironment({ mode: 'resume' }, catalog, options)).rejects.toThrow('continuation_token');
    await expect(setupEnvironment({ mode: 'update' }, catalog, options)).rejects.toThrow('target_release');
    await expect(setupEnvironment({ mode: 'ensure', target_release: 'x' }, catalog, options)).rejects.toThrow('only accepted');
  });
});
