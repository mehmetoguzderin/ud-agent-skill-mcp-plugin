import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ image: vi.fn(), daemon: vi.fn(), run: vi.fn() }));
vi.mock('../../packages/coordinator/src/docker-worker.js', () => ({ inspectDockerImageIdentity: mocks.image, inspectDockerDaemonIdentity: mocks.daemon }));
vi.mock('../../packages/runtime-manager/src/command.js', () => ({ runCommand: mocks.run }));
import { ensureDockerImage } from '../../packages/coordinator/src/docker-import.js';

beforeEach(() => { for (const fn of Object.values(mocks)) fn.mockReset(); });
async function fixture(test: (input: Parameters<typeof ensureDockerImage>[0], root: string) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-docker-import-')));
  try {
    await mkdir(path.join(root, 'runtime/images'), { recursive: true });
    const bytes = Buffer.from('verified platform transport');
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    await writeFile(path.join(root, 'runtime/images/core.tar'), bytes);
    await test({ guard: process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined, sourceRoot: root, stateRoot: path.join(root, 'state'), engine: '/verified/docker', host: { platform: 'darwin', arch: 'arm64' }, network: 'offline', image: { digest: `sha256:${'1'.repeat(64)}`, reference: `ghcr.io/mehmetoguzderin/core@sha256:${'1'.repeat(64)}`, contextSha256: `sha256:${'2'.repeat(64)}`, configDigest: `sha256:${'3'.repeat(64)}`, diffIds: [`sha256:${'4'.repeat(64)}`], transports: [{ format: 'docker-archive', path: 'runtime/images/core.tar', sha256: digest, sizeBytes: bytes.length }] } }, root);
  } finally { await rm(root, { recursive: true, force: true }); }
}

it('imports exact offline bytes into a bound daemon and reuses the immutable image without downloads', async () => fixture(async input => {
  let loaded = false;
  const identity = { endpoint: 'unix:///verified.sock', daemonId: 'daemon', imageId: input.image.configDigest, rootless: false };
  mocks.image.mockImplementation(async () => { if (!loaded) throw new Error('DOCKER_IMAGE_NOT_PRESENT'); return identity; });
  mocks.daemon.mockResolvedValue({ ...identity, architecture: 'arm64' });
  mocks.run.mockImplementation(async () => { loaded = true; return { code: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }; });
  const fetcher = vi.fn();
  expect(await ensureDockerImage({ ...input, fetcher })).toBe(true);
  expect(mocks.run).toHaveBeenCalledWith(input.engine, ['--host', identity.endpoint, 'image', 'load', '--input', expect.stringMatching(/\.tar$/)], expect.any(Object));
  expect(await ensureDockerImage({ ...input, fetcher })).toBe(true);
  expect(mocks.run).toHaveBeenCalledTimes(1); expect(fetcher).not.toHaveBeenCalled();
}));

it('blocks corrupt transport bytes and does not substitute another route', async () => fixture(async (input, root) => {
  mocks.image.mockRejectedValue(new Error('DOCKER_IMAGE_NOT_PRESENT'));
  mocks.daemon.mockResolvedValue({ endpoint: 'unix:///verified.sock', daemonId: 'daemon', architecture: 'arm64', rootless: false });
  await writeFile(path.join(root, 'runtime/images/core.tar'), Buffer.alloc(input.image.transports![0]!.sizeBytes, 0));
  const fetcher = vi.fn();
  await expect(ensureDockerImage({ ...input, network: 'bootstrap_only', fetcher })).rejects.toThrow('DOCKER_TRANSPORT_INTEGRITY_FAILED');
  expect(mocks.run).not.toHaveBeenCalled(); expect(fetcher).not.toHaveBeenCalled();
}));

it('returns availability failure offline and rejects a corrupt owned cache', async () => fixture(async (input, root) => {
  mocks.image.mockRejectedValue(new Error('DOCKER_IMAGE_NOT_PRESENT'));
  mocks.daemon.mockResolvedValue({ endpoint: 'unix:///verified.sock', daemonId: 'daemon', architecture: 'arm64', rootless: false });
  await rm(path.join(root, 'runtime/images/core.tar'));
  const fetcher = vi.fn();
  expect(await ensureDockerImage({ ...input, fetcher })).toBe(false);
  const transport = input.image.transports![0]!;
  const cached = path.join(input.stateRoot, `${transport.sha256.slice(7)}.tar`);
  await writeFile(cached, Buffer.alloc(transport.sizeBytes, 0)); await chmod(cached, 0o400);
  await expect(ensureDockerImage({ ...input, fetcher })).rejects.toThrow('digest does not match');
  expect(fetcher).not.toHaveBeenCalled(); expect(mocks.run).not.toHaveBeenCalled();
}));
