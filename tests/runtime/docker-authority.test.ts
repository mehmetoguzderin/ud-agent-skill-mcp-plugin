import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ pack: vi.fn(), inspect: vi.fn() }));
vi.mock('../../packages/runtime-manager/src/userspace.js', () => ({ verifyUserspacePack: mocks.pack }));
vi.mock('../../packages/coordinator/src/docker-worker.js', () => ({ inspectDockerImageIdentity: mocks.inspect }));
import { resolveDockerAuthority, verifyDockerAuthority } from '../../packages/coordinator/src/docker-authority.js';

const sha = (bytes: Buffer | string) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const host = { platform: 'darwin', arch: 'arm64' };
const imageDigest = `sha256:${'1'.repeat(64)}`;
const manifest = `sha256:${'2'.repeat(64)}`;
const identity = { endpoint: 'unix:///private/tmp/docker.sock', daemonId: 'fixture', imageId: `sha256:${'3'.repeat(64)}`, rootless: false };

async function fixture(test: (root: string, engine: string) => Promise<void>) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ud-docker-authority-'));
  try {
    const engine = path.join(root, 'engine'); const guard = path.join(root, 'guard');
    await mkdir(path.join(root, 'runtime')); await writeFile(engine, 'engine', { mode: 0o700 }); await chmod(engine, 0o700); await writeFile(guard, 'guard', { mode: 0o700 });
    const lock = { schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: { core: { context_sha256: `sha256:${'4'.repeat(64)}`, images: { 'linux/arm64': { digest: imageDigest, reference: `ghcr.io/mehmetoguzderin/core@${imageDigest}` } } } } };
    await writeFile(path.join(root, 'runtime', 'runtime.lock.json'), JSON.stringify(lock));
    mocks.pack.mockResolvedValue({ manifestSha256: manifest, packs: ['core'], guard, guardSha256: sha('guard') });
    await test(root, engine);
  } finally { await rm(root, { recursive: true, force: true }); }
}

describe('Docker product authority', () => {
  beforeEach(() => { mocks.pack.mockReset(); mocks.inspect.mockReset().mockResolvedValue(identity); });

  it('rejects fabricated and copied capabilities', async () => fixture(async (root, engine) => {
    const capability = await resolveDockerAuthority(root, engine, host);
    expect(await verifyDockerAuthority(capability)).toBe(capability);
    await expect(verifyDockerAuthority({ ...capability })).rejects.toThrow('DOCKER_PRODUCT_AUTHORITY_REQUIRED');
    expect(mocks.inspect).toHaveBeenCalledTimes(2);
  }));

  it('rejects changed daemon and product receipt', async () => fixture(async (root, engine) => {
    const capability = await resolveDockerAuthority(root, engine, host);
    mocks.inspect.mockResolvedValueOnce({ ...identity, daemonId: 'different' });
    await expect(verifyDockerAuthority(capability)).rejects.toThrow('DOCKER_IDENTITY_CHANGED');
    const lock = path.join(root, 'runtime', 'runtime.lock.json');
    await writeFile(lock, `${await readFile(lock, 'utf8')} `);
    await expect(verifyDockerAuthority(capability)).rejects.toThrow('DOCKER_RECEIPT_CHANGED');
  }));

  it('rejects changed engine and changed guard receipt', async () => fixture(async (root, engine) => {
    const capability = await resolveDockerAuthority(root, engine, host);
    await writeFile(engine, 'changed');
    await expect(verifyDockerAuthority(capability)).rejects.toThrow('DOCKER_EXECUTABLE_CHANGED');
    mocks.pack.mockResolvedValue({ manifestSha256: manifest, packs: ['core'], guard: '/different/guard', guardSha256: sha('guard') });
    await expect(verifyDockerAuthority(capability)).rejects.toThrow('DOCKER_RECEIPT_CHANGED');
  }));

  it('rejects a symbolic executable alias before inspection even when its bytes match', async () => fixture(async (root, engine) => {
    const alias = path.join(root, 'alias' + (process.platform === 'win32' ? '.exe' : ''));
    await symlink(engine, alias);
    await expect(resolveDockerAuthority(root, alias, host)).rejects.toThrow('DOCKER_EXECUTABLE_UNVERIFIED');
    expect(mocks.inspect).not.toHaveBeenCalled();
    expect(await readFile(engine, 'utf8')).toBe('engine');
  }));

  it('does not issue a capability if genuine image inspection fails', async () => fixture(async (root, engine) => {
    mocks.inspect.mockRejectedValueOnce(new Error('DOCKER_IMAGE_NOT_VERIFIED'));
    await expect(resolveDockerAuthority(root, engine, host)).rejects.toThrow('DOCKER_IMAGE_NOT_VERIFIED');
  }));
});
