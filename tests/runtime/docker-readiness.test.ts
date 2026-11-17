import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { RuntimeOptions } from '../../packages/runtime-manager/src/environment.js';

const mocks = vi.hoisted(() => ({ resolve: vi.fn(), verify: vi.fn(), run: vi.fn(), inspect: vi.fn() }));
vi.mock('../../packages/coordinator/src/docker-authority.js', () => ({ resolveDockerAuthority: mocks.resolve, verifyDockerAuthority: mocks.verify }));
vi.mock('../../packages/coordinator/src/docker-worker.js', () => ({ runDockerValidation: mocks.run }));
vi.mock('../../packages/runtime-manager/src/docker-inspection.js', () => ({ inspectLocalDocker: mocks.inspect }));
import { dockerReadiness, dockerStateRoot, setupDocker } from '../../packages/coordinator/src/docker-readiness.js';

const sha = (n: string) => `sha256:${n.repeat(64)}`;
const host = { platform: 'darwin', arch: 'arm64' };
const authority = { engine: '/test/docker', engineSha256: sha('1'), guard: path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), guardSha256: sha('2'), productLockSha256: sha('3'), manifestSha256: sha('4'), image: { digest: sha('5'), reference: `ghcr.io/mehmetoguzderin/core@${sha('5')}`, contextSha256: sha('6') }, identity: { endpoint: 'unix:///test/docker.sock', daemonId: 'test', imageId: sha('7'), rootless: false } };

async function fixture(test: (options: RuntimeOptions) => Promise<void>) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-docker-ready-'));
  try { await test({ sourceRoot: directory, userspaceStateRoot: path.join(directory, 'state') }); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

describe('Docker readiness probe', () => {
  beforeEach(() => {
    mocks.resolve.mockReset().mockResolvedValue(authority);
    mocks.verify.mockReset().mockResolvedValue(authority);
    mocks.inspect.mockReset().mockResolvedValue({ status: 'available', rootless: false });
    mocks.run.mockReset().mockResolvedValue({ result: { passed: false, incidents: [{ testid: 'non-unique-sent-id' }] } });
  });

  it('records only a successful worker probe and reuses matching identity without rerunning', async () => fixture(async options => {
    expect(await dockerReadiness(options, 'docker', authority.engine, host, ['validation_report'])).toBeNull();
    const result = await setupDocker(options, 'docker', authority.engine, host, ['validation_report']);
    expect(result).toMatchObject({ verification: 'verified', image_digest: authority.image.digest });
    expect(await dockerReadiness(options, 'docker', authority.engine, host, ['validation_report'])).toEqual(result);
    expect(await setupDocker(options, 'docker', authority.engine, host, ['validation_report'])).toEqual(result);
    expect(mocks.run).toHaveBeenCalledTimes(1);
    expect(mocks.run.mock.calls[0]![0].expectedIdentity).toEqual(authority.identity);
  }));

  it('does not record a failed cross-file or failed worker probe', async () => fixture(async options => {
    mocks.run.mockResolvedValueOnce({ result: { passed: false, incidents: [] } });
    await expect(setupDocker(options, 'docker', authority.engine, host, ['validation_report'])).rejects.toThrow('DOCKER_VALIDATION_PROBE_FAILED');
    await expect(readFile(path.join(dockerStateRoot(options, host), 'probe.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    mocks.run.mockRejectedValueOnce(new Error('DOCKER_CLEANUP_UNVERIFIED'));
    await expect(setupDocker(options, 'docker', authority.engine, host, ['validation_report'])).rejects.toThrow('DOCKER_CLEANUP_UNVERIFIED');
    expect(await dockerReadiness(options, 'docker', authority.engine, host, ['validation_report'])).toBeNull();
  }));

  it('invalidates identity changes and malformed markers, and refuses rootless claims', async () => fixture(async options => {
    await setupDocker(options, 'docker', authority.engine, host, ['validation_report']);
    mocks.resolve.mockResolvedValueOnce({ ...authority, identity: { ...authority.identity, daemonId: 'changed' } });
    expect(await dockerReadiness(options, 'docker', authority.engine, host, ['validation_report'])).toBeNull();
    await writeFile(path.join(dockerStateRoot(options, host), 'probe.json'), '{}\n');
    expect(await dockerReadiness(options, 'docker', authority.engine, host, ['validation_report'])).toBeNull();
    expect(await setupDocker(options, 'docker-rootless', authority.engine, host, ['validation_report'])).toBeNull();
    expect(await setupDocker(options, 'docker', authority.engine, host, ['project_consistency_report'])).toBeNull();
  }));

  it('does not hide a corrupt image or receipt as runtime unavailability', async () => fixture(async options => {
    mocks.resolve.mockRejectedValueOnce(new Error('DOCKER_IMAGE_NOT_VERIFIED'));
    await expect(dockerReadiness(options, 'docker', authority.engine, host, ['validation_report'])).rejects.toThrow('DOCKER_IMAGE_NOT_VERIFIED');
    mocks.resolve.mockRejectedValueOnce(new Error('Worker image platform is absent from the receipt.'));
    await expect(dockerReadiness(options, 'docker', authority.engine, host, ['validation_report'])).rejects.toThrow('Worker image platform is absent');
  }));
});
