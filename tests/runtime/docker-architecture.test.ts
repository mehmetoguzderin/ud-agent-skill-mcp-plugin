import { expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ inspect: vi.fn(), run: vi.fn() }));
vi.mock('../../packages/runtime-manager/src/docker-inspection.js', () => ({ inspectLocalDocker: mocks.inspect }));
vi.mock('../../packages/runtime-manager/src/command.js', () => ({ runCommand: mocks.run }));
import { inspectDockerDaemonIdentity, inspectDockerImageIdentity } from '../../packages/coordinator/src/docker-worker.js';

it('admits an exact amd64 worker on an arm64 daemon as emulation without relabeling either architecture', async () => {
  const sha = (digit: string) => `sha256:${digit.repeat(64)}`;
  const image = { digest: sha('1'), contextSha256: sha('2'), configDigest: sha('3'), diffIds: [sha('4')], reference: `ghcr.io/mehmetoguzderin/core@${sha('1')}` };
  const host = { platform: 'linux' as const, arch: 'x64' };
  let daemonArch = 'aarch64', imageArch = 'amd64';
  mocks.inspect.mockResolvedValue({ status: 'available', rootless: false, reason: 'Local Docker daemon.' });
  mocks.run.mockImplementation(async (_engine: string, args: readonly string[]) => {
    let value;
    if (args[0] === 'context') value = [{ Endpoints: { docker: { Host: 'unix:///fixture.sock' } } }];
    else if (args.includes('info')) value = { ID: 'fixture-daemon', Architecture: daemonArch };
    else { expect(args).toContain('linux/amd64'); value = [{ Id: image.configDigest, Os: 'linux', Architecture: imageArch, RootFS: { Type: 'layers', Layers: image.diffIds } }]; }
    return { code: 0, stdout: Buffer.from(JSON.stringify(value)), stderr: Buffer.alloc(0) };
  });
  expect(await inspectDockerDaemonIdentity('/verified/docker', host)).toMatchObject({ architecture: 'arm64' });
  expect(await inspectDockerImageIdentity('/verified/docker', host, image)).toMatchObject({ daemonArchitecture: 'arm64', workerArchitecture: 'amd64', emulation: true, imageId: image.configDigest });
  imageArch = 'arm64'; await expect(inspectDockerImageIdentity('/verified/docker', host, image)).rejects.toThrow('DOCKER_IMAGE_NOT_VERIFIED');
  daemonArch = 's390x'; await expect(inspectDockerDaemonIdentity('/verified/docker', host)).rejects.toThrow('DOCKER_DAEMON_ARCHITECTURE_MISMATCH');
});
