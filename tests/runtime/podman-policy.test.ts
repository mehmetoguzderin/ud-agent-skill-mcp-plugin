import { describe, expect, it } from 'vitest';
import { inspectPodmanJob, podmanCreateArgs, podmanIsLocalRootless, podmanLocalMode, validatePodmanOciSpec } from '../../packages/runtime-manager/src/podman.js';
import type { PodmanJob } from '../../packages/runtime-manager/src/podman.js';

const digest = `sha256:${'a'.repeat(64)}`;
const job: PodmanJob = {
  name: 'ud-agent-01234567-89ab-cdef-0123-456789abcdef', snapshotDirectory: '/private/snapshot',
  hooksDirectory: '/private/hooks', defaultMountsFile: '/private/mounts.conf', seccompProfile: '/private/seccomp.json',
  image: { digest, reference: `ghcr.io/mehmetoguzderin/ud-core@${digest}`, contextSha256: `sha256:${'b'.repeat(64)}` },
  expectedEnvironment: ['PATH=/usr/bin', 'LANG=C'],
};
const seccomp = { defaultAction: 'SCMP_ACT_ERRNO', syscalls: [{ names: ['read'], action: 'SCMP_ACT_ALLOW' }] };

function secureSpec() {
  return {
    root: { path: 'rootfs', readonly: true },
    process: { terminal: false, noNewPrivileges: true, cwd: '/work', user: { uid: 10001, gid: 10001 },
      args: ['python', '-m', 'ud_agent.worker'], env: ['PATH=/usr/bin', 'LANG=C'],
      capabilities: { bounding: [], effective: [], inheritable: [], permitted: [], ambient: [] },
      rlimits: [{ type: 'RLIMIT_NOFILE', soft: 1024, hard: 1024 }] },
    mounts: [{ type: 'bind', source: job.snapshotDirectory, destination: '/work', options: ['rbind', 'ro'] },
      { type: 'tmpfs', source: 'tmpfs', destination: '/tmp', options: ['rw', 'nosuid', 'nodev', 'noexec', 'size=67108864'] }],
    linux: { namespaces: [{ type: 'pid' }, { type: 'ipc' }, { type: 'network' }, { type: 'user' }, { type: 'cgroup' }], seccomp,
      devices: [], resources: { memory: { limit: 2_147_483_648 }, cpu: { quota: 200_000, period: 100_000 }, pids: { limit: 128 }, devices: [] } },
  };
}

describe('rootless Podman command and effective OCI policy', () => {
  it('uses a local immutable image, no pull, no network, an unprivileged worker and bounded resources', () => {
    const args = podmanCreateArgs(job);
    expect(args).toContain('--remote=false');
    expect(args).toContain('--pull=never');
    expect(args).toContain('--network=none');
    expect(args).toContain('--read-only');
    expect(args).toContain('--cap-drop=ALL');
    expect(args).toContain('--user=10001:10001');
    expect(args).toContain('--pids-limit=128');
    expect(args.at(-1)).toBe(job.image.reference);
    expect(() => podmanCreateArgs({ ...job, snapshotDirectory: '/tmp/a,options=rw' })).toThrow('runtime path');
    expect(() => podmanCreateArgs({ ...job, image: { ...job.image, reference: 'ghcr.io/mehmetoguzderin/ud-core:latest' } })).toThrow('locked digest');
    expect(podmanIsLocalRootless({ host: { arch: 'arm64', security: { rootless: true } } }, 'arm64')).toBe(true);
    expect(podmanIsLocalRootless({ host: { arch: 'arm64', security: { rootless: false } } }, 'arm64')).toBe(false);
    expect(podmanIsLocalRootless({ host: { arch: 'amd64', security: { rootless: true } } }, 'arm64')).toBe(false);
  });

  it('accepts only a complete independently inspected OCI specification', () => {
    expect(validatePodmanOciSpec(secureSpec(), job, seccomp)).toEqual([]);
    expect(validatePodmanOciSpec({}, job, seccomp)).toEqual(['missing_oci_spec']);
  });

  it('separates rootful engine identity from mandatory unprivileged worker confinement', () => {
    const rootful: PodmanJob = { ...job, engineMode: 'rootful' };
    expect(podmanLocalMode({ host: { arch: 'arm64', security: { rootless: false } } }, 'arm64')).toBe('rootful');
    expect(podmanLocalMode({ host: { arch: 'arm64', security: {} } }, 'arm64')).toBeUndefined();
    expect(podmanLocalMode({ host: { arch: 'amd64', security: { rootless: false } } }, 'arm64')).toBeUndefined();
    const args = podmanCreateArgs(rootful);
    expect(args).not.toContain('--userns=keep-id:uid=10001,gid=10001');
    for (const flag of ['--pull=never', '--network=none', '--read-only', '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128']) expect(args).toContain(flag);
    const spec = secureSpec(); spec.linux.namespaces = spec.linux.namespaces.filter(namespace => namespace.type !== 'user');
    expect(validatePodmanOciSpec(spec, rootful, seccomp)).toEqual([]);
    expect(validatePodmanOciSpec(spec, job, seccomp)).toContain('namespace_user');
    spec.process.user.uid = 0; expect(validatePodmanOciSpec(spec, rootful, seccomp)).toContain('worker_uid');
    spec.process.user.uid = 10001; spec.linux.namespaces.push({ type: 'user', path: '/proc/1/ns/user' } as { type: string });
    expect(validatePodmanOciSpec(spec, rootful, seccomp)).toContain('namespace_user');
  });

  it('binds inspection and cleanup to the exact owned container and immutable image', () => {
    const id = '1'.repeat(64);
    const inspection = [{ Id: id, Name: job.name, ImageDigest: job.image.digest, OCIConfigPath: '/engine/storage/id/config.json',
      EffectiveCaps: [], BoundingCaps: [], State: { Status: 'created' },
      Config: { Labels: { 'io.ud-agent.job': job.name }, User: '10001:10001', Tty: false, OpenStdin: true },
      HostConfig: { Privileged: false, ReadonlyRootfs: true, NetworkMode: 'none', Devices: [], PublishAllPorts: false } }];
    expect(inspectPodmanJob(inspection, job, id, '/engine/storage')).toEqual({ configPath: '/engine/storage/id/config.json', failures: [] });
    const forged = structuredClone(inspection); forged[0]!.Config.Labels['io.ud-agent.job'] = 'foreign';
    forged[0]!.OCIConfigPath = '/etc/passwd';
    expect(inspectPodmanJob(forged, job, id, '/engine/storage').failures).toEqual(['job_ownership', 'oci_config_path']);
    expect(inspectPodmanJob(inspection, job, 'not-an-id', '/engine/storage').failures).toEqual(['invalid_inspection']);
  });

  it.each([
    ['writable root', (spec: any) => { spec.root.readonly = false; }, 'writable_root'],
    ['root worker', (spec: any) => { spec.process.user.uid = 0; }, 'worker_uid'],
    ['privilege escalation', (spec: any) => { spec.process.noNewPrivileges = false; }, 'process_privileges'],
    ['capabilities', (spec: any) => { spec.process.capabilities.effective = ['CAP_SYS_ADMIN']; }, 'capabilities'],
    ['worker command', (spec: any) => { spec.process.args = ['sh', '-c', 'id']; }, 'worker_command'],
    ['environment injection', (spec: any) => { spec.process.env.push('SSH_AUTH_SOCK=/secrets'); }, 'injected_environment'],
    ['file limit', (spec: any) => { spec.process.rlimits = []; }, 'file_limit'],
    ['network namespace', (spec: any) => { spec.linux.namespaces[2].path = '/host/net'; }, 'namespace_network'],
    ['seccomp', (spec: any) => { spec.linux.seccomp = { defaultAction: 'SCMP_ACT_ALLOW' }; }, 'seccomp'],
    ['memory', (spec: any) => { spec.linux.resources.memory.limit = 0; }, 'memory_limit'],
    ['processor budget', (spec: any) => { spec.linux.resources.cpu.quota = 300_000; }, 'cpu_limit'],
    ['process budget', (spec: any) => { spec.linux.resources.pids.limit = 129; }, 'pid_limit'],
    ['device injection', (spec: any) => { spec.linux.devices.push({ path: '/dev/kvm', type: 'c', major: 10, minor: 232 }); }, 'host_devices'],
    ['wildcard devices', (spec: any) => { spec.linux.resources.devices.push({ allow: true, type: 'a' }); }, 'device_permissions'],
    ['hook injection', (spec: any) => { spec.hooks = { prestart: [{ path: '/bin/sh' }] }; }, 'injected_hooks'],
    ['writable input', (spec: any) => { spec.mounts[0].options = ['rw']; }, 'bind_mounts'],
    ['conflicting input mount flags', (spec: any) => { spec.mounts[0].options = ['ro', 'rw']; }, 'bind_mounts'],
    ['disguised host bind', (spec: any) => { spec.mounts.push({ type: 'none', source: '/home', destination: '/dev/shm', options: ['bind'] }); }, 'unexpected_mounts'],
    ['unbounded temp', (spec: any) => { spec.mounts[1].options = ['rw']; }, 'temporary_storage'],
    ['overriding temp size', (spec: any) => { spec.mounts[1].options.push('size=0'); }, 'temporary_storage'],
  ])('rejects %s', (_name, mutate, expected) => {
    const spec = structuredClone(secureSpec()); mutate(spec);
    expect(validatePodmanOciSpec(spec, job, seccomp)).toContain(expected);
  });
});
