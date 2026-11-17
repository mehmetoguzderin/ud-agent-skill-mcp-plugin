import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { admitLimaRuntime, inspectLimaJob, limaCommand } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import type { LimaRuntime, LimaRuntimeReceipt } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';
const sha = (value: string | Buffer) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const bytes = await readFile(path.resolve('tests/fixtures/lima-native/container.json'));
const native = JSON.parse(bytes.toString('utf8'));
const record = JSON.parse(await readFile(path.resolve('tests/fixtures/lima-native/container-receipt.json'), 'utf8'));
const workerBytes = await readFile(path.resolve('tests/fixtures/lima-native/worker.json'));
const worker = JSON.parse(workerBytes.toString('utf8'));
const workerRecord = JSON.parse(await readFile(path.resolve('tests/fixtures/lima-native/worker-receipt.json'), 'utf8'));
const success = (value: unknown = '') => ({ code: 0, stdout: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)), stderr: Buffer.alloc(0) });

async function fixture(test: (runtime: LimaRuntime, runner: typeof runCommand, alter: () => void) => Promise<void>, nsenter = true) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-lima-native-container-')));
  try {
    const executable = path.join(root, 'limactl'); await writeFile(executable, 'fixture Lima');
    const receipt: LimaRuntimeReceipt = { schema_version: 1, executable, binarySha256: sha('fixture Lima'), instance: 'ud-agent', guestUid: 1001, guestHome: '/home/udagent', architecture: 'arm64', address: '/run/user/1001/containerd/containerd.sock', nerdctl: '/usr/local/bin/nerdctl', nerdctlSha256: sha('fixture nerdctl'), containerd: '/usr/local/bin/containerd', containerdSha256: sha('fixture containerd'), ...(nsenter ? { nsenter: '/usr/bin/nsenter', nsenterSha256: sha('fixture pinned nsenter') } : {}) };
    let changed = false;
    const runner: typeof runCommand = async (_executable, args) => {
      if (args[0] === '--version') return success('limactl version 2.3.0\n');
      if (args[0] === 'list') return success([{ name: 'ud-agent', status: 'Running', arch: 'aarch64', vmType: 'vz' }]);
      if (args.includes('/usr/bin/id')) return success('1001\n');
      if (args.includes('/usr/bin/sha256sum')) return success([`${receipt.nerdctlSha256.slice(7)}  ${receipt.nerdctl}`, `${receipt.containerdSha256.slice(7)}  ${receipt.containerd}`, ...(receipt.nsenter ? [`${(changed ? sha('wrong') : receipt.nsenterSha256!).slice(7)}  ${receipt.nsenter}`] : [])].join('\n') + '\n');
      if (args.includes('/proc/sys/kernel/random/boot_id')) return success('11111111-1111-4111-8111-111111111111\n');
      if (args.includes('info')) return success({ Rootless: true, Namespace: 'ud-agent', Snapshotter: 'overlayfs', CgroupManager: 'systemd', Daemon: {} });
      throw new Error('Unexpected actual-execution fixture command');
    };
    await test(await admitLimaRuntime(receipt, runner), runner, () => { changed = true; });
  } finally { await rm(root, { recursive: true, force: true }); }
}

describe('captured native rootless containerd containment', () => {
  it('requires an issued rootless authority for inherited user namespaces and exact built-in hooks', async () => fixture(async runtime => {
    expect(sha(bytes).slice(7)).toBe(record.fixture_sha256);
    expect(inspectLimaJob(native, { ...record.expected, runtime })).toEqual([]);
    expect(inspectLimaJob(native, record.expected)).toEqual(['namespace_user', 'hooks']);
    expect(inspectLimaJob(native, { ...record.expected, runtime: { ...runtime } })).toEqual(['namespace_user', 'hooks']);
    const worker = structuredClone(native); worker[0].Spec.mounts.find((value: any) => value.destination === '/input').options = ['rbind', 'ro'];
    expect(inspectLimaJob(worker, { ...record.expected, readOnlyInput: true, runtime })).toEqual([]);
    expect(inspectLimaJob(native, { ...record.expected, readOnlyInput: true, runtime })).toContain('input');
    worker[0].Spec.mounts.find((value: any) => value.destination === '/input').options.push('rw');
    expect(inspectLimaJob(worker, { ...record.expected, readOnlyInput: true, runtime })).toContain('input');
  }));

  it('accepts the actual kernel-recursive read-only worker mount without accepting writable input', async () => fixture(async runtime => {
    expect(sha(workerBytes).slice(7)).toBe(workerRecord.fixture_sha256);
    expect(inspectLimaJob(worker, { ...workerRecord.expected, runtime })).toEqual([]);
    for (const options of [['rbind'], ['rbind', 'rro', 'rw'], ['rro'], ['rw'], ['rbind', 'ro', 'rw']]) {
      const value = structuredClone(worker); value[0].Spec.mounts.find((mount: any) => mount.destination === '/input').options = options;
      expect(inspectLimaJob(value, { ...workerRecord.expected, runtime })).toContain('input');
    }
    expect(inspectLimaJob(worker, { ...workerRecord.expected, readOnlyInput: false, runtime })).toContain('input');
    const contradictory = structuredClone(worker); contradictory[0].Spec.mounts.find((mount: any) => mount.destination === '/input').options.push('rw');
    expect(inspectLimaJob(contradictory, { ...workerRecord.expected, readOnlyInput: false, runtime })).toContain('input');
  }));

  it('rejects added hook code, redirected sockets/namespaces, ambient secrets, duplicate environment and missing identities', async () => fixture(async runtime => {
    const changes = [
      (spec: any) => { spec.hooks.createRuntime[0].path = '/tmp/project-hook'; },
      (spec: any) => { spec.hooks.createRuntime[0].args[1] = '-n/proc/1/ns/net'; },
      (spec: any) => { spec.hooks.createRuntime[0].args[5] = '--H=/foreign.sock'; },
      (spec: any) => { spec.hooks.createRuntime[0].args.push('--untrusted'); },
      (spec: any) => { spec.hooks.createRuntime[0].env.push('AWS_SECRET_ACCESS_KEY=foreign'); },
      (spec: any) => { spec.hooks.createRuntime[0].env.push('PATH=/usr/local/bin:/usr/bin:/bin'); },
      (spec: any) => { spec.hooks.createRuntime[0].env = spec.hooks.createRuntime[0].env.filter((value: string) => !value.startsWith('ROOTLESSKIT_PARENT_EUID=')); },
      (spec: any) => { spec.hooks.createRuntime[0].env = spec.hooks.createRuntime[0].env.map((value: string) => value.startsWith('NERDCTL_HOST_GATEWAY_IP=') ? 'NERDCTL_HOST_GATEWAY_IP=999.1.1.1' : value); },
      (spec: any) => { spec.hooks.createRuntime[0].timeout = 1; },
      (spec: any) => { spec.hooks.prestart = spec.hooks.createRuntime; },
      (spec: any) => { spec.hooks.poststop = []; },
      (spec: any) => { spec.hooks.createRuntime.push(spec.hooks.createRuntime[0]); },
    ];
    for (const change of changes) { const value = structuredClone(native); change(value[0].Spec); expect(inspectLimaJob(value, { ...record.expected, runtime })).toContain('hooks'); }
    const mapped = structuredClone(native); mapped[0].Spec.linux.uidMappings = [{ containerID: 0, hostID: 0, size: 65536 }];
    expect(inspectLimaJob(mapped, { ...record.expected, runtime })).toContain('namespace_user');
    const hostNamespace = structuredClone(native); hostNamespace[0].Spec.linux.namespaces.push({ type: 'user', path: '/proc/1/ns/user' });
    expect(inspectLimaJob(hostNamespace, { ...record.expected, runtime })).toContain('namespace_user');
  }));

  it('rechecks the pinned helper identity and rejects a legacy receipt that cannot authorize nsenter hooks', async () => {
    await fixture(async (runtime, runner, alter) => { alter(); await expect(limaCommand(runtime, ['info'], undefined, runner)).rejects.toThrow('LIMA_GUEST_EXECUTABLE_CHANGED'); });
    await fixture(async runtime => { expect(inspectLimaJob(native, { ...record.expected, runtime })).toContain('hooks'); }, false);
  });
});
