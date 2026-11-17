/** Scoped Lima discovery is portable protocol evidence, not native VM acceptance. */
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ command: vi.fn(), home: vi.fn(), guard: vi.fn() }));
vi.mock('../../packages/runtime-manager/src/command.js', () => ({ runCommand: mocks.command }));
vi.mock('../../packages/runtime-manager/src/lima-storage.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/lima-storage.js')>(), resolveOwnedLimaHome: mocks.home }));
vi.mock('../../packages/coordinator/src/docker-authority.js', async original => ({ ...await original<typeof import('../../packages/coordinator/src/docker-authority.js')>(), resolveProductGuard: mocks.guard }));
import { providerInspection } from '../../packages/coordinator/src/provider-runtime.js';
import { LIMA_INSTANCE_FORMAT } from '../../packages/runtime-manager/src/lima.js';
import type { RuntimeOptions } from '../../packages/runtime-manager/src/environment.js';
const sha = `sha256:${'a'.repeat(64)}`, host = { platform: 'darwin', arch: 'arm64' };
async function fixture(action: (options: RuntimeOptions, record: Record<string, unknown>) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-provider-inspection-')));
  try {
    const sourceRoot = path.join(root, 'product'); await mkdir(path.join(sourceRoot, 'runtime'), { recursive: true });
    const record = { schema_version: 1, executable_sha256: sha, instance: 'ud-agent', nerdctl: '/usr/bin/nerdctl', nerdctl_sha256: sha, containerd: '/usr/bin/containerd', containerd_sha256: sha, address: '/run/user/1001/containerd.sock', guest_uid: 1001, guest_home: '/home/udagent', architecture: 'arm64', provisioning: { template_path: 'runtime/template.yaml', template_sha256: sha, offline_ready: true, assets: [] } };
    await writeFile(path.join(sourceRoot, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: {}, provider_receipts: { 'lima-nerdctl/darwin/arm64': record } }));
    await action({ sourceRoot, host, userspaceStateRoot: path.join(root, 'private-state') }, record);
  } finally { await rm(root, { recursive: true, force: true }); }
}
describe('Lima discovery context', () => {
  beforeEach(() => { mocks.command.mockReset(); mocks.home.mockReset(); mocks.guard.mockReset(); mocks.guard.mockResolvedValue({ guard: '/verified/product/guard' }); });
  it('preserves the original three-argument global read-only inspection API', async () => {
    mocks.command.mockResolvedValue({ code: 0, stdout: Buffer.from('{"name":"legacy","status":"Running","arch":"aarch64","vmType":"vz"}'), stderr: Buffer.alloc(0) });
    expect(await providerInspection('lima-nerdctl', '/verified/limactl', host)).toEqual({ availability: 'available', rootless: null, reason: 'A running Lima VM is present; receipt-bound rootless containerd admission is separate.' });
    expect(mocks.command).toHaveBeenCalledExactlyOnceWith('/verified/limactl', ['list', '--format', LIMA_INSTANCE_FORMAT], { timeoutMs: 10000, maxOutputBytes: 4 * 1024 * 1024 }); expect(mocks.home).not.toHaveBeenCalled();
  });
  it('discovers only the receipt-selected instance in the verified product-owned home', async () => fixture(async options => {
    const home = '/verified/owned/lima-home', controller = new AbortController(); mocks.home.mockResolvedValue(home);
    mocks.command.mockResolvedValue({ code: 0, stdout: Buffer.from(JSON.stringify([{ name: 'ud-agent', status: 'Running', arch: 'aarch64' }, { name: 'foreign', status: 'Stopped', arch: 'aarch64' }])), stderr: Buffer.alloc(0) });
    expect(await providerInspection('lima-nerdctl', '/verified/limactl', host, { ...options, signal: controller.signal })).toMatchObject({ availability: 'available', rootless: null });
    expect(mocks.home).toHaveBeenCalledExactlyOnceWith(`${options.userspaceStateRoot}-lima-nerdctl`, '/verified/product/guard');
    expect(mocks.command).toHaveBeenCalledExactlyOnceWith('/verified/limactl', ['list', '--format', LIMA_INSTANCE_FORMAT], { timeoutMs: 10000, maxOutputBytes: 4 * 1024 * 1024, limaHome: home, signal: controller.signal });
    mocks.command.mockResolvedValue({ code: 0, stdout: Buffer.from(JSON.stringify([{ name: 'ud-agent', status: 'Stopped', arch: 'aarch64' }, { name: 'foreign', status: 'Running', arch: 'aarch64' }])), stderr: Buffer.alloc(0) });
    expect(await providerInspection('lima-nerdctl', '/verified/limactl', host, options)).toMatchObject({ availability: 'unavailable', rootless: null });
  }));
  it('does not inspect or prepare global Lima when owned state has not been installed', async () => fixture(async options => {
    mocks.home.mockResolvedValue(undefined); const before = await readFile(path.join(options.sourceRoot, 'runtime/runtime.lock.json'));
    expect(await providerInspection('lima-nerdctl', '/verified/limactl', host, options)).toMatchObject({ availability: 'unavailable', rootless: null }); expect(mocks.command).not.toHaveBeenCalled();
    expect(await readFile(path.join(options.sourceRoot, 'runtime/runtime.lock.json'))).toEqual(before);
  }));
  it('keeps missing or corrupted admitted ownership fatal instead of falling back to an unrelated VM', async () => fixture(async options => {
    mocks.home.mockRejectedValue(new Error('LIMA_HOME_BINDING_CHANGED'));
    await expect(providerInspection('lima-nerdctl', '/verified/limactl', host, options)).rejects.toThrow('LIMA_HOME_BINDING_CHANGED'); expect(mocks.command).not.toHaveBeenCalled();
    mocks.home.mockResolvedValue(undefined); const state = `${options.userspaceStateRoot}-lima-nerdctl`; await mkdir(state); await writeFile(path.join(state, 'lima-instance.json'), '{}');
    await expect(providerInspection('lima-nerdctl', '/verified/limactl', host, options)).rejects.toThrow('LIMA_HOME_BINDING_MISSING'); expect(mocks.command).not.toHaveBeenCalled();
  }));
  it('validates the frozen provider contract and preserves legacy named-instance discovery', async () => fixture(async (options, record) => {
    const file = path.join(options.sourceRoot, 'runtime/runtime.lock.json'), lock = JSON.parse(await readFile(file, 'utf8'));
    await writeFile(file, JSON.stringify({ ...lock, provider_receipts: [] })); await expect(providerInspection('lima-nerdctl', '/verified/limactl', host, options)).rejects.toThrow('PROVIDER_RECEIPT_INVALID');
    const { provisioning: _provisioning, ...legacy } = record; await writeFile(file, JSON.stringify({ ...lock, provider_receipts: { 'lima-nerdctl/darwin/arm64': legacy } }));
    mocks.command.mockResolvedValue({ code: 0, stdout: Buffer.from('[{"name":"foreign","status":"Running","arch":"aarch64"}]'), stderr: Buffer.alloc(0) }); expect(await providerInspection('lima-nerdctl', '/verified/limactl', host, options)).toMatchObject({ availability: 'unavailable' });
    expect(mocks.home).not.toHaveBeenCalled(); expect(mocks.command.mock.calls[0]![2]).not.toHaveProperty('limaHome');
    const controller = new AbortController(); controller.abort(); await expect(providerInspection('lima-nerdctl', '/verified/limactl', host, { ...options, signal: controller.signal })).rejects.toThrow('WORKER_CANCELLED');
  }));
});
