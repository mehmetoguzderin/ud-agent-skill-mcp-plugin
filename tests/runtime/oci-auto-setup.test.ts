import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../packages/runtime-manager/src/profiles.js', async original => (await import('./posix-policy-fixture.js')).physicalExecutablePolicyFixture(await original<typeof import('../../packages/runtime-manager/src/profiles.js')>()));
const mocks = vi.hoisted(() => ({ inspect: vi.fn(), verifyPack: vi.fn(), resolve: vi.fn(), prepare: vi.fn() }));
vi.mock('../../packages/runtime-manager/src/docker-inspection.js', () => ({ inspectLocalDocker: mocks.inspect }));
vi.mock('../../packages/runtime-manager/src/userspace.js', () => ({
  verifyUserspacePack: mocks.verifyPack, resolveUserspaceExecution: mocks.resolve, prepareUserspace: mocks.prepare,
  userspaceStateRoot: () => '/fixture/userspace',
}));
import { checkEnvironment, setupEnvironment } from '../../packages/runtime-manager/src/environment.js';

const catalog = [{ id: '048', name: 'validation_report', runtime_pack: 'core' }];
const host = { platform: 'darwin', arch: 'arm64' };
const digest = (digit: string) => `sha256:${digit.repeat(64)}`;

async function fixture(test: (sourceRoot: string, bin: string) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-oci-auto-')));
  try {
    const bin = path.join(root, 'bin'); const source = path.join(root, 'source');
    await mkdir(bin); await mkdir(path.join(source, 'runtime'), { recursive: true });
    await writeFile(path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')), '#!/bin/sh\nexit 0\n', { mode: 0o700 }); await chmod(path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')), 0o700);
    await writeFile(path.join(source, 'runtime', 'runtime.lock.json'), '{}');
    await test(source, bin);
  } finally { await rm(root, { recursive: true, force: true }); }
}

describe('OCI-first automatic setup', () => {
  beforeEach(() => {
    for (const fn of Object.values(mocks)) fn.mockReset();
    mocks.inspect.mockResolvedValue({ status: 'available', rootless: false, reason: 'fixture' });
    mocks.verifyPack.mockResolvedValue({ packs: ['core'] });
    mocks.resolve.mockResolvedValue({ packs: ['core'], manifestSha256: digest('1') });
    mocks.prepare.mockResolvedValue({ installer: 'uv', reused: true });
  });

  it('probes existing Docker before choosing an unsaved prepared userspace', async () => fixture(async (sourceRoot, bin) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')); const ready = { engine: 'docker' as const, executable, rootless: false, image_digest: digest('2'), context_sha256: digest('3'), verification: 'verified' as const, available_operations: ['validation_report'] as const };
    let probed = false;
    const ociReadiness = vi.fn(async () => probed ? ready : null);
    const ociSetup = vi.fn(async () => { probed = true; return ready; });
    const options = { sourceRoot, host, searchPath: bin, ociReadiness, ociSetup };
    const setup = await setupEnvironment({}, catalog, options);
    expect(setup).toMatchObject({ status: 'ready', ready: true, runtime: { engine: 'docker', selection_reason: 'existing_oci_engine' }, reused: false });
    expect(ociSetup).toHaveBeenCalledOnce(); expect(mocks.prepare).not.toHaveBeenCalled();
    expect(await checkEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' } });
  }));

  it('uses an available lightweight provider before Docker and advances only for availability failures', async () => fixture(async (sourceRoot, bin) => {
    await writeFile(path.join(bin, 'container' + (process.platform === 'win32' ? '.exe' : '')), '#!/bin/sh\nexit 0\n', { mode: 0o700 });
    const ready = (engine: 'apple-container' | 'docker') => ({ engine, executable: path.join(bin, (engine === 'docker' ? 'docker' : 'container') + (process.platform === 'win32' ? '.exe' : '')), rootless: engine === 'docker' ? false : null, image_digest: digest('2'), context_sha256: digest('3'), verification: 'verified' as const, available_operations: ['validation_report'] });
    const ociSetup = vi.fn(async (engine: 'apple-container' | 'docker') => ready(engine));
    const options = { sourceRoot, host, searchPath: bin, ociInspection: async () => ({ availability: 'available' as const, rootless: null, reason: 'An already running lightweight provider.' }), ociReadiness: async () => null, ociSetup };
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'apple-container', selection_reason: 'existing_oci_engine', worker_uid_verified: true } });
    expect(ociSetup.mock.calls.map(([engine]) => engine)).toEqual(['apple-container']);
    ociSetup.mockClear(); ociSetup.mockImplementation(async engine => engine === 'apple-container' ? null as never : ready(engine));
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' } });
    expect(ociSetup.mock.calls.map(([engine]) => engine)).toEqual(['apple-container', 'docker']);
    ociSetup.mockClear(); ociSetup.mockImplementation(async () => { throw new Error('CONTAINMENT_INTEGRITY_FAILED'); });
    await expect(setupEnvironment({}, catalog, options)).rejects.toThrow('CONTAINMENT_INTEGRITY_FAILED');
    expect(ociSetup).toHaveBeenCalledOnce(); expect(mocks.prepare).not.toHaveBeenCalled();
  }));

  it('reuses admitted Docker before setting up another responding provider and retains explicit or saved choices', async () => fixture(async (sourceRoot, bin) => {
    await writeFile(path.join(bin, 'container' + (process.platform === 'win32' ? '.exe' : '')), '#!/bin/sh\nexit 0\n', { mode: 0o700 });
    const docker = { engine: 'docker' as const, executable: path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')), rootless: false, image_digest: digest('2'), context_sha256: digest('3'), verification: 'verified' as const, available_operations: ['validation_report'] };
    const ociSetup = vi.fn(); const inspected: string[] = [];
    const options = { sourceRoot, host, searchPath: bin, ociInspection: async () => ({ availability: 'available' as const, rootless: null, reason: 'Responding provider requiring worker setup.' }), ociReadiness: async (engine: string) => { inspected.push(engine); return engine === 'docker' ? docker : null; }, ociSetup };
    expect(await checkEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' } });
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, reused: true, runtime: { engine: 'docker' } }); expect(ociSetup).not.toHaveBeenCalled();
    inspected.length = 0;
    expect(await checkEnvironment({ engine: 'apple-container' }, catalog, options)).toMatchObject({ ready: false, runtime: { engine: 'apple-container' } }); expect(inspected).toEqual(['apple-container']);
    inspected.length = 0;
    expect(await checkEnvironment({}, catalog, { ...options, savedEngine: 'apple-container' as const })).toMatchObject({ ready: false, runtime: { engine: 'apple-container' } }); expect(inspected).toEqual(['apple-container']);
  }));

  it('reports guest rootlessness separately from host VM containment on check and setup', async () => fixture(async (sourceRoot, bin) => {
    for (const [engine, command] of [['podman', 'podman'], ['lima-nerdctl', 'limactl']] as const) {
    await writeFile(path.join(bin, command + (process.platform === 'win32' ? '.exe' : '')), '#!/bin/sh\nexit 0\n', { mode: 0o700 });
    const ready = { engine, executable: path.join(bin, command + (process.platform === 'win32' ? '.exe' : '')), rootless: null, isolation_model: 'rootless_oci_in_vm', guest_rootless: true, virtual_machine: { name: 'owned-test-vm', fingerprint: digest('7'), boot_id: 'verified-boot' }, image_digest: digest('2'), context_sha256: digest('3'), verification: 'verified' as const, available_operations: ['validation_report'] };
    const options = { sourceRoot, host, searchPath: bin, ociInspection: async () => ({ availability: 'available' as const, rootless: null, reason: 'Rootless guest in a verified VM.' }), ociReadiness: async () => ready, ociSetup: async () => ready };
    expect(await checkEnvironment({ engine }, catalog, options)).toMatchObject({ ready: true, runtime: { rootless_verified: null, worker_uid_verified: true, guest_rootless: true, isolation_model: 'rootless_oci_in_vm', virtual_machine: ready.virtual_machine } });
    expect(await setupEnvironment({ engine }, catalog, { ...options, ociReadiness: async () => null })).toMatchObject({ ready: true, runtime: { rootless_verified: null, guest_rootless: true, virtual_machine: ready.virtual_machine } });
    await expect(checkEnvironment({ engine }, catalog, { ...options, ociReadiness: async () => ({ ...ready, guest_rootless: 'pretend' as never }) })).rejects.toThrow('INVALID_OCI_READINESS_EVIDENCE');
    }
  }));

  it('falls back for unavailable OCI assets but never for integrity or probe errors', async () => fixture(async (sourceRoot, bin) => {
    const unavailable = vi.fn().mockResolvedValue(null);
    const options = { sourceRoot, host, searchPath: bin, ociReadiness: async () => null, ociSetup: unavailable };
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'userspace' } });
    expect(unavailable).toHaveBeenCalledOnce(); expect(mocks.prepare).toHaveBeenCalledOnce();
    mocks.prepare.mockClear();
    const corrupt = vi.fn().mockRejectedValue(new Error('IMAGE_INTEGRITY_FAILED'));
    await expect(setupEnvironment({}, catalog, { ...options, ociSetup: corrupt })).rejects.toThrow('IMAGE_INTEGRITY_FAILED');
    expect(mocks.prepare).not.toHaveBeenCalled();
    corrupt.mockRejectedValue(new Error('DOCKER_CONTAINER_POLICY_FAILED'));
    await expect(setupEnvironment({}, catalog, { ...options, ociSetup: corrupt })).rejects.toThrow('DOCKER_CONTAINER_POLICY_FAILED');
    expect(mocks.prepare).not.toHaveBeenCalled();
  }));

  it('honors explicit userspace, a verified saved userspace, and read-only dry runs', async () => fixture(async (sourceRoot, bin) => {
    const ociSetup = vi.fn(); const options = { sourceRoot, host, searchPath: bin, ociReadiness: async () => null, ociSetup };
    expect(await setupEnvironment({ engine: 'userspace' }, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'userspace' } });
    expect(await setupEnvironment({}, catalog, { ...options, savedEngine: 'userspace' as const })).toMatchObject({ ready: true, runtime: { engine: 'userspace' } });
    expect(await setupEnvironment({ dry_run: true }, catalog, options)).toMatchObject({ dry_run: true });
    expect(ociSetup).not.toHaveBeenCalled();
  }));

  it('does not reuse an unavailable saved userspace over an admitted Docker', async () => fixture(async (sourceRoot, bin) => {
    const executable = path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')); const ready = { engine: 'docker' as const, executable, rootless: false, image_digest: digest('2'), context_sha256: digest('3'), verification: 'verified' as const, available_operations: ['validation_report'] as const };
    const missing = Object.assign(new Error('missing'), { code: 'ENOENT' });
    mocks.resolve.mockRejectedValue(missing);
    let probed = false;
    const options = { sourceRoot, host, searchPath: bin, savedEngine: 'userspace' as const, ociReadiness: async () => probed ? ready : null, ociSetup: async () => { probed = true; return ready; } };
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' } });
    expect(await checkEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' } });
  }));

  it('keeps OCI independent of unused userspace assets but rejects damage in a selected fallback', async () => fixture(async (sourceRoot, bin) => {
    await writeFile(path.join(sourceRoot, 'runtime', 'runtime.lock.json'), JSON.stringify({ state: 'frozen' }));
    mocks.verifyPack.mockRejectedValue(Object.assign(new Error('missing frozen asset'), { code: 'ENOENT' }));
    const ociSetup = vi.fn();
    const ready = { engine: 'docker' as const, executable: path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')), rootless: false, image_digest: digest('2'), context_sha256: digest('3'), verification: 'verified' as const, available_operations: ['validation_report'] };
    const options = { sourceRoot, host, searchPath: bin, ociReadiness: async () => ready, ociSetup };
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' } });
    expect(mocks.verifyPack).not.toHaveBeenCalled();
    await expect(setupEnvironment({}, catalog, { ...options, savedEngine: 'userspace' as const })).rejects.toThrow('missing frozen asset');
    expect(ociSetup).not.toHaveBeenCalled(); expect(mocks.prepare).not.toHaveBeenCalled();
  }));

  it('prepares fallback once when neither runtime is prepared', async () => fixture(async (sourceRoot, bin) => {
    mocks.verifyPack.mockRejectedValue(new Error('USERSPACE_RECEIPT_NOT_FROZEN'));
    mocks.resolve.mockRejectedValue(new Error('USERSPACE_RECEIPT_NOT_FROZEN'));
    mocks.prepare.mockRejectedValue(new Error('USERSPACE_COMPATIBLE_PYTHON_REQUIRED'));
    const ociSetup = vi.fn().mockResolvedValue(null);
    const result = await setupEnvironment({}, catalog, { sourceRoot, host, searchPath: bin, ociReadiness: async () => null, ociSetup });
    expect(result).toMatchObject({ status: 'needs_host_prerequisite', runtime: { engine: 'userspace', selection_reason: 'no_admitted_oci_engine' }, reason: 'USERSPACE_COMPATIBLE_PYTHON_REQUIRED' });
    expect(ociSetup).toHaveBeenCalledOnce(); expect(mocks.prepare).toHaveBeenCalledOnce();
  }));
});
