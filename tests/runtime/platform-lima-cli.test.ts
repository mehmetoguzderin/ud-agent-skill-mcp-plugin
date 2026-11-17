/** Portable coordinator fixtures; these mocks provide no native VM acceptance. */
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../packages/runtime-manager/src/profiles.js', async original => (await import('./posix-policy-fixture.js')).physicalExecutablePolicyFixture(await original<typeof import('../../packages/runtime-manager/src/profiles.js')>()));
const mocks = vi.hoisted(() => ({ image: vi.fn(), admit: vi.fn(), command: vi.fn(), worker: vi.fn(), import: vi.fn(), acquire: vi.fn(), closure: vi.fn(), lease: false, lock: false, version: '2.3.0', stages: [] as string[], root: '' }));
vi.mock('node:fs/promises', async original => (await import('./posix-policy-fixture.js')).posixPolicyFixture(await original<typeof import('node:fs/promises')>()));
vi.mock('../../packages/runtime-manager/src/command.js', () => ({ runCommand: async (_exe: string, args: string[], options: unknown) => { expect(args).toEqual(['--version']); expect(options).toMatchObject({ timeoutMs: 5000, maxOutputBytes: 65536 }); return { code: 0, stdout: Buffer.from(`limactl version ${mocks.version}\n`), stderr: Buffer.alloc(0) }; } }));
vi.mock('../../packages/runtime-manager/src/receipt.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/receipt.js')>(), loadImageReceipt: mocks.image }));
vi.mock('../../packages/coordinator/src/docker-authority.js', () => ({ resolveProductGuard: async () => ({ guard: '/portable-fixture/guard', guardSha256: `sha256:${'c'.repeat(64)}` }) }));
vi.mock('../../packages/runtime-manager/src/lima-nerdctl.js', async original => ({ ...await original<typeof import('../../packages/runtime-manager/src/lima-nerdctl.js')>(), admitLimaRuntime: mocks.admit, limaCommand: mocks.command, bindLimaOfflineImage: async () => { expect(mocks.lease).toBe(true); expect(mocks.lock).toBe(true); } }));
vi.mock('../../packages/runtime-manager/src/archive.js', () => ({ stageVerifiedArchive: async () => ({ filename: path.resolve('package.json'), cleanup: async () => undefined }) }));
vi.mock('../../packages/runtime-manager/src/oci-closure.js', () => ({ verifyOciClosure: mocks.closure }));
vi.mock('../../packages/runtime-manager/src/worker-image-assets.js', () => ({ acquireWorkerImageTransport: mocks.acquire }));
vi.mock('../../packages/runtime-manager/src/stream-command.js', () => ({ streamCommand: mocks.import }));
vi.mock('../../packages/coordinator/src/platform-worker.js', () => ({ runPlatformWorker: mocks.worker, recoverPlatformJobs: async () => undefined }));
// This fixture models the native lease boundary. Cache repair itself has
// separate real-helper tests; here assert it remains outside the setup lease.
vi.mock('../../packages/coordinator/src/image-repair.js', () => ({ repairWorkerImageTransport: async () => { expect(mocks.lease).toBe(false); mocks.stages.push('cache-repair'); return { repaired: false }; } }));
vi.mock('../../packages/coordinator/src/provider-leases.js', () => ({ withProviderLease: async (_guard: string, _root: string, action: () => Promise<unknown>) => { mocks.lease = true; mocks.stages.push('lease-start'); try { return await action(); } finally { mocks.stages.push('lease-end'); mocks.lease = false; } }, withProviderMaintenance: async (_guard: string, _root: string, action: () => Promise<unknown>) => action() }));
vi.mock('../../packages/workspace/src/journal.js', async original => ({ ...(await import('./posix-policy-fixture.js')).posixJournalPolicyFixture(await original<typeof import('../../packages/workspace/src/journal.js')>(), await import('node:fs/promises'), () => mocks.root, ['lima-cli.json', 'probe-core.json', 'probe-render.json', 'selected.json']), openStateAuthority: async () => undefined, JournalStore: { open: async () => ({ withWorkspaceLock: async (_name: string, action: () => Promise<unknown>) => { expect(mocks.lease).toBe(true); mocks.lock = true; try { return await action(); } finally { mocks.lock = false; } } }) } }));
import { platformReadiness, setupPlatform } from '../../packages/coordinator/src/platform-readiness.js';
import { checkEnvironment, setupEnvironment } from '../../packages/runtime-manager/src/environment.js';
import type { RuntimeOptions } from '../../packages/runtime-manager/src/environment.js';
import { loadContracts } from '../../packages/coordinator/src/catalog.js';
import { writableFixtureCopy } from '../fixtures/writable-copy.mjs';

const hash = (value: string | Buffer) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const digest = hash('fixture image identity'), host = { platform: 'darwin', arch: 'x64' };
async function fixture(action: (options: RuntimeOptions, executable: string) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-platform-lima-cli-')));
  mocks.root = root;
  try {
    const sourceRoot = path.join(root, 'product'), bin = path.join(root, 'external-bin');
    await mkdir(path.join(sourceRoot, 'runtime'), { recursive: true }); writableFixtureCopy('contracts', path.join(sourceRoot, 'contracts'), root); await mkdir(bin);
    const executable = path.join(bin, 'limactl' + (process.platform === 'win32' ? '.exe' : '')); await writeFile(executable, 'external supported Lima', { mode: 0o700 }); await writeFile(path.join(bin, 'docker' + (process.platform === 'win32' ? '.exe' : '')), 'independent Docker', { mode: 0o700 });
    const record = { schema_version: 1, executable_sha256: hash('official tar binary'), instance: 'ud-agent', nerdctl: '/usr/bin/nerdctl', nerdctl_sha256: digest, containerd: '/usr/bin/containerd', containerd_sha256: digest, address: '/run/user/1000/containerd.sock', guest_uid: 1000, guest_home: '/home/user', architecture: 'amd64' };
    await writeFile(path.join(sourceRoot, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', provider_receipts: { 'lima-nerdctl/darwin/x64': record } }));
    const options: RuntimeOptions = { sourceRoot, host, searchPath: bin, userspaceStateRoot: path.join(root, 'private-state') };
    await action(options, executable);
  } finally { mocks.root = ''; await rm(root, { recursive: true, force: true }); }
}
describe('external Lima CLI through public environment selection and platform setup', () => {
  beforeEach(() => {
    for (const key of ['image', 'admit', 'command', 'worker', 'import', 'acquire', 'closure'] as const) mocks[key].mockReset(); mocks.lease = false; mocks.lock = false; mocks.version = '2.3.0'; mocks.stages = [];
    mocks.image.mockResolvedValue({ digest, reference: `localhost/ud-agent-core@${digest}`, contextSha256: digest, configDigest: digest, diffIds: [digest], transports: [{ format: 'oci-archive', path: 'runtime/fixture.tar', sha256: digest, sizeBytes: 1, indexDigest: hash('actual per-arch fixture index') }] });
    mocks.acquire.mockImplementation(async () => { expect(mocks.lease).toBe(true); expect(mocks.lock).toBe(true); mocks.stages.push('acquire-worker'); return path.resolve('package.json'); });
    mocks.closure.mockResolvedValue(undefined);
    mocks.admit.mockImplementation(async receipt => { expect(mocks.lease).toBe(true); expect(mocks.lock).toBe(true); mocks.stages.push('admit'); return { engine: 'lima-nerdctl', receipt, identity: 'owned-rootless-guest', bootId: 'fixture-boot', rootless: true }; });
    mocks.command.mockResolvedValue({ code: 0, stdout: Buffer.from('{"Rootless":true,"Namespace":"ud-agent","Snapshotter":"overlayfs","CgroupManager":"systemd"}'), stderr: Buffer.alloc(0) });
    mocks.import.mockImplementation(async (_exe, _args, input) => { for await (const _chunk of input) { /* consume the owned fixture stream */ } return Buffer.alloc(0); });
    mocks.worker.mockImplementation(async (_runtime, _image, _guard, _state, input) => { expect(mocks.lease).toBe(true); expect(mocks.lock).toBe(true); expect(input.arguments).toEqual({ working_tree_path: input.workingTree, file_paths: ['a.conllu', 'b.conllu'], options: { language_code: 'en', level: 2 } }); mocks.stages.push('containment-workflow'); return { result: { passed: false, incidents: [{ testid: 'non-unique-sent-id' }] } }; });
  });
  it('read-only auto selection reuses admitted Docker before trying an unknown external Lima CLI', async () => fixture(async (options, executable) => {
    const catalog = loadContracts(options.sourceRoot).domain, calls: string[] = [];
    const docker = { engine: 'docker' as const, executable: path.join(path.dirname(executable), 'docker' + (process.platform === 'win32' ? '.exe' : '')), rootless: false, image_digest: digest, context_sha256: digest, verification: 'verified' as const, available_operations: ['validation_report'] };
    options.ociInspection = async () => ({ availability: 'available', rootless: null, reason: 'Portable running-Lima inspection fixture' });
    options.dockerRunner = async (_exe, args) => ({ code: 0, stdout: Buffer.from(args[0] === '--version' ? 'limactl version 2.2.9' : JSON.stringify(args[0] === 'context' ? [{ Endpoints: { docker: { Host: 'unix:///fixture/docker.sock' } } }] : { ServerVersion: '29.0.0', SecurityOptions: ['name=seccomp'] })), stderr: Buffer.alloc(0) });
    mocks.version = '2.2.9';
    options.ociReadiness = async (engine, exe, actualHost, requested) => { calls.push(`read:${engine}`); return engine === 'lima-nerdctl' ? platformReadiness(options, engine, exe, actualHost, requested) : engine === 'docker' ? docker : null; };
    options.ociSetup = async (engine, exe, actualHost, requested) => { calls.push(`setup:${engine}`); return engine === 'lima-nerdctl' ? setupPlatform(options, engine, exe, actualHost, requested) : engine === 'docker' ? docker : null; };
    expect(await checkEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' } });
    expect(calls).toEqual(['read:lima-nerdctl', 'read:docker']); calls.length = 0;
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' }, reused: true });
    expect(calls).toEqual(['read:lima-nerdctl', 'read:docker']); expect(mocks.admit).not.toHaveBeenCalled(); expect(mocks.worker).not.toHaveBeenCalled();
    // A responding Docker engine without prior worker admission still follows
    // setup; unsupported external Lima must not turn into an integrity error.
    calls.length = 0;
    options.ociReadiness = async (engine, exe, actualHost, requested) => { calls.push(`read:${engine}`); return engine === 'lima-nerdctl' ? platformReadiness(options, engine, exe, actualHost, requested) : null; };
    expect(await setupEnvironment({}, catalog, options)).toMatchObject({ ready: true, runtime: { engine: 'docker' }, reused: false });
    expect(calls).toEqual(['read:lima-nerdctl', 'read:docker', 'read:lima-nerdctl', 'setup:lima-nerdctl', 'read:docker', 'setup:docker']);
  }));
  it('binds supported setup to actual CLI bytes/version, runs containment, then persists under the setup lease', async () => fixture(async (options, executable) => {
    await writeFile(executable, '#!/bin/sh\nprintf "limactl version 2.3.0\\n"\n', { mode: 0o700 });
    expect(await platformReadiness(options, 'lima-nerdctl', executable, host, ['validation_report'])).toBeNull();
    const result = await setupPlatform(options, 'lima-nerdctl', executable, host, ['validation_report']); expect(result).toMatchObject({ engine: 'lima-nerdctl', rootless: null, guest_rootless: true, verification: 'verified' });
    expect(mocks.stages).toEqual(['lease-start', 'acquire-worker', 'admit', 'containment-workflow', 'lease-end']);
    expect(mocks.closure).toHaveBeenCalledWith(path.resolve('package.json'), { manifestDigest: digest, architecture: 'amd64', indexDigest: hash('actual per-arch fixture index'), configDigest: digest, diffIds: [digest] });
    const receipt = mocks.admit.mock.calls[0]![0]; expect(receipt.binarySha256).toBe(hash(await readFile(executable))); expect(receipt.cliVersion).toBe('2.3.0');
    const state = `${options.userspaceStateRoot}-lima-nerdctl`, admission = JSON.parse(await readFile(path.join(state, 'lima-cli.json'), 'utf8')); expect(admission.version).toBe('2.3.0'); expect(admission.sha256).toBe(receipt.binarySha256);
    const probe = JSON.parse(await readFile(path.join(state, 'probe-core.json'), 'utf8')); expect(probe.fingerprint).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(await platformReadiness(options, 'lima-nerdctl', executable, host, ['validation_report'])).toMatchObject({ verification: 'verified', available_operations: expect.arrayContaining(['validation_report']) });
    expect(mocks.worker).toHaveBeenCalledOnce();
    await writeFile(executable, '#!/bin/sh\nprintf "limactl version 2.4.0\\n"\n', { mode: 0o700 });
    mocks.version = '2.4.0';
    await expect(platformReadiness(options, 'lima-nerdctl', executable, host, ['validation_report'])).rejects.toThrow('LIMA_CLI_IDENTITY_CHANGED_REPAIR_REQUIRED');
    expect(await platformReadiness({ ...options, setupMode: 'repair' }, 'lima-nerdctl', executable, host, ['validation_report'])).toBeNull();
    expect(await setupPlatform({ ...options, setupMode: 'repair' }, 'lima-nerdctl', executable, host, ['validation_report'])).toMatchObject({ verification: 'verified' });
    expect(mocks.stages.indexOf('cache-repair')).toBeLessThan(mocks.stages.lastIndexOf('lease-start'));
    expect(JSON.parse(await readFile(path.join(state, 'lima-cli.json'), 'utf8')).version).toBe('2.4.0'); expect(JSON.parse(await readFile(path.join(state, 'probe-core.json'), 'utf8')).fingerprint).not.toBe(probe.fingerprint);
  }));
  it('does not store a new admission or ready probe when containment fails', async () => fixture(async (options, executable) => {
    await writeFile(executable, '#!/bin/sh\nprintf "limactl version 2.3.0\\n"\n', { mode: 0o700 }); mocks.worker.mockResolvedValue({ result: { passed: true, incidents: [] } });
    await expect(setupPlatform(options, 'lima-nerdctl', executable, host, ['validation_report'])).rejects.toThrow('PLATFORM_VALIDATION_PROBE_FAILED');
    for (const name of ['lima-cli.json', 'probe-core.json']) await expect(readFile(path.join(`${options.userspaceStateRoot}-lima-nerdctl`, name))).rejects.toMatchObject({ code: 'ENOENT' });
  }));
  it('rejects damaged frozen provider metadata before an unknown CLI can authorize fallback', async () => fixture(async (options, executable) => {
    const filename = path.join(options.sourceRoot, 'runtime/runtime.lock.json'), lock = JSON.parse(await readFile(filename, 'utf8'));
    for (const invalid of [[], 'not an object', null]) {
      await writeFile(filename, JSON.stringify({ ...lock, provider_receipts: invalid }));
      await expect(platformReadiness(options, 'lima-nerdctl', executable, host, ['validation_report'])).rejects.toThrow('PROVIDER_RECEIPT_INVALID');
    }
    expect(mocks.admit).not.toHaveBeenCalled(); expect(mocks.worker).not.toHaveBeenCalled();
  }));
  it('acquires before VM admission and distinguishes unavailable archives from integrity failure', async () => fixture(async (options, executable) => {
    const controller = new AbortController(); options.setupNetwork = 'bootstrap_only'; options.signal = controller.signal;
    mocks.acquire.mockResolvedValue(null);
    expect(await setupPlatform(options, 'lima-nerdctl', executable, host, ['validation_report'])).toBeNull();
    expect(mocks.acquire).toHaveBeenCalledWith(expect.objectContaining({ sourceRoot: options.sourceRoot, stateRoot: `${options.userspaceStateRoot}-lima-nerdctl`, guard: '/portable-fixture/guard', network: 'bootstrap_only', signal: controller.signal, transport: expect.objectContaining({ format: 'oci-archive', indexDigest: hash('actual per-arch fixture index') }) }));
    expect(mocks.admit).not.toHaveBeenCalled(); expect(mocks.import).not.toHaveBeenCalled(); expect(mocks.worker).not.toHaveBeenCalled();
    mocks.acquire.mockRejectedValue(new Error('WORKER_IMAGE_TRANSPORT_INTEGRITY_FAILED'));
    await expect(setupPlatform(options, 'lima-nerdctl', executable, host, ['validation_report'])).rejects.toThrow('WORKER_IMAGE_TRANSPORT_INTEGRITY_FAILED');
    expect(mocks.admit).not.toHaveBeenCalled(); expect(mocks.import).not.toHaveBeenCalled();
  }));

function rendererFixture(format: string) {
  const bytes = Buffer.alloc(150); if (format === 'png') Buffer.from('89504e470d0a1a0a', 'hex').copy(bytes); else { bytes.write('%PDF-1.7'); bytes.write('%%EOF', 140); }
  return { result: { status: 'complete', artifacts: [{ relative_path: 'probe.' + format, mime_type: format === 'png' ? 'image/png' : 'application/pdf', content_base64: bytes.toString('base64'), size_bytes: bytes.length, sha256: hash(bytes).slice(7) }] } };
}
it('public environment setup admits render only after both real worker formats complete, then reuses the bound evidence read-only', async () => fixture(async (options, executable) => {
  await writeFile(executable, '#!/bin/sh\nprintf "limactl version 2.3.0\\n"\n', { mode: 0o700 });
  mocks.worker.mockImplementation(async (_runtime, _image, _guard, _state, input) => {
    expect(mocks.lease).toBe(true);expect(mocks.lock).toBe(true);
    if (input.operation === 'validation_report') return { result: { passed: false, incidents: [{ testid: 'non-unique-sent-id' }] } };
    expect(input.operation).toBe('sentence_render');expect(input.arguments.sentence_conllu).toContain('العربية 日本語');
    return rendererFixture(input.arguments.output_format);
  });
  const catalog = loadContracts(options.sourceRoot).domain;
  options.ociInspection = async () => ({ availability:'available',rootless:null,reason:'Explicit fixture engine observation' });
  options.ociReadiness = (engine, exe, actualHost, requested) => engine === 'lima-nerdctl' ? platformReadiness(options, engine, exe, actualHost, requested) : Promise.resolve(null);
  options.ociSetup = (engine, exe, actualHost, requested) => engine === 'lima-nerdctl' ? setupPlatform(options, engine, exe, actualHost, requested) : Promise.resolve(null);
  const ready = await setupEnvironment({ engine:'lima-nerdctl',required_tools:['sentence_render'],network:'offline' },catalog,options);
  expect(ready).toMatchObject({ ready:true,runtime:{engine:'lima-nerdctl'} });
  expect(mocks.worker.mock.calls.map(call=>[call[4].operation,call[4].arguments.output_format])).toEqual([['validation_report',undefined],['sentence_render','png'],['sentence_render','pdf']]);
  expect(await checkEnvironment({engine:'lima-nerdctl',required_tools:['sentence_render']},catalog,options)).toMatchObject({ready:true});expect(mocks.worker).toHaveBeenCalledTimes(3);
}));
it('a failed sandboxed render leaves no render-readiness or new external-CLI admission receipt', async () => fixture(async (options, executable) => {
  await writeFile(executable, '#!/bin/sh\nprintf "limactl version 2.3.0\\n"\n', { mode: 0o700 });
  mocks.worker.mockImplementation(async (_runtime, _image, _guard, _state, input) => input.operation === 'validation_report' ? { result:{passed:false,incidents:[{testid:'non-unique-sent-id'}]} } : input.arguments.output_format === 'png' ? rendererFixture('png') : { result:{status:'incomplete',reason:'sandbox could not initialize'} });
  await expect(setupPlatform(options,'lima-nerdctl',executable,host,['sentence_render'])).rejects.toThrow('RENDER_PROBE_INCOMPLETE');
  for(const name of ['probe-render.json','lima-cli.json']) await expect(readFile(path.join(`${options.userspaceStateRoot}-lima-nerdctl`,name))).rejects.toMatchObject({code:'ENOENT'});
  expect(await platformReadiness(options,'lima-nerdctl',executable,host,['sentence_render'])).toBeNull();
}));

});
