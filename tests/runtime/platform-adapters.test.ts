import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { admitAppleRuntime, appleCreateArguments, appleLocalImageIdentity, withAppleRuntime } from '../../packages/runtime-manager/src/apple-runtime.js';
import { appleExecutionAvailability } from '../../packages/runtime-manager/src/apple.js';
import { admitLimaRuntime, inspectLimaJob, limaCommand, limaCreateArguments, limaImageIdentity, limaShellArguments } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import { admitWslcRuntime, closeWslcRuntime, inspectWslcJob, wslcCommand, wslcCreateArguments } from '../../packages/runtime-manager/src/wslc-runtime.js';
import { verifyOciClosure } from '../../packages/runtime-manager/src/oci-closure.js';
import { createOciFixture, fixtureTar } from '../release/oci-fixture.mjs';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';
import { platformIsolation } from '../../packages/coordinator/src/platform-readiness.js';
import { tar } from '../fixtures/ustar.js';
import { gunzipSync } from 'node:zlib';

const digest = (value: string | Buffer) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const success = (value: unknown = '') => ({ code: 0, stdout: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)), stderr: Buffer.alloc(0) });
async function fixture<T>(run: (root: string) => Promise<T>) { const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-platform-adapter-'))); try { return await run(root); } finally { await rm(root, { recursive: true, force: true }); } }
function imageFixture() {
  const archive = createOciFixture('platform'); const manifestDigest = archive.platforms['linux/arm64'];
  const manifest = JSON.parse(Buffer.from(archive.entries.find(([name]: [string, unknown]) => name === `blobs/sha256/${manifestDigest.slice(7)}`)![1]).toString());
  const config = JSON.parse(Buffer.from(archive.entries.find(([name]: [string, unknown]) => name === `blobs/sha256/${manifest.config.digest.slice(7)}`)![1]).toString());
  return { archive, image: { digest: manifestDigest, reference: `ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin-core@${manifestDigest}`, contextSha256: digest('context'), configDigest: manifest.config.digest, diffIds: config.rootfs.diff_ids }, manifest, config };
}

describe('provider-specific OCI adapters', () => {
  it('admits only timestamp PAX metadata for Apple exports and keeps all structural overrides forbidden', async () => fixture(async root => {
    const { archive, image } = imageFixture(); const file = path.join(root, 'pax.tar'); const entries = archive.entries.map(([name, bytes]: [string, Buffer]) => ({ name, bytes: Buffer.from(bytes) }));
    const write = async (metadata: string, suffix = false) => { const record = { name: 'PaxHeader/oci-layout', bytes: Buffer.from(metadata), type: 'x' }; await writeFile(file, gunzipSync(tar(suffix ? [...entries, record] : [record, ...entries]))); };
    const expected = { manifestDigest: image.digest, architecture: 'arm64' as const, configDigest: image.configDigest, diffIds: image.diffIds };
    await write('20 ctime=1794193195\n20 atime=1794193195\n'); await expect(verifyOciClosure(file, expected)).rejects.toThrow('extended tar'); expect(await verifyOciClosure(file, { ...expected, timestampPax: true })).toMatchObject({ manifestDigest: image.digest });
    const pax = (pair: string) => { let length = Buffer.byteLength(pair) + 3; while (Buffer.byteLength(`${length} ${pair}\n`) !== length) length = Buffer.byteLength(`${length} ${pair}\n`); return `${length} ${pair}\n`; };
    for (const invalid of [pax('path=../escape'), pax('linkpath=outside'), pax('size=1'), pax('atime=NaN'), pax('ctime=1e9'), pax('ctime=1') + pax('ctime=2'), '0 ctime=1\n', '99 ctime=1\n', '12 ctime=1x']) { await write(invalid); await expect(verifyOciClosure(file, { ...expected, timestampPax: true })).rejects.toThrow('PAX'); }
    await write(pax('ctime=1'), true); await expect(verifyOciClosure(file, { ...expected, timestampPax: true })).rejects.toThrow('end marker');
  }));
  it('verifies full per-architecture OCI closure and rejects corrupt or hostile transports', async () => fixture(async root => {
    const { archive, image } = imageFixture(); const file = path.join(root, 'image.tar'); await writeFile(file, archive.bytes);
    expect(await verifyOciClosure(file, { manifestDigest: image.digest, architecture: 'arm64', configDigest: image.configDigest, diffIds: image.diffIds })).toMatchObject({ manifestDigest: image.digest, configDigest: image.configDigest });
    await expect(verifyOciClosure(file, { manifestDigest: image.digest, architecture: 'amd64' })).rejects.toThrow('platform config');
    await expect(verifyOciClosure(file, { manifestDigest: image.digest, architecture: 'arm64', configDigest: digest('wrong') })).rejects.toThrow('config receipt');
    await writeFile(file, fixtureTar([...archive.entries, ['../escape', 'bad']])); await expect(verifyOciClosure(file, { manifestDigest: image.digest, architecture: 'arm64' })).rejects.toThrow('unexpected path');
    await writeFile(file, fixtureTar([...archive.entries, archive.entries[0]])); await expect(verifyOciClosure(file, { manifestDigest: image.digest, architecture: 'arm64' })).rejects.toThrow('duplicate');
    const changed = archive.entries.map(([name, bytes]: [string, Buffer]) => name.endsWith(image.configDigest.slice(7)) ? [name, Buffer.from('altered')] : [name, bytes]);
    await writeFile(file, fixtureTar(changed)); await expect(verifyOciClosure(file, { manifestDigest: image.digest, architecture: 'arm64' })).rejects.toThrow('blob digest');
    await writeFile(file, archive.bytes.subarray(0, 520)); await expect(verifyOciClosure(file, { manifestDigest: image.digest, architecture: 'arm64' })).rejects.toThrow();
  }));
  it('binds the exact archive root index bytes independently of its selected manifest', async () => fixture(async root => {
    const { archive, image } = imageFixture(); const file = path.join(root, 'index-bound.tar'); await writeFile(file, archive.bytes);
    const index = archive.entries.find(([name]: [string, Buffer]) => name === 'index.json')![1], indexDigest = digest(index);
    const expected = { manifestDigest: image.digest, architecture: 'arm64' as const, configDigest: image.configDigest, diffIds: image.diffIds };
    expect(indexDigest).not.toBe(image.digest);
    expect(await verifyOciClosure(file, { ...expected, indexDigest })).toMatchObject({ manifestDigest: image.digest, indexDigest });
    await expect(verifyOciClosure(file, { ...expected, indexDigest: image.digest })).rejects.toThrow('index receipt');
    await expect(verifyOciClosure(file, { ...expected, indexDigest: 'not-a-digest' })).rejects.toThrow('OCI_CLOSURE_RECEIPT_INVALID');
    const changed = archive.entries.map(([name, bytes]: [string, Buffer]) => name === 'index.json' ? [name, Buffer.concat([Buffer.from(bytes), Buffer.from('\n')])] : [name, bytes]);
    await writeFile(file, fixtureTar(changed));
    await expect(verifyOciClosure(file, { ...expected, indexDigest })).rejects.toThrow('index receipt');
    // Optional legacy verification still traverses the complete blob graph.
    expect(await verifyOciClosure(file, expected)).toMatchObject({ manifestDigest: image.digest, configDigest: image.configDigest, indexDigest: digest(Buffer.concat([Buffer.from(index), Buffer.from('\n')])) });
  }));

  it('admits Apple local closure under a native lock and never issues a registry fetch', async () => fixture(async root => {
    const { image, archive, config } = imageFixture(); const executable = path.join(root, 'container'); const kernel = path.join(root, 'kernel'); const state = path.join(root, 'state'); await mkdir(state, { mode: 0o700 }); await writeFile(executable, 'apple binary'); await writeFile(kernel, 'kernel');
    const commands: string[][] = []; let present = true; const localImage = { configuration: { name: image.reference, descriptor: { digest: image.digest } }, variants: [{ platform: { architecture: 'arm64', os: 'linux' }, digest: image.digest, config }] };
    const runner: typeof runCommand = async (_executable, args) => {
      commands.push([...args]);
      if (args[0] === 'image' && args[1] === 'list') return success(present ? [localImage] : []);
      if (args[0] === 'image' && args[1] === 'inspect') return success([localImage]);
      if (args[0] === 'image' && args[1] === 'save') { await writeFile(args[args.indexOf('--output') + 1]!, archive.bytes); return success(); }
      if (args[0] === 'inspect') return success([]);
      throw new Error('unexpected provider operation');
    };
    const receipt = { schema_version: 1 as const, engine: { executable, binarySha256: digest('apple binary') }, initImage: image, kernel: { path: kernel, sha256: digest('kernel') }, guard, stateRoot: await import('node:fs/promises').then(fs => fs.realpath(state)) };
    const runtime = await admitAppleRuntime(receipt, image, runner); expect(appleExecutionAvailability(runtime).ready).toBe(true);
    expect(appleExecutionAvailability({ ...runtime }).ready).toBe(false);
    expect(runtime.no_pull_atomic).toBe(false); expect(runtime.rootless).toBeNull();
    const args = appleCreateArguments(runtime, { name: `ud-agent-${'a'.repeat(8)}-1234-1234-1234-${'b'.repeat(12)}-worker`, jobId: `${'a'.repeat(8)}-1234-1234-1234-${'b'.repeat(12)}`, volume: `ud-agent-${'a'.repeat(8)}-1234-1234-1234-${'b'.repeat(12)}-input`, readOnlyInput: true, command: ['-c', 'pass'] });
    expect(args).toContain('--kernel'); expect(args).toContain('--init-image'); expect(args).not.toContain('--pull=never');
    await withAppleRuntime(runtime, command => command(['inspect', 'owned']), runner);
    expect(commands.some(command => command.includes('pull') || command.includes('run'))).toBe(false);
    present = false; const before = commands.length;
    await expect(withAppleRuntime(runtime, command => command(['create', 'never']), runner)).rejects.toThrow('LOCAL_IMAGE_CLOSURE_MISSING');
    expect(commands.slice(before).some(command => command[0] === 'create')).toBe(false);
    await writeFile(kernel, 'corrupt'); await expect(withAppleRuntime(runtime, async () => null, runner)).rejects.toThrow('digest');
    expect(appleLocalImageIdentity([{ configuration: { name: image.reference, descriptor: { digest: digest('other') } } }], image)).toBe(false);
  }));

  it('verifies Lima host and guest identities and uses dedicated native nerdctl inspection', async () => fixture(async root => {
    const executable = path.join(root, 'limactl'); await writeFile(executable, 'lima');
    const receipt = { schema_version: 1 as const, executable, binarySha256: digest('lima'), instance: 'ud-agent', nerdctl: '/usr/local/bin/nerdctl', nerdctlSha256: digest('nerdctl'), containerd: '/usr/local/bin/containerd', containerdSha256: digest('containerd'), address: '/run/user/1000/containerd/containerd.sock', guestUid: 1000, guestHome: '/home/test', architecture: 'arm64' as const };
    const commands: string[][] = []; let uid = '1000'; let boot = '11111111-1111-4111-8111-111111111111';
    const runner: typeof runCommand = async (_executable, args) => {
      commands.push([...args]); if (args[0] === '--version') return success('limactl version 2.0.0\n'); if (args[0] === 'list') return success([{ name: 'ud-agent', status: 'Running', arch: 'aarch64', vmType: 'vz' }]);
      if (args.includes('/usr/bin/id')) return success(`${uid}\n`);
      if (args.includes('/proc/sys/kernel/random/boot_id')) return success(`${boot}\n`);
      if (args.includes('/usr/bin/sha256sum')) return success(`${receipt.nerdctlSha256.slice(7)}  ${receipt.nerdctl}\n${receipt.containerdSha256.slice(7)}  ${receipt.containerd}\n`);
      if (args.includes('info')) return success({ Rootless: true, Namespace: 'ud-agent', Snapshotter: 'overlayfs', CgroupManager: 'systemd', Daemon: {} });
      return success('container');
    };
    const runtime = await admitLimaRuntime(receipt, runner); await limaCommand(runtime, ['ps'], undefined, runner);
    expect(runtime.rootless).toBe(true);
    expect(platformIsolation(runtime)).toEqual({ rootless: null, guest_rootless: true, isolation_model: 'rootless_oci_in_vm', virtual_machine: { name: 'ud-agent', fingerprint: runtime.identity, boot_id: '11111111-1111-4111-8111-111111111111' } });
    expect(commands.at(-1)).toEqual(expect.arrayContaining(['NERDCTL_TOML=/dev/null', '--namespace', 'ud-agent', '--address', receipt.address]));
    expect(limaShellArguments(receipt, ['/usr/bin/id'])).not.toContain('--start');
    uid = '0'; await expect(limaCommand(runtime, ['ps'], undefined, runner)).rejects.toThrow('GUEST_USER_CHANGED');
    uid = '1000'; boot = '22222222-2222-4222-8222-222222222222'; await expect(limaCommand(runtime, ['ps'], undefined, runner)).rejects.toThrow('GUEST_BOOT_CHANGED');
    await expect(limaCommand({ ...runtime }, ['ps'], undefined, runner)).rejects.toThrow('AUTHORITY_REQUIRED');
    const { image, config, manifest } = imageFixture();
    expect(limaImageIdentity([{ Image: { name: image.reference, target: { digest: image.digest } }, ManifestDesc: { digest: image.digest }, ImageConfigDesc: { digest: image.configDigest }, ImageConfig: config }], image, 'arm64')).toBe(image.reference);
    expect(limaImageIdentity([{ ManifestDesc: { digest: manifest.config.digest } }], image, 'arm64')).toBeUndefined();
    const args = limaCreateArguments({ name: `ud-agent-${'a'.repeat(36)}-worker`, jobId: 'a'.repeat(36), image: image.reference, volume: `ud-agent-${'a'.repeat(36)}-input`, command: ['-c', 'pass'], readOnlyInput: true }); expect(args).toContain('--pull=never'); expect(args).toContain('--pids-limit');
    expect(inspectLimaJob([], { id: 'x', jobId: 'x', image: image.reference, command: [], readOnlyInput: true })).toEqual(expect.arrayContaining(['identity', 'process', 'limits', 'input']));
  }));

  it('owns WSL sessions with null rootlessness and does not invent Docker-only flags', async () => fixture(async root => {
    const executable = path.join(root, 'wslc'); const sdk = path.join(root, 'wslcsdk.dll'); await writeFile(executable, 'wsl'); await writeFile(sdk, 'sdk');
    const calls: string[][] = []; let alive = true; let closed = 0; const runner: typeof runCommand = async (_exe, args) => { calls.push([...args]); return success(args[0] === 'version' ? 'wslc 3.0.5\n' : args.includes('info') ? { Server: { Sessions: [{ ID: 42, CreatorPid: 100, Name: args[1] }] } } : '{}'); };
    const runtime = await admitWslcRuntime({ schema_version: 1, executable, binarySha256: digest('wsl'), sdk, sdkSha256: digest('sdk'), guard, storage: root, architecture: 'arm64' }, runner, async () => ({ alive: () => alive, close: async () => { closed++; alive = false; } }));
    expect(runtime.rootless).toBeNull(); await wslcCommand(runtime, ['image', 'inspect', 'owned'], undefined, runner); expect(calls.at(-1)?.slice(0, 2)).toEqual(['--session', runtime.session]);
    const { image } = imageFixture(); const args = wslcCreateArguments({ name: `ud-agent-${'a'.repeat(36)}-worker`, jobId: 'a'.repeat(36), image: image.reference, volume: `ud-agent-${'a'.repeat(36)}-input`, command: ['-c', 'pass'], readOnlyInput: true });
    expect(args).toContain('never'); expect(args).not.toContain('--read-only'); expect(args).not.toContain('--security-opt');
    expect(inspectWslcJob([], { id: 'x', name: 'x', jobId: 'x', imageId: image.configDigest, volume: 'x', command: [], readOnlyInput: true })).toEqual(expect.arrayContaining(['identity', 'process', 'limits', 'input']));
    await closeWslcRuntime(runtime); expect(closed).toBe(1); await expect(wslcCommand(runtime, ['ps'], undefined, runner)).rejects.toThrow('AUTHORITY_REQUIRED');
  }));
});
