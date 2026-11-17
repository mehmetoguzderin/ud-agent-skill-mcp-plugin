import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { admitLimaRuntime, bindLimaOfflineImage, limaImageIdentity, limaVolumeIdentity } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import type { LimaRuntimeReceipt } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import type { ImageReceipt } from '../../packages/runtime-manager/src/receipt.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

const sha = (value: string | Buffer) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const directory = path.resolve('tests/fixtures/lima-native');
const source = JSON.parse(await readFile(path.join(directory, 'receipt.json'), 'utf8'));
const manifestBytes = await readFile(path.join(directory, 'manifest.json'));
const indexBytes = await readFile(path.join(directory, 'index.json'));
const manifest = JSON.parse(manifestBytes.toString('utf8'));
const index = JSON.parse(indexBytes.toString('utf8'));
const raw = source.image;
const image: ImageReceipt = { reference: raw.reference, digest: raw.digest, configDigest: raw.config_digest, diffIds: raw.diff_ids, contextSha256: sha('captured-context'), transports: raw.transports.map((item: Record<string, unknown>) => ({ ...item, ...(item.index_digest ? { indexDigest: item.index_digest } : {}) })) };
const clone = <T>(value: T): T => structuredClone(value);
const success = (value: unknown = '') => ({ code: 0, stdout: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)), stderr: Buffer.alloc(0) });
const knownImport = `import@${image.digest}`;

describe('captured native Lima image identity', () => {
  it('binds actual immutable native records to their exact imported names and full selected graph', () => {
    expect(sha(manifestBytes).slice(7)).toBe(source.files['manifest.json']);
    expect(sha(indexBytes).slice(7)).toBe(source.files['index.json']);
    expect(manifest[0].Image.Name).toBe(knownImport);
    expect(limaImageIdentity(manifest, image, 'arm64')).toBeUndefined();
    expect(limaImageIdentity(manifest, { ...image, reference: knownImport }, 'arm64')).toBe(knownImport);
    const indexName = `import@${raw.transports[1].index_digest}`;
    expect(limaImageIdentity(index, { ...image, reference: indexName }, 'arm64')).toBe(indexName);
    const named = clone(manifest); named[0].Image.Name = image.reference;
    expect(limaImageIdentity(named, image, 'arm64')).toBe(image.reference);
    const namedIndex = clone(index); namedIndex[0].Image.Name = image.reference;
    expect(limaImageIdentity(namedIndex, image, 'arm64')).toBe(image.reference);
    expect(limaImageIdentity([...manifest, ...named], image, 'arm64')).toBe(image.reference);
    expect(limaImageIdentity([...named, ...named], image, 'arm64')).toBeUndefined();
    const unprojected = clone(named); unprojected[0].ImageConfig.rootfs.diff_ids = image.diffIds;
    expect(limaImageIdentity(unprojected, image, 'arm64')).toBe(image.reference);
  });

  it('rejects conflicts, foreign aliases, target/index substitutions and changed selected config or layers', () => {
    const invalid: Array<(value: typeof manifest) => void> = [
      value => { value[0].Image.name = knownImport; },
      value => { value[0].Image.target = value[0].Image.Target; },
      value => { delete value[0].Image.Target; },
      value => { value[0].Image.Name = 'foreign@' + image.digest; },
      value => { value[0].ManifestDesc.digest = sha('foreign-manifest'); },
      value => { value[0].ImageConfigDesc.digest = sha('foreign-config'); },
      value => { value[0].ImageConfig.architecture = 'amd64'; },
      value => { value[0].ImageConfig.os = 'windows'; },
      value => { value[0].ImageConfig.rootfs.type = 'unknown'; },
      value => { value[0].ImageConfig.rootfs.diff_ids.reverse(); },
      value => { value[0].Manifest.config.digest = sha('foreign-config'); },
      value => { value[0].Manifest.layers.pop(); },
      value => { value[0].Manifest.layers[0].digest = 'invalid'; },
    ];
    for (const change of invalid) { const value = clone(manifest); change(value); expect(limaImageIdentity(value, { ...image, reference: knownImport }, 'arm64')).toBeUndefined(); }
    for (const change of [
      (value: typeof index) => { value[0].IndexDesc.digest = sha('foreign-index'); },
      (value: typeof index) => { value[0].Image.Target.digest = value[0].IndexDesc.digest = sha('foreign-index'); value[0].Image.Name = `import@${sha('foreign-index')}`; },
      (value: typeof index) => { value[0].Index.manifests = []; },
      (value: typeof index) => { value[0].Index.schemaVersion = 1; },
    ]) { const value = clone(index); change(value); expect(limaImageIdentity(value, { ...image, reference: value[0].Image.Name }, 'arm64')).toBeUndefined(); }
  });
});

describe('Lima local-only image naming', () => {
  async function fixture(test: (context: { receipt: LimaRuntimeReceipt; runner: typeof runCommand; commands: string[][]; alter: (value: string) => void }) => Promise<void>, withCtr = true) {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-lima-image-')));
    try {
      const executable = path.join(root, 'limactl'); await writeFile(executable, 'lima fixture');
      const receipt: LimaRuntimeReceipt = { schema_version: 1, executable, binarySha256: sha('lima fixture'), instance: 'ud-agent', nerdctl: '/usr/local/bin/nerdctl', nerdctlSha256: sha('nerdctl'), containerd: '/usr/local/bin/containerd', containerdSha256: sha('containerd'), address: '/run/user/1001/containerd/containerd.sock', guestUid: 1001, guestHome: '/home/udagent', architecture: 'arm64', ...(withCtr ? { ctr: '/usr/local/bin/ctr', ctrSha256: sha('ctr') } : {}) };
      const commands: string[][] = []; let mode = 'unbound'; let bound = false;
      const runner: typeof runCommand = async (_executable, args) => {
        commands.push([...args]);
        if (args[0] === '--version') return success('limactl version 2.3.0\n');
        if (args[0] === 'list') return success([{ name: 'ud-agent', status: 'Running', arch: 'aarch64', vmType: 'vz' }]);
        if (args.includes('/usr/bin/id')) return success('1001\n');
        if (args.includes('/usr/bin/sha256sum')) return success([`${receipt.nerdctlSha256.slice(7)}  ${receipt.nerdctl}`, `${receipt.containerdSha256.slice(7)}  ${receipt.containerd}`, ...(receipt.ctr ? [`${(mode === 'changed-ctr' ? sha('changed') : receipt.ctrSha256!).slice(7)}  ${receipt.ctr}`] : [])].join('\n') + '\n');
        if (args.includes('/proc/sys/kernel/random/boot_id')) return success('11111111-1111-4111-8111-111111111111\n');
        if (args.includes('info')) return success({ Rootless: true, Namespace: 'ud-agent', Snapshotter: 'overlayfs', CgroupManager: 'systemd', Daemon: {} });
        if (args.includes('inspect')) {
          const value = clone(manifest);
          if (args.at(-1) === knownImport) { if (mode === 'corrupt-import') value[0].ImageConfig.rootfs.diff_ids = []; return success(value); }
          if (bound || mode === 'bound' || mode === 'conflict') value[0].Image.Name = image.reference;
          if (mode === 'conflict' || mode === 'post-corrupt' && bound) value[0].ImageConfigDesc.digest = sha('wrong');
          return success(bound ? [...manifest, ...value] : value);
        }
        if (args.includes('/usr/local/bin/ctr')) { if (mode === 'tag-failed') return { ...success(), code: 1 }; bound = true; return success(); }
        throw new Error(`Unexpected Lima fixture command: ${JSON.stringify(args)}`);
      };
      await test({ receipt, runner, commands, alter: value => { mode = value; } });
    } finally { await rm(root, { recursive: true, force: true }); }
  }

  it('creates only the exact publisher name with pinned ctr and verifies the resulting local graph', async () => fixture(async ({ receipt, runner, commands }) => {
    const runtime = await admitLimaRuntime(receipt, runner);
    expect(runtime.identity).toContain(receipt.ctrSha256);
    expect(await bindLimaOfflineImage(runtime, image, runner)).toEqual({ bound: true, reference: image.reference });
    const tag = commands.filter(args => args.includes('/usr/local/bin/ctr') && args.includes('images') && args.includes('tag'));
    expect(tag).toHaveLength(1);
    expect(tag[0]!.slice(tag[0]!.indexOf('/usr/local/bin/ctr'))).toEqual(['/usr/local/bin/ctr', '--address', receipt.address, '--namespace', 'ud-agent', 'images', 'tag', knownImport, image.reference]);
    expect(commands.some(args => args.includes('pull') || args.includes('--force') || args.includes('tag') && args.includes(receipt.nerdctl))).toBe(false);
    const before = commands.length;
    expect(await bindLimaOfflineImage(runtime, image, runner)).toEqual({ bound: false, reference: image.reference });
    expect(commands.slice(before).some(args => args.includes('tag'))).toBe(false);
  }));

  it('preserves foreign names and rejects corrupt imports, changed tools and failed or unverifiable tags', async () => {
    for (const [mode, code] of [['conflict', 'LIMA_IMAGE_IDENTITY_INVALID'], ['corrupt-import', 'LIMA_IMPORTED_IMAGE_IDENTITY_INVALID'], ['changed-ctr', 'LIMA_GUEST_EXECUTABLE_CHANGED'], ['tag-failed', 'LIMA_LOCAL_TAG_FAILED'], ['post-corrupt', 'LIMA_IMAGE_IDENTITY_INVALID']]) await fixture(async ({ receipt, runner, commands, alter }) => {
      const runtime = await admitLimaRuntime(receipt, runner); alter(mode!);
      await expect(bindLimaOfflineImage(runtime, image, runner)).rejects.toThrow(code);
      if (!['tag-failed', 'post-corrupt'].includes(mode!)) expect(commands.some(args => args.includes('tag'))).toBe(false);
    });
    await fixture(async ({ receipt, runner, commands }) => {
      const runtime = await admitLimaRuntime(receipt, runner);
      await expect(bindLimaOfflineImage(runtime, image, runner)).rejects.toThrow('LIMA_LOCAL_TAG_HELPER_REQUIRED');
      expect(commands.some(args => args.includes('tag'))).toBe(false);
      await expect(bindLimaOfflineImage({ ...runtime }, image, runner)).rejects.toThrow('LIMA_AUTHORITY_REQUIRED');
    }, false);
  });
});

it('cross-checks native driver inventory against exact inspected volume identity and journal label', () => {
  const jobId = 'e884a670-500c-4650-bc7f-ba790b48ec6c', name = `ud-agent-${jobId}-input`;
  const source = `/home/udagent/.local/share/nerdctl/e3456513/volumes/ud-agent/${name}/_data`;
  const inspected = [{ Name: name, Mountpoint: source, Labels: { 'io.ud-agent.job': jobId } }];
  const listing = [{ Name: name, Driver: 'local', Mountpoint: source, Labels: `io.ud-agent.job=${jobId}` }];
  expect(limaVolumeIdentity(inspected, listing, { name, jobId })).toBe(source);
  for (const fields of [{ Name: 'foreign' }, { Mountpoint: '/elsewhere' }, { Driver: 'plugin' }]) expect(limaVolumeIdentity(inspected, [{ ...listing[0], ...fields }], { name, jobId })).toBeUndefined();
  expect(limaVolumeIdentity(inspected, [...listing, ...listing], { name, jobId })).toBeUndefined();
  for (const fields of [{ Name: 'foreign' }, { Mountpoint: '../escape' }, { Mountpoint: '/a/../b' }, { Mountpoint: '/a\0b' }, { Labels: { 'io.ud-agent.job': 'foreign' } }, { Driver: 'plugin' }]) expect(limaVolumeIdentity([{ ...inspected[0], ...fields }], listing, { name, jobId })).toBeUndefined();
});
