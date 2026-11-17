import { describe, expect, it, vi } from 'vitest';
import { access, chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
// Mac adapter policy uses inert engine responses, with physical fixture file lookup.
vi.mock('node:fs/promises', async original => (await import('./posix-policy-fixture.js')).posixPolicyFixture(await original<typeof import('node:fs/promises')>()));
vi.mock('../../packages/runtime-manager/src/profiles.js', async original => (await import('./posix-policy-fixture.js')).physicalExecutablePolicyFixture(await original<typeof import('../../packages/runtime-manager/src/profiles.js')>()));
import { appleExecutionAvailability, appleImageIsPresent, importAppleOfflineImage } from '../../packages/runtime-manager/src/apple.js';
import { loadAppleEngineReceipt, verifyAppleEngine } from '../../packages/runtime-manager/src/apple-engine.js';
import { setupEnvironment } from '../../packages/runtime-manager/src/environment.js';
import type { ImageReceipt } from '../../packages/runtime-manager/src/receipt.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';
import { createOciFixture } from '../release/oci-fixture.mjs';

const hash = (value: string | Buffer) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

describe('Apple Container offline provisioning', () => {
  it('binds an unannotated import only through the exact local platform and rootfs identity', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-apple-untagged-'));
    try {
      const executable = path.join(root, 'container'); const archive = path.join(root, 'image.tar'); await writeFile(executable, 'binary'); const oci = createOciFixture('untagged'); await writeFile(archive, oci.bytes); const digest = oci.platforms['linux/arm64'];
      const manifest = JSON.parse(Buffer.from(oci.entries.find(([name]: [string, unknown]) => name === `blobs/sha256/${digest.slice(7)}`)![1]).toString()); const config = JSON.parse(Buffer.from(oci.entries.find(([name]: [string, unknown]) => name === `blobs/sha256/${manifest.config.digest.slice(7)}`)![1]).toString());
      const receipt: ImageReceipt = { digest, reference: `ghcr.io/mehmetoguzderin/core@${digest}`, contextSha256: hash('context'), configDigest: manifest.config.digest, diffIds: config.rootfs.diff_ids, transportSha256: hash(oci.bytes), transportSizeBytes: oci.bytes.length, transportIndexDigest: oci.index_digest };
      const beforeImport: string[][] = [];
      const missing: typeof runCommand = async (_exe, args) => { beforeImport.push([...args]); return { code: 0, stdout: Buffer.from('[]'), stderr: Buffer.alloc(0) }; };
      await expect(importAppleOfflineImage({ executable, binarySha256: hash('binary') }, { ...receipt, transportIndexDigest: hash('wrong per-arch index') }, archive, missing)).rejects.toThrow('index receipt');
      expect(beforeImport).toEqual([['image', 'list', '--format', 'json']]);
      for (const valid of [true, false]) {
        let loaded = false; let tagged = false; const calls: string[][] = [];
        const runner: typeof runCommand = async (_exe, args) => { calls.push([...args]); if (args[1] === 'load') { loaded = true; return { code: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }; } if (args[1] === 'tag') { expect(args).toEqual(['image', 'tag', `untagged@${digest}`, receipt.reference]); tagged = true; return { code: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }; } const entry = { configuration: { name: tagged ? receipt.reference : `untagged@${digest}`, descriptor: { digest: oci.index_digest } }, variants: [{ digest, platform: { os: 'linux', architecture: 'arm64' }, config: valid ? config : { ...config, rootfs: { ...config.rootfs, diff_ids: [hash('wrong layer')] } } }] }; return { code: 0, stdout: Buffer.from(JSON.stringify(loaded ? [entry] : [])), stderr: Buffer.alloc(0) }; };
        if (valid) expect(await importAppleOfflineImage({ executable, binarySha256: hash('binary') }, receipt, archive, runner)).toEqual({ imported: true, digest }); else await expect(importAppleOfflineImage({ executable, binarySha256: hash('binary') }, receipt, archive, runner)).rejects.toThrow('identity');
        expect(calls.filter(args => args[1] === 'tag')).toHaveLength(valid ? 1 : 0); expect(calls.some(args => args.includes('pull'))).toBe(false);
      }
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it('callbackless setup rejects missing runtime authority before any imports', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-apple-setup-'));
    try {
      await mkdir(path.join(root, 'bin')); await mkdir(path.join(root, 'runtime')); await mkdir(path.join(root, 'runtime', 'images'));
      const executable = path.join(root, 'bin', 'container' + (process.platform === 'win32' ? '.exe' : '')); await writeFile(executable, 'signed binary'); await chmod(executable, 0o700);
      await writeFile(path.join(root, 'runtime', 'images', 'core-linux-arm64.tar'), 'accepted image');
      const digest = `sha256:${'1'.repeat(64)}`;
      const reference = `ghcr.io/mehmetoguzderin/ud-core@${digest}`;
      await writeFile(path.join(root, 'runtime', 'runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: { core: { context_sha256: `sha256:${'2'.repeat(64)}`, images: { 'linux/arm64': { digest, reference, transport_sha256: hash('accepted image'), transport_size_bytes: 14 } } } } }));
      await writeFile(path.join(root, 'runtime', 'engine-distributions.lock.json'), JSON.stringify({ schema_version: 1, state: 'frozen', engines: { 'apple-container': { 'darwin/arm64': { version: '1.0.0', binary_sha256: hash('signed binary'), publisher_team_id: 'ABCDEFGHIJ', signing_identifier: 'example.container' } } } }));
      let loaded = false; const commands: string[][] = [];
      const runner: typeof runCommand = async (binary, args) => {
        commands.push([binary, ...args]);
        if (binary === '/usr/bin/codesign') return { code: 0, stdout: Buffer.alloc(0), stderr: Buffer.from(args[0] === '-d' ? 'Identifier=example.container\nTeamIdentifier=ABCDEFGHIJ\n' : '') };
        if (args[1] === 'list') return { code: 0, stdout: Buffer.from(JSON.stringify(loaded ? [{ reference, descriptor: { digest } }] : [])), stderr: Buffer.alloc(0) };
        if (args[1] === 'load') { loaded = true; return { code: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }; }
        throw new Error('unexpected engine operation');
      };
      const result = await setupEnvironment({ network: 'offline' }, [{ id: '048', name: 'validation_report', runtime_pack: 'core' }], { sourceRoot: root, userspaceStateRoot: path.join(root, 'state'), searchPath: path.join(root, 'bin'), host: { platform: 'darwin', arch: 'arm64' }, appleRunner: runner });
      expect(result).toMatchObject({ ready: false, status: 'blocked_by_policy' });
      expect(result.imported_images).toBeUndefined();
      expect(commands).toEqual([]);
      expect(commands.some(command => command.includes('run') || command.includes('pull'))).toBe(false);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('requires a frozen engine receipt, exact binary bytes, and matching OS signature identity', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-apple-engine-'));
    try {
      const executable = path.join(root, 'container'); await writeFile(executable, 'signed binary');
      await mkdir(path.join(root, 'runtime'));
      const lock = { schema_version: 1, state: 'frozen', engines: { 'apple-container': { 'darwin/arm64': {
        version: '1.0.0', binary_sha256: hash('signed binary'), publisher_team_id: 'ABCDEFGHIJ', signing_identifier: 'example.container',
      } } } };
      const file = path.join(root, 'runtime', 'engine-distributions.lock.json');
      await writeFile(file, JSON.stringify(lock));
      const receipt = await loadAppleEngineReceipt(root);
      const runner: typeof runCommand = async (command, args, options) => {
        expect(command).toBe('/usr/bin/codesign');
        expect(args.at(-1)).toBe(executable);
        expect(options.supervisor).toBeUndefined();
        return { code: 0, stdout: Buffer.alloc(0), stderr: Buffer.from(args[0] === '-d' ? 'Identifier=example.container\nTeamIdentifier=ABCDEFGHIJ\n' : '') };
      };
      expect(await verifyAppleEngine(executable, receipt, runner)).toEqual({ executable, binarySha256: hash('signed binary') });
      const wrongTeam: typeof runCommand = async () => ({ code: 0, stdout: Buffer.alloc(0), stderr: Buffer.from('Identifier=example.container\nTeamIdentifier=DIFFERENT0\n') });
      await expect(verifyAppleEngine(executable, receipt, wrongTeam)).rejects.toThrow('publisher');
      lock.state = 'unbuilt'; await writeFile(file, JSON.stringify(lock));
      await expect(loadAppleEngineReceipt(root)).rejects.toThrow('ENGINE_RECEIPT_NOT_FROZEN');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('imports only verified bytes from private scratch, inspects the exact image, and cleans staging', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-apple-import-'));
    try {
      const executable = path.join(root, 'container'); const archive = path.join(root, 'image.tar');
      await writeFile(executable, 'trusted engine binary'); await writeFile(archive, 'accepted image');
      const digest = `sha256:${'a'.repeat(64)}`;
      const receipt: ImageReceipt = { digest, reference: `ghcr.io/mehmetoguzderin/ud-core@${digest}`, contextSha256: `sha256:${'b'.repeat(64)}`, transportSha256: hash('accepted image'), transportSizeBytes: 14 };
      let loaded = false; let stagedPath = ''; const commands: string[][] = [];
      const runner: typeof runCommand = async (_exe, args) => {
        commands.push([...args]);
        if (args[0] === 'image' && args[1] === 'list') return { code: 0, stdout: Buffer.from(JSON.stringify(loaded ? [{ reference: receipt.reference, descriptor: { digest } }] : [])), stderr: Buffer.alloc(0) };
        if (args[0] === 'image' && args[1] === 'load') {
          stagedPath = args[3] ?? '';
          expect(await readFile(stagedPath, 'utf8')).toBe('accepted image');
          expect((await stat(stagedPath)).mode & 0o077).toBe(0);
          loaded = true;
          return { code: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
        }
        throw new Error('unexpected command');
      };
      expect(await importAppleOfflineImage({ executable, binarySha256: hash('trusted engine binary') }, receipt, archive, runner)).toEqual({ imported: true, digest });
      expect(commands.map(command => command.slice(0, 2))).toEqual([['image', 'list'], ['image', 'load'], ['image', 'list']]);
      await expect(access(stagedPath)).rejects.toThrow();
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('reuses an exact local descriptor but rejects same-name wrong-digest images', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-apple-existing-'));
    try {
      const executable = path.join(root, 'container'); await writeFile(executable, 'binary');
      const digest = `sha256:${'c'.repeat(64)}`;
      const receipt: ImageReceipt = { digest, reference: `ghcr.io/mehmetoguzderin/ud-core@${digest}`, contextSha256: `sha256:${'d'.repeat(64)}` };
      expect(appleImageIsPresent([{ reference: receipt.reference, descriptor: { digest: `sha256:${'0'.repeat(64)}` } }], receipt)).toBe(false);
      const runner: typeof runCommand = async () => ({ code: 0, stdout: Buffer.from(JSON.stringify([{ reference: receipt.reference, descriptor: { digest } }])), stderr: Buffer.alloc(0) });
      expect(await importAppleOfflineImage({ executable, binarySha256: hash('binary') }, receipt, path.join(root, 'missing'), runner)).toEqual({ imported: false, digest });
      expect(appleExecutionAvailability()).toMatchObject({ ready: false, code: 'APPLE_NO_PULL_UNVERIFIED' });
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('admits only the owned local init namespace through the explicit init path', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-apple-init-'));
    try {
      const executable = path.join(root, 'container'); await writeFile(executable, 'binary');
      const digest = `sha256:${'c'.repeat(64)}`;
      const receipt: ImageReceipt = { digest, reference: `localhost/ud-agent-skill-mcp-plugin-init@${digest}`, contextSha256: `sha256:${'d'.repeat(64)}` };
      const runner: typeof runCommand = async () => ({ code: 0, stdout: Buffer.from(JSON.stringify([{ reference: receipt.reference, descriptor: { digest } }])), stderr: Buffer.alloc(0) });
      expect(await importAppleOfflineImage({ executable, binarySha256: hash('binary') }, receipt, path.join(root, 'missing'), runner, 'init')).toEqual({ imported: false, digest });
      await expect(importAppleOfflineImage({ executable, binarySha256: hash('binary') }, receipt, path.join(root, 'missing'), runner)).rejects.toThrow('publisher');
      await expect(importAppleOfflineImage({ executable, binarySha256: hash('binary') }, { ...receipt, reference: `localhost/unrelated@${digest}` }, path.join(root, 'missing'), runner, 'init')).rejects.toThrow('publisher');
      await expect(importAppleOfflineImage({ executable, binarySha256: hash('binary') }, { ...receipt, reference: `ghcr.io/apple/containerization/vminit@${digest}` }, path.join(root, 'missing'), runner, 'init')).rejects.toThrow('publisher');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('never invokes image load for a mismatched archive or unverified engine', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-apple-invalid-'));
    try {
      const executable = path.join(root, 'container'); const archive = path.join(root, 'image.tar');
      await writeFile(executable, 'binary'); await writeFile(archive, 'wrong');
      const digest = `sha256:${'e'.repeat(64)}`;
      const receipt: ImageReceipt = { digest, reference: `ghcr.io/mehmetoguzderin/ud-core@${digest}`, contextSha256: `sha256:${'f'.repeat(64)}`, transportSha256: hash('right'), transportSizeBytes: 5 };
      const commands: string[] = [];
      const runner: typeof runCommand = async (_exe, args) => { commands.push(args[1] ?? ''); return { code: 0, stdout: Buffer.from('[]'), stderr: Buffer.alloc(0) }; };
      await expect(importAppleOfflineImage({ executable, binarySha256: hash('binary') }, receipt, archive, runner)).rejects.toThrow('digest');
      expect(commands).toEqual(['list']);
      await expect(importAppleOfflineImage({ executable, binarySha256: hash('bad binary') }, receipt, archive, runner)).rejects.toThrow('digest');
      expect(commands).toEqual(['list']);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
