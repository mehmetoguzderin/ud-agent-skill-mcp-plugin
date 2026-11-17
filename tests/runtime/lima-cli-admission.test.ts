import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
const fixtureState = vi.hoisted(() => ({ root: '' }));
vi.mock('node:fs/promises', async original => (await import('./posix-policy-fixture.js')).posixPolicyFixture(await original<typeof import('node:fs/promises')>()));
vi.mock('../../packages/workspace/src/journal.js', async original => (await import('./posix-policy-fixture.js')).posixJournalPolicyFixture(await original<typeof import('../../packages/workspace/src/journal.js')>(), await import('node:fs/promises'), () => fixtureState.root, ['lima-cli.json']));
import { commitLimaCli, selectLimaCli } from '../../packages/runtime-manager/src/lima-cli-admission.js';
import type { LimaCliOptions } from '../../packages/runtime-manager/src/lima-cli-admission.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

const sha = (data: Buffer | string) => `sha256:${createHash('sha256').update(data).digest('hex')}`;
const ok = (text: string) => ({ code: 0, stdout: Buffer.from(text), stderr: Buffer.alloc(0) });
async function fixture(action: (options: LimaCliOptions) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-lima-cli-')));
  fixtureState.root = root;
  try {
    const sourceRoot = path.join(root, 'product'), stateRoot = path.join(root, 'state'), executable = path.join(root, 'external-limactl');
    await mkdir(sourceRoot, { mode: 0o700 }); await mkdir(stateRoot, { mode: 0o700 });
    await writeFile(executable, 'independent installed Lima bytes', { mode: 0o700 });
    await action({ sourceRoot, stateRoot, executable, officialSha256: sha('official bundled CLI') });
  } finally { fixtureState.root = ''; await rm(root, { recursive: true, force: true }); }
}
describe('external Lima CLI admission', () => {
  it('keeps unknown external binaries read-only and unavailable without a version subprocess', async () => fixture(async options => {
    const runner: typeof runCommand = async () => { throw new Error('read-only admission must not execute an unknown CLI'); };
    expect(await selectLimaCli(options, runner)).toBeNull();
    expect(await readdir(options.stateRoot)).toEqual([]);
    await expect(selectLimaCli({ ...options, executable: path.join(options.stateRoot, 'absent') }, runner)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await selectLimaCli({ ...options, executable: `${options.executable}-absent` }, runner)).toBeNull();
  }));
  it('admits only maintained stable version syntax through the bounded sanitized command interface', async () => fixture(async options => {
    for (const version of ['2.3.0', '2.12.4', '3.0.0']) {
      const runner: typeof runCommand = async (executable, args, limits) => {
        expect(executable).toBe(options.executable); expect(args).toEqual(['--version']); expect(limits).toEqual({ timeoutMs: 5000, maxOutputBytes: 65536 });
        return ok(`limactl version ${version}\n`);
      };
      const selected = await selectLimaCli({ ...options, prepare: true }, runner);
      expect(selected).toMatchObject({ source: 'external', binarySha256: sha('independent installed Lima bytes'), version });
      expect(selected?.identity).toMatchObject({ schema_version: 1, engine: 'lima-nerdctl', executable: options.executable, version });
      expect(await readdir(options.stateRoot)).toEqual([]);
    }
    for (const text of ['limactl version 2.2.9', 'limactl version 1.99.0', 'limactl version 2.3.0-beta.1', 'limactl version 02.3.0', 'limactl version 2.3.0+unverified', 'limactl version 2.3.0\nother output', 'Lima 2.3.0', 'limactl version 9007199254740992.0.0']) {
      expect(await selectLimaCli({ ...options, prepare: true }, async () => ok(text))).toBeNull();
    }
    expect(await selectLimaCli({ ...options, prepare: true }, async () => ({ ...ok('limactl version 2.3.0'), code: 1 }))).toBeNull();
    expect(await selectLimaCli({ ...options, prepare: true }, async () => { throw new Error('COMMAND_TIMEOUT'); })).toBeNull();
  }));
  it('commits only a still-current identity and reuses its exact receipt without another version invocation', async () => fixture(async options => {
    const selected = await selectLimaCli({ ...options, prepare: true }, async () => ok('limactl version 2.3.0'));
    expect(selected).not.toBeNull(); await commitLimaCli(selected!, options.stateRoot);
    const filename = path.join(options.stateRoot, 'lima-cli.json'), before = await readFile(filename);
    expect((await lstat(filename)).mode & 0o777).toBe(0o600);
    const saved = JSON.parse(before.toString()); expect(saved.sha256).toBe(sha('independent installed Lima bytes')); expect(saved.version).toBe('2.3.0');
    const reused = await selectLimaCli(options, async () => { throw new Error('warm admission must reuse the verified version'); });
    expect(reused).toMatchObject({ binarySha256: selected!.binarySha256, version: '2.3.0', previousReceiptSha256: sha(before) });
    await commitLimaCli(reused!, options.stateRoot); expect(await readFile(filename)).toEqual(before);
    await expect(commitLimaCli(selected!, options.stateRoot)).rejects.toThrow('LIMA_CLI_ADMISSION_CONFLICT');
  }));
  it('requires explicit repair after an admitted executable changes and freezes the renewed version', async () => fixture(async options => {
    const first = await selectLimaCli({ ...options, prepare: true }, async () => ok('limactl version 2.3.0')); await commitLimaCli(first!, options.stateRoot);
    await writeFile(options.executable, 'upgraded supported Lima binary', { mode: 0o700 });
    await expect(selectLimaCli(options)).rejects.toThrow('LIMA_CLI_IDENTITY_CHANGED_REPAIR_REQUIRED');
    await expect(selectLimaCli({ ...options, prepare: true })).rejects.toThrow('LIMA_CLI_IDENTITY_CHANGED_REPAIR_REQUIRED');
    expect(await selectLimaCli({ ...options, repair: true })).toBeNull();
    const replacement = await selectLimaCli({ ...options, repair: true, prepare: true }, async () => ok('limactl version 2.4.0'));
    expect(replacement).toMatchObject({ version: '2.4.0', binarySha256: sha('upgraded supported Lima binary') }); await commitLimaCli(replacement!, options.stateRoot);
    expect(await selectLimaCli(options)).toMatchObject({ version: '2.4.0' });
  }));
  it('retains legacy official CLI admission while product-owned corruption cannot fall back', async () => fixture(async options => {
    const official = { ...options, officialSha256: sha('independent installed Lima bytes') };
    expect(await selectLimaCli(official)).toEqual({ source: 'official', binarySha256: official.officialSha256 });
    for (const root of [options.sourceRoot, options.stateRoot]) {
      const executable = path.join(root, 'owned-limactl'); await writeFile(executable, 'damaged owned CLI', { mode: 0o700 });
      for (const changes of [{}, { prepare: true }, { repair: true, prepare: true }]) await expect(selectLimaCli({ ...options, executable, ...changes })).rejects.toThrow('LIMA_OWNED_CLI_INTEGRITY_FAILED');
    }
  }));
  it('rejects unsafe executables, receipt tampering, concurrent admission and changes during probes', async () => fixture(async options => {
    await chmod(options.executable, 0o777); expect(await selectLimaCli({ ...options, prepare: true })).toBeNull(); await chmod(options.executable, 0o700);
    const alias = `${options.executable}-link`; await symlink(options.executable, alias); expect(await selectLimaCli({ ...options, executable: alias, prepare: true })).toBeNull();
    await expect(selectLimaCli({ ...options, prepare: true }, async () => { await writeFile(options.executable, 'changed during version'); return ok('unsupported output'); })).rejects.toThrow('LIMA_CLI_CHANGED_DURING_ADMISSION');
    const selected = await selectLimaCli({ ...options, prepare: true }, async () => ok('limactl version 2.3.0')); await commitLimaCli(selected!, options.stateRoot);
    const receipt = path.join(options.stateRoot, 'lima-cli.json'); await chmod(receipt, 0o644); await expect(selectLimaCli(options)).rejects.toThrow('LIMA_CLI_RECEIPT_UNSAFE'); await chmod(receipt, 0o600);
    const saved = JSON.parse(await readFile(receipt, 'utf8')); await writeFile(receipt, JSON.stringify({ ...saved, unknown: true })); await expect(selectLimaCli(options)).rejects.toThrow('LIMA_CLI_RECEIPT_INVALID');
  }));
  it('honors cancellation without turning it into an availability fallback', async () => fixture(async options => {
    const controller = new AbortController(); controller.abort();
    await expect(selectLimaCli({ ...options, signal: controller.signal, prepare: true })).rejects.toThrow('PLATFORM_SETUP_CANCELLED');
    const active = new AbortController(); await expect(selectLimaCli({ ...options, signal: active.signal, prepare: true }, async () => { active.abort(); throw new Error('COMMAND_CANCELLED'); })).rejects.toThrow('PLATFORM_SETUP_CANCELLED');
    expect(await readdir(options.stateRoot)).toEqual([]);
  }));
});
