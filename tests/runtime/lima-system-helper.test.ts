import { beforeEach, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import path from 'node:path';
import * as fs from 'node:fs/promises';
import { admitLimaSshKeygen, limaProvisionRunner } from '../../packages/runtime-manager/src/lima-system-helper.js';
import type { LimaRuntimeReceipt } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, realpath: vi.fn(actual.realpath), lstat: vi.fn(actual.lstat), open: vi.fn(actual.open) };
});
const sha = (value: string) => 'sha256:' + createHash('sha256').update(value).digest('hex');
const receipt: LimaRuntimeReceipt = { schema_version: 1, executable: '/owned/limactl', binarySha256: sha('lima'), instance: 'ud-agent', nerdctl: '/usr/local/bin/nerdctl', nerdctlSha256: sha('nerdctl'), containerd: '/usr/local/bin/containerd', containerdSha256: sha('containerd'), address: '/run/user/1001/containerd/containerd.sock', guestUid: 1001, guestHome: '/home/udagent', architecture: 'arm64', home: '/owned/lima' };
const guard = '/owned/guard', guardSha = sha('guard'), executable = '/usr/bin/ssh-keygen';
const ownedKey = path.join(receipt.home!, '_config/user');
beforeEach(() => vi.resetAllMocks());

function systemFixture() {
  const bytes = Buffer.from('independent fixed OS public-key reader');
  const info = { dev: 1n, ino: 2n, mode: 0o100755n, uid: 0n, gid: 0n, nlink: 1n, size: BigInt(bytes.length), mtimeNs: 10n, ctimeNs: 11n, isFile: () => true, isSymbolicLink: () => false };
  const directory = { uid: 0, mode: 0o40755, isDirectory: () => true, isSymbolicLink: () => false };
  const close = vi.fn(async () => undefined), stat = vi.fn(async () => info);
  const read = vi.fn(async (buffer: Buffer, _offset: number, length: number, position: number) => { const part = bytes.subarray(position, position + length); part.copy(buffer); return { bytesRead: part.length, buffer }; });
  vi.mocked(fs.realpath).mockResolvedValue(executable);
  vi.mocked(fs.lstat).mockImplementation(async (file: unknown) => (file === executable ? info : directory) as never);
  vi.mocked(fs.open).mockResolvedValue({ stat, read, close } as never);
  return { bytes, info, directory, close, stat, read };
}

it('admits only canonical fixed root-owned executable bytes with stable FD and path identities', async () => {
  const fixture = systemFixture();
  expect(await admitLimaSshKeygen()).toEqual({ executable, sha256: sha(fixture.bytes.toString()) });
  expect(fs.realpath).toHaveBeenCalledWith(executable);
  expect(vi.mocked(fs.lstat).mock.calls.map(call => call[0])).toEqual(['/', '/usr', '/usr/bin', executable]);
  expect(fixture.stat).toHaveBeenCalledTimes(2); expect(fixture.close).toHaveBeenCalledOnce();
});

it('rejects aliases, writable/unowned parents and executable metadata without issuing an identity', async () => {
  for (const kind of ['alias', 'parent-link', 'parent-writable', 'parent-unowned', 'file-directory', 'file-unowned', 'file-links', 'file-writable', 'file-not-executable', 'file-empty', 'file-oversized']) {
    const fixture = systemFixture();
    if (kind === 'alias') vi.mocked(fs.realpath).mockResolvedValue('/foreign/ssh-keygen');
    if (kind === 'parent-link') fixture.directory.isSymbolicLink = () => true;
    if (kind === 'parent-writable') fixture.directory.mode |= 0o002;
    if (kind === 'parent-unowned') fixture.directory.uid = 501;
    if (kind === 'file-directory') fixture.info.isFile = () => false;
    if (kind === 'file-unowned') fixture.info.uid = 501n;
    if (kind === 'file-links') fixture.info.nlink = 2n;
    if (kind === 'file-writable') fixture.info.mode |= 0o002n;
    if (kind === 'file-not-executable') fixture.info.mode &= ~0o111n;
    if (kind === 'file-empty') fixture.info.size = 0n;
    if (kind === 'file-oversized') fixture.info.size = 128n * 1024n * 1024n + 1n;
    await expect(admitLimaSshKeygen(), kind).rejects.toThrow('LIMA_SYSTEM_HELPER_UNSAFE');
  }
});

it('rejects changed FD/path metadata, truncated bytes and growing reads, always closing its FD', async () => {
  for (const key of ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) {
    const fixture = systemFixture(); fixture.stat.mockResolvedValueOnce(fixture.info).mockResolvedValueOnce({ ...fixture.info, [key]: fixture.info[key as keyof typeof fixture.info] as bigint + 1n });
    await expect(admitLimaSshKeygen(), key).rejects.toThrow('LIMA_SYSTEM_HELPER_CHANGED'); expect(fixture.close).toHaveBeenCalledOnce();
  }
  for (const kind of ['named-link', 'named-replacement', 'short-read', 'growing-read']) {
    const fixture = systemFixture();
    if (kind.startsWith('named')) vi.mocked(fs.lstat).mockImplementation(async (file: unknown) => (file === executable ? { ...fixture.info, ...(kind === 'named-link' ? { isSymbolicLink: () => true } : { ino: 3n }) } : fixture.directory) as never);
    if (kind === 'short-read') fixture.read.mockResolvedValue({ bytesRead: 0, buffer: Buffer.alloc(0) });
    if (kind === 'growing-read') fixture.read.mockResolvedValueOnce({ bytesRead: fixture.bytes.length + 1, buffer: Buffer.alloc(1024) });
    await expect(admitLimaSshKeygen(), kind).rejects.toThrow('LIMA_SYSTEM_HELPER_CHANGED'); expect(fixture.close).toHaveBeenCalledOnce();
  }
});

it('uses the engine SHA for Lima and separately admitted system SHA for only the owned public-key query', async () => {
  const runner = vi.fn<typeof runCommand>(async () => ({ code: 0, stdout: Buffer.from('public key'), stderr: Buffer.alloc(0) }));
  const admit = vi.fn(async () => ({ executable, sha256: sha('system ssh-keygen') } as const));
  const execute = limaProvisionRunner(receipt, guard, guardSha, runner, admit);
  await execute(receipt.executable, ['list'], { timeoutMs: 1000, maxOutputBytes: 1000, limaHome: receipt.home });
  expect(admit).not.toHaveBeenCalled(); expect(runner.mock.calls[0]?.[2].supervisor).toEqual({ guard, guardSha256: guardSha, executableSha256: receipt.binarySha256 });
  for (let index = 0; index < 2; index++) await execute(executable, ['-y', '-f', ownedKey], { timeoutMs: 1000, maxOutputBytes: 1000, limaHome: receipt.home });
  expect(admit).toHaveBeenCalledOnce(); expect(runner.mock.calls[1]?.[2].supervisor).toEqual({ guard, guardSha256: guardSha, executableSha256: sha('system ssh-keygen') });
});

it('rejects unexpected executable/arguments, foreign keys or scopes and invalid admission before spawning', async () => {
  const runner = vi.fn<typeof runCommand>(); const admit = vi.fn(async () => ({ executable, sha256: sha('system') } as const));
  for (const [command, args, home, input] of [[executable, ['-y','-f','/foreign/key'], receipt.home], [executable,['-y','-f',ownedKey,'extra'],receipt.home], [executable,['-f',ownedKey],receipt.home], [executable,['-y','-f',ownedKey],'/foreign/home'], ['/bin/sh',['-c','ignored'],receipt.home], [executable,['-y','-f',ownedKey],receipt.home,Buffer.from('stdin')]] as const) {
    await expect(limaProvisionRunner(receipt, guard, guardSha, runner, admit)(command, args, { timeoutMs: 1000, maxOutputBytes: 1000, limaHome: home, ...(input ? { input } : {}) })).rejects.toThrow('UNAUTHORIZED');
  }
  expect(runner).not.toHaveBeenCalled(); expect(admit).not.toHaveBeenCalled();
  await expect(limaProvisionRunner(receipt, guard, guardSha, runner, async () => ({ executable, sha256: 'invalid' }))(executable, ['-y','-f',ownedKey], { timeoutMs: 1000, maxOutputBytes: 1000, limaHome: receipt.home })).rejects.toThrow('UNSAFE');
});
