import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { inspectWslcClient, meetsWslcMinimum, parseWslcClientVersion } from '../../packages/runtime-manager/src/wslc-inspection.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

const hash = (value: string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
async function fixture<T>(run: (input: any) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'ud-wslc-'));
  try {
    const executable = path.join(dir, 'wslc.exe');
    await writeFile(executable, 'verified client');
    return await run({ executable, expectedSha256: hash('verified client'), host: { platform: 'win32', arch: 'arm64' } });
  } finally { await rm(dir, { recursive: true, force: true }); }
}

function fake(stdout: Buffer | string, code = 0): { commands: string[][]; runner: typeof runCommand } {
  const commands: string[][] = [];
  return { commands, runner: async (_executable, args, options) => {
    commands.push([...args]);
    expect(options).toEqual({ timeoutMs: 10000, maxOutputBytes: 4096 });
    return { code, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0) };
  } };
}

describe('WSL Containers client inspection', () => {
  it('recognizes only bounded WSLc version output, including Windows UTF-16', () => {
    expect(parseWslcClientVersion(Buffer.from('wslc.exe 2.9.3.0\r\n'))).toBe('2.9.3.0');
    expect(parseWslcClientVersion(Buffer.from('wslc 3.0.1\r\n', 'utf16le'))).toBe('3.0.1');
    expect(parseWslcClientVersion(Buffer.concat([Buffer.from([255, 254]), Buffer.from('wslc 3.0.1.0', 'utf16le')]))).toBe('3.0.1.0');
    for (const invalid of ['podman 3.0.1', 'wslc 2.9.3-preview', 'wslc 2.09.3', 'wslc 2.9', 'wslc 2.9.3\n3.0.0', '']) expect(parseWslcClientVersion(Buffer.from(invalid))).toBeUndefined();
    expect(parseWslcClientVersion(Buffer.alloc(4097))).toBeUndefined();
  });
  it('compares the WSL minimum numerically', () => {
    expect(meetsWslcMinimum('2.9.2.99')).toBe(false);
    expect(meetsWslcMinimum('2.9.3')).toBe(true);
    expect(meetsWslcMinimum('2.10.0')).toBe(true);
    expect(meetsWslcMinimum('3.0.0.0')).toBe(true);
    expect(meetsWslcMinimum('2.9.3-preview')).toBe(false);
  });
  it('uses only the dedicated client version command and never claims VM or worker guarantees', async () => fixture(async input => {
    const command = fake('wslc.exe 3.0.1.0\r\n');
    const result = await inspectWslcClient({ ...input, runner: command.runner });
    expect(command.commands).toEqual([['version']]);
    expect(result).toMatchObject({ status: 'client_present_unverified', client_version: '3.0.1.0', client_hash_verified: true, minimum_version_met: true, isolation_model: 'managed-wsl-vm', rootless_verified: null, session_state: 'not_inspected', worker_uid_verified: false, networking_disabled_verified: false, resource_bounds_verified: false, image_identity_verified: false, cleanup_verified: false, production_ready: false });
  }));
  it('reports old installations and bad or interrupted version queries accurately', async () => fixture(async input => {
    const old = await inspectWslcClient({ ...input, runner: fake('wslc 2.9.2').runner });
    expect(old).toMatchObject({ status: 'host_prerequisite', minimum_version_met: false });
    for (const command of [fake('not version'), fake('wslc 2.9.3', 1), { runner: async () => { throw new Error('timeout'); } }]) {
      const result = await inspectWslcClient({ ...input, runner: command.runner });
      expect(result).toMatchObject({ status: 'inspection_incomplete', minimum_version_met: null, production_ready: false });
    }
  }));
  it('never executes on an unsupported host or with a mismatched hash', async () => fixture(async input => {
    const command = fake('wslc 3.0.1');
    const unsupported = await inspectWslcClient({ ...input, host: { platform: 'linux', arch: 'x64' }, runner: command.runner });
    expect(unsupported.status).toBe('host_prerequisite');
    await expect(inspectWslcClient({ ...input, expectedSha256: hash('different'), runner: command.runner })).rejects.toThrow();
    expect(command.commands).toEqual([]);
  }));
  it('rejects executable replacement during inspection', async () => fixture(async input => {
    const runner: typeof runCommand = async () => {
      // A different size is observable even where file timestamps are coarser
      // than this write (equal-size rewrites in one tick keep mtime/ctime).
      await writeFile(input.executable, 'modified client bytes');
      return { code: 0, stdout: Buffer.from('wslc 3.0.1'), stderr: Buffer.alloc(0) };
    };
    await expect(inspectWslcClient({ ...input, runner })).rejects.toThrow('changed during inspection');
  }));
});
