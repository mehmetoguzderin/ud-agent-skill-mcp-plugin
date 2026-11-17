import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { inspectLima, parseLimaInstances, LIMA_INSTANCE_FORMAT } from '../../packages/runtime-manager/src/lima.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

const digest = (value: string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const ok = (value: string) => ({ code: 0, stdout: Buffer.from(value), stderr: Buffer.alloc(0) });

async function fixture<T>(run: (engine: { executable: string; binarySha256: string }) => Promise<T>): Promise<T> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ud-lima-'));
  try {
    const executable = path.join(root, 'limactl');
    await writeFile(executable, 'verified lima binary');
    return await run({ executable, binarySha256: digest('verified lima binary') });
  } finally { await rm(root, { recursive: true, force: true }); }
}

describe('Lima inventory', () => {
  it('parses upstream JSON lines and arrays without treating VM status as rootlessness', () => {
    const input = [
      { name: 'default', status: 'Running', arch: 'x86_64', vmType: 'qemu', dir: '/private/path', network: ['opaque'] },
      { name: 'stopped', status: 'Stopped', arch: 'aarch64', vmType: 'vz' },
      { name: 'unknown', status: 'Broken', arch: 'riscv64', vmType: 'custom' },
    ];
    const expected = [
      { name: 'default', status: 'running', arch: 'amd64', vm_type: 'qemu' },
      { name: 'stopped', status: 'stopped', arch: 'arm64', vm_type: 'vz' },
      { name: 'unknown', status: 'other', arch: null, vm_type: null },
    ];
    expect(parseLimaInstances(Buffer.from(input.map(row => JSON.stringify(row)).join('\n')))).toEqual(expected);
    expect(parseLimaInstances(Buffer.from(JSON.stringify(input)))).toEqual(expected);
    expect(parseLimaInstances(Buffer.from('  \n'))).toEqual([]);
  });

  it('rejects malformed data, duplicate names, unsafe identities, invalid encoding, and overlong output', () => {
    for (const text of ['not json', '{}', '[null]', '[{"name":"-x","status":"Running"}]', '[{"name":"x","status":"Running"},{"name":"x","status":"Stopped"}]']) {
      expect(() => parseLimaInstances(Buffer.from(text))).toThrow();
    }
    expect(() => parseLimaInstances(Buffer.from([0xff]))).toThrow('UTF-8');
    expect(() => parseLimaInstances(Buffer.alloc(4 * 1024 * 1024 + 1))).toThrow('byte limit');
    expect(() => parseLimaInstances(Buffer.from(JSON.stringify(Array.from({ length: 10001 }, () => ({})))))).toThrow('instance limit');
  });

  it('uses only bounded read-only Lima commands and leaves all containment claims unverified', async () => fixture(async engine => {
    const calls: string[][] = [];
    const runner: typeof runCommand = async (exe, args, options) => {
      expect(exe).toBe(engine.executable);
      expect(options).toEqual({ timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024 });
      calls.push([...args]);
      if (args[0] === '--version') return ok('limactl version 2.1.4\n');
      return ok('{"name":"default","status":"Running","arch":"x86_64","vmType":"qemu"}\n');
    };
    const result = await inspectLima(engine, 'default', runner);
    expect(calls).toEqual([['--version'], ['list', '--format', LIMA_INSTANCE_FORMAT]]);
    expect(result).toMatchObject({ engine: 'lima-nerdctl', version: '2.1.4', selected: { name: 'default', status: 'running', arch: 'amd64' }, ready: false,
      isolation: { model: 'lima-vm', rootless_verified: null, host_isolation_verified: false, worker_uid_verified: false, network_disabled_verified: false, resource_limits_verified: false } });
    expect(result.missing).toContain('offline_execution_proof');
    expect(result.missing).toContain('verified_nerdctl_and_containerd');
  }));

  it('requires explicit selection and reports absent or stopped VMs without starting them', async () => fixture(async engine => {
    const calls: string[] = [];
    const runner: typeof runCommand = async (_exe, args) => { calls.push(args[0] ?? ''); return ok(args[0] === '--version' ? 'limactl version 2.1.4' : '{"name":"guest","status":"Stopped","arch":"x86_64"}'); };
    expect((await inspectLima(engine, undefined, runner)).missing).toContain('explicit_instance_selection');
    expect((await inspectLima(engine, 'absent', runner)).missing).toContain('selected_instance');
    expect((await inspectLima(engine, 'guest', runner)).missing).toContain('running_instance');
    expect(calls).toEqual(['--version', 'list', '--version', 'list', '--version', 'list']);
  }));

  it('rejects wrong receipts and unsafe selections before executing anything', async () => fixture(async engine => {
    const runner: typeof runCommand = async () => { throw new Error('unexpected invocation'); };
    await expect(inspectLima({ ...engine, binarySha256: digest('wrong') }, undefined, runner)).rejects.toThrow('digest');
    await expect(inspectLima({ ...engine, executable: 'limactl' }, undefined, runner)).rejects.toThrow('absolute');
    await expect(inspectLima(engine, '../guest', runner)).rejects.toThrow('instance name');
  }));

  it('rejects failed commands, changed executable bytes, and malformed version or inventory', async () => fixture(async engine => {
    const failure: typeof runCommand = async () => ({ ...ok(''), code: 1 });
    await expect(inspectLima(engine, undefined, failure)).rejects.toThrow('version inspection');
    const invalidVersion: typeof runCommand = async () => ok('something else');
    await expect(inspectLima(engine, undefined, invalidVersion)).rejects.toThrow('invalid version');
    const invalidInventory: typeof runCommand = async (_exe, args) => ok(args[0] === '--version' ? 'limactl version 2.1.4' : 'broken');
    await expect(inspectLima(engine, undefined, invalidInventory)).rejects.toThrow('invalid instance JSON');
    const changed: typeof runCommand = async () => { await writeFile(engine.executable, 'changed'); return ok('limactl version 2.1.4'); };
    await expect(inspectLima(engine, undefined, changed)).rejects.toThrow('digest');
  }));
});
