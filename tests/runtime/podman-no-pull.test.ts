import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { JobJournal } from '../../packages/runtime-manager/src/job-journal.js';
import { probePodmanNoPull } from '../../packages/runtime-manager/src/podman-no-pull.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';
import { posixTest } from '../fixtures/native-scope.mjs';

const hash = (text: string) => `sha256:${createHash('sha256').update(text).digest('hex')}`;

async function fixture<T>(action: (input: any, journal: JobJournal) => Promise<T>): Promise<T> {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-no-pull-'));
  const root = await realpath(temporary);
  try {
    await mkdir(path.join(root, 'state'), { mode: 0o700 });
    await mkdir(path.join(root, 'hooks'), { mode: 0o700 });
    const engine = path.join(root, 'podman'); const tracer = path.join(root, 'strace');
    const config = path.join(root, 'containers.conf'); const mounts = path.join(root, 'mounts.conf');
    const configText = '[containers]\nmounts = []\n[engine]\nhooks_dir = []\n';
    await writeFile(engine, 'engine'); await writeFile(tracer, 'tracer');
    await writeFile(config, configText, { mode: 0o600 }); await writeFile(mounts, '', { mode: 0o600 });
    const journal = await JobJournal.open(path.join(root, 'state'));
    const input = { engine, engineSha256: hash('engine'), tracer, tracerSha256: hash('tracer'), hooksDirectory: path.join(root, 'hooks'), defaultMountsFile: mounts, containersConf: config, containersConfSha256: hash(configText), journal };
    return await action(input, journal);
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

describe('independent Podman no-pull probe', () => {
  posixTest('attests an absent-image rejection with intercepted network and retains a cleaned journal', async () => fixture(async (input, journal) => {
    const commands: string[][] = [];
    const runner: typeof runCommand = async (exe, args) => {
      commands.push([...args]);
      if (exe === input.engine) return { code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
      const output = args[args.indexOf('-o') + 1];
      if (!output) throw new Error('trace output missing');
      await writeFile(output, `execve(${JSON.stringify(input.engine)}, ["podman"], 0x0) = 0\nsocket(AF_UNIX, SOCK_STREAM, 0) = 3\n`);
      return { code: 125, stdout: Buffer.alloc(0), stderr: Buffer.from('image not known locally') };
    };
    await expect(probePodmanNoPull({ ...input, runner })).resolves.toBeUndefined();
    expect(commands[1]).toContain('inject=connect:error=ENETUNREACH');
    expect(commands[1]).toContain('inject=io_uring_setup:error=ENOSYS');
    expect(commands[1]).toContain('--pull=never');
    expect(await journal.pending()).toEqual([]);
  }));

  posixTest('rejects any IP socket attempt, even when the requested image was absent', async () => fixture(async (input, journal) => {
    const runner: typeof runCommand = async (exe, args) => {
      if (exe === input.engine) return { code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
      const output = args[args.indexOf('-o') + 1]; if (!output) throw new Error('trace output missing');
      await writeFile(output, `execve(${JSON.stringify(input.engine)}, [], 0x0) = 0\nsocket(AF_INET, SOCK_STREAM, 0) = 3\n`);
      return { code: 125, stdout: Buffer.alloc(0), stderr: Buffer.from('image not known locally') };
    };
    await expect(probePodmanNoPull({ ...input, runner })).rejects.toThrow('IP networking');
    expect(await journal.pending()).toEqual([]);
  }));

  posixTest('retains a planned journal when tracing is interrupted during create', async () => fixture(async (input, journal) => {
    const runner: typeof runCommand = async exe => {
      if (exe === input.engine) return { code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
      throw new Error('COMMAND_TIMEOUT');
    };
    await expect(probePodmanNoPull({ ...input, runner })).rejects.toThrow('COMMAND_TIMEOUT');
    expect(await journal.pending()).toMatchObject([{ phase: 'planned' }]);
  }));

  if (process.platform === 'win32') it('Windows refuses an unguarded POSIX no-pull probe before journaling or engine and tracer dispatch', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-no-pull-refusal-')));
    const state = path.join(root, 'state');
    const runner = vi.fn<typeof runCommand>(async () => { throw new Error('Unsupported no-pull probe must not launch an engine or tracer.'); });
    try {
      await mkdir(state);
      const probe = async () => {
        const journal = await JobJournal.open(state);
        await probePodmanNoPull({ engine: path.join(root, 'podman.exe'), engineSha256: hash('engine'), tracer: path.join(root, 'strace.exe'), tracerSha256: hash('tracer'),
          hooksDirectory: path.join(root, 'hooks'), defaultMountsFile: path.join(root, 'mounts.conf'), containersConf: path.join(root, 'containers.conf'), containersConfSha256: hash('configuration'), journal, runner });
      };
      await expect(probe()).rejects.toThrow('WINDOWS_STATE_GUARD_REQUIRED');
      expect(runner).not.toHaveBeenCalled(); expect(await readdir(state)).toEqual([]);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
