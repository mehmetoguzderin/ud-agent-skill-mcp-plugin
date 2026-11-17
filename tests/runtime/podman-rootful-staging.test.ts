import { posixTest } from '../fixtures/native-scope.mjs';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { captureValidationSnapshot } from '../../packages/workspace/src/snapshot.js';
import { JobJournal } from '../../packages/runtime-manager/src/job-journal.js';
import { cleanupRootfulSnapshot, stageRootfulSnapshot } from '../../packages/runtime-manager/src/podman-rootful-staging.js';

if (process.platform !== 'win32') describe('rootful Podman staging', () => {
  posixTest('requires an authorized root context and journal-bound private staging', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-rootful-staging-test-')));
    const guard = path.resolve('target/debug', process.platform === 'win32' ? 'ud-agent-guard.exe' : 'ud-agent-guard');
    let snapshot: Awaited<ReturnType<typeof captureValidationSnapshot>> | undefined;
    try {
      const tree = path.join(root, 'tree'); const state = path.join(root, 'state');
      await mkdir(tree, { mode: 0o700 }); await mkdir(state, { mode: 0o700 }); await mkdir(path.join(tree, 'nested'));
      const bytes = Buffer.from('# sent_id = 1\n1\tA\t_\tX\t_\t_\t0\troot\t_\t_\n\n');
      await writeFile(path.join(tree, 'nested/a.conllu'), bytes);
      snapshot = await captureValidationSnapshot(guard, tree, [tree]);
      const journal = await JobJournal.open(state); const name = 'ud-agent-12345678-1234-1234-1234-123456789abc';
      await journal.create({ version: 1, name, engine: 'podman', engine_sha256: 'sha256:' + 'a'.repeat(64), image_digest: 'sha256:' + 'b'.repeat(64), phase: 'planned', engine_mode: 'rootful' });
      if (typeof process.getuid !== 'function' || process.getuid() !== 0) {
        await expect(stageRootfulSnapshot(journal, name, guard, snapshot, snapshot.directory)).rejects.toThrow('AUTHORIZED_ROOT_CONTEXT');
        expect(await journal.load(name)).toMatchObject({ phase: 'planned', engine_mode: 'rootful' });
      } else {
        const staged = await stageRootfulSnapshot(journal, name, guard, snapshot, snapshot.directory);
        const info = await stat(path.join(staged, 'nested/a.conllu'));
        expect(info.uid).toBe(10001); expect(info.gid).toBe(10001); expect(info.mode & 0o777).toBe(0o400);
        expect(createHash('sha256').update(await readFile(path.join(staged, 'nested/a.conllu'))).digest('hex')).toBe(createHash('sha256').update(bytes).digest('hex'));
        expect(await readFile(path.join(tree, 'nested/a.conllu'))).toEqual(bytes);
        await expect(cleanupRootfulSnapshot(journal, name)).rejects.toThrow('pending owned job');
        await journal.transition(name, 'cleanup_pending'); await cleanupRootfulSnapshot(journal, name);
        await expect(stat(staged)).rejects.toMatchObject({ code: 'ENOENT' });
      }
    } finally { if (snapshot) await snapshot.cleanup(); await rm(root, { recursive: true, force: true }); }
  });
});

if (process.platform === 'win32') it('legacy Podman journal refuses Windows state without manufacturing POSIX authority', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-podman-journal-refusal-')));
  try {
    await expect(JobJournal.open(root)).rejects.toThrow('WINDOWS_STATE_GUARD_REQUIRED');
    expect(await readdir(root)).toEqual([]);
  } finally { await rm(root, { recursive: true, force: true }); }
});
