import { describe, expect, it } from 'vitest';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { JobJournal } from '../../packages/runtime-manager/src/job-journal.js';
import type { JobRecord } from '../../packages/runtime-manager/src/job-journal.js';
import { posixTest } from '../fixtures/native-scope.mjs';

const name = 'ud-agent-01234567-89ab-cdef-0123-456789abcdef';
const id = 'c'.repeat(64);
function planned(): JobRecord { return { version: 1, name, engine: 'podman', engine_sha256: `sha256:${'a'.repeat(64)}`, image_digest: `sha256:${'b'.repeat(64)}`, phase: 'planned' }; }

describe('durable job ownership', () => {
  posixTest('persists planned ownership before create and keeps unfinished work visible', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-jobs-'));
    try {
      const journal = await JobJournal.open(root);
      await journal.create(planned());
      expect(await journal.pending()).toEqual([planned()]);
      await journal.transition(name, 'created', id);
      await journal.transition(name, 'running');
      expect(await journal.pending()).toMatchObject([{ name, phase: 'running', container_id: id }]);
      await journal.transition(name, 'cleanup_pending');
      await journal.transition(name, 'cleaned');
      expect(await journal.pending()).toEqual([]);
      expect(await journal.load(name)).toMatchObject({ phase: 'cleaned', container_id: id });
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  posixTest('refuses unknown transitions, changed IDs, stale locks and unsafe journal paths', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-jobs-'));
    try {
      const journal = await JobJournal.open(root);
      await journal.create(planned());
      await expect(journal.transition(name, 'running', id)).rejects.toThrow('transition');
      await journal.transition(name, 'created', id);
      await expect(journal.transition(name, 'running', 'd'.repeat(64))).rejects.toThrow('ID changed');
      await expect(journal.load('../outside')).rejects.toThrow('identifier');
      expect((await journal.load(name)).phase).toBe('created');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  if (process.platform === 'win32') it('Windows refuses legacy POSIX journal initialization before creating any state entries', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-jobs-refusal-'));
    try {
      expect(await readdir(root)).toEqual([]);
      await expect(JobJournal.open(root)).rejects.toThrow('WINDOWS_STATE_GUARD_REQUIRED');
      expect(await readdir(root)).toEqual([]);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
