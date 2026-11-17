import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DockerJobJournal } from '../../packages/coordinator/src/docker-journal.js';
import { writeNativeEngine } from './native-engine-fixture.js';
import { recoverDockerValidation } from '../../packages/coordinator/src/docker-worker.js';

const guard = process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined;

describe('Docker job journal', () => {
  it('records ownership and each pending creation before cleanup', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-docker-journal-'));
    try {
      const journal = await DockerJobJournal.open(root, guard); const id = randomUUID();
      const record = { version: 1 as const, id, engine: path.resolve('/bin/true'), engine_sha256: `sha256:${'a'.repeat(64)}`, image_digest: `sha256:${'b'.repeat(64)}`, image_id: `sha256:${'c'.repeat(64)}`, endpoint: 'unix:///tmp/docker.sock', daemon_id: 'daemon-one', owner_pid: process.pid, phase: 'planned' as const };
      await journal.create(record);
      await expect(journal.transition(id, 'worker_created')).rejects.toThrow('transition');
      await journal.transition(id, 'volume_pending');
      expect((await journal.pending())[0]).toMatchObject({ id, phase: 'volume_pending' });
      await journal.transition(id, 'volume_ready'); await journal.transition(id, 'loader_pending');
      const loader = 'd'.repeat(64); const worker = 'e'.repeat(64);
      await expect(journal.transition(id, 'loader_created')).rejects.toThrow('transition data');
      await journal.transition(id, 'loader_created', { loader_id: loader });
      await journal.transition(id, 'loaded'); await journal.transition(id, 'worker_pending');
      await expect(journal.transition(id, 'worker_created', { loader_id: worker, worker_id: worker })).rejects.toThrow('identity changed');
      await journal.transition(id, 'worker_created', { worker_id: worker });
      await journal.transition(id, 'ran'); await journal.transition(id, 'cleanup_pending');
      expect((await journal.pending())[0]).toMatchObject({ loader_id: loader, worker_id: worker, phase: 'cleanup_pending' });
      await journal.transition(id, 'cleaned'); expect(await journal.pending()).toEqual([]);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('rejects altered journals and paths outside its own job directory', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-docker-journal-'));
    try {
      const journal = await DockerJobJournal.open(root, guard); const id = randomUUID();
      await journal.create({ version: 1, id, engine: path.resolve('/bin/true'), engine_sha256: `sha256:${'a'.repeat(64)}`, image_digest: `sha256:${'b'.repeat(64)}`, image_id: `sha256:${'c'.repeat(64)}`, endpoint: 'unix:///tmp/docker.sock', daemon_id: 'daemon-one', owner_pid: process.pid, phase: 'planned' });
      const file = path.join(journal.directory, id, 'job.json');
      const data = JSON.parse(await readFile(file, 'utf8')); data.image_id = 'sha256:bad';
      await writeFile(file, JSON.stringify(data));
      await expect(journal.load(id)).rejects.toThrow('Invalid Docker job journal');
      await expect(journal.load('../escape')).rejects.toThrow('Invalid Docker job identifier');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('never recovers an active owner or assumes an interrupted create finished', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-docker-journal-'));
    try {
      const journal = await DockerJobJournal.open(root, guard); const active = randomUUID();
      const program = `#!${process.execPath}\nconst a=process.argv.slice(2); if(a.includes('info')) process.stdout.write(JSON.stringify({ID:'daemon-one',Architecture:'aarch64'})); else process.exitCode=1;\n`;
      const engine = await writeNativeEngine({ root, name: 'docker', program });
      const base = { version: 1 as const, engine, engine_sha256: `sha256:${createHash('sha256').update(await readFile(engine)).digest('hex')}`, image_digest: `sha256:${'b'.repeat(64)}`, image_id: `sha256:${'c'.repeat(64)}`, endpoint: 'unix:///tmp/docker.sock', daemon_id: 'daemon-one', phase: 'planned' as const };
      await journal.create({ ...base, id: active, owner_pid: process.pid });
      await expect(recoverDockerValidation(root, active, guard)).rejects.toThrow('DOCKER_JOB_OWNER_ACTIVE');
      const unknown = randomUUID(); await journal.create({ ...base, id: unknown, owner_pid: 2_147_483_647 });
      await journal.transition(unknown, 'volume_pending');
      await expect(recoverDockerValidation(root, unknown, guard)).rejects.toThrow('DOCKER_CREATE_OUTCOME_UNKNOWN');
      expect((await journal.load(unknown)).phase).toBe('volume_pending');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
