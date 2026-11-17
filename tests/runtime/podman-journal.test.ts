import { createHash } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { PodmanJobJournal, samePodmanVmForCleanup } from '../../packages/coordinator/src/podman-journal.js';

const machine = `sha256:${'a'.repeat(64)}`, oldBoot = '11111111-1111-4111-8111-111111111111', newBoot = '22222222-2222-4222-8222-222222222222';
const original = `${machine}:${oldBoot}`, current = `${machine}:${newBoot}`;
const sha = `sha256:${'b'.repeat(64)}`;

describe('Podman cleanup-only reboot reconciliation', () => {
  it('requires the same persistent machine and valid original/current boot identities', () => {
    expect(samePodmanVmForCleanup(original, current)).toBe(true);
    expect(samePodmanVmForCleanup(original, original)).toBe(true);
    for (const value of [undefined, null, '', `${machine}:invalid`, `sha256:${'c'.repeat(64)}:${newBoot}`]) expect(samePodmanVmForCleanup(original, value)).toBe(false);
  });
  it('retains the original execution identity and records fresh cleanup evidence without promoting execution', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-podman-reboot-')));
    try {
      const journal = await PodmanJobJournal.open(root, process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined), id = '33333333-3333-4333-8333-333333333333';
      const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
      await journal.create({ version: 1, id, engine: guard, engine_sha256: `sha256:${createHash('sha256').update(await readFile(guard)).digest('hex')}`, image_digest: sha, image_id: sha, graph_root: '/home/guest/storage', graph_identity: '1:2', owner_pid: 2147483647, phase: 'planned', vm_identity: original, policy_sha256: sha });
      await journal.recordVmCleanup(id, current);
      const record = await journal.load(id);
      expect(record.vm_identity).toBe(original); expect(record.phase).toBe('planned');
      expect(record.vm_cleanup_reconciliation).toEqual({ mode: 'cleanup_only', original_vm_identity: original, current_vm_identity: current });
      await expect(journal.recordVmCleanup(id, `sha256:${'c'.repeat(64)}:${newBoot}`)).rejects.toThrow('PODMAN_VM_RECOVERY_CONTEXT_CHANGED');
      const file = path.join(journal.directory, id, 'job.json'), raw = JSON.parse(await readFile(file, 'utf8'));
      raw.vm_cleanup_reconciliation.mode = 'execution'; await writeFile(file, JSON.stringify(raw));
      await expect(journal.load(id)).rejects.toThrow('Invalid Podman job journal');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
