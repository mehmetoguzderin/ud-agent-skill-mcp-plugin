import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { runCommand } from '../../packages/runtime-manager/src/command.js';
import { loadImageReceipt, verifyArchive } from '../../packages/runtime-manager/src/receipt.js';

describe('bounded engine subprocesses', () => {
  it('executes an absolute argv without a shell and removes control environment variables', async () => {
    const previous = process.env.DOCKER_HOST;
    process.env.DOCKER_HOST = 'tcp://unexpected.example:2375';
    try {
      const result = await runCommand(process.execPath, ['-e', 'process.stdout.write(JSON.stringify({arg:process.argv[1],docker:process.env.DOCKER_HOST ?? null}))', '$(not-a-shell)'], { timeoutMs: 5000, maxOutputBytes: 4096 });
      expect(result.code).toBe(0);
      expect(JSON.parse(result.stdout.toString())).toEqual({ arg: '$(not-a-shell)', docker: null });
    } finally { if (previous === undefined) delete process.env.DOCKER_HOST; else process.env.DOCKER_HOST = previous; }
  });

  it('rejects relative executables and enforces output/time budgets', async () => {
    await expect(runCommand('node', [], { timeoutMs: 1000, maxOutputBytes: 1024 })).rejects.toThrow('absolute');
    await expect(runCommand(process.execPath, ['-e', 'process.stdout.write("a".repeat(5000))'], { timeoutMs: 5000, maxOutputBytes: 128 })).rejects.toThrow('COMMAND_OUTPUT_LIMIT');
    await expect(runCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 25, maxOutputBytes: 1024 })).rejects.toThrow('COMMAND_TIMEOUT');
  });

  it('honors cancellation without returning a successful result', async () => {
    const abort = new AbortController();
    const running = runCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 500, maxOutputBytes: 1024, signal: abort.signal });
    abort.abort();
    await expect(running).rejects.toThrow('COMMAND_CANCELLED');
  });
});

describe('immutable runtime receipts', () => {
  it('requires frozen publisher-bound images and a complete context digest', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-receipt-'));
    try {
      await mkdir(path.join(root, 'runtime'));
      const digest = `sha256:${'a'.repeat(64)}`;
      const context = `sha256:${'b'.repeat(64)}`;
      const lock = { schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: { core: { context_sha256: context, images: { 'linux/arm64': { digest, reference: `ghcr.io/mehmetoguzderin/ud-core@${digest}` } } } } };
      const filename = path.join(root, 'runtime', 'runtime.lock.json');
      await writeFile(filename, JSON.stringify(lock));
      expect(await loadImageReceipt(root, 'core', 'arm64')).toEqual({ digest, reference: `ghcr.io/mehmetoguzderin/ud-core@${digest}`, contextSha256: context });
      await expect(loadImageReceipt(root, 'render', 'arm64')).rejects.toThrow('missing');
      lock.state = 'unbuilt'; await writeFile(filename, JSON.stringify(lock));
      await expect(loadImageReceipt(root, 'core', 'arm64')).rejects.toThrow('RUNTIME_RECEIPT_NOT_FROZEN');
      lock.state = 'frozen'; lock.packs.core.images['linux/arm64'].reference = `ghcr.io/attacker/ud-core@${digest}`; await writeFile(filename, JSON.stringify(lock));
      await expect(loadImageReceipt(root, 'core', 'arm64')).rejects.toThrow('publisher-bound');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('verifies exact offline archive bytes and refuses symlinks and bad digests', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-archive-'));
    try {
      const archive = path.join(root, 'worker.tar');
      await writeFile(archive, 'offline worker bytes');
      const digest = `sha256:${createHash('sha256').update('offline worker bytes').digest('hex')}`;
      await expect(verifyArchive(archive, digest)).resolves.toBeUndefined();
      await expect(verifyArchive(archive, `sha256:${'0'.repeat(64)}`)).rejects.toThrow('digest');
      const link = path.join(root, 'link'); await symlink(archive, link);
      await expect(verifyArchive(link, digest)).rejects.toThrow();
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
