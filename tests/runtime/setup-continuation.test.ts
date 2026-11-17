import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it, vi } from 'vitest';
import { ResourceStore } from '../../packages/coordinator/src/resources.js';
import { setupContinuation } from '../../packages/coordinator/src/setup-continuation.js';

it('resumes the exact scoped setup request and rejects changed policy, source or arguments', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-setup-resume-')));
  try {
    const resources = await ResourceStore.open(path.join(root, 'resources'), ['/workspace'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
    await mkdir(path.join(root, 'runtime')); await writeFile(path.join(root, 'runtime/runtime.lock.json'), '{}');
    const args = { engine: 'userspace' as const, network: 'offline' as const, required_tools: ['validation_report'] };
    const run = vi.fn().mockResolvedValueOnce({ ready: false, status: 'setup_needed' }).mockResolvedValue({ ready: true, status: 'ready', reused: true });
    const first = await setupContinuation(args, root, resources, run);
    expect(first.continuation_token).toMatch(/^setup-v1:/);
    const resume = { mode: 'resume' as const, continuation_token: first.continuation_token as string };
    expect(await setupContinuation(resume, root, resources, run)).toMatchObject({ ready: true, resumed: true, mode: 'resume' });
    expect(run.mock.calls[1]![0]).toEqual(args);
    await expect(setupContinuation({ ...resume, engine: 'docker' }, root, resources, run)).rejects.toThrow('SETUP_CONTINUATION_ARGUMENT_MISMATCH');
    await expect(setupContinuation({ ...args, continuation_token: first.continuation_token as string }, root, resources, run)).rejects.toThrow('SETUP_CONTINUATION_REQUIRES_RESUME');
    await expect(setupContinuation({ ...resume, dry_run: true }, root, resources, run)).rejects.toThrow('SETUP_CONTINUATION_DRY_RUN_INVALID');
    const other = await ResourceStore.open(path.join(root, 'resources'), ['/other'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
    await expect(setupContinuation(resume, root, other, run)).rejects.toThrow('RESOURCE_ACCESS_DENIED');
    await writeFile(path.join(root, 'runtime/runtime.lock.json'), '{"changed":true}');
    await expect(setupContinuation(resume, root, resources, run)).rejects.toThrow('SETUP_CONTINUATION_STALE_OR_INVALID');
    await setupContinuation({ ...args, dry_run: true }, root, resources, run);
    expect(run.mock.calls.at(-1)![0]).toMatchObject({ dry_run: true });
  } finally { await rm(root, { recursive: true, force: true }); }
});

it('retains a usable continuation after a setup process fails without claiming readiness', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-setup-failed-')));
  try {
    const resources = await ResourceStore.open(path.join(root, 'resources'), ['/workspace'], process.platform === 'win32' ? path.resolve('target/debug/ud-agent-guard.exe') : undefined);
    const run = vi.fn().mockRejectedValueOnce(Object.assign(new Error('Verified download was interrupted.'), { code: 'DOWNLOAD_INTERRUPTED' })).mockResolvedValue({ ready: true, status: 'ready' });
    const first = await setupContinuation({ engine: 'userspace', network: 'offline' }, root, resources, run);
    expect(first).toMatchObject({ status: 'failed', ready: false, code: 'DOWNLOAD_INTERRUPTED', reason: 'Verified download was interrupted.' });
    expect(await setupContinuation({ mode: 'resume', continuation_token: first.continuation_token as string }, root, resources, run)).toMatchObject({ ready: true, resumed: true });
    expect(run.mock.calls[1]![0]).toEqual({ engine: 'userspace', network: 'offline' });
  } finally { await rm(root, { recursive: true, force: true }); }
});
