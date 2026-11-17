import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { chmod, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { withProviderLease, withProviderMaintenance } from '../../packages/coordinator/src/provider-leases.js';
import { guardedIdentity, guardedPrivateDirectory, guardedStateLock } from '../../packages/workspace/src/guard.js';

const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
async function fixture(action: (root: string) => Promise<void>) { const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-provider-leases-')); const root = await realpath(temporary); await chmod(root, 0o700); try { await guardedPrivateDirectory(guard, root, '.', await guardedIdentity(guard, root), true); await action(root); } finally { await rm(root, { recursive: true, force: true }); } }
describe('ownership-bound provider maintenance', () => {
  it('admits concurrent unique job leases and refuses maintenance until every job exits', async () => fixture(async root => {
    let firstStarted!: () => void; let secondStarted!: () => void; let finishFirst!: () => void; let finishSecond!: () => void;
    const startedA = new Promise<void>(done => { firstStarted = done; }); const startedB = new Promise<void>(done => { secondStarted = done; });
    const pendingA = new Promise<void>(done => { finishFirst = done; }); const pendingB = new Promise<void>(done => { finishSecond = done; });
    const a = withProviderLease(guard, root, async () => { firstStarted(); await pendingA; }); await startedA;
    const b = withProviderLease(guard, root, async () => { secondStarted(); await pendingB; }); await startedB;
    expect((await readdir(root)).filter(name => name.endsWith('.json'))).toHaveLength(2);
    let mutated = false; await expect(withProviderMaintenance(guard, root, async () => { mutated = true; })).rejects.toThrow('PROVIDER_RUNTIME_IN_USE'); expect(mutated).toBe(false);
    finishFirst(); await a; await expect(withProviderMaintenance(guard, root, async () => {})).rejects.toThrow('PROVIDER_RUNTIME_IN_USE');
    finishSecond(); await b; expect((await readdir(root)).filter(name => name.startsWith('.provider-lease-'))).toEqual([]);
    expect(await withProviderMaintenance(guard, root, async inventory => inventory)).toEqual({ active_leases: [], stale_leases: [], protected_leases: [] });
  }), 30_000);
  it('reconciles only exact stale records, keeps unknown state and leaves dry runs unchanged', async () => fixture(async root => {
    const identity = await guardedIdentity(guard, root); const id = randomUUID(); const record = `.provider-lease-${id}.json`; const kernel = `.provider-lease-${id}.native`;
    await writeFile(path.join(root, record), JSON.stringify({ schema_version: 1, id, identity, kernel_lock: kernel }), { mode: 0o600 });
    const release = await guardedStateLock(guard, root, kernel, identity); await release(); await writeFile(path.join(root, 'unrelated.txt'), 'keep');
    const before = await readdir(root); const dry = await withProviderMaintenance(guard, root, async inventory => inventory, { dryRun: true }); expect(dry.stale_leases).toEqual([record]); expect(await readdir(root)).toEqual(before);
    const outcome = await withProviderMaintenance(guard, root, async inventory => inventory); expect(outcome.stale_leases).toEqual([record]); expect(await readFile(path.join(root, 'unrelated.txt'), 'utf8')).toBe('keep');
    expect((await readdir(root)).includes(kernel)).toBe(false); expect((await readdir(root)).includes(record)).toBe(false);
    const unrecorded = `.provider-lease-${randomUUID()}.native`; const held = await guardedStateLock(guard, root, unrecorded, identity);
    await expect(withProviderMaintenance(guard, root, async () => {})).rejects.toThrow('PROVIDER_RUNTIME_IN_USE'); await held();
    expect((await withProviderMaintenance(guard, root, async inventory => inventory)).protected_leases).toEqual([unrecorded]); expect((await readdir(root)).includes(unrecorded)).toBe(true);
  }));
  it('fails closed on changed ownership and cleans leases after rejected/cancelled work', async () => fixture(async root => {
    const controller = new AbortController(); controller.abort(); const before = await readdir(root);
    await expect(withProviderLease(guard, root, async () => {}, { signal: controller.signal })).rejects.toThrow('PROVIDER_MAINTENANCE_CANCELLED'); expect(await readdir(root)).toEqual(before);
    await expect(withProviderLease(guard, root, async () => { throw new Error('cancelled work'); })).rejects.toThrow('cancelled work'); expect((await readdir(root)).filter(name => name.startsWith('.provider-lease-'))).toEqual([]);
    const id = randomUUID(); const record = `.provider-lease-${id}.json`;
    await writeFile(path.join(root, record), JSON.stringify({ schema_version: 1, id, identity: { device: '0', inode: '0' }, kernel_lock: `.provider-lease-${id}.native` }), { mode: 0o600 });
    await expect(withProviderMaintenance(guard, root, async () => {})).rejects.toThrow('PROVIDER_LEASE_RECORD_INVALID'); expect((await readdir(root)).includes(record)).toBe(true);
  }));
});
