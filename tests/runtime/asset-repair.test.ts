import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { assetRepairRecords, repairOwnedAssetPack } from '../../packages/runtime-manager/src/asset-repair.js';
import { withProviderMaintenance } from '../../packages/coordinator/src/provider-leases.js';
import { JournalStore } from '../../packages/workspace/src/journal.js';
import { guardedIdentity } from '../../packages/workspace/src/guard.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const sha = (value: string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
async function fixture(action: (input: any) => Promise<void>) {
  const state = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-asset-repair-')));
  try { await JournalStore.open(state, guard); const archive = { sha256: sha('transport'), size: 9 }; const key = archive.sha256.slice(7); const pack = `providerpacks/${key}`; await mkdir(path.join(state, pack), { recursive: true, mode: 0o700 }); await writeFile(path.join(state, pack, 'sdk'), 'corrupt'); const validate = async () => { if (await readFile(path.join(state, pack, 'sdk'), 'utf8') !== 'verified') throw new Error('independent integrity failure'); }; const prepare = async () => { await mkdir(path.join(state, pack), { mode: 0o700 }); await writeFile(path.join(state, pack, 'sdk'), 'verified'); }; await action({ state, archive, key, pack, validate, prepare }); }
  finally { await rm(state, { recursive: true, force: true }); }
}
describe('owned lazy-asset repair transactions', () => {
  it('quarantines exact damaged bytes and rolls back failed acquisition before a later successful retry', async () => fixture(async ({ state, archive, pack, validate, prepare }) => {
    await expect(withProviderMaintenance(guard, state, () => repairOwnedAssetPack(state, guard, 'provider', archive, validate, async () => { throw new Error('network unavailable'); }))).rejects.toMatchObject({ message: 'ASSET_REPAIR_FAILED: network unavailable', repair: { previous_state_restored: true } }); expect(await readFile(path.join(state, pack, 'sdk'), 'utf8')).toBe('corrupt');
    const repaired = await withProviderMaintenance(guard, state, () => repairOwnedAssetPack(state, guard, 'provider', archive, validate, prepare)); expect(repaired.repaired).toBe(true); expect(await readFile(path.join(state, repaired.quarantine!, 'item-0/sdk'), 'utf8')).toBe('corrupt'); expect(await readFile(path.join(state, pack, 'sdk'), 'utf8')).toBe('verified'); expect((await assetRepairRecords(state, guard)).map(item => item.record.phase).sort()).toEqual(['completed', 'rolled_back']);
  }), 30_000);
  it('resumes an identity-bound interrupted move and recognizes response loss after verified publication', async () => fixture(async ({ state, archive, key, pack, validate, prepare }) => {
    const quarantine = `quarantine-${randomUUID()}`; await mkdir(path.join(state, quarantine), { mode: 0o700 }); const identity = await guardedIdentity(guard, path.join(state, pack)); await rename(path.join(state, pack), path.join(state, quarantine, 'item-0'));
    const file = path.join(state, `asset-repair-provider-${key}.json`); const journal = { schema_version: 1, kind: 'provider', key, phase: 'building', quarantine, moves: [{ from: pack, to: 'item-0', ...identity }] }; await writeFile(file, JSON.stringify(journal), { mode: 0o600 });
    const first = await withProviderMaintenance(guard, state, () => repairOwnedAssetPack(state, guard, 'provider', archive, validate, prepare)); expect(first).toEqual({ repaired: true, quarantine }); journal.phase = 'building'; await writeFile(file, JSON.stringify(journal));
    const second = await withProviderMaintenance(guard, state, () => repairOwnedAssetPack(state, guard, 'provider', archive, validate, async () => { throw new Error('must not rebuild a published verified pack'); })); expect(second).toEqual({ repaired: true, quarantine }); expect(JSON.parse(await readFile(file, 'utf8')).phase).toBe('completed');
  }));
  it('rejects cancellation and escaped persisted paths before changing the original cache', async () => fixture(async ({ state, archive, key, pack, validate, prepare }) => {
    const controller = new AbortController(); controller.abort(); await expect(repairOwnedAssetPack(state, guard, 'provider', archive, validate, prepare, controller.signal)).rejects.toThrow('CANCELLED');
    await writeFile(path.join(state, `asset-repair-provider-${key}.json`), JSON.stringify({ schema_version: 1, kind: 'provider', key, phase: 'building', quarantine: `quarantine-${randomUUID()}`, moves: [{ from: '../escape', to: 'item-0', device: '1', inode: '1' }] }), { mode: 0o600 }); await expect(repairOwnedAssetPack(state, guard, 'provider', archive, validate, prepare)).rejects.toThrow('JOURNAL_INVALID'); expect(await readFile(path.join(state, pack, 'sdk'), 'utf8')).toBe('corrupt');
  }));
});
