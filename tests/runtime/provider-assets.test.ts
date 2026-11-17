import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { cleanProviderAssets, prepareProviderAssets, providerAssetDescriptor, providerAssetRoot } from '../../packages/runtime-manager/src/provider-assets.js';
import { withProviderLease, withProviderMaintenance } from '../../packages/coordinator/src/provider-leases.js';
import { JournalStore } from '../../packages/workspace/src/journal.js';
import { tar } from '../fixtures/ustar.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const hash = (bytes: Buffer | string) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const profile = { platform: 'win32', arch: 'arm64' };
async function fixture(action: (input: any) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-provider-assets-')));
  try { const state = path.join(root, 'state'); const file = 'runtime/providers/wslc/win32-arm64/bin/wslcsdk.dll'; const bytes = Buffer.from('independent provider bytes'); const archive = tar([{ name: file, bytes }]); const descriptor = { url: 'https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-provider-wslc-win32-arm64.tar.gz', sha256: hash(archive), size: archive.length, files: [{ path: file, sha256: hash(bytes), size_bytes: bytes.length }] }; const record = { lazy_assets: descriptor }; await action({ root, state, archive, file, record, descriptor }); }
  finally { await rm(root, { recursive: true, force: true }); }
}
describe('lazy provider dependency assets', () => {
  it('keeps missing checks read-only and acquires only the selected closed profile under its job lease', async () => fixture(async ({ root, state, archive, file, record }) => {
    await expect(providerAssetRoot(root, state, guard, record, 'wslc', profile)).rejects.toMatchObject({ code: 'ENOENT', message: 'PROVIDER_ASSETS_MISSING' }); await expect(readdir(state)).rejects.toMatchObject({ code: 'ENOENT' });
    await mkdir(state, { mode: 0o700 }); await JournalStore.open(state, guard); let downloads = 0; const fetcher: typeof fetch = async () => { downloads++; return new Response(archive); };
    const assets = await withProviderLease(guard, state, () => prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'bootstrap_only', undefined, fetcher)); expect(await readFile(path.join(assets, file), 'utf8')).toBe('independent provider bytes'); expect(downloads).toBe(1);
    expect(await prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'offline', undefined, async () => { throw new Error('unintended download'); })).toBe(assets);
    expect(() => providerAssetDescriptor(record, 'wslc', { platform: 'win32', arch: 'x64' })).toThrow('RECEIPT_INVALID'); expect(() => providerAssetDescriptor(record, 'apple-container', profile)).toThrow('RECEIPT_INVALID');
  }));
  it('blocks corrupt cached assets or extra files without redownloading or falling back', async () => fixture(async ({ root, state, archive, file, record }) => {
    await mkdir(state, { mode: 0o700 }); await JournalStore.open(state, guard); const assets = await prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'bootstrap_only', undefined, async () => new Response(archive));
    await writeFile(path.join(assets, 'runtime/unlisted'), 'unexpected'); const fetcher: typeof fetch = async () => { throw new Error('must not redownload integrity failures'); };
    await expect(prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'bootstrap_only', undefined, fetcher)).rejects.toThrow('INVENTORY_INVALID'); await rm(path.join(assets, 'runtime/unlisted')); await chmod(path.join(assets, file), 0o600); await writeFile(path.join(assets, file), 'corrupt'); await expect(prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'bootstrap_only', undefined, fetcher)).rejects.toThrow(/INVENTORY_INVALID|digest/);
  }), 30_000);
  it('requires complete offline bytes and honors cancellation before publication', async () => fixture(async ({ root, state, archive, record }) => {
    await mkdir(state, { mode: 0o700 }); await JournalStore.open(state, guard); await expect(prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'offline')).rejects.toThrow('PROVIDER_ASSET_OFFLINE_CACHE_MISSING');
    const controller = new AbortController(); const fetcher: typeof fetch = async () => { controller.abort(); return new Response(archive); };
    await expect(prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'bootstrap_only', controller.signal, fetcher)).rejects.toThrow(/CANCELLED/); await expect(providerAssetRoot(root, state, guard, record, 'wslc', profile)).rejects.toMatchObject({ code: 'ENOENT' });
  }));
  it('uninstalls only verified owned packs after the maintenance gate excludes jobs', async () => fixture(async ({ root, state, archive, record, file }) => {
    await mkdir(state, { mode: 0o700 }); await JournalStore.open(state, guard); const assets = await prepareProviderAssets(root, state, guard, record, 'wslc', profile, 'bootstrap_only', undefined, async () => new Response(archive)); await writeFile(path.join(state, 'provider-cache/unrelated'), 'retain');
    const dry = await withProviderMaintenance(guard, state, () => cleanProviderAssets(state, guard, record, 'wslc', profile, 'owned-runtime', true), { dryRun: true }); expect(dry.paths).toHaveLength(2); expect(dry.protected).toEqual(['provider-cache/unrelated']); expect(await readFile(path.join(assets, file), 'utf8')).toBe('independent provider bytes');
    await withProviderMaintenance(guard, state, () => cleanProviderAssets(state, guard, record, 'wslc', profile, 'owned-runtime', false)); await expect(readdir(assets)).rejects.toMatchObject({ code: 'ENOENT' }); expect(await readFile(path.join(state, 'provider-cache/unrelated'), 'utf8')).toBe('retain');
  }), 30_000);
});
