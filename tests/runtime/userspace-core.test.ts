import { createHash } from 'node:crypto';
import { tar } from '../fixtures/ustar.js';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { coreAssetRoot, coreDescriptor, coreInventory, extractCoreArchive, prepareCoreAssets } from '../../packages/runtime-manager/src/userspace-core.js';
import { guardedIdentity } from '../../packages/workspace/src/guard.js';

const host = { platform: process.platform, arch: process.arch };
const guardRelative = 'runtime/helpers/guard' + (process.platform === 'win32' ? '.exe' : '');
const hash = (bytes: Buffer | string) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

async function fixture(action: (input: { root: string; source: string; state: string; item: any; archive: Buffer; receipt: { url: string; sha256: string; size: number }; guard: string }) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-core-pack-')));
  try {
    const source = path.join(root, 'release'); await mkdir(path.join(source, 'runtime/helpers'), { recursive: true }); const guard = path.join(source, guardRelative); await copyFile(path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), guard); await chmod(guard, 0o700); const guardBytes = await readFile(guard);
    const bytes = Buffer.from('independent worker bytes\n'); const archive = tar([{ name: 'runtime/worker/a.py', bytes, mode: 0o755 }]); const receipt = { url: `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-userspace-${host.platform}-${host.arch}.tar.gz`, sha256: hash(archive), size: archive.length };
    const item = { worker: 'runtime/worker', upstream: 'runtime/upstream', wheels: 'runtime/wheels', files: [{ path: 'runtime/worker/a.py', sha256: hash(bytes), size: bytes.length }], lazy_core: receipt };
    const manifest = JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', platforms: { [`${host.platform}/${host.arch}`]: item } }); await writeFile(path.join(source, 'runtime/userspace.lock.json'), manifest); await writeFile(path.join(source, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(manifest), native_helpers: { [`${host.platform}/${host.arch}`]: { guard: { path: guardRelative, sha256: hash(guardBytes), size_bytes: guardBytes.length } } } }));
    await action({ root, source, state: path.join(root, 'state'), item, archive, receipt, guard });
  } finally { await rm(root, { recursive: true, force: true }); }
}
describe('selected-host userspace core acquisition', () => {
  it('reuses a complete embedded native closure despite its lazy descriptor, and rejects partial embedding', async () => fixture(async ({ source, state, item, guard }) => {
    // A separately installed native guard must not count as a core payload.
    const guardBytes = await readFile(guard); const selected = { ...item, guard: guardRelative, files: [{ path: guardRelative, sha256: hash(guardBytes), size: guardBytes.length }, ...item.files] };
    await expect(coreAssetRoot(source, state, selected, host)).rejects.toMatchObject({ code: 'ENOENT' }); await mkdir(path.join(source, 'runtime/worker'), { recursive: true }); await writeFile(path.join(source, 'runtime/worker/a.py'), 'independent worker bytes\n');
    expect(await coreAssetRoot(source, state, selected, host)).toBe(source); await prepareCoreAssets(source, state, host, 'offline', async () => { throw new Error('unintended native archive download'); }); await expect(readdir(state)).rejects.toMatchObject({ code: 'ENOENT' });
    const partial = { ...selected, files: [...selected.files, { path: 'runtime/worker/missing.py', sha256: hash('missing'), size: 7 }] }; await expect(coreAssetRoot(source, state, partial, host)).rejects.toThrow('EMBEDDED_INVENTORY_INCOMPLETE'); await expect(readdir(state)).rejects.toMatchObject({ code: 'ENOENT' });
  }));
  it('keeps absent checks read-only, downloads once across concurrent setups, and reuses offline', async () => fixture(async ({ source, state, item, archive }) => {
    await expect(coreAssetRoot(source, state, item, host)).rejects.toMatchObject({ code: 'ENOENT', message: 'USERSPACE_CORE_ASSETS_MISSING' }); await expect(readdir(state)).rejects.toMatchObject({ code: 'ENOENT' }); let downloads = 0;
    const fetcher: typeof fetch = async () => { downloads++; return new Response(archive, { headers: { 'content-length': String(archive.length) } }); };
    const outcomes = await Promise.allSettled([prepareCoreAssets(source, state, host, 'bootstrap_only', fetcher), prepareCoreAssets(source, state, host, 'bootstrap_only', fetcher)]); for (const outcome of outcomes) if (outcome.status === 'rejected') throw outcome.reason; expect(downloads).toBe(1); const assets = await coreAssetRoot(source, state, item, host); expect(await readFile(path.join(assets, 'runtime/worker/a.py'), 'utf8')).toBe('independent worker bytes\n'); expect(await readdir(path.join(assets, 'runtime/wheels'))).toEqual([]);
    await prepareCoreAssets(source, state, host, 'offline', async () => { throw new Error('unintended download'); }); await expect(readdir(path.join(source, 'runtime/worker'))).rejects.toMatchObject({ code: 'ENOENT' });
  }));
  it('requires a verified offline transport and recovers only identity-bound interrupted staging', async () => fixture(async ({ source, state, item, archive, receipt, guard }) => {
    await expect(prepareCoreAssets(source, state, host, 'offline', async () => { throw new Error('unintended download'); })).rejects.toThrow('USERSPACE_CORE_OFFLINE_CACHE_MISSING');
    await writeFile(path.join(state, 'core-cache', `${receipt.sha256.slice(7)}.tar.gz`), archive); const parent = path.join(state, 'corepacks'); const temporary = await mkdtemp(path.join(parent, '.install-')); await writeFile(path.join(temporary, 'partial'), 'interrupted'); await writeFile(path.join(parent, `${receipt.sha256.slice(7)}.install.json`), JSON.stringify({ schema_version: 1, sha256: receipt.sha256, staging: path.basename(temporary), identity: await guardedIdentity(guard, temporary) }), { mode: 0o600 });
    await prepareCoreAssets(source, state, host, 'offline', fetch); await expect(readdir(temporary)).rejects.toMatchObject({ code: 'ENOENT' }); expect(await coreAssetRoot(source, state, item, host)).toContain(receipt.sha256.slice(7));
  }));
  it('rejects unsupported coordinates, collisions, hostile members and missing outcomes', async () => fixture(async ({ root, item, receipt }) => {
    expect(() => coreDescriptor({ lazy_core: { ...receipt, url: receipt.url.replace(host.arch, 'other') } }, host)).toThrow('RECEIPT');
    expect(() => coreInventory({ ...item, files: [item.files[0], { ...item.files[0], path: 'runtime/WORKER/a.py' }] })).toThrow('RECEIPT');
    for (const members of [[{ name: '../escape', bytes: Buffer.from('x') }], [{ name: 'runtime/worker/a.py', bytes: Buffer.alloc(0), type: '2' }], [{ name: 'runtime/worker/a.py', bytes: Buffer.from('wrong') }], []]) {
      const bytes = tar(members); const file = path.join(root, 'hostile.tar.gz'); await writeFile(file, bytes); const destination = await mkdtemp(path.join(root, 'extract-')); await expect(extractCoreArchive(file, destination, item, { ...receipt, sha256: hash(bytes), size: bytes.length })).rejects.toThrow('USERSPACE_CORE_');
    }
  }));
});
