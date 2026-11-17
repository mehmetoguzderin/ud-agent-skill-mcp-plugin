import { lstat, mkdir, mkdtemp, readdir, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import type { Host } from './profiles.js';
import type { UvDownload } from './userspace-download.js';
import { acquireProviderArchive } from './userspace-download.js';
import { coreInventory, extractClosedArchive } from './userspace-core.js';
import { readBoundedReceiptBytes, verifyArchive } from './receipt.js';
import { JournalStore, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';
import { guardedIdentity } from '../../workspace/src/guard.js';
import { assetRepairRecords } from './asset-repair.js';
type Engine = 'apple-container' | 'lima-nerdctl' | 'wslc';
type Entry = { path: string; sha256: string; size: number };
type Descriptor = UvDownload & { files: Entry[] };
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('PROVIDER_ASSET_RECEIPT_INVALID'); return value as Record<string, unknown>; }
function check(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('PROVIDER_SETUP_CANCELLED'); }
export function providerAssetDescriptor(record: Record<string, unknown>, engine: Engine, host: Host): Descriptor | undefined {
  if (record.lazy_assets === undefined) return undefined;
  const raw = object(record.lazy_assets);
  if (Object.keys(raw).sort().join(',') !== 'files,sha256,size,url' || raw.url !== `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-provider-${engine}-${host.platform}-${host.arch}.tar.gz` || typeof raw.sha256 !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(raw.sha256) || !Number.isSafeInteger(raw.size) || (raw.size as number) < 1 || (raw.size as number) > 4 * 1024 ** 3 || !Array.isArray(raw.files)) throw new Error('PROVIDER_ASSET_RECEIPT_INVALID');
  const files = raw.files.map(value => { const item = object(value); if (Object.keys(item).sort().join(',') !== 'path,sha256,size_bytes') throw new Error('PROVIDER_ASSET_RECEIPT_INVALID'); return { path: item.path, sha256: item.sha256, size: item.size_bytes }; });
  const inventory = coreInventory({ files, worker: 'runtime', upstream: 'runtime', wheels: 'runtime' }, { fileBytes: 4 * 1024 ** 3, totalBytes: 8 * 1024 ** 3 });
  if (inventory.files.some(file => !file.path.startsWith('runtime/'))) throw new Error('PROVIDER_ASSET_RECEIPT_INVALID');
  return { url: raw.url, sha256: raw.sha256, size: raw.size as number, files: inventory.files };
}
async function owned(directory: string, guard: string, create = false): Promise<string> {
  if (create) await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory); if (!info.isDirectory() || info.isSymbolicLink() || process.platform !== 'win32' && ((info.mode & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('PROVIDER_ASSET_STATE_UNSAFE');
  await openStateAuthority(directory, guard, create); return realpath(directory);
}
/** Read-only lookup; callers still verify each asset when it is consumed. */
export async function providerAssetRoot(source: string, state: string, guard: string, record: Record<string, unknown>, engine: Engine, host: Host): Promise<string> {
  const descriptor = providerAssetDescriptor(record, engine, host); if (!descriptor) return source;
  try { await owned(state, guard); const parent = await owned(path.join(state, 'providerpacks'), guard); return await owned(path.join(parent, descriptor.sha256.slice(7)), guard); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') { const missing = new Error('PROVIDER_ASSETS_MISSING') as Error & { code: string }; missing.code = 'ENOENT'; throw missing; } throw error; }
}
export async function verifyProviderAssetTree(root: string, descriptor: Descriptor, signal?: AbortSignal): Promise<void> {
  const files = new Map(descriptor.files.map(file => [file.path, file])); const directories = coreInventory({ files: descriptor.files, worker: 'runtime', upstream: 'runtime', wheels: 'runtime' }, { fileBytes: 4 * 1024 ** 3, totalBytes: 8 * 1024 ** 3 }).directories;
  const queue = ['']; let count = 0;
  while (queue.length) { check(signal); const selected = queue.shift()!; for (const name of await readdir(path.join(root, selected))) { if (++count > 40000) throw new Error('PROVIDER_ASSET_INVENTORY_INVALID'); const relative = selected ? `${selected}/${name}` : name; const absolute = path.join(root, ...relative.split('/')); const info = await lstat(absolute); if (info.isSymbolicLink()) throw new Error('PROVIDER_ASSET_INVENTORY_INVALID'); if (info.isDirectory()) { if (!directories.has(relative)) throw new Error('PROVIDER_ASSET_INVENTORY_INVALID'); queue.push(relative); } else { const expected = files.get(relative); if (!info.isFile() || !expected || info.size !== expected.size) throw new Error('PROVIDER_ASSET_INVENTORY_INVALID'); await verifyArchive(absolute, expected.sha256, signal); files.delete(relative); } } }
  if (files.size) throw new Error('PROVIDER_ASSET_INVENTORY_INCOMPLETE');
}
/** Called only inside the provider's maintenance-excluding setup lease. */
export async function prepareProviderAssets(source: string, state: string, guard: string, record: Record<string, unknown>, engine: Engine, host: Host, network: 'bootstrap_only' | 'offline', signal?: AbortSignal, fetcher: typeof fetch = fetch): Promise<string> {
  const descriptor = providerAssetDescriptor(record, engine, host); if (!descriptor) return source;
  check(signal); await owned(state, guard, true); const store = await JournalStore.open(state, guard);
  return store.withWorkspaceLock(`provider-assets-${descriptor.sha256.slice(7)}`, async () => {
    try { const existing = await providerAssetRoot(source, state, guard, record, engine, host); await verifyProviderAssetTree(existing, descriptor, signal); return existing; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const parent = await owned(path.join(state, 'providerpacks'), guard, true); const native = await openStateAuthority(parent, guard); const journal = path.join(parent, `${descriptor.sha256.slice(7)}.install.json`);
    try { const value = object(JSON.parse((await readBoundedReceiptBytes(journal)).toString('utf8'))); if (value.schema_version !== 1 || value.sha256 !== descriptor.sha256 || typeof value.staging !== 'string' || !/^\.install-[A-Za-z0-9]+$/.test(value.staging)) throw new Error('PROVIDER_ASSET_INSTALL_JOURNAL_INVALID'); const staging = path.join(parent, value.staging); try { const actual = await guardedIdentity(guard, staging); const expected = object(value.identity); if (actual.device !== expected.device || actual.inode !== expected.inode) throw new Error('PROVIDER_ASSET_INSTALL_IDENTITY_CHANGED'); await rm(staging, { recursive: true }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } await rm(journal); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    await owned(path.join(state, 'provider-cache'), guard, true); const acquire: typeof fetch = (url, options) => fetcher(url, signal ? { ...options, signal: options?.signal ? AbortSignal.any([signal, options.signal]) : signal } : options);
    const archive = await acquireProviderArchive(descriptor, state, engine, host, network, acquire); if (!archive) throw new Error('PROVIDER_ASSET_OFFLINE_CACHE_MISSING');
    const temporary = await mkdtemp(path.join(parent, '.install-')); await owned(temporary, guard, true); await durableWrite(journal, Buffer.from(`${JSON.stringify({ schema_version: 1, sha256: descriptor.sha256, staging: path.basename(temporary), identity: await guardedIdentity(guard, temporary) })}\n`), native);
    try { await extractClosedArchive(archive, temporary, descriptor.files, descriptor, signal); await verifyProviderAssetTree(temporary, descriptor, signal); check(signal); const destination = path.join(parent, descriptor.sha256.slice(7)); await rename(temporary, destination); await fsyncDirectory(parent, native); await rm(journal); await fsyncDirectory(parent, native); return destination; }
    catch (error) { await rm(temporary, { recursive: true, force: true }); await rm(journal, { force: true }); throw error; }
  });
}

/** Caller holds the provider maintenance gate and has recovered its jobs. */
export async function cleanProviderAssets(state: string, guard: string, record: Record<string, unknown>, engine: Engine, host: Host, action: 'cache' | 'owned-runtime', dryRun: boolean, signal?: AbortSignal): Promise<{ paths: string[]; protected: string[] }> {
  const descriptor = providerAssetDescriptor(record, engine, host); const result = { paths: [] as string[], protected: [] as string[] }; if (!descriptor) return result;
  const deletions: { target: string; recursive: boolean }[] = []; const parents = new Set<string>();
  const repairs = action === 'owned-runtime' ? (await assetRepairRecords(state, guard)).filter(saved => saved.record.kind === 'provider' && saved.record.key === descriptor.sha256.slice(7)) : [];
  if (repairs.some(saved => saved.record.phase === 'building')) throw new Error('ASSET_REPAIR_RECOVERY_REQUIRED');
  for (const directory of ['provider-cache', ...(action === 'owned-runtime' ? ['providerpacks'] : [])]) {
    let parent: string; try { parent = await owned(path.join(state, directory), guard); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
    const names = await readdir(parent); if (names.length > 10000) throw new Error('PROVIDER_ASSET_INVENTORY_INVALID');
    for (const name of names) {
      check(signal); const target = path.join(parent, name); const expected = directory === 'provider-cache' ? `${descriptor.sha256.slice(7)}.tar.gz` : descriptor.sha256.slice(7);
      if (name !== expected) { result.protected.push(`${directory}/${name}`); continue; }
      if (directory === 'provider-cache') { const info = await lstat(target); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== descriptor.size) throw new Error('PROVIDER_ASSET_CACHE_CHANGED'); await verifyArchive(target, descriptor.sha256, signal); }
      else { await owned(target, guard); await verifyProviderAssetTree(target, descriptor, signal); }
      result.paths.push(`${directory}/${name}`); deletions.push({ target, recursive: directory === 'providerpacks' }); parents.add(parent);
    }
  }
  if (action === 'owned-runtime') {
    const removed = new Set<string>();
    for (const saved of repairs) { const directory = path.join(state, saved.record.quarantine); if (!removed.has(directory)) { try { await owned(directory, guard); result.paths.push(saved.record.quarantine); deletions.push({ target: directory, recursive: true }); removed.add(directory); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; } } result.paths.push(saved.file); deletions.push({ target: path.join(state, saved.file), recursive: false }); } parents.add(state);
  }
  if (!dryRun) { for (const deletion of deletions) { check(signal); await rm(deletion.target, { recursive: deletion.recursive }); } for (const parent of parents) await fsyncDirectory(parent, await openStateAuthority(parent, guard)); }
  return result;
}
