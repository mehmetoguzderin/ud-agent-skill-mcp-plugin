import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { boundedRead, durableWrite, fsyncDirectory, JournalStore, openStateAuthority } from '../../workspace/src/journal.js';
import { guardedIdentity, guardedOwnedDirectory, guardedPrivateDirectory } from '../../workspace/src/guard.js';
import type { GuardIdentity } from '../../workspace/src/guard.js';
import type { ImageTransport } from '../../runtime-manager/src/receipt.js';
import { verifyArchive } from '../../runtime-manager/src/receipt.js';
import { withWorkerImageImportLock } from '../../runtime-manager/src/worker-image-lock.js';
import { ownedImageCacheEntry, recordImageCacheAccess } from '../../runtime-manager/src/image-cache.js';
import { requireProviderMaintenance } from './provider-leases.js';

type Snapshot = { device: string; inode: string; size: number; sha256: string; mode: number };
export type ImageRepairRecord = { schema_version: 1; sha256: string; size: number; root_identity: GuardIdentity; phase: 'planned' | 'quarantined' | 'completed' | 'rolled_back'; directory: string; token: string; directory_identity: GuardIdentity | null; original: Snapshot; failed?: Snapshot };
const SHA = /^sha256:[0-9a-f]{64}$/;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const MAX_EVIDENCE_RECORDS = 32;
const MAX_EVIDENCE_BYTES = 4 * 1024 ** 3;
const NAME = new RegExp(`^\\.image-repair-(?:([0-9a-f]{64})|history-(${UUID}))\\.json$`);
function identity(value: unknown): value is GuardIdentity { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === 'device,inode' && /^\d{1,40}$/.test((value as GuardIdentity).device) && /^\d{1,40}$/.test((value as GuardIdentity).inode); }
function snapshot(value: unknown): value is Snapshot { const item = value as Snapshot; return identity(item && { device: item.device, inode: item.inode }) && !!item && Object.keys(item).sort().join(',') === 'device,inode,mode,sha256,size' && SHA.test(item.sha256) && Number.isSafeInteger(item.size) && item.size >= 0 && item.size <= 20 * 1024 ** 3 && Number.isSafeInteger(item.mode) && item.mode >= 0 && item.mode <= 0o7777; }
function parse(value: unknown): ImageRepairRecord { const item = value as ImageRepairRecord; if (!item || Object.keys(item).filter(key => key !== 'failed').sort().join(',') !== 'directory,directory_identity,original,phase,root_identity,schema_version,sha256,size,token' || item.schema_version !== 1 || !SHA.test(item.sha256) || !Number.isSafeInteger(item.size) || item.size < 1 || item.size > 20 * 1024 ** 3 || !identity(item.root_identity) || !new RegExp(`^\\.image-quarantine-${UUID}$`).test(item.directory) || !/^[0-9a-f]{64}$/.test(item.token) || item.directory_identity !== null && !identity(item.directory_identity) || !['planned', 'quarantined', 'completed', 'rolled_back'].includes(item.phase) || item.phase !== 'planned' && item.directory_identity === null || !snapshot(item.original) || item.failed !== undefined && !snapshot(item.failed)) throw new Error('IMAGE_REPAIR_JOURNAL_INVALID'); return item; }
function same(a: GuardIdentity, b: GuardIdentity): boolean { return a.device === b.device && a.inode === b.inode; }
function cancel(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('WORKER_CANCELLED'); }
async function exists(file: string): Promise<boolean> { try { await lstat(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; } }
async function observe(file: string, signal?: AbortSignal): Promise<Snapshot> {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { const before = await handle.stat({ bigint: true }); if (!before.isFile() || before.nlink !== 1n || before.size > 20n * 1024n ** 3n || typeof process.getuid === 'function' && before.uid !== BigInt(process.getuid())) throw new Error('IMAGE_REPAIR_UNOWNED_PATH');
    const hash = createHash('sha256'); const buffer = Buffer.alloc(1024 * 1024); let offset = 0;
    for (;;) { cancel(signal); const part = await handle.read(buffer, 0, buffer.length, offset); if (!part.bytesRead) break; offset += part.bytesRead; if (BigInt(offset) > before.size) throw new Error('IMAGE_REPAIR_FILE_CHANGED'); hash.update(buffer.subarray(0, part.bytesRead)); }
    const after = await handle.stat({ bigint: true }); if (BigInt(offset) !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mode !== after.mode || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('IMAGE_REPAIR_FILE_CHANGED'); return { device: before.dev.toString(), inode: before.ino.toString(), size: offset, sha256: `sha256:${hash.digest('hex')}`, mode: Number(before.mode & 0o7777n) };
  } finally { await handle.close(); }
}
async function check(file: string, expected: Snapshot): Promise<void> { if (JSON.stringify(await observe(file)) !== JSON.stringify(expected)) throw new Error('IMAGE_REPAIR_FILE_CHANGED'); }
export async function verifyImageRepairQuarantine(root: string, guard: string, record: ImageRepairRecord): Promise<void> {
  const directory = path.join(root, record.directory); if (!await exists(directory)) { if (record.phase === 'planned' && record.directory_identity === null) return; throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); }
  await guardedPrivateDirectory(guard, root, record.directory, record.root_identity); const actual = await guardedIdentity(guard, directory); if (record.directory_identity && !same(record.directory_identity, actual)) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED');
  const marker = await boundedRead(path.join(directory, '.ud-agent-directory-owner'), 128, await openStateAuthority(directory, guard)); if (marker.toString('ascii') !== record.token) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); const names = await readdir(directory); if (names.some(name => !['.ud-agent-directory-owner', 'original.tar', 'failed.tar'].includes(name))) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED');
  const original = path.join(directory, 'original.tar'); if (await exists(original)) { if (record.phase === 'rolled_back') throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); await check(original, record.original); } else if (['quarantined', 'completed'].includes(record.phase)) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED');
  const failed = path.join(directory, 'failed.tar'); if (await exists(failed)) { if (!record.failed) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); await check(failed, record.failed); } else if (record.failed) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED');
}
async function sourcePreflight(sourceRoot: string, transport: ImageTransport, signal?: AbortSignal): Promise<boolean> {
  if (!path.isAbsolute(sourceRoot) || typeof transport.path !== 'string' || transport.path.startsWith('/') || /[\\:\0]/.test(transport.path) || transport.path.split('/').some(part => !part || part === '.' || part === '..') || !SHA.test(transport.sha256) || !Number.isSafeInteger(transport.sizeBytes) || transport.sizeBytes < 1 || transport.sizeBytes > 20 * 1024 ** 3) throw new Error('IMAGE_REPAIR_SOURCE_INVALID');
  let selected = sourceRoot;
  try { for (const part of transport.path.split('/')) { selected = path.join(selected, part); const info = await lstat(selected); if (info.isSymbolicLink()) throw new Error('IMAGE_REPAIR_SOURCE_INVALID'); } } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
  const info = await lstat(selected); if (!info.isFile() || info.size !== transport.sizeBytes) throw new Error('IMAGE_REPAIR_SOURCE_INTEGRITY_FAILED'); await verifyArchive(selected, transport.sha256, signal); return true;
}
export async function imageRepairRecords(root: string, guard: string): Promise<{ name: string; record: ImageRepairRecord }[]> {
  const rows: { name: string; record: ImageRepairRecord }[] = []; const names = await readdir(root); if (names.length > 10000) throw new Error('IMAGE_REPAIR_INVENTORY_LIMIT'); const actual = await guardedIdentity(guard, root);
  for (const name of names) { if (name === '.image-repair-cleanup.json' || !name.startsWith('.image-repair-') || !name.endsWith('.json')) continue; const match = NAME.exec(name); if (!match) throw new Error('IMAGE_REPAIR_JOURNAL_INVALID'); const record = parse(JSON.parse((await boundedRead(path.join(root, name), 16384, await openStateAuthority(root, guard))).toString('utf8'))); if (match[1] && record.sha256 !== `sha256:${match[1]}` || !same(record.root_identity, actual)) throw new Error('IMAGE_REPAIR_ROOT_CHANGED'); rows.push({ name, record }); } return rows;
}
type Cleanup = { schema_version: 1; root_identity: GuardIdentity; phase: 'planned' | 'completed'; entries: { name: string; sha256: string; record: ImageRepairRecord }[] };
export async function planImageRepairCleanup(root: string, guard: string): Promise<Cleanup> {
  const entries: Cleanup['entries'] = [];
  for (const row of await imageRepairRecords(root, guard)) { if (!['completed', 'rolled_back'].includes(row.record.phase)) throw new Error('IMAGE_REPAIR_RECOVERY_REQUIRED'); await verifyImageRepairQuarantine(root, guard, row.record); const bytes = await boundedRead(path.join(root, row.name), 16384, await openStateAuthority(root, guard)); entries.push({ ...row, sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}` }); }
  return { schema_version: 1, root_identity: await guardedIdentity(guard, root), phase: 'planned', entries };
}
function cleanupPlan(value: unknown): Cleanup {
  const item = value as Cleanup;
  if (!item || Object.keys(item).sort().join(',') !== 'entries,phase,root_identity,schema_version' || item.schema_version !== 1 || !identity(item.root_identity) || !['planned', 'completed'].includes(item.phase) || !Array.isArray(item.entries) || item.entries.length > 64 || new Set(item.entries.map(entry => entry?.name)).size !== item.entries.length || new Set(item.entries.map(entry => entry?.record?.directory)).size !== item.entries.length) throw new Error('IMAGE_REPAIR_CLEANUP_INVALID');
  for (const entry of item.entries) { if (!entry || Object.keys(entry).sort().join(',') !== 'name,record,sha256' || !NAME.test(entry.name) || !SHA.test(entry.sha256)) throw new Error('IMAGE_REPAIR_CLEANUP_INVALID'); parse(entry.record); if (!['completed', 'rolled_back'].includes(entry.record.phase) || !same(item.root_identity, entry.record.root_identity)) throw new Error('IMAGE_REPAIR_CLEANUP_INVALID'); } return item;
}
/** Explicit owned-runtime uninstall only; ordinary repair retains the evidence. */
export async function cleanImageRepairArtifacts(providerRoot: string, root: string, guard: string, dryRun: boolean): Promise<string[]> {
  if (!dryRun) await requireProviderMaintenance(guard, providerRoot); const native = await openStateAuthority(root, guard); const file = path.join(root, '.image-repair-cleanup.json'); let plan: Cleanup | undefined;
  try { plan = cleanupPlan(JSON.parse((await boundedRead(file, 256 * 1024, native)).toString('utf8'))); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  if (!plan || plan.phase === 'completed') { plan = await planImageRepairCleanup(root, guard); if (!plan.entries.length) return []; if (!dryRun) await durableWrite(file, Buffer.from(`${JSON.stringify(plan)}\n`), native); }
  if (!same(plan.root_identity, await guardedIdentity(guard, root))) throw new Error('IMAGE_REPAIR_ROOT_CHANGED');
  const paths: string[] = []; const remaining: { directory: string; record: ImageRepairRecord; names: string[]; metadata: string }[] = [];
  for (const entry of plan.entries) {
    const metadata = path.join(root, entry.name); if (await exists(metadata)) { const bytes = await boundedRead(metadata, 16384, native); if (`sha256:${createHash('sha256').update(bytes).digest('hex')}` !== entry.sha256) throw new Error('IMAGE_REPAIR_JOURNAL_CHANGED'); }
    const record = entry.record, directory = path.join(root, record.directory), expected = new Map<string, Snapshot>(); if (record.phase === 'completed') expected.set('original.tar', record.original); if (record.failed) expected.set('failed.tar', record.failed);
    let names: string[] = [];
    if (await exists(directory)) { await guardedPrivateDirectory(guard, root, record.directory, plan.root_identity); const actual = await guardedIdentity(guard, directory); if (!record.directory_identity || !same(actual, record.directory_identity)) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); names = await readdir(directory); if (names.some(name => name !== '.ud-agent-directory-owner' && !expected.has(name)) || !names.includes('.ud-agent-directory-owner') && names.length) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); if (names.includes('.ud-agent-directory-owner')) { const marker = await boundedRead(path.join(directory, '.ud-agent-directory-owner'), 128, await openStateAuthority(directory, guard)); if (marker.toString('ascii') !== record.token) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); }
      for (const name of names.filter(name => name !== '.ud-agent-directory-owner')) { const actual = await observe(path.join(directory, name)); const wanted = expected.get(name)!; const mode = process.platform === 'win32' && actual.mode === (wanted.mode | 0o222) ? wanted.mode : actual.mode; if (JSON.stringify({ ...actual, mode }) !== JSON.stringify(wanted)) throw new Error('IMAGE_REPAIR_FILE_CHANGED'); }
    }
    remaining.push({ directory, record, names, metadata }); paths.push(entry.name, record.directory);
  }
  if (!dryRun) {
    for (const item of remaining) { await requireProviderMaintenance(guard, providerRoot); if (!same(plan.root_identity, await guardedIdentity(guard, root))) throw new Error('IMAGE_REPAIR_ROOT_CHANGED'); for (const name of item.names.filter(name => name !== '.ud-agent-directory-owner')) { if (process.platform === 'win32') await chmod(path.join(item.directory, name), 0o600); await rm(path.join(item.directory, name)); } if (await exists(item.directory)) await fsyncDirectory(item.directory, await openStateAuthority(item.directory, guard)); await guardedOwnedDirectory(guard, root, item.record.directory, plan.root_identity, item.record.token, 'rmdir-owned', item.record.directory_identity ?? undefined); await rm(item.metadata, { force: true }); await fsyncDirectory(root, native); }
    plan.phase = 'completed'; await durableWrite(file, Buffer.from(`${JSON.stringify(plan)}\n`), native);
  }
  return [...paths, '.image-repair-cleanup.json'];
}
/** Only an opaque active provider-maintenance scope can authorize quarantine. */
export async function repairWorkerImageTransport(input: { sourceRoot: string; stateRoot: string; guard: string; transport: ImageTransport; network: 'offline' | 'bootstrap_only'; acquire: () => Promise<string | null>; signal?: AbortSignal }): Promise<{ repaired: boolean; quarantine?: string }> {
  await requireProviderMaintenance(input.guard, input.stateRoot); cancel(input.signal);
  const transport = input.transport; if (!path.isAbsolute(input.sourceRoot) || !['offline', 'bootstrap_only'].includes(input.network) || !transport || !['oci-archive', 'docker-archive'].includes(transport.format) || !SHA.test(transport.sha256) || !Number.isSafeInteger(transport.sizeBytes) || transport.sizeBytes < 1 || transport.sizeBytes > 20 * 1024 ** 3 || typeof transport.path !== 'string' || transport.path.startsWith('/') || /[\\:\0]/.test(transport.path) || transport.path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('IMAGE_REPAIR_SOURCE_INVALID');
  const root = path.join(input.stateRoot, 'images'); await mkdir(root, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; }); const store = await JournalStore.open(root, input.guard);
  return withWorkerImageImportLock(store.root, input.guard, async () => {
    const rootIdentity = await guardedIdentity(input.guard, store.root), native = await openStateAuthority(store.root, input.guard); const target = path.join(store.root, `${input.transport.sha256.slice(7)}.tar`); const journalName = `.image-repair-${input.transport.sha256.slice(7)}.json`, journal = path.join(store.root, journalName); const rows = await imageRepairRecords(store.root, input.guard); let saved = rows.find(row => row.name === journalName)?.record; if (saved) await verifyImageRepairQuarantine(store.root, input.guard, saved);
    const valid = async () => { if (!await exists(target)) return false; const item = await observe(target, input.signal); return item.sha256 === input.transport.sha256 && item.size === input.transport.sizeBytes && (process.platform === 'win32' || (item.mode & 0o222) === 0); };
    if (saved && saved.size !== input.transport.sizeBytes) throw new Error('IMAGE_REPAIR_SOURCE_CHANGED');
    const save = async () => { await requireProviderMaintenance(input.guard, input.stateRoot); if (!same(rootIdentity, await guardedIdentity(input.guard, store.root))) throw new Error('IMAGE_REPAIR_ROOT_CHANGED'); await durableWrite(journal, Buffer.from(`${JSON.stringify(saved)}\n`), native); };
    if (saved?.phase === 'quarantined' && await valid()) { await check(path.join(store.root, saved.directory, 'original.tar'), saved.original); await recordImageCacheAccess(store.root, input.guard, input.transport); saved.phase = 'completed'; await save(); return { repaired: true, quarantine: saved.directory }; }
    if ((!saved || saved.phase === 'completed' || saved.phase === 'rolled_back') && await valid()) { await recordImageCacheAccess(store.root, input.guard, input.transport); return { repaired: false }; }
    if (!saved && !await exists(target)) return { repaired: false };
    const available = await sourcePreflight(input.sourceRoot, input.transport, input.signal); if (!available && input.network === 'offline') throw new Error('IMAGE_REPAIR_OFFLINE_SOURCE_MISSING');
    const restoredOwnership = saved?.phase === 'rolled_back' ? saved.original : undefined;
    if (saved && ['completed', 'rolled_back'].includes(saved.phase)) { if (rows.length >= MAX_EVIDENCE_RECORDS) throw new Error('IMAGE_REPAIR_EVIDENCE_LIMIT'); await durableWrite(path.join(store.root, `.image-repair-history-${randomUUID()}.json`), Buffer.from(`${JSON.stringify(saved)}\n`), native); saved = undefined; }
    if (!saved) {
      if (!await exists(target)) { const acquired = await input.acquire(); if (acquired !== target || !await valid()) throw new Error('IMAGE_REPAIR_SOURCE_UNAVAILABLE'); return { repaired: false }; }
      const original = await observe(target, input.signal); const retainedBytes = rows.reduce((total, row) => total + (row.record.phase === 'rolled_back' ? 0 : row.record.original.size) + (row.record.failed?.size ?? 0), 0); if (rows.length >= MAX_EVIDENCE_RECORDS || retainedBytes + original.size > MAX_EVIDENCE_BYTES) throw new Error('IMAGE_REPAIR_EVIDENCE_LIMIT'); const ownership = await ownedImageCacheEntry(store.root, input.guard, input.transport.sha256); const indexed = ownership?.size === input.transport.sizeBytes && ownership.identity.device === original.device && ownership.identity.inode === original.inode; const restored = restoredOwnership && JSON.stringify(restoredOwnership) === JSON.stringify(original); if (!indexed && !restored) throw new Error('IMAGE_REPAIR_OWNERSHIP_REQUIRED');
      saved = { schema_version: 1, sha256: input.transport.sha256, size: input.transport.sizeBytes, root_identity: rootIdentity, phase: 'planned', directory: `.image-quarantine-${randomUUID()}`, token: randomBytes(32).toString('hex'), directory_identity: null, original }; await save();
    }
    const owned = await guardedOwnedDirectory(input.guard, store.root, saved.directory, rootIdentity, saved.token, 'mkdir-owned'); if (!owned || saved.directory_identity && !same(saved.directory_identity, owned)) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED'); saved.directory_identity = owned;
    const directory = path.join(store.root, saved.directory), original = path.join(directory, 'original.tar');
    await guardedPrivateDirectory(input.guard, store.root, saved.directory, rootIdentity); const names = await readdir(directory); if (names.some(name => !['.ud-agent-directory-owner', 'original.tar', 'failed.tar'].includes(name))) throw new Error('IMAGE_REPAIR_QUARANTINE_CHANGED');
    const from = await exists(target), to = await exists(original);
    if (saved.phase === 'planned' && from && !to) { await check(target, saved.original); await save(); await rename(target, original); await fsyncDirectory(store.root, native); await fsyncDirectory(directory, await openStateAuthority(directory, input.guard)); }
    else if (!from && to) await check(original, saved.original);
    else throw new Error('IMAGE_REPAIR_RECOVERY_REQUIRED');
    saved.phase = 'quarantined'; await save();
    try { cancel(input.signal); const acquired = await input.acquire(); if (acquired !== target || !await valid()) throw new Error('IMAGE_REPAIR_SOURCE_UNAVAILABLE'); saved.phase = 'completed'; await save(); return { repaired: true, quarantine: saved.directory }; }
    catch (failure) {
      await check(original, saved.original);
      if (await exists(target)) { const candidate = await observe(target); if (candidate.sha256 !== input.transport.sha256 || candidate.size !== input.transport.sizeBytes || await exists(path.join(directory, 'failed.tar'))) throw new Error('IMAGE_REPAIR_RECOVERY_REQUIRED', { cause: failure }); saved.failed = candidate; await save(); await rename(target, path.join(directory, 'failed.tar')); }
      await rename(original, target); await fsyncDirectory(store.root, native); await fsyncDirectory(directory, await openStateAuthority(directory, input.guard)); saved.phase = 'rolled_back'; await save(); throw new Error('IMAGE_REPAIR_FAILED: previous owned cache restored', { cause: failure });
    }
  });
}
