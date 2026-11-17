import { randomBytes } from 'node:crypto';
import { chmod, lstat, readdir, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import type { ImageTransport } from './receipt.js';
import { verifyArchive } from './receipt.js';
import { guardedIdentity, guardedOwnedDirectory, guardedPrivateDirectory } from '../../workspace/src/guard.js';
import type { GuardIdentity } from '../../workspace/src/guard.js';
import { boundedRead, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';
import { recordImageCacheAccess } from './image-cache.js';

type Receipt = { sha256: string; size: number };
type Record = { schema_version: 1; sha256: string; size: number; root_identity: GuardIdentity; directory: string; token: string; directory_identity: GuardIdentity | null; phase: 'planned' | 'writing' | 'ready' | 'published'; transport?: ImageTransport };
const SHA = /^sha256:[0-9a-f]{64}$/;
const journalName = (sha: string) => `.image-import-${sha.slice(7)}.json`;
function same(a: GuardIdentity, b: GuardIdentity) { return a.device === b.device && a.inode === b.inode; }
function identity(value: unknown): value is GuardIdentity { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === 'device,inode' && /^\d{1,40}$/.test((value as GuardIdentity).device) && /^\d{1,40}$/.test((value as GuardIdentity).inode); }
function parse(value: unknown): Record {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('IMAGE_IMPORT_STAGING_JOURNAL_INVALID');
  const record = value as Record;
  if (Object.keys(record).filter(key => key !== 'transport').sort().join(',') !== 'directory,directory_identity,phase,root_identity,schema_version,sha256,size,token' || record.schema_version !== 1 || !SHA.test(record.sha256) || !Number.isSafeInteger(record.size) || record.size < 1 || record.size > 20 * 1024 ** 3 || !identity(record.root_identity) || !/^[0-9a-f]{64}$/.test(record.token) || record.directory !== `.image-import-${record.sha256.slice(7, 23)}-${record.token.slice(0, 16)}` || record.directory_identity !== null && !identity(record.directory_identity) || !['planned', 'writing', 'ready', 'published'].includes(record.phase) || record.phase !== 'planned' && record.directory_identity === null) throw new Error('IMAGE_IMPORT_STAGING_JOURNAL_INVALID');
  const transport = record.transport; if (transport !== undefined && (!transport || typeof transport !== 'object' || Array.isArray(transport) || Object.keys(transport).sort().join(',') !== (transport.indexDigest === undefined ? 'format,path,sha256,sizeBytes' : 'format,indexDigest,path,sha256,sizeBytes') || !['oci-archive', 'docker-archive'].includes(transport.format) || transport.sha256 !== record.sha256 || transport.sizeBytes !== record.size || typeof transport.path !== 'string' || transport.path.length > 4096 || transport.path.startsWith('/') || /[\\:\0\r\n]/.test(transport.path) || transport.path.split('/').some(part => !part || part === '.' || part === '..') || transport.indexDigest !== undefined && (transport.format !== 'oci-archive' || !SHA.test(transport.indexDigest)))) throw new Error('IMAGE_IMPORT_STAGING_JOURNAL_INVALID');
  return record;
}
async function present(file: string): Promise<boolean> { try { await lstat(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; } }
async function inspect(root: string, guard: string, record: Record): Promise<{ directory: boolean; file: boolean }> {
  const rootIdentity = await guardedIdentity(guard, root); if (!same(rootIdentity, record.root_identity)) throw new Error('IMAGE_IMPORT_STAGING_ROOT_CHANGED');
  const directory = path.join(root, record.directory);
  const directoryExists = await present(directory);
  if (record.phase === 'published' || record.phase === 'ready' && !directoryExists) { const cached = path.join(root, `${record.sha256.slice(7)}.tar`); const info = await lstat(cached); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== record.size) throw new Error('IMAGE_IMPORT_STAGING_PUBLICATION_CHANGED'); await verifyArchive(cached, record.sha256); }
  if (!directoryExists) return { directory: false, file: false };
  await guardedPrivateDirectory(guard, root, record.directory, rootIdentity);
  const actual = await guardedIdentity(guard, directory); if (record.directory_identity && !same(record.directory_identity, actual)) throw new Error('IMAGE_IMPORT_STAGING_IDENTITY_CHANGED');
  const native = await openStateAuthority(directory, guard); const marker = await boundedRead(path.join(directory, '.ud-agent-directory-owner'), 128, native); if (marker.toString('ascii') !== record.token) throw new Error('IMAGE_IMPORT_STAGING_OWNER_CHANGED');
  const names = await readdir(directory); if (names.some(name => name !== '.ud-agent-directory-owner' && name !== 'worker.tar')) throw new Error('IMAGE_IMPORT_STAGING_HAS_UNOWNED_FILES');
  const file = names.includes('worker.tar');
  if (file) { const info = await lstat(path.join(directory, 'worker.tar')); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > record.size || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('IMAGE_IMPORT_STAGING_FILE_CHANGED'); }
  if (record.phase === 'ready' && file) { const info = await lstat(path.join(directory, 'worker.tar')); if (info.size !== record.size) throw new Error('IMAGE_IMPORT_STAGING_FILE_CHANGED'); await verifyArchive(path.join(directory, 'worker.tar'), record.sha256); }
  if (record.phase === 'ready' && !file) { const cached = path.join(root, `${record.sha256.slice(7)}.tar`); const info = await lstat(cached); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size !== record.size) throw new Error('IMAGE_IMPORT_STAGING_PUBLICATION_CHANGED'); await verifyArchive(cached, record.sha256); }
  return { directory: true, file };
}
/** Caller holds the image-import lock (or provider maintenance plus that lock). */
export async function recoverImageImportStaging(root: string, guard: string, receipts: ReadonlyMap<string, Receipt>, dryRun: boolean): Promise<{ paths: string[]; protected: string[] }> {
  const native = await openStateAuthority(root, guard); const names = await readdir(root); if (names.length > 10000) throw new Error('IMAGE_IMPORT_STAGING_INVENTORY_LIMIT');
  const records: { name: string; record: Record; contents: { directory: boolean; file: boolean } }[] = []; const protectedPaths: string[] = [];
  for (const name of names.filter(name => name.startsWith('.image-import-') && name.endsWith('.json')).sort()) {
    const record = parse(JSON.parse((await boundedRead(path.join(root, name), 8192, native)).toString('utf8'))); if (name !== journalName(record.sha256)) throw new Error('IMAGE_IMPORT_STAGING_JOURNAL_INVALID');
    const receipt = receipts.get(`${record.sha256.slice(7)}.tar`); if (!receipt) { protectedPaths.push(name, record.directory); continue; } if (receipt.sha256 !== record.sha256 || receipt.size !== record.size) throw new Error('IMAGE_IMPORT_STAGING_RECEIPT_CHANGED');
    records.push({ name, record, contents: await inspect(root, guard, record) });
  }
  const paths: string[] = [];
  for (const { name, record, contents } of records) {
    paths.push(name, record.directory);
    if (dryRun) continue;
    if (record.transport && (record.phase === 'published' || record.phase === 'ready' && !contents.file)) await recordImageCacheAccess(root, guard, record.transport);
    if (contents.file) { await chmod(path.join(root, record.directory, 'worker.tar'), 0o600); await rm(path.join(root, record.directory, 'worker.tar')); await fsyncDirectory(path.join(root, record.directory), await openStateAuthority(path.join(root, record.directory), guard)); }
    await guardedOwnedDirectory(guard, root, record.directory, record.root_identity, record.token, 'rmdir-owned', record.directory_identity ?? undefined);
    await rm(path.join(root, name)); await fsyncDirectory(root, native);
  }
  return { paths, protected: protectedPaths };
}

/** Native token-bound directories make even interrupted first creation recoverable. */
export async function beginImageImportStaging(root: string, guard: string, receipt: ImageTransport): Promise<{ filename: string; publish: () => Promise<void>; cleanup: () => Promise<void> }> {
  const receipts = new Map([[`${receipt.sha256.slice(7)}.tar`, { sha256: receipt.sha256, size: receipt.sizeBytes }]]); await recoverImageImportStaging(root, guard, receipts, false);
  const origin: ImageTransport = receipt.format === 'oci-archive' ? { format: 'oci-archive', path: receipt.path, sha256: receipt.sha256, sizeBytes: receipt.sizeBytes, ...(receipt.indexDigest ? { indexDigest: receipt.indexDigest } : {}) } : { format: 'docker-archive', path: receipt.path, sha256: receipt.sha256, sizeBytes: receipt.sizeBytes };
  const token = randomBytes(32).toString('hex'); const record: Record = { schema_version: 1, sha256: receipt.sha256, size: receipt.sizeBytes, root_identity: await guardedIdentity(guard, root), directory: `.image-import-${receipt.sha256.slice(7, 23)}-${token.slice(0, 16)}`, token, directory_identity: null, phase: 'planned', transport: origin }; parse(record);
  const journal = path.join(root, journalName(receipt.sha256)); const native = await openStateAuthority(root, guard); const save = () => durableWrite(journal, Buffer.from(`${JSON.stringify(record)}\n`), native); await save();
  const directoryIdentity = await guardedOwnedDirectory(guard, root, record.directory, record.root_identity, token, 'mkdir-owned'); if (!directoryIdentity) throw new Error('IMAGE_IMPORT_STAGING_CREATE_FAILED'); record.directory_identity = directoryIdentity; record.phase = 'writing'; await save();
  const filename = path.join(root, record.directory, 'worker.tar');
  return { filename, cleanup: async () => { await recoverImageImportStaging(root, guard, receipts, false); }, publish: async () => {
    await inspect(root, guard, record); const info = await lstat(filename); if (info.size !== record.size) throw new Error('IMAGE_IMPORT_STAGING_FILE_CHANGED'); await verifyArchive(filename, record.sha256); await chmod(filename, 0o400); record.phase = 'ready'; await save();
    const cached = path.join(root, `${receipt.sha256.slice(7)}.tar`); if (await present(cached)) { const prior = await lstat(cached); if (!prior.isFile() || prior.isSymbolicLink() || prior.nlink !== 1 || prior.size !== record.size) throw new Error('IMAGE_IMPORT_STAGING_PUBLICATION_CHANGED'); await verifyArchive(cached, record.sha256); await rm(filename); } else await rename(filename, cached);
    await fsyncDirectory(root, native); record.phase = 'published'; await save(); await recoverImageImportStaging(root, guard, receipts, false);
  } };
}
