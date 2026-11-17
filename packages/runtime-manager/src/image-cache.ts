import { createHash } from 'node:crypto';
import { lstat, rm } from 'node:fs/promises';
import path from 'node:path';
import type { ImageTransport } from './receipt.js';
import { verifyArchive } from './receipt.js';
import { guardedIdentity } from '../../workspace/src/guard.js';
import type { GuardIdentity } from '../../workspace/src/guard.js';
import { boundedRead, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';

type Source = { format: 'oci-archive' | 'docker-archive'; path: string; index_digest?: string };
export type ImageCacheEntry = { sha256: string; size: number; identity: GuardIdentity; source: Source; source_contract_sha256: string; last_used: number };
type Index = { schema_version: 1; root_identity: GuardIdentity; sequence: number; entries: ImageCacheEntry[] };
const SHA = /^sha256:[0-9a-f]{64}$/;
const NAME = '.image-cache.json';
function identity(value: unknown): value is GuardIdentity { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === 'device,inode' && /^\d{1,40}$/.test((value as GuardIdentity).device) && /^\d{1,40}$/.test((value as GuardIdentity).inode); }
function same(a: GuardIdentity, b: GuardIdentity) { return a.device === b.device && a.inode === b.inode; }
function source(value: unknown): value is Source { if (!value || typeof value !== 'object' || Array.isArray(value)) return false; const item = value as Source; return Object.keys(item).sort().join(',') === (item.index_digest === undefined ? 'format,path' : 'format,index_digest,path') && ['oci-archive', 'docker-archive'].includes(item.format) && typeof item.path === 'string' && item.path.length < 4096 && !item.path.startsWith('/') && !/[\\:\0\r\n]/.test(item.path) && item.path.split('/').every(part => !!part && part !== '.' && part !== '..') && (item.index_digest === undefined || item.format === 'oci-archive' && SHA.test(item.index_digest)); }
function contract(item: Pick<ImageCacheEntry, 'sha256' | 'size' | 'source'>): string { return `sha256:${createHash('sha256').update(JSON.stringify({ sha256: item.sha256, size: item.size, source: { format: item.source.format, path: item.source.path, ...(item.source.index_digest ? { index_digest: item.source.index_digest } : {}) } })).digest('hex')}`; }
async function index(root: string, guard: string): Promise<Index> {
  const rootIdentity = await guardedIdentity(guard, root); let value: Index;
  try { value = JSON.parse((await boundedRead(path.join(root, NAME), 256 * 1024, await openStateAuthority(root, guard))).toString('utf8')) as Index; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { schema_version: 1, root_identity: rootIdentity, sequence: 0, entries: [] }; throw error; }
  if (!value || Object.keys(value).sort().join(',') !== 'entries,root_identity,schema_version,sequence' || value.schema_version !== 1 || !identity(value.root_identity) || !same(value.root_identity, rootIdentity) || !Number.isSafeInteger(value.sequence) || value.sequence < 0 || !Array.isArray(value.entries) || value.entries.length > 256 || new Set(value.entries.map(entry => entry?.sha256)).size !== value.entries.length || value.entries.some(entry => !entry || Object.keys(entry).sort().join(',') !== 'identity,last_used,sha256,size,source,source_contract_sha256' || !SHA.test(entry.sha256) || !Number.isSafeInteger(entry.size) || entry.size < 1 || entry.size > 20 * 1024 ** 3 || !identity(entry.identity) || !source(entry.source) || entry.source_contract_sha256 !== contract(entry) || !Number.isSafeInteger(entry.last_used) || entry.last_used < 1 || entry.last_used > value.sequence)) throw new Error('IMAGE_CACHE_OWNERSHIP_INDEX_INVALID');
  return value;
}
async function save(root: string, guard: string, value: Index): Promise<void> { if (!same(value.root_identity, await guardedIdentity(guard, root))) throw new Error('IMAGE_CACHE_ROOT_CHANGED'); await durableWrite(path.join(root, NAME), Buffer.from(`${JSON.stringify(value)}\n`), await openStateAuthority(root, guard)); }
/** Ownership metadata alone never certifies current bytes; repair uses its inode binding. */
export async function ownedImageCacheEntry(root: string, guard: string, sha256: string): Promise<ImageCacheEntry | undefined> { return (await index(root, guard)).entries.find(entry => entry.sha256 === sha256); }
async function inspect(root: string, entry: ImageCacheEntry, verifyIdentity: boolean): Promise<boolean> {
  const file = path.join(root, `${entry.sha256.slice(7)}.tar`); let info;
  try { info = await lstat(file, { bigint: true }); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n || info.size !== BigInt(entry.size) || typeof process.getuid === 'function' && info.uid !== BigInt(process.getuid()) || process.platform !== 'win32' && (Number(info.mode) & 0o222) !== 0 || verifyIdentity && (info.dev.toString() !== entry.identity.device || info.ino.toString() !== entry.identity.inode)) throw new Error('IMAGE_CACHE_OWNED_FILE_CHANGED');
  await verifyArchive(file, entry.sha256); return true;
}
/** Called only under the engine's native image-import lock after hash admission. */
export async function recordImageCacheAccess(root: string, guard: string, transport: ImageTransport): Promise<void> {
  const current = await index(root, guard); const file = path.join(root, `${transport.sha256.slice(7)}.tar`); const info = await lstat(file, { bigint: true });
  const origin: Source = { format: transport.format, path: transport.path, ...(transport.indexDigest ? { index_digest: transport.indexDigest } : {}) };
  const entry: ImageCacheEntry = { sha256: transport.sha256, size: transport.sizeBytes, identity: { device: info.dev.toString(), inode: info.ino.toString() }, source: origin, source_contract_sha256: '', last_used: current.sequence + 1 }; if (!source(origin) || !SHA.test(entry.sha256) || !Number.isSafeInteger(entry.size) || entry.size < 1 || entry.size > 20 * 1024 ** 3 || !Number.isSafeInteger(entry.last_used)) throw new Error('IMAGE_CACHE_SOURCE_INVALID');
  await inspect(root, entry, true); entry.source_contract_sha256 = contract(entry); current.entries = current.entries.filter(item => item.sha256 !== entry.sha256); current.entries.push(entry); if (current.entries.length > 256) throw new Error('IMAGE_CACHE_INDEX_LIMIT'); current.sequence = entry.last_used; await save(root, guard, current);
}
/** Maintenance holds the provider gate and native import lock; active readers block it. */
export async function reclaimImageCache(root: string, guard: string, options: { dryRun: boolean; all?: boolean; keep?: ReadonlySet<string>; maxBytes?: number; maxEntries?: number }): Promise<{ removed: string[]; retained: string[]; bytes: number }> {
  const current = await index(root, guard); const present: ImageCacheEntry[] = [];
  for (const entry of current.entries) if (await inspect(root, entry, true)) present.push(entry);
  const maxBytes = options.maxBytes ?? 4 * 1024 ** 3, maxEntries = options.maxEntries ?? 8; if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || !Number.isSafeInteger(maxEntries) || maxEntries < 0) throw new Error('IMAGE_CACHE_RETENTION_INVALID');
  const retained = new Map(present.map(entry => [entry.sha256, entry])); let bytes = present.reduce((sum, entry) => sum + entry.size, 0); const removed: string[] = [];
  for (const entry of [...present].sort((a, b) => a.last_used - b.last_used)) { if (!options.all && (options.keep?.has(entry.sha256) || bytes <= maxBytes && retained.size <= maxEntries)) continue; retained.delete(entry.sha256); bytes -= entry.size; removed.push(`${entry.sha256.slice(7)}.tar`); }
  if (!options.dryRun) { const previousCount = current.entries.length; for (const name of removed) await rm(path.join(root, name)); await fsyncDirectory(root, await openStateAuthority(root, guard)); current.entries = [...retained.values()]; if (removed.length || previousCount !== current.entries.length) await save(root, guard, current); }
  return { removed, retained: [...retained.keys()].map(sha => `${sha.slice(7)}.tar`), bytes };
}
