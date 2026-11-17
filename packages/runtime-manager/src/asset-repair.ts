import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { boundedRead, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';
import { verifyArchive } from './receipt.js';
type Move = { from: string; to: string; device: string; inode: string };
type Journal = { schema_version: 1; kind: 'core' | 'provider'; key: string; phase: 'building' | 'completed' | 'rolled_back'; quarantine: string; moves: Move[] };
function journal(value: unknown, kind: 'core' | 'provider', key: string): Journal {
  const item = value as Journal; const pack = `${kind === 'core' ? 'corepacks' : 'providerpacks'}/${key}`; const cache = `${kind}-cache/${key}.tar.gz`;
  if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).sort().join(',') !== 'key,kind,moves,phase,quarantine,schema_version' || item.schema_version !== 1 || item.kind !== kind || item.key !== key || !['building', 'completed', 'rolled_back'].includes(item.phase) || !/^quarantine-[0-9a-f-]{36}$/.test(item.quarantine) || !Array.isArray(item.moves) || item.moves.length > 2 || item.moves.some((move, index) => !move || Object.keys(move).sort().join(',') !== 'device,from,inode,to' || ![pack, cache].includes(move.from) || move.to !== `item-${index}` || !/^\d+$/.test(move.device) || !/^\d+$/.test(move.inode)) || new Set(item.moves.map(move => move.from)).size !== item.moves.length) throw new Error('ASSET_REPAIR_JOURNAL_INVALID'); return item;
}
export async function assetRepairRecords(state: string, guard: string): Promise<{ file: string; record: Journal }[]> {
  const native = await openStateAuthority(state, guard); const result: { file: string; record: Journal }[] = []; const names = await readdir(state); if (names.length > 10000) throw new Error('ASSET_REPAIR_INVENTORY_LIMIT');
  for (const name of names) { const match = /^asset-repair-(?:(core|provider)-([0-9a-f]{64})|history-[0-9a-f-]{36})\.json$/.exec(name); if (!match) continue; const value = JSON.parse((await boundedRead(path.join(state, name), 16384, native)).toString('utf8')) as Journal; const kind = match[1] ?? value?.kind; const key = match[2] ?? value?.key; if ((kind !== 'core' && kind !== 'provider') || typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key)) throw new Error('ASSET_REPAIR_JOURNAL_INVALID'); result.push({ file: name, record: journal(value, kind, key) }); } return result;
}
async function exists(file: string): Promise<boolean> { try { await lstat(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; } }
/** Only called under the host runtime's active-lease-excluding maintenance gate. */
export async function repairOwnedAssetPack(state: string, guard: string, kind: 'core' | 'provider', archive: { sha256: string; size: number }, validate: () => Promise<void>, prepare: () => Promise<void>, signal?: AbortSignal): Promise<{ repaired: boolean; quarantine?: string }> {
  if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED');
  const key = archive.sha256.slice(7); if (!/^sha256:[0-9a-f]{64}$/.test(archive.sha256)) throw new Error('ASSET_REPAIR_RECEIPT_INVALID');
  const native = await openStateAuthority(state, guard); const pack = `${kind === 'core' ? 'corepacks' : 'providerpacks'}/${key}`; const cache = `${kind}-cache/${key}.tar.gz`; const journalPath = path.join(state, `asset-repair-${kind}-${key}.json`);
  let saved: Journal | undefined; let previous: Buffer | undefined;
  try { const bytes = await boundedRead(journalPath, 16384, native); const item = journal(JSON.parse(bytes.toString('utf8')), kind, key); if (item.phase === 'building') saved = item; else previous = bytes; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  try { await validate(); if (saved) { saved.phase = 'completed'; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(saved)}\n`), native); return { repaired: true, quarantine: saved.quarantine }; } return { repaired: false }; } catch { /* The independently verified source descriptor remains authority. */ }
  if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED');
  if (!saved) {
    if (previous) await durableWrite(path.join(state, `asset-repair-history-${randomUUID()}.json`), previous, native);
    const quarantine = `quarantine-${randomUUID()}`; await mkdir(path.join(state, quarantine), { mode: 0o700 }); await openStateAuthority(path.join(state, quarantine), guard, true); const moves: Move[] = [];
    const add = async (relative: string) => { if (!await exists(path.join(state, relative))) return; const info = await lstat(path.join(state, relative), { bigint: true }); if (info.isSymbolicLink() || !info.isDirectory() && !info.isFile() || typeof process.getuid === 'function' && info.uid !== BigInt(process.getuid())) throw new Error('ASSET_REPAIR_UNOWNED_PATH'); moves.push({ from: relative, to: `item-${moves.length}`, device: info.dev.toString(), inode: info.ino.toString() }); };
    await add(pack);
    if (await exists(path.join(state, cache))) { try { const info = await lstat(path.join(state, cache)); if (info.size !== archive.size) throw new Error('cached size differs'); await verifyArchive(path.join(state, cache), archive.sha256, signal); } catch { if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED'); await add(cache); } }
    saved = { schema_version: 1, kind, key, phase: 'building', quarantine, moves }; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(saved)}\n`), native);
  }
  const quarantine = path.join(state, saved.quarantine); await openStateAuthority(quarantine, guard); const checkIdentity = async (file: string, move: Move) => { const info = await lstat(file, { bigint: true }); if (info.isSymbolicLink() || info.dev.toString() !== move.device || info.ino.toString() !== move.inode) throw new Error('ASSET_REPAIR_IDENTITY_CHANGED'); };
  for (const move of saved.moves) { if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED'); const from = path.join(state, move.from); const to = path.join(quarantine, move.to); const a = await exists(from); const b = await exists(to); if (a && !b) { await checkIdentity(from, move); await rename(from, to); await fsyncDirectory(path.dirname(from), native); await fsyncDirectory(quarantine, native); } else if (!a && b) await checkIdentity(to, move); else throw new Error('ASSET_REPAIR_RECOVERY_REQUIRED'); }
  try { if (signal?.aborted) throw new Error('USERSPACE_SETUP_CANCELLED'); await prepare(); await validate(); saved.phase = 'completed'; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(saved)}\n`), native); return { repaired: true, quarantine: saved.quarantine }; }
  catch (failure) {
    for (const [index, move] of [...saved.moves].reverse().entries()) { const from = path.join(state, move.from); const to = path.join(quarantine, move.to); await checkIdentity(to, move); if (await exists(from)) { const info = await lstat(from); if (info.isSymbolicLink() || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('ASSET_REPAIR_RECOVERY_REQUIRED'); await rename(from, path.join(quarantine, `failed-${index}`)); } await rename(to, from); await fsyncDirectory(path.dirname(from), native); }
    saved.phase = 'rolled_back'; await durableWrite(journalPath, Buffer.from(`${JSON.stringify(saved)}\n`), native); const error = new Error(`ASSET_REPAIR_FAILED: ${failure instanceof Error ? failure.message : String(failure)}`, { cause: failure }) as Error & { repair: unknown }; error.repair = { previous_state_restored: true, quarantine: saved.quarantine }; throw error;
  }
}
