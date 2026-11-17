import path from 'node:path';
import { readdir, realpath } from 'node:fs/promises';
import { guardedCreate, guardedIdentity, guardedPrivateDirectory } from '../../workspace/src/guard.js';
import { boundedRead, durableWrite, openStateAuthority } from '../../workspace/src/journal.js';
import type { WslcRuntimeReceipt, WslcSessionIdentity } from './wslc-runtime.js';

export type WslcOwnedSession = { schema_version: 1; session: string; storage_identity: { device: string; inode: string }; engine_sha256: string; sdk_sha256: string; phase: 'creating' | 'active' | 'terminated'; identity?: WslcSessionIdentity };
const SESSION = /^ud-agent-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^sha256:[0-9a-f]{64}$/;
export async function writeWslcSessionIntent(receipt: WslcRuntimeReceipt, session: string): Promise<WslcOwnedSession> {
  if (!SESSION.test(session)) throw new Error('WSLC_SESSION_IDENTITY_INVALID');
  const identity = await guardedIdentity(receipt.guard, receipt.storage); await guardedPrivateDirectory(receipt.guard, receipt.storage, '.', identity);
  const record: WslcOwnedSession = { schema_version: 1, session, storage_identity: identity, engine_sha256: receipt.binarySha256, sdk_sha256: receipt.sdkSha256, phase: 'creating' };
  await guardedCreate(receipt.guard, receipt.storage, `session-${session}.json`, identity, Buffer.from(`${JSON.stringify(record)}\n`)); return record;
}
export async function saveWslcSession(receipt: WslcRuntimeReceipt, record: WslcOwnedSession): Promise<void> {
  const actual = await guardedIdentity(receipt.guard, receipt.storage); if (actual.device !== record.storage_identity.device || actual.inode !== record.storage_identity.inode || !SESSION.test(record.session)) throw new Error('WSLC_SESSION_STORAGE_CHANGED');
  await durableWrite(path.join(receipt.storage, `session-${record.session}.json`), Buffer.from(`${JSON.stringify(record)}\n`), await openStateAuthority(receipt.storage, receipt.guard));
}
export async function readWslcSessions(receipt: WslcRuntimeReceipt): Promise<WslcOwnedSession[]> {
  let storage: string; try { storage = await realpath(receipt.storage); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error; }
  const identity = await guardedIdentity(receipt.guard, storage); await guardedPrivateDirectory(receipt.guard, storage, '.', identity);
  const native = await openStateAuthority(storage, receipt.guard); const names = await readdir(storage); if (names.length > 10000) throw new Error('WSLC_SESSION_INVENTORY_TOO_LARGE'); const records: WslcOwnedSession[] = [];
  for (const name of names.filter(name => name.startsWith('session-') && name.endsWith('.json')).sort()) {
    const raw: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await boundedRead(path.join(storage, name), 8192, native)));
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('WSLC_SESSION_STATE_INVALID'); const item = raw as WslcOwnedSession;
    if (Object.keys(item).some(key => !['schema_version', 'session', 'storage_identity', 'engine_sha256', 'sdk_sha256', 'phase', 'identity'].includes(key)) || item.schema_version !== 1 || typeof item.session !== 'string' || !SESSION.test(item.session) || name !== `session-${item.session}.json` || !SHA.test(item.engine_sha256) || !SHA.test(item.sdk_sha256) || !item.storage_identity || item.storage_identity.device !== identity.device || item.storage_identity.inode !== identity.inode || !['creating', 'active', 'terminated'].includes(item.phase) || item.identity !== undefined && (!item.identity || typeof item.identity !== 'object' || Array.isArray(item.identity) || Object.keys(item.identity).some(key => !['id', 'creatorPid'].includes(key)) || !/^[1-9][0-9]{0,19}$/.test(item.identity.id) || !Number.isSafeInteger(item.identity.creatorPid) || item.identity.creatorPid < 1 || item.identity.creatorPid > 0xffffffff) || item.phase === 'active' && !item.identity) throw new Error('WSLC_SESSION_STATE_INVALID');
    records.push(item);
  }
  return records;
}
