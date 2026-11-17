import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { readdir, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { guardedCreate, guardedIdentity, guardedPrivateDirectory, guardedStateLock } from '../../workspace/src/guard.js';
import { boundedRead, fsyncDirectory, openStateAuthority, sha256 } from '../../workspace/src/journal.js';
import type { GuardIdentity } from '../../workspace/src/guard.js';
import type { NativeState } from '../../workspace/src/journal.js';

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const RECORD = new RegExp(`^\\.provider-lease-(${UUID})\\.json$`);
const KERNEL = new RegExp(`^\\.provider-lease-(${UUID})\\.native$`);
const GATE = '.provider-maintenance.native';
const current = new AsyncLocalStorage<{ root: string; kernel: string }>();
const maintenance = new AsyncLocalStorage<{ root: string; identity: GuardIdentity; guard: string; dryRun: boolean }>();
export async function requireProviderMaintenance(guard: string, root: string): Promise<void> {
  const active = maintenance.getStore(); const canonical = await realpath(root);
  if (!active || active.dryRun || active.root !== canonical || active.guard !== guard) throw new Error('PROVIDER_MAINTENANCE_AUTHORITY_REQUIRED');
  const identity = await guardedIdentity(guard, canonical); if (identity.device !== active.identity.device || identity.inode !== active.identity.inode) throw new Error('PROVIDER_MAINTENANCE_ROOT_CHANGED');
}
export async function currentProviderLease(root: string): Promise<string | undefined> { const lease = current.getStore(); return lease && lease.root === await realpath(root) ? lease.kernel : undefined; }
export async function providerLeaseActive(guard: string, root: string, kernel: string): Promise<boolean> {
  if (!KERNEL.test(kernel)) throw new Error('PROVIDER_LEASE_RECORD_INVALID');
  try { const release = await guardedStateLock(guard, root, kernel, await guardedIdentity(guard, root), true); await release(); return false; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'EBUSY') return true; if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
}
type Authority = { root: string; identity: GuardIdentity; native: NativeState | undefined; guard: string };
type Lease = { schema_version: 1; id: string; identity: { device: string; inode: string }; kernel_lock: string };
type SavedLease = { record: string; kernel: string; sha256: string; active: boolean };
export type ProviderMaintenanceInventory = { stale_leases: string[]; active_leases: string[]; protected_leases: string[] };
function cancelled(signal?: AbortSignal): void { if (signal?.aborted) throw new Error('PROVIDER_MAINTENANCE_CANCELLED'); }
async function authority(guard: string, root: string): Promise<Authority> {
  root = await realpath(root); const identity = await guardedIdentity(guard, root); await guardedPrivateDirectory(guard, root, '.', identity);
  return { root, identity, guard, native: await openStateAuthority(root, guard) };
}
async function gate(value: Authority, existingOnly = false, signal?: AbortSignal): Promise<() => Promise<void>> {
  const deadline = Date.now() + 5000;
  for (;;) {
    cancelled(signal);
    try { return await guardedStateLock(value.guard, value.root, GATE, value.identity, existingOnly); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EBUSY' || Date.now() >= deadline) throw error; await new Promise(done => setTimeout(done, 10)); }
  }
}
async function inventory(value: Authority): Promise<{ rows: SavedLease[]; protected: string[] }> {
  const names = await readdir(value.root); if (names.length > 10000) throw new Error('PROVIDER_LEASE_INVENTORY_TOO_LARGE'); const leases: SavedLease[] = [];
  for (const name of names.sort()) {
    if (!name.startsWith('.provider-lease-') || name.endsWith('.native')) continue;
    const id = RECORD.exec(name)?.[1]; if (!id) throw new Error('PROVIDER_LEASE_RECORD_INVALID');
    const bytes = await boundedRead(path.join(value.root, name), 4096, value.native); const item: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('PROVIDER_LEASE_RECORD_INVALID');
    const record = item as Lease;
    if (Object.keys(record).sort().join(',') !== 'id,identity,kernel_lock,schema_version' || record.schema_version !== 1 || record.id !== id || record.kernel_lock !== `.provider-lease-${id}.native` || !record.identity || record.identity.device !== value.identity.device || record.identity.inode !== value.identity.inode) throw new Error('PROVIDER_LEASE_RECORD_INVALID');
    let active = false;
    try { const release = await guardedStateLock(value.guard, value.root, record.kernel_lock, value.identity, true); await release(); }
    catch (error) { const code = (error as NodeJS.ErrnoException).code; if (code === 'EBUSY') active = true; else if (code !== 'ENOENT') throw error; }
    leases.push({ record: name, kernel: record.kernel_lock, sha256: sha256(bytes), active });
  }
  const protectedFiles: string[] = [];
  for (const name of names.filter(name => name.startsWith('.provider-lease-') && name.endsWith('.native'))) {
    if (!KERNEL.test(name)) throw new Error('PROVIDER_LEASE_RECORD_INVALID');
    if (leases.some(lease => lease.kernel === name)) continue;
    try { const release = await guardedStateLock(value.guard, value.root, name, value.identity, true); await release(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'EBUSY') throw new Error('PROVIDER_RUNTIME_IN_USE'); throw error; }
    // Unknown free files cannot authorize deletion. They are retained, while
    // their kernel probe still prevents maintenance from overlooking a job.
    protectedFiles.push(name);
  }
  return { rows: leases, protected: protectedFiles };
}
async function unchanged(value: Authority, record: string, expected: string): Promise<void> { if (sha256(await boundedRead(path.join(value.root, record), 4096, value.native)) !== expected) throw new Error('PROVIDER_LEASE_RECORD_CHANGED'); }

/** Register briefly under the gate, then hold a unique kernel lease per job. */
export async function withProviderLease<T>(guard: string, root: string, action: () => Promise<T>, options: { signal?: AbortSignal } = {}): Promise<T> {
  cancelled(options.signal); const state = await authority(guard, root); const unlockGate = await gate(state, false, options.signal);
  const id = randomUUID(); const name = `.provider-lease-${id}.json`; const kernel = `.provider-lease-${id}.native`;
  const bytes = Buffer.from(`${JSON.stringify({ schema_version: 1, id, identity: { device: state.identity.device, inode: state.identity.inode }, kernel_lock: kernel })}\n`);
  let release: (() => Promise<void>) | undefined;
  try { await guardedCreate(guard, state.root, name, state.identity, bytes); release = await guardedStateLock(guard, state.root, kernel, state.identity); }
  finally { await unlockGate(); }
  try { cancelled(options.signal); return await current.run({ root: state.root, kernel }, action); }
  finally {
    try {
      const done = await gate(state);
      try { await unchanged(state, name, sha256(bytes)); await rm(path.join(state.root, name)); await release?.(); release = undefined; await rm(path.join(state.root, kernel)); await fsyncDirectory(state.root, state.native); }
      finally { await done(); }
    } finally { await release?.(); }
  }
}

/** Maintenance never competes with live jobs or steals a PID/start-time lease. */
export async function withProviderMaintenance<T>(guard: string, root: string, action: (inventory: ProviderMaintenanceInventory) => Promise<T>, options: { dryRun?: boolean; signal?: AbortSignal } = {}): Promise<T> {
  cancelled(options.signal); const state = await authority(guard, root); let unlock: (() => Promise<void>) | undefined;
  try { unlock = await gate(state, options.dryRun === true, options.signal); }
  catch (error) { if (!(options.dryRun && (error as NodeJS.ErrnoException).code === 'ENOENT')) throw error; }
  try {
    const inventoryRows = await inventory(state); const rows = inventoryRows.rows; const active = rows.filter(row => row.active).map(row => row.record); const stale = rows.filter(row => !row.active);
    if (active.length) { const error = new Error('PROVIDER_RUNTIME_IN_USE') as Error & { leases: string[] }; error.leases = active; throw error; }
    cancelled(options.signal);
    if (!options.dryRun) for (const row of stale) { await unchanged(state, row.record, row.sha256); await rm(path.join(state.root, row.record)); await rm(path.join(state.root, row.kernel), { force: true }); }
    if (!options.dryRun && stale.length) await fsyncDirectory(state.root, state.native);
    return await maintenance.run({ root: state.root, identity: state.identity, guard, dryRun: options.dryRun === true }, () => action({ stale_leases: stale.map(row => row.record), active_leases: active, protected_leases: inventoryRows.protected }));
  } finally { await unlock?.(); }
}
