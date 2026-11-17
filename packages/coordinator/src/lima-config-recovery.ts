import path from 'node:path';
import { readdir } from 'node:fs/promises';
import { guardedIdentity } from '../../workspace/src/guard.js';
import { boundedRead, durableWrite, JournalStore, openStateAuthority, sha256 } from '../../workspace/src/journal.js';
import { resolveOwnedLimaHome } from '../../runtime-manager/src/lima-storage.js';
import { verifyGeneratedLimaConfig } from '../../runtime-manager/src/lima-provision.js';
import type { LimaProvisioning } from '../../runtime-manager/src/lima-provision.js';
import type { LimaRuntimeReceipt } from '../../runtime-manager/src/lima-nerdctl.js';
import { admitLimaSshKeygen, limaProvisionRunner } from '../../runtime-manager/src/lima-system-helper.js';
import { runCommand } from '../../runtime-manager/src/command.js';
import { requireProviderMaintenance } from './provider-leases.js';
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value !== null && typeof value === 'object') return '{' + Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => JSON.stringify(key) + ':' + canonicalJson(item)).join(',') + '}';
  return JSON.stringify(value);
}
function completedConfigMatches(recovery: Record<string, unknown>, config: Buffer | undefined, expectedNetwork: string | undefined): boolean {
  if (!config || !recovery.config_receipt || sha256(Buffer.from(JSON.stringify(recovery.config_receipt) + '\n')) !== recovery.config_sha256) return false;
  const current = JSON.parse(config.toString('utf8')) as Record<string, any>, old = recovery.config_receipt as Record<string, any>;
  if (canonicalJson(old) === canonicalJson(current)) return true;
  return Array.isArray(old.files) && old.files.length === 2 && Array.isArray(current.files) && current.files.length === 3 && current.files.some((file: Record<string, unknown>) => file.name === 'networks.yaml' && file.sha256 === expectedNetwork) && canonicalJson({ ...current, files: current.files.filter((file: Record<string, unknown>) => file.name !== 'networks.yaml') }) === canonicalJson(old);
}

/** A maintenance-only recovery; no VM is started and no unknown file is removed. */
export async function recoverLimaGeneratedConfig(stateRoot: string, guard: string, guardSha256: string, receipt: LimaRuntimeReceipt, provisioning: Pick<LimaProvisioning, 'generatedConfig'>, runner: typeof runCommand = runCommand, admitHelper = admitLimaSshKeygen): Promise<{ status: 'absent' | 'admitted' | 'recovered' | 'protected'; reason?: string }> {
  await requireProviderMaintenance(guard, stateRoot);
  const store = await JournalStore.open(stateRoot, guard), native = await openStateAuthority(store.root, guard);
  const home = await resolveOwnedLimaHome(store.root, guard);
  if (!home || home !== receipt.home) throw new Error('LIMA_CONFIG_RECOVERY_HOME_CHANGED');
  let names: string[];
  try { names = await readdir(path.join(home, '_config')); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'absent' }; throw error; }
  if (!names.length) return { status: 'absent' };
  if (!['user,user.pub', 'networks.yaml,user,user.pub'].includes(names.sort().join(','))) return { status: 'protected', reason: 'Unknown generated-config files are preserved.' };
  const execute = limaProvisionRunner(receipt, guard, guardSha256, runner, admitHelper);
  let config: Buffer | undefined, recovery: Record<string, unknown> | undefined;
  try { recovery = JSON.parse((await boundedRead(path.join(store.root, 'lima-generated-config-recovery.json'), 16384, native)).toString('utf8')); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  try {
    config = await boundedRead(path.join(store.root, 'lima-generated-config.json'), 16384, native);
    // An already admitted keypair may acquire only the exact pinned default
    // network file; the verifier preserves both original key identities.
    await verifyGeneratedLimaConfig(home, store, provisioning, true, execute, guard);
    if (!recovery) return { status: 'admitted' };
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  let originBytes: Buffer;
  try { originBytes = await boundedRead(path.join(store.root, 'lima-create-origin.json'), 16384, native); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { status: 'protected', reason: 'No durable pre-create config absence evidence.' }; throw error; }
  const origin = JSON.parse(originBytes.toString('utf8')) as Record<string, any>;
  const identity = await guardedIdentity(guard, store.root), homeIdentity = await guardedIdentity(guard, home);
  if (!origin || Object.keys(origin).sort().join(',') !== 'home,home_identity,initial_config,instance,schema_version,state_identity,template_sha256' || origin.schema_version !== 1 || origin.instance !== receipt.instance || origin.home !== home || canonicalJson(origin.state_identity) !== canonicalJson(identity) || canonicalJson(origin.home_identity) !== canonicalJson(homeIdentity) || !/^sha256:[a-f0-9]{64}$/.test(origin.template_sha256) || !origin.initial_config || !['absent', 'empty'].includes(origin.initial_config.kind) || Object.keys(origin.initial_config).sort().join(',') !== (origin.initial_config.kind === 'absent' ? 'kind' : 'directory,kind')) throw new Error('LIMA_CONFIG_RECOVERY_ORIGIN_CHANGED');
  const owner = JSON.parse((await boundedRead(path.join(store.root, 'lima-instance.json'), 16384, native)).toString('utf8')) as Record<string, unknown>;
  if (!owner || owner.schema_version !== 1 || owner.instance !== receipt.instance || owner.home !== home || owner.template_sha256 !== origin.template_sha256 || !['creating', 'created', 'running'].includes(owner.phase as string)) throw new Error('LIMA_CONFIG_RECOVERY_CREATE_CHANGED');
  if (origin.initial_config.kind === 'empty' && canonicalJson(origin.initial_config.directory) !== canonicalJson(await guardedIdentity(guard, path.join(home, '_config')))) throw new Error('LIMA_CONFIG_RECOVERY_DIRECTORY_CHANGED');
  const stamp = { schema_version: 1, home, state_identity: identity, home_identity: homeIdentity, origin_sha256: sha256(originBytes), authority: 'exclusive-provider-maintenance-origin-bound-key-consistency' };
  if (recovery && (Object.keys(recovery).sort().join(',') !== [...Object.keys(stamp), 'phase', ...(recovery.phase === 'completed' ? ['config_sha256', 'config_receipt'] : [])].sort().join(',') || Object.entries(stamp).some(([key, value]) => canonicalJson(recovery![key]) !== canonicalJson(value)) || !['planned', 'completed'].includes(recovery.phase as string) || recovery.phase === 'completed' && !completedConfigMatches(recovery, config, provisioning.generatedConfig?.networksSha256))) throw new Error('LIMA_CONFIG_RECOVERY_RECEIPT_CHANGED');
  const journal = path.join(store.root, 'lima-generated-config-recovery.json');
  if (!recovery) await durableWrite(journal, Buffer.from(JSON.stringify({ ...stamp, phase: 'planned' }) + '\n'), native);
  await verifyGeneratedLimaConfig(home, store, provisioning, config === undefined, execute, guard);
  await requireProviderMaintenance(guard, store.root);
  if (canonicalJson(await guardedIdentity(guard, home)) !== canonicalJson(homeIdentity)) throw new Error('LIMA_CONFIG_RECOVERY_HOME_CHANGED');
  const recovered = await boundedRead(path.join(store.root, 'lima-generated-config.json'), 16384, native);
  await durableWrite(journal, Buffer.from(JSON.stringify({ ...stamp, phase: 'completed', config_sha256: sha256(recovered), config_receipt: JSON.parse(recovered.toString('utf8')) }) + '\n'), native);
  return { status: 'recovered' };
}
