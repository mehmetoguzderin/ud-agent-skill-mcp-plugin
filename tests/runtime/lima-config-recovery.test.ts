import { afterAll, beforeAll, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { recoverLimaGeneratedConfig } from '../../packages/coordinator/src/lima-config-recovery.js';
import { withProviderLease, withProviderMaintenance } from '../../packages/coordinator/src/provider-leases.js';
import { prepareOwnedLimaHome } from '../../packages/runtime-manager/src/lima-storage.js';
import { verifyGeneratedLimaConfig } from '../../packages/runtime-manager/src/lima-provision.js';
import { guardedIdentity } from '../../packages/workspace/src/guard.js';
import { JournalStore } from '../../packages/workspace/src/journal.js';
import type { LimaRuntimeReceipt } from '../../packages/runtime-manager/src/lima-nerdctl.js';
import type { runCommand } from '../../packages/runtime-manager/src/command.js';

const hash = (value: string | Buffer) => 'sha256:' + createHash('sha256').update(value).digest('hex');
let tools: string, guard: string;
beforeAll(async () => { tools = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-lima-config-tools-'))); guard = path.join(tools, process.platform === 'win32' ? 'guard.exe' : 'guard'); await copyFile(path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : '')), guard); await chmod(guard, 0o500); });
afterAll(async () => { await rm(tools, { recursive: true, force: true }); });

async function fixture(run: (data: { root: string; home: string; receipt: LimaRuntimeReceipt; origin: Record<string, unknown>; recover: () => ReturnType<typeof recoverLimaGeneratedConfig>; commands: string[][]; controls: { derived: string; duringDerive?: () => Promise<void> } }) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-lima-config-'))); let home: string | undefined;
  try {
    await JournalStore.open(root, guard); home = await prepareOwnedLimaHome(root, guard, path.join(root, 'owned-home-parent'));
    const receipt: LimaRuntimeReceipt = { schema_version: 1, executable: '/owned/limactl', binarySha256: hash('lima'), instance: 'ud-agent', nerdctl: '/usr/local/bin/nerdctl', nerdctlSha256: hash('nerdctl'), containerd: '/usr/local/bin/containerd', containerdSha256: hash('containerd'), address: '/run/user/1001/containerd/containerd.sock', guestUid: 1001, guestHome: '/home/udagent', architecture: 'arm64', home };
    const origin = { schema_version: 1, instance: 'ud-agent', home, state_identity: await guardedIdentity(guard, root), home_identity: await guardedIdentity(guard, home), template_sha256: hash('template'), initial_config: { kind: 'absent' } };
    await writeFile(path.join(root, 'lima-create-origin.json'), JSON.stringify(origin), { mode: 0o600 });
    await writeFile(path.join(root, 'lima-instance.json'), JSON.stringify({ schema_version: 1, instance: 'ud-agent', home, template_sha256: hash('template'), phase: 'creating' }), { mode: 0o600 });
    await mkdir(path.join(home, '_config'), { mode: 0o700 }); await writeFile(path.join(home, '_config/user'), 'private fixture key', { mode: 0o600 }); await writeFile(path.join(home, '_config/user.pub'), 'ssh-ed25519 AAECAwQF fixture\n', { mode: 0o600 });
    const commands: string[][] = [];
    const controls: { derived: string; duringDerive?: () => Promise<void> } = { derived: 'ssh-ed25519 AAECAwQF\n' };
    const runner: typeof runCommand = async (executable, arguments_, options) => { expect(executable).toBe('/usr/bin/ssh-keygen'); expect(options.supervisor?.executableSha256).toBe(hash('system helper')); expect(options.limaHome).toBe(home); commands.push([...arguments_]); await controls.duringDerive?.(); return { code: 0, stdout: Buffer.from(controls.derived), stderr: Buffer.alloc(0) }; };
    const recover = () => recoverLimaGeneratedConfig(root, guard, hash(awaitGuardBytes), receipt, { generatedConfig: { networksSha256: hash('pinned network\n') } }, runner, async () => ({ executable: '/usr/bin/ssh-keygen' as const, sha256: hash('system helper') }));
    await run({ root, home, receipt, origin, recover, commands, controls });
  } finally { if (home) await rm(home, { recursive: true, force: true }); await rm(root, { recursive: true, force: true }); }
}
// Guard bytes are read once after construction; the test runner is a portable
// protocol fixture, while actual kernel maintenance locks use the native guard.
let awaitGuardBytes: Buffer;
beforeAll(async () => { awaitGuardBytes = await readFile(guard); });

it('requires an actual exclusive maintenance gate before reading or admitting keys', async () => fixture(async ({ root, recover, commands }) => {
  await expect(recover()).rejects.toThrow('MAINTENANCE_AUTHORITY_REQUIRED'); expect(commands).toEqual([]);
  await withProviderLease(guard, root, async () => { await expect(withProviderMaintenance(guard, root, async () => recover())).rejects.toThrow('PROVIDER_RUNTIME_IN_USE'); });
  await expect(readFile(path.join(root, 'lima-generated-config.json'))).rejects.toMatchObject({ code: 'ENOENT' });
}), 30_000);

it('durably records origin-bound recovered config before ordinary cleanup and repeats idempotently', async () => fixture(async ({ root, home, recover, commands }) => {
  const first = await withProviderMaintenance(guard, root, async () => recover()); expect(first.status).toBe('recovered');
  const configBytes = await readFile(path.join(root, 'lima-generated-config.json')), config = JSON.parse(configBytes.toString());
  const proof = JSON.parse(await readFile(path.join(root, 'lima-generated-config-recovery.json'), 'utf8'));
  expect(proof).toEqual(expect.objectContaining({ phase: 'completed', home, config_sha256: hash(configBytes).slice(7), origin_sha256: hash(await readFile(path.join(root, 'lima-create-origin.json'))).slice(7) }));
  expect(config.files.map((row: { name: string }) => row.name)).toEqual(['user', 'user.pub']); expect(commands).toEqual([['-y','-f',path.join(home,'_config/user')]]);
  expect((await withProviderMaintenance(guard, root, async () => recover())).status).toBe('recovered'); expect(commands).toHaveLength(1);
  proof.phase = 'planned'; delete proof.config_sha256; delete proof.config_receipt; await writeFile(path.join(root, 'lima-generated-config-recovery.json'), JSON.stringify(proof));
  expect((await withProviderMaintenance(guard, root, async () => recover())).status).toBe('recovered'); expect(JSON.parse(await readFile(path.join(root,'lima-generated-config-recovery.json'),'utf8')).phase).toBe('completed');
}), 30_000);

it('preserves unknown files and legacy keys without a durable pre-create absence proof', async () => fixture(async ({ root, home, recover, commands }) => {
  await rm(path.join(root, 'lima-create-origin.json'));
  expect((await withProviderMaintenance(guard, root, async () => recover())).status).toBe('protected');
  await writeFile(path.join(home,'_config/foreign'),'unrelated');
  expect((await withProviderMaintenance(guard, root, async () => recover())).status).toBe('protected'); expect(commands).toEqual([]);
  expect(await readFile(path.join(home,'_config/foreign'),'utf8')).toBe('unrelated');
  await expect(readFile(path.join(root,'lima-generated-config.json'))).rejects.toMatchObject({code:'ENOENT'});
}), 30_000);

it('rejects origin, create, empty-directory and recovered-receipt identity substitutions', async () => {
  for (const mutation of ['root','home','template','initial','owner','empty','extra','proof']) await fixture(async ({ root, home, origin, recover }) => {
    const changed = structuredClone(origin) as any;
    if (mutation === 'root') changed.state_identity.inode = '0';
    if (mutation === 'home') changed.home_identity.inode = '0';
    if (mutation === 'template') changed.template_sha256 = hash('other template');
    if (mutation === 'initial') changed.initial_config = { kind: 'present' };
    if (mutation === 'empty') changed.initial_config = { kind: 'empty', directory: { device: '0', inode: '0' } };
    if (mutation === 'extra') changed.unbound = true;
    await writeFile(path.join(root,'lima-create-origin.json'),JSON.stringify(changed));
    if (mutation === 'owner') await writeFile(path.join(root,'lima-instance.json'),JSON.stringify({schema_version:1,instance:'foreign',home,template_sha256:hash('template'),phase:'creating'}));
    if (mutation === 'proof') await writeFile(path.join(root,'lima-generated-config-recovery.json'),JSON.stringify({phase:'completed',config_sha256:hash('fabricated')}),{mode:0o600});
    await expect(withProviderMaintenance(guard,root,async()=>recover()),mutation).rejects.toThrow(/CHANGED|ENOENT/);
    expect(await readFile(path.join(home,'_config/user'),'utf8')).toBe('private fixture key');
  });
}, 60_000);

it('never admits mismatching keypairs, wrong networks, insecure keys or changed bytes/inodes', async () => {
  for (const mutation of ['pair','network',...(process.platform === 'win32' ? [] : ['mode']),'bytes','inode']) await fixture(async ({root,home,recover,controls,commands}) => {
    if (mutation === 'pair') controls.derived = 'ssh-ed25519 OTHER\n';
    if (mutation === 'network') await writeFile(path.join(home,'_config/networks.yaml'),'unrelated network\n',{mode:0o600});
    if (mutation === 'mode') await chmod(path.join(home,'_config/user'),0o644);
    if (mutation === 'bytes') controls.duringDerive = async () => { await writeFile(path.join(home,'_config/user'),'changed fixture key'); };
    if (mutation === 'inode') controls.duringDerive = async () => { const file=path.join(home,'_config/user');await rename(file,file+'.previous');await writeFile(file,'private fixture key',{mode:0o600}); };
    await expect(withProviderMaintenance(guard,root,async()=>recover()),mutation).rejects.toThrow(/INVALID|CHANGED|UNSAFE/);
    await expect(readFile(path.join(root,'lima-generated-config.json'))).rejects.toMatchObject({code:'ENOENT'});
    if (['network','mode'].includes(mutation)) expect(commands).toEqual([]);
    expect(await readFile(path.join(home,'_config/user'),'utf8')).toBe(mutation==='bytes'?'changed fixture key':'private fixture key');
  });
},60_000);

it('resumes an interrupted planned recovery and permits only the pinned network append',async()=>fixture(async({root,home,recover,controls,commands})=>{
  controls.duringDerive=async()=>{throw new Error('READ_ONLY_HELPER_INTERRUPTED');};
  await expect(withProviderMaintenance(guard,root,async()=>recover())).rejects.toThrow('READ_ONLY_HELPER_INTERRUPTED');
  expect(JSON.parse(await readFile(path.join(root,'lima-generated-config-recovery.json'),'utf8')).phase).toBe('planned');
  await expect(readFile(path.join(root,'lima-generated-config.json'))).rejects.toMatchObject({code:'ENOENT'});
  delete controls.duringDerive;
  expect((await withProviderMaintenance(guard,root,async()=>recover())).status).toBe('recovered');expect(commands).toHaveLength(2);
  await writeFile(path.join(home,'_config/networks.yaml'),'pinned network\n',{mode:0o600});
  // Ordinary start can admit the pinned append before maintenance resumes the
  // earlier recovery record. That historical two-key proof remains valid.
  await withProviderMaintenance(guard,root,async()=>verifyGeneratedLimaConfig(home,await JournalStore.open(root,guard),{generatedConfig:{networksSha256:hash('pinned network\n')}},true,async()=>{throw new Error('known pair must not be rederived');},guard));
  expect((await withProviderMaintenance(guard,root,async()=>recover())).status).toBe('recovered');
  expect(JSON.parse(await readFile(path.join(root,'lima-generated-config.json'),'utf8')).files.map((row:{name:string})=>row.name)).toEqual(['networks.yaml','user','user.pub']);
  expect(commands).toHaveLength(2);
  await rm(path.join(root,'lima-generated-config-recovery.json'));
  expect((await withProviderMaintenance(guard,root,async()=>recover())).status).toBe('admitted');
}),30_000);
