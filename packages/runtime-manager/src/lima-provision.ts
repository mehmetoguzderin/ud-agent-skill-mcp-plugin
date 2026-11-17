import { guardedIdentity, guardedPrivateRead } from '../../workspace/src/guard.js';
import { createHash, randomUUID } from 'node:crypto';
import { chmod, copyFile, lstat, mkdir, open, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { parseDocument, stringify } from 'yaml';
import { JournalStore, boundedRead, durableWrite, fsyncDirectory, openStateAuthority } from '../../workspace/src/journal.js';
import { inspectLima } from './lima.js';
import type { LimaRuntimeReceipt } from './lima-nerdctl.js';
import { runCommand } from './command.js';
import { readBoundedReceiptBytes, verifyArchive } from './receipt.js';
import { stageVerifiedArchive } from './archive.js';
import { resolveOwnedLimaHome, limaSocketPathFits } from './lima-storage.js';

export type LimaProvisioning = { template: string; templateSha256: string; offlineReady: boolean; assets: { key: string; path: string; sha256: string; sizeBytes: number }[]; generatedConfig?: { networksSha256: string } };
type Runner = typeof runCommand;
function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function digest(value: Buffer | string): string { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function canonical(value: unknown): string { if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`; if (value !== null && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`; return JSON.stringify(value); }
function parse(bytes: Buffer | string): Record<string, unknown> { const document = parseDocument(bytes.toString(), { uniqueKeys: true }); if (document.errors.length || document.warnings.length) throw new Error('LIMA_PROVISION_TEMPLATE_INVALID'); const value = object(document.toJS({ maxAliasCount: 0 })); if (!value) throw new Error('LIMA_PROVISION_TEMPLATE_INVALID'); return value; }

/** Bind Lima's generated SSH identity; global overrides are never admitted. */
export async function verifyGeneratedLimaConfig(home: string, store: JournalStore, provisioning: Pick<LimaProvisioning, 'generatedConfig'>, mayCapture: boolean, runner: Runner, guard: string): Promise<void> {
  const native = await openStateAuthority(store.root, guard);
  const directory = path.join(home, '_config'); let names: string[];
  try { names = await readdir(directory); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
  if (!names.length) return;
  if (!['networks.yaml,user,user.pub', 'user,user.pub'].includes(names.sort().join(','))) throw new Error('LIMA_UNDECLARED_GLOBAL_CONFIG');
  if (!provisioning.generatedConfig || !/^sha256:[0-9a-f]{64}$/.test(provisioning.generatedConfig.networksSha256)) throw new Error('LIMA_GENERATED_CONFIG_RECEIPT_REQUIRED');
  const info = await lstat(directory, { bigint: true }); if (!info.isDirectory() || info.isSymbolicLink() || process.platform !== 'win32' && (Number(info.mode) & 0o077) !== 0 || typeof process.getuid === 'function' && info.uid !== BigInt(process.getuid())) throw new Error('LIMA_GENERATED_CONFIG_UNSAFE');
  if (process.platform === 'win32') await openStateAuthority(directory, guard);
  const entries: Record<string, unknown>[] = [];
  for (const name of names) { const file = path.join(directory, name); const stat = await lstat(file, { bigint: true }); if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size < 1n || stat.size > 16384n || process.platform !== 'win32' && (Number(stat.mode) & (name === 'user' ? 0o077 : 0o022)) !== 0 || typeof process.getuid === 'function' && stat.uid !== BigInt(process.getuid())) throw new Error('LIMA_GENERATED_CONFIG_UNSAFE'); const bytes = process.platform === 'win32' ? await guardedPrivateRead(guard, directory, name, 16384, await guardedIdentity(guard, directory)) : await readBoundedReceiptBytes(file, 16384); entries.push({ name, device: stat.dev.toString(), inode: stat.ino.toString(), sha256: digest(bytes), size: bytes.length }); }
  const networks = entries.find(entry => entry.name === 'networks.yaml');
  if (networks && networks.sha256 !== provisioning.generatedConfig.networksSha256) throw new Error('LIMA_DEFAULT_NETWORK_CONFIG_CHANGED');
  const value = { schema_version: 1, home, directory: { device: info.dev.toString(), inode: info.ino.toString() }, files: entries }; const journal = path.join(store.root, 'lima-generated-config.json');
  try {
    const previous = object(JSON.parse((await boundedRead(journal, 16384, native)).toString('utf8')));
    if (canonical(previous) === canonical(value)) return;
    // Creation writes the SSH keypair; Lima creates its default network config
    // later. Admit only that pinned append, preserving both existing key IDs.
    if (!mayCapture || previous?.schema_version !== 1 || previous.home !== home || canonical(previous.directory) !== canonical(value.directory) || !Array.isArray(previous.files) || previous.files.length !== 2 || entries.length !== 3 || canonical(previous.files) !== canonical(entries.filter(entry => entry.name !== 'networks.yaml'))) throw new Error('LIMA_GENERATED_CONFIG_CHANGED');
    await durableWrite(journal, Buffer.from(`${JSON.stringify(value)}\n`), native); return;
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  if (!mayCapture) throw new Error('LIMA_UNDECLARED_GLOBAL_CONFIG');
  const publicKey = (await readBoundedReceiptBytes(path.join(directory, 'user.pub'), 16384)).toString('utf8').trim().split(/\s+/).slice(0, 2).join(' ');
  const derived = await runner('/usr/bin/ssh-keygen', ['-y', '-f', path.join(directory, 'user')], { timeoutMs: 10000, maxOutputBytes: 16384, limaHome: home });
  if (derived.code !== 0 || !/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/.test(publicKey) || derived.stdout.toString('utf8').trim().split(/\s+/).slice(0, 2).join(' ') !== publicKey) throw new Error('LIMA_GENERATED_SSH_IDENTITY_INVALID');
  for (const entry of entries) {
    const file = path.join(directory, entry.name as string), stat = await lstat(file, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.dev.toString() !== entry.device || stat.ino.toString() !== entry.inode || stat.size !== BigInt(entry.size as number) || typeof process.getuid === 'function' && stat.uid !== BigInt(process.getuid()) || process.platform !== 'win32' && (Number(stat.mode) & (entry.name === 'user' ? 0o077 : 0o022)) !== 0 || digest(await readBoundedReceiptBytes(file, 16384)) !== entry.sha256) throw new Error('LIMA_GENERATED_CONFIG_CHANGED');
  }
  const after = await lstat(directory, { bigint: true }); if (after.dev !== info.dev || after.ino !== info.ino || after.uid !== info.uid || after.mode !== info.mode || !after.isDirectory() || after.isSymbolicLink()) throw new Error('LIMA_GENERATED_CONFIG_CHANGED');
  await durableWrite(journal, Buffer.from(`${JSON.stringify(value)}\n`), native);
}

export function validateOwnedLimaTemplate(value: Record<string, unknown>, architecture: 'amd64' | 'arm64'): void {
  const containerd = object(value.containerd); const ssh = object(value.ssh);
  if (value.arch !== (architecture === 'amd64' ? 'x86_64' : 'aarch64') || !['qemu', 'vz'].includes(value.vmType as string) || !Array.isArray(value.mounts) || value.mounts.length !== 0 || containerd?.user !== true || containerd.system !== false || ssh?.loadDotSSHPubKeys !== false || ssh.forwardAgent !== false || !Array.isArray(value.images) || value.images.length === 0 || value.images.some(raw => { const image = object(raw); return !image || typeof image.location !== 'string' || !image.location.startsWith('file:') || typeof image.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(image.digest); }) || !Number.isSafeInteger(value.cpus) || (value.cpus as number) < 2 || (value.cpus as number) > 4 || typeof value.memory !== 'string' || !/^[2-8]GiB$/.test(value.memory)) throw new Error('LIMA_PROVISION_TEMPLATE_POLICY_FAILED');
  if (object(value.rosetta)?.enabled === true || object(object(object(value.vmOpts)?.vz)?.rosetta)?.enabled === true || value.copyToHost !== undefined && JSON.stringify(value.copyToHost) !== '[]') throw new Error('LIMA_PROVISION_HOST_ACCESS_FORBIDDEN');
}

/** Create/start only a receipt-bound instance in a separate product LIMA_HOME. */
export async function ensureOwnedLimaInstance(receipt: LimaRuntimeReceipt, provisioning: LimaProvisioning, guard: string, stateRoot: string, network: 'bootstrap_only' | 'offline', runner: Runner = runCommand, signal?: AbortSignal): Promise<{ created: boolean; started: boolean }> {
  const checkCancelled = () => { if (signal?.aborted) throw new Error('LIMA_SETUP_CANCELLED'); }; checkCancelled();
  const execute = runner; runner = (executable, args, options) => { checkCancelled(); return execute(executable, args, { ...options, ...(signal ? { signal } : {}) }); };
  if (!receipt.home || !path.isAbsolute(receipt.home) || !receipt.instance.startsWith('ud-agent') || !path.isAbsolute(provisioning.template) || !/^sha256:[0-9a-f]{64}$/.test(provisioning.templateSha256) || !Array.isArray(provisioning.assets) || provisioning.assets.length > 128) throw new Error('LIMA_OWNED_PROVISION_RECEIPT_REQUIRED');
  if (network === 'offline' && !provisioning.offlineReady) throw new Error('LIMA_OFFLINE_GUEST_PACK_REQUIRED');
  await verifyArchive(receipt.executable, receipt.binarySha256); await verifyArchive(provisioning.template, provisioning.templateSha256);
  const store = await JournalStore.open(stateRoot, guard);
  const native = await openStateAuthority(store.root, guard);
  const boundHome = await resolveOwnedLimaHome(store.root, guard);
  if (boundHome ? boundHome !== receipt.home : path.relative(store.root, receipt.home) !== 'lima-home') throw new Error('LIMA_OWNED_HOME_UNSAFE');
  await mkdir(receipt.home, { recursive: true, mode: 0o700 });
  const home = await realpath(receipt.home); const homeInfo = await lstat(home); if (process.platform !== 'win32' && (homeInfo.mode & 0o077) !== 0 || typeof process.getuid === 'function' && homeInfo.uid !== process.getuid() || home !== receipt.home) throw new Error('LIMA_OWNED_HOME_UNSAFE');
  if (process.platform === 'win32') await openStateAuthority(home, guard, true);
  if (process.platform === 'darwin' && !limaSocketPathFits(home)) throw new Error('LIMA_OWNED_HOME_PATH_TOO_LONG');
  return store.withWorkspaceLock('lima-owned-provision', async () => {
    checkCancelled();
    const assets = new Map<string, string>();
    const assetsDirectory = path.join(home, '_assets'); await mkdir(assetsDirectory, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; });
    const assetsInfo = await lstat(assetsDirectory); if (!assetsInfo.isDirectory() || assetsInfo.isSymbolicLink() || process.platform !== 'win32' && (assetsInfo.mode & 0o077) !== 0) throw new Error('LIMA_ASSET_CACHE_UNSAFE');
    if (process.platform === 'win32') await openStateAuthority(assetsDirectory, guard, true);
    for (const asset of provisioning.assets) {
      checkCancelled();
      if (!/^[a-z][a-z0-9-]{0,63}$/.test(asset.key) || assets.has(asset.key) || !/^sha256:[0-9a-f]{64}$/.test(asset.sha256) || !Number.isSafeInteger(asset.sizeBytes) || asset.sizeBytes < 1) throw new Error('LIMA_PROVISION_ASSET_INVALID');
      const cached = path.join(assetsDirectory, asset.sha256.slice(7));
      try { const info = await lstat(cached); if (!info.isFile() || info.isSymbolicLink() || info.size !== asset.sizeBytes || (info.mode & 0o222) !== 0) throw new Error('LIMA_ASSET_CACHE_CORRUPT'); await verifyArchive(cached, asset.sha256); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const staged = await stageVerifiedArchive(asset.path, asset.sha256, asset.sizeBytes, { stateRoot: path.join(store.root, 'archive-staging'), guard, ...(signal ? { signal } : {}) });
        try { await copyFile(staged.filename, cached, constants.COPYFILE_EXCL); await chmod(cached, 0o600); const handle = await open(cached, 'r+'); try { await handle.sync(); } finally { await handle.close(); } await chmod(cached, 0o400); await fsyncDirectory(assetsDirectory, await openStateAuthority(assetsDirectory, guard)); } finally { await staged.cleanup(); }
      }
      assets.set(asset.key, pathToFileURL(cached).toString());
    }
    const original = parse(await readBoundedReceiptBytes(provisioning.template));
    const substitute = (value: unknown): unknown => {
      if (typeof value === 'string') { const match = /^\{\{asset:([a-z][a-z0-9-]{0,63})\}\}$/.exec(value); if (match) { const selected = assets.get(match[1]!); if (!selected) throw new Error('LIMA_PROVISION_ASSET_MISSING'); return selected; } if (/(?:https?|file):\/\//i.test(value)) throw new Error('LIMA_UNDECLARED_DOWNLOAD_FORBIDDEN'); return value; }
      if (Array.isArray(value)) return value.map(substitute); if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, substitute(item)])); return value;
    };
    const config = substitute(original) as Record<string, unknown>;
    const unexpandedTemplateIdentity = digest(canonical(config));
    const containerd = object(config.containerd);
    if (containerd?.archives !== undefined) {
      if (!Array.isArray(containerd.archives) || !containerd.archives.length) throw new Error('LIMA_PROVISION_ARCHIVE_NOT_BOUND');
      for (const raw of containerd.archives) {
        const archive = object(raw);
        if (!archive || typeof archive.location !== 'string' || ![...assets.values()].includes(archive.location) || typeof archive.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(archive.digest)) throw new Error('LIMA_PROVISION_ARCHIVE_NOT_BOUND');
        const local = fileURLToPath(archive.location); await verifyArchive(local, archive.digest);
        // Lima's cidata builder opens local containerd archives directly; a
        // file: URI survives download handling and cannot be opened as a path.
        archive.location = local;
      }
    }
    if (config.provision !== undefined) {
      if (!Array.isArray(config.provision)) throw new Error('LIMA_PROVISION_TEMPLATE_INVALID');
      for (const raw of config.provision) {
        const item = object(raw); if (!item) throw new Error('LIMA_PROVISION_TEMPLATE_INVALID');
        if (item.file === undefined) continue;
        const file = object(item.file);
        if (!file || Object.keys(file).sort().join(',') !== 'digest,url' || typeof file.url !== 'string' || ![...assets.values()].includes(file.url) || typeof file.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(file.digest) || item.script !== undefined || !['dependency', 'system', 'user', 'boot'].includes(item.mode as string)) throw new Error('LIMA_PROVISION_SCRIPT_NOT_BOUND');
        const bytes = await readBoundedReceiptBytes(fileURLToPath(file.url));
        if (digest(bytes) !== file.digest) throw new Error('LIMA_PROVISION_SCRIPT_CHANGED');
        // Match Lima's file-to-script normalization before recording ownership.
        item.script = new TextDecoder('utf-8', { fatal: true }).decode(bytes); delete item.file;
      }
    }
    validateOwnedLimaTemplate(config, receipt.architecture);
    const templateIdentity = digest(canonical(config)); const ownerFile = path.join(store.root, 'lima-instance.json');
    let owner: Record<string, unknown> | undefined;
    try { owner = object(JSON.parse((await boundedRead(ownerFile, 16384, native)).toString('utf8'))); if (owner?.schema_version !== 1 || owner.instance !== receipt.instance || owner.home !== home || owner.template_sha256 !== templateIdentity && owner.template_sha256 !== unexpandedTemplateIdentity || !['creating', 'created', 'running'].includes(owner.phase as string)) throw new Error('LIMA_OWNERSHIP_CHANGED'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    await verifyGeneratedLimaConfig(home, store, provisioning, owner !== undefined, runner, guard);
    let inventory = await inspectLima(receipt, receipt.instance, runner); let created = false; let started = false;
    if (inventory.selected && !owner) throw new Error('LIMA_INSTANCE_NOT_OWNED');
    if (!inventory.selected) {
      checkCancelled();
      // Record absence before the create side effect. A later recovery may
      // admit only this origin-bound generated pair, never an arbitrary key.
      const configDirectory = path.join(home, '_config'); let initial: Record<string, unknown> | undefined;
      try { const names = await readdir(configDirectory); if (!names.length) initial = { kind: 'empty', directory: await guardedIdentity(guard, configDirectory) }; }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; initial = { kind: 'absent' }; }
      if (initial) {
        const origin = { schema_version: 1, instance: receipt.instance, home, state_identity: await guardedIdentity(guard, store.root), home_identity: await guardedIdentity(guard, home), template_sha256: templateIdentity, initial_config: initial };
        const originPath = path.join(store.root, 'lima-create-origin.json');
        try { const previous = object(JSON.parse((await boundedRead(originPath, 16384, native)).toString('utf8'))); if (canonical(previous) !== canonical(origin)) throw new Error('LIMA_CREATE_ORIGIN_CHANGED'); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; await durableWrite(originPath, Buffer.from(`${JSON.stringify(origin)}\n`), native); }
      }
      const pending = { schema_version: 1, instance: receipt.instance, home, template_sha256: templateIdentity, phase: 'creating' }; await durableWrite(ownerFile, Buffer.from(`${JSON.stringify(pending)}\n`), native);
      const temporary = path.join(store.root, `lima-template-${randomUUID()}.yaml`); await writeFile(temporary, stringify(config), { mode: 0o400, flag: 'wx' });
      try { const result = await runner(receipt.executable, ['create', '--name', receipt.instance, '--tty=false', temporary], { timeoutMs: 600_000, maxOutputBytes: 4 * 1024 * 1024, limaHome: home }); if (result.code !== 0) throw new Error('LIMA_CREATE_OUTCOME_REQUIRES_RECOVERY'); } finally { await rm(temporary, { force: true }); }
      inventory = await inspectLima(receipt, receipt.instance, runner); if (!inventory.selected) throw new Error('LIMA_CREATE_OUTCOME_REQUIRES_RECOVERY'); created = true;
    }
    const observed = parse(await readBoundedReceiptBytes(path.join(home, receipt.instance, 'lima.yaml'))); if (canonical(observed) !== canonical(config)) throw new Error('LIMA_OWNED_CONFIG_CHANGED');
    await verifyGeneratedLimaConfig(home, store, provisioning, true, runner, guard);
    await durableWrite(ownerFile, Buffer.from(`${JSON.stringify({ schema_version: 1, instance: receipt.instance, home, template_sha256: templateIdentity, phase: 'created' })}\n`), native);
    if (inventory.selected?.status !== 'running') { const result = await runner(receipt.executable, ['start', '--tty=false', receipt.instance], { timeoutMs: 600_000, maxOutputBytes: 4 * 1024 * 1024, limaHome: home }); if (result.code !== 0) throw new Error('LIMA_START_FAILED'); started = true; }
    inventory = await inspectLima(receipt, receipt.instance, runner); if (inventory.selected?.status !== 'running' || inventory.selected.arch !== receipt.architecture) throw new Error('LIMA_RUNNING_INSTANCE_REQUIRED');
    await verifyGeneratedLimaConfig(home, store, provisioning, true, runner, guard);
    checkCancelled(); await durableWrite(ownerFile, Buffer.from(`${JSON.stringify({ schema_version: 1, instance: receipt.instance, home, template_sha256: templateIdentity, phase: 'running' })}\n`), native);
    await verifyArchive(receipt.executable, receipt.binarySha256); return { created, started };
  });
}
