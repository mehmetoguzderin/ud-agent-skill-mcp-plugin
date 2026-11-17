import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { cleanOwnedLimaFiles } from '../../packages/runtime-manager/src/lima-cleanup.js';
import { prepareOwnedLimaHome, removeEmptyOwnedLimaHome } from '../../packages/runtime-manager/src/lima-storage.js';
import { guardedIdentity } from '../../packages/workspace/src/guard.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const sha = (value: string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
async function fixture(action: (input: any) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-lc-')));
  try {
    const state = path.join(root, 'state'); await mkdir(state, { mode: 0o700 }); const home = await prepareOwnedLimaHome(state, guard, path.join(root, 'cache'), process.env.UD_TEST_LIMA_FALLBACK ?? (process.env.UD_STORAGE_LEASE ? path.dirname(os.tmpdir()) : undefined)); await mkdir(path.join(home, '_config'), { mode: 0o700 }); await mkdir(path.join(home, '_assets'), { mode: 0o700 });
    const files = [];
    for (const [name, content] of [['user', 'fixed private key'], ['user.pub', 'fixed public key'], ['networks.yaml', 'pinned defaults']]) { const file = path.join(home, '_config', name!); await writeFile(file, content!, { mode: 0o600 }); const info = await lstat(file, { bigint: true }); files.push({ name, sha256: sha(content!), size: Buffer.byteLength(content!), device: info.dev.toString(), inode: info.ino.toString() }); }
    await writeFile(path.join(state, 'lima-generated-config.json'), JSON.stringify({ schema_version: 1, home, directory: await guardedIdentity(guard, path.join(home, '_config')), files }), { mode: 0o600 }); const asset = path.join(home, '_assets', sha('guest').slice(7)); await writeFile(asset, 'guest', { mode: 0o400 }); await chmod(asset, 0o400);
    const policy = { assets: [{ sha256: sha('guest'), size_bytes: 5 }], generated_config: { networks_sha256: sha('pinned defaults') } }; await action({ root, state, home, asset, policy });
  } finally { await rm(root, { recursive: true, force: true }); }
}
describe('receipt-bound Lima auxiliary cleanup', () => {
  it('previews without writes, removes verified generated files/imports, and preserves unknown work', async () => fixture(async ({ state, home, policy }) => {
    await writeFile(path.join(home, '_assets/foreign'), 'retain'); const dry = await cleanOwnedLimaFiles(state, home, guard, policy, true); expect(dry.paths).toHaveLength(4); expect(dry.protected).toEqual(['_assets/foreign']); await expect(readFile(path.join(state, 'lima-aux-cleanup.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    const done = await cleanOwnedLimaFiles(state, home, guard, policy, false); expect(done.paths).toContain('_config'); expect(await readFile(path.join(home, '_assets/foreign'), 'utf8')).toBe('retain'); expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(false);
    await rm(path.join(home, '_assets/foreign')); expect((await cleanOwnedLimaFiles(state, home, guard, policy, false)).paths).toContain('_assets'); expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(true);
  }), 30_000);
  it('resumes already removed entries using its durable initial inventory', async () => fixture(async ({ state, home, policy, asset }) => {
    await cleanOwnedLimaFiles(state, home, guard, policy, false); const journalFile = path.join(state, 'lima-aux-cleanup.json'); const journal = JSON.parse(await readFile(journalFile, 'utf8')); journal.phase = 'planned'; await writeFile(journalFile, JSON.stringify(journal)); expect(await cleanOwnedLimaFiles(state, home, guard, policy, false)).toEqual({ paths: [], protected: [] }); expect(JSON.parse(await readFile(journalFile, 'utf8')).phase).toBe('completed'); await expect(readFile(asset)).rejects.toMatchObject({ code: 'ENOENT' });
  }), 30_000);
  it('admits the pinned default network append after the generated SSH keypair was captured', async () => fixture(async ({ state, home, policy }) => {
    const journalFile = path.join(state, 'lima-generated-config.json'); const journal = JSON.parse(await readFile(journalFile, 'utf8')); journal.files = journal.files.filter((file: { name: string }) => file.name !== 'networks.yaml'); await writeFile(journalFile, JSON.stringify(journal), { mode: 0o600 });
    const result = await cleanOwnedLimaFiles(state, home, guard, policy, false); expect(result.protected).toEqual([]); expect(result.paths).toEqual(expect.arrayContaining(['_config/user', '_config/user.pub', '_config/networks.yaml', '_config', '_assets'])); expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(true);
  }), 30_000);
  it('rejects an altered default network append before deleting either generated key', async () => fixture(async ({ state, home, policy }) => {
    const journalFile = path.join(state, 'lima-generated-config.json'); const journal = JSON.parse(await readFile(journalFile, 'utf8')); journal.files = journal.files.filter((file: { name: string }) => file.name !== 'networks.yaml'); await writeFile(journalFile, JSON.stringify(journal), { mode: 0o600 }); await writeFile(path.join(home, '_config/networks.yaml'), 'unrelated defaults');
    await expect(cleanOwnedLimaFiles(state, home, guard, policy, false)).rejects.toThrow('digest'); expect(await readFile(path.join(home, '_config/user'), 'utf8')).toBe('fixed private key'); expect(await readFile(path.join(home, '_config/user.pub'), 'utf8')).toBe('fixed public key');
  }), 30_000);
  it('rejects changed known assets and forged cleanup paths before removing any valid offline transport', async () => fixture(async ({ state, home, policy, asset }) => {
    await chmod(asset, 0o600); await writeFile(asset, 'wrong'); await expect(cleanOwnedLimaFiles(state, home, guard, policy, false)).rejects.toThrow('digest'); expect(await readFile(path.join(home, '_config/user'), 'utf8')).toBe('fixed private key'); await writeFile(asset, 'guest');
    await cleanOwnedLimaFiles(state, home, guard, policy, true); await writeFile(path.join(state, 'lima-aux-cleanup.json'), JSON.stringify({ schema_version: 1, home, identity: await guardedIdentity(guard, home), policy_sha256: 'invalid', phase: 'planned', files: [{ relative: '../escape' }], directories: [] }), { mode: 0o600 }); await expect(cleanOwnedLimaFiles(state, home, guard, policy, false)).rejects.toThrow('STATE_INVALID'); expect(await readdir(path.join(home, '_config'))).toHaveLength(3);
  }), 30_000);
});
