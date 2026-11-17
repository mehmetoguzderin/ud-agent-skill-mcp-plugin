import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { limaSocketPathFits, prepareOwnedLimaHome, removeEmptyOwnedLimaHome, resolveOwnedLimaHome } from '../../packages/runtime-manager/src/lima-storage.js';
const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const fallback = process.env.UD_TEST_LIMA_FALLBACK ?? (process.env.UD_STORAGE_LEASE ? path.dirname(os.tmpdir()) : undefined);

async function fixture(action: (state: string, cache: string, root: string) => Promise<void>) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-ls-')));
  try { const state = path.join(root, 'state'), cache = path.join(root, 'cache'); await mkdir(state, { mode: 0o700 }); await action(state, cache, root); }
  finally { await rm(root, { recursive: true, force: true }); }
}
describe('physical product-owned Lima storage', () => {
  it('keeps absent detection read-only', async () => fixture(async (state, cache) => {
    expect(await resolveOwnedLimaHome(state, guard)).toBeUndefined(); expect(await readdir(state)).toEqual([]); await expect(readdir(cache)).rejects.toMatchObject({ code: 'ENOENT' });
  }));
  it('binds a short physical home to the exact state and reuses it without VM or SSH setup', async () => fixture(async (state, cache) => {
    const home = await prepareOwnedLimaHome(state, guard, cache, fallback); const binding = JSON.parse(await readFile(path.join(state, 'lima-home.json'), 'utf8'));
    const digest=createHash('sha256').update(state).digest('hex'),candidate=path.join(cache,digest.slice(0,16));
    expect(home).toBe(process.platform==='darwin'&&!limaSocketPathFits(candidate)?fallback ? path.join(fallback,`l-${digest.slice(0,16)}`) : path.join('/private/tmp',`ud-agent-lima-${digest.slice(0,24)}`):candidate); expect(await realpath(home)).toBe(home);
    expect(binding).toMatchObject({ schema_version: 1, state, home }); expect(await readFile(path.join(home, '_ud-agent-owner.json'), 'utf8')).toBe(JSON.stringify(binding));
    expect(await prepareOwnedLimaHome(state, guard, cache, fallback)).toBe(home); expect(await resolveOwnedLimaHome(state, guard)).toBe(home); expect(await readdir(home)).toEqual(['_ud-agent-owner.json']);
    expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(true); expect(await resolveOwnedLimaHome(state, guard)).toBeUndefined(); await expect(readdir(home)).rejects.toMatchObject({ code: 'ENOENT' });
  }), 30_000);
  it('recovers a fully bound orphan after the state receipt write was interrupted', async () => fixture(async (state, cache) => {
    const home = await prepareOwnedLimaHome(state, guard, cache, fallback); const marker = await readFile(path.join(home, '_ud-agent-owner.json'));
    await rm(path.join(state, 'lima-home.json')); expect(await prepareOwnedLimaHome(state, guard, cache, fallback)).toBe(home); expect(await readFile(path.join(home, '_ud-agent-owner.json'))).toEqual(marker);
  }), 30_000);
  it('rejects replacement homes and does not adopt an unrelated directory', async () => fixture(async (state, cache) => {
    const home = await prepareOwnedLimaHome(state, guard, cache, fallback); await rename(home, `${home}.previous`); await mkdir(home, { mode: 0o700 }); await writeFile(path.join(home, 'foreign'), 'retain');
    await expect(resolveOwnedLimaHome(state, guard)).rejects.toThrow('LIMA_HOME_BINDING_CHANGED'); await expect(prepareOwnedLimaHome(state, guard, cache, fallback)).rejects.toThrow('LIMA_HOME_BINDING_CHANGED'); expect(await readFile(path.join(home, 'foreign'), 'utf8')).toBe('retain');
  }), 30_000);
  it('preserves nonempty owned homes until verified provider cleanup completes', async () => fixture(async (state, cache) => {
    const home = await prepareOwnedLimaHome(state, guard, cache, fallback); await writeFile(path.join(home, 'unknown'), 'retain'); expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(false); expect(await resolveOwnedLimaHome(state, guard)).toBe(home); expect(await readFile(path.join(home, 'unknown'), 'utf8')).toBe('retain');
  }), 30_000);
  it('rejects malformed bindings, marker changes, nonprivate parents and symlinked storage', async () => fixture(async (state, cache, root) => {
    await mkdir(cache, { mode: 0o700 }); await chmod(cache, 0o755); if (process.platform !== 'win32') await expect(prepareOwnedLimaHome(state, guard, cache, fallback)).rejects.toThrow('LIMA_OWNED_HOME_UNSAFE'); await chmod(cache, 0o700);
    const home = await prepareOwnedLimaHome(state, guard, cache, fallback); const binding = JSON.parse(await readFile(path.join(state, 'lima-home.json'), 'utf8'));
    await writeFile(path.join(home, '_ud-agent-owner.json'), JSON.stringify({ ...binding, state: root }), { mode: 0o600 }); await expect(resolveOwnedLimaHome(state, guard)).rejects.toThrow('LIMA_HOME_BINDING_CHANGED');
    await writeFile(path.join(home, '_ud-agent-owner.json'), JSON.stringify(binding), { mode: 0o600 }); await writeFile(path.join(state, 'lima-home.json'), JSON.stringify({ ...binding, extra: true }), { mode: 0o600 }); await expect(resolveOwnedLimaHome(state, guard)).rejects.toThrow('LIMA_HOME_BINDING_INVALID');
    await writeFile(path.join(state, 'lima-home.json'), JSON.stringify(binding), { mode: 0o600 }); await rename(home, `${home}.previous`); await symlink(`${home}.previous`, home, process.platform === 'win32' ? 'junction' : 'dir'); await expect(resolveOwnedLimaHome(state, guard)).rejects.toThrow('LIMA_OWNED_HOME_UNSAFE');
  }));
  it('reads the previous state-local home without migrating during a check', async () => fixture(async (state) => {
    const home = path.join(state, 'lima-home'); await mkdir(home, { mode: 0o700 }); await writeFile(path.join(state, 'lima-instance.json'), JSON.stringify({ schema_version: 1, home }), { mode: 0o600 });
    expect(await resolveOwnedLimaHome(state, guard)).toBe(home); await expect(readFile(path.join(state, 'lima-home.json'))).rejects.toMatchObject({ code: 'ENOENT' });
  }));
  it('counts UTF-8 socket bytes rather than characters', () => { expect(limaSocketPathFits('/short')).toBe(true); expect(limaSocketPathFits(`/${'é'.repeat(60)}`)).toBe(false); });
  it('separates long physical-cache identity from Unix socket capacity and keeps native Mac homes short',async()=>fixture(async(state,_cache,root)=>{
    const cache=path.join(root,'long-cache-'+ 'x'.repeat(150)),home=await prepareOwnedLimaHome(state,guard,cache,fallback);
    expect(await realpath(home)).toBe(home);expect(await resolveOwnedLimaHome(state,guard)).toBe(home);
    if(process.platform==='darwin'){expect(home.startsWith(fallback ? path.join(fallback, 'l-') : '/private/tmp/ud-agent-lima-')).toBe(true);expect(limaSocketPathFits(home)).toBe(true);}else{expect(home.startsWith(cache+path.sep)).toBe(true);expect(limaSocketPathFits(home)).toBe(false);}
    expect(await removeEmptyOwnedLimaHome(state,guard)).toBe(true);
  }));
  it('calibrates conservative socket capacity against an actual owned Unix-domain bind',async()=>fixture(async(_state,_cache,root)=>{
    const suffix=Buffer.byteLength(path.join('ud-agent','ssh.sock.1234567890123456'))+1,short='s'.repeat(103-suffix),long='l'.repeat(180);
    expect(limaSocketPathFits(short)).toBe(true);expect(limaSocketPathFits(long)).toBe(false);
    if(process.platform!=='win32'){
      const available=103-suffix-Buffer.byteLength(root)-1; expect(available).toBeGreaterThan(0);
      const bindShort=path.join(root,'s'.repeat(available)),bindLong=path.join(root,long);
      expect(limaSocketPathFits(bindShort)).toBe(true); expect(limaSocketPathFits(bindLong)).toBe(false);
      const script='import{createServer}from"node:net";import{mkdirSync}from"node:fs";import path from"node:path";const home=process.argv[1];mkdirSync(path.join(home,"ud-agent"),{recursive:true});const server=createServer();server.on("error",e=>{process.stdout.write(e.code);process.exitCode=2});server.listen(path.join(home,"ud-agent","ssh.sock.1234567890123456"),()=>server.close(()=>{process.stdout.write("bound")}));';
      const good=spawnSync(process.execPath,['--input-type=module','-e',script,bindShort],{cwd:root,encoding:'utf8',timeout:5000});expect(good.error).toBeUndefined();expect(good.status,good.stderr).toBe(0);expect(good.stdout).toBe('bound');
      const bad=spawnSync(process.execPath,['--input-type=module','-e',script,bindLong],{cwd:root,encoding:'utf8',timeout:5000});expect(bad.error).toBeUndefined();expect(bad.status).toBe(2);expect(['EINVAL','ENAMETOOLONG']).toContain(bad.stdout);
    }
  }));
  it('recovers each interrupted final deletion without needing a surviving home marker', async () => {
    for (const phase of ['planned', 'marker_removed', 'home_removed'] as const) await fixture(async (state, cache) => {
      const home = await prepareOwnedLimaHome(state, guard, cache, fallback); const binding = JSON.parse(await readFile(path.join(state, 'lima-home.json'), 'utf8')); const record = { schema_version: 1, binding, legacy: false, phase }; await writeFile(path.join(state, 'lima-home-delete.json'), JSON.stringify(record), { mode: 0o600 });
      await rm(path.join(home, '_ud-agent-owner.json')); if (phase !== 'planned') await rm(home, { recursive: true }); if (phase === 'home_removed') await rm(path.join(state, 'lima-home.json'));
      await expect(resolveOwnedLimaHome(state, guard)).rejects.toThrow('REMOVAL_REQUIRES_RECOVERY'); expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(true); expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(true); expect(await resolveOwnedLimaHome(state, guard)).toBeUndefined(); expect(JSON.parse(await readFile(path.join(state, 'lima-home-delete.json'), 'utf8')).phase).toBe('completed');
      const fresh = await prepareOwnedLimaHome(state, guard, cache, fallback); expect(fresh).toBe(home); expect(await resolveOwnedLimaHome(state, guard)).toBe(home);
    });
  }, process.platform === 'win32' ? 90_000 : 30_000);
  it('protects replacement homes and unknown contents during deletion recovery', async () => fixture(async (state, cache) => {
    const home = await prepareOwnedLimaHome(state, guard, cache, fallback); const binding = JSON.parse(await readFile(path.join(state, 'lima-home.json'), 'utf8')); await writeFile(path.join(state, 'lima-home-delete.json'), JSON.stringify({ schema_version: 1, binding, legacy: false, phase: 'planned' }), { mode: 0o600 });
    await writeFile(path.join(home, 'foreign'), 'retain'); expect(await removeEmptyOwnedLimaHome(state, guard)).toBe(false); expect(await readFile(path.join(home, 'foreign'), 'utf8')).toBe('retain'); await rename(home, `${home}.saved`); await mkdir(home, { mode: 0o700 }); await writeFile(path.join(home, 'foreign'), 'replacement'); await expect(removeEmptyOwnedLimaHome(state, guard)).rejects.toThrow('LIMA_HOME_BINDING_CHANGED'); expect(await readFile(path.join(home, 'foreign'), 'utf8')).toBe('replacement');
  }), 30_000);
});
