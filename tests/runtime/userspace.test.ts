import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { chmod, copyFile, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { acquireUserspaceLease, cleanUserspaceState, isCompatibleUvVersion, prepareUserspace, prepareUserspaceRender, repairUserspace, resolveUserspaceExecution, userspaceStateRoot, verifyUserspaceExecution } from '../../packages/runtime-manager/src/userspace.js';
import { checkEnvironment, setupEnvironment } from '../../packages/runtime-manager/src/environment.js';
import { guardedIdentity, guardedStateLock } from '../../packages/workspace/src/guard.js';

const renderWorker = vi.hoisted(() => vi.fn());
vi.mock('../../packages/coordinator/src/userspace-worker.js', () => ({ runUserspaceValidation: renderWorker }));

const nativeFixtureTimeout = (milliseconds: number) => process.platform === 'win32' ? Math.max(milliseconds, 180_000) : milliseconds;
const nativeGuard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
function hash(bytes: Buffer | string): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }

async function fixture(root: string) {
  const release = path.join(root, 'release'); const bin = path.join(root, 'bin');
  await mkdir(path.join(release, 'runtime', 'pack', 'worker'), { recursive: true });
  await mkdir(path.join(release, 'runtime', 'pack', 'upstream'), { recursive: true });
  await mkdir(path.join(release, 'runtime', 'pack', 'context', 'rules'), { recursive: true });
  await mkdir(path.join(release, 'runtime', 'pack', 'wheels'), { recursive: true });
  await mkdir(path.join(release, 'runtime', 'pack', 'worker', 'ud_agent'));
  for (const module of ['udtools', 'udapi']) await mkdir(path.join(release, 'runtime', 'pack', 'upstream', module));
  await mkdir(bin);
  const rules = Object.fromEntries(['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'].map(name => [name, hash('{}\n').slice(7)]));
  const guardPath = process.platform === 'win32' ? 'runtime/pack/guard.exe' : 'runtime/pack/guard';
  const files = new Map<string, string | Buffer>([
    ['runtime/pack/worker/ud_agent/__init__.py', ''],
    ['runtime/pack/worker/ud_agent/worker.py', 'print("worker")\n'],
    ['runtime/pack/upstream/udtools/__init__.py', ''],
    ['runtime/pack/upstream/udapi/__init__.py', ''],
    ['runtime/pack/upstream/regex.py', ''],
    ['runtime/pack/context/context.json', JSON.stringify({ rule_dir: 'rules', rules, context_sha256: hash(JSON.stringify(rules)).slice(7) }) + '\n'],
    ...Object.keys(rules).map(name => [`runtime/pack/context/rules/${name}`, '{}\n'] as [string, string]),
    ['runtime/pack/bootstrap.py', 'print("bootstrap")\n'],
    [guardPath, await readFile(nativeGuard)],
    ['runtime/pack/requirements.txt', ''],
  ]);
  const entries = [];
  for (const [name, content] of files) { const file = path.join(release, ...name.split('/')); await writeFile(file, content); entries.push({ path: name, sha256: hash(content), size: Buffer.byteLength(content) }); }
  await chmod(path.join(release, guardPath), 0o700);
  const platform = {
    worker: 'runtime/pack/worker', upstream: 'runtime/pack/upstream', context: 'runtime/pack/context/context.json',
    bootstrap: 'runtime/pack/bootstrap.py', guard: guardPath, requirements: 'runtime/pack/requirements.txt',
    wheels: 'runtime/pack/wheels', packs: ['core'], files: entries,
  };
  const manifest = JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', platforms: { [`${process.platform}/${process.arch}`]: platform } }) + '\n';
  await writeFile(path.join(release, 'runtime/userspace.lock.json'), manifest);
  await writeFile(path.join(release, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(manifest) }));
  const found = spawnSync(process.env.UD_AGENT_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3'), ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' });
  if (found.status !== 0) throw new Error('A supported Python is required for userspace integration tests.');
  const python = await realpath(found.stdout.trim());
  if (process.platform === 'win32') {
    const source = path.join(root, 'python-shim.rs');
    await writeFile(source, `use std::{env,process::{self,Command}}; fn main(){ let s=Command::new(r###"${python}"###).args(env::args_os().skip(1)).status().unwrap(); process::exit(s.code().unwrap_or(1)); }\n`);
    const built = spawnSync('rustc', [source, '-o', path.join(bin, 'python3.exe')], { encoding: 'utf8' });
    if (built.status !== 0) throw new Error(`Could not build the Python fixture: ${built.stderr}`);
  } else await symlink(python, path.join(bin, 'python3'));
  return { release, bin, state: path.join(root, 'state') };
}

describe('private userspace fallback', () => {
  it('installs a host-only lazy core offline before Python setup and keeps installed guard authority separate', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-lazy-')));
    try {
      const { release, bin, state } = await fixture(root); const manifestPath = path.join(release, 'runtime/userspace.lock.json'); const manifest = JSON.parse(await readFile(manifestPath, 'utf8')); const item = manifest.platforms[`${process.platform}/${process.arch}`]; const chunks: Buffer[] = [];
      for (const entry of item.files) {
        const bytes = await readFile(path.join(release, entry.path)); const header = Buffer.alloc(512); header.write(entry.path); header.write((entry.path === item.guard ? '0000755' : '0000644'), 100); header.write('0000000', 108); header.write('0000000', 116); header.write(bytes.length.toString(8).padStart(11, '0'), 124); header.write('00000000000', 136); header.fill(32, 148, 156); header.write('0', 156); header.write('ustar\0', 257); header.write('00', 263); header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148); chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
      }
      const archive = gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)])); item.lazy_core = { url: `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-userspace-${process.platform}-${process.arch}.tar.gz`, sha256: hash(archive), size: archive.length };
      const helperRelative = `runtime/helpers/guard${process.platform === 'win32' ? '.exe' : ''}`; const installedGuard = path.join(release, helperRelative); await mkdir(path.dirname(installedGuard)); await copyFile(nativeGuard, installedGuard); await chmod(installedGuard, 0o700); const helper = await readFile(installedGuard);
      const text = JSON.stringify(manifest); await writeFile(manifestPath, text); await writeFile(path.join(release, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(text), native_helpers: { [`${process.platform}/${process.arch}`]: { guard: { path: helperRelative, sha256: hash(helper), size_bytes: helper.length } } } }));
      await rm(path.join(release, 'runtime/pack'), { recursive: true }); await mkdir(path.join(state, 'core-cache'), { recursive: true, mode: 0o700 }); await writeFile(path.join(state, 'core-cache', `${hash(archive).slice(7)}.tar.gz`), archive);
      const result = await prepareUserspace(release, state, bin, undefined, 'offline'); expect(result.capability.guard).toBe(installedGuard); expect(result.capability.workerPath).toContain(path.join(state, 'corepacks')); expect((await prepareUserspace(release, state, bin, undefined, 'offline')).reused).toBe(true);
      const lease = await acquireUserspaceLease(result.capability); await chmod(path.join(result.capability.workerPath, 'ud_agent/worker.py'), 0o600); await writeFile(path.join(result.capability.workerPath, 'ud_agent/worker.py'), 'corrupt private cache'); await expect(prepareUserspace(release, state, bin, undefined, 'offline')).rejects.toThrow(/receipt|digest/);
      await expect(repairUserspace(release, state, bin, undefined, 'offline')).rejects.toThrow('USERSPACE_RUNTIME_IN_USE'); await lease();
      const repaired = await repairUserspace(release, state, bin, undefined, 'offline'); expect(repaired.repaired).toBe(true); expect(repaired.capability.python).toBe(result.capability.python); expect(await readFile(path.join(repaired.capability.workerPath, 'ud_agent/worker.py'), 'utf8')).toBe('print("worker")\n');
      const staleCore = path.join(state, 'corepacks', 'b'.repeat(64)); await mkdir(staleCore, { mode: 0o700 }); await writeFile(path.join(staleCore, 'old'), 'owned obsolete cache'); const bounded = await repairUserspace(release, state, bin, undefined, 'offline'); expect(bounded.retention.removed).toContain(`corepacks/${'b'.repeat(64)}`);
      const cleaned = await cleanUserspaceState(state, 'owned-runtime', false, installedGuard); expect(cleaned.paths).toEqual(expect.arrayContaining(['corepacks', 'core-cache'])); await expect(readdir(path.join(state, 'corepacks'))).rejects.toMatchObject({ code: 'ENOENT' });
      expect(cleaned.paths.some(name => name.startsWith('quarantine-'))).toBe(true);
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(30000));
  it('cancels setup subprocess trees, releases native locks, and resumes with the same dependency contract', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-cancel-'));
    try {
      const { release, bin, state } = await fixture(root); const controller = new AbortController(); controller.abort();
      await expect(prepareUserspace(release, state, bin, undefined, 'offline', controller.signal)).rejects.toThrow('USERSPACE_SETUP_CANCELLED');
      const source = path.join(root, 'stall-uv.rs'); const executable = path.join(bin, process.platform === 'win32' ? 'uv.exe' : 'uv');
      await writeFile(source, `use std::{env,fs,process::{self,Command},thread,time::Duration};
fn main(){ let home=env::var("HOME").unwrap(); if env::args().nth(1).as_deref()==Some("child"){ let mut n=0; loop{fs::write(format!("{home}/heartbeat"),n.to_string()).unwrap();n+=1;thread::sleep(Duration::from_millis(20));} }
let child=Command::new(env::current_exe().unwrap()).arg("child").spawn().unwrap();fs::write(format!("{home}/setup-pids"),format!("{} {}",process::id(),child.id())).unwrap();thread::sleep(Duration::from_secs(60)); }
`);
      const built = spawnSync('rustc', [source, '-o', executable], { encoding: 'utf8' }); if (built.status !== 0) throw new Error(`Could not build cancellation fixture: ${built.stderr}`);
      const active = new AbortController(); const pending = prepareUserspace(release, state, bin, undefined, 'offline', active.signal); const rejected = expect(pending).rejects.toThrow('USERSPACE_SETUP_CANCELLED');
      const deadline = Date.now() + 5000; let pids: number[] | undefined;
      while (Date.now() < deadline) { try { pids = (await readFile(path.join(state, 'setup-pids'), 'utf8')).split(' ').map(Number); break; } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; await new Promise(done => setTimeout(done, 10)); } }
      expect(pids).toHaveLength(2); active.abort(); await rejected;
      const stopped = Date.now() + 5000; let alive = true;
      while (Date.now() < stopped) { alive = pids!.some(pid => { try { process.kill(pid, 0); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false; throw error; } }); if (!alive) break; await new Promise(done => setTimeout(done, 10)); }
      expect(alive).toBe(false); await rm(executable);
      expect((await prepareUserspace(release, state, bin)).reused).toBe(false);
      expect((await prepareUserspace(release, state, bin)).reused).toBe(true);
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(30_000));

  it('repairs only owned state after checking product bytes and rolls back a failed rebuild', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-repair-'));
    try {
      const { release, bin, state } = await fixture(root); const first = await prepareUserspace(release, state, bin);
      const environment = path.dirname(path.dirname(first.capability.python)); const index = path.join(state, (await readdir(state)).find(name => name.startsWith('current-'))!); const originalIndex = await readFile(index);
      const lease = await acquireUserspaceLease(first.capability); await writeFile(path.join(environment, 'corrupt.txt'), 'retain evidence');
      await expect(repairUserspace(release, state, bin)).rejects.toThrow('USERSPACE_RUNTIME_IN_USE'); await lease();
      await expect(repairUserspace(release, state, '')).rejects.toMatchObject({ message: expect.stringContaining('USERSPACE_REPAIR_FAILED'), repair: { previous_state_restored: true, previous_usable: false } });
      expect(await readFile(index)).toEqual(originalIndex); expect(await readFile(path.join(environment, 'corrupt.txt'), 'utf8')).toBe('retain evidence');
      const fixed = await repairUserspace(release, state, bin); expect(fixed.repaired).toBe(true); expect(fixed.capability.python).not.toBe(first.capability.python); await verifyUserspaceExecution(fixed.capability);
      expect(await readFile(path.join(state, fixed.quarantine!, 'item-1/corrupt.txt'), 'utf8')).toBe('retain evidence');
      const journalPath = path.join(state, (await readdir(state)).find(name => /^repair-[0-9a-f]{64}\.json$/.test(name))!); const interrupted = JSON.parse(await readFile(journalPath, 'utf8')); interrupted.phase = 'building'; await writeFile(journalPath, JSON.stringify(interrupted));
      const resumed = await repairUserspace(release, state, bin); expect(resumed).toMatchObject({ reused: true, repaired: true }); expect(resumed.capability.python).toBe(fixed.capability.python); expect(JSON.parse(await readFile(journalPath, 'utf8')).phase).toBe('completed');
      const cache = path.join(state, 'uv-cache'); await mkdir(cache, { mode: 0o700, recursive: true }); const oversized = await open(path.join(cache, 'oversized-cache'), 'wx', 0o600); try { await oversized.truncate(2 * 1024 ** 3 + 1); } finally { await oversized.close(); }
      const bounded = await repairUserspace(release, state, bin); expect(bounded.retention.cache_bytes).toBeLessThanOrEqual(2 * 1024 ** 3); expect(bounded.retention.removed).toContain(path.join('uv-cache', 'oversized-cache'));
      expect((await repairUserspace(release, state, bin)).reused).toBe(true);
      await writeFile(path.join(release, 'runtime/pack/worker/ud_agent/worker.py'), 'corrupt product'); const before = await readdir(state);
      await expect(repairUserspace(release, state, bin)).rejects.toThrow(/receipt|digest/); expect(await readdir(state)).toEqual(before);
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60000));
  it('repairs fresh offline state with a preseeded installer and rejects a corrupt cache', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-offline-repair-'));
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Unexpected network request.'));
    try {
      const { release, bin, state } = await fixture(root);
      const extension = process.platform === 'win32' ? '.exe' : '';
      const source = path.join(root, 'offline-uv.rs'), executable = path.join(root, 'offline-uv' + extension);
      await writeFile(source, `use std::{env, process::{self, Command}};
fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.first().and_then(|arg| arg.to_str()) {
        Some("--version") => println!("uv 0.13.7"),
        Some("venv") => {
            let code = Command::new(&args[2]).args(["-I", "-m", "venv", "--copies"])
                .arg(args.last().unwrap()).status().unwrap().code().unwrap_or(1);
            process::exit(code);
        }
        Some("pip") => (), // The fixture's hash-locked requirements are empty.
        _ => process::exit(2),
    }
}
`);
      const compiled = spawnSync('rustc', [source, '-o', executable], { encoding: 'utf8' });
      if (compiled.status !== 0) throw new Error(`Could not build offline uv fixture: ${compiled.stderr}`);
      const bytes = await readFile(executable), digest = hash(bytes);
      const manifestPath = path.join(release, 'runtime/userspace.lock.json'), lockPath = path.join(release, 'runtime/runtime.lock.json');
      const manifest = JSON.parse(await readFile(manifestPath, 'utf8')), runtime = JSON.parse(await readFile(lockPath, 'utf8'));
      manifest.platforms[`${process.platform}/${process.arch}`].uv_download = {
        url: `https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/uv-${process.platform}-${process.arch}${extension}`,
        sha256: digest, size: bytes.length,
      };
      const updated = JSON.stringify(manifest);
      await writeFile(manifestPath, updated);
      await writeFile(lockPath, JSON.stringify({ ...runtime, userspace_sha256: hash(updated) }));
      async function preseed(profile: string, payload: Buffer): Promise<string> {
        const directory = path.join(profile, 'tools');
        await mkdir(directory, { recursive: true, mode: 0o700 });
        const file = path.join(directory, `uv-${digest.slice(7)}${extension}`);
        await writeFile(file, payload, { mode: 0o700 });
        return file;
      }
      const seeded = await preseed(state, bytes);
      expect(await repairUserspace(release, state, bin, undefined, 'offline')).toMatchObject({ installer: 'uv', repaired: true, reused: false });
      expect(await readFile(seeded)).toEqual(bytes);
      const broken = state + '-broken', corrupt = Buffer.from(bytes);
      corrupt[0] = corrupt[0]! ^ 1;
      const brokenCache = await preseed(broken, corrupt);
      await expect(repairUserspace(release, broken, bin, undefined, 'offline')).rejects.toThrow(/USERSPACE_REPAIR_FAILED: .*digest/i);
      expect(await readFile(brokenCache)).toEqual(corrupt);
      expect((await readdir(broken)).some(name => name.startsWith('current-'))).toBe(false);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally { fetchMock.mockRestore(); await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60000));

  it('does not reuse an incompatible or malformed uv executable', () => {
    expect(isCompatibleUvVersion('uv 0.6.9\n')).toBe(false);
    expect(isCompatibleUvVersion('uv 0.7.0 (build)\n')).toBe(true);
    expect(isCompatibleUvVersion('uv 1.0.0\n')).toBe(true);
    expect(isCompatibleUvVersion('uv 0.7.0-beta\n')).toBe(false);
    expect(isCompatibleUvVersion('not uv 0.7.0')).toBe(false);
  });
  it('uses platform-owned locations without touching the treebank', () => {
    expect(userspaceStateRoot({ platform: 'linux', arch: 'x64' }, { HOME: '/home/test', XDG_DATA_HOME: '/private-data' })).toBe('/private-data/ud-agent/userspace');
    expect(userspaceStateRoot({ platform: 'darwin', arch: 'arm64' }, { HOME: '/Users/test' })).toBe('/Users/test/Library/Application Support/ud-agent/userspace');
    expect(userspaceStateRoot({ platform: 'win32', arch: 'arm64' }, { LOCALAPPDATA: 'C:\\Users\\test\\AppData\\Local' })).toBe('C:\\Users\\test\\AppData\\Local\\ud-agent\\data\\userspace');
  });

  it('creates and reuses a private venv and rejects changed or forged execution authority', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-test-'));
    try {
      const { release, bin, state } = await fixture(root);
      const first = await prepareUserspace(release, state, bin);
      expect(first.installer).toBe('venv'); expect(first.reused).toBe(false);
      expect(first.capability).toMatchObject({ isolation: 'userspace', packs: ['core'] });
      await verifyUserspaceExecution(first.capability);
      const second = await prepareUserspace(release, state, bin);
      expect(second.reused).toBe(true); expect(second.capability.python).toBe(first.capability.python);
      const name = (await readdir(state)).find(value => value.startsWith('current-'))!;
      const index = path.join(state, name); const original = await readFile(index, 'utf8'); const meta = JSON.parse(original);
      expect(meta).toMatchObject({ platform: process.platform, arch: process.arch, abi: `cp${meta.python_version.split('.').slice(0, 2).join('')}` });
      meta.arch = process.arch === 'arm64' ? 'x64' : 'arm64'; await writeFile(index, JSON.stringify(meta));
      await expect(resolveUserspaceExecution(release, state)).rejects.toThrow('USERSPACE_PLATFORM_CHANGED');
      const legacy = JSON.parse(original); delete legacy.platform; delete legacy.arch; delete legacy.abi; await writeFile(index, JSON.stringify(legacy));
      expect((await resolveUserspaceExecution(release, state)).python).toBe(first.capability.python);
      await writeFile(index, original);
      const lease = await acquireUserspaceLease(first.capability);
      await expect(cleanUserspaceState(state, 'owned-runtime', false, nativeGuard)).rejects.toThrow('USERSPACE_RUNTIME_IN_USE');
      await lease();
      const stale = '.lease-12345678-1234-1234-1234-123456789abc';
      await writeFile(path.join(state, stale), JSON.stringify({ schema_version: 1, pid: 2_147_483_647 }));
      expect((await cleanUserspaceState(state, 'owned-runtime', true, nativeGuard)).paths).toContain(stale);
      expect((await readFile(path.join(state, stale), 'utf8'))).toContain('2147483647');
      await writeFile(path.join(state, '.maintenance.lock'), JSON.stringify({ schema_version: 1, pid: 2_147_483_647 }));
      expect((await cleanUserspaceState(state, 'cache', true, nativeGuard)).paths).toContain('.maintenance.lock');
      expect((await cleanUserspaceState(state, 'cache', false, nativeGuard)).paths).toContain(stale);
      await writeFile(path.join(state, '.maintenance.lock'), JSON.stringify({ schema_version: 1, pid: process.pid }));
      await expect(cleanUserspaceState(state, 'cache', false, nativeGuard)).rejects.toThrow('USERSPACE_MAINTENANCE_IN_PROGRESS');
      await rm(path.join(state, '.maintenance.lock'));
      await writeFile(path.join(state, '.recovery.lock'), JSON.stringify({ schema_version: 1, pid: 2_147_483_647 }), { mode: 0o600 });
      expect((await cleanUserspaceState(state, 'cache', true, nativeGuard)).paths).toContain('.recovery.lock');
      await cleanUserspaceState(state, 'cache', false, nativeGuard);
      await expect(readFile(path.join(state, '.recovery.lock'))).rejects.toMatchObject({ code: 'ENOENT' });
      const reusedPidLease = '.lease-98765432-1234-1234-1234-123456789abc'; const kernelLock = `${reusedPidLease}.native`;
      const releaseDeadLease = await guardedStateLock(nativeGuard, await realpath(state), kernelLock, await guardedIdentity(nativeGuard, await realpath(state))); await releaseDeadLease();
      await writeFile(path.join(state, reusedPidLease), JSON.stringify({ schema_version: 1, pid: process.pid, kernel_lock: kernelLock }), { mode: 0o600 });
      const reconciled = await cleanUserspaceState(state, 'cache', false, nativeGuard);
      expect(reconciled.paths).toContain(reusedPidLease); expect(reconciled.paths).toContain(kernelLock);
      await expect(readFile(path.join(state, reusedPidLease))).rejects.toMatchObject({ code: 'ENOENT' });
      expect((await cleanUserspaceState(state, 'owned-runtime', true, nativeGuard)).paths).toContain(path.basename(path.dirname(path.dirname(first.capability.python))));
      expect(JSON.parse(await readFile(first.capability.contextPath, 'utf8')).rule_dir).toBe('rules');
      await expect(verifyUserspaceExecution({ ...second.capability })).rejects.toThrow('USERSPACE_AUTHORITY_REQUIRED');
      await writeFile(path.join(path.dirname(path.dirname(first.capability.python)), 'injected.py'), 'x = 1\n');
      await expect(verifyUserspaceExecution(first.capability)).rejects.toThrow('USERSPACE_ENVIRONMENT_CHANGED');
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60_000));

  it('prefers an existing uv to create an equally private environment', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-uv-test-'));
    try {
      const { release, bin, state } = await fixture(root);
      const windows = process.platform === 'win32';
      const found = spawnSync(windows ? 'where.exe' : 'which', [windows ? 'uv.exe' : 'uv'], { encoding: 'utf8', timeout: 10_000, maxBuffer: 65_536 });
      if (found.error || found.status !== 0 || !found.stdout.trim()) throw new Error('The pinned uv is required for this integration test: ' + (found.error?.message ?? found.stderr.trim()).slice(-2048));
      const uv = await realpath(found.stdout.trim().split(/\r?\n/)[0]!);
      if (process.platform === 'win32') await copyFile(uv, path.join(bin, 'uv.exe'));
      else await symlink(uv, path.join(bin, 'uv'));
      const result = await prepareUserspace(release, state, bin);
      expect(result.installer).toBe('uv'); expect(result.reused).toBe(false);
      await verifyUserspaceExecution(result.capability);
      const run = spawnSync(result.capability.python, ['-I', '-B', '-c', 'import sys;sys.path.insert(0,sys.argv[1]);import ud_agent.worker', result.capability.workerPath], { encoding: 'utf8' });
      expect(run.status).toBe(0);
      await verifyUserspaceExecution(result.capability);
      expect((await prepareUserspace(release, state, bin)).reused).toBe(true);
      const cleaned = await cleanUserspaceState(state, 'owned-runtime', false, nativeGuard);
      expect(cleaned.paths.some(item => item.startsWith('env-'))).toBe(true);
      await expect(resolveUserspaceExecution(release, state)).rejects.toThrow();
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60_000));

  it('reclaims an interrupted setup only after native lock acquisition and preserves active ownership', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-setup-recovery-'));
    try {
      const { release, bin, state } = await fixture(root);
      await mkdir(state, { mode: 0o700 });
      const digest = hash(await readFile(path.join(release, 'runtime/userspace.lock.json'))).slice(7);
      const owner = path.join(state, `.setup-${digest}.lock`);
      await writeFile(owner, JSON.stringify({ schema_version: 1, pid: process.pid }), { mode: 0o600 });
      await expect(prepareUserspace(release, state, bin)).rejects.toThrow('USERSPACE_SETUP_IN_PROGRESS_OR_RECOVERY_REQUIRED');
      expect(JSON.parse(await readFile(owner, 'utf8')).pid).toBe(process.pid);
      // A released kernel lock proves the old owner ended even if its PID has
      // since been reused by this live process. Legacy PID records stay conservative.
      await writeFile(owner, JSON.stringify({ schema_version: 1, pid: process.pid, kernel_lock: `.setup-${digest}.native` }));
      const recovered = await prepareUserspace(release, state, bin);
      expect(recovered.reused).toBe(false);
      await verifyUserspaceExecution(recovered.capability);
      await expect(readFile(owner)).rejects.toMatchObject({ code: 'ENOENT' });
      expect((await prepareUserspace(release, state, bin)).reused).toBe(true);
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60_000));

  it('rejects changed, unlisted or unfrozen product assets before creating state', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-test-'));
    try {
      const { release, bin, state } = await fixture(root);
      await writeFile(path.join(release, 'runtime/pack/worker/extra.py'), 'not in receipt');
      await expect(prepareUserspace(release, state, bin)).rejects.toThrow('unlisted file');
      await rm(path.join(release, 'runtime/pack/worker/extra.py'));
      await writeFile(path.join(release, 'runtime/pack/worker/ud_agent/worker.py'), 'changed');
      await expect(resolveUserspaceExecution(release, state)).rejects.toThrow();
      const lock = JSON.parse(await readFile(path.join(release, 'runtime/runtime.lock.json'), 'utf8'));
      lock.state = 'unbuilt'; await writeFile(path.join(release, 'runtime/runtime.lock.json'), JSON.stringify(lock));
      await expect(prepareUserspace(release, state, bin)).rejects.toThrow('USERSPACE_RECEIPT_NOT_FROZEN');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('does not mark an environment ready when a declared dependency cannot import', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-missing-test-'));
    try {
      const { release, bin, state } = await fixture(root);
      const missing = 'runtime/pack/upstream/udapi/__init__.py'; await rm(path.join(release, 'runtime/pack/upstream/udapi'), { recursive: true });
      const manifestPath = path.join(release, 'runtime/userspace.lock.json'); const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
      const platform = manifest.platforms[`${process.platform}/${process.arch}`]; platform.files = platform.files.filter((file: { path: string }) => file.path !== missing);
      const raw = JSON.stringify(manifest) + '\n'; await writeFile(manifestPath, raw);
      await writeFile(path.join(release, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(raw) }));
      await expect(prepareUserspace(release, state, bin)).rejects.toThrow('USERSPACE_DEPENDENCY_PROBE_FAILED');
      await expect(resolveUserspaceExecution(release, state)).rejects.toThrow();
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60_000));

  it('rejects a context whose claimed rule fingerprints do not match its verified files', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-rules-test-'));
    try {
      const { release, bin, state } = await fixture(root);
      const relative = 'runtime/pack/context/context.json'; const contextPath = path.join(release, ...relative.split('/'));
      const context = JSON.parse(await readFile(contextPath, 'utf8')); context.rules['data.json'] = 'a'.repeat(64);
      const contextBytes = JSON.stringify(context) + '\n'; await writeFile(contextPath, contextBytes);
      const manifestPath = path.join(release, 'runtime/userspace.lock.json'); const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
      const item = manifest.platforms[`${process.platform}/${process.arch}`].files.find((file: { path: string }) => file.path === relative);
      item.sha256 = hash(contextBytes); item.size = Buffer.byteLength(contextBytes);
      const raw = JSON.stringify(manifest) + '\n'; await writeFile(manifestPath, raw);
      await writeFile(path.join(release, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(raw) }));
      await expect(prepareUserspace(release, state, bin)).rejects.toThrow('rule context does not match');
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it('uses only a verified offline mirror when a managed Python is needed', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-managed-test-'));
    try {
      const { release, bin, state } = await fixture(root);
      await rm(path.join(bin, process.platform === 'win32' ? 'python3.exe' : 'python3'));
      const exe = process.platform === 'win32' ? '.exe' : '';
      const fakePython = path.join(root, `fake-python${exe}`);
      const pythonSource = path.join(root, 'fake-python.rs');
      await writeFile(pythonSource, 'fn main() { println!("3.14.10"); }\n');
      const pythonBuild = spawnSync('rustc', [pythonSource, '-o', fakePython], { encoding: 'utf8' });
      if (pythonBuild.status !== 0) throw new Error(`Could not build the managed Python fixture: ${pythonBuild.stderr}`);
      const literal = (value: string) => `r###"${value}"###`;
      const uvSource = path.join(root, 'fake-uv.rs');
      await writeFile(uvSource, `use std::{env,fs,path::PathBuf,process};
fn main() {
 let a:Vec<String> = env::args().collect();
 if a.get(1).map(String::as_str)==Some("--version") { println!("uv 0.13.7"); return; }
 let p=PathBuf::from(env::var("UV_PYTHON_INSTALL_DIR").unwrap()).join("cpython-fixture");
 let python=if cfg!(windows){p.join("python.exe")}else{p.join("bin/python3.14")};
 if a.get(1).map(String::as_str)==Some("python") && a.get(2).map(String::as_str)==Some("find") {
  if a.last().unwrap().starts_with("3.14") && python.exists(){println!("{}",python.display());return;} process::exit(1);
 }
 if a.get(1).map(String::as_str)==Some("python") && a.get(2).map(String::as_str)==Some("install") {
  if env::var("UV_OFFLINE").ok().as_deref()!=Some("1") || !a.iter().any(|x| x=="--offline") || !a.iter().any(|x| x.starts_with("file:")) {process::exit(2)}
  fs::create_dir_all(python.parent().unwrap()).unwrap(); fs::copy(${literal(fakePython)},python).unwrap(); return;
 }
 if a.get(1).map(String::as_str)==Some("venv") {
  let dir=PathBuf::from(a.last().unwrap()); let output=if cfg!(windows){dir.join("Scripts/python.exe")}else{dir.join("bin/python")};
  fs::create_dir_all(output.parent().unwrap()).unwrap(); fs::copy(${literal(fakePython)},output).unwrap(); return;
 }
 if a.get(1).map(String::as_str)==Some("pip") && a.iter().any(|x| x=="--no-index") && a.iter().any(|x| x=="--require-hashes"){return}
 process::exit(3);
}\n`);
      const uvBuild = spawnSync('rustc', [uvSource, '-o', path.join(bin, `uv${exe}`)], { encoding: 'utf8' });
      if (uvBuild.status !== 0) throw new Error(`Could not build the uv fixture: ${uvBuild.stderr}`);
      const arch = process.arch === 'arm64' ? 'aarch64' : 'x86_64';
      const triple = process.platform === 'darwin' ? 'apple-darwin' : process.platform === 'win32' ? 'pc-windows-msvc' : 'unknown-linux-gnu';
      const filename = `cpython-3.14.10+20261026-${arch}-${triple}-install_only_stripped.tar.gz`;
      const archive = 'offline-managed-python-fixture';
      const file = path.join(release, 'runtime/userspace.lock.json');
      const manifest = JSON.parse(await readFile(file, 'utf8'));
      manifest.platforms[`${process.platform}/${process.arch}`].python_download = { version: '3.14.10', url: `https://github.com/astral-sh/python-build-standalone/releases/download/20261026/${filename.replace('+', '%2B')}`, sha256: hash(archive), size: Buffer.byteLength(archive) };
      const raw = JSON.stringify(manifest) + '\n'; await writeFile(file, raw);
      await writeFile(path.join(release, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(raw) }));
      await expect(prepareUserspace(release, state, bin, undefined, 'offline')).rejects.toThrow('USERSPACE_COMPATIBLE_PYTHON_REQUIRED');
      const mirror = path.join(state, 'python-mirror', '20261026'); await writeFile(path.join(mirror, filename), archive);
      const prepared = await prepareUserspace(release, state, bin, undefined, 'offline');
      expect(prepared.installer).toBe('uv'); expect(prepared.reused).toBe(false);
      await verifyUserspaceExecution(prepared.capability);
      expect((await prepareUserspace(release, state, bin, undefined, 'offline')).reused).toBe(true);
      const managed = path.join(state, 'pythons', 'cpython-fixture', process.platform === 'win32' ? 'python.exe' : 'bin/python3.14');
      await writeFile(managed, 'tampered');
      await expect(verifyUserspaceExecution(prepared.capability)).rejects.toThrow('USERSPACE_MANAGED_PYTHON_CHANGED');
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60_000));

  it('prepares automatic userspace through the shared environment API and denies project code', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-api-test-'));
    try {
      const { release, bin, state } = await fixture(root);
      const catalog = [{ id: '048', name: 'validation_report', runtime_pack: 'core' }, { id: '050', name: 'project_consistency_report', runtime_pack: 'core' }];
      const options = { sourceRoot: release, searchPath: bin, userspaceStateRoot: state };
      const docker = path.join(bin, process.platform === 'win32' ? 'docker.exe' : 'docker'); await writeFile(docker, 'fixture'); await chmod(docker, 0o700);
      const dockerRunner = async (_exe: string, args: readonly string[]) => ({ code: 0, stdout: Buffer.from(JSON.stringify(args[0] === 'context' ? [{ Endpoints: { docker: { Host: process.platform === 'win32' ? 'npipe:////./pipe/docker_engine' : 'unix:///run/docker.sock' } } }] : { ServerVersion: '29.0.0', SecurityOptions: ['name=seccomp'] })), stderr: Buffer.alloc(0) });
      const optionsWithDocker = { ...options, dockerRunner };
      expect(await checkEnvironment({}, catalog, optionsWithDocker)).toMatchObject({ ready: false, runtime: { engine: 'userspace', selection_reason: 'no_admitted_oci_engine' } });
      const ready = await setupEnvironment({}, catalog, optionsWithDocker);
      expect(ready).toMatchObject({ ready: true, status: 'ready', installer: 'venv', reused: false });
      expect(await setupEnvironment({}, catalog, optionsWithDocker)).toMatchObject({ ready: true, reused: true });
      expect(await checkEnvironment({ engine: 'userspace', required_tools: ['project_consistency_report'] }, catalog, options)).toMatchObject({ ready: false, status: 'blocked_by_policy', unsupported_operations: ['project_consistency_report'] });
      expect(await checkEnvironment({}, catalog, optionsWithDocker)).toMatchObject({ ready: true, runtime: { engine: 'userspace', selection_reason: 'no_admitted_oci_engine', detected_oci: [{ engine: 'docker', availability: 'available', rootless_verified: false }] } });
      expect(await checkEnvironment({ engine: 'docker' }, catalog, optionsWithDocker)).toMatchObject({ ready: false, runtime: { engine: 'docker', selection_reason: 'explicit' } });
      await writeFile(path.join(release, 'runtime/pack/worker/ud_agent/worker.py'), 'tampered');
      await expect(checkEnvironment({}, catalog, optionsWithDocker)).rejects.toThrow();
    } finally { await rm(root, { recursive: true, force: true }); }
  }, nativeFixtureTimeout(60_000));
});


async function renderFixture(root: string) {
  const prepared = await fixture(root), file = path.join(prepared.release, 'runtime/userspace.lock.json');
  const manifest = JSON.parse(await readFile(file, 'utf8')), item = manifest.platforms[`${process.platform}/${process.arch}`];
  // Fixture-only browser metadata; the worker is explicitly mocked below.
  // Actual browser/sandbox acceptance runs against the built native/OCI packs.
  const bytes = Buffer.from('{"schema_version":1,"fixture_browser":"receipt-only"}');
  await writeFile(path.join(prepared.release, 'runtime/pack/render.json'), bytes);
  item.packs.push('render');item.render = { manifest: 'runtime/pack/render.json' };
  item.files.push({ path: 'runtime/pack/render.json', sha256: hash(bytes), size: bytes.length });
  const text = JSON.stringify(manifest);await writeFile(file, text);
  await writeFile(path.join(prepared.release, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: hash(text) }));
  return prepared;
}
function fixtureRender(format: string) {
  const bytes = Buffer.alloc(150);if (format === 'png')Buffer.from('89504e470d0a1a0a','hex').copy(bytes);else { bytes.write('%PDF-1.7');bytes.write('%%EOF',140); }
  return { result: { status: 'complete', artifacts: [{ relative_path: 'probe.' + format, mime_type: format === 'png' ? 'image/png' : 'application/pdf', content_base64: bytes.toString('base64'), sha256: hash(bytes).slice(7), size_bytes: bytes.length }] } };
}
describe('userspace render readiness requires actual bounded worker exports', () => {
  let root: string | undefined;
  let context: Awaited<ReturnType<typeof renderFixture>>;
  let prepared: Awaited<ReturnType<typeof prepareUserspace>>;
  beforeEach(async () => {
    root = await mkdtemp(path.join(os.tmpdir(),'ud-userspace-render-probe-'));
    root = await realpath(root);
    context = await renderFixture(root);
    renderWorker.mockReset().mockImplementation(async (_runtime, input) => fixtureRender(input.arguments.output_format));
    // Installing an isolated Python environment is fixture setup. The render
    // assertions retain their own bound and all product deadlines stay intact.
    prepared = await prepareUserspace(context.release,context.state,context.bin,undefined,'offline');
  }, nativeFixtureTimeout(60_000));
  afterEach(async () => {
    if (root) await rm(root,{recursive:true,force:true});
    root = undefined;
  }, nativeFixtureTimeout(30_000));
  it('keeps core usable while render is unprobed, probes both formats once, and reuses readiness', async () => {
      const { release, bin, state } = context;expect(prepared.capability.renderReady).toBe(false);
      const catalog = [{name:'validation_report',runtime_pack:'core'},{name:'sentence_render',runtime_pack:'render'}], options = {sourceRoot:release,userspaceStateRoot:state,searchPath:bin};
      expect(await checkEnvironment({engine:'userspace',required_tools:['validation_report']},catalog,options)).toMatchObject({ready:true});
      expect(await checkEnvironment({engine:'userspace',required_tools:['sentence_render']},catalog,options)).toMatchObject({ready:false,status:'setup_needed'});
      const results = await Promise.all([prepareUserspaceRender(prepared.capability,'offline'),prepareUserspaceRender(prepared.capability,'offline')]);
      expect(results.every(result=>result.renderReady===true)).toBe(true);expect(renderWorker).toHaveBeenCalledTimes(2);
      expect(renderWorker.mock.calls.map(call=>call[1].arguments.output_format)).toEqual(['png','pdf']);
      expect(renderWorker.mock.calls[0]![1].arguments.sentence_conllu).toContain('العربية 日本語');
      expect(await checkEnvironment({engine:'userspace',required_tools:['sentence_render']},catalog,options)).toMatchObject({ready:true});
      await prepareUserspaceRender(results[0]!,'offline');expect(renderWorker).toHaveBeenCalledTimes(2);
  }, nativeFixtureTimeout(30000));
  it('invalidates a stale browser binding and requires both formats to be proved again', async () => {
      const { release, bin, state } = context;
      const catalog = [{name:'sentence_render',runtime_pack:'render'}], options = {sourceRoot:release,userspaceStateRoot:state,searchPath:bin};
      await prepareUserspaceRender(prepared.capability,'offline');expect(renderWorker).toHaveBeenCalledTimes(2);
      const name = (await readdir(state)).find(name=>/^current-.*\.json$/.test(name))!, markerFile=path.join(state,name), marker=JSON.parse(await readFile(markerFile,'utf8'));
      expect(Object.keys(marker.render_probe.outputs).sort()).toEqual(['pdf','png']);marker.render_probe.browser_manifest_sha256='sha256:'+'0'.repeat(64);await writeFile(markerFile,JSON.stringify(marker));
      expect((await resolveUserspaceExecution(release,state)).renderReady).toBe(false);
      expect(await checkEnvironment({engine:'userspace',required_tools:['sentence_render']},catalog,options)).toMatchObject({ready:false,status:'setup_needed'});
      await prepareUserspaceRender(await resolveUserspaceExecution(release,state),'offline');expect(renderWorker).toHaveBeenCalledTimes(4);
  }, nativeFixtureTimeout(30000));
  it('cannot save readiness when PDF or cleanup fails, and cancellation releases setup ownership', async () => {
      const {release,state}=context;
      renderWorker.mockReset().mockImplementation(async (_runtime,input)=> {if(input.arguments.output_format==='pdf')throw new Error('FIXTURE_BROWSER_SANDBOX_FAILURE');return fixtureRender('png');});
      await expect(prepareUserspaceRender(prepared.capability,'offline')).rejects.toThrow('FIXTURE_BROWSER_SANDBOX_FAILURE');
      expect((await resolveUserspaceExecution(release,state)).renderReady).toBe(false);
      const aborted=new AbortController();aborted.abort();await expect(prepareUserspaceRender(prepared.capability,'offline',aborted.signal)).rejects.toThrow('USERSPACE_SETUP_CANCELLED');
      const marker=JSON.parse(await readFile(path.join(state,(await readdir(state)).find(name=>/^current-.*\.json$/.test(name))!),'utf8'));expect(marker.render_probe).toBeUndefined();
      expect((await readdir(path.join(state,'uv-cache'))).filter(name=>name.startsWith('render-probe-'))).toEqual([]);
  }, nativeFixtureTimeout(30000));
});
